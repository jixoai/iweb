// 用户原始需求（2026-08-12）：以统一 MinIO 文件空间管理个人 iweb 的应用、域名与 MCP 协作。
// 正交意图：owner key 鉴权；MinIO 工作区；应用与域名注册表；host 到 celld 的受控网关；恢复入口。
// 不可调和的原因：Kernel API 必须脱离 celld 部署生命周期，才能在 admin 应用损坏时恢复节点。
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { createHash, randomBytes, timingSafeEqual } = require("node:crypto");

const appNamePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const hostIdPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const BASE_HOST = requiredHost(process.env.IWEB_BASE_HOST, "IWEB_BASE_HOST");
const API_TOKEN = requiredString(process.env.IWEB_API_TOKEN, "IWEB_API_TOKEN");
const ROUTES_FILE = requiredString(process.env.IWEB_ROUTES_FILE, "IWEB_ROUTES_FILE");
const RECOVERY_WORKER = requiredString(process.env.IWEB_RECOVERY_WORKER, "IWEB_RECOVERY_WORKER");
const CELLD_BUCKET = requiredString(process.env.IWEB_CELLD_BUCKET, "IWEB_CELLD_BUCKET");
const CELLD_ENDPOINT = requiredString(process.env.IWEB_CELLD_ENDPOINT, "IWEB_CELLD_ENDPOINT");
const CELLD_REGION = requiredString(process.env.IWEB_CELLD_REGION, "IWEB_CELLD_REGION");
const ROUTES_OBJECT = "local/iweb-system/routes.json";
const WORKSPACE_OBJECT = "local/iweb-workspace";
const API_PORT = 7070;
const CELLD_PORT = 8787;
const CGROUP_MEMORY_CURRENT_FILE = "/sys/fs/cgroup/memory.current";
const CGROUP_MEMORY_MAX_FILE = "/sys/fs/cgroup/memory.max";
const reservedHostIds = new Set(["api", "admin", "mcp"]);

let routeStore = loadRouteStore();
const startedAt = Date.now();
const monitorSockets = new Set();
const monitorTickets = new Map();
const appMetrics = new Map();
let workspaceUsage = { fileCount: 0, bytes: 0, refreshedAt: 0 };

function positiveInteger(value) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function memorySnapshot() {
  let usageBytes = null;
  let limitBytes = null;
  try {
    usageBytes = positiveInteger(fs.readFileSync(CGROUP_MEMORY_CURRENT_FILE, "utf8"));
    const rawLimit = fs.readFileSync(CGROUP_MEMORY_MAX_FILE, "utf8").trim();
    limitBytes = rawLimit === "max" ? null : positiveInteger(rawLimit);
  } catch {
    // cgroup v2 is expected in the container; preserve API availability on
    // development hosts where the controller is absent.
  }
  return {
    usageBytes,
    limitBytes,
    usagePercent: usageBytes !== null && limitBytes !== null && limitBytes > 0 ? Math.round((usageBytes / limitBytes) * 10_000) / 100 : null,
    kernelHeapUsedBytes: process.memoryUsage().heapUsed,
  };
}

function requiredString(value, name) {
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredHost(value, name) {
  const host = requiredString(value, name).toLowerCase().replace(/\.$/, "");
  if (!hostIdPattern.test(host) || host.includes("..")) {
    throw new Error(`${name} must be a hostname without scheme, port, or path`);
  }
  return host;
}

function normalizeHost(value) {
  const host = String(value ?? "").trim().toLowerCase();
  return host.replace(/:\d+$/, "").replace(/\.$/, "");
}

function loadRouteStore() {
  const raw = fs.readFileSync(ROUTES_FILE, "utf8");
  const parsed = JSON.parse(raw);
  if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.routes)) {
    throw new Error("invalid iweb route registry");
  }
  return parsed;
}

function persistRouteStore(next) {
  const directory = path.dirname(ROUTES_FILE);
  fs.mkdirSync(directory, { recursive: true });
  const temporary = `${ROUTES_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(next, null, 2)}\n`, "utf8");
  execFileSync("mc", ["cp", temporary, ROUTES_OBJECT], { stdio: "pipe" });
  fs.renameSync(temporary, ROUTES_FILE);
  routeStore = next;
}

function systemRoute(hostId, appName) {
  return { hostId, target: { kind: "celld-app", appName }, system: true, enabled: true };
}

function ensureSystemRoutes() {
  const required = [
    systemRoute("admin", "admin"),
    systemRoute("admin.app", "admin"),
    systemRoute("mcp", "mcp"),
    systemRoute("mcp.app", "mcp"),
  ];
  const missing = required.filter((route) => !routeStore.routes.some((candidate) => candidate.hostId === route.hostId));
  if (missing.length === 0) return;
  persistRouteStore({ version: 1, routes: [...routeStore.routes, ...missing] });
}

function safeTokenEquals(value) {
  const received = Buffer.from(value ?? "");
  const expected = Buffer.from(API_TOKEN);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

function isAuthorized(request) {
  const authorization = request.headers.authorization ?? "";
  return authorization.startsWith("Bearer ") && safeTokenEquals(authorization.slice(7));
}

function routeForHost(hostId) {
  return routeStore.routes.find((route) => route.enabled !== false && route.hostId === hostId) ?? null;
}

function routeForApp(appName) {
  return routeStore.routes.find(
    (route) =>
      route.enabled !== false &&
      route.hostId === `${appName}.app` &&
      route.target?.kind === "celld-app" &&
      route.target.appName === appName,
  ) ?? null;
}

function validateRoute(input) {
  if (!input || typeof input !== "object") throw new Error("route body must be an object");
  const hostId = String(input.hostId ?? "").toLowerCase();
  const appName = String(input.appName ?? "").toLowerCase();
  if (!hostIdPattern.test(hostId)) throw new Error("hostId is not a valid relative hostname");
  if (!appNamePattern.test(appName)) throw new Error("appName is not a valid app identifier");
  const firstLabel = hostId.split(".")[0];
  if (reservedHostIds.has(firstLabel)) throw new Error(`hostId prefix ${firstLabel} is reserved`);
  if (!hostId.endsWith(".app")) throw new Error("v1 user routes must use the .app namespace");
  return {
    hostId,
    target: { kind: "celld-app", appName },
    system: false,
    enabled: input.enabled !== false,
  };
}

function normalizeWorkspacePath(value, { allowEmpty = false } = {}) {
  const path = String(value ?? "").trim().replace(/^\/+/, "").replace(/\/+$/, "");
  if (!path) {
    if (allowEmpty) return "";
    throw new Error("workspace path is required");
  }
  if (path.includes("..") || path.split("/").some((segment) => !segment || segment === ".")) {
    throw new Error("workspace path must stay inside the iweb root");
  }
  if (!/^[A-Za-z0-9._/@+=-]+(?:\/[A-Za-z0-9._,@+=-]+)*$/.test(path)) {
    throw new Error("workspace path contains unsupported characters");
  }
  return path;
}

function parseMcRecords(output) {
  return output
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function listWorkspaceFiles(prefix = "") {
  const normalizedPrefix = normalizeWorkspacePath(prefix, { allowEmpty: true });
  let output = "";
  try {
    output = execFileSync("mc", ["ls", "--json", "--recursive", WORKSPACE_OBJECT], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "workspace is unavailable";
    throw new Error(`workspace listing failed: ${message}`);
  }
  return parseMcRecords(output)
    .filter((record) => record.status === "success" && record.type === "file" && typeof record.key === "string")
    .map((record) => ({ path: record.key, size: Number(record.size ?? 0), lastModified: String(record.lastModified ?? "") }))
    .filter((file) => !normalizedPrefix || file.path === normalizedPrefix || file.path.startsWith(`${normalizedPrefix}/`))
    .sort((left, right) => left.path.localeCompare(right.path));
}

function workspaceApps(files) {
  const appIds = new Set(
    files.filter((file) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/iweb\.json$/.test(file.path)).map((file) => file.path.split("/")[0]),
  );
  for (const route of routeStore.routes) {
    if (route.target?.kind === "celld-app" && appNamePattern.test(route.target.appName ?? "")) {
      appIds.add(route.target.appName);
    }
  }
  return [...appIds]
    .sort()
    .map((id) => {
      const routes = routeStore.routes.filter((route) => route.target?.kind === "celld-app" && route.target.appName === id);
      return {
        id,
        sourcePath: `/${id}/app/`,
        manifestPath: `/${id}/iweb.json`,
        deployed: routes.some((route) => route.enabled !== false),
        system: routes.some((route) => route.system),
        domains: routes.map((route) => route.hostId).sort(),
      };
    });
}

function workspaceSnapshot(prefix = "") {
  const files = listWorkspaceFiles(prefix);
  return { root: "/", files, apps: workspaceApps(listWorkspaceFiles()) };
}

function metricForApp(appName) {
  const current = appMetrics.get(appName);
  if (current) return current;
  const created = { requests: 0, errors: 0, inFlight: 0, totalLatencyMs: 0, lastRequestAt: null };
  appMetrics.set(appName, created);
  return created;
}

function refreshWorkspaceUsage() {
  const files = listWorkspaceFiles();
  workspaceUsage = {
    fileCount: files.length,
    bytes: files.reduce((total, file) => total + file.size, 0),
    refreshedAt: Date.now(),
  };
}

function monitorSnapshot() {
  if (Date.now() - workspaceUsage.refreshedAt > 30_000) {
    try {
      refreshWorkspaceUsage();
    } catch {
      // Workspace metrics are advisory. A temporary MinIO failure must not stop app traffic.
    }
  }
  const apps = workspaceApps([]).map((app) => {
    const metric = metricForApp(app.id);
    return {
      id: app.id,
      sourcePath: app.sourcePath,
      domains: app.domains,
      deployed: app.deployed,
      system: app.system,
      requests: metric.requests,
      errors: metric.errors,
      inFlight: metric.inFlight,
      averageLatencyMs: metric.requests === 0 ? 0 : Math.round((metric.totalLatencyMs / metric.requests) * 10) / 10,
      lastRequestAt: metric.lastRequestAt,
    };
  });
  return {
    type: "snapshot",
    emittedAt: new Date().toISOString(),
    node: {
      uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
      routeCount: routeStore.routes.length,
      workspaceFileCount: workspaceUsage.fileCount,
      workspaceBytes: workspaceUsage.bytes,
      memory: memorySnapshot(),
    },
    apps,
  };
}

function encodeWebSocketFrame(payload) {
  const body = Buffer.from(payload, "utf8");
  if (body.length >= 65_536) throw new Error("monitor frame is too large");
  if (body.length < 126) return Buffer.concat([Buffer.from([0x81, body.length]), body]);
  const header = Buffer.alloc(4);
  header[0] = 0x81;
  header[1] = 126;
  header.writeUInt16BE(body.length, 2);
  return Buffer.concat([header, body]);
}

function broadcastMonitorSnapshot() {
  if (monitorSockets.size === 0) return;
  const frame = encodeWebSocketFrame(JSON.stringify(monitorSnapshot()));
  for (const socket of monitorSockets) {
    if (socket.destroyed) {
      monitorSockets.delete(socket);
      continue;
    }
    socket.write(frame);
  }
}

function createMonitorTicket() {
  const ticket = randomBytes(24).toString("base64url");
  const expiresAt = Date.now() + 30_000;
  monitorTickets.set(ticket, expiresAt);
  return { ticket, expiresAt: new Date(expiresAt).toISOString() };
}

function consumeMonitorTicket(ticket) {
  const expiresAt = monitorTickets.get(ticket);
  monitorTickets.delete(ticket);
  return typeof expiresAt === "number" && expiresAt >= Date.now();
}

function readWorkspaceFile(inputPath) {
  const path = normalizeWorkspacePath(inputPath);
  const content = execFileSync("mc", ["cat", `${WORKSPACE_OBJECT}/${path}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 1024 * 1024,
  });
  return { path, content };
}

function writeWorkspaceFile(input) {
  if (!input || typeof input !== "object") throw new Error("workspace file body must be an object");
  const path = normalizeWorkspacePath(input.path);
  if (typeof input.content !== "string") throw new Error("workspace file content must be text");
  if (Buffer.byteLength(input.content, "utf8") > 1024 * 1024) throw new Error("workspace file is limited to 1 MiB");
  const temporary = `${ROUTES_FILE}.${process.pid}.${Date.now()}.workspace`;
  try {
    fs.writeFileSync(temporary, input.content, "utf8");
    execFileSync("mc", ["cp", temporary, `${WORKSPACE_OBJECT}/${path}`], { stdio: "pipe" });
  } finally {
    fs.rmSync(temporary, { force: true });
  }
  return { path, bytes: Buffer.byteLength(input.content, "utf8") };
}

function deleteWorkspaceFile(inputPath) {
  const workspacePath = normalizeWorkspacePath(inputPath);
  execFileSync("mc", ["rm", `${WORKSPACE_OBJECT}/${workspacePath}`], { stdio: "pipe" });
}

function jsonHeaders(request) {
  const headers = { "content-type": "application/json; charset=utf-8" };
  const origin = request.headers.origin;
  let isAdminOrigin = false;
  if (origin) {
    try {
      const originHost = normalizeHost(new URL(origin).host);
      isAdminOrigin =
        originHost === BASE_HOST ||
        originHost === `admin.${BASE_HOST}` ||
        originHost === `admin.app.${BASE_HOST}`;
    } catch {
      isAdminOrigin = false;
    }
  }
  if (origin && isAdminOrigin) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-headers"] = "authorization, content-type";
    headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, OPTIONS";
    headers["vary"] = "Origin";
  }
  return headers;
}

function sendJson(request, response, status, body) {
  response.writeHead(status, jsonHeaders(request));
  response.end(`${JSON.stringify(body)}\n`);
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 64 * 1024) reject(new Error("request body too large"));
    });
    request.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch {
        reject(new Error("request body must be JSON"));
      }
    });
    request.on("error", reject);
  });
}

function routeFromRequest(request, url) {
  const host = normalizeHost(request.headers.host);
  if (host === BASE_HOST) {
    const match = url.pathname.match(/^\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\/app(?:\/(.*))?$/);
    if (!match) return null;
    const appName = match[1];
    const route = routeForApp(appName);
    if (!route) return null;
    const suffix = match[2] ? `/${match[2]}` : "/";
    return { route, upstreamPath: `${suffix}${url.search}`, appBasePath: `/${appName}/app/` };
  }

  const suffix = `.${BASE_HOST}`;
  if (!host.endsWith(suffix)) return null;
  const hostId = host.slice(0, -suffix.length);
  const route = routeForHost(hostId);
  if (!route) return null;
  const appName = route.target?.appName;
  if (route.target?.kind !== "celld-app" || !appNamePattern.test(appName ?? "")) return null;
  return { route, upstreamPath: `${url.pathname}${url.search}` };
}

function proxyToCelld(request, response, resolved) {
  const appName = resolved.route.target.appName;
  const metric = metricForApp(appName);
  const started = performance.now();
  metric.inFlight += 1;
  const headers = { ...request.headers };
  delete headers.connection;
  headers.host = `${appName}.app.${BASE_HOST}`;
  headers["x-iweb-original-host"] = normalizeHost(request.headers.host);
  const externalHost = String(request.headers["x-iweb-external-host"] ?? request.headers.host ?? "");
  const externalPort = String(request.headers["x-iweb-external-port"] ?? "");
  headers["x-iweb-external-host"] = /^\d+$/.test(externalPort) ? `${normalizeHost(externalHost)}:${externalPort}` : externalHost;
  if (resolved.appBasePath) headers["x-iweb-app-base"] = resolved.appBasePath;
  const upstream = http.request(
    {
      host: "127.0.0.1",
      port: CELLD_PORT,
      method: request.method,
      path: resolved.upstreamPath,
      headers,
    },
    (upstreamResponse) => {
      let recorded = false;
      const record = () => {
        if (recorded) return;
        recorded = true;
        metric.inFlight = Math.max(0, metric.inFlight - 1);
        metric.requests += 1;
        if ((upstreamResponse.statusCode ?? 500) >= 500) metric.errors += 1;
        metric.totalLatencyMs += performance.now() - started;
        metric.lastRequestAt = new Date().toISOString();
        broadcastMonitorSnapshot();
      };
      upstreamResponse.once("end", record);
      upstreamResponse.once("error", record);
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", (error) => {
    metric.inFlight = Math.max(0, metric.inFlight - 1);
    metric.requests += 1;
    metric.errors += 1;
    metric.totalLatencyMs += performance.now() - started;
    metric.lastRequestAt = new Date().toISOString();
    broadcastMonitorSnapshot();
    if (!response.headersSent) sendJson(request, response, 502, { error: "celld unavailable", detail: error.message });
    else response.destroy(error);
  });
  request.pipe(upstream);
}

async function handleApi(request, response, url) {
  if (request.method === "OPTIONS") {
    response.writeHead(204, jsonHeaders(request));
    response.end();
    return;
  }
  if (!isAuthorized(request)) {
    sendJson(request, response, 401, { error: "missing or invalid API token" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/status") {
    sendJson(request, response, 200, { baseHost: BASE_HOST, runtime: "celld", routes: routeStore.routes.length, memory: memorySnapshot() });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/key") {
    sendJson(request, response, 200, {
      kind: "owner",
      capabilities: {
        read: ["/**"],
        write: ["/**"],
        deploy: ["*"],
        domains: ["*"],
        environment: ["*"]
      }
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/monitor/session") {
    sendJson(request, response, 201, createMonitorTicket());
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/workspace") {
    sendJson(request, response, 200, workspaceSnapshot(url.searchParams.get("prefix") ?? ""));
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/workspace/file") {
    sendJson(request, response, 200, readWorkspaceFile(url.searchParams.get("path")));
    return;
  }
  if (request.method === "PUT" && url.pathname === "/v1/workspace/file") {
    sendJson(request, response, 201, writeWorkspaceFile(await readJson(request)));
    return;
  }
  if (request.method === "DELETE" && url.pathname === "/v1/workspace/file") {
    deleteWorkspaceFile(url.searchParams.get("path"));
    response.writeHead(204, jsonHeaders(request));
    response.end();
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/routes") {
    sendJson(request, response, 200, routeStore);
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/routes") {
    const route = validateRoute(await readJson(request));
    const existing = routeStore.routes.find((candidate) => candidate.hostId === route.hostId);
    if (existing?.system) {
      sendJson(request, response, 409, { error: "system route cannot be overwritten" });
      return;
    }
    const routes = routeStore.routes.filter((candidate) => candidate.hostId !== route.hostId);
    persistRouteStore({ version: 1, routes: [...routes, route] });
    sendJson(request, response, 201, route);
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/recover/admin") {
    execFileSync(
      "celld",
      [
        "deploy",
        RECOVERY_WORKER,
        "--bucket",
        CELLD_BUCKET,
        "--endpoint",
        CELLD_ENDPOINT,
        "--region",
        CELLD_REGION,
      ],
      { stdio: "pipe" },
    );
    sendJson(request, response, 202, { restarting: true, restored: "image-seed Dispatcher" });
    setTimeout(() => process.kill(1, "SIGTERM"), 250).unref();
    return;
  }
  if (request.method === "DELETE" && url.pathname.startsWith("/v1/routes/")) {
    const hostId = decodeURIComponent(url.pathname.slice("/v1/routes/".length));
    const existing = routeStore.routes.find((candidate) => candidate.hostId === hostId);
    if (!existing) {
      sendJson(request, response, 404, { error: "route not found" });
      return;
    }
    if (existing.system) {
      sendJson(request, response, 409, { error: "system route cannot be deleted" });
      return;
    }
    persistRouteStore({ version: 1, routes: routeStore.routes.filter((candidate) => candidate.hostId !== hostId) });
    sendJson(request, response, 204, {});
    return;
  }
  sendJson(request, response, 404, { error: "unknown kernel API route" });
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", `http://${normalizeHost(request.headers.host) || "localhost"}`);
    if (request.method === "GET" && url.pathname === "/health") {
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      response.end("ok\n");
      return;
    }
    if (
      normalizeHost(request.headers.host) === `api.${BASE_HOST}` ||
      request.headers["x-iweb-internal-control"] === "1"
    ) {
      await handleApi(request, response, url);
      return;
    }
    const resolved = routeFromRequest(request, url);
    if (!resolved) {
      sendJson(request, response, 404, { error: "host is not registered" });
      return;
    }
    proxyToCelld(request, response, resolved);
  } catch (error) {
    sendJson(request, response, 400, { error: error instanceof Error ? error.message : "kernel request failed" });
  }
});

server.on("upgrade", (request, socket) => {
  try {
    const url = new URL(request.url ?? "/", `http://${normalizeHost(request.headers.host) || "localhost"}`);
    if (normalizeHost(request.headers.host) !== `api.${BASE_HOST}` || url.pathname !== "/v1/monitor") {
      socket.destroy();
      return;
    }
    const ticket = url.searchParams.get("ticket") ?? "";
    const key = request.headers["sec-websocket-key"];
    if (!consumeMonitorTicket(ticket) || typeof key !== "string" || request.headers.upgrade?.toLowerCase() !== "websocket") {
      socket.destroy();
      return;
    }
    const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    monitorSockets.add(socket);
    socket.write(encodeWebSocketFrame(JSON.stringify(monitorSnapshot())));
    socket.on("data", (frame) => {
      // Browser WebSocket clients mask frames. A ping is answered without parsing application data.
      if ((frame[0] & 0x0f) === 0x9) socket.write(Buffer.from([0x8a, 0x00]));
    });
    socket.on("close", () => monitorSockets.delete(socket));
    socket.on("error", () => monitorSockets.delete(socket));
  } catch {
    socket.destroy();
  }
});

ensureSystemRoutes();

server.listen(API_PORT, "127.0.0.1", () => {
  process.stdout.write(`iweb kernel listening on 127.0.0.1:${API_PORT}\n`);
});
