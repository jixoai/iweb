// 用户原始需求（2026-08-12）：以统一 MinIO 文件空间管理个人 iweb 的应用、域名与 MCP 协作。
// 正交意图：owner key 鉴权；MinIO 工作区；应用与域名注册表；host 到 celld 的受控网关；恢复入口。
// 不可调和的原因：Kernel API 必须脱离 celld 部署生命周期，才能在 admin 应用损坏时恢复节点。
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { createHash, randomBytes, timingSafeEqual } = require("node:crypto");
const { evaluateApplicationPublicationGate } = require("./application-publication-gate.js");
const { supervisorHealth } = require("./supervisor-client.js");
const { createApplicationControl } = require("./application-control.js");
const { mcPackageStore } = require("./package-store.js");
const { createDeployHooks } = require("./deploy-hooks.js");
const contracts = require("./contracts-bundle.cjs");

const appNamePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const hostIdPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const BASE_HOST = requiredHost(process.env.IWEB_BASE_HOST, "IWEB_BASE_HOST");
const API_TOKEN = requiredString(process.env.IWEB_API_TOKEN, "IWEB_API_TOKEN");
const ROUTES_FILE = requiredString(process.env.IWEB_ROUTES_FILE, "IWEB_ROUTES_FILE");
const RECOVERY_WORKER = requiredString(process.env.IWEB_RECOVERY_WORKER, "IWEB_RECOVERY_WORKER");
const ADMIN_CELLD_BUCKET = requiredString(process.env.IWEB_ADMIN_CELLD_BUCKET, "IWEB_ADMIN_CELLD_BUCKET");
const CELLD_ENDPOINT = requiredString(process.env.IWEB_CELLD_ENDPOINT, "IWEB_CELLD_ENDPOINT");
const CELLD_REGION = requiredString(process.env.IWEB_CELLD_REGION, "IWEB_CELLD_REGION");
const ROUTES_OBJECT = "local/iweb-system/routes.json";
const SYSTEM_ALIAS = "local/iweb-system";
const WORKSPACE_OBJECT = "local/iweb-workspace";
const API_PORT = 7070;
// 用户设计（2026-08-15）：admin/mcp 是普通 celld 应用，各自独立进程监听独立端口。
// 端口表来自 IWEB_CELLD_PORTS（entrypoint 注入），逐字段严格校验；缺省回退到固定端口。
function parseCelldPorts(raw) {
  const fallback = { admin: 8787, mcp: 8797, notes: 8807 };
  if (!raw) return fallback;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("IWEB_CELLD_PORTS is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("IWEB_CELLD_PORTS is not an object");
  const ports = {};
  for (const app of ["admin", "mcp", "notes"]) {
    const port = parsed[app];
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("IWEB_CELLD_PORTS." + app + " is not a TCP port");
    ports[app] = port;
  }
  for (const key of Object.keys(parsed)) {
    if (key !== "admin" && key !== "mcp" && key !== "notes") throw new Error("IWEB_CELLD_PORTS has unknown app " + key);
  }
  return ports;
}
const CELLD_PORTS = parseCelldPorts(process.env.IWEB_CELLD_PORTS);
const CELLD_PIDS_DIR = process.env.IWEB_CELLD_PIDS_DIR ?? "";
// Per-app celld process RSS (bytes), refreshed with the sandbox sample cycle.
// Each control-plane app is exactly one celld process now, so its RSS is a
// real, attributable per-application measurement at the process boundary.
const celldRss = new Map();
const CGROUP_MEMORY_CURRENT_FILE = "/sys/fs/cgroup/memory.current";
const CGROUP_MEMORY_MAX_FILE = "/sys/fs/cgroup/memory.max";
const SUPERVISOR_SOCKET = process.env.IWEB_SANDBOX_SOCKET ?? "";
const GATEWAY_DIRECTORY = process.env.IWEB_SANDBOX_GATEWAY_DIR ?? "/run/iweb-sandbox/gw";
// Object endpoint as the sandbox gateway must see MinIO. The gateway container
// is the only sandbox resource attached to a routable network; the operator
// sets this to the MinIO address reachable from that network (commonly the
// network's host-gateway address). It must never equal the gateway's own
// listener (127.0.0.1/localhost/0.0.0.0 on the proxy ports); application-control
// rejects those combinations before any supervisor call. Empty stays
// unconfigured and fails closed at prepare.
const SANDBOX_OBJECT_ENDPOINT = process.env.IWEB_SANDBOX_OBJECT_ENDPOINT ?? "http://10.0.2.2:9000";
const CONTROL_DB_FILE = process.env.IWEB_CONTROL_DB_FILE ?? path.join(path.dirname(ROUTES_FILE), "control-db.json");
const CONTROL_SECRETS_FILE = process.env.IWEB_CONTROL_SECRETS_FILE ?? path.join(path.dirname(ROUTES_FILE), "control-secrets.json");
const reservedHostIds = new Set(["api", "admin", "mcp"]);
const applicationPublicationGate = evaluateApplicationPublicationGate();

let routeStore = loadRouteStore();
const controlStore = new contracts.ControlStore({
  io: contracts.systemControlStoreIO,
  path: CONTROL_DB_FILE,
  empty: contracts.emptyControlStateFile,
  parse: contracts.validateControlStateFile,
});
const applicationControl = createApplicationControl({
  controlStore,
  secretsFile: CONTROL_SECRETS_FILE,
  supervisorSocket: SUPERVISOR_SOCKET,
  gatewayDirectory: GATEWAY_DIRECTORY,
  objectEndpoint: SANDBOX_OBJECT_ENDPOINT,
  // Production snapshot-to-celld chain (2.33/2.34/2.48): every version deploy
  // materializes the verified snapshot into a staging celld project and runs
  // the image-pinned celld deploy with a one-shot bucket-scoped credential
  // (argv-free issuance, retired immediately). A deploy that produces no
  // deploy/current.json pointer fails closed inside package-store.deploy.
  packageStore: mcPackageStore(SYSTEM_ALIAS, createDeployHooks({ endpoint: CELLD_ENDPOINT, region: CELLD_REGION })),
});
const startedAt = Date.now();
const monitorSockets = new Set();
const monitorTickets = new Map();
const appMetrics = new Map();
const sandboxSamples = new Map();
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

// typescript-monorepo：apps 纯路由派生（唯一权威）；无 sourcePath/manifestPath。
function workspaceApps() {
  const appIds = new Set();
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
        deployed: routes.some((route) => route.enabled !== false),
        system: routes.some((route) => route.system),
        domains: routes.map((route) => route.hostId).sort(),
      };
    });
}

function workspaceSnapshot(prefix = "") {
  const files = listWorkspaceFiles(prefix);
  return { root: "/", files, apps: workspaceApps() };
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
  const apps = workspaceApps().map((app) => {
    const metric = metricForApp(app.id);
    return {
      id: app.id,
      domains: app.domains,
      deployed: app.deployed,
      system: app.system,
      requests: metric.requests,
      errors: metric.errors,
      inFlight: metric.inFlight,
      averageLatencyMs: metric.requests === 0 ? 0 : Math.round((metric.totalLatencyMs / metric.requests) * 10) / 10,
      lastRequestAt: metric.lastRequestAt,
      // 控制面应用（admin/mcp）拥有独立 celld 进程：进程 RSS 是真实的逐应用
      // 内存测量；沙箱化应用由 control 投影提供 cgroup 采样。两者都不存在时为 null。
      resources: celldRss.has(app.id)
        ? {
            versionId: "celld-process",
            sampledAt: celldRss.get(app.id).sampledAt,
            cpuMillis: { available: false },
            memoryBytes: { available: true, value: celldRss.get(app.id).bytes },
            pidCount: { available: false },
            terminated: { available: false },
            limits: null,
          }
        : null,
    };
  });
  const sandboxes = Object.values(applicationControl.state().applications).map(controlApplicationProjection);
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
    sandboxes,
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
  // 10.4: sanitize at the boundary — protected diagnostics never enter a frame
  const frame = encodeWebSocketFrame(JSON.stringify(contracts.sanitizeMonitorFrame(monitorSnapshot())));
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
      port: CELLD_PORTS[appName] ?? CELLD_PORTS.admin,
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

// A route only resolves to a sandbox when the control database carries an
// active pointer for a version whose lifecycle is active. Everything else
// stays on the transitional image-seeded Dispatcher until publication begins.
function activeSandboxForApp(appName) {
  const application = applicationControl.state().applications[appName];
  if (!application || application.active.kind !== "active") return null;
  const version = application.versions.find((entry) => entry.versionId === application.active.version.digest);
  if (!version || version.lifecycle !== "active") return null;
  return contracts.deriveSandboxId(application.active.applicationId, application.active.version.digest, application.active.version.sequence);
}

// The private application ingress: Kernel connects to the sandbox gateway's
// 0600 unix socket. Failures are shaped generically; no supervisor, celld, or
// Durable Object diagnostics ever reach the caller.
function proxyToSandbox(request, response, resolved, appName, sandboxId) {
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
      socketPath: `${GATEWAY_DIRECTORY}/${sandboxId}/ingress.sock`,
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
  upstream.on("error", () => {
    metric.inFlight = Math.max(0, metric.inFlight - 1);
    metric.requests += 1;
    metric.errors += 1;
    metric.totalLatencyMs += performance.now() - started;
    metric.lastRequestAt = new Date().toISOString();
    broadcastMonitorSnapshot();
    if (!response.headersSent) sendJson(request, response, 502, { error: "application unavailable" });
    else response.destroy();
  });
  request.pipe(upstream);
}

// Narrow public-object gateway for the base hostname: only explicitly public
// owner objects, never bucket listings or workspace credentials. The operator
// whitelist comes from IWEB_PUBLIC_OBJECTS (comma-separated; an entry ending
// in "/" is a prefix). Defaults to the seeded index.html only.
const publicObjects = contracts.parsePublicObjectSet(process.env.IWEB_PUBLIC_OBJECTS);

function contentHeaderFor(name) {
  const extension = path.extname(name).toLowerCase();
  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".json") return "application/json; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".js") return "text/javascript; charset=utf-8";
  if (extension === ".png") return "image/png";
  if (extension === ".jpg" || extension === ".jpeg") return "image/jpeg";
  if (extension === ".svg") return "image/svg+xml";
  return "application/octet-stream";
}

function servePublicObject(request, response, url) {
  const objectPath = contracts.resolvePublicObject(publicObjects, url.pathname);
  if (objectPath === null) {
    sendJson(request, response, 404, { error: "host is not registered" });
    return;
  }
  try {
    const content = execFileSync("mc", ["cat", `${WORKSPACE_OBJECT}/${objectPath}`], {
      encoding: null,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 1024 * 1024,
    });
    response.writeHead(200, { "content-type": contentHeaderFor(objectPath), "content-length": content.length });
    response.end(content);
  } catch {
    sendJson(request, response, 404, { error: "public object is unavailable" });
  }
}

// Per-application sandbox samples refresh asynchronously; unavailable values
// are preserved and never replaced with zero or node aggregates.
async function refreshSandboxSamples() {
  const applications = Object.values(applicationControl.state().applications);
  for (const application of applications) {
    for (const version of application.versions) {
      if (version.lifecycle !== "active" && version.lifecycle !== "ready") continue;
      const sandboxId = contracts.deriveSandboxId(version.identity.applicationId, version.identity.digest, version.identity.sequence);
      try {
        const response = await applicationControl.sandboxMetrics(application.applicationId, version.versionId);
        sandboxSamples.set(sandboxId, { sample: response.sample ?? null, fetchedAt: Date.now() });
      } catch {
        sandboxSamples.set(sandboxId, { sample: null, fetchedAt: Date.now() });
      }
    }
  }
  refreshCelldRss();
}

// Read each control-plane app's own celld process RSS from its pidfile +
// /proc/<pid>/status. One app = exactly one process, so VmRSS is a real
// per-application memory measurement at the process boundary. A missing
// pidfile or an exited process simply leaves the previous sample stale-checked
// out (deleted): the projection then reports no sample, never a fabricated 0.
function refreshCelldRss() {
  for (const app of Object.keys(CELLD_PORTS)) {
    if (app === "notes") continue; // not running by default until sandbox migration
    let rssBytes = null;
    if (CELLD_PIDS_DIR) {
      try {
        const pid = Number.parseInt(fs.readFileSync(path.join(CELLD_PIDS_DIR, "celld-" + app + ".pid"), "utf8").trim(), 10);
        if (Number.isSafeInteger(pid) && pid > 0) {
          const status = fs.readFileSync("/proc/" + pid + "/status", "utf8");
          const match = status.match(/^VmRSS:\s+(\d+) kB$/m);
          if (match) rssBytes = Number(match[1]) * 1024;
        }
      } catch {
        rssBytes = null;
      }
    }
    if (rssBytes !== null) celldRss.set(app, { bytes: rssBytes, sampledAt: new Date().toISOString() });
    else celldRss.delete(app);
  }
}

setInterval(refreshSandboxSamples, 15_000).unref();
void refreshSandboxSamples();

function controlApplicationProjection(application) {
  const active = application.active.kind === "active" ? application.active.version : null;
  const sandboxId = active ? contracts.deriveSandboxId(active.applicationId, active.digest, active.sequence) : null;
  // 10.4: the validated projection preserves unavailable semantics and rejects
  // malformed samples instead of forwarding them to monitor frames.
  const sample = sandboxId ? contracts.projectSandboxResources(sandboxSamples.get(sandboxId)?.sample) : null;
  // Control-plane apps (own celld process, never sandboxed): resources are the
  // process-boundary RSS sample. This is a real measurement for exactly one
  // process per app — never a share of the node total.
  const resources = sample ?? (celldRss.has(application.applicationId)
    ? {
        versionId: "celld-process",
        sampledAt: celldRss.get(application.applicationId).sampledAt,
        cpuMillis: { available: false },
        memoryBytes: { available: true, value: celldRss.get(application.applicationId).bytes },
        pidCount: { available: false },
        terminated: { available: false },
        limits: null,
      }
    : null);
  return {
    id: application.applicationId,
    sandboxId,
    activeVersion: active ? { digest: active.digest, sequence: active.sequence } : null,
    routeGeneration: application.active.routeGeneration,
    lifecycle: active ? application.versions.find((version) => version.versionId === active.digest)?.lifecycle ?? "failed" : "unavailable",
    versions: application.versions.map((version) => ({
      versionId: version.versionId,
      sequence: version.identity.sequence,
      lifecycle: version.lifecycle,
      admittedAt: version.admittedAt,
      readinessExpiresAt: version.readinessExpiresAt,
    })),
    resources,
  };
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
  if (url.pathname === "/v1/applications" || url.pathname.startsWith("/v1/applications/")) {
    if (!applicationPublicationGate.enabled) {
      sendJson(request, response, 503, {
        error: "application publication is disabled until sandbox acceptance passes",
        code: "APPLICATION_PUBLICATION_DISABLED",
      });
      return;
    }
  }
  if (request.method === "GET" && url.pathname === "/v1/status") {
    const sandboxSupervisor = await supervisorHealth(SUPERVISOR_SOCKET);
    sendJson(request, response, 200, {
      baseHost: BASE_HOST,
      runtime: "celld",
      routes: routeStore.routes.length,
      memory: memorySnapshot(),
      applicationPublication: {
        enabled: applicationPublicationGate.enabled,
        reasons: applicationPublicationGate.reasons,
      },
      sandboxSupervisor,
      applications: Object.values(applicationControl.state().applications).map(controlApplicationProjection),
    });
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
        ADMIN_CELLD_BUCKET,
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
  // Application lifecycle endpoints. Owner-authenticated; the publication
  // gate above keeps every /v1/applications operation at 503 until acceptance.
  if (request.method === "GET" && url.pathname === "/v1/applications") {
    sendJson(request, response, 200, {
      applications: Object.values(applicationControl.state().applications).map(controlApplicationProjection),
    });
    return;
  }
  const applicationMatch = url.pathname.match(/^\/v1\/applications\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\/versions$/);
  if (request.method === "POST" && applicationMatch) {
    const applicationId = applicationMatch[1];
    const body = await readJson(request);
    const admission = await admitWorkspacePackage(applicationId, body);
    sendJson(request, response, 201, admission);
    return;
  }
  const versionMatch = url.pathname.match(/^\/v1\/applications\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\/versions\/([a-f0-9]{64})(?:\/(prepare|readiness|activate|rollback|start|stop))?$/);
  if (versionMatch) {
    const applicationId = versionMatch[1];
    const versionId = versionMatch[2];
    const action = versionMatch[3] ?? null;
    if (request.method === "GET" && action === null) {
      sendJson(request, response, 200, await applicationControl.inspectVersion(applicationId, versionId));
      return;
    }
    if (request.method === "POST" && action === "prepare") {
      sendJson(request, response, 201, await applicationControl.prepare(applicationId, versionId));
      return;
    }
    if (request.method === "POST" && action === "readiness") {
      sendJson(request, response, 200, await applicationControl.probeReady(applicationId, versionId));
      return;
    }
    if (request.method === "POST" && action === "activate") {
      // The control surface is single-writer serialized: await the committed
      // activation BEFORE responding or draining, so the response carries the
      // real generation/retired result (not a serialized Promise) and drain only
      // runs after the active pointer is durably committed.
      const activation = await applicationControl.activate(applicationId, versionId);
      void applicationControl.drainRetired(applicationId).catch(() => undefined);
      sendJson(request, response, 200, activation);
      return;
    }
    if (request.method === "POST" && action === "rollback") {
      const rollback = await applicationControl.rollback(applicationId, versionId);
      void applicationControl.drainRetired(applicationId).catch(() => undefined);
      sendJson(request, response, 200, rollback);
      return;
    }
    if ((request.method === "POST" && (action === "start" || action === "stop")) || (request.method === "GET" && action === null) || (request.method === "POST" && (action === "prepare" || action === "readiness"))) {
      // 7.3/7.4/9.2: every version action goes through the shared dispatcher,
      // which awaits each committed result before the transport layer responds.
      const outcome = await contracts.handleVersionAction(applicationControl, applicationId, versionId, request.method, action);
      if (outcome.drainAfterCommit) void applicationControl.drainRetired(applicationId).catch(() => undefined);
      sendJson(request, response, outcome.status, outcome.body);
      return;
    }
    if (request.method === "DELETE" && action === null) {
      sendJson(request, response, 200, await applicationControl.deleteVersion(applicationId, versionId));
      return;
    }
  }
  // Owner-authorized destruction of an application's persistent-data namespace.
  // Distinct from version deletion: deleting a version never removes data.
  const dataMatch = url.pathname.match(/^\/v1\/applications\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\/data$/);
  if (request.method === "DELETE" && dataMatch) {
    await applicationControl.deleteApplicationData(dataMatch[1]);
    sendJson(request, response, 200, { applicationId: dataMatch[1], deleted: "data" });
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/recover/sandboxes") {
    const reconciliation = await applicationControl.reconcile();
    const recovered = reconciliation.missingActive.length > 0 ? await applicationControl.recoverMissingActive() : { recovered: [] };
    sendJson(request, response, 200, { reconciliation, recovered });
    return;
  }
  sendJson(request, response, 404, { error: "unknown kernel API route" });
}

// 7.2 admission from the canonical owner workspace snapshot. Nothing from the
// package executes; the manifest and file set are validated before any digest
// persists, and the snapshot is re-verified against the live listing (TOCTOU).
async function admitWorkspacePackage(applicationId, body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("admission body must be an object");
  const manifestPath = applicationId + "/iweb.json";
  const listing = listWorkspaceFiles(applicationId);
  const manifestEntry = listing.find((file) => file.path === manifestPath);
  if (!manifestEntry) throw new Error("package manifest is missing");
  const manifestText = execFileSync("mc", ["cat", WORKSPACE_OBJECT + "/" + manifestPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1024 * 1024 });
  let parsedManifest;
  try {
    parsedManifest = JSON.parse(manifestText);
  } catch {
    throw new Error("package manifest is not valid JSON");
  }
  // The manifest is the ONLY policy authority: schema validation rejects
  // unknown fields, unbounded resources, and non-celld runtimes before any
  // digest persists. Request-body policy overrides are ignored by design.
  const validatedManifest = contracts.validateApplicationManifest(parsedManifest);
  if (!validatedManifest.ok) {
    const error = new Error("package manifest is invalid");
    error.code = "MANIFEST_REJECTED";
    error.issues = validatedManifest.errors;
    throw error;
  }
  const manifest = validatedManifest.value;
  const files = listing
    .filter((file) => file.path !== manifestPath)
    .map((file) => ({ path: file.path.slice(applicationId.length + 1), size: file.size, kind: "file" }));
  const statFile = (packagePath) => {
    const entry = listing.find((file) => file.path === applicationId + "/" + packagePath);
    return entry ? { kind: "regular", size: entry.size, mtimeNs: 0 } : { kind: "missing", size: 0, mtimeNs: 0 };
  };
  const readContent = (packagePath) =>
    execFileSync("mc", ["cat", WORKSPACE_OBJECT + "/" + applicationId + "/" + packagePath], {
      encoding: null,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 64 * 1024 * 1024,
    });
  const collected = contracts.collectPackage({ manifest, manifestText, files, readContent, statFile });
  if (!collected.ok) {
    const error = new Error("package collection rejected");
    error.code = "PACKAGE_REJECTED";
    error.issues = collected.errors;
    throw error;
  }
  // TOCTOU: the live listing must still agree with the collected snapshot.
  const after = listWorkspaceFiles(applicationId);
  const changed = after.some((file) => {
    if (file.path === manifestPath) return false;
    const entry = listing.find((candidate) => candidate.path === file.path);
    return !entry || entry.size !== file.size;
  });
  if (changed) {
    const error = new Error("workspace changed during package collection");
    error.code = "PACKAGE_TOCTOU_CHANGED";
    throw error;
  }
  const snapshotFiles = collected.value.files.map((file) => ({ path: file.path, content: readContent(file.path) }));
  const policy = { resources: manifest.resources, egress: manifest.egress };
  return applicationControl.admit({ applicationId, packageDigest: collected.value.digest, manifest, policy, snapshotFiles });
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
      // The base hostname may still serve an explicitly public owner object
      // through the narrow gateway; everything else stays 404.
      if (normalizeHost(request.headers.host) === BASE_HOST && request.method === "GET") {
        servePublicObject(request, response, url);
        return;
      }
      sendJson(request, response, 404, { error: "host is not registered" });
      return;
    }
    const appName = resolved.route.target?.appName;
    const sandboxId = activeSandboxForApp(appName);
    // A user application route is served only by its ready active sandbox via
    // the private ingress. With no ready active sandbox it is a bounded generic
    // 502 — never a fallback to the shared Dispatcher, which would execute
    // untrusted code outside the sandbox boundary. Trusted image-seeded system
    // routes (admin/mcp) remain on the Dispatcher.
    const action = contracts.routeAction(resolved.route, sandboxId);
    if (action.kind === "system") proxyToCelld(request, response, resolved);
    else if (action.kind === "sandbox") proxyToSandbox(request, response, resolved, appName, action.sandboxId);
    else sendJson(request, response, 502, { error: "application unavailable" });
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
// 2.52 startup reconciliation: on boot, Kernel reconciles admitted versions
// against the supervisor automatically (missing actives, stale preparing,
// quarantined unknown resources) instead of waiting for a manual recovery call.
// Recovery itself stays explicit (/v1/recover/sandboxes) — reconciliation only
// observes; it never executes mutable workspace packages.
void applicationControl.reconcile().catch((error) => {
  // a supervisor that is absent or briefly unavailable at boot must not crash
  // Kernel: the observation lands on the next refresh/recovery call
  process.stderr.write("startup sandbox reconciliation unavailable: " + ((error && error.code) || "unknown") + "\n");
});

server.listen(API_PORT, "127.0.0.1", () => {
  process.stdout.write(`iweb kernel listening on 127.0.0.1:${API_PORT}\n`);
});
