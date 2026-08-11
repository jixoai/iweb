// 用户原始需求（2026-08-12）：保留 api.<base> 作为不可覆盖的恢复与管理入口。
// 正交意图：API 鉴权；MinIO 路由注册表；host 到 celld 的受控网关；路径别名；应用代理。
// 不可调和的原因：Kernel API 必须脱离 celld 部署生命周期，才能在 admin 应用损坏时恢复节点。
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { timingSafeEqual } = require("node:crypto");

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
const API_PORT = 7070;
const CELLD_PORT = 8787;
const reservedHostIds = new Set(["api", "admin", "mcp"]);

let routeStore = loadRouteStore();

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

function jsonHeaders(request) {
  const headers = { "content-type": "application/json; charset=utf-8" };
  const origin = request.headers.origin;
  let isAdminOrigin = false;
  if (origin) {
    try {
      const originHost = normalizeHost(new URL(origin).host);
      isAdminOrigin = originHost === `admin.${BASE_HOST}` || originHost === `admin.app.${BASE_HOST}`;
    } catch {
      isAdminOrigin = false;
    }
  }
  if (origin && isAdminOrigin) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-headers"] = "authorization, content-type";
    headers["access-control-allow-methods"] = "GET, POST, DELETE, OPTIONS";
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
    return { route, upstreamPath: `${suffix}${url.search}` };
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
  const headers = { ...request.headers };
  delete headers.connection;
  headers.host = `${appName}.app.${BASE_HOST}`;
  headers["x-iweb-original-host"] = normalizeHost(request.headers.host);
  const externalHost = String(request.headers["x-iweb-external-host"] ?? request.headers.host ?? "");
  const externalPort = String(request.headers["x-iweb-external-port"] ?? "");
  headers["x-iweb-external-host"] = /^\d+$/.test(externalPort) ? `${normalizeHost(externalHost)}:${externalPort}` : externalHost;
  const upstream = http.request(
    {
      host: "127.0.0.1",
      port: CELLD_PORT,
      method: request.method,
      path: resolved.upstreamPath,
      headers,
    },
    (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", (error) => {
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
    sendJson(request, response, 200, { baseHost: BASE_HOST, runtime: "celld", routes: routeStore.routes.length });
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
    if (normalizeHost(request.headers.host) === `api.${BASE_HOST}`) {
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

server.listen(API_PORT, "127.0.0.1", () => {
  process.stdout.write(`iweb kernel listening on 127.0.0.1:${API_PORT}\n`);
});
