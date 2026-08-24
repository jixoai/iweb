// 用户原始需求（2026-08-14）：每个沙箱 pod 内运行 supervisor 所有的 gateway：版本对象代理、策略 egress 代理、Kernel 私有 ingress 与固定健康契约。
// 正交意图：结构上无法绕行——pod 网络为 none；对象代理只放行本 version bucket 并代签名；egress 默认拒绝且每次 redirect 复检；ingress 只有健康端点与转发。
import { createHmac, createHash } from "node:crypto";
import { chmodSync, readFileSync, rmSync } from "node:fs";
import { connect, type Socket } from "node:net";
import { request as httpRequest, type IncomingMessage, type Server } from "node:http";
import { request as httpsRequest } from "node:https";
import { createServer as createHttpServer } from "node:http";
import { createServer as createUnixServer } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";
import { type ManifestEgress } from "../packages/contracts/manifest.ts";
import { compileEgressPolicy, isDeniedEgressDestination, normalizeHostname, isReservedAddress, type CompiledEgressPolicy } from "../packages/contracts/egress-policy.ts";
import { GATEWAY_DATA_LISTEN, GATEWAY_EGRESS_LISTEN, GATEWAY_INGRESS_SOCKET, GATEWAY_OBJECT_LISTEN, READINESS_PATH } from "./sandbox-spec.ts";
import { validateGatewaySecret } from "./desired-state.ts";
import { issueStorageCapability, verifyStorageCapability, applicationDataPrefix, type NonceReplayStore } from "../packages/contracts/storage-gateway.ts";

export interface GatewayObjectConfig {
	readonly endpoint: string;
	readonly region: string;
	readonly accessKeyId: string;
	readonly secretAccessKey: string;
}

export interface GatewayConfig {
	readonly version: 1;
	readonly sandboxId: string;
	readonly versionId: string;
	readonly generation: number;
	readonly bucket: string;
	readonly object: GatewayObjectConfig;
	readonly egress: ManifestEgress;
	// Optional application persistent-data plane. When present the gateway runs a
	// capability-verified data proxy scoped to this application's stable namespace.
	readonly applicationId?: string;
	readonly storageSecret?: string;
	readonly data?: GatewayObjectConfig;
	readonly ingressTarget: string;
	readonly socketDirectory: string;
}

export const MAX_EGRESS_REDIRECTS = 5;
export const MAX_EGRESS_RESPONSE_BYTES = 64 * 1024 * 1024;
export const MAX_GATEWAY_REQUEST_BYTES = 64 * 1024 * 1024;
export const MAX_TUNNEL_BYTES = 512 * 1024 * 1024;
export const EGRESS_REQUEST_TIMEOUT_MS = 30_000;
export const TUNNEL_TIMEOUT_MS = 300_000;
export const HEALTH_DIAL_TIMEOUT_MS = 2_000;

export interface GatewayIO {
	readonly fetchText: (url: string, options: { readonly method: string; readonly headers: Record<string, string>; readonly body: Buffer | null; readonly timeoutMs: number; readonly maxBytes?: number; readonly address?: string }) => Promise<{ readonly status: number; readonly headers: Record<string, string>; readonly body: Buffer }>;
	readonly resolveDns: (host: string) => Promise<string[]>;
	readonly openTunnel: (host: string, port: number, timeoutMs: number, address?: string) => Promise<Socket>;
	readonly dialTcp: (host: string, port: number, timeoutMs: number) => Promise<boolean>;
	readonly signS3: (options: { readonly method: string; readonly host: string; readonly path: string; readonly query: string; readonly payload: Buffer; readonly config: GatewayObjectConfig }) => Promise<Record<string, string>>;
}

// --- S3 SigV4 signing (pure, testable) ---

function hmac(key: Buffer | string, data: string): Buffer {
	return createHmac("sha256", key).update(data, "utf8").digest();
}

export function sha256Hex(data: Buffer | string): string {
	return createHash("sha256").update(data).digest("hex");
}

export function signS3Request(options: { readonly method: string; readonly host: string; readonly path: string; readonly query: string; readonly payload: Buffer; readonly config: GatewayObjectConfig }): Record<string, string> {
	const now = new Date();
	const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
	const dateStamp = amzDate.slice(0, 8);
	const payloadHash = sha256Hex(options.payload);
	const headers: Record<string, string> = {
		host: options.host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date": amzDate,
	};
	const sortedHeaders = ["host", "x-amz-content-sha256", "x-amz-date"];
	const canonicalHeaders = sortedHeaders.map((name) => name + ":" + headers[name].trim() + "\n").join("");
	const signedHeaders = sortedHeaders.join(";");
	const canonicalRequest = [options.method.toUpperCase(), options.path, options.query, canonicalHeaders, signedHeaders, payloadHash].join("\n");
	const scope = dateStamp + "/" + options.config.region + "/s3/aws4_request";
	const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
	const dateKey = hmac("AWS4" + options.config.secretAccessKey, dateStamp);
	const regionKey = hmac(dateKey, options.config.region);
	const serviceKey = hmac(regionKey, "s3");
	const signingKey = hmac(serviceKey, "aws4_request");
	const signature = hmac(signingKey, stringToSign).toString("hex");
	return {
		...headers,
		authorization: "AWS4-HMAC-SHA256 Credential=" + options.config.accessKeyId + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature,
	};
}

// --- gateway config ---

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseGatewayConfig(text: string): GatewayConfig | null {
	try {
		const parsed: unknown = JSON.parse(text);
		if (!isRecord(parsed) || parsed.version !== 1) return null;
		if (typeof parsed.sandboxId !== "string" || typeof parsed.versionId !== "string" || typeof parsed.bucket !== "string") return null;
		if (typeof parsed.generation !== "number" || !Number.isSafeInteger(parsed.generation) || parsed.generation < 1) return null;
		if (typeof parsed.ingressTarget !== "string" || typeof parsed.socketDirectory !== "string") return null;
		if (!isRecord(parsed.object)) return null;
		if (typeof parsed.object.endpoint !== "string" || typeof parsed.object.region !== "string" || typeof parsed.object.accessKeyId !== "string" || typeof parsed.object.secretAccessKey !== "string") return null;
		if (!isRecord(parsed.egress) || parsed.egress.default !== "deny" || !Array.isArray(parsed.egress.allow)) return null;
		// Boot consumer authority: the mounted secret must pass the SAME
		// field-by-field validation the supervisor applies to persisted secrets
		// (bucket, endpoint, credentials, per-entry egress, unknown fields) — a
		// secret the supervisor would reject can never boot the gateway (2.47).
		const validated = validateGatewaySecret(parsed, parsed.sandboxId);
		if (validated === null) return null;
		return validated;
	} catch {
		return null;
	}
}

export function loadGatewayConfig(path: string): GatewayConfig {
	const text = readFileSync(path, "utf8");
	const config = parseGatewayConfig(text);
	if (config === null) throw new Error("gateway config is invalid");
	return config;
}

// --- egress policy enforcement (pure, testable) ---

export interface EgressVerdict {
	readonly allowed: boolean;
	readonly reason: string;
	/** The verified connectable IP; present only when allowed. The connection
	 * is pinned to this address (DNS-rebinding prevention). */
	readonly address?: string;
}

export async function checkEgressTarget(options: { readonly host: string; readonly port: number; readonly policy: CompiledEgressPolicy; readonly resolveDns: (host: string) => Promise<string[]> }): Promise<EgressVerdict> {
	const normalized = normalizeHostname(options.host);
	if (normalized === null) return { allowed: false, reason: "invalid-host" };
	let resolved: string[];
	try {
		resolved = await options.resolveDns(normalized);
	} catch {
		return { allowed: false, reason: "unresolved" };
	}
	const verdict = isDeniedEgressDestination({ host: normalized, resolvedAddresses: resolved, port: options.port, policy: options.policy });
	if (verdict.denied) return { allowed: false, reason: verdict.reason ?? "denied" };
	const connectable = resolved.filter((address) => !isReservedAddress(address));
	if (connectable.length === 0) return { allowed: false, reason: "no-global-address" };
	// The verified address is pinned: the outbound request MUST connect to this
	// exact IP so a rebinding between validation and connection cannot reach a
	// different (private/internal) target.
	return { allowed: true, reason: "allowed", address: connectable[0] };
}

export function classifyRedirectTarget(location: string): { readonly host: string; readonly port: number } | null {
	try {
		const parsed = new URL(location);
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
		const host = parsed.hostname;
		const port = parsed.port !== "" ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
		if (!Number.isSafeInteger(port) || port < 1 || port > 65535) return null;
		return { host, port };
	} catch {
		return null;
	}
}

// --- gateway runtime ---

export interface RunningGateway {
	readonly objectAddress: string;
	readonly egressAddress: string;
	readonly dataAddress?: string;
	readonly close: () => Promise<void>;
}

export interface GatewayListenAddresses {
	readonly object?: string;
	readonly egress?: string;
	readonly data?: string;
}

function trackConnections(server: Server | ReturnType<typeof createUnixServer>): Set<import("node:net").Socket> {
	const sockets = new Set<import("node:net").Socket>();
	server.on("connection", (socket) => {
		sockets.add(socket);
		socket.once("close", () => sockets.delete(socket));
	});
	return sockets;
}

function destroyAll(sockets: Set<import("node:net").Socket>): void {
	for (const socket of sockets) socket.destroy();
}

const HOP_BY_HOP_HEADERS = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]);

function forwardableHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
	const result: Record<string, string> = {};
	for (const [name, value] of Object.entries(headers)) {
		if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
		if (typeof value === "string") result[name] = value;
		else if (Array.isArray(value)) result[name] = value.join(", ");
	}
	return result;
}

// An object/data endpoint must forward to a real MinIO, never back to this
// gateway's own listener: an endpoint whose host:port equals the gateway's own
// listen address would loop forever. Pure so the supervisor adapter can reject
// the combination BEFORE creating any pod, and the gateway re-checks at boot.
export function assertEndpointNotSelfLoop(endpoint: string, listenAddress: string, label: string): void {
	let host = "";
	try {
		host = new URL(endpoint).host;
	} catch {
		throw new Error(label + " endpoint is not a valid absolute URL");
	}
	if (host === listenAddress) throw new Error(label + " endpoint must not equal the gateway's own " + label + " listener (self-loop)");
}

// Read a request body up to a fixed ceiling before any signing or forwarding.
// Returns null when the ceiling is exceeded so the caller answers a bounded 413
// instead of allocating unbounded memory. Bodies are never logged.
export function readBoundedBody(request: IncomingMessage, maxBytes: number): Promise<Buffer | null> {
	return new Promise((resolve) => {
		const chunks: Buffer[] = [];
		let total = 0;
		let settled = false;
		const finish = (value: Buffer | null): void => { if (!settled) { settled = true; resolve(value); } };
		request.on("data", (chunk: Buffer) => {
			if (settled) return;
			total += chunk.length;
			if (total > maxBytes) { finish(null); return; }
			chunks.push(chunk);
		});
		request.on("end", () => finish(Buffer.concat(chunks)));
		request.on("error", () => finish(null));
	});
}

function plainError(status: number, code: string): { readonly status: number; readonly body: string } {
	return { status, body: JSON.stringify({ version: 1, ok: false, code }) + "\n" };
}

export async function startGateway(config: GatewayConfig, io: GatewayIO, listen: GatewayListenAddresses = {}, options: { readonly nonceStore?: NonceReplayStore } = {}): Promise<RunningGateway> {
	const policy = compileEgressPolicy(config.egress);
	const objectListen = listen.object ?? GATEWAY_OBJECT_LISTEN;
	const egressListen = listen.egress ?? GATEWAY_EGRESS_LISTEN;
	const dataPlane = config.applicationId && config.storageSecret && config.data ? { applicationId: config.applicationId, storageSecret: config.storageSecret, data: config.data, nonceStore: options.nonceStore ?? inMemoryNonceStore() } : null;
	const dataListen = listen.data ?? GATEWAY_DATA_LISTEN;
	// Fail closed on self-referential endpoints at boot; the supervisor adapter
	// already rejects the same combinations before any pod is created.
	assertEndpointNotSelfLoop(config.object.endpoint, objectListen, "object");
	if (config.data) assertEndpointNotSelfLoop(config.data.endpoint, dataListen, "data");

	const objectServer = createHttpServer((request, response) => {
		void handleObjectRequest(config, io, request, response);
	});

	const egressServer = createHttpServer((request, response) => {
		void handleEgressRequest(io, policy, request, response);
	});
	// Node emits 'connect' for the CONNECT method instead of a normal request,
	// so HTTPS tunneling must be wired through this event explicitly.
	egressServer.on("connect", (request, socket, head) => {
		void handleConnectEvent(io, policy, request, socket, head);
	});

	const dataServer = dataPlane
		? createHttpServer((request, response) => {
				void handleDataRequest(dataPlane, io, request, response);
			})
		: null;

	const socketPath = config.socketDirectory + "/" + GATEWAY_INGRESS_SOCKET;
	rmSync(socketPath, { force: true });
	const ingressServer = createUnixServer((socket) => {
		void handleIngressConnection(config, io, socket);
	});
	const objectSockets = trackConnections(objectServer);
	const egressSockets = trackConnections(egressServer);
	const ingressSockets = trackConnections(ingressServer);
	const dataSockets = dataServer ? trackConnections(dataServer) : null;

	const listenOn = (server: Server, address: string): Promise<void> =>
		new Promise<void>((resolve, reject) => {
			server.once("error", reject);
			const separator = address.lastIndexOf(":");
			const host = separator > 0 ? address.slice(0, separator) : "127.0.0.1";
			const port = separator > 0 ? Number(address.slice(separator + 1)) : 0;
			server.listen(port, host, () => resolve());
		});
	await listenOn(objectServer, objectListen);
	await listenOn(egressServer, egressListen);
	if (dataServer) await listenOn(dataServer, dataListen);
	await new Promise<void>((resolve, reject) => {
		ingressServer.once("error", reject);
		ingressServer.listen(socketPath, () => resolve());
	});
	// Kernel (container root) connects to this socket; keep it owner+group
	// accessible without opening it to the world.
	chmodSync(socketPath, 0o660);

	const closeServers = (server: Server | ReturnType<typeof createUnixServer>): Promise<void> =>
		new Promise<void>((resolve) => server.close(() => resolve()));

	const addressOf = (server: Server): string => {
		const address = server.address();
		if (typeof address === "object" && address !== null) return address.address + ":" + address.port;
		return String(address ?? "");
	};

	return {
		objectAddress: addressOf(objectServer),
		egressAddress: addressOf(egressServer),
		dataAddress: dataServer ? addressOf(dataServer) : undefined,
		close: async () => {
			// Keep-alive clients (e.g. Kernel's ingress connections) must not
			// hold the listeners open after shutdown.
			destroyAll(objectSockets);
			destroyAll(egressSockets);
			destroyAll(ingressSockets);
			if (dataSockets) destroyAll(dataSockets);
			await closeServers(objectServer);
			await closeServers(egressServer);
			await closeServers(ingressServer);
			if (dataServer) await closeServers(dataServer);
			rmSync(socketPath, { force: true });
		},
	};
}

function inMemoryNonceStore(): NonceReplayStore {
	const seen = new Set<string>();
	return { consume: (nonce) => { if (seen.has(nonce)) return "replayed"; seen.add(nonce); return "fresh"; } };
}

function isSafeDataKey(key: string): boolean {
	if (!key || key.length > 512) return false;
	if (key.startsWith("/")) return false;
	return key.split("/").every((segment) => segment.length > 0 && segment !== ".." && segment !== "." && !/[\u0000-\u001f]/.test(segment));
}

// The application persistent-data plane. The Worker obtains a short-lived
// single-use storage capability from the gateway (the sole holder of the storage
// secret) and presents it for each data operation. Every operation is scoped to
// this application's stable namespace; listing and cross-application access are
// refused, and the signed S3 request never carries the capability itself.
async function handleDataRequest(dataPlane: { readonly applicationId: string; readonly storageSecret: string; readonly data: GatewayObjectConfig; readonly nonceStore: NonceReplayStore }, io: GatewayIO, request: IncomingMessage, response: import("node:http").ServerResponse): Promise<void> {
	const url = new URL(request.url ?? "/", "http://gateway.invalid");
	if (request.method === "GET" && url.pathname === "/iweb-capability") {
		const issued = issueStorageCapability({ secret: dataPlane.storageSecret, applicationId: dataPlane.applicationId, ttlMs: 60_000 });
		if (!issued.ok) { response.writeHead(503, { "content-type": "application/json" }); response.end(plainError(503, "capability-unavailable").body); return; }
		response.writeHead(200, { "content-type": "application/json" });
		response.end(JSON.stringify({ token: issued.value.token, expiresAt: issued.value.expiresAt }) + "\n");
		return;
	}
	const keyMatch = url.pathname.match(/^\/iweb-data\/([^\/].*)$/);
	if (!keyMatch) { response.writeHead(403, { "content-type": "application/json" }); response.end(plainError(403, "data-listing-denied").body); return; }
	const relativeKey = decodeURIComponent(keyMatch[1]);
	if (!isSafeDataKey(relativeKey)) { response.writeHead(400, { "content-type": "application/json" }); response.end(plainError(400, "invalid-data-key").body); return; }
	const method = (request.method ?? "GET").toUpperCase();
	if (method !== "GET" && method !== "PUT" && method !== "DELETE") { response.writeHead(405, { "content-type": "application/json" }); response.end(plainError(405, "method-not-allowed").body); return; }
	const authHeader = String(request.headers.authorization ?? "");
	const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
	const verified = verifyStorageCapability({ secret: dataPlane.storageSecret, token, applicationId: dataPlane.applicationId, replay: dataPlane.nonceStore });
	if (!verified.ok) {
		const status = verified.reason === "expired" || verified.reason === "reused" ? 401 : 403;
		response.writeHead(status, { "content-type": "application/json" });
		response.end(plainError(status, "capability-" + (verified.reason ?? "invalid")).body);
		return;
	}
	const objectKey = applicationDataPrefix(dataPlane.applicationId) + relativeKey;
	const payload = await readBoundedBody(request, MAX_GATEWAY_REQUEST_BYTES);
	if (payload === null) { response.writeHead(413, { "content-type": "application/json" }); response.end(plainError(413, "data-request-too-large").body); return; }
	const upstream = new URL(dataPlane.data.endpoint);
	const path = "/" + objectKey;
	try {
		const signed = await io.signS3({ method, host: upstream.host, path, query: url.searchParams.toString(), payload, config: dataPlane.data });
		const result = await io.fetchText(dataPlane.data.endpoint + path + (url.search === "" ? "" : "?" + url.search), { method, headers: signed, body: method === "PUT" ? payload : null, timeoutMs: 60_000 });
		for (const [name, value] of Object.entries(result.headers)) {
			if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
			response.setHeader(name, value);
		}
		response.writeHead(result.status);
		response.end(result.body);
	} catch {
		response.writeHead(502, { "content-type": "application/json" });
		response.end(plainError(502, "data-backend-unavailable").body);
	}
}

async function handleObjectRequest(config: GatewayConfig, io: GatewayIO, request: IncomingMessage, response: import("node:http").ServerResponse): Promise<void> {
	const url = new URL(request.url ?? "/", "http://gateway.invalid");
	const segments = url.pathname.split("/").filter(Boolean);
	// celld may only READ its own version's deployment objects through this
	// gateway. Listing, writing, and deleting are refused so hostile Worker
	// code cannot enumerate or mutate version objects via the signing proxy.
	if (segments.length < 2) {
		response.writeHead(403, { "content-type": "application/json" });
		response.end(plainError(403, "object-listing-denied").body);
		return;
	}
	if (segments[0] !== config.bucket) {
		response.writeHead(403, { "content-type": "application/json" });
		response.end(plainError(403, "bucket-not-authorised").body);
		return;
	}
	const method = (request.method ?? "GET").toUpperCase();
	// The runtime celld writes its own lease/peer state and Durable Object
	// segments under nodes/, fleet/, cells/; the deployment objects (deploy/)
	// stay read-only to the runtime at the HTTP layer as well as in the MinIO
	// policy (both verified on a real node). Everything else is GET/HEAD only.
	const objectKey = segments.slice(1).join("/");
	const runtimeWritable = objectKey.startsWith("nodes/") || objectKey.startsWith("fleet/") || objectKey.startsWith("cells/");
	if (method !== "GET" && method !== "HEAD" && !(method === "PUT" && runtimeWritable)) {
		response.writeHead(405, { "content-type": "application/json" });
		response.end(plainError(405, "method-not-allowed").body);
		return;
	}
	// GET/HEAD carry no forwarded body: the signed payload hash is of the empty
	// body and no client body is ever buffered, so the read is bound by
	// construction rather than by allocation. A signing or backend failure is a
	// fixed bounded JSON error; no signing or exception detail is logged.
	const payload = method === "PUT" ? await readBoundedBody(request, MAX_GATEWAY_REQUEST_BYTES) : Buffer.alloc(0);
	if (payload === null) { response.writeHead(413, { "content-type": "application/json" }); response.end(plainError(413, "object-request-too-large").body); return; }
	const upstream = new URL(config.object.endpoint);
	const upstreamHost = upstream.host;
	try {
		const signed = await io.signS3({ method, host: upstreamHost, path: url.pathname, query: url.searchParams.toString(), payload, config: config.object });
		const result = await io.fetchText(config.object.endpoint + url.pathname + (url.search === "" ? "" : "?" + url.search), { method, headers: signed, body: method === "PUT" ? payload : null, timeoutMs: 60_000 });
		for (const [name, value] of Object.entries(result.headers)) {
			if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
			response.setHeader(name, value);
		}
		response.writeHead(result.status);
		response.end(method === "HEAD" ? undefined : result.body);
	} catch {
		response.writeHead(502, { "content-type": "application/json" });
		response.end(plainError(502, "object-unavailable").body);
	}
}

async function handleEgressRequest(io: GatewayIO, policy: CompiledEgressPolicy, request: IncomingMessage, response: import("node:http").ServerResponse): Promise<void> {
	// CONNECT never reaches this handler: Node routes it to the server's
	// 'connect' event, which startGateway wires to handleConnectEvent.
	const method = (request.method ?? "GET").toUpperCase();
	const target = request.url ?? "";
	let parsed: URL;
	try {
		parsed = new URL(target);
	} catch {
		response.writeHead(400, { "content-type": "application/json" });
		response.end(plainError(400, "absolute-form-required").body);
		return;
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		response.writeHead(400, { "content-type": "application/json" });
		response.end(plainError(400, "unsupported-scheme").body);
		return;
	}
	const verdict = await checkEgressTarget({ host: parsed.hostname, port: parsed.port === "" ? (parsed.protocol === "https:" ? 443 : 80) : Number(parsed.port), policy, resolveDns: io.resolveDns });
	if (!verdict.allowed) {
		response.writeHead(403, { "content-type": "application/json" });
		response.end(plainError(403, "egress-" + verdict.reason).body);
		return;
	}
	await proxyForward(io, policy, method, parsed, request.headers, request, response, 0, verdict.address);
}

async function proxyForward(io: GatewayIO, policy: CompiledEgressPolicy, method: string, target: URL, incomingHeaders: Record<string, string | string[] | undefined>, request: IncomingMessage, response: import("node:http").ServerResponse, redirectCount: number, pinnedAddress?: string): Promise<void> {
	if (redirectCount > MAX_EGRESS_REDIRECTS) {
		response.writeHead(502, { "content-type": "application/json" });
		response.end(plainError(502, "too-many-redirects").body);
		return;
	}
	const verdict = await checkEgressTarget({ host: target.hostname, port: target.port === "" ? (target.protocol === "https:" ? 443 : 80) : Number(target.port), policy, resolveDns: io.resolveDns });
	if (!verdict.allowed) {
		response.writeHead(403, { "content-type": "application/json" });
		response.end(plainError(403, "egress-redirect-" + verdict.reason).body);
		return;
	}
	const body = await readBoundedBody(request, MAX_GATEWAY_REQUEST_BYTES);
	if (body === null) { response.writeHead(413, { "content-type": "application/json" }); response.end(plainError(413, "egress-request-too-large").body); return; }
	const headers = forwardableHeaders(incomingHeaders);
	headers.host = target.host;
	try {
		const result = await io.fetchText(target.toString(), { method, headers, body: body.length > 0 ? body : null, timeoutMs: EGRESS_REQUEST_TIMEOUT_MS, maxBytes: MAX_EGRESS_RESPONSE_BYTES, ...(pinnedAddress !== undefined ? { address: pinnedAddress } : {}) });
		if (result.body.byteLength > MAX_EGRESS_RESPONSE_BYTES) {
			response.writeHead(502, { "content-type": "application/json" });
			response.end(plainError(502, "response-too-large").body);
			return;
		}
		if ([301, 302, 303, 307, 308].includes(result.status)) {
			const location = result.headers["location"] ?? "";
			const next = classifyRedirectTarget(location);
			if (next === null) {
				response.writeHead(502, { "content-type": "application/json" });
				response.end(plainError(502, "invalid-redirect").body);
				return;
			}
			// Every redirect hop is re-validated against the compiled policy.
			const hop = await checkEgressTarget({ host: next.host, port: next.port, policy, resolveDns: io.resolveDns });
			if (!hop.allowed) {
				response.writeHead(403, { "content-type": "application/json" });
				response.end(plainError(403, "egress-redirect-" + hop.reason).body);
				return;
			}
			response.writeHead(result.status, { location: result.headers["location"] ?? "" });
			response.end();
			return;
		}
		response.writeHead(result.status, forwardableHeaders(result.headers as Record<string, string>));
		response.end(result.body);
	} catch {
		response.writeHead(502, { "content-type": "application/json" });
		response.end(plainError(502, "egress-target-unavailable").body);
	}
}

// CONNECT arrives as the server's 'connect' event, never as a normal request:
// Node emits 'connect' for the CONNECT method, so the egress request handler
// can never see it. This handler receives (request, socket, head) and answers
// on the raw socket.
async function handleConnectEvent(io: GatewayIO, policy: CompiledEgressPolicy, request: IncomingMessage, socket: import("node:net").Socket, head: Buffer): Promise<void> {
	const deny = (status: number, code: string): void => {
		socket.end("HTTP/1.1 " + status + " " + code + "\r\ncontent-type: application/json\r\ncontent-length: " + plainError(status, code).body.length + "\r\nconnection: close\r\n\r\n" + plainError(status, code).body);
	};
	const authority = request.url ?? "";
	const separator = authority.lastIndexOf(":");
	const host = separator > 0 ? authority.slice(0, separator).replace(/^\[|\]$/g, "") : authority;
	const port = separator > 0 ? Number(authority.slice(separator + 1)) : 443;
	const verdict = await checkEgressTarget({ host, port, policy, resolveDns: io.resolveDns });
	if (!verdict.allowed) {
		deny(403, "egress-" + verdict.reason);
		return;
	}
	try {
		// 2.45: dial the ALREADY-VALIDATED IP, never the hostname again — a
		// rebinding DNS answer between validation and connect cannot redirect
		// the tunnel. The TLS handshake (SNI) flows inside the tunnel untouched.
		const tunnel = await io.openTunnel(host, port, TUNNEL_TIMEOUT_MS, verdict.address);
		socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
		let forwarded = head.byteLength;
		if (head.byteLength > 0) tunnel.write(head);
		let aborted = false;
		const stop = (): void => {
			if (aborted) return;
			aborted = true;
			tunnel.destroy();
			socket.destroy();
		};
		socket.on("data", (chunk: Buffer) => {
			forwarded += chunk.byteLength;
			if (forwarded > MAX_TUNNEL_BYTES) { stop(); return; }
			tunnel.write(chunk);
		});
		tunnel.on("data", (chunk: Buffer) => {
			if (!socket.writableEnded) socket.write(chunk);
		});
		socket.on("end", () => tunnel.end());
		tunnel.on("end", () => socket.end());
		tunnel.on("error", stop);
		socket.on("error", stop);
		socket.on("close", () => tunnel.destroy());
	} catch {
		deny(502, "egress-tunnel-unavailable");
	}
}

// The ingress socket serves one request per connection and parses it from
// the data stream: HTTP clients do not half-close before reading the
// response, so waiting for a FIN would never dispatch.
function handleIngressConnection(config: GatewayConfig, io: GatewayIO, socket: Socket): void {
	const MAX_INGRESS_REQUEST_BYTES = 1024 * 1024;
	const INGRESS_IDLE_TIMEOUT_MS = 15_000;
	let buffer = Buffer.alloc(0);
	const tryParse = (): void => {
		const headerEnd = buffer.indexOf("\r\n\r\n");
		if (headerEnd < 0) return;
		const headText = buffer.subarray(0, headerEnd).toString("utf8");
		const lengthMatch = /content-length:\s*(\d+)/i.exec(headText);
		const contentLength = lengthMatch ? Number.parseInt(lengthMatch[1], 10) : 0;
		if (!Number.isSafeInteger(contentLength) || contentLength < 0) {
			socket.end("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
			return;
		}
		if (buffer.length < headerEnd + 4 + contentLength) return;
		const raw = buffer.subarray(0, headerEnd + 4 + contentLength);
		buffer = buffer.subarray(headerEnd + 4 + contentLength);
		void processIngressRequest(config, io, raw, socket);
	};
	socket.on("data", (chunk: Buffer) => {
		buffer = Buffer.concat([buffer, chunk]);
		if (buffer.length > MAX_INGRESS_REQUEST_BYTES) {
			socket.end("HTTP/1.1 413 Payload Too Large\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n" + plainError(413, "ingress-request-too-large").body);
			return;
		}
		tryParse();
	});
	socket.setTimeout(INGRESS_IDLE_TIMEOUT_MS, () => socket.destroy());
}

async function processIngressRequest(config: GatewayConfig, io: GatewayIO, raw: Buffer, socket: Socket): Promise<void> {
	const headerEnd = raw.indexOf("\r\n\r\n");
	if (headerEnd < 0) {
		socket.end("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
		return;
	}
	const headText = raw.subarray(0, headerEnd).toString("utf8");
	const firstLine = headText.split("\r\n")[0] ?? "";
	const [method, targetPath] = firstLine.split(" ");
	if (method === undefined || targetPath === undefined) {
		socket.end("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
		return;
	}
	const url = new URL(targetPath, "http://ingress.invalid");
	if (method === "GET" && url.pathname === READINESS_PATH) {
		await answerHealth(config, io, url, socket);
		return;
	}
	await forwardIngress(config, io, method, url, raw, socket);
}

async function answerHealth(config: GatewayConfig, io: GatewayIO, url: URL, socket: Socket): Promise<void> {
	const queryVersionId = url.searchParams.get("versionId");
	const queryGeneration = url.searchParams.get("generation");
	if (queryVersionId !== null && queryVersionId !== config.versionId) {
		socket.end("HTTP/1.1 409 Conflict\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n" + plainError(409, "version-mismatch").body);
		return;
	}
	if (queryGeneration !== null && queryGeneration !== String(config.generation)) {
		socket.end("HTTP/1.1 409 Conflict\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n" + plainError(409, "generation-mismatch").body);
		return;
	}
	const separator = config.ingressTarget.lastIndexOf(":");
	const host = config.ingressTarget.slice(0, separator);
	const port = Number(config.ingressTarget.slice(separator + 1));
	const reachable = await io.dialTcp(host, port, HEALTH_DIAL_TIMEOUT_MS);
	if (!reachable) {
		socket.end("HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n" + plainError(503, "not-ready").body);
		return;
	}
	const payload = JSON.stringify({ version: 1, ok: true, versionId: config.versionId, generation: config.generation }) + "\n";
	socket.end("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: " + payload.length + "\r\nconnection: close\r\n\r\n" + payload);
}

async function forwardIngress(config: GatewayConfig, io: GatewayIO, method: string, url: URL, raw: Buffer, socket: Socket): Promise<void> {
	const headerEnd = raw.indexOf("\r\n\r\n");
	const headText = raw.slice(0, headerEnd).toString("utf8");
	const headLines = headText.split("\r\n");
	const headers: Record<string, string> = {};
	for (const line of headLines.slice(1)) {
		const separator = line.indexOf(":");
		if (separator > 0) headers[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim();
	}
	delete headers["connection"];
	delete headers["keep-alive"];
	headers["host"] = config.ingressTarget;
	headers["x-iweb-sandbox"] = config.sandboxId;
	const separator = config.ingressTarget.lastIndexOf(":");
	const host = config.ingressTarget.slice(0, separator);
	const port = Number(config.ingressTarget.slice(separator + 1));
	const upstreamRequest = httpRequest({ host, port, method: method.toUpperCase(), path: url.pathname + url.search, headers }, (upstream) => {
		socket.write("HTTP/1.1 " + upstream.statusCode + " " + (upstream.statusMessage ?? "") + "\r\n");
		for (const [name, value] of Object.entries(upstream.headers)) {
			if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
			if (value !== undefined) socket.write(name + ": " + value + "\r\n");
		}
		socket.write("\r\n");
		upstream.on("data", (chunk: Buffer) => socket.write(chunk));
		upstream.on("end", () => socket.end());
	});
	upstreamRequest.on("error", () => {
		socket.end("HTTP/1.1 502 Bad Gateway\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n" + plainError(502, "application-unavailable").body);
	});
	const body = raw.subarray(headerEnd + 4);
	if (body.length > 0) upstreamRequest.write(body);
	upstreamRequest.end();
}

// --- system IO (used by the gateway container process) ---

export const systemGatewayIO: GatewayIO = {
	fetchText: (url, options) =>
		new Promise((resolve, reject) => {
			const requester = url.startsWith("https:") ? httpsRequest : httpRequest;
			// DNS pinning: when the caller verified a destination IP, the connection
			// resolves to exactly that address (custom lookup) while the Host header
			// and TLS SNI keep the original hostname. A rebinding DNS answer between
			// validation and connection can never redirect the socket.
			const requestOptions: import("node:http").RequestOptions = { method: options.method, headers: options.headers, timeout: options.timeoutMs };
			if (options.address !== undefined) {
				requestOptions.lookup = ((_hostname: string, _options: unknown, callback: (err: Error | null, address: string) => void) => {
					callback(null, options.address as string);
				}) as unknown as import("node:net").LookupFunction;
			}
			const upstream = requester(url, requestOptions, (incoming) => {
				const chunks: Buffer[] = [];
				let received = 0;
				let over = false;
				incoming.on("data", (chunk: Buffer) => {
					if (over) return;
					received += chunk.byteLength;
					// Enforce the ceiling DURING download: destroy the socket instead of
					// buffering an unbounded body and checking the size afterwards.
					if (options.maxBytes !== undefined && received > options.maxBytes) {
						over = true;
						incoming.destroy();
						reject(new Error("response-too-large"));
						return;
					}
					chunks.push(chunk);
				});
				incoming.on("end", () => resolve({ status: incoming.statusCode ?? 0, headers: incoming.headers as Record<string, string>, body: Buffer.concat(chunks) }));
				incoming.on("error", (error) => { if (!over) reject(error); });
			});
			upstream.on("error", reject);
			upstream.on("timeout", () => {
				upstream.destroy();
				reject(new Error("timeout"));
			});
			if (options.body !== null) upstream.write(options.body);
			upstream.end();
		}),
	resolveDns: async (host) => {
		const result = await dnsLookup(host, { all: true });
		return result.map((entry) => entry.address);
	},
	openTunnel: (host, port, timeoutMs, address) =>
		new Promise((resolve, reject) => {
			// dial the verified IP when the caller pinned one; the hostname is kept
			// only for diagnostics and never re-resolved here
			const socket = connect({ host: address ?? host, port });
			socket.setTimeout(timeoutMs, () => {
				socket.destroy();
				reject(new Error("tunnel timeout"));
			});
			socket.once("connect", () => resolve(socket));
			socket.once("error", reject);
		}),
	dialTcp: (host, port, timeoutMs) =>
		new Promise((resolve) => {
			const socket = connect({ host, port });
			socket.setTimeout(timeoutMs, () => {
				socket.destroy();
				resolve(false);
			});
			socket.once("connect", () => {
				socket.destroy();
				resolve(true);
			});
			socket.once("error", () => resolve(false));
		}),
	signS3: async (options) => signS3Request(options),
};
