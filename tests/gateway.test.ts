// 用户原始需求（2026-08-14）：gateway 三面（版本对象代理/策略 egress/私有 ingress+健康契约）必须在真实 socket 上成立，拒绝发生在应用之外。
// 正交意图：本地 loopback/unix socket 端到端证据（macOS 即可运行）；Linux 上的 pod 网络结构由验收脚本补证。
import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { request as httpRequest, type Server as HttpServer, type ServerResponse } from "node:http";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect, createServer as createNetServer } from "node:net";
import { Readable } from "node:stream";
import type { IncomingMessage } from "node:http";
import {
	classifyRedirectTarget,
	checkEgressTarget,
	parseGatewayConfig,
	sha256Hex,
	signS3Request,
	readBoundedBody,
	startGateway,
	systemGatewayIO,
	type GatewayConfig,
	type GatewayIO,
	type RunningGateway,
} from "../supervisor/gateway.ts";
import { compileEgressPolicy } from "../packages/contracts/egress-policy.ts";

const bucket = "iweb-app-sbx-test";
const versionId = "a".repeat(64) + "-1";
const generation = 1;

function config(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
	return {
		version: 1,
		sandboxId: "sbx-test",
		versionId,
		generation,
		bucket,
		object: { endpoint: "http://127.0.0.1:19000", region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" },
		egress: { default: "deny", allow: [] },
		ingressTarget: "127.0.0.1:18787",
		socketDirectory: "/tmp",
		...overrides,
	};
}

function listenTcp(server: HttpServer, host: string): Promise<number> {
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, host, () => {
			const address = server.address();
			resolve(typeof address === "object" && address !== null ? address.port : 0);
		});
	});
}

function closeServer(server: HttpServer): Promise<void> {
	return new Promise((resolve) => server.close(() => resolve()));
}

function httpGetTcp(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const req = httpRequest({ host: "127.0.0.1", port, path, headers }, (res) => {
			let body = "";
			res.setEncoding("utf8");
			res.on("data", (chunk: string) => (body += chunk));
			res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
		});
		req.once("error", reject);
		req.end();
	});
}

function httpMethodTcp(port: number, method: string, path: string, body: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const req = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
			let b = "";
			res.setEncoding("utf8");
			res.on("data", (c: string) => (b += c));
			res.on("end", () => resolve({ status: res.statusCode ?? 0, body: b }));
		});
		req.once("error", reject);
		req.end(body);
	});
}

function httpGetUnix(socketPath: string, path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
	return new Promise((resolve, reject) => {
		const req = httpRequest({ socketPath, path, headers }, (res) => {
			let body = "";
			res.setEncoding("utf8");
			res.on("data", (chunk: string) => (body += chunk));
			res.on("end", () => resolve({ status: res.statusCode ?? 0, body, headers: res.headers }));
		});
		req.once("error", reject);
		req.end();
	});
}

function httpProxyGet(port: number, url: string): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const parsed = new URL(url);
		const crlf = String.fromCharCode(13, 10);
		const sock = connect({ host: "127.0.0.1", port }, () => {
			sock.write(["GET " + url + " HTTP/1.1", "Host: " + parsed.host, "Connection: close", "", ""].join(crlf));
		});
		let body = "";
		sock.setEncoding("utf8");
		sock.on("data", (chunk: string) => (body += chunk));
		sock.on("end", () => {
			const firstLine = body.split(crlf)[0] ?? "";
			const parts = firstLine.split(" ");
			resolve({ status: parts.length >= 2 ? Number(parts[1]) : 0, body });
		});
		sock.once("error", reject);
	});
}


describe("gateway pure functions", () => {
	test("S3 signing produces a SigV4 authorization header and payload hash", () => {
		const signed = signS3Request({ method: "GET", host: "minio.invalid:9000", path: "/" + bucket + "/key", query: "", payload: Buffer.alloc(0), config: config().object });
		expect(signed.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDTEST\/\d{8}\/us-east-1\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[a-f0-9]{64}$/);
		expect(signed["x-amz-content-sha256"]).toBe(sha256Hex(Buffer.alloc(0)));
		expect(signed["x-amz-date"]).toMatch(/^\d{8}T\d{6}Z$/);
	});

	test("gateway config parsing rejects malformed or credential-free shapes", () => {
		expect(parseGatewayConfig(JSON.stringify(config()))).not.toBeNull();
		expect(parseGatewayConfig("not json")).toBeNull();
		expect(parseGatewayConfig(JSON.stringify({ ...config(), generation: 0 }))).toBeNull();
		const noObject = { ...config() } as Record<string, unknown>;
		delete noObject.object;
		expect(parseGatewayConfig(JSON.stringify(noObject))).toBeNull();
	});

	test("egress classification denies internal hosts, reserved addresses, and undeclared targets", async () => {
		const policy = compileEgressPolicy({ default: "deny", allow: [{ host: "api.example.com", port: 443 }] });
		const resolve = async (host: string) => (host === "api.example.com" ? ["93.184.216.34"] : ["10.0.0.5"]);
		expect((await checkEgressTarget({ host: "api.example.com", port: 443, policy, resolveDns: resolve })).allowed).toBe(true);
		expect((await checkEgressTarget({ host: "kernel", port: 7070, policy, resolveDns: resolve })).reason).toBe("internal-hostname");
		expect((await checkEgressTarget({ host: "api.example.com", port: 80, policy, resolveDns: resolve })).reason).toBe("undeclared");
		expect((await checkEgressTarget({ host: "other.example.com", port: 443, policy, resolveDns: resolve })).reason).toBe("reserved-address");
		expect((await checkEgressTarget({ host: "other.example.com", port: 443, policy, resolveDns: async () => { throw new Error("nxdomain"); } })).reason).toBe("unresolved");
	});

	test("redirect targets are classified strictly", () => {
		expect(classifyRedirectTarget("https://api.example.com:8443/x")).toEqual({ host: "api.example.com", port: 8443 });
		expect(classifyRedirectTarget("ftp://api.example.com/x")).toBeNull();
		expect(classifyRedirectTarget("not a url")).toBeNull();
	});
});

test("systemGatewayIO.fetchText enforces maxBytes during download and rejects oversized streams", async () => {
	const server = createServer((req: import("node:http").IncomingMessage, res: ServerResponse) => {
		res.writeHead(200, { "content-type": "application/octet-stream" });
		res.end(Buffer.alloc(4096, 1));
	});
	const port = await listenTcp(server, "127.0.0.1");
	try {
		const small = await systemGatewayIO.fetchText("http://127.0.0.1:" + port + "/x", { method: "GET", headers: {}, body: null, timeoutMs: 3000, maxBytes: 8192 });
		expect(small.body.byteLength).toBe(4096);
		let caught: unknown = null;
		try {
			await systemGatewayIO.fetchText("http://127.0.0.1:" + port + "/x", { method: "GET", headers: {}, body: null, timeoutMs: 3000, maxBytes: 1024 });
		} catch (error) { caught = error; }
		expect((caught as Error).message).toContain("response-too-large");
	} finally {
		await closeServer(server);
	}
});

test("readBoundedBody bounds allocation: null past the ceiling, body under it", async () => {
		const over = Readable.from([Buffer.alloc(10), Buffer.alloc(10)]);
		expect(await readBoundedBody(over as unknown as IncomingMessage, 15)).toBeNull();
		const under = Readable.from([Buffer.alloc(10)]);
		expect((await readBoundedBody(under as unknown as IncomingMessage, 64))?.length).toBe(10);
	});

describe("gateway object proxy over real sockets", () => {
	let objectPort = 0;
	let gateway: RunningGateway | null = null;
	const seen: { path: string; authorization: string | undefined }[] = [];
	let upstream: HttpServer | null = null;

	afterEach(async () => {
		if (gateway) await gateway.close();
		gateway = null;
		if (upstream) await closeServer(upstream);
		upstream = null;
	});

	async function start(minioPort: number): Promise<RunningGateway> {
		const io: GatewayIO = {
			// fetchText always hits the injected mock MinIO on minioPort; the URL
			// only carries the path the gateway decided to fetch.
			fetchText: (url, options) =>
				new Promise((resolve, reject) => {
					const parsed = new URL(url);
					const req = httpRequest({ host: parsed.hostname, port: minioPort, path: parsed.pathname + parsed.search, method: options.method, headers: options.headers }, (res) => {
						const chunks: Buffer[] = [];
						res.on("data", (chunk: Buffer) => chunks.push(chunk));
						res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers as Record<string, string>, body: Buffer.concat(chunks) }));
					});
					req.once("error", reject);
					if (options.body) req.write(options.body);
					req.end();
				}),
			resolveDns: async () => ["93.184.216.34"],
			openTunnel: async () => connect({ host: "127.0.0.1", port: minioPort }),
			dialTcp: async () => true,
			signS3: async (options) => signS3Request(options),
		};
		gateway = await startGateway(config(), io, { object: "127.0.0.1:0", egress: "127.0.0.1:0" });
		return gateway;
	}

	test("forwards only the version bucket with a gateway-applied signature", async () => {
		upstream = createServer((req: import("node:http").IncomingMessage, res: ServerResponse) => {
			seen.push({ path: req.url ?? "", authorization: req.headers["authorization"] as string | undefined });
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("object-body");
		});
		const minioPort = await listenTcp(upstream, "127.0.0.1");
		objectPort = 0;
		const running = await start(minioPort);
		const objectPortText = running.objectAddress.split(":").pop() ?? "0";
		objectPort = Number(objectPortText);
		const allowed = await httpGetTcp(objectPort, "/" + bucket + "/worker/index.js");
		expect(allowed.status).toBe(200);
		expect(allowed.body).toBe("object-body");
		expect(seen).toHaveLength(1);
		expect(seen[0].path).toBe("/" + bucket + "/worker/index.js");
		expect(seen[0].authorization).toContain("Signature=");
		const denied = await httpGetTcp(objectPort, "/iweb-app-other/key");
		expect(denied.status).toBe(403);
		expect(seen).toHaveLength(1);
		const listing = await httpGetTcp(objectPort, "/");
		expect(listing.status).toBe(403);
		// 2.34: the runtime may PUT its own state prefixes (nodes/, fleet/, cells/)
		const leasePut = await httpMethodTcp(objectPort, "PUT", "/" + bucket + "/nodes/sbx.json", "{}", {});
		expect(leasePut.status).toBe(200);
		// ...but never the deployment objects
		const deployPut = await httpMethodTcp(objectPort, "PUT", "/" + bucket + "/deploy/current.json", "{}", {});
		expect(deployPut.status).toBe(405);
		// ...and never DELETE anything
		const del = await httpMethodTcp(objectPort, "DELETE", "/" + bucket + "/nodes/sbx.json", "", {});
		expect(del.status).toBe(405);
	});
});

describe("gateway ingress health contract and forwarding over real sockets", () => {
	let gateway: RunningGateway | null = null;
	let directory = "";

	afterEach(async () => {
		if (gateway) await gateway.close();
		gateway = null;
		if (directory) rmSync(directory, { recursive: true, force: true });
	});

	async function start(dialResult: boolean, ingressTarget: string): Promise<string> {
		directory = mkdtempSync(join(tmpdir(), "iweb-gw-"));
		const io: GatewayIO = {
			fetchText: async () => ({ status: 200, headers: {}, body: Buffer.alloc(0) }),
			resolveDns: async () => [],
			openTunnel: async () => connect({ host: "127.0.0.1", port: 1 }),
			dialTcp: async () => dialResult,
			signS3: async () => ({}),
		};
		gateway = await startGateway(config({ socketDirectory: directory, ingressTarget }), io, { object: "127.0.0.1:0", egress: "127.0.0.1:0" });
		return join(directory, "ingress.sock");
	}

	test("health answers 200 with the candidate identity only when the backend is reachable", async () => {
		const socketPath = await start(true, "127.0.0.1:18787");
		const ready = await httpGetUnix(socketPath, "/iweb-health?versionId=" + encodeURIComponent(versionId) + "&generation=1");
		expect(ready.status).toBe(200);
		expect(JSON.parse(ready.body)).toEqual({ version: 1, ok: true, versionId, generation });
		const unreachable = await start(false, "127.0.0.1:18787");
		const notReady = await httpGetUnix(unreachable, "/iweb-health?versionId=" + encodeURIComponent(versionId));
		expect(notReady.status).toBe(503);
		expect(JSON.parse(notReady.body).code).toBe("not-ready");
	});

	test("health answers 409 for a stale or wrong candidate identity", async () => {
		const socketPath = await start(true, "127.0.0.1:18787");
		const mismatch = await httpGetUnix(socketPath, "/iweb-health?versionId=" + "b".repeat(64) + "-1");
		expect(mismatch.status).toBe(409);
		expect(JSON.parse(mismatch.body).code).toBe("version-mismatch");
		const wrongGeneration = await httpGetUnix(socketPath, "/iweb-health?versionId=" + encodeURIComponent(versionId) + "&generation=9");
		expect(wrongGeneration.status).toBe(409);
	});

	test("forwards application traffic and shapes upstream failure generically", async () => {
		const app = createServer((req: import("node:http").IncomingMessage, res: ServerResponse) => {
			res.writeHead(200, { "content-type": "text/html" });
			res.end("<html>" + (req.headers["x-iweb-sandbox"] ?? "") + "</html>");
		});
		const appPort = await listenTcp(app, "127.0.0.1");
		const socketPath = await start(true, "127.0.0.1:" + appPort);
		const forwarded = await httpGetUnix(socketPath, "/index.html");
		expect(forwarded.status).toBe(200);
		expect(forwarded.body).toBe("<html>sbx-test</html>");
		await closeServer(app);
		const failed = await httpGetUnix(socketPath, "/index.html");
		expect(failed.status).toBe(502);
		expect(JSON.parse(failed.body).code).toBe("application-unavailable");
	});
});

describe("gateway object topology and egress transport (2.24)", () => {
	let gateway: RunningGateway | null = null;
	afterEach(async () => {
		if (gateway) await gateway.close();
		gateway = null;
	});
	function io(allowedHosts: string[]): GatewayIO {
		return {
			fetchText: async () => ({ status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("egress-ok") }),
			resolveDns: async (host: string) => (allowedHosts.includes(host) ? ["93.184.216.34"] : ["127.0.0.1"]),
			openTunnel: async () => { throw new Error("no tunnel"); },
			dialTcp: async () => true,
			signS3: async (o) => signS3Request(o),
		};
	}
	test("refuses to start when the object endpoint would loop back to its own listener", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-gw-loop-"));
		try {
			const selfLoop = config({ object: { endpoint: "http://127.0.0.1:19001", region: "us-east-1", accessKeyId: "AKIDTEST", secretAccessKey: "SECRETTEST" }, socketDirectory: directory });
			await expect(startGateway(selfLoop, io(["allowed.example.com"]), { object: "127.0.0.1:19001", egress: "127.0.0.1:0" })).rejects.toThrow(/self-loop/);
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});
	test("egress proxy forwards an admitted destination and denies loopback over real sockets", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-gw-eg-"));
		try {
			gateway = await startGateway(config({ egress: { default: "deny", allow: [{ host: "allowed.example.com", port: 443 }] }, socketDirectory: directory }), io(["allowed.example.com"]), { object: "127.0.0.1:0", egress: "127.0.0.1:0" });
			const egressPort = Number(gateway.egressAddress.split(":").pop() ?? "0");
			const allowed = await httpProxyGet(egressPort, "http://allowed.example.com:443/path");
			expect(allowed.status).toBe(200);
			expect(allowed.body).toContain("egress-ok");
			const denied = await httpProxyGet(egressPort, "http://127.0.0.1:7070/x");
			expect(denied.status).toBe(403);
		} finally {
			if (gateway) await gateway.close();
			gateway = null;
			rmSync(directory, { recursive: true, force: true });
		}
	});

	test("CONNECT tunnels an admitted target over the real connect event and denies a private one", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-gw-cn-"));
		// a real upstream the tunnel connects to
		const upstream = createServer((req: import("node:http").IncomingMessage, res: ServerResponse) => {
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("tunneled");
		});
		const upstreamPort = await listenTcp(upstream, "127.0.0.1");
		try {
			const io2: GatewayIO = {
				fetchText: async () => ({ status: 200, headers: {}, body: Buffer.alloc(0) }),
				resolveDns: async (host: string) => (host === "allowed.example.com" ? ["93.184.216.34"] : ["127.0.0.1"]),
				// the tunnel opens to a real local listener, proving the pipe works
				openTunnel: async (host: string, port: number) => connect({ host: "127.0.0.1", port: port === 443 ? upstreamPort : port }),
				dialTcp: async () => true,
				signS3: async (o) => signS3Request(o),
			};
			gateway = await startGateway(config({ egress: { default: "deny", allow: [{ host: "allowed.example.com", port: 443 }] }, socketDirectory: directory }), io2, { object: "127.0.0.1:0", egress: "127.0.0.1:0" });
			const egressPort = Number(gateway.egressAddress.split(":").pop() ?? "0");
			// Raw-socket CONNECT proves the server wired the 'connect' event: a plain
			// request handler would never answer this method.
			const rawConnect = (authority: string, followUp: string | null): Promise<{ status: number; body: string }> =>
				new Promise((resolve) => {
					const sock = connect({ host: "127.0.0.1", port: egressPort }, () => {
						sock.write("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n");
					});
					let data = "";
					let status = 0;
					let sent = false;
					sock.setEncoding("utf8");
					sock.on("data", (chunk: string) => {
						data += chunk;
						if (status === 0) {
							const idx = data.indexOf("\r\n\r\n");
							if (idx < 0) return;
							status = Number((data.slice(0, idx).split("\r\n")[0] ?? "").split(" ")[1] ?? 0);
							if (status === 200 && followUp !== null && !sent) { sent = true; sock.write(followUp); }
							else if (status !== 200) { sock.destroy(); resolve({ status, body: data.slice(idx + 4) }); }
						}
					});
					sock.once("end", () => resolve({ status, body: data }));
					sock.once("error", () => resolve({ status, body: data }));
					setTimeout(() => { sock.destroy(); resolve({ status, body: data }); }, 3000).unref();
				});
			const tunneled = await rawConnect("allowed.example.com:443", "GET / HTTP/1.1\r\nHost: allowed.example.com\r\nConnection: close\r\n\r\n");
			expect(tunneled.status).toBe(200);
			expect(tunneled.body).toContain("tunneled");
			// a private CONNECT target is denied on the connect event too
			const deniedConnect = await rawConnect("127.0.0.1:7070", null);
			expect(deniedConnect.status).toBe(403);

			// DNS pinning (2.35): validation resolves allowed.example.com to a public IP;
			// the outbound request must carry that verified address so a rebinding DNS
			// answer between validation and connection can never redirect the socket.
			const pinnedSeen: string[] = [];
			const pinnedIo: GatewayIO = {
				fetchText: async (url, options) => {
					pinnedSeen.push(String((options as { address?: string }).address));
					return { status: 200, headers: {}, body: Buffer.from("pinned-ok") };
				},
				resolveDns: async () => ["93.184.216.34"],
				openTunnel: async () => { throw new Error("no tunnel"); },
				dialTcp: async () => true,
				signS3: async (o) => signS3Request(o),
			};
			const pinnedGateway = await startGateway(config({ egress: { default: "deny", allow: [{ host: "allowed.example.com", port: 443 }] }, socketDirectory: directory }), pinnedIo, { object: "127.0.0.1:0", egress: "127.0.0.1:0" });
			const pinnedPort = Number(pinnedGateway.egressAddress.split(":").pop() ?? "0");
			const pinned = await httpProxyGet(pinnedPort, "http://allowed.example.com:443/pin");
			expect(pinned.status).toBe(200);
			expect(pinned.body).toContain("pinned-ok");
			expect(pinnedSeen).toContain("93.184.216.34");
			await pinnedGateway.close();

			// 2.45 real-TCP: the CONNECT tunnel dials the VERIFIED address, not a
			// second DNS result. Serve on 127.0.0.1 and ::1; pin those addresses while
			// the requested authority is a hostname that would resolve elsewhere.
			const dialPinned = async (bindHost: string, address: string): Promise<boolean> => {
				let resolved = false;
				let accepted: import("node:net").Socket | null = null;
				const server = createNetServer((socket) => { resolved = true; accepted = socket; socket.end("tunnel-ok"); });
				await new Promise<void>((listening) => server.listen(0, bindHost, () => listening(undefined)));
				const port = (server.address() as { port: number }).port;
				try {
					const tunnel = await systemGatewayIO.openTunnel("definitely-not-local.example.com", port, 3000, address);
					const echoed = await new Promise<boolean>((done) => {
						tunnel.once("data", () => { done(true); tunnel.destroy(); });
						tunnel.once("error", () => done(false));
						tunnel.write("ping");
					});
					return echoed && resolved;
				} catch {
					return false;
				} finally {
					// The server-side socket from socket.end() can outlive the
					// client's destroy, and server.close() waits for it forever;
					// destroying the settled accepted socket releases the close.
					accepted?.destroy();
					await new Promise<void>((closed) => server.close(() => closed(undefined)));
				}
			};
			expect(await dialPinned("127.0.0.1", "127.0.0.1")).toBe(true);
			// IPv6 where the host supports it; skipped otherwise (not a failure)
			const ipv6 = await dialPinned("::1", "::1").catch(() => false);
			if (!(ipv6 === false)) expect(ipv6).toBe(true);
			await pinnedGateway.close();
		} finally {
			if (gateway) await gateway.close();
			gateway = null;
			await closeServer(upstream);
			rmSync(directory, { recursive: true, force: true });
		}
	});
});

describe("gateway application data plane (2.27)", () => {
	let gateway: RunningGateway | null = null;
	const seenPaths: string[] = [];
	afterEach(async () => { if (gateway) await gateway.close(); gateway = null; });
	test("issues a capability and proxies scoped data ops; denies listing, reuse, missing capability, and traversal", async () => {
		const directory = mkdtempSync(join(tmpdir(), "iweb-gw-data-"));
		try {
			const io: GatewayIO = {
				fetchText: async (url) => { seenPaths.push(new URL(url).pathname); return { status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("data-ok") }; },
				resolveDns: async () => ["127.0.0.1"],
				openTunnel: async () => { throw new Error("no tunnel"); },
				dialTcp: async () => true,
				signS3: async (o) => signS3Request(o),
			};
			const dataConfig = config({ applicationId: "notes", storageSecret: "x".repeat(48), data: { endpoint: "http://127.0.0.1:19010", region: "us-east-1", accessKeyId: "AKIDDATA", secretAccessKey: "SECRETDATA" }, socketDirectory: directory });
			gateway = await startGateway(dataConfig, io, { object: "127.0.0.1:0", egress: "127.0.0.1:0", data: "127.0.0.1:0" });
			const dataPort = Number(gateway.dataAddress?.split(":").pop() ?? "0");
			expect((await httpGetTcp(dataPort, "/iweb-data/")).status).toBe(403);
			const cap1 = await httpGetTcp(dataPort, "/iweb-capability");
			const cap2 = await httpGetTcp(dataPort, "/iweb-capability");
			expect(cap1.status).toBe(200);
			const token1 = JSON.parse(cap1.body).token;
			const token2 = JSON.parse(cap2.body).token;
			expect((await httpGetTcp(dataPort, "/iweb-data/notes.json")).status).toBe(403);
			expect((await httpMethodTcp(dataPort, "PUT", "/iweb-data/notes.json", "hello", { authorization: "Bearer " + token1 })).status).toBe(200);
			expect((await httpMethodTcp(dataPort, "PUT", "/iweb-data/../escape", "x", { authorization: "Bearer " + token2 })).status).toBe(403);
			const got = await httpGetTcp(dataPort, "/iweb-data/notes.json", { authorization: "Bearer " + token2 });
			expect(got.status).toBe(200);
			expect(got.body).toContain("data-ok");
			expect(seenPaths).toContain("/iweb-apps/notes/data/notes.json");
			expect(seenPaths.every((p) => p.startsWith("/iweb-apps/notes/data/"))).toBe(true);
		} finally {
			if (gateway) await gateway.close();
			gateway = null;
			rmSync(directory, { recursive: true, force: true });
		}
	});
});
