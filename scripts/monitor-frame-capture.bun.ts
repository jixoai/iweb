// Capture a REAL ticketed monitor frame from the current Kernel and scan it
// as the 12.3 "monitor-frame" location kind. The owner token is the needle.
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { createHash } from "node:crypto";

const BASE_HOST = "monitorframe.test";
const TOKEN = "monitor-frame-needle-token-123456";
const PORT = 7070;

const directory = mkdtempSync(join(tmpdir(), "iweb-monitor-frame-"));
// 注：JS kernel 启动依赖 mc 子进程（本机通常无 mc）；采集默认指向 Rust kernel
// 或经 KERNEL_TEST_COMMAND 提供可用 JS 环境（含 mc）。Rust kernel 无此依赖。
writeFileSync(join(directory, "routes.json"), JSON.stringify({ version: 1, routes: [
	{ hostId: "admin", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
	{ hostId: "admin.app", target: { kind: "celld-app", appName: "admin" }, system: true, enabled: true },
	{ hostId: "mcp", target: { kind: "celld-app", appName: "mcp" }, system: true, enabled: true },
	{ hostId: "mcp.app", target: { kind: "celld-app", appName: "mcp" }, system: true, enabled: true },
] }, null, 2) + "\n");

// rust-kernel-rustfs-storage：同一采集脚本驱动任一 Kernel 实现（默认 JS）。
const command = (process.env.KERNEL_TEST_COMMAND ?? `node ${join(import.meta.dir, "..", "kernel", "index.js")}`).split(" ");
const child = spawn(command[0], command.slice(1), {
	env: {
		...process.env,
		IWEB_BASE_HOST: BASE_HOST,
		IWEB_API_TOKEN: TOKEN,
		IWEB_ROUTES_FILE: join(directory, "routes.json"),
		IWEB_RECOVERY_WORKER: "recovery-worker",
		IWEB_CELLD_BUCKET: "iweb-cells",
		IWEB_CELLD_ENDPOINT: "http://127.0.0.1:9000",
		IWEB_CELLD_REGION: "us-east-1",
		IWEB_SANDBOX_SOCKET: join(directory, "supervisor.sock"),
		IWEB_CONTROL_DB_FILE: join(directory, "control-db.json"),
		IWEB_CONTROL_SECRETS_FILE: join(directory, "control-secrets.json"),
		IWEB_SANDBOX_GATEWAY_DIR: join(directory, "gw"),
	},
	stdio: ["ignore", "pipe", "pipe"],
});

async function until<T>(fn: () => Promise<T>, timeoutMs: number): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		try { return await fn(); } catch (error) { if (Date.now() > deadline) throw error; await new Promise((r) => setTimeout(r, 100)); }
	}
}

function decodeTextFrame(buffer: Buffer): string {
	// server frames are unmasked: 0x81 <len> [ext len] payload
	if (buffer[0] !== 0x81) throw new Error("not a text frame");
	let offset = 2;
	let length = buffer[1];
	if (length === 126) { length = buffer.readUInt16BE(2); offset = 4; }
	return buffer.subarray(offset, offset + length).toString("utf8");
}

	try {
		await until(async () => {
			const response = await fetch(`http://127.0.0.1:${PORT}/health`);
			if (!response.ok) throw new Error("not healthy");
		}, 15000);
		// fetch 实现会剥 Host 头；会话签发改走裸 socket，显式 Host: api.<base> +
		// owner Bearer 打回环控制监听器（x-iweb-internal-control 头已废除，Codex R3）。
		const sessionResponse = await new Promise<string>((resolve, reject) => {
			const socket = net.connect(PORT, "127.0.0.1", () => {
				socket.write(`POST /v1/monitor/session HTTP/1.1\r\nHost: api.${BASE_HOST}\r\nAuthorization: Bearer ${TOKEN}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
			});
			let seen = Buffer.alloc(0);
			const timer = setTimeout(() => reject(new Error("no session response within 5s")), 5000);
			socket.on("data", (chunk: Buffer) => {
				seen = Buffer.concat([seen, chunk]);
				const headerEnd = seen.indexOf("\r\n\r\n");
				if (headerEnd >= 0 && seen.length >= headerEnd + 4 + Number(seen.subarray(0, headerEnd).toString().match(/content-length:\s*(\d+)/i)?.[1] ?? 0)) {
					clearTimeout(timer);
					socket.destroy();
					resolve(seen.subarray(headerEnd + 4).toString("utf8"));
				}
			});
			socket.on("error", reject);
		});
		const session = JSON.parse(sessionResponse) as { ticket?: string };
		if (typeof session.ticket !== "string") throw new Error("no ticket: " + sessionResponse);
	const frameText = await new Promise<string>((resolve, reject) => {
		const key = createHash("sha1").update("monitor-frame-probe").digest("base64");
		const socket = net.connect(PORT, "127.0.0.1", () => {
			socket.write(`GET /v1/monitor?ticket=${encodeURIComponent(session.ticket)} HTTP/1.1\r\nHost: api.${BASE_HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
		});
		let seen = Buffer.alloc(0);
		const timer = setTimeout(() => reject(new Error("no frame within 5s")), 5000);
		socket.on("data", (chunk: Buffer) => {
			seen = Buffer.concat([seen, chunk]);
			const headerEnd = seen.indexOf("\r\n\r\n");
			if (headerEnd < 0) return;
			const body = seen.subarray(headerEnd + 4);
			if (body.length >= 2 && (body.length - 2 >= (body[1] === 126 ? body.readUInt16BE(2) : body[1]))) {
				clearTimeout(timer);
			socket.destroy();
			resolve(decodeTextFrame(body));
			}
		});
		socket.on("error", reject);
	});
	// scan the REAL frame: the owner token must not appear anywhere in it
	const { scanForSecrets, scanForCredentialPatterns } = await import("../contracts/credential-scan.ts");
	const location = { kind: "monitor-frame" as const, label: "kernel:/v1/monitor snapshot frame (current source, ticketed)", content: frameText };
	const secretScan = scanForSecrets({ secrets: [{ value: TOKEN, category: "owner-token" }], locations: [location] });
	const patternScan = scanForCredentialPatterns([location]);
	const parsed = JSON.parse(frameText);
	console.log(JSON.stringify({
		kind: "monitor-frame",
		capturedAt: new Date().toISOString(),
		frameBytes: Buffer.byteLength(frameText),
		frameTopLevelKeys: Object.keys(parsed).sort(),
		containsOwnerToken: frameText.includes(TOKEN),
		secretScanClean: secretScan.clean,
		secretFindings: secretScan.findings,
		patternScanClean: patternScan.clean,
		patternFindings: patternScan.findings,
	}, null, 2));
} finally {
	child.kill("SIGTERM");
	await new Promise((resolve) => child.once("exit", resolve));
	rmSync(directory, { recursive: true, force: true });
}
