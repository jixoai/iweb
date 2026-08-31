import { afterAll, describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import { connect } from "node:net";
import { statSync } from "node:fs";
import { join } from "node:path";
import {
	createWasmIngressGatewayController,
	removeGatewayRoot,
	sandboxIngressGatewayDirectory,
	tempGatewayRoot,
	validSandboxGatewayId,
} from "../supervisor/wasm-ingress-gateway.ts";

const roots: string[] = [];
afterAll(() => {
	for (const root of roots) removeGatewayRoot(root);
});

function freshRoot(): string {
	const root = tempGatewayRoot("iweb-gw-test-");
	roots.push(root);
	return root;
}

/** 本地 TCP echo 上游：收到即回显（验证双向字节透传）。 */
function echoUpstream(port: number): Promise<void> {
	return new Promise((resolve) => {
		const server = createServer((socket) => {
			// 转发器拆连接时 echo 侧可能撞 EPIPE——吞掉属正常拓扑噪声。
			socket.on("error", () => {});
			socket.pipe(socket);
		});
		server.listen(port, "127.0.0.1", () => resolve());
	});
}

describe("wasm ingress gateway controller", () => {
	test("validates the same sandbox id grammar as the kernel proxy", () => {
		expect(validSandboxGatewayId("sbx-vector")).toBe(true);
		expect(validSandboxGatewayId("Sbx/escape")).toBe(false);
		expect(validSandboxGatewayId("../escape")).toBe(false);
		expect(validSandboxGatewayId("")).toBe(false);
	});

	test("directory env resolves with the kernel-side default contract", () => {
		expect(sandboxIngressGatewayDirectory({})).toBe("/run/iweb-sandbox/gw");
		expect(sandboxIngressGatewayDirectory({ IWEB_SANDBOX_GATEWAY_DIR: "  " })).toBe("/run/iweb-sandbox/gw");
		expect(sandboxIngressGatewayDirectory({ IWEB_SANDBOX_GATEWAY_DIR: "/tmp/custom-gw" })).toBe("/tmp/custom-gw");
	});

	test("start forwards bytes to the sandbox listener; stop removes the socket", async () => {
		const root = freshRoot();
		await echoUpstream(18787);
		const controller = createWasmIngressGatewayController(root);
		await controller.start("sbx-demo", "127.0.0.1:18787");

		const socketPath = join(root, "sbx-demo", "ingress.sock");
		const stats = statSync(socketPath);
		expect(stats.isSocket()).toBe(true);
		expect(stats.mode & 0o777).toBe(0o600);

		const reply = await new Promise<string>((resolve, reject) => {
			const client = connect(socketPath, () => client.write("ping-through-gateway"));
			client.on("data", (chunk) => {
				resolve(chunk.toString("utf8"));
				client.end();
			});
			client.on("error", reject);
		});
		expect(reply).toBe("ping-through-gateway");

		await controller.stop("sbx-demo");
		expect(() => statSync(socketPath)).toThrow();
		// 未知 id 幂等。
		await controller.stop("sbx-demo");
	});

	test("restarting the same sandbox id replaces the stale socket (idempotent convergence)", async () => {
		const root = freshRoot();
		await echoUpstream(18788);
		const controller = createWasmIngressGatewayController(root);
		await controller.start("sbx-relace", "127.0.0.1:18788");
		await controller.start("sbx-relace", "127.0.0.1:18788");

		const reply = await new Promise<string>((resolve, reject) => {
			const client = connect(join(root, "sbx-relace", "ingress.sock"), () => client.write("second"));
			client.on("data", (chunk) => {
				resolve(chunk.toString("utf8"));
				client.end();
			});
			client.on("error", reject);
		});
		expect(reply).toBe("second");
		await controller.stop("sbx-relace");
	});
});
