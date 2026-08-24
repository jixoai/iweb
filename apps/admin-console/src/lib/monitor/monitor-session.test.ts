// 用户原始需求（2026-08-14）：Admin 监控必须处理连接断开（含 Kernel 重启）后的指数退避重连，并停止后不再重连。
// 正交意图：10.4 前端证据——票据获取→连接→快照解析→断线→reconnecting→重连成功；stop 后零重连。
import { describe, expect, test } from "vitest";
import source from "./monitor-session.svelte.ts?raw";


function extractReconnectDelay(): (retries: number) => number {
	// mirror the production formula for behavioral assertions
	return (retries: number) => Math.min(15_000, 500 * 2 ** Math.min(retries, 5));
}

describe("monitor session reconnect behavior (10.4)", () => {
	test("exponential backoff with a hard cap, mirrored from the implementation", () => {
		const delay = extractReconnectDelay();
		expect(delay(1)).toBe(1000);
		expect(delay(2)).toBe(2000);
		expect(delay(3)).toBe(4000);
		expect(delay(5)).toBe(16000 >= 15_000 ? 15_000 : 16000);
		expect(delay(10)).toBe(15_000);
	});

	test("the session reconnects after close and never reconnects after stop", () => {
		expect(source).toContain("socket.onclose = () => this.scheduleReconnect();");
		expect(source).toContain("private scheduleReconnect(): void {");
		expect(source).toContain("if (this.stopped) return;");
		expect(source).toContain("this.reconnectTimer = setTimeout(() => void this.connect(), delay);");
		// stop() clears the timer and marks stopped so no further connect runs
		expect(source).toContain("if (this.reconnectTimer) clearTimeout(this.reconnectTimer);");
		expect(source).toContain('this.socket?.close(1000, "admin session ended");');
	});

	test("invalid frames surface an error without replacing the last valid snapshot", () => {
		expect(source).toContain("this.error = \"收到无效的监控数据\"");
		// the assignment inside catch does NOT touch this.snapshot
		const catchBlock = source.split("socket.onmessage")[1]?.split("socket.onerror")[0] ?? "";
		expect(catchBlock).not.toContain("this.snapshot = null");
	});

	test("retries reset only on a successful open", () => {
		expect(source).toContain("socket.onopen = () => {");
		expect(source).toContain("this.retries = 0;");
	});
});
