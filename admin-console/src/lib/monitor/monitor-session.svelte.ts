// 用户原始需求（2026-08-13）：总览基于 WebSocket 展示应用实时监控与必要统计。
// 正交意图：换取短时监控票据；维护连接与重连；验证推送快照；在退出会话后完全停止。
import { KernelApiClient } from "$lib/iweb/api";
import { monitorSnapshotSchema, type MonitorSnapshot } from "$lib/iweb/contracts";

function monitorSocketOrigin(apiOrigin: string): string {
	const origin = new URL(apiOrigin);
	origin.protocol = origin.protocol === "https:" ? "wss:" : "ws:";
	return origin.toString().replace(/\/$/, "");
}

export class MonitorSession {
	snapshot = $state<MonitorSnapshot | null>(null);
	state = $state<"idle" | "connecting" | "connected" | "reconnecting" | "error">("idle");
	error = $state("");
	private socket: WebSocket | null = null;
	private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	private retries = 0;
	private stopped = true;
	private client: KernelApiClient | null = null;

	start(client: KernelApiClient): void {
		this.stop();
		this.client = client;
		this.stopped = false;
		void this.connect();
	}

	stop(): void {
		this.stopped = true;
		this.retries = 0;
		if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
		this.reconnectTimer = null;
		this.socket?.close(1000, "admin session ended");
		this.socket = null;
		this.state = "idle";
	}

	private async connect(): Promise<void> {
		if (this.stopped || !this.client) return;
		this.state = this.retries === 0 ? "connecting" : "reconnecting";
		this.error = "";
		try {
			const ticket = await this.client.createMonitorTicket();
			if (this.stopped) return;
			const socket = new WebSocket(`${monitorSocketOrigin(this.client.origin)}/v1/monitor?ticket=${encodeURIComponent(ticket.ticket)}`);
			this.socket = socket;
			socket.onopen = () => {
				this.retries = 0;
				this.state = "connected";
			};
			socket.onmessage = (event: MessageEvent<string>) => {
				try {
					this.snapshot = monitorSnapshotSchema.parse(JSON.parse(event.data));
				} catch {
					this.error = "收到无效的监控数据";
				}
			};
			socket.onerror = () => {
				this.error = "监控连接暂时不可用";
			};
			socket.onclose = () => this.scheduleReconnect();
		} catch (error) {
			this.error = error instanceof Error ? error.message : "无法建立监控连接";
			this.scheduleReconnect();
		}
	}

	private scheduleReconnect(): void {
		if (this.stopped) return;
		this.retries += 1;
		const delay = Math.min(15_000, 500 * 2 ** Math.min(this.retries, 5));
		this.state = "reconnecting";
		this.reconnectTimer = setTimeout(() => void this.connect(), delay);
	}
}
