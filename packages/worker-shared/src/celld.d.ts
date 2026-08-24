// celld v0.3 与 @cloudflare/workers-types 的 API 差异本地声明（不 fork 官方类型）。
// 差异记录：CF 的 state.accept 在 celld 不存在（实测）；celld 提供 Hibernation 形态
// acceptWebSocket（实测可用）。两处声明都补齐，行为选择留给应用代码。

interface DurableObjectState {
	acceptWebSocket(ws: WebSocket): void;
	accept(ws: WebSocket): void;
}
