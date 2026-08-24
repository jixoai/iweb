// collab 前端：WebSocket 实时订阅（DO 广播），失败时降级 3s 轮询。
const board = document.getElementById("board");
const form = document.getElementById("composer");

const escapeHtml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

function render(data) {
	board.innerHTML = data.messages
		.map((message) => `<div class="msg"><div class="meta">#${message.id} · ${escapeHtml(message.author)} · ${new Date(message.createdAt).toLocaleString("zh-CN")}</div><div>${escapeHtml(message.text)}</div></div>`)
		.join("");
}

let live = false;
let poller = 0;
function startPolling() {
	if (poller) return;
	const tick = async () => {
		try { render(await (await fetch("/api/messages")).json()); } catch { /* 轮询是兜底 */ }
	};
	tick();
	poller = setInterval(tick, 3000);
}

function connect() {
	const protocol = location.protocol === "https:" ? "wss:" : "ws:";
	const socket = new WebSocket(`${protocol}//${location.host}/api/ws`);
	socket.addEventListener("open", () => { live = true; });
	socket.addEventListener("message", (event) => {
		const data = JSON.parse(event.data);
		if (data.type === "board") render(data);
	});
	socket.addEventListener("close", () => {
		live = false;
		startPolling();
		setTimeout(connect, 2000);
	});
	socket.addEventListener("error", () => socket.close());
}
connect();
// WS 未在 2s 内建立即先启用轮询兜底（建立成功后由 WS 帧接管渲染）。
setTimeout(() => { if (!live) startPolling(); }, 2000);

form.addEventListener("submit", async (event) => {
	event.preventDefault();
	const author = document.getElementById("author").value;
	const text = document.getElementById("text").value;
	const response = await fetch("/api/messages", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ author, text }),
	});
	if (response.ok) {
		document.getElementById("text").value = "";
		if (!live) render(await (await fetch("/api/messages")).json());
	}
});
