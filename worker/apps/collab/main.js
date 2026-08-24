// 用户原始需求（2026-08-22）：iweb 实用性实战 3——前后端分离多实例协作站。
// 正交意图：/api/* 由 DO 支撑（跨实例一致），其余请求委派 celld 标准文件接口。
// 安全底线：JSON 边界解析 + 字段白名单 + 长度上限；访客错误一律泛化。
const json = (data, status = 200) => Response.json(data, { status });

export class CollabBoard {
	// SQLite-backed DO：消息板状态跨实例持久且一致；WS 订阅者实时广播。
	constructor(state) {
		this.state = state;
		this.storage = state.storage;
		this.sockets = new Set();
	}

	async ensureSchema() {
		if (!this.ready) {
			await this.storage.sql.exec(`CREATE TABLE IF NOT EXISTS messages (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				author TEXT NOT NULL,
				text TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`);
			this.ready = true;
		}
	}

	async currentPayload() {
		const rows = [...this.storage.sql.exec("SELECT id, author, text, created_at FROM messages ORDER BY id DESC LIMIT 50")];
		const count = [...this.storage.sql.exec("SELECT COUNT(*) AS n FROM messages")][0];
		return { count: Number(count.n), messages: rows.map((row) => ({ id: Number(row.id), author: String(row.author), text: String(row.text), createdAt: String(row.created_at) })) };
	}

	broadcast() {
		const frame = JSON.stringify({ type: "board", ...(this.pending ?? {}) });
		for (const socket of this.sockets) {
			try { socket.send(frame); } catch { this.sockets.delete(socket); }
		}
	}

	async fetch(request) {
		await this.ensureSchema();
		const url = new URL(request.url);
		// WebSocket 实时订阅：连接由 DO 持有，任何实例的写入都向全部订阅者广播。
		// celld v0.3 的 DurableObjectState 无 Cloudflare 的 accept() API——
		// 直接持有 server 端 socket（celld 生命周期跟随 DO 对象）。
		if (url.pathname === "/api/ws" && request.headers.get("upgrade") === "websocket") {
			const pair = new WebSocketPair();
			const [client, server] = [pair[0], pair[1]];
			// celld 支持 hibernatable WebSocket：acceptWebSocket（Hibernation API 命名），
			// 无则退化为直接持有——帧中继依赖 accept 语义，必须任选其一成立。
			if (typeof this.state.acceptWebSocket === "function") this.state.acceptWebSocket(server);
			else if (typeof this.state.accept === "function") this.state.accept(server);
			this.sockets.add(server);
			server.send(JSON.stringify({ type: "board", ...(await this.currentPayload()) }));
			server.addEventListener("close", () => this.sockets.delete(server));
			server.addEventListener("error", () => this.sockets.delete(server));
			return new Response(null, { status: 101, webSocket: client });
		}
		if (url.pathname === "/api/messages" && request.method === "GET") {
			return json(await this.currentPayload());
		}
		if (url.pathname === "/api/messages" && request.method === "POST") {
			let body;
			try {
				body = await request.json();
			} catch {
				return json({ error: "invalid body" }, 400);
			}
			// Codex 安全挑战实测发现：null/数组体会触发 500——先验证对象形状再取字段。
			if (body === null || typeof body !== "object" || Array.isArray(body)) {
				return json({ error: "body must be an object" }, 400);
			}
			const author = typeof body.author === "string" ? body.author.trim().slice(0, 32) : "";
			const text = typeof body.text === "string" ? body.text.trim().slice(0, 280) : "";
			if (!author || !text) return json({ error: "author and text are required" }, 400);
			await this.storage.sql.exec("INSERT INTO messages (author, text, created_at) VALUES (?, ?, ?)", author, text, new Date().toISOString());
			this.pending = await this.currentPayload();
			this.broadcast();
			return json({ ok: true }, 201);
		}
		return json({ error: "not found" }, 404);
	}
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (url.pathname.startsWith("/api/")) {
			const id = env.BOARD.idFromName("shared-board");
			return env.BOARD.get(id).fetch(request);
		}
		if (request.method === "GET" || request.method === "HEAD") {
			// celld v0.3 缺陷规避：assets 服务对条件 GET（If-None-Match/If-Modified-Since）
			// 返回 404 而非 304——转发前剥掉条件头，强制走完整 200（浏览器照常缓存复用）。
			const url = new URL(request.url);
			const unconditioned = new Request(url, { method: request.method, headers: { accept: request.headers.get("accept") ?? "*/*" } });
			const direct = await env.SITE.fetch(unconditioned);
			if (direct.status !== 404) return direct;
			const index = await env.SITE.fetch(new Request(new URL("/index.html", url.origin), { method: "GET" }));
			if (index.ok) return index;
			return direct;
		}
		return json({ error: "method not allowed" }, 405);
	},
};
