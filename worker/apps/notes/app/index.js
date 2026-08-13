// 用户原始需求（2026-08-13）：将 notes 从运行时调试响应升级为可直接使用的 Web 应用。
// 正交意图：提供笔记 Web UI；持久化文本笔记；提供最小 JSON API；不暴露 celld 或 Durable Object 实现细节。
const defaultNotes = [
  {
    id: "welcome",
    title: "欢迎使用 Notes",
    content: "这是运行在你的 iweb 节点上的第一条笔记。它的数据保存在 notes 应用自己的 Durable Object SQLite 中。",
    updatedAt: "2026-08-13T00:00:00.000Z",
  },
];

function json(value, status = 200) {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function notesId(env) {
  return env.NOTES_CELL.idFromName("notes");
}

function appBasePath(request) {
  const candidate = request.headers.get("x-iweb-app-base") ?? "";
  return /^\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\/app\/$/.test(candidate) ? candidate : "/";
}

function html(request) {
  const basePath = appBasePath(request);
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Notes · iweb</title>
    <base href="${basePath}">
    <style>
      :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #f8fafc; color: #0f172a; }
      * { box-sizing: border-box; }
      body { min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px; }
      main { width: min(100%, 760px); display: grid; gap: 16px; }
      header, form, article { border: 1px solid #e2e8f0; border-radius: 16px; background: #fff; box-shadow: 0 12px 36px rgb(15 23 42 / 0.06); }
      header { padding: 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
      h1, h2, p { margin: 0; } h1 { font-size: 1.5rem; } h2 { font-size: 1rem; } .muted { color: #64748b; font-size: .875rem; }
      form { padding: 20px; display: grid; gap: 12px; } input, textarea, button { font: inherit; } input, textarea { width: 100%; border: 1px solid #cbd5e1; border-radius: 10px; padding: 10px 12px; background: #fff; color: #0f172a; } textarea { min-height: 128px; resize: vertical; } button { justify-self: end; border: 0; border-radius: 10px; padding: 10px 14px; color: #fff; background: #0f172a; cursor: pointer; } button:disabled { opacity: .55; cursor: wait; } .remove { justify-self: start; padding: 6px 9px; background: transparent; color: #64748b; border: 1px solid #cbd5e1; font-size: .75rem; }
      #notes { display: grid; gap: 12px; } article { padding: 18px; display: grid; gap: 8px; } article p { white-space: pre-wrap; line-height: 1.55; }
      @media (prefers-color-scheme: dark) { :root { background: #0f172a; color: #e2e8f0; } header, form, article { background: #111827; border-color: #334155; box-shadow: none; } input, textarea { background: #0f172a; color: #e2e8f0; border-color: #475569; } button { background: #e2e8f0; color: #0f172a; } .remove { color: #cbd5e1; background: transparent; border-color: #475569; } .muted { color: #94a3b8; } }
    </style>
  </head>
  <body>
    <main>
      <header><div><p class="muted">iweb application</p><h1>Notes</h1></div><p class="muted" id="state">正在同步…</p></header>
      <form id="compose"><input name="title" required maxlength="120" placeholder="笔记标题"><textarea name="content" required maxlength="20000" placeholder="写下一件要记住的事…"></textarea><button type="submit">保存笔记</button></form>
      <section id="notes" aria-live="polite"></section>
    </main>
    <script>
      const notes = document.getElementById('notes');
      const state = document.getElementById('state');
      const form = document.getElementById('compose');
      function render(items) {
        notes.replaceChildren(...items.map((note) => {
          const article = document.createElement('article');
          const title = document.createElement('h2'); title.textContent = note.title;
          const content = document.createElement('p'); content.textContent = note.content;
          const time = document.createElement('p'); time.className = 'muted'; time.textContent = new Date(note.updatedAt).toLocaleString();
          const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = '删除'; remove.className = 'remove';
          remove.addEventListener('click', async () => {
            remove.disabled = true;
            try { const response = await fetch('./api/notes/' + encodeURIComponent(note.id), { method: 'DELETE' }); if (!response.ok) throw new Error('无法删除笔记'); await refresh(); }
            catch (error) { state.textContent = error instanceof Error ? error.message : '请求失败'; remove.disabled = false; }
          });
          article.append(title, content, time, remove); return article;
        }));
        state.textContent = items.length + ' 条笔记';
      }
      async function refresh() {
        state.textContent = '正在同步…';
        const response = await fetch('./api/notes');
        if (!response.ok) throw new Error('无法读取笔记');
        render((await response.json()).notes);
      }
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const button = form.querySelector('button'); button.disabled = true;
        try {
          const values = new FormData(form);
          const response = await fetch('./api/notes', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ title: values.get('title'), content: values.get('content') }) });
          if (!response.ok) throw new Error('无法保存笔记');
          form.reset(); await refresh();
        } catch (error) { state.textContent = error instanceof Error ? error.message : '请求失败'; }
        finally { button.disabled = false; }
      });
      refresh().catch((error) => { state.textContent = error instanceof Error ? error.message : '请求失败'; });
    </script>
  </body>
</html>`;
}

export class NotesCell {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const noteMatch = url.pathname.match(/^\/api\/notes\/([A-Za-z0-9-]+)$/);
    if (noteMatch && request.method === "DELETE") {
      const notes = (await this.state.storage.get("notes")) ?? defaultNotes;
      const next = notes.filter((note) => note.id !== noteMatch[1]);
      if (next.length === notes.length) return json({ error: "note not found" }, 404);
      await this.state.storage.put("notes", next);
      return new Response(null, { status: 204 });
    }
    if (url.pathname !== "/api/notes") return new Response("not found", { status: 404 });
    if (request.method === "GET") {
      const notes = (await this.state.storage.get("notes")) ?? defaultNotes;
      return json({ notes });
    }
    if (request.method !== "POST") return new Response("method not allowed", { status: 405, headers: { allow: "GET, POST" } });
    let input;
    try {
      input = await request.json();
    } catch {
      return json({ error: "request body must be JSON" }, 400);
    }
    const title = typeof input?.title === "string" ? input.title.trim() : "";
    const content = typeof input?.content === "string" ? input.content.trim() : "";
    if (!title || !content || title.length > 120 || content.length > 20_000) {
      return json({ error: "title and content are required" }, 400);
    }
    const notes = (await this.state.storage.get("notes")) ?? defaultNotes;
    const note = { id: crypto.randomUUID(), title, content, updatedAt: new Date().toISOString() };
    const next = [note, ...notes].slice(0, 200);
    await this.state.storage.put("notes", next);
    return json({ note }, 201);
  }
}

export async function fetch(request, env) {
  const url = new URL(request.url);
  if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    return new Response(html(request), { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
  }
  if (url.pathname === "/api/notes" || url.pathname.startsWith("/api/notes/")) return env.NOTES_CELL.get(notesId(env)).fetch(request);
  return new Response("not found", { status: 404 });
}
