// 用户原始需求（2026-08-12）：admin 作为可替换的 celld 应用，仅提供 Kernel API 的 Web UI。
// 正交意图：渲染路由管理界面；调用 api.<base>；不持有任何控制面权限。
function apiOrigin(request, env) {
  const baseHost = env.IWEB_BASE_HOST ?? new URL(request.url).hostname.replace(/^(?:admin\.)/, "");
  const externalHost = request.headers.get("x-iweb-external-host") ?? "";
  const port = externalHost.match(/:(\d+)$/)?.[1];
  const protocol = request.headers.get("x-forwarded-proto") ?? new URL(request.url).protocol.slice(0, -1);
  return `${protocol}://api.${baseHost}${port ? `:${port}` : ""}`;
}

export async function fetch(request, env) {
  if (request.method !== "GET") return new Response("method not allowed", { status: 405 });
  const origin = apiOrigin(request, env);
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>iweb admin</title>
    <style>
      :root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
      body { max-width: 760px; margin: 40px auto; padding: 0 20px; }
      input, button { font: inherit; padding: 8px; margin: 4px 0; }
      input { width: min(100%, 420px); box-sizing: border-box; }
      button { cursor: pointer; }
      table { width: 100%; border-collapse: collapse; margin-top: 20px; }
      th, td { text-align: left; border-bottom: 1px solid #8886; padding: 8px 4px; }
      #message { min-height: 1.4em; }
    </style>
  </head>
  <body>
    <h1>iweb admin</h1>
    <p><label>API token<br><input id="token" type="password" autocomplete="off"></label></p>
    <p><button id="refresh">Refresh routes</button></p>
    <p><button id="recover" type="button">Restore admin from image</button></p>
    <form id="route-form">
      <fieldset>
        <legend>Register celld app</legend>
        <label>Host ID<br><input id="hostId" required pattern="[a-z0-9-]+\\.app" placeholder="notes.app"></label><br>
        <label>App name<br><input id="appName" required pattern="[a-z0-9-]+" placeholder="notes"></label><br>
        <button type="submit">Save route</button>
      </fieldset>
    </form>
    <p id="message" role="status"></p>
    <table>
      <thead><tr><th>Host ID</th><th>Target</th><th>State</th><th></th></tr></thead>
      <tbody id="routes"></tbody>
    </table>
    <script>
      const API_ORIGIN = ${JSON.stringify(origin)};
      const tokenInput = document.querySelector('#token');
      const message = document.querySelector('#message');
      const routes = document.querySelector('#routes');
      tokenInput.value = sessionStorage.getItem('iweb-api-token') || '';
      function authHeaders() {
        const token = tokenInput.value.trim();
        sessionStorage.setItem('iweb-api-token', token);
        return { authorization: 'Bearer ' + token, 'content-type': 'application/json' };
      }
      async function call(path, options = {}) {
        const response = await fetch(API_ORIGIN + path, { ...options, headers: { ...authHeaders(), ...(options.headers || {}) } });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(body.error || ('HTTP ' + response.status));
        return body;
      }
      function render(store) {
        routes.innerHTML = store.routes.map((route) => '<tr><td>' + route.hostId + '</td><td>' + route.target.appName + '</td><td>' + (route.system ? 'system' : 'user') + '</td><td>' + (route.system ? '' : '<button data-delete="' + encodeURIComponent(route.hostId) + '">Delete</button>') + '</td></tr>').join('');
        routes.querySelectorAll('[data-delete]').forEach((button) => button.addEventListener('click', async () => {
          try { await call('/v1/routes/' + button.dataset.delete, { method: 'DELETE' }); await refresh(); } catch (error) { message.textContent = error.message; }
        }));
      }
      async function refresh() {
        try { render(await call('/v1/routes')); message.textContent = 'Ready'; } catch (error) { message.textContent = error.message; }
      }
      document.querySelector('#refresh').addEventListener('click', refresh);
      document.querySelector('#recover').addEventListener('click', async () => {
        try { await call('/v1/recover/admin', { method: 'POST' }); message.textContent = 'Node is restarting'; } catch (error) { message.textContent = error.message; }
      });
      document.querySelector('#route-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        try {
          await call('/v1/routes', { method: 'POST', body: JSON.stringify({ hostId: document.querySelector('#hostId').value, appName: document.querySelector('#appName').value }) });
          message.textContent = 'Saved';
          await refresh();
        } catch (error) { message.textContent = error.message; }
      });
    </script>
  </body>
</html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
}
