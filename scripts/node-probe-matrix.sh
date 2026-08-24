#!/bin/sh
# 用户原始需求（2026-08-15，2026-08-20 参数化）：§8.1 探针矩阵在任何真实节点上一键复跑。
# 正交意图：7 探针 + monitor 票据/WS 链；owner token 只在宿主内传递，绝不打印/入 URL。
# 用法：node-probe-matrix.sh <env-file> [published-port]   （在节点宿主上运行，探 127.0.0.1）
set -eu

ENVFILE=${1:?usage: node-probe-matrix.sh <env-file> [published-port]}
PORT=${2:-9010}
# bash 的 `.` 对无斜杠文件名只搜 PATH 不搜 cwd；规范成显式路径。
case "${ENVFILE}" in */*) ;; *) ENVFILE="./${ENVFILE}" ;; esac
# shellcheck disable=SC1090
. "${ENVFILE}"
: "${IWEB_BASE_HOST:?IWEB_BASE_HOST missing in env file}"
: "${IWEB_API_TOKEN:?IWEB_API_TOKEN missing in env file}"
BASE="${IWEB_BASE_HOST}"

pass=0
fail=0
report() {
  name="$1"; expected="$2"; got="$3"
  if [ "${got}" = "${expected}" ]; then
    pass=$((pass + 1)); printf 'PASS %s (%s)\n' "${name}" "${got}"
  else
    fail=$((fail + 1)); printf 'FAIL %s expected=%s got=%s\n' "${name}" "${expected}" "${got}"
  fi
}

code() { curl --noproxy '*' -s -o /dev/null -w '%{http_code}' "$@"; }
body() { curl --noproxy '*' -s "$@"; }
# token 经 stdin curl config 下发（Codex R1 非阻塞项）：不进 argv，避免同机进程表读取。
bearer_config() { printf 'header = "Authorization: Bearer %s"\n' "${IWEB_API_TOKEN}"; }

report health 200 "$(code "http://127.0.0.1:${PORT}/_iweb/health" -H "Host: ${BASE}")"
report api-no-auth 401 "$(code "http://127.0.0.1:${PORT}/v1/status" -H "Host: api.${BASE}")"
report api-bearer 200 "$(bearer_config | curl --noproxy '*' -s -o /dev/null -w '%{http_code}' -K - "http://127.0.0.1:${PORT}/v1/status" -H "Host: api.${BASE}")"
report api-bearer-body yes "$(bearer_config | curl --noproxy '*' -s -K - "http://127.0.0.1:${PORT}/v1/status" -H "Host: api.${BASE}" | grep -q '"baseHost"' && echo yes || echo no)"
report admin-html 200 "$(code "http://127.0.0.1:${PORT}/" -H "Host: admin.${BASE}")"
report admin-alias 200 "$(code "http://127.0.0.1:${PORT}/admin/app/" -H "Host: ${BASE}")"
report mcp-get 405 "$(code "http://127.0.0.1:${PORT}/mcp" -H "Host: mcp.${BASE}")"
report unknown-host 404 "$(code "http://127.0.0.1:${PORT}/" -H "Host: probe-matrix-unknown.${BASE}")"

# monitor 链：票据签发（owner）→ WS 首帧真实 JSON → 票据单次使用拒绝。
python_failed=0
IWEB_PORT="${PORT}" IWEB_BASE_HOST="${BASE}" IWEB_API_TOKEN="${IWEB_API_TOKEN}" python3 - <<'PY' || python_failed=1
import json, os, re, socket, base64, sys

port, base, token = os.environ["IWEB_PORT"], os.environ["IWEB_BASE_HOST"], os.environ["IWEB_API_TOKEN"]
ok = True

def report(name, expected, got):
    global ok
    status = "PASS" if expected == got else "FAIL"
    if status == "FAIL":
        ok = False
    print(f"{status} {name} expected={expected} got={got}")

request = (
    f"POST /v1/monitor/session HTTP/1.1\r\nHost: api.{base}\r\n"
    f"Authorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)
with socket.create_connection(("127.0.0.1", int(port)), timeout=10) as sock:
    sock.sendall(request.encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode()
    body = response.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in response else b""
    ticket_status = status_line.split()[1] if len(status_line.split()) > 1 else "?"
    report("monitor-ticket-status", "2xx", f"{ticket_status[0]}xx" if ticket_status.startswith("2") else ticket_status)
match = re.search(rb'"ticket"\s*:\s*"([^"]+)"', body)
report("monitor-ticket-shape", "found", "found" if match else "missing")
ticket = match.group(1).decode() if match else ""
if not ticket:
    print("RESULT monitor-chain fail (no ticket)")
    sys.exit(0)

key = base64.b64encode(os.urandom(16)).decode()
upgrade = (
    f"GET /v1/monitor?ticket={ticket} HTTP/1.1\r\nHost: api.{base}\r\n"
    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
)
with socket.create_connection(("127.0.0.1", int(port)), timeout=10) as sock:
    sock.sendall(upgrade.encode())
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = sock.recv(4096)
        if not chunk:
            break
        header += chunk
    report("monitor-ws-status", "101", header.split(b" ", 2)[1].decode() if b" " in header else "?")
    raw = header.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in header else b""
    while True:
        if len(raw) >= 2:
            flag = raw[1] & 0x7F
            need = 2 if flag < 0x7E else 4 if flag == 0x7E else 10
            if len(raw) >= need:
                break
        raw += sock.recv(65536)
    length = raw[1] & 0x7F
    offset = 2
    if length == 0x7E:
        length = int.from_bytes(raw[2:4], "big"); offset = 4
    elif length == 0x7F:
        length = int.from_bytes(raw[2:10], "big"); offset = 10
    while len(raw) < offset + length:
        raw += sock.recv(65536)
    frame = raw[offset:offset + length].decode("utf-8", "replace")
try:
    parsed = json.loads(frame)
    # 浏览器契约（monitorSnapshotSchema）：node.memory 扁平四字段；
    # Linux 节点上 cgroup 读数必须是真实正整数（缺测为 null，绝不 0 冒充）。
    memory = parsed.get("node", {}).get("memory", {})
    usage = memory.get("usageBytes")
    valid = isinstance(usage, int) and usage > 0 and isinstance(memory.get("kernelHeapUsedBytes"), int)
    report("monitor-frame-node-memory", "real-int", "real-int" if valid else str(memory)[:80])
except Exception as error:
    report("monitor-frame-json", "object", f"error:{error.__class__.__name__}")

with socket.create_connection(("127.0.0.1", int(port)), timeout=10) as sock:
    sock.sendall(upgrade.encode())
    retry = b""
    while b"\r\n\r\n" not in retry and not retry:
        chunk = sock.recv(4096)
        if not chunk:
            break
        retry += chunk
    reuse_code = retry.split(b" ", 2)[1].decode() if b" " in retry else "?"
    report("monitor-ticket-reuse", "rejected", "rejected" if reuse_code in ("400", "401") else reuse_code)
print(f"RESULT monitor-chain {'pass' if ok else 'fail'}")
sys.exit(0 if ok else 1)
PY
if [ "${python_failed}" -ne 0 ]; then fail=$((fail + 1)); fi

printf 'SUMMARY pass=%d fail=%d\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
