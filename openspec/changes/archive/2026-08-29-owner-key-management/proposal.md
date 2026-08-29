## Why

iweb 当前把所有控制请求绑定到单一、不可吊销的 `IWEB_API_TOKEN`。这使节点无法安全地把控制权交给多个部署 Agent，也无法在某个 Agent 泄露或异常时按身份审计并立即停止它；同时，bootstrap 恢复凭据必须继续独立于 Admin、MCP 和可变应用。

## What Changes

- 新增一个身份、多把同等授权的 owner key；每把 delegated key 可独立吊销、过期并在审计记录中归因，不引入 scope 或角色拆分。
- 以固定的 `/data/kernel/keys.json` 保存 key 元数据和 SHA-256 secret hash，以固定的有界、轮转 `audit.log` 保存控制面证据；两者不进入应用生命周期 `control-db`，但纳入同一节点备份和 quiesced restore。
- 扩展 Rust Kernel 鉴权和控制 API：`GET/POST /v1/keys`、`DELETE /v1/keys/{keyId}`、`GET /v1/audit`；bootstrap `IWEB_API_TOKEN` 永远有效、不可吊销，且只作为内存配置参与鉴权。
- 规定令牌格式、绝对 UTC 过期时间、文件权限、原子写、单写者并发、损坏文件 fail-closed、审计轮转和秘密不落盘/不进 URL 的安全契约。
- delegated key 的 ban 对后续 HTTP/MCP 请求立即生效，并关闭由该 key 建立的 monitor WebSocket；已在途的普通 HTTP/MCP 请求不回溯取消。
- Admin 增加 Keys 与 Audit 视图：创建时仅一次显示明文、吊销二次确认、过期预设、元数据列表和一次性部署提示词复制；bootstrap 行明确不可吊销。
- MCP 保持逐 JSON-RPC 请求透传原始 `Authorization`，不存储或伪造 actor header；Kernel 以实际 Bearer key 归因 MCP 调用。
- **BREAKING**：Admin 登录不再要求 bootstrap 专属密钥，任一有效 owner key 均可登录；`/v1/key` 的能力语义仍为同一 owner 全权限。
- Rust Kernel 是唯一运行时实现；现存 JS reference kernel 保持冻结，不为该能力做双实现。契约测试以 Rust HTTP 行为和 MCP 转发行为为准。

## Capabilities

### New Capabilities

- `owner-key-management`: owner key 生命周期、鉴权、持久化、审计、恢复和安全边界。

### Modified Capabilities

- `kernel-control-plane`: owner credential requirement becomes bootstrap-or-revocable-key authorization with actor attribution, recovery, and long-connection revocation semantics.
- `administration-console`: Admin accepts any valid owner key and provides key/audit management without persisting newly-created secrets.
- `mcp-control`: every JSON-RPC request continues to authenticate and forwards the caller credential so Kernel audit attribution remains truthful.

## Impact

- Rust: `kernel-rs/iweb-kernel/src/auth.rs`, `http.rs`, `config.rs`, `monitor.rs`, plus a new owner-key state/audit module and focused integration tests. `control_journal.rs` remains the application lifecycle journal and is not widened to contain credentials.
- Admin: `admin-console/src/lib/iweb/api.ts`, `contracts.ts`, session/navigation/page components and tests.
- MCP: `worker/apps/mcp/app/index.js`, tool/contract tests, with no credential persistence or new authority header.
- Operations: node backup and restore must include `/data/kernel/keys.json` and rotated audit files while never copying `IWEB_API_TOKEN` from the environment into artifacts.
