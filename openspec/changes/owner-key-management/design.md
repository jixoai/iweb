## Context

当前 Rust Kernel 在 `kernel-rs/iweb-kernel` 中把单一 `IWEB_API_TOKEN` 直接放在 `Config`，`auth.rs` 只比较一个 bearer，`http.rs` 每个 handler 重复调用鉴权；`control_journal.rs` 只负责应用版本/生命周期状态的原子快照。Admin 在 tab-scoped `sessionStorage` 保存登录凭据，MCP Worker 将当前请求的 Authorization 原样转发到 Kernel。详见 `proposal.md` 和本 change 的 delta specs。

## Goals / Non-Goals

**Goals:**

- 在不拆分 owner capability 的前提下发行、过期、吊销和归因多把 bearer key。
- 让 bootstrap key 在 delegated key 状态损坏时仍能从 `api.<base>` 恢复节点。
- 为 key 变更提供崩溃可恢复的 durable state、有限审计和真实 monitor WS 吊销。
- 让 Admin/MCP 只成为调用面，身份判断和 actor 归因始终由 Rust Kernel 完成。

**Non-Goals:**

- 不引入 scopes、roles、per-key rate limits、应用级授权或二次身份验证协议。
- 不把 owner keys 放入 `control-db.json`、MinIO workspace、celld/Sandbox 环境或应用凭据。
- 不让 JS reference kernel 获得新能力；它继续作为冻结的历史/契约参考，不作为生产实现。
- 不在本 change 中建立跨节点同步、远程密钥托管或长期审计查询系统。

## Decisions

### 1. 独立安全状态文件，而非 control-db

`control-db.json` 是应用生命周期和版本指针的产品状态；owner key 是节点安全状态。把二者合并会扩大应用恢复/迁移代码读取秘密元数据的范围，并使生命周期回滚影响认证状态。因此使用 `/data/kernel/keys.json`，权限 0700 目录/0600 文件，拒绝符号链接和不受支持的 schema/version。

独立不等于独立备份：node backup 在 quiesced 边界同时复制 keys、pending journal 和全部审计段；restore 必须把它们作为一个 Kernel-state 集合恢复。`IWEB_API_TOKEN` 仍只来自启动环境，不写入该集合。

### 2. 两阶段小型 journal 解决 keys/audit 崩溃窗口

单独的 JSON snapshot 与 append-only audit 不可能仅靠 rename 同时提交。因此每次 create/ban 使用一个同目录的 `keys.pending`（0600）事务记录：operation id、before digest、after digest、目标 key id、审计事件摘要和阶段。写入顺序为：

```text
lock -> pending=prepared -> audit intent -> keys.json temp+fsync+rename
     -> audit commit -> pending=committed -> remove pending
```

启动时只接受以下两种状态：

```text
pending absent                         => current keys.json
pending present + valid commit        => after snapshot + committed audit
pending present without commit         => before snapshot + aborted marker/event
```

如果 pending、snapshot 或 audit 任一摘要不一致，Kernel 不猜测、不清空，delegated auth 进入 unavailable/deny；bootstrap 仍工作并暴露有界恢复错误。该 journal 不是控制数据库，也不包含明文 secret。

所有 key mutation 通过进程内单写者队列；临时文件同目录创建、写入、`fsync`、rename，必要时 `fsync` 目录。启动恢复和 HTTP mutation 共用同一锁。

### 3. Token format and authorization

发行 32 random bytes 的 secret；`keyId` 仅为 32-bit random public handle，不承载时间、顺序或权限。它会出现在列表、路径和审计过滤器中，不是认证因素；穷举 keyId 只能得到统一 401。secret 采用 256-bit 熵，格式解析失败不访问磁盘。

启动时对配置 bootstrap secret 计算 SHA-256 digest 并仅在内存保存 digest。请求先解析 `Bearer `，计算 presented digest；对 bootstrap digest 做 constant-time compare，再按 keyId 查 delegated record 对其 hash 做同样比较。未知、过期、banned、损坏和错误格式全部使用同一 401 body/status；不接受 caller-provided actor header。

不做二次确认协议：在 unsplit owner authority 下，任何有效 owner key 都可创建/吊销其它 delegated key，增加一个“二次确认 key”只会伪装成 scope。Admin 的确认 dialog 只是防误触 UX，不能改变 API authorization。

### 4. Absolute expiry

wire contract 只接受 `YYYY-MM-DDTHH:mm:ss.sssZ`（UTC RFC3339）绝对时间，比较 Kernel 当前 UTC；等于当前时间即过期。Admin 的“1 天/7 天/30 天/永不过期”只是本地生成绝对时间，Agent/MCP 可以直接提交绝对时间，避免 relative TTL 在客户端、网络和重试之间漂移。

### 5. Bounded audit

active `audit.log` 上限 1 MiB，历史保留 `audit.log.1` 至 `.3`，总计最多 4 MiB；每行是严格 schema 的单行 JSON，path/action/method 有长度上限，拒绝换行和任意 body。轮转只发生在完整事件写入前，先 rename 完整文件、创建新 active，再删除最老段。读接口只读可解析行并 newest-first；损坏段不自动修复，返回保留的有效范围和 `audit-unavailable` 标记，避免伪造完整历史。

审计是安全证据但不是高可靠日志服务。写失败时 key mutation 失败并返回 503；普通请求的审计写失败按 endpoint 类别 bounded-fail（控制 mutation 失败，纯 GET 可返回结果但标示 audit unavailable），决不把 Authorization 或 secret 写入错误日志。

### 6. Monitor and MCP revocation

monitor ticket 在签发时绑定 actor（bootstrap 或 keyId）。WS upgrade 消费 ticket 后将 actor 注册到连接表；ban 通过 broadcast/close channel 关闭该 actor 的连接，并删除其尚未消费的 tickets。由于当前 MCP 是每个 JSON-RPC 一个 HTTP 请求，没有长连接授权状态：已经进入 handler 的调用允许完成，下一请求重新鉴权并失败。若未来启用 MCP streaming，必须复用同一 actor close 规则后才可发布。

### 7. Rust-only implementation boundary

生产路由、恢复入口和契约测试以 Rust Kernel 为唯一权威；`kernel/index.js` 不接入新 endpoint、不生成 keys/audit 资产。MCP Worker 不实现 token 校验副本，只用现有 `/v1/status` preflight/当前请求转发；这样不会出现 Rust 与 JS 的过期、ban 或归因漂移。跨实现 golden vectors 仅覆盖既有冻结契约，不声称 JS 支持本 change。

### 8. Admin surface

Admin 复用现有 `KernelApiClient`/zod boundary，新增严格 response schemas。新 secret 只存在创建 dialog 的内存状态，关闭/复制后清零引用；Clipboard 是用户明确动作，提示词不经过 Kernel。列表和审计都使用页面级 view header，bootstrap 行禁用 revoke。401 自动清 session 并回到登录页，避免 stale key 无限重试。

## Risks / Trade-offs

- [Risk] 家庭节点 SD 卡仍会承受审计写放大 → 单事件严格限长、4 MiB 硬上限、轮转前完整段写入；未来可加 opt-in 外部 sink，但不扩大本 change。
- [Risk] keys.json 与 audit.log 的双文件事务增加恢复复杂度 → `keys.pending` 只保存摘要/阶段，启动矩阵覆盖每个崩溃点；不做静默修复。
- [Risk] 32-bit public keyId 可被大量枚举 → keyId 不是秘密且每次猜测仍需 256-bit secret；统一响应和不暴露 existence，安全预算在 secret 而非 id。
- [Risk] 任一 delegated key 都可再发 key，泄露会形成同权限扩散 → 这是 owner identity unsplit 的直接结果；只允许 owner 通过显式 UI/API ban，scope/delegation hierarchy 留待另一个明确的授权 change。
- [Risk] ban 无法回滚一个已执行副作用的请求 → 规范只保证新请求和 monitor 长连接；控制 mutation 仍由 Kernel 单写者和幂等语义保护。
- [Risk] 宕机期间无法读取 delegated store → bootstrap recovery 仍可用，delegated auth fail-closed；恢复接口不执行 mutable workspace package。

## Migration Plan

1. 发布包含新 Rust Kernel 的镜像；启动时创建不存在的 keys/audit 目录，但不自动生成 delegated key，也不改变现有 `IWEB_API_TOKEN`。
2. 以 bootstrap 首次调用 `GET /v1/keys` 验证 synthetic bootstrap 行，再创建和验证一把短 TTL delegated key；验证 Admin 登录、MCP initialize/tools/call、audit attribution 和 monitor close。
3. 备份脚本/恢复脚本以 quiesced 节点为边界纳入 keys、pending、audit 段，执行损坏/恢复矩阵。
4. 回滚时停止新 Kernel，恢复上一镜像和原 control state；保留 `/data/kernel` 文件但旧 Kernel 忽略它，bootstrap `IWEB_API_TOKEN` 继续恢复。禁止在未验证 restore 前删除旧审计段。

## Open Questions

无。TTL 默认值、审计外部导出和未来 scope 模型都会改变可观察契约，应另开 change 决定。
