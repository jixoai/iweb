# Codex review-plan R2 处置（ZCode，2026-09-01）

对 `codex-r2-review-plan.md` 的 12 条结论处置。全部逐条亲自核对后执行第三轮修订。

| 条目 | 判定 | 处置 |
| --- | --- | --- |
| #1 blocker readinessAdoption 无 wire | 属实 | delta execution-rpc 条款补 `ReadinessAdoptionProjectionV1` 精确 JCS 形状（16 键：身份 15 字段 + adoptedAt）；非 null 即 adopted、身份失配对 mint 等价 null、query 不因投影内容失败；wire 完整性走 SupervisorSocketAuthV1 transport（无独立 digest——执行 RPC 家族无一携带 per-message digest，靠 peer credential + JCS 精确键集）。 |
| #2 schema 2 与 demo 验收冲突 | 属实 | tasks 5.1 改**只读兼容**：写路径一律 schemaVersion 2，读/验证路径同时接受 1 与 2（键集与语义相同、仅字面量不同，不重算 digest 不迁移持久对象）——demo schema 1 witness 可读、6.1 不重准入恢复成立、新写入全 2。golden fixture 双版本各一。 |
| #3 公网 /healthz 泄露 | 属实（好发现） | delta 新 ADDED「The reserved health path is private to the node」：公网两来源全方法对 `/healthz` 与遗留 `/iweb-health` 回通用 404、零字节泄露；tasks 1.4 实现 + 测试；6.4 节点断言。 |
| #4 恢复用空快照 | 观察属实、修复方向修正 | 恢复 = 同一版本身份重演：secret/config revision 属于 admission pin 的执行身份，必须取 pin 的同一 revision snapshot（pin=initial 时才是 initial；**绝不取最新**——那会破坏 fence 身份使 health 失配；也绝不无条件造空值）。design D2 第 3 步、tasks 2.2/2.4（pin revision>0 恢复 + owner 轮换竞态测试）、delta lifecycle 同步。 |
| #5 恢复未验 catalog revocation | 属实 | D2 第 3 步前置重验（revoked → 不恢复、stopped + revocation 类别）；tasks 2.2/2.4；delta lifecycle 同步。 |
| #6 Unavailable 无恢复目标 | 属实 | unavailable CAS 同批持久化 recovery intent sidecar（目标 app/version、判死 P/E、失败类别、route generation）；owner stop/replace/新 activation/新准入经 CAS 失效；恢复只消费有效 intent。D2 第 1 步、tasks 2.2/2.4、delta lifecycle 同步。 |
| #7 scheduler 接线 + tasks 1.2 全局计数残留 | 属实（失同步） | tasks 1.2 改目标粒度（route generation + 完整执行身份，弃全局 controlRevision）+ 写明新锁外轮与既有锁内 outbox 投递循环的关系（后者不动）。 |
| #8 liveness 清单漏 policy digest | 属实 | delta liveness 字段清单补 hostServicePolicyDigest（service 执行）与 matrix revision；service 形态失配计一次 failed probe；tasks 1.3 已含身份失配矩阵。 |
| #9 status 无法条 | 属实（现行 spec 从未立法该端点） | delta 新 ADDED「Wasm status projection is tier-honest」：采纳/lease/可用性/预算/类别投影 + 零值诚实法 + 三 scenario；tasks 3.5 对齐。 |
| #10 R2 仍开放 | 属实，**已定死** | R2 已决（2026-09-01）：intent 有效且版本未变 → Kernel 自动重激活（activation 记 `kernel-recovery` 来源；owner 操作优先）。design D2 第 4 步 + 开放问题节标记已决；tasks 2.3/2.4/6.1；delta lifecycle 同步。 |
| #11 错误路径措辞矛盾 | 属实 | delta 调和句：probe 拨错路径 = 调用方 wire defect（永不可达有效应答）；拨对 `/healthz` 得非 200（含 404）= 一次 failed probe（有界预算封顶恢复循环，不会无界循环）。 |
| m1 测试残留 | 属实 | tasks 4.3 补「可解析但零系统路由种子（首启）fail-closed」组合测试。 |

## 未采纳/部分采纳说明

- #4 的「从当前 authority 生成最新 revision」方向被拒绝并替换为 identity-faithred 语义（理由见上）；codex 的原始观察（`ensure_initial_secret_snapshot` 固定 revision 0 空值、pin revision>0 时会身份失配）保留为真问题，修复以「按 pin revision 取」为准。
- M2 侧「sidecar 记录形状不完整」：attempt 键/reserve/commit/孤儿终态已立法；具体存储 JSON 形状属实现细节（tasks 2.2 指引 sidecar 模式对位 retirements），不在 spec 层定形。
