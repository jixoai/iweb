# Codex review-plan R2（2026-09-01，增量复审）

- Agent: herdr `wasm-review-plan`（gpt-5.6-terra / xhigh），R1 同一会话续审
- 用时：9m37s（增量复审 + 核验报告基线；对照 R1 的 2h33m）
- 输入：R1 报告 + ZCode 核验报告 + 两个子代理 R1' 报告 + 二轮修订稿（a2ad0c8）
- 结论原文如下；处置见 `codex-r2-disposition.md`

## 1. 对驳回的回应

- B1：接受。双 ABI 代际是现行有意设计；修订后的 reserve 匹配键明确排除 hostABI，见 specs/wasm-application-runtime/spec.md:196，与 catalog/execution 分层一致。
- B4：不接受"已闭合"。既有偏差判断成立，但 tasks.md:133-136 明确"不做 v1 迁移"，同时 tasks.md:150-153 要求既有 demo 不重准入恢复；schema 1 的既有 witness 无法直接通过新 schema 2 读取，验收条件互相冲突。
- B5：不完全接受。tasks.md:75-85 补了 contracts/parser 触点，但 specs/wasm-application-runtime/spec.md:259 仍未定义非空 readinessAdoption 的精确键集、身份、时间、新鲜度和 digest；这不是单纯"现有 parser 尚未改"的问题。

## 2. 修订验证

- B2/B3：设计层已正确吸收。D8 与 tasks.md:58-74 统一 /healthz、Service health producer、policyless 空串、health/metrics validator、golden 和真实 relay 验收。
- M1：部分解决。D1 已改为按目标 route generation + 完整身份比对（design.md:94-101），但 tasks.md:26-30 仍把全局 controlRevision 列为漂移条件。
- M2：部分解决。D2 已补 command ID、reserve-before-send 和孤儿键终态（design.md:116-128），但 sidecar 记录形状、崩溃恢复关系和 exactly-once 持久语义仍不完整。
- M3：基本解决但法条未完全同步。D2 已澄清请求级 engine trap 不触发 unavailable（design.md:137-144），delta lifecycle 仍保留宽泛的 "exceeds an engine limit"。
- M4：已解决。tasks.md:106-113 明确监听器启动前执行一次 merge，并沿用原子 tmp+rename。
- M5：未解决。只有"批次收口前决定"的期限，没有决定 owner activation 还是 Kernel recovery activation。
- M6：已解决。D4 与 tasks.md:114-116 已加入 IWEB_SANDBOX_GATEWAY_DIR 透传及同值同缺省语义。
- M7：设计已补，验证不足。D0 已要求消费时重读并 pin 比对，但 tasks.md:17-19 没有覆盖读写间替换、篡改和 TOCTOU 场景。
- m1：语义已解决，测试不完整。workspace delta 已规定首启坏种子和 systemless seed fail-closed，但 tasks.md:117-119 未明确测试 parseable-but-systemless 组合。

## 3. 新引入问题

1. [blocker] readinessAdoption 没有可执行 wire —— delta :259 只声明字段存在；现有 query contract 仍是精确键集。修复：定义 canonical ReadinessAdoptionProjectionV1（完整 fence、health/policy digest、采纳时间、新鲜度、状态枚举和 null/未知字段规则），同步 TS、Rust、supervisor、golden tests。
2. [major] schema 2 升级与既有 demo 验收不可同时成立 —— 不迁移 v1 + 要求 demo 不重准入恢复互相冲突。修复：v1→v2 witness 迁移/兼容读取，或移除"不重准入恢复"验收。
3. [major] 公网路由可直接泄露 /healthz 身份证明 —— wasmd 返回完整 attestation，Kernel 对任意应用路径原样转发。修复：Kernel 对公网保留路径固定拒绝，仅私有 probe 面可达，加 GET/HEAD 负向验收。
4. [major] 恢复会重新使用空 secret/config 快照 —— ensure_initial_secret_snapshot 固定 revision 0 空值，违反现行快照法条。修复：恢复时从当前 secret/config authority 生成最新 revision/ref/digest 并测试旋转竞态。
5. [major] 恢复未检查 catalog revocation —— 法条要求撤销后拒绝新 prepare；planner 不检查。修复：恢复 prepare/start 前重验 catalog revision/status。
6. [major] unavailable 指针没有持久恢复目标 —— Unavailable 仅 kind/app/routeGeneration。修复：持久化带完整身份和原 route generation 的 recovery intent；owner 操作经 CAS 使其失效。
7. [major] 锁外 probe 尚未接入真实 scheduler，且全局计数条件与 D1 相悖 —— scheduler 仍在 mutex 内同步 delivery；tasks 1.2 仍要求比较全局 controlRevision。修复：定义并接入 run_convergence_round，明确顺序与延迟验证。
8. [major] liveness 比对遗漏 service policy digest —— liveness 字段清单不含 hostServicePolicyDigest，Service health 要求该字段。修复：policy digest、service matrix/form 纳入比对和失配测试。
9. [major] D7 状态面没有正式 delta 法条 —— status 扩展无法条支撑。修复：新增精确 status requirement/scenarios。
10. [major] R2 激活权威仍是开放决策 —— 只规定未来写结论；6.1 依赖该结论。修复：Apply 前固定唯一激活来源、审计字段、owner stop 语义和重放/CAS 行为。
11. [minor] 错误路径语义自相矛盾 —— 「wire defect 不是 not-ready」与「非 200/404 计 failed probe」需调和。

## 4. 综合评分：5/10

相较 R1 的 4/10，端点、Service health、policyless 空串、路由 merge、gateway 环境透传及目标粒度 probe 已有实质修订。
但 readiness adoption 和既有 demo schema 仍是阻塞性闭环缺口。
恢复身份、快照、撤销、状态面和 scheduler 接线仍不足以证明安全且可重放。
修订稿尚未达到可进入 Apply 的条件。
