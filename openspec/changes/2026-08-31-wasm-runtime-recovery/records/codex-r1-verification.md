# Codex review-plan R1 逐条核验（ZCode，2026-08-31）

对 `codex-r1-review-plan.md` 的 13 条结论逐条亲自查证后的判定与处置。
核验方法：直接读 codex 引用的文件:行 + 对照 `openspec/specs/` 现行法条原文。

## 判定总表

| 条目 | 判定 | 依据摘要 |
| --- | --- | --- |
| B1 ABI 代际自相矛盾 | **不成立** | 现行 spec 有意双代际并存：catalog/matrix 层 V1 标签 `1.0.0`（specs :51/:69/:129/:140/:526/:531/:1114），execution-rpc/activation 层 service V2 标签 `1.1.0`（specs :328/:918/:937）。wasmd `wire.rs:37` 注释明言「Service-enabled V2 uses hostABI 1.1.0; V1 keeps 1.0.0」；`capability.rs` reserve 匹配的 `artifact_matches` 刻意不含 hostABI（代际标签不参与身份匹配）。实现与法条一致，演示全链路跑通。delta 系 MODIFIED 全文复刻，未引入矛盾。 |
| B2 probe 端点 404 | **属实（真 blocker）** | supervisor `wasm-shared.ts:81` `READINESS_PATH="/iweb-health"`；wasmd `ingress.rs:32` 只应答 `GET /healthz`（:174 匹配）。gw ingress 网关纯字节转发不改写路径。真实链路 probe 必 404 → 永不采纳 → Kernel 无从铸 lease。演示未暴露因 probe 缺省关 + owner 手工铸 lease。 |
| B3 health wire 断裂 | **属实（真 blocker）** | wasmd `main.rs:187` 唯一产出 `WasmReadinessHealthV2::from_identity`（base 形态，ABI `1.0.0`，无 `hostServicePolicyDigest`；golden 见 `wire.rs:438`）；supervisor `wasm-executor.ts:1180` 先 `validateServiceReadinessHealthV2`（要求 Service 形态 ABI `1.1.0` + policy pin），base 形态必 `WASM_EXECUTION_WIRE_INVALID`。即使端点修好，wire 也不匹配。与 B2 合并为「readiness 链路双重断裂」，D3 前提缺失。 |
| B4 proof schemaVersion 2 vs 1 | **既有偏差，非本变更引入** | 现行 spec `AdmissionProofV1` 本来就是 `schemaVersion: 2`（specs :258/:266，two-tier-runtime-trust 归档法条）；Rust 实现 `wasm_admission.rs:801/:818` 要求 1。实现自洽（生成与消费同为 1）故演示未暴露。delta 复刻现行法条无误。处置：文稿声明既有偏差 + tasks 5.1 顺带对齐（或明确另行变更）。 |
| B5 query wire 未闭合 | **已覆盖（task 3.1 即此工作）** | contracts/TS/Rust 现状为旧是事实，但那正是 task 3.1 的实现内容；delta :212 已定义 null/fresh-probe/身份语义。采纳其细化建议：tasks 3.1 显式列出 `packages/contracts/wasm-execution.ts` 键集与 `wasm_commands.rs` 解析同步触点。 |
| M1 probe 晚到无代次绑定 | 合理细化，采纳 | design D1 锁协议补「应用前比对快照代次（controlRevision/route generation/完整 P/E fence），失配即丢弃」；tasks 1.3 增交错测试。 |
| M2 预算 exactly-once 未定义 | 合理细化，采纳 | design D2 补记账协议：attempt 键 = 恢复 command ID（outbox 既有幂等键），先持久 reserve 后提交；tasks 2.4 对应。 |
| M3 越限无 execution 级事件 | 部分属实，采纳为澄清 | wasmd 为 per-request 引擎模型（`host.rs:3-10`：每请求新 Store+新实例，epoch/fuel 超限终止该请求、进程与执行存活）。spec 法条「exceeds an engine limit」触发器在该模型下无 execution 级事件路径。处置：design D2 写明——D1 probe 是统一死亡判据；请求级引擎错误不触发 unavailable（计数经 metrics 可见）；「执行级引擎限」仅当表现为进程死亡/不可服务时由 probe 判死收敛。 |
| M4 merge 无原子协议 | 大体已覆盖，采纳补充 | `RouteStore::persist`（routes.rs:184-190）已是原子 tmp+rename；tasks 4.1 已定启动装载点。补：tasks 4.1 明确「监听器启动前执行一次」与并发注册语义。 |
| M5 R2 激活来源未定 | 部分采纳 | design 明示 R2 为实现批次内开放问题（有意安排）。采纳其可验证性批评：tasks 6.1 前固定「激活来源决策记录进 design（R2 收敛）」。 |
| M6 gateway dir 不透传 | **属实，采纳** | `iweb-entrypoint.sh:535-560` supervisor_env allowlist 无 `IWEB_SANDBOX_GATEWAY_DIR`；supervisor `wasm-ingress-gateway.ts:19` 与 Kernel `proxy.rs:275` 均读该 env。非默认目录时两侧寻址分裂。低成本修复：allowlist 加一项（+ 法条一句对齐说明）。 |
| M7 D0 无 TOCTOU/hash 校验 | 合理细化，采纳 | Kernel 消费投影时重读并比对 `capabilityRecordRevision/Hash` 与 pin（对位既有 `verify_admission_node_identity` 每次重读模式）；design D0 补写。 |
| m1 首启坏种子组合未定义 | 属实，采纳 | registry 缺失 + seed 存在但不可解析的组合未定语义。定为 fail-closed 启动失败（无有效系统路由不是合法节点态），spec delta 补句 + tasks 4.3 补组合测试。 |

## 综合判定

- 真 blocker：B2+B3（readiness 链路双重断裂，合并为一个前置任务组：统一 health 端点 + wasmd Service 形态产出 + golden vectors + 真实链路验收）。
- 既有偏差声明：B4。
- 任务/设计细化：B5/M1/M2/M3/M4/M5/M7。
- 新增小任务：M6。
- spec delta 修正：m1（组合语义补句）。
- 驳回：B1（双代际为有意设计，非矛盾）。

评分 4/10 的主因（「producer/consumer/durable state 未闭环」）部分源于审对象错位——change 的 tasks 本就负责把现状推进到 delta；但 B2/B3 是 tasks 确实遗漏的真前置缺口，codex 的核心价值成立。

## 流程教训（应于后续复审采用）

给 codex 的 review 请求必须附带：(1) 前置子代理复核报告文件；(2) 「现状 vs 目标」的错位警示（delta 描述目标态，tasks 负责弥合）；(3) 双代际等既有有意设计的背景注记。否则 codex 会从零重探并误报任务已覆盖项。
