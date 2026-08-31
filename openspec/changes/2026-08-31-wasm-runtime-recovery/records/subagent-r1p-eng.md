# 工程可行性复审 R1'（subagent-eng，2026-08-31）

- 对象：openspec change `2026-08-31-wasm-runtime-recovery` @ commit `e13b7b4`（main）修订后的
  `design.md`（D8/D1/D2/D0）与 `tasks.md`（3.0/1.2/2.2）。
- 方法：只读代码核验（不跑 cargo/bun），逐条对照 design/tasks 的可行性声明与实现现状的
  文件:行证据；B2/B3 双断裂做了独立复核。
- 约束遵守：仅写本文件；无 git 操作；无重负载命令。

## 总判定：PASS（无 blocker；1 项 major + 6 项 minor，均为文稿/任务边界修订，不动摇设计骨架）

四个审阅点全部核验通过：A（D8）可行、B（D1）落点清晰、C（D2）与既有 outbox 机器可拼、
D（tasks 3.0 测试）可落地。major 项是 D8 文法对齐在 metrics 姊妹族上的遗漏——修复成本
极低（一行换既有助手函数），但按 change 自己声明的「policyless 空串闭环」口径应当补上，
否则 3.0 收口后会留下一个与 B3 同构、且当天即可触发的断裂。

## 判定总表

| 审阅点 | 判定 | 摘要 |
| --- | --- | --- |
| A. D8 可行性 | 成立，1 major + 2 minor | wasmd argv 确有 policy digest 可供 Service 形态产出；「policyless=空串」与激活面文法真一致；READINESS_PATH 单点修改影响面=2 文件；validator 扩空串不破坏既有测试。但 design/tasks 把解析位置写错为 wire.rs（实为 argv.rs + host_services/policy.rs），且 metrics 族同文法未同步。 |
| B. D1 晚到结果代次绑定 | 清晰，1 minor + 1 实现注记 | 收敛循环（http.rs:245-256，std Mutex + 10s tick）与快照素材（control state + fences file）俱在；「锁内快照→锁外探测→重取锁比对」两段锁的自然落点存在。比对谓词粒度需澄清（controlRevision 是全局计数器）。 |
| C. D2 记账协议 | 成立，1 minor | outbox 追加即持久 controlRevision CAS（authorize_command），投递在其后独立进行——「先持久 reserve 再发令」可直接拼装；attempt 键=prepare command ID 与 outbox commandId 唯一性/幂等重放语义吻合；(P+1,E+1)/(P+1,E+2) 与 planner 双迁移函数逐字吻合。孤儿 reserve 键的终态语义需 design 补名。 |
| D. tasks 3.0 测试 | 可落地 | bun 侧 probe 的 fetch/载荷均可注入直调（既有测试同款模式）；Rust golden 模式现成（wire.rs 既有 999 字节 golden + contracts example 函数）。措辞 minor 一项。 |

---

## Major

### M-1 metrics 族 policyless 空串文法未纳入 3.0(c)（D8 同族遗漏，当天可触发）

**证据**：

- `packages/contracts/wasm-health.ts:1079`：`requireServiceEngineMetricsV2` 对
  `hostServicePolicyDigest` 用 `requireSha256Hex`（只收 64-hex，不收空串）——与
  `:940` 的 `requireServiceReadinessHealthV2` 完全同款、同错。
- `supervisor/wasm-executor.ts:1302`：`sampleWasmEngineMetrics` 把
  `current.hostServicePolicyDigest`（policyless 执行为 `""`，来源
  `wasm-executor.ts:179` 由命令 echo）直接填进 `ServiceEngineMetricsV2`；`:1317`
  自我校验失败后降级路径 `:1321-1323` 用同一字段再校验同样失败 → **返回 null**。
  即：policyless wasm 执行的 supervisor metrics 采样今天恒为 null，`/v1/execution-metrics`
  对其恒 404（`supervisor/server.ts:106-113`）。
- 对照激活面：`wasm-health.ts:119-125` 的 `requirePolicyDigestOrEmpty` 已存在并被
  lease（:1270）/activation（:1526）/route event（:1698）/rollback（:1811）四处使用；
  Rust 侧 `wasm_commands.rs:353-360` `validate_policy_digest` 同文法（空串或 64-hex）。
  health/metrics 是仅剩的两个未对齐的消费面，3.0(c) 只修了 health。

**影响**：不修则 3.0 收口后 readiness 链路通、metrics 链路对 policyless 应用仍断裂；
D7 状态面与 monitor 的「engine 指标诚实投影」对 policyless 应用退化为永久无样本。

**修复建议**：tasks 3.0(c) 扩为「`validateServiceReadinessHealthV2` 与
`validateServiceEngineMetricsV2` 两处 `hostServicePolicyDigest` 均换
`requirePolicyDigestOrEmpty`」（各一行，helper 现成）；spec delta 的 service wire
条款若提及 metrics 族文法则同步一句。测试侧 `tests/wasm-engine-metrics.test.ts`
增一条 policyless 空串采样通过断言即可。

---

## Minor

### m-1 policy digest 解析位置的文件归因错误（design.md D8 / tasks.md 3.0(b)）

**证据**：design D8 写「argv 已携带 policy digest，`wasmd/src/wire.rs` argv 解析已有
该字段」；tasks 3.0(b) 同句。事实：`wasmd/src/wire.rs` 全文无 policy 字段（grep "policy"
零命中）；policy digest 的真实解析在 `wasmd/src/argv.rs:131-139`（argv[10] →
`WasmdHostServicesContextV2`）与 `wasmd/src/host_services/policy.rs:156-161`
（`HostServicePolicyV2.policy_digest`，:181-191 已定义「空串=精确零值策略」合法形态）。
main.rs 消费点 `:107`（`invocation.host_services`）与 `:183`（health 构造）同作用域，
D8(b) 的 producer 改造落点真实存在，只是文件名写错。

**修复建议**：两处文稿改为 `wasmd/src/argv.rs`（context 在
`host_services/policy.rs`），避免实现子代理在 wire.rs 里找不存在的字段。

### m-2 「Rust golden 向量重制」措辞可能诱导删除 base 形态 golden

**证据**：argv@1（base 代际）仍保留 base `WasmReadinessHealthV2` 产出路径
（wire.rs `from_identity`、golden `wire.rs:434-441` 999 字节向量）；D8 只是把
service 代际（argv@2）升为 Service 形态。tasks 3.0(b)「Rust golden 向量重制」未说明
是「新增 Service golden 与 `exampleServiceReadinessHealthV2`
（wasm-health.ts:2239）对齐、base golden 保留」。

**修复建议**：tasks 3.0(b) 措辞改为「新增 Service 形态 golden（与 contracts
example 逐字节对齐）；base 形态 golden（argv@1 路径）不动」。

### m-3 kernel metrics 拉取侧 V1-only 校验 vs supervisor V2 产出——既有断裂未声明（B4 同类）

**证据**：kernel `metrics.rs:303-304` `validate_wasm_engine_metrics_v1` 要求
`schemaVersion` 恒 1；supervisor 采样产出的是 `ServiceEngineMetricsV2`
（schemaVersion 2，`wasm-executor.ts:1297`），`server.ts` 原样返回、无降维转换。
即拉取链若接线，任何 wasm 执行的样本都会被 kernel 拒绝。当前生产无周期 poller
（`supervisor.rs:408` 的 pull 仅 http.rs:35 注记提及、未见调用方），断裂是潜伏的。

**修复建议**：按 B4 先例在 design「现状与证据」声明为既有偏差，并在 tasks 里二选一：
（a）本变更顺带把 kernel 拉取校验升 V2（对位 metrics.rs 的 V2 validator）；或
（b）明确记为后续变更，避免 D7 验收时被当成本变更回归。

### m-4 D1 晚到结果比对谓词的粒度需澄清（controlRevision 是全局计数器）

**证据**：design D1「锁内快照携带每目标的 `controlRevision`…任一漂移即丢弃该轮结果」。
`WasmControlStateFileV2.control_revision`（wasm_runtime.rs:1355）是全局单调计数器，
任一无关 owner 操作（另一应用 admission/outbox）都会推进它；逐字面实现会把所有目标
的整轮 probe 结果因无关变更而丢弃（活跃节点上频繁空转）。真正的漂移信号是每目标的
route generation（`WasmApplicationControlRecordV1.route_generation:1338`）与完整执行
身份（fence 记录 :941-975）。

**修复建议**：design D1 澄清为「逐目标比对 route generation + 完整执行身份；
controlRevision 仅作快照序（可选）」，或在 tasks 1.2 写明按目标粒度应用丢弃。

### m-5 D2 孤儿 reserve 键（reserve 落盘后、outbox append 前崩溃）终态语义未命名

**证据**：design D2 记账协议声明「先 reserve 再发令…漏计不可能、双计不可能」，但
sidecar 写与 outbox CAS（`authorize_command` + `save_control_state`，
wasm_runtime.rs:2577-2589 模式）是两个落盘动作，中间崩溃留下「有键无命令」的孤儿
reserve。重放时该键按「已存在即不重复计数」会被永久计入窗口（保守方向的过量计数，
安全但未声明）。tasks 2.4 的「reserve 后崩溃」三态测试会逼出该决策，design 未先给名。

**修复建议**：design D2 补一句：「reserve 落盘即计为一次已消耗尝试（保守过量，
方向安全）；重放对孤儿键不重发、不复活」——与 2.4 测试断言对齐。

### m-6 D1 实现注记：锁模型与 probe 并发方式

**证据**：收敛锁是 `std::sync::Mutex<WasmRuntime>`（http.rs:196），现有 10s 任务在
锁内做阻塞 socket 投递（http.rs:250-254，design 已声明维持现状）。新 probe 序列
（快照→放锁→并发探测→重取锁）中：探测必须以独立阻塞线程/tokio spawn_blocking 在锁外
执行（std Mutex 非异步感知）；重取锁可能排队在一次锁内投递轮之后——与 design
「容器重启场景持锁时长与现状持平」的声明一致，非新增风险，但实现子代理应知晓。

**修复建议**：tasks 1.2 验收标准可加一句「probe 阶段不得持有收敛锁（代码评审项）」。

---

## 逐项核验证据

### A. D8 可行性

1. **argv 确有 policy digest 供 Service 形态产出**：argv@2 第 11 元素 =
   `WasmdHostServicesContextV2`（argv.rs:131-139），含 `hostServicePolicy.policy_digest`
   （policy.rs:156-161）；policyless 执行由 supervisor 以
   `WASM_EMPTY_HOST_SERVICE_POLICY_V2`（wasm-host-policy.ts:420）零值策略 spawn
   （wasm-executor.ts:711-715；wasm-spawn.ts:28-36 注明单一命令形态恒 argv@2），
   wasmd 侧 `HostServicePolicyV2::validate` 精确接受「空串+全 null 服务+零资源」形态
   （policy.rs:181-191）。producer 侧数据齐备，无需新 argv 元素。
2. **health 产出落点**：main.rs:183 `WasmReadinessHealthV2::from_identity` 是唯一
   产出点；ingress 以预序列化字节应答 `GET /healthz`（ingress.rs:32/:174-183），
   改 Service 形态=main.rs 单点构造替换（`invocation.host_services` 同作用域可用，
   main.rs:107）。argv@2 窄化的 `invocation.identity.runtime_binding` 已携带
   ABI 1.1.0（wire.rs `to_v1` 原样克隆），与 Service 形态 binding V2
   （wasm_commands.rs:258-273，七字段同形、仅 ABI 字面量不同）JCS 字节一致。
3. **「policyless=空串」与激活面文法一致**：wasm-health.ts:119-125 注释与
   `requirePolicyDigestOrEmpty` 即激活面文法；lease/activation/route/rollback 四处
   已用；Rust `validate_policy_digest`（wasm_commands.rs:353-360）同文法。3.0(c)
   把 health 校验换成该 helper 即闭环（M-1 要求 metrics 同步）。
4. **READINESS_PATH 影响面**：全仓 grep 仅 `supervisor/wasm-shared.ts:81`（定义）与
   `supervisor/wasm-executor.ts:1137`（唯一使用）。无测试断言旧路径 `/iweb-health`；
   delta 法条已写死 `GET /healthz`（specs/wasm-application-runtime/spec.md:72/:92-93）。
   单点修改声明属实。
5. **validator 扩空串不破坏既有消费方**：`validateServiceReadinessHealthV2` 消费方=
   supervisor correlate（wasm-executor.ts:1186，先 wire 校验再比对，顺序与 D8 声明
   一致）+ golden 测试（wasm-host-services-golden.test.ts:640，用非空 digest example）。
   `correlateServiceReadinessHealthV2`（wasm-health.ts:1012）是相等比对，双空串成立。
   既有测试无「health 空串必须被拒」的负例（wasm-health-contracts.test.ts 空串正例
   只覆盖 lease/activation/route/rollback :584-607）。`correlateServiceReadinessLeaseV2`
   （:1580）同为相等比对，不受影响。
6. **B2/B3 独立复核**：wasm-shared.ts:81 `/iweb-health` vs ingress.rs:32/:174
   `/healthz`；gw 网关纯字节转发不改写路径（wasm-ingress-gateway.ts:1-9 模块头、
   proxy.rs:299 同一 socket 契约）；main.rs:183 唯一产出 base 形态 vs supervisor
   correlate :1186 先过 Service 校验——双重断裂属实，D8 方向正确。

### B. D1 晚到结果代次绑定的落点

- 收敛循环：http.rs:245-256（10s tick、`std::sync::Mutex`、现状锁内投递）。
- 快照素材：`load_control_state()`（wasm_runtime.rs:1854）一次返回
  (control state, registry file, applications)——controlRevision（:1355）、每应用
  route_generation（:1338）、active 指针、版本行俱备；`load_fences_file()` 给执行身份
  （WasmFenceRecordV1:941-975：sandbox/version/P/E/secret/config）；
  outbox start 命令在 `state.command_outbox`。design「fence ⋈ registry 行/outbox
  start 命令」的联合快照可一次锁内组装。
- 重取锁比对位置：同一 tokio 任务两次 `lock()` 之间放锁探测；重取后再次
  `load_control_state` + `load_fences_file` 做逐目标比对。结构清晰，无需新锁原语。
- 谓词粒度见 m-4；锁模型注记见 m-6。

### C. D2 记账协议与既有机器的可拼性

- **「先持久 reserve 再发令」可拼**：outbox 追加本身即持久 controlRevision CAS
  （`authorize_command` wasm_commands.rs:1076-1098：CAS 校验 + commandId 唯一性
  fail-closed + revision+1；调用方随继 `save_control_state` 落盘，
  wasm_runtime.rs:2577-2589 现行模式），网络投递是其后独立循环（run_outbox_delivery
  :4157）。恢复编排=同一锁内「unavailable CAS → sidecar reserve（键=将铸的
  command ID）→ plan+authorize+save」三步，天然满足「reserve 先于任何投递可能」。
- **attempt 键=command ID 成立**：commandId 由 Kernel 铸（`generate_uuid_v7`，
  wasm_runtime.rs:2550）且 outbox 全局唯一（:1085-1087）；重放幂等既有语义
  （journal_observation_from_query 按 commandId 冲突拒绝，wasm_commands.rs:821-838；
  重复 append 抛 `EXECUTION_OUTBOX_DUPLICATE_COMMAND`）。键即命令身份，孤儿键问题
  收敛为 m-5。
- **双代次数字吻合**：`prepare_generation_transition`：(P,E)→(P+1,E+1)
  （wasm_commands.rs:194-204）；`execution_generation_transition`：(P,E)→(P,E+1)
  （:207-220）。死亡执行 (P,E) 的恢复=prepare (P+1,E+1)、start (P+1,E+2)——
  design D2.3 与 planner 语义逐字一致。
- **secret snapshot 复用**：`ensure_initial_secret_snapshot(proof, P, now)` P 已
  参数化（wasm_runtime.rs:2289-2293）。
- **sidecar 先例**：retirements（paths.retirements()）与 journal-head-hint 即
  「v2 控制态 spec-exact 键集之外」的既有持久面，模式可复制。
- 恢复重放定位在途尝试应按键（sidecar 键→outbox commandId 精确查找），不要复用
  `reconcile_visible_execution_state` 的按 version+operation 无代次扫描
  （wasm_runtime.rs:2513-2517——同版本多次恢复合法存在多代 prepare，该扫描会错认
  旧代命令）；attempt 键机制本身已解决此点，建议 tasks 2.2 实现触点注明。

### D. tasks 3.0 测试可落地性

- **bun mock `/healthz`**：`probeWasmExecutionReadiness`（wasm-executor.ts:1124-1157）
  的 `options.fetch`/`options.sleep` 可注入——测试可注入 fetch stub 断言 URL 以
  `/healthz` 结尾（端点命中），无需真实 socket；`correlateReadinessHealthV2`
  （:1177-1194）可直调载荷对象做 wire/correlate 全字段断言。既有同款模式：
  tests/wasm-serve.test.ts:536-552（probe 配置）、tests/wasm-execution-executor.test.ts
  :202-281（correlate 直调 example 载荷）。
- **policyless 空串 wire 校验**：构造 `{...exampleServiceReadinessHealthV2(),
  hostServicePolicyDigest: ""}`（example 函数在 wasm-health.ts:2239）过
  `validateServiceReadinessHealthV2` 即可断言（contracts 改后）。
- **wasmd cargo golden**：模式现成——wire.rs:434-441 现有 base golden（999 字节、
  注明「由 bun 现场生成后固化」）；Service golden 同法新增（见 m-2 措辞）。
- 3.0(d) 的 spec delta 已含 `/healthz` 法条与 policyless 空串场景
  （specs :72/:89-93），与测试要求对齐。

---

## D0 抽查（顺带）

- 「gate-node-identity.json 今天无任何写入者」属实：全仓引用仅 kernel 测试 fixture
  （wasm_runtime.rs:5523/:5997、kernel-rs 集成测试）；生产代码只读
  （startup :1576、:3106）。
- 现结构 `GateNodeIdentityFileV1`（wasm_runtime.rs:1124-1140）只 pin 架构+各 hash，
  无 runtimeReserves/restart——D0 schema 2 的增量空间与 fail-closed 装载点明确。

## 困难与解决方式（子代理反馈协议）

1. **大文件定位**：wasm-executor.ts/wasm_runtime.rs/wasm-health.ts 均超千行，无法整读。
   解决：先用 grep 锁定行号（READINESS_PATH、policyDigest、authorize_command、
   converge），再按 offset 精读；全部结论附文件:行。
2. **metrics 拉取是否已接线**：`supervisor.rs:408` 的 pull 函数在 http.rs/monitor.rs
   grep 不到生产调用方（仅注释提及「客户端…喂入」）。解决：按「潜伏断裂」降级定性
   （m-3 声明即可），不判为生产事故，避免过度升级严重度。
3. **「wire.rs 已解析 policy digest」声明的证伪**：grep wire.rs 无 policy 字段后，
   顺 argv[10] 找到真实解析链（argv.rs → host_services/policy.rs），确认是文稿归因
   错误而非可行性缺口（m-1）；producer 落点（main.rs:183 + host_services）真实存在。
4. **不跑测试的代价**：无法实证「扩空串后 bun 套件全绿」。缓解：逐条核对既有测试的
   断言方向（正例用非空 digest、无 health 空串负例），把「不破坏既有语义」的判定
   建立在断言语义而非执行结果上；建议 3.0 实现批跑一次 bun test 复核本判定。
