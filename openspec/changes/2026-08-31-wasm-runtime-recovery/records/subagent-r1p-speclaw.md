# R1' spec-law 复审（subagent，2026-08-31）

- 审阅人：spec-law 子代理（独立于 ZCode 主线与 codex-r1p-eng）
- 审阅对象：commit `e13b7b4` 后的 change 五文件（proposal/design/tasks/两个 delta），对照
  `openspec/specs/wasm-application-runtime/spec.md`（1136 行现行法）与
  `openspec/specs/workspace-and-routes/spec.md`，并抽查实现证据
  （`kernel-rs/wasmd/src/{capability,wire,main,ingress}.rs`、`kernel-rs/iweb-kernel/src/wasm_runtime.rs`、
  `packages/contracts/wasm-health.ts`、`supervisor/wasm-shared.ts`、`config/wasm/*.json`）。
- 方法：先读 `records/codex-r1-review-plan.md` 与 `records/codex-r1-verification.md`；对全部
  MODIFIED 条款做机械化全文 diff（非目测）；对 B1/B2/B3/B4 的驳回或采纳证据逐条亲查源码。

## 总判定：1 blocker / 2 major / 6 minor

修订整体质量高：五个 MODIFIED 条款经机械 diff 证明均为「全文复刻 + 有意增改」，无一处
无意漂移；Codex B2/B3（readiness 双重断裂）、B4（既有偏差声明）、m1（首启坏种子）的
吸收忠实且落点正确；B1 驳回的核心结论成立。但新增的两条 ADDED 条款中，lease 铸造触发
条件使用了与 fence 状态机矛盾的词汇（blocker），两条 ADDED 的比对字段来源句均有可
指认的缺陷（major）。以下分级列出。

---

## Blocker

### BL-1 lease 铸造触发条件「whose fence is preparing」与 fence 状态机自相矛盾

- 证据（delta `specs/wasm-application-runtime/spec.md` ADDED「Kernel mints readiness leases
  from adopted readiness」首句）："For a version whose start is applied and whose fence is
  preparing, the Kernel convergence loop reads the supervisor's readiness adoption record…"。
- 对照实现与法条词汇：`wasm_runtime.rs` `fence_from_planned_start(…, "preparing")`（:2529/:2654）
  在 start 命令规划期建档 `lifecycle:"preparing", alive:false`；start acknowledgement 应用后
  `project_start_fence_alive`（:2422-2446）把该记录翻为 `alive:true, lifecycle:"ready"`
  （幂等护栏 `if record.alive || record.lifecycle != "preparing" { return }` 证明 preparing
  仅存在于 start-ack 投影之前）。因此「start is applied ∧ fence is preparing」只在中断
  窗口（ack 投影与 fence 投影两段持久写之间，由 `heal_acknowledged_start_fences` 收口）
  成立；稳态下「已启动、未激活、等待铸造 lease」的候选 fence 一律是 `ready+alive`。
- 后果：按字面实现，稳态候选不满足触发条件 → Kernel 永不铸 lease → 本变更要修的缺口 2
  （「readiness lease 无生产签发面」）在法条层面复现。同条款自己的 scenario
  （"Deployment reaches activation without owner-minted leases"）要求 mint 发生在 owner
  激活之前（即 fence ready 稳态），与触发条件字面直接冲突——同一 requirement 内
  normative 文本与 scenario 互相矛盾。
- 根因：design.md D3 用了同一短语（「applied start + fence preparing 且未激活」），delta
  原样继承；tasks 3.2 未复用该条件（只说 exact-match），说明是 design/delta 层的措辞
  错误而非既定语义。
- 修复建议：触发条件改为按状态语义表述，例如 "For a version whose start is applied and
  which is not yet activated (fence alive, lifecycle preparing or ready)"；design.md D3 同步
  改写。顺带建议（可与 minor MN-5 合并处理）：fence 记录/台账（alive、lifecycle:
  preparing|ready|active）目前只有实现无法条，本条款与 liveness 条款都直接引用它，宜在
  liveness 条款内用一句话最小定义所依赖的 fence 记录字段。

---

## Major

### MJ-1 两条 ADDED 条款的比对字段来源句遗漏 capability pin 的载体

- 证据（delta ADDED「Kernel observes execution liveness…」）："comparing every field
  (… capability pin …) against the Kernel fence record joined with that version's registry
  row, **which together carry every named field**"。ADDED「Kernel mints readiness leases…」
  同句式："when the adoption identity equals the fence and registry facts field-for-field"。
- 对照持久形状：`WasmFenceRecordV1`（`wasm_runtime.rs:941-971`）14 键中无
  capabilityRecordRevision/Hash；控制态版本行（现行 spec :466）字段集为
  `{versionId,identity,packageDigest,normalizedPolicy,lifecycle,runtimeBinding,
  admissionProofRef,admissionProofDigest,readinessLeaseDigest}`，同样无 capability pin。
  pin 位于 admission proof（经 admissionProofRef 间接可达）与 outbox start 命令。
- design.md D1 的三元 join 是正确表述：「fence 记录 ⋈ 版本 registry 行/outbox start
  命令（联合携带全部比对字段：…/capability/…）」；tasks 1.2 亦如此。delta 落盘时丢掉了
  第三来源并把「两源携带全部字段」写成事实断言——该断言为假。
- 后果：法条要求的逐字段比对中，capability pin 的期望值来源在 cited join 中不存在；
  字面实现者要么无法比对、要么自行引入第三真相源（违背 D1 的单一事实源论证）。
- 修复建议：两条 ADDED 的 join 补上第三来源（对位 design D1：「joined with that version's
  registry row and its outbox start command」），或显式写明 capability pin 经
  admissionProofRef 由 proof 携带。

### MJ-2 reserve 门匹配键「complete runtime binding identity」的字面与实现相悖——字面读法已由生产实证为全量拒绝

- 证据（delta MODIFIED「Kernel-owned admission uses one visible-state predicate」新增段）：
  "the `runtimeReserves` entry for the selected **complete runtime binding identity** plus
  host architecture must exist (no default or zero reserve is substituted)"。
- 对照实现：`wasmd/src/capability.rs:243-257` 注释明言「hostABI 是 wire 代际标签（V2 命令
  1.1.0 ↔ V1 记录 1.0.0），**不参与匹配**——按制品身份逐字段比对（生产实证 2026-08-31：
  全字面量匹配让每个 V2 命令都落到 no-measured-reserve）」；`artifact_matches` 比较七字段
  中的六个（kind/catalogRevision/catalogHash/entryKey/imageDigest/world），刻意排除 hostABI。
  实际记录模板（`config/wasm/node-capability-record.template.json`）reserve 条目 hostABI 全为
  `1.0.0`，而 service 代际 ExecutionCommand 的 binding 是 `1.1.0`。
- 字面冲突链：现行法（spec :241）「for the selected complete runtime binding identity」中
  `RuntimeBindingIdentityV1` 的定义（spec :517-528）把 hostABI 列为字段之一，故「complete
  identity」字面 = 七字段含 ABI；按此字面匹配，每条 policyless 准入都会
  no-measured-reserve 被拒——正是代码注释记录过的生产事故模式。delta 的 D6 前置门把同一
  字面又写进一处新法条。design D6 虽写明「与 wasmd capability.rs 同一语义」「binding 工件
  身份」，但英文法条字母没有体现「ABI 代际标签不参与匹配」。
- 对核验报告的反向修正（B 项）：`codex-r1-verification.md` B1 行称「`artifact_matches`
  刻意不含 hostABI……实现与法条一致」——前半句属实，后半句对 reserve 匹配句不成立：
  法条字面（complete identity 含 ABI）与实现（排除 ABI）恰相悖，实现靠违背字面才可用。
  B1 的最终判定（双代际并存为有意设计、非矛盾）不受影响，但「实现与法条一致」的表述
  应更正。
- 修复建议：在 delta 该段（或能力记录条款的 delta 增补）写明匹配键语义：「runtimeReserves
  匹配按 binding 制品身份（kind/catalogRevision/catalogHash/entryKey/imageDigest/world）加
  架构精确比对，hostABI 作为 wire 代际标签不参与 reserve 匹配（与 wasmd 侧同一语义）」，
  或立法规定 reserve 条目必须以 service ABI 字面量书写。二选一，消灭歧义。

---

## Minor

### MN-1 proposal/tasks 称「新增 service health 条款」，delta 实为并入 MODIFIED readiness 条款

proposal.md Capabilities（:124-126）与 tasks 3.0(d) 都表述为「新增『readiness health 的
service 形态与固定端点』条款」；实际 delta 是修改既有「Wasm readiness is a full identity
attestation」条款纳入双形态与固定端点（无新增 requirement 头）。并入是正确选择（避免
同域双条款），但 change 文档间措辞应一致，否则归档对照时会找不到「新增条款」。建议把
proposal/tasks 措辞改为「修改 readiness 条款以立法 service 形态与固定端点」。

### MN-2 workspace-and-routes delta 缺 fail-closed 组合的 scenario

条款正文已完整定义四种组合（文件在+好种子=upsert；文件在+坏种子=跳过+日志；文件缺+
无种子=fail-closed；文件缺+坏种子=fail-closed，即 m1 修复），tasks 4.3 测试亦齐备；但
scenario 集只新增了持久/升级/冲突三个正向场景，两个 fail-closed 组合与「坏种子跳过」
均无 scenario。m1 是本轮评审专门补的语义，建议至少补「首启坏种子 → 启动失败」一条
scenario，便于归档后独立可读。

### MN-3 首启「可解析但零系统路由」种子与 rationale 句不一致

条款 rationale 写「a node booting without any valid system route is not a legal steady
state」，但规则只对「种子缺失/不可解析」fail-closed；若首启种子可解析却不含任何
`system:true` 行，将 wholesale 装载出空注册表并正常启动，违背所述 rationale。建议要么把
fail-closed 扩为「首启装载后无任何有效系统路由」，要么收窄 rationale 措辞。

### MN-4 base 形态（matrixRevision<2）经命令面不可达，且 base lease 签发者未定义

现行法 ExecutionCommand 的 `matrixRevision` 是字面量 `2`（spec :328），不存在合法的
matrixRevision<2 执行路径（base 形态仅对应 wasmd argv@1 遗留路径）；同时 ADDED 铸造
条款只覆盖 `ServiceReadinessLeaseV2` 的 Kernel 签发，base `ReadinessLeaseV2` 的签发者
在两形态立法后悬空。不是矛盾（防御性 wire 立法与 contracts 双形态现实一致），但建议
一句标注：base 形态/base lease 为 legacy 防御性 wire（无生产签发面），避免读者寻找不
存在的 base lease 发行路径。顺带：「a consumer MUST reject a form that disagrees with
the **fenced** matrix revision」——matrixRevision 在命令身份回显律中属 fence 面，但不在
双代次 fence 身份对象（spec :488-504）七字段内，建议改「commanded matrix revision」
以免与既有 fence 定义混淆。

### MN-5 fence 记录/台账词汇无法条定义

两条 ADDED 条款与 lifecycle 新 scenario（"the fence ledger still records the executions
alive"）都依赖 fence 台账概念（alive、lifecycle: preparing|ready|active），但现行 spec
只定义了 fence 身份元组，fence 记录文件本身是 9e139a3 的实现事实无法条。BL-1 的判定
正是靠读实现代码才可定谳——这本身说明可发现性问题。建议随 BL-1 修复在 liveness 条款
内最小定义 fence 记录的字段与状态词汇（一句话即可）。

### MN-6 design D4 承诺的 GATEWAY_DIR「同值同缺省」法条句未落盘

design.md D4（M6 处置）明言「补入 allowlist 并**在法条写明**『Kernel 与 supervisor 的
gateway 目录 env 语义一致（同值同缺省 /run/iweb-sandbox/gw）』」；两个 delta 均无此句
（grep 证）。liveness 条款以硬编码默认路径 + "resolved by the existing gateway ingress
socket addressing" 间接锚定，可用但未兑现 design 的承诺。建议在 liveness 条款补一句
env 同值同缺省的对齐法。

---

## 四项指定检查的逐项结论

### A. readiness MODIFIED 与现行条款 / lease 条款 / mint ADDED 的自洽性 —— 基本自洽，两处例外

- 机械 diff 证明：MODIFIED readiness 条款的复刻部分零漂移，仅两处有意修改（双形态绑
  定句、mismatch 清单增补 `hostServicePolicyDigest` where the service form applies）+ 两个
  新 scenario；「only in the exact v2 shapes」的复数化是有意的，无失真。
- 与 D3 无冲突：health 面双形态按 matrixRevision 绑定、lease 面双形态按 digest 域分隔
  （`iweb-readiness-lease-v2` "\n" 域 vs `digestV2("iweb-wasm-readiness-v2")` 0x00 域，
  与 contracts :52/:1197 实测一致），激活面消费 service 形态，两侧同一 service/base
  二分，衔接一致。
- 「probe grants a readiness lease only from an exact v2 200」与「Kernel 是唯一生产签发
  面」的潜在张力由 mint 条款第二段的调和句（"the Kernel-side execution of the
  exact-v2-200 probe grant…no other issuance path exists"）显式消解，成立。
- 例外一：mint 条款触发条件的 fence 词汇错误 = BL-1。例外二：mint/liveness 的字段来源
  句 = MJ-1。另见 MN-4（base 形态可达性）。

### B. ZCode 对 Codex B1 的驳回是否站得住 —— 结论站得住，一处佐证表述需修正

- 亲查证据全部支持双代际有意设计：现行法 catalog/matrix/证明层钉 1.0.0（spec :51/:69/
  :140/:526-527/:1114），execution-rpc/activation 层钉 1.1.0（:328/:918）；`wire.rs:33-39`
  注释注明 V2 字面量来源（add-wasm-host-services H1 终裁），:67-69 注明 argv@1→1.0.0、
  argv@2→1.1.0 的 argv 层耦合；kernel golden 控制态同一文件内 version 行 binding 1.0.0
  与 outbox 命令 binding 1.1.0 并存。Codex 把设计状态误读为矛盾，驳回正确。
- 但 `codex-r1-verification.md` B1 行「实现与法条一致」对 reserve 匹配句过头：法条字面
  （complete identity 含 hostABI）与 `artifact_matches`（排除 hostABI）相悖，且代码注释
  记录了全字面量匹配在生产全量拒绝的实证。delta 的 D6 段继承了该字面 → MJ-2。建议核
  验报告措辞更正 + delta 补匹配键语义句。

### C. 修订是否引入新矛盾 / 场景遗漏 / delta 格式问题 —— 格式与复刻全过；新缺陷如上

- 五个 MODIFIED（readiness、lifecycle、lease wire、admission、execution-rpc）+ workspace
  一个 MODIFIED 全部逐行 diff：复刻零漂移、增改均为申明过的意图；标题不变、ADDED/
  MODIFIED 分节合规、scenario 均为 WHEN/THEN 规范形。
- lifecycle 条款保留「dies, exceeds an engine limit, or is declared lost…」三触发并列，
  与 D2/M3 澄清（请求级引擎错误不触发 unavailable、execution 级引擎限经 probe 判死收
  敛）不冲突——法条未说请求级错误触发翻转，机制上统一由 liveness 条款承载，自洽。
- 新引入的规范级缺陷即 BL-1 / MJ-1 / MJ-2；场景遗漏见 MN-2/MN-3。

### D. m1 fail-closed 句与 workspace delta scenario 集是否一致 —— 语义一致，scenario 覆盖不足

四组合 + 首启 wholesale + 冲突用户优先在条款正文、design D4、tasks 4.3 三处口径一致；
唯 scenario 集缺 fail-closed 与坏种子跳过场景（MN-2）。另发现 rationale 边缘缺口
（MN-3）。

## 对既有核验结论的抽查确认（附）

- B2/B3 属实：`wasm-shared.ts:81` `READINESS_PATH="/iweb-health"` vs `wasmd/ingress.rs:32`
  `HEALTH_PATH="/healthz"`（:174 仅匹配该路径）；`wasmd/main.rs:183` 唯一产出 base 形态
  `WasmReadinessHealthV2::from_identity`；contracts `wasm-health.ts:940` health 校验用
  `requireSha256Hex`（不收空串），而激活面已有 `requirePolicyDigestOrEmpty`（:119-124）——
  D8 的三段修复（端点/Service 形态产出/validator 扩空串）与事实完全对位。
- B4 处置妥当：现行法 proof `schemaVersion:2`（spec :258/:266），delta 原样复刻，实现
  1→2 对齐收敛进 task 5.1 并明确「不做 v1 迁移」，声明与任务边界一致。

## 子代理反馈（困难与处理）

1. Codex 报告与核验表大量使用「specs :行号」式引用，行号锚定的是审阅时的文件版本；本
   轮全部改按条文内容定位复核，未直接沿用行号。建议后续送审材料附引文片段而非纯行号。
2. BL-1 的判定无法从 spec 文本单独得出——fence 记录状态词汇（preparing/ready/alive）
   只存在于实现，spec 无从查证（见 MN-5）。这是本次复审最大的摩擦点，也是最具复用
   价值的发现：依赖实现概念的新法条应自带最小定义，否则法条可判性依赖读码。
3. `openspec validate` CLI 本环境不可用，delta 格式按 tasks 7.2 的人工口径核验（已过）。

## 结论

修订方向与 Codex 13 条的吸收质量均可靠，进入 Apply 前需完成：BL-1（mint 触发条件改
写，连带 MN-5）、MJ-1（join 补第三来源）、MJ-2（reserve 匹配键语义句 + 核验报告
「实现与法条一致」表述更正）；六个 minor 可随批处理或声明接受。修完后本 change 的
delta 即达到可归档的法条质量。
