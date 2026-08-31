# Codex review-plan R1（2026-08-31）

- Agent: herdr `wasm-review-plan`（gpt-5.6-terra / xhigh），workspace `zcode-iweb-wasm-recovery`
- 用时：2h33m（含其内部子代理协作层；主会话曾陷入等待循环，经收口指令后输出）
- 结论原文如下，未删改；ZCode 的逐条核验与处置见 `codex-r1-verification.md`

## 阻塞问题（blocker）

1. Wasm ABI 代际在变更法条内自相矛盾 / 证据：变更 spec :51-53、:68-70 将 config/normalized manifest 的 hostABI 固定为 iweb-wasmd-abi@1.0.0，且 ConfigRuntimeProjectionV1 要求字节一致；同一文件 :208 又要求 ExecutionCommand 的 runtime binding 为 iweb-wasmd-abi@1.1.0。/ 修复建议：先确定唯一 ABI 代际，统一 config、manifest、capability matrix、runtime binding、health wire、acceptance record、digest vectors 和 producer/consumer；为混用版本增加明确拒绝测试，不能靠兼容分支掩盖冲突。

2. Readiness probe 端点无法获得 exact v2 200 / 证据：supervisor/wasm-shared.ts:79-81、supervisor/wasm-executor.ts:1137 请求 /iweb-health；wasmd 仅处理 /healthz，见 kernel-rs/wasmd/src/ingress.rs:31-32,173-182；supervisor/wasm-ingress-gateway.ts:1-7,90-118 只是字节转发，不改写路径。默认 probe 因此不能成功，Kernel 无法铸造 readiness lease。/ 修复建议：统一唯一 health endpoint，并在真实 relay → wasmd 链路上验证 exact v2 200、非 200、EOF、连接后 reset 和 body 上限。

3. Readiness producer/consumer wire 不兼容 / 证据：wasmd 生成 WasmReadinessHealthV2，ABI 为 1.0.0 且不含 hostServicePolicyDigest，见 kernel-rs/wasmd/src/wire.rs:238-295、kernel-rs/wasmd/src/main.rs:182-189；supervisor 只接受 ServiceReadinessHealthV2、ABI 1.1.0 和 policy digest，见 supervisor/wasm-executor.ts:1172-1193、packages/contracts/wasm-health.ts:884-990。/ 修复建议：把 Rust producer、TS validator、共享 contracts、golden vectors 和真实节点验收列为同一迁移批次，明确拒绝旧 wire，不能只修改 supervisor 侧。

4. Admission proof 持久格式升级没有迁移闭环 / 证据：变更 spec :117-139 要求 AdmissionProofV1.schemaVersion:2 和 lifecycleAdmissionRecord.schemaVersion:2；当前 kernel-rs/iweb-kernel/src/wasm_admission.rs:800-825,1077-1108 仍只验证并生成 schema version 1。tasks 5.1-5.2 只覆盖 witness/join 状态转移，没有 proof、journal、marker、DB row、receipt、registry 和既有 demo 数据的迁移或明确拒绝策略。/ 修复建议：定义 v1 持久数据的迁移、只读兼容或 fail-closed 方案，并为每个 witness 和 recovery replay 提供版本化 golden fixture；在此之前不能声称既有版本可恢复。

5. readinessAdoption query wire 未闭合 / 证据：变更 spec :212 将 query-result 改为精确包含 readinessAdoption；现有 packages/contracts/wasm-execution.ts:984-1017 仍是旧精确键集，Rust 解析仍在 kernel-rs/iweb-kernel/src/wasm_commands.rs:743-807，TS producer 仍在 supervisor/wasm-control.ts:697-708 返回旧对象。/ 修复建议：先定义带 sandbox/version/P/E fence、digest、freshness 和 null 语义的共享类型，再同步 Rust parser、TS producer、supervisor handler、Kernel consumer、replay/query tests；字段缺失或身份不匹配必须 fail closed。

## 主要问题（major）

1. 锁外 probe 的晚到结果没有 CAS 代际绑定 / 证据：design.md:62-67 只要求"快照 → 放锁探测 → 重取锁应用计数/翻转"，没有要求比较原始 controlRevision、route generation、完整 P/E fence 与当前值；tasks.md:45-47 也没有 probe 与 activation/recovery 交错测试。/ 修复建议：probe 结果必须携带并校验原始 control revision、route pointer generation、sandbox/version/binding/secret/config/P/E 全 fence；任一变化即丢弃结果，并增加旧 probe 晚到、新 execution 已激活的并发测试。

2. restart budget sidecar 缺少 exactly-once 记账协议 / 证据：design.md:79-94 仅规定 sidecar、窗口滚动和"崩溃重放不双计"，未定义 durable attempt ID、唯一键、记账顺序，以及预算写入与 unavailable CAS/outbox 的崩溃原子关系。/ 修复建议：定义以原始 fence/目标 fence/command ID 为键的持久 attempt 状态机，明确 reserve、commit、replay、rollback 和每个崩溃点；验证不会漏计导致超预算，也不会双计导致提前 stopped。

3. "越引擎限"没有 Kernel 可消费的生产事件路径 / 证据：设计 :79-94 将 engine-limit 与进程死亡并列恢复；但现有 kernel-rs/wasmd/src/host.rs:381-390 主要产生单请求错误/计数，计划没有定义 wasmd → supervisor → Kernel 的 execution-level termination 事件、分类或 fence 投影。/ 修复建议：定义并实现可认证的 execution-limit event/ack，区分请求被拒绝与 execution 被终止，写入同一生命周期投影，并用真实 fuel/epoch/store 超限场景验收自动 unavailable 和恢复。

4. 路由 seed merge 没有落到确定的启动接线和原子写入协议 / 证据：当前 kernel-rs/iweb-kernel/src/routes.rs:107-120 的 RouteStore::load 仍是只读装载并可能 panic，scripts/iweb-entrypoint.sh:367-370 仍无条件覆盖路由；变更 design.md:129-145、tasks.md:79-89 没有明确 merge 调用点、临时文件/fsync/rename、并发锁和崩溃恢复语义。/ 修复建议：指定在监听器启动前执行一次 merge，采用原子替换并定义失败退出条件；补充首启、升级、写入中断、并发注册和 malformed seed 场景。

5. 同版本自动重激活仍是会改变权限边界的开放问题 / 证据：design.md:89-91 要求恢复后仍需 lease + activation，design.md:197-203 又把 owner activation 与 Kernel 自动 activation 留作 R2；tasks.md:116-123 的真实验收没有固定激活来源。/ 修复建议：在 spec/tasks 中明确唯一权威：owner command 或 Kernel recovery command；定义审计来源、CAS、重放和 unavailable 的最终状态，不能把核心生命周期行为留到实现批次临时决定。

6. 可配置 gateway 路径不会完整传入 supervisor / 证据：design.md:53-55 使用 IWEB_SANDBOX_GATEWAY_DIR，但 scripts/iweb-entrypoint.sh:535-555 的 supervisor 环境 allowlist 未包含该变量。非默认目录下 Kernel 与 supervisor 可能寻址不同，所有 probe 都会表现为 socket missing。/ 修复建议：统一环境变量 allowlist、默认值和启动日志，并加入非默认 gateway 目录的真实节点测试。

7. D0 能力投影缺少不可篡改的 pin/TOCTOU 验证 / 证据：design.md:39-49 只要求从 IWEB_SANDBOX_WASM_CAPABILITY_RECORD 计算 projection；现状 design.md:21-23 说明 Kernel 仅持有 hash/架构投影。计划没有规定 Kernel 如何重新计算并校验完整 recordHash、revision、架构和 reserve 条目，也没有记录读取与 spawn 之间的变更处理。/ 修复建议：定义 canonical projection hash 和原子快照，admission、prepare、recovery 均校验同一 revision/hash；增加篡改、替换和读取期间变更的 fail-closed 测试。

## 次要问题（minor）

1. 首启 malformed seed 的最终启动语义未定义 / 证据：变更 spec :6 同时规定 malformed seed "跳过"和 registry+seed 缺失时 fail-closed；没有说明 registry 缺失但 seed 存在且不可解析时是否启动空注册表。tasks.md:87-89 也未覆盖该组合。/ 修复建议：明确"无有效系统路由即启动失败"或另一确定语义，并加入组合测试。

## 综合评分：4/10

方案识别的缺口方向基本正确，也坚持了 Kernel 路由权威和 wasm 引擎边界。
但 readiness、query、ABI 和 admission 持久格式在现有 producer、consumer 与 durable state 上均未形成可执行闭环。
恢复并发、预算 exactly-once、越限事件和路由启动接线仍停留在概念描述，无法由当前 tasks 得到可验证实现。
在修复 blocker 并收敛上述 authority/CAS 细节前，不具备进入 Apply 的条件。
