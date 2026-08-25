<!-- 用户原始需求（2026-08-25）：为 iweb 引入与 celld 同等级的 Wasmtime wasm runtime，不能削弱既有沙箱与 Kernel 恢复权威。 -->
<!-- 正交意图：先交付可互操作 contracts/向量；再接 Kernel-supervisor-runtime；最后以真实 Linux 拓扑验收；显式登记 owner/环境门槛。 -->
<!-- R5（2026-08-26）：Codex 接手后按 R4 的 authority/digest/generation/transaction/wire 缺口重排。作者：codex-wasm-author，gpt-5.6-terra max。 -->
<!-- R6（2026-08-26）：按 R5（7.0/10）补 execution transport、control revision/outbox、proof versionId、secrets WIT、双 gate、lease nonce 与 grammar 任务。作者：codex-wasm-author，gpt-5.6-terra max。 -->
<!-- R7（2026-08-26）：按 R6（6.0/10）补真实 socket peer auth、per-kind migration、snapshot FD handoff、config、activation/drain、catalog history、gate wiring 的独立 wire-vector/crash-recovery 任务。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner 评分回落升级政策。 -->

# add-wasm-runtime Tasks

> 开工序门：`typescript-monorepo` 的 contracts/protocol 迁移完成，或 owner 书面分配 `manifest/records/desired-state/sandbox-spec/protocol` 的文件 owner。所有 **契约先行**项必须先有 validator、canonical encoder 和跨实现向量，后续宿主代码不得自行解释字段。

## 1. 契约、identity 与准入（契约先行）

- [ ] 1.0 **R6/R7 transport/persistence boundary**：实现 `iweb-execution-rpc-v1` 的 `/v1/execution-rpc` envelope、固定 socket 双端 peer auth 与 query/replay；建立独立 `wasm-control-state-v2.json`、`controlRevision` CAS、outbox 和 `wasm-execution-journal-v1`，证明 celld `/v1/rpc` 与 `ControlStateFile` 不被降级解析或原地迁移，并接入 runtime-kind registry/migration receipt。

- [ ] 1.1 **wasm 制品 digest 契约**：实现 `wasmPackageDigestV1` / `wasmVersionDigestV1` 的 RFC 8785 encoder、OCI strict-subset validator 和向量。覆盖 `oci-layout`、index、唯一 manifest、descriptor、config、所有 layer、未引用 blob、重复 digest、空 artifact、media type、大小/hash 不匹配、raw JSON 非 JCS、config runtime projection↔admission-manifest runtime 不一致；证明它从不调用现行 `versionDigest`。
- [ ] 1.2 **wasm manifest 与 generation schema**：在 `packages/contracts` 定义 `NormalizedWasmManifestV1`、`RuntimeBindingIdentityV1`、`WasmExecutionIdentityV1`、health v2 和 metrics v1 的 unknown-field-rejecting validator/encoder；证明 wasm manifest 不接受 celld `assets`/`entrypoint` 或执行权字段。向量覆盖初始 `(P=1,E=1)`、no-execution `E=0`、CAS 失败、旧 tuple、以及“celld sequence/generation 不可作为 wasm generation”。
- [ ] 1.3 **revision 1 capability matrix 与闭包 scanner**：把 `wasi:http/proxy@0.2.8` 的精确 `{package,interface,direction}`/host ABI、`iweb:config@1.0.0` 与 `iweb:secrets@1.0.0` WIT 定义和错误码表落入 contracts。实现由 Component Model type identity 驱动的嵌套 component/core module/re-export/adapter traversal；测试唯一内部解析、歧义、未解析、cycle、adapter host import、预算超限、声明集合不等于发现集合。
- [ ] 1.4 **runtime catalog 与 node capability record v1**：实现 JCS hash、entryKey、revision CAS、sorted/no-duplicate validation、owner update protocol 与 round-trip vectors。测试 reserve 与同一 binding+arch 的 `resources.memoryBytes` 均以 bytes 比较，缺失/不等/`reserve >= memoryBytes` 均 fail-closed。
- [ ] 1.5 **Kernel-owned admission transaction**：实现 admission journal、opaque commit token hash、含完整 `versionId`/`sequence`/`normalizedPolicy` 的 `AdmissionProofV1`、到现行 `VersionRecord`/active pointer 的 projection、`AdmittedVisible` predicate 和 idempotent materializer receipt。逐点故障测试：staging 失败、部分 blob、marker 无 DB、DB 事务失败、DB 成功但 handoff 未发/ack 丢失、ack 后 final DB flip 失败、lease 过期、请求响应丢失、并发同 proof；验证 restart replay 或 GC 的唯一结果。

## 2. Kernel 与 supervisor 执行协议

- [ ] 2.1 **权威协议**：Kernel 生成 owner-authorized `commandId`、expected control/journal revision、full tuple 与 typed completion acknowledgement；supervisor journal 仅接受幂等 execution commands，不能铸 version 或改 route pointer。实现 query/replay ack，使 journal 完成而 Kernel projection 失败时只有 replay 可发生、绝不先路由。
- [ ] 2.2 **双 generation fencing**：Kernel 在每次 prepare 分配单调 `preparationGeneration`，每次进程 spawn/restart/rebind 分配单调 `executionGeneration`；gateway/wasmd/readiness/metrics 均精确比对 tuple + binding。验证 active pointer 切换后旧 execution 可以 drain，但不得接受新流量或报告为新 execution。
- [ ] 2.3 **secrets rotation 线性化**：实现 app mutation fence → Kernel secret-store revision commit/outbox → supervisor sandbox journal fence 的固定锁序；journal 只存 revision/opaque reference。覆盖每个 crash 点、ack 丢失和连续两次 rotation，验证最终只接受最大 revision 的 candidate，active snapshot 保留到下一次激活。
- [ ] 2.4 **通用激活 gate**：按 `application-sandbox` delta，在 Kernel route CAS 事务内再次检查 readiness lease 未过期；rollback event 持久化目标 runtime binding identity。覆盖 lease 恰在 CAS 中过期、candidate killed、route CAS conflict 与旧 active 保留。

## 3. iweb-wasmd 与 gateway 接线

- [ ] 3.1 **固定启动契约**：构建 digest-pinned `iweb-wasmd`，由 supervisor 独占生成 argv、snapshot FD handoff、listener、gateway 地址和 limit；manifest 中 image/command/mount/capability 一律拒绝。Linux 双容器实测 listener 与 gateway ingress 一致。
- [ ] 3.2 **host capability 与资源强制**：实现矩阵中唯一的 wasi host imports、gateway-only outgoing handler、TLS/SNI/证书验证、store limits、epoch 与可选 fuel。所有 HTTP/request/response/header/concurrency/staging/restart/drain 限额必须来自 pinned capability record；CVE-2026-27887 无界响应只失败该请求。
- [ ] 3.3 **readiness health v2**：gateway 从 wasmd 固定内部 health endpoint 校验而非由配置合成；只在实际 ingress 可达且已加载精确 package digest、binding（含 catalogRevision/hash）、capability pin、secretRevision 及 P/E 时返回 health。对 sandbox/version/package/binding/capability/secret/P/E 任一错配返回内部 mismatch，probe 不签发或采纳 lease；celld health v1 保持独立解析路径。
- [ ] 3.4 **生命周期执行**：ready 后激活前被杀保留旧版；active crash 先进 `unavailable`、为 recovery 依次推进 P/E、按 restart budget 重备；activation 后旧 execution drain 至 deadline 后强杀。验证 no double-routing、no stale health/metrics adoption、无影响相邻沙箱。

## 4. 发布与观测

- [ ] 4.1 **metrics v1**：实现完整 identity（含 `secretRevision`、`configRevision/configSnapshotRef` 与 `preparationGeneration`）和 availability union；所有字段必须出现，fuel disabled 唯一表示为 `null`，未有首样本唯一表示为 `unavailable`。验证 counter/high-water 在同 E 内非负单调、E 变更才可重置、out-of-order/unknown/mismatch 一律拒绝。
- [ ] 4.2 **catalog 生命周期与 CVE 流程**：实现 active/rollback/prepare 引用扫描、release version 的 owner 流程、revoke 不删除、阻断新 prepare/activation/rollback、显式 migrate-or-stop 处置和 release 后可删。测试历史 binding 可审计，已释放 entry 可删。
- [ ] 4.3 **发布门 v2**：实现 Kernel release 固定路径的 unknown-field-rejecting acceptance record validator、JCS self-digest 计算及逐字段 gate；拒绝环境变量重定向、runtime/app mount 提供的伪记录。覆盖 malformed identity、digest 不匹配、catalog/capability/arch 不匹配、v1 不能开 wasm、v2 wasm 不能开 celld，以及显式开关和固定镜像验收记录双条件。
- [ ] 4.4 **Admin/monitor projection**：只向 owner 投影 engine 与 cgroup 的不同口径；visitor 仍只见 generic unavailable。projection 读取 Kernel 权威状态，不把 supervisor journal 当 route authority。

## 5. 真实路径验收

- [ ] 5.1 Linux 双网络沙箱：恶意 imports、nested/re-export/adapter、socket/TLS/filesystem、DNS rebinding、redirect、HTTPS CONNECT 全按网关已验证 IP 路径抓包验证；无共享 slirp、代理变量或 host-loopback 绕过。
- [ ] 5.2 Linux 双容器 lifecycle matrix：marker/DB/materializer 中断点、lease-CAS 过期、journal/projection failure、rotation crash matrix、连续 rotation、runtime image rebind、old execution drain 和 all tuple mismatch 全部可复现。
- [ ] 5.3 arm64/amd64 reserve 实测：冷启动、ready、首编译、稳态并发、最大响应、epoch kill 峰值写入 node capability record；没有对应实测记录的 binding/arch 保持关闭。
- [ ] 5.4 全套验证：`bunx openspec validate add-wasm-runtime --strict`、contracts/supervisor/kernel 的定向测试、真实 Linux 证据；只有 owner 可创建 acceptance record、同步/归档或启用发布。

## 6. R6 接缝验证

- [ ] 6.1 **secrets WIT 与 owner mutation**：落入固定 `iweb:secrets@1.0.0` schema、key grammar、allowlist/snapshot/value digest、错误向量和 owner CAS；验证无枚举、无值泄漏、连续 rotation 只接受最大 revision。
- [ ] 6.2 **readiness/lifecycle grammar**：实现 `ReadinessLeaseV2` nonce/digest/consume/replay，统一 applicationId 63 字符与 versionId 无前导零 sequence；验证 lease 在 CAS 中过期、nonce 重放、supervisor-only retiring 与旧 execution drain。
- [ ] 6.3 **digest/gate compatibility vectors**：加入单次 `hex(SHA-256(bytes))` 术语和 R6 vector；验证 celld v1 与 wasm v2 acceptance record 路径/开关/validator 互不启用。

## 7. R7 真实接缝与恢复向量

- [ ] 7.1 **socket auth wire + crash vector**：在 Linux 真实 `iweb-sandbox-supervisor.service` 拓扑中验证 supervisor UID/GID 创建固定 `/run/iweb-sandbox/supervisor.sock`、mode `0600`、Kernel `0/0` peer、双端 `SO_PEERCRED`/inode/path 检查；覆盖 wrong UID、symlink/alternate path、inode replacement、supervisor restart、HTTP body 未解析即拒绝与 command/query/replay 零副作用。
- [ ] 7.2 **per-kind registry/migration wire + crash vector**：实现 `WasmKernelRouteRegistryV1`、`runtimeKind`/binding/proof refs 和 `MigrationRecordV1`/receipt；用当前无 `controlRevision` 的 celld `ControlStateFile` 生成 `sourceRevision:0` 向量，覆盖 target 写入丢 receipt、source digest 冲突、目标校验失败 quarantine、幂等 replay、active pointer 不变与 celld parser 隔离。
- [ ] 7.3 **SnapshotRef wire + crash vector**：为 secret `SnapshotRefV1`、allowlist mutation、keys/values exact set、值长度、digest 和固定 `SCM_RIGHTS` 只读 FD handoff 生成正/负向量；覆盖 source rename 前后、fd-before-start、Kernel/supervisor crash、TTL 过期、rotation 期间旧 active fd 保留、未知 ref 与 kind 交叉。
- [ ] 7.4 **iweb:config wire + crash vector**：为 `iweb:config@1.0.0` WIT、config allowlist/snapshot、`configRevision/configSnapshotRef` exact binding、负向错误向量和固定只读 FD handoff 生成独立测试；覆盖 keys/values 不等、stale CAS、expired/missing ref、owner mutation crash、config/secret ref 交叉和 restart replay。
- [ ] 7.5 **ActivationCommand/route-event/replay wire + crash vector**：实现 `iweb-wasm-activation-v1` envelope、`expectedRouteGeneration` CAS、`LeaseConsumeRecordV1`、`RouteEventV1` query/replay；覆盖 response lost、partial lease marker、route/event 同一 control CAS、stale nonce、rollback binding、重复 activation 不递增 generation。
- [ ] 7.6 **DrainReceipt wire + crash vector**：实现 `DrainReceiptV1`/`drainReceiptDigest`，验证 drained request count、deadline、forced-kill 时间与完整 execution identity；覆盖 receipt 丢失、stale execution、deadline 强杀、重复 replay、Kernel 仅在 receipt projection 后写 `retired`。
- [ ] 7.7 **Catalog history/recovery/GC wire + crash vector**：实现固定 revision/history/index/release-receipt/delete-audit 路径和 digest；覆盖 index 损坏重建、revision 文件缺失、active/rollback/CVE 引用保护、release retention、GC 与新 rollback CAS 竞态、删除审计缺失 fail-closed。
- [ ] 7.8 **dual publication gate wiring vector**：将现行 `kernel/application-publication-gate.js` 作为 celld adapter，与 wasm v2 fixed-path validator 在启动时并行评估；验证 `PublicationGateSetV1` reasons wire、runtime-kind selector、双开/单开、v1 不能开 wasm、v2 不能开 celld、环境变量路径重定向和 malformed record 均无 fallback。
