<!-- 用户原始需求（2026-08-25）：引入与 celld 同等级的 wasm runtime；调研结论主选 Wasmtime（docs/research/wasm-runtime-selection.md）；Wasmer/WASIX 留观其 9 月 4 日大版本后另议。 -->
<!-- 正交意图：定义 wasm 应用执行形态的制品与能力契约；扩展准入法与版本身份支持 runtime kind；celld 路径与沙箱法零回归。 -->
<!-- R2（2026-08-26）：按 Codex R1（3/10）修复；R3（2026-08-26）：按 Codex R2（4.5/10）闭合 allowlist/digest/秘密时机/catalog/状态机/门控/schema。映射见 design.md。 -->
<!-- R6（2026-08-26）：按 R5（7.0/10）重写 What Changes，闭合 execution transport、双 CAS 持久化、最终 version identity、secrets WIT、双 runtime gate、lease wire 与 grammar。作者：codex-wasm-author，gpt-5.6-terra max。 -->
<!-- R7（2026-08-26）：按 R6（6.0/10）对照真实部署文件，闭合 socket peer auth、per-kind Kernel registry/migration、secret/config snapshot FD handoff、activation/drain replay、catalog history 与 gate startup 接线。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner 评分回落升级政策。 -->

## Why

iweb 的应用执行形态目前只有 celld（JS/TS Workers API）一种，而部署代理产出的应用语言是开放的：Rust/Go 等静态语言没有受支持的出口。WASI 组件模型是 2026 年服务端 wasm 的事实收敛标准（`wasi:http` 被 Wasmtime/Spin/wasmCloud/Fastly 共同采纳，WASI 0.3 已于 2026-06-11 发布）。调研结论（`docs/research/wasm-runtime-selection.md`）：以 Wasmtime + wasi:http 组件为基线，除语言出口外还能获得三项 celld 形态给不了的结构性保证：

1. **出网收敛是能力性的**：不授予 socket 级 WASI 接口，组件出网唯一通道是宿主实现的 `wasi:http/outgoing-handler`——落在「HTTP 转发与 CONNECT 均拨已校验 IP」的网关法条上，且模块无法绕过（celld 场景下 `HTTP_PROXY` 只是合作提示）。
2. **准入期能力校验**：能力矩阵是显式版本化 allowlist；声明与静态发现的传递 imports 闭包必须一致，矩阵外接口（socket、`wasi:tls`、`wasi:filesystem`、未知接口）在物化执行前 fail-closed 拒绝。
3. **引擎级资源强制**：epoch/store 内存上限与 cgroup 限额构成两层边界，所有限额数值来自版本化节点能力记录，缺失即 fail-closed。

## What Changes

- **Wasm 制品与 digest**：严格 `iweb-wasm-oci-layout-v1`（单 index/manifest/config、非空且无重复的 typed layers、精确 media type、raw-byte hash/size、无未引用 blob、JCS JSON）。`wasmPackageDigestV1` 和 `wasmVersionDigestV1` 是自包含的 `hex(SHA-256(bytes))` 算法，明确不复用 celld 的自定义 `versionDigest`；规范附带可复算 vector。
- **能力矩阵与闭包**：能力记录 revision 1 精确锁定 `wasi:http/proxy@0.2.8`（官方 Releases 最新 patch 注记）、WIT package→interface→direction 规范化、嵌套/re-export/adapter 闭包解析和稳定错误码；`iweb:config@1.0.0` 与 `iweb:secrets@1.0.0` 都只提供逐版本 allowlist 的 `store.get`，权限、snapshot 和负向错误向量固定。
- **最终准入身份与业务权威**：`AdmissionProofV1` 同时绑定 package/version digest、完整 `versionId = digest-sequence`、sequence、normalized policy、runtime binding、capability pin 和 token hash；Kernel 以严格隔离的 `runtimeKind:"wasm"` registry 保存 binding/proof 引用和 active pointer，现行 celld `VersionRecord`/validator、sequence/generation 不被 wasm 解析或复用。
- **单一可见性与恢复**：Kernel 维持唯一 `AdmittedVisible` 谓词，覆盖 object marker、hidden/visible DB row、materializer receipt 的每个中断点和 GC。Kernel 业务/版本/路由权威不变；supervisor journal 只是受 command/fence 约束的执行事务日志。
- **独立执行 RPC 与真实 socket 认证**：celld 继续专用 `POST /v1/rpc`；wasm 使用 `POST /v1/execution-rpc` 的 `iweb-execution-rpc-v1` envelope，未知协议拒绝不降级。supervisor 以 `iweb-sandbox` 身份创建固定 `0600` socket，Kernel 当前以 root 连接，双端用 `SO_PEERCRED`、inode/path 检查和 command/ack CAS 双向授权；替代路径和 TCP 均拒绝。独立 `wasm-control-state-v2.json` 提供 `controlRevision`、command outbox、journal `command-received/completed`、query/replay wire 与三段 CAS 恢复，和现行 celld `ControlStateFile` 物理隔离。
- **运行时绑定/catalog/发布门**：typed catalog revision/hash、entry 唯一键、owner CAS、active/rollback 保留、CVE revoke 与 release/delete 流程；catalog 历史有固定 revision/index/release/delete audit wire。启动同时评估 celld v1 和 wasm v2 gate，由 Kernel `runtimeKind` 精确选择并返回 reasons；两者使用不同 acceptance record 路径、开关和 validator，互不启用。
- **代次、readiness、metrics、生命周期**：固定 `(sandboxId, versionId, preparationGeneration, executionGeneration)` schema、初值/单调/CAS/fencing；readiness v2 携完整 package/binding/catalogRevision 与 32-hex lease nonce；metrics 携 preparationGeneration，`unavailable`/fuel `null`/重启首样本语义闭合；`retiring` 仅 supervisor execution substate，Kernel 仍写既有 `retired`。
- **秘密/config 交接与安全边界**：Kernel secret/config store→supervisor journal 的锁序和线性化点固定，`SnapshotRefV1` 一一映射 Kernel snapshot，采用同一 peer-auth UDS 上的 `SCM_RIGHTS` 只读 FD handoff、ACL、TTL 与崩溃恢复；owner mutation 的 keys/values 键集完全相等，值暂采 string。`iweb:config@1.0.0` 与 `iweb:secrets@1.0.0` 均为完整 allowlist WIT。连续 rotation 只接受最大 revision；值不进入 journal/包/URL/环境/日志。wasmd 只经网关出网、TLS 在已验证连接终结、宿主 limits 来自 typed node capability record。
- **激活、Drain 与历史恢复**：`ActivationCommandV1`/`RouteEventV1`/`LeaseConsumeRecordV1` 提供 owner API 的 query/replay 与单 CAS 线性化；`DrainReceiptV1` 在 Kernel 写 `retired` 前确认完整 execution identity、drained count、deadline 和 forced-kill 时间。catalog revision 固定路径保留，release receipt、恢复 index、GC 与 deletion audit 使 CVE/release 可重放。
- **兼容边界**：不修改现行 celld validator、`/v1/rpc`、`ControlStateFile` 或 celld publication gate 的语义；wasm 运行时未完成独立 Linux 拓扑验收、owner 对暂采项裁决前，发布门保持关闭。

## Capabilities

### New Capabilities

- `wasm-application-runtime`：wasm 应用执行形态契约——沙箱法继承、能力矩阵 allowlist、OCI 布局制品与两阶段闭包准入、canonical digest 公式、runtime catalog 与版本身份绑定、对等拓扑与固定命令契约、宿主中介出网与 TLS、节点记录驱动的宿主限额、引擎级限额、生命周期状态机、宿主注入配置与 `iweb:secrets`、通用可用性、引擎指标 schema、kind 绑定发布门。

### Modified Capabilities

- `application-sandbox`：准入要求扩展 runtime kind 与 wasm 包形状；imports 越出能力矩阵或声明与发现闭包不一致成为结构化拒绝的合法理由（拒绝时零物化、零执行、零版本变更）。

## Non-goals

- 不改 Kernel 路由/host 法、网关拓扑、supervisor 生命周期法（wasm 与 celld 共用同一沙箱法；contracts/supervisor 需要 runtime kind 接线扩展，但网络与恢复拓扑不变）。
- 不引入 WASIX/Wasmer 形态（其 2026-09-04 大版本发布后另行评估，如需将作为独立 runtime kind 提案）。
- 不在本变更内定义 Durable Objects 等**有状态** wasm 等价物（后续独立 capability）。
- 不承诺语言分级支持：制品契约语言无关；v1 参考工具链仅 Rust（`wasm32-wasip2`）与 TS（ComponentizeJS 产出同一组件制品），Go/Python 支持留给后续变更按需评估。
- 不引入外部 OCI registry 拉取、镜像仓库凭证或新的包上传面（复用现行准入通道）。
- 不向组件暴露 `wasi:tls`、socket 级接口或文件系统投影。
- 不承诺 wasm 与 celld 的性能/内存对比结论（容量决策按「节点实测」法另行执行）。

## Owner 待决（R3 暂采建议值，Apply 前裁决）

1. **TLS 终结位置**：暂采宿主终结（组件只见 `wasi:http`；wasmd 经网关 CONNECT 拨已校验 IP 并负责 TLS/SNI/证书校验；`wasi:tls` 不进能力矩阵）。
2. **wasmd 内存 gate 与 runtime reserve**：先测后定、未定不发布（未实测架构 fail-closed 已写入契约）；实测矩阵含 arm64/amd64 × 冷启动/ready/首编译/稳态并发/最大响应/epoch kill 峰值。
3. **world 窗口**：v1 仅 0.2 proxy world；0.3 开放由后续变更触发，拒绝码与 owner 可见迁移状态进契约，不设日历截止。
4. **宿主 key/value 类型**：独立 `iweb:secrets`（不走 `iweb:config/store` 承载秘密）与 `iweb:config` 的 WIT、allowlist、snapshot、错误向量已固定；值暂采 `string`，Apply 前由 owner 最终裁决。
5. **与 `typescript-monorepo` 的排序**：暂采「其 contracts/protocol 迁移完成后开工本变更」；若需并行，先书面固定文件 owner 与协议 revision 交接。

## 序门（Apply 前置）

1. 对抗评审闭环：R1（3/10）→ R2（4.5/10）→ R3（6.0/10）→ R4（5.5/10）→ R5（7.0/10）→ R6（6.0/10）；本 R7 规范已逐项处理 R6 的 P0/P1 接缝，但实现与真实 Linux 证据仍是 Apply 前置。
2. Owner 对待决项 1-5 给出最终裁决（或确认暂采值）。
3. 实现开工前与 `typescript-monorepo` 的文件交叠处理方式已确认（manifest/records/desired-state/sandbox-spec/protocol 存在直接交叠）。
