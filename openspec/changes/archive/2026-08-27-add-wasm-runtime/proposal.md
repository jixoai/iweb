<!-- 用户原始需求（2026-08-25）：引入与 celld 同等级的 wasm runtime；调研结论主选 Wasmtime（docs/research/wasm-runtime-selection.md）；Wasmer/WASIX 留观其 9 月 4 日大版本后另议。 -->
<!-- 正交意图：定义 wasm 应用执行形态的制品与能力契约；扩展准入法与版本身份支持 runtime kind；celld 路径与沙箱法零回归。 -->
<!-- R2（2026-08-26）：按 Codex R1（3/10）修复；R3（2026-08-26）：按 Codex R2（4.5/10）闭合 allowlist/digest/秘密时机/catalog/状态机/门控/schema。映射见 design.md。 -->
<!-- R6（2026-08-26）：按 R5（7.0/10）重写 What Changes，闭合 execution transport、双 CAS 持久化、最终 version identity、secrets WIT、双 runtime gate、lease wire 与 grammar。作者：codex-wasm-author，gpt-5.6-terra max。 -->
<!-- R7（2026-08-26）：按 R6（6.0/10）对照真实部署文件，闭合 socket peer auth、per-kind Kernel registry/migration、secret/config snapshot FD handoff、activation/drain replay、catalog history 与 gate startup 接线。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner 评分回落升级政策。 -->
<!-- R8（2026-08-26）：按 R7 复审闭合独立 raw-UDS FD transport、valuesDigest 三方绑定、applicationId/runtimeKind 终身互斥与 WIT import 方向；落档 owner 2026-08-26 最终裁决。作者：codex-wasm-author，gpt-5.6-terra max；终轮硬时限由 owner 设定。 -->

## Why

iweb 的应用执行形态目前只有 celld（JS/TS Workers API）一种，而部署代理产出的应用语言是开放的：Rust/Go 等静态语言没有受支持的出口。WASI 组件模型是 2026 年服务端 wasm 的事实收敛标准（`wasi:http` 被 Wasmtime/Spin/wasmCloud/Fastly 共同采纳，WASI 0.3 已于 2026-06-11 发布）。调研结论（`docs/research/wasm-runtime-selection.md`）：以 Wasmtime + wasi:http 组件为基线，除语言出口外还能获得三项 celld 形态给不了的结构性保证：

1. **出网收敛是能力性的**：不授予 socket 级 WASI 接口，组件出网唯一通道是宿主实现的 `wasi:http/outgoing-handler`——落在「HTTP 转发与 CONNECT 均拨已校验 IP」的网关法条上，且模块无法绕过（celld 场景下 `HTTP_PROXY` 只是合作提示）。
2. **准入期能力校验**：能力矩阵是显式版本化 allowlist；声明与静态发现的传递 imports 闭包必须一致，矩阵外接口（socket、`wasi:tls`、`wasi:filesystem`、未知接口）在物化执行前 fail-closed 拒绝。
3. **引擎级资源强制**：epoch/store 内存上限与 cgroup 限额构成两层边界，所有限额数值来自版本化节点能力记录，缺失即 fail-closed。

## What Changes

- **Wasm 制品与 digest**：严格 `iweb-wasm-oci-layout-v1`（单 index/manifest/config、非空且无重复的 typed layers、精确 media type、raw-byte hash/size、无未引用 blob、JCS JSON）。`wasmPackageDigestV1` 和 `wasmVersionDigestV1` 是自包含的 `hex(SHA-256(bytes))` 算法，明确不复用 celld 的自定义 `versionDigest`；规范附带可复算 vector。
- **能力矩阵与闭包**：能力记录 revision 1 精确锁定 `wasi:http/proxy@0.2.8`（官方 Releases 最新 patch 注记）、WIT package→interface→direction 规范化、嵌套/re-export/adapter 闭包解析和稳定错误码；`iweb:config@1.0.0` 与 `iweb:secrets@1.0.0` 都只提供逐版本 allowlist 的 `store.get`，权限、snapshot 和负向错误向量固定。
- **最终准入身份与业务权威**：`AdmissionProofV1` 同时绑定 package/version digest、完整 `versionId = digest-sequence`、sequence、normalized policy、runtime binding、capability pin 和 token hash；Kernel 以严格隔离的 `runtimeKind:"wasm"` registry 保存 binding/proof 引用和 active pointer，并以跨 registry CAS 将每个 `applicationId` 终身绑定单一 runtime kind（换 kind 必须新 ID）；现行 celld `VersionRecord`/validator、sequence/generation 不被 wasm 解析或复用。
- **单一可见性与恢复**：Kernel 维持唯一 `AdmittedVisible` 谓词，覆盖 object marker、hidden/visible DB row、materializer receipt 的每个中断点和 GC。Kernel 业务/版本/路由权威不变；supervisor journal 只是受 command/fence 约束的执行事务日志。
- **独立执行 RPC 与真实 socket 认证**：celld 继续专用 `POST /v1/rpc`；wasm 使用 `POST /v1/execution-rpc` 的 `iweb-execution-rpc-v1` envelope，未知协议拒绝不降级。supervisor 以 `iweb-sandbox` 身份创建固定 `0600` HTTP socket，Kernel 当前以 root 连接，双端用 `SO_PEERCRED`、inode/path 检查和 command/ack CAS 双向授权；v1 明确假设宿主 root 是可信主体，`0/0` 不能区分其它 root，非 root Kernel 需新修订；替代路径和 TCP 均拒绝。秘密/config FD 只在独立的 `/run/iweb-sandbox/snapshot-fd.sock` `AF_UNIX/SOCK_SEQPACKET` raw transport 传递，绝不与 HTTP 连接混用。独立 `wasm-control-state-v2.json` 提供 `controlRevision`、command outbox、journal `command-received/completed`、query/replay wire 与三段 CAS 恢复，和现行 celld `ControlStateFile` 物理隔离。
- **运行时绑定/catalog/发布门**：typed catalog revision/hash、entry 唯一键、owner CAS、active/rollback 保留、CVE revoke 与 release/delete 流程；catalog 历史有固定 revision/index/release/delete audit wire。启动同时评估 celld v1 和 wasm v2 gate，由 Kernel `runtimeKind` 精确选择并返回 reasons；两者使用不同 acceptance record 路径、开关和 validator，互不启用。
- **代次、readiness、metrics、生命周期**：固定 `(sandboxId, versionId, preparationGeneration, executionGeneration)` schema、初值/单调/CAS/fencing；readiness v2 携完整 package/binding/catalogRevision 与 32-hex lease nonce；metrics 携 preparationGeneration，`unavailable`/fuel `null`/重启首样本语义闭合；`retiring` 仅 supervisor execution substate，Kernel 仍写既有 `retired`。
- **秘密/config 交接与安全边界**：Kernel secret/config store→supervisor journal 的锁序和线性化点固定，`SnapshotRefV1` 一一映射 Kernel snapshot；`valuesDigest` 同时写入 Kernel command、独立 raw-UDS handoff 和 wasmd 校验链，FD 通过 `SCM_RIGHTS` 只读传递，具备 ACL、TTL 与崩溃恢复。owner mutation 的 keys/values 键集完全相等，v1 值类型最终锁定为 `string`。`iweb:config@1.0.0` 与 `iweb:secrets@1.0.0` 的 world 均以 `import store` 表示 host 提供语义。连续 rotation 只接受最大 revision；值不进入 journal/包/URL/环境/日志。wasmd 只经网关出网、受信宿主在已验证连接终结 TLS、宿主 limits 来自 typed node capability record。
- **激活、Drain 与历史恢复**：`ActivationCommandV1`/`RouteEventV1`/`LeaseConsumeRecordV1` 提供 owner API 的 query/replay 与单 CAS 线性化；`DrainReceiptV1` 在 Kernel 写 `retired` 前确认完整 execution identity、drained count、deadline 和 forced-kill 时间。catalog revision 固定路径保留，release receipt、恢复 index、GC 与 deletion audit 使 CVE/release 可重放。
- **兼容边界**：不修改现行 celld validator、`/v1/rpc`、`ControlStateFile` 或 celld publication gate 的语义；wasm 运行时未完成独立 Linux 拓扑验收与 reserve/acceptance 证据前，发布门保持关闭。

## Capabilities

### New Capabilities

- `wasm-application-runtime`：wasm 应用执行形态契约——沙箱法继承、能力矩阵 allowlist、OCI 布局制品与两阶段闭包准入、canonical digest 公式、runtime catalog 与版本身份绑定、对等拓扑与固定命令契约、宿主中介出网与 TLS、节点记录驱动的宿主限额、引擎级限额、生命周期状态机、宿主注入配置与 `iweb:secrets`、通用可用性、引擎指标 schema、kind 绑定发布门。

### Modified Capabilities

- `application-sandbox`：准入要求扩展 runtime kind 与 wasm 包形状；imports 越出能力矩阵或声明与发现闭包不一致成为结构化拒绝的合法理由（拒绝时零物化、零执行、零版本变更）。

## Non-goals

- 不改 Kernel 路由/host 法、网关拓扑、supervisor 生命周期法（wasm 与 celld 共用同一沙箱法；contracts/supervisor 需要 runtime kind 接线扩展，但网络与恢复拓扑不变）。
- 不引入 WASIX/Wasmer 形态（其 2026-09-04 大版本发布后另行评估，如需将作为独立 runtime kind 提案）。
- 不在本变更内定义 Durable Objects 等**有状态** wasm 等价物（后续独立 capability）。
- 不承诺语言分级支持：制品契约语言无关；v1 参考工具链为 Rust（`wasm32-wasip2`）、TS（ComponentizeJS）与 MoonBit（固定 `moon 0.1.20260824`、`wit-bindgen 0.57.1`），Go/Python 支持留给后续变更按需评估。
- 不引入外部 OCI registry 拉取、镜像仓库凭证或新的包上传面（复用现行准入通道）。
- 不向组件暴露 `wasi:tls`、socket 级接口或文件系统投影。
- 不承诺 wasm 与 celld 的性能/内存对比结论（容量决策按「节点实测」法另行执行）。

## Owner 已裁决（2026-08-26，最终决策）

1. **Q1 TLS**：宿主终结。组件只见 `wasi:http`；出站 TLS 由受信 `iweb-wasmd` 在网关已验证的连接上终结并负责 SNI/证书校验；`wasi:tls` 不暴露。
2. **Q2 值类型**：`iweb:secrets@1.0.0` 与 `iweb:config@1.0.0` 的 v1 值类型均为 `string`，不再是暂采项。
3. **Q3 排序**：`typescript-monorepo` 归档后本变更才开工；实现期不得绕过该序门。
4. **Q4 world**：v1 仅 `wasi:http/proxy@0.2.8`；0.3 由后续变更显式触发，不设日历截止。
5. **Q5 MoonBit**：MoonBit 升为第三个参考工具链，与 Rust/TypeScript 同等；fixture 固定 `moon 0.1.20260824` 与 `wit-bindgen 0.57.1`。
6. **Q6 拓扑**：接受 v1 现状：Kernel 以 root 连接，supervisor 以 `iweb-sandbox` 运行。v1 信任假设是宿主 root 为可信主体；`SO_PEERCRED=0/0` 无法区分 Kernel 与其它 root 进程；非 root Kernel 必须走新 socket-auth 契约修订。
7. **终轮硬时限（已执行）**：R8 终审 7.4/10，无全新范围 P0，3/4 最小闭合集判定闭合；唯一收尾 P0（legacy celld kind-claim bootstrap）与 P1（快照过期语义不一致）已按评审最小闭合文本直接落笔入 spec，评审循环按硬时限规则关闭，不再开启评审轮。

实现门槛（不是待决）：每个 `linux/amd64`、`linux/arm64` binding 的 wasmd reserve 仍须有真实节点能力实测；没有记录前发布门保持关闭。

## 序门（Apply 前置）

1. 对抗评审闭环：R1（3.0）→ R2（4.5）→ R3（6.0）→ R4（5.5）→ R5（7.0）→ R6（6.0）→ R7（6.5）→ R8（7.4，无全新范围 P0）；两项收尾（kind-claim bootstrap、快照过期窗口语义）已入 spec，循环关闭。实现与真实 Linux 证据是 Apply 后的 fail-closed 实测门。
2. Owner 最终裁决已于 2026-08-26 落档；Q3 序门在 `typescript-monorepo` 归档前不得开工。
3. reserve 实测和 acceptance record 仍是发布门的客观证据要求；缺失时保持 fail-closed。
