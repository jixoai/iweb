<!-- 用户原始需求（2026-08-25）：技术决策必须可追溯到一手调研，评审与 owner 裁决落到同一张决策表。 -->
<!-- 正交意图：固化 Wasmtime 基线；明确 Kernel 与 supervisor 的权威边界；固定可互操作的 v1 wire/制品记录；登记 owner 待决与评审闭环。 -->
<!-- 不可调和原因：本 Change 的制品、执行、控制与观测契约必须一起决定，不能在不新增 capability 的前提下拆成独立设计文件；细节由两个 delta spec 分担。 -->
<!-- R5（2026-08-26）：按 R4（5.5/10）直接修订。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner「评分回落时由 Codex 接手」政策。 -->
<!-- R6（2026-08-26）：按 R5（7.0/10）闭合 5 个 P0 与 3 个 P1 接缝。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner 升级政策。 -->
<!-- R7（2026-08-26）：按 R6（6.0/10）对照真实部署文件闭合 socket peer auth、per-kind registry/migration、snapshot FD handoff、config/activation/drain/catalog/gate 接线。作者：codex-wasm-author，gpt-5.6-terra max；依据 owner 评分回落升级政策。 -->

# add-wasm-runtime Design

R7 评审结论（6.0/10）：R6 的 digest、AdmissionProof、双 generation、allowlist、metrics、lease 基础 wire 获认可，但对照真实部署发现 socket owner/peer auth、Kernel per-kind 业务记录与 migration、snapshot 交接、config WIT、activation/drain replay、catalog history 和双 gate startup 接线仍未闭合。本轮选择 supervisor 创建 socket + 双端 `SO_PEERCRED`、严格 wasm per-kind registry、同一 UDS 上 `SCM_RIGHTS` 只读 FD handoff、独立 activation/drain records、固定 catalog history 与双 gate selector；R7 delta spec 优先于本表的历史摘要。

一手调研全文见 `docs/research/wasm-runtime-selection.md`（2026-08-25，官方信源 + ZCode 复核）。R7 的规范优先级是：两个 delta spec 的 R7 文字覆盖本变更中 R3/R4/R5/R6 的同名摘要；`proposal.md` 只保留用户可读的变更范围，凡与 R7 delta spec 冲突的 authority/digest/matrix/wire 文字均不具规范效力；现行 `kernel-control-plane` 继续是版本、生命周期业务状态和 active route pointer 的产品法。

## R7 决策增补

| # | 决策 | R7 结论 | 取舍 |
| --- | --- | --- | --- |
| D20 | socket owner/auth | systemd `iweb-sandbox` supervisor 创建固定 `/run/iweb-sandbox/supervisor.sock`，Kernel 当前为 root peer；双端 `SO_PEERCRED` + inode/path/mode 校验，拒绝替代路径/TCP | 对齐 `packaging/iweb-sandbox-supervisor.service` 与 `supervisor/server.ts` 的真实创建顺序；不假称 Kernel 是 owner，非 root Kernel 另开 revision |
| D21 | Kernel business registry | celld v1 `ControlStateFile` 保持原样；Kernel 维护严格 `runtimeKind:"wasm"` registry，记录完整 binding/proof ref；迁移显式 source revision/digest、target digest、receipt、幂等/回滚 | 避免动 `packages/contracts/records.ts` 的 celld validator，同时保留 Kernel 唯一业务与 route 权威 |
| D22 | secret/config snapshot | 选择同一 peer-auth UDS 上的 `SCM_RIGHTS` 只读 FD handoff；`SnapshotRefV1` 一对一指向 Kernel snapshot，supervisor 只按 ref 校验 fd，wasmd 只见 pre-opened fd；owner keys/values 完整等集 | `docker-compose.sandbox.yml` 对 `/run/iweb-sandbox` 是只读挂载，FD handoff 可跨容器边界且不增加共享可写目录；引用解析仍由 Kernel 授权 |
| D23 | config interface | 固定 `iweb:config@1.0.0` `store.get` 字符串 WIT、allowlist/snapshot/revision CAS 与负向错误向量 | 与 secrets 对称但保留非秘密语义；值类型 `string` 继续标记为 owner Apply 前裁决 |
| D24 | activation replay | `POST /v1/wasm/activation-rpc` + `ActivationCommandV1`/`RouteEventV1`/`LeaseConsumeRecordV1`，route pointer、lease consume、event 同一 control CAS | 使 response lost/partial replay 不会重复激活或递增 generation |
| D25 | drain receipt | 独立 `DrainReceiptV1` 绑定完整 execution identity，确认 drained count/deadline/forced-kill；Kernel 收 receipt 后才写 `retired` | 不扩散 supervisor execution substate 到 Kernel celld lifecycle validator |
| D26 | catalog history | 固定 revision 文件、recovery index、release receipt、1 年 retention、GC deletion audit；active/rollback/CVE 引用不可删 | 以可重放历史换取磁盘保留成本；释放后再按 owner receipt GC |
| D27 | publication gate wiring | 启动同时评估现行 celld 单 gate 与 wasm v2 gate；由 Kernel `runtimeKind` 精确选择，返回 typed reasons，绝不 fallback | 复用 `kernel/application-publication-gate.js` 的 celld 语义，同时物理隔离 wasm validator/path/switch |

## R6 决策增补

| # | 决策 | R6 结论 | 取舍 |
| --- | --- | --- | --- |
| D16 | execution transport | `POST /v1/execution-rpc`，`protocol:"iweb-execution-rpc-v1"`；旧 `POST /v1/rpc` 仍 celld-only，协议错配拒绝 | 新路径避免同 version/operation union 被误解析，不做降级兼容 |
| D17 | control persistence | wasm 使用独立 `wasm-control-state-v2.json`，含 `controlRevision`、`commandOutbox` 与 journal command-received/completed；现行 celld `ControlStateFile` 原样保留 | 迁移时导入一次 Kernel 业务记录，不把 celld 文件升级成双格式 |
| D18 | secrets | 固定 `iweb:secrets@1.0.0` `store.get` 字符串接口、无枚举；值类型按 R3 暂采 string，Apply 前由 owner 最终裁决 | 先闭合安全与线性化，不扩大 WIT API |
| D19 | lifecycle/lease | `retiring` 仅 supervisor execution substate；Kernel 仍写 `retired`。lease 采用 nonce-bound v2 canonical record | 避免修改 celld LifecycleState validator，同时阻断 replay |

## R5 决策表

| # | 决策 | R5 结论 | 依据 / 约束 |
| --- | --- | --- | --- |
| D1 | 引擎与宿主 | Wasmtime + 自建 digest-pinned `iweb-wasmd` 薄宿主；`wasmtime serve` 仅开发参考 | 调研 §3/§4；每个应用仍在独立沙箱中运行 |
| D2 | world 基线 | 仅 `wasi:http/proxy@0.2.8`；不接受 0.3、范围、别名或裸 package 声明 | WASI `wasi-http` Releases 的 Latest `v0.2.8`（2026-08-26 核验）；0.3 另开 Change |
| D3 | 权威模型 | **Kernel 保持唯一业务权威**：准入版本、策略、生命周期状态、active route pointer 和 owner 授权均在 Kernel control DB。supervisor journal 仅是受 Kernel `commandId`/CAS/fence 约束的执行事务日志，不能铸版本或翻转路由 | 现行 `kernel-control-plane`；R4 D22 冲突的推荐裁决。无需反转既有主 spec |
| D4 | 准入提交 | Kernel-owned admission journal + 仅一个 `AdmittedVisible` 谓词；对象完成标记、DB 记录、materializer receipt 都以同一 typed proof 和 token hash 交叉验证才可见 | R4：object store / DB / materializer 不可假装成单库事务 |
| D5 | 制品与 digest | 新建 `wasmPackageDigestV1` 与 `wasmVersionDigestV1`，均以 RFC 8785 JCS 定义；**不复用**现行 celld `versionDigest` | `package-collection.ts` 当前公式使用项目自定义缩进 JSON 序列化，语义与 JCS 不同 |
| D6 | OCI 子集 | 一个 canonical OCI layout、一个 manifest、一个 config、非空且无重复的 wasm layers；未知字段、未引用 blob、宽松 media type、空制品均拒绝 | 可复现性和全闭包扫描优先于 registry 兼容面 |
| D7 | 代次身份 | `sandboxId/versionId/preparationGeneration/executionGeneration` 是 wasm 唯一运行身份；generation 初值、单调性、CAS 与 gateway fence 全部显式 | 现行 celld `sequence`/单 `generation` 仅是 celld 旧信号，不可充当 wasm generation |
| D8 | 运行时绑定 | binding identity = `{kind, catalogRevision, catalogHash, entryKey, imageDigest, hostABI, world}`；写入 version、准备、激活和 rollback history | image 不进入版本 digest，但必须可重放且不可漂移 |
| D9 | catalog | append-only catalog revision + 覆盖 schema/revision/每个 entry（含 status/revocation）的 JCS hash + revision CAS；entryKey 唯一；active/rollback 保留引用不可删，CVE 用 revoke 而非删除 | R4：catalog 不是字段列表，而是可重放的选择记录 |
| D10 | 节点能力记录 | typed v1、JCS hash、revision CAS、owner 逐 revision 更新；所有上限、staging 预算、matrix 和 reserve 明确单位/上界 | 缺失值不推默认；`resources.memoryBytes` 是 cgroup 总预算，reserve 是同一 binding+arch 的宿主预算 |
| D11 | imports 闭包 | 由 Component Model 类型身份规范化为 `{package,interface,direction}`，而非字符串猜测；嵌套、re-export、adapter 必须求到唯一内部来源或矩阵 host import | 允许内部组合但不允许借 adapter 偷渡 host capability |
| D12 | 秘密 rotation | Kernel app mutation fence 在前、secret-store 提交为线性化点、supervisor journal sandbox fence 在后；journal 永不保存 secret value | 连续 rotation 线性化为最大 revision，旧候选一律不能激活 |
| D13 | readiness / metrics | wasm health v2 和 metrics v1 均携带 package digest、完整 binding、secretRevision 与双 generation；无首样本=`unavailable`，fuel 禁用=`null` | 现行 health 只有 versionId/generation，不能误采纳 wasm signal |
| D14 | 发布门 | celld v1 固定 `/opt/iweb/release/sandbox-acceptance.json`；wasm v2 固定 `/opt/iweb/release/wasm-sandbox-acceptance.json`，各自 JCS self-digest、未知字段拒绝、独立开关与 validator | v1 继续只开 celld；wasm 不借用 celld 验收 |
| D15 | 生命周期 | lease 在 Kernel activation CAS 内再次检查；journal 完成但 projection 失败只可 replay、不可路由；新 execution 激活后旧 execution 只 drain、被 gateway fence 阻断新流量 | R4 指出的三个遗漏场景进入 spec 与任务 |

## 边界与取舍

```text
owner request
    │ authorization + immutable version + route CAS
    ▼
Kernel control DB ── commandId / expected revision ──► supervisor execution journal
    │                         ▲                           │ prepare/start/drain only
    │ AdmittedVisible          └── exact ack/identity ──────┘
    └── active route pointer ─────► gateway fences new traffic by full tuple
```

- 选择 D3 而非“journal 是生命周期唯一权威”：后者会直接违背 `kernel-control-plane` 的恢复与业务授权法，并把 route 业务状态变成异步投影。Kernel 发送命令、journal 证明执行，二者以不可伪造的 `commandId` 和 revision CAS 收敛。
- 选择 D5 的新 digest 而非改写现行公式：celld 已发布的 `versionDigest` 依赖 `canonicalSerializeManifest()` 的项目内部格式。把它称为 RFC 8785 会制造跨实现冲突；wasm 以新算法和新向量隔离。
- 选择 D6 的严格 OCI 子集：v1 不接外部 registry，也不允许 annotations/未引用 blob 成为隐性输入。后续若需要扩展 media type，必须提高 `wasmPackageDigest` algorithm 名称或另立 schema revision。
- 选择 D2 的 `0.2.8`：它是官方 Releases 在本次核验时的 Latest 0.2 tag，不是 `0.2.x` 范围。WIT 依赖包也按 tag 内的 `0.2.8` 固定。
- 选择 D14 的 Kernel release 固定记录，而非让 wasmd 镜像内的文件声明该镜像自身 digest 或让 catalog 引用该文件 digest：前者会形成镜像自摘要，后者会形成 catalog hash 与 record hash 的循环。记录由受信 Kernel release 固定路径提供，绑定被选的 immutable wasmd image；catalog 与 capability record 仍各自独立 CAS，gate 同时校验三者。

## Owner 待决（不替代 R5 已闭合契约）

| # | 问题 | 当前门槛 | 为什么仍由 owner 决定 |
| --- | --- | --- |
| Q1 | wasmd 实测 reserve 数值 | 每个 `linux/amd64`、`linux/arm64` binding 都未录实测前 fail-closed | 数值是节点/镜像实测，不可由规范臆定 |
| Q2 | TLS 宿主终结 | 暂采宿主在 gateway 已验证连接上终结 TLS；不暴露 `wasi:tls` | 影响对外兼容与证书责任，需 owner 最终确认 |
| Q3 | 0.3 开放时点 | v1 稳定拒绝，迁移状态 owner 可见 | 需独立评审新的 world/adapter/matrix |
| Q4 | `iweb:secrets`/`iweb:config` WIT 的值类型 | schema、key grammar、错误向量、allowlist/snapshot/rotation wire 已固定；值暂采 `string`，Apply 前由 owner 最终裁决 | API ergonomics 不得绕过秘密边界；config 仍不得承载 secret |
| Q5 | 与 `typescript-monorepo` 的开工顺序 | 其 contracts/protocol 迁移完成后再 Apply | manifest/records/desired-state/protocol 有直接文件交叠 |

## 评审闭环（历史摘要，non-normative）

- **non-normative｜R1（2026-08-26，3/10）**：运行契约、OCI 准入、world、出网、强杀、秘密、版本身份、metrics 与发布门缺少可执行定义。R2 补方向但仍停留在字段名。
- **non-normative｜R2（2026-08-26，4.5/10）**：确认 0.2/0.3 收敛、固定网关与 kind 绑定；指出 allowlist、digest、catalog、limits、ingestion 仍不可互操作。R3 增加 generation、journal、catalog/record 概念。
- **non-normative｜R3（2026-08-26，6.0/10）**：认可选型与 fail-closed 方向；指出完整闭包、代次、原子边界、secret rotation、catalog/schema/wire 仍未落到可实现协议。R4 后评分回落。
- **non-normative｜R4（2026-08-26，5.5/10）**：结论是“决策已显式化，但三组直接契约矛盾仍在，且多处字段列表不等于可互操作定义”，不可 Apply。R5 分别以 D3/D5/D7 关闭 authority、digest、identity 三组矛盾，并将 admission、rotation、catalog、node record、matrix、readiness、metrics、gate 和生命周期写为可验证记录/状态机。
- **non-normative｜R5（2026-08-26，7.0/10）**：三组概念矛盾与字节级 schema 已通过；评审仍指出 5 个 P0 接缝（execution RPC 并存、control revision/outbox、最终 version identity、secrets 权限接口、双 runtime gate）与 3 个 P1（retiring、lease wire、grammar），另要求实际 vector、proposal 重写和 query/replay/auth 选择。
- **non-normative｜R6（2026-08-26，6.0/10）**：认可 digest、AdmissionProof、双 generation、allowlist、metrics、lease 基础 wire；对照真实部署指出 socket owner/peer auth、per-kind business records/migration、snapshot、config、activation/drain、catalog history、gate startup 接线未闭合。本 R7 delta spec 已逐项固定协议，但实现/真实 Linux 证据仍是 Apply 前置。
- **non-normative｜R7 作者出处（2026-08-26）**：`codex-wasm-author`，`gpt-5.6-terra max`，由 owner 评分回落升级政策接手；本条只记录起草来源，不覆盖 R7 normative spec。
