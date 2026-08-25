<!--
原始需求（2026-08-25）：为 iweb 引入与 celld 同等级的 wasm 应用运行时做技术选型调研。
正交意图：给出运行时引擎与标准的跟随决策；给出与现行沙箱法/网络法/资源法的映射；给出落地路径与待决问题。
信源：三个并行子调研（引擎 / WASI 标准 / celld 同级平台），全部官方一手信源，关键论断经 ZCode 复核（见文末复核记录）。
-->

# iweb wasm 运行时选型调研

调研日期：2026-08-25。「与 celld 同等级」在当前架构里的准确含义：**同一套 Kernel 路由、supervisor 沙箱法、网关拓扑下的另一种 runtime image**——应用容器 ENTRYPOINT 从 celld 换成 wasm 宿主进程（`supervisor/sandbox-spec.ts` 中可执行权威就是 runtime image 的 ENTRYPOINT， celld 只是名字从未出现在 spec 里）。

```text
                    ┌──────────── 同一沙箱法（digest-pinned image + 内网 + 网关 + cgroup）────────────┐
                    │                                                                                  │
   iweb-kernel ────►│  app container: ENTRYPOINT=celld        app container: ENTRYPOINT=iweb-wasmd   │
   (Rust, :8080)    │   JS/TS Workers API                    wasm component (wasi:http)              │
                    │        │                                      │                                    │
                    │        └──────────────┬──────────────────────┘                                    │
                    │                  gateway container（唯一可达对端）                                  │
                    │                  object :9000 / egress :8081 / data :8082                          │
                    └──────────────────────────────────────────────────────────────────────────────────┘
```

## 结论（TL;DR）

1. **引擎唯一候选：Wasmtime**（Bytecode Alliance，Apache-2.0，v48.0.1 / 2026-08-24，月度发布 + 每 12 版 LTS）。它是唯一同时满足：Rust 原生嵌入（与 kernel 同语言）、wasi:HTTP/组件模型完整（0.2 原生 + 0.3 自 v46 默认）、进程内资源强制（fuel + epoch + `ResourceLimiter`）、安全流程透明（48 条全公开公告、月度修复、LTS 回移）。
2. **标准跟随：WASI 组件模型主线**。部署基线 = WASI 0.2 `wasi:http/proxy` world；战略主线 = WASI 0.3 `wasi:http/service|middleware` world（0.3.0 于 2026-06-11 发布，Wasmtime 同二进制双栈运行 0.2/0.3 组件）。分发用 **OCI artifact + digest 固定**（wkg 工具链），与 iweb 不可变版本对象准入法同构。
3. **宿主形态：自建薄宿主 `iweb-wasmd`**（Rust 二进制，内嵌 `wasmtime-wasi-http` crate，tokio/hyper 栈与 kernel 同生态）作为 per-app runtime image 的 ENTRYPOINT。`wasmtime serve` 官方定位 **dev-only**（原文 "intended solely for local development and testing"、"Not recommended for production use"），只可作为开发期过渡。
4. **落选与理由**：WasmEdge（组件模型执行链路未收尾、Rust SDK 落后 3 个 minor）、WAMR（WASI 停在 P1、2025-26 连续内存安全 CVE 含 critical OOB write）、Wasmer（MIT 开源、Rust 原生嵌入无短板，但 WASIX 是**单厂商主导的标准分叉**——治理名义多实体、实际仍由 Wasmer 一家驱动，且是唯一完整实现；与组件模型主线脱节，见 §3 补充）、Spin（`spin up` 同为 dev 定位、无内建资源限额、CVE-2026-27887 宿主缓冲 OOM）、wasmCloud（v2 重构仅 5 个月历史、K8s 优先）、Lunatic（实质停滞，最后实质提交 2024-03）、wazero（Go 宿主限定，仅作 footprint 参照）。
5. **wasm 不豁免 Podman 边界**。现行安全法的类推仍然成立：wasm 实例 + 能力模型不自动等于 iweb 应用沙箱；它是**沙箱边界内的第二层纵深**（引擎层 fuel/epoch/内存上限 + cgroup 层限额 + 网络拓扑层断路）。
6. **语言出口分层**（AI 代理产出视角）：Rust（`wasm32-wasip2` Tier 2 原生）与 TS/JS（ComponentizeJS/StarlingMonkey → 产出**同一个** wasi:http 组件）为一级；Go 走 BA 工具链（componentize-go，非 Go 官方支持）；Python 最薄，准入管道须内置最严格构建验收。

## 1. iweb 约束基线（本地事实，评估基准）

| 法条 | 现行实现 | 对 wasm 运行时的含义 |
| --- | --- | --- |
| 可执行权威 = runtime image ENTRYPOINT（digest-pinned） | `sandbox-spec.ts:149` | wasm 引擎以新 runtime image 引入，准入/supervisor/kernel 全部复用 |
| 网络法：app 仅挂 `--internal` 网，唯一可达对端是网关 | `sandbox-spec.ts:72-80` | wasm 模块**无环境网络权限**：不给 `wasi:sockets`，出网唯一通道是宿主实现的 `wasi:http/outgoing-handler`。出口收敛从「拓扑强制 + 合作提示」升级为「能力缺失 + 宿主必经 + 拓扑兜底」三层 |
| 出网必须拨已校验 IP（HTTP 转发与 CONNECT 皆然） | gateway :8081 | 宿主 outgoing-handler 实现 = `HTTP_PROXY` 的**非合作版**：模块无法绕过，宿主把请求/CONNECT 交给网关执行校验拨号 |
| 资源法：cgroup cpu/memory/pids/storage 限额 | `--cpus/--memory/--pids-limit` | 引擎内 fuel（CPU 近似）/ epoch（墙钟超时）/ `ResourceLimiter`（线性内存、实例数）构成第二层强制 |
| 准入法：不可变版本对象、snapshot 物化、digest 固定 | supervisor materializer | wasm 组件天然是内容寻址制品（sha256）；OCI artifact + wkg 与现行物化管道同构 |
| 全节点 idle ≤ 240 MB RssAnon | node-boundary spec | 引擎常驻成本必须实测（见 §6 风险）；Wasmtime 官方无 RSS 承诺数字 |

## 2. 标准版图：跟随什么

状态标记：`[stable]` 组织级表决通过、可依赖 ｜ `[de-facto]` 事实标准未定稿 ｜ `[stalled]` 停滞 ｜ `[deprecated]` 废弃。

| 领域 | 跟随对象 | 状态 | 关键事实（信源见 §7） |
| --- | --- | --- | --- |
| 应用 ABI | WASI 0.2 → 0.3 | `[stable]` | 0.2 于 2024-02-06 官宣 stable；0.3.0 于 **2026-06-11** 发布（wasi.dev roadmap 原文 "WASI 0.3.0 was released on June 11, 2026"，Wasmtime 43+ 支持）。注意 Phase 4/5（W3C 标准化阶段）至今为空——「stable」是 WASI SG 表决 + 版本承诺，非 W3C 定稿 |
| HTTP 接口 | wasi:http | `[de-facto]` Phase 3 | 0.2 `proxy` world → 0.3 拆为 `service` + `middleware` world（组件间进程内链式组合）。Wasmtime/Spin/wasmCloud/Fastly 四方共同收敛，是服务端 wasm HTTP 的唯一标准化载体 |
| 接口描述 | WIT + Component Model | `[de-facto]` | 版本随 WASI 预览演进（0.3.1 增 `map<K,V>`、`implements`）；CM 1.0 有官方路线图（2026-06-08）但无时间表，WASI 1.0 依赖 CM 1.0 |
| ~~WGSI~~ | **不存在** | — | 经 WebAssembly org 仓库枚举、代码搜索、多组检索彻底核验为查无此物。可能的混淆源：WAGI（已被 wasi-http 取代）、proxy-wasm（Envoy 线，独立 ABI）、wasi:http service world 本身 |
| 配置/秘密 | wasi:config/store | `[de-facto]` Phase 2 | 仅 `get/get-all` 纯字符串；**secrets 语义仍是 open issue 未进规范**。iweb 须以自有宿主接口定义秘密可见性/审计语义，保持 wasi:config 形状对齐 |
| keyvalue / blob-store | 不依赖 | `[stalled]` | keyvalue 最后实质设计变更 2024-03；blob-store Phase 1 自述 TODO。存储投影做成 iweb 自有宿主接口 |
| TLS | wasi:tls | Phase 1 draft | Wasmtime v44 起随 0.3 线提供 `wasi:tls@0.3.0-draft` 初始实现；决定 TLS 在宿主终结（可审计）还是组件内终结（对齐现行 gateway CONNECT 语义）是**待决设计点** |
| 分发 | OCI artifact + wkg CLI | `[de-facto]` | warg registry 已归档（2025-07-28）；Docker Desktop 内置 wasm 已官方 deprecated；WASI 0.3.1 起提案晋级明确要求 OCI 打包；`module.wasm.image/variant=compat` 注解约定可用 |
| 容器面（可选） | runwasi/containerd | `[de-facto]` | containerd 非核心子项目，活跃；iweb 不需要——supervisor 直接管 Podman 沙箱 |

**p2→p3 兼容策略**：无二进制兼容，迁移是源码级（官方称基本机械化）；运行时侧 Wasmtime 同一二进制双栈运行 0.2/0.3 组件按组件分派。iweb 应**准入 0.2 组件、宿主双栈**，给生态 6-12 个月窗口自然迁 0.3。

## 3. 引擎对比

| 维度 | **Wasmtime** | WasmEdge | WAMR | Wasmer | wazero |
| --- | --- | --- | --- | --- | --- |
| 治理 | Bytecode Alliance，Apache-2.0 | CNCF sandbox | BA org 托管（Intel 发起） | Wasmer Inc（商业），MIT | wazero org，Apache-2.0 |
| 最新 release（2026-08-25 实测） | v48.0.1（08-24） | 0.17.1（07-06） | 2.4.5（06-29） | v7.3.0（08-21） | v1.12.0（05-29） |
| WASI P1 / 0.2 / 0.3 | adapter / 原生 / v46 起默认 | 有 / CM 进行中 / 无 | 有 / 无 / 无 | WASIX 超集 / 无 / 无 | 仅 P1 / 无 / 无 |
| wasi:http | ✅（serve 自 18.0.0） | ❌ | ❌ | ❌ | ❌ |
| 进程内资源强制 | **最全**：fuel + epoch + ResourceLimiter + 栈/预留参数 | gas 上限、内存页上限、异步取消 | 未见一手文档 | 未见等价机制 | 无 |
| Rust 嵌入 | **原生**（本体即 Rust 库） | SDK 落后 3 个 minor | SDK v1.1.0（2024-09） | 原生 | 不适用（Go） |
| 安全记录 | 48 条公告，含 2 critical 沙箱逃逸，修复快速透明 | 1 条 medium | 8 条（2025-26），含 1 critical OOB write | 2 条（含「文件系统沙箱未强制」high） | 0 条 |
| iweb 判定 | **首选** | 中 | 极端 envelope 备选 | 低-中 | 参照 |

**Wasmer / WASIX 补充（许可证 ≠ 治理 ≠ 标准，2026-08-25 核验）**：Wasmer 本体 MIT，真开源可分叉；WASIX 规范放在 [wasix-org](https://github.com/wasix-org)（witx 规范 + wasix-libc），其[治理讨论](https://github.com/orgs/wasix-org/discussions/1)明言「aims to be governed by many entities, not just one」，但 wasix.org 版权仍为 © 2026 Wasmer Inc，且 Wasmer 是唯一完整实现（wasix.org 自述）。它的真实卖点是 POSIX 完备性（线程、fork、动态链接、承诺前后向全兼容）——适合**移植存量软件**而非 AI 产出新应用；代价是 WASIX 给应用 socket 能力（出网法退回 netns+合作代理层，丢失 wasi:http 结构性收敛）、无 WIT imports 准入校验、官方文档未见 fuel/epoch 等价机制。若未来出现「跑存量 POSIX 软件」的产品需求，可作为独立 runtime kind 另行评估。

**Wasmtime 安全记录细读**（这既是风险也是资质）：

- 2026-04-09 一次性发布 12 条公告，含两个 critical 沙箱逃逸：CVE-2026-34987（Winch 后端）、CVE-2026-34971（aarch64 Cranelift，影响 32.0.0 起）；修复覆盖至 LTS 线。响应动作包括把 LLM 辅助漏洞挖掘常态化、Cranelift lowering 形式化验证进 CI。
- 对 iweb 的操作含义：**runtime image digest 必须紧跟上游安全版**（supervisor 已具备 digest 替换通道）；**不启用 Winch 后端**即避开其专属 critical 面；aarch64 部署（Dockerfile arm64）对 Cranelift 线 CVE 尤其敏感。
- 未找到公开第三方整体审计报告——保证来自流程（持续 fuzz、cargo vet、形式化验证）与全公开公告史，而非一份审计 PDF。如实记录为信息缺口。

## 4. 平台层判定（谁当 celld 的对等物）

| 候选 | 判定 | 核心证据 |
| --- | --- | --- |
| **wasmtime（自建薄宿主）** | **基座** | `wasmtime-wasi-http` crate 暴露 p2/p3 双栈实现，tokio + hyper 官方栈；`serve` 源码（v48.0.1）已示范全部所需参数形态：`-W fuel`/`-W timeout`（epoch 线程 50ms）/store limits、`-S config=`、`--shutdown-addr`（连接即优雅停机，契合 supervisor 生命周期）、实例复用（p3 默认 128 请求/实例、16 并发/实例；p2 每请求新实例） |
| wasmtime serve（直接用） | 仅开发期过渡 | 官方文档明确 "intended solely for local development and testing"、"Not recommended for production use"，缺限流/请求大小限制/TLS 终止（ZCode 已一手复核原文） |
| Spin v4 | 参考实现，不采用 | CNCF sandbox、活跃（v4.0.2），HTTP trigger 默认标准 wasi:http 组件；但 `spin up` 同为本地开发定位、生产路径指向 SpinKube（K8s）；无内建 fuel/内存限额；CVE-2026-27887（2026-02-26）：无界响应可致宿主整缓冲 OOM——直接违反 240MB envelope 法 |
| wasmCloud wash-runtime v2 | 跟踪 6-12 个月 | 形态最接近（可嵌入 Rust host + 全 WASI + wasi:http + 插件系统，v2.5.0 起 0.3 常开）；但 v2 是 2026-03-22 的激进重构（lattice/NATS 移除），稳定历史仅 5 个月，K8s operator 是一等公民 |
| Extism | 不适配 | 插件/函数调用框架（宿主进程内 `call()`），非 per-app HTTP 服务形态；其「宿主全控出网（不用 WASI）+ 内建 limiter」设计值得借鉴 |
| Hyperlight | 不适配 | 需 /dev/kvm 微 VM 的强化件（wasm 变体官方自 declared 实验性）；容器内嵌套虚拟化不可用 |
| Lunatic | 排除 | 实质停滞（最后实质提交 2024-03），WASIX 绑定 Wasmer 生态 |
| JS-on-wasm（ComponentizeJS + StarlingMonkey + jco） | **采纳为 JS 出口** | Fastly js-compute-runtime 生产规模证明「Workers 风格 API → wasm 组件」成立；JS 与 Rust 产出**同一个 wasi:http 组件**，宿主侧完全同构——iweb 可保持「一种制品模型、多语言出口」，celld（JS 直跑）与 wasmd（组件）并存 |

## 5. 架构映射

### 网络（最关键的增益）

```text
wasm component ── outgoing-handler(host 实现) ──► 沙箱内 gateway :8081 ──► 已校验 IP 拨号
      │                                                                              ▲
      └── 不授予 wasi:sockets ──► 模块无原始 socket 能力（能力缺失层）                │
                                              宿主必经层（模块无法绕过）──────────────┘
                                              拓扑兜底层（internal 网无默认路由）─────┘
```

对比 celld 场景：`HTTP_PROXY` 对 JS 是合作提示，强制靠 netns；wasm 场景出口收敛是**结构性的**——这正好满足「出网必须由应用进程外的边界强制执行」法条，且多出一层。

### 资源

- 引擎层：`ResourceLimiter`（线性内存/table/实例数）、fuel 或 epoch（epoch 官方注明比 fuel 快 2-3 倍、适合不可信 guest）、`max_wasm_stack`。
- cgroup 层：现行 `--cpus/--memory/--pids-limit` 不变，兜住引擎本身被攻破的最坏情况。
- 监控法对齐：`unavailable` 语义照搬；per-app fuel/epoch 用量可上报为 wasm 专属指标，与 cgroup 读数分开陈述（勿混同口径——AGENTS.md 已有「容器内存是 cgroup 全量」的教训）。

### 准入与生命周期

- 包形状：OCI artifact 内含组件（们）+ 声明的 WIT imports。**准入校验 imports 对能力矩阵的子集关系**：`wasi:http`（经宿主）、`wasi:config`（宿主注入）、`iweb:*` 自有接口；`wasi:sockets`、未授权 host 接口一律拒绝——恶意 imports 在准入期即拒绝，而非运行期。
- `versionId` ↔ 组件 sha256 digest，物化走现行 snapshot materializer。
- 停止/回收：SIGTERM → 宿主 drain（`--shutdown-addr` 同款机制）；epoch 强杀死循环；容器回收复用现行 sandbox 生命周期。

### 内存 envelope（必须实测的风险区）

- Wasmtime 官方无嵌入进程 RSS 数字，仅文档化虚拟内存策略（默认 4GiB reservation/32MiB guard）；「比 wazero/WAMR 重」是第三方口碑非权威数字。**按 AGENTS.md「容量决策需实测」法执行**：JIT 编译内存峰值、pooling allocator、每 wasmd 进程常驻基线、组件实例化增量（官方 2022 基准：实例化 5µs、每实例化写入 CoW 后数百 KB）都需在 arm64 节点实测后再定 gate。
- per-app 一进程的拓扑与 celld 相同，进程数不因 wasm 增加。

## 6. 落地路径建议（供未来 OpenSpec change 起草）

新变更（暂名 `add-wasm-runtime`，须等 `iweb-mini-product` 序门状态明确后排序）：

1. **契约层**：admission 契约扩展 `runtime kind`（`celld` | `wasm`）；wasm 包形状（OCI artifact + 组件 + WIT imports 声明）；能力矩阵（拒绝 sockets、未授权接口）。
2. **宿主层**：`iweb-wasmd` 薄宿主（Rust，内嵌 `wasmtime-wasi-http`，绑定 `127.0.0.1:8787` 对齐 `CELLD_LISTEN_ADDRESS` 契约）；outgoing-handler 全量经网关；config/秘密经宿主注入（wasi:config 形状 + iweb 自有语义）；fuel/epoch/ResourceLimiter 从 policy.resources 映射。
3. **镜像层**：wasmd runtime image digest-pinned 进 supervisor；安全版跟随流程（2026-04 双 critical 教训）。
4. **验收**：镜像内固定验收记录 + 显式开关双条件照旧适用；preflight 增加 wasmd 冒烟；验收必须覆盖：恶意 imports 拒绝、出网仅经网关（含 HTTPS CONNECT 拨已校验 IP）、fuel/epoch 触发、epoch 强杀不影响邻居沙箱、双栈 0.2/0.3 组件各跑通。
5. **待决问题（owner 裁决）**：TLS 终结位置（宿主终结=可审计 vs 组件内终结=对齐现行 CONNECT 语义）；秘密宿主接口的最终 WIT 形状；0.2 组件准入窗口期；wasmd 进程内存 gate 数值（实测后定）。

## 7. 关键信源（全部 2026-08-25 访问）

- WASI 路线图（0.3.0 = 2026-06-11，Wasmtime 43+ 支持）：https://wasi.dev/roadmap （ZCode 一手复核）
- wasmtime serve 官方定位（dev-only）：https://docs.wasmtime.dev/cli-options.html （ZCode 一手复核）
- Wasmtime 发布节奏/LTS/安全策略：https://docs.wasmtime.dev/stability-release.html 、https://docs.wasmtime.dev/security.html
- Wasmtime 2026-04-09 安全公告（12 条含双 critical）：https://bytecodealliance.org/articles/wasmtime-security-advisories
- 资源强制 API：https://docs.rs/wasmtime/latest/wasmtime/struct.Config.html 、https://docs.rs/wasmtime/latest/wasmtime/trait.ResourceLimiter.html
- WASI 0.3 官宣：https://bytecodealliance.org/articles/WASI-0-3 ；CM 1.0 路线：https://bytecodealliance.org/articles/the-road-to-component-model-1-0
- wasi-http（归档前仓库）：https://github.com/WebAssembly/wasi-http ；提案状态表：https://github.com/WebAssembly/WASI/blob/main/docs/Proposals.md
- wasi-config（WIT 原文 + secrets open issue #16）：https://github.com/WebAssembly/wasi-config
- warg 已归档：https://github.com/bytecodealliance/registry ；wkg：https://github.com/bytecodealliance/wasm-pkg-tools ；wasm OCI 布局：https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/
- Spin：https://github.com/spinframework/spin （CVE-2026-27887 经 NVD API 验证）；wasmCloud v2：https://wasmcloud.com/blog/wasmcloud-v2-is-here/
- 语言工具链：https://github.com/bytecodealliance/wit-bindgen 、https://github.com/bytecodealliance/ComponentizeJS 、https://github.com/bytecodealliance/componentize-py 、https://github.com/bytecodealliance/componentize-go 、Go wasip3 提案 https://github.com/golang/go/issues/77141
- Wasmtime 实例化性能（2022 官方，机制仍有效）：https://bytecodealliance.org/articles/wasmtime-10-performance

## 附：子调研摩擦点与复核记录（子代理反馈协议）

- **编排者预设错误 ×2，已被子调研纠正**：①「WGSI」标准不存在（我在任务书中断言其为 2025 年提案——查无此物，混淆源为 WAGI/proxy-wasm/service world）；②「AppMetering」非 Spin 官方命名（实为 SpinKube per-workload limits）。教训：任务书中的记忆性断言必须显式标注「待核验」。
- **三份子调研交叉一致**：WASI 0.3 日期（2026-06-11）、wasi:http 四方收敛、Wasmtime 首选结论在引擎/标准/平台三线独立得出。
- **ZCode 复核**：wasmtime serve dev-only 定位、WASI 0.3.0 发布日期两条最关键论断已换独立通道一手复核通过。
- **已知缺口（诚实声明）**：① Wasmtime 无公开第三方整体审计；② 「wasm 实例 vs V8 isolate 常驻内存」无官方 head-to-head benchmark，容量决策须节点实测；③ WAMR 资源限制机制未取到一手文档（不影响主结论）。
