<!-- 用户原始需求（2026-08-24）：seed iweb.json 判定过度设计移除（与路由注册表/wrangler 三处重复）。 -->
<!-- Codex 审稿 R1/R2：须同时修订 One unified workspace、应用目录约定与 Workspace writes；
     沙箱准入输入保留 workspace staging（属 owner/agent 普通写入，非节点种子）；投影断言四项。 -->

## MODIFIED Requirements

### Requirement: One unified workspace
The system SHALL present one RustFS-backed `iweb-workspace` root as the owner's ordinary file area. The node SHALL NOT seed application manifests, entry conventions, or application code mirrors into the workspace; application source of the trusted transitional fleet lives only in the per-app celld deployment projects. Application-facing projections (workspace apps, monitor apps, Admin application views) derive from the Kernel route registry alone. Owner- or agent-written files of any shape — including a future sandbox admission package staged for publication — remain ordinary files until an explicit admission succeeds.

#### Scenario: Operator lists workspace content
- WHEN an authorized caller lists the workspace
- THEN ordinary owner files are visible in one logical root, with no application manifests or code mirrors seeded by the node

#### Scenario: Application attempts workspace-wide access
- WHEN application code attempts to list or read objects outside its admitted package and application-scoped storage
- THEN access is denied without exposing workspace-wide credentials

### Requirement: Workspace writes do not publish code
The system SHALL persist authorized workspace file writes immediately. Such writes MUST NOT alter an admitted version, a running sandbox, the active version pointer, or any celld deployment project until an explicit publication succeeds. Workspace object additions or deletions MUST NOT change any application projection, because projections derive from the route registry alone.

#### Scenario: Operator edits an application source file
- WHEN an authorized caller writes any workspace object (including `notes/app/index.js` or a staged admission package) while a Notes version is active
- THEN the object is stored, the active application behavior, its admitted versions, and its celld deployment project remain unchanged

#### Scenario: Publication of edited content fails
- WHEN workspace-staged content fails package admission or sandbox readiness
- THEN the previous active version remains unchanged and continues receiving traffic

## REMOVED Requirements

### Requirement: Application directory convention is explicit
应用身份（存在性、域名投影、系统保护）完全由 Kernel 路由注册表定义；节点不再种子 `<app>/iweb.json` 清单或 `<app>/app/` 代码镜像，也不赋予任何 workspace 目录结构以投影语义。沙箱准入包（contracts/manifest.ts 契约）仍可由 Agent 作为普通文件写入 workspace 并作为准入输入读取——那是显式发布流程的暂存，不是节点种子的结构约定。
