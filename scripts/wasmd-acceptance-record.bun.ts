// 用户原始需求（2026-08-26，add-wasm-runtime 镜像批次）：wasmd 镜像验收（acceptance record v2）
// 需要的身份字段必须有一份可执行的采集手册——字段从哪台机器、哪条命令、哪个契约函数取得。
// 正交意图：(1) 打印 acceptance record v2 全字段的采集清单；(2) 固定 digest 公式与权威实现出处；
// (3) 记录开关/固定路径/fail-closed 语义；(4) 镜像体积纪律注记。纯 stdout 文档，无副作用。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//   「Wasm publication requires a canonical kind-bound acceptance record」。
// 运行：~/.bun/bin/bun scripts/wasmd-acceptance-record.bun.ts

const CHECKLIST: readonly string[] = [
	"iweb wasmd acceptance record v2 — identity field collection checklist",
	"",
	"固定字面量（不可采集、不可协商）：",
	'  version=2  result="passed"  gate="application-sandbox"  runtimeKind="wasm"',
	'  hostABI="iweb-wasmd-abi@1.0.0"  world="wasi:http/proxy@0.2.8"',
	"",
	"1. runtimeImageDigest —— 架构专属 OCI image-manifest digest（绝不能填 index/list digest）：",
	"   指向独立的 digest-pinned wasmd 运行时镜像（对标 packaging/celld-runtime.Dockerfile 的 celld 运行时镜像），",
	"   由运行时镜像批次构建；镜像就绪后在远程构建器采集：",
	"   podman build --platform linux/<arch> -f <wasmd-runtime.Dockerfile> -t wasmd:<arch> .",
	"   podman push --digestfile wasmd-<arch>.digest wasmd:<arch> <registry-ref>",
	"   （digestfile 内容即 manifest digest；或 skopeo inspect --raw <ref> | openssl dgst -sha256 复核）",
	"   与 catalog entry 的 imageDigest 必须逐字节相等。",
	"   注意：节点镜像（Dockerfile / Dockerfile.amd64）内 /opt/iweb/wasmd/iweb-wasmd 只是静态存在锚点，",
	"   节点镜像 digest 不等于 runtimeImageDigest——catalog 引用的是上述独立运行时镜像。",
	"",
	"2. arch —— 目标节点架构字面量：",
	"   uname -m 映射：aarch64/arm64 -> linux/arm64；x86_64/amd64 -> linux/amd64",
	"",
	"3. capabilityRecordRevision / capabilityRecordHash —— 实测 seal 后的 node capability record：",
	"   先完成 5.3 reserve 实测（冷启动/ready/首编译/稳态并发/最大响应/epoch kill 峰值），",
	"   填 /opt/iweb/wasm/templates/node-capability-record.template.json（null 占位必须全部替换），",
	"   seal：packages/contracts wasm-catalog.ts sealNodeCapabilityRecordV1 / computeNodeCapabilityRecordHashV1",
	"   模板直接当 live 记录用会被 unknown-field/null 校验拒绝（fail-closed，缺失值不推默认）。",
	"",
	"4. catalogRevision / catalogHash / catalogEntryKey —— seal 后的 RuntimeCatalogV1：",
	"   按构建出的 imageDigest 填 /opt/iweb/wasm/templates/runtime-catalog.revision-1.template.json，",
	"   seal：packages/contracts wasm-catalog.ts sealRuntimeCatalogV1 / computeRuntimeCatalogHashV1",
	"   live 文件名与路径（Kernel-owned）：/data/kernel/runtime-catalog/revisions/<revision>-<catalogHash>.json",
	'   entryKey 文法 /^[a-z][a-z0-9.-]{0,63}$/，模板预置 wasmtime-48.0.1-<amd64|arm64>，一架构一 entry。',
	"",
	"5. evidenceDigest —— 5.1/5.2 Linux 证据包（双网络沙箱抓包 + lifecycle matrix）的 SHA-256；",
	"   没有对应实测记录时发布门保持关闭（证据门，不是待决项）。",
	"",
	"6. recordDigest —— 自 digest，公式（与 kernel/application-publication-gate.js 同一权威）：",
	'   hex(SHA-256(UTF8("iweb-wasm-acceptance-record-v2\\n" || JCS(record with recordDigest omitted))))',
	"   键集合精确等于 spec 所列，未知字段/缺字段/大写 hex/非 JCS 一律拒绝。",
	"",
	"落盘与开关（fail-closed 默认关）：",
	"  记录仅 owner 可写入固定路径 /opt/iweb/release/wasm-sandbox-acceptance.json（镜像已预建空目录）；",
	"  发布门双条件：合法 v2 记录 + IWEB_WASM_PUBLICATION_ENABLED=1（叠加现行 IWEB_APPLICATION_PUBLICATION_ENABLED=1）；",
	"  supervisor 执行通道另需 IWEB_SANDBOX_WASM_EXECUTION_ENABLED=1 显式 opt-in；",
	"  IWEB_WASM_SANDBOX_ACCEPTANCE_FILE / IWEB_WASM_ACCEPTANCE_FILE 重定向变量出现非空值即 gate 关闭，不得设置。",
	"",
	"镜像体积纪律注记：Dockerfile* 的 wasmd-rs 阶段仅拷 release binary（/opt/iweb/wasmd/iweb-wasmd）出",
	"stage；wasmtime 48.0.1 静态链接 release binary 预期数十 MB 级（cranelift+component-model+rustls），",
	"显著大于 iweb-kernel。最终数字以远程构建 `podman images` 实测为准并回填本文件下方登记表。",
	"",
	"体积登记（远程构建后回填）：",
	"  linux/arm64 iweb-wasmd = <pending 远程实测>",
	"  linux/amd64 iweb-wasmd = <pending 远程实测>",
];

for (const line of CHECKLIST) {
	console.log(line);
}
