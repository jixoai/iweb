// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x）：MoonBit 一级参考语言的
// wasi:http@0.2.8 proxy world 组件 fixture 的可重复构建脚本（add-wasm-runtime 8.4 的本地
// 构建面；OCI/admission/readiness/gateway 路径归 kernel/supervisor 批次）。
// 正交意图：单一来源生成（本脚本 + wit/ + handle.mbt）；工具链版本钉死校验；产物只落在本目
// 录 lang-moonbit-proxy.wasm；构建后用 contracts 的角色校验 + 闭包扫描自检，再清理生成物。
// 运行：bun tests/fixtures/wasm/lang-moonbit/build.sh.ts
//
// 工具链链路（2026-08-26 实证）：
// - wit-bindgen moonbit（0.57.1）从 wit/ 生成完整 MoonBit 工程：gen/（导出 stub）、
//   interface/（import 绑定）、world/、moon.mod.json（name=wasi/http, preferred-target=wasm）。
// - stub 包 gen/interface/wasi/http/incomingHandler 只声明 `declare pub fn handle`；手写实现
//   在仓库根 handle.mbt，构建时拷入同包。该包的 moon.pkg.json 生成时只 import types——
//   实现需要 @streams（OutgoingBody::write 的返回类型），构建时补一条 import（结构性补丁）。
// - moon build --target wasm --release 产出 core module（_build/wasm/release/build/gen/gen.wasm）。
// - wasm-tools component embed（--world proxy，--encoding utf16：MoonBit 字符串是 UTF-16）
//   + wasm-tools component new 组装为 component。
import { $ } from "bun";
import { existsSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";

const OUT = import.meta.dir;
const EXPECTED_MOON = "moon 0.1.20260824 (dae026a 2026-08-24)";
const EXPECTED_WIT_BINDGEN = "wit-bindgen-cli 0.57.1";
const EXPECTED_WASM_TOOLS = "wasm-tools 1.258.0";
const ARTIFACT = `${OUT}/lang-moonbit-proxy.wasm`;
const BUILD_DIR = `${OUT}/build`;
const GENERATED = [`${OUT}/gen`, `${OUT}/interface`, `${OUT}/world`, `${OUT}/moon.mod.json`, `${OUT}/_build`];

const moon = (await $`moon version`.text()).split("\n")[0]?.trim() ?? "";
if (moon !== EXPECTED_MOON) {
	console.error(`expected "${EXPECTED_MOON}", found "${moon}"`);
	process.exit(1);
}
const witBindgen = process.env.WIT_BINDGEN ?? (existsSync(join(process.env.HOME ?? "", ".cargo/bin/wit-bindgen")) ? join(process.env.HOME ?? "", ".cargo/bin/wit-bindgen") : "wit-bindgen");
const bindgenVersion = (await $`${witBindgen} --version`.text()).trim();
if (bindgenVersion !== EXPECTED_WIT_BINDGEN) {
	console.error(`expected ${EXPECTED_WIT_BINDGEN}, found ${bindgenVersion}`);
	process.exit(1);
}
const wasmTools = (await $`wasm-tools --version`.text()).trim();
if (wasmTools !== EXPECTED_WASM_TOOLS) {
	console.error(`expected ${EXPECTED_WASM_TOOLS}, found ${wasmTools}`);
	process.exit(1);
}

// 生成物全量再生（可重复构建：每次从 wit/ 重新生成，再套两个确定性补丁）。
for (const path of [...GENERATED, BUILD_DIR, ARTIFACT]) rmSync(path, { recursive: true, force: true });
await $`${witBindgen} moonbit ${OUT}/wit --world proxy --out-dir ${OUT} --derive-eq --derive-show --derive-error`.quiet();

// 补丁 1：stub 包补 streams import（handle.mbt 调用 OutputStream::blocking_write_and_flush）。
const pkgJsonPath = `${OUT}/gen/interface/wasi/http/incomingHandler/moon.pkg.json`;
const pkgJson = await Bun.file(pkgJsonPath).json();
pkgJson.import.push({ path: "wasi/http/interface/wasi/io/streams", alias: "streams" });
await Bun.write(pkgJsonPath, JSON.stringify(pkgJson, null, 2) + "\n");

// 补丁 2：手写实现与生成的 declare 同包链接。
await $`cp ${OUT}/handle.mbt ${OUT}/gen/interface/wasi/http/incomingHandler/`.quiet();

await $`moon build --target wasm --release`.cwd(OUT).quiet();
await $`mkdir -p ${BUILD_DIR}`;
await $`wasm-tools component embed ${OUT}/wit --world proxy ${OUT}/_build/wasm/release/build/gen/gen.wasm --encoding utf16 -o ${BUILD_DIR}/embedded.wasm`.quiet();
await $`wasm-tools component new ${BUILD_DIR}/embedded.wasm -o ${ARTIFACT}`.quiet();
console.log(`artifact: ${ARTIFACT} (${statSync(ARTIFACT).size} bytes)`);

// contracts 自检：component 角色 + 闭包扫描（imports ⊆ revision-1 矩阵且声明=发现）。
const { scanAndValidateWasmClosure, validateWasmLayerRole } = await import("../../../../packages/contracts/wasm-closure-scanner.ts");
const { WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL } = await import("../../../../packages/contracts/wasm-package.ts");
const bytes = new Uint8Array(await Bun.file(ARTIFACT).arrayBuffer());
const role = validateWasmLayerRole("component", bytes);
if (!role.ok) {
	console.error(`role validation failed: ${role.code} ${role.detail}`);
	process.exit(1);
}
const scan = scanAndValidateWasmClosure({
	entry: bytes,
	world: WASM_WORLD_LITERAL,
	hostABI: WASM_HOST_ABI_LITERAL,
	declaredHostImports: [
		{ package: "wasi:http@0.2.8", interface: "types", direction: "import" },
		{ package: "wasi:io@0.2.8", interface: "error", direction: "import" },
		{ package: "wasi:io@0.2.8", interface: "streams", direction: "import" },
	],
	budget: { maxNodes: 4096, maxEdges: 16384, maxDepth: 64 },
});
if (!scan.ok) {
	console.error(`closure scan failed: ${scan.code} ${scan.detail}`);
	process.exit(1);
}
console.log(`closure scan ok; discovered: ${JSON.stringify(scan.discoveredHostImports)}`);

// 磁盘约束：生成物（gen/interface/world/moon.mod.json/_build/build）全部清理；入库的只有
// wit/ + handle.mbt + 本脚本 + 产物。
for (const path of [...GENERATED, BUILD_DIR]) rmSync(path, { recursive: true, force: true });
console.log("generated project files removed (wit/ + handle.mbt + artifact stay in-repo)");
