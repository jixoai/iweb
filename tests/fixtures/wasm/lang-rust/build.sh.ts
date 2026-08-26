// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x）：Rust 一级参考语言的
// wasi:http@0.2.8 proxy world 组件 fixture 的可重复构建脚本。
// 正交意图：单一来源生成（本脚本 + Cargo.toml/Cargo.lock + wit/ + src/）；工具链与依赖版本
// 钉死校验；产物只落在本目录 lang-rust-proxy.wasm（绝不放仓库根）；构建后用 contracts 的
// 角色校验 + 闭包扫描自检，再清空 target 控制磁盘占用。
// 运行：bun tests/fixtures/wasm/lang-rust/build.sh.ts
import { $ } from "bun";
import { rmSync, statSync } from "node:fs";

const OUT = import.meta.dir;
// 工具链事实（2026-08-26 实证）：PATH 首位的 Homebrew rustc 没有 wasm32-wasip2 sysroot
// （E0463 can't find crate for `core`）；wasm32-wasip2 std 属 rustup stable 工具链，构建必须
// 经 `rustup run stable` 显式选链。
const EXPECTED_RUSTC = "rustc 1.98.0 (88d9e12ae 2026-08-18)";
const EXPECTED_WASM_TOOLS = "wasm-tools 1.258.0";
const ARTIFACT = `${OUT}/lang-rust-proxy.wasm`;
const TARGET_DIR = `${OUT}/target`;
const CARGO_OUTPUT = `${TARGET_DIR}/wasm32-wasip2/release/lang_rust_proxy_fixture.wasm`;

function dirSize(path: string): number {
	try {
		return statSync(path).size;
	} catch {
		return 0;
	}
}

const rustc = (await $`rustup run stable rustc --version`.text()).trim();
if (rustc !== EXPECTED_RUSTC) {
	console.error(`expected "${EXPECTED_RUSTC}", found "${rustc}"`);
	process.exit(1);
}
const wasmTools = (await $`wasm-tools --version`.text()).trim();
if (wasmTools !== EXPECTED_WASM_TOOLS) {
	console.error(`expected ${EXPECTED_WASM_TOOLS}, found ${wasmTools}`);
	process.exit(1);
}
const targets = await $`rustup target list --installed`.text();
if (!targets.split("\n").includes("wasm32-wasip2")) {
	console.error("rustup target wasm32-wasip2 is not installed");
	process.exit(1);
}

// --locked：Cargo.lock（wit-bindgen =0.57.1）是依赖权威，禁止构建期漂移。
// RUSTC 显式钉死（2026-08-26 实证）：Homebrew rustup 的 `rustup run` 不把工具链 bin 前置到
// PATH，cargo 裸调 `rustc` 会解析到无 wasm32-wasip2 sysroot 的 Homebrew rustc（E0463）；
// bun 的 $ shell 还会丢掉 /usr/bin——host build script 链接需要显式补 PATH。
const RUSTC = (await $`rustup which --toolchain stable rustc`.text()).trim();
await $`rustup run stable cargo build --locked --release --target wasm32-wasip2`
	.env({ RUSTC, PATH: `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${process.env.PATH ?? ""}` })
	.cwd(OUT)
	.quiet();
await $`cp ${CARGO_OUTPUT} ${ARTIFACT}`;
console.log(`artifact: ${ARTIFACT} (${dirSize(ARTIFACT)} bytes)`);

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

// 磁盘约束：产物已拷出，target 全量清理（下次构建由 cargo 重建缓存）。
rmSync(TARGET_DIR, { recursive: true, force: true });
console.log("target/ removed (cargo cache is rebuildable; artifact stays in-repo)");
