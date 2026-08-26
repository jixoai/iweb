// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x）：TypeScript 一级参考语言的
// wasi:http@0.2.8 proxy world 组件 fixture 的可重复构建脚本。
// 正交意图：单一来源生成（本脚本 + handler.ts + wit/ + package.json/bun.lock）；工具链版本
// 钉死校验；产物只落在本目录 lang-ts-proxy.wasm（绝不放仓库根）；构建后用 contracts 的
// 角色校验 + 闭包图解码自检，再清理临时目录。node_modules 不入库（根 .gitignore 已覆盖）。
// 运行：bun tests/fixtures/wasm/lang-ts/build.sh.ts
// 已知缺口（如实记录，2026-08-26 实证钉死）：StarlingMonkey 引擎把组件 import 表面钉在
// wasi 0.2.10（revision-1 矩阵钉 0.2.8），且引擎 core module 的 0.2.8 命名 raw import 面经
// inline core instance（canon lower 拼装）接线——闭包 scanner 刻意不建模 core instance 段，
// 这些 raw 保持未绑定，闭包判定以 WASM_IMPORT_UNMAPPABLE fail-closed（先于 0.2.10 版本分类），
// 见 tests/wasm-lang-fixtures.test.ts。本脚本只自检「component 角色 + 0.2.8 导出身份 + 引擎
// import 面形状钉死」。
import { $ } from "bun";
import { rmSync, statSync } from "node:fs";

const OUT = import.meta.dir;
const EXPECTED_COMPONENTIZE = "0.22.0";
const ARTIFACT = `${OUT}/lang-ts-proxy.wasm`;
const BUILD_DIR = `${OUT}/build`;

const version = (await $`${OUT}/node_modules/.bin/componentize-js --version`.text()).trim();
if (version !== EXPECTED_COMPONENTIZE) {
	console.error(`expected componentize-js ${EXPECTED_COMPONENTIZE}, found ${version}`);
	process.exit(1);
}

rmSync(BUILD_DIR, { recursive: true, force: true });
await $`mkdir -p ${BUILD_DIR}`;

// TS → JS：componentize-js 只吃 JS；Bun.Transpiler 做 1:1 语法降级（不引入 polyfill，
// 保证进引擎的代码就是本仓库源码的直译）。
const source = await Bun.file(`${OUT}/handler.ts`).text();
const transpiled = new Bun.Transpiler({ loader: "ts" }).transformSync(source);
await Bun.write(`${BUILD_DIR}/handler.js`, transpiled);

// --disable stdio random clocks：world 是最小导出 world（wit/app.wit），include 全量 imports
// world 会把引擎 0.2.10 表面里的 filesystem/terminal-* 一并锁死且不可禁用；http 不能禁——
// incoming-handler 的手工绑定与 Response 全局都挂在 http feature 上（实证：禁用即
// "failed to find export ... incoming-handler@0.2.8 function handle"）。
await $`${OUT}/node_modules/.bin/componentize-js ${BUILD_DIR}/handler.js --wit ${OUT}/wit --world-name iweb-proxy --disable stdio random clocks -o ${ARTIFACT}`.quiet();
console.log(`artifact: ${ARTIFACT} (${statSync(ARTIFACT).size} bytes)`);

// contracts 自检：component 角色 + 图解码 + 0.2.8 导出身份 + import 闭包形状钉死（防工具链
// 静默漂移：接口集合变化或导出身份变化都在构建期失败）。
const { scanWasmClosureGraph, validateWasmLayerRole } = await import("../../../../packages/contracts/wasm-closure-scanner.ts");
const { WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL } = await import("../../../../packages/contracts/wasm-package.ts");
const bytes = new Uint8Array(await Bun.file(ARTIFACT).arrayBuffer());
const role = validateWasmLayerRole("component", bytes);
if (!role.ok) {
	console.error(`role validation failed: ${role.code} ${role.detail}`);
	process.exit(1);
}
const scanned = scanWasmClosureGraph({
	entry: bytes,
	world: WASM_WORLD_LITERAL,
	hostABI: WASM_HOST_ABI_LITERAL,
	declaredHostImports: [],
	budget: { maxNodes: 4096, maxEdges: 16384, maxDepth: 64 },
});
if (!scanned.ok) {
	console.error(`closure graph decode failed: ${scanned.code} ${scanned.detail}`);
	process.exit(1);
}
const imports = new Set<string>();
let exportOk = false;
for (const node of scanned.graph.nodes) {
	for (const occurrence of node.interfaces) {
		if (occurrence.direction === "import") imports.add(`${occurrence.package}/${occurrence.interface}`);
		if (occurrence.direction === "export" && occurrence.package === "wasi:http@0.2.8" && occurrence.interface === "incoming-handler") exportOk = true;
	}
}
const expectedImports = [
	"wasi:clocks@0.2.10/monotonic-clock",
	"wasi:http@0.2.10/outgoing-handler",
	"wasi:http@0.2.10/types",
	"wasi:io@0.2.10/error",
	"wasi:io@0.2.10/poll",
	"wasi:io@0.2.10/streams",
];
const sorted = [...imports].sort();
const drift = sorted.length !== expectedImports.length || sorted.some((value, index) => value !== expectedImports[index]);
if (!exportOk || drift) {
	console.error(`component shape drifted: export=${exportOk} imports=${JSON.stringify(sorted)}`);
	process.exit(1);
}
console.log(`component shape ok: export wasi:http@0.2.8/incoming-handler + ${expectedImports.length} engine imports (pinned 0.2.10; see matrix gap note)`);

rmSync(BUILD_DIR, { recursive: true, force: true });
