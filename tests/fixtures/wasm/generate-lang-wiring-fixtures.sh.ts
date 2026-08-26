// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x 收尾）：真实语言工具链组件触发的三条
// scanner 布线路径（实例绑定 raw import、匿名 shim 重接线形状、instance type 内 export decl
// 引入局部资源类型）需要最小合成 fixture 做单元钉死——真实产物（lang-rust/lang-moonbit/
// lang-ts）只做端到端，负例与形状边界用合成二进制精确控制。
// 正交意图：单一来源生成（本脚本，WAT 内联）；wasm-tools 版本钉死校验；产物提交入库，
// 测试不依赖工具链与网络。刻意不复用 generate-wasm-fixtures.sh.ts 全量再生（其清理段会删
// 目录下全部 .wat，殃及 wasmd-*.wat 提交物）。
// 运行：bun tests/fixtures/wasm/generate-lang-wiring-fixtures.sh.ts
import { $ } from "bun";

const EXPECTED_WASM_TOOLS = "wasm-tools 1.258.0";
const OUT = import.meta.dir;

const version = (await $`wasm-tools --version`.text()).trim();
if (version !== EXPECTED_WASM_TOOLS) {
	console.error(`expected ${EXPECTED_WASM_TOOLS}, found ${version}`);
	process.exit(1);
}

const written: string[] = [];
async function writeWat(name: string, text: string): Promise<string> {
	const path = `${OUT}/${name}`;
	await Bun.write(path, text);
	written.push(path);
	return path;
}

// ---------------------------------------------------------------------------
// 1. instance-bound-import.wasm：主 core module 的 raw import（模块名 = 实例导入名
//    wasi:http/types@0.2.8，字段 = 实例成员 make）经 instanceBoundImports 消化，无需
//    adapter。正例：声明=发现={types}，闭包判定通过。
// ---------------------------------------------------------------------------
const boundImport = await writeWat(
	"instance-bound-import.wat",
	`(component
  (import "wasi:http/types@0.2.8"
    (instance (;0;)
      (type (;0;) (func (result u32)))
      (export "make" (func (type 0)))
    )
  )
  (core module (;0;)
    (import "wasi:http/types@0.2.8" "make" (func (result i32)))
    (func (export "run") (result i32) i32.const 0)
  )
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${boundImport} -o ${OUT}/instance-bound-import.wasm`.quiet();

// ---------------------------------------------------------------------------
// 2. instance-bound-unmapped.wasm：同一实例导入名下字段 steal 不是成员——绑定判定
//    fail-closed（WASM_IMPORT_UNMAPPABLE），实例导入名本身不豁免未声明成员。
// ---------------------------------------------------------------------------
const boundUnmapped = await writeWat(
	"instance-bound-unmapped.wat",
	`(component
  (import "wasi:http/types@0.2.8"
    (instance (;0;)
      (type (;0;) (func (result u32)))
      (export "make" (func (type 0)))
    )
  )
  (core module (;0;)
    (import "wasi:http/types@0.2.8" "steal" (func (result i32)))
    (func (export "run") (result i32) i32.const 0)
  )
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${boundUnmapped} -o ${OUT}/instance-bound-unmapped.wasm`.quiet();

// ---------------------------------------------------------------------------
// 3. shim-rewiring-anon.wasm：匿名模块全量 ("", 纯数字)/("", "$imports") 导入形状 =
//    wit-component 匿名 shim/fixup 重接线（rustc 1.98 产物不写 component-name 段），
//    raw import 不计费。正例：闭包判定通过。
// ---------------------------------------------------------------------------
const shimAnon = await writeWat(
	"shim-rewiring-anon.wat",
	`(component
  (import "wasi:http/types@0.2.8"
    (instance (;0;)
      (type (;0;) (func))
      (export "noop" (func (type 0)))
    )
  )
  (core module (;0;)
    (import "" "0" (func))
    (import "" "$imports" (table 1 funcref))
  )
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${shimAnon} -o ${OUT}/shim-rewiring-anon.wasm`.quiet();

// ---------------------------------------------------------------------------
// 4. shim-rewiring-escape.wasm：near-miss——同形状多一个 ("", "named-escape") 具名
//    字段即不再匹配全量重接线形状，raw 恢复计费 → WASM_IMPORT_UNMAPPABLE（fail-closed，
//    防结构识别被名字伪装逃逸）。
// ---------------------------------------------------------------------------
const shimEscape = await writeWat(
	"shim-rewiring-escape.wat",
	`(component
  (import "wasi:http/types@0.2.8"
    (instance (;0;)
      (type (;0;) (func))
      (export "noop" (func (type 0)))
    )
  )
  (core module (;0;)
    (import "" "0" (func))
    (import "" "$imports" (table 1 funcref))
    (import "" "named-escape" (func))
  )
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${shimEscape} -o ${OUT}/shim-rewiring-escape.wasm`.quiet();

// ---------------------------------------------------------------------------
// 5. inst-type-local-resource.wasm：instance type 内 export decl 引入 (sub resource)
//    局部类型、后续内联 functype 以 (borrow N) 解析该局部索引——rustc wasm32-wasip2 组件的
//    编码路径（wit-component 0.234.0 只用显式 type decl + alias，故 wasm-tools 生成物不含
//    该路径；此 fixture 以手写 WAT 钉死漏 push 时的 WASM_BINARY_SECTION_INVALID 误报回归）。
// ---------------------------------------------------------------------------
const localResource = await writeWat(
	"inst-type-local-resource.wat",
	`(component
  (import "wasi:http/types@0.2.8"
    (instance (;0;)
      (export "request" (type $request (sub resource)))
      (export "take" (func (param "x" (borrow $request))))
    )
  )
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${localResource} -o ${OUT}/inst-type-local-resource.wasm`.quiet();

// 清理本脚本自己的 .wat 中间物（不动其它提交物）并校验输出可解码。
for (const path of written) await $`rm -f ${path}`.quiet();
for (const name of ["instance-bound-import", "instance-bound-unmapped", "shim-rewiring-anon", "shim-rewiring-escape", "inst-type-local-resource"]) {
	await $`wasm-tools print ${OUT}/${name}.wasm -o /dev/null`.quiet();
	console.log(`ok ${name}.wasm`);
}
