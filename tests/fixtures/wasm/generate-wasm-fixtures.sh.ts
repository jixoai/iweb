// 用户原始需求（2026-08-26，add-wasm-runtime 任务 1.3 剩余部分）：闭包 scanner 测试需要真实合法的
// component/core/adapter 二进制 fixture；fixture 由参考工具链一次性生成并连同本脚本提交，
// 测试本身不依赖工具链与网络。
// 正交意图：fixture 单一来源生成（wat/wit 源内联）；wasm-tools 版本钉死校验；生成后字节级 patch
// （adapter 改名负例）也在此完成。运行：bun tests/fixtures/wasm/generate-wasm-fixtures.sh.ts
//
// 版本钉死：wasm-tools 1.258.0（Homebrew）；生成的 component 由 wit-component 0.258.0 编码
// （见产物 producers 段）。adapter/glue 识别约定依赖该版本的命名约定：
//   - 适配器核心模块名：wit-component:adapter:<abi>
//   - 胶水核心模块名：wit-component-shim-module / wit-component-fixup（raw import 不计费）
import { $ } from "bun";

const EXPECTED_WASM_TOOLS = "wasm-tools 1.258.0";
const OUT = import.meta.dir;

const version = (await $`wasm-tools --version`.text()).trim();
if (version !== EXPECTED_WASM_TOOLS) {
	console.error(`expected ${EXPECTED_WASM_TOOLS}, found ${version}`);
	process.exit(1);
}

async function writeWat(name: string, text: string): Promise<string> {
	const path = `${OUT}/${name}`;
	await Bun.write(path, text);
	return path;
}

async function witPkg(name: string, files: Record<string, string>): Promise<string> {
	const dir = `${OUT}/tmp-${name}`;
	await $`rm -rf ${dir}`.quiet();
	await Bun.write(`${dir}/.keep`, "");
	for (const [file, text] of Object.entries(files)) await Bun.write(`${dir}/${file}`, text);
	return dir;
}

// ---------------------------------------------------------------------------
// WIT：wasi:http@0.2.8 最小代理形状（types 资源 + incoming-handler）。
// ---------------------------------------------------------------------------

const TYPES_IFACE = `
interface types {
  resource request;
  make: func() -> request;
}

interface incoming-handler {
  use types.{request};
  handle: func(req: borrow<request>);
}
`;

const consumerPkg = await witPkg("consumer-pkg", {
	"consumer.wit": `package wasi:http@0.2.8;
${TYPES_IFACE}
world consumer {
  import types;
  export incoming-handler;
}
`,
});

const providerPkg = await witPkg("provider-pkg", {
	"provider.wit": `package wasi:http@0.2.8;
${TYPES_IFACE}
world provider {
  export types;
}
`,
});

const coreHandle = await writeWat(
	"consumer-core.wat",
	`(module
  (func (export "wasi:http/incoming-handler@0.2.8#handle") (param i32))
)
`,
);

const coreMake = await writeWat(
	"provider-core.wat",
	`(module
  (func (export "wasi:http/types@0.2.8#make") (result i32) i32.const 0)
)
`,
);

// 主模块带 wasi_snapshot_preview1 原始导入，用于 adapter 翻译闭包。
const coreAdapted = await writeWat(
	"adapted-core.wat",
	`(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "random_get" (func $random_get (param i32 i32) (result i32)))
  (func (export "wasi:http/incoming-handler@0.2.8#handle") (param i32)
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const 0
    call $fd_write
    drop
  )
)
`,
);

// 适配器核心模块：导出原始 ABI 函数（wit-component 约定的 reactor 形状的最小替身）。
const adapterModule = await writeWat(
	"adapter-core.wat",
	`(module
  (func (export "fd_write") (param i32 i32 i32 i32) (result i32) i32.const 0)
  (func (export "random_get") (param i32 i32) (result i32) i32.const 0)
)
`,
);

// ---------------------------------------------------------------------------
// 1. proxy-minimal.wasm：入口组件，host import wasi:http/types@0.2.8 + 根导出
//    incoming-handler，内嵌一个核心模块与 shim 嵌套组件（无 adapter）。
// ---------------------------------------------------------------------------
await $`wasm-tools component embed ${consumerPkg} ${coreHandle} -o ${OUT}/tmp-consumer.embedded.wasm`.quiet();
await $`wasm-tools component new ${OUT}/tmp-consumer.embedded.wasm -o ${OUT}/proxy-minimal.wasm`.quiet();

// ---------------------------------------------------------------------------
// 2. proxy-adapter.wasm：主模块带 wasi_snapshot_preview1 原始导入，经
//    --adapt 包装：内嵌 adapter（wit-component:adapter:wasi_snapshot_preview1）。
// ---------------------------------------------------------------------------
await $`wasm-tools component embed ${consumerPkg} ${coreAdapted} -o ${OUT}/tmp-adapted.embedded.wasm`.quiet();
await $`wasm-tools component new ${OUT}/tmp-adapted.embedded.wasm --adapt wasi_snapshot_preview1=${adapterModule} -o ${OUT}/proxy-adapter.wasm`.quiet();

// ---------------------------------------------------------------------------
// 3. proxy-adapter-renamed.wasm：把 component-name 段中的
//    wit-component:adapter:wasi_snapshot_preview1 等长改名为
//    wit-component:adapter:wasi_snapshot_previeX1（结构仍合法，ABI 名失配，
//    原始导入失去翻译覆盖）。
// ---------------------------------------------------------------------------
{
	const bytes = new Uint8Array(await Bun.file(`${OUT}/proxy-adapter.wasm`).arrayBuffer());
	const from = new TextEncoder().encode("wit-component:adapter:wasi_snapshot_preview1");
	const to = new TextEncoder().encode("wit-component:adapter:wasi_snapshot_previeX1");
	if (from.length !== to.length) throw new Error("adapter rename patch failed");
	let patched = 0;
	for (let at = bytes.indexOf(from[0]); at >= 0 && at + from.length <= bytes.length; at = bytes.indexOf(from[0], at + 1)) {
		if (from.every((f, j) => bytes[at + j] === f)) {
			bytes.set(to, at);
			patched++;
		}
	}
	if (patched === 0) throw new Error("adapter rename patch failed");
	await Bun.write(`${OUT}/proxy-adapter-renamed.wasm`, bytes);
}

// ---------------------------------------------------------------------------
// 4. proxy-composed.wasm：consumer + provider 组合。真实嵌套 provider、内部
//    唯一解析、根导出 re-export 折叠到原 provider 节点。
// ---------------------------------------------------------------------------
await $`wasm-tools component embed ${providerPkg} ${coreMake} -o ${OUT}/tmp-provider.embedded.wasm`.quiet();
await $`wasm-tools component new ${OUT}/tmp-provider.embedded.wasm -o ${OUT}/tmp-provider-component.wasm`.quiet();
await $`wasm-tools compose ${OUT}/proxy-minimal.wasm -d ${OUT}/tmp-provider-component.wasm -o ${OUT}/proxy-composed.wasm`.quiet();

// ---------------------------------------------------------------------------
// 5. provider-only.wasm：只导出 wasi:http/types@0.2.8 的组件（缺根导出）。
// ---------------------------------------------------------------------------
await $`cp ${OUT}/tmp-provider-component.wasm ${OUT}/provider-only.wasm`;

// ---------------------------------------------------------------------------
// 6. two-providers.wasm：两个嵌套组件都重导出 types（歧义）。
// ---------------------------------------------------------------------------
const twoProviders = await writeWat(
	"two-providers.wat",
	`(component
  (component (;0;)
    (import "wasi:http/types@0.2.8" (instance (;0;)))
    (export "wasi:http/types@0.2.8" (instance 0))
  )
  (component (;1;)
    (import "wasi:http/types@0.2.8" (instance (;0;)))
    (export "wasi:http/types@0.2.8" (instance 0))
  )
  (import "wasi:http/types@0.2.8" (instance (;2;)))
  (export "wasi:http/incoming-handler@0.2.8" (instance 2))
)
`,
);
await $`wasm-tools parse ${twoProviders} -o ${OUT}/two-providers.wasm`.quiet();

// ---------------------------------------------------------------------------
// 7. provider-type-mismatch.wasm：provider 的 types 接口结构不同（make 参数
//    不同 → 类型不一致）。
// ---------------------------------------------------------------------------
const providerMismatch = await writeWat(
	"provider-type-mismatch.wat",
	`(component
  (import "wasi:http/types@0.2.8"
    (instance (;0;)
      (type (;0;) (func))
      (export "a" (func (type 0)))
    )
  )
  (component (;0;)
    (import "wasi:http/types@0.2.8"
      (instance (;0;)
        (type (;0;) (func (param "x" string)))
        (export "a" (func (type 0)))
      )
    )
    (export "wasi:http/types@0.2.8" (instance 0))
  )
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${providerMismatch} -o ${OUT}/provider-type-mismatch.wasm`.quiet();

// ---------------------------------------------------------------------------
// 8. unknown-interface.wasm / 9. unlisted-version.wasm / 10. entry-func-import.wasm
// ---------------------------------------------------------------------------
const unknownInterface = await writeWat(
	"unknown-interface.wat",
	`(component
  (component (;0;))
  (instance (;0;) (instantiate 0))
  (import "wasi:sockets/tcp@0.2.8" (instance (;1;)))
  (export "wasi:http/incoming-handler@0.2.8" (instance 1))
)
`,
);
await $`wasm-tools parse ${unknownInterface} -o ${OUT}/unknown-interface.wasm`.quiet();

const unlistedVersion = await writeWat(
	"unlisted-version.wat",
	`(component
  (component (;0;))
  (instance (;0;) (instantiate 0))
  (import "wasi:http/types@0.2.7" (instance (;1;)))
  (export "wasi:http/incoming-handler@0.2.8" (instance 1))
)
`,
);
await $`wasm-tools parse ${unlistedVersion} -o ${OUT}/unlisted-version.wasm`.quiet();

const entryFuncImport = await writeWat(
	"entry-func-import.wat",
	`(component
  (import "log" (func (;0;)))
)
`,
);
await $`wasm-tools parse ${entryFuncImport} -o ${OUT}/entry-func-import.wasm`.quiet();

// ---------------------------------------------------------------------------
// 11. extra-type-export.wasm：根导出条目数 ≠ 1（含 type 类导出）。
// ---------------------------------------------------------------------------
const extraTypeExport = await writeWat(
	"extra-type-export.wat",
	`(component
  (import "wasi:http/types@0.2.8"
    (instance (;0;)
      (export "r" (type (sub resource)))
    )
  )
  (alias export 0 "r" (type (;0;)))
  (export "t" (type 0))
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${extraTypeExport} -o ${OUT}/extra-type-export.wasm`.quiet();

// ---------------------------------------------------------------------------
// 12. nested-deep.wasm：6 层嵌套组件（节点/深度预算用）。入口保持合法
//     （import types + 根导出），内嵌 5 层嵌套 component → 6 节点/5 边/深度 6。
// ---------------------------------------------------------------------------
{
	let chain = "(component)";
	for (let i = 0; i < 4; i++) chain = `(component ${chain})`;
	const wat = `(component
  (import "wasi:http/types@0.2.8" (instance (;0;)))
  ${chain}
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`;
	const deep = await writeWat("nested-deep.wat", wat);
	await $`wasm-tools parse ${deep} -o ${OUT}/nested-deep.wasm`.quiet();
}

// ---------------------------------------------------------------------------
// 13. core-raw-imports.wasm：带 wasi 原始导入的核心模块（角色校验与入口角色
//     负例）。
// ---------------------------------------------------------------------------
const coreRaw = await writeWat(
	"core-raw.wat",
	`(module
  (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "random_get" (func (param i32 i32) (result i32)))
  (func (export "run") (result i32) i32.const 0)
)
`,
);
await $`wasm-tools parse ${coreRaw} -o ${OUT}/core-raw-imports.wasm`.quiet();

// ---------------------------------------------------------------------------
// 14. core-empty.wasm：空核心模块（角色校验基线）。
// ---------------------------------------------------------------------------
const coreEmpty = await writeWat("core-empty.wat", "(module)");
await $`wasm-tools parse ${coreEmpty} -o ${OUT}/core-empty.wasm`.quiet();

// ---------------------------------------------------------------------------
// 15. iweb-store-import.wasm：手工 component，导入 iweb:config@1.0.0/store
//     （形状与 packages/contracts/wit/iweb-config.wit 的 store 接口一致）。
//     wit deps 目录布局与 component embed 的组合在本机未能解析跨包依赖，
//     故以等价 WAT 直写（见报告）；接口形状逐字段对齐真实 WIT。
// ---------------------------------------------------------------------------
const iwebStoreImport = await writeWat(
	"iweb-store-import.wat",
	`(component
  (import "iweb:config/store@1.0.0"
    (instance (;0;)
      (type (;0;)
        (variant
          (case "not-assigned")
          (case "denied")
          (case "snapshot-expired")
          (case "revision-stale")
          (case "internal")
        )
      )
      (type (;1;) (result string (error 0)))
      (type (;2;) (func (param "key" string) (result 1)))
      (export "get" (func (type 2)))
    )
  )
  (export "wasi:http/incoming-handler@0.2.8" (instance 0))
)
`,
);
await $`wasm-tools parse ${iwebStoreImport} -o ${OUT}/iweb-store-import.wasm`.quiet();

// ---------------------------------------------------------------------------
// 16. import-root-export-identity.wasm：导入根导出身份（incoming-handler 是
//     export-only 能力）→ WASM_IMPORT_UNRESOLVED。
// ---------------------------------------------------------------------------
const importRootExport = await writeWat(
	"import-root-export-identity.wat",
	`(component
  (component (;0;))
  (instance (;0;) (instantiate 0))
  (import "wasi:http/incoming-handler@0.2.8" (instance (;1;)))
  (export "wasi:http/types@0.2.8" (instance 1))
)
`,
);
await $`wasm-tools parse ${importRootExport} -o ${OUT}/import-root-export-identity.wasm`.quiet();

// ---------------------------------------------------------------------------
// 清理中间产物并校验全部输出可被 wasm-tools 解码。
// ---------------------------------------------------------------------------
await $`rm -rf ${OUT}/tmp-*`.quiet();
await $`rm -f ${OUT}/*.wat`.quiet();
for (const file of await Array.fromAsync(new Bun.Glob("*.wasm").scan({ cwd: OUT }))) {
	await $`wasm-tools print ${OUT}/${file} -o /dev/null`.quiet();
	console.log(`ok ${file}`);
}
