// 用户原始需求（2026-08-26，add-wasm-runtime 任务 3.1-3.4）：wasmd 端到端测试需要
// 真实 wasi:http@0.2.8 组件 fixture——由 wasm-tools 直构（canonical ABI 手写，不实现
// 真实 HTTP 语义），验证宿主调用路径（incoming-handler 调用/响应设置）与拒绝路径
// （epoch 死循环终止单请求、矩阵外 import 实例化失败）。
// 正交意图：fixture 单一来源生成（WAT/WIT 源内联）；wasm-tools 版本钉死校验；
// WIT 闭包来自 wasi-http v0.2.8 官方 tag（git clone --depth 1 --branch v0.2.8），
// 一次性提交进 wasmd-wit-0.2.8/；运行本脚本不再需要网络。
// 运行：bun tests/fixtures/wasm/generate-wasmd-fixtures.sh.ts
// （与 generate-wasm-fixtures.sh.ts 分离：那套是闭包 scanner 的最小形状 fixture，
// 本套是 wasmd 宿主的真实类型身份 fixture；wasi:http@0.2.8 组件在 wasmtime 48 的
// 0.2.12 宿主栈上经结构子类型化实例化——版本钉死见 kernel-rs/wasmd/Cargo.toml。）

import { $ } from "bun";

const EXPECTED_WASM_TOOLS = "wasm-tools 1.258.0";
const OUT = import.meta.dir;
const WIT = `${OUT}/wasmd-wit-0.2.8`;

const version = (await $`wasm-tools --version`.text()).trim();
if (version !== EXPECTED_WASM_TOOLS) {
	console.error(`expected ${EXPECTED_WASM_TOOLS}, found ${version}`);
	process.exit(1);
}

// WIT 闭包已在库中（wasi-http v0.2.8 tag 的 wit/ 全量：types/handler/proxy + deps/）。
// 锚点 world：只 import wasi:http/types@0.2.8（handle 借用的资源所在）并 export
// incoming-handler——矩阵允许 import 集的最小子集。
await Bun.write(`${WIT}/deps/local/wasmd-fixture.wit`, `package local:wasmd-fixture;

world noop {
  import wasi:http/types@0.2.8;
  export wasi:http/incoming-handler@0.2.8;
}

world sockets-fixture {
  import wasi:sockets/instance-network@0.2.8;
  import wasi:http/types@0.2.8;
  export wasi:http/incoming-handler@0.2.8;
}
`);

// 1. noop：handle 直接返回（guest 从不调用 response-outparam::set → 宿主侧
//    "guest never invoked set" 负路径）。
await Bun.write(`${OUT}/wasmd-noop.wat`, `(module
  (func (export "wasi:http/incoming-handler@0.2.8#handle") (param i32 i32))
)
`);

// 2. loop：handle 死循环 → epoch 墙钟 deadline 终止该执行（进程不崩）。
await Bun.write(`${OUT}/wasmd-loop.wat`, `(module
  (func (export "wasi:http/incoming-handler@0.2.8#handle") (param i32 i32)
    (loop $spin (br $spin))
  )
)
`);

// 3. respond：canonical ABI 直构默认 200 响应（[constructor]fields →
//    [constructor]outgoing-response → [static]response-outparam.set）。
//    result<own<outgoing-response>, error-code> 的 flat 布局
//    [I32,I32,I32,I32,I64,I32,I32,I32,I32] 由 wasm-tools 校验器给出（判别 0 =
//    ok，payload 槽 0 = 响应句柄，其余清零）。
await Bun.write(`${OUT}/wasmd-respond.wat`, `(module
  (import "wasi:http/types@0.2.8" "[constructor]fields" (func $ctor_fields (result i32)))
  (import "wasi:http/types@0.2.8" "[constructor]outgoing-response" (func $ctor_response (param i32) (result i32)))
  (import "wasi:http/types@0.2.8" "[static]response-outparam.set" (func $set (param i32 i32 i32 i32 i64 i32 i32 i32 i32)))
  (func (export "wasi:http/incoming-handler@0.2.8#handle") (param $req i32) (param $out i32)
    (local $fields i32)
    (local $resp i32)
    (local.set $fields (call $ctor_fields))
    (local.set $resp (call $ctor_response (local.get $fields)))
    (call $set (local.get $out) (i32.const 0) (local.get $resp) (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))
  )
  (memory (export "memory") 1)
)
`);

// 4. sockets：import wasi:sockets/instance-network@0.2.8（矩阵外）→ wasmd 启动期
//    pre-instantiation 即 fail-closed。
await Bun.write(`${OUT}/wasmd-sockets.wat`, `(module
  (import "wasi:sockets/instance-network@0.2.8" "instance-network" (func $default_network (result i32)))
  (func (export "wasi:http/incoming-handler@0.2.8#handle") (param i32 i32)
    (drop (call $default_network))
  )
)
`);

async function build(name: string, world: string): Promise<void> {
	const wat = `${OUT}/wasmd-${name}.wat`;
	const embedded = `${OUT}/tmp-wasmd-${name}.embedded.wasm`;
	await $`wasm-tools component embed ${WIT} ${wat} --world local:wasmd-fixture/${world} -o ${embedded}`.quiet();
	await $`wasm-tools component new ${embedded} -o ${OUT}/wasmd-proxy-${name}.wasm`.quiet();
	await $`rm -f ${embedded}`.quiet();
}

await build("noop", "noop");
await build("loop", "noop");
await build("respond", "noop");
await build("sockets", "sockets-fixture");

console.log("generated wasmd-proxy-{noop,loop,respond,sockets}.wasm");
