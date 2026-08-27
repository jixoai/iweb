// 用户原始需求（2026-08-28，add-wasm-host-services 任务 7.5 加分项）：host-services
// linker 注册与「策略禁用即实例化失败」的端到端验证需要一个 import 三服务
// （iweb:kv@1.0.0/store、iweb:sql@1.0.0/store、iweb:logging@1.0.0/logger）的最小组件
// fixture——由 wasm-tools 直构（canonical ABI 手写、cabi_realloc 最小 bump 分配器，
// 不实现任何真实语义；只声明 import，从不调用）。
// 运行：bun tests/fixtures/wasm/generate-host-services-fixtures.sh.ts
// WIT 权威：kernel-rs/wasmd/wit（anchor world iweb:host/host-service-imports；包本体
// 逐字节来自 packages/contracts/wit），运行本脚本不需要网络。

import { $ } from "bun";

const EXPECTED_WASM_TOOLS = "wasm-tools 1.258.0";
const OUT = import.meta.dir;
const WIT = `${OUT}/../../../kernel-rs/wasmd/wit`;

const version = (await $`wasm-tools --version`.text()).trim();
if (version !== EXPECTED_WASM_TOOLS) {
	console.error(`expected ${EXPECTED_WASM_TOOLS}, found ${version}`);
	process.exit(1);
}

// 每接口只 import 一个函数（embed 允许 world import 的子集）；签名来自 wasm-tools
// 校验器：result payload 展平超限 → 末位返回指针（无 core 多值返回），guest 侧
// 必须导出 cabi_realloc（host→guest 拷贝的分配器）。
await Bun.write(`${OUT}/host-services-imports.wat`, `(module
  (import "iweb:kv/store@1.0.0" "set"
    (func $kv_set (param i32 i32 i32 i32 i32 i64 i32)))
  (import "iweb:sql/store@1.0.0" "execute"
    (func $sql_execute (param i32 i32 i32 i32 i32)))
  (import "iweb:logging/logger@1.0.0" "write"
    (func $log_write (param i32 i32 i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "cabi_realloc") (param $old i32) (param $old_size i32) (param $align i32) (param $new_size i32) (result i32)
    (local $ret i32)
    (local.set $ret
      (i32.and
        (i32.add (global.get $heap) (i32.sub (local.get $align) (i32.const 1)))
        (i32.xor (local.get $align) (i32.const -1))))
    (global.set $heap (i32.add (local.get $ret) (local.get $new_size)))
    (local.get $ret)
  )
)
`);

const wat = `${OUT}/host-services-imports.wat`;
const embedded = `${OUT}/tmp-host-services.embedded.wasm`;
await $`wasm-tools component embed ${WIT} ${wat} --world iweb:host/host-service-imports -o ${embedded}`.quiet();
await $`wasm-tools component new ${embedded} -o ${OUT}/host-services-imports.wasm`.quiet();
await $`rm -f ${embedded}`.quiet();

console.log("generated host-services-imports.wasm (imports kv/sql/logging only)");
