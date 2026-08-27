(module
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
