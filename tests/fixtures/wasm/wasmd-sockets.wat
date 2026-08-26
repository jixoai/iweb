(module
  (import "wasi:sockets/instance-network@0.2.8" "instance-network" (func $default_network (result i32)))
  (func (export "wasi:http/incoming-handler@0.2.8#handle") (param i32 i32)
    (drop (call $default_network))
  )
)
