<!-- 正交意图：单版本化 wire 类型；TS 契约降级为便捷封装；简化指针身份。 -->

# simplify-wasm-host-services Tasks

## 1. Wire 类型单版本化
- [ ] 1.1 Rust：去掉所有 V1/V2 版本联合（ActivationCommand/RouteEvent/RollbackRecord/Pointer/Lease 只留一种形态），V2 字段变为唯一字段（非 Option）
- [ ] 1.2 TS：wasm-execution.ts / wasm-health.ts 的版本联合展开为单类型；去掉跨版本拒绝码
- [ ] 1.3 测试：全量电池绿（去掉跨语言 golden 对拍的失败路径）

## 2. TS 契约降级
- [ ] 2.1 删除 TS↔Rust 双向 golden 测试（保留单侧 digest 复算测试）
- [ ] 2.2 TS 类型注释标注「Rust 为权威，本文件为便捷访问」

## 3. 指针身份简化
- [ ] 3.1 Rust：WasmActivePointer 的 v2_* 字段合并为单一 `hostServicePolicyDigest: Option<String>` + `executionTuple: Option<(P, E, fence)>`（3 字段非 7 字段）
- [ ] 3.2 TS：requireWasmActivePointer 接受简化字段集

## 4. 验证
- [ ] 4.1 全量电池：cargo + bun + typecheck + openspec validate
