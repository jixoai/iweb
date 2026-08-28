<!-- 用户原始需求（2026-08-29）：简化 wasm 宿主服务——去掉 V1/V2 双轨与跨语言 golden 锁。 -->
<!-- 正交意图：单版本宿主服务；Rust 为唯一 wire 权威；TS 契约为便捷封装非权威对拍。 -->

## Why

add-wasm-host-services（13 轮评审）证明 V1/V2 双轨 + 跨语言 golden 锁的架构复杂度远超其安全收益。
功能本身（KV/SQL/Logging 三能力 + wasmd 内嵌 SQLite 后端 + 身份绑定）已完整实现且测试充分；
卡住归档的只是「V2 命令校验是否强制 capability 字段为 required」这类严格性问题。
本变更将已实现的功能简化为单版本形态，去掉双轨维护成本。

## What Changes

- **单版本宿主服务**：host services 只在 `iweb-wasmd-abi@1.1.0` 上提供；V1 应用不获得 host services（无版本联合、无双轨）。
- **Rust 为唯一 wire 权威**：wire 类型（命令/事件/指针/租约）由 kernel-rs 定义；TS contracts 提供类型化便捷访问但不做跨语言 golden 对拍。
- **简化身份**：指针身份 = applicationId + versionId + hostServicePolicyDigest（3 字段，非 10 字段）；catalog/capability 通过 admissionProofDigest 传递性绑定。
- **去掉版本联合**：所有 wire 类型只有一种形态（无 V1/V2 union、无跨版本拒绝逻辑）。

## Non-goals

- 不改变已实现的安全边界（身份门/quota ledger/出网 fail-closed/WIT 经 frame 原子路径）。
- 不删除已实现的代码——只简化 wire 层的类型结构与校验。

