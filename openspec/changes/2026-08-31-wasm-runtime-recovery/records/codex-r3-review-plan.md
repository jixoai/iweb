     activation 法条，并为 P+1 生成新的 snapshot/ref/digest，补 config 同等测试。

  5. #5：成立。
     证据：design D1、tasks §1.2 已将 catalog/capability revocation 与 admission pin 绑定，按
     pinned revision/hash 判定，撤销或缺失时 fail closed，不回退到最新记录。

  6. #6：不成立。
     证据：design.md:116-121、tasks.md:51-63 声称 unavailable pointer 与 recovery intent “同批”持久
     化，但现行控制态 CAS 只覆盖 control-state 文件（openspec/specs/wasm-application-runtime/
     spec.md:453-474），sidecar 是独立持久对象。若 pointer CAS 成功后在 sidecar 写入前崩溃，恢复又
     禁止从裸 Unavailable 推断目标，应用可永久 unavailable。另，文稿称新 admission 会使旧 intent 失
     效，但 admission 本身不递增 route generation。
     应改为原子 WAL/commit marker，或将 intent 纳入 control state，并测试 CAS 后、sidecar 前崩溃及
     新 admission 竞态。

  7. #7：成立。
     证据：design D2 与对应 tasks 已要求锁外 probe，并覆盖 probe 与锁内状态转换并发的重试/放弃语
     义，避免健康探测持有恢复锁或读取半提交状态。

  8. #8：成立。
     证据：修订后的 design D4、相关 delta 和 tasks 已要求使用 pinned policy digest，并在
     admission、启动及恢复路径进行一致性校验，不以当前最新 policy 替代已记录身份。

  9. #9：成立。
     证据：新增 status tier-honest 条款明确区分 celld 进程采样与 wasm engine 指标，保留
     unavailable，禁止用零值掩盖缺失采样、重启或归属不明状态，符合现行资源监控法条。

  10. #10：不成立。
     证据：design.md:152-156、tasks.md:65-75、177-180 要求 route event 携带 source:"kernel-
     recovery"；但现行 RouteEvent 是 exact wire schema，openspec/specs/wasm-application-runtime/
     spec.md:945-963 没有 source 字段，且 proposal.md:190-192 声明 activation wire 不变。
     应正式修改 RouteEvent/activation delta 并更新 parser、兼容性和 golden tests，或改用独立
     recovery audit event。

  11. #11：成立。
     证据：workspace-and-routes delta 与 tasks §4.1 已明确未知 host 为 404、已注册但无 Dispatcher
     handler 为通用 502，并禁止将幽灵 admission/health 状态映射为公开 503 或泄露诊断信息。

  12. m1：成立。
     证据：tasks §3.0 及 workspace delta 已按 systemless seed 实施：workspace 不植入 app manifest/
     code mirror，route registry 保持唯一应用身份源，seed 仅提供必要系统资源。

  ## 2. 第三轮修订新引入问题

  - 恢复 secret revision 与现行 rotation 法条冲突
    证据：design.md:139-148、tasks.md:56-75 对照现行法条 openspec/specs/wasm-application-runtime/
    spec.md:690-716。
    修复：在 delta 中显式修改 current-revision 规则，统一 activation、crash recovery、secret
    rotation 的 fence 语义；同时为 P+1 生成并校验新 snapshot/ref/digest。

  - control-state CAS 与 recovery-intent sidecar 非原子
    证据：design.md:116-121、tasks.md:51-63 对照 openspec/specs/wasm-application-runtime/
    spec.md:453-474。
    修复：引入同一 WAL/提交标记，或把 intent 直接纳入 control state；增加 CAS 成功但 sidecar 未落
    盘、新 admission 并发的崩溃恢复测试。

  - kernel-recovery route-event 字段破坏现有 wire contract
    证据：design.md:152-156、tasks.md:65-75、177-180 对照 openspec/specs/wasm-application-runtime/
    spec.md:945-963 及 proposal.md:190-192。
    修复：正式扩展 RouteEvent schema 并定义旧读者兼容策略，或使用独立 recovery audit event。

  - 设计文稿残留互相矛盾的旧风险描述
    证据：design.md:308-310 仍称无人激活时停在 unavailable 并将自动重激活列为后续讨论，但
    design.md:152-158、325-327 已采用自动恢复语义。
    修复：删除或改写该段，避免实现者按旧语义执行。

  ## 3. 综合评分：5/10

  相较 R2 的 5/10，第三轮正确补齐了 projection 形状、兼容读取、私有 health、锁外探测、policy
  digest、错误路径和 systemless seed，局部质量明显提高。
  但 secret-generation 语义、sidecar 原子性和 route-event wire 仍存在直接的法条或实现冲突，且都位于
  恢复核心路径。
  因此尚未达到可进入 Apply 的条件；需先完成上述三项协议级修订并补相应崩溃/兼容性验证。

─ Worked for 11m 44s ──────────────────────────────────────────────────────────────────────────────


› Ask Codex to do anything

  gpt-5.6-terra xhigh · ~/Dev/GitHub/iweb · Ready · Context 13% used · main · +1752 -0 · 258K wind…