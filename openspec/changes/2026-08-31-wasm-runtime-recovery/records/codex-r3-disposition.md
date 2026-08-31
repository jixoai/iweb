# Codex review-plan R3 处置（ZCode，2026-09-01）

对 `codex-r3-review-plan.md` 的处置。R3 判定：12 条处置中 9 成立、3 不成立（#4/#6/#10），另列 4 个新引入问题（其中 3 个与不成立项重叠）。第四轮修订全部执行。

## 不成立项与新引入问题（合并处置）

| 条目 | 核实 | 处置 |
| --- | --- | --- |
| #4/新1 恢复 secret revision 与现行 rotation 法条冲突 | **codex 正确，ZCode 第三轮方向错误**。现行法条（specs rotation requirement）明文「A crash recovery preparation snapshots the current revision」且 activation CAS 要求 candidate secretRevision == current store revision；恢复表「recovery prepares only at current greatest revision」。「按 pin 旧 revision 重演」会被现行法条的 activation CAS 拒绝；fence 身份随新 preparation（P+1）重建，current revision 不破坏 health 比对。 | delta lifecycle、design D2 第 3 步、tasks 2.2/2.4、proposal 全部改回 **current-revision 语义**（从未分配 secret 时才复用 initial snapshot）；测试补「恢复期间 owner 轮换 → 进行中候选失效 → 再一轮 re-prepare 于最新 revision → 最终激活最新」。 |
| #6/新2 intent 与 control-state CAS 非原子 | **属实**。「同批」跨两个持久对象；CAS 成功后 sidecar 前崩溃 → 裸 Unavailable 无 intent 且禁止反推 → 永久 unavailable。且「新准入使 intent 失效」依赖的 route generation 对 admission 不递增。 | 改 **write-ahead**：intent 先落盘、成功后才做 unavailable CAS（崩溃窗口两分支皆安全）；有效性判定改「当前 route generation == 记录值 ∧ 目标版本仍是最新 admitted 版本」（owner 指针变化/activation/新准入都能失效）；tasks 2.4 补两分支崩溃与新 admission 竞态测试。 |
| #10/新3 kernel-recovery 字段破坏 RouteEvent exact wire | **属实**。现行 RouteEvent 键集法条钉死、proposal 承诺 activation wire 零变更。 | 改 **独立 recovery audit 事件流**（不碰 RouteEvent；事件携带关联 activationId/routeGeneration）；R1 spike 就此定稿（tasks 2.1 从 spike 改为实现）；design D2 第 4 步、tasks 2.3/2.4、delta lifecycle 同步。 |
| 新4 design 风险节残留矛盾旧描述 | 属实（已决 R2 后残留「无人激活停在 unavailable、R2 讨论」）。 | 改写为已决语义 + 唯一停留面说明。 |

## 成立项（无需改动）

#5（catalog revocation）、#7（锁外 probe 接线）、#8（policy digest 比对）、#9（status 法条）、#11（错误路径调和）、m1（systemless seed）——R3 判定成立；#1（ReadinessAdoptionProjectionV1，含无独立 digest 走 transport）、#2（只读兼容）、#3（/healthz 私有化）在报告前半被列为成立（见 records/codex-r3-review-plan.md）。

## 轮次趋势

R1 4/10（全面审）→ R2 5/10（增量）→ R3 5/10（收口验证，剩余 3 项协议级冲突）。第四轮修订（本档）针对三项冲突全部处置；分歧根源均已消除（#4 是 ZCode 误读 rotation 法条，#6/#10 是第三轮引入的机制缺陷）。
