// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x）：TypeScript 一级参考语言的最小
// wasi:http@0.2.8 proxy world 组件——导出 incoming-handler，恒定返回 200 文本。
// 正交意图：唯一意图是「健康探针级 handler」；不读请求、不 fetch、不打日志。
//
// 运行形态与编码事实（2026-08-26 实证，componentize-js 0.22.0 = npm 最新 2026-07-31）：
// - 本文件由 build.sh.ts 用 bun 转译为 JS 后交 @bytecodealliance/componentize-js
//   （StarlingMonkey 引擎）编译成组件；不进入任何浏览器或宿主 bundle。
// - fetch-event 自动挂接对 0.2.8 导出不成立：splicer 的 incoming-handler 版本改写表只有
//   {0.2.0..0.2.3, 0.2.10}（spidermonkey-embedding-splicer.core.wasm 字符串实证），
//   `addEventListener("fetch")` 路径对 wasi:http@0.2.8 world 得到空导出、componentNew 直接
//   失败。README 的手工路径——从 ES module 导出 `incomingHandler` 对象——按目标 world 的
//   全限定导出身份生成绑定，是 0.2.8 导出在钉死工具链下唯一可用的写法。
// - StarlingMonkey 引擎自身的 import 表面被钉在 wasi 0.2.10（含 http/types@0.2.10），与
//   revision-1 能力矩阵的 0.2.8 精确版本不匹配；且引擎 core module 的 0.2.8 命名 raw import
//   面经 inline core instance 接线（scanner 不建模）——闭包扫描以 WASM_IMPORT_UNMAPPABLE
//   fail-closed（先于版本分类），这是 TS 线的已记录工具链缺口，见 tests/wasm-lang-fixtures.test.ts。

/** 每语言 fixture 的响应体刻意互异，保证三者 packageDigest 必然不同。 */
const BODY = "iweb lang-ts wasi-http proxy fixture\n";

/** StarlingMonkey 引擎提供的 Response 全局（http feature）；绑定侧签名由生成器消费。 */
declare const Response: new (body: string, init?: { status?: number; headers?: Record<string, string> }) => Response;

/** 手工 incoming-handler：唯一参数约定是 (request, responseOut)，引擎包装后注入。 */
export const incomingHandler = {
  handle(_request: unknown, responseOut: { set(response: Response): void }): void {
    responseOut.set(new Response(BODY, { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } }));
  },
};
