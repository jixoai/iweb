// Worker-safe 子集入口（typescript-monorepo design）：闭包内无 node builtin。
// manifest 验证器是纯函数（无 Node 依赖），Worker 可直接消费。
export { validateApplicationManifest, validateResources, validateEgress } from "./manifest.ts";
export { issue } from "./validation.ts";
