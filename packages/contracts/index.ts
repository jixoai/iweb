// typescript-monorepo：根入口是包身份 marker（全量 re-export 因循环依赖不可行）。
// Node tsconfig 只做全量源码类型门禁；运行时消费一律子路径直连 contracts/<module>.ts。
export const CONTRACTS_NODE_ENTRY = true;
