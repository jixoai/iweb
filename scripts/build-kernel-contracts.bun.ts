// 用户原始需求（2026-08-14）：Kernel 是 CommonJS 进程；把安全契约模块编译为单文件 CJS 供其 require，保持单一权威实现。
// 正交意图：构建脚本在节点镜像构建前执行；输出 kernel/contracts-bundle.cjs 随 kernel/ 一起 COPY。
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const entry = join(projectRoot, "kernel/contracts-entry.ts");
const output = join(projectRoot, "kernel/contracts-bundle.cjs");

const result = Bun.spawnSync(["bun", "build", entry, "--target=node", "--format=cjs", "--outfile", output], { cwd: projectRoot, stdout: "inherit", stderr: "inherit" });
if (result.exitCode !== 0) throw new Error("kernel contracts bundle build failed");
process.stdout.write("kernel contracts bundle written to kernel/contracts-bundle.cjs\n");
