#!/usr/bin/env node
// Orthogonal intents (2026-09-06): [cname-gate] Owner 管理的自定义域名
// CNAME 门控——SITE_CNAME=1 且 SITE_CNAME_DOMAIN 给定（默认
// iweb.jixoai.com）时写 dist/CNAME，其余构建保持 CNAME-free（GitHub
// Pages 项目页路径形态）；[no-op] 其余情况零写入，绝不删改既有产物。
// Original request (2026-09-06, Asia/Shanghai): 新增 ./openiweb 官网站点。
// 切换契约：根路径服务 = SITE_CNAME=1 + SITE_BASE 留空（+ 按需 SITE_URL）。
import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(packageRoot, "dist");

if (process.env.SITE_CNAME === "1") {
  const domain = process.env.SITE_CNAME_DOMAIN ?? "iweb.jixoai.com";
  writeFileSync(path.join(distDir, "CNAME"), `${domain}\n`);
  console.log(`[postbuild] CNAME written (${domain}) — root-serving build`);
} else {
  console.log("[postbuild] CNAME skipped (preview/subpath build)");
}
