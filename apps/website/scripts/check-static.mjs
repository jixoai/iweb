#!/usr/bin/env node
// Orthogonal intents (2026-09-06): [link-check] 构建产物的静态抽查——
// dist/index.html 存在、站内绝对 URL 均带 SITE_BASE 前缀、内部链接目标
// 文件真实存在（base path 下 200 的等价静态证明）；[ai-export] llms.txt /
// llms-full.txt / 每页 .md 镜像存在且以绝对 URL 引用；[cname-gate] 非生产
// 构建不得携带 CNAME。
// Original request (2026-09-06, Asia/Shanghai): 新增 ./openiweb 官网站点。
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(packageRoot, "dist");
const base = process.env.SITE_BASE
  ? `/${String(process.env.SITE_BASE).replace(/^\/+|\/+$/g, "")}`
  : "";

const failures = [];
const ok = (message) => console.log(`[check-static] ok: ${message}`);
const fail = (message) => failures.push(message);

function walkFiles(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    return statSync(full).isDirectory() ? walkFiles(full) : [full];
  });
}

// 1. 页面产物存在。
const indexPath = path.join(distDir, "index.html");
if (!existsSync(indexPath)) fail("dist/index.html missing");
else ok("dist/index.html exists");

if (existsSync(indexPath)) {
  const html = readFileSync(indexPath, "utf8");

  // 2. 站内绝对 URL 必须带 base 前缀（漏前缀 = 根路径 404）；等于 base
  //    本身的目录 URL（如品牌块 homeHref）合法。
  const absolute = [...html.matchAll(/(?:href|src)="(\/[^"]*)"/g)].map((m) => m[1]);
  const unprefixed = absolute.filter((url) => base && url !== base && !url.startsWith(`${base}/`));
  if (base && unprefixed.length > 0) {
    fail(`absolute URLs missing the ${base} prefix: ${unprefixed.join(", ")}`);
  } else {
    ok(`all ${absolute.length} absolute page URLs carry the base prefix`);
  }

  // 3. 页面引用的本地文件真实存在（base 剥离后落盘路径）。
  const missing = absolute
    .map((url) => url.replace(/[#?].*$/, ""))
    .filter((url) => !url.startsWith("//"))
    .filter((url) => {
      const rel = base ? url.slice(base.length) : url;
      if (rel === "/" || rel === "") return false;
      const target = path.join(distDir, rel);
      if (existsSync(target) && statSync(target).isFile()) return false;
      // 目录 URL 允许落点为 <dir>/index.html。
      const asDirectory = path.join(distDir, rel, "index.html");
      return !(existsSync(asDirectory) && statSync(asDirectory).isFile());
    });
  if (missing.length > 0) fail(`referenced local targets missing on disk: ${missing.join(", ")}`);
  else ok("every referenced local target resolves to a file in dist");
}

// 4. AI export 层。
for (const file of ["llms.txt", "llms-full.txt", "index.md"]) {
  const target = path.join(distDir, file);
  if (!existsSync(target)) fail(`${file} missing`);
  else ok(`${file} exists`);
}
const llms = existsSync(path.join(distDir, "llms.txt"))
  ? readFileSync(path.join(distDir, "llms.txt"), "utf8")
  : "";
const expectedOrigin = process.env.SITE_URL ?? `https://jixoai.github.io${base}`;
const relativeLinks = [...llms.matchAll(/\]\(([^)]+)\)/g)]
  .map((m) => m[1])
  .filter((url) => !/^[a-z]+:\/\//i.test(url) && !url.startsWith("#"));
if (llms && relativeLinks.length > 0) {
  fail(`llms.txt carries non-absolute links: ${relativeLinks.slice(0, 5).join(", ")}`);
} else if (llms) {
  ok(`llms.txt links are absolute (origin ${expectedOrigin})`);
}

// 5. CNAME 门控。
const cnamePath = path.join(distDir, "CNAME");
if (process.env.SITE_CNAME === "1") {
  if (!existsSync(cnamePath)) fail("SITE_CNAME=1 but dist/CNAME missing");
  else ok(`dist/CNAME exists (${readFileSync(cnamePath, "utf8").trim()})`);
} else if (existsSync(cnamePath)) {
  fail("dist/CNAME present without SITE_CNAME=1");
} else {
  ok("no CNAME in this build (subpath/preview mode)");
}

if (failures.length > 0) {
  console.error("[check-static] FAILED");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log("[check-static] all checks passed");
