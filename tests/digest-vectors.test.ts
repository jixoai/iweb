// 用户原始需求（2026-08-15）：bun 侧消费 golden vectors —— 与 cargo 侧吃同一份文件，
// 证明 canonical 摘要跨实现逐字节一致（rust-kernel-rustfs-storage §3.2）。
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

interface Vector { readonly name: string; readonly files: readonly { readonly path: string; readonly contentBase64: string }[]; readonly digest: string; }
const doc = JSON.parse(readFileSync(join(import.meta.dir, "..", "packages", "contracts", "fixtures", "digest-vectors.json"), "utf8")) as { version: number; cases: readonly Vector[] };

describe("golden digest vectors (TS side)", () => {
	test("fixture version is pinned", () => {
		expect(doc.version).toBe(1);
		expect(doc.cases.length).toBeGreaterThanOrEqual(6);
	});
	for (const vector of doc.cases) {
		test(`vector: ${vector.name}`, () => {
			const files = vector.files.map((f) => ({ path: f.path, content: Buffer.from(f.contentBase64, "base64") }));
			expect(packageFilesDigest(files)).toBe(vector.digest);
		});
	}
	test("vectors include the collation-divergence pairs (byte order, not ICU)", () => {
		const names = doc.cases.map((c) => c.name);
		expect(names).toContain("collation-divergence-punctuation");
		expect(names).toContain("collation-divergence-case");
		expect(names).toContain("collation-divergence-accent");
	});
});
