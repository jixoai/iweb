// 用户原始需求（2026-08-15）：rust-kernel-rustfs-storage §3.2 —— canonical 摘要是跨实现契约，
// golden vectors 由 TS 权威生成，bun 与 cargo 测试双侧消费同一文件。
// 正交意图：向量必须包含 localeCompare 与字节序分歧的路径对（标点权重、大小写、重音）与二进制内容。
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

interface Case { readonly name: string; readonly files: readonly { readonly path: string; readonly contentBase64: string }[]; }
const enc = (s: string): string => Buffer.from(s, "utf8").toString("base64");
const bin = (bytes: readonly number[]): string => Buffer.from(bytes).toString("base64");

const cases: readonly Case[] = [
	{ name: "empty-content-file", files: [{ path: "app/main.js", contentBase64: enc("") }] },
	{
		name: "collation-divergence-punctuation",
		// ICU treats "-" as secondary-weighted: "ab" < "a-b" collation vs "a-b" < "ab" byte order
		files: [
			{ path: "a-b.txt", contentBase64: enc("dash") },
			{ path: "ab.txt", contentBase64: enc("plain") },
		],
	},
	{
		name: "collation-divergence-case",
		files: [
			{ path: "App.js", contentBase64: enc("upper") },
			{ path: "app.js", contentBase64: enc("lower") },
			{ path: "b.js", contentBase64: enc("bee") },
		],
	},
	{
		name: "collation-divergence-accent",
		files: [
			{ path: "café.txt", contentBase64: enc("accent") },
			{ path: "cafe.txt", contentBase64: enc("no-accent") },
			{ path: "cz.txt", contentBase64: enc("zee") },
		],
	},
	{
		name: "nested-paths-and-binary",
		files: [
			{ path: "app/iweb.json", contentBase64: enc('{\n  "kind": "celld"\n}\n') },
			{ path: "app/sub/deep/module.js", contentBase64: enc("export const value = 42;\n") },
			{ path: "app/blob.bin", contentBase64: bin([0, 1, 2, 255, 254, 0, 10, 13]) },
			{ path: "app/empty.bin", contentBase64: bin([]) },
		],
	},
	{
		name: "newline-in-content",
		files: [
			{ path: "a.txt", contentBase64: enc("line1\nline2\n") },
			{ path: "z.txt", contentBase64: enc("\n") },
		],
	},
];

const vectors = cases.map((c) => {
	const files = c.files.map((f) => ({ path: f.path, content: Buffer.from(f.contentBase64, "base64") }));
	return { name: c.name, files: c.files, digest: packageFilesDigest(files) };
});

const out = { version: 1, algorithm: "sha256 over sorted-by-utf8-byte-order of (path \\0 decimal-length \\0 content)", generatedBy: "TS authority contracts/package-collection.ts", cases: vectors };
const dir = join(import.meta.dir, "..", "contracts", "fixtures");
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, "digest-vectors.json"), JSON.stringify(out, null, 2) + "\n");
console.log("wrote", vectors.length, "vectors");
