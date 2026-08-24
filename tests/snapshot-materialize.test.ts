// 用户原始需求（2026-08-14）：沙箱必须从物化且摘要校验过的不可变快照运行；缺失/残缺/摘要不符 fail closed，绝不建 pod。
// 正交意图：2.33 本地证据——注入 exec 与真实文件系统，验证下载布局、二进制安全、失败类别与 verify 重查。
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSnapshotMaterializer, verifyMaterializedSnapshot, MaterializationFailure } from "../supervisor/snapshot-materialize.ts";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

describe("snapshot materialization (2.33)", () => {
	const digestFor = (files: { path: string; content: Buffer }[]) => packageFilesDigest(files);

	function fakeMcStore(objects: Map<string, Buffer>) {
		const calls: string[] = [];
		const exec = (command: string, args: readonly string[], options?: { binary?: boolean }) => {
			calls.push(args.join(" "));
			const key = args[1];
			const value = objects.get(key);
			if (value === undefined) throw new Error("mc: object not found: " + key);
			return options?.binary === true ? Buffer.from(value) : value.toString("utf8");
		};
		return { exec, calls };
	}

	test("materializes the indexed files, writes the index, and verifies the digest", async () => {
		const files = [
			{ path: "app/index.js", content: Buffer.from("export default {};\n") },
			{ path: "app/assets/logo.png", content: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff]) },
		];
		const digest = digestFor(files);
		const objects = new Map<string, Buffer>();
		objects.set("local/iweb-system/packages/" + digest + "/files.json", Buffer.from(JSON.stringify({ v: 1, files: files.map((f) => f.path) })));
		for (const file of files) objects.set("local/iweb-system/packages/" + digest + "/files/" + file.path, file.content);
		const mc = fakeMcStore(objects);
		const directory = mkdtempSync(join(tmpdir(), "iweb-mat-"));
		try {
			const materialize = createSnapshotMaterializer("/state", { exec: mc.exec, alias: "local/iweb-system" });
			await materialize(digest, join(directory, "packages", digest));
			expect(readFileSync(join(directory, "packages", digest, "app/assets/logo.png"))).toEqual(files[1].content);
			expect(readFileSync(join(directory, "packages", digest, "app/index.js")).toString("utf8")).toBe("export default {};\n");
			expect(JSON.parse(readFileSync(join(directory, "packages", digest, "files.json"), "utf8")).files).toHaveLength(2);
			expect(verifyMaterializedSnapshot(digest, join(directory, "packages", digest))).toBe(true);
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});

	test("fails closed with missing when the snapshot index is absent", async () => {
		const mc = fakeMcStore(new Map());
		const materialize = createSnapshotMaterializer("/state", { exec: mc.exec });
		let caught: unknown = null;
		try { await materialize("a".repeat(64), "/tmp/never"); } catch (error) { caught = error; }
		expect(caught).toBeInstanceOf(MaterializationFailure);
		expect((caught as MaterializationFailure).kind).toBe("missing");
	});

	test("fails closed with partial when an indexed file is missing or the index is malformed", async () => {
		const digest = "b".repeat(64);
		const mc = fakeMcStore(new Map([
			["local/iweb-system/packages/" + digest + "/files.json", Buffer.from("{\"files\":[\"only.js\"]}")],
		]));
		const materialize = createSnapshotMaterializer("/state", { exec: mc.exec });
		let caught: unknown = null;
		try { await materialize(digest, "/tmp/never"); } catch (error) { caught = error; }
		expect((caught as MaterializationFailure).kind).toBe("partial");
		const mc2 = fakeMcStore(new Map([["local/iweb-system/packages/" + digest + "/files.json", Buffer.from("not-json")]]));
		const m2 = createSnapshotMaterializer("/state", { exec: mc2.exec });
		let caught2: unknown = null;
		try { await m2(digest, "/tmp/never"); } catch (error) { caught2 = error; }
		expect((caught2 as MaterializationFailure).kind).toBe("partial");
	});

	test("fails closed with digest-mismatch when restored content does not match the digest", async () => {
		const files = [{ path: "app/index.js", content: Buffer.from("original\n") }];
		const digest = digestFor(files);
		const mc = fakeMcStore(new Map([
			["local/iweb-system/packages/" + digest + "/files.json", Buffer.from(JSON.stringify({ files: ["app/index.js"] }))],
			["local/iweb-system/packages/" + digest + "/files/app/index.js", Buffer.from("tampered\n")],
		]));
		const materialize = createSnapshotMaterializer("/state", { exec: mc.exec });
		let caught: unknown = null;
		try { await materialize(digest, "/tmp/never"); } catch (error) { caught = error; }
		expect((caught as MaterializationFailure).kind).toBe("digest-mismatch");
	});

	test("verifyMaterializedSnapshot detects tampering of an already-materialized tree", () => {
		const files = [{ path: "a.js", content: Buffer.from("x") }];
		const digest = digestFor(files);
		const directory = mkdtempSync(join(tmpdir(), "iweb-ver-"));
		try {
			const target = join(directory, "packages", digest);
			mkdirSync(target, { recursive: true });
			writeFileSync(join(target, "files.json"), JSON.stringify({ files: ["a.js"] }));
			writeFileSync(join(target, "a.js"), "x");
			expect(verifyMaterializedSnapshot(digest, target)).toBe(true);
			writeFileSync(join(target, "a.js"), "tampered");
			expect(verifyMaterializedSnapshot(digest, target)).toBe(false);
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});
});