// 用户原始需求（2026-08-14）：验证 canonical 包快照与短生命周期应用存储能力；跨应用/复用/过期/非法路径/越界大小全部失败。
// 正交意图：4.1/4.3/4.4/4.5。
import { describe, expect, test } from "bun:test";
import {
	canonicalSerializeManifest,
	collectPackage,
	versionDigest,
	MAX_PACKAGE_FILE_BYTES,
	type CollectPackageOptions,
	type PackageFileEntry,
	type PackageSnapshot,
	type PackageStat,
} from "../packages/contracts/package-collection.ts";
import {
	applicationDataPrefix,
	applicationVersionPrefix,
	DurableNonceStore,
	issueStorageCapability,
	verifyStorageCapability,
	type NonceReplayStore,
} from "../packages/contracts/storage-gateway.ts";
import { type ApplicationManifest } from "../packages/contracts/manifest.ts";
import { type ValidationResult } from "../packages/contracts/validation.ts";

const SECRET = "gateway-secret-0123456789abcdef0"; // 32 bytes
const APPLICATION_ID = "notes";

function packageManifest(): ApplicationManifest {
	return {
		schemaVersion: 1,
		name: "notes",
		runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint: "app/index.js" },
		assets: { root: "app" },
		resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 1024 * 2 ** 20 },
		storage: { persistent: true, requestBytes: 256 * 2 ** 20 },
		egress: { default: "deny", allow: [{ host: "api.example.com", port: 443 }] },
	};
}

function statRegular(size: number, mtimeNs = 1000): PackageStat {
	return { kind: "regular", size, mtimeNs };
}

function collectWith(overrides: Partial<CollectPackageOptions>): ValidationResult<PackageSnapshot> {
	const files: PackageFileEntry[] = [
		{ path: "app/index.js", size: 5, kind: "file" },
		{ path: "app/index.html", size: 5, kind: "file" },
	];
	const stats: Record<string, PackageStat> = {
		"app/index.js": statRegular(5),
		"app/index.html": statRegular(5),
	};
	const contents: Record<string, string> = { "app/index.js": "hello", "app/index.html": "world" };
	return collectPackage({
		manifest: packageManifest(),
		files,
		readContent: (path) => {
			const value = contents[path];
			if (value === undefined) throw new Error("missing " + path);
			return Buffer.from(value, "utf8");
		},
		statFile: (path) => stats[path] ?? null,
		...overrides,
	});
}

function issueCodes(result: ValidationResult<PackageSnapshot>): string[] {
	return result.ok ? [] : result.errors.map((error) => error.code);
}

describe("canonical package collection", () => {
	test("produces a stable content-addressed digest without executing package code", () => {
		const result = collectWith({});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.digest).toMatch(/^[a-f0-9]{64}$/);
			expect(result.value.fileCount).toBe(2);
			expect(result.value.files.map((file) => file.path)).toEqual(["app/index.html", "app/index.js"]);
		}
	});

	test("rejects traversal, absolute, and control-character paths", () => {
		for (const path of ["../escape", "/etc/passwd", "a/../../b", "a b", "a\u0000b"]) {
			const result = collectPackage({
				manifest: packageManifest(),
				files: [{ path, size: 1, kind: "file" }],
				readContent: () => Buffer.alloc(0),
				statFile: () => null,
			});
			expect(result.ok).toBe(false);
		}
	});

	test("rejects duplicate canonical paths", () => {
		const result = collectPackage({
			manifest: packageManifest(),
			files: [
				{ path: "app/a.js", size: 1, kind: "file" },
				{ path: "app//a.js", size: 1, kind: "file" },
				{ path: "app/./a.js", size: 1, kind: "file" },
			],
			readContent: () => Buffer.from("x"),
			statFile: () => statRegular(1),
		});
		expect(issueCodes(result)).toContain("PACKAGE_DUPLICATE_PATH");
	});

	test("treats case-distinct paths as different files", () => {
		const result = collectPackage({
			manifest: packageManifest(),
			files: [
				{ path: "app/index.js", size: 1, kind: "file" },
				{ path: "app/Index.js", size: 1, kind: "file" },
			],
			readContent: () => Buffer.from("x"),
			statFile: () => statRegular(1),
		});
		expect(result.ok).toBe(true);
	});

	test("rejects symlink, non-regular, and missing files", () => {
		const symlink = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: 5, kind: "file" }],
			readContent: () => Buffer.from("hello"),
			statFile: () => ({ kind: "symlink", size: 5, mtimeNs: 1000 }),
		});
		expect(issueCodes(symlink)).toContain("PACKAGE_SYMLINK");

		const nonRegular = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: 5, kind: "file" }],
			readContent: () => Buffer.from("hello"),
			statFile: () => ({ kind: "other", size: 5, mtimeNs: 1000 }),
		});
		expect(issueCodes(nonRegular)).toContain("PACKAGE_NON_REGULAR");

		const missing = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: 5, kind: "file" }],
			readContent: () => Buffer.from("hello"),
			statFile: () => ({ kind: "missing", size: 0, mtimeNs: 0 }),
		});
		expect(issueCodes(missing)).toContain("PACKAGE_MISSING");
	});

	test("rejects size mismatches between stat, content, and declared size", () => {
		const statMismatch = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: 5, kind: "file" }],
			readContent: () => Buffer.from("hello"),
			statFile: () => statRegular(6),
		});
		expect(issueCodes(statMismatch)).toContain("SIZE_MISMATCH");

		const contentMismatch = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: 999, kind: "file" }],
			readContent: () => Buffer.from("x"),
			statFile: () => statRegular(999),
		});
		expect(issueCodes(contentMismatch)).toContain("SIZE_MISMATCH");
	});

	test("rejects TOCTOU changes between the two stat calls", () => {
		let calls = 0;
		const result = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: 5, kind: "file" }],
			readContent: () => Buffer.from("hello"),
			statFile: () => {
				calls += 1;
				return calls === 1 ? statRegular(5, 1000) : statRegular(5, 2000);
			},
		});
		expect(issueCodes(result)).toContain("PACKAGE_TOCTOU_CHANGED");
		expect(calls).toBe(2);

		calls = 0;
		const sizeChange = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: 5, kind: "file" }],
			readContent: () => Buffer.from("hello"),
			statFile: () => {
				calls += 1;
				return calls === 1 ? statRegular(5, 1000) : statRegular(6, 1000);
			},
		});
		expect(issueCodes(sizeChange)).toContain("PACKAGE_TOCTOU_CHANGED");
	});

	test("rejects oversized files and packages", () => {
		const oversized = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.js", size: MAX_PACKAGE_FILE_BYTES + 1, kind: "file" }],
			readContent: () => Buffer.alloc(0),
			statFile: () => statRegular(1),
		});
		expect(issueCodes(oversized)).toContain("INVALID_SIZE");

		const tooMany = collectPackage({
			manifest: packageManifest(),
			files: Array.from({ length: 10_001 }, (_, i): PackageFileEntry => ({ path: "app/f" + i, size: 0, kind: "file" })),
			readContent: () => Buffer.alloc(0),
			statFile: () => statRegular(0),
		});
		expect(issueCodes(tooMany)).toContain("PACKAGE_TOO_MANY_FILES");
	});

	test("rejects a manifest whose entrypoint is missing from the snapshot", () => {
		const result = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "app/index.html", size: 5, kind: "file" }],
			readContent: () => Buffer.from("world"),
			statFile: () => statRegular(5),
		});
		const codes = issueCodes(result);
		expect(codes).toContain("MANIFEST_ENTRYPOINT_MISSING");
		expect(codes).not.toContain("MANIFEST_ENTRYPOINT_OUTSIDE_ASSETS");
	});

	test("rejects an entrypoint outside the declared assets root", () => {
		const base = packageManifest();
		const manifest: ApplicationManifest = { ...base, runtime: { ...base.runtime, entrypoint: "index.js" } };
		const result = collectPackage({
			manifest,
			files: [
				{ path: "index.js", size: 5, kind: "file" },
				{ path: "app/index.html", size: 5, kind: "file" },
			],
			readContent: () => Buffer.from("hello"),
			statFile: () => statRegular(5),
		});
		const codes = issueCodes(result);
		expect(codes).toContain("MANIFEST_ENTRYPOINT_OUTSIDE_ASSETS");
		expect(codes).not.toContain("MANIFEST_ENTRYPOINT_MISSING");
	});

	test("rejects an assets root with no collected file beneath it", () => {
		const result = collectPackage({
			manifest: packageManifest(),
			files: [{ path: "index.js", size: 5, kind: "file" }],
			readContent: () => Buffer.from("hello"),
			statFile: () => statRegular(5),
		});
		expect(issueCodes(result)).toContain("MANIFEST_ASSETS_ROOT_MISSING");
	});

	test("rejects a manifest text that is not canonically serialized", () => {
		const manifest = packageManifest();
		const text = canonicalSerializeManifest(manifest);
		const parsed = JSON.parse(text) as Record<string, unknown>;
		const reordered: Record<string, unknown> = {
			name: parsed.name,
			schemaVersion: parsed.schemaVersion,
			runtime: parsed.runtime,
			assets: parsed.assets,
			resources: parsed.resources,
			storage: parsed.storage,
			egress: parsed.egress,
		};
		const result = collectWith({ manifest, manifestText: JSON.stringify(reordered, null, 2) });
		expect(issueCodes(result)).toContain("MANIFEST_NOT_CANONICAL");
	});

	test("rejects a manifest text that parses to a different manifest", () => {
		const manifest = packageManifest();
		const text = canonicalSerializeManifest(manifest).replace("app/index.js", "app/other.js");
		const result = collectWith({ manifest, manifestText: text });
		expect(issueCodes(result)).toContain("MANIFEST_NOT_CANONICAL");
	});

	test("rejects unparseable manifest text without throwing", () => {
		const result = collectWith({ manifestText: "{ not valid json" });
		expect(issueCodes(result)).toContain("MANIFEST_INVALID_TEXT");
	});

	test("accepts a manifest text that is the canonical serialization", () => {
		const manifest = packageManifest();
		const result = collectWith({ manifest, manifestText: canonicalSerializeManifest(manifest) });
		expect(result.ok).toBe(true);
	});

	test("derives a version digest from the package digest and canonical manifest", () => {
		const digestA = versionDigest("a".repeat(64), packageManifest());
		const digestB = versionDigest("b".repeat(64), packageManifest());
		expect(digestA).not.toBe(digestB);
	});

	test("versionDigest is stable across property-order variations of an equivalent manifest", () => {
		const base = packageManifest();
		const reordered: ApplicationManifest = {
			egress: base.egress,
			storage: base.storage,
			resources: base.resources,
			assets: base.assets,
			runtime: base.runtime,
			name: base.name,
			schemaVersion: base.schemaVersion,
		};
		expect(canonicalSerializeManifest(base)).toBe(canonicalSerializeManifest(reordered));
		expect(versionDigest("a".repeat(64), base)).toBe(versionDigest("a".repeat(64), reordered));
	});
});

describe("application storage capability", () => {
	function memoryStore(): { store: NonceReplayStore } {
		const consumed = new Set<string>();
		return {
			store: {
				consume: (nonce: string): "fresh" | "replayed" => {
					if (consumed.has(nonce)) return "replayed";
					consumed.add(nonce);
					return "fresh";
				},
			},
		};
	}

	test("issues and verifies a scoped, time-bounded, single-use capability", () => {
		const now = Date.now();
		const issued = issueStorageCapability({ secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now });
		expect(issued.ok).toBe(true);
		if (!issued.ok) return;
		expect(issued.value.token.split(".")).toHaveLength(4);
		expect(issued.value.applicationId).toBe(APPLICATION_ID);
		const replay = memoryStore();
		const verified = verifyStorageCapability({ secret: SECRET, token: issued.value.token, applicationId: APPLICATION_ID, now, replay: replay.store });
		expect(verified).toMatchObject({ ok: true, applicationId: APPLICATION_ID });
		const reused = verifyStorageCapability({ secret: SECRET, token: issued.value.token, applicationId: APPLICATION_ID, now, replay: replay.store });
		expect(reused).toMatchObject({ ok: false, reason: "reused" });
	});

	test("rejects invalid inputs without throwing and reports machine-readable issues", () => {
		const now = Date.now();
		const cases: { label: string; options: Parameters<typeof issueStorageCapability>[0]; code: string }[] = [
			{ label: "uppercase applicationId", options: { secret: SECRET, applicationId: "Notes", ttlMs: 60_000, now }, code: "INVALID_IDENTIFIER" },
			{ label: "applicationId with punctuation", options: { secret: SECRET, applicationId: "notes!", ttlMs: 60_000, now }, code: "INVALID_IDENTIFIER" },
			{ label: "secret too short", options: { secret: "short", applicationId: APPLICATION_ID, ttlMs: 60_000, now }, code: "INVALID_SECRET" },
			{ label: "secret too long", options: { secret: "s".repeat(513), applicationId: APPLICATION_ID, ttlMs: 60_000, now }, code: "INVALID_SECRET" },
			{ label: "ttl below minimum", options: { secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 999, now }, code: "INVALID_TTL" },
			{ label: "ttl above maximum", options: { secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 86_400_001, now }, code: "INVALID_TTL" },
			{ label: "now too far in the past", options: { secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now: now - 3_660_001 }, code: "INVALID_TIMESTAMP" },
			{ label: "now too far in the future", options: { secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now: now + 3_660_001 }, code: "INVALID_TIMESTAMP" },
			{ label: "nonce not hexadecimal", options: { secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now, nonce: "z".repeat(32) }, code: "INVALID_NONCE" },
			{ label: "nonce wrong length", options: { secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now, nonce: "a".repeat(31) }, code: "INVALID_NONCE" },
		];
		for (const entry of cases) {
			const result = issueStorageCapability(entry.options);
			expect(result.ok, entry.label).toBe(false);
			if (!result.ok) {
				expect(result.errors.map((error) => error.code), entry.label).toContain(entry.code);
			}
		}
	});

	test("rejects oversized, undersized, and malformed tokens", () => {
		const now = Date.now();
		const replay = memoryStore();
		const future = String(now + 60_000);
		const verify = (token: string) => verifyStorageCapability({ secret: SECRET, token, applicationId: APPLICATION_ID, now, replay: replay.store });
		expect(verify("a".repeat(513))).toMatchObject({ ok: false, reason: "invalid" });
		expect(verify("a.b")).toMatchObject({ ok: false, reason: "invalid" });
		expect(verify("a.b.c.d.e")).toMatchObject({ ok: false, reason: "invalid" });
		expect(verify("Notes." + future + "." + "a".repeat(32) + "." + "x".repeat(43))).toMatchObject({ ok: false, reason: "invalid" });
		expect(verify(APPLICATION_ID + "." + future + ".zz." + "x".repeat(43))).toMatchObject({ ok: false, reason: "invalid" });
		expect(verify(APPLICATION_ID + "." + "abc." + "a".repeat(32) + "." + "x".repeat(43))).toMatchObject({ ok: false, reason: "invalid" });
		expect(verify(APPLICATION_ID + "." + future + "." + "a".repeat(32) + ".x")).toMatchObject({ ok: false, reason: "invalid" });
	});

	test("rejects tampered signatures", () => {
		const now = Date.now();
		const issued = issueStorageCapability({ secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now });
		expect(issued.ok).toBe(true);
		if (!issued.ok) return;
		const tampered = issued.value.token.slice(0, -4) + "AAAA";
		const result = verifyStorageCapability({ secret: SECRET, token: tampered, applicationId: APPLICATION_ID, now, replay: memoryStore().store });
		expect(result).toMatchObject({ ok: false, reason: "invalid" });
	});

	test("rejects expired capabilities", () => {
		const now = Date.now();
		const issued = issueStorageCapability({ secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now });
		expect(issued.ok).toBe(true);
		if (!issued.ok) return;
		const result = verifyStorageCapability({ secret: SECRET, token: issued.value.token, applicationId: APPLICATION_ID, now: now + 60_001, replay: memoryStore().store });
		expect(result).toMatchObject({ ok: false, reason: "expired" });
	});

	test("rejects cross-application capability use", () => {
		const now = Date.now();
		const issued = issueStorageCapability({ secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now });
		expect(issued.ok).toBe(true);
		if (!issued.ok) return;
		const result = verifyStorageCapability({ secret: SECRET, token: issued.value.token, applicationId: "other", now, replay: memoryStore().store });
		expect(result).toMatchObject({ ok: false, reason: "mismatch" });
	});

	test("rejects a reused nonce across two verify calls with the same store", () => {
		const now = Date.now();
		const issued = issueStorageCapability({ secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now });
		expect(issued.ok).toBe(true);
		if (!issued.ok) return;
		const replay = memoryStore();
		expect(verifyStorageCapability({ secret: SECRET, token: issued.value.token, applicationId: APPLICATION_ID, now, replay: replay.store }).ok).toBe(true);
		expect(verifyStorageCapability({ secret: SECRET, token: issued.value.token, applicationId: APPLICATION_ID, now, replay: replay.store })).toMatchObject({ ok: false, reason: "reused" });
	});

	test("verify never throws even when the replay store fails", () => {
		const now = Date.now();
		const issued = issueStorageCapability({ secret: SECRET, applicationId: APPLICATION_ID, ttlMs: 60_000, now });
		expect(issued.ok).toBe(true);
		if (!issued.ok) return;
		const failingStore: NonceReplayStore = {
			consume: () => {
				throw new Error("disk unavailable");
			},
		};
		const result = verifyStorageCapability({ secret: SECRET, token: issued.value.token, applicationId: APPLICATION_ID, now, replay: failingStore });
		expect(result).toMatchObject({ ok: false, reason: "invalid" });
	});

	test("durable nonce store persists nonces through an injected file system", () => {
		const content: string[] = [];
		const writes: string[] = [];
		const mkdirs: string[] = [];
		const fileSystem = {
			readFile: (): string | null => (content.length ? content.join("") : null),
			appendFile: (_path: string, data: string): void => {
				writes.push(data);
				content.push(data);
			},
			mkdir: (path: string): void => {
				mkdirs.push(path);
			},
		};
		const nonce = "a".repeat(32);
		const store = new DurableNonceStore({ filePath: "/tmp/iweb/replay.txt", ...fileSystem });
		expect(store.consume(nonce)).toBe("fresh");
		expect(writes).toContain(nonce + "\n");
		expect(mkdirs).toContain("/tmp/iweb");
		const reopened = new DurableNonceStore({ filePath: "/tmp/iweb/replay.txt", ...fileSystem });
		expect(reopened.consume(nonce)).toBe("replayed");
	});

	test("separates application data from version objects", () => {
		expect(applicationDataPrefix("notes")).toBe("iweb-apps/notes/data/");
		expect(applicationVersionPrefix("sbx-1")).toBe("iweb-versions/sbx-1/");
		expect(applicationDataPrefix("notes")).not.toContain(applicationVersionPrefix("sbx-1"));
	});
});
