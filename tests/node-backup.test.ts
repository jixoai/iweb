// 用户原始需求（2026-08-14）：备份必须校验 label/destination、固定权限、一致 staging、预检归档成员、原子替换，且 previous-image 编排顺序可验证。
// 正交意图：覆盖 2.5-2.7 correction gate 的失败关闭与安全属性。
import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, statSync, symlinkSync, linkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	countRoutes,
	createNodeBackup,
	defaultBackupIO,
	NodeBackupError,
	preflightNodeBackup,
	restoreNodeBackup,
	validateBackupManifest,
	validateArchiveMembers,
	validateDestination,
	validateSourceLabel,
	validateSources,
	type BackupIO,
	type ArchiveMember,
	type NodeBackupSource,
} from "../scripts/node-backup.ts";
import { createDockerComposeOrchestrator, createQuiescedNodeBackup, restorePreviousImage, type CommandOptions } from "../scripts/node-backup-orchestrator.ts";

function makeIO(overrides: Partial<BackupIO> = {}): BackupIO {
	return { ...defaultBackupIO, ...overrides };
}

function rootIO(): BackupIO {
	return makeIO({ effectiveUserId: () => 0 });
}

function fixture(): { root: string; cleanup: () => void } {
	const root = mkdtempSync(join(tmpdir(), "iweb-node-backup-"));
	return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function writeFixture(root: string, secretValue = "owner-secret-do-not-leak"): { sources: NodeBackupSource[] } {
	mkdirSync(join(root, "src", "minio", "sub"), { recursive: true });
	mkdirSync(join(root, "src", "celld"), { recursive: true });
	mkdirSync(join(root, "src", "kernel"), { recursive: true });
	writeFileSync(join(root, "src", "minio", "a.txt"), "alpha\n");
	writeFileSync(join(root, "src", "minio", "sub", "b.txt"), "beta\n" + secretValue + "\n");
	writeFileSync(join(root, "src", "celld", "runtime-version"), "v0.2.0\n");
	writeFileSync(join(root, "src", "kernel", "routes.json"), JSON.stringify({ version: 1, routes: [1, 2, 3, 4, 5] }) + "\n");
	return {
		sources: [
			{ label: "objects", path: join(root, "src", "minio"), destination: join(root, "dest", "minio") },
			{ label: "celld", path: join(root, "src", "celld"), destination: join(root, "dest", "celld") },
			{ label: "kernel", path: join(root, "src", "kernel"), destination: join(root, "dest", "kernel") },
		],
	};
}

describe("source label and destination validation", () => {
	test("rejects traversal, absolute, control, and duplicate labels", () => {
		for (const label of ["../../escaped", "/abs", "a/b", ".", "..", "a b", "a\u0000b"]) {
			expect(validateSourceLabel(label).ok).toBe(false);
		}
		expect(validateSourceLabel("objects").ok).toBe(true);
		const duplicate = validateSources([
			{ label: "objects", path: "/a", destination: "/d/a" },
			{ label: "objects", path: "/b", destination: "/d/b" },
		]);
		expect(duplicate.ok).toBe(false);
		expect(duplicate.errors.join(" ")).toContain("duplicate source label");
	});

	test("rejects invalid restore destinations", () => {
		expect(validateDestination("/data/minio").ok).toBe(true);
		for (const destination of ["data/minio", "/data/../etc", "/data/./x", "/data/\u0000"]) {
			expect(validateDestination(destination).ok).toBe(false);
		}
	});

	test("rejects a symlink source root before any write", () => {
		const { root, cleanup } = fixture();
		try {
			mkdirSync(join(root, "real"), { recursive: true });
			writeFileSync(join(root, "real", "x.txt"), "x");
			symlinkSync(join(root, "real"), join(root, "link"));
			mkdirSync(join(root, "out"), { recursive: true });
			const outcome = preflightNodeBackup(rootIO(), {
				sources: [{ label: "objects", path: join(root, "link"), destination: join(root, "dest") }],
				outputDirectory: join(root, "out"),
			});
			expect(outcome.ok).toBe(false);
			expect(outcome.errors.join(" ")).toContain("symbolic link");
		} finally {
			cleanup();
		}
	});
});

describe("backup permissions and consistent snapshot", () => {
	test("creates backup artifacts with fixed 0700/0600 modes regardless of umask", async () => {
		const previousUmask = process.umask(0);
		const { root, cleanup } = fixture();
		try {
			const { sources } = writeFixture(root);
			mkdirSync(join(root, "out"), { recursive: true });
			await createNodeBackup({ io: rootIO(), sources, outputDirectory: join(root, "out"), backupId: "backup-perms" });
			const backupDir = join(root, "out", "backup-perms");
			expect(statSync(backupDir).mode & 0o777).toBe(0o700);
			expect(statSync(join(backupDir, "backup.tar.gz")).mode & 0o777).toBe(0o600);
			expect(statSync(join(backupDir, "manifest.json")).mode & 0o777).toBe(0o600);
			expect(statSync(join(root, "out", "latest.json")).mode & 0o777).toBe(0o600);
		} finally {
			process.umask(previousUmask);
			cleanup();
		}
	});

	test("computes the digest from staging so a live mutation after copy stays out of the backup", async () => {
		const { root, cleanup } = fixture();
		try {
			const { sources } = writeFixture(root);
			mkdirSync(join(root, "out"), { recursive: true });
			const mutatingIo = makeIO({
				effectiveUserId: () => 0,
				copyTree: (source, dest) => {
					(defaultBackupIO as BackupIO).copyTree(source, dest);
					// Mutate the live source AFTER the snapshot copy, simulating a concurrent write.
					writeFileSync(join(root, "src", "minio", "late.txt"), "late-mutation");
				},
			});
			const manifest = await createNodeBackup({ io: mutatingIo, sources, outputDirectory: join(root, "out"), backupId: "backup-staging" });
			const objectsRecord = manifest.sources.find((source) => source.label === "objects");
			expect(objectsRecord?.fileCount).toBe(2);
			const report = await restoreNodeBackup({ io: rootIO(), backupDirectory: join(root, "out", "backup-staging") });
			expect(report.verified.find((source) => source.label === "objects")?.fileCount).toBe(2);
			expect(() => readFileSync(join(root, "dest", "minio", "late.txt"), "utf8")).toThrow();
		} finally {
			cleanup();
		}
	});
});

describe("restore", () => {
	test("restores to the real destination (label != destination basename)", async () => {
		const { root, cleanup } = fixture();
		try {
			const { sources } = writeFixture(root);
			mkdirSync(join(root, "out"), { recursive: true });
			await createNodeBackup({ io: rootIO(), sources, outputDirectory: join(root, "out"), backupId: "backup-dest" });
			const report = await restoreNodeBackup({ io: rootIO(), backupDirectory: join(root, "out", "backup-dest") });
			expect(report.destinations).toEqual([join(root, "dest", "minio"), join(root, "dest", "celld"), join(root, "dest", "kernel")]);
			expect(readFileSync(join(root, "dest", "minio", "a.txt"), "utf8")).toBe("alpha\n");
			expect(() => readFileSync(join(root, "dest", "objects", "a.txt"), "utf8")).toThrow();
		} finally {
			cleanup();
		}
	});

	test("rejects unsafe archive members before extraction", async () => {
		const { root, cleanup } = fixture();
		try {
			const { sources } = writeFixture(root);
			mkdirSync(join(root, "out"), { recursive: true });
			await createNodeBackup({ io: rootIO(), sources, outputDirectory: join(root, "out"), backupId: "backup-members" });
			const maliciousIo = makeIO({
				effectiveUserId: () => 0,
				listArchiveMembers: () => [
					{ path: "objects/a.txt", type: "file" },
					{ path: "../escape", type: "file" },
					{ path: "evil", type: "symbolic-link" },
					{ path: "/abs/path", type: "file" },
				],
			});
			await expect(
				restoreNodeBackup({ io: maliciousIo, backupDirectory: join(root, "out", "backup-members") }),
			).rejects.toMatchObject({ code: "UNSAFE_ARCHIVE_MEMBER" });
		} finally {
			cleanup();
		}
	});

	test("rejects real symbolic-link and hard-link tar entries", () => {
		const { root, cleanup } = fixture();
		try {
			const archiveRoot = join(root, "archive-root");
			mkdirSync(archiveRoot, { recursive: true });
			writeFileSync(join(archiveRoot, "regular.txt"), "content");
			symlinkSync("regular.txt", join(archiveRoot, "symbolic.txt"));
			linkSync(join(archiveRoot, "regular.txt"), join(archiveRoot, "hard.txt"));
			const archive = join(root, "links.tar.gz");
			execFileSync("tar", ["-czf", archive, "-C", archiveRoot, "."]);
			const members = defaultBackupIO.listArchiveMembers(archive);
			expect(members.some((member) => member.type === "symbolic-link")).toBe(true);
			expect(members.some((member) => member.type === "hard-link")).toBe(true);
			expect(() => validateArchiveMembers(members)).toThrow("non-file entry");
		} finally {
			cleanup();
		}
	});

	test("rejects traversal and absolute names from real tar listings", () => {
		const { root, cleanup } = fixture();
		try {
			mkdirSync(join(root, "nested"), { recursive: true });
			writeFileSync(join(root, "escape.txt"), "escape");
			const traversalArchive = join(root, "traversal.tar.gz");
			execFileSync("tar", ["-czf", traversalArchive, "-C", join(root, "nested"), "../escape.txt"]);
			expect(() => validateArchiveMembers(defaultBackupIO.listArchiveMembers(traversalArchive))).toThrow("escapes the staging root");

			const absoluteArchive = join(root, "absolute.tar.gz");
			execFileSync("tar", ["-Pczf", absoluteArchive, join(root, "escape.txt")]);
			expect(() => validateArchiveMembers(defaultBackupIO.listArchiveMembers(absoluteArchive))).toThrow("absolute path");
		} finally {
			cleanup();
		}
	});

	test("removes stale files from the destination on success", async () => {
		const { root, cleanup } = fixture();
		try {
			const { sources } = writeFixture(root);
			mkdirSync(join(root, "out"), { recursive: true });
			await createNodeBackup({ io: rootIO(), sources, outputDirectory: join(root, "out"), backupId: "backup-stale" });
			mkdirSync(join(root, "dest", "minio"), { recursive: true });
			writeFileSync(join(root, "dest", "minio", "stale.txt"), "stale");
			await restoreNodeBackup({ io: rootIO(), backupDirectory: join(root, "out", "backup-stale") });
			expect(readFileSync(join(root, "dest", "minio", "a.txt"), "utf8")).toBe("alpha\n");
			expect(() => readFileSync(join(root, "dest", "minio", "stale.txt"), "utf8")).toThrow();
		} finally {
			cleanup();
		}
	});

	test("leaves the live destination unchanged when verification fails", async () => {
		const { root, cleanup } = fixture();
		try {
			const { sources } = writeFixture(root);
			mkdirSync(join(root, "out"), { recursive: true });
			await createNodeBackup({ io: rootIO(), sources, outputDirectory: join(root, "out"), backupId: "backup-unchanged" });
			mkdirSync(join(root, "dest", "minio"), { recursive: true });
			writeFileSync(join(root, "dest", "minio", "existing.txt"), "existing");
			// Tamper the archive so the staged tree digest mismatches the manifest.
			writeFileSync(join(root, "out", "backup-unchanged", "backup.tar.gz"), "tampered");
			await expect(
				restoreNodeBackup({ io: rootIO(), backupDirectory: join(root, "out", "backup-unchanged") }),
			).rejects.toMatchObject({ code: "DIGEST_MISMATCH" });
			expect(readFileSync(join(root, "dest", "minio", "existing.txt"), "utf8")).toBe("existing");
		} finally {
			cleanup();
		}
	});

	test("rolls back every destination when a later commit rename fails", async () => {
		const { root, cleanup } = fixture();
		try {
			const { sources } = writeFixture(root);
			mkdirSync(join(root, "out"), { recursive: true });
			for (const source of sources) {
				mkdirSync(source.destination, { recursive: true });
				writeFileSync(join(source.destination, "before.txt"), "before-" + source.label);
			}
			await createNodeBackup({ io: rootIO(), sources, outputDirectory: join(root, "out"), backupId: "backup-transaction" });
			const secondDestination = sources[1].destination;
			const failingIo = makeIO({
				effectiveUserId: () => 0,
				rename: (from, to) => {
					if (to === secondDestination && from.includes(".iweb-restore-")) throw new Error("injected commit failure");
					defaultBackupIO.rename(from, to);
				},
			});
			await expect(restoreNodeBackup({ io: failingIo, backupDirectory: join(root, "out", "backup-transaction") })).rejects.toThrow("injected commit failure");
			for (const source of sources) {
				expect(readFileSync(join(source.destination, "before.txt"), "utf8")).toBe("before-" + source.label);
				expect(() => readFileSync(join(source.destination, source.label === "objects" ? "a.txt" : source.label === "celld" ? "runtime-version" : "routes.json"), "utf8")).toThrow();
			}
		} finally {
			cleanup();
		}
	});

	test("round-trips and rejects an incomplete manifest", () => {
		expect(() =>
			validateBackupManifest({ version: 1, kind: "iweb-node-backup", backupId: "backup-x", createdAt: "2026-08-14T00:00:00.000Z", complete: false }),
		).toThrow("not marked complete");
	});
});

describe("previous-image orchestration", () => {
	test("stops the node before starting the previous image and verifies the order", async () => {
		const order: string[] = [];
		const orchestrator = {
			stopCurrentNode: async () => { order.push("stop"); },
			restoreVolume: async () => { order.push("restore"); },
			startPreviousImage: async () => { order.push("start"); },
			verifyRecovery: async () => { order.push("verify"); },
		};
		await restorePreviousImage(orchestrator, { image: "iweb:previous", backupDirectory: "/backup/x", baseHost: "family.iweb.test" });
		expect(order).toEqual(["stop", "restore", "start", "verify"]);
	});

	test("constructs an executable restore using the mounted backup root, pinned image, and owner-authorized recovery check", async () => {
		const calls: { command: string; args: readonly string[]; options?: CommandOptions }[] = [];
		const secret = "owner-secret-value";
		const orchestrator = createDockerComposeOrchestrator({
			COMPOSE_PROJECT_NAME: "family-node",
			IWEB_HTTP_PORT: "9010",
			IWEB_API_TOKEN: secret,
		}, (command, args, options) => { calls.push({ command, args, options }); return ""; });
		await restorePreviousImage(orchestrator, { image: "registry.example/iweb@sha256:" + "a".repeat(64), backupDirectory: "/host/backups/backup-1", baseHost: "family.iweb.test" });
		expect(calls.map((call) => call.command)).toEqual(["docker", "docker", "docker", "curl"]);
		expect(calls[1].args).toContain("type=bind,source=/host/backups/backup-1,target=/backup,readonly");
		expect(calls[1].options?.env?.IWEB_BACKUP_DIR).toBe("/backup");
		expect(calls[2].options?.env?.IWEB_IMAGE).toContain("@sha256:");
		expect(calls[3].args).not.toContain(secret);
		expect(calls[3].options?.input).toContain("Authorization: Bearer " + secret);
	});

	test("quiesces the node while the helper snapshots the persistent volume", async () => {
		const order: string[] = [];
		const result = await createQuiescedNodeBackup({
			stopCurrentNode: async () => { order.push("stop"); },
			backupStoppedVolume: async () => { order.push("backup"); return '{"complete":true}\n'; },
			startCurrentNode: async () => { order.push("start"); },
		}, "/backups");
		expect(order).toEqual(["stop", "backup", "start"]);
		expect(result).toContain('"complete":true');
	});

	test("restarts the current node when a quiesced backup fails", async () => {
		const order: string[] = [];
		await expect(createQuiescedNodeBackup({
			stopCurrentNode: async () => { order.push("stop"); },
			backupStoppedVolume: async () => { order.push("backup"); throw new Error("backup failed"); },
			startCurrentNode: async () => { order.push("start"); },
		}, "/backups")).rejects.toThrow("backup failed");
		expect(order).toEqual(["stop", "backup", "start"]);
	});

	test("never starts the previous image when restore fails", async () => {
		const order: string[] = [];
		const orchestrator = {
			stopCurrentNode: async () => { order.push("stop"); },
			restoreVolume: async () => { throw new Error("restore failed"); },
			startPreviousImage: async () => { order.push("start"); },
			verifyRecovery: async () => { order.push("verify"); },
		};
		await expect(restorePreviousImage(orchestrator, { image: "iweb:previous", backupDirectory: "/backup/x", baseHost: "family.iweb.test" })).rejects.toThrow("restore failed");
		expect(order).toEqual(["stop"]);
	});
});

describe("route state helper", () => {
	test("counts routes from the route state fixture", () => {
		expect(countRoutes(JSON.stringify({ version: 1, routes: [1, 2, 3] }))).toBe(3);
		expect(() => countRoutes("{}")).toThrow("route state is invalid");
	});
});
