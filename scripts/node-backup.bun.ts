// 用户原始需求（2026-08-14）：升级前的备份与旧镜像恢复是节点运维命令，必须无 secret、失败关闭、结果机器可读。
// 正交意图：backup/restore/preflight/restore-previous 子命令；固定默认备份槽与真实 restore 目的地；previous-image 编排顺序由 restorePreviousImage 保证。
import {
	createNodeBackup,
	defaultBackupIO,
	preflightNodeBackup,
	restoreNodeBackup,
	type NodeBackupSource,
} from "./node-backup.ts";
import { createDockerComposeOrchestrator, createQuiescedNodeBackup, restorePreviousImage } from "./node-backup-orchestrator.ts";

const DEFAULT_SOURCES: readonly NodeBackupSource[] = [
	{ label: "objects", path: "/data/minio", destination: "/data/minio" },
	{ label: "celld", path: "/data/celld", destination: "/data/celld" },
	{ label: "kernel", path: "/data/kernel", destination: "/data/kernel" },
];

const outputDirectory = process.env.IWEB_BACKUP_OUTPUT?.trim() || "/var/lib/iweb-backups";
const backupDirectory = process.env.IWEB_BACKUP_DIR?.trim() || "";
const previousImage = process.env.IWEB_PREVIOUS_IMAGE?.trim() || "";
const baseHost = process.env.IWEB_BASE_HOST?.trim() || "";
const command = process.argv[2] ?? "help";

function parseSources(): readonly NodeBackupSource[] {
	const requested = process.argv.filter((argument) => argument.startsWith("--source="));
	if (requested.length === 0) return DEFAULT_SOURCES;
	return requested.map((argument) => {
		const value = argument.slice("--source=".length);
		const separator = value.indexOf(":");
		const destSeparator = value.indexOf(":", separator + 1);
		if (separator <= 0) throw new Error("--source must be label:absolute-source-path[:absolute-destination]");
		const label = value.slice(0, separator);
		const path = destSeparator > 0 ? value.slice(separator + 1, destSeparator) : value.slice(separator + 1);
		const destination = destSeparator > 0 ? value.slice(destSeparator + 1) : path;
		if (!path.startsWith("/")) throw new Error("--source path must be absolute");
		if (!destination.startsWith("/")) throw new Error("--source destination must be absolute");
		return { label, path, destination };
	});
}

async function run(): Promise<void> {
	if (command === "backup") {
		const manifest = await createNodeBackup({ io: defaultBackupIO, sources: parseSources(), outputDirectory });
		process.stdout.write(JSON.stringify(manifest, null, 2) + "\n");
		return;
	}
	if (command === "backup-node") {
		const manifestJson = await createQuiescedNodeBackup(createDockerComposeOrchestrator(), outputDirectory);
		process.stdout.write(manifestJson);
		return;
	}
	if (command === "restore") {
		if (!backupDirectory) throw new Error("IWEB_BACKUP_DIR must name the backup directory to restore");
		const report = await restoreNodeBackup({ io: defaultBackupIO, backupDirectory });
		process.stdout.write(JSON.stringify(report, null, 2) + "\n");
		return;
	}
	if (command === "restore-previous") {
		if (!previousImage) throw new Error("IWEB_PREVIOUS_IMAGE must pin the previous image identifier");
		if (!backupDirectory) throw new Error("IWEB_BACKUP_DIR must name the backup directory to restore");
		if (!baseHost) throw new Error("IWEB_BASE_HOST is required to verify recovery");
		await restorePreviousImage(createDockerComposeOrchestrator(), { image: previousImage, backupDirectory, baseHost });
		process.stdout.write("previous image restored and verified\n");
		return;
	}
	if (command === "preflight") {
		const outcome = preflightNodeBackup(defaultBackupIO, { sources: parseSources(), outputDirectory });
		process.stdout.write(JSON.stringify(outcome, null, 2) + "\n");
		if (!outcome.ok) process.exitCode = 1;
		return;
	}
	throw new Error("usage: node-backup.bun.ts backup|backup-node|restore|restore-previous|preflight");
}

try {
	await run();
} catch (error) {
	const message = error instanceof Error && error.name === "NodeBackupError" ? error.message : "node backup command failed";
	process.stderr.write("node-backup: " + message + "\n");
	process.exitCode = 1;
}
