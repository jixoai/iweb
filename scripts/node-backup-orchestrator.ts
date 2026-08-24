// 用户原始需求（2026-08-14）：旧镜像恢复必须停止当前节点、恢复同一数据卷、启动明确的旧镜像，并使用 owner 授权验证 recovery API。
// 正交意图：构造可审计的 Docker Compose/helper/curl 命令；停机备份；旧镜像恢复；secret 仅经 stdin 进入 curl。
import { execFileSync } from "node:child_process";
import { mkdirSync, chmodSync } from "node:fs";

export interface CommandOptions {
	readonly env?: NodeJS.ProcessEnv;
	readonly input?: string;
}

export type CommandExecutor = (command: string, args: readonly string[], options?: CommandOptions) => string;

const executeCommand: CommandExecutor = (command, args, options = {}) => {
	if (options.input === undefined) {
		return execFileSync(command, [...args], { encoding: "utf8", stdio: "pipe", env: options.env });
	}
	return execFileSync(command, [...args], { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], env: options.env, input: options.input });
};

export interface PreviousImageOrchestrator {
	stopCurrentNode(): Promise<void>;
	restoreVolume(backupDirectory: string): Promise<void>;
	startPreviousImage(image: string): Promise<void>;
	verifyRecovery(baseHost: string): Promise<void>;
}

export interface QuiescedBackupOrchestrator {
	stopCurrentNode(): Promise<void>;
	backupStoppedVolume(outputDirectory: string): Promise<string>;
	startCurrentNode(): Promise<void>;
}

export async function restorePreviousImage(orchestrator: PreviousImageOrchestrator, options: { readonly image: string; readonly backupDirectory: string; readonly baseHost: string }): Promise<void> {
	if (!options.image || /[\r\n]/.test(options.image)) throw new Error("previous image identifier is required");
	await orchestrator.stopCurrentNode();
	await orchestrator.restoreVolume(options.backupDirectory);
	await orchestrator.startPreviousImage(options.image);
	await orchestrator.verifyRecovery(options.baseHost);
}

export async function createQuiescedNodeBackup(orchestrator: QuiescedBackupOrchestrator, outputDirectory: string): Promise<string> {
	await orchestrator.stopCurrentNode();
	try {
		return await orchestrator.backupStoppedVolume(outputDirectory);
	} finally {
		await orchestrator.startCurrentNode();
	}
}

export function createDockerComposeOrchestrator(
	environment: NodeJS.ProcessEnv = process.env,
	execute: CommandExecutor = executeCommand,
): PreviousImageOrchestrator & QuiescedBackupOrchestrator {
	const composeFiles = ["-f", "docker-compose.yml", "-f", "docker-compose.sandbox.yml"];
	const projectName = environment.COMPOSE_PROJECT_NAME?.trim() || "iweb-local";
	const port = environment.IWEB_HTTP_PORT?.trim() || "9010";
	const ownerKey = environment.IWEB_API_TOKEN?.trim() || "";
	return {
		stopCurrentNode: async () => {
			execute("docker", ["compose", ...composeFiles, "--project-name", projectName, "down"]);
		},
		restoreVolume: async (backupDirectory) => {
			const helperImage = environment.IWEB_RESTORE_HELPER_IMAGE?.trim() || "oven/bun:1.3.14";
			const volume = environment.IWEB_DATA_VOLUME?.trim() || projectName + "_iweb-data";
			execute("docker", [
				"run", "--rm",
				"--mount", "type=volume,source=" + volume + ",target=/data",
				"--mount", "type=bind,source=" + backupDirectory + ",target=/backup,readonly",
				"--mount", "type=bind,source=" + process.cwd() + ",target=/opt/iweb,readonly",
				helperImage, "bun", "/opt/iweb/scripts/node-backup.bun.ts", "restore",
			], { env: { ...environment, IWEB_BACKUP_DIR: "/backup" } });
		},
		backupStoppedVolume: async (outputDirectory) => {
			mkdirSync(outputDirectory, { recursive: true });
			chmodSync(outputDirectory, 0o700);
			const helperImage = environment.IWEB_RESTORE_HELPER_IMAGE?.trim() || "oven/bun:1.3.14";
			const volume = environment.IWEB_DATA_VOLUME?.trim() || projectName + "_iweb-data";
			return execute("docker", [
				"run", "--rm",
				"--mount", "type=volume,source=" + volume + ",target=/data,readonly",
				"--mount", "type=bind,source=" + outputDirectory + ",target=/backups",
				"--mount", "type=bind,source=" + process.cwd() + ",target=/opt/iweb,readonly",
				helperImage, "bun", "/opt/iweb/scripts/node-backup.bun.ts", "backup",
			], { env: { ...environment, IWEB_BACKUP_OUTPUT: "/backups" } });
		},
		startCurrentNode: async () => {
			execute("docker", ["compose", ...composeFiles, "--project-name", projectName, "up", "--detach"], { env: environment });
		},
		startPreviousImage: async (image) => {
			execute("docker", ["compose", ...composeFiles, "--project-name", projectName, "up", "--detach"], { env: { ...environment, IWEB_IMAGE: image } });
		},
		verifyRecovery: async (baseHost) => {
			if (!ownerKey) throw new Error("IWEB_API_TOKEN is required to verify recovery");
			const curlConfig = 'header = "Authorization: Bearer ' + ownerKey.replace(/["\\\r\n]/g, "") + '"\n';
			execute("curl", ["--config", "-", "--fail", "--silent", "--show-error", "--max-time", "20", "-H", "Host: api." + baseHost, "http://127.0.0.1:" + port + "/v1/status"], { input: curlConfig });
		},
	};
}
