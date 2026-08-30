// two-tier-runtime-trust（2026-08-30）：celld OCI 沙箱机器（adapter/gateway/desired-state/
//   sandbox-spec 等）整体退役后，wasm 执行链仍然真实依赖的两类共享物收拢在本模块：
//   1. 持久化 StateStoreIO（tmp+fsync+rename、0600/0700、目录 fsync 容错集）——原
//      desired-state.ts 的实现逐字迁入（wasm-control / wasm-serve / wasm-catalog-store
//      的 journal、control-state、catalog store 共用；语义一字不变）；
//   2. readiness 探测路径常量 READINESS_PATH——原 sandbox-spec.ts 的纯常量迁入
//      （wasm-executor 的 readiness/health v2 探测 URL 组装）。
//   其余 sandbox-spec 常量（OCI/seccomp/子网/容器命名）随 Podman 链路一并删除，
//   不做迁移（wasm 边界由引擎强制，spec "Wasm applications inherit the application
//   sandbox law" 的 two-tier 修订）。
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface StateStoreIO {
	readFile(path: string): string | null;
	writeFileAtomic(path: string, content: string): void;
	deleteFile(path: string): void;
	ensureDirectory(path: string): void;
}

// Durability contract (原 desired-state.ts 2.28 语义)：状态替换在 FILE 级 durable
// (write → fsync → atomic rename)。rename 之后的父目录 fsync 让 rename 本身 crash-safe；
// 唯一容错是平台报告不支持（无目录 fsync 的文件系统上的 EINVAL/ENOSYS/EPERM）。
// 其它目录 fsync 错误（EIO/EDQUOT/...）是 infrastructure failure 并抛出：静默吞掉会在
// 不声明的情况下收窄持久化契约。
const DIRECTORY_FSYNC_UNSUPPORTED = new Set(["EINVAL", "ENOSYS", "EPERM"]);

export function syncDirectoryOrFail(directory: string): void {
	let dirFd: number | undefined;
	try {
		dirFd = openSync(directory, "r");
		fsyncSync(dirFd);
	} catch (error) {
		const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
		if (!DIRECTORY_FSYNC_UNSUPPORTED.has(code)) throw error;
	} finally {
		if (dirFd !== undefined) {
			try { closeSync(dirFd); } catch { /* closing an fd never carries durability meaning */ }
		}
	}
}

export const systemStateStoreIO: StateStoreIO = {
	readFile: (path) => {
		try {
			return readFileSync(path, "utf8");
		} catch (error) {
			// ENOENT 是合法的「尚未创建」；权限或 I/O 失绝不允许伪装成缺失状态。
			const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
			if (code !== "ENOENT") throw error;
			return null;
		}
	},
	writeFileAtomic: (path, content) => {
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		const temporary = path + ".tmp";
		const fd = openSync(temporary, "w", 0o600);
		try {
			writeFileSync(fd, content);
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
		renameSync(temporary, path);
		syncDirectoryOrFail(dirname(path));
	},
	deleteFile: (path) => {
		try {
			rmSync(path, { force: true });
		} catch {
			// deleting a missing file is already the desired end state
		}
	},
	ensureDirectory: (path) => {
		mkdirSync(path, { recursive: true, mode: 0o700 });
	},
};

// wasmd readiness/health 端点的固定路径（原 sandbox-spec.ts READINESS_PATH 迁入；
// wasmd ingress.rs 在唯一 listener 上以 GET <path> 返回完整身份的 health v2 JCS）。
export const READINESS_PATH = "/iweb-health";
