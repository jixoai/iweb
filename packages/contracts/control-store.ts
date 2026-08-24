// 用户原始需求（2026-08-14）：Kernel 控制库必须是 single-writer transactional 持久化：原子替换、损坏即隔离、事务要么全写要么不写。
// 正交意图：7.1；纯 store 实现，供 Kernel 在 Node 中直接使用；写路径 tmp+fsync+rename；读路径校验版本。
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync as writeFd } from "node:fs";
import { dirname } from "node:path";

// Best-effort durability sync of a directory entry so an atomic rename survives
// a crash. Directory fsync is not supported on every platform/filesystem; a
// failure here is intentionally swallowed because the file fsync already guards
// the data and the rename is the atomicity boundary.
function syncDirectory(directory: string): void {
	let dirFd: number | undefined;
	try {
		dirFd = openSync(directory, "r");
		fsyncSync(dirFd);
	} catch {
		// directory fsync is best-effort and unsupported on some platforms
	} finally {
		if (dirFd !== undefined) {
			try { closeSync(dirFd); } catch { /* ignore */ }
		}
	}
}

export interface ControlStoreIO {
	readFile(path: string): string | null;
	writeFileAtomic(path: string, content: string): void;
	deleteFile(path: string): void;
	ensureDirectory(path: string): void;
}

export const systemControlStoreIO: ControlStoreIO = {
	readFile: (path) => {
		try {
			return readFileSync(path, "utf8");
		} catch (error) {
			// ENOENT is a legitimate "not created yet" and maps to null; a
			// permission or I/O failure is an infrastructure error that must
			// never masquerade as an absent control DB (2.37/2.47).
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
			writeFd(fd, content);
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
		renameSync(temporary, path);
		syncDirectory(dirname(path));
	},
	deleteFile: (path) => {
		try {
			rmSync(path, { force: true });
		} catch {
			// missing is the desired end state
		}
	},
	ensureDirectory: (path) => {
		mkdirSync(path, { recursive: true, mode: 0o700 });
	},
};

// Single-writer transactional store. The Kernel process is the only writer;
// every save is an atomic replace, so a reader never observes a torn state and
// a crash never leaves a partial file. A corrupt file is quarantined aside and
// the store falls back to empty (recovery must re-admit, never guess).
export class ControlStore<T> {
	private readonly io: ControlStoreIO;
	private readonly path: string;
	private readonly empty: () => T;
	private readonly parse: (value: unknown) => T | null;

	constructor(options: { readonly io: ControlStoreIO; readonly path: string; readonly empty: () => T; readonly parse: (value: unknown) => T | null }) {
		this.io = options.io;
		this.path = options.path;
		this.empty = options.empty;
		this.parse = options.parse;
	}

	load(): T {
		const text = this.io.readFile(this.path);
		if (text === null) return this.empty();
		try {
			const parsed = this.parse(JSON.parse(text));
			if (parsed !== null) return parsed;
		} catch {
			// fall through to quarantine
		}
		// Quarantine the corrupt file instead of silently overwriting it.
		this.io.deleteFile(this.path + ".corrupt");
		this.io.writeFileAtomic(this.path + ".corrupt", text);
		return this.empty();
	}

	save(value: T): void {
		this.io.ensureDirectory(dirname(this.path));
		this.io.writeFileAtomic(this.path, JSON.stringify(value, null, 2) + "\n");
	}

	// Transaction discipline: the mutation runs against the loaded state and
	// only a non-null return is persisted. A thrown error aborts without write.
	transaction(mutate: (current: T) => T | null): T | null {
		const current = this.load();
		const next = mutate(current);
		if (next === null) return null;
		this.save(next);
		return next;
	}
}
