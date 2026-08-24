// 用户原始需求（2026-08-14）：Notes Durable Object 导出/导入适配器，带 record count 与内容摘要校验；原数据保持不动；可重复。
// 正交意图：纯函数；synthetic fixture 可验证。
import { createHash } from "node:crypto";

export interface NotesRecord {
	readonly id: string;
	readonly content: string;
}

export interface NotesExport {
	readonly records: readonly NotesRecord[];
	readonly count: number;
	readonly digest: string;
}

export function notesDigest(records: readonly NotesRecord[]): string {
	const hash = createHash("sha256");
	for (const record of [...records].sort((a, b) => a.id.localeCompare(b.id))) {
		hash.update(record.id);
		hash.update("\0");
		hash.update(record.content);
		hash.update("\0");
	}
	return hash.digest("hex");
}

// Export never mutates the source; it only reads records.
export function exportNotes(list: () => readonly NotesRecord[]): NotesExport {
	const records = list();
	return { records, count: records.length, digest: notesDigest(records) };
}

export function importNotes(write: (records: readonly NotesRecord[]) => void, records: readonly NotesRecord[]): { count: number } {
	write(records);
	return { count: records.length };
}

export function verifyNotesEquality(exported: NotesExport, imported: readonly NotesRecord[]): { equal: boolean; count: number } {
	const count = imported.length;
	return { equal: count === exported.count && notesDigest(imported) === exported.digest, count };
}

export interface DurableObjectExportSource {
	readonly readState: () => readonly NotesRecord[];
	readonly provenance: string;
}

// Real Durable Object export source (2.39). The operator supplies the state
// reader for the pinned celld version's Durable Object storage (the exact
// object key and record layout come from that celld release and MUST be
// confirmed against it at migration time — this seam deliberately does not
// guess the internal format). Every record is runtime-validated; any invalid
// record aborts the read so a partial export can never proceed to import.
export function createDurableObjectExportSource(readState: () => unknown, provenance: string): DurableObjectExportSource {
	return {
		provenance,
		readState: () => {
			const raw = readState();
			if (!Array.isArray(raw)) throw new Error("durable object state is not a record array");
			const records: NotesRecord[] = [];
			for (const entry of raw) {
				if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw new Error("durable object record is malformed");
				const candidate = entry as { id?: unknown; content?: unknown };
				if (typeof candidate.id !== "string" || candidate.id.length === 0 || candidate.id.length > 512) throw new Error("durable object record id is invalid");
				if (typeof candidate.content !== "string") throw new Error("durable object record content is invalid");
				records.push({ id: candidate.id, content: candidate.content });
			}
			return records;
		},
	};
}
export interface DryRunReport {
	readonly count: number;
	readonly digest: string;
	readonly repeatable: boolean;
	readonly rollbackInputs: { readonly backupDigest: string; readonly recordCount: number };
	readonly destructive: false;
}

// Non-destructive verifier: exports the source twice (read-only) to prove the
// digest is repeatable, records the rollback inputs (the export is its own
// backup), and never writes or imports. Real-source execution is the caller's
// responsibility and must be owner-authorized; this function mutates nothing.
export function dryRunNotesVerification(list: () => readonly NotesRecord[]): DryRunReport {
	const first = exportNotes(list);
	const second = exportNotes(list);
	return {
		count: first.count,
		digest: first.digest,
		repeatable: first.digest === second.digest,
		rollbackInputs: { backupDigest: first.digest, recordCount: first.count },
		destructive: false,
	};
}

export interface MigrationReport {
	readonly mode: "dry-run" | "migrate";
	readonly count: number;
	readonly digest: string;
	readonly repeatable: boolean;
	readonly rollbackInputs: { readonly backupDigest: string; readonly recordCount: number };
	readonly imported?: { readonly equal: boolean; readonly count: number };
}

// Production export/import adapter. readSource connects to the Durable Object
// (celld operator API in production, synthetic in tests); writeTarget writes the
// application-storage target. dry-run is fully non-destructive (read-only, no
// import). A migrate run writes the target and, when readTarget is provided,
// re-reads it to verify equality. Execution against real data is owner-gated by
// the caller; this function performs no network or destructive IO on its own.
export function migrateNotes(options: {
	readonly readSource: () => readonly NotesRecord[];
	readonly writeTarget?: (records: readonly NotesRecord[]) => void;
	readonly readTarget?: () => readonly NotesRecord[];
	readonly dryRun: boolean;
}): MigrationReport {
	const verification = dryRunNotesVerification(options.readSource);
	if (options.dryRun || !options.writeTarget) {
		return { mode: "dry-run", count: verification.count, digest: verification.digest, repeatable: verification.repeatable, rollbackInputs: verification.rollbackInputs };
	}
	const exported = exportNotes(options.readSource);
	options.writeTarget(exported.records);
	const targetRecords = options.readTarget ? options.readTarget() : exported.records;
	const equality = verifyNotesEquality(exported, targetRecords);
	return { mode: "migrate", count: verification.count, digest: verification.digest, repeatable: verification.repeatable, rollbackInputs: verification.rollbackInputs, imported: { equal: equality.equal, count: equality.count } };
}

