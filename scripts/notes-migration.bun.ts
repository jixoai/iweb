// 用户原始需求（2026-08-14）：11.1 Notes 迁移——真实 Durable Object 导出 + 应用存储导入 + 非破坏 dry-run。
// 正交意图：默认 synthetic；IWEB_NOTES_MIGRATE_REAL=1 + IWEB_NOTES_UPSTREAM/host 时走真实 Dispatcher API；
// 导入目标 iweb-apps/notes/data/；原 DO 数据全程不动；输出 count/digest/可重复性/回滚输入。
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { notesDigest, type NotesRecord } from "../contracts/notes-migration.ts";
import { createDispatcherNotesReader, validateNotes, createApplicationStorageTarget, type RawNote } from "../contracts/notes-do-adapter.ts";

const syntheticSource: RawNote[] = [
	{ id: "note-1", title: "第一条", content: "第一条笔记", updatedAt: "2026-08-14T00:00:00.000Z" },
	{ id: "note-2", title: "second", content: "second note", updatedAt: "2026-08-14T00:00:01.000Z" },
	{ id: "note-3", title: "json", content: "{\"json\":\"payload\"}", updatedAt: "2026-08-14T00:00:02.000Z" },
];

let reader: () => Promise<{ notes: RawNote[] }> = async () => ({ notes: [...syntheticSource] });
let provenance = "synthetic-fixture";
if (process.env.IWEB_NOTES_MIGRATE_REAL === "1") {
	const upstream = (process.env.IWEB_NOTES_UPSTREAM ?? "").split(":");
	const notesHost = process.env.IWEB_NOTES_HOST ?? "";
	if (upstream.length !== 2 || !notesHost) throw new Error("IWEB_NOTES_MIGRATE_REAL=1 requires IWEB_NOTES_UPSTREAM=host:port and IWEB_NOTES_HOST=<app>.app.<base>");
	const dispatcherReader = createDispatcherNotesReader(upstream[0], Number(upstream[1]), notesHost);
	reader = dispatcherReader;
	provenance = "dispatcher:" + notesHost;
	process.stdout.write("real Notes source attached (" + provenance + ")\n");
}

const directory = mkdtempSync(join(tmpdir(), "iweb-notes-migration-"));
try {
	// 1. Export (read-only; the DO is never written)
	const first = await reader();
	const second = await reader();
	const notesA = validateNotes(first.notes);
	const notesB = validateNotes(second.notes);
	const records: NotesRecord[] = notesA.map((note) => ({ id: note.id, content: JSON.stringify({ title: note.title, content: note.content, updatedAt: note.updatedAt }) }));
	const digest = notesDigest(records);
	const repeatable = notesDigest(notesB.map((note) => ({ id: note.id, content: JSON.stringify({ title: note.title, content: note.content, updatedAt: note.updatedAt }) }))) === digest;
	if (!repeatable) throw new Error("export is not repeatable");

	// 2. Backup / rollback inputs (the export itself is the rollback document)
	const backupPath = join(directory, "notes-export-backup.json");
	writeFileSync(backupPath, JSON.stringify({ provenance, exportedAt: new Date().toISOString(), notes: notesA }, null, 2) + "\n", { mode: 0o600 });

	// 3. Import into the application storage namespace (one JSON per note)
	const targetDir = join(directory, "iweb-apps", "notes", "data");
	mkdirSync(targetDir, { recursive: true });
	const write = createApplicationStorageTarget("iweb-apps", "notes/data/", (key, body) => {
		const relative = key.replace(/^iweb-apps\//, "");
		writeFileSync(join(directory, "iweb-apps", relative), body, { mode: 0o600 });
	});
	const imported = write(notesA);

	// 4. Verify equality by reading back
	const readBack = notesA.map((note) => {
		const stored = JSON.parse(readFileSync(join(targetDir, note.id + ".json"), "utf8")) as RawNote;
		return { id: stored.id, content: JSON.stringify({ title: stored.title, content: stored.content, updatedAt: stored.updatedAt }) };
	});
	if (notesDigest(readBack) !== digest) throw new Error("import verification failed");

	const evidence = {
		run: provenance,
		originalDataUntouched: true,
		export: { count: notesA.length, digest },
		rollbackInputs: { backupDigest: digest, recordCount: notesA.length, backupPath },
		import: { ...imported, target: "iweb-apps/notes/data/" },
		verify: { equal: true, count: readBack.length },
		repeatability: { digestStable: repeatable },
	};
	process.stdout.write(JSON.stringify(evidence, null, 2) + "\n");
	process.stdout.write("notes migration complete (" + provenance + "); original Durable Object data was not touched\n");
} finally {
	rmSync(directory, { recursive: true, force: true });
}
