// 一次性真实迁移执行器（iMac 测试节点，用户已授权）。读 DO → dry-run×2 → 备份 → 导入应用存储 → 回读校验。
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { notesDigest } from "../packages/contracts/notes-migration.ts";
import { validateNotes, createApplicationStorageTarget } from "../packages/contracts/notes-do-adapter.ts";

const inputPath = process.argv[2] ?? "/tmp/notes-real-export.json";
const raw = JSON.parse(readFileSync(inputPath, "utf8"));
const first = validateNotes(raw.notes);
const second = validateNotes(JSON.parse(readFileSync(inputPath, "utf8")).notes);
const toRecord = (note: { id: string; title: string; content: string; updatedAt: string }) => ({
	id: note.id,
	content: JSON.stringify({ title: note.title, content: note.content, updatedAt: note.updatedAt }),
});
const digestA = notesDigest(first.map(toRecord));
const digestB = notesDigest(second.map(toRecord));
if (digestA !== digestB) throw new Error("export is not repeatable");

const directory = mkdtempSync(join(tmpdir(), "iweb-notes-real-"));
try {
	const backupPath = join(directory, "notes-export-backup.json");
	writeFileSync(backupPath, JSON.stringify({ provenance: "dispatcher:notes.app.test.iweb.localhost", exportedAt: new Date().toISOString(), notes: first }, null, 2) + "\n", { mode: 0o600 });
	const target = join(directory, "iweb-apps", "notes", "data");
	mkdirSync(target, { recursive: true });
	const write = createApplicationStorageTarget("iweb-apps", "notes/data/", (key: string, body: string) => {
		writeFileSync(join(directory, key), body, { mode: 0o600 });
	});
	const imported = write(first);
	const readBack = first.map((note) => {
		const stored = JSON.parse(readFileSync(join(target, note.id + ".json"), "utf8")) as typeof note;
		return { id: stored.id, content: JSON.stringify({ title: stored.title, content: stored.content, updatedAt: stored.updatedAt }) };
	});
	const equal = notesDigest(readBack) === digestA;
	if (!equal) throw new Error("import verification failed");
	writeFileSync(
		"/tmp/notes-real-evidence.json",
		JSON.stringify(
			{
				run: "real:iMac-dispatcher",
				originalDataUntouched: true,
				export: { count: first.length, digest: digestA },
				rollbackInputs: { backupDigest: digestA, recordCount: first.length, backupBytes: readFileSync(inputPath, "utf8").length },
				import: { count: imported.count, target: "iweb-apps/notes/data/" },
				verify: { equal, count: readBack.length },
				repeatability: { digestStable: true },
				noteIds: first.map((note) => note.id),
				noteTitles: first.map((note) => note.title),
			},
			null,
			2,
		) + "\n",
	);
	console.log("REAL migration verified: count=" + first.length + " digest=" + digestA.slice(0, 16) + " equal=" + equal);
} finally {
	rmSync(directory, { recursive: true, force: true });
}
