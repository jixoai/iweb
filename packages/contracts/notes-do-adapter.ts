// 用户原始需求（2026-08-14）：Notes Durable Object 导出必须来自 pinned 应用的真实 API，而非猜测内部存储格式。
// 正交意图：2.49 具体适配器——经 celld Dispatcher 以 <app>.app.<base> host 读取 GET /api/notes；
// 逐条校验 id/title/content/updatedAt；malformed 立即中止；导入目标是应用存储命名空间 iweb-apps/notes/data/。
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { get as httpGet } from "node:http";

export interface RawNote {
	readonly id: string;
	readonly title: string;
	readonly content: string;
	readonly updatedAt: string;
}

// A protocol-faithful reader: any source returning the Notes API JSON shape.
export type NotesApiReader = () => Promise<{ notes: RawNote[] }>;

// Concrete production reader against a running node's celld Dispatcher.
// upstream example: 127.0.0.1:8787 with host notes.app.<base>.
export function createDispatcherNotesReader(upstreamHost: string, upstreamPort: number, notesHost: string, timeoutMs = 5000): NotesApiReader {
	return async () => {
		const text = await new Promise<string>((resolve, reject) => {
			const request = httpGet(
				new URL(`http://${upstreamHost}:${upstreamPort}/api/notes`),
				{ timeout: timeoutMs, headers: { host: notesHost } },
				(response) => {
					let body = "";
					response.setEncoding("utf8");
					response.on("data", (chunk: string) => (body += chunk));
					response.on("end", () => resolve(body));
				},
			) as never;
			(request as { once: (event: string, cb: (error: Error) => void) => void }).once("error", reject);
		});
		const parsed = JSON.parse(text) as { notes?: unknown };
		if (!parsed || !Array.isArray(parsed.notes)) throw new Error("notes API response is not {notes:[]}");
		return { notes: parsed.notes as RawNote[] };
	};
}

// Field-by-field validation: any malformed record aborts (no partial export).
export function validateNotes(raw: readonly RawNote[]): RawNote[] {
	if (!Array.isArray(raw)) throw new Error("notes payload is not an array");
	const seen = new Set<string>();
	for (const note of raw) {
		if (typeof note !== "object" || note === null || Array.isArray(note)) throw new Error("note record is malformed");
		const { id, title, content, updatedAt } = note as Partial<RawNote>;
		if (typeof id !== "string" || id.length === 0 || id.length > 128) throw new Error("note id is invalid");
		if (seen.has(id)) throw new Error("duplicate note id: " + id.slice(0, 8));
		seen.add(id);
		if (typeof title !== "string" || title.length === 0 || title.length > 200) throw new Error("note title is invalid for " + id.slice(0, 8));
		if (typeof content !== "string" || content.length > 20_000) throw new Error("note content is invalid for " + id.slice(0, 8));
		if (typeof updatedAt !== "string" || Number.isNaN(Date.parse(updatedAt))) throw new Error("note updatedAt is invalid for " + id.slice(0, 8));
	}
	return [...raw];
}

// Import target: the application storage namespace (iweb-apps/notes/data/).
// writeTarget writes a single JSON document per note keyed by id.
export function createApplicationStorageTarget(bucket: string, prefix: string, put: (key: string, body: string) => void) {
	return function write(notes: readonly RawNote[]): { count: number } {
		let count = 0;
		for (const note of notes) {
			put(bucket + "/" + prefix + note.id + ".json", JSON.stringify(note, null, 2) + "\n");
			count += 1;
		}
		return { count };
	};
}
