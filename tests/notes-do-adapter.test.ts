import { describe, expect, test } from "bun:test";
import { validateNotes, createApplicationStorageTarget, type RawNote } from "../contracts/notes-do-adapter.ts";

const good: RawNote[] = [
	{ id: "a", title: "t1", content: "c1", updatedAt: "2026-08-14T00:00:00.000Z" },
	{ id: "b", title: "t2", content: "c2", updatedAt: "2026-08-14T00:00:01.000Z" },
];

describe("notes Durable Object adapter (2.49)", () => {
	test("validates every field and aborts on malformed or duplicate records", () => {
		expect(validateNotes(good)).toHaveLength(2);
		expect(() => validateNotes([{ ...good[0], id: "" }])).toThrow();
		expect(() => validateNotes([{ ...good[0], title: "" }])).toThrow();
		expect(() => validateNotes([{ ...good[0], updatedAt: "not-a-date" }])).toThrow();
		expect(() => validateNotes([...good, good[0]])).toThrow(/duplicate/);
		expect(() => validateNotes(null as unknown as RawNote[])).toThrow();
	});

	test("the application-storage target writes one JSON per note under the app namespace", () => {
		const written: Record<string, string> = {};
		const write = createApplicationStorageTarget("iweb-apps", "notes/data/", (key, body) => { written[key] = body; });
		const result = write(good);
		expect(result.count).toBe(2);
		expect(Object.keys(written).sort()).toEqual(["iweb-apps/notes/data/a.json", "iweb-apps/notes/data/b.json"].sort());
		expect(JSON.parse(written["iweb-apps/notes/data/a.json"]).title).toBe("t1");
	});
});