// 用户原始需求（2026-08-14）：凭据扫描执行器必须 fail closed——缺失路径、空目录、零输入、声明 kind 零覆盖、模式命中都判失败；报告绝不包含 secret 值。
// 正交意图：12.3；以真实子进程驱动 scripts/credential-scan-run.bun.ts。
import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function run(args: string[]): { exitCode: number | null; stdout: string } {
	const result = Bun.spawnSync(["bun", join(import.meta.dir, "..", "scripts", "credential-scan-run.bun.ts"), ...args], {
		cwd: import.meta.dir,
		stdout: "pipe",
		stderr: "pipe",
	});
	return { exitCode: result.exitCode, stdout: result.stdout.toString("utf8") };
}

function fixture(setup: (root: string) => void): string {
	const root = mkdtempSync(join(tmpdir(), "iweb-credscan-"));
	setup(root);
	return root;
}

describe("credential scan runner fails closed (12.3)", () => {
	test("a clean scan over a real readable location exits zero with coverage", () => {
		const root = fixture((dir) => {
			writeFileSync(join(dir, "notes.js"), "export default {};\n");
			writeFileSync(join(dir, "secrets.txt"), "# secrets\nnot-present-anywhere\n");
		});
		try {
			const { exitCode, stdout } = run(["--secrets-file", join(root, "secrets.txt"), "package:" + root]);
			const report = JSON.parse(stdout);
			expect(exitCode).toBe(0);
			expect(report.clean).toBe(true);
			// the secrets file itself is excluded from the scan surface
			expect(report.locationsScanned).toBeGreaterThanOrEqual(1);
			expect(report.kindsCovered.package).toBeGreaterThanOrEqual(1);
			expect(report.failures).toEqual([]);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	test("a missing declared location is a failure, never a silent skip", () => {
		const root = fixture((dir) => {
			writeFileSync(join(dir, "app.js"), "export default {};\n");
		});
		try {
			const { exitCode, stdout } = run(["package:" + root, "log:" + join(root, "does-not-exist.log")]);
			const report = JSON.parse(stdout);
			expect(exitCode).toBe(1);
			expect(report.clean).toBe(false);
			expect(report.failures.some((f: { reason: string }) => f.reason.includes("location-missing-or-unreadable"))).toBe(true);
			// the declared-but-uncovered kind is itself a failure
			expect(report.failures.some((f: { reason: string }) => f.reason.startsWith("UNCOVERED_KIND"))).toBe(true);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	test("an empty declared directory fails instead of scanning nothing", () => {
		const root = fixture((dir) => {
			mkdirSync(join(dir, "empty"));
		});
		try {
			const { exitCode, stdout } = run(["package:" + join(root, "empty")]);
			const report = JSON.parse(stdout);
			expect(exitCode).toBe(1);
			expect(report.failures.some((f: { reason: string }) => f.reason.startsWith("EMPTY_LOCATION"))).toBe(true);
			expect(report.failures.some((f: { reason: string }) => f.reason.startsWith("ZERO_INPUT"))).toBe(true);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	test("infrastructure credential patterns are found without caller secrets and values never appear in the report", () => {
		const root = fixture((dir) => {
			writeFileSync(join(dir, "leaked.txt"), "key = AKIAIOSFODNN7EXAMPLE\nurl = http://root:supersecret@127.0.0.1:9000\n");
		});
		try {
			const { exitCode, stdout } = run(["log:" + join(root, "leaked.txt")]);
			const report = JSON.parse(stdout);
			expect(exitCode).toBe(1);
			expect(report.patternFindings.map((f: { category: string }) => f.category).sort()).toEqual(["aws-access-key-id", "credential-url"]);
			// the report carries only sanitized locations and categories
			expect(stdout).not.toContain("AKIAIOSFODNN7EXAMPLE");
			expect(stdout).not.toContain("supersecret");
			expect(stdout).not.toContain("leaked.txt");
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	test("a caller-provided secret found in a scanned location is reported without its value", () => {
		const root = fixture((dir) => {
			writeFileSync(join(dir, "secrets.txt"), "tok-abcdef123456\n");
			writeFileSync(join(dir, "frame.json"), '{"token":"tok-abcdef123456"}');
		});
		try {
			const { exitCode, stdout } = run(["--secrets-file", join(root, "secrets.txt"), "monitor-frame:" + join(root, "frame.json")]);
			const report = JSON.parse(stdout);
			expect(exitCode).toBe(1);
			expect(report.findings).toHaveLength(1);
			expect(report.findings[0].category).toBe("caller-provided");
			expect(stdout).not.toContain("tok-abcdef123456");
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
});