// 用户原始需求（2026-08-14）：hostile 矩阵测试覆盖凭据扫描值/位置清洗、fixture 九攻击声明、dry/run 矩阵可执行性。
// 正交意图：2.20 / 12.1 / 12.3。
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAX_SCAN_LOCATIONS, MAX_SCAN_SECRETS, scanForSecrets, scanForCredentialPatterns, isExemptPublicIdentifier, isPureParameterExpansion, isRequiredParameterAssertion, PUBLIC_IDENTIFIER_EXEMPTIONS } from "../packages/contracts/credential-scan.ts";
import { validateApplicationManifest } from "../packages/contracts/manifest.ts";
import { ATTACKS } from "./fixtures/hostile-app/app/index.js";

interface DeclaredAttack {
	readonly id: string;
	readonly name: string;
	readonly description: string;
}

const declaredAttacks: readonly DeclaredAttack[] = ATTACKS;

const REQUIRED_ATTACK_IDS = [
	"credential-discovery",
	"workspace-access",
	"cross-app-access",
	"internal-probes",
	"undeclared-egress",
	"filesystem-escape",
	"supervisor-access",
	"process-escape",
	"resource-exhaustion",
] as const;

const repoRoot = join(import.meta.dir, "..");

function sanitizedLocation(kind: string, label: string): string {
	return kind + ":" + createHash("sha256").update(label).digest("hex").slice(0, 12);
}

describe("credential scan hardening", () => {
	test("sanitizes values and locations: findings carry neither", () => {
		const secret = "IWEB_API_TOKEN_super_secret_value";
		const label = "assets/" + secret + "/app.js";
		const result = scanForSecrets({
			secrets: [{ value: secret, category: "owner-key" }],
			locations: [
				{ kind: "admin-assets", label, content: "const x = '" + secret + "';" },
				{ kind: "env-projection", label: "env", content: "clean" },
			],
		});
		expect(result.clean).toBe(false);
		expect(result.findings).toHaveLength(1);
		const finding = result.findings[0];
		expect(finding.location).toMatch(/^[a-z-]+:[a-f0-9]{12}$/);
		expect(finding.location).toBe(sanitizedLocation("admin-assets", label));
		expect(finding.category).toBe("owner-key");
		const serialized = JSON.stringify(result);
		expect(serialized).not.toContain(secret);
		expect(serialized).not.toContain(label);
		expect(serialized).not.toContain("assets/");
	});

	test("deduplicates identical findings across label and content", () => {
		const secret = "minio-root-credentials";
		const label = "objects/" + secret;
		const result = scanForSecrets({
			secrets: [{ value: secret, category: "minio" }],
			locations: [
				{ kind: "object-store", label, content: "config: " + secret },
				{ kind: "object-store", label, content: "same sanitized location again" },
			],
		});
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].category).toBe("minio");
		expect(result.findings[0].location).toBe(sanitizedLocation("object-store", label));
		expect(result.clean).toBe(false);
	});

	test("skips empty secret values", () => {
		const result = scanForSecrets({
			secrets: [{ value: "", category: "owner-key" }, { value: "  ", category: "owner-key" }],
			locations: [{ kind: "package", label: "app/index.js", content: "whatever" }],
		});
		expect(result.clean).toBe(true);
		expect(result.findings).toEqual([]);
	});

	test("respects the documented caps", () => {
		const secret = "IWEB_API_TOKEN_capped_secret";
		const manySecrets: { value: string; category: string }[] = Array.from({ length: MAX_SCAN_SECRETS + 1 }, (_, i) => ({ value: "secret-" + i, category: "owner-key" }));
		manySecrets[MAX_SCAN_SECRETS] = { value: secret, category: "owner-key" };
		const secretCapped = scanForSecrets({ secrets: manySecrets, locations: [{ kind: "package", label: "app/index.js", content: secret }] });
		expect(secretCapped.clean).toBe(true);

		const manyLocations: { kind: "package"; label: string; content: string }[] = Array.from({ length: MAX_SCAN_LOCATIONS + 1 }, (_, i) => ({
			kind: "package",
			label: "file-" + i,
			content: i === MAX_SCAN_LOCATIONS ? secret : "clean",
		}));
		const locationCapped = scanForSecrets({ secrets: [{ value: secret, category: "owner-key" }], locations: manyLocations });
		expect(locationCapped.clean).toBe(true);
	});
});

describe("credential scan false-positive discrimination rules (2026-08-26 review)", () => {
	test("a needle exactly equal to a registered repo-public identifier is exempt; near-misses are not", () => {
		// the exact false positive from the 2026-08-26 run: the dev node's celld
		// S3 access key is textually identical to the repo-public policy name
		const entrypointText = 'mc admin policy create local iweb-celld /etc/iweb/celld-policy.json\nmc admin policy attach local iweb-celld --user "${CELLD_S3_ACCESS_KEY}"\n';
		const exempt = scanForSecrets({
			secrets: [{ value: "iweb-celld", category: "caller-provided" }],
			locations: [{ kind: "image-layer", label: "iweb-entrypoint.sh", content: entrypointText }],
		});
		expect(exempt.clean).toBe(true);
		expect(exempt.findings).toEqual([]);

		// exact equality only: superstrings, substrings, and case variants stay findings
		for (const nearMiss of ["iweb-celld-prod", "prod-iweb-celld", "IWEB-CELLD"]) {
			const stillFound = scanForSecrets({
				secrets: [{ value: nearMiss, category: "caller-provided" }],
				locations: [{ kind: "image-layer", label: "entrypoint", content: nearMiss + " " + entrypointText }],
			});
			expect(stillFound.clean).toBe(false);
			expect(stillFound.findings).toHaveLength(1);
		}

		// a real secret scanned alongside the exempt identifier is still reported
		const mixed = scanForSecrets({
			secrets: [{ value: "iweb-celld", category: "caller-provided" }, { value: "real-secret-half-value", category: "caller-provided" }],
			locations: [{ kind: "log", label: "startup.log", content: 'iweb-celld attached; AWS_SECRET_ACCESS_KEY=real-secret-half-value' }],
		});
		expect(mixed.clean).toBe(false);
		expect(mixed.findings).toHaveLength(1);
		expect(mixed.findings[0].category).toBe("caller-provided");
	});

	test("isExemptPublicIdentifier matches the explicit registry exactly", () => {
		for (const identifier of PUBLIC_IDENTIFIER_EXEMPTIONS) {
			expect(isExemptPublicIdentifier(identifier)).toBe(true);
			expect(identifier.length).toBeGreaterThan(0);
		}
		expect(isExemptPublicIdentifier("")).toBe(false);
		expect(isExemptPublicIdentifier(" iweb-celld")).toBe(false);
		expect(isExemptPublicIdentifier("iweb-celld\n")).toBe(false);
	});

	test("owner-token-assignment ignores pure parameter-expansion re-exports but keeps literal assignments", () => {
		// the exact entrypoint lines that produced the 2026-08-26 pattern hit
		// (re-export to iweb-kernel) and its 2026-08-27 residue (required-
		// parameter assertion with the variable's own name in the message)
		const entrypointGuards = ': "${IWEB_API_TOKEN:?IWEB_API_TOKEN must protect the kernel API}"\nIWEB_API_TOKEN="${IWEB_API_TOKEN}" \\\niweb-kernel &\n';
		expect(scanForCredentialPatterns([{ kind: "image-layer", label: "entrypoint", content: entrypointGuards }]).findings).toEqual([]);
		for (const pure of ['IWEB_API_TOKEN=$IWEB_API_TOKEN', "IWEB_API_TOKEN='${IWEB_API_TOKEN}'", 'IWEB_API_TOKEN: ${IWEB_API_TOKEN}', ': "${IWEB_API_TOKEN:?IWEB_API_TOKEN is required}"']) {
			expect(scanForCredentialPatterns([{ kind: "env-projection", label: "env", content: pure }]).findings).toEqual([]);
		}

		// literal values, concatenations, and mixed files still report
		for (const leaking of [
			'IWEB_API_TOKEN="tok-abcdefghijklmnop"',
			"IWEB_API_TOKEN=${IWEB_API_TOKEN}-fallback-suffix",
			'IWEB_API_TOKEN=${IWEB_API_TOKEN:-tok-abcdefghijklmnop',
			'IWEB_API_TOKEN="?other-variable-name"',
			'other line\nIWEB_API_TOKEN="tok-abcdefghijklmnop"\nIWEB_API_TOKEN="${IWEB_API_TOKEN}"',
		]) {
			const result = scanForCredentialPatterns([{ kind: "log", label: "env.log", content: leaking }]);
			expect(result.clean).toBe(false);
			expect(result.findings.map((finding) => finding.category)).toEqual(["owner-token-assignment"]);
		}
	});

	test("isRequiredParameterAssertion exempts only the self-name residue", () => {
		expect(isRequiredParameterAssertion("?IWEB_API_TOKEN", "IWEB_API_TOKEN")).toBe(true);
		expect(isRequiredParameterAssertion('"?IWEB_API_TOKEN', "IWEB_API_TOKEN")).toBe(true);
		expect(isRequiredParameterAssertion("?IWEB_API_TOKEN", "OTHER_TOKEN")).toBe(false);
		expect(isRequiredParameterAssertion("?IWEB_API_TOKEN-with-message", "IWEB_API_TOKEN")).toBe(false);
		expect(isRequiredParameterAssertion("", "IWEB_API_TOKEN")).toBe(false);
		expect(isRequiredParameterAssertion("?IWEB_API_TOKEN", "")).toBe(false);
	});

	test("isPureParameterExpansion accepts only the pure expansion shape", () => {
		for (const pure of ['${IWEB_API_TOKEN}', '$IWEB_API_TOKEN', '"${IWEB_API_TOKEN}"', "'${IWEB_API_TOKEN}'", '"${IWEB_API_TOKEN}', ' ${VAR} ']) {
			expect(isPureParameterExpansion(pure)).toBe(true);
		}
		for (const notPure of ["", "   ", "literal-value", "${VAR}suffix", "prefix${VAR}", "${VAR}${OTHER}", "${}", "$1", '"quoted literal"', "${VAR} tail"]) {
			expect(isPureParameterExpansion(notPure)).toBe(false);
		}
	});
});

describe("hostile application fixture", () => {
	test("declares exactly the nine 12.1 attack ids", () => {
		const ids = declaredAttacks.map((attack) => attack.id);
		expect(ids).toHaveLength(9);
		expect(new Set(ids)).toEqual(new Set(REQUIRED_ATTACK_IDS));
		for (const attack of declaredAttacks) {
			expect(attack.name.length).toBeGreaterThan(0);
			expect(attack.description.length).toBeGreaterThan(0);
		}
	});

	test("iweb.json is a valid manifest with deny-all egress and non-persistent storage", () => {
		const manifest = validateApplicationManifest(JSON.parse(readFileSync(join(repoRoot, "tests/fixtures/hostile-app/iweb.json"), "utf8")));
		expect(manifest.ok).toBe(true);
		if (!manifest.ok) return;
		expect(manifest.value.egress.default).toBe("deny");
		expect(manifest.value.egress.allow).toEqual([]);
		expect(manifest.value.storage.persistent).toBe(false);
		expect(manifest.value.runtime.entrypoint).toBe("index.js");
	});

	test("worker file contains no obvious secrets", () => {
		const source = readFileSync(join(repoRoot, "tests/fixtures/hostile-app/app/index.js"), "utf8");
		expect(source).not.toContain("IWEB_API_TOKEN=");
		expect(source).not.toContain("MINIO_ROOT");
		expect(source).not.toContain("PASSWORD=");
	});
});

describe("sandbox matrix CLI", () => {
	const ENFORCEMENT_POINTS = new Set(["oci-boundary", "egress-gateway", "object-gateway", "supervisor-acl", "cgroup-limit", "seccomp"]);

	test("dry mode prints the full expected-denial matrix and exits 0", () => {
		const stdout = execFileSync("bun", ["scripts/sandbox-matrix.bun.ts", "dry"], { cwd: repoRoot, encoding: "utf8" });
		const report = JSON.parse(stdout) as {
			matrix: { attackId: string; name: string; expectedDenial: string; enforcementPoint: string }[];
			meta: { sandbox: string | null; host: string | null; ran: boolean };
		};
		expect(report.meta.ran).toBe(false);
		expect(report.meta.sandbox).toBeNull();
		expect(report.meta.host).toBeNull();
		expect(report.matrix).toHaveLength(9);
		expect(new Set(report.matrix.map((entry) => entry.attackId))).toEqual(new Set(REQUIRED_ATTACK_IDS));
		for (const entry of report.matrix) {
			expect(entry.expectedDenial).toBe("outside-app");
			expect(ENFORCEMENT_POINTS.has(entry.enforcementPoint)).toBe(true);
			expect(entry.name.length).toBeGreaterThan(0);
		}
	});

	test("run mode without TARGET_URL writes an honest requiresLinuxNode report", () => {
		const reportPath = join(mkdtempSync(join(tmpdir(), "hostile-matrix-")), "sandbox-matrix-report.json");
		let threw = false;
		try {
			execFileSync("bun", ["scripts/sandbox-matrix.bun.ts", "run"], {
				cwd: repoRoot,
				encoding: "utf8",
				env: { ...process.env, TARGET_URL: "", REPORT_PATH: reportPath },
				stdio: "pipe",
			});
		} catch {
			threw = true;
		}
		expect(threw).toBe(true); // run mode exits non-zero when not all attacks pass
		const report = JSON.parse(readFileSync(reportPath, "utf8")) as {
			meta: { ran: boolean; timestamp: string };
			results: { attackId: string; attempted: boolean; deniedOutsideApp: boolean; observed: string; pass: boolean }[];
		};
		expect(report.meta.ran).toBe(true);
		expect(typeof report.meta.timestamp).toBe("string");
		expect(report.results).toHaveLength(9);
		expect(new Set(report.results.map((result) => result.attackId))).toEqual(new Set(REQUIRED_ATTACK_IDS));
		expect(report.results.every((result) => result.pass === false)).toBe(true);
		expect(JSON.stringify(report)).toContain("requiresLinuxNode");
	});
});
