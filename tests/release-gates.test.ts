// 用户原始需求（2026-08-14）：Notes export/import 可重复且内容相等；hostile fixture 的 internal egress 全部拒绝；credential scan 只报类别不报值。
// 正交意图：11.x / 12.1 / 12.3。
import { describe, expect, test } from "bun:test";
import { exportNotes, importNotes, verifyNotesEquality, dryRunNotesVerification, migrateNotes, createDurableObjectExportSource } from "../packages/contracts/notes-migration.ts";
import { scanForSecrets } from "../packages/contracts/credential-scan.ts";
import { compileEgressPolicy, isDeniedEgressDestination } from "../packages/contracts/egress-policy.ts";
import { buildSandboxSpec } from "../supervisor/sandbox-spec.ts";
import { validateApplicationManifest } from "../packages/contracts/manifest.ts";
import { readFileSync } from "node:fs";

describe("notes migration", () => {
	test("exports, imports, and verifies record count and content equality", () => {
		const source = () => [{ id: "1", content: "hello" }, { id: "2", content: "world" }];
		const exported = exportNotes(source);
		expect(exported.count).toBe(2);
		let written: { id: string; content: string }[] = [];
		importNotes((records) => { written = [...records]; }, exported.records);
		expect(verifyNotesEquality(exported, written)).toEqual({ equal: true, count: 2 });
		// repeatability: same source produces the same digest
		expect(exportNotes(source).digest).toBe(exported.digest);
	});

	test("dry-run verification is non-destructive, repeatable, and reports rollback inputs", () => {
		const source = () => [{ id: "a", content: "x" }, { id: "b", content: "y" }, { id: "c", content: "z" }];
		let readCount = 0;
		const report = dryRunNotesVerification(() => { readCount += 1; return source(); });
		expect(report.destructive).toBe(false);
		expect(report.count).toBe(3);
		expect(report.repeatable).toBe(true);
		expect(report.rollbackInputs.recordCount).toBe(3);
		expect(report.rollbackInputs.backupDigest).toBe(report.digest);
		expect(readCount).toBeGreaterThanOrEqual(2);
	});

	test("migrateNotes dry-run writes nothing; a migrate run writes and verifies equality", () => {
		const source = () => [{ id: "1", content: "hello" }];
		let writes = 0;
		let store: { id: string; content: string }[] = [];
		const dry = migrateNotes({ readSource: source, writeTarget: (records) => { writes += 1; store = [...records]; }, dryRun: true });
		expect(dry.mode).toBe("dry-run");
		expect(writes).toBe(0);
		expect(dry.imported).toBeUndefined();
		const migrated = migrateNotes({ readSource: source, writeTarget: (records) => { store = [...records]; }, readTarget: () => store, dryRun: false });
		expect(migrated.mode).toBe("migrate");
		expect(migrated.imported?.equal).toBe(true);
		expect(migrated.imported?.count).toBe(1);
	});

	test("the Durable Object export source validates every record and aborts on any malformed one", () => {
		const good = [{ id: "1", content: "a" }, { id: "2", content: "b" }];
		const source = createDurableObjectExportSource(() => good, "test-pinned-celld");
		expect(source.provenance).toBe("test-pinned-celld");
		expect(dryRunNotesVerification(source.readState).count).toBe(2);
		// malformed id / content / non-array all abort rather than partially export
		expect(() => createDurableObjectExportSource(() => [{ id: "", content: "x" }], "p").readState()).toThrow();
		expect(() => createDurableObjectExportSource(() => [{ id: "1", content: 5 }], "p").readState()).toThrow();
		expect(() => createDurableObjectExportSource(() => "not-an-array", "p").readState()).toThrow();
	});
});

describe("hostile application fixture", () => {
	test("its internal egress targets are denied by the egress policy", () => {
		const manifestText = readFileSync("tests/fixtures/hostile-app/iweb.json", "utf8");
		const manifest = validateApplicationManifest(JSON.parse(manifestText));
		expect(manifest.ok).toBe(true);
		if (!manifest.ok) return;
		const policy = compileEgressPolicy(manifest.value.egress);
		for (const host of ["kernel", "minio", "metadata.google.internal"]) {
			const verdict = isDeniedEgressDestination({ host, resolvedAddresses: ["93.184.216.34"], port: 80, policy });
			expect(verdict.denied).toBe(true);
		}
	});

	test("its sandbox spec carries no control-plane credentials", () => {
		const spec = buildSandboxSpec({ sandboxId: "sbx-hostile", versionIdentity: { applicationId: "hostile", digest: "a".repeat(64), sequence: 1 }, packageDigest: "a".repeat(64), policy: { resources: { cpuMillis: 1000, memoryBytes: 2 ** 30, pidLimit: 10000, storageBytes: 2 ** 34 }, egress: { default: "deny", allow: [] } }, gatewayAddress: "10.200.9.2", subnetIndex: 9 }, { runtimeImage: "ghcr.io/denoland/celld@sha256:" + "c".repeat(64), gatewayImage: "localhost/iweb-sandbox-gateway@sha256:" + "d".repeat(64), stateDirectory: "/state", gatewayRuntimeDirectory: "/run/iweb-sandbox/gw", region: "us-east-1" });
		expect(spec.environment).toContain("CELLD_NODE=sbx-hostile");
		// outbound transport points at the gateway's internal-network address,
		// never a control-plane host; the enforced boundary is the internal-only
		// network, the proxy variables are a cooperative hint
		expect(spec.environment.some((entry) => entry.startsWith("HTTP_PROXY=http://10."))).toBe(true);
		expect(spec.environment.some((entry) => entry.startsWith("NO_PROXY=" + spec.gatewayAddress))).toBe(true);
		expect(spec.environment.join(" ")).not.toContain("TOKEN");
		expect(spec.environment.join(" ")).not.toContain("PASSWORD");
		expect(spec.environment.join(" ")).not.toContain("MINIO");
		// the executable authority lives in the image entrypoint, never in the command
		expect(spec.command.join(" ")).not.toContain("celld");
		// finite limits are enforced from policy
		expect(spec.cpuMillis).toBe(1000);
		expect(spec.pidLimit).toBe(10000);
	});
});

describe("credential scan", () => {
	test("reports category and sanitized location without echoing secret values or labels", () => {
		const secret = "IWEB_API_TOKEN_super_secret_value";
		const result = scanForSecrets({
			secrets: [{ value: secret, category: "owner-key" }, { value: "minio-root", category: "minio" }],
			locations: [
				{ kind: "admin-assets", label: "app.js", content: "const x = '" + secret + "';" },
				{ kind: "log", label: "worker/index.js", content: "clean" },
			],
		});
		expect(result.clean).toBe(false);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].category).toBe("owner-key");
		expect(result.findings[0].location).toMatch(/^admin-assets:[a-f0-9]{12}$/);
		expect(JSON.stringify(result)).not.toContain(secret);
		expect(JSON.stringify(result)).not.toContain("app.js");
	});
});

