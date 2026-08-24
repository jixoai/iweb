// 用户原始需求（2026-08-14）：snapshot → staging → pinned celld deploy 的生产链路必须真实接线：Kernel 构造的 mcPackageStore 注入生产 hooks。
// 正交意图：2.33/2.34/2.48 生产证据——物化字节精确、wrangler 描述符来自 manifest、部署凭据 argv-free 签发且用后即退役、
// celld 命令行与 entrypoint.sh 一致（凭据只走环境变量）、无指针即 fail closed。
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mcPackageStore, versionDeployPolicy } from "../kernel/package-store.js";
import { createDeployHooks } from "../kernel/deploy-hooks.js";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

const manifest = {
	schemaVersion: 1 as const,
	name: "notes",
	runtime: { kind: "celld" as const, celldVersion: "0.2.0", entrypoint: "index.js" },
	assets: { root: "app" },
	resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 },
	storage: { persistent: false, requestBytes: 0 },
	egress: { default: "deny" as const, allow: [] },
};

function identityFor(digest: string, sequence = 1) {
	return { applicationId: "notes", versionId: "a".repeat(64), digest, sequence };
}

function double(options: { deployProducesPointer?: boolean } = {}) {
	const objects = new Map<string, Buffer>();
	const mcLog: string[] = [];
	const celldRuns: { args: string[]; env: Record<string, string> }[] = [];
	const retired: string[] = [];
	const issued: { accessKey: string; secretKey: string }[] = [];
	const policyWrites = new Map<string, string>();
	function mc(args: string[], execOptions: { input?: Buffer; encoding?: string | null } = {}) {
		mcLog.push(args.join(" "));
		const [cmd, ...rest] = args;
		if (cmd === "pipe") {
			objects.set(rest[0], Buffer.from(execOptions.input ?? Buffer.alloc(0)));
			return "";
		}
		if (cmd === "mb") return "";
		if (cmd === "cat") {
			const content = objects.get(rest[0]);
			if (!content) throw new Error("mc: object not found: " + rest[0]);
			return execOptions.encoding === null ? content : content.toString("utf8");
		}
		if (cmd === "admin" && rest[0] === "user" && rest[1] === "svcacct" && rest[2] === "add") {
			const account = { status: "success", accessKey: "DEPLOY-AK-" + (issued.length + 1), secretKey: "DEPLOY-SK-" + (issued.length + 1) };
			issued.push(account);
			return JSON.stringify(account);
		}
		if (cmd === "admin" && rest[0] === "user" && rest[1] === "svcacct" && rest[2] === "rm") {
			retired.push(rest[rest.length - 1]);
			return "";
		}
		throw new Error("unexpected mc command: " + args.join(" "));
	}
	function runCelld(args: string[], execOptions: { env?: Record<string, string> } = {}) {
		celldRuns.push({ args: [...args], env: { ...(execOptions.env ?? {}) } });
		if (options.deployProducesPointer === false) return "";
		const bucketArg = args[args.indexOf("--bucket") + 1];
		const bucket = bucketArg.slice("s3://".length);
		objects.set("local/" + bucket + "/deploy/current.json", Buffer.from('{"script":"app","version":"v1"}\n'));
		return "";
	}
	return {
		objects, mcLog, celldRuns, retired, issued, policyWrites, mc, runCelld,
		writeFile: (file: string, content: string | Buffer, mode?: number) => {
			if (file.includes("iweb-policy-deploy-")) policyWrites.set(file, String(content));
			writeFileSync(file, content, mode === undefined ? {} : { mode });
		},
	};
}

function hooksWith(stageRoot: string, d: ReturnType<typeof double>, opts: { deployProducesPointer?: boolean } = {}) {
	return createDeployHooks({
		endpoint: "http://127.0.0.1:9000",
		region: "us-east-1",
		stageRoot,
		alias: "local",
		parentUser: "iweb-sandbox-issuer",
		tmpdir: stageRoot,
		mc: d.mc as unknown as (args: string[], options?: { input?: Buffer; encoding?: string | null }) => string | Buffer,
		runCelld: d.runCelld as unknown as (args: string[], options?: { env?: Record<string, string> }) => string | Buffer,
		writeFile: d.writeFile as unknown as (file: string, content: string | Buffer, mode?: number) => void,
		unlink: (file: string) => undefined,
		deployProducesPointer: opts.deployProducesPointer,
	});
}

describe("production snapshot-to-celld deploy chain (2.33/2.34/2.48)", () => {
	test("the production hooks materialize the snapshot, deploy with a one-shot credential, and retire it", async () => {
		const stageRoot = mkdtempSync(join(tmpdir(), "iweb-deploy-"));
		const d = double();
		const hooks = hooksWith(stageRoot, d);
		const store = mcPackageStore("local/iweb-system", Object.assign({ exec: d.mc as never }, hooks));
		const files = [
			{ path: "app/index.js", content: Buffer.from("export default {};\n") },
			{ path: "app/assets/style.css", content: Buffer.from("body{color:#000}\n") },
		];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		await store.deploy("sbx-prod1", identityFor(digest), hooks);

		// staged project: exact snapshot bytes plus a generated descriptor whose
		// main derives from the manifest entrypoint + assets root
		const stageDir = join(stageRoot, "sbx-prod1", digest);
		expect(readFileSync(join(stageDir, "app/index.js"), "utf8")).toBe("export default {};\n");
		expect(readFileSync(join(stageDir, "app/assets/style.css"), "utf8")).toBe("body{color:#000}\n");
		const descriptor = JSON.parse(readFileSync(join(stageDir, "wrangler.jsonc"), "utf8"));
		expect(descriptor).toEqual({ name: "notes", main: "app/index.js", compatibility_date: "2026-08-01" });

		// one-shot deploy credential: argv-free issuance under the issuer parent,
		// policy scoped by versionDeployPolicy to exactly this bucket
		expect(d.issued).toHaveLength(1);
		const issuance = d.mcLog.find((line) => line.includes("svcacct add"));
		expect(issuance).toMatch(/admin user svcacct add --json --policy .*iweb-policy-deploy-iweb-app-sbx-prod1-[a-f0-9]+.json local iweb-sandbox-issuer/);
		expect(issuance).not.toContain("DEPLOY-SK");
		expect(issuance).not.toContain("--secret-key");
		const policy = JSON.parse([...d.policyWrites.values()][0]);
		expect(policy.Statement[0].Action).toEqual(["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]);
		expect(policy.Statement[0].Resource).toEqual(["arn:aws:s3:::iweb-app-sbx-prod1", "arn:aws:s3:::iweb-app-sbx-prod1/*"]);
		expect(JSON.stringify(versionDeployPolicy("iweb-app-sbx-prod1"))).toBe(JSON.stringify(policy));

		// pinned platform command mirrors scripts/iweb-entrypoint.sh; the
		// credential rides the environment, never argv
		expect(d.celldRuns).toHaveLength(1);
		const run = d.celldRuns[0];
		expect(run.args).toEqual(["deploy", stageDir, "--bucket", "s3://iweb-app-sbx-prod1", "--endpoint", "http://127.0.0.1:9000", "--region", "us-east-1"]);
		expect(run.args.join(" ")).not.toContain("DEPLOY-SK");
		expect(run.env).toEqual({ AWS_ACCESS_KEY_ID: "DEPLOY-AK-1", AWS_SECRET_ACCESS_KEY: "DEPLOY-SK-1" });

		// retired immediately after the deploy attempt
		expect(d.retired).toEqual(["DEPLOY-AK-1"]);
		expect(await store.deployed("sbx-prod1", identityFor(digest))).toBe(true);
		rmSync(stageRoot, { recursive: true, force: true });
	});

	test("the credential is retired even when celld produces no deployment pointer, and the deploy fails closed", async () => {
		const stageRoot = mkdtempSync(join(tmpdir(), "iweb-deploy-"));
		const d = double({ deployProducesPointer: false });
		const hooks = hooksWith(stageRoot, d);
		const store = mcPackageStore("local/iweb-system", Object.assign({ exec: d.mc as never }, hooks));
		const files = [{ path: "app/index.js", content: Buffer.from("export default {};\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		await expect(store.deploy("sbx-prod2", identityFor(digest), hooks)).rejects.toThrow(/no deployment pointer/);
		expect(d.retired).toEqual(["DEPLOY-AK-1"]);
		expect(await store.deployed("sbx-prod2", identityFor(digest))).toBe(false);
		rmSync(stageRoot, { recursive: true, force: true });
	});

	test("a tampered manifest entrypoint cannot escape the stage", async () => {
		const stageRoot = mkdtempSync(join(tmpdir(), "iweb-deploy-"));
		const d = double();
		const hooks = hooksWith(stageRoot, d);
		const store = mcPackageStore("local/iweb-system", Object.assign({ exec: d.mc as never }, hooks));
		const files = [{ path: "app/index.js", content: Buffer.from("export default {};\n") }];
		const digest = packageFilesDigest(files);
		const hostile = JSON.parse(JSON.stringify(manifest)) as { runtime: { entrypoint: string } };
		hostile.runtime.entrypoint = "../../escape.js";
		await store.persist(digest, hostile, files);
		await expect(store.deploy("sbx-prod3", identityFor(digest), hooks)).rejects.toThrow(/safe relative path/);
		expect(d.celldRuns).toHaveLength(0);
		rmSync(stageRoot, { recursive: true, force: true });
	});
});
