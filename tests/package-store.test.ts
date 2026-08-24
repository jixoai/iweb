// 用户原始需求（2026-08-14）：admission 必须把 canonical 快照持久化到非匿名系统路径，版本部署对象从快照以固定命令生成；缺快照/部署对象即 fail closed。
// 正交意图：2.22 生产边界证据；注入 exec 断言 mc 命令形状与内容寻址校验；无真实 MinIO。
import { describe, expect, test } from "bun:test";
import { mcPackageStore, versionScopedObjectPolicy, applicationDataPolicy } from "../kernel/package-store.js";
import { defaultObjectCredentialIssuer } from "../kernel/application-control.js";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

const manifest = { schemaVersion: 1, name: "notes", runtime: { kind: "celld", celldVersion: "0.2.0", entrypoint: "index.js" }, assets: { root: "app" } };

// The full version identity deploy/deployed field-validate against (2.22).
function identityFor(digest: string, sequence = 1, applicationId = "notes") {
	return { applicationId, versionId: "a".repeat(64), digest, sequence };
}

// A well-formed Kernel version-deployment record for a given identity.
function deploymentRecord(sandboxId: string, identity: ReturnType<typeof identityFor>, overrides: Record<string, unknown> = {}) {
	return {
		v: 1,
		kind: "iweb-version-deployment",
		sandboxId,
		applicationId: identity.applicationId,
		versionId: identity.versionId,
		digest: identity.digest,
		sequence: identity.sequence,
		deployedAt: new Date().toISOString(),
		...overrides,
	};
}

// Minimal in-process mc double: stores piped objects and answers cat/cp/mb/stat
// by full key. It mirrors the full-key mc surface the production store relies
// on, so the exact platform commands and content-addressed verification are
// asserted without depending on "mc ls --recursive" key relativity.
function fakeMc() {
	const objects = new Map<string, Buffer>();
	const log: string[] = [];
	function exec(args: string[], options: { input?: Buffer; encoding?: string | null } = {}) {
		log.push(args.join(" "));
		const cmd = args[0];
		const rest = args.slice(1);
		if (cmd === "pipe") {
			objects.set(rest[0], Buffer.from(options.input ?? Buffer.alloc(0)));
			return "";
		}
		if (cmd === "mb") return "";
		if (cmd === "rm") return "";
		if (cmd === "stat") {
			if (!objects.has(rest[0])) throw new Error("mc: object not found");
			return "";
		}
		if (cmd === "cp") {
			const [src, dst] = rest;
			const content = objects.get(src);
			if (!content) throw new Error("mc: source object not found");
			objects.set(dst, content);
			return "";
		}
		if (cmd === "cat") {
			const content = objects.get(rest[0]);
			if (!content) throw new Error("mc: object not found");
			return options.encoding === null ? content : content.toString(options.encoding ?? "utf8");
		}
		throw new Error("unexpected mc command: " + cmd);
	}
	return { exec, log, objects };
}

describe("mc package store (production boundary)", () => {
	test("persist writes the manifest, file index, and each file under the non-anonymous system prefix", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [
			{ path: "app/index.js", content: Buffer.from("export default {};\n") },
			{ path: "app/assets/style.css", content: Buffer.from("body{color:#000}\n") },
		];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		const prefix = "local/iweb-system/packages/" + digest;
		expect(mc.log.some((cmd) => cmd.startsWith("pipe " + prefix + "/manifest.json"))).toBe(true);
		expect(mc.log.some((cmd) => cmd.startsWith("pipe " + prefix + "/files.json"))).toBe(true);
		expect(mc.log.some((cmd) => cmd.startsWith("pipe " + prefix + "/files/app/index.js"))).toBe(true);
		expect(mc.log.some((cmd) => cmd.startsWith("pipe " + prefix + "/files/app/assets/style.css"))).toBe(true);
	});

	test("verify re-derives the digest from restored content and reports absent snapshots as null", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [{ path: "app/index.js", content: Buffer.from("hello world\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		expect(await store.verify(digest)).toBe(digest);
		expect(await store.verify("f".repeat(64))).toBeNull();
	});

	test("deploy creates the version bucket and runs the real celld deploy flow from the staged snapshot", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [{ path: "app/index.js", content: Buffer.from("payload\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		const staged: string[] = [];
		const deployed: string[] = [];
		const finished: boolean[] = [];
		const envBuckets: string[] = [];
		await store.deploy("sbx-abc123", identityFor(digest), {
			stage: (prefix, stageDir, context) => staged.push(prefix + "->" + stageDir + ":" + context.main),
			stageDirectory: "/tmp/stage-abc",
			deployEnv: (bucketName) => { envBuckets.push(bucketName); return { AWS_ACCESS_KEY_ID: "deploy", AWS_SECRET_ACCESS_KEY: "deploy-secret" }; },
			deployCelld: (stageDir, bucketName) => {
				deployed.push(stageDir + "->" + bucketName);
				// the pinned celld flow publishes the deployment pointer
				mc.objects.set("local/iweb-app-sbx-abc123/deploy/current.json", Buffer.from('{"script":"app","version":"v1"}\n'));
			},
			deployDone: () => finished.push(true),
		});
		expect(mc.log.some((cmd) => cmd.startsWith("mb --ignore-existing local/iweb-app-sbx-abc123"))).toBe(true);
		// the staged project main comes from the snapshot manifest (entrypoint + assets root), not caller input
		expect(staged).toEqual(["local/iweb-system/packages/" + digest + "->/tmp/stage-abc:app/index.js"]);
		// hooks see the pure bucket name (celld takes s3://<bucket>, not an mc alias path)
		expect(envBuckets).toEqual(["iweb-app-sbx-abc123"]);
		expect(deployed).toEqual(["/tmp/stage-abc->iweb-app-sbx-abc123"]);
		expect(finished).toEqual([true]);
		// the deploy persisted the version-deployment record under deploy/version.json
		expect(mc.log.some((cmd) => cmd.startsWith("pipe local/iweb-app-sbx-abc123/deploy/version.json"))).toBe(true);
		expect(await store.deployed("sbx-abc123", identityFor(digest))).toBe(true);
	});

	test("deploy fails closed when the celld flow produces no deployment pointer (2.33)", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [{ path: "app/index.js", content: Buffer.from("payload\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		// a silent no-op celld hook must not count as a deployment
		await expect(store.deploy("sbx-abc123", identityFor(digest), {
			deployCelld: () => undefined,
			deployDone: () => undefined,
		})).rejects.toThrow(/no deployment pointer/);
		expect(await store.deployed("sbx-abc123", identityFor(digest))).toBe(false);
	});

	test("deploy fails closed without a celld deploy hook: a bucket alone is not a deployment", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [{ path: "app/index.js", content: Buffer.from("payload\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		await expect(store.deploy("sbx-abc123", identityFor(digest), {})).rejects.toThrow(/requires the celld deploy hook/);
	});

	test("deployed() requires a well-formed pointer AND a matching deployment record (2.22)", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [{ path: "app/index.js", content: Buffer.from("payload\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		const identity = identityFor(digest);
		const key = "local/iweb-app-sbx-abc123/deploy/current.json";
		const recordKey = "local/iweb-app-sbx-abc123/deploy/version.json";
		mc.objects.set(key, Buffer.from("not json"));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		mc.objects.set(key, Buffer.from("[1,2]"));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		// well-formed pointer but NO deployment record: not a deployment
		mc.objects.set(key, Buffer.from('{"script":"app","version":"v1"}'));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		// a record that field-matches makes it a deployment...
		mc.objects.set(recordKey, Buffer.from(JSON.stringify(deploymentRecord("sbx-abc123", identity))));
		expect(await store.deployed("sbx-abc123", identity)).toBe(true);
		// ...but any identity drift is stale, never a deployment
		mc.objects.set(recordKey, Buffer.from(JSON.stringify(deploymentRecord("sbx-abc123", identity, { digest: "b".repeat(64) }))));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		mc.objects.set(recordKey, Buffer.from(JSON.stringify(deploymentRecord("sbx-abc123", identity, { versionId: "c".repeat(64) }))));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		mc.objects.set(recordKey, Buffer.from(JSON.stringify(deploymentRecord("sbx-abc123", identity, { sequence: 2 }))));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		mc.objects.set(recordKey, Buffer.from(JSON.stringify(deploymentRecord("sbx-abc123", identity, { applicationId: "other" }))));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		// malformed record (unknown field / bad shape): not a deployment
		mc.objects.set(recordKey, Buffer.from(JSON.stringify(deploymentRecord("sbx-abc123", identity, { extra: "smuggled" }))));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		mc.objects.set(recordKey, Buffer.from("nope"));
		expect(await store.deployed("sbx-abc123", identity)).toBe(false);
		// an older requested version against a newer record is stale too
		expect(await store.deployed("sbx-abc123", identityFor(digest, 2))).toBe(false);
	});

	test("deploy fails closed when the snapshot no longer restores to the admitted digest (2.22)", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [{ path: "app/index.js", content: Buffer.from("original\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		// tamper with the persisted snapshot AFTER admission
		mc.objects.set("local/iweb-system/packages/" + digest + "/files/app/index.js", Buffer.from("tampered\n"));
		await expect(store.deploy("sbx-abc123", identityFor(digest), {
			deployCelld: () => { throw new Error("celld must not run"); },
			deployDone: () => undefined,
		})).rejects.toThrow(/does not match its digest/);
		// an absent snapshot is equally fatal
		const absent = packageFilesDigest([{ path: "app/index.js", content: Buffer.from("ghost\n") }]);
		await expect(store.deploy("sbx-abc123", identityFor(absent), {
			deployCelld: () => { throw new Error("celld must not run"); },
			deployDone: () => undefined,
		})).rejects.toThrow(/absent or unreadable/);
	});
	test("a tampered snapshot is detected: verify no longer matches the admitted digest", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		const files = [{ path: "app/index.js", content: Buffer.from("original\n") }];
		const digest = packageFilesDigest(files);
		await store.persist(digest, manifest, files);
		const key = "local/iweb-system/packages/" + digest + "/files/app/index.js";
		mc.objects.set(key, Buffer.from("tampered\n"));
		expect(await store.verify(digest)).not.toBe(digest);
	});
	test("deleteApplicationData removes only the application data namespace with a fixed command", async () => {
		const mc = fakeMc();
		const store = mcPackageStore("local/iweb-system", { exec: mc.exec });
		await store.deleteApplicationData("notes");
		expect(mc.log.some((c) => c === "rm --recursive --force local/iweb-apps/notes/data/")).toBe(true);
		await expect(store.deleteApplicationData("Bad!")).rejects.toThrow();
	});
});

describe("per-version object authority (2.23)", () => {
	test("versionScopedObjectPolicy: least-privilege by construction, not by gateway denial (2.34)", () => {
		const policy = versionScopedObjectPolicy("iweb-app-sbx-abc123");
		expect(policy.Version).toBe("2012-10-17");
		const [read, list, write] = policy.Statement;
		// GetObject ONLY under the four runtime prefixes — never bucket-wide
		expect(read.Action).toEqual(["s3:GetObject"]);
		expect(read.Resource).toEqual([
			"arn:aws:s3:::iweb-app-sbx-abc123/deploy/*",
			"arn:aws:s3:::iweb-app-sbx-abc123/nodes/*",
			"arn:aws:s3:::iweb-app-sbx-abc123/fleet/*",
			"arn:aws:s3:::iweb-app-sbx-abc123/cells/*",
		]);
		expect(read.Resource).not.toContain("arn:aws:s3:::iweb-app-sbx-abc123/*");
		// ListBucket carries a prefix condition: bucket-wide listing is NOT granted
		expect(list.Action).toEqual(["s3:ListBucket"]);
		expect(list.Resource).toEqual(["arn:aws:s3:::iweb-app-sbx-abc123"]);
		const prefixes = list.Condition.StringLike["s3:prefix"] as string[];
		for (const prefix of prefixes) {
			expect(prefix === "deploy/" || prefix === "deploy/*" || prefix === "nodes/" || prefix === "nodes/*" || prefix === "fleet/" || prefix === "fleet/*" || prefix === "cells/" || prefix === "cells/*").toBe(true);
		}
		expect(prefixes).not.toContain("");
		// PutObject only under celld's own state prefixes; deploy/* stays immutable
		expect(write.Action).toEqual(["s3:PutObject"]);
		expect(write.Resource).toEqual(["arn:aws:s3:::iweb-app-sbx-abc123/nodes/*", "arn:aws:s3:::iweb-app-sbx-abc123/fleet/*", "arn:aws:s3:::iweb-app-sbx-abc123/cells/*"]);
		expect(JSON.stringify(write)).not.toContain("/deploy/*");
		const flat = JSON.stringify(policy);
		expect(flat).not.toContain("DeleteObject");
		expect(flat).not.toContain("iweb-app-*");
	});

	test("applicationDataPolicy is read-write and scoped to exactly one application's data namespace", () => {
		const policy = applicationDataPolicy("notes");
		expect(policy.Version).toBe("2012-10-17");
		expect(policy.Statement[0].Action).toEqual(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]);
		expect(policy.Statement[0].Resource).toEqual(["arn:aws:s3:::iweb-apps/notes/data", "arn:aws:s3:::iweb-apps/notes/data/*"]);
		const flat = JSON.stringify(policy);
		expect(flat).not.toContain("ListBucket");
		expect(flat).not.toContain("iweb-app-");
	});

	test("the production issuer creates a per-version read-only policy and a generated credential (argv-free)", () => {
		const execLog: string[] = [];
		let writtenPolicy = "";
		const issue = defaultObjectCredentialIssuer("http://10.37.0.1:9000", "us-east-1", {
			exec: (args: string[]) => { execLog.push(args.join(" ")); return JSON.stringify({ status: "success", accessKey: "GEN-AK", secretKey: "GEN-SK" }); },
			writeFile: (_file: string, content: string) => { writtenPolicy = content; },
			unlink: () => undefined,
			tmpdir: "/tmp",
			parentUser: "issuer",
		});
		const issued = issue("sbx-abc123", "iweb-app-sbx-abc123");
		expect(Object.keys(issued.object).sort()).toEqual(["accessKeyId", "endpoint", "region", "secretAccessKey"]);
		expect(issued.object.accessKeyId).toBe("GEN-AK");
		expect(issued.retire.accessKey).toBe("GEN-AK");
		expect(issued.retire.parentUser).toBe("issuer");
		const flat = execLog.join(" ");
		// the inline policy DOCUMENT file path rides argv; no named policy exists
		expect(flat).toMatch(/admin user svcacct add --json --policy \/tmp\/iweb-policy-sbx-abc123-[a-f0-9]+\.json local issuer/);
		expect(flat).not.toContain("admin policy create");
		// credentials never appear in argv and no user-add runs at issuance
		expect(flat).not.toContain("GEN-SK");
		expect(flat).not.toContain("--secret-key");
		expect(flat).not.toContain("--access-key");
		expect(execLog.some((c) => c.startsWith("admin user add"))).toBe(false);
		const parsed = JSON.parse(writtenPolicy);
		// the persisted policy document itself is least-privilege (2.34)
		expect(parsed.Statement[0].Action).toEqual(["s3:GetObject"]);
		expect(parsed.Statement[0].Resource).toContain("arn:aws:s3:::iweb-app-sbx-abc123/deploy/*");
		expect(parsed.Statement[1].Condition.StringLike["s3:prefix"]).toContain("deploy/*");
		expect(parsed.Statement[2].Action).toEqual(["s3:PutObject"]);
		expect(parsed.Statement[2].Resource).toContain("arn:aws:s3:::iweb-app-sbx-abc123/nodes/*");
		expect(JSON.stringify(parsed.Statement[2])).not.toContain("deploy/*");
	});
});
