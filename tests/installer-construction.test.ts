// 用户原始需求（2026-08-14）：安装器的一切镜像操作必须落在 iweb-sandbox 用户的 rootless store；systemd 服务才能看到 pinned 镜像。
// 正交意图：2.40 本地证据——解析安装器源码，断言命令构造；真实 clean-install 由 operator acceptance 补证。
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { snapshotReadPolicy } from "../kernel/package-store.js";

const source = readFileSync("scripts/install-sandbox-supervisor.bun.ts", "utf8");

describe("installer image-store command construction (2.40)", () => {
	test("every podman invocation runs as the iweb-sandbox service user with the unit's HOME/XDG environment, never as root (2.50)", () => {
		const podmanLines = source.split("\n").filter((line) => (line.includes("podman ") || line.includes("podmanAsService")) && !line.trim().startsWith("//"));
		expect(podmanLines.length).toBeGreaterThanOrEqual(4);
		for (const line of podmanLines) {
			// either the env-pinned runuser form or one of the shared helpers
			// (podmanAsService / podmanCaptureAsService both pin the service env)
			const isRunuser = line.includes("runuser -u iweb-sandbox --");
			const isHelper = line.includes("podmanAsService") || line.includes("podmanCaptureAsService");
			expect(isRunuser || isHelper).toBe(true);
			expect(line).not.toMatch(/\$`podman/);
		}
		// the shared helper pins HOME/XDG_DATA_HOME/XDG_RUNTIME_DIR on every call
		expect(source).toContain("HOME=${serviceUserEnv.HOME} XDG_DATA_HOME=${serviceUserEnv.XDG_DATA_HOME} XDG_RUNTIME_DIR=${serviceUserEnv.XDG_RUNTIME_DIR}");
	});

	test("service directories are created and owned by iweb-sandbox before any podman command (2.50)", () => {
		expect(source).toContain("install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /var/lib/iweb-sandbox");
		expect(source).toContain("-m 0700 /var/lib/iweb-sandbox/.local/share/containers");
		// directory creation precedes the first podman helper definition
		expect(source.indexOf("install -d -o iweb-sandbox")).toBeLessThan(source.indexOf("async function podmanAsService"));
	});

	test("the build directory is made readable for the unprivileged build", () => {
		// root-owned contexts present as unmapped inside the rootless userns;
		// the context must be service-user OWNED, not merely world-readable
		expect(source).toContain("chown -R iweb-sandbox:iweb-sandbox");
	});

	test("both pinned images are verified present in the service-user store after install", () => {
		expect(source).toContain("for (const pinned of [gatewayImage, runtimeImage])");
		expect(source).toContain('podmanAsService(["image", "inspect", pinned])');
	});

	test("the unit drop-in carries digest-pinned image references", () => {
		expect(source).toContain("IWEB_SANDBOX_RUNTIME_IMAGE=${runtimeImage}");
		expect(source).toContain("IWEB_SANDBOX_GATEWAY_IMAGE=${gatewayImage}");
		expect(source).toContain("localhost/iweb-sandbox-gateway@");
	});
});

describe("supervisor snapshot wiring (2.48/4.2)", () => {
	test("the installer provisions a read-only service credential and writes the alias into the service user's mc config", () => {
		// issuance is argv-free and policy-file based, under the issuer parent
		expect(source).toContain("mc admin user svcacct add --json --policy");
		expect(source).toContain("snapshotReadPolicy()");
		expect(source).not.toContain("--access-key");
		expect(source).not.toContain("--secret-key");
		// the alias + credentials live in the SERVICE USER's HOME-scoped mc config
		expect(source).toContain("install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /var/lib/iweb-sandbox/.mc");
		expect(source).toContain('"/var/lib/iweb-sandbox/.mc/config.json"');
		expect(source).toContain("chmod 0600 /var/lib/iweb-sandbox/.mc/config.json");
		// the service identity is proven BEFORE the unit is restarted onto it;
		// the proof operates inside the packages/ prefix (ListBucket there is
		// prefix-conditioned — a bucket-root stat is denied by design)
		expect(source).toContain("runuser -u iweb-sandbox --");
		expect(source.indexOf("mc ls ${supervisorAlias}/iweb-system/packages/")).toBeGreaterThan(0);
		expect(source.indexOf("runuser -u iweb-sandbox")).toBeLessThan(source.indexOf("systemctl daemon-reload"));
	});

	test("the unit drop-in pins the snapshot alias and region the running supervisor uses", () => {
		expect(source).toContain("IWEB_SANDBOX_SYSTEM_ALIAS=${supervisorAlias}/iweb-system");
		expect(source).toContain("IWEB_SANDBOX_REGION=${snapshotRegion}");
		expect(source).toContain('"iweb-snapshot"');
	});

	test("the snapshot policy itself is least-privilege: packages/ reads only", () => {
		const policy = snapshotReadPolicy();
		expect(policy.Statement[0].Action).toEqual(["s3:GetObject"]);
		expect(policy.Statement[0].Resource).toEqual(["arn:aws:s3:::iweb-system/packages/*"]);
		expect(policy.Statement[1].Action).toEqual(["s3:ListBucket"]);
		expect((policy.Statement[1].Condition.StringLike["s3:prefix"] as string[]).every((prefix) => prefix.startsWith("packages/"))).toBe(true);
		const flat = JSON.stringify(policy);
		expect(flat).not.toContain("PutObject");
		expect(flat).not.toContain("DeleteObject");
		expect(flat).not.toContain("iweb-workspace");
	});
});

describe("relay delivery (codex-final P0-3)", () => {
	test("cargo is a required installer command and the relay is built from the pinned kernel-rs workspace", () => {
		expect(source).toContain('for (const command of ["bun", "podman", "systemctl", "useradd", "usermod", "mc", "cargo"])');
		// --locked: the checked-out Cargo.lock is the dependency authority; any
		// divergent resolution fails the install instead of silently drifting.
		expect(source).toContain("cargo build --release --locked -p snapshot-fd-relay");
		expect(source).toContain('const relaySourceDirectory = join(projectRoot, "kernel-rs")');
	});

	test("the relay binary is installed exactly where the supervisor expects it", () => {
		// supervisor/main.ts (via wasm-serve.ts) spawns this default path; a drift
		// here would strand enablement on a missing-binary failure.
		expect(source).toContain('const relayExecutable = "/usr/local/libexec/iweb-sandbox/snapshot-fd-relay"');
		expect(source).toContain("install -m 0755 ${relayBuildOutput} ${relayExecutable}");
	});

	test("the built relay artifact is identity-probed before install and its digest is reported", () => {
		// the relay has no --version flag; --help exits 0 and prints usage to stderr —
		// a stale or misnamed binary fails the probe and the install fails closed.
		expect(source).toContain('Bun.spawnSync([relayBuildOutput, "--help"]');
		expect(source).toContain("--help identity probe");
		expect(source).toContain("snapshot-fd-relay sha256:");
	});
});