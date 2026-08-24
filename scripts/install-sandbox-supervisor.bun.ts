// 用户原始需求（2026-08-14）：节点安装器要把 supervisor 作为专用宿主服务交付，而不是暴露 OCI daemon。
// 正交意图：限制 Linux/root 权限；创建稳定用户；安装 seccomp；编译安装 supervisor 与 gateway；digest 固定两个镜像；安装 systemd 单元；执行 preflight。
import { $ } from "bun";
import { mkdtempSync, copyFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { findAvailableSubordinateIdStart, parseSubordinateIdRanges } from "../supervisor/subordinate-ids.ts";
import { snapshotReadPolicy } from "../kernel/package-store.js";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const executable = "/usr/local/libexec/iweb-sandbox-supervisor";
const seccompProfile = "/usr/local/libexec/iweb-sandbox/seccomp.json";
const unit = "/etc/systemd/system/iweb-sandbox-supervisor.service";
const dropInDirectory = "/etc/systemd/system/iweb-sandbox-supervisor.service.d";
const runtimeImage = "ghcr.io/denoland/celld@sha256:76225bc06f15d1de90901e32aae52cb81c800e19800e695dc2774625610c22d2";
const subordinateRangeSize = 65_536;

function requireInstallHost(): void {
	if (process.platform !== "linux") throw new Error("sandbox supervisor installation requires Linux");
	if (process.geteuid?.() !== 0) throw new Error("sandbox supervisor installation requires root");
}

requireInstallHost();
for (const command of ["bun", "podman", "systemctl", "useradd", "usermod", "mc"]) {
	const result = await $`command -v ${command}`.quiet().nothrow();
	if (result.exitCode !== 0) throw new Error(`${command} is required to install the sandbox supervisor`);
}
await $`install -d -m 0755 /usr/local/libexec`;
// Operator-facing command name: the acceptance and operator docs invoke the
// supervisor as `iweb-sandbox-supervisor`; expose the libexec binary on PATH.
await $`ln -sf ${executable} /usr/local/bin/iweb-sandbox-supervisor`;
await $`id -u iweb-sandbox`.quiet().nothrow().then(async (result) => {
	if (result.exitCode !== 0) await $`useradd --system --home-dir /var/lib/iweb-sandbox --shell /usr/sbin/nologin --user-group iweb-sandbox`;
});
// 2.50: create and own every service directory BEFORE any podman command runs,
// so rootless storage/state never lands in root-owned paths.
await $`install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /var/lib/iweb-sandbox`;
await $`install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /var/lib/iweb-sandbox/data`;
await $`install -d -o iweb-sandbox -g iweb-sandbox -m 0755 /run/iweb-sandbox`;
// the rootless image store lives under the service home; same ownership
await $`install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /var/lib/iweb-sandbox/.local/share/containers`;

// Every podman invocation runs as the service user WITH the exact environment
// the systemd unit will use (HOME + XDG dirs), so the image store written
// during install is byte-identical to the one the service reads at runtime.
const serviceUserEnv = {
	HOME: "/var/lib/iweb-sandbox",
	XDG_DATA_HOME: "/var/lib/iweb-sandbox/.local/share",
	XDG_RUNTIME_DIR: "/run/iweb-sandbox",
};
// Capture a podman command's stdout as the service user. Same neutral-cwd and
// env rules as podmanAsService (see below).
function podmanCaptureAsService(args: readonly string[]): string {
	const command = ["runuser", "-u", "iweb-sandbox", "--", "env", `HOME=${serviceUserEnv.HOME}`, `XDG_DATA_HOME=${serviceUserEnv.XDG_DATA_HOME}`, `XDG_RUNTIME_DIR=${serviceUserEnv.XDG_RUNTIME_DIR}`, "podman", ...args];
	const result = Bun.spawnSync(command, { cwd: "/tmp", encoding: "utf8" });
	if (result.exitCode !== 0) throw new Error(`service-user image-store capture failed: ${result.stderr}`);
	return result.stdout.toString();
}
async function podmanAsService(args: readonly string[]): Promise<void> {
	// systemd removes RuntimeDirectory on service stop; the installer's own
	// restart can land mid-window where /run/iweb-sandbox is gone and podman
	// (as the service user) cannot recreate it under root-owned /run. Recreate
	// it root-side before every service-user podman call.
	await $`install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /run/iweb-sandbox`;
	// Run from a neutral cwd: under some sudo/session combinations runuser
	// cannot chdir into the invoking project directory as the service user.
	// No proxy passthrough: rootless podman reaches registries through the
	// host stack (slirp/pasta resolve and route via the host), and forcing an
	// operator HTTP proxy into the pull path has been observed to break
	// registry TLS where direct rootless egress succeeds.
	const command = ["runuser", "-u", "iweb-sandbox", "--", "env", `HOME=${serviceUserEnv.HOME}`, `XDG_DATA_HOME=${serviceUserEnv.XDG_DATA_HOME}`, `XDG_RUNTIME_DIR=${serviceUserEnv.XDG_RUNTIME_DIR}`, "podman", ...args];
	await Bun.spawn(command, { cwd: "/tmp", stdout: "inherit", stderr: "inherit" }).exited.then((code) => {
		if (code !== 0) throw new Error(`service-user image-store command failed with exit code ${code}`);
	});
}

async function ensureSubordinateRange(path: "/etc/subuid" | "/etc/subgid", option: "--add-subuids" | "--add-subgids"): Promise<void> {
	const existing = await Bun.file(path).text().catch(() => "");
	const parsed = parseSubordinateIdRanges(existing);
	if (parsed.some((range) => range.owner === "iweb-sandbox" && range.count >= subordinateRangeSize)) return;
	const candidate = findAvailableSubordinateIdStart(parsed, subordinateRangeSize);
	await $`usermod ${option} ${`${candidate}-${candidate + subordinateRangeSize - 1}`} iweb-sandbox`;
}

await ensureSubordinateRange("/etc/subuid", "--add-subuids");
await ensureSubordinateRange("/etc/subgid", "--add-subgids");
if (process.arch !== "arm64" && process.arch !== "x64") throw new Error(`unsupported supervisor architecture: ${process.arch}`);
const archTarget = "bun-linux-" + process.arch;
await $`bun build --compile --target=${archTarget} ${join(projectRoot, "supervisor/main.ts")} --outfile ${executable}`;
await $`chmod 0755 ${executable}`;
// The seccomp profile referenced by the sandbox spec must ship with the
// supervisor package, or every podman create would fail on the installed node.
await $`install -d -m 0755 /usr/local/libexec/iweb-sandbox`;
await $`install -m 0644 ${join(projectRoot, "packaging/seccomp.json")} ${seccompProfile}`;

// Build the gateway image locally and pin it by digest so the supervisor can
// reject any floating reference.
// 2.40: the images MUST land in the iweb-sandbox user's rootless image store —
// building or pulling as root puts them in root's store, where the systemd
// service (User=iweb-sandbox) can never see them. Everything image-related
// runs through runuser as the service identity.
// Build context must live under a path the SERVICE USER owns: inside the
// rootless user namespace, files created by root (even chmod a+rX) can present
// as unmapped and podman-build rejects the context ("context must be a
// directory"). /tmp is therefore unsuitable as the build-context parent.
const gatewayBuildRoot = "/var/lib/iweb-sandbox/build";
await $`install -d -o iweb-sandbox -g iweb-sandbox -m 0700 ${gatewayBuildRoot}`;
const gatewayBuildDirectory = mkdtempSync(join(gatewayBuildRoot, "gateway-"));
try {
	const gatewayBinary = join(gatewayBuildDirectory, "iweb-gateway");
	await $`bun build --compile --target=${archTarget} ${join(projectRoot, "supervisor/gateway-main.ts")} --outfile ${gatewayBinary}`;
	copyFileSync(join(projectRoot, "packaging/gateway-runtime.Dockerfile"), join(gatewayBuildDirectory, "Dockerfile"));
	await $`chown -R iweb-sandbox:iweb-sandbox ${gatewayBuildDirectory}`;
	await podmanAsService(["build", "-t", "iweb-sandbox-gateway:latest", gatewayBuildDirectory]);
} finally {
	rmSync(gatewayBuildDirectory, { recursive: true, force: true });
}
const gatewayDigest = podmanCaptureAsService(["image", "inspect", "--format", "{{.Digest}}", "iweb-sandbox-gateway:latest"]).trim();
if (!/^sha256:[a-f0-9]{64}$/.test(gatewayDigest)) throw new Error("gateway image digest could not be determined");
const gatewayImage = "localhost/iweb-sandbox-gateway@" + gatewayDigest;

// Pull the pinned celld runtime image into the SAME user store so prepare
// never depends on a tag or on root's image store.
// Pull only when the pinned digest is not already resolvable in the service
// user's store: preloaded/offline stores (air-gapped hosts, proxy-only
// networks where registry blobs are unreliable) must not be forced through
// a network fetch. When a pull IS needed, retry — registry transfers are
// transiently flaky (reset connections, config-blob fetch failures).
const imagePresent = async (ref: string): Promise<boolean> => {
	const probe = Bun.spawn(["runuser", "-u", "iweb-sandbox", "--", "env", `HOME=${serviceUserEnv.HOME}`, `XDG_DATA_HOME=${serviceUserEnv.XDG_DATA_HOME}`, `XDG_RUNTIME_DIR=${serviceUserEnv.XDG_RUNTIME_DIR}`, "podman", "image", "inspect", ref], { cwd: "/tmp", stdout: "ignore", stderr: "ignore" });
	return (await probe.exited) === 0;
};
if (!(await imagePresent(runtimeImage))) {
	for (let attempt = 1; attempt <= 4; attempt++) {
		try {
			await podmanAsService(["pull", runtimeImage]);
			break;
		} catch (error) {
			if (attempt === 4) throw error;
			await new Promise((resolve) => setTimeout(resolve, attempt * 2000));
		}
	}
}
// Post-install proof (local half): both pinned images resolve in the service
// user's store by digest. The running-service proof is the Linux acceptance.
for (const pinned of [gatewayImage, runtimeImage]) {
	await podmanAsService(["image", "inspect", pinned]);
}

// 2.48/4.2: the running supervisor must reach admitted snapshots through a
// REPRODUCIBLE service credential path, not a developer shell alias. The
// installer provisions a read-only service account (snapshotReadPolicy:
// GetObject/ListBucket on iweb-system/packages/* only), writes the mc alias
// into the service user's own mc config, and pins the alias + region in a
// unit drop-in so the systemd service uses exactly this identity.
const snapshotEndpoint = process.env.IWEB_SNAPSHOT_ENDPOINT ?? "http://127.0.0.1:9000";
const snapshotRegion = process.env.IWEB_SNAPSHOT_REGION ?? "us-east-1";
const adminAlias = process.env.IWEB_MC_ADMIN_ALIAS ?? "local";
const issuerParent = process.env.IWEB_SNAPSHOT_ISSUER_PARENT ?? "iweb-sandbox-issuer";
const supervisorAlias = "iweb-snapshot";
// the operator's admin alias must already see the system bucket (fail closed
// BEFORE any credential is issued)
await $`mc stat ${adminAlias}/iweb-system`;
const snapshotPolicyFile = join(tmpdir(), "iweb-policy-snapshot-read.json");
await Bun.write(snapshotPolicyFile, JSON.stringify(snapshotReadPolicy(), null, 2) + "\n");
const snapshotIssuance = JSON.parse((await $`mc admin user svcacct add --json --policy ${snapshotPolicyFile} ${adminAlias} ${issuerParent}`.text()));
rmSync(snapshotPolicyFile, { force: true });
if (snapshotIssuance.status !== "success" || typeof snapshotIssuance.accessKey !== "string" || typeof snapshotIssuance.secretKey !== "string") {
	throw new Error("supervisor snapshot credential issuance failed");
}
// the alias lives in the SERVICE USER's mc config (HOME-scoped), mode 0600
await $`install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /var/lib/iweb-sandbox/.mc`;
await Bun.write("/var/lib/iweb-sandbox/.mc/config.json", JSON.stringify({
	version: "10",
	aliases: {
		[supervisorAlias]: {
			url: snapshotEndpoint,
			accessKey: snapshotIssuance.accessKey,
			secretKey: snapshotIssuance.secretKey,
			api: "S3v4",
			path: "auto",
		},
	},
}, null, 2) + "\n");
await $`chown iweb-sandbox:iweb-sandbox /var/lib/iweb-sandbox/.mc/config.json`;
await $`chmod 0600 /var/lib/iweb-sandbox/.mc/config.json`;
// prove the SERVICE identity (not the operator shell) can read snapshots
// through the new alias before the service is restarted onto it. The service
// credential's ListBucket is prefix-conditioned to packages/, so the proof
// must operate INSIDE that scope — a bucket-root stat is denied by design.
await $`runuser -u iweb-sandbox -- env HOME=${serviceUserEnv.HOME} XDG_DATA_HOME=${serviceUserEnv.XDG_DATA_HOME} XDG_RUNTIME_DIR=${serviceUserEnv.XDG_RUNTIME_DIR} mc ls ${supervisorAlias}/iweb-system/packages/`;
await $`install -m 0644 ${join(projectRoot, "packaging/iweb-sandbox-supervisor.service")} ${unit}`;
await $`install -d -m 0755 ${dropInDirectory}`;
await Bun.write(join(dropInDirectory, "images.conf"), `[Service]
Environment=IWEB_SANDBOX_RUNTIME_IMAGE=${runtimeImage}
Environment=IWEB_SANDBOX_GATEWAY_IMAGE=${gatewayImage}
`);
await Bun.write(join(dropInDirectory, "snapshot.conf"), `[Service]
Environment=IWEB_SANDBOX_SYSTEM_ALIAS=${supervisorAlias}/iweb-system
Environment=IWEB_SANDBOX_REGION=${snapshotRegion}
`);
await $`systemctl daemon-reload`;
await $`systemctl enable iweb-sandbox-supervisor.service`;
// restart (not start): `start` is a no-op on a running unit, so a re-install
// that recompiled the binary would leave the old process serving forever.
await $`systemctl restart iweb-sandbox-supervisor.service`;
await $`systemctl --quiet is-active iweb-sandbox-supervisor.service`;
process.stdout.write("iweb sandbox supervisor installed and active (gateway image " + gatewayImage + ")\n");
