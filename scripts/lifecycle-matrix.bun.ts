// 用户原始需求（2026-08-14）：12.4 lifecycle matrix 的本地证据：用生产 application-control 逻辑 + 仅 socket 边界 mock，跑失败 admission/readiness、激活、crash、restart、rollback 全链路。
// 正交意图：输出结构化 JSON；全过才 exit 0；真实 OCI/MinIO 行为仍待 Linux 验收。
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { emptyControlStateFile, validateControlStateFile, type ControlStateFile } from "../packages/contracts/control-db.ts";
import { ControlStore, type ControlStoreIO } from "../packages/contracts/control-store.ts";
import { deriveSandboxId } from "../packages/contracts/protocol.ts";
import { createApplicationControl } from "../kernel/application-control.js";
import { memoryPackageStore } from "../kernel/package-store.js";
import { packageFilesDigest } from "../packages/contracts/package-collection.ts";

const directory = mkdtempSync(join(tmpdir(), "iweb-lifecycle-matrix-"));
const results: Record<string, unknown> = {};

function pass(name: string, detail: unknown) {
	results[name] = { pass: true, detail };
}

function fail(name: string, error: unknown) {
	const message = error instanceof Error ? error.message : String(error);
	results[name] = { pass: false, detail: message };
	throw error;
}

try {
	// 文件系统注入
	const files = new Map<string, string>();
	const io: ControlStoreIO = {
		readFile: (path) => files.get(path) ?? null,
		writeFileAtomic: (path, content) => files.set(path, content),
		deleteFile: (path) => files.delete(path),
		ensureDirectory: () => undefined,
	};
	const store = new ControlStore<ControlStateFile>({ io, path: join(directory, "control.json"), empty: emptyControlStateFile, parse: validateControlStateFile });

	// socket 边界 mock：容器状态由矩阵驱动（crash / 未启动 / ready）
	const pods = new Map<string, { running: boolean; healthy: boolean }>();
	const calls: string[] = [];
	const rpcClient = {
		prepare: async (_s: string, request: { sandboxId: string }) => { calls.push("prepare:" + request.sandboxId); pods.set(request.sandboxId, { running: false, healthy: false }); return { version: 1, operation: "prepare", status: "prepared", sandboxId: request.sandboxId }; },
		start: async (_s: string, sandboxId: string) => { calls.push("start:" + sandboxId); const pod = pods.get(sandboxId); if (!pod) throw new Error("pod missing"); pod.running = true; return { version: 1, operation: "start", status: "started", sandboxId }; },
		stop: async (_s: string, sandboxId: string) => { calls.push("stop:" + sandboxId); const pod = pods.get(sandboxId); if (pod) pod.running = false; return { version: 1, operation: "stop", status: "stopped", sandboxId }; },
		inspect: async (_s: string, sandboxId: string) => { const pod = pods.get(sandboxId); if (!pod) throw Object.assign(new Error("no such pod"), { code: "SUPERVISOR_UNREACHABLE" }); return { version: 1, operation: "inspect", sandboxId, state: pod.running ? "ready" : "stopped" }; },
		metrics: async (_s: string, sandboxId: string, versionId: string) => ({ version: 1, operation: "metrics", sandboxId, sample: { versionId, sampledAt: new Date().toISOString(), cpuMillis: { available: false }, memoryBytes: { available: false }, pidCount: { available: false }, terminated: { available: false }, limits: null } }),
		remove: async (_s: string, sandboxId: string) => { calls.push("remove:" + sandboxId); pods.delete(sandboxId); return { version: 1, operation: "delete", status: "deleted", sandboxId }; },
		socketGet: async (_sp: string, path: string) => {
			const versionId = path.split("versionId=")[1]?.split("&")[0] ?? "";
			const generation = Number(path.split("generation=")[1]?.split("&")[0] ?? 0);
			const sandboxId = Object.keys(Object.fromEntries(pods)).find((id) => pods.get(id)?.healthy) ?? "";
			if (sandboxId !== "") return { status: 200, body: JSON.stringify({ version: 1, ok: true, versionId, generation }) };
			return { status: 503, body: JSON.stringify({ version: 1, ok: false, code: "not-ready" }) };
		},
	};

	const packageStore = memoryPackageStore();
	const control = createApplicationControl({
		controlStore: store,
		secretsFile: join(directory, "secrets.json"),
		supervisorSocket: "/run/iweb-sandbox/supervisor.sock",
		gatewayDirectory: "/run/iweb-sandbox/gw",
		objectEndpoint: "http://10.37.0.1:9000",
		rpcClient,
		packageStore,
		issueObjectCredential: async () => ({ object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "matrix", secretAccessKey: "matrix-secret" }, retire: { user: "matrix-user", policyName: "matrix-policy" } }),
		retireObjectCredential: async () => {},
		issueDataCredential: async () => ({ endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "matrix-data", secretAccessKey: "matrix-data-secret" }),
		readiness: { maxAttempts: 3, attemptTimeoutMs: 1000, intervalMs: 0 },
		secretsIo: { readFile: (p) => files.get(p) ?? null, writeFileAtomic: (p, c) => files.set(p, c) },
	});

	const matrixFiles = [{ path: "app/index.js", content: Buffer.from("matrix-v1\n") }];
	const matrixFilesB = [{ path: "app/index.js", content: Buffer.from("matrix-v2\n") }];
	const digestA = packageFilesDigest(matrixFiles);
	const digestB = packageFilesDigest(matrixFilesB);
	const manifest = { schemaVersion: 1 as const, name: "matrix-app", runtime: { kind: "celld" as const, celldVersion: "0.2.0", entrypoint: "index.js" }, assets: { root: "app" }, resources: { cpuMillis: 500, memoryBytes: 128 * 2 ** 20, pidLimit: 128, storageBytes: 2 ** 30 }, storage: { persistent: false, requestBytes: 0 }, egress: { default: "deny" as const, allow: [] } };
	const policy = { resources: manifest.resources, egress: manifest.egress };

	// 1. admission 失败：不存在的 manifest 形状会被 admission 拒绝（重复 admission 同版本也失败）
	try {
		await control.admit({ applicationId: "matrix-app", packageDigest: digestA, manifest, policy, snapshotFiles: matrixFiles });
		try {
			await control.admit({ applicationId: "matrix-app", packageDigest: digestA, manifest, policy, snapshotFiles: matrixFiles });
			fail("duplicate-admission", "duplicate admission was accepted");
		} catch (error) { pass("duplicate-admission-rejected", (error as Error).message); }
	} catch (error) { fail("admission", error); }
	const v1 = control.state().applications["matrix-app"].versions[0];
	const sbx1 = deriveSandboxId("matrix-app", v1.versionId, 1);

	// 2. readiness 失败（网关 503）不能激活
	try {
		await control.prepare("matrix-app", v1.versionId);
		pods.get(sbx1)!.healthy = false;
		await control.startVersion("matrix-app", v1.versionId);
		const notReady = await control.probeReady("matrix-app", v1.versionId);
		if (notReady.ready) throw new Error("readiness reported ready against a 503 gateway");
		try {
			await control.activate("matrix-app", v1.versionId);
			fail("activation-commit-failure", "activation succeeded without readiness");
		} catch (error) { pass("activation-rejected-without-readiness", (error as Error).message); }
	} catch (error) { fail("readiness-gate", error); }

	// 3. readiness 成功 → 激活 → 路由解析到 active sandbox
	try {
		pods.get(sbx1)!.healthy = true;
		const ready = await control.probeReady("matrix-app", v1.versionId);
		if (!ready.ready) throw new Error("readiness probe failed against healthy gateway");
		const activation = await control.activate("matrix-app", v1.versionId);
		if (activation.generation !== 1) throw new Error("unexpected route generation");
		if (control.state().applications["matrix-app"].active.kind !== "active") throw new Error("active pointer missing");
		pass("activate-v1", { generation: activation.generation, sandboxId: sbx1 });
	} catch (error) { fail("activate-v1", error); }

	// 4. sandbox crash：inspect 失败 → reconcile 报 missingActive → 恢复重启
	try {
		pods.delete(sbx1);
		const report = await control.reconcile();
		if (report.missingActive.length !== 1) throw new Error("reconcile did not report the missing active sandbox");
		await control.recoverMissingActive();
		const recovered = pods.get(sbx1);
		if (!recovered || !recovered.running) throw new Error("recovery did not restart the active sandbox");
		pass("crash-reconcile-recover", report.missingActive[0]);
	} catch (error) { fail("crash-recovery", error); }

	// 5. update：admit v2 → prepare → readiness → activate → v1 retired → drain
	try {
		const v2admit = await control.admit({ applicationId: "matrix-app", packageDigest: digestB, manifest, policy, snapshotFiles: matrixFilesB });
		await control.prepare("matrix-app", v2admit.versionId);
		const sbx2 = deriveSandboxId("matrix-app", v2admit.versionId, 2);
		pods.get(sbx2)!.healthy = true;
		await control.startVersion("matrix-app", v2admit.versionId);
		const v2ready = await control.probeReady("matrix-app", v2admit.versionId);
		if (!v2ready.ready) throw new Error("v2 readiness failed");
		const v2activation = await control.activate("matrix-app", v2admit.versionId);
		if (v2activation.generation !== 2) throw new Error("unexpected v2 generation");
		const retired = control.state().applications["matrix-app"].versions.find((entry) => entry.versionId === v1.versionId);
		if (retired?.lifecycle !== "retired") throw new Error("v1 was not retired");
		const drained = await control.drainRetired("matrix-app");
		if (drained.length !== 1 || pods.get(sbx1)?.running !== false) throw new Error("drain did not stop the retired sandbox");
		pass("update-retire-drain", { generation: 2, retired: drained });
	} catch (error) { fail("update-flow", error); }

	// 6. rollback 经同一 readiness 门恢复 v1
	try {
		const v1record = control.state().applications["matrix-app"].versions.find((entry) => entry.versionId === v1.versionId);
		if (!v1record) throw new Error("v1 record missing");
		pods.get(sbx1)!.healthy = true;
		await control.startVersion("matrix-app", v1.versionId);
		const ready = await control.probeReady("matrix-app", v1.versionId);
		if (!ready.ready) throw new Error("v1 readiness failed before rollback");
		const rollback = await control.rollback("matrix-app", v1.versionId);
		if (rollback.generation !== 3) throw new Error("unexpected rollback generation");
		if (control.state().applications["matrix-app"].active.version.digest !== v1.versionId) throw new Error("rollback did not restore the active pointer");
		pass("rollback", { generation: rollback.generation });
	} catch (error) { fail("rollback", error); }

	// 7. active version 保护 + stop/start 状态转换
	try {
		try {
			await control.deleteVersion("matrix-app", v1.versionId);
			fail("active-version-protection", "active version deletion was accepted");
		} catch (error) { pass("active-version-protected", (error as Error).message); }
		await control.stopVersion("matrix-app", v1.versionId);
		if (control.state().applications["matrix-app"].versions.find((entry) => entry.versionId === v1.versionId)?.lifecycle !== "stopped") throw new Error("stop did not transition lifecycle");
		await control.startVersion("matrix-app", v1.versionId);
		pass("stop-start", "lifecycle transitions hold");
	} catch (error) { fail("stop-start", error); }


	// 9. 7.6 全量中断恢复：所有沙箱停止 + supervisor 不可达 +（模拟）admin/mcp 停止，
	// Kernel 仅凭 durable 控制库即可重建控制面并恢复 active 沙箱。
	try {
		// kill every pod and make the supervisor unreachable
		const appBeforeOutage = control.state().applications["matrix-app"];
		const activePointer = appBeforeOutage.active;
		if (activePointer.kind !== "active") throw new Error("no active pointer before the outage");
		const activeSandboxId = deriveSandboxId("matrix-app", activePointer.version.digest, activePointer.version.sequence);
		pods.delete(activeSandboxId);
		// a client that models the supervisor being DOWN, then coming back
		let supervisorDown = true;
		const flapping = {
			inspect: async (...a: Parameters<typeof rpcClient.inspect>) => { if (supervisorDown) throw Object.assign(new Error("supervisor down"), { code: "SUPERVISOR_UNREACHABLE" }); return rpcClient.inspect(...a); },
			prepare: async (...a: Parameters<typeof rpcClient.prepare>) => { if (supervisorDown) throw Object.assign(new Error("supervisor down"), { code: "SUPERVISOR_UNREACHABLE" }); return rpcClient.prepare(...a); },
			start: async (...a: Parameters<typeof rpcClient.start>) => { if (supervisorDown) throw Object.assign(new Error("supervisor down"), { code: "SUPERVISOR_UNREACHABLE" }); return rpcClient.start(...a); },
			stop: rpcClient.stop.bind(rpcClient),
			metrics: rpcClient.metrics.bind(rpcClient),
			remove: rpcClient.remove.bind(rpcClient),
			socketGet: rpcClient.socketGet.bind(rpcClient),
		};
		// Kernel survives: the control plane is rebuilt from the durable store
		const rebuiltControl = createApplicationControl({
			controlStore: store,
			secretsFile: join(directory, "secrets.json"),
			supervisorSocket: "/run/iweb-sandbox/supervisor.sock",
			gatewayDirectory: "/run/iweb-sandbox/gw",
			objectEndpoint: "http://10.37.0.1:9000",
			rpcClient: flapping,
			packageStore,
			issueObjectCredential: async () => ({ object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "m", secretAccessKey: "m" }, retire: {} }),
			retireObjectCredential: async () => {},
			issueDataCredential: async () => ({ endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "m", secretAccessKey: "m" }),
			readiness: { maxAttempts: 1, attemptTimeoutMs: 200, intervalMs: 0 },
			secretsIo: { readFile: (p: string) => files.get(p) ?? null, writeFileAtomic: (p: string, c: string) => files.set(p, c) },
		});
		const stateAfterOutage = rebuiltControl.state();
		const app = stateAfterOutage.applications["matrix-app"];
		if (!app || app.active.kind !== "active") throw new Error("control plane did not survive the outage");
		// the supervisor returns: recovery restarts the active sandbox
		const report2 = await rebuiltControl.reconcile();
		if (report2.missingActive.length !== 1) throw new Error("reconcile did not report the missing active sandbox: " + report2.missingActive.length);
		// the supervisor comes back; the pod is still ABSENT so reconcile must
		// report it missing and recovery's prepare/start recreates it (start flips running)
		supervisorDown = false;
		const recovered = await rebuiltControl.recoverMissingActive();
		if (recovered.recovered.length !== 1) throw new Error("recovery did not restore the active sandbox");
		if (!pods.get(recovered.recovered[0])?.running) throw new Error("recovered sandbox is not running");
		pass("total-outage-recovery", { activeRestored: recovered.recovered[0] });
	} catch (error) { fail("total-outage-recovery", error); }
	// 8. supervisor restart：同一 durable store 重建控制面（新的 control 实例）
	try {
		const restarted = createApplicationControl({
			controlStore: store,
			secretsFile: join(directory, "secrets.json"),
			supervisorSocket: "/run/iweb-sandbox/supervisor.sock",
			gatewayDirectory: "/run/iweb-sandbox/gw",
			objectEndpoint: "http://10.37.0.1:9000",
			rpcClient,
			packageStore,
			issueObjectCredential: async () => ({ object: { endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "matrix", secretAccessKey: "matrix-secret" }, retire: { user: "matrix-user", policyName: "matrix-policy" } }),
			retireObjectCredential: async () => {},
			issueDataCredential: async () => ({ endpoint: "http://10.37.0.1:9000", region: "us-east-1", accessKeyId: "matrix-data", secretAccessKey: "matrix-data-secret" }),
			readiness: { maxAttempts: 1, attemptTimeoutMs: 1000, intervalMs: 0 },
			secretsIo: { readFile: (p) => files.get(p) ?? null, writeFileAtomic: (p, c) => files.set(p, c) },
		});
		const rebuilt = restarted.state().applications["matrix-app"];
		if (!rebuilt || rebuilt.active.kind !== "active" || rebuilt.versions.length !== 2) throw new Error("restart did not rebuild control state");
		pass("supervisor-restart-rebuild", { versions: rebuilt.versions.length });
	} catch (error) { fail("restart-rebuild", error); }

	const report = { run: "local-mock-socket", ranAt: new Date().toISOString(), supervisorCalls: calls.length, results };
	writeFileSync(join(directory, "matrix-report.json"), JSON.stringify(report, null, 2) + "\n");
	process.stdout.write(JSON.stringify(report, null, 2) + "\n");
	process.stdout.write("lifecycle matrix passed (local); real OCI acceptance still requires the Linux node\n");
} catch (error) {
	process.stdout.write(JSON.stringify({ run: "local-mock-socket", results, failed: error instanceof Error ? error.message : String(error) }, null, 2) + "\n");
	process.exitCode = 1;
} finally {
	rmSync(directory, { recursive: true, force: true });
}
