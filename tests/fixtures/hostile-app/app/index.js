// 用户原始需求（2026-08-14）：hostile fixture 尝试 12.1 全部攻击（凭据发现、工作区/跨应用访问、内部探测、未声明 egress、文件系统逃逸、supervisor 访问、进程逃逸、资源耗尽）；全部必须被沙箱边界拒绝。
// 正交意图：2.20 / 12.1 / 12.2。
export const ATTACKS = [
	{ id: "credential-discovery", name: "Credential discovery", description: "Probe environment, globals, and argv for owner or infrastructure credential keys" },
	{ id: "workspace-access", name: "Workspace access", description: "Read workspace files outside the app root and reach the object store" },
	{ id: "cross-app-access", name: "Cross-application access", description: "Read another application's files or ingress" },
	{ id: "internal-probes", name: "Internal service probes", description: "Probe kernel, minio, celld, loopback, and cloud metadata listeners" },
	{ id: "undeclared-egress", name: "Undeclared egress", description: "Open outbound connections to destinations absent from the manifest allow list" },
	{ id: "filesystem-escape", name: "Filesystem escape", description: "Read host paths outside the sandbox root: /etc, /proc, /run/iweb*" },
	{ id: "supervisor-access", name: "Supervisor access", description: "Reach the sandbox supervisor control surface" },
	{ id: "process-escape", name: "Process escape", description: "Spawn or inspect processes outside the sandbox boundary" },
	{ id: "resource-exhaustion", name: "Resource exhaustion", description: "Allocate memory up to a bounded, configurable cap" },
];

const ATTACK_TIMEOUT_MS = 1500;
const OBSERVED_MAX_LENGTH = 240;

const ATTACK_RUNNERS = {
	"credential-discovery": async () => {
		const env = globalThis.process?.env ?? {};
		const envHits = Object.keys(env).filter((key) => /TOKEN|SECRET|PASSWORD|MINIO|IWEB|KEY/i.test(key));
		const globalHits = Object.keys(globalThis).filter((key) => /TOKEN|SECRET|PASSWORD|KEY/.test(key));
		const argvHits = (globalThis.process?.argv ?? []).filter((arg) => /TOKEN|SECRET|PASSWORD/.test(arg));
		return `env:${envHits.length} global:${globalHits.length} argv:${argvHits.length}`;
	},

	"workspace-access": async () => {
		const fs = await loadFs();
		const reads = [];
		if (fs === null) {
			reads.push("no-filesystem");
		} else {
			for (const path of ["../index.html", "../../index.html", "../../workspace/index.html"]) {
				try {
					const data = fs.readFileSync(path, "utf8");
					reads.push(`${path}:readable:${data.length}`);
				} catch (error) {
					reads.push(`${path}:${shortError(error)}`);
				}
			}
		}
		const bucket = await probe("http://minio:9000/iweb-workspace/?list-type=2");
		return `fs:[${reads.join(" ")}] bucket:${bucket}`;
	},

	"cross-app-access": async () => {
		const fs = await loadFs();
		const reads = [];
		if (fs === null) {
			reads.push("no-filesystem");
		} else {
			for (const path of ["../notes/iweb.json", "../mcp/iweb.json", "../notes/app/index.js"]) {
				try {
					fs.readFileSync(path, "utf8");
					reads.push(`${path}:readable`);
				} catch (error) {
					reads.push(`${path}:${shortError(error)}`);
				}
			}
		}
		const otherApp = await probe("http://notes:8787/");
		return `fs:[${reads.join(" ")}] other-app:${otherApp}`;
	},

	"internal-probes": async () => {
		const targets = [
			"http://kernel:7070/v1/status",
			"http://minio:9000",
			"http://celld:8787",
			"http://celld:8788",
			"http://169.254.169.254/latest/meta-data",
			"http://127.0.0.1:7070/v1/status",
		];
		const results = await Promise.all(targets.map(async (target) => `${target}:${await probe(target)}`));
		return results.join(" ");
	},

	"undeclared-egress": async () => {
		const targets = ["https://example.com/", "https://1.1.1.1/", "https://api.example.com/v1/status"];
		const results = await Promise.all(targets.map(async (target) => `${target}:${await probe(target)}`));
		return results.join(" ");
	},

	"filesystem-escape": async () => {
		const fs = await loadFs();
		if (fs === null) return "no-filesystem";
		const targets = [
			"/etc/passwd",
			"/etc/shadow",
			"/proc/self/environ",
			"/proc/1/cmdline",
			"/run/iweb",
			"/run/iweb-supervisor.sock",
			"/run/iweb/supervisor.sock",
			"/var/run/docker.sock",
		];
		const results = [];
		for (const path of targets) {
			try {
				const data = fs.readFileSync(path);
				results.push(`${path}:readable:${data.length}`);
			} catch (error) {
				results.push(`${path}:${shortError(error)}`);
			}
		}
		return results.join(" ");
	},

	"supervisor-access": async () => {
		const fs = await loadFs();
		const socketResults = [];
		if (fs === null) {
			socketResults.push("no-filesystem");
		} else {
			for (const path of ["/run/iweb-supervisor.sock", "/run/iweb/supervisor.sock", "/var/run/iweb-supervisor.sock"]) {
				try {
					fs.accessSync(path);
					socketResults.push(`${path}:reachable`);
				} catch (error) {
					socketResults.push(`${path}:${shortError(error)}`);
				}
			}
		}
		const listenerResults = await Promise.all(["http://celld:8788/", "http://supervisor:8788/"].map(async (target) => `${target}:${await probe(target)}`));
		return `socket:[${socketResults.join(" ")}] ${listenerResults.join(" ")}`;
	},

	"process-escape": async () => {
		const spawnResults = [];
		let childProcess = null;
		try {
			childProcess = await import("node:child_process");
		} catch {
			childProcess = null;
		}
		if (childProcess === null) {
			spawnResults.push("spawn:denied");
		} else {
			try {
				const result = childProcess.spawnSync("/bin/sh", ["-c", "id"]);
				spawnResults.push(`spawn:${result.status === null ? "signaled" : "ok"}`);
			} catch (error) {
				spawnResults.push(`spawn:${shortError(error)}`);
			}
		}
		const fs = await loadFs();
		if (fs === null) {
			spawnResults.push("proc:denied");
		} else {
			try {
				const data = fs.readFileSync("/proc/1/cmdline");
				spawnResults.push(`proc:readable:${data.length}`);
			} catch (error) {
				spawnResults.push(`proc:${shortError(error)}`);
			}
		}
		return spawnResults.join(" ");
	},

	"resource-exhaustion": async () => {
		const raw = Number(globalThis.process?.env?.HOSTILE_ALLOCATION_MB ?? 256);
		const mb = Number.isFinite(raw) && raw > 0 ? Math.min(Math.floor(raw), 4096) : 256;
		const bytes = mb * 1024 * 1024;
		try {
			const buffer = new Float64Array(Math.floor(bytes / 8));
			buffer.fill(1);
			const length = buffer.length;
			void length;
			return `allocated:${bytes}`;
		} catch (error) {
			return `failed:${shortError(error)}`;
		}
	},
};

async function loadFs() {
	try {
		return await import("node:fs");
	} catch {
		return null;
	}
}

// Probe with a bounded timeout; never follows redirects and never carries a
// payload. A refused/errored target reports "denied", a reachable one reports
// its status. No data is ever transmitted beyond the connection attempt itself.
async function probe(url, timeoutMs = 1200) {
	try {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const response = await fetch(url, { signal: controller.signal, redirect: "manual" });
			return `status:${response.status}`;
		} finally {
			clearTimeout(timer);
		}
	} catch {
		return "denied";
	}
}

async function withTimeout(promise, ms) {
	let timer;
	const timeout = new Promise((_, reject) => {
		timer = setTimeout(() => reject(new Error("attack timed out")), ms);
	});
	try {
		return await Promise.race([promise, timeout]);
	} finally {
		clearTimeout(timer);
	}
}

function shortError(error) {
	const code = error?.code;
	if (code === "EACCES" || code === "EPERM") return "denied";
	return code ?? (error?.name ?? "error");
}

function bound(value) {
	return String(value).replace(/[\u0000-\u001f]/g, " ").trim().slice(0, OBSERVED_MAX_LENGTH);
}

export default {
	async fetch() {
		const report = [];
		for (const attack of ATTACKS) {
			const runner = ATTACK_RUNNERS[attack.id];
			let observed = "no-runner";
			if (runner) {
				try {
					observed = await withTimeout(runner(), ATTACK_TIMEOUT_MS);
				} catch (error) {
					observed = error?.message ?? String(error ?? "error");
				}
			}
			report.push({ attack: attack.id, attempted: true, observed: bound(observed) });
		}
		return new Response(JSON.stringify(report), { headers: { "content-type": "application/json" } });
	},
};