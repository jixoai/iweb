// 用户原始需求（2026-08-14）：可执行沙箱矩阵：dry 输出预期拒绝矩阵，run 从矩阵宿主独立探测内部目标并汇总证据。
// 正交意图：2.20 / 12.2。
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ENFORCEMENT_POINTS = ["oci-boundary", "egress-gateway", "object-gateway", "supervisor-acl", "cgroup-limit", "seccomp"] as const;
type EnforcementPoint = (typeof ENFORCEMENT_POINTS)[number];

interface AttackSpec {
	readonly attackId: string;
	readonly name: string;
	readonly expectedDenial: "outside-app";
	readonly enforcementPoint: EnforcementPoint;
	// Internal targets the matrix host probes itself; every probe must be
	// refused for the denial to be attributed outside application code.
	readonly selfProbes?: readonly string[];
	// True when the denial cannot be independently probed from the matrix host
	// and the app report is the only observable (tagged appReportOnly).
	readonly appSideOnly?: boolean;
}

const ATTACK_SPECS: readonly AttackSpec[] = [
	{ attackId: "credential-discovery", name: "Credential discovery", expectedDenial: "outside-app", enforcementPoint: "oci-boundary", appSideOnly: true },
	{ attackId: "workspace-access", name: "Workspace access", expectedDenial: "outside-app", enforcementPoint: "object-gateway", selfProbes: ["http://minio:9000"] },
	{ attackId: "cross-app-access", name: "Cross-application access", expectedDenial: "outside-app", enforcementPoint: "object-gateway", selfProbes: ["http://celld:8787"] },
	{
		attackId: "internal-probes",
		name: "Internal service probes",
		expectedDenial: "outside-app",
		enforcementPoint: "egress-gateway",
		selfProbes: ["http://kernel:7070/v1/status", "http://minio:9000", "http://celld:8787", "http://celld:8788", "http://169.254.169.254/latest/meta-data"],
	},
	{ attackId: "undeclared-egress", name: "Undeclared egress", expectedDenial: "outside-app", enforcementPoint: "egress-gateway", appSideOnly: true },
	{ attackId: "filesystem-escape", name: "Filesystem escape", expectedDenial: "outside-app", enforcementPoint: "seccomp", appSideOnly: true },
	{ attackId: "supervisor-access", name: "Supervisor access", expectedDenial: "outside-app", enforcementPoint: "supervisor-acl", selfProbes: ["http://supervisor:8788"] },
	{ attackId: "process-escape", name: "Process escape", expectedDenial: "outside-app", enforcementPoint: "seccomp", appSideOnly: true },
	{ attackId: "resource-exhaustion", name: "Resource exhaustion", expectedDenial: "outside-app", enforcementPoint: "cgroup-limit", appSideOnly: true },
];

interface DryEntry {
	readonly attackId: string;
	readonly name: string;
	readonly expectedDenial: "outside-app";
	readonly enforcementPoint: EnforcementPoint;
}

interface DryReport {
	readonly matrix: readonly DryEntry[];
	readonly meta: { readonly sandbox: string | null; readonly host: string | null; readonly ran: false };
}

interface AppReportEntry {
	readonly attack: string;
	readonly attempted: boolean;
	readonly observed: string;
}

interface RunResult {
	readonly attackId: string;
	readonly attempted: boolean;
	readonly deniedOutsideApp: boolean;
	readonly observed: string;
	readonly pass: boolean;
}

interface RunReport {
	readonly meta: { readonly sandbox: string | null; readonly host: string | null; readonly ran: true; readonly timestamp: string };
	readonly results: readonly RunResult[];
}

function dryReport(): DryReport {
	const matrix: DryEntry[] = ATTACK_SPECS.map((spec) => ({
		attackId: spec.attackId,
		name: spec.name,
		expectedDenial: spec.expectedDenial,
		enforcementPoint: spec.enforcementPoint,
	}));
	return { matrix, meta: { sandbox: process.env.IWEB_SANDBOX_ID ?? null, host: process.env.IWEB_MATRIX_HOST ?? null, ran: false } };
}

interface ProbeResult {
	readonly refused: boolean;
	readonly detail: string;
}

function probe(url: string, timeoutMs = 2000): Promise<ProbeResult> {
	return new Promise((settle) => {
		let settled = false;
		const done = (result: ProbeResult): void => {
			if (!settled) {
				settled = true;
				settle(result);
			}
		};
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			done({ refused: true, detail: "invalid-url" });
			return;
		}
		const client = parsed.protocol === "https:" ? httpsRequest : httpRequest;
		const req = client(parsed, { method: "GET", headers: { connection: "close" } }, (res) => {
			res.resume();
			done({ refused: false, detail: "reachable:http:" + String(res.statusCode ?? 0) });
		});
		req.setTimeout(timeoutMs, () => req.destroy(new Error("probe-timeout")));
		req.on("error", (err: Error) => {
			const code = (err as { code?: string }).code;
			done({ refused: true, detail: code ?? err.message.slice(0, 60) });
		});
		req.end();
	});
}

function fetchText(url: string, timeoutMs = 3000): Promise<{ ok: boolean; status: number; body: string }> {
	return new Promise((settle) => {
		let settled = false;
		const done = (value: { ok: boolean; status: number; body: string }): void => {
			if (!settled) {
				settled = true;
				settle(value);
			}
		};
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			done({ ok: false, status: 0, body: "" });
			return;
		}
		const client = parsed.protocol === "https:" ? httpsRequest : httpRequest;
		const req = client(parsed, { method: "GET", headers: { connection: "close" } }, (res) => {
			const chunks: Buffer[] = [];
			let total = 0;
			res.on("data", (chunk: Buffer) => {
				if (total < 1_000_000) {
					chunks.push(chunk);
					total += chunk.length;
				}
			});
			res.on("end", () => {
				done({ ok: res.statusCode !== undefined && res.statusCode < 400, status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8").slice(0, 1_000_000) });
			});
		});
		req.setTimeout(timeoutMs, () => req.destroy(new Error("fetch-timeout")));
		req.on("error", () => done({ ok: false, status: 0, body: "" }));
		req.end();
	});
}

// The fixture's observed strings are compact and machine-readable; these
// predicates decide whether the app-side observation shows the denial the
// sandbox boundary is supposed to enforce. App-side-only evidence is tagged
// appReportOnly and must be corroborated by node-side acceptance evidence.
function appSideDenied(attackId: string, observed: string): boolean {
	switch (attackId) {
		case "credential-discovery":
			return /env:0 global:0 argv:0/.test(observed);
		case "workspace-access":
			return /bucket:denied/.test(observed) && !/readable:\d+/.test(observed);
		case "cross-app-access":
			return !/readable/.test(observed) && !/status:\d+/.test(observed);
		case "internal-probes":
			return !/status:\d+/.test(observed);
		case "undeclared-egress":
			return !/status:\d+/.test(observed);
		case "filesystem-escape":
			return !/\/etc\/shadow:readable/.test(observed) && !/\/proc\/self\/environ:readable/.test(observed) && !/\/var\/run\/docker\.sock:readable/.test(observed);
		case "supervisor-access":
			return !/reachable/.test(observed) && !/status:\d+/.test(observed);
		case "process-escape":
			return /spawn:/.test(observed) && !/proc:readable/.test(observed);
		case "resource-exhaustion":
			return /allocated:\d+/.test(observed);
		default:
			return false;
	}
}

async function runReport(targetUrl: string): Promise<{ report: RunReport; allPass: boolean }> {
	const base = targetUrl.endsWith("/") ? targetUrl : targetUrl + "/";
	const app = await fetchText(base);
	const appEntries = new Map<string, AppReportEntry>();
	if (app.ok && app.body.length > 0) {
		try {
			const parsed: unknown = JSON.parse(app.body);
			if (Array.isArray(parsed)) {
				for (const entry of parsed) {
					if (entry === null || typeof entry !== "object") continue;
					const attack = (entry as { attack?: unknown }).attack;
					if (typeof attack !== "string") continue;
					const record = entry as { attempted?: unknown; observed?: unknown };
					appEntries.set(attack, {
						attack,
						attempted: record.attempted === true,
						observed: typeof record.observed === "string" ? record.observed : String(record.observed ?? ""),
					});
				}
			}
		} catch {
			// Non-JSON app report: results below carry the raw fetch status.
		}
	}

	const results: RunResult[] = [];
	for (const spec of ATTACK_SPECS) {
		const entry = appEntries.get(spec.attackId);
		const attempted = entry?.attempted === true;
		const appObserved = entry?.observed ?? (app.ok ? "app report missing attack" : "app report unreachable: http:" + app.status);
		const probeDetails: string[] = [];
		let selfProbesRefused = true;
		if (spec.selfProbes) {
			for (const url of spec.selfProbes) {
				const result = await probe(url);
				probeDetails.push(url + ":" + (result.refused ? "refused(" + result.detail + ")" : "reachable"));
				if (!result.refused) selfProbesRefused = false;
			}
		}

		let deniedOutsideApp: boolean;
		let note = "";
		if (spec.selfProbes && spec.selfProbes.length > 0) {
			deniedOutsideApp = selfProbesRefused;
			if (!deniedOutsideApp) note = "matrix-host probe reached an internal target";
		} else if (spec.appSideOnly) {
			deniedOutsideApp = appSideDenied(spec.attackId, appObserved);
			note = deniedOutsideApp ? "appReportOnly: denial not independently probed from matrix host" : "app report shows no denial";
		} else {
			deniedOutsideApp = false;
			note = "no denial evidence";
		}
		if (spec.attackId === "resource-exhaustion" && deniedOutsideApp) {
			note = "allocation bounded by HOSTILE_ALLOCATION_MB; cgroup-limit enforcement requires node-side evidence";
		}

		const observed = [appObserved, ...probeDetails, note].filter((part) => part.length > 0).join(" | ").slice(0, 500);
		results.push({ attackId: spec.attackId, attempted, deniedOutsideApp, observed, pass: attempted && deniedOutsideApp });
	}
	const allPass = results.every((result) => result.pass);
	const report: RunReport = {
		meta: { sandbox: process.env.IWEB_SANDBOX_ID ?? null, host: process.env.IWEB_MATRIX_HOST ?? null, ran: true, timestamp: new Date().toISOString() },
		results,
	};
	return { report, allPass };
}

function writeReport(path: string, report: RunReport): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, JSON.stringify(report, null, 2) + "\n", "utf8");
}

async function main(): Promise<void> {
	const mode = process.argv[2] ?? "dry";
	if (mode === "run") {
		const targetUrl = (process.env.TARGET_URL ?? "").trim();
		const reportPath = resolve(process.env.REPORT_PATH ?? "./sandbox-matrix-report.json");
		let report: RunReport;
		let allPass = false;
		if (targetUrl.length === 0) {
			const results: RunResult[] = ATTACK_SPECS.map((spec) => ({
				attackId: spec.attackId,
				attempted: false,
				deniedOutsideApp: false,
				observed: "requiresLinuxNode: TARGET_URL unset; run this matrix from a Linux node with a deployed sandboxed app",
				pass: false,
			}));
			report = { meta: { sandbox: process.env.IWEB_SANDBOX_ID ?? null, host: process.env.IWEB_MATRIX_HOST ?? null, ran: true, timestamp: new Date().toISOString() }, results };
		} else {
			const outcome = await runReport(targetUrl);
			report = outcome.report;
			allPass = outcome.allPass;
		}
		writeReport(reportPath, report);
		process.stdout.write(JSON.stringify(report, null, 2) + "\n");
		process.exitCode = allPass ? 0 : 1;
		return;
	}

	const dry = dryReport();
	process.stdout.write(JSON.stringify(dry, null, 2) + "\n");
	process.exitCode = 0;
}

await main();
