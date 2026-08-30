/**
 * 入口脚本世代回收的行为测试（Codex R5 终审缺口：无 dash/BusyBox 负向 fixture）。
 *
 * macOS 无 /proc，无法直接运行生产回收路径；本测试从 scripts/iweb-entrypoint.sh
 * 提取真实函数源码，在 POSIX shell（优先 dash，回退 /bin/sh）中覆盖 kill、
 * pid_matches_generation、rm_sandbox_sockets、sleep 后执行，验证：
 *  1. pid:ticks 冒号二元组不被空白分词破坏（R5 P1 回归守卫——starttime 永不被当 pid 发信号）；
 *  2. TERM 全灭 → 成功清 socket、绝不升级 KILL；
 *  3. TERM 顽固者 → 仅对仍匹配同 pid+starttime 者补 KILL 后成功；
 *  4. 永久幸存者 → 返回 1、拒绝清 socket、stderr 点名幸存者；
 *  5. pid 复用（同 pid 不同 starttime）→ 不再发信号、不计为幸存者（绝不误杀复用者）；
 *  6. 捕获后、TERM 前即已复用 → TERM 阶段同样过栅栏，零信号（Codex R6 P1）；
 *  7. 残缺 token（空 ticks/非数字）→ 枚举产物直接拒绝回收，fail-closed（Codex R6 P1）。
 */
import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ENTRYPOINT = join(import.meta.dir, "..", "scripts", "iweb-entrypoint.sh");
const SH_BIN = execFileSync("sh", ["-c", "command -v dash || command -v sh"], { encoding: "utf8" }).trim();

function extractFunction(source: string, name: string): string {
	const start = source.indexOf(`${name}() {`);
	if (start < 0) throw new Error(`entrypoint function not found: ${name}`);
	const end = source.indexOf("\n}\n", start);
	if (end < 0) throw new Error(`entrypoint function has no terminator: ${name}`);
	return source.slice(start, end + 3);
}

const entrypointSource = readFileSync(ENTRYPOINT, "utf8");
const reclaimFunctions = [
	"proc_start_ticks",
	"sandbox_generation_pids",
	"pid_matches_generation",
	"rm_sandbox_sockets",
	"reclaim_sandbox_generation",
]
	.map((name) => extractFunction(entrypointSource, name))
	.join("\n");

interface Scenario {
	/** 初始存活注册表：每行一个 pid:ticks。 */
	alive: string;
	/** 忽略 TERM 的顽固 pid 列表。 */
	stubborn?: string[];
	/** 连 KILL 都无视的 pid 列表（模拟 D 状态进程）。 */
	unkillable?: string[];
	/** 收到 TERM 后改换 starttime 的 pid（模拟 pid 复用）。 */
	reusedAfterTerm?: string;
	/** 覆盖世代枚举输出（模拟捕获时点与执行时点的身份错位；如 "404:111" 或残缺 "404:"）。 */
	captured?: string;
}

interface ReclaimResult {
	/** reclaim 的返回码；shell 中途崩溃（set -u 中止）时为 null。 */
	code: number | null;
	stderr: string;
	/** 每项形如 "-TERM:101" / "-KILL:202"。 */
	signals: string[];
	socketRemovals: number;
}

function runScenario(scenario: Scenario): ReclaimResult {
	const dir = mkdtempSync(join(tmpdir(), "iweb-reclaim-"));
	try {
		const registry = join(dir, "alive");
		const stubbornList = join(dir, "stubborn");
		const unkillableList = join(dir, "unkillable");
		const killLog = join(dir, "signals");
		const errFile = join(dir, "stderr");
		const sockCounter = join(dir, "sock-removals");
		const rcFile = join(dir, "rc");
		writeFileSync(registry, `${scenario.alive}\n`);
		writeFileSync(stubbornList, `${(scenario.stubborn ?? []).join("\n")}\n`);
		writeFileSync(unkillableList, `${(scenario.unkillable ?? []).join("\n")}\n`);
		writeFileSync(killLog, "");
		writeFileSync(sockCounter, "0");

		// 驱动脚本在严格模式（set -u）下先加载真实函数，再安装覆盖层：
		// kill 记录信号并按剧情模拟死亡；世代枚举/匹配走注册表而非 /proc。
		// shellcheck disable=SC2016 -- $ 展开属于被测 shell，不是本 TS 文件
		const driver = [
			"set -u",
			reclaimFunctions,
			"kill() {",
			'  sig="$1"; pid="$2"',
			'  echo "${sig}:${pid}" >> "$KILLLOG"',
			'  if [ "${sig}" = "-KILL" ]; then',
			'    if grep -qx "$pid" "$UNKILLABLE" 2>/dev/null; then return 0; fi',
			'    grep -v "^${pid}:" "$REGISTRY" > "$REGISTRY.t" 2>/dev/null || true; mv "$REGISTRY.t" "$REGISTRY"',
			"    return 0",
			"  fi",
			'  if ! grep -qx "$pid" "$STUBBORN" 2>/dev/null; then',
			'    grep -v "^${pid}:" "$REGISTRY" > "$REGISTRY.t" 2>/dev/null || true; mv "$REGISTRY.t" "$REGISTRY"',
			"  fi",
			'  if [ -n "$REUSED_AFTER_TERM" ] && [ "$pid" = "$REUSED_AFTER_TERM" ]; then',
			'    grep -v "^${pid}:" "$REGISTRY" > "$REGISTRY.t" 2>/dev/null || true',
			'    echo "${pid}:99999" >> "$REGISTRY.t"; mv "$REGISTRY.t" "$REGISTRY"',
			"  fi",
			"  return 0",
			"}",
			'sandbox_generation_pids() {' +
				(scenario.captured === undefined
					? ' cat "$REGISTRY"; }'
					: ` printf '%s\\n' '${scenario.captured}'; }`),
			'pid_matches_generation() { grep -qx "$1:$2" "$REGISTRY" 2>/dev/null; }',
			'rm_sandbox_sockets() { n=$(($(cat "$SOCK") + 1)); echo "$n" > "$SOCK"; }',
			"sleep() { :; }",
			`REGISTRY='${registry}'`,
			`STUBBORN='${stubbornList}'`,
			`UNKILLABLE='${unkillableList}'`,
			`KILLLOG='${killLog}'`,
			`SOCK='${sockCounter}'`,
			`REUSED_AFTER_TERM='${scenario.reusedAfterTerm ?? ""}'`,
			"reclaim_sandbox_generation 2>'" + errFile + "'",
			"rc=$?",
			`echo "$rc" > '${rcFile}'`,
			"exit 0",
		].join("\n");
		const script = join(dir, "driver.sh");
		writeFileSync(script, driver);

		try {
			execFileSync(SH_BIN, ["-u", script], { encoding: "utf8" });
		} catch {
			// 驱动恒以 exit 0 收尾；抛错只可能来自 shell 中途崩溃（set -u 中止），
			// 此时 rcFile 缺失 → code=null，由调用方断言。
		}
		return {
			code: existsSync(rcFile) ? Number(readFileSync(rcFile, "utf8").trim()) : null,
			stderr: existsSync(errFile) ? readFileSync(errFile, "utf8") : "",
			signals: readFileSync(killLog, "utf8").split("\n").filter(Boolean),
			socketRemovals: Number(readFileSync(sockCounter, "utf8").trim()),
		};
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

function signalTargets(signals: string[], signal: "-TERM" | "-KILL"): string[] {
	return signals.filter((entry) => entry.startsWith(`${signal}:`)).map((entry) => entry.slice(signal.length + 1));
}

describe("entrypoint sandbox generation reclaim", () => {
	test("pid:ticks tuples survive word splitting under set -u (R5 P1 regression guard)", () => {
		const result = runScenario({ alive: "101:555\n202:777" });
		// set -u 下未发生 unbound 中止；starttime 值（555/777）绝不出现在任何信号目标里。
		expect(result.code).not.toBeNull();
		const everyTarget = result.signals.map((entry) => entry.split(":")[1]);
		expect(everyTarget).not.toContain("555");
		expect(everyTarget).not.toContain("777");
		expect(new Set(everyTarget)).toEqual(new Set(["101", "202"]));
	});

	test("TERM-fatal generation reclaims cleanly and removes sockets exactly once", () => {
		const result = runScenario({ alive: "101:555\n202:777" });
		expect(result.code).toBe(0);
		expect(signalTargets(result.signals, "-TERM").sort()).toEqual(["101", "202"]);
		expect(signalTargets(result.signals, "-KILL")).toEqual([]);
		expect(result.socketRemovals).toBe(1);
	});

	test("TERM-ignoring survivor is escalated to KILL and reclaim still succeeds", () => {
		const result = runScenario({ alive: "101:555\n202:777", stubborn: ["202"] });
		expect(result.code).toBe(0);
		expect(signalTargets(result.signals, "-TERM").sort()).toEqual(["101", "202"]);
		expect(signalTargets(result.signals, "-KILL")).toEqual(["202"]);
		expect(result.socketRemovals).toBe(1);
	});

	test("eternal survivor fails closed: rc=1, sockets kept, survivor named on stderr", () => {
		const result = runScenario({ alive: "303:888", stubborn: ["303"], unkillable: ["303"] });
		expect(result.code).toBe(1);
		expect(result.socketRemovals).toBe(0);
		expect(result.stderr).toContain("303");
		expect(result.stderr).toContain("refusing to start the next generation");
	});

	test("pid reuse after TERM is never re-signaled and never blocks reclaim", () => {
		const result = runScenario({ alive: "404:111", reusedAfterTerm: "404" });
		// 404 在 TERM 后被新进程复用（starttime 变为 99999）：回收不得对其补 KILL，
		// 也不得把复用者计为幸存者——直接成功清 socket。
		expect(result.code).toBe(0);
		expect(signalTargets(result.signals, "-TERM")).toEqual(["404"]);
		expect(signalTargets(result.signals, "-KILL")).toEqual([]);
		expect(result.socketRemovals).toBe(1);
	});

	test("empty generation removes sockets immediately without signals", () => {
		const result = runScenario({ alive: "" });
		expect(result.code).toBe(0);
		expect(result.signals).toEqual([]);
		expect(result.socketRemovals).toBe(1);
	});

	test("pid reused between capture and TERM is never signaled (Codex R6 P1)", () => {
		// 捕获时点 token 为 404:111，TERM 时点注册表已是复用者 404:99999：
		// TERM 阶段必须与 KILL 同栅栏——零信号、复用者不算幸存者、直接成功清 socket。
		const result = runScenario({ alive: "404:99999", captured: "404:111" });
		expect(result.code).toBe(0);
		expect(result.signals).toEqual([]);
		expect(result.socketRemovals).toBe(1);
	});

	test("a malformed generation token refuses reclaim fail-closed", () => {
		// 空 ticks（"404:"）身份不可证明：枚举产物被拒收——不发信号、不清 socket。
		const result = runScenario({ alive: "404:111", captured: "404:" });
		expect(result.code).toBe(1);
		expect(result.signals).toEqual([]);
		expect(result.socketRemovals).toBe(0);
		expect(result.stderr).toContain("malformed generation token");
	});

	test("a non-numeric token component refuses reclaim fail-closed", () => {
		const result = runScenario({ alive: "404:111", captured: "40x:111" });
		expect(result.code).toBe(1);
		expect(result.signals).toEqual([]);
		expect(result.socketRemovals).toBe(0);
	});
});
