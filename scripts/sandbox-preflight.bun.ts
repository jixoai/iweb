// 用户原始需求（2026-08-13）：安装应用沙箱前自动证明宿主具备强制隔离前提。
// 正交意图：解析安装目录；运行 preflight；提供机器可读结果；失败时阻止继续安装。
import { runSandboxPreflight } from "../supervisor/preflight.ts";

function requiredPath(value: string | undefined, name: string): string {
	const normalized = value?.trim();
	if (!normalized?.startsWith("/")) throw new Error(`${name} must be an absolute path`);
	return normalized;
}

const stateDirectory = requiredPath(process.env.IWEB_SANDBOX_STATE_DIR ?? process.argv[2] ?? "/var/lib/iweb-sandbox", "sandbox state directory");
const runtimeDirectory = requiredPath(process.env.IWEB_SANDBOX_RUNTIME_DIR ?? process.argv[3] ?? `/run/user/${process.geteuid?.() ?? -1}/iweb-sandbox`, "sandbox runtime directory");
const report = await runSandboxPreflight({ stateDirectory, runtimeDirectory });

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.ready) process.exitCode = 1;
