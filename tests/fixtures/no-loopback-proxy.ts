// 用户原始需求（2026-08-20）：回环测试不得被宿主代理环境劫持（Codex R1 非阻塞项）。
// 正交意图：测试引导期把回环域加入 no_proxy；不清除既有代理设置（网络用例仍按需自管）。
const loopback = "127.0.0.1,localhost";
for (const key of ["no_proxy", "NO_PROXY"] as const) {
	const current = process.env[key];
	process.env[key] = current?.includes(loopback) ? current : current ? `${current},${loopback}` : loopback;
}
