// 用户原始需求（2026-08-14）：无 ready active sandbox 的用户应用路由返回有界 502，未知 host 404。
// two-tier-runtime-trust（2026-08-29）：celld ControlState 已删（准入与路由解析权威移至 Rust kernel routes.rs，
// 应用身份由路由注册表唯一承载）；本文件只剩 routeAction 处置策略，与 routes.rs 的 action_for 对位。
export type RouteAction = { readonly kind: "system" } | { readonly kind: "sandbox"; readonly sandboxId: string } | { readonly kind: "unavailable" };

// Policy for a resolved host route. Trusted image-seeded system routes (admin,
// mcp) stay on the shared Dispatcher. A user application route is served ONLY by
// its ready active sandbox through the private ingress; with no ready active
// sandbox it is a bounded generic 502 — never a fallback to the shared
// Dispatcher, which would execute untrusted application code outside the
// sandbox boundary. (An unknown host never reaches here: it is a 404 upstream.)
export function routeAction(route: { readonly system: boolean } | null, activeSandboxId: string | null): RouteAction {
	if (route && route.system) return { kind: "system" };
	if (activeSandboxId !== null) return { kind: "sandbox", sandboxId: activeSandboxId };
	return { kind: "unavailable" };
}
