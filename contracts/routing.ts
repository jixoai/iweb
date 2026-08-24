// 用户原始需求（2026-08-14）：enabled route 只解析到 ready active sandbox version；无 ready active version 返回 502，未知 host 404。
// 正交意图：纯解析；hostname/path alias 指向同一 generation。
import { type ControlState } from "./control-db.ts";
import { deriveSandboxId } from "./protocol.ts";

export interface RouteRecord {
	readonly hostId: string;
	readonly appName: string;
	readonly enabled: boolean;
}

export function resolveActiveSandboxId(state: ControlState, appName: string): string | null {
	const application = state.applications[appName];
	if (!application || application.active.kind !== "active") return null;
	return deriveSandboxId(application.active.applicationId, application.active.version.digest, application.active.version.sequence);
}

export interface ResolvedRoute {
	readonly appName: string;
	readonly sandboxId: string;
	readonly appBasePath: string | null;
}

// Resolve an enabled route to its ready active sandbox version. hostId lookup
// returns the appName; the path alias also yields an appBasePath.
export function resolveRoute(state: ControlState, route: RouteRecord | null, appBasePath: string | null): ResolvedRoute | null {
	if (!route || route.enabled === false) return null;
	const sandboxId = resolveActiveSandboxId(state, route.appName);
	if (sandboxId === null) return null;
	return { appName: route.appName, sandboxId, appBasePath };
}

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

