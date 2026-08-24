// 用户原始需求（2026-08-14）：public-object gateway 只服务 owner 明确公开的对象，无 bucket listing、无 workspace 凭据、无直接 MinIO 代理权。
// 正交意图：路径归一化 + 显式对象集合/前缀。
export interface PublicObjectSet {
	readonly objects: ReadonlySet<string>;
	readonly prefixes: readonly string[];
}

export function normalizePublicObjectPath(value: string): string | null {
	const normalized = String(value ?? "").trim().replace(/^\/+/, "").replace(/\/+$/, "");
	if (!normalized || normalized.includes("..") || normalized.split("/").some((segment) => !segment || segment === ".")) return null;
	if (/[\u0000-\u001f]/.test(normalized)) return null;
	return normalized;
}

// The conventional root document. A request for "/" resolves to it only when
// the operator explicitly whitelisted it; otherwise the root is not public.
export const ROOT_PUBLIC_DOCUMENT = "index.html";

export function resolvePublicObject(set: PublicObjectSet, path: string): string | null {
	const trimmed = String(path ?? "").trim();
	if (trimmed !== "" && trimmed.replaceAll("/", "") === "") {
		return set.objects.has(ROOT_PUBLIC_DOCUMENT) ? ROOT_PUBLIC_DOCUMENT : null;
	}
	const normalized = normalizePublicObjectPath(path);
	if (normalized === null) return null;
	if (set.objects.has(normalized)) return normalized;
	if (set.prefixes.some((prefix) => normalized === prefix || normalized.startsWith(prefix + "/"))) return normalized;
	return null;
}

// Parses the operator whitelist (comma-separated; an entry ending in "/" is a
// prefix). Invalid entries are skipped; the set defaults to the seeded index.
export function parsePublicObjectSet(value: string | undefined): PublicObjectSet {
	const objects = new Set<string>();
	const prefixes: string[] = [];
	for (const entry of String(value ?? "index.html").split(",")) {
		const trimmed = entry.trim();
		if (trimmed === "") continue;
		const normalized = normalizePublicObjectPath(trimmed);
		if (normalized === null) continue;
		if (trimmed.endsWith("/")) prefixes.push(normalized);
		else objects.add(normalized);
	}
	return { objects, prefixes };
}

