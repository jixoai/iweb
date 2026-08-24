// 用户原始需求（2026-08-13，rust-kernel 时代更新）：验收原生 Admin 资产的三入口、缓存、登录与密钥边界。
// 正交意图：启动隔离完整节点；执行 Kernel 入口（Caddy 已废除）验收；扫描资产凭据；清理本次测试资源。
import { $ } from "bun";
import { randomUUID } from "node:crypto";

interface HttpResponse {
	readonly status: number;
	readonly headers: Headers;
	readonly body: string;
}

const suffix = randomUUID().slice(0, 8);
const container = `iweb-native-assets-${suffix}`;
const volume = `${container}-data`;
const image = process.env.IWEB_ACCEPTANCE_IMAGE ?? "gaubee/iweb:rust-kernel";
const baseHost = `accept-${suffix}.iweb.test`;
const ownerKey = `owner-${randomUUID()}-${randomUUID()}`;
const rootPassword = `root-${randomUUID()}-${randomUUID()}`;
const celldSecret = `celld-${randomUUID()}-${randomUUID()}`;

function assert(condition: unknown, message: string): asserts condition {
	if (!condition) throw new Error(message);
}

async function request(host: string, path: string, options: { method?: "GET" | "HEAD"; owner?: boolean } = {}): Promise<HttpResponse> {
	const headers = ["Host:", host];
	if (options.owner) headers.push("Authorization:", `Bearer ${ownerKey}`);
	const responseArguments = options.method === "HEAD" ? ["--head"] : ["--dump-header", "-"];
	const result = await $`docker exec ${container} curl --silent --show-error --max-time 10 ${responseArguments} -H ${headers[0]}${headers[1]} ${options.owner ? ["-H", `${headers[2]} ${headers[3]}`] : []} ${`http://127.0.0.1:8080${path}`}`.text();
	const separator = result.indexOf("\r\n\r\n");
	assert(separator >= 0, `response for ${host}${path} has no HTTP header block`);
	const headerBlock = result.slice(0, separator);
	const body = options.method === "HEAD" ? "" : result.slice(separator + 4);
	const lines = headerBlock.split("\r\n");
	const status = Number(lines[0]?.split(" ")[1]);
	const responseHeaders = new Headers();
	for (const line of lines.slice(1)) {
		const index = line.indexOf(":");
		if (index > 0) responseHeaders.append(line.slice(0, index), line.slice(index + 1).trim());
	}
	return { status, headers: responseHeaders, body };
}

async function waitForNode(): Promise<void> {
	for (let attempt = 0; attempt < 90; attempt += 1) {
		const probe = await $`docker exec ${container} curl --silent --fail --max-time 2 -H ${`Host: ${baseHost}`} http://127.0.0.1:8080/_iweb/health`.quiet().nothrow();
		if (probe.exitCode === 0 && probe.text().trim() === "ok") return;
		await Bun.sleep(500);
	}
	const logs = await $`docker logs ${container}`.text();
	throw new Error(`isolated iweb node did not become ready\n${logs}`);
}

await $`docker volume create ${volume}`.quiet();
try {
	await $`docker run --detach --name ${container} --init --mount ${`type=volume,source=${volume},target=/data`} -e ${`CELLD_NODE=${container}`} -e ${`IWEB_BASE_HOST=${baseHost}`} -e ${`IWEB_API_TOKEN=${ownerKey}`} -e ${`MINIO_ROOT_USER=root-${suffix}`} -e ${`MINIO_ROOT_PASSWORD=${rootPassword}`} -e ${`CELLD_S3_ACCESS_KEY=celld-${suffix}`} -e ${`CELLD_S3_SECRET_KEY=${celldSecret}`} -e IWEB_DEPLOY_ON_START=1 ${image}`.quiet();
	await waitForNode();

	const systemHost = await request(`admin.${baseHost}`, "/");
	const appHost = await request(`admin.app.${baseHost}`, "/");
	const pathAlias = await request(baseHost, "/admin/app");
	for (const [label, response] of [["system host", systemHost], ["app host", appHost], ["path alias", pathAlias]] as const) {
		assert(response.status === 200, `${label} returned ${response.status}`);
		assert(response.headers.get("content-type")?.startsWith("text/html"), `${label} did not return HTML`);
		assert(response.body.includes("iweb Admin"), `${label} did not return the Admin document`);
	}
	assert(!systemHost.body.includes("<base "), "direct system host unexpectedly received a mounted base");
	assert(!appHost.body.includes("<base "), "direct app host unexpectedly received a mounted base");
	assert(pathAlias.body.includes('<base href="/admin/app/">'), "path alias did not receive its mounted base");

	const immutableMatch = appHost.body.match(/(?:href|src)="\.\/(?:_app\/immutable\/[^\"]+\.(?:js|css))"/);
	assert(immutableMatch, "Admin HTML has no relative immutable asset reference");
	const immutablePath = immutableMatch[0].match(/"\.\/(.+)"/)?.[1];
	assert(immutablePath, "cannot parse immutable asset path");

	const directAsset = await request(`admin.app.${baseHost}`, `/${immutablePath}`);
	const aliasAsset = await request(baseHost, `/admin/app/${immutablePath}`);
	for (const [label, response] of [["direct immutable asset", directAsset], ["alias immutable asset", aliasAsset]] as const) {
		assert(response.status === 200, `${label} returned ${response.status}`);
		assert(response.headers.get("cache-control") === "public, max-age=31536000, immutable", `${label} has incorrect cache policy`);
		const contentType = response.headers.get("content-type") ?? "";
		assert(contentType.includes("javascript") || contentType.includes("text/css"), `${label} has incorrect MIME ${contentType}`);
		assert(response.body.length > 0, `${label} returned an empty cold-load body`);
	}

	const head = await request(`admin.app.${baseHost}`, `/${immutablePath}`, { method: "HEAD" });
	assert(head.status === 200, `immutable HEAD returned ${head.status}`);
	assert(head.body === "", "immutable HEAD returned a body");
	assert(Boolean(head.headers.get("etag")), "immutable HEAD has no ETag");

	const unauthorized = await request(`api.${baseHost}`, "/v1/status");
	const authorized = await request(`api.${baseHost}`, "/v1/status", { owner: true });
	assert(unauthorized.status === 401, `login boundary returned ${unauthorized.status} without an owner key`);
	assert(authorized.status === 200, `login flow returned ${authorized.status} with an owner key`);
	const status = JSON.parse(authorized.body) as { baseHost?: string; applicationPublication?: { enabled?: boolean; reasons?: string[] }; sandboxSupervisor?: { configured?: boolean; available?: boolean } };
	assert(status.baseHost === baseHost, "authorized status response belongs to another node");
	assert(status.applicationPublication?.enabled === false, "generic application publication is unexpectedly enabled");
	assert(status.applicationPublication.reasons?.includes("sandbox-acceptance-missing") === true, "status does not report the missing sandbox acceptance gate");
	assert(status.sandboxSupervisor?.configured === false && status.sandboxSupervisor.available === false, "transitional image unexpectedly reports a sandbox supervisor");
	const publication = await request(`api.${baseHost}`, "/v1/applications/publish", { owner: true });
	assert(publication.status === 503, `disabled publication path returned ${publication.status}`);
	assert(JSON.parse(publication.body).code === "APPLICATION_PUBLICATION_DISABLED", "disabled publication path returned an unstable error code");

	const secretScan = await $`docker exec -e IWEB_SCAN_OWNER=${ownerKey} -e IWEB_SCAN_ROOT=${rootPassword} -e IWEB_SCAN_CELLD=${celldSecret} ${container} sh -c ${'for secret in "$IWEB_SCAN_OWNER" "$IWEB_SCAN_ROOT" "$IWEB_SCAN_CELLD"; do grep -R -a -l -F "$secret" /opt/iweb/worker/apps/admin/admin-assets && exit 1 || true; done'}`.quiet();
	assert(secretScan.exitCode === 0, "a node credential appears in Admin browser assets");
	assert(!systemHost.body.includes(ownerKey) && !appHost.body.includes(ownerKey) && !pathAlias.body.includes(ownerKey), "owner key appears in Admin HTML");
	assert(!immutablePath.includes(ownerKey), "owner key appears in an Admin request URL");

	process.stdout.write(JSON.stringify({
		baseHost,
		origins: { systemHost: systemHost.status, appHost: appHost.status, pathAlias: pathAlias.status },
		immutable: { status: directAsset.status, contentType: directAsset.headers.get("content-type"), cacheControl: directAsset.headers.get("cache-control"), head: head.status },
		login: { withoutOwnerKey: unauthorized.status, withOwnerKey: authorized.status },
		applicationPublication: { enabled: false, status: publication.status },
		secretScan: "clean"
	}) + "\n");
} finally {
	await $`docker rm --force ${container}`.quiet().nothrow();
	await $`docker volume rm ${volume}`.quiet().nothrow();
}
