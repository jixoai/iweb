// 用户原始需求（2026-08-13）：以隔离环境验证 pinned celld v0.2 原生静态资产行为。
// 正交意图：编排临时 MinIO/celld；断言 Worker-first 与 binding 响应；可靠清理本次 fixture 资源。
import { $ } from "bun";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(root, "tests/fixtures/celld-static-assets");
const suffix = randomUUID().slice(0, 8);
const network = `iweb-celld-assets-${suffix}`;
const minio = `${network}-minio`;
const celld = `${network}-celld`;
const image = process.env.IWEB_FIXTURE_IMAGE ?? "iweb:native-assets-work";
const fixtureImage = `iweb:celld-assets-fixture-${suffix}`;
const curlImage = "curlimages/curl:8.17.0";
const accessKey = `fixture-${suffix}`;
const secretKey = `fixture-secret-${suffix}`;

async function retry(label: string, action: () => Promise<void>): Promise<void> {
	let lastError: unknown;
	for (let attempt = 0; attempt < 30; attempt += 1) {
		try {
			await action();
			return;
		} catch (error) {
			lastError = error;
			await Bun.sleep(250);
		}
	}
	throw new Error(`${label} did not become ready`, { cause: lastError });
}

function assertIncludes(actual: string, expected: string, label: string): void {
	if (!actual.toLowerCase().includes(expected.toLowerCase())) {
		throw new Error(`${label}: expected ${JSON.stringify(expected)} in ${JSON.stringify(actual)}`);
	}
}

await $`docker build --quiet --tag ${fixtureImage} --build-arg ${`IWEB_FIXTURE_BASE=${image}`} ${fixture}`.quiet();
await $`docker network create ${network}`.quiet();
try {
	await $`docker run --detach --name ${minio} --network ${network} -e MINIO_ROOT_USER=${accessKey} -e MINIO_ROOT_PASSWORD=${secretKey} minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e server /data --address :9000`.quiet();
	await retry("MinIO", async () => {
		await $`docker run --rm --network ${network} --entrypoint sh ${image} -c ${`mc alias set fixture http://${minio}:9000 '${accessKey}' '${secretKey}' >/dev/null && mc mb fixture/celld-fixture >/dev/null`}`.quiet();
	});

	await $`docker run --rm --network ${network} -e AWS_ACCESS_KEY_ID=${accessKey} -e AWS_SECRET_ACCESS_KEY=${secretKey} ${fixtureImage} deploy /fixture --bucket s3://celld-fixture --endpoint ${`http://${minio}:9000`} --region us-east-1`.quiet();
	await $`docker run --detach --name ${celld} --network ${network} -e CELLD_NODE=${celld} -e CELLD_WATCH=/tmp/celld -e AWS_ACCESS_KEY_ID=${accessKey} -e AWS_SECRET_ACCESS_KEY=${secretKey} --entrypoint celld ${image} --bucket s3://celld-fixture --endpoint ${`http://${minio}:9000`} --region us-east-1 --listen 0.0.0.0:8787 --internal-listen 0.0.0.0:8788 --advertise ${`${celld}:8788`}`.quiet();

	await retry("celld", async () => {
		await $`docker run --rm --network ${network} ${curlImage} --max-time 2 -fsS ${`http://${celld}:8787/worker`}`.quiet();
	});

	const direct = await $`docker run --rm --network ${network} ${curlImage} --max-time 5 -fsS -D - ${`http://${celld}:8787/worker`}`.text();
	assertIncludes(direct, "x-fixture-worker: direct", "Worker-first direct response");
	assertIncludes(direct, "worker response", "Worker-first response body");

	const asset = await $`docker run --rm --network ${network} ${curlImage} --max-time 5 -fsS -D - ${`http://${celld}:8787/probe.txt`}`.text();
	assertIncludes(asset, "content-type: text/plain", "asset MIME");
	assertIncludes(asset, "cache-control: public, max-age=31536000, immutable", "asset cache policy");
	assertIncludes(asset, "x-fixture-asset: probe", "_headers override");
	assertIncludes(asset, "x-fixture-worker: binding", "asset binding response");
	assertIncludes(asset, "native asset probe", "asset body");

	const head = await $`docker run --rm --network ${network} ${curlImage} --max-time 5 -fsS -I ${`http://${celld}:8787/probe.txt`}`.text();
	assertIncludes(head, "HTTP/1.1 200", "HEAD status");
	assertIncludes(head, "etag:", "HEAD ETag");
	assertIncludes(head, "x-fixture-worker: binding", "HEAD binding response");

	process.stdout.write("celld v0.2 native static-assets fixture passed\n");
} finally {
	await $`docker rm --force ${celld} ${minio}`.quiet().nothrow();
	await $`docker network rm ${network}`.quiet().nothrow();
	await $`docker image rm ${fixtureImage}`.quiet().nothrow();
}
