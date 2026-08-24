// 用户原始需求（2026-08-14）：协议服务器必须先验证 framing、body size、content type、schema 与 semantic identity，再调用 adapter。
// 正交意图：拒绝请求产生零 adapter/Podman 调用；错误机器可读、有界、不回显 secret 或整份 payload。
import {
	boundedText,
	type ValidationIssue,
} from "./validation.ts";
import {
	correlateResponse,
	validateSemanticIdentity,
	validateSupervisorRequest,
	validateSupervisorResponse,
	type DeleteRequest,
	type DeleteResponse,
	type InspectRequest,
	type InspectResponse,
	type MetricsRequest,
	type MetricsResponse,
	type PrepareRequest,
	type PrepareResponse,
	type StartRequest,
	type StartResponse,
	type StopRequest,
	type StopResponse,
	type SupervisorRequest,
	type SupervisorResponse,
} from "./protocol.ts";

export const SUPERVISOR_RPC_PATH = "/v1/rpc";
export const DEFAULT_MAX_REQUEST_BYTES = 64 * 1024;

export interface SupervisorAdapter {
	prepare(request: PrepareRequest): Promise<PrepareResponse>;
	start(request: StartRequest): Promise<StartResponse>;
	stop(request: StopRequest): Promise<StopResponse>;
	inspect(request: InspectRequest): Promise<InspectResponse>;
	metrics(request: MetricsRequest): Promise<MetricsResponse>;
	delete(request: DeleteRequest): Promise<DeleteResponse>;
}

export interface SupervisorHttpRequest {
	readonly method: string;
	readonly path: string;
	readonly contentType: string | null;
	readonly body: Buffer;
}

export interface SupervisorHttpResult {
	readonly status: number;
	readonly body: string;
}

function jsonBody(status: number, body: unknown): SupervisorHttpResult {
	return { status, body: JSON.stringify(body) + "\n" };
}

function errorResult(status: number, code: string, message: string): SupervisorHttpResult {
	return jsonBody(status, { version: 1, ok: false, code, message });
}

export function serializeIssues(issues: readonly ValidationIssue[]): { readonly version: 1; readonly ok: false; readonly code: string; readonly message: string; readonly issues: readonly ValidationIssue[] } {
	return { version: 1, ok: false, code: "INVALID_REQUEST", message: "supervisor request is invalid", issues: issues.slice(0, 50) };
}

function isJsonContentType(contentType: string | null): boolean {
	if (contentType === null) return false;
	const mediaType = contentType.split(";")[0]?.trim().toLowerCase();
	return mediaType === "application/json";
}

async function dispatchToAdapter(adapter: SupervisorAdapter, request: SupervisorRequest): Promise<SupervisorResponse> {
	switch (request.operation) {
		case "prepare":
			return adapter.prepare(request);
		case "start":
			return adapter.start(request);
		case "stop":
			return adapter.stop(request);
		case "inspect":
			return adapter.inspect(request);
		case "metrics":
			return adapter.metrics(request);
		case "delete":
			return adapter.delete(request);
		default:
			throw new Error("unreachable supervisor operation");
	}
}

export async function handleSupervisorRpc(adapter: SupervisorAdapter, request: SupervisorHttpRequest, options: { readonly maxRequestBytes?: number } = {}): Promise<SupervisorHttpResult> {
	// 1. Framing: only the narrow versioned RPC path over the private Unix socket.
	if (request.method !== "POST" || request.path !== SUPERVISOR_RPC_PATH) {
		return errorResult(404, "UNKNOWN_ROUTE", "unknown supervisor route");
	}
	// 2. Body size.
	const maximumBytes = options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES;
	if (request.body.byteLength > maximumBytes) {
		return errorResult(413, "BODY_TOO_LARGE", "supervisor request is too large");
	}
	// 3. Content type.
	if (!isJsonContentType(request.contentType)) {
		return errorResult(415, "UNSUPPORTED_CONTENT_TYPE", "supervisor expects application/json");
	}
	// 4. Schema.
	let parsed: unknown;
	try {
		parsed = JSON.parse(request.body.toString("utf8"));
	} catch {
		return errorResult(400, "INVALID_JSON", "supervisor request body must be JSON");
	}
	const validated = validateSupervisorRequest(parsed);
	if (!validated.ok) {
		return jsonBody(400, serializeIssues(validated.errors));
	}
	// 5. Semantic identity.
	const semantic = validateSemanticIdentity(validated.value);
	if (!semantic.ok) {
		return jsonBody(400, serializeIssues(semantic.errors));
	}
	// 6. Adapter dispatch (the only point where a side effect may begin).
	try {
		const rawResponse = await dispatchToAdapter(adapter, semantic.value);
		const validated = validateSupervisorResponse(rawResponse);
		if (!validated.ok) {
			return errorResult(500, "ADAPTER_RESPONSE_INVALID", "supervisor adapter returned an invalid response");
		}
		const correlated = correlateResponse(semantic.value, validated.value);
		if (!correlated.ok) {
			return errorResult(500, "ADAPTER_RESPONSE_INVALID", "supervisor adapter response does not match the request");
		}
		return jsonBody(200, correlated.value);
	} catch {
		return errorResult(500, "ADAPTER_ERROR", "supervisor adapter failed");
	}
}

