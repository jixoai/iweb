// 用户原始需求（2026-08-26，add-wasm-runtime 任务 7.7 + 4.2）：把 packages/contracts/wasm-catalog.ts
//   落地的 catalog 纯函数契约接进 supervisor 的持久化与 owner 流程——RuntimeCatalogV1 与历史 revision
//   按 spec 固定路径布局存储（revisions/<revision>-<catalogHash>.json + catalog-history-index-v1.json +
//   release-receipts/<releaseId>.json + delete-audit/<deleteId>.json），tmp+rename 原子写、JCS 字节权威、
//   启动时以 rebuildCatalogHistoryIndex 语义校验重建，损坏/分歧 fail-closed；owner 侧 append/revoke/
//   release/gc 全部走契约纯函数后落盘并产出审计对象。
// 正交意图：(1) 固定布局的文件存储与逻辑/物理路径映射；(2) 启动恢复（文件为权威、index 为派生缓存、
//   有效 index 与文件分歧 fail-closed、缺失/损坏 index 重建）；(3) owner 更新操作（CAS append、CVE revoke、
//   release receipt、GC 审计先行）与幂等重放；(4) 读取面（current/receipts/audits/binding fence）。
// 不可调和原因：四组意图共享同一套恢复状态机与 IO 原语，物理拆分会重引入「文件 vs index」权威分歧。
// 接线缺口（本文件刻意不做的部分）：supervisor socket 现无 owner 凭据通道（SO_PEERCRED 双端契约属任务
//   7.1 的 Linux 实测；owner-key 授权在 Kernel 侧），因此本模块只以类型化 store API 暴露 owner 管理面，
//   不在 server.ts 挂任何未授权 HTTP/RPC 路由；授权通道落地后由宿主接线并做来源检查（契约备注 #10）。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
//   「Catalog history has fixed recovery and deletion records」「GC first writes delete-audit, then removes
//   the revision file and marks the index entry deleted」「an index/file disagreement fails closed」。
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { systemStateStoreIO } from "./desired-state.ts";
import { failure, issue, type ValidationIssue, type ValidationResult } from "../packages/contracts/validation.ts";
import { jcsCanonicalBytes } from "../packages/contracts/wasm-package.ts";
import {
	appendRuntimeCatalogRevision,
	CATALOG_DELETE_AUDIT_DIR,
	CATALOG_HISTORY_INDEX_PATH,
	CATALOG_HISTORY_REVISIONS_DIR,
	CATALOG_RELEASE_RECEIPTS_DIR,
	catalogDeleteAuditFilePath,
	catalogHistoryRevisionFilePath,
	catalogReleaseReceiptFilePath,
	checkRuntimeBindingNotReleased,
	checkRuntimeBindingUsable,
	computeCatalogHistoryIndexDigestV1,
	gcCatalogHistoryRevision,
	rebuildCatalogHistoryIndex,
	releaseRuntimeCatalogEntry,
	revokeRuntimeCatalogEntry,
	sealCatalogHistoryRecordV1,
	sealRuntimeCatalogV1,
	validateCatalogDeleteAuditV1,
	validateCatalogHistoryFileName,
	validateCatalogHistoryIndexV1,
	validateCatalogHistoryRecordV1,
	validateCatalogReleaseReceiptV1,
	WASM_CATALOG_ENTRY_PROTECTED,
	type CatalogDeleteAuditV1,
	type CatalogHistoryGcResultV1,
	type CatalogHistoryIndexPayloadV1,
	type CatalogHistoryIndexV1,
	type CatalogHistoryRecordV1,
	type CatalogReleaseReceiptV1,
	type CatalogReleaseRequestV1,
	type RuntimeCatalogEntryV1,
	type RuntimeCatalogRevocationV1,
	type RuntimeCatalogRevisionPinV1,
	type RuntimeCatalogV1,
	type WasmCatalogEntryReferenceV1,
	type WasmRuntimeArchitecture,
} from "../packages/contracts/wasm-catalog.ts";
import type { RuntimeBindingIdentityV1 } from "../packages/contracts/wasm-execution.ts";

// ---------------------------------------------------------------------------
// 固定路径布局与 IO：逻辑路径 = 契约公式（spec 权威 /data/kernel/runtime-catalog/...）；
// 物理路径 = root + 逻辑路径去掉 spec 前缀（生产 root 即 spec 前缀；测试注入临时 root）。
// ---------------------------------------------------------------------------

export const WASM_CATALOG_STORE_DEFAULT_ROOT = CATALOG_HISTORY_INDEX_PATH.slice(0, CATALOG_HISTORY_INDEX_PATH.lastIndexOf("/"));

export interface WasmCatalogStoreIO {
	readFile(path: string): string | null;
	writeFileAtomic(path: string, content: string): void;
	deleteFile(path: string): void;
	ensureDirectory(path: string): void;
	listFiles(path: string): readonly string[];
}

// 复用 desired-state.ts 的 tmp+fsync+rename 持久化契约（0600/0700、目录 fsync 容错集），
// 只补 listFiles；不在本文件重写第二套写入语义。
export const systemWasmCatalogStoreIO: WasmCatalogStoreIO = {
	...systemStateStoreIO,
	listFiles: (directory) => {
		let names: string[];
		try {
			names = readdirSync(directory, { withFileTypes: true }).filter((entry) => entry.isFile()).map((entry) => entry.name);
		} catch (error) {
			const code = typeof error === "object" && error !== null && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
			if (code !== "ENOENT") throw error;
			return [];
		}
		return names.sort();
	},
};

export function wasmCatalogPhysicalPath(root: string, logicalPath: string): string {
	if (!logicalPath.startsWith(WASM_CATALOG_STORE_DEFAULT_ROOT + "/")) {
		throw new Error("logical catalog path escapes the fixed spec root: " + logicalPath);
	}
	return join(root, logicalPath.slice(WASM_CATALOG_STORE_DEFAULT_ROOT.length));
}

// ---------------------------------------------------------------------------
// 稳定错误码与结果形状
// ---------------------------------------------------------------------------

export const WASM_CATALOG_STORE_CORRUPT = "WASM_CATALOG_STORE_CORRUPT";
export const WASM_CATALOG_STORE_DIVERGENT = "WASM_CATALOG_STORE_DIVERGENT";
export const WASM_CATALOG_STORE_UNINITIALIZED = "WASM_CATALOG_STORE_UNINITIALIZED";
export const WASM_CATALOG_STORE_ALREADY_INITIALIZED = "WASM_CATALOG_STORE_ALREADY_INITIALIZED";
export const WASM_CATALOG_STORE_INVALID = "WASM_CATALOG_STORE_INVALID";
export const CATALOG_RELEASE_RECEIPT_MISSING = "CATALOG_RELEASE_RECEIPT_MISSING";
export const CATALOG_RELEASE_RECEIPT_STORE_MISMATCH = "CATALOG_RELEASE_RECEIPT_STORE_MISMATCH";
export const CATALOG_HISTORY_RECORD_MISSING = "CATALOG_HISTORY_RECORD_MISSING";
export const CATALOG_HISTORY_LAST_PRESENT = "CATALOG_HISTORY_LAST_PRESENT";
export const CATALOG_DELETE_AUDIT_STORE_MISMATCH = "CATALOG_DELETE_AUDIT_STORE_MISMATCH";

/** 恢复期 fail-closed：损坏（单对象不可验证）或分歧（对象间互相矛盾）。 */
export class WasmCatalogStoreError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.code = code;
	}
}

export type WasmCatalogStoreOutcome<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly code: string; readonly issues: readonly ValidationIssue[] };

function contractFailure<T>(errors: readonly ValidationIssue[]): WasmCatalogStoreOutcome<T> {
	return { ok: false, code: errors.length > 0 && errors[0] !== undefined ? errors[0].code : WASM_CATALOG_STORE_INVALID, issues: errors };
}

function storeFailure<T>(code: string, message: string): WasmCatalogStoreOutcome<T> {
	return { ok: false, code, issues: [issue(code, "", message)] };
}

function firstIssueSummary(issues: readonly ValidationIssue[]): string {
	const first = issues[0];
	return first ? first.code + " at " + first.path + ": " + first.message : "validation failed";
}

// ---------------------------------------------------------------------------
// JCS 字节权威读写（与 wasm-control.ts 同语义：读时 raw bytes 必须等于 JCS(parse)，写时只落 JCS）
// ---------------------------------------------------------------------------

function readCanonicalRecord(io: WasmCatalogStoreIO, path: string, noun: string): { readonly status: "absent" } | { readonly status: "present"; readonly value: unknown } {
	const text = io.readFile(path);
	if (text === null) return { status: "absent" };
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, noun + " is not parseable JSON: " + path);
	}
	if (Buffer.from(jcsCanonicalBytes(parsed)).toString("utf8") !== text) {
		throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, noun + " bytes are not canonical JCS: " + path);
	}
	return { status: "present", value: parsed };
}

function writeCanonicalRecord(io: WasmCatalogStoreIO, path: string, value: unknown): void {
	io.writeFileAtomic(path, Buffer.from(jcsCanonicalBytes(value)).toString("utf8"));
}

// 已验证值域上的结构相等性以 JCS 字节为准（不引入第二套 deep-equal 语义）。
function jcsEqual(left: unknown, right: unknown): boolean {
	return Buffer.compare(Buffer.from(jcsCanonicalBytes(left)), Buffer.from(jcsCanonicalBytes(right))) === 0;
}

// ---------------------------------------------------------------------------
// 恢复状态机：revisions / release-receipts / delete-audit 文件扫描 + index 重建/比对
// ---------------------------------------------------------------------------

const REVISION_FILE_NAME_PATTERN = /^\d+-[a-f0-9]{64}\.json$/;

interface WasmCatalogRecoveredState {
	readonly records: readonly CatalogHistoryRecordV1[];
	readonly receipts: readonly CatalogReleaseReceiptV1[];
	readonly audits: readonly CatalogDeleteAuditV1[];
	readonly index: CatalogHistoryIndexV1 | null;
	readonly current: RuntimeCatalogV1 | null;
}

interface WasmCatalogRecoverMode {
	/** 允许在 index 缺失/损坏（或显式 rebuild）时落盘重建结果。读路径必须为 false。 */
	readonly persistRepairs: boolean;
	/** owner 显式修复：忽略已存 index，一律以文件重建并落盘。 */
	readonly ignoreStoredIndex: boolean;
}

type StoredIndexState =
	| { readonly status: "absent" }
	| { readonly status: "corrupt"; readonly detail: string }
	| { readonly status: "valid"; readonly index: CatalogHistoryIndexV1 };

function readHistoryRecords(io: WasmCatalogStoreIO, root: string): CatalogHistoryRecordV1[] {
	const directory = wasmCatalogPhysicalPath(root, CATALOG_HISTORY_REVISIONS_DIR);
	const records: CatalogHistoryRecordV1[] = [];
	const seenRevisions = new Set<number>();
	for (const name of io.listFiles(directory)) {
		// tmp+rename 原子写的崩溃残留：跳过，不当分歧。
		if (name.endsWith(".tmp")) continue;
		if (!REVISION_FILE_NAME_PATTERN.test(name)) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "unexpected object in the fixed revisions directory: " + name);
		}
		const record = readCanonicalRecord(io, join(directory, name), "catalog history revision file");
		if (record.status === "absent") throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "listed revision file disappeared: " + name);
		const validated = validateCatalogHistoryRecordV1(record.value);
		if (!validated.ok) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "catalog history revision " + name + " failed validation: " + firstIssueSummary(validated.errors));
		}
		const fileName = validateCatalogHistoryFileName(name, validated.value);
		if (!fileName.ok) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "catalog history revision file name disagrees with its record: " + name);
		}
		// 同 revision 两份文件（不同 hash）= 分歧，绝不选「最近」。
		if (seenRevisions.has(validated.value.revision)) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "catalog revision " + validated.value.revision + " appears more than once in the fixed revisions directory");
		}
		seenRevisions.add(validated.value.revision);
		records.push(validated.value);
	}
	records.sort((left, right) => left.revision - right.revision);
	return records;
}

function readReleaseReceipts(io: WasmCatalogStoreIO, root: string): CatalogReleaseReceiptV1[] {
	const directory = wasmCatalogPhysicalPath(root, CATALOG_RELEASE_RECEIPTS_DIR);
	const receipts: CatalogReleaseReceiptV1[] = [];
	for (const name of io.listFiles(directory)) {
		if (name.endsWith(".tmp")) continue;
		const record = readCanonicalRecord(io, join(directory, name), "catalog release receipt file");
		if (record.status === "absent") throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "listed release receipt disappeared: " + name);
		const validated = validateCatalogReleaseReceiptV1(record.value);
		if (!validated.ok) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "release receipt " + name + " failed validation: " + firstIssueSummary(validated.errors));
		}
		if (name !== validated.value.releaseId + ".json") {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "release receipt file name disagrees with its releaseId: " + name);
		}
		receipts.push(validated.value);
	}
	return receipts;
}

function readDeleteAudits(io: WasmCatalogStoreIO, root: string): CatalogDeleteAuditV1[] {
	const directory = wasmCatalogPhysicalPath(root, CATALOG_DELETE_AUDIT_DIR);
	const audits: CatalogDeleteAuditV1[] = [];
	for (const name of io.listFiles(directory)) {
		if (name.endsWith(".tmp")) continue;
		const record = readCanonicalRecord(io, join(directory, name), "catalog delete audit file");
		if (record.status === "absent") throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "listed delete audit disappeared: " + name);
		const validated = validateCatalogDeleteAuditV1(record.value);
		if (!validated.ok) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "delete audit " + name + " failed validation: " + firstIssueSummary(validated.errors));
		}
		if (name !== validated.value.deleteId + ".json") {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "delete audit file name disagrees with its deleteId: " + name);
		}
		audits.push(validated.value);
	}
	return audits;
}

// delete audit 必须有 bind 同一 (revision, hash) 的 release receipt；同一 revision 最多一份 audit。
function crossCheckAudits(state: { readonly receipts: readonly CatalogReleaseReceiptV1[]; readonly audits: readonly CatalogDeleteAuditV1[] }): Map<number, CatalogDeleteAuditV1> {
	const receiptByReleaseId = new Map(state.receipts.map((receipt) => [receipt.releaseId, receipt] as const));
	const auditByRevision = new Map<number, CatalogDeleteAuditV1>();
	for (const audit of state.audits) {
		const receipt = receiptByReleaseId.get(audit.releaseId);
		if (receipt === undefined || receipt.catalogRevision !== audit.revision || receipt.catalogHash !== audit.catalogHash) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "delete audit " + audit.deleteId + " has no release receipt binding its revision and hash");
		}
		if (auditByRevision.has(audit.revision)) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "catalog revision " + audit.revision + " has more than one delete audit");
		}
		auditByRevision.set(audit.revision, audit);
	}
	return auditByRevision;
}

// 已 release 的 revision：其历史文件必须仍在，或已有 delete audit 证明被收集；
// 两者皆无 = 历史对象在无审计的情况下消失 → fail-closed（审计缺失 fail-closed 的恢复面）。
function crossCheckReceipts(records: readonly CatalogHistoryRecordV1[], receipts: readonly CatalogReleaseReceiptV1[], auditByRevision: ReadonlyMap<number, CatalogDeleteAuditV1>): void {
	const recordKeys = new Set(records.map((record) => record.revision + "-" + record.catalogHash));
	for (const receipt of receipts) {
		if (!recordKeys.has(receipt.catalogRevision + "-" + receipt.catalogHash) && !auditByRevision.has(receipt.catalogRevision)) {
			throw new WasmCatalogStoreError(
				WASM_CATALOG_STORE_DIVERGENT,
				"release receipt " + receipt.releaseId + " names revision " + receipt.catalogRevision + " whose history file and delete audit are both missing",
			);
		}
	}
}

function latestRetentionFor(receipts: readonly CatalogReleaseReceiptV1[], revision: number, catalogHash: string): string | null {
	let latest: number | null = null;
	for (const receipt of receipts) {
		if (receipt.catalogRevision !== revision || receipt.catalogHash !== catalogHash) continue;
		const at = Date.parse(receipt.releaseRetentionUntil);
		if (latest === null || at > latest) latest = at;
	}
	return latest === null ? null : new Date(latest).toISOString();
}

// 组装完整 index：present 条目复用契约 rebuildCatalogHistoryIndex（含 protectedReferenceCount 与
// retention），deleted 条目来自「audit 存在且文件已消失」的 revision；最后整体验证（排序/唯一/指针/digest）。
function assembleCatalogHistoryIndex(
	records: readonly CatalogHistoryRecordV1[],
	audits: readonly CatalogDeleteAuditV1[],
	receipts: readonly CatalogReleaseReceiptV1[],
	references: readonly WasmCatalogEntryReferenceV1[],
	updatedAt: string,
): ValidationResult<CatalogHistoryIndexV1> {
	if (records.length === 0) {
		return failure<CatalogHistoryIndexV1>([issue(WASM_CATALOG_STORE_DIVERGENT, "", "no present catalog history revision survives; a current pointer cannot be proven")]);
	}
	const present = rebuildCatalogHistoryIndex(records, { updatedAt, references, releaseReceipts: receipts });
	if (!present.ok) return present;
	const deletedEntries = audits
		.filter((audit) => !records.some((record) => record.revision === audit.revision))
		.map((audit) => ({
			revision: audit.revision,
			catalogHash: audit.catalogHash,
			path: catalogHistoryRevisionFilePath(audit.revision, audit.catalogHash),
			status: "deleted" as const,
			protectedReferenceCount: 0,
			releaseRetentionUntil: latestRetentionFor(receipts, audit.revision, audit.catalogHash),
			deletedAt: audit.deletedAt,
		}));
	const revisions = [...present.value.revisions, ...deletedEntries].sort((left, right) => left.revision - right.revision);
	const payload: CatalogHistoryIndexPayloadV1 = {
		schemaVersion: 1,
		runtimeKind: "wasm",
		currentRevision: present.value.currentRevision,
		currentHash: present.value.currentHash,
		revisions,
		updatedAt,
	};
	return validateCatalogHistoryIndexV1({ ...payload, indexDigest: computeCatalogHistoryIndexDigestV1(payload) });
}

// 语义核心比较：current 指针 + (revision, hash, status) 三元组集合。updatedAt/受保护计数/retention
// 是随上下文刷新的快照字段，不构成分歧。
function semanticIndexCore(index: CatalogHistoryIndexV1): string {
	return Buffer.from(
		jcsCanonicalBytes({
			currentRevision: index.currentRevision,
			currentHash: index.currentHash,
			revisions: index.revisions.map((entry) => [entry.revision, entry.catalogHash, entry.status]),
		}),
	).toString("utf8");
}

function readStoredIndex(io: WasmCatalogStoreIO, root: string): StoredIndexState {
	const physical = wasmCatalogPhysicalPath(root, CATALOG_HISTORY_INDEX_PATH);
	const text = io.readFile(physical);
	if (text === null) return { status: "absent" };
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return { status: "corrupt", detail: "not parseable JSON" };
	}
	if (Buffer.from(jcsCanonicalBytes(parsed)).toString("utf8") !== text) {
		return { status: "corrupt", detail: "bytes are not canonical JCS" };
	}
	const validated = validateCatalogHistoryIndexV1(parsed);
	if (!validated.ok) return { status: "corrupt", detail: firstIssueSummary(validated.errors) };
	return { status: "valid", index: validated.value };
}

function recoverState(io: WasmCatalogStoreIO, root: string, references: readonly WasmCatalogEntryReferenceV1[], now: () => string, mode: WasmCatalogRecoverMode): WasmCatalogRecoveredState {
	const records = readHistoryRecords(io, root);
	const receipts = readReleaseReceipts(io, root);
	const audits = readDeleteAudits(io, root);
	const auditByRevision = crossCheckAudits({ receipts, audits });
	crossCheckReceipts(records, receipts, auditByRevision);

	const finish = (index: CatalogHistoryIndexV1): WasmCatalogRecoveredState => {
		const currentRecord = records.find((record) => record.revision === index.currentRevision && record.catalogHash === index.currentHash);
		if (currentRecord === undefined) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "the index current pointer names revision " + index.currentRevision + " which has no surviving history file");
		}
		return { records, receipts, audits, index, current: currentRecord.catalog };
	};

	// 空存储：无任何历史对象且无 index → 未初始化；index 存在却无任何历史对象 → 分歧。
	if (records.length === 0 && audits.length === 0 && receipts.length === 0) {
		const stored = readStoredIndex(io, root);
		if (stored.status === "valid") {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "a catalog history index exists without any revision, receipt, or audit object");
		}
		return { records, receipts, audits, index: null, current: null };
	}

	const assembled = assembleCatalogHistoryIndex(records, audits, receipts, references, now());
	if (!assembled.ok) {
		throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "catalog history index rebuild failed: " + firstIssueSummary(assembled.errors));
	}
	const rebuilt = assembled.value;
	const indexPhysical = wasmCatalogPhysicalPath(root, CATALOG_HISTORY_INDEX_PATH);

	if (mode.ignoreStoredIndex) {
		if (mode.persistRepairs) writeCanonicalRecord(io, indexPhysical, rebuilt);
		return finish(rebuilt);
	}
	const stored = readStoredIndex(io, root);
	if (stored.status === "absent" || stored.status === "corrupt") {
		// spec 场景「index missing or corrupt but revision files intact → rebuild」；读路径不落盘。
		if (mode.persistRepairs) writeCanonicalRecord(io, indexPhysical, rebuilt);
		return finish(rebuilt);
	}
	if (semanticIndexCore(stored.index) !== semanticIndexCore(rebuilt)) {
		throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "the stored catalog history index disagrees with the fixed-path history objects (index/file disagreement fails closed)");
	}
	// 语义核心一致：返回持久化的 index 快照（其 protectedReferenceCount/retention 是落盘时刻的
	// 审计记录），而不是以本调用传入的引用集合重新推导的瞬时计数。
	return finish(stored.index);
}

// ---------------------------------------------------------------------------
// owner 侧 catalog store：owner 管理面的独立模块形态（授权通道接线缺口见文件头）
// ---------------------------------------------------------------------------

export interface WasmCatalogRevisionResult {
	readonly catalog: RuntimeCatalogV1;
	readonly historyRecord: CatalogHistoryRecordV1;
}

export interface WasmCatalogReleaseInput {
	readonly entryKey: string;
	readonly references: readonly WasmCatalogEntryReferenceV1[];
	readonly releaseId: string;
	readonly ownerCommandId: string;
	readonly drainedAt: string;
	readonly releasedAt: string;
}

export interface WasmCatalogGcInput {
	readonly releaseId: string;
	readonly deleteId: string;
	readonly ownerCommandId: string;
	readonly deletedAt: string;
	readonly reason: string;
	readonly references: readonly WasmCatalogEntryReferenceV1[];
}

export interface WasmCatalogStoreOptions {
	readonly now?: () => string;
}

export class WasmCatalogStore {
	private readonly io: WasmCatalogStoreIO;
	private readonly root: string;
	private readonly now: () => string;

	constructor(io: WasmCatalogStoreIO = systemWasmCatalogStoreIO, root: string = WASM_CATALOG_STORE_DEFAULT_ROOT, options: WasmCatalogStoreOptions = {}) {
		if (!root.startsWith("/")) throw new Error("wasm catalog store root must be an absolute path");
		this.io = io;
		this.root = root;
		this.now = options.now ?? (() => new Date().toISOString());
	}

	get rootDirectory(): string {
		return this.root;
	}

	// --- 读取面（零写入；恢复失败 fail-closed 抛出） ---

	// 启动恢复（任务 7.7）：重建/校验 catalog-history-index——index 缺失或损坏时按 spec 场景
	// 重建并落盘；任何对象损坏或 index/文件分歧 fail-closed 抛出。返回恢复出的 current catalog。
	open(references: readonly WasmCatalogEntryReferenceV1[] = []): RuntimeCatalogV1 | null {
		return recoverState(this.io, this.root, references, this.now, { persistRepairs: true, ignoreStoredIndex: false }).current;
	}

	current(): RuntimeCatalogV1 | null {
		return this.recoverReadonly().current;
	}

	readIndex(): CatalogHistoryIndexV1 | null {
		return this.recoverReadonly().index;
	}

	receipts(): readonly CatalogReleaseReceiptV1[] {
		return this.recoverReadonly().receipts;
	}

	audits(): readonly CatalogDeleteAuditV1[] {
		return this.recoverReadonly().audits;
	}

	// 4.2 阻断面：新 prepare/activation/rebind/rollback 的统一 fence——
	// 已释放 binding 不可复活（receipt 审计），已 revoke entry 拒绝新操作（契约 fence）。
	checkBindingUsable(runtimeBinding: RuntimeBindingIdentityV1, architecture: WasmRuntimeArchitecture): ValidationResult<RuntimeCatalogEntryV1> {
		const state = this.recoverReadonly();
		if (state.current === null || state.index === null) {
			return { ok: false, errors: [issue(WASM_CATALOG_STORE_UNINITIALIZED, "", "the runtime catalog store has no proven current revision")] };
		}
		const notReleased = checkRuntimeBindingNotReleased(state.receipts, runtimeBinding);
		if (!notReleased.ok) return notReleased;
		return checkRuntimeBindingUsable(state.current, runtimeBinding, architecture);
	}

	// --- owner 更新面（全部先走契约纯函数，成功后才落盘） ---

	// 首个 revision：空存储的确定性引导；不接受任何 expected pin（没有可钉住的上一 revision）。
	bootstrap(payload: unknown): WasmCatalogStoreOutcome<WasmCatalogRevisionResult> {
		const state = this.recoverReadonly();
		if (state.index !== null || state.current !== null) {
			return storeFailure(WASM_CATALOG_STORE_ALREADY_INITIALIZED, "the catalog store already holds a proven current revision; use append with an expected (revision, catalogHash) pin");
		}
		const sealed = sealRuntimeCatalogV1(payload);
		if (!sealed.ok) return contractFailure(sealed.errors);
		return this.persistAppendedRevision(state, sealed.value);
	}

	// owner 追加：CAS + 受保护 entry 禁删 + revoke 单向性（契约）→ 历史 revision 文件 + index 落盘。
	// 幂等性说明：append 没有 commandId/receipt 一类的对象键；spec 场景明确「同一 expected pin 的第二次
	// append 一律 CATALOG_REVISION_CONFLICT」——即使字节与已落盘 revision 相同也不静默重放（见文末备注 6）。
	append(expected: RuntimeCatalogRevisionPinV1, next: unknown, references: readonly WasmCatalogEntryReferenceV1[] = []): WasmCatalogStoreOutcome<WasmCatalogRevisionResult> {
		const state = this.recoverForMutation(references);
		if (state.current === null) return storeFailure(WASM_CATALOG_STORE_UNINITIALIZED, "the catalog store is uninitialized; bootstrap the first revision before appending");
		const appended = appendRuntimeCatalogRevision(state.current, expected, next, references);
		if (!appended.ok) return contractFailure(appended.errors);
		return this.persistAppendedRevision(state, appended.value, references);
	}

	// CVE revoke：追加标记 revoked 的 revision+1（不删除 entry）；重复 revoke → ALREADY_REVOKED fail-closed。
	revoke(expected: RuntimeCatalogRevisionPinV1, entryKey: string, revocation: RuntimeCatalogRevocationV1, references: readonly WasmCatalogEntryReferenceV1[] = []): WasmCatalogStoreOutcome<WasmCatalogRevisionResult> {
		const state = this.recoverForMutation(references);
		if (state.current === null) return storeFailure(WASM_CATALOG_STORE_UNINITIALIZED, "the catalog store is uninitialized; bootstrap the first revision before revoking");
		const revoked = revokeRuntimeCatalogEntry(state.current, expected, entryKey, revocation);
		if (!revoked.ok) return contractFailure(revoked.errors);
		return this.persistAppendedRevision(state, revoked.value, references);
	}

	// release：零受保护引用才可释放；产出带一年保留期的 receipt 并落盘。同 releaseId 重放幂等。
	release(input: WasmCatalogReleaseInput): WasmCatalogStoreOutcome<CatalogReleaseReceiptV1> {
		const state = this.recoverForMutation(input.references);
		const receiptPhysical = wasmCatalogPhysicalPath(this.root, catalogReleaseReceiptFilePath(input.releaseId));
		const existing = readCanonicalRecord(this.io, receiptPhysical, "catalog release receipt file");
		if (existing.status === "present") {
			const validated = validateCatalogReleaseReceiptV1(existing.value);
			if (!validated.ok) {
				throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "stored release receipt failed validation: " + firstIssueSummary(validated.errors));
			}
			const matches = validated.value.entryKey === input.entryKey &&
				validated.value.ownerCommandId === input.ownerCommandId &&
				validated.value.drainedAt === input.drainedAt &&
				validated.value.releasedAt === input.releasedAt;
			if (!matches) {
				return storeFailure(CATALOG_RELEASE_RECEIPT_STORE_MISMATCH, "releaseId " + input.releaseId + " already holds a receipt for a different release request");
			}
			return { ok: true, value: validated.value };
		}
		if (state.current === null) return storeFailure(WASM_CATALOG_STORE_UNINITIALIZED, "the catalog store is uninitialized; release requires a proven current revision");
		const request: CatalogReleaseRequestV1 = {
			catalog: state.current,
			entryKey: input.entryKey,
			references: input.references,
			releaseId: input.releaseId,
			ownerCommandId: input.ownerCommandId,
			drainedAt: input.drainedAt,
			releasedAt: input.releasedAt,
		};
		const receipt = releaseRuntimeCatalogEntry(request);
		if (!receipt.ok) return contractFailure(receipt.errors);
		writeCanonicalRecord(this.io, receiptPhysical, receipt.value);
		// 写后回读验证：receipt 是 GC 的资格凭证，落盘失败必须在使用前暴露。
		const readback = readCanonicalRecord(this.io, receiptPhysical, "catalog release receipt file");
		const readbackValid = readback.status === "present" ? validateCatalogReleaseReceiptV1(readback.value) : null;
		if (readbackValid === null || !readbackValid.ok || !jcsEqual(readbackValid.value, receipt.value)) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "release receipt readback diverged for releaseId " + input.releaseId);
		}
		// 刷新 index 的 retention/受保护计数快照（语义核心不变，不构成分歧）。
		this.writeRefreshedIndex(state.records, state.audits, [...state.receipts, receipt.value], input.references);
		return { ok: true, value: receipt.value };
	}

	// GC：先写 delete audit（写后回读验证），再删 revision 文件，再标记 index deleted。
	// 保留期内 / 有受保护引用 / receipt 不绑定 → 契约 fail-closed，文件保持原样；
	// 受保护引用失败会把引用计数写入下一次 index（spec 场景「GC races a new rollback reference」）。
	gc(input: WasmCatalogGcInput): WasmCatalogStoreOutcome<CatalogHistoryGcResultV1> {
		const state = this.recoverForMutation(input.references);
		const receipt = state.receipts.find((candidate) => candidate.releaseId === input.releaseId);
		if (receipt === undefined) {
			return storeFailure(CATALOG_RELEASE_RECEIPT_MISSING, "gc names releaseId " + input.releaseId + " whose release receipt does not exist");
		}
		const existingAudit = state.audits.find((candidate) => candidate.deleteId === input.deleteId) ?? null;
		const record = state.records.find((candidate) => candidate.revision === receipt.catalogRevision && candidate.catalogHash === receipt.catalogHash) ?? null;

		// 完成态重放：audit 已存在且 revision 文件已收集。
		if (record === null) {
			if (existingAudit !== null) {
				if (!this.auditMatchesRequest(existingAudit, receipt, input)) {
					return storeFailure(CATALOG_DELETE_AUDIT_STORE_MISMATCH, "deleteId " + input.deleteId + " already holds an audit for a different gc request");
				}
				const indexEntry = state.index?.revisions.find((entry) => entry.revision === existingAudit.revision) ?? null;
				if (indexEntry === null) {
					throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "the collected revision " + existingAudit.revision + " has no index entry");
				}
				return { ok: true, value: { audit: existingAudit, indexEntry } };
			}
			return storeFailure(CATALOG_HISTORY_RECORD_MISSING, "the release receipt names revision " + receipt.catalogRevision + " whose history file does not exist");
		}
		// 删除最后一个 present revision 会使 current 指针无法证明 → 预检 fail-closed。
		if (state.records.length === 1) {
			return storeFailure(CATALOG_HISTORY_LAST_PRESENT, "gc would remove the last present catalog history revision; append a replacement revision first");
		}
		const computed = gcCatalogHistoryRevision({
			record,
			receipt,
			references: input.references,
			deleteId: input.deleteId,
			ownerCommandId: input.ownerCommandId,
			deletedAt: input.deletedAt,
			reason: input.reason,
		});
		if (!computed.ok) {
			if (computed.errors.some((entry) => entry.code === WASM_CATALOG_ENTRY_PROTECTED)) {
				this.writeRefreshedIndex(state.records, state.audits, state.receipts, input.references);
			}
			return contractFailure(computed.errors);
		}
		if (existingAudit !== null) {
			// 崩溃恢复重入：audit 已持久化，核对一致后续走文件删除。
			if (!jcsEqual(existingAudit, computed.value.audit)) {
				return storeFailure(CATALOG_DELETE_AUDIT_STORE_MISMATCH, "deleteId " + input.deleteId + " already holds an audit for a different gc request");
			}
		} else {
			const auditPhysical = wasmCatalogPhysicalPath(this.root, catalogDeleteAuditFilePath(input.deleteId));
			writeCanonicalRecord(this.io, auditPhysical, computed.value.audit);
			// 审计缺失 fail-closed：audit 对象无法在盘上证明之前，绝不删除 revision 文件。
			const readback = readCanonicalRecord(this.io, auditPhysical, "catalog delete audit file");
			const readbackValid = readback.status === "present" ? validateCatalogDeleteAuditV1(readback.value) : null;
			if (readbackValid === null || !readbackValid.ok || !jcsEqual(readbackValid.value, computed.value.audit)) {
				throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "delete audit readback diverged for deleteId " + input.deleteId + "; the revision file is preserved");
			}
		}
		const revisionPhysical = wasmCatalogPhysicalPath(this.root, catalogHistoryRevisionFilePath(record.revision, record.catalogHash));
		this.io.deleteFile(revisionPhysical);
		const nextAudits = existingAudit !== null ? state.audits : [...state.audits, computed.value.audit];
		this.writeRefreshedIndex(
			state.records.filter((candidate) => candidate !== record),
			nextAudits,
			state.receipts,
			input.references,
		);
		return { ok: true, value: computed.value };
	}

	// owner 显式修复路径：诊断出 index/文件分歧后，以固定路径对象为准强制重建并落盘。
	rebuildIndex(references: readonly WasmCatalogEntryReferenceV1[] = []): WasmCatalogStoreOutcome<CatalogHistoryIndexV1> {
		const state = recoverState(this.io, this.root, references, this.now, { persistRepairs: true, ignoreStoredIndex: true });
		if (state.index === null) return storeFailure(WASM_CATALOG_STORE_UNINITIALIZED, "the catalog store holds no history objects to rebuild an index from");
		return { ok: true, value: state.index };
	}

	// --- 内部 ---

	private recoverReadonly(): WasmCatalogRecoveredState {
		return recoverState(this.io, this.root, [], this.now, { persistRepairs: false, ignoreStoredIndex: false });
	}

	private recoverForMutation(references: readonly WasmCatalogEntryReferenceV1[]): WasmCatalogRecoveredState {
		return recoverState(this.io, this.root, references, this.now, { persistRepairs: true, ignoreStoredIndex: false });
	}

	private persistAppendedRevision(state: WasmCatalogRecoveredState, catalog: RuntimeCatalogV1, references: readonly WasmCatalogEntryReferenceV1[] = []): WasmCatalogStoreOutcome<WasmCatalogRevisionResult> {
		const sealedRecord = sealCatalogHistoryRecordV1({
			schemaVersion: 1,
			runtimeKind: "wasm",
			revision: catalog.revision,
			catalogHash: catalog.catalogHash,
			catalog,
			storedAt: this.now(),
		});
		if (!sealedRecord.ok) return contractFailure(sealedRecord.errors);
		if (state.records.some((record) => record.revision === sealedRecord.value.revision)) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_DIVERGENT, "catalog revision " + sealedRecord.value.revision + " already exists; the append path must only create current.revision + 1");
		}
		const revisionPhysical = wasmCatalogPhysicalPath(this.root, catalogHistoryRevisionFilePath(sealedRecord.value.revision, sealedRecord.value.catalogHash));
		writeCanonicalRecord(this.io, revisionPhysical, sealedRecord.value);
		this.writeRefreshedIndex([...state.records, sealedRecord.value], state.audits, state.receipts, references);
		return { ok: true, value: { catalog, historyRecord: sealedRecord.value } };
	}

	private writeRefreshedIndex(records: readonly CatalogHistoryRecordV1[], audits: readonly CatalogDeleteAuditV1[], receipts: readonly CatalogReleaseReceiptV1[], references: readonly WasmCatalogEntryReferenceV1[]): void {
		const assembled = assembleCatalogHistoryIndex(records, audits, receipts, references, this.now());
		if (!assembled.ok) {
			throw new WasmCatalogStoreError(WASM_CATALOG_STORE_CORRUPT, "generated catalog history index failed validation: " + firstIssueSummary(assembled.errors));
		}
		writeCanonicalRecord(this.io, wasmCatalogPhysicalPath(this.root, CATALOG_HISTORY_INDEX_PATH), assembled.value);
	}

	private auditMatchesRequest(audit: CatalogDeleteAuditV1, receipt: CatalogReleaseReceiptV1, input: WasmCatalogGcInput): boolean {
		return audit.releaseId === receipt.releaseId &&
			audit.revision === receipt.catalogRevision &&
			audit.catalogHash === receipt.catalogHash &&
			audit.ownerCommandId === input.ownerCommandId &&
			audit.deletedAt === input.deletedAt &&
			audit.reason === input.reason;
	}
}

// 歧义备注（保守 fail-closed 取舍，供 review 与后续任务对照）：
// 1. 「当前 catalog」不落独立文件：spec 定义 current 指针 = index 的 (currentRevision, currentHash)
//    指向的最高 present 历史文件；另设「当前 catalog 文件」会制造第二权威并可分歧。任务描述中的
//    「当前 catalog」即此派生视图（store.current()）。
// 2. 恢复权威：revisions/receipts/audits 文件是唯一持久权威，index 是派生缓存——缺失或损坏
//    （不可解析/非 JCS/校验失败）时按 spec 场景自动重建；「有效 index 与文件语义核心不一致」
//    （current 指针或 (revision,hash,status) 三元组集合分歧，含 index 声称存在而文件缺失、或多出
//    未知 revision 文件）fail-closed 抛出，由 owner 显式 rebuildIndex 修复。
// 3. append 的崩溃窗口（revision 文件已写、index 未更新）在下次恢复时表现为「有效 index 缺少该
//    三元组」→ fail-closed 而非自动接受（spec「index/file disagreement fails closed」严格化）；
//    owner 以 rebuildIndex 确认后即恢复。gc 的崩溃窗口（audit 已写、文件未删）重入同一 gc 命令
//    即可确定性完成（audit 是 owner 批准删除的持久意图记录）。
// 4. delete audit 与 revision 文件同时存在 = GC 未完成（pending），index 仍按 present 记录；audit
//    存在而文件已消失才产生 deleted 条目。receipt 所绑定 revision 的文件与 audit 两者皆无 →
//    分歧 fail-closed（即「审计缺失 fail-closed」的恢复面）。
// 5. bootstrap 只接受空存储的完整首 revision payload（sealRuntimeCatalogV1 校验 revision >= 1，
//    不额外强制 revision === 1，备份部分恢复等场景可重播种）；重复 bootstrap fail-closed。
// 6. 幂等重放只存在于有对象键的 owner 操作：release 按 releaseId（文件存在 + 请求字段逐字相等）、
//    gc 按 deleteId（audit 已存且与请求派生字段一致；audit 在文件仍在时可重入完成删除）。append 与
//    revoke 没有 commandId 一类的对象键，spec 场景明确同一 expected pin 的第二次 append 一律
//    CATALOG_REVISION_CONFLICT（即使字节相同也不静默重放）、重复 revoke 一律 ALREADY_REVOKED；
//    调用方以冲突响应 + current() 读取对账崩溃点。
// 7. 受保护引用（active/ready-preparing/rollback）由调用方按 binding 状态扫描后以 references
//    传入；本模块不拥有 binding 状态，也不在存储内缓存引用快照（index 中的计数只是落盘时快照）。
// 8. owner 来源检查（拒绝 supervisor 来源更新）无法在本模块实现：supervisor socket 无 owner 凭据
//    通道（7.1 SO_PEERCRED 未落地，owner-key 授权在 Kernel 侧），故本模块只暴露类型化 store API，
//    不新增任何未授权路由；授权通道落地后由宿主在通道层做 origin 检查。
