// 用户原始需求（2026-08-13）：应用沙箱通过独立安全验收前，任意应用发布与执行必须保持关闭。
// 正交意图：要求显式开关；要求镜像验收证明；提供有界状态；默认失败关闭。
// 用户原始需求（2026-08-26，add-wasm-runtime 任务 4.3 + 7.8）：发布门 v2 与双 runtime gate——
// wasm 验收记录 v2 固定路径、精确键集、recordDigest 复算、节点 catalog/capability/arch 逐字段
// 相等；celld v1 与 wasm v2 并行评估、runtime-kind 精确选择、互不启用、无 fallback。
// 规范权威：openspec/changes/add-wasm-runtime/specs/wasm-application-runtime/spec.md
// "Wasm publication requires a canonical kind-bound acceptance record" 与
// "Runtime-kind publication gate selection is a dual-gate wire"。
// Rust 对位实现：kernel-rs/iweb-kernel/src/wasm_publication.rs（双实现同套断言见
// tests/wasm-publication-gate.test.ts；celld v1 行为与本文件旧版逐字一致）。
const fs = require("node:fs");
const { createHash } = require("node:crypto");

const DEFAULT_ACCEPTANCE_FILE = "/opt/iweb/release/sandbox-acceptance.json";
// wasm v2 验收记录固定 Kernel-owned 路径（spec 逐字；环境变量不得重定向）。
const WASM_ACCEPTANCE_FILE = "/opt/iweb/release/wasm-sandbox-acceptance.json";
const WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN = "iweb-wasm-acceptance-record-v2";

const ENV_APPLICATION_PUBLICATION_ENABLED = "IWEB_APPLICATION_PUBLICATION_ENABLED";
const ENV_WASM_PUBLICATION_ENABLED = "IWEB_WASM_PUBLICATION_ENABLED";
// 尝试重定向 wasm 验收记录路径的环境变量名（补充 fail-closed 名单；spec 未列举名字）。
const ENV_WASM_ACCEPTANCE_PATH_REDIRECTS = ["IWEB_WASM_SANDBOX_ACCEPTANCE_FILE", "IWEB_WASM_ACCEPTANCE_FILE"];

const RUNTIME_KIND_CELLD = "celld";
const RUNTIME_KIND_WASM = "wasm";

// spec GateResultV1.reasons 的稳定顺序（duplicate-free；成功 gate 为空数组）。
const GATE_REASON_ORDER = [
	"publication-not-requested",
	"sandbox-acceptance-missing",
	"wasm-acceptance-invalid",
	"wasm-identity-mismatch",
	"runtime-kind-mismatch",
	"capability-record-mismatch",
	"catalog-mismatch",
	"unsupported-architecture",
];
const REASON_PUBLICATION_NOT_REQUESTED = "publication-not-requested";
const REASON_SANDBOX_ACCEPTANCE_MISSING = "sandbox-acceptance-missing";
const REASON_WASM_ACCEPTANCE_INVALID = "wasm-acceptance-invalid";
const REASON_WASM_IDENTITY_MISMATCH = "wasm-identity-mismatch";
const REASON_RUNTIME_KIND_MISMATCH = "runtime-kind-mismatch";
const REASON_CAPABILITY_RECORD_MISMATCH = "capability-record-mismatch";
const REASON_CATALOG_MISMATCH = "catalog-mismatch";
const REASON_UNSUPPORTED_ARCHITECTURE = "unsupported-architecture";

const WASM_RUNTIME_ARCHITECTURES = ["linux/amd64", "linux/arm64"];
const WASM_WORLD_LITERAL = "wasi:http/proxy@0.2.8";
const WASM_HOST_ABI_LITERAL = "iweb-wasmd-abi@1.0.0";
const WASM_U53_MAX = 9007199254740991;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const OCI_SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CATALOG_ENTRY_KEY_PATTERN = /^[a-z][a-z0-9.-]{0,63}$/;

// ---------------------------------------------------------------------------
// celld v1 gate（行为与本文件旧版逐字一致；勿改）
// ---------------------------------------------------------------------------

function acceptanceRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (value.version !== 1 || value.result !== "passed" || value.gate !== "application-sandbox") return null;
  if (typeof value.evidenceDigest !== "string" || !/^[a-f0-9]{64}$/.test(value.evidenceDigest)) return null;
  return { version: 1, result: "passed", gate: "application-sandbox", evidenceDigest: value.evidenceDigest };
}

function evaluateApplicationPublicationGate(options = {}) {
  const environment = options.environment ?? process.env;
  const readText = options.readText ?? ((path) => fs.readFileSync(path, "utf8"));
  const requested = environment.IWEB_APPLICATION_PUBLICATION_ENABLED === "1";
  let accepted = false;
  try {
    accepted = acceptanceRecord(JSON.parse(readText(DEFAULT_ACCEPTANCE_FILE))) !== null;
  } catch {
    accepted = false;
  }
  const reasons = [];
  if (!requested) reasons.push("publication-not-requested");
  if (!accepted) reasons.push("sandbox-acceptance-missing");
  return Object.freeze({ enabled: requested && accepted, requested, accepted, reasons: Object.freeze(reasons) });
}

function requireApplicationPublication(gate) {
  if (!gate?.enabled) {
    const error = new Error("application publication is disabled until sandbox acceptance passes");
    error.code = "APPLICATION_PUBLICATION_DISABLED";
    throw error;
  }
}

// ---------------------------------------------------------------------------
// wasm v2：严格 JSON 解析（重复成员在覆盖前检测）与受限域 JCS
// ---------------------------------------------------------------------------

// 严格 JSON 解析器（对位 contracts parseStrictJson 的语义；本文件不得依赖 TS 模块）。
function parseStrictJsonText(text) {
  if (text.charCodeAt(0) === 0xfeff) return { ok: false, error: "byte-order mark is not valid JSON" };
  let pos = 0;
  try {
    skipWhitespace();
    const value = parseValue();
    skipWhitespace();
    if (pos !== text.length) throw new Error("unexpected trailing content after JSON value");
    return { ok: true, value };
  } catch (error) {
    return { ok: false, error: String(error && error.message ? error.message : error) };
  }

  function skipWhitespace() {
    while (pos < text.length) {
      const c = text.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
      else break;
    }
  }

  function parseValue() {
    const c = text[pos];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseString();
    if (text.startsWith("true", pos)) { pos += 4; return true; }
    if (text.startsWith("false", pos)) { pos += 5; return false; }
    if (text.startsWith("null", pos)) { pos += 4; return null; }
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    throw new Error("unexpected character in JSON at offset " + pos);
  }

  function parseObject() {
    pos++; // '{'
    const out = {};
    skipWhitespace();
    if (text[pos] === "}") { pos++; return out; }
    for (;;) {
      skipWhitespace();
      if (text[pos] !== '"') throw new Error("object member name must be a string");
      const key = parseString();
      skipWhitespace();
      if (text[pos] !== ":") throw new Error("expected ':' after object member name");
      pos++;
      skipWhitespace();
      if (Object.prototype.hasOwnProperty.call(out, key)) {
        throw new Error('duplicate object member name "' + key + '" must be rejected before last-value override');
      }
      out[key] = parseValue();
      skipWhitespace();
      if (text[pos] === ",") { pos++; continue; }
      if (text[pos] === "}") { pos++; return out; }
      throw new Error("expected ',' or '}' in object");
    }
  }

  function parseArray() {
    pos++; // '['
    const out = [];
    skipWhitespace();
    if (text[pos] === "]") { pos++; return out; }
    for (;;) {
      skipWhitespace();
      out.push(parseValue());
      skipWhitespace();
      if (text[pos] === ",") { pos++; continue; }
      if (text[pos] === "]") { pos++; return out; }
      throw new Error("expected ',' or ']' in array");
    }
  }

  function parseString() {
    pos++; // '"'
    let out = "";
    for (;;) {
      if (pos >= text.length) throw new Error("unterminated string");
      const c = text.charCodeAt(pos);
      if (c === 0x22) { pos++; return out; }
      if (c === 0x5c) {
        pos++;
        const escape = text[pos];
        if (escape === '"') out += '"';
        else if (escape === "\\") out += "\\";
        else if (escape === "/") out += "/";
        else if (escape === "b") out += "\b";
        else if (escape === "f") out += "\f";
        else if (escape === "n") out += "\n";
        else if (escape === "r") out += "\r";
        else if (escape === "t") out += "\t";
        else if (escape === "u") {
          const hex = text.slice(pos + 1, pos + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error("invalid \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          pos += 4;
        } else throw new Error("invalid string escape");
        pos++;
        continue;
      }
      if (c < 0x20) throw new Error("unescaped control character in string");
      out += text[pos];
      pos++;
    }
  }

  function parseNumber() {
    const start = pos;
    if (text[pos] === "-") pos++;
    if (text[pos] === "0") {
      pos++;
    } else if (text[pos] >= "1" && text[pos] <= "9") {
      while (pos < text.length && text[pos] >= "0" && text[pos] <= "9") pos++;
    } else {
      throw new Error("invalid number");
    }
    if (text[pos] === ".") {
      pos++;
      if (!(text[pos] >= "0" && text[pos] <= "9")) throw new Error("invalid number fraction");
      while (pos < text.length && text[pos] >= "0" && text[pos] <= "9") pos++;
    }
    if (text[pos] === "e" || text[pos] === "E") {
      pos++;
      if (text[pos] === "+" || text[pos] === "-") pos++;
      if (!(text[pos] >= "0" && text[pos] <= "9")) throw new Error("invalid number exponent");
      while (pos < text.length && text[pos] >= "0" && text[pos] <= "9") pos++;
    }
    return Number(text.slice(start, pos));
  }
}

// 受限域 JCS 序列化（null/bool/string/安全整数/数组/普通对象；键按 UTF-8 字节序——
// 全 ASCII 域内与 RFC 8785 一致；非 ASCII/浮点/孤立代理对一律报错 fail-closed）。
function jcsStringify(value) {
  return serializeValue(value);

  function serializeValue(node) {
    if (node === null) return "null";
    switch (typeof node) {
      case "boolean":
        return node ? "true" : "false";
      case "number": {
        if (!Number.isInteger(node) || !Number.isSafeInteger(node)) {
          throw new Error("only u53 safe integers are part of the canonical record domain");
        }
        return String(node);
      }
      case "string":
        return serializeString(node);
      case "object": {
        if (Array.isArray(node)) return "[" + node.map(serializeValue).join(",") + "]";
        const proto = Object.getPrototypeOf(node);
        if (proto !== Object.prototype && proto !== null) throw new Error("only plain JSON objects are serializable as JCS");
        const keys = Object.keys(node).sort(compareUtf8Bytes);
        return "{" + keys.map((key) => serializeString(key) + ":" + serializeValue(node[key])).join(",") + "}";
      }
      default:
        throw new Error("value of type " + typeof node + " is not canonical JSON");
    }
  }

  function serializeString(node) {
    let out = '"';
    for (let i = 0; i < node.length; i++) {
      const unit = node.charCodeAt(i);
      if (unit === 0x22) out += '\\"';
      else if (unit === 0x5c) out += "\\\\";
      else if (unit === 0x08) out += "\\b";
      else if (unit === 0x09) out += "\\t";
      else if (unit === 0x0a) out += "\\n";
      else if (unit === 0x0c) out += "\\f";
      else if (unit === 0x0d) out += "\\r";
      else if (unit < 0x20) out += "\\u00" + unit.toString(16).padStart(2, "0");
      else if (unit >= 0xd800 && unit <= 0xdfff) throw new Error("lone surrogate is not valid Unicode for JCS");
      else out += node[i];
    }
    return out + '"';
  }
}

function compareUtf8Bytes(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

// ---------------------------------------------------------------------------
// wasm v2 acceptance record：键集、文法、JCS 字节相等、recordDigest 复算
// ---------------------------------------------------------------------------

const WASM_ACCEPTANCE_RECORD_KEYS = [
  "version",
  "result",
  "gate",
  "runtimeKind",
  "runtimeImageDigest",
  "hostABI",
  "world",
  "arch",
  "capabilityRecordRevision",
  "capabilityRecordHash",
  "catalogRevision",
  "catalogHash",
  "catalogEntryKey",
  "evidenceDigest",
  "recordDigest",
];

function isPlainRecord(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validateWasmAcceptanceRecordFields(record) {
  for (const key of Object.keys(record)) {
    if (!WASM_ACCEPTANCE_RECORD_KEYS.includes(key)) return "unknown field is not allowed: " + key;
  }
  for (const key of WASM_ACCEPTANCE_RECORD_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) return "required field is missing: " + key;
  }
  if (record.version !== 2) return "version must be the literal 2";
  if (record.result !== "passed") return 'result must be exactly "passed"';
  if (record.gate !== "application-sandbox") return 'gate must be exactly "application-sandbox"';
  if (record.runtimeKind !== RUNTIME_KIND_WASM) return 'runtimeKind must be exactly "wasm"';
  if (typeof record.runtimeImageDigest !== "string" || !OCI_SHA256_PATTERN.test(record.runtimeImageDigest)) {
    return "runtimeImageDigest must be sha256: plus 64 lower-case hex characters";
  }
  if (record.hostABI !== WASM_HOST_ABI_LITERAL) return "hostABI must be exactly the matrix ABI literal";
  if (record.world !== WASM_WORLD_LITERAL) return "world must be exactly the matrix world literal";
  if (!WASM_RUNTIME_ARCHITECTURES.includes(record.arch)) return "arch must be one of linux/amd64 or linux/arm64";
  for (const [field, minimum] of [["capabilityRecordRevision", 1], ["catalogRevision", 1]]) {
    if (!Number.isSafeInteger(record[field]) || record[field] < minimum || record[field] > WASM_U53_MAX) {
      return field + " must be a u53 integer >= 1";
    }
  }
  for (const field of ["capabilityRecordHash", "catalogHash", "evidenceDigest", "recordDigest"]) {
    if (typeof record[field] !== "string" || !SHA256_HEX_PATTERN.test(record[field])) {
      return field + " must be 64 lower-case hex characters";
    }
  }
  if (typeof record.catalogEntryKey !== "string" || !CATALOG_ENTRY_KEY_PATTERN.test(record.catalogEntryKey)) {
    return "catalogEntryKey must match ^[a-z][a-z0-9.-]{0,63}$";
  }
  return null;
}

/** digest 输入对象：record 去掉 recordDigest 本身（spec 逐字）。 */
function wasmAcceptanceRecordPayload(record) {
  const { recordDigest: _omitted, ...payload } = record;
  return payload;
}

/** `recordDigest = hex(SHA-256(UTF8("iweb-wasm-acceptance-record-v2\n" || JCS(record with recordDigest omitted))))`。 */
function computeWasmAcceptanceRecordDigestV2(record) {
  const jcs = jcsStringify(wasmAcceptanceRecordPayload(record));
  return createHash("sha256")
    .update(Buffer.from(WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN + "\n", "utf8"))
    .update(Buffer.from(jcs, "utf8"))
    .digest("hex");
}

/**
 * 完整 v2 校验（纯文本输入）：严格解析（重复成员拒绝）→ 精确键集 + 字段文法 →
 * 原始字节等于 JCS(parse(bytes)) → recordDigest 复算。
 * 返回 null 表示拒绝（理由不进入公开响应；owner 侧由 reasons wire 承载）。
 */
function validateWasmAcceptanceRecordV2(text) {
  const parsed = parseStrictJsonText(text);
  if (!parsed.ok || !isPlainRecord(parsed.value)) return null;
  const record = parsed.value;
  if (validateWasmAcceptanceRecordFields(record) !== null) return null;
  let canonical;
  try {
    canonical = jcsStringify(record);
  } catch {
    return null;
  }
  if (Buffer.compare(Buffer.from(text, "utf8"), Buffer.from(canonical, "utf8")) !== 0) return null;
  let digest;
  try {
    digest = computeWasmAcceptanceRecordDigestV2(record);
  } catch {
    return null;
  }
  if (digest !== record.recordDigest) return null;
  return { ...record };
}

// ---------------------------------------------------------------------------
// 双 runtime gate：wasm v2 评估 + PublicationGateSetV1 + runtime-kind 选择
// ---------------------------------------------------------------------------

function pushReasonStable(reasons, reason) {
  if (reasons.includes(reason)) return;
  const position = GATE_REASON_ORDER.indexOf(reason);
  let insertAt = reasons.length;
  for (let i = 0; i < reasons.length; i++) {
    if (GATE_REASON_ORDER.indexOf(reasons[i]) > position) {
      insertAt = i;
      break;
    }
  }
  reasons.splice(insertAt, 0, reason);
}

function gateResult(runtimeKind, enabled, requested, accepted, reasons) {
  return Object.freeze({
    schemaVersion: 1,
    runtimeKind,
    enabled,
    requested,
    accepted,
    reasons: Object.freeze(reasons),
  });
}

/** 节点 pin 视图（wasm gate 逐字段相等比较的输入）。 */
function isPlainNodeIdentity(node) {
  return (
    isPlainRecord(node) &&
    typeof node.architecture === "string" &&
    Number.isSafeInteger(node.capabilityRecordRevision) &&
    typeof node.capabilityRecordHash === "string" &&
    Number.isSafeInteger(node.catalogRevision) &&
    typeof node.catalogHash === "string" &&
    isPlainRecord(node.catalogEntry) &&
    typeof node.catalogEntry.entryKey === "string" &&
    typeof node.catalogEntry.imageDigest === "string" &&
    typeof node.catalogEntry.hostABI === "string" &&
    typeof node.catalogEntry.world === "string"
  );
}

function detectWasmPathRedirect(environment) {
  for (const name of ENV_WASM_ACCEPTANCE_PATH_REDIRECTS) {
    const value = environment[name];
    if (value !== undefined && value !== "") return name;
  }
  return null;
}

/**
 * wasm v2 gate：固定路径记录 + 节点 pin + 双开关 → GateResultV1。
 * 双开关（fail-closed 取舍）：wasm 发布同时要求 IWEB_APPLICATION_PUBLICATION_ENABLED=1
 * （application switch）与 IWEB_WASM_PUBLICATION_ENABLED=1。
 */
function evaluateWasmPublicationGate(options = {}) {
  const environment = options.environment ?? process.env;
  const readText = options.readText ?? ((path) => fs.readFileSync(path, "utf8"));
  const node = isPlainNodeIdentity(options.node) ? options.node : null;
  const requested = environment[ENV_APPLICATION_PUBLICATION_ENABLED] === "1" && environment[ENV_WASM_PUBLICATION_ENABLED] === "1";
  const reasons = [];
  if (!requested) reasons.push(REASON_PUBLICATION_NOT_REQUESTED);
  let accepted = false;
  let identityOk = true;
  const redirect = detectWasmPathRedirect(environment);
  if (redirect !== null) {
    // fail-closed：固定路径不可被环境变量重定向；检测到尝试即拒绝且不读任何文件。
    reasons.push(REASON_WASM_ACCEPTANCE_INVALID);
  } else {
    let text = null;
    try {
      text = readText(WASM_ACCEPTANCE_FILE);
    } catch {
      text = null;
    }
    if (text === null) {
      reasons.push(REASON_SANDBOX_ACCEPTANCE_MISSING);
    } else {
      const record = validateWasmAcceptanceRecordV2(text);
      if (record === null) {
        reasons.push(REASON_WASM_ACCEPTANCE_INVALID);
      } else {
        accepted = true;
        if (node === null) {
          // 未加载节点 pin：三项 pin 比较全部按失配关闭，不推断默认值。
          reasons.push(REASON_WASM_IDENTITY_MISMATCH, REASON_CAPABILITY_RECORD_MISMATCH, REASON_CATALOG_MISMATCH);
          identityOk = false;
        } else {
          if (!WASM_RUNTIME_ARCHITECTURES.includes(node.architecture) || record.arch !== node.architecture) {
            reasons.push(REASON_UNSUPPORTED_ARCHITECTURE);
            identityOk = false;
          }
          if (record.capabilityRecordRevision !== node.capabilityRecordRevision || record.capabilityRecordHash !== node.capabilityRecordHash) {
            reasons.push(REASON_CAPABILITY_RECORD_MISMATCH);
            identityOk = false;
          }
          if (record.catalogRevision !== node.catalogRevision || record.catalogHash !== node.catalogHash) {
            reasons.push(REASON_CATALOG_MISMATCH);
            identityOk = false;
          }
          if (
            record.catalogEntryKey !== node.catalogEntry.entryKey ||
            record.runtimeImageDigest !== node.catalogEntry.imageDigest ||
            record.hostABI !== node.catalogEntry.hostABI ||
            record.world !== node.catalogEntry.world
          ) {
            reasons.push(REASON_WASM_IDENTITY_MISMATCH);
            identityOk = false;
          }
        }
      }
    }
  }
  reasons.sort((left, right) => GATE_REASON_ORDER.indexOf(left) - GATE_REASON_ORDER.indexOf(right));
  return gateResult(RUNTIME_KIND_WASM, requested && accepted && identityOk, requested, accepted, reasons);
}

/** 现行 celld gate 结果 → GateResultV1 投影（保留 enabled/requested/accepted/reasons 语义）。 */
function celldGateResultFromV1(result) {
  const reasons = [];
  if (!result.requested) reasons.push(REASON_PUBLICATION_NOT_REQUESTED);
  if (!result.accepted) reasons.push(REASON_SANDBOX_ACCEPTANCE_MISSING);
  return gateResult(RUNTIME_KIND_CELLD, result.enabled, result.requested, result.accepted, reasons);
}

/**
 * 启动时并行评估两个 runtime kind（spec「The v2 gate is connected at startup in this order」）：
 * (1) 现行 celld gate；(2) 独立读取并校验固定 wasm 验收记录；(3) 发布不可变
 * PublicationGateSetV1。readText 只会被以两个固定路径常量调用；两 gate 互不启用、无 fallback。
 */
function evaluatePublicationGateSet(options = {}) {
  const environment = options.environment ?? process.env;
  const readText = options.readText ?? ((path) => fs.readFileSync(path, "utf8"));
  const celld = celldGateResultFromV1(evaluateApplicationPublicationGate({ environment, readText }));
  const wasm = evaluateWasmPublicationGate({ environment, readText, node: options.node });
  return Object.freeze({ schemaVersion: 1, celld, wasm });
}

function selectionResponse(gate) {
  return Object.freeze({ schemaVersion: 1, runtimeKind: gate.runtimeKind, enabled: gate.enabled, reasons: gate.reasons });
}

/**
 * `selectPublicationGate(runtimeKind, PublicationGateSetV1)`：celld 返回现行 v1 gate 契约
 * 结果、wasm 返回 v2 validator 结果、其它值抛 RUNTIME_KIND_UNSUPPORTED typed error，
 * 不尝试任何一个 parser。
 */
function selectPublicationGate(runtimeKind, gateSet) {
  if (!gateSet || gateSet.schemaVersion !== 1) {
    const error = new Error("a PublicationGateSetV1 is required");
    error.code = "RUNTIME_KIND_UNSUPPORTED";
    throw error;
  }
  if (runtimeKind === RUNTIME_KIND_CELLD) return selectionResponse(gateSet.celld);
  if (runtimeKind === RUNTIME_KIND_WASM) return selectionResponse(gateSet.wasm);
  const error = new Error("runtime kind '" + String(runtimeKind) + "' has no publication gate; no parser is tried");
  error.code = "RUNTIME_KIND_UNSUPPORTED";
  throw error;
}

/** 跨 kind 守卫：把一个 gate 的结果喂给另一个 runtime kind 时返回 disabled 结果并合并 runtime-kind-mismatch。 */
function publicationGateForRuntimeKind(gate, runtimeKind) {
  if (gate.runtimeKind === runtimeKind) return gate;
  const reasons = [...gate.reasons];
  pushReasonStable(reasons, REASON_RUNTIME_KIND_MISMATCH);
  return gateResult(runtimeKind, false, gate.requested, gate.accepted, reasons);
}

/** wasm 发布守卫（对位 requireApplicationPublication 的 wasm 版）。 */
function requireWasmPublication(gate) {
  if (!gate || gate.runtimeKind !== RUNTIME_KIND_WASM || !gate.enabled) {
    const error = new Error("wasm publication is disabled until the v2 acceptance record passes");
    error.code = "WASM_PUBLICATION_DISABLED";
    throw error;
  }
}

module.exports = {
  DEFAULT_ACCEPTANCE_FILE,
  WASM_ACCEPTANCE_FILE,
  WASM_ACCEPTANCE_RECORD_DIGEST_DOMAIN,
  ENV_APPLICATION_PUBLICATION_ENABLED,
  ENV_WASM_PUBLICATION_ENABLED,
  ENV_WASM_ACCEPTANCE_PATH_REDIRECTS,
  GATE_REASON_ORDER,
  evaluateApplicationPublicationGate,
  requireApplicationPublication,
  parseStrictJsonText,
  jcsStringify,
  computeWasmAcceptanceRecordDigestV2,
  validateWasmAcceptanceRecordV2,
  evaluateWasmPublicationGate,
  evaluatePublicationGateSet,
  selectPublicationGate,
  publicationGateForRuntimeKind,
  requireWasmPublication,
};
