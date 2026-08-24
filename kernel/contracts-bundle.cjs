var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __hasOwnProp = Object.prototype.hasOwnProperty;
function __accessProp(key) {
  return this[key];
}
var __toCommonJS = (from) => {
  var entry = (__moduleCache ??= new WeakMap).get(from), desc;
  if (entry)
    return entry;
  entry = __defProp({}, "__esModule", { value: true });
  if (from && typeof from === "object" || typeof from === "function") {
    for (var key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(entry, key))
        __defProp(entry, key, {
          get: __accessProp.bind(from, key),
          enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
        });
  }
  __moduleCache.set(from, entry);
  return entry;
};
var __moduleCache;
var __returnValue = (v) => v;
function __exportSetter(name, newValue) {
  this[name] = __returnValue.bind(null, newValue);
}
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: __exportSetter.bind(all, name)
    });
};

// kernel/contracts-entry.ts
var exports_contracts_entry = {};
__export(exports_contracts_entry, {
  versionLabel: () => versionLabel,
  versionDigest: () => versionDigest,
  validateVersionDeploymentRecord: () => validateVersionDeploymentRecord,
  validateTimestamp: () => validateTimestamp,
  validateSupervisorResponse: () => validateSupervisorResponse,
  validateStorageSecret: () => validateStorageSecret,
  validateSha256Digest: () => validateSha256Digest,
  validateObjectEndpoint: () => validateObjectEndpoint,
  validateObjectCredentialRecord: () => validateObjectCredentialRecord,
  validateCredentialString: () => validateCredentialString,
  validateControlStateFile: () => validateControlStateFile,
  validateBucketName: () => validateBucketName,
  validateApplicationManifest: () => validateApplicationManifest,
  validateApplicationId: () => validateApplicationId,
  systemControlStoreIO: () => systemControlStoreIO,
  setVersionLifecycle: () => setVersionLifecycle,
  sanitizeMonitorFrame: () => sanitizeMonitorFrame,
  routeAction: () => routeAction,
  rollbackVersion: () => rollbackVersion,
  resolveRoute: () => resolveRoute,
  resolvePublicObject: () => resolvePublicObject,
  resolveActiveSandboxId: () => resolveActiveSandboxId,
  removeVersion: () => removeVersion,
  readinessUrl: () => readinessUrl,
  projectSandboxResources: () => projectSandboxResources,
  probeReadiness: () => probeReadiness,
  parsePublicObjectSet: () => parsePublicObjectSet,
  parseHealthPayload: () => parseHealthPayload,
  packageFilesDigest: () => packageFilesDigest,
  normalizePublicObjectPath: () => normalizePublicObjectPath,
  markVersionReady: () => markVersionReady,
  handleVersionAction: () => handleVersionAction,
  emptyControlStateFile: () => emptyControlStateFile,
  emptyControlState: () => emptyControlState,
  deriveSandboxId: () => deriveSandboxId,
  deploymentRecordMatches: () => deploymentRecordMatches,
  correlateResponse: () => correlateResponse,
  controlStateToFile: () => controlStateToFile,
  controlStateFromFile: () => controlStateFromFile,
  collectPackage: () => collectPackage,
  admitVersion: () => admitVersion,
  activateVersion: () => activateVersion,
  PROTOCOL_VERSION: () => PROTOCOL_VERSION,
  ControlStore: () => ControlStore
});
module.exports = __toCommonJS(exports_contracts_entry);

// contracts/validation.ts
var MAX_VALIDATION_ERRORS = 50;
var OPAQUE_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
var SHA256_PATTERN = /^[a-f0-9]{64}$/;
var DNS_NAME_PATTERN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
var SAFE_RELATIVE_PATH_PATTERN = /^[A-Za-z0-9._@+=-]+(?:\/[A-Za-z0-9._@+=-]+)*$/;
function ok(value) {
  return { ok: true, value };
}
function failure(issues) {
  return { ok: false, errors: issues.slice(0, MAX_VALIDATION_ERRORS) };
}
function issue(code, path, message) {
  return { code, path: boundedText(path, 200), message: boundedText(message, 200) };
}
function boundedText(value, max = 200) {
  return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").replace(/\s+/g, " ").trim().slice(0, max);
}
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function boundedKey(value, max = 40) {
  return boundedText(value, max);
}
function validateOpaqueId(value, path, fieldName, errors) {
  if (typeof value !== "string" || !OPAQUE_ID_PATTERN.test(value)) {
    errors.push(issue("INVALID_IDENTIFIER", path, fieldName + " must be a lowercase opaque identifier"));
    return null;
  }
  return value;
}
function validateSha256(value, path, fieldName, errors) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    errors.push(issue("INVALID_DIGEST", path, fieldName + " must be a 64-character lowercase hex digest"));
    return null;
  }
  return value;
}
function validateInteger(value, path, fieldName, minimum, maximum, errors) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    errors.push(issue("INVALID_NUMBER", path, fieldName + " must be an integer between " + minimum + " and " + maximum));
    return null;
  }
  return value;
}
function validateDnsName(value, path, fieldName, errors) {
  if (typeof value !== "string" || !DNS_NAME_PATTERN.test(value) || isIpLiteral(value)) {
    errors.push(issue("INVALID_HOST", path, fieldName + " must be a DNS name, not an address literal"));
    return null;
  }
  return value;
}
function validateSafeRelativePath(value, path, fieldName, errors) {
  if (typeof value !== "string" || !SAFE_RELATIVE_PATH_PATTERN.test(value) || value.length > 512) {
    errors.push(issue("INVALID_PATH", path, fieldName + " must be a bounded relative path without traversal"));
    return null;
  }
  if (value.startsWith("/") || value.split("/").some((segment) => segment === ".." || segment === "." || segment === "")) {
    errors.push(issue("INVALID_PATH", path, fieldName + " must not contain absolute or traversal segments"));
    return null;
  }
  return value;
}
function rejectUnknownFields(input, path, allowed, errors) {
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) {
      errors.push(issue("UNKNOWN_FIELD", path + "/" + boundedKey(key), "unknown field is not allowed"));
    }
  }
}
function isIpLiteral(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(":") || value === "localhost";
}

// contracts/manifest.ts
var MANIFEST_SCHEMA_VERSION = 1;
var MAX_EGRESS_RULES = 256;
var RESOURCE_BOUNDS = {
  cpuMillisMin: 1,
  cpuMillisMax: 1e6,
  memoryBytesMin: 1,
  memoryBytesMax: 64 * 2 ** 30,
  pidLimitMin: 1,
  pidLimitMax: 1e6,
  storageBytesMin: 0,
  storageBytesMax: 2 ** 40
};
var CELD_VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
function validateRuntime(input, path) {
  const errors = [];
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", path, "runtime must be an object")]);
  rejectUnknownFields(input, path, ["kind", "celldVersion", "entrypoint"], errors);
  if (input.kind !== "celld")
    errors.push(issue("INVALID_RUNTIME", path + "/kind", "runtime kind must be celld"));
  const celldVersion = typeof input.celldVersion === "string" && CELD_VERSION_PATTERN.test(input.celldVersion) ? input.celldVersion : null;
  if (celldVersion === null)
    errors.push(issue("INVALID_VERSION", path + "/celldVersion", "celldVersion must be a pinned semver"));
  const entrypoint = typeof input.entrypoint === "string" ? input.entrypoint : null;
  if (entrypoint === null || !entrypoint.endsWith(".js"))
    errors.push(issue("INVALID_ENTRYPOINT", path + "/entrypoint", "entrypoint must be a .js module"));
  else
    validateSafeRelativePath(entrypoint, path + "/entrypoint", "entrypoint", errors);
  if (errors.length)
    return failure(errors);
  return ok({ kind: "celld", celldVersion, entrypoint });
}
function validateAssets(input, path) {
  const errors = [];
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", path, "assets must be an object")]);
  rejectUnknownFields(input, path, ["root"], errors);
  const root = validateSafeRelativePath(input.root, path + "/root", "assets.root", errors);
  if (errors.length)
    return failure(errors);
  return ok({ root });
}
function validateResources(input, path) {
  const errors = [];
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", path, "resources must be an object")]);
  rejectUnknownFields(input, path, ["cpuMillis", "memoryBytes", "pidLimit", "storageBytes"], errors);
  const cpuMillis = validateInteger(input.cpuMillis, path + "/cpuMillis", "cpuMillis", RESOURCE_BOUNDS.cpuMillisMin, RESOURCE_BOUNDS.cpuMillisMax, errors);
  const memoryBytes = validateInteger(input.memoryBytes, path + "/memoryBytes", "memoryBytes", RESOURCE_BOUNDS.memoryBytesMin, RESOURCE_BOUNDS.memoryBytesMax, errors);
  const pidLimit = validateInteger(input.pidLimit, path + "/pidLimit", "pidLimit", RESOURCE_BOUNDS.pidLimitMin, RESOURCE_BOUNDS.pidLimitMax, errors);
  const storageBytes = validateInteger(input.storageBytes, path + "/storageBytes", "storageBytes", RESOURCE_BOUNDS.storageBytesMin, RESOURCE_BOUNDS.storageBytesMax, errors);
  if (errors.length)
    return failure(errors);
  return ok({ cpuMillis, memoryBytes, pidLimit, storageBytes });
}
function validateStorage(input, path) {
  const errors = [];
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", path, "storage must be an object")]);
  rejectUnknownFields(input, path, ["persistent", "requestBytes"], errors);
  if (typeof input.persistent !== "boolean")
    errors.push(issue("INVALID_BOOLEAN", path + "/persistent", "persistent must be a boolean"));
  const requestBytes = validateInteger(input.requestBytes, path + "/requestBytes", "requestBytes", RESOURCE_BOUNDS.storageBytesMin, RESOURCE_BOUNDS.storageBytesMax, errors);
  if (errors.length)
    return failure(errors);
  return ok({ persistent: input.persistent === true, requestBytes });
}
function validateEgress(input, path) {
  const errors = [];
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", path, "egress must be an object")]);
  rejectUnknownFields(input, path, ["default", "allow"], errors);
  if (input.default !== "deny")
    errors.push(issue("INVALID_EGRESS_DEFAULT", path + "/default", "egress default must be deny"));
  if (!Array.isArray(input.allow)) {
    errors.push(issue("INVALID_EGRESS", path + "/allow", "egress allow must be an array"));
    return failure(errors);
  }
  if (input.allow.length > MAX_EGRESS_RULES) {
    errors.push(issue("INVALID_EGRESS", path + "/allow", "egress allow list exceeds the maximum length"));
    return failure(errors);
  }
  const allow = [];
  input.allow.forEach((entry, index) => {
    if (!isRecord(entry)) {
      errors.push(issue("TYPE_OBJECT", path + "/allow/" + index, "egress rule must be an object"));
      return;
    }
    rejectUnknownFields(entry, path + "/allow/" + index, ["host", "port"], errors);
    const host = validateDnsName(entry.host, path + "/allow/" + index + "/host", "host", errors);
    const port = validateInteger(entry.port, path + "/allow/" + index + "/port", "port", 1, 65535, errors);
    if (host !== null && port !== null)
      allow.push({ host, port });
  });
  if (errors.length)
    return failure(errors);
  return ok({ default: "deny", allow });
}
function validateApplicationManifest(input) {
  const errors = [];
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", "", "manifest must be an object")]);
  rejectUnknownFields(input, "", ["schemaVersion", "name", "runtime", "assets", "resources", "storage", "egress"], errors);
  if (input.schemaVersion !== MANIFEST_SCHEMA_VERSION)
    errors.push(issue("INVALID_VERSION", "/schemaVersion", "schemaVersion must be " + MANIFEST_SCHEMA_VERSION));
  const name = validateOpaqueId(input.name, "/name", "name", errors);
  const runtime = validateRuntime(input.runtime, "/runtime");
  if (!runtime.ok)
    errors.push(...runtime.errors);
  const assets = validateAssets(input.assets, "/assets");
  if (!assets.ok)
    errors.push(...assets.errors);
  const resources = validateResources(input.resources, "/resources");
  if (!resources.ok)
    errors.push(...resources.errors);
  const storage = validateStorage(input.storage, "/storage");
  if (!storage.ok)
    errors.push(...storage.errors);
  const egress = validateEgress(input.egress, "/egress");
  if (!egress.ok)
    errors.push(...egress.errors);
  if (storage.ok && resources.ok && storage.value.requestBytes > resources.value.storageBytes) {
    errors.push(issue("STORAGE_EXCEEDS_POLICY", "/storage/requestBytes", "storage request exceeds the declared storage policy"));
  }
  if (errors.length)
    return failure(errors);
  return ok({
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    name,
    runtime: runtime.value,
    assets: assets.value,
    resources: resources.value,
    storage: storage.value,
    egress: egress.value
  });
}

// contracts/records.ts
function versionLabel(identity) {
  return identity.digest + "-" + identity.sequence;
}
var LIFECYCLE_STATES = ["admitted", "preparing", "ready", "active", "retired", "stopped", "failed"];
function validateVersionIdentity(input) {
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", "", "version identity must be an object")]);
  const errors = [];
  rejectUnknownFields(input, "", ["applicationId", "digest", "sequence"], errors);
  const applicationId = validateOpaqueId(input.applicationId, "/applicationId", "applicationId", errors);
  const digest = validateSha256(input.digest, "/digest", "digest", errors);
  const sequence = validateInteger(input.sequence, "/sequence", "sequence", 1, Number.MAX_SAFE_INTEGER, errors);
  if (errors.length)
    return failure(errors);
  return ok({ applicationId, digest, sequence });
}
function validateNormalizedPolicy(input) {
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", "", "policy must be an object")]);
  const errors = [];
  rejectUnknownFields(input, "", ["resources", "egress"], errors);
  const resources = validateResources(input.resources, "/resources");
  if (!resources.ok)
    errors.push(...resources.errors);
  const egress = validateEgress(input.egress, "/egress");
  if (!egress.ok)
    errors.push(...egress.errors);
  if (errors.length)
    return failure(errors);
  return ok({
    resources: resources.value,
    egress: egress.value
  });
}
function validateResourceLimits(input, path) {
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", path, "limits must be an object")]);
  const errors = [];
  rejectUnknownFields(input, path, ["cpuMillis", "memoryBytes", "pidLimit", "storageBytes"], errors);
  const component = (value, field) => {
    if (value === null)
      return null;
    const parsed = validateInteger(value, path + "/" + field, field, 0, Number.MAX_SAFE_INTEGER, errors);
    return parsed;
  };
  const cpuMillis = component(input.cpuMillis, "cpuMillis");
  const memoryBytes = component(input.memoryBytes, "memoryBytes");
  const pidLimit = component(input.pidLimit, "pidLimit");
  const storageBytes = component(input.storageBytes, "storageBytes");
  if (errors.length)
    return failure(errors);
  return ok({ cpuMillis, memoryBytes, pidLimit, storageBytes });
}
function validateMeasuredValue(input, path, fieldName, errors) {
  if (!isRecord(input)) {
    errors.push(issue("TYPE_OBJECT", path, fieldName + " must be an object"));
    return null;
  }
  rejectUnknownFields(input, path, ["available", "value"], errors);
  if (input.available !== true && input.available !== false) {
    errors.push(issue("INVALID_AVAILABILITY", path + "/available", fieldName + " must carry an availability flag"));
    return null;
  }
  if (input.available === true) {
    const value = validateInteger(input.value, path + "/value", fieldName + " value", 0, Number.MAX_SAFE_INTEGER, errors);
    if (errors.length)
      return null;
    return { available: true, value };
  }
  if (input.value !== undefined) {
    errors.push(issue("UNEXPECTED_FIELD", path + "/value", fieldName + " unavailable must not carry a value"));
    return null;
  }
  return { available: false };
}
function validateResourceSample(input) {
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", "", "resource sample must be an object")]);
  const errors = [];
  rejectUnknownFields(input, "", ["versionId", "sampledAt", "cpuMillis", "memoryBytes", "pidCount", "terminated", "limits"], errors);
  const versionId = validateOpaqueId(input.versionId, "/versionId", "versionId", errors);
  const sampledAt = typeof input.sampledAt === "string" && !Number.isNaN(Date.parse(input.sampledAt)) ? input.sampledAt : null;
  if (sampledAt === null)
    errors.push(issue("INVALID_TIMESTAMP", "/sampledAt", "sampledAt must be an ISO timestamp"));
  const cpuMillis = validateMeasuredValue(input.cpuMillis, "/cpuMillis", "cpuMillis", errors);
  const memoryBytes = validateMeasuredValue(input.memoryBytes, "/memoryBytes", "memoryBytes", errors);
  const pidCount = validateMeasuredValue(input.pidCount, "/pidCount", "pidCount", errors);
  const terminated = validateMeasuredValue(input.terminated, "/terminated", "terminated", errors);
  let limits = null;
  if (input.limits !== null) {
    const validatedLimits = validateResourceLimits(input.limits, "/limits");
    if (!validatedLimits.ok)
      errors.push(...validatedLimits.errors);
    else
      limits = validatedLimits.value;
  }
  if (errors.length)
    return failure(errors);
  return ok({
    versionId,
    sampledAt,
    cpuMillis,
    memoryBytes,
    pidCount,
    terminated,
    limits
  });
}
function validateActiveVersionRecord(input) {
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", "", "active-version record must be an object")]);
  const errors = [];
  rejectUnknownFields(input, "", ["kind", "applicationId", "version", "routeGeneration"], errors);
  const applicationId = validateOpaqueId(input.applicationId, "/applicationId", "applicationId", errors);
  const routeGeneration = validateInteger(input.routeGeneration, "/routeGeneration", "routeGeneration", 0, Number.MAX_SAFE_INTEGER, errors);
  if (input.kind === "unavailable") {
    if (input.version !== undefined)
      errors.push(issue("UNEXPECTED_FIELD", "/version", "unavailable record must not carry a version"));
    if (errors.length)
      return failure(errors);
    return ok({ kind: "unavailable", applicationId, routeGeneration });
  }
  if (input.kind === "active") {
    const version = validateVersionIdentity(input.version);
    if (!version.ok)
      errors.push(...version.errors);
    else if (version.value.applicationId !== applicationId) {
      errors.push(issue("IDENTITY_MISMATCH", "/version/applicationId", "active version must belong to the same application"));
    }
    if (errors.length)
      return failure(errors);
    return ok({
      kind: "active",
      applicationId,
      version: version.value,
      routeGeneration
    });
  }
  errors.push(issue("INVALID_KIND", "/kind", "kind must be unavailable or active"));
  return failure(errors);
}

// contracts/package-collection.ts
var import_node_crypto = require("node:crypto");
var MAX_PACKAGE_FILES = 1e4;
var MAX_PACKAGE_BYTES = 512 * 1024 * 1024;
var MAX_PACKAGE_FILE_BYTES = 64 * 1024 * 1024;
function safePackagePath(value) {
  if (!value || value.length > 512)
    return false;
  if (value.startsWith("/"))
    return false;
  const segments = value.split("/");
  if (segments.some((segment) => segment === ".."))
    return false;
  if (/[\u0000-\u001f]/.test(value))
    return false;
  return true;
}
function normalizePath(value) {
  return value.split("/").filter((segment) => segment !== "" && segment !== ".").join("/");
}
function filePath(path) {
  return "/files/" + path.slice(0, 40);
}
function collectPackage(options) {
  const errors = [];
  if (options.files.length > MAX_PACKAGE_FILES) {
    errors.push(issue("PACKAGE_TOO_MANY_FILES", "/files", "package exceeds the maximum file count"));
  }
  let totalBytes = 0;
  const seenPaths = new Set;
  for (const file of options.files) {
    if (!safePackagePath(file.path))
      errors.push(issue("INVALID_PATH", filePath(file.path), "package file path is unsafe"));
    const normalized = normalizePath(file.path);
    if (seenPaths.has(normalized)) {
      errors.push(issue("PACKAGE_DUPLICATE_PATH", filePath(file.path), "package file path duplicates another file after normalization"));
    }
    seenPaths.add(normalized);
    if (file.kind !== "file")
      errors.push(issue("INVALID_FILE_KIND", filePath(file.path), "package file kind must be file"));
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_PACKAGE_FILE_BYTES) {
      errors.push(issue("INVALID_SIZE", filePath(file.path), "package file size is out of bounds"));
    }
    totalBytes += file.size;
  }
  if (totalBytes > MAX_PACKAGE_BYTES)
    errors.push(issue("PACKAGE_TOO_LARGE", "/files", "package exceeds the maximum total size"));
  const statFile = options.statFile;
  if (typeof statFile !== "function") {
    errors.push(issue("PACKAGE_STAT_FAILED", "/statFile", "statFile callback is required to verify package metadata"));
  }
  const canonical = [...options.files].sort((left, right) => left.path.localeCompare(right.path));
  const digested = [];
  for (const file of canonical) {
    let before = null;
    if (typeof statFile === "function") {
      before = statFile(file.path);
      if (before === null) {
        errors.push(issue("PACKAGE_STAT_FAILED", filePath(file.path), "package file could not be stat'ed"));
        continue;
      }
      if (before.kind === "symlink") {
        errors.push(issue("PACKAGE_SYMLINK", filePath(file.path), "package file is a symlink"));
        continue;
      }
      if (before.kind === "missing") {
        errors.push(issue("PACKAGE_MISSING", filePath(file.path), "package file is missing"));
        continue;
      }
      if (before.kind !== "regular") {
        errors.push(issue("PACKAGE_NON_REGULAR", filePath(file.path), "package file is not a regular file"));
        continue;
      }
      if (before.size !== file.size) {
        errors.push(issue("SIZE_MISMATCH", filePath(file.path), "package file stat size does not match the declared size"));
        continue;
      }
    }
    let content;
    try {
      content = options.readContent(file.path);
    } catch {
      errors.push(issue("PACKAGE_READ_FAILED", filePath(file.path), "package file could not be read"));
      continue;
    }
    if (content.length !== file.size) {
      errors.push(issue("SIZE_MISMATCH", filePath(file.path), "package file size does not match its content"));
      continue;
    }
    if (typeof statFile === "function" && before !== null) {
      const after = statFile(file.path);
      if (after === null || after.kind !== "regular" || after.size !== before.size || after.mtimeNs !== before.mtimeNs) {
        errors.push(issue("PACKAGE_TOCTOU_CHANGED", filePath(file.path), "package file changed while being collected"));
        continue;
      }
    }
    digested.push({ path: file.path, content });
  }
  const entrypoint = options.manifest.runtime.entrypoint;
  const assetsRoot = options.manifest.assets.root;
  const normalizedFiles = options.files.map((file) => normalizePath(file.path));
  if (!normalizedFiles.includes(entrypoint)) {
    errors.push(issue("MANIFEST_ENTRYPOINT_MISSING", "/runtime/entrypoint", "declared entrypoint is not present in the collected files"));
  }
  if (!entrypoint.startsWith(assetsRoot + "/")) {
    errors.push(issue("MANIFEST_ENTRYPOINT_OUTSIDE_ASSETS", "/runtime/entrypoint", "declared entrypoint is not under the declared assets root"));
  }
  if (!normalizedFiles.some((path) => path.startsWith(assetsRoot + "/"))) {
    errors.push(issue("MANIFEST_ASSETS_ROOT_MISSING", "/assets/root", "no collected file exists under the declared assets root"));
  }
  if (options.manifestText !== undefined) {
    let parsed = null;
    let parseFailed = false;
    try {
      parsed = JSON.parse(options.manifestText);
    } catch {
      parseFailed = true;
    }
    if (parseFailed) {
      errors.push(issue("MANIFEST_INVALID_TEXT", "/manifestText", "manifest text is not valid JSON"));
    } else {
      const canonicalText = canonicalSerializeManifest(options.manifest);
      if (options.manifestText !== canonicalText || canonicalSerialize(parsed) !== canonicalText) {
        errors.push(issue("MANIFEST_NOT_CANONICAL", "/manifestText", "manifest text is not the canonical serialization of the collected manifest"));
      }
    }
  }
  if (errors.length)
    return failure(errors);
  return ok({ digest: packageFilesDigest(digested), fileCount: canonical.length, bytes: totalBytes, files: canonical });
}
function canonicalKeySorter(_key, value) {
  if (Array.isArray(value))
    return value.map((item) => canonicalKeySorter("", item));
  if (isRecord(value)) {
    const result = {};
    for (const key of Object.keys(value).sort())
      result[key] = canonicalKeySorter(key, value[key]);
    return result;
  }
  return value;
}
function canonicalSerialize(value) {
  return JSON.stringify(value, canonicalKeySorter, 2);
}
function canonicalSerializeManifest(manifest) {
  return canonicalSerialize(manifest);
}
function versionDigest(packageDigest, manifest) {
  const hash = import_node_crypto.createHash("sha256");
  hash.update("package:" + packageDigest);
  hash.update("\x00");
  hash.update("manifest:" + canonicalSerializeManifest(manifest));
  return hash.digest("hex");
}
function packageFilesDigest(files) {
  const canonical = [...files].sort((left, right) => left.path.localeCompare(right.path));
  const hash = import_node_crypto.createHash("sha256");
  for (const file of canonical) {
    hash.update(file.path);
    hash.update("\x00");
    hash.update(String(file.content.length));
    hash.update("\x00");
    hash.update(file.content);
  }
  return hash.digest("hex");
}

// contracts/control-db.ts
function emptyControlState() {
  return { applications: {} };
}
function emptyControlStateFile() {
  return { version: 1, applications: {} };
}
function controlStateFromFile(file) {
  return { applications: file.applications };
}
function controlStateToFile(state) {
  return { version: 1, applications: state.applications };
}
function validateControlStateFile(input) {
  if (!isRecord2(input) || input.version !== 1 || !isRecord2(input.applications))
    return null;
  const applications = {};
  for (const [applicationId, rawApplication] of Object.entries(input.applications)) {
    if (!isRecord2(rawApplication))
      return null;
    for (const key of Object.keys(rawApplication)) {
      if (key !== "applicationId" && key !== "active" && key !== "versions")
        return null;
    }
    if (typeof rawApplication.applicationId !== "string" || rawApplication.applicationId !== applicationId)
      return null;
    if (!Array.isArray(rawApplication.versions))
      return null;
    const versions = [];
    for (const rawVersion of rawApplication.versions) {
      if (!isRecord2(rawVersion))
        return null;
      for (const key of Object.keys(rawVersion)) {
        if (key !== "versionId" && key !== "identity" && key !== "packageDigest" && key !== "policy" && key !== "lifecycle" && key !== "admittedAt" && key !== "readinessExpiresAt")
          return null;
      }
      if (typeof rawVersion.versionId !== "string" || rawVersion.versionId.length === 0 || rawVersion.versionId.length > 200)
        return null;
      const identity = validateVersionIdentity(rawVersion.identity);
      if (!identity.ok)
        return null;
      if (typeof rawVersion.packageDigest !== "string" || !/^[a-f0-9]{64}$/.test(rawVersion.packageDigest))
        return null;
      const policy = validateNormalizedPolicy(rawVersion.policy);
      if (!policy.ok)
        return null;
      if (!LIFECYCLE_STATES.includes(rawVersion.lifecycle))
        return null;
      if (typeof rawVersion.admittedAt !== "string" || Number.isNaN(Date.parse(rawVersion.admittedAt)))
        return null;
      if (rawVersion.readinessExpiresAt !== null && (typeof rawVersion.readinessExpiresAt !== "string" || Number.isNaN(Date.parse(rawVersion.readinessExpiresAt))))
        return null;
      versions.push({
        versionId: rawVersion.versionId,
        identity: identity.value,
        packageDigest: rawVersion.packageDigest,
        policy: policy.value,
        lifecycle: rawVersion.lifecycle,
        admittedAt: rawVersion.admittedAt,
        readinessExpiresAt: rawVersion.readinessExpiresAt
      });
    }
    const active = validateActiveVersionRecord(rawApplication.active);
    if (!active.ok || active.value.applicationId !== applicationId)
      return null;
    if (active.value.kind === "active") {
      const pointed = active.value.version;
      const matched = versions.some((version) => version.identity.applicationId === pointed.applicationId && version.identity.digest === pointed.digest && version.identity.sequence === pointed.sequence);
      if (!matched)
        return null;
    }
    applications[applicationId] = { applicationId, active: active.value, versions };
  }
  return { version: 1, applications };
}
function isRecord2(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function admitVersion(state, input) {
  const digest = versionDigest(input.packageDigest, input.manifest);
  const existing = state.applications[input.applicationId];
  const duplicate = existing?.versions.some((version2) => version2.versionId === digest);
  if (duplicate) {
    return failure([{ code: "DUPLICATE_VERSION", path: "/version", message: "an identical admitted version already exists" }]);
  }
  const sequence = (existing?.versions.length ?? 0) + 1;
  const identity = { applicationId: input.applicationId, digest, sequence };
  const version = { versionId: digest, identity, packageDigest: input.packageDigest, policy: input.policy, lifecycle: "admitted", admittedAt: input.admittedAt, readinessExpiresAt: null };
  const application = existing ? { ...existing, versions: [...existing.versions, version] } : { applicationId: input.applicationId, active: { kind: "unavailable", applicationId: input.applicationId, routeGeneration: 0 }, versions: [version] };
  return ok({ state: { applications: { ...state.applications, [input.applicationId]: application } }, version });
}
function activeVersionDigest(active) {
  return active.kind === "active" ? active.version.digest : null;
}
function activateVersion(state, applicationId, versionId) {
  const application = state.applications[applicationId];
  if (!application)
    return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
  const candidate = application.versions.find((version) => version.versionId === versionId);
  if (!candidate)
    return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
  if (candidate.lifecycle !== "ready")
    return failure([{ code: "NOT_READY", path: "/lifecycle", message: "candidate version is not ready" }]);
  const previousDigest = activeVersionDigest(application.active);
  const retired = previousDigest === null ? null : application.versions.find((version) => version.versionId === previousDigest) ?? null;
  const generation = application.active.routeGeneration + 1;
  const active = { kind: "active", applicationId, version: candidate.identity, routeGeneration: generation };
  const nextApplication = {
    ...application,
    active,
    versions: application.versions.map((version) => {
      if (version.versionId === versionId)
        return { ...version, lifecycle: "active" };
      if (version.versionId === previousDigest)
        return { ...version, lifecycle: "retired" };
      return version;
    })
  };
  return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } }, retired });
}
function rollbackVersion(state, applicationId, versionId) {
  return activateVersion(state, applicationId, versionId);
}
function markVersionReady(state, applicationId, versionId, expiresAt) {
  const application = state.applications[applicationId];
  if (!application)
    return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
  const candidate = application.versions.find((version2) => version2.versionId === versionId);
  if (!candidate)
    return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
  const version = { ...candidate, lifecycle: "ready", readinessExpiresAt: expiresAt };
  const nextApplication = { ...application, versions: application.versions.map((entry) => entry.versionId === versionId ? version : entry) };
  return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } }, version });
}
function removeVersion(state, applicationId, versionId) {
  const application = state.applications[applicationId];
  if (!application)
    return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
  const candidate = application.versions.find((version) => version.versionId === versionId);
  if (!candidate)
    return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
  if (application.active.kind === "active" && application.active.version.digest === versionId) {
    return failure([{ code: "ACTIVE_VERSION_PROTECTED", path: "/versionId", message: "the active version cannot be deleted" }]);
  }
  const nextApplication = { ...application, versions: application.versions.filter((version) => version.versionId !== versionId) };
  return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } } });
}
function setVersionLifecycle(state, applicationId, versionId, lifecycle) {
  const application = state.applications[applicationId];
  if (!application)
    return failure([{ code: "UNKNOWN_APPLICATION", path: "/applicationId", message: "application is not admitted" }]);
  const candidate = application.versions.find((version2) => version2.versionId === versionId);
  if (!candidate)
    return failure([{ code: "UNKNOWN_VERSION", path: "/versionId", message: "version is not admitted" }]);
  const version = { ...candidate, lifecycle };
  const nextApplication = { ...application, versions: application.versions.map((entry) => entry.versionId === versionId ? version : entry) };
  return ok({ state: { applications: { ...state.applications, [applicationId]: nextApplication } }, version });
}
// contracts/control-store.ts
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
function syncDirectory(directory) {
  let dirFd;
  try {
    dirFd = import_node_fs.openSync(directory, "r");
    import_node_fs.fsyncSync(dirFd);
  } catch {} finally {
    if (dirFd !== undefined) {
      try {
        import_node_fs.closeSync(dirFd);
      } catch {}
    }
  }
}
var systemControlStoreIO = {
  readFile: (path) => {
    try {
      return import_node_fs.readFileSync(path, "utf8");
    } catch (error) {
      const code = typeof error === "object" && error !== null && "code" in error ? String(error.code ?? "") : "";
      if (code !== "ENOENT")
        throw error;
      return null;
    }
  },
  writeFileAtomic: (path, content) => {
    import_node_fs.mkdirSync(import_node_path.dirname(path), { recursive: true, mode: 448 });
    const temporary = path + ".tmp";
    const fd = import_node_fs.openSync(temporary, "w", 384);
    try {
      import_node_fs.writeFileSync(fd, content);
      import_node_fs.fsyncSync(fd);
    } finally {
      import_node_fs.closeSync(fd);
    }
    import_node_fs.renameSync(temporary, path);
    syncDirectory(import_node_path.dirname(path));
  },
  deleteFile: (path) => {
    try {
      import_node_fs.rmSync(path, { force: true });
    } catch {}
  },
  ensureDirectory: (path) => {
    import_node_fs.mkdirSync(path, { recursive: true, mode: 448 });
  }
};

class ControlStore {
  io;
  path;
  empty;
  parse;
  constructor(options) {
    this.io = options.io;
    this.path = options.path;
    this.empty = options.empty;
    this.parse = options.parse;
  }
  load() {
    const text = this.io.readFile(this.path);
    if (text === null)
      return this.empty();
    try {
      const parsed = this.parse(JSON.parse(text));
      if (parsed !== null)
        return parsed;
    } catch {}
    this.io.deleteFile(this.path + ".corrupt");
    this.io.writeFileAtomic(this.path + ".corrupt", text);
    return this.empty();
  }
  save(value) {
    this.io.ensureDirectory(import_node_path.dirname(this.path));
    this.io.writeFileAtomic(this.path, JSON.stringify(value, null, 2) + `
`);
  }
  transaction(mutate) {
    const current = this.load();
    const next = mutate(current);
    if (next === null)
      return null;
    this.save(next);
    return next;
  }
}
// contracts/protocol.ts
var import_node_crypto2 = require("node:crypto");
var PROTOCOL_VERSION = 1;
function deriveSandboxId(applicationId, versionDigest2, sequence) {
  const identity = applicationId + "\x00" + versionDigest2 + "\x00" + sequence;
  return "sbx-" + import_node_crypto2.createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 40);
}
function validateSupervisorResponse(input) {
  if (!isRecord(input))
    return failure([issue("TYPE_OBJECT", "", "supervisor response must be an object")]);
  const errors = [];
  if (input.version !== PROTOCOL_VERSION)
    errors.push(issue("INVALID_VERSION", "/version", "protocol version must be " + PROTOCOL_VERSION));
  const operation = input.operation;
  switch (operation) {
    case "prepare": {
      rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
      if (input.status !== "prepared")
        errors.push(issue("INVALID_STATUS", "/status", "prepare response status must be prepared"));
      const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
      if (errors.length)
        return failure(errors);
      return ok({ version: 1, operation: "prepare", status: "prepared", sandboxId });
    }
    case "start": {
      rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
      if (input.status !== "started")
        errors.push(issue("INVALID_STATUS", "/status", "start response status must be started"));
      const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
      if (errors.length)
        return failure(errors);
      return ok({ version: 1, operation: "start", status: "started", sandboxId });
    }
    case "stop": {
      rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
      if (input.status !== "stopped")
        errors.push(issue("INVALID_STATUS", "/status", "stop response status must be stopped"));
      const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
      if (errors.length)
        return failure(errors);
      return ok({ version: 1, operation: "stop", status: "stopped", sandboxId });
    }
    case "delete": {
      rejectUnknownFields(input, "", ["version", "operation", "status", "sandboxId"], errors);
      if (input.status !== "deleted")
        errors.push(issue("INVALID_STATUS", "/status", "delete response status must be deleted"));
      const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
      if (errors.length)
        return failure(errors);
      return ok({ version: 1, operation: "delete", status: "deleted", sandboxId });
    }
    case "inspect": {
      rejectUnknownFields(input, "", ["version", "operation", "sandboxId", "state"], errors);
      const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
      const state = input.state;
      if (state !== "admitted" && state !== "preparing" && state !== "ready" && state !== "active" && state !== "retired" && state !== "stopped" && state !== "failed") {
        errors.push(issue("INVALID_LIFECYCLE_STATE", "/state", "lifecycle state is not recognized"));
      }
      if (errors.length)
        return failure(errors);
      return ok({ version: 1, operation: "inspect", sandboxId, state });
    }
    case "metrics": {
      rejectUnknownFields(input, "", ["version", "operation", "sandboxId", "sample"], errors);
      const sandboxId = validateOpaqueId(input.sandboxId, "/sandboxId", "sandboxId", errors);
      const sample = validateResourceSample(input.sample);
      if (!sample.ok)
        errors.push(...sample.errors);
      if (errors.length)
        return failure(errors);
      return ok({ version: 1, operation: "metrics", sandboxId, sample: sample.value });
    }
    default:
      return failure([issue("INVALID_OPERATION", "/operation", "operation is not recognized")]);
  }
}
function correlateResponse(request, response) {
  const errors = [];
  if (response.version !== PROTOCOL_VERSION)
    errors.push(issue("INVALID_VERSION", "/version", "protocol version must be " + PROTOCOL_VERSION));
  if (response.operation !== request.operation)
    errors.push(issue("OPERATION_MISMATCH", "/operation", "response operation does not match the request"));
  if (response.sandboxId !== request.sandboxId)
    errors.push(issue("SANDBOX_MISMATCH", "/sandboxId", "response sandbox identity does not match the request"));
  if (request.operation === "metrics" && response.operation === "metrics" && response.sample.versionId !== request.versionId) {
    errors.push(issue("VERSION_MISMATCH", "/sample/versionId", "metrics version identity does not match the requested sandbox version"));
  }
  if (errors.length)
    return failure(errors);
  return ok(response);
}
// contracts/routing.ts
function resolveActiveSandboxId(state, appName) {
  const application = state.applications[appName];
  if (!application || application.active.kind !== "active")
    return null;
  return deriveSandboxId(application.active.applicationId, application.active.version.digest, application.active.version.sequence);
}
function resolveRoute(state, route, appBasePath) {
  if (!route || route.enabled === false)
    return null;
  const sandboxId = resolveActiveSandboxId(state, route.appName);
  if (sandboxId === null)
    return null;
  return { appName: route.appName, sandboxId, appBasePath };
}
function routeAction(route, activeSandboxId) {
  if (route && route.system)
    return { kind: "system" };
  if (activeSandboxId !== null)
    return { kind: "sandbox", sandboxId: activeSandboxId };
  return { kind: "unavailable" };
}
// contracts/public-objects.ts
function normalizePublicObjectPath(value) {
  const normalized = String(value ?? "").trim().replace(/^\/+/, "").replace(/\/+$/, "");
  if (!normalized || normalized.includes("..") || normalized.split("/").some((segment) => !segment || segment === "."))
    return null;
  if (/[\u0000-\u001f]/.test(normalized))
    return null;
  return normalized;
}
var ROOT_PUBLIC_DOCUMENT = "index.html";
function resolvePublicObject(set, path) {
  const trimmed = String(path ?? "").trim();
  if (trimmed !== "" && trimmed.replaceAll("/", "") === "") {
    return set.objects.has(ROOT_PUBLIC_DOCUMENT) ? ROOT_PUBLIC_DOCUMENT : null;
  }
  const normalized = normalizePublicObjectPath(path);
  if (normalized === null)
    return null;
  if (set.objects.has(normalized))
    return normalized;
  if (set.prefixes.some((prefix) => normalized === prefix || normalized.startsWith(prefix + "/")))
    return normalized;
  return null;
}
function parsePublicObjectSet(value) {
  const objects = new Set;
  const prefixes = [];
  for (const entry of String(value ?? "index.html").split(",")) {
    const trimmed = entry.trim();
    if (trimmed === "")
      continue;
    const normalized = normalizePublicObjectPath(trimmed);
    if (normalized === null)
      continue;
    if (trimmed.endsWith("/"))
      prefixes.push(normalized);
    else
      objects.add(normalized);
  }
  return { objects, prefixes };
}
// contracts/monitor-frame.ts
function projectSandboxResources(sample) {
  if (sample === null || sample === undefined)
    return null;
  if (typeof sample !== "object" || Array.isArray(sample))
    return null;
  const candidate = sample;
  if (typeof candidate.versionId !== "string" || typeof candidate.sampledAt !== "string")
    return null;
  for (const key of ["cpuMillis", "memoryBytes", "pidCount", "terminated"]) {
    const value = candidate[key];
    if (typeof value !== "object" || value === null || Array.isArray(value))
      return null;
    const measured = value;
    if (typeof measured.available !== "boolean")
      return null;
    if (measured.available && (typeof measured.value !== "number" || !Number.isFinite(measured.value) || measured.value < 0))
      return null;
    if (!measured.available && measured.value !== undefined)
      return null;
  }
  return {
    versionId: candidate.versionId,
    sampledAt: candidate.sampledAt,
    cpuMillis: candidate.cpuMillis,
    memoryBytes: candidate.memoryBytes,
    pidCount: candidate.pidCount,
    terminated: candidate.terminated,
    limits: candidate.limits ?? null
  };
}
var CREDENTIAL_PATTERN = /(authorization|bearer|secret|password|token)/i;
function sanitizeValue(value) {
  if (typeof value === "string")
    return CREDENTIAL_PATTERN.test(value) ? undefined : value;
  if (Array.isArray(value)) {
    const kept = [];
    for (const element of value) {
      const sanitized = sanitizeValue(element);
      if (sanitized !== undefined)
        kept.push(sanitized);
    }
    return kept;
  }
  if (value !== null && typeof value === "object")
    return sanitizeMonitorFrame(value);
  return value;
}
function sanitizeMonitorFrame(input) {
  const out = {};
  for (const [key, value] of Object.entries(input)) {
    if (CREDENTIAL_PATTERN.test(key))
      continue;
    const sanitized = sanitizeValue(value);
    if (sanitized !== undefined)
      out[key] = sanitized;
  }
  return out;
}
// contracts/lifecycle-routes.ts
async function handleVersionAction(control, applicationId, versionId, method, action) {
  if (method === "GET" && action === null) {
    return { status: 200, body: await control.inspectVersion(applicationId, versionId), drainAfterCommit: false };
  }
  if (method === "POST" && action === "prepare") {
    return { status: 201, body: await control.prepare(applicationId, versionId), drainAfterCommit: false };
  }
  if (method === "POST" && action === "readiness") {
    return { status: 200, body: await control.probeReady(applicationId, versionId), drainAfterCommit: false };
  }
  if (method === "POST" && action === "activate") {
    const activation = await control.activate(applicationId, versionId);
    return { status: 200, body: activation, drainAfterCommit: true };
  }
  if (method === "POST" && action === "rollback") {
    const rollback = await control.rollback(applicationId, versionId);
    return { status: 200, body: rollback, drainAfterCommit: true };
  }
  if (method === "POST" && action === "start") {
    return { status: 200, body: await control.startVersion(applicationId, versionId), drainAfterCommit: false };
  }
  if (method === "POST" && action === "stop") {
    return { status: 200, body: await control.stopVersion(applicationId, versionId), drainAfterCommit: false };
  }
  return { status: 405, body: { error: "method not allowed" }, drainAfterCommit: false };
}
// supervisor/sandbox-spec.ts
var GATEWAY_BIND_HOST = "0.0.0.0";
var GATEWAY_OBJECT_LISTEN = GATEWAY_BIND_HOST + ":9000";
var GATEWAY_EGRESS_LISTEN = GATEWAY_BIND_HOST + ":8081";
var GATEWAY_DATA_LISTEN = GATEWAY_BIND_HOST + ":8082";
var READINESS_PATH = "/iweb-health";

// supervisor/readiness.ts
var MAX_ATTEMPTS = 100;
var MAX_TIMEOUT_MS = 60000;
var defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function readinessUrl(baseUrl, versionId, generation) {
  const query = "?versionId=" + encodeURIComponent(versionId) + (generation === undefined ? "" : "&generation=" + String(generation));
  return baseUrl + READINESS_PATH + query;
}
function parseHealthPayload(body) {
  try {
    const parsed = JSON.parse(body);
    if (isRecord3(parsed) && parsed.version === 1 && parsed.ok === true && typeof parsed.versionId === "string" && typeof parsed.generation === "number" && Number.isSafeInteger(parsed.generation)) {
      return { version: 1, ok: true, versionId: parsed.versionId, generation: parsed.generation };
    }
  } catch {}
  return null;
}
function isRecord3(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
async function probeReadiness(options) {
  const sleep = options.sleep ?? defaultSleep;
  const maxAttempts = Math.min(Math.max(1, Math.floor(options.maxAttempts)), MAX_ATTEMPTS);
  const timeoutMs = Math.min(Math.max(100, Math.floor(options.attemptTimeoutMs)), MAX_TIMEOUT_MS);
  let lastStatus = null;
  let mismatch = false;
  let timedOut = false;
  for (let attempt = 1;attempt <= maxAttempts; attempt += 1) {
    const controller = new AbortController;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await options.fetch(readinessUrl(options.baseUrl, options.versionId, options.generation), { signal: controller.signal });
      lastStatus = response.status;
      if (response.status === 200) {
        const payload = parseHealthPayload(response.body);
        if (payload !== null && payload.versionId === options.versionId && (options.generation === undefined || payload.generation === options.generation)) {
          return { ready: true, attempts: attempt, lastStatus: 200, mismatch: false, timedOut: false };
        }
        mismatch = true;
      } else if (response.status === 409) {
        mismatch = true;
      }
    } catch (error) {
      if (isAbortError(error))
        timedOut = true;
      lastStatus = null;
    } finally {
      clearTimeout(timer);
    }
    if (attempt < maxAttempts)
      await sleep(options.intervalMs);
  }
  return { ready: false, attempts: maxAttempts, lastStatus, mismatch, timedOut };
}
function isAbortError(error) {
  return typeof error === "object" && error !== null && error.name === "AbortError";
}
// contracts/persisted-records.ts
function validateObjectEndpoint(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048)
    return { ok: false, reason: "endpoint is not a bounded string" };
  let url;
  try {
    url = new URL(value);
  } catch {
    return { ok: false, reason: "endpoint is not an absolute URL" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:")
    return { ok: false, reason: "endpoint protocol must be http(s)" };
  if (url.username !== "" || url.password !== "")
    return { ok: false, reason: "endpoint must not embed credentials" };
  if (url.hash !== "")
    return { ok: false, reason: "endpoint must not carry a fragment" };
  return { ok: true };
}
function validateBucketName(value) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(value))
    return { ok: false, reason: "bucket name is invalid" };
  return { ok: true };
}
function validateCredentialString(value, min, max) {
  return typeof value === "string" && value.length >= min && value.length <= max && /^[\x20-\x7e]+$/.test(value);
}
function validateTimestamp(value) {
  return typeof value === "string" && value.length >= 10 && value.length <= 64 && !Number.isNaN(Date.parse(value));
}
function validateApplicationId(value) {
  return typeof value === "string" && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value);
}
function validateSha256Digest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}
function validateStorageSecret(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
function validateObjectCredentialRecord(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return { ok: false, reason: "credential is not a JSON object" };
  const record = value;
  const known = new Set(["endpoint", "region", "accessKeyId", "secretAccessKey"]);
  for (const key of Object.keys(record)) {
    if (!known.has(key))
      return { ok: false, reason: "credential has unknown field " + key };
  }
  const endpoint = validateObjectEndpoint(record.endpoint);
  if (!endpoint.ok)
    return { ok: false, reason: endpoint.reason ?? "endpoint is invalid" };
  if (typeof record.region !== "string" || record.region.length === 0 || record.region.length > 64)
    return { ok: false, reason: "region is not a bounded string" };
  if (!validateCredentialString(record.accessKeyId, 1, 256))
    return { ok: false, reason: "accessKeyId is not a bounded credential string" };
  if (!validateCredentialString(record.secretAccessKey, 1, 512))
    return { ok: false, reason: "secretAccessKey is not a bounded credential string" };
  return { ok: true, value: { endpoint: record.endpoint, region: record.region, accessKeyId: record.accessKeyId, secretAccessKey: record.secretAccessKey } };
}
function validateVersionDeploymentRecord(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return { ok: false, reason: "deployment record is not a JSON object" };
  const record = value;
  const known = new Set(["v", "kind", "sandboxId", "applicationId", "versionId", "digest", "sequence", "deployedAt"]);
  for (const key of Object.keys(record)) {
    if (!known.has(key))
      return { ok: false, reason: "deployment record has unknown field " + key };
  }
  if (record.v !== 1)
    return { ok: false, reason: "deployment record v must be 1" };
  if (record.kind !== "iweb-version-deployment")
    return { ok: false, reason: "deployment record kind is wrong" };
  if (typeof record.sandboxId !== "string" || !record.sandboxId.startsWith("sbx-") || record.sandboxId.length < 8 || record.sandboxId.length > 128)
    return { ok: false, reason: "sandboxId is not an opaque sandbox id" };
  if (!validateApplicationId(record.applicationId))
    return { ok: false, reason: "applicationId is invalid" };
  if (typeof record.versionId !== "string" || record.versionId.length < 64 || record.versionId.length > 200 || !/^[a-f0-9]{64}$/.test(record.versionId))
    return { ok: false, reason: "versionId is not a version digest label" };
  if (!validateSha256Digest(record.digest))
    return { ok: false, reason: "digest is not a sha-256 digest" };
  if (typeof record.sequence !== "number" || !Number.isSafeInteger(record.sequence) || record.sequence < 1)
    return { ok: false, reason: "sequence is not a positive safe integer" };
  if (!validateTimestamp(record.deployedAt))
    return { ok: false, reason: "deployedAt is not a timestamp" };
  return {
    ok: true,
    record: { v: 1, kind: "iweb-version-deployment", sandboxId: record.sandboxId, applicationId: record.applicationId, versionId: record.versionId, digest: record.digest, sequence: record.sequence, deployedAt: record.deployedAt }
  };
}
function deploymentRecordMatches(record, expected) {
  return record.sandboxId === expected.sandboxId && record.applicationId === expected.applicationId && record.versionId === expected.versionId && record.digest === expected.digest && record.sequence === expected.sequence;
}
