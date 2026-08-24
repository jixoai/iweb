// 用户原始需求（2026-08-14）：Kernel 是唯一授权与激活权威：admission 只从不可变快照；prepare/readiness/activation 走窄 supervisor 协议；desired secrets 与可检查记录分离。
// 正交意图：7.x 生产消费者；纯函数全部来自 contracts-bundle；对 supervisor 的一切调用有界、可注入、失败即基础设施失败。
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomBytes } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const bundle = require("./contracts-bundle.cjs");
const rpc = require("./supervisor-rpc.js");
const { versionScopedObjectPolicy, applicationDataPolicy } = require("./package-store.js");

const READINESS_LEASE_MS = 60_000;
// Must mirror GATEWAY_OBJECT_LISTEN / GATEWAY_DATA_LISTEN in supervisor/sandbox-spec.ts.
// An endpoint equal to either is a self-loop: the gateway would forward to itself.
// The concrete pod topology reaches the host MinIO through the slirp gateway
// address (hostObjectEndpoint in sandbox-spec.ts), which never collides with a
// pod-loopback listener.
const GATEWAY_SELF_LOOP_ENDPOINTS = new Set(["http://127.0.0.1:9000", "http://127.0.0.1:8082", "http://localhost:9000", "http://localhost:8082", "http://0.0.0.0:9000", "http://0.0.0.0:8082"]);

function assertEndpointReachable(endpoint, codePrefix) {
  if (typeof endpoint !== "string" || endpoint === "") {
    throw codedError(codePrefix + "_UNCONFIGURED", "IWEB_SANDBOX_OBJECT_ENDPOINT is not configured for the sandbox topology");
  }
  if (GATEWAY_SELF_LOOP_ENDPOINTS.has(endpoint)) {
    throw codedError(codePrefix + "_SELF_LOOP", "object endpoint " + endpoint + " is the gateway listener itself; configure the MinIO address reachable from the sandbox pod");
  }
}

function codedError(code, message) {
  const error = new Error(message ?? code);
  error.code = code;
  return error;
}

const defaultSecretsIo = {
  readFile: (file) => {
    try {
      return fs.readFileSync(file, "utf8");
    } catch (error) {
      // ENOENT is a legitimate fresh install; a permission or I/O failure is an
      // infrastructure error that must never masquerade as absent (2.37/2.47).
      if (error && error.code !== "ENOENT") throw error;
      return null;
    }
  },
  writeFileAtomic: (file, content) => {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const temporary = file + ".tmp";
    const fd = fs.openSync(temporary, "w", 0o600);
    try {
      fs.writeFileSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temporary, file);
    // Durability contract (2.28): file-level durability is guaranteed; the
    // post-rename directory fsync throws on real infrastructure errors and is
    // skipped ONLY when the platform reports directory fsync unsupported.
    let dirFd;
    try {
      dirFd = fs.openSync(path.dirname(file), "r");
      fs.fsyncSync(dirFd);
    } catch (e) {
      const code = e && e.code ? String(e.code) : "";
      if (code !== "EINVAL" && code !== "ENOSYS" && code !== "EPERM") throw e;
    } finally {
      if (dirFd !== undefined) { try { fs.closeSync(dirFd); } catch (e2) {} }
    }
  },
};

// Shared persisted-record authority (contracts/persisted-records via the
// bundle): bucket names, object endpoints, credential strings, and timestamps
// are validated with the SAME rules the supervisor applies to its state files,
// so the Kernel can never accept a persisted secret the supervisor side would
// reject. Unknown fields reject the entry outright.
function validObjectCredential(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const keys = Object.keys(value);
  if (keys.length !== 4 || !keys.every((k) => k === "endpoint" || k === "region" || k === "accessKeyId" || k === "secretAccessKey")) return null;
  if (!bundle.validateObjectEndpoint(value.endpoint).ok) return null;
  if (typeof value.region !== "string" || value.region.length === 0 || value.region.length > 64) return null;
  if (!bundle.validateCredentialString(value.accessKeyId, 1, 256) || !bundle.validateCredentialString(value.secretAccessKey, 1, 512)) return null;
  return { endpoint: value.endpoint, region: value.region, accessKeyId: value.accessKeyId, secretAccessKey: value.secretAccessKey };
}

// Shared persisted-record authority (contracts/persisted-records via the
// bundle): bucket names, object endpoints, credential strings, timestamps,
// application ids, storage secrets, and complete nested credential records are
// validated with the SAME rules the supervisor applies to its state files, so
// the Kernel can never accept a persisted secret the supervisor side would
// reject. Unknown fields reject the entry outright.
function validObjectCredential(value) {
  const result = bundle.validateObjectCredentialRecord(value);
  return result.ok ? result.value : null;
}

// Durable quarantine journal for rejected control-secret state (2.47): a
// malformed FILE or ENTRY is never silently dropped — every rejection is
// appended here with its reason, and the journal itself is validated strictly
// (a corrupt journal is an explicit infrastructure failure, never an empty one).
function secretsQuarantinePath(file) {
  return file + ".quarantine.json";
}

function readSecretsQuarantine(io, file) {
  const text = io.readFile(secretsQuarantinePath(file));
  if (text === null) return [];
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw codedError("SECRETS_QUARANTINE_CORRUPT", "control-secrets quarantine journal is not parseable JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || parsed.version !== 1 || !Array.isArray(parsed.entries)) {
    throw codedError("SECRETS_QUARANTINE_CORRUPT", "control-secrets quarantine journal top level is malformed");
  }
  const entries = [];
  for (const entry of parsed.entries) {
    const ok =
      typeof entry === "object" && entry !== null && !Array.isArray(entry) &&
      Object.keys(entry).length === 4 &&
      typeof entry.kind === "string" && entry.kind.length > 0 && entry.kind.length <= 64 &&
      typeof entry.key === "string" && entry.key.length > 0 && entry.key.length <= 200 &&
      typeof entry.reason === "string" && entry.reason.length > 0 && entry.reason.length <= 512 &&
      bundle.validateTimestamp(entry.at);
    if (!ok) throw codedError("SECRETS_QUARANTINE_CORRUPT", "control-secrets quarantine journal entry is malformed");
    entries.push({ kind: entry.kind, key: entry.key, reason: entry.reason, at: entry.at });
  }
  return entries;
}

function appendSecretsQuarantine(io, file, additions) {
  if (additions.length === 0) return;
  const merged = [...readSecretsQuarantine(io, file), ...additions];
  io.writeFileAtomic(secretsQuarantinePath(file), JSON.stringify({ version: 1, entries: merged }, null, 2) + "\n");
}

function loadSecrets(io, file) {
  const text = io.readFile(file);
  // null = absent (fresh install): empty is correct, no quarantine needed.
  if (text === null) return { version: 1, sandboxes: {} };
  const quarantine = (kind, key, reason) => appendSecretsQuarantine(io, file, [{ kind, key, reason, at: new Date().toISOString() }]);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    // documented failure path (2.47): the corrupt file is quarantined durably,
    // the runtime state starts empty, and prepare re-issues. Never silent.
    quarantine("control-secrets", "control-secrets", "control-secrets.json is not parseable JSON");
    return { version: 1, sandboxes: {} };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    quarantine("control-secrets", "control-secrets", "control-secrets.json is not a JSON object");
    return { version: 1, sandboxes: {} };
  }
  const knownTopLevel = new Set(["version", "sandboxes", "appData"]);
  for (const key of Object.keys(parsed)) {
    if (!knownTopLevel.has(key)) {
      quarantine("control-secrets", "control-secrets", "control-secrets.json has unknown top-level field " + key);
      return { version: 1, sandboxes: {} };
    }
  }
  if (parsed.version !== 1 || typeof parsed.sandboxes !== "object" || parsed.sandboxes === null || Array.isArray(parsed.sandboxes)) {
    quarantine("control-secrets", "control-secrets", "control-secrets.json top level is malformed (version/sandboxes)");
    return { version: 1, sandboxes: {} };
  }
  const knownSandboxKeys = new Set(["version", "sandboxId", "versionId", "generation", "bucket", "object", "retire", "createdAt"]);
  const sandboxes = {};
  for (const [sandboxId, entry] of Object.entries(parsed.sandboxes)) {
    const reject = (reason) => quarantine("control-secrets", sandboxId, reason);
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      reject("sandbox entry is not a JSON object");
      continue;
    }
    const unknownField = Object.keys(entry).find((k) => !knownSandboxKeys.has(k));
    if (unknownField) {
      reject("sandbox entry has unknown field " + unknownField);
      continue;
    }
    const object = validObjectCredential(entry.object);
    const retireOk =
      typeof entry.retire === "object" && entry.retire !== null && !Array.isArray(entry.retire) &&
      Object.keys(entry.retire).length === 2 &&
      Object.keys(entry.retire).every((k) => k === "accessKey" || k === "parentUser") &&
      bundle.validateCredentialString(entry.retire.accessKey, 1, 256) &&
      bundle.validateCredentialString(entry.retire.parentUser, 1, 256);
    if (!retireOk) { reject("retire handle is malformed"); continue; }
    if (entry.version !== 1) { reject("entry version must be 1"); continue; }
    if (typeof entry.sandboxId !== "string" || entry.sandboxId !== sandboxId) { reject("entry sandboxId does not match its key"); continue; }
    if (typeof entry.versionId !== "string" || entry.versionId.length === 0 || entry.versionId.length > 200) { reject("versionId is not a bounded string"); continue; }
    if (typeof entry.generation !== "number" || !Number.isSafeInteger(entry.generation) || entry.generation < 1) { reject("generation is not a positive safe integer"); continue; }
    if (!bundle.validateBucketName(entry.bucket).ok) { reject("bucket name is invalid"); continue; }
    if (object === null) { reject("object credential failed field validation"); continue; }
    if (!bundle.validateTimestamp(entry.createdAt)) { reject("createdAt is not a timestamp"); continue; }
    sandboxes[sandboxId] = { version: 1, sandboxId, versionId: entry.versionId, generation: entry.generation, bucket: entry.bucket, object, retire: { accessKey: entry.retire.accessKey, parentUser: entry.retire.parentUser }, createdAt: entry.createdAt };
  }
  // appData entries: per-application data-plane authority, validated the same way
  const appData = {};
  if (parsed.appData !== undefined) {
    if (typeof parsed.appData !== "object" || parsed.appData === null || Array.isArray(parsed.appData)) {
      quarantine("control-secrets", "appData", "appData is not a JSON object");
    } else {
      for (const [applicationId, entry] of Object.entries(parsed.appData)) {
        const reject = (reason) => quarantine("control-secrets", "appData:" + applicationId, reason);
        if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
          reject("appData entry is not a JSON object");
          continue;
        }
        const unknownField = Object.keys(entry).find((k) => k !== "version" && k !== "applicationId" && k !== "storageSecret" && k !== "data");
        if (unknownField) {
          reject("appData entry has unknown field " + unknownField);
          continue;
        }
        const data = validObjectCredential(entry.data);
        if (entry.version !== 1) { reject("appData entry version must be 1"); continue; }
        if (typeof entry.applicationId !== "string" || entry.applicationId !== applicationId || !bundle.validateApplicationId(applicationId)) { reject("appData applicationId is invalid or does not match its key"); continue; }
        if (!bundle.validateStorageSecret(entry.storageSecret)) { reject("storageSecret is not a 64-hex storage secret"); continue; }
        if (data === null) { reject("data credential failed field validation"); continue; }
        appData[applicationId] = { version: 1, applicationId, storageSecret: entry.storageSecret, data };
      }
    }
  }
  return { version: 1, sandboxes, ...(Object.keys(appData).length > 0 ? { appData } : {}) };
}

function createApplicationControl(options) {
  const {
    controlStore,
    secretsFile,
    supervisorSocket,
    gatewayDirectory,
    objectEndpoint,
    objectRegion = "us-east-1",
    rpcClient = rpc,
    issueObjectCredential = defaultObjectCredentialIssuer(objectEndpoint, objectRegion),
    issueDataCredential = defaultDataCredentialIssuer(objectEndpoint, objectRegion),
    retireObjectCredential = defaultRetireObjectCredential(),
    readiness = {},
    secretsIo = defaultSecretsIo,
    packageStore,
    now = () => Date.now(),
  } = options;

  if (!controlStore) throw new Error("controlStore is required");
  if (!packageStore) throw new Error("packageStore is required");
  let secrets = loadSecrets(secretsIo, secretsFile);

  // 2.46 single production writer: every lifecycle mutation is serialized
  // through one queue so concurrent admission, prepare, activation, rollback,
  // deletion, and reconcile can never interleave read-modify-write cycles on
  // the control state (no lost updates, no duplicate sequence allocation, no
  // split active pointers). Reads stay concurrent; mutations queue.
  let writeTail = Promise.resolve();
  function serialized(action) {
    const run = writeTail.then(action, action);
    writeTail = run.then(() => undefined, () => undefined);
    return run;
  }

  function saveSecrets() {
    secretsIo.writeFileAtomic(secretsFile, JSON.stringify(secrets, null, 2) + "\n");
  }

  function state() {
    const file = controlStore.load();
    return bundle.controlStateFromFile(file);
  }

  function requireVersion(applicationId, versionId) {
    const application = state().applications[applicationId];
    const version = application?.versions.find((entry) => entry.versionId === versionId);
    if (!version) throw codedError("UNKNOWN_VERSION", "version is not admitted");
    return version;
  }

  function sandboxIdFor(version) {
    return bundle.deriveSandboxId(version.identity.applicationId, version.identity.digest, version.identity.sequence);
  }

  function gatewaySocket(sandboxId) {
    return gatewayDirectory + "/" + sandboxId + "/ingress.sock";
  }

  function saveState(next) {
    controlStore.save(bundle.controlStateToFile(next));
    return next;
  }

  // 7.2 admission: immutable version created exactly once from a canonical
  // snapshot. The complete snapshot is persisted atomically under its
  // verified digest BEFORE the version is committed, so a later workspace
  // mutation can never alter an admitted version and a crash never leaves an
  // admitted version whose content cannot be restored.
  async function admit(input) {
    const admittedAt = new Date(now()).toISOString();
    const admission = bundle.admitVersion(state(), {
      applicationId: input.applicationId,
      packageDigest: input.packageDigest,
      manifest: input.manifest,
      policy: input.policy,
      admittedAt,
    });
    if (!admission.ok) throw codedError(admission.errors[0]?.code ?? "ADMISSION_REJECTED", "admission rejected");
    await packageStore.persist(input.packageDigest, input.manifest, input.snapshotFiles);
    saveState(admission.value.state);
    return { versionId: admission.value.version.versionId, identity: admission.value.version.identity };
  }

  // Fail closed: a version is prepared or recovered only from a verified
  // immutable snapshot and a deployment object created from it. A missing or
  // tampered snapshot, or a deployment that cannot be created, is an
  // infrastructure failure — never a silent success and never a fallback to
  // mutable workspace content. Callers wrap this so a failure marks the
  // version failed.
  async function ensureSnapshotAndDeployment(version) {
    const sandboxId = sandboxIdFor(version);
    const verifiedDigest = await packageStore.verify(version.packageDigest);
    if (verifiedDigest === null) throw codedError("PACKAGE_SNAPSHOT_MISSING", "admitted package snapshot is absent or unreadable");
    if (verifiedDigest !== version.packageDigest) throw codedError("PACKAGE_DIGEST_MISMATCH", "admitted package snapshot content does not match its digest");
    // Full version identity travels to the store so the deployment record in
    // the version bucket is field-validated against applicationId, versionId,
    // digest AND sequence; a stale pointer can never satisfy deployed() (2.22).
    const identity = {
      sandboxId,
      applicationId: version.identity.applicationId,
      versionId: version.versionId,
      digest: version.packageDigest,
      sequence: version.identity.sequence,
    };
    try {
      if (!(await packageStore.deployed(sandboxId, identity))) {
        await packageStore.deploy(sandboxId, identity);
      }
    } catch (error) {
      const wrapped = codedError("DEPLOYMENT_OBJECT_MISSING", "version deployment object could not be created from the snapshot");
      wrapped.cause = error;
      throw wrapped;
    }
  }

  // Per-application persistent-data plane provisioning (2.27): one storage
  // secret and one data credential per application, issued once and reused
  // across versions so data authority survives updates and rollback. Version
  // deletion never removes it; only the separate owner-authorized data-delete
  // operation destroys the data namespace itself.
  async function ensureAppData(applicationId) {
    if (!secrets.appData || typeof secrets.appData !== "object") secrets.appData = {};
    let entry = secrets.appData[applicationId];
    if (!entry) {
      entry = {
        version: 1,
        applicationId,
        storageSecret: randomBytes(32).toString("hex"),
        data: await issueDataCredential(applicationId),
      };
      secrets.appData[applicationId] = entry;
      saveSecrets();
    }
    return entry;
  }

  // 7.3 prepare: desired secrets persist before the supervisor creates
  // anything, and only after the immutable snapshot and deployment object
  // have been verified to exist.
  async function prepare(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const sandboxId = sandboxIdFor(version);
    const lifecycle = bundle.setVersionLifecycle(state(), applicationId, versionId, "preparing");
    if (lifecycle.ok) saveState(lifecycle.value.state);
    const markFailed = () => {
      const failed = bundle.setVersionLifecycle(state(), applicationId, versionId, "failed");
      if (failed.ok) saveState(failed.value.state);
    };
    try {
      await ensureSnapshotAndDeployment(version);
    } catch (error) {
      markFailed();
      throw error;
    }
    let secret = secrets.sandboxes[sandboxId];
    if (!secret) {
      const issued = await issueObjectCredential(sandboxId, "iweb-app-" + sandboxId);
      secret = {
        version: 1,
        sandboxId,
        versionId: bundle.versionLabel(version.identity),
        generation: version.identity.sequence,
        bucket: "iweb-app-" + sandboxId,
        object: issued.object,
        retire: issued.retire,
        createdAt: new Date(now()).toISOString(),
      };
      secrets.sandboxes[sandboxId] = secret;
      saveSecrets();
    }
    const appData = await ensureAppData(applicationId);
    // Fail closed before any supervisor side effect: an unconfigured or
    // self-referential object/data endpoint cannot produce a bootable gateway.
    assertEndpointReachable(secret.object.endpoint, "OBJECT_ENDPOINT");
    assertEndpointReachable(appData.data.endpoint, "DATA_ENDPOINT");
    try {
      await rpcClient.prepare(supervisorSocket, {
        sandboxId,
        versionIdentity: version.identity,
        packageDigest: version.packageDigest,
        policy: version.policy,
        object: secret.object,
        storageSecret: appData.storageSecret,
        data: appData.data,
      });
    } catch (error) {
      markFailed();
      throw error;
    }
    return { sandboxId };
  }

  // 7.4 readiness through the fixed health contract on the private ingress.
  async function probeReady(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const sandboxId = sandboxIdFor(version);
    const label = bundle.versionLabel(version.identity);
    const result = await bundle.probeReadiness({
      fetch: async (url) => rpcClient.socketGet(gatewaySocket(sandboxId), new URL(url).pathname + new URL(url).search),
      baseUrl: "http://ingress",
      versionId: label,
      generation: version.identity.sequence,
      maxAttempts: readiness.maxAttempts ?? 10,
      attemptTimeoutMs: readiness.attemptTimeoutMs ?? 3000,
      intervalMs: readiness.intervalMs ?? 500,
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    });
    if (result.ready) {
      const expiresAt = new Date(now() + READINESS_LEASE_MS).toISOString();
      const marked = bundle.markVersionReady(state(), applicationId, versionId, expiresAt);
      if (marked.ok) saveState(marked.value.state);
    }
    return result;
  }

  // 7.4 atomic activation: exactly one active pointer switches and increments
  // the route generation; the previous version is preserved for rollback.
  function activate(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const leaseValid = version.lifecycle === "ready" && version.readinessExpiresAt !== null && Date.parse(version.readinessExpiresAt) > now();
    if (!leaseValid) throw codedError("NOT_READY", "candidate version has no valid readiness lease");
    const activation = bundle.activateVersion(state(), applicationId, versionId);
    if (!activation.ok) throw codedError(activation.errors[0]?.code ?? "ACTIVATION_REJECTED", "activation rejected");
    saveState(activation.value.state);
    return {
      generation: activation.value.state.applications[applicationId].active.routeGeneration,
      retired: activation.value.retired ? sandboxIdFor(activation.value.retired) : null,
    };
  }

  function rollback(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const leaseValid = version.lifecycle === "ready" && version.readinessExpiresAt !== null && Date.parse(version.readinessExpiresAt) > now();
    if (!leaseValid) throw codedError("NOT_READY", "target version has no valid readiness lease");
    const activation = bundle.rollbackVersion(state(), applicationId, versionId);
    if (!activation.ok) throw codedError(activation.errors[0]?.code ?? "ROLLBACK_REJECTED", "rollback rejected");
    saveState(activation.value.state);
    // 7.3 protocol union: rollback commits generation AND names the retired
    // version's sandbox so callers can verify drain targets. The production
    // response may never omit the declared retired field.
    return {
      generation: activation.value.state.applications[applicationId].active.routeGeneration,
      retired: activation.value.retired ? sandboxIdFor(activation.value.retired) : null,
    };
  }

  // The retired sandbox is drained (stopped) but retained for rollback.
  async function drainRetired(applicationId) {
    const application = state().applications[applicationId];
    if (!application) return [];
    const activeDigest = application.active.kind === "active" ? application.active.version.digest : null;
    const drained = [];
    for (const version of application.versions) {
      if (version.lifecycle !== "retired") continue;
      const sandboxId = sandboxIdFor(version);
      try {
        await rpcClient.stop(supervisorSocket, sandboxId);
        drained.push(sandboxId);
      } catch (error) {
        if (error?.code !== "SUPERVISOR_UNREACHABLE") throw error;
      }
    }
    return drained;
  }

  async function startVersion(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const sandboxId = sandboxIdFor(version);
    await rpcClient.start(supervisorSocket, sandboxId);
    const preparing = bundle.setVersionLifecycle(state(), applicationId, versionId, "preparing");
    if (preparing.ok) saveState(preparing.value.state);
    return { sandboxId };
  }

  async function stopVersion(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const sandboxId = sandboxIdFor(version);
    await rpcClient.stop(supervisorSocket, sandboxId);
    const stopped = bundle.setVersionLifecycle(state(), applicationId, versionId, "stopped");
    if (stopped.ok) saveState(stopped.value.state);
    return { sandboxId };
  }

  async function inspectVersion(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const sandboxId = sandboxIdFor(version);
    return rpcClient.inspect(supervisorSocket, sandboxId);
  }

  async function deleteVersion(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const sandboxId = sandboxIdFor(version);
    const removal = bundle.removeVersion(state(), applicationId, versionId);
    if (!removal.ok) throw codedError(removal.errors[0]?.code ?? "DELETE_REJECTED", "version deletion rejected");
    // Retire the per-version object authority with the version lifecycle BEFORE
    // removing the supervisor resource, so a leaked credential stops working
    // even if the supervisor is unreachable; a retire failure aborts deletion.
    const secret = secrets.sandboxes[sandboxId];
    if (secret && secret.retire) await retireObjectCredential(secret.retire);
    await rpcClient.remove(supervisorSocket, sandboxId);
    saveState(removal.value.state);
    if (secret) {
      delete secrets.sandboxes[sandboxId];
      saveSecrets();
    }
    return { sandboxId };
  }

  async function sandboxMetrics(applicationId, versionId) {
    const version = requireVersion(applicationId, versionId);
    const sandboxId = sandboxIdFor(version);
    return rpcClient.metrics(supervisorSocket, sandboxId, bundle.versionLabel(version.identity));
  }

  // 7.5 restart reconciliation from admitted versions only. Unknown resources
  // are quarantined by the supervisor; Kernel reports observations and stale
  // states without executing mutable workspace content.
  async function reconcile() {
    const report = { missingActive: [], stalePreparing: [], observations: {} };
    for (const application of Object.values(state().applications)) {
      for (const version of application.versions) {
        const sandboxId = sandboxIdFor(version);
        let observation = null;
        try {
          observation = await rpcClient.inspect(supervisorSocket, sandboxId);
        } catch (error) {
          observation = { error: error?.code ?? "SUPERVISOR_ERROR" };
        }
        report.observations[sandboxId] = observation;
        const activeMissing =
          application.active.kind === "active" &&
          application.active.version.digest === version.versionId &&
          (observation === null || observation.error !== undefined || observation.state === "failed");
        if (activeMissing) report.missingActive.push({ applicationId: application.applicationId, versionId: version.versionId, sandboxId });
        if (version.lifecycle === "preparing" && (observation === null || observation.error !== undefined || observation.state === "failed" || observation.state === "stopped")) {
          report.stalePreparing.push({ applicationId: application.applicationId, versionId: version.versionId, sandboxId });
        }
      }
    }
    return report;
  }

  // 7.6 recovery: restart missing active sandboxes from their admitted version
  // and persisted secrets. Never re-admits or executes mutable workspace code.
  async function recoverMissingActive() {
    const report = await reconcile();
    const recovered = [];
    for (const entry of report.missingActive) {
      const version = requireVersion(entry.applicationId, entry.versionId);
      const sandboxId = sandboxIdFor(version);
      const secret = secrets.sandboxes[sandboxId];
      if (!secret) throw codedError("RECOVERY_SECRET_MISSING", "sandbox secret is unavailable; re-admission is required");
      // Fail closed: recovery proceeds only from the verified immutable
      // snapshot and an existing deployment object — the same gate as a fresh
      // prepare — without disturbing the active lifecycle pointer.
      await ensureSnapshotAndDeployment(version);
      const appData = await ensureAppData(entry.applicationId);
      await rpcClient.prepare(supervisorSocket, {
        sandboxId,
        versionIdentity: version.identity,
        packageDigest: version.packageDigest,
        policy: version.policy,
        object: secret.object,
        storageSecret: appData.storageSecret,
        data: appData.data,
      });
      await rpcClient.start(supervisorSocket, sandboxId);
      recovered.push(sandboxId);
    }
    return { recovered };
  }

  // Owner-authorized destruction of an application's persistent-data namespace.
  // This is deliberately separate from version deletion: deleting a version must
  // never implicitly remove the application's durable data.
  function deleteApplicationData(applicationId) {
    return packageStore.deleteApplicationData(applicationId);
  }

  // Public surface: every mutation runs through the single-writer queue (2.46).
  // Reads (state, inspectVersion) stay concurrent.
  return {
    state,
    admit: (input) => serialized(() => admit(input)),
    prepare: (applicationId, versionId) => serialized(() => prepare(applicationId, versionId)),
    probeReady: (applicationId, versionId) => serialized(() => probeReady(applicationId, versionId)),
    activate: (applicationId, versionId) => serialized(() => activate(applicationId, versionId)),
    rollback: (applicationId, versionId) => serialized(() => rollback(applicationId, versionId)),
    drainRetired: (applicationId) => serialized(() => drainRetired(applicationId)),
    startVersion: (applicationId, versionId) => serialized(() => startVersion(applicationId, versionId)),
    stopVersion: (applicationId, versionId) => serialized(() => stopVersion(applicationId, versionId)),
    inspectVersion,
    deleteVersion: (applicationId, versionId) => serialized(() => deleteVersion(applicationId, versionId)),
    deleteApplicationData: (applicationId) => serialized(() => deleteApplicationData(applicationId)),
    sandboxMetrics,
    reconcile: () => serialized(() => reconcile()),
    recoverMissingActive: () => serialized(() => recoverMissingActive()),
    sandboxIdFor,
    gatewaySocket,
  };
}

// Issues a per-version MinIO service-account credential whose object policy is
// scoped to exactly that version's bucket (read-only). This is the production
// issuer; tests inject their own. Credentials never enter logs or argv. exec,
// writeFile, and unlink are injectable so the exact platform commands and the
// per-version policy are unit-testable without a running MinIO.
function defaultObjectCredentialIssuer(endpoint, region, options) {
  const opts = options || {};
  const exec = opts.exec || (function (args) { return execFileSync("mc", args, { stdio: ["ignore", "pipe", "pipe"] }); });
  const writeFile = opts.writeFile || (function (file, content) { return fs.writeFileSync(file, content, { mode: 0o600 }); });
  const unlink = opts.unlink || (function (file) { return fs.rmSync(file, { force: true }); });
  const tmpdir = opts.tmpdir || os.tmpdir();
  const parentUser = opts.parentUser || "iweb-sandbox-issuer";
  // 2.38: credentials NEVER enter argv. mc generates the access/secret pair
  // itself when --access-key/--secret-key are omitted and prints them via
  // --json on stdout (verified on the real node); only the policy file path
  // appears in argv. The parent is the pre-provisioned issuer account, so
  // issuance runs no user-add command at all.
  // svcacct add embeds the inline policy DOCUMENT (file path, verified on a
  // real node); no named policy exists to retire — the account itself is
  // removed by access key on retirement.
  return function issue(sandboxId, bucket) {
    const policyFile = tmpdir + "/iweb-policy-" + sandboxId + "-" + randomBytes(8).toString("hex") + ".json";
    writeFile(policyFile, JSON.stringify(versionScopedObjectPolicy(bucket), null, 2) + "\n");
    const output = exec(["admin", "user", "svcacct", "add", "--json", "--policy", policyFile, "local", parentUser]);
    unlink(policyFile);
    const created = JSON.parse(output);
    if (created.status !== "success" || typeof created.accessKey !== "string" || typeof created.secretKey !== "string") {
      throw codedError("CREDENTIAL_ISSUANCE_FAILED", "service account generation failed");
    }
    return {
      object: { endpoint: endpoint, region: region, accessKeyId: created.accessKey, secretAccessKey: created.secretKey },
      retire: { accessKey: created.accessKey, parentUser: parentUser },
    };
  };
}

// Issues a per-application data credential: read/write authority over exactly
// this application's stable data namespace (iweb-apps/<applicationId>/data/).
// Issued once per application and reused across versions; retire happens only
// via the separate owner-authorized data-delete operation. Injectables mirror
// defaultObjectCredentialIssuer for unit testing.
function defaultDataCredentialIssuer(endpoint, region, options) {
  const opts = options || {};
  const exec = opts.exec || (function (args) { return execFileSync("mc", args, { stdio: ["ignore", "pipe", "pipe"] }); });
  const writeFile = opts.writeFile || (function (file, content) { return fs.writeFileSync(file, content, { mode: 0o600 }); });
  const unlink = opts.unlink || (function (file) { return fs.rmSync(file, { force: true }); });
  const tmpdirPath = opts.tmpdir || os.tmpdir();
  const parentUser = opts.parentUser || "iweb-sandbox-issuer";
  // 2.38: same argv-free issuance as the version credential — mc generates the
  // pair and prints it via --json; only the policy file path appears in argv.
  return async function issue(applicationId) {
    const policyFile = tmpdirPath + "/iweb-policy-data-" + applicationId + "-" + randomBytes(8).toString("hex") + ".json";
    writeFile(policyFile, JSON.stringify(applicationDataPolicy(applicationId), null, 2) + "\n");
    const output = exec(["admin", "user", "svcacct", "add", "--json", "--policy", policyFile, "local", parentUser]);
    const created = JSON.parse(output);
    if (created.status !== "success" || typeof created.accessKey !== "string" || typeof created.secretKey !== "string") {
      throw codedError("CREDENTIAL_ISSUANCE_FAILED", "service account generation failed");
    }
    return { endpoint: endpoint, region: region, accessKeyId: created.accessKey, secretAccessKey: created.secretKey };
  };
}

// Retires a version's object authority with its lifecycle: the parent user and
// the per-version policy are removed so a leaked credential can no longer reach
// any object. exec is injectable for unit testing.
function defaultRetireObjectCredential(options) {
  const opts = options || {};
  const exec = opts.exec || (function (args) { return execFileSync("mc", args, { stdio: ["ignore", "pipe", "pipe"] }); });
  return async function retire(retire) {
    if (!retire || typeof retire !== "object") return;
    // Inline-policy service accounts carry no named policy; retirement removes
    // the account itself so a leaked credential stops working immediately.
    // Real-node syntax: svcacct rm takes ALIAS ACCESSKEY only (the parent user
    // is implied by the admin credential performing the removal).
    if (typeof retire.accessKey === "string" && retire.accessKey) {
      exec(["admin", "user", "svcacct", "rm", "local", retire.accessKey]);
    }
    if (typeof retire.policyName === "string" && retire.policyName) exec(["admin", "policy", "rm", "local", retire.policyName]);
  };
}

module.exports = { createApplicationControl, READINESS_LEASE_MS, codedError, defaultObjectCredentialIssuer, defaultRetireObjectCredential };
