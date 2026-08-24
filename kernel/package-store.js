// Production content-addressed package snapshot and version deployment-object
// store for sandboxed application versions (OpenSpec 2.22).
//
// Snapshots persist under the non-anonymous system alias (never the anonymous
// iweb-workspace bucket) and are content-addressed by the single contracts
// digest authority. A snapshot is laid out as:
//   <alias>/packages/<digest>/manifest.json   canonical manifest
//   <alias>/packages/<digest>/files.json      stable index of file paths
//   <alias>/packages/<digest>/files/<path>    each file's bytes
// The private version deployment objects are created from that snapshot with
// fixed mc commands only; no package-provided script ever runs. Verification
// recomputes the digest from restored content so a missing or tampered snapshot
// is detected before any sandbox is prepared or recovered.
//
// Only full-key mc operations are used (pipe/cat/cp/mb/stat) so the store never
// depends on the relative-key semantics of "mc ls --recursive". exec is
// injectable: the default shells out to mc, and tests assert the exact platform
// commands without a running MinIO. Credentials never enter argv.
const { execFileSync } = require("node:child_process");
const bundle = require("./contracts-bundle.cjs");

const PACKAGE_PREFIX = "packages";

function defaultExec(args, options) {
  const opts = options || {};
  return execFileSync("mc", args, {
    encoding: opts.encoding === undefined ? "utf8" : opts.encoding,
    maxBuffer: opts.maxBuffer || 16 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"],
    input: opts.input,
  });
}

function isValidApplicationId(applicationId) {
  return typeof applicationId === "string" && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(applicationId);
}

function sortedPaths(files) {
  return files.map(function (file) { return file.path; }).sort(function (a, b) { return a.localeCompare(b); });
}

// Production store bound to a system alias such as "local/iweb-system".
function mcPackageStore(systemAlias, options) {
  const opts = options || {};
  const exec = opts.exec || defaultExec;
  const aliasHost = systemAlias.split("/")[0];
  const dataRoot = aliasHost + "/iweb-apps";

  function snapshotPrefix(digest) {
    return systemAlias + "/" + PACKAGE_PREFIX + "/" + digest;
  }
  function versionBucket(sandboxId) {
    return aliasHost + "/iweb-app-" + sandboxId;
  }
  function versionBucketName(sandboxId) {
    return "iweb-app-" + sandboxId;
  }

  function readIndex(digest) {
    const prefix = snapshotPrefix(digest);
    const text = exec(["cat", prefix + "/files.json"], { encoding: "utf8" });
    const parsed = JSON.parse(text);
    if (!parsed || !Array.isArray(parsed.files)) throw new Error("snapshot file index is malformed");
    return { prefix: prefix, paths: parsed.files };
  }

  async function persist(digest, manifest, files) {
    const prefix = snapshotPrefix(digest);
    const paths = sortedPaths(files);
    exec(["pipe", prefix + "/manifest.json"], { input: Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf8") });
    exec(["pipe", prefix + "/files.json"], { input: Buffer.from(JSON.stringify({ v: 1, files: paths }, null, 2) + "\n", "utf8") });
    for (const file of files) {
      exec(["pipe", prefix + "/files/" + file.path], { input: file.content });
    }
  }

  function isSafeRelativePath(value) {
    return typeof value === "string" && value.length > 0 && value.length <= 512 && !value.startsWith("/") && value.split("/").every(function (segment) { return segment.length > 0 && segment !== "." && segment !== ".."; });
  }

  function readManifest(digest) {
    const text = exec(["cat", snapshotPrefix(digest) + "/manifest.json"], { encoding: "utf8" });
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object") throw new Error("snapshot manifest is malformed");
    return parsed;
  }

  // The staged project main is derived from the snapshot manifest (the single
  // admission authority): <assets.root>/<runtime.entrypoint>, both validated as
  // safe relative paths so a tampered manifest cannot escape the stage.
  function projectMain(manifest) {
    const entrypoint = manifest && manifest.runtime && manifest.runtime.entrypoint;
    const assetsRoot = (manifest && manifest.assets && manifest.assets.root) || "app";
    if (!isSafeRelativePath(String(entrypoint)) || !isSafeRelativePath(String(assetsRoot))) throw new Error("manifest entrypoint or assets root is not a safe relative path");
    return assetsRoot + "/" + entrypoint;
  }

  async function verify(digest) {
    let index;
    try {
      index = readIndex(digest);
    } catch (error) {
      return null; // absent or unreadable index
    }
    if (index.paths.length === 0) return null;
    const restored = [];
    for (const path of index.paths) {
      let content;
      try {
        content = exec(["cat", index.prefix + "/files/" + path], { encoding: null });
      } catch (error) {
        return null; // corrupt: indexed but unreadable
      }
      restored.push({ path: path, content: content });
    }
    return bundle.packageFilesDigest(restored);
  }

  // 2.33: the real deployment flow. The materialized snapshot files are staged
  // as a celld project (app files + a generated wrangler.jsonc naming the
  // package entrypoint), then the pinned `celld deploy` publishes the
  // deployment objects into the version bucket. Credentials ride the child
  // environment (never argv): a one-shot deploy credential is generated the
  // argv-free way and retired after the deploy. The snapshot stays the sole
  // authority; no package-provided code executes on the Kernel side.
  //
  // 2.22: a deployment is only complete when the bucket carries BOTH the
  // celld deployment pointer (deploy/current.json, well-formed object) AND the
  // Kernel-owned version-deployment record (deploy/version.json) whose every
  // identity field matches the requested version exactly. The record is
  // written after the celld deploy and verified by reading it back; any
  // missing, partial, stale, or mismatched state fails closed.
  const DEPLOYMENT_RECORD_KEY = "deploy/version.json";

  function expectedIdentity(sandboxId, identity) {
    if (!identity || typeof identity !== "object") throw new Error("deploy/deployed require the full version identity");
    return {
      sandboxId: sandboxId,
      applicationId: identity.applicationId,
      versionId: identity.versionId,
      digest: identity.digest,
      sequence: identity.sequence,
    };
  }

  function readDeploymentRecord(bucketKey) {
    const text = exec(["cat", bucketKey + "/" + DEPLOYMENT_RECORD_KEY], { encoding: "utf8" });
    return JSON.parse(text);
  }

  async function deploy(sandboxId, identity, options) {
    const opts = options || {};
    const expected = expectedIdentity(sandboxId, identity);
    const digest = expected.digest;
    const bucketKey = versionBucket(sandboxId);
    const bucketName = versionBucketName(sandboxId);
    // Fail closed before anything is created: the snapshot must restore to
    // exactly the admitted digest. A missing/partial/tampered snapshot is an
    // infrastructure failure, never a deploy from other content (2.22).
    const verified = await verify(digest);
    if (verified === null) throw new Error("admitted package snapshot is absent or unreadable; refusing to deploy");
    if (verified !== digest) throw new Error("admitted package snapshot content does not match its digest; refusing to deploy");
    exec(["mb", "--ignore-existing", bucketKey]);
    const index = readIndex(digest);
    const manifest = readManifest(digest);
    const stageDirectory = (typeof opts.stageDirectory === "function" ? opts.stageDirectory(sandboxId, digest) : opts.stageDirectory) || "/tmp/iweb-deploy-" + sandboxId;
    const context = { sandboxId: sandboxId, digest: digest, name: (typeof manifest.name === "string" && manifest.name) || sandboxId, main: projectMain(manifest), assetsRoot: (manifest.assets && manifest.assets.root) || "app" };
    opts.stage && opts.stage(index.prefix, stageDirectory, context);
    // A production deploy MUST run the pinned celld flow: creating the bucket
    // alone is never a deployment. Hooks absent = misconfiguration, fail closed.
    if (typeof opts.deployCelld !== "function") throw new Error("production deploy requires the celld deploy hook");
    const env = opts.deployEnv ? opts.deployEnv(bucketName) : {};
    try {
      opts.deployCelld(stageDirectory, bucketName, env);
    } finally {
      opts.deployDone && opts.deployDone(bucketName);
    }
    // Fail closed: the deploy must have produced the deployment pointer the
    // runtime boots from; a silent no-op celld hook is a failed deploy (2.33).
    let pointer;
    try {
      pointer = exec(["cat", bucketKey + "/deploy/current.json"], { encoding: "utf8" });
    } catch (error) {
      throw new Error("celld deploy produced no deployment pointer (deploy/current.json)");
    }
    try {
      const parsed = JSON.parse(pointer);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("bad pointer");
    } catch (error) {
      throw new Error("deployment pointer deploy/current.json is malformed");
    }
    // 2.22: write the Kernel-owned version-deployment record and verify it by
    // reading it back through the shared field validator. Only then does this
    // bucket declare WHICH version it serves.
    const record = {
      v: 1,
      kind: "iweb-version-deployment",
      sandboxId: expected.sandboxId,
      applicationId: expected.applicationId,
      versionId: expected.versionId,
      digest: expected.digest,
      sequence: expected.sequence,
      deployedAt: new Date().toISOString(),
    };
    exec(["pipe", bucketKey + "/" + DEPLOYMENT_RECORD_KEY], { input: Buffer.from(JSON.stringify(record, null, 2) + "\n", "utf8") });
    let verifiedRecord;
    try {
      verifiedRecord = readDeploymentRecord(bucketKey);
    } catch (error) {
      throw new Error("deployment record deploy/version.json was not persisted by the deploy");
    }
    const validation = bundle.validateVersionDeploymentRecord(verifiedRecord);
    if (!validation.ok || !bundle.deploymentRecordMatches(validation.record, expected)) {
      throw new Error("deployment record deploy/version.json does not match the requested version identity");
    }
  }

  async function deployed(sandboxId, identity) {
    // A sandbox is deployed only when its version bucket carries a well-formed
    // celld deployment pointer (deploy/current.json) AND a version-deployment
    // record (deploy/version.json) that field-validates and matches the
    // requested applicationId/versionId/digest/sequence EXACTLY. Raw snapshot
    // files, an unparsable pointer, a missing record, or a stale record from
    // another version are all "not deployed" — prepare must redeploy or fail
    // bounded (2.22); it must never boot from stale bucket content.
    const expected = expectedIdentity(sandboxId, identity);
    const bucket = versionBucket(sandboxId);
    let pointer;
    try {
      pointer = exec(["cat", bucket + "/deploy/current.json"], { encoding: "utf8" });
    } catch (error) {
      return false;
    }
    try {
      const parsed = JSON.parse(pointer);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    } catch (error) {
      return false;
    }
    let recordText;
    try {
      recordText = exec(["cat", bucket + "/" + DEPLOYMENT_RECORD_KEY], { encoding: "utf8" });
    } catch (error) {
      return false;
    }
    let record;
    try {
      record = JSON.parse(recordText);
    } catch (error) {
      return false;
    }
    const validation = bundle.validateVersionDeploymentRecord(record);
    if (!validation.ok) return false;
    return bundle.deploymentRecordMatches(validation.record, expected);
  }

  async function deleteApplicationData(applicationId) {
    if (!isValidApplicationId(applicationId)) throw new Error("invalid applicationId");
    // Fixed platform command: removes only this application's persistent-data
    // namespace. Version deletion never reaches here; this is a distinct
    // owner-authorized destructive operation.
    exec(["rm", "--recursive", "--force", dataRoot + "/" + applicationId + "/data/"]);
  }

  return { persist: persist, verify: verify, deploy: deploy, deployed: deployed, deleteApplicationData: deleteApplicationData };
}

// In-memory store for tests and offline development: identical interface and
// digest authority, no external process.
function memoryPackageStore() {
  const snapshots = new Map();
  const deployments = new Map();
  const deletedData = new Set();
  return {
    async persist(digest, manifest, files) {
      snapshots.set(digest, { manifest: manifest, files: files.map(function (file) { return { path: file.path, content: file.content }; }) });
    },
    async verify(digest) {
      const snapshot = snapshots.get(digest);
      if (!snapshot) return null;
      return bundle.packageFilesDigest(snapshot.files);
    },
    async deploy(sandboxId, identity) {
      if (!identity || typeof identity !== "object") throw new Error("deploy requires the full version identity");
      if (!snapshots.has(identity.digest)) throw new Error("cannot deploy an absent snapshot");
      deployments.set(sandboxId, {
        applicationId: identity.applicationId,
        versionId: identity.versionId,
        digest: identity.digest,
        sequence: identity.sequence,
      });
    },
    async deployed(sandboxId, identity) {
      const record = deployments.get(sandboxId);
      if (!record || !identity || typeof identity !== "object") return false;
      return (
        record.applicationId === identity.applicationId &&
        record.versionId === identity.versionId &&
        record.digest === identity.digest &&
        record.sequence === identity.sequence
      );
    },
    async deleteApplicationData(applicationId) {
      if (!isValidApplicationId(applicationId)) throw new Error("invalid applicationId");
      deletedData.add(applicationId);
    },
    deletedApplicationIds() {
      return [...deletedData];
    },
  };
}

// Read-only-plus-runtime-state object authority scoped to exactly one immutable
// application version bucket (2.34). The POLICY ITSELF is least-privilege —
// Gateway HTTP denials are defense-in-depth, not the boundary:
//   - GetObject only under deploy/, nodes/, fleet/, cells/ (never bucket-wide)
//   - ListBucket ONLY under a StringLike prefix condition covering those same
//     prefixes; bucket-wide listing is NOT granted
//   - PutObject only under nodes/, fleet/, cells/ (celld's own runtime state);
//     deploy/* is immutable to the runtime — only the Kernel's one-shot deploy
//     credential may write it
//   - no DeleteObject, no cross-bucket resource, no signing paths
function versionScopedObjectPolicy(bucket) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetObject"],
        Resource: [
          "arn:aws:s3:::" + bucket + "/deploy/*",
          "arn:aws:s3:::" + bucket + "/nodes/*",
          "arn:aws:s3:::" + bucket + "/fleet/*",
          "arn:aws:s3:::" + bucket + "/cells/*",
        ],
      },
      {
        Effect: "Allow",
        Action: ["s3:ListBucket"],
        Resource: ["arn:aws:s3:::" + bucket],
        Condition: {
          StringLike: {
            "s3:prefix": ["deploy/", "deploy/*", "nodes/", "nodes/*", "fleet/", "fleet/*", "cells/", "cells/*"],
          },
        },
      },
      {
        Effect: "Allow",
        Action: ["s3:PutObject"],
        Resource: [
          "arn:aws:s3:::" + bucket + "/nodes/*",
          "arn:aws:s3:::" + bucket + "/fleet/*",
          "arn:aws:s3:::" + bucket + "/cells/*",
        ],
      },
    ],
  };
}

// One-shot authority for the Kernel's celld-deploy step: full read/write on
// exactly one version bucket for the duration of the deploy, then retired.
function versionDeployPolicy(bucket) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
        Resource: ["arn:aws:s3:::" + bucket, "arn:aws:s3:::" + bucket + "/*"],
      },
    ],
  };
}

// Read-write object authority scoped to exactly one application's stable
// persistent-data namespace (iweb-apps/<applicationId>/data/). The application
// data credential can Get/Put/Delete objects only inside its own data prefix:
// no listing, no reach into another application, the version buckets, or the
// workspace. Version credentials stay read-only (versionScopedObjectPolicy).
function applicationDataPolicy(applicationId) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        Resource: ["arn:aws:s3:::iweb-apps/" + applicationId + "/data", "arn:aws:s3:::iweb-apps/" + applicationId + "/data/*"],
      },
    ],
  };
}

// Read-only snapshot authority for the sandbox supervisor materializer
// (2.48/4.2): the service identity may read ONLY the admitted package
// snapshots under packages/ of the system bucket - no writes, no deletes, no
// bucket-wide listing, no reach into workspace, version buckets, or data
// namespaces. The installer issues a service-account credential carrying
// exactly this policy to the iweb-sandbox host user, so the running
// supervisor reads snapshots through a documented, reproducible path instead
// of a developer shell alias.
function snapshotReadPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:GetObject"],
        Resource: ["arn:aws:s3:::iweb-system/packages/*"],
      },
      {
        Effect: "Allow",
        Action: ["s3:ListBucket"],
        Resource: ["arn:aws:s3:::iweb-system"],
        Condition: {
          StringLike: { "s3:prefix": ["packages/", "packages/*"] },
        },
      },
    ],
  };
}

module.exports = { mcPackageStore: mcPackageStore, memoryPackageStore: memoryPackageStore, versionScopedObjectPolicy: versionScopedObjectPolicy, versionDeployPolicy: versionDeployPolicy, applicationDataPolicy: applicationDataPolicy, snapshotReadPolicy: snapshotReadPolicy };
