// 用户原始需求（2026-08-14）：admitted snapshot 必须经真实 pinned celld deploy 发布成版本部署对象；Kernel 侧绝不执行包内代码。
// 正交意图：2.33/2.48 生产 deploy hooks——物化快照为 celld 项目（mc cat 逐文件）、argv-free 一次性部署凭据
// （versionDeployPolicy 只授权该版本桶）、固定 celld deploy 命令行、部署后立即退役凭据。
// exec/run/writeFile/unlink 均可注入：单测断言确切平台命令与凭据不进 argv。
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { randomBytes } = require("node:crypto");
const { versionDeployPolicy } = require("./package-store.js");

// The image-pinned celld binary (same binary the trusted Dispatcher deploys
// with); overridable for node layouts and tests.
function createDeployHooks(options) {
  const opts = options || {};
  const celldBinary = opts.celldBinary || process.env.IWEB_CELLD_BINARY || "celld";
  const endpoint = opts.endpoint || process.env.IWEB_CELLD_ENDPOINT;
  const region = opts.region || process.env.IWEB_CELLD_REGION || "us-east-1";
  const stageRoot = opts.stageRoot || process.env.IWEB_DEPLOY_STAGE_ROOT || "/var/lib/iweb/deploy";
  const parentUser = opts.parentUser || "iweb-sandbox-issuer";
  const alias = opts.alias || "local";
  const mc = opts.mc || function (args, execOptions) {
    return execFileSync("mc", args, Object.assign({ stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 }, execOptions || {}));
  };
  const runCelld = opts.runCelld || function (args, execOptions) {
    return execFileSync(celldBinary, args, Object.assign({ stdio: ["ignore", "pipe", "pipe"] }, execOptions || {}));
  };
  const writeFile = opts.writeFile || function (file, content, mode) { fs.writeFileSync(file, content, { mode: mode }); };
  const mkdirSync = opts.mkdirSync || fs.mkdirSync;
  const rmSync = opts.rmSync || fs.rmSync;
  const tmpdir = opts.tmpdir || os.tmpdir();
  if (!endpoint) throw new Error("production celld deploy requires IWEB_CELLD_ENDPOINT");
  let activeRetire = null;

  return {
    // Deterministic per-sandbox per-digest stage directory.
    stageDirectory: function (sandboxId, digest) {
      return path.join(stageRoot, sandboxId, digest);
    },

    // Materialize the verified snapshot into a celld project: every indexed
    // file byte-for-byte through mc (the object store is the only source), plus
    // a generated descriptor naming the manifest entrypoint. No package code
    // ever executes on the Kernel side.
    stage: function (prefix, stageDirectory, context) {
      rmSync(stageDirectory, { recursive: true, force: true });
      mkdirSync(stageDirectory, { recursive: true, mode: 0o700 });
      const indexText = String(mc(["cat", prefix + "/files.json"]));
      const index = JSON.parse(indexText);
      if (!index || !Array.isArray(index.files) || index.files.length === 0) throw new Error("snapshot index is malformed or empty");
      for (const file of index.files) {
        if (typeof file !== "string" || file.startsWith("/") || file.split("/").some(function (s) { return s === ".." || s === "." || s.length === 0; })) {
          throw new Error("snapshot index contains an unsafe path");
        }
        const destination = path.join(stageDirectory, file);
        mkdirSync(path.dirname(destination), { recursive: true });
        writeFile(destination, Buffer.from(mc(["cat", prefix + "/files/" + file], { encoding: null })), 0o644);
      }
      const descriptor = { name: context.name, main: context.main, compatibility_date: "2026-08-01" };
      writeFile(path.join(stageDirectory, "wrangler.jsonc"), JSON.stringify(descriptor, null, 2) + "\n", 0o644);
    },

    // One-shot deploy credential, argv-free exactly like the runtime credential:
    // mc generates the pair and prints it as JSON; only the policy document file
    // path appears in argv. Scoped by versionDeployPolicy to the single bucket.
    deployEnv: function (bucketName) {
      const policyFile = path.join(tmpdir, "iweb-policy-deploy-" + bucketName + "-" + randomBytes(8).toString("hex") + ".json");
      writeFile(policyFile, JSON.stringify(versionDeployPolicy(bucketName), null, 2) + "\n", 0o600);
      let created;
      try {
        created = JSON.parse(String(mc(["admin", "user", "svcacct", "add", "--json", "--policy", policyFile, alias, parentUser])));
      } finally {
        try { (opts.unlink || fs.rmSync)(policyFile, { force: true }); } catch (e) { /* best-effort */ }
      }
      if (!created || created.status !== "success" || typeof created.accessKey !== "string" || typeof created.secretKey !== "string") {
        throw new Error("deploy credential issuance failed");
      }
      activeRetire = created.accessKey;
      return { AWS_ACCESS_KEY_ID: created.accessKey, AWS_SECRET_ACCESS_KEY: created.secretKey };
    },

    // The pinned platform command, mirroring the trusted Dispatcher deploy in
    // scripts/iweb-entrypoint.sh. Credentials ride the child environment only.
    deployCelld: function (stageDirectory, bucketName, env) {
      runCelld(["deploy", stageDirectory, "--bucket", "s3://" + bucketName, "--endpoint", endpoint, "--region", region], {
        env: { AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY: env.AWS_SECRET_ACCESS_KEY },
      });
    },

    // Retire the one-shot credential as soon as the deploy attempt finishes,
    // success or failure.
    deployDone: function () {
      if (!activeRetire) return;
      const accessKey = activeRetire;
      activeRetire = null;
      try {
        // real-node syntax: svcacct rm takes ALIAS ACCESSKEY only
        mc(["admin", "user", "svcacct", "rm", alias, accessKey]);
      } catch (e) {
        // retirement is best-effort; the credential is scoped to one bucket
      }
    },
  };
}

module.exports = { createDeployHooks: createDeployHooks };
