// 用户原始需求（2026-08-13）：应用沙箱通过独立安全验收前，任意应用发布与执行必须保持关闭。
// 正交意图：要求显式开关；要求镜像验收证明；提供有界状态；默认失败关闭。
const fs = require("node:fs");

const DEFAULT_ACCEPTANCE_FILE = "/opt/iweb/release/sandbox-acceptance.json";

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

module.exports = { DEFAULT_ACCEPTANCE_FILE, evaluateApplicationPublicationGate, requireApplicationPublication };
