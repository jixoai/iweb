// 用户原始需求（2026-08-14）：Kernel 是 CommonJS；安全契约模块经一次 bun bundle 编译为单文件 CJS 供其 require。
// 正交意图：只再导出 Kernel 需要的最小 API；构建脚本 scripts/build-kernel-contracts.bun.ts 生成 kernel/contracts-bundle.cjs。
export {
	activateVersion,
	admitVersion,
	controlStateFromFile,
	controlStateToFile,
	emptyControlState,
	emptyControlStateFile,
	markVersionReady,
	removeVersion,
	rollbackVersion,
	setVersionLifecycle,
	validateControlStateFile,
	type ApplicationRecord,
	type ControlState,
	type ControlStateFile,
	type VersionRecord,
} from "../packages/contracts/control-db.ts";
export { ControlStore, systemControlStoreIO, type ControlStoreIO } from "../packages/contracts/control-store.ts";
export { versionLabel, type LifecycleState, type ResourceSample } from "../packages/contracts/records.ts";
export { correlateResponse, deriveSandboxId, PROTOCOL_VERSION, validateSupervisorResponse } from "../packages/contracts/protocol.ts";
export { resolveActiveSandboxId, resolveRoute, routeAction, type RouteAction } from "../packages/contracts/routing.ts";
export { normalizePublicObjectPath, parsePublicObjectSet, resolvePublicObject } from "../packages/contracts/public-objects.ts";
export { projectSandboxResources, sanitizeMonitorFrame } from "../packages/contracts/monitor-frame.ts";
export { handleVersionAction } from "../packages/contracts/lifecycle-routes.ts";
export { collectPackage, packageFilesDigest, versionDigest, type PackageFileEntry, type PackageSnapshot } from "../packages/contracts/package-collection.ts";
export { validateApplicationManifest } from "../packages/contracts/manifest.ts";
export { probeReadiness, readinessUrl, parseHealthPayload, type ReadinessResult } from "../supervisor/readiness.ts";
export {
	validateApplicationId,
	validateBucketName,
	validateCredentialString,
	validateObjectEndpoint,
	validateObjectCredentialRecord,
	validateSha256Digest,
	validateStorageSecret,
	validateTimestamp,
	validateVersionDeploymentRecord,
	deploymentRecordMatches,
	type VersionDeploymentRecord,
} from "../packages/contracts/persisted-records.ts";
