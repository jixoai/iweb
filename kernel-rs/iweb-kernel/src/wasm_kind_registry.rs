//! 用户原始需求（2026-08-30，two-tier-runtime-trust）：Kernel 业务权威收敛为 wasm
//! 单注册表——严格 `WasmKernelRouteRegistryV1`、全局 kind-claim CAS 索引；终身 celld
//! claims 从**路由注册表**确定性派生（所有 `celld-app` 目标的应用名），与
//! wasm-control-state-v2 持久 claims 在启动时合并。celld 控制态文件、
//! `WASM_KIND_BOOTSTRAP_PENDING` 状态机与 `MigrationRecordV1` 跨 kind 迁移事务全部
//! 删除：bootstrap 成为确定性步骤（路由注册表可解析即成功），无 pending 失败模式。
//! 规范权威：openspec/changes/two-tier-runtime-trust/specs/wasm-application-runtime/spec.md
//! "Kernel business authority is a wasm-only registry"（含全部场景）。
//! wire 权威：packages/contracts/wasm-execution.ts（binding digest 公式与校验器），
//! Rust 侧字节一致复算；行/指针/proof 形状复用 wasm_admission.rs。
//!
//! 正交意图：
//! 1. digest 纯函数（kind binding digest）——与 TS 向量 golden 对齐（测试内再配
//!    独立 preimage oracle 双保险）；
//! 2. 全局 kind-claim CAS（applicationId 终身绑定一个 runtime kind；先取全局 claim
//!    CAS 再写 kind-specific registry，绝不反序；APPLICATION_RUNTIME_KIND_CONFLICT /
//!    APPLICATION_KIND_SPLIT_BRAIN fail-closed）；
//! 3. 路由派生 bootstrap：启动时从路由注册表读取所有 `target.kind == "celld-app"`
//!    的 appName，作为终身 celld claim 与共享 index 合并（幂等：已存在的字节一致
//!    claim 直接跳过；路由文件不可解析 → 节点启动失败，无 pending 模式）。
//!
//! 接线备注：启动序契约：先 `derive_celld_claims_from_routes` + `merge_route_derived_
//! claims` 完成确定性引导，再开放 wasm 写路径与 `recover`。celld-app 路由是镜像种子
//! （用户路由只能创建 `sandbox` kind），运行期不可变更，因此无需 digest 重验证链。

use crate::wasm_admission::{
    jcs_bytes, verify_admission_proof, AdmissionError, AdmissionProofV1,
    WasmKernelRouteRegistry, WASM_U53_MAX, WasmVersionRegistryRow,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// 常量与稳定错误码（spec 已命名码优先；补充码沿用 contracts 命名风格）
// ---------------------------------------------------------------------------

pub const KIND_CLAIM_BINDING_DIGEST_DOMAIN: &str = "iweb-application-kind-binding-v1";

pub const RUNTIME_KIND_CELLD: &str = "celld";
pub const RUNTIME_KIND_WASM: &str = "wasm";

/// bootstrap 状态投影的来源字面量（/v1/wasm/status 的 bootstrap.source）。
pub const KIND_CLAIM_SOURCE_ROUTE_REGISTRY: &str = "route-registry";

// spec 已命名的稳定码。
pub const APPLICATION_RUNTIME_KIND_CONFLICT: &str = "APPLICATION_RUNTIME_KIND_CONFLICT";
pub const APPLICATION_KIND_SPLIT_BRAIN: &str = "APPLICATION_KIND_SPLIT_BRAIN";
pub const WASM_BUSINESS_RECORD_MISSING: &str = "WASM_BUSINESS_RECORD_MISSING";

// contracts 已命名的补充码（TS KIND_CLAIM_CODE 与 digest mismatch 码）。
pub const WASM_KIND_CLAIM_INVALID: &str = "WASM_KIND_CLAIM_INVALID";
pub const KIND_CLAIM_BINDING_DIGEST_MISMATCH: &str = "KIND_CLAIM_BINDING_DIGEST_MISMATCH";

// spec 未命名的补充 fail-closed 码（不覆盖 spec 已命名码）。
pub const KIND_REGISTRY_REVISION_CONFLICT: &str = "KIND_REGISTRY_REVISION_CONFLICT";
pub const KIND_REGISTRY_STORE_IO: &str = "KIND_REGISTRY_STORE_IO";

/// 结构化错误：code 为稳定 owner 可见码，detail 携带路径/上下文，不含秘密。
#[derive(Debug, Clone, PartialEq)]
pub struct KindRegistryError {
    pub code: &'static str,
    pub detail: String,
}

impl KindRegistryError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl std::fmt::Display for KindRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for KindRegistryError {}

/// wasm_admission 侧错误的透传映射（code 原样保留，保持稳定码语义）。
fn aerr(error: AdmissionError) -> KindRegistryError {
    KindRegistryError { code: error.code, detail: error.detail }
}

fn err(code: &'static str, detail: impl Into<String>) -> KindRegistryError {
    KindRegistryError::new(code, detail)
}

fn kind_regexes() -> &'static KindRegexes {
    static REGEXES: OnceLock<KindRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| KindRegexes {
        sha256_hex: regex::Regex::new(r"^[a-f0-9]{64}$").expect("sha256 hex regex"),
        application_id: regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("application id regex"),
    })
}

struct KindRegexes {
    sha256_hex: regex::Regex,
    application_id: regex::Regex,
}

/// applicationId 文法（与 contracts WASM_APPLICATION_ID_PATTERN / wasm_admission 同款；
/// 那边的校验器是模块私有，这里独立设防避免改动共享文件）。
fn validate_kind_application_id(value: &str) -> Result<(), KindRegistryError> {
    if kind_regexes().application_id.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_KIND_CLAIM_INVALID, format!("applicationId must match ^[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?$: {value}")))
    }
}

fn validate_sha256_hex(value: &str, field: &str) -> Result<(), KindRegistryError> {
    if kind_regexes().sha256_hex.is_match(value) {
        Ok(())
    } else {
        Err(err(WASM_KIND_CLAIM_INVALID, format!("{field} must be 64 lower-case hex characters")))
    }
}

fn require_u53(value: u64, minimum: u64, field: &str) -> Result<(), KindRegistryError> {
    if value >= minimum && value <= WASM_U53_MAX {
        Ok(())
    } else {
        Err(err(WASM_KIND_CLAIM_INVALID, format!("{field} must be an integer between {minimum} and the u53 maximum")))
    }
}

fn domain_digest(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// 从原始字节解析 typed 记录：serde derive 自带 duplicate-member 检测 +
/// deny_unknown_fields 精确键集；原始字节必须等于 JCS(解析值)（对位 TS
/// parseStrictJson + jcsCanonicalBytes 比对，不接受"解析后等价"）。
fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8], code: &'static str, noun: &str) -> Result<T, KindRegistryError> {
    let parsed: T = serde_json::from_slice(bytes).map_err(|e| err(code, format!("{noun} bytes do not parse as the typed record: {e}")))?;
    let canonical = jcs_bytes(&parsed).map_err(aerr)?;
    if canonical != bytes {
        return Err(err(code, format!("{noun} bytes must equal JCS(parse(bytes))")));
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// digest 纯函数（逐字对照 contracts wasm-execution.ts；域前缀 + 单次 SHA-256）
// ---------------------------------------------------------------------------

/// binding digest 的 JCS preimage：{schemaVersion:1, applicationId, runtimeKind,
/// bindingRevision}（camelCase 键；BTreeMap 序即 RFC 8785 序）。
#[derive(Serialize)]
struct BindingDigestPreimage {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    #[serde(rename = "applicationId")]
    application_id: String,
    #[serde(rename = "runtimeKind")]
    runtime_kind: String,
    #[serde(rename = "bindingRevision")]
    binding_revision: u64,
}

/// bindingDigest = hex(SHA-256(UTF8("iweb-application-kind-binding-v1\n" ||
///   JCS({schemaVersion:1, applicationId, runtimeKind, bindingRevision})))。
pub fn kind_binding_digest(application_id: &str, runtime_kind: &str, binding_revision: u64) -> Result<String, KindRegistryError> {
    let preimage = BindingDigestPreimage {
        schema_version: 1,
        application_id: application_id.to_string(),
        runtime_kind: runtime_kind.to_string(),
        binding_revision,
    };
    let bytes = jcs_bytes(&preimage).map_err(aerr)?;
    Ok(domain_digest(KIND_CLAIM_BINDING_DIGEST_DOMAIN, &bytes))
}

// ---------------------------------------------------------------------------
// typed wire 记录（精确键集；camelCase 对位 contracts/spec）
// ---------------------------------------------------------------------------

/// RuntimeKindClaimV1 / ApplicationRuntimeKindBindingV1 的 claim 形状。
/// bindingRevision 从 1 起且永不改变；本实现值域内唯一合法值是 1。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeKindClaimV1 {
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "bindingRevision")]
    pub binding_revision: u64,
    #[serde(rename = "bindingDigest")]
    pub binding_digest: String,
}

/// `ApplicationRuntimeKindBindingV1`：/data/kernel/application-kind-registry-v1/
/// &lt;applicationId&gt;.json 的完整记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KindClaimBindingV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "applicationId")]
    pub application_id: String,
    #[serde(rename = "runtimeKind")]
    pub runtime_kind: String,
    #[serde(rename = "bindingRevision")]
    pub binding_revision: u64,
    #[serde(rename = "bindingDigest")]
    pub binding_digest: String,
}

/// 共享 CAS 索引：/data/kernel/application-kind-registry-v1/index.json。
/// 空索引 revision 0；每次 claim 变更恰好 +1；claims 按 applicationId 字节序严格排序。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KindClaimIndexV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    #[serde(rename = "registryRevision")]
    pub registry_revision: u64,
    pub claims: Vec<RuntimeKindClaimV1>,
}

impl Default for KindClaimIndexV1 {
    fn default() -> Self {
        // 空索引从 revision 0 起步，但 schemaVersion 恒为 1（不能 derive：会把 1 也归零）。
        Self { schema_version: 1, registry_revision: 0, claims: Vec::new() }
    }
}

// ---------------------------------------------------------------------------
// 记录校验（fail-closed；对位 contracts validator 语义）
// ---------------------------------------------------------------------------

fn sort_claims(claims: &mut [RuntimeKindClaimV1]) {
    claims.sort_by(|a, b| a.application_id.as_bytes().cmp(b.application_id.as_bytes()));
}

fn claims_strictly_sorted(claims: &[RuntimeKindClaimV1]) -> bool {
    claims.windows(2).all(|pair| pair[0].application_id.as_bytes() < pair[1].application_id.as_bytes())
}

/// 单条 claim 校验（celld/wasm 两 kind；bindingRevision 恒 1）。
fn validate_runtime_kind_claim(claim: &RuntimeKindClaimV1) -> Result<(), KindRegistryError> {
    validate_kind_application_id(&claim.application_id)?;
    if claim.runtime_kind != RUNTIME_KIND_CELLD && claim.runtime_kind != RUNTIME_KIND_WASM {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/runtimeKind must be one of: celld, wasm"));
    }
    // bindingRevision 从 1 起且永不改变；本实现唯一合法值 1。
    if claim.binding_revision != 1 {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/bindingRevision must be exactly 1 (it starts at 1 and never changes)"));
    }
    validate_sha256_hex(&claim.binding_digest, "bindingDigest")?;
    let recomputed = kind_binding_digest(&claim.application_id, &claim.runtime_kind, claim.binding_revision)?;
    if recomputed != claim.binding_digest {
        return Err(err(KIND_CLAIM_BINDING_DIGEST_MISMATCH, "bindingDigest must equal the application-kind-binding-v1 domain digest of the claim"));
    }
    Ok(())
}

pub fn validate_kind_claim_index(index: &KindClaimIndexV1) -> Result<(), KindRegistryError> {
    if index.schema_version != 1 {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/schemaVersion must be 1"));
    }
    require_u53(index.registry_revision, 0, "registryRevision")?;
    for claim in &index.claims {
        validate_runtime_kind_claim(claim)?;
    }
    if !claims_strictly_sorted(&index.claims) {
        return Err(err(WASM_KIND_CLAIM_INVALID, "/claims must be bytewise sorted by unique applicationId"));
    }
    Ok(())
}

// 存储抽象（kind-registry / migration；JCS 字节读写，文件层 tmp+rename 原子落盘）
// ---------------------------------------------------------------------------

pub trait KindRegistryStore {
    /// index.json 原始 JCS 字节（不存在 = 空索引 revision 0）。
    fn index_bytes(&self) -> Option<Vec<u8>>;
    fn write_index(&mut self, bytes: &[u8]) -> Result<(), KindRegistryError>;
    /// <applicationId>.json 原始 JCS 字节。
    fn binding_bytes(&self, application_id: &str) -> Option<Vec<u8>>;
    fn write_binding(&mut self, application_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError>;
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), KindRegistryError> {
    let temporary = path.with_extension(format!("tmp-{}", crate::monitor::now_millis()));
    std::fs::write(&temporary, bytes).map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot write {}: {e}", temporary.display())))?;
    std::fs::rename(&temporary, path).map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot rename into {}: {e}", path.display())))
}

/// kind-registry 目录存储：root = /data/kernel/application-kind-registry-v1。
/// 布局：index.json、<applicationId>.json。
#[derive(Debug, Clone)]
pub struct KindRegistryStoreDir {
    root: PathBuf,
}

impl KindRegistryStoreDir {
    pub fn open(root: &Path) -> Result<Self, KindRegistryError> {
        std::fs::create_dir_all(root)
            .map_err(|e| err(KIND_REGISTRY_STORE_IO, format!("cannot create kind registry root {}: {e}", root.display())))?;
        Ok(Self { root: root.to_path_buf() })
    }
}

impl KindRegistryStore for KindRegistryStoreDir {
    fn index_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.root.join("index.json")).ok()
    }

    fn write_index(&mut self, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(&self.root.join("index.json"), bytes)
    }

    fn binding_bytes(&self, application_id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.join(format!("{application_id}.json"))).ok()
    }

    fn write_binding(&mut self, application_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
        atomic_write(&self.root.join(format!("{application_id}.json")), bytes)
    }
}

// ---------------------------------------------------------------------------
// WasmKernelRouteRegistryV1：per-kind wasm registry + 全局 kind-claim CAS + bootstrap
// ---------------------------------------------------------------------------

/// 中断的 kind 事务重放句柄：byte-identical owner 事务（同 proof + 同
/// expectedKindRegistryRevision），恢复时幂等补全 claim+row。
#[derive(Debug, Clone)]
pub struct PendingKindTransaction {
    pub expected_kind_registry_revision: u64,
    pub proof: AdmissionProofV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KindClaimOutcome {
    /// true = 本次调用创建了 claim（revision +1）；false = 同 kind 幂等重试（零写入）。
    pub created: bool,
    pub claim: RuntimeKindClaimV1,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct KindRecoveryReport {
    /// 重放补全的 applicationId（claim 与 row 都已落位）。
    pub replayed: Vec<String>,
    /// 孤儿 claim（全局 claim 存在、kind-specific row 缺失）→ quarantine。
    pub quarantined_claims: Vec<String>,
    /// 孤儿 row（kind-specific row 存在、全局 claim 缺失）→ quarantine。
    pub quarantined_rows: Vec<String>,
}

/// Kernel 拥有的 wasm 单注册表（V1）：
/// - `records` 只承载 runtimeKind:"wasm" 的业务行/指针（复用 wasm_admission 的形状）；
/// - `index` 是 celld/wasm 共享的全局 kind-claim CAS 索引（applicationId 终身
///   绑定一个 runtime kind；celld claim 来自路由注册表的确定性派生）；
/// - `quarantined` 是恢复期隔离的 applicationId（fence，等 owner 修复 CAS）。
#[derive(Debug, Clone, Default)]
pub struct WasmKernelRouteRegistryV1 {
    index: KindClaimIndexV1,
    records: WasmKernelRouteRegistry,
    quarantined: BTreeMap<String, &'static str>,
}

impl WasmKernelRouteRegistryV1 {
    pub fn empty() -> Self {
        Self::default()
    }

    /// 从持久存储重建（index 全量校验；路由派生 claims 随后由
    /// merge_route_derived_claims 合并，无 pending 失败模式）。
    pub fn load(store: &dyn KindRegistryStore) -> Result<Self, KindRegistryError> {
        let index = match store.index_bytes() {
            Some(bytes) => {
                let parsed: KindClaimIndexV1 = parse_canonical(&bytes, WASM_KIND_CLAIM_INVALID, "kind claim index")?;
                validate_kind_claim_index(&parsed)?;
                parsed
            }
            None => KindClaimIndexV1::default(),
        };
        Ok(Self { index, records: WasmKernelRouteRegistry::default(), quarantined: BTreeMap::new() })
    }

    pub fn index(&self) -> &KindClaimIndexV1 {
        &self.index
    }

    pub fn registry_revision(&self) -> u64 {
        self.index.registry_revision
    }

    pub fn records(&self) -> &WasmKernelRouteRegistry {
        &self.records
    }

    pub fn claim(&self, application_id: &str) -> Option<&RuntimeKindClaimV1> {
        self.index.claims.iter().find(|claim| claim.application_id == application_id)
    }

    pub fn is_quarantined(&self, application_id: &str) -> Option<&'static str> {
        self.quarantined.get(application_id).copied()
    }

    fn ensure_not_quarantined(&self, application_id: &str) -> Result<(), KindRegistryError> {
        match self.quarantined.get(application_id) {
            Some(reason) => Err(err(APPLICATION_KIND_SPLIT_BRAIN, format!("applicationId {application_id} is fenced ({reason}) and waits for an owner repair CAS"))),
            None => Ok(()),
        }
    }

    /// 全局 kind-claim CAS。写序恒为：全局 claim（binding + index）→ kind-specific
    /// registry 写，绝不反序。同 kind 重试幂等（零写入零 revision 变更）；不同 kind
    /// 返回 APPLICATION_RUNTIME_KIND_CONFLICT 且不触碰任何 registry；期望 revision
    /// 不匹配返回 KIND_REGISTRY_REVISION_CONFLICT 且不写任何东西。
    pub fn claim_runtime_kind(
        &mut self,
        store: &mut dyn KindRegistryStore,
        application_id: &str,
        runtime_kind: &str,
        expected_kind_registry_revision: u64,
    ) -> Result<KindClaimOutcome, KindRegistryError> {
        if runtime_kind != RUNTIME_KIND_CELLD && runtime_kind != RUNTIME_KIND_WASM {
            return Err(err(WASM_KIND_CLAIM_INVALID, "runtimeKind must be one of: celld, wasm"));
        }
        self.ensure_not_quarantined(application_id)?;
        validate_kind_application_id(application_id)?;
        if let Some(existing) = self.claim(application_id) {
            if existing.runtime_kind == runtime_kind {
                return Ok(KindClaimOutcome { created: false, claim: existing.clone() });
            }
            return Err(err(
                APPLICATION_RUNTIME_KIND_CONFLICT,
                format!("applicationId {application_id} is permanently {}-bound; changing runtime kind requires a new applicationId", existing.runtime_kind),
            ));
        }
        if expected_kind_registry_revision != self.index.registry_revision {
            return Err(err(
                KIND_REGISTRY_REVISION_CONFLICT,
                format!("expectedKindRegistryRevision {expected_kind_registry_revision} != current {}; the claim CAS writes nothing on mismatch", self.index.registry_revision),
            ));
        }
        let binding_digest = kind_binding_digest(application_id, runtime_kind, 1)?;
        let claim = RuntimeKindClaimV1 { application_id: application_id.to_string(), runtime_kind: runtime_kind.to_string(), binding_revision: 1, binding_digest: binding_digest.clone() };
        let binding = KindClaimBindingV1 { schema_version: 1, application_id: claim.application_id.clone(), runtime_kind: claim.runtime_kind.clone(), binding_revision: 1, binding_digest };
        let mut next = self.index.clone();
        next.registry_revision += 1;
        next.claims.push(claim.clone());
        sort_claims(&mut next.claims);
        validate_kind_claim_index(&next)?;
        // 持久先于内存：任一写失败时内存索引不变，重试幂等重放同一步。
        store.write_binding(application_id, &jcs_bytes(&binding).map_err(aerr)?)?;
        store.write_index(&jcs_bytes(&next).map_err(aerr)?)?;
        self.index = next;
        Ok(KindClaimOutcome { created: true, claim })
    }

    /// 单个 kind 事务的统一路径：先全局 claim CAS，再 kind-specific row 插入
    /// （幂等）。恢复重放与正常注册共用，保证字节一致语义。
    fn apply_kind_transaction(&mut self, store: &mut dyn KindRegistryStore, transaction: &PendingKindTransaction) -> Result<WasmVersionRegistryRow, KindRegistryError> {
        verify_admission_proof(&transaction.proof).map_err(aerr)?;
        let application_id = transaction.proof.application_id.clone();
        self.claim_runtime_kind(store, &application_id, RUNTIME_KIND_WASM, transaction.expected_kind_registry_revision)?;
        self.records.insert_admitted(&transaction.proof).map_err(aerr)
    }

    /// 注册（投影）一条 wasm 准入记录：kind claim CAS 成功后才写 wasm registry 行。
    /// 同 kind 幂等；celld-bound ID（持久 claim 或路由派生 claim）冲突。
    pub fn register_wasm_admission(
        &mut self,
        store: &mut dyn KindRegistryStore,
        expected_kind_registry_revision: u64,
        proof: &AdmissionProofV1,
    ) -> Result<WasmVersionRegistryRow, KindRegistryError> {
        self.apply_kind_transaction(store, &PendingKindTransaction { expected_kind_registry_revision, proof: proof.clone() })
    }

    /// supervisor/gateway 投影一致性检查：上报的 wasm version/binding 缺少 Kernel
    /// registry 记录或缺 admission-proof 引用时拒绝（WASM_BUSINESS_RECORD_MISSING），
    /// 既有 active 指针保持不变（纯读路径，无任何 mutation）。
    pub fn check_wasm_route_projection(&self, application_id: &str, version_id: &str, admission_proof_ref: Option<&str>) -> Result<(), KindRegistryError> {
        let application = self
            .records
            .applications
            .get(application_id)
            .ok_or_else(|| err(WASM_BUSINESS_RECORD_MISSING, format!("applicationId {application_id} has no Kernel wasm registry record")))?;
        let row = application
            .versions
            .iter()
            .find(|row| row.version_id == version_id)
            .ok_or_else(|| err(WASM_BUSINESS_RECORD_MISSING, format!("version {version_id} is absent from the Kernel wasm registry")))?;
        let expected_ref = format!("admission-proof/{application_id}/{version_id}");
        if row.admission_proof_ref != expected_ref || admission_proof_ref != Some(row.admission_proof_ref.as_str()) {
            return Err(err(WASM_BUSINESS_RECORD_MISSING, "the projected version lacks its admission-proof reference"));
        }
        Ok(())
    }

    /// 恢复：重放中断的 owner kind 事务 → split-brain 检测（fail-closed，绝不按
    /// 时间戳/journal 序启发式选边）→ binding/index 一致性 → 孤儿 quarantine。
    pub fn recover(
        &mut self,
        store: &mut dyn KindRegistryStore,
        celld_application_ids: &[String],
        pending: &[PendingKindTransaction],
    ) -> Result<KindRecoveryReport, KindRegistryError> {
        let mut report = KindRecoveryReport::default();
        for transaction in pending {
            self.apply_kind_transaction(store, transaction)?;
            report.replayed.push(transaction.proof.application_id.clone());
        }
        let wasm_rows: Vec<String> = self.records.applications.keys().cloned().collect();
        let wasm_claims: Vec<String> = self
            .index
            .claims
            .iter()
            .filter(|claim| claim.runtime_kind == RUNTIME_KIND_WASM)
            .map(|claim| claim.application_id.clone())
            .collect();
        // 两个 kind registry 同时主张同一 applicationId（含双 active 指针的上位情形）。
        for celld_id in celld_application_ids {
            if wasm_rows.iter().any(|id| id == celld_id) || wasm_claims.iter().any(|id| id == celld_id) {
                return Err(err(
                    APPLICATION_KIND_SPLIT_BRAIN,
                    format!("both celld and wasm registries claim applicationId {celld_id}; all traffic for it is fenced pending an owner repair receipt"),
                ));
            }
        }
        // binding/index 一致性：被索引引用的 binding 必须逐字段一致；缺失则按 claim
        // 确定性重建（binding digest 是纯函数）。
        for claim in &self.index.claims {
            match store.binding_bytes(&claim.application_id) {
                Some(bytes) => {
                    let binding: KindClaimBindingV1 = parse_canonical(&bytes, WASM_KIND_CLAIM_INVALID, "kind binding record")?;
                    if binding.schema_version != 1
                        || binding.application_id != claim.application_id
                        || binding.runtime_kind != claim.runtime_kind
                        || binding.binding_revision != claim.binding_revision
                        || binding.binding_digest != claim.binding_digest
                    {
                        return Err(err(
                            APPLICATION_KIND_SPLIT_BRAIN,
                            format!("the binding record and the shared kind index disagree on applicationId {}", claim.application_id),
                        ));
                    }
                }
                None => {
                    let binding = binding_from_claim(claim);
                    store.write_binding(&claim.application_id, &jcs_bytes(&binding).map_err(aerr)?)?;
                }
            }
        }
        // 孤儿：claim 无 row / row 无 claim。不得成为 active；等 owner 重放或修复。
        for id in &wasm_claims {
            if !self.records.applications.contains_key(id) {
                self.quarantined.insert(id.clone(), "wasm kind claim without its kind-specific registry row");
                report.quarantined_claims.push(id.clone());
            }
        }
        for id in &wasm_rows {
            if !self.index.claims.iter().any(|claim| claim.application_id == *id && claim.runtime_kind == RUNTIME_KIND_WASM) {
                self.quarantined.insert(id.clone(), "wasm registry row without its global kind claim");
                report.quarantined_rows.push(id.clone());
            }
        }
        Ok(report)
    }

    /// 启动期路由派生引导：把 `derive_celld_claims_from_routes` 的确定性 claim 集
    /// 合并进共享 index（幂等：已存在的字节一致 claim 直接跳过；index 已对该
    /// applicationId 写入 wasm claim 或不一致 claim → APPLICATION_KIND_SPLIT_BRAIN
    /// fail-closed，绝不覆盖）。每次新增 claim revision +1；中途崩溃重放幂等。
    pub fn merge_route_derived_claims(
        &mut self,
        store: &mut dyn KindRegistryStore,
        derived: &[RuntimeKindClaimV1],
    ) -> Result<(), KindRegistryError> {
        for claim in derived {
            // position() 先结算借用，None 分支才能安全改写 self.index。
            let found = self.index.claims.iter().position(|existing| existing.application_id == claim.application_id);
            match found {
                Some(index) if &self.index.claims[index] == claim => {}
                Some(index) if self.index.claims[index].runtime_kind == RUNTIME_KIND_WASM => {
                    return Err(err(APPLICATION_KIND_SPLIT_BRAIN, format!("the route registry derives a celld claim on applicationId {} that the shared kind index already binds to wasm", claim.application_id)));
                }
                Some(_) => {
                    return Err(err(APPLICATION_KIND_SPLIT_BRAIN, format!("the index claim on applicationId {} disagrees with the deterministic route-registry derivation", claim.application_id)));
                }
                None => {
                    let mut next = self.index.clone();
                    next.registry_revision += 1;
                    next.claims.push(claim.clone());
                    sort_claims(&mut next.claims);
                    validate_kind_claim_index(&next)?;
                    let binding = binding_from_claim(claim);
                    store.write_binding(&claim.application_id, &jcs_bytes(&binding).map_err(aerr)?)?;
                    store.write_index(&jcs_bytes(&next).map_err(aerr)?)?;
                    self.index = next;
                }
            }
        }
        Ok(())
    }
}

fn binding_from_claim(claim: &RuntimeKindClaimV1) -> KindClaimBindingV1 {
    KindClaimBindingV1 {
        schema_version: 1,
        application_id: claim.application_id.clone(),
        runtime_kind: claim.runtime_kind.clone(),
        binding_revision: claim.binding_revision,
        binding_digest: claim.binding_digest.clone(),
    }
}

/// 从路由注册表推导终身 celld claims：所有 `target.kind == "celld-app"` 的 route
/// 的 `target.app_name` 去重后按 bytewise 排序（runtimeKind 恒 celld、bindingRevision
/// 恒 1、digest 按公式复算）。路由文件不可解析由 RouteStore::load 直接 panic-fail-closed
/// （节点启动失败）；此处只对派生出的 applicationId 文法 fail-closed。
pub fn derive_celld_claims_from_routes(routes: &[crate::routes::RouteRecord]) -> Result<Vec<RuntimeKindClaimV1>, KindRegistryError> {
    let mut names: Vec<&str> = routes
        .iter()
        .filter(|route| route.target.kind == crate::routes::ROUTE_KIND_CELLD_APP)
        .filter_map(|route| route.target.app_name.as_deref())
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut claims = Vec::new();
    for id in names {
        validate_kind_application_id(id).map_err(|e| err(WASM_KIND_CLAIM_INVALID, format!("celld application id derived from the route registry: {}", e.detail)))?;
        claims.push(RuntimeKindClaimV1 {
            application_id: id.to_string(),
            runtime_kind: RUNTIME_KIND_CELLD.to_string(),
            binding_revision: 1,
            binding_digest: kind_binding_digest(id, RUNTIME_KIND_CELLD, 1)?,
        });
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{RouteRecord, RouteTarget};
    use crate::wasm_admission::{
        wasm_version_digest_v1, LifecycleAdmissionRecord, NormalizedWasmManifestV1, RuntimeBindingIdentityV1, WasmActivePointerV1,
        WASM_HOST_ABI_LITERAL, WASM_WORLD_LITERAL,
    };

    // -- golden 向量（TS 权威 packages/contracts/wasm-execution.ts 于 2026-08-26
    //    经 bun 直读产出；值写死，改公式必须先改契约再重算） --

    const GOLDEN_BINDING_CELLD_ADMIN: &str = "d7a016dab24dfebcb8e12b4156e8b1fd6d70a9d32918fa17f901281527690600";
    const GOLDEN_BINDING_CELLD_NOTES: &str = "c467357ac32bd89a2e9cdde3bf96f78957825df97ca34ba82ee9ce552e46263d";
    const GOLDEN_BINDING_CELLD_MCP: &str = "26c7ea53f6067d7f01a075061539a15d06cf7b924a627159dd244499fe5ad112";
    const GOLDEN_BINDING_WASM_VECTOR: &str = "5cdbc1c45afc1242f171b295ce70a6058cf982d51da1bd952b16db9be9a73664";

    // 独立 oracle：手工拼 preimage 再单次 SHA-256（不复用被测实现）。
    fn oracle_sha256_hex(parts: &[&[u8]]) -> String {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hex::encode(hasher.finalize())
    }

    fn vector_manifest() -> NormalizedWasmManifestV1 {
        serde_json::from_str(
            r#"{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}"#,
        )
        .expect("vector manifest parses")
    }

    fn vector_binding() -> RuntimeBindingIdentityV1 {
        RuntimeBindingIdentityV1 {
            kind: "wasm".into(),
            catalog_revision: 9,
            catalog_hash: "ab".repeat(32),
            entry_key: "iweb-wasmd".into(),
            image_digest: format!("sha256:{}", "cd".repeat(32)),
            host_abi: WASM_HOST_ABI_LITERAL.into(),
            world: WASM_WORLD_LITERAL.into(),
        }
    }

    fn proof_for(application_id: &str) -> AdmissionProofV1 {
        let mut manifest = vector_manifest();
        manifest.name = application_id.to_string();
        let manifest_jcs = jcs_bytes(&manifest).expect("manifest jcs");
        let package_digest = "0".repeat(64);
        let version_digest = wasm_version_digest_v1(&package_digest, &manifest_jcs);
        AdmissionProofV1 {
            schema_version: 1,
            application_id: application_id.to_string(),
            package_digest,
            version_digest: version_digest.clone(),
            sequence: 1,
            version_id: format!("{version_digest}-1"),
            normalized_policy: manifest,
            lifecycle_admission_record: LifecycleAdmissionRecord {
                schema_version: 1,
                state: "admitted".into(),
                admitted_at: "2026-08-26T00:00:00Z".into(),
                admission_journal_revision: 0,
            },
            runtime_binding: vector_binding(),
            capability_record_revision: 5,
            capability_record_hash: "2".repeat(64),
            commit_token_hash: "4".repeat(64),
            host_service_policy: None,
        }
    }

    fn celld_route(host: &str, app: &str, enabled: bool) -> RouteRecord {
        RouteRecord {
            host_id: host.into(),
            target: RouteTarget { kind: crate::routes::ROUTE_KIND_CELLD_APP.into(), app_name: Some(app.into()), sandbox_id: None },
            system: true,
            enabled,
        }
    }

    fn wasm_route(host: &str, app: &str) -> RouteRecord {
        RouteRecord {
            host_id: host.into(),
            target: RouteTarget { kind: crate::routes::ROUTE_KIND_SANDBOX.into(), app_name: Some(app.into()), sandbox_id: None },
            system: false,
            enabled: true,
        }
    }

    // -- 内存 mock 存储 --

    #[derive(Default)]
    struct MockKindStore {
        index: Option<Vec<u8>>,
        bindings: BTreeMap<String, Vec<u8>>,
        index_writes: usize,
        /// 崩溃注入：第 n 次 index 写成功后，后续 index 写失败（模拟中途掉电）。
        fail_index_after: Option<usize>,
    }

    impl MockKindStore {
        fn maybe_fail_index(&mut self) -> Result<(), KindRegistryError> {
            self.index_writes += 1;
            if self.fail_index_after.is_some_and(|limit| self.index_writes > limit) {
                return Err(err(KIND_REGISTRY_STORE_IO, "injected crash: index write lost"));
            }
            Ok(())
        }
    }

    impl KindRegistryStore for MockKindStore {
        fn index_bytes(&self) -> Option<Vec<u8>> {
            self.index.clone()
        }
        fn write_index(&mut self, bytes: &[u8]) -> Result<(), KindRegistryError> {
            self.maybe_fail_index()?;
            self.index = Some(bytes.to_vec());
            Ok(())
        }
        fn binding_bytes(&self, application_id: &str) -> Option<Vec<u8>> {
            self.bindings.get(application_id).cloned()
        }
        fn write_binding(&mut self, application_id: &str, bytes: &[u8]) -> Result<(), KindRegistryError> {
            self.bindings.insert(application_id.to_string(), bytes.to_vec());
            Ok(())
        }
    }

    // -- digest/记录 golden 对齐 --

    #[test]
    fn binding_digests_match_ts_vectors() {
        assert_eq!(kind_binding_digest("admin", RUNTIME_KIND_CELLD, 1).unwrap(), GOLDEN_BINDING_CELLD_ADMIN);
        assert_eq!(kind_binding_digest("notes", RUNTIME_KIND_CELLD, 1).unwrap(), GOLDEN_BINDING_CELLD_NOTES);
        assert_eq!(kind_binding_digest("mcp", RUNTIME_KIND_CELLD, 1).unwrap(), GOLDEN_BINDING_CELLD_MCP);
        assert_eq!(kind_binding_digest("vector", RUNTIME_KIND_WASM, 1).unwrap(), GOLDEN_BINDING_WASM_VECTOR);
        // 独立 oracle：域前缀 + 手工 preimage 单次 SHA-256。
        let preimage = br#"{"applicationId":"admin","bindingRevision":1,"runtimeKind":"celld","schemaVersion":1}"#;
        let oracle = oracle_sha256_hex(&[b"iweb-application-kind-binding-v1\n", preimage]);
        assert_eq!(kind_binding_digest("admin", RUNTIME_KIND_CELLD, 1).unwrap(), oracle);
        assert_eq!(oracle, GOLDEN_BINDING_CELLD_ADMIN);
    }

    #[test]
    fn claim_validation_recomputes_digests_and_rejects_divergence() {
        let mut claim = derive_celld_claims_from_routes(&[celld_route("admin", "admin", true)]).unwrap().remove(0);
        validate_runtime_kind_claim(&claim).expect("valid celld claim");
        let mut wasm_variant = claim.clone();
        wasm_variant.runtime_kind = RUNTIME_KIND_WASM.into();
        wasm_variant.binding_digest = kind_binding_digest("admin", RUNTIME_KIND_WASM, 1).unwrap();
        assert!(validate_runtime_kind_claim(&wasm_variant).is_ok(), "wasm claim 同样合法（kind 二选一）");
        claim.binding_digest = "0".repeat(64);
        assert_eq!(validate_runtime_kind_claim(&claim).unwrap_err().code, KIND_CLAIM_BINDING_DIGEST_MISMATCH);
        claim.binding_revision = 2;
        assert_eq!(validate_runtime_kind_claim(&claim).unwrap_err().code, WASM_KIND_CLAIM_INVALID);
        // index：乱序/重复 applicationId 拒绝（derive 会排序，这里显式构造乱序）。
        let mut claims = derive_celld_claims_from_routes(&[celld_route("a", "admin", true), celld_route("n", "notes", true)]).unwrap();
        claims.reverse();
        let mut index = KindClaimIndexV1 { schema_version: 1, registry_revision: 2, claims };
        assert_eq!(validate_kind_claim_index(&index).unwrap_err().code, WASM_KIND_CLAIM_INVALID, "乱序 claim 集必须拒绝");
        index.claims.push(index.claims[0].clone());
        sort_claims(&mut index.claims);
        assert_eq!(validate_kind_claim_index(&index).unwrap_err().code, WASM_KIND_CLAIM_INVALID, "重复 applicationId 必须拒绝");
    }

    // -- 路由派生：确定性、去重、非 celld 路由不参与、文法 fail-closed --

    #[test]
    fn route_derivation_collects_dedupes_and_sorts_celld_app_names() {
        let routes = vec![
            celld_route("notes", "notes", true),
            celld_route("notes.app", "notes", false),
            celld_route("admin", "admin", true),
            celld_route("admin.app", "admin", true),
            wasm_route("vector.app", "vector"),
            RouteRecord { host_id: "dead".into(), target: RouteTarget { kind: "celld-app".into(), app_name: None, sandbox_id: None }, system: true, enabled: true },
        ];
        let claims = derive_celld_claims_from_routes(&routes).unwrap();
        assert_eq!(claims.iter().map(|claim| claim.application_id.as_str()).collect::<Vec<_>>(), vec!["admin", "notes"], "bytewise 排序 + 去重；sandbox 目标与无名 celld-app 不参与");
        assert_eq!(claims[0].runtime_kind, "celld");
        assert_eq!(claims[0].binding_revision, 1);
        assert_eq!(claims[0].binding_digest, GOLDEN_BINDING_CELLD_ADMIN);
        // 禁用路由同样贡献终身 claim（kind 绑定不随路由开关改变）。
        let only_disabled = vec![celld_route("x", "search", false)];
        assert_eq!(derive_celld_claims_from_routes(&only_disabled).unwrap().len(), 1);
        // 文法非法的 celld-app 名（镜像种子被篡改）→ fail-closed。
        let bad = vec![celld_route("bad", "Not Valid", true)];
        assert_eq!(derive_celld_claims_from_routes(&bad).unwrap_err().code, WASM_KIND_CLAIM_INVALID);
    }

    // -- 路由派生 bootstrap：幂等、崩溃重放、冲突 --

    #[test]
    fn route_derived_claims_merge_idempotently() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let routes = vec![celld_route("n", "notes", true), celld_route("a", "admin", true)];
        let derived = derive_celld_claims_from_routes(&routes).unwrap();
        registry.merge_route_derived_claims(&mut store, &derived).unwrap();
        // 两条 claim 变更 → revision 恰好 0→2（每次 mutation +1）。
        assert_eq!(registry.registry_revision(), 2);
        assert!(store.index_bytes().is_some());
        assert_eq!(store.bindings.len(), 2);
        // 幂等重放：同派生集再合并不产生新 revision。
        registry.merge_route_derived_claims(&mut store, &derived).unwrap();
        assert_eq!(registry.registry_revision(), 2);
    }

    #[test]
    fn route_derived_merge_crash_replays_identically() {
        let mut store = MockKindStore { fail_index_after: Some(1), ..Default::default() };
        let derived = derive_celld_claims_from_routes(&[
            celld_route("a", "admin", true),
            celld_route("n", "notes", true),
        ])
        .unwrap();
        {
            let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
            let interrupted = registry.merge_route_derived_claims(&mut store, &derived);
            assert_eq!(interrupted.unwrap_err().code, KIND_REGISTRY_STORE_IO);
        }
        // 重启后重放：同一派生集补齐（无 pending 模式，确定性收敛）。
        store.fail_index_after = None;
        let mut recovered = WasmKernelRouteRegistryV1::load(&store).unwrap();
        recovered.merge_route_derived_claims(&mut store, &derived).unwrap();
        assert_eq!(recovered.registry_revision(), 2);
        // 与无崩溃路径结果完全一致。
        let mut clean_store = MockKindStore::default();
        let mut clean = WasmKernelRouteRegistryV1::load(&clean_store).unwrap();
        clean.merge_route_derived_claims(&mut clean_store, &derived).unwrap();
        assert_eq!(
            serde_json::to_value(recovered.index()).unwrap(),
            serde_json::to_value(clean.index()).unwrap()
        );
    }

    #[test]
    fn route_derivation_never_overwrites_a_wasm_claim() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, 0).unwrap();
        // 路由派生对 wasm-bound ID 推导 celld claim → split-brain，绝不覆盖。
        let derived = derive_celld_claims_from_routes(&[celld_route("v", "vector", true)]).unwrap();
        let error = registry.merge_route_derived_claims(&mut store, &derived).unwrap_err();
        assert_eq!(error.code, APPLICATION_KIND_SPLIT_BRAIN);
        assert_eq!(registry.claim("vector").unwrap().runtime_kind, "wasm");
        // 结构性说明：binding digest 是 claim 的纯函数，任何「与确定性推导分歧的
        // celld claim」都无法通过 validate_kind_claim_index——篡改 index 会在 load
        // 阶段 fail-closed（WASM_KIND_CLAIM_INVALID），不会进入 merge。
        let mut store_b = MockKindStore::default();
        let mut registry_b = WasmKernelRouteRegistryV1::load(&store_b).unwrap();
        registry_b.merge_route_derived_claims(&mut store_b, &derive_celld_claims_from_routes(&[celld_route("a", "admin", true)]).unwrap()).unwrap();
        let mut tampered: KindClaimIndexV1 = serde_json::from_slice(&store_b.index_bytes().unwrap()).unwrap();
        tampered.claims[0].binding_digest = "0".repeat(64);
        store_b.write_index(&jcs_bytes(&tampered).unwrap()).unwrap();
        assert_eq!(
            WasmKernelRouteRegistryV1::load(&store_b).unwrap_err().code,
            KIND_CLAIM_BINDING_DIGEST_MISMATCH,
            "篡改的 index 在 load 即拒绝（binding digest 复算失败）"
        );
    }

    #[test]
    fn same_name_wasm_admission_after_route_derivation_rejected() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry
            .merge_route_derived_claims(&mut store, &derive_celld_claims_from_routes(&[celld_route("a", "admin", true)]).unwrap())
            .unwrap();
        let rejected = registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof_for("admin"));
        assert_eq!(rejected.unwrap_err().code, APPLICATION_RUNTIME_KIND_CONFLICT);
        // celld 绑定原样保留：claim/digest/revision 均未动，wasm registry 无行。
        let claim = registry.claim("admin").unwrap().clone();
        assert_eq!(claim.runtime_kind, "celld");
        assert_eq!(claim.binding_digest, GOLDEN_BINDING_CELLD_ADMIN);
        assert_eq!(registry.registry_revision(), 1);
        assert!(registry.records().applications.is_empty());
    }

    // -- kind-claim CAS：幂等、CAS 冲突、kind 终身绑定 --

    #[test]
    fn kind_claim_cas_conflict_and_idempotent_retry() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry
            .merge_route_derived_claims(&mut store, &derive_celld_claims_from_routes(&[celld_route("a", "admin", true)]).unwrap())
            .unwrap();
        let base = registry.registry_revision();
        // 期望 revision 过期 → CAS 拒绝且零写入。
        let stale = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, base - 1);
        assert_eq!(stale.unwrap_err().code, KIND_REGISTRY_REVISION_CONFLICT);
        assert_eq!(registry.registry_revision(), base);
        assert!(registry.claim("vector").is_none());
        // 正确期望 → 创建（revision 恰好 +1）。
        let created = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, base).unwrap();
        assert!(created.created);
        assert_eq!(registry.registry_revision(), base + 1);
        assert_eq!(created.claim.binding_digest, GOLDEN_BINDING_WASM_VECTOR);
        // 同 kind 幂等重试（即使带旧期望值）：零写入零 revision 变更。
        let retry = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, base).unwrap();
        assert!(!retry.created);
        assert_eq!(retry.claim, created.claim);
        assert_eq!(registry.registry_revision(), base + 1);
        // 反向：wasm-bound ID 提交给 celld → 冲突，绑定不变。
        let reverse = registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_CELLD, base + 1);
        assert_eq!(reverse.unwrap_err().code, APPLICATION_RUNTIME_KIND_CONFLICT);
        assert_eq!(registry.claim("vector").unwrap().runtime_kind, "wasm");
        // register 全路径幂等：claim + row 重复注册返回同一行。
        let proof = proof_for("vector");
        let row = registry.register_wasm_admission(&mut store, base, &proof).unwrap();
        let again = registry.register_wasm_admission(&mut store, base, &proof).unwrap();
        assert_eq!(row, again);
        assert_eq!(registry.records().applications["vector"].versions.len(), 1);
        assert_eq!(registry.registry_revision(), base + 1);
    }

    // -- 恢复：中断重放、孤儿 quarantine、split-brain --

    #[test]
    fn interrupted_claim_without_row_replays_byte_identical_transaction() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let expected = registry.registry_revision();
        let proof = proof_for("vector");
        // 模拟崩溃：claim 已提交、kind-specific row 未写。
        registry.claim_runtime_kind(&mut store, "vector", RUNTIME_KIND_WASM, expected).unwrap();
        assert!(registry.records().applications.is_empty());
        // 恢复：byte-identical owner 事务（同 proof + 同 expected revision）幂等补全。
        let pending = vec![PendingKindTransaction { expected_kind_registry_revision: expected, proof: proof.clone() }];
        let report = registry.recover(&mut store, &[], &pending).unwrap();
        assert_eq!(report.replayed, vec!["vector".to_string()]);
        assert!(report.quarantined_claims.is_empty() && report.quarantined_rows.is_empty());
        assert_eq!(registry.records().applications["vector"].versions[0].version_id, proof.version_id);
        assert!(matches!(registry.records().applications["vector"].active, WasmActivePointerV1::Unavailable { .. }));
    }

    #[test]
    fn orphan_claim_and_orphan_row_are_quarantined() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        // 孤儿 claim（无 row、无 pending 事务）：quarantine，不得成为 active。
        registry.claim_runtime_kind(&mut store, "orphan-claim", RUNTIME_KIND_WASM, registry.registry_revision()).unwrap();
        // 孤儿 row（直接投影，无全局 claim——模拟跨层泄漏）。
        registry.records.insert_admitted(&proof_for("orphan-row")).unwrap();
        let report = registry.recover(&mut store, &[], &[]).unwrap();
        assert_eq!(report.quarantined_claims, vec!["orphan-claim".to_string()]);
        assert_eq!(report.quarantined_rows, vec!["orphan-row".to_string()]);
        // 隔离后任何写路径 fail-closed，等 owner 修复。
        assert_eq!(registry.claim_runtime_kind(&mut store, "orphan-claim", RUNTIME_KIND_WASM, registry.registry_revision()).unwrap_err().code, APPLICATION_KIND_SPLIT_BRAIN);
        assert_eq!(registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof_for("orphan-row")).unwrap_err().code, APPLICATION_KIND_SPLIT_BRAIN);
        assert!(registry.is_quarantined("orphan-claim").is_some());
    }

    #[test]
    fn two_registries_claim_same_id_after_recovery_split_brain() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        // wasm registry 出现与路由派生同名 "admin" 的行（模拟崩溃后两侧都主张）。
        registry.records.insert_admitted(&proof_for("admin")).unwrap();
        let before = registry.index().clone();
        let error = registry.recover(&mut store, &["admin".to_string()], &[]).unwrap_err();
        assert_eq!(error.code, APPLICATION_KIND_SPLIT_BRAIN);
        // 绝不启发式选边：索引与记录状态原样保留，只 fence 流量。
        assert_eq!(registry.index().clone(), before);
        assert!(registry.records().applications.contains_key("admin"));
    }

    #[test]
    fn binding_index_disagreement_split_brain() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        registry.claim_runtime_kind(&mut store, "admin", RUNTIME_KIND_CELLD, 0).unwrap();
        // 篡改 binding 文件（合法 JCS 但 revision 与 index 分歧）。
        let mut binding: KindClaimBindingV1 = serde_json::from_slice(&store.binding_bytes("admin").unwrap()).unwrap();
        binding.binding_revision = 3;
        store.write_binding("admin", &jcs_bytes(&binding).unwrap()).unwrap();
        let error = registry.recover(&mut store, &[], &[]).unwrap_err();
        assert_eq!(error.code, APPLICATION_KIND_SPLIT_BRAIN);
        // 缺失 binding 文件则按 claim 确定性重建（digest 是纯函数）。
        store.bindings.remove("admin");
        registry.recover(&mut store, &[], &[]).unwrap();
        let rebuilt: KindClaimBindingV1 = serde_json::from_slice(&store.binding_bytes("admin").unwrap()).unwrap();
        assert_eq!(rebuilt.binding_digest, GOLDEN_BINDING_CELLD_ADMIN);
    }

    #[test]
    fn supervisor_projection_missing_record_rejected_and_pointer_retained() {
        let mut store = MockKindStore::default();
        let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
        let proof = proof_for("vector");
        registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof).unwrap();
        let pointer_before = registry.records().applications["vector"].active.clone();
        // 未知版本 → 拒绝。
        let unknown = registry.check_wasm_route_projection("vector", &format!("{}-9", "b".repeat(64)), None);
        assert_eq!(unknown.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        // 已知版本但缺 admission-proof 引用 → 拒绝。
        let missing_ref = registry.check_wasm_route_projection("vector", &proof.version_id, None);
        assert_eq!(missing_ref.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        let wrong_ref = registry.check_wasm_route_projection("vector", &proof.version_id, Some("admission-proof/other/x"));
        assert_eq!(wrong_ref.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        // 未知应用 → 拒绝。
        let unknown_app = registry.check_wasm_route_projection("ghost", &proof.version_id, None);
        assert_eq!(unknown_app.unwrap_err().code, WASM_BUSINESS_RECORD_MISSING);
        // 完整引用 → 通过；active 指针全程未变。
        registry.check_wasm_route_projection("vector", &proof.version_id, Some(&format!("admission-proof/vector/{}", proof.version_id))).unwrap();
        assert_eq!(registry.records().applications["vector"].active, pointer_before);
    }

    // -- 文件持久化存储（kind-registry 目录） --

    #[test]
    fn file_stores_round_trip_route_derived_claims_across_restart() {
        let dir = std::env::temp_dir().join("iweb-kernel-wasm-kind-registry-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.join("application-kind-registry-v1");
        let derived = derive_celld_claims_from_routes(&[
            celld_route("n", "notes", true),
            celld_route("a", "admin", true),
        ])
        .unwrap();
        {
            let mut store = KindRegistryStoreDir::open(&root).unwrap();
            let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
            registry.merge_route_derived_claims(&mut store, &derived).unwrap();
            let proof = proof_for("vector");
            registry.register_wasm_admission(&mut store, registry.registry_revision(), &proof).unwrap();
        }
        {
            let mut store = KindRegistryStoreDir::open(&root).unwrap();
            let mut registry = WasmKernelRouteRegistryV1::load(&store).unwrap();
            // 重启后路由派生重放幂等（同派生集零新增 revision）。
            registry.merge_route_derived_claims(&mut store, &derived).unwrap();
            assert_eq!(registry.registry_revision(), 3);
            assert_eq!(registry.claim("vector").unwrap().runtime_kind, "wasm");
            let index: KindClaimIndexV1 = serde_json::from_slice(&store.index_bytes().unwrap()).unwrap();
            assert_eq!(index.claims.len(), 3);
            assert_eq!(index.claims[0].application_id, "admin");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
