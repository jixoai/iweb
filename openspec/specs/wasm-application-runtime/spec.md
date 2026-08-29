# wasm-application-runtime Specification

## Purpose
定义 wasm 组件作为第二种应用执行形态的制品、能力、宿主接口和执行协议。wasm 通过能力矩阵并不完成 sandbox 验证；它无条件继承 `application-sandbox` 的存储、凭证、网络、资源、生命周期和 Kernel 恢复法。

## Requirements

### Requirement: Wasm applications inherit the application sandbox law
The system SHALL apply every `application-sandbox` requirement verbatim to wasm applications. Passing the import capability matrix SHALL NOT be interpreted as completing sandbox validation, and a wasm component SHALL NOT receive owner credentials, workspace authority, another application's storage, the runtime operator listener, raw host loopback, or a direct network path.

#### Scenario: Compromised wasm application probes another principal
- **WHEN** a wasm application attempts to read another application's storage, owner workspace objects, or node credentials
- **THEN** the sandbox boundary denies access identically to a celld application without exposing target data

### Requirement: Wasm package and version digests use new self-contained algorithms
The system SHALL validate one strict OCI-layout subset named `iweb-wasm-oci-layout-v1` before calculating a digest. It SHALL NOT call or claim equivalence with the existing celld `versionDigest` formula. A valid layout contains exactly these paths and no others:

```text
oci-layout
index.json
blobs/sha256/<manifest-hex>
blobs/sha256/<config-hex>
blobs/sha256/<layer-hex>...
```

`oci-layout` SHALL be exactly `JCS({"imageLayoutVersion":"1.0.0"})`. `index.json` SHALL be exactly `JCS({"schemaVersion":2,"manifests":[D]})`, with exactly one descriptor `D`; no annotations, platform, subject, referrer, or unknown field is accepted. `D` has exactly `mediaType`, `digest`, and `size`, with media type `application/vnd.oci.image.manifest.v1+json`, an `oci-sha256` digest, and `size` in `1..134217728` bytes. Its referenced manifest blob must be JCS and exactly:

```json
{
  "config": { "digest": "oci-sha256", "mediaType": "application/vnd.iweb.wasm.config.v1+json", "size": "u53" },
  "layers": [
    { "digest": "oci-sha256", "mediaType": "application/vnd.iweb.wasm.component.v1+wasm|application/vnd.iweb.wasm.core-module.v1+wasm|application/vnd.iweb.wasm.adapter.v1+wasm", "size": "u53" }
  ],
  "schemaVersion": 2
}
```

The display above describes field types, not a permissive JSON schema: descriptor `size` is a JSON integer, all descriptor objects have exactly the three listed fields, a layer media type is exactly one of the three literals separated by `|`, manifest `layers.length` is in `1..node.admission.maxLayerCount`, and manifest fields are exactly `schemaVersion`, `config`, and `layers`. Each `blobs/sha256/<hex>` filename is exactly the lower-case `<hex>` suffix of the descriptor's `sha256:<hex>` and names no other content. Every descriptor digest equals SHA-256 of its referenced **raw bytes** and every descriptor size equals raw byte length. The index descriptor, config, every layer, and the raw manifest blob are each in `1..min(node.admission.maxBlobBytes, 134217728)` bytes; the sum of `oci-layout`, `index.json`, and every referenced raw blob is at most `node.admission.maxPackageBytes`. All descriptor digests across index-manifest, config, and layers are pairwise distinct; duplicate digest, duplicate layer, unreferenced blob, missing referenced blob, or an empty layer list is rejected. A component layer must decode as a Component Model component, a core-module layer as a core module, and an adapter layer as a component-model adapter; a config `entryLayerDigest` must name exactly one component layer.

The config blob SHALL be JCS with exactly these fields:

```text
schemaVersion: 1
kind: "wasm"
entryLayerDigest: oci-sha256
world: "wasi:http/proxy@0.2.8"
hostABI: "iweb-wasmd-abi@1.0.0"
declaredHostImports: sorted non-duplicate ImportCapability[]
```

`ImportCapability` has exactly `{ package, interface, direction }`; `package` is a lower-case WIT package identity `namespace:name@major.minor.patch`, `interface` is a lower-case WIT interface identifier, and `direction` is the literal `"import"` for a component-to-host capability. The canonical sort key is `(package, interface, direction)` in UTF-8 byte order, and duplicate keys are rejected. A root export is represented separately by the same typed shape with `direction:"export"`; it is not a host capability.

`ConfigRuntimeProjectionV1(config)` is exactly `JCS({"kind":config.kind,"entryLayerDigest":config.entryLayerDigest,"world":config.world,"hostABI":config.hostABI,"declaredHostImports":config.declaredHostImports})`. `schemaVersion` is the config wrapper's revision and is deliberately not part of this projection.

`NormalizedWasmManifestV1` is the exact object hashed by `wasmVersionDigestV1`:

```text
{
  schemaVersion: 1,
  name: /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
  runtime: {
    kind: "wasm",
    entryLayerDigest: oci-sha256,
    world: "wasi:http/proxy@0.2.8",
    hostABI: "iweb-wasmd-abi@1.0.0",
    declaredHostImports: sorted unique ImportCapability[]
  },
  resources: { cpuMillis: u53, memoryBytes: u53, pidLimit: u53, storageBytes: u53 },
  storage: { persistent: boolean, requestBytes: u53 },
  egress: { default: "deny", allow: sorted unique { host: DNS name, port: 1..65535 }[] }
}
```

There are no `assets`, `entrypoint`, image, command, mount, socket, or arbitrary environment fields in this wasm manifest; the OCI `entryLayerDigest` is the sole executable entry. `cpuMillis`, `memoryBytes`, and `pidLimit` use inclusive integer bounds `1..1000000`, `1..68719476736`, and `1..1000000`; `storageBytes` and `storage.requestBytes` use inclusive integer bounds `0..1099511627776`, with `storage.requestBytes <= storageBytes`. `egress.allow` has at most 256 items, is sorted by `(host, port)`, and contains no duplicate pair. The object has exactly the keys shown and rejects unknown or missing fields. The admitted normalized wasm manifest has an identical `runtime` projection `{kind, entryLayerDigest, world, hostABI, declaredHostImports}`. `ConfigRuntimeProjectionV1(config)` and `JCS(normalizedManifest.runtime)` must be byte-for-byte equal; their discovered host-import set must also exactly equal `declaredHostImports`. At admission, `normalizedManifest.name` must exactly equal `AdmissionProofV1.applicationId`.

Let `raw(path)` be that layout file's exact stored bytes, `sha256hex(bytes)` be lower-case hexadecimal `SHA-256` of exactly `bytes`, and `dec(n)` be base-10 ASCII without leading zero. Let `L=(l_0,...,l_{n-1})` be the manifest `layers` array in its original listed order; OCI layer order is significant and is therefore part of the digest. `wasmPackageDigestV1` is:

```text
sha256hex(
  "iweb-wasm-package-digest-v1\n" ||
  "layout "   || sha256hex(raw(oci-layout)) || " " || dec(byteLength(raw(oci-layout))) || "\n" ||
  "index "    || sha256hex(raw(index.json)) || " " || dec(byteLength(raw(index.json))) || "\n" ||
  "manifest " || D.mediaType || " " || D.digest || " " || dec(D.size) || "\n" ||
  "config "   || M.config.mediaType || " " || M.config.digest || " " || dec(M.config.size) || "\n" ||
  for each l_i in L:
    "layer " || dec(i) || " " || l_i.mediaType || " " || l_i.digest || " " || dec(l_i.size) || "\n"
)
```

Here `D` is the sole index descriptor and `M` is the decoded OCI manifest. The `layout` and `index` lines include `SHA-256` of their exact raw JCS bytes; the manifest/config/layer lines bind exact descriptors whose referenced raw bytes were already digest- and size-verified. Thus index, manifest, every descriptor, config, every layer's media type/digest/size, and the manifest layer order are all committed. `oci-sha256` text uses exactly `sha256:` plus lower-case hex, so the record grammar is unambiguous.

Let `A` be the full normalized admission manifest JCS bytes. `wasmVersionDigestV1` is:

```text
sha256hex(
  "iweb-wasm-version-digest-v1\n" ||
  "package " || wasmPackageDigestV1 || "\n" ||
  "admission-manifest " || dec(byteLength(A)) || "\n" || A
)
```

The immutable version's digest field for runtime kind `wasm` is `wasmVersionDigestV1`; content identity is `(applicationId, wasmVersionDigestV1)` and version identity is the allocated `(applicationId, versionId)` pair. A `versionId` is `<wasmVersionDigestV1>-<sequence>`, where `sequence` is a positive `u53` decimal without leading zero. Runtime image, catalog revision, acceptance record, node capability record, secret revision, preparation generation, and execution generation do not enter either wasm digest; they are separately pinned runtime state.

#### Scenario: Same strict OCI content has one package and version identity
- **WHEN** two implementations validate byte-identical strict layouts and the same normalized admission manifest
- **THEN** both calculate the published `wasmPackageDigestV1` and `wasmVersionDigestV1` vectors exactly, without using the celld serializer

#### Scenario: JSON formatting or an unreferenced blob is supplied
- **WHEN** an OCI JSON file is semantically valid but not raw JCS, or the layout contains a blob not reachable from its one index descriptor
- **THEN** admission rejects before commit with `WASM_OCI_NON_CANONICAL_JSON` or `WASM_OCI_UNREFERENCED_BLOB`

#### Scenario: Duplicate digest or empty artifact is supplied
- **WHEN** two OCI descriptors name the same digest, a layer is zero bytes, or the manifest has no layers
- **THEN** admission rejects with `WASM_OCI_DUPLICATE_DIGEST` or `WASM_OCI_EMPTY_ARTIFACT`

#### Scenario: Config and admission manifest disagree
- **WHEN** config and normalized admission manifest differ on kind, entry layer, world, host ABI, or declared host imports
- **THEN** admission rejects with `WASM_CONFIG_MANIFEST_MISMATCH` before a durable visible version exists

#### Scenario: Published digest vector is reproduced
- **WHEN** a validator uses `packageDigest = 0000000000000000000000000000000000000000000000000000000000000000` and the normalized manifest JCS bytes below (405 UTF-8 bytes)
- **THEN** `wasmVersionDigestV1` is exactly `a405ef8d2951e580f70c465aabb96a32b9a29526998b3ef920edfff3c1caa532`

```text
{"egress":{"allow":[],"default":"deny"},"name":"vector","resources":{"cpuMillis":1,"memoryBytes":2,"pidLimit":3,"storageBytes":4},"runtime":{"declaredHostImports":[],"entryLayerDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","hostABI":"iweb-wasmd-abi@1.0.0","kind":"wasm","world":"wasi:http/proxy@0.2.8"},"schemaVersion":1,"storage":{"persistent":false,"requestBytes":0}}
```

The notation `hex(SHA-256(bytes))` always means one SHA-256 operation followed by lowercase hexadecimal encoding. It MUST NOT be read as hashing a hexadecimal digest a second time; every `hex(SHA-256(...))` occurrence in this capability uses the bytes shown between the parentheses.

### Requirement: Capability record revision 1 is a typed exact matrix
The system SHALL select host capabilities only from a pinned `NodeCapabilityRecordV1`. Its revision-1 matrix is the following exact data, not a semantic-version range. Source note: on 2026-08-26 the official `WebAssembly/wasi-http` Releases page marked `v0.2.8` as Latest; the corresponding primary WIT source is `https://github.com/WebAssembly/wasi-http/tree/v0.2.8`.

```text
world                 wasi:http/proxy@0.2.8
required root export  {package:"wasi:http@0.2.8", interface:"incoming-handler", direction:"export"}
host ABI              iweb-wasmd-abi@1.0.0

allowed host imports
  {package:"wasi:http@0.2.8", interface:"types", direction:"import"}
  {package:"wasi:http@0.2.8", interface:"outgoing-handler", direction:"import"}
  {package:"wasi:clocks@0.2.8", interface:"monotonic-clock", direction:"import"}
  {package:"wasi:clocks@0.2.8", interface:"wall-clock", direction:"import"}
  {package:"wasi:random@0.2.8", interface:"random", direction:"import"}
  {package:"wasi:io@0.2.8", interface:"streams", direction:"import"}
  {package:"wasi:io@0.2.8", interface:"error", direction:"import"}
  {package:"wasi:io@0.2.8", interface:"poll", direction:"import"}
  {package:"wasi:cli@0.2.8", interface:"stdin", direction:"import"}
  {package:"wasi:cli@0.2.8", interface:"stdout", direction:"import"}
  {package:"wasi:cli@0.2.8", interface:"stderr", direction:"import"}
  {package:"iweb:config@1.0.0", interface:"store", direction:"import"}
  {package:"iweb:secrets@1.0.0", interface:"store", direction:"import"}
```

The mapping above is the exact package-to-component import normalization from the official `wasi-http` v0.2.8 WIT tree: `wasi:http` owns `types` and `outgoing-handler`; its dependency packages own the clock, random, I/O, and CLI interfaces. The owner phrase “component only sees `wasi:http`” means the selected application world and its fixed transitive ABI; it does not grant `wasi:tls`, sockets, or an unlisted network world. A package version is part of the package identity, not a range or a free-form suffix. `iweb:config@1.0.0` and `iweb:secrets@1.0.0` WIT packages SHALL live in `packages/contracts`; `config/store` exposes only assigned non-secret configuration, while `secrets/store` exposes only the revisioned, allowlisted secret operations defined below. `stdin` is an EOF source; `stdout` and `stderr` are bounded discard sinks and MUST NOT become application logs.

The final entry component's externally visible export set SHALL contain exactly `{package:"wasi:http@0.2.8",interface:"incoming-handler",direction:"export"}`. It may consume a subset of allowed host imports, but every actual host import must be present in the record matrix and in its declared set. Socket-level interfaces, `wasi:tls`, `wasi:filesystem`, all unlisted `wasi:*` packages, a listed interface at any other patch, a bare package, and a host ABI mismatch SHALL fail closed.

The scanner SHALL obtain WIT package/interface identities from decoded Component Model type information, not from raw import-name string splitting. Starting at `entryLayerDigest`, it SHALL:

1. Parse every reachable component, nested component, core module, and adapter; reject invalid binary role, a graph cycle, or a node/edge/depth budget breach before continuing.
2. Expand component instantiation and re-export edges. A re-export aliases its original provider and does not create a new host capability.
3. For each component import, compare its normalized type identity and expected direction to providers reachable in the artifact. Exactly one type-identical internal provider resolves it internally. Zero internal providers makes it a proposed host import; multiple providers or a non-identical provider is rejection.
4. For a proposed host import, require an exact `{package, interface, direction:"import"}` in both declared set and matrix. A core-module import and an adapter import must resolve to an internal provider or an explicit Component Model adapter translation; an untyped raw core import may never become a host capability by name.
5. Require the discovered host-import set, sorted and deduplicated by `(package, interface, direction)`, to equal the config and normalized-manifest declared set. Resolve the root export last and require the exact required export object, including `direction:"export"`.

The stable rejection codes are:

| Code | Rejection condition |
| --- | --- |
| `WASM_WORLD_UNSUPPORTED` | world is not the exact matrix world |
| `WASM_EXPORT_MISMATCH` | root export package/interface/direction differs |
| `WASM_INTERFACE_UNKNOWN` | package/interface is not in the normalized WIT mapping |
| `WASM_INTERFACE_VERSION_UNLISTED` | known interface has a non-recorded patch |
| `WASM_HOST_ABI_MISMATCH` | host ABI is not the matrix ABI |
| `WASM_IMPORT_UNMAPPABLE` | raw core/adapter import has no typed Component Model mapping |
| `WASM_IMPORT_UNRESOLVED` | no unique internal provider and no exact host capability |
| `WASM_IMPORT_AMBIGUOUS` | more than one type-identical provider is reachable |
| `WASM_INTERNAL_TYPE_MISMATCH` | provider exists but its full type identity/direction differs |
| `WASM_ADAPTER_EXTERNAL_IMPORT` | adapter leaks an import outside the decoded closure |
| `WASM_CLOSURE_CYCLE` | component/module/adapter graph contains a cycle |
| `WASM_CLOSURE_BUDGET_EXCEEDED` | node, edge, or depth budget is exceeded |
| `WASM_DECLARATION_MISMATCH` | discovered set differs from config or normalized manifest |

Each code is owner-visible; public traffic receives only the generic availability response.

#### Scenario: Nested component and re-export resolve internally
- **WHEN** an entry component imports a type-identical interface re-exported from one reachable nested component
- **THEN** the scanner records no host capability for that edge and accepts it only if the provider is unique and the complete graph remains within budget

#### Scenario: Adapter attempts to smuggle a host import
- **WHEN** an adapter or core module has an external import that cannot be proven to resolve internally through decoded Component Model linkage
- **THEN** admission rejects with `WASM_ADAPTER_EXTERNAL_IMPORT` or `WASM_IMPORT_UNMAPPABLE`

#### Scenario: Known interface has the wrong patch
- **WHEN** a component imports `wasi:http/outgoing-handler@0.2.7` or any non-`0.2.8` revision
- **THEN** admission rejects with `WASM_INTERFACE_VERSION_UNLISTED`

### Requirement: Node capability records are canonical revisioned bounds
The system SHALL persist a `NodeCapabilityRecordV1` beside Kernel control state. It has exactly the following fields; bytes are octets, `ms` milliseconds, `s` seconds, and `fuel` Wasmtime fuel units.

| Field | Type and bound | Meaning |
| --- | --- | --- |
| `schemaVersion` | literal `1` | record wire revision |
| `revision` | `u53`, `1..9007199254740991` | strictly increasing record revision |
| `recordHash` | `sha256-hex` | hash defined below |
| `policyMaxima.cpuMillis` | integer `1..1000000` | cgroup CPU policy maximum in millicores |
| `policyMaxima.memoryBytes` | integer `1..68719476736` | cgroup total memory policy maximum in bytes |
| `policyMaxima.pidLimit` | integer `1..1000000` | cgroup pid maximum |
| `policyMaxima.storageBytes` | integer `0..1099511627776` | application storage maximum in bytes |
| `http.maxRequestBytes` | integer `1..16777216` | inbound request bytes |
| `http.maxResponseBytes` | integer `1..67108864` | outbound response bytes |
| `http.maxRequestHeaderBytes` | integer `1..65536` | inbound header section bytes |
| `http.maxResponseHeaderBytes` | integer `1..65536` | outbound header section bytes |
| `http.maxRequestHeaderCount` | integer `1..256` | inbound header fields |
| `http.maxResponseHeaderCount` | integer `1..256` | outbound header fields |
| `http.maxConcurrentRequests` | integer `1..4096` | per-sandbox concurrent requests |
| `engine.maxEpochDeadlineMs` | integer `1..300000` | per-request wall-clock epoch deadline |
| `engine.fuelPerRequest` | `null` or integer `1..1000000000000` | `null` disables fuel; numeric enables it |
| `engine.maxLiveInstances` | integer `1..4096` | live component instances |
| `admission.maxPackageBytes` | integer `1..536870912` | complete strict OCI layout bytes |
| `admission.maxBlobBytes` | integer `1..134217728` | one blob bytes |
| `admission.maxLayerCount` | integer `1..128` | OCI layers |
| `admission.maxClosureNodes` | integer `1..4096` | parsed component/core/adapter graph nodes |
| `admission.maxClosureEdges` | integer `1..16384` | graph edges |
| `admission.maxClosureDepth` | integer `1..64` | nested traversal depth |
| `admission.stagingTtlSeconds` | integer `1..3600` | stale staging and hidden admission retention |
| `restart.maxRestarts` | integer `0..100` | restarts permitted in one window |
| `restart.windowMs` | integer `1000..86400000` | restart budget window |
| `drainDeadlineMs` | integer `1..300000` | retiring execution drain time |
| `runtimeReserves` | sorted non-empty array, max 256 | per-binding/per-architecture wasmd reserve entries below |
| `matrix` | exactly the revision-1 matrix above | world, ABI, required export, host-import set |

`matrix` has exactly `{world,hostABI,requiredRootExport,hostImports}`: `world` and `hostABI` equal the literals in the revision-1 matrix above; `requiredRootExport` is its exact typed export object; and `hostImports` is the exact sorted list of its typed import objects. Each `runtimeReserves[]` object has exactly `runtimeBinding`, `architecture`, and `reserveBytes`; `runtimeBinding` is the complete `RuntimeBindingIdentityV1` below, `architecture` is one of `linux/amd64` or `linux/arm64`, `(JCS(runtimeBinding), architecture)` is unique and sorted first by the raw JCS UTF-8 bytes then by architecture, and `reserveBytes` is an integer `1..68719476735` bytes measured for that exact binding on that architecture. The record has exactly nested objects `policyMaxima`, `http`, `engine`, `admission`, `restart`, plus the listed scalar/array fields; every array has its specified sort order and no duplicates.

`recordHash` equals `hex(SHA-256(UTF8("iweb-node-capability-record-v1\n" || JCS(record with recordHash omitted))))`. The raw persisted record must equal JCS including its validated `recordHash`. An owner update supplies an expected `(revision, recordHash)` and a complete next record with `revision = current.revision + 1`; the Kernel validates, computes the new hash, and atomically writes it by compare-and-swap. A stale expected pair, mutation of an historical revision, or a supervisor-originated update is rejected. New preparations pin both capability revision and hash; missing pinned record, absent current-architecture reserve, or an incompatible catalog ABI fails closed.

At admission and preparation, each requested policy field is rejected if above its matching `policyMaxima` field. `resources.memoryBytes` means the application's total cgroup memory limit in bytes. `reserveBytes` means the measured wasmd runtime share in that same cgroup and for the selected complete `runtime binding identity` plus host architecture. They are compared in identical byte units: `reserveBytes >= resources.memoryBytes` rejects; otherwise guest linear-memory limit is exactly `resources.memoryBytes - reserveBytes`. Catalog never supplies a reserve; no reserve is inferred from an image label, process RSS, another catalog revision, or another architecture.

#### Scenario: Owner races a node capability update
- **WHEN** two owner-authorized updates use the same expected record revision and hash
- **THEN** exactly one CAS writes revision `current + 1`; the other receives a revision conflict and cannot silently overwrite limits or the matrix

#### Scenario: Reserve is missing or consumes the total memory limit
- **WHEN** the selected binding has no reserve for the node architecture, or its reserve is greater than or equal to `resources.memoryBytes`
- **THEN** admission or preparation fails closed with `WASM_RESOURCE_RECORD_INVALID` and no default or zero reserve is substituted

### Requirement: Kernel-owned admission uses one visible-state predicate
The Kernel SHALL own wasm admission authorization, version creation, and admission journal. A staging area and an admission-journal row are temporary execution-independent state, not an admitted version. The opaque admission commit token is 256 random bits generated by Kernel, never supplied by a package, and persisted only as `commitTokenHash = hex(SHA-256(UTF8("iweb-wasm-admission-token-v1\n" || tokenBytes)))`.

`AdmissionProofV1` is the exact JCS object shared by every durable admission witness:

```text
{
  schemaVersion: 1,
  applicationId: /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
  packageDigest: sha256-hex,
  versionDigest: sha256-hex,
  sequence: integer 1..9007199254740991,
  versionId: /^[a-f0-9]{64}-[1-9][0-9]{0,15}$/ where versionId = versionDigest || "-" || decimal(sequence),
  normalizedPolicy: NormalizedWasmManifestV1,
  lifecycleAdmissionRecord: {
    schemaVersion: 1,
    state: "admitted",
    admittedAt: RFC3339-UTC,
    admissionJournalRevision: u53
  },
  runtimeBinding: RuntimeBindingIdentityV1,
  capabilityRecordRevision: u53 >= 1,
  capabilityRecordHash: sha256-hex,
  commitTokenHash: sha256-hex
}
```

`normalizedPolicy` is the complete normalized manifest from the digest requirement, not a mutable user manifest or a subset. It SHALL have `name = applicationId`; `lifecycleAdmissionRecord` is the immutable admission-time projection used to create the Kernel wasm registry row and has no later lifecycle states; `versionDigest` SHALL equal `wasmVersionDigestV1(packageDigest, JCS(normalizedPolicy))`; and `versionId` is the only version identity carried into object markers, database rows, materializer receipts, execution commands, leases, active pointers, and rollback records. The version key is `(applicationId, versionId)`, not merely `(applicationId, versionDigest)`: a retry joins an existing exact proof; a later owner-authorized admission of the same digest allocates a higher sequence and therefore a different proof/versionId. Sequence allocation is a Kernel control-state CAS and never inferred from an array length.

For one `(applicationId, versionId)`, the normal journal path is exactly `staging -> validated -> object-complete -> db-hidden -> materializer-acknowledged -> visible`. `visible`, `failed`, and `collected` are terminal; a nonterminal state may transition to `failed`, and only `failed` may transition to `collected`. No other transition or regression is valid. Its exact durable object is `{schemaVersion:1,proof:AdmissionProofV1,state,journalRevision,leaseExpiresAt}`; `state` is one of those literals, `journalRevision` starts at `0` and increases by exactly one for each committed transition, and `leaseExpiresAt` is `RFC3339-UTC` for a nonterminal state or `null` for a terminal state. When it creates a journal, Kernel derives `leaseExpiresAt` from the proof-pinned `admission.stagingTtlSeconds`; it may extend the lease only with a successful journal-revision CAS before expiry. An expired nonterminal row may only transition to `failed` and then collection; it MUST NOT continue toward `visible`. Kernel atomically creates-or-joins the one journal row keyed by `(applicationId, versionId)`: it generates the 256-bit token only for the winning insert, and every concurrent retry of that exact proof receives that same persisted proof and token hash. Each later mutation is idempotent by `(applicationId, versionId, commitTokenHash)`. The object completion marker is exactly `{schemaVersion:1,proof:AdmissionProofV1}`. The hidden or visible Kernel DB row is exactly `{schemaVersion:1,proof:AdmissionProofV1,visibility:"hidden"|"visible"}`. The materializer receipt is exactly `{schemaVersion:1,proof:AdmissionProofV1,materializationTarget}` where `materializationTarget` is `mat-` followed by the first 40 lower-case hex characters of `SHA-256(UTF8("iweb-wasm-materializer-target-v1\n" || JCS(proof)))`. All three witnesses must use byte-identical `proof`; materialization may cache bytes but MUST NOT start an execution while the row is hidden.

When projected to the Kernel-owned wasm `WasmKernelRouteRegistryV1`, the record uses `runtimeKind:"wasm"`, `versionId = proof.versionId`, `identity = {applicationId: proof.applicationId, digest: proof.versionDigest, sequence: proof.sequence}`, `packageDigest = proof.packageDigest`, `normalizedPolicy = proof.normalizedPolicy`, `runtimeBinding = proof.runtimeBinding`, `admissionProofRef = "admission-proof/" || proof.applicationId || "/" || proof.versionId`, `admissionProofDigest = hex(SHA-256(UTF8("iweb-admission-proof-v1\n" || JCS(proof))))`, and lifecycle `admitted`/later Kernel-valid values. The existing celld `VersionRecord` projection remains available only for celld records; its `policy` projection rule is not a wasm parser. The wasm active pointer names the same `{applicationId,digest,sequence}` plus complete binding/proof reference; no implementation may use the legacy celld `VersionRecord.versionId = digest` representation for wasm.

`AdmittedVisible(version)` is the only visibility predicate and is true exactly when all of these hold simultaneously:

```text
1. verified content-addressed object + matching completion marker exists;
2. one Kernel control-DB row is committed with visibility "visible";
3. one durable materializer receipt exists;
4. the complete `AdmissionProofV1`, including `versionId`, `sequence`, and `normalizedPolicy`, is byte-identical in all three records.
```

Readers, prepare, route selection, rollback selection, and ordinary version APIs MUST use this predicate. They MUST NOT treat an object marker, a hidden DB row, a materializer cache, or a supervisor journal entry as a visible version. The durable sequence is: stream/validate staging under record budgets; write all content-addressed blobs and verified marker; insert hidden DB row; send idempotent materializer handoff and receive receipt; atomically change the Kernel row to `visible`; record journal `visible`. This is a recovery protocol, not a claim of cross-store atomic write.

Recovery and collection SHALL be deterministic:

| Observed durable state after interruption | Required recovery / GC result |
| --- | --- |
| staging only | resume same upload only while its journal lease is valid; otherwise transition it to failed and collect staging at `stagingTtlSeconds` |
| complete marker, no DB row | only while the validated journal/token lease remains valid, insert the same hidden row; otherwise transition failed and collect the unreferenced prefix after TTL |
| hidden DB row, no receipt | while the journal lease remains valid, resend the same handoff; a missing/corrupt object or lease expiry marks the hidden row failed and then collects only after no replay owner remains |
| receipt, hidden DB row | retry only the DB `hidden -> visible` CAS; the materialized bytes remain non-executable until it succeeds |
| visible DB row, missing marker/receipt on verification | fail closed, remove it from eligible routing, and require owner recovery; never recreate from mutable workspace bytes |
| visible DB row, journal still `materializer-acknowledged` | verify the complete proof and append the idempotent terminal journal `visible` transition; readers already use the predicate and never use journal state alone |
| client response lost | query by application/versionId returns the one journal outcome; retry with the exact proof cannot create another version or materializer target |

GC MUST retain any object, hidden row, receipt, or journal record still reachable by a nonterminal token. It may delete only terminal collected staging/prefixes or failed records whose retention window expired and whose object/DB/materializer references have all been checked. Concurrent retries of the same proof join `(applicationId, versionId)`; a new sequence is never silently allocated by a retry.

#### Scenario: Completion marker exists with no DB record
- **WHEN** the object-store marker is durable but the node loses power before the hidden DB insert
- **THEN** the version is not visible; replay either inserts the same hidden row using its token or garbage-collects the marker after its journal expires

#### Scenario: DB commit succeeds but materializer handoff fails
- **WHEN** a hidden DB row commits and the handoff request or acknowledgement is lost
- **THEN** replay resends the same token-bound handoff, and the row cannot become visible or executable until one matching receipt exists

#### Scenario: Concurrent duplicate admission
- **WHEN** two owner-authorized callers submit the same layout and normalized manifest for one application
- **THEN** they converge on one token-bound version transaction and one immutable visible version, without duplicate object or materializer ownership

### Requirement: Kernel authorizes lifecycle while supervisor journals execution only
The Kernel SHALL remain the authority for admitted version identities, policies, lifecycle business state, owner authorization, and the active route pointer. The supervisor SHALL keep a durable **execution transaction journal** only: it receives a Kernel-authorized `ExecutionCommand`, starts, checks, drains, or stops a concrete sandbox execution, and records an acknowledgement. It SHALL NOT create an admitted version, choose a rollback target, update a Kernel lifecycle state, or make a route pointer visible.

The wasm protocol is physically and grammatically separate from the existing celld supervisor protocol. Celld continues to use only `POST /v1/rpc`, `version:1`, and the existing celld operation union. Wasm uses only `POST /v1/execution-rpc` with a raw JCS `ExecutionRpcEnvelopeV1`; `/v1/rpc` MUST reject an envelope containing `protocol`, `command`, `query`, or `replay`, and `/v1/execution-rpc` MUST reject the celld `version`/`operation` envelope. No receiver may retry a rejected request through the other path, infer a default protocol, or parse an unknown protocol as celld. The execution HTTP socket carries HTTP request/response bytes only: it MUST reject the raw snapshot magic, any `SCM_RIGHTS` ancillary data, and any non-HTTP preamble before parsing the body. Snapshot descriptors use the separate `SnapshotFdTransportV1` socket defined below; a receiver MUST never switch sockets or reinterpret one transport as the other.

`ExecutionRpcEnvelopeV1` has exactly `{protocol,requestId,body}`. `protocol` is the literal `"iweb-execution-rpc-v1"`; `requestId` is a lower-case UUIDv7; and `body` is exactly one of the three typed payloads below. The response has exactly `{protocol,requestId,body}` with the same protocol and requestId. This transport is carried only over the fixed `/run/iweb-sandbox/supervisor.sock` Unix-domain socket. In the current deployment the **supervisor process** (systemd `User=iweb-sandbox`, `Group=iweb-sandbox`) calls `listen`, creates the inode, and applies mode `0600`; Kernel is the connecting peer and runs as UID/GID `0/0` in the image entrypoint. The socket is never container-published, and neither envelope carries an owner bearer token. The precise peer and path authorization is specified by `SupervisorSocketAuthV1` below; a caller unable to pass both filesystem and peer-credential checks cannot submit, query, or replay a command. A future non-root Kernel deployment or cross-host transport requires a new deployment/protocol revision and explicit mutual authentication; it may not weaken this v1 by changing an environment path or adding an optional header.

`ExecutionCommand` has exactly `schemaVersion:2`, `commandId`, `expectedControlRevision`, `expectedJournalRevision`, `operation`, `identity`, `applicationId`, `packageDigest`, `runtimeBinding`, `matrixRevision`, `hostServicePolicyDigest`, `fenceNonce`, `capabilityRecordRevision`, `capabilityRecordHash`, `secretRevision`, `secretSnapshotRef`, `secretValuesDigest`, `configRevision`, `configSnapshotRef`, and `configValuesDigest`. `commandId` is a lower-case UUIDv7; `operation` is one of `prepare`, `start`, `drain`, `stop`; `expectedControlRevision` is the expected single `wasm-control-state-v2` `controlRevision`, and with `expectedJournalRevision`, `secretRevision`, and `configRevision` is `u53`; `identity` is the full execution identity below; `applicationId` is the host-injected execution identity; `runtimeBinding` is the complete `RuntimeBindingIdentityV1` field set with `hostABI` exactly `iweb-wasmd-abi@1.1.0`; `matrixRevision` is the literal `2`; `hostServicePolicyDigest` is the admitted `HostServicePolicyV2.policyDigest` `sha256-hex` pin, or exactly the empty string when the admitted version carries no host-service policy (the policyless zero-value policy: `kv`, `sql`, and `logging` all `null`, `storageBytes:0`, `reserveBytes:0`, `policyDigest:""`); `fenceNonce` is `/^[a-f0-9]{32}$/`; `secretSnapshotRef` is a `sha256-hex` opaque Kernel reference that contains no value; `secretValuesDigest` is the exact `SnapshotRefV1.valuesDigest` for that ref; `configSnapshotRef` is a `sha256-hex` opaque Kernel reference or `null` exactly when `configRevision` is `0`; and `configValuesDigest` is the exact config snapshot `valuesDigest` or `null` exactly when `configSnapshotRef` is `null`. For `prepare`/`start`, both digest bindings are checked before execution; for `drain`/`stop`, the command still carries the adopted snapshot digests and they remain part of the identity fence. `CommandRequestV1` is exactly `{kind:"command",command:ExecutionCommand}`.

`ExecutionAcknowledgement` has exactly `{schemaVersion:1,commandId,operation,identity,packageDigest,runtimeBinding,capabilityRecordRevision,capabilityRecordHash,secretRevision,secretSnapshotRef,secretValuesDigest,configRevision,configSnapshotRef,configValuesDigest,drainReceiptDigest,result,failureCode,journalRevision}`. All echoed identity, config, snapshot, and values-digest fields must exactly equal the command; `drainReceiptDigest` is non-null only when `operation:"drain"` and `result:"applied"`, and then is the digest of the exact `DrainReceiptV1`; a rejected drain has `drainReceiptDigest:null`. `result` is `applied` or `rejected`; `failureCode` is `null` if and only if result is `applied`, otherwise it matches `/^[A-Z][A-Z0-9_]{0,63}$/`; and `journalRevision` is the durable revision that recorded this terminal command result. `CommandResponseV1` is exactly `{kind:"acknowledgement",acknowledgement:ExecutionAcknowledgement}`.

`CommandQueryV1` is exactly `{kind:"query",commandId:UUIDv7}` and returns exactly `{kind:"query-result",commandId,status,received,acknowledgement}`. `status` is `"missing"`, `"received"`, or `"completed"`; `received` is `null` only for `missing`, otherwise its exact `CommandReceivedV1`; and `acknowledgement` is non-null if and only if `status:"completed"`. `CommandReplayV1` is exactly `{kind:"replay",command:ExecutionCommand}` and returns the same `CommandResponseV1` for that command ID. Replay accepts only a byte-identical command JCS body: a known command ID with any differing field returns `EXECUTION_COMMAND_ID_CONFLICT`; a completed command returns its stored acknowledgement without repeating the execution side effect; a received but incomplete command resumes exactly its recorded operation under its stored fence. Kernel writes its outbox in the same wasm control-state CAS that authorizes the command, delivers it through this channel, and uses query/replay after any uncertain response; no owner key travels in this channel.

The supervisor first CAS-writes a `command-received` journal entry at `expectedJournalRevision`, performs the idempotent execution side effect, then CAS-writes this completion acknowledgement before returning it. It accepts no command unless both expected revisions and the identity fence match. Kernel accepts an acknowledgement only when command ID, every echoed command field, result wire, and current Kernel control revision still match; otherwise it treats it as stale, reconciles it, and never routes from it.

A supervisor completion that arrives before or after a Kernel crash is replay evidence, not routing authority. On reconciliation Kernel queries/replays the exact command ID, validates its acknowledgement, writes its own projection with CAS, and only then may issue the Kernel route-pointer CAS required by `application-sandbox`.

#### Scenario: Supervisor journal commits before Kernel projection
- **WHEN** a supervisor has durably acknowledged an execution command and Kernel crashes before persisting its projection
- **THEN** restart reconciliation replays the same command ID and never routes from the journal alone

#### Scenario: Unauthorised supervisor mutation is attempted
- **WHEN** a supervisor journal entry attempts to name a new version, replacement binding, or active route without a matching Kernel command
- **THEN** the Kernel rejects it and retains its own authoritative version and route records

#### Scenario: Celld RPC envelope is sent to the wasm endpoint
- **WHEN** a caller sends `{version:1,operation:"prepare",...}` to `POST /v1/execution-rpc`, or sends an execution envelope to `POST /v1/rpc`
- **THEN** the receiver rejects it with `EXECUTION_PROTOCOL_MISMATCH` or `CELLD_PROTOCOL_MISMATCH`, performs no side effect, and never falls back to the other parser

#### Scenario: Kernel loses the command response
- **WHEN** a supervisor may have received a command but Kernel loses the HTTP response or restarts before projection
- **THEN** Kernel sends `CommandQueryV1` and, if needed, byte-identical `CommandReplayV1`; one stored acknowledgement and at most one execution side effect result

### Requirement: The execution socket has an explicit two-sided peer-credential contract
`SupervisorSocketAuthV1` is the only authentication envelope for the local execution transport. Its canonical deployment object is:

```text
{
  schemaVersion: 1,
  socketPath: "/run/iweb-sandbox/supervisor.sock",
  socketCreator: { uidName: "iweb-sandbox", gidName: "iweb-sandbox", mode: "0600" },
  kernelPeer: { uid: 0, gid: 0 },
  supervisorPeer: { uidName: "iweb-sandbox", gidName: "iweb-sandbox" },
  credentialMechanism: "linux-so-peercred",
  pathPolicy: "fixed-no-symlink-no-fallback"
}
```

The names `iweb-sandbox` resolve to the numeric UID/GID installed by the packaging step; the current image topology fixes the Kernel peer to numeric UID/GID `0/0`. The supervisor service is the socket creator, not Kernel: systemd creates `/run/iweb-sandbox` for that service, the supervisor calls `listen`, and it applies `chmod 0600` after bind. Kernel may connect as root despite the mode, but a non-root Kernel is not a supported v1 deployment. A deployment that wants a non-root Kernel MUST introduce a new socket-auth revision with an explicit group/mode policy; it MUST NOT silently change `0600`.

Before connecting, Kernel MUST `lstat` the exact path and require a socket inode, owner UID/GID equal to the resolved `iweb-sandbox` pair, mode exactly `0600`, a non-symlink parent `/run/iweb-sandbox` owned by the same pair with mode `0700`, and the configured path equal byte-for-byte to the fixed literal. `IWEB_SANDBOX_SOCKET` may only repeat that literal; empty, alternate, relative, symlinked, bind-mounted-at-another-path, or TCP paths are `SUPERVISOR_SOCKET_PATH_REJECTED`. Kernel MUST perform the same checks again after connect to defeat path replacement.

The supervisor obtains `SO_PEERCRED` (Linux `getsockopt(SOL_SOCKET, SO_PEERCRED)`) on every accepted HTTP connection and requires peer UID/GID `0/0` in the current topology. Kernel obtains the peer credentials on its connected socket and requires the resolved `iweb-sandbox` UID/GID. A missing, unavailable, or mismatched credential is `SUPERVISOR_PEER_CREDENTIALS_REJECTED`; the HTTP body is not parsed and no journal entry is written. The supervisor also rejects a connection whose local socket inode/path identity changed after bind. These checks are mandatory even when the caller is root: filesystem access proves access to the inode, while peer credentials prove the service at the other end. The v1 trust assumption is that the host root account is a trusted principal; `SO_PEERCRED=0/0` cannot distinguish Kernel from any other root process, so this is not a claim of root-process identity isolation. A non-root Kernel MUST use a new socket-auth revision with an explicit credential/group policy. The HTTP socket rejects every `SCM_RIGHTS` ancillary message and every raw snapshot magic; celld `/v1/rpc` remains its existing HTTP-only protocol and rejects any FD or wasm frame as `CELLD_PROTOCOL_MISMATCH`.

After peer authorization, Kernel is authorized to send only a command that it created under owner authentication, the expected control/journal revisions, the complete execution identity, and the command digest. Supervisor accepts only that command and records `command-received`; Kernel accepts a response only from the peer-credential-checked socket whose command ID, digest, full identity, and journal revision match. Thus the current cross-service topology has bidirectional authorization without an owner bearer token on the socket: systemd identity + fixed inode authorize the channel, and command/ack CAS fences authorize each operation. A socket copied to another path, a process running under the wrong UID, or a syntactically valid envelope from an unapproved peer is rejected before side effects.

#### Scenario: A replacement path is supplied
- **WHEN** Kernel is configured with `/tmp/supervisor.sock`, a relative path, a symlink, or a second bind-mounted path
- **THEN** startup fails with `SUPERVISOR_SOCKET_PATH_REJECTED`; it does not try the fixed path as a fallback and does not open a TCP listener

#### Scenario: A process connects with the wrong UID
- **WHEN** a peer reaches the fixed socket but `SO_PEERCRED` is not the configured Kernel UID/GID, or Kernel sees a peer other than the resolved supervisor UID/GID
- **THEN** both sides close the connection before HTTP parsing and no command, query, replay, or journal mutation occurs

#### Scenario: The supervisor restarts between path check and connect
- **WHEN** the old socket inode is removed and a new supervisor binds the same literal path before Kernel connects
- **THEN** Kernel re-checks inode owner/mode and peer credentials after connect; a mismatch is rejected and no stale command is sent

### Requirement: Snapshot descriptors use an independent framed raw socket
The system SHALL use a second, fixed Unix socket for snapshot descriptor handoff. `SnapshotFdTransportV1` is exactly:

```text
{
  schemaVersion: 1,
  protocol: "iweb-snapshot-fd-v1",
  socketPath: "/run/iweb-sandbox/snapshot-fd.sock",
  socketFamily: "AF_UNIX",
  socketType: "SOCK_SEQPACKET",
  socketCreator: { uidName: "iweb-sandbox", gidName: "iweb-sandbox", mode: "0600" },
  kernelPeer: { uid: 0, gid: 0 },
  frameMagicHex: "4957454246443100",
  headerBytes: 16,
  lengthEncoding: "u32-big-endian",
  maxPayloadBytes: 65536
}
```

The supervisor creates and binds this socket as `iweb-sandbox`; it is never the HTTP execution socket and is never TCP or an environment-selected alternate. On every raw connection the supervisor calls `getsockopt(SOL_SOCKET, SO_PEERCRED)` and requires Kernel UID/GID `0/0`; Kernel requires the connected peer to be the resolved `iweb-sandbox` UID/GID. Both sides repeat the fixed-path, inode, owner, mode, and peer checks from `SupervisorSocketAuthV1`, and reject before `recvmsg` payload handling when any check fails. The v1 root trust assumption and the non-root-Kernel revision rule apply to this socket as well.

Each request packet is one complete frame with no stream reassembly:

```text
offset 0..7   ASCII bytes I W E B F D 1 NUL
offset 8..9   version u16 big-endian = 1
offset 10     frameType u8: 1 secret-request, 2 config-request, 0x81 acknowledgement
offset 11     flags u8 = 0
offset 12..15 payloadLength u32 big-endian, 1..65536
offset 16..   payloadLength bytes of UTF-8 JCS payload
```

The framing vector is fixed: payload bytes `7b22736368656d6156657273696f6e223a317d` (JCS `{"schemaVersion":1}`, 19 bytes) with `frameType:1` has header hex `49574542464431000001010000000013` and total frame length `35` bytes. A parser must accept the boundary and then reject the payload as `SNAPSHOT_WIRE_INVALID` for its missing handoff fields; it MUST NOT report a length or magic error. Appending one byte changes the expected total length and returns `SNAPSHOT_FRAME_INVALID`.

Kernel sends each request with exactly one `sendmsg` call, one iovec containing the complete frame, and exactly one `SOL_SOCKET/SCM_RIGHTS` control message containing exactly one FD. Supervisor uses one `recvmsg` call and requires `MSG_EOR`, rejects `MSG_TRUNC`/`MSG_CTRUNC`, extra control messages, a missing descriptor, or more than one descriptor. The acknowledgement is one `SOCK_SEQPACKET` frame with `frameType:0x81` and **no** ancillary descriptor. Any packet with a wrong magic, version, flags, length, packet boundary, or unexpected frame type is rejected before payload parsing with `SNAPSHOT_FRAME_INVALID`.

`SecretSnapshotFdHandoffV1` is exactly `{schemaVersion:1,kind:"secret",commandId,commandDigest,ref,applicationId,versionId,preparationGeneration,secretRevision,valuesDigest,fdDigest,expiresAt}`; `ConfigSnapshotFdHandoffV1` is exactly `{schemaVersion:1,kind:"config",commandId,commandDigest,ref,applicationId,versionId,preparationGeneration,configRevision,valuesDigest,fdDigest,expiresAt}`. `frameType:1` MUST carry the secret shape, `frameType:2` MUST carry the config shape, and the JCS `kind` must agree with the frame type. `commandDigest` is the command digest defined for `CommandReceivedV1`; `valuesDigest` is the matching `SnapshotRefV1` digest. The FD bytes MUST be byte-identical to the canonical JCS `SnapshotValuesPayloadV1` or `ConfigValuesPayloadV1` (the digest-input object, not the Kernel metadata record); `fdDigest` is the one SHA-256 operation `hex(SHA-256(UTF8("iweb-secret-snapshot-v1\n" || fdBytes)))` for `kind:"secret"`, or `hex(SHA-256(UTF8("iweb-config-snapshot-v1\n" || fdBytes)))` for `kind:"config"`, where `fdBytes` are returned by `pread(fd, offset=0)` until the `fstat` byte length is exhausted, with a final read at EOF and no re-serialization. This domain prefix is the same one used by the corresponding `valuesDigest` formula; it is not a second hash of a hex string. All identities, revisions, expiry, and digests are byte-for-byte checked before the descriptor is retained. The acknowledgement payload is exactly `{schemaVersion:1,kind:"ack",commandId,handoffDigest,status:"accepted"|"rejected",failureCode:null|/^[A-Z][A-Z0-9_]{0,63}$/,journalRevision}` and `handoffDigest = hex(SHA-256(UTF8("iweb-snapshot-handoff-v1\n" || JCS(request payload))))`.

For `prepare` and `start`, Kernel sends exactly one secret frame first (including revision `0`'s canonical empty snapshot), then exactly one config frame iff `configRevision > 0`; it sends no config frame and the command carries `configValuesDigest:null` when `configRevision:0`. No other frame is allowed. Kernel closes the raw connection after the accepted acknowledgements and sends the `ExecutionRpcEnvelopeV1` on a newly opened HTTP connection. `drain` and `stop` send no snapshot frames; replay of a `prepare`/`start` command replays its exact raw frames before replaying the HTTP command. The HTTP socket rejects a packet beginning with `IWEBFD1\0`, any ancillary FD, or a body fallback with `EXECUTION_HTTP_FRAME_REJECTED`; the raw socket rejects `POST `, `GET `, or an HTTP header with `SNAPSHOT_HTTP_ON_RAW_SOCKET`.

The handoff is persisted by command ID and handoff digest, not by an open FD: a supervisor crash closes all descriptors and recovery requires the same byte-identical frames before replaying a received command. A duplicate command ID with the same handoff digest returns the stored acknowledgement without a second side effect; a different `commandDigest`, tuple, ref, or `valuesDigest` returns `SNAPSHOT_HANDOFF_ID_CONFLICT`. If the raw acknowledgement is lost, Kernel queries the execution command and resends the exact frames only when the journal says the command is received but the handoff is not durably accepted; it never sends an HTTP envelope with an embedded or preceding FD.

The raw transport's stable failure codes are `SNAPSHOT_SOCKET_PATH_REJECTED`, `SNAPSHOT_FRAME_INVALID` (header, boundary, ancillary count, or socket type), `SNAPSHOT_WIRE_INVALID` (JCS payload shape), `SNAPSHOT_HTTP_ON_RAW_SOCKET`, `EXECUTION_HTTP_FRAME_REJECTED`, `SNAPSHOT_HANDOFF_ID_CONFLICT`, `SNAPSHOT_VALUES_DIGEST_MISMATCH`, and `SNAPSHOT_FD_POLICY_REJECTED`. They are uppercase bounded codes, contain no path or secret value, and are never translated into a successful celld or wasm command.

#### Scenario: HTTP and raw transports are crossed
- **WHEN** a caller puts `IWEBFD1\0` before an HTTP request, sends `SCM_RIGHTS` on `/run/iweb-sandbox/supervisor.sock`, or sends `POST /v1/execution-rpc` to `snapshot-fd.sock`
- **THEN** the receiving socket returns `EXECUTION_HTTP_FRAME_REJECTED` or `SNAPSHOT_HTTP_ON_RAW_SOCKET`, closes the connection before journal mutation, and does not try the other parser

#### Scenario: A raw frame is split or carries two descriptors
- **WHEN** `recvmsg` reports no `MSG_EOR`, truncation, a payload length different from the packet, or two FDs in one request
- **THEN** supervisor returns `SNAPSHOT_FRAME_INVALID`, closes every received FD, and records no command or handoff

#### Scenario: Raw socket path is redirected
- **WHEN** a deployment supplies an empty, relative, symlinked, TCP, or alternate path instead of `/run/iweb-sandbox/snapshot-fd.sock`
- **THEN** Kernel returns `SNAPSHOT_SOCKET_PATH_REJECTED`, performs no connect fallback, and sends no descriptor

#### Scenario: Raw handoff response is lost during restart
- **WHEN** Kernel sent the secret/config frames but lost the acknowledgement while supervisor restarted
- **THEN** query/replay finds either one persisted handoff digest and reuses it idempotently or no accepted handoff; Kernel resends the exact frames, and no alternate FD or HTTP preamble is accepted

### Requirement: Snapshot FD content is bound across Kernel, supervisor, Podman, and wasmd
For every secret snapshot, the following equality is mandatory before a `prepare` or `start` side effect:

```text
ExecutionCommand.secretValuesDigest
  == SecretSnapshotFdHandoffV1.valuesDigest
  == SecretSnapshotRefV1.valuesDigest
  == fdDigest(SCM_RIGHTS fd bytes)
  == wasmd.readDigest(fd 3)
```

`wasmd.readDigest` uses the same single domain-prefixed SHA-256 algorithm as `fdDigest`, so it hashes bytes rather than a hexadecimal digest string. The config chain is identical with `configValuesDigest` and FD `4`; when `configRevision:0`, all config references and digests are `null` and FD `4` MUST be absent. `fdBytes` must equal the exact raw canonical values-payload bytes, and the domain-separated `fdDigest` above must equal the ref's `valuesDigest`; no parsed/re-serialized JSON or hex digest text may substitute. Supervisor treats `ref` as opaque and does not parse Kernel's private snapshot index: the Kernel-authenticated command/handoff digest is the binding proof, while the received bytes provide the independently checkable content witness. A supervisor MUST reject `SNAPSHOT_VALUES_DIGEST_MISMATCH` before journal completion if any link differs, even when the ref itself is valid.

The three-party process contract is fixed. Kernel opens the verified source `O_RDONLY|O_CLOEXEC` and sends it only through the raw socket. Supervisor verifies regular-file `fstat`, read-only `fcntl(F_GETFL)`, exact digest, and tuple, then reserves descriptor `3` for secret and `4` for config. Its rootless Podman invocation is generated exactly by supervisor and includes `--preserve-fds=2`; no application-supplied OCI argument, mount, environment, or path can add a descriptor. In the Podman exec child, `FD_CLOEXEC` is cleared only for descriptors `3` and `4`, all other inherited descriptors are closed, and the container entrypoint closes every descriptor except the required slots before `execve` of the digest-pinned `wasmd`. `wasmd` verifies the slot number, `O_RDONLY` status, regular-file identity, and digest again; it closes `4` when config is absent and never passes either FD to gateway, a sidecar, another sandbox, or a non-wasmd child. The application receives only host `store.get` bindings backed by those descriptors and no host path.

Inside the container, a write attempt on either assigned descriptor MUST fail (`EBADF` or `EROFS`), `/proc/self/fd` path resolution MUST not grant a directory or alternate path, and a child spawned by wasmd MUST inherit neither descriptor unless it is the same trusted host adapter process. A wrong FD number, writable descriptor, extra inherited descriptor, missing descriptor, wrong command ID/digest, or a descriptor visible in gateway/another sandbox is a negative vector and leaves the command rejected with no readiness lease.

#### Scenario: A valid ref is paired with bytes from another snapshot
- **WHEN** `fdDigest` or `wasmd.readDigest(fd 3)` differs from `ExecutionCommand.secretValuesDigest` while the opaque ref exists
- **THEN** supervisor returns `SNAPSHOT_VALUES_DIGEST_MISMATCH`, closes the FD, does not start Podman/wasmd, and records no successful acknowledgement

#### Scenario: Descriptor inheritance is widened
- **WHEN** Podman receives an extra preserved FD, wasmd sees secret FD `4`, or a gateway/sidecar can open FD `3`
- **THEN** the launch fails with `SNAPSHOT_FD_POLICY_REJECTED`, all child processes are stopped, and the snapshot source remains subject to normal TTL GC

#### Scenario: A replay uses a different values digest
- **WHEN** a known `commandId` is replayed with the same opaque ref but a different `secretValuesDigest` or `configValuesDigest`
- **THEN** supervisor returns `SNAPSHOT_HANDOFF_ID_CONFLICT` before execution and Kernel retains the original command/acknowledgement bytes

### Requirement: Kernel business authority is partitioned by runtime kind
This change SHALL use a strict per-kind Kernel registry instead of adding `runtimeKind` to the existing celld `VersionRecord` validator. The Kernel therefore owns two disjoint business record sets: the existing celld `ControlStateFile`/`VersionRecord` and the wasm-only `WasmKernelRouteRegistryV1`. They share the Kernel owner authorization and active-route authority, but never share a file, sequence allocator, lifecycle validator, or route-generation counter. A celld record is never parsed as wasm, and a wasm record is never projected into the celld file.

The canonical wasm business registry is the `runtimeKind:"wasm"` section of `/data/kernel/wasm-control-state-v2.json`; its exact application record is:

```text
{
  runtimeKind: "wasm",
  applicationId: ApplicationId,
  versions: [
    {
      versionId: VersionId,
      identity: { applicationId, digest: sha256-hex, sequence: u53 },
      packageDigest: sha256-hex,
      normalizedPolicy: NormalizedWasmManifestV1,
      lifecycle: KernelLifecycleState,
      runtimeBinding: RuntimeBindingIdentityV1,
      admissionProofRef: "admission-proof/" || applicationId || "/" || versionId,
      admissionProofDigest: sha256-hex,
      readinessLeaseDigest: sha256-hex|null
    }
  ],
  active: WasmActivePointerV1,
  routeGeneration: u53,
  secretRevision: u53,
  configRevision: u53
}
```

`WasmActivePointerV1` is the exact tagged union `{kind:"active",runtimeKind:"wasm",applicationId,versionId,identity,runtimeBinding,admissionProofRef,admissionProofDigest,routeGeneration,hostServicePolicyDigest?,preparationGeneration?,executionGeneration?}` or `{kind:"unavailable",runtimeKind:"wasm",applicationId,routeGeneration}`. The three optional increments carry the activation-time policy pin and execution tuple: `hostServicePolicyDigest` is a `sha256-hex` digest or the empty policyless pin, and `preparationGeneration` and `executionGeneration` are `u53 >= 1`; historical pointers may omit any of them. An active pointer's identity, binding, proof reference, and route generation must match one registry version; an unavailable pointer has no candidate version and cannot be used for routing. `KernelLifecycleState` is the existing accepted celld validator set; `retiring` remains supervisor-only. The registry's `runtimeKind`, `runtimeBinding`, `admissionProofRef`, and `admissionProofDigest` are mandatory business references, so a route cannot be reconstructed from a mutable package, catalog lookup, or supervisor journal.

`MigrationRecordV1` is an owner-authorized, one-way snapshot transaction and has the exact record:

```text
{
  schemaVersion: 1,
  migrationId: UUIDv7,
  sourceKind: "celld",
  sourceApplicationId: ApplicationId,
  sourcePath: "/data/kernel/control-db.json",
  sourceRevision: u53,
  sourceDigest: sha256-hex,
  targetKind: "wasm",
  targetApplicationId: ApplicationId,
  targetPath: "/data/kernel/wasm-control-state-v2.json",
  targetDigest: sha256-hex,
  status: "started"|"committed"|"rolled-back",
  receiptRef: "migration-receipt/" || migrationId,
  startedAt: RFC3339-UTC,
  completedAt: RFC3339-UTC|null
}
```

Because the current celld `ControlStateFile` has no revision field, `sourceRevision` is the explicit snapshot revision `0` for that legacy schema; it is never inferred from `versions.length`. A future source export with a revision uses that exact value. `sourceDigest` is the SHA-256 of the raw canonical source snapshot; `targetDigest` is the SHA-256 of the complete target JCS file, including `controlRevision`; `targetRevision` is that committed target `controlRevision`. `sourceApplicationId` and `targetApplicationId` are required for every migration, and `sourceApplicationId != targetApplicationId` is mandatory when `sourceKind != targetKind`; the migration is storage/bootstrap transfer only and never changes an existing application's runtime-kind binding or active pointer. `MigrationReceiptV1` is exactly `{schemaVersion:1,migrationId,sourceKind,sourceApplicationId,sourceRevision,sourceDigest,targetKind,targetApplicationId,targetRevision,targetDigest,completedAt}` and is written once at `committed`.

Migration is idempotent on `(sourceKind,sourceApplicationId,sourceRevision,sourceDigest,targetKind,targetApplicationId)`: a byte-identical replay returns the original receipt, while the same source tuple with a different digest or target ID returns `MIGRATION_SOURCE_CONFLICT`. A crash after target write but before receipt recomputes and verifies `targetDigest`, then writes the same receipt; a crash before target commit leaves the source untouched and retries the same migration ID. A validation failure or digest mismatch quarantines the target, writes `rolled-back`, and leaves every active pointer unchanged. No celld row is converted into a wasm version without a complete `AdmissionProofV1`, binding, and `runtimeKind:"wasm"`; the migration never guesses those fields and cannot use it to change an existing application ID's kind.

#### Scenario: Celld and wasm records use the same application ID
- **WHEN** a migration or registration tries to create a wasm record for `alpha` after `alpha` is celld-bound
- **THEN** the Kernel returns `APPLICATION_RUNTIME_KIND_CONFLICT`, writes neither target registry nor active pointer, and requires a new application ID

#### Scenario: Migration target is written but receipt is lost
- **WHEN** the node loses power after the target file is durable and before `MigrationReceiptV1` is written
- **THEN** recovery recomputes the exact target digest and writes the one idempotent receipt, or quarantines the target on any mismatch; no route becomes visible during recovery

### Requirement: Wasm control state has a revisioned outbox and isolated journal
The wasm control store SHALL be a separate physical record from the existing celld `ControlStateFile` (`version:1, applications`). Its canonical file is `wasm-control-state-v2.json`; a celld file parser MUST reject this shape and a wasm parser MUST reject `version:1` celld state. A node upgrade may copy Kernel-owned admitted wasm version/route records into the new file through an owner-approved migration transaction, but it MUST NOT rewrite the celld file in place, infer wasm records from celld desired state, or share a sequence allocator between the two stores. Until the migration has a complete receipt, wasm publication and execution remain closed; celld behavior remains unchanged.

The exact top-level `WasmControlStateFileV2` JCS object is:

```text
{
  schemaVersion: 2,
  runtimeKind: "wasm",
  controlRevision: u53,
  applications: Record<ApplicationId,WasmApplicationControlRecordV1>,
  commandOutbox: CommandOutboxRecordV1[],
  migration: { source: "celld-control-state-v1", status: "not-started"|"in-progress"|"complete", sourceDigest: sha256-hex|null, completedAt: RFC3339-UTC|null }
}
```

`WasmApplicationControlRecordV1` has exactly `{runtimeKind:"wasm",applicationId,versions,active,routeGeneration,secretRevision,configRevision}`. `versions` is a unique-by-`versionId` array of `{versionId,identity,packageDigest,normalizedPolicy,lifecycle,runtimeBinding,admissionProofRef,admissionProofDigest,readinessLeaseDigest}`; `identity` is the proof-derived `{applicationId,digest,sequence}`, `lifecycle` is one of the existing Kernel `LifecycleState` literals (never `retiring`), and nullable `readinessLeaseDigest` is required for a ready/active candidate. `active` is the wasm `WasmActivePointerV1` shape with `versionId` and binding consistency; `routeGeneration`, `secretRevision`, and `configRevision` are non-negative `u53` CAS values. The file rejects a version row whose `versionId` is not the proof's complete digest-sequence label or whose identity, normalized policy, runtime binding, proof digest, or proof reference disagrees.

`controlRevision` starts at `0` for an empty wasm file and increases by exactly one for every committed Kernel mutation, including an outbox append, acknowledgement projection, lifecycle projection, route-pointer CAS, and migration transition. Every write supplies `expectedControlRevision`; a mismatch returns `CONTROL_REVISION_CONFLICT` and writes nothing. The state file is written with the existing file-level temp/fsync/rename discipline, but the revision CAS is the logical compare-and-swap that the current `ControlStore` lacks.

`CommandOutboxRecordV1` has exactly `{commandId,command,createdAt,deliveryState,attempts,lastAttemptAt}`. `deliveryState` is `pending`, `sent`, `acknowledged`, or `dead`; `attempts` is a non-negative integer; the command body is byte-identical to the command in the execution envelope. An outbox record is appended in the same revision-CAS commit that authorizes the command. `sent` is advisory and may be replayed; `acknowledged` is set only after an identity-checked acknowledgement is projected; `dead` is owner-visible and never silently retried after a permanent fence error. Outbox deletion is forbidden until the command is terminal, its acknowledgement/projection is durable, and the Kernel has recorded a replay retention timestamp.

The supervisor journal is a separate `wasm-execution-journal-v1` file owned by supervisor and has exactly `{schemaVersion:1,journalRevision,entries}`. Each entry is either `CommandReceivedV1 = {kind:"command-received",commandId,commandDigest,command,snapshotHandoffDigest:sha256-hex|null,receivedAt,journalRevision}` or `CommandCompletedV1 = {kind:"completed",commandId,commandDigest,acknowledgement,snapshotHandoffDigest:sha256-hex|null,completedAt,journalRevision}`. `commandDigest = hex(SHA-256(UTF8("iweb-execution-command-v1\n" || JCS(command))))`; a received entry must precede its completed entry, and each journal revision increases by one with a CAS. `snapshotHandoffDigest` is null only for commands with no snapshot handoff; otherwise it is the accepted raw-transport digest and must match the command's values-digest fields. Kernel control revision and supervisor journal revision are independent counters; a command carries both expected values and neither counter may be substituted for the other. Query/replay reads this journal and never reads celld desired-state or its `/v1/rpc` history.

The double-CAS sequence is: (1) Kernel CAS `controlRevision` while appending the outbox; (2) supervisor CAS `journalRevision` for received/completed; (3) Kernel CAS `controlRevision` to project the checked acknowledgement. A failure between any two steps leaves the route unchanged and is resolved by query/replay or outbox GC only after the command's terminal proof is present. An acknowledgement cannot advance a Kernel route without a successful third CAS and the separate route-pointer CAS.

#### Scenario: Celld state is presented to the wasm store
- **WHEN** `wasm-control-state-v2.json` is absent but a `version:1` celld `ControlStateFile` is present, or a v2 parser sees celld-only fields
- **THEN** wasm state is treated as uninitialized/migration-required, never parsed as wasm, and celld state remains readable by its original parser

#### Scenario: Outbox append races another Kernel writer
- **WHEN** two owner commands use the same `expectedControlRevision`
- **THEN** exactly one appends its command and increments `controlRevision`; the other receives `CONTROL_REVISION_CONFLICT` and must query/retry from the new revision

#### Scenario: Supervisor completion arrives before projection
- **WHEN** the supervisor journal contains `command-received` and `completed` but the Kernel outbox is still `sent`
- **THEN** reconciliation verifies `commandDigest`, projects the acknowledgement with a control-revision CAS, and leaves the active pointer unchanged until the separately authorized route CAS

### Requirement: Every wasm execution uses a typed dual-generation fence
The system SHALL use exactly this `WasmExecutionIdentityV1` object on wasm lifecycle, readiness, gateway health, metrics, secret snapshots, and activation CAS:

```text
{
  sandboxId: /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/,
  versionId: /^[a-f0-9]{64}-[1-9][0-9]{0,15}$/ and parsed sequence <= 9007199254740991,
  preparationGeneration: u53,
  executionGeneration: u53
}
```

For a newly allocated sandbox record both generations are `0`. A Kernel `prepare` CAS changes `preparationGeneration` from `p` to `p + 1`, where `p >= 0`; it never reuses a prior value, including after failed preparation, secret rotation, runtime rebind, rollback, or crash recovery. An execution allocation CAS changes `executionGeneration` from `e` to `e + 1`, where `e >= 0`; an execution that is alive or reports health/metrics must have both generations at least `1`. A stopped/unprepared record may retain its last positive generations; `executionGeneration:0` is permitted only before the first allocation. No transition may decrease either value.

If either current generation is `9007199254740991`, the corresponding allocation fails with `WASM_GENERATION_EXHAUSTED`; the Kernel does not wrap, reuse, or substitute zero, and the existing route remains unchanged.

The target identity, package digest, runtime binding, capability revision/hash, and expected current pair are the compare-and-swap fence. Gateway accepts a new request only when the Kernel active route pointer names that exact identity and binding. The wasmd process receives the same immutable values at startup and MUST refuse a request, health report, metrics report, or drain command that fails its own fence. Kernel and supervisor reject signals with a missing field, different tuple, or out-of-date command/revision as stale; they do not coerce a celld signal.

Celld's version `sequence` distinguishes immutable version labels and its existing one-field gateway/readiness `generation` is a legacy celld signal. Neither proves wasm preparation or execution freshness. A wasm health/metrics/readiness signal carrying only `versionId` and celld `generation` is `WASM_IDENTITY_INCOMPLETE` and must not be adopted.

#### Scenario: First preparation and later process restart
- **WHEN** a newly admitted wasm sandbox is prepared and its process later restarts
- **THEN** first preparation allocates `(preparationGeneration:1, executionGeneration:1)`, and the restart allocates a strictly higher execution generation; recovery that creates a new preparation also allocates a strictly higher preparation generation

#### Scenario: Old process speaks after a replacement execution starts
- **WHEN** an old execution sends readiness, health, metrics, or a drain acknowledgement after a higher execution generation is current
- **THEN** each receiver rejects it as stale and the old execution cannot receive new routed traffic

### Requirement: Runtime binding and catalog are replayable and revocable
The Kernel SHALL pin this `RuntimeBindingIdentityV1` into the admitted version, each preparation, active route event, and rollback event:

```text
{
  kind: "wasm",
  catalogRevision: u53 in 1..9007199254740991,
  catalogHash: sha256-hex,
  entryKey: /^[a-z][a-z0-9.-]{0,63}$/,
  imageDigest: /^sha256:[a-f0-9]{64}$/,
  hostABI: "iweb-wasmd-abi@1.0.0",
  world: "wasi:http/proxy@0.2.8"
}
```

The immutable `RuntimeCatalogV1` record has exactly `schemaVersion:1`, `revision`, `catalogHash`, and `entries`, where `revision` is `u53` in `1..9007199254740991`. `entries` is UTF-8-bytewise sorted by unique `entryKey`, has at most 128 entries, and every entry has exactly `entryKey`, `kind`, `imageDigest`, `hostABI`, `world`, `architecture`, `status`, and optional `revocation`. `kind` is `wasm`; `imageDigest` is an architecture-specific OCI image-manifest digest, never an OCI index/list digest; `hostABI` is the exact v1 ABI literal; `world` is exactly `wasi:http/proxy@0.2.8`; `architecture` is exactly `linux/amd64` or `linux/arm64`; and `status` is `active` or `revoked`. One entry is selected by exact `(entryKey, architecture, imageDigest, hostABI, world)` equality; no fallback or range selection exists. Because `entryKey` is globally unique, a multi-architecture runtime uses distinct entry keys, one per architecture. The node capability record is the sole authority for measured reserve bytes. A `revocation` exists exactly when status is `revoked` and has exactly `cve`, `reasonCode`, and `revokedAt`; `cve` matches `CVE-YYYY-NNNN...`, `reasonCode` is a bounded opaque lower-case identifier, and `revokedAt` is `RFC3339-UTC`.

`catalogHash` equals `hex(SHA-256(UTF8("iweb-runtime-catalog-v1\n" || JCS(catalog with catalogHash omitted))))`. Its hash input includes `schemaVersion`, `revision`, the complete ordered `entries` array, and every entry's `entryKey`, runtime identity, architecture, status, and present revocation fields; it excludes only `catalogHash` itself. An acceptance record is deliberately not a catalog entry or catalog-hash input: the trusted Kernel release gate joins its independently self-digested record to the selected catalog revision. An owner supplies expected `(revision, catalogHash)` and a full next revision. Kernel validates `next.revision = current.revision + 1`, computes its hash, atomically appends it, and preserves old revisions for binding replay. Stale CAS, duplicate entry key, floating image, a binding not equal to the selected entry/revision/hash, or a supervisor-originated update fails closed.

An entry is protected while referenced by an active version, a ready/preparing candidate, or a retained rollback target. It SHALL NOT be deleted from a subsequent catalog revision. A rollback record has exactly `applicationId`, `fromVersionId`, `toVersionId`, `targetRuntimeBinding`, `routeGeneration`, `createdAt`, and `ownerCommandId`; therefore a rollback target includes binding identity rather than re-resolving a mutable catalog. To release an entry, the owner first stops/retires all candidates, removes all rollback retention for every version bound to it through an owner-authorized release operation, waits for drain/receipt acknowledgement, and records a `releasedAt` audit event. Only an entry with no protected reference may be removed; immutable version/rollback history retains the old binding and catalog revision for audit but cannot reactivate it after release.

For a CVE, the owner appends a new revision that marks the existing entry `revoked`; it does not delete it. Revocation immediately rejects new prepare, activation, rebind, and rollback using that binding. Kernel stops an active execution bound to a newly revoked entry and exposes generic unavailable unless a non-revoked, acceptance-gated replacement has already completed the normal readiness and route CAS. The owner path is: add/accept a replacement entry, prepare/rebind with a new P/E tuple, activate it, remove rollback retention for the revoked binding, then release/delete only after no protected reference remains.

#### Scenario: Catalog revision conflict
- **WHEN** two owner requests attempt to append catalog revision 9 from the same revision-8 hash
- **THEN** one append succeeds and the other fails with a catalog revision conflict; no binding is silently rebound

#### Scenario: Owner attempts to delete a rollback entry
- **WHEN** an entry is named by any retained rollback record
- **THEN** deletion fails with an owner-visible protected-reference reason and the historical binding remains replayable

#### Scenario: CVE revokes an active runtime entry
- **WHEN** the owner marks an active entry revoked
- **THEN** the node denies further activation through it and stops its active execution unless a normally activated non-revoked replacement already owns the route

### Requirement: Catalog history has fixed recovery and deletion records
Every accepted `RuntimeCatalogV1` revision SHALL be stored as the complete JCS `CatalogHistoryRecordV1` at the fixed Kernel-owned path `/data/kernel/runtime-catalog/revisions/<revision>-<catalogHash>.json`. The wrapper is exactly:

```text
{
  schemaVersion: 1,
  runtimeKind: "wasm",
  revision: u53,
  catalogHash: sha256-hex,
  catalog: RuntimeCatalogV1,
  storedAt: RFC3339-UTC,
  recordDigest: sha256-hex
}
```

`recordDigest = hex(SHA-256(UTF8("iweb-catalog-history-v1\n" || JCS(record with recordDigest omitted))))`. The filename revision/hash, wrapper, nested catalog revision/hash, and digest must agree. The current index is exactly `/data/kernel/runtime-catalog/catalog-history-index-v1.json` with object `{schemaVersion:1,runtimeKind:"wasm",currentRevision,currentHash,revisions,updatedAt,indexDigest}`; each `revisions[]` entry is exactly `{revision,catalogHash,path,status,protectedReferenceCount,releaseRetentionUntil,deletedAt}` where `status` is `present` or `deleted`, `releaseRetentionUntil`/`deletedAt` are `RFC3339-UTC|null`, sorted by revision, and `indexDigest` hashes the wrapper with the digest omitted. Kernel rebuilds the index from history files before accepting a route; an index/file disagreement fails closed rather than selecting a nearest revision.

An owner release produces exactly `/data/kernel/runtime-catalog/release-receipts/<releaseId>.json`:

```text
{
  schemaVersion: 1,
  runtimeKind: "wasm",
  releaseId: UUIDv7,
  entryKey: EntryKey,
  catalogRevision: u53,
  catalogHash: sha256-hex,
  targetRuntimeBinding: RuntimeBindingIdentityV1,
  ownerCommandId: UUIDv7,
  protectedReferenceCount: 0,
  drainedAt: RFC3339-UTC,
  releasedAt: RFC3339-UTC,
  releaseRetentionUntil: RFC3339-UTC,
  receiptDigest: sha256-hex
}
```

`protectedReferenceCount` must be zero only after active, ready/preparing, and rollback scans plus the drain receipt have completed. `releaseRetentionUntil` is at least `releasedAt + 31536000 seconds`; before it, the entry and all referenced history remain recoverable. Immutable retired-version proofs and rollback history retain the old binding for audit but do not by themselves block a release after the owner has explicitly removed rollback retention; a released binding cannot be reactivated. A history revision may be garbage-collected only when no active/ready/preparing/rollback route reference remains, its release receipt exists and has passed retention, and the owner has approved deletion. GC first writes `/data/kernel/runtime-catalog/delete-audit/<deleteId>.json`, exactly `{schemaVersion:1,runtimeKind:"wasm",deleteId:UUIDv7,revision,catalogHash,path,releaseId,ownerCommandId,deletedAt,reason,objectDigest}`, then atomically removes the revision file and marks the index entry `deleted` with its digest. A missing audit object, a protected reference, or an index recovery failure aborts GC and preserves the file.

Recovery scans fixed revision paths, verifies every `recordDigest`, reconstructs the index, and chooses only the highest non-deleted revision whose nested catalog hash and current pointer agree; it never falls back to a mutable catalog or image label. A released entry's immutable binding/proof history remains auditable through its version and rollback records even after the history blob is collected, but the released binding cannot be reactivated. CVE-revoked or active/rollback-referenced entries are never eligible for release deletion.

#### Scenario: Catalog history survives a restart
- **WHEN** the current index is missing or corrupt but revision files and their release receipts are intact
- **THEN** Kernel verifies and rebuilds the index from the fixed path, retains protected revisions, and does not open a gate until the current hash is proven

#### Scenario: GC races a new rollback reference
- **WHEN** GC sees zero references but a concurrent owner rollback CAS adds one before deletion
- **THEN** the deletion CAS fails, no file is removed, and the next index records the protected reference; a release receipt cannot be forged after the reference appears

### Requirement: Wasmd has a fixed command and host-mediated network contract
  The system SHALL execute wasm applications through a catalog-selected digest-pinned `iweb-wasmd` image. Supervisor alone generates every argv element, snapshot FD handoff, listen address, sandbox gateway address, resource limit, identity field, package digest, binding, and capability-record pin. An admission manifest carrying image, command, mount, host capability, socket, TLS, or arbitrary environment authority is rejected as `WASM_MANIFEST_EXECUTABLE_AUTHORITY`.

The runtime SHALL listen only at the exact address that the paired sandbox gateway ingress dials for this sandbox. A real dual-container readiness test is required before an image/catalog entry is acceptance-gated. `wasi:http/outgoing-handler` is the only component egress interface. Wasmd dials exactly its fixed sandbox gateway address; it does not resolve application destination DNS or dial an application destination directly. Gateway owns policy, DNS, reserved-address checks, redirect revalidation, and HTTP/HTTPS CONNECT to its already validated IP. Wasmd terminates origin TLS only on that gateway-validated connection and validates SNI/certificate there; visitor-facing TLS remains the front proxy's concern. Components never receive `wasi:sockets`, `wasi:tls`, or a filesystem capability. Wasmd and gateway MUST NOT log request bodies, authorization credentials, configuration values, or secret values.

Host limits come only from the pinned node capability record. It SHALL enforce inbound/outbound byte and header caps while streaming, concurrency, store/instance limits, guest linear-memory limit, epoch deadline, optional fuel, restart budget, and drain deadline. Absence or mismatch of a pin is failure closed; no environment variable may replace a record value.

#### Scenario: Component requests a denied network interface
- **WHEN** a component requires `wasi:sockets`, `wasi:tls`, or any non-matrix import at instantiation
- **THEN** admission or instantiation fails closed and no direct network path is granted

#### Scenario: Response exceeds its record cap
- **WHEN** a guest or upstream response exceeds `http.maxResponseBytes`
- **THEN** only that request fails with the application-attributed resource category; wasmd, Kernel, and neighboring sandboxes remain running

### Requirement: Wasm readiness is a full identity attestation
The system SHALL emit the wasm internal health payload only in the exact v2 shape below, as JCS, and only after wasmd loaded and verified the stated package bytes, binding, capability pin, secret snapshot revision/digest, config snapshot revision/digest, and live execution:

```text
{
  schemaVersion: 2,
  ok: true,
  sandboxId: SandboxId,
  versionId: VersionId,
  packageDigest: sha256-hex,
  runtimeBinding: RuntimeBindingIdentityV1,
  capabilityRecordRevision: u53,
  capabilityRecordHash: sha256-hex,
  secretRevision: u53,
  secretValuesDigest: sha256-hex,
  configRevision: u53,
  configSnapshotRef: sha256-hex|null,
  configValuesDigest: sha256-hex|null,
  preparationGeneration: u53 >= 1,
  executionGeneration: u53 >= 1
}
```

Gateway receives an expected full attestation from the supervisor command and obtains the raw v2 attestation from wasmd over the fixed sandbox-local ingress target; it MUST NOT synthesize v2 health from gateway configuration or a successful TCP dial. It may return health 200 only if that ingress dial succeeds and every field exactly matches. A query or payload mismatch in sandbox ID, version ID, package digest, binding including catalog revision/hash, capability revision/hash, secret revision/digest, config revision/reference/digest, preparation generation, execution generation, schema version, or unknown field is a 409 internal mismatch; malformed/missing fields are 503 not-ready. The probe grants a readiness lease only from an exact v2 200 and records the same full identity, secret/config revisions, values digests, and snapshot references, `leaseNonce`, and `expiresAt`. A v1 celld health payload is parsed only by the celld route and can never ready wasm.

#### Scenario: Matching listener has the wrong package digest
- **WHEN** gateway can dial a wasmd listener but its health payload names another package digest
- **THEN** gateway returns mismatch, Kernel creates no readiness lease, and activation cannot proceed

#### Scenario: Matching package has a stale catalog binding
- **WHEN** health names the right version and package but a different catalog revision, catalog hash, entry key, image digest, ABI, or world
- **THEN** gateway returns mismatch and the candidate must be stopped or re-prepared with the pinned binding

#### Scenario: Readiness lease expires during CAS
- **WHEN** the exact health attestation once produced a lease but the lease expires before the Kernel route CAS linearizes
- **THEN** the route remains on the previous active identity and a fresh preparation plus exact health attestation is required

### Requirement: Readiness leases use a nonce-bound canonical wire
The system SHALL represent every wasm readiness lease as `ReadinessLeaseV2`, not the existing celld `{versionId,expiresAt}` record. Its exact JCS object is:

```text
{
  schemaVersion: 2,
  leaseNonce: /^[a-f0-9]{32}$/,
  sandboxId: SandboxId,
  versionId: VersionId,
  packageDigest: sha256-hex,
  runtimeBinding: RuntimeBindingIdentityV1,
  capabilityRecordRevision: u53,
  capabilityRecordHash: sha256-hex,
  secretRevision: u53,
  secretValuesDigest: sha256-hex,
  configRevision: u53,
  configSnapshotRef: sha256-hex|null,
  configValuesDigest: sha256-hex|null,
  preparationGeneration: u53 >= 1,
  executionGeneration: u53 >= 1,
  issuedAt: RFC3339-UTC,
  expiresAt: RFC3339-UTC,
  leaseDigest: sha256-hex
}
```

`leaseNonce` is exactly 16 random bytes rendered as 32 lower-case hexadecimal characters; it is generated by Kernel for each successful v2 probe and is never derived from a timestamp or version ID. `secretValuesDigest` must equal the adopted `SnapshotRefV1.valuesDigest`; `configRevision:0` requires both `configSnapshotRef:null` and `configValuesDigest:null`, while a non-zero revision requires both non-null values and exact ref/digest equality. `expiresAt` must be later than `issuedAt` and no farther than the node capability `stagingTtlSeconds` from `issuedAt`. `leaseDigest = hex(SHA-256(UTF8("iweb-readiness-lease-v2\n" || JCS(record with leaseDigest omitted))))`. The persisted version candidate stores the complete lease bytes (or an exact content-addressed reference plus its digest), not merely `versionId` and `expiresAt`; a restart must either reload and validate this canonical record or mark the candidate not-ready.

The Kernel route CAS matches `expectedRouteGeneration`, `applicationId`, the complete wasm `versionId`/package/binding/capability/secret/config/P/E identity, and `leaseNonce` plus `leaseDigest`. At the CAS linearization instant it compares the monotonic clock to `expiresAt`; an equal or later instant rejects with `READINESS_LEASE_EXPIRED`. A successful CAS consumes the nonce by recording `consumedAt` in the Kernel route event; the same nonce cannot activate, rollback, or rebind twice. Query/replay of an activation command returns the original consumed/rejected result. A lease from celld health v1, a lease with a missing nonce, a duplicate nonce for another tuple, a config reference inconsistent with `configRevision`, or a payload whose query parameters disagree with the record is rejected as `READINESS_LEASE_MISMATCH`.

#### Scenario: Lease replay after a successful route CAS
- **WHEN** a client retries an activation request carrying a previously consumed `leaseNonce`
- **THEN** Kernel returns the original route-CAS result and does not increment route generation or activate a second version

#### Scenario: Lease record is lost on restart
- **WHEN** a candidate's old control row contains only `versionId` and `expiresAt`, without a valid v2 nonce/digest
- **THEN** Kernel treats it as celld-only/invalid for wasm, retains the current route, and requires a fresh v2 probe

### Requirement: Secrets rotate through one Kernel linearization point
The system SHALL make the Kernel secret store the authority for secret values and each application's monotonic `secretRevision`; supervisor journal stores only application ID, revision, opaque snapshot reference, and identity fence, never secret values. Revision `0` denotes an application with no secret assignment; every first assignment or rotation commits a strictly higher `u53` revision. A preparation snapshots its allowlisted values and revision at prepare start, passes only its opaque reference plus revision in `ExecutionCommand`, and health-attests the same revision. A candidate may read only its snapshot through `iweb:secrets/store`; unknown key returns `IWEB_SECRET_NOT_ASSIGNED`, no enumeration operation exists, and no package, URL, environment variable, audit event, or log contains a value.

The fixed linearization and lock order for one application is:

```text
1. Kernel acquires that application's mutation fence.
2. Kernel CAS-locks the secret-store revision row and writes next revision + invalidation outbox.
3. Secret-store COMMIT is the rotation linearization point.
4. Kernel releases the secret-store row lock, persists the supervisor invalidation command,
   then releases the application mutation fence; it never waits for supervisor while holding
   the secret-store row lock.
5. Supervisor journal fences/stops every non-active preparation below the committed revision;
   it re-prepares only at the greatest committed revision.
6. Kernel activation CAS requires candidate secretRevision equal to current secret-store
   revision and candidate preparationGeneration equal to the current preparation.
```

The active execution keeps its adopted snapshot until a later successful activation. A crash recovery preparation snapshots the current revision. For two rotations, the second waits for the first's outbox persistence, commits a larger revision, and the journal's invalidation reducer retains the maximum revision; an out-of-order old invalidation cannot lower it or revive a candidate.

| Crash point | Required recovery |
| --- | --- |
| before secret-store commit | no rotation occurred; existing candidate remains subject to normal activation CAS |
| after commit, before invalidation command | recovery scans committed outbox and appends the same revision fence before allowing activation |
| after command, before stop acknowledgement | activation CAS already rejects old revision; replay stops stale candidate idempotently |
| after stop, before fresh prepare | recovery prepares only at current greatest revision |
| after candidate health, before activation CAS | a newer committed revision rejects that candidate; it never activates |
| between consecutive rotations | recovery/reducer chooses only highest committed revision and converges to one candidate set |

#### Scenario: Rotation races a ready candidate
- **WHEN** a candidate with secret revision 7 is ready and Kernel commits revision 8 before the activation CAS
- **THEN** the CAS rejects revision 7, the journal stops it idempotently, and only a preparation snapshotting revision 8 may become active

#### Scenario: Two rotations arrive around supervisor restart
- **WHEN** revisions 8 and 9 commit while supervisor restarts and their journal messages arrive in either order
- **THEN** recovery retains revision 9 as the only accepted preparation target and never resurrects a revision-8 candidate

### Requirement: The iweb secrets host interface is fixed and allowlisted
The system SHALL expose exactly the v1 Component Model package `iweb:secrets@1.0.0`; its only declared host interface is `store`, and its complete WIT schema is:

```wit
package iweb:secrets@1.0.0;

interface store {
  type key = string;
  variant error {
    not-assigned,
    denied,
    snapshot-expired,
    revision-stale,
    internal,
  }
  get: func(key: key) -> result<string, error>;
}

world secrets {
  import store;
}
```

`key` is UTF-8, 1..128 bytes, lower-case ASCII grammar `^[a-z][a-z0-9._-]{0,127}$`; it cannot contain a slash, whitespace, colon, NUL, or a second encoding of the same byte sequence. `get` returns a `string` value of 0..65536 UTF-8 bytes; `string` is the final v1 owner decision, not a temporary choice. There is deliberately no `list`, enumeration, prefix query, write, delete, or error-detail payload. The WIT call error variant is the exact closed set `not-assigned | denied | snapshot-expired | revision-stale | internal`; its wire error is one of `IWEB_SECRET_NOT_ASSIGNED`, `IWEB_SECRET_DENIED`, `IWEB_SECRET_SNAPSHOT_EXPIRED`, `IWEB_SECRET_REVISION_STALE`, or `IWEB_SECRET_INTERNAL`, with no key or value echoed. The transport may additionally return `IWEB_SECRET_SNAPSHOT_FD_REQUIRED` before instantiation when the required raw-UDS descriptor is missing or duplicated.

For every admitted version, Kernel persists an allowlist record exactly `{schemaVersion:1,applicationId,versionId,secretRevision,keys}` where `keys` is a sorted, duplicate-free array of the above keys; an absent assignment is revision `0` with an empty array. Even revision `0` receives a canonical empty snapshot and non-null `secretSnapshotRef`, so the fixed secret fd slot remains present for every `prepare`/`start` command. A preparation receives an opaque `secretSnapshotRef` and the internal snapshot record exactly `{schemaVersion:1,applicationId,versionId,preparationGeneration,secretRevision,keys,values,valuesDigest,expiresAt}`. `SnapshotValuesPayloadV1` is exactly `{applicationId,versionId,preparationGeneration,secretRevision,keys,values}`; its `JCS` bytes are the only values payload placed in FD `3`. `valuesDigest = hex(SHA-256(UTF8("iweb-secret-snapshot-v1\n" || JCS(SnapshotValuesPayloadV1))))`; the `values` object is stored only in Kernel's secret store and is never present in the supervisor journal, package, URL, environment, health, metrics, or logs. The snapshot map contains exactly one string value per allowlisted key; a key outside the allowlist is `denied`, while a call against no-assignment revision `0` yields `IWEB_SECRET_NOT_ASSIGNED`.

Owner mutation is `PUT /v1/applications/<applicationId>/secret-allowlist` over the existing owner Bearer channel with exact JCS `{schemaVersion:1,expectedSecretRevision,keys,values}`; `keys.length` is `0..256`, each key is unique and sorted, `values` is an object whose key set is byte-for-byte equal to `keys` (no missing, extra, duplicate, or prototype-like key), and each value is a UTF-8 string of `0..65536` bytes. Kernel checks application ownership, key grammar, complete replacement semantics, and `expectedSecretRevision`, then commits the next revision under the rotation lock order above. The response is `{schemaVersion:1,applicationId,secretRevision,keys}` and never contains values. The WIT import is usable only when the version's declared imports, allowlist record, and snapshot all agree byte-for-byte on the key set and revision.

#### Scenario: A component tries to enumerate secrets
- **WHEN** a component requests an operation other than `store.get`, or supplies a malformed key
- **THEN** instantiation or call fails with `IWEB_SECRET_DENIED`/`IWEB_SECRET_INTERNAL`; no key names or values are disclosed

#### Scenario: Owner rotates with a stale revision
- **WHEN** an owner submits a replacement allowlist with `expectedSecretRevision` lower than the Kernel current revision
- **THEN** Kernel returns `SECRET_REVISION_CONFLICT`, writes no value, and emits no supervisor invalidation command

#### Scenario: Secrets world exports instead of importing
- **WHEN** a component or WIT world declares `export store` for `iweb:secrets@1.0.0`
- **THEN** component compilation/closure validation returns `IWEB_SECRET_WIT_DIRECTION_INVALID`, no host capability is granted, and no execution starts

### Requirement: Secret snapshot references have one Kernel-resolved, read-only FD
The system SHALL use `SnapshotRefV1` as the exact Kernel record for every `secretSnapshotRef`, including the canonical empty revision-0 snapshot:

```text
{
  schemaVersion: 1,
  kind: "iweb-secret-snapshot",
  ref: sha256-hex,
  applicationId: ApplicationId,
  versionId: VersionId,
  preparationGeneration: u53 >= 1,
  secretRevision: u53,
  valuesDigest: sha256-hex,
  expiresAt: RFC3339-UTC
}
```

`ref = hex(SHA-256(UTF8("iweb-secret-snapshot-ref-v1\n" || JCS(ref record with ref omitted))))`; the ref is the sole key of the one-to-one index entry at `/data/kernel/secrets/snapshot-index-v1/<ref>.json`, and that entry points only to `/data/kernel/secrets/snapshots/<ref>.json`. The target snapshot bytes are the exact internal `SnapshotRecordV1` above; its `valuesDigest` must equal the digest named by `SnapshotRefV1`, while its application/version/generation/revision/key set must equal the allowlist record and ref. A missing, duplicate, or differently addressed index entry is `IWEB_SECRET_SNAPSHOT_REF_INVALID`. The Kernel is the only component allowed to resolve a ref to a record; supervisor and wasmd treat `ref` as opaque and never accept a caller-supplied filesystem path.

The handoff mechanism is fixed to a **read-only `SCM_RIGHTS` file descriptor** because `docker-compose.sandbox.yml` mounts `/run/iweb-sandbox` read-only inside the Kernel container. Kernel writes the canonical snapshot atomically under `/data/kernel/secrets/snapshots/<ref>.json`, opens it `O_RDONLY|O_CLOEXEC`, and sends the descriptor on the independent `SnapshotFdTransportV1` raw socket. The exact payload is the `SecretSnapshotFdHandoffV1` defined by that transport:

```text
{
  schemaVersion: 1,
  kind: "secret",
  commandId: UUIDv7,
  commandDigest: sha256-hex,
  ref: sha256-hex,
  applicationId: ApplicationId,
  versionId: VersionId,
  preparationGeneration: u53 >= 1,
  secretRevision: u53,
  valuesDigest: sha256-hex,
  fdDigest: sha256-hex,
  expiresAt: RFC3339-UTC
}
```

`fdBytes` are the exact bytes read from the received descriptor and must equal the canonical `SnapshotValuesPayloadV1` JCS; the domain-separated `fdDigest` must equal both the indexed snapshot `valuesDigest` and `ExecutionCommand.secretValuesDigest`; the payload contains no value or path. The raw frame boundary, ancillary association, order, and Podman handoff are defined by `SnapshotFdTransportV1`; no frame is placed before or on the HTTP execution envelope. Supervisor validates `fstat` regular-file identity plus `fcntl(F_GETFL)` read-only flags, canonical bytes, ref/tuple/revision/expiry, command digest, and peer credentials before accepting the handoff. It passes descriptor `3` to wasmd only through the three-party contract and never passes it to a gateway or another process.

ACL is therefore explicit: Kernel UID `0` creates, resolves, opens, and deletes refs; supervisor UID `iweb-sandbox` may receive exactly one descriptor bound to an accepted `ExecutionCommand`; wasmd/application UID may read only pre-opened fd `3`. Any other UID, path, ref, generation, version, revision, descriptor number, or digest is denied. `expiresAt` is no later than the preparation lease and bounds the handoff window only: it is rechecked before fd handoff and before activation adoption; an execution that activated on its adopted snapshot keeps reading it through `store.get` for that execution's lifetime (until a later activation or re-preparation), and `IWEB_SECRET_SNAPSHOT_EXPIRED` applies only to handoffs and adoptions attempted after `expiresAt`. Supervisor crash closes fd `3` and no process may inherit it on restart; Kernel recovery either reuses the same unexpired ref for the same command and exact values digest or creates a higher preparation generation. A ref is never reused for another tuple.

| Snapshot interruption | Recovery and collection |
| --- | --- |
| before snapshot rename | no ref is usable; replay recreates the same ref or rejects the command without an fd |
| source durable, before supervisor command | query/replay verifies the ref and expiry; an abandoned unreferenced source is collected after its TTL |
| fd handoff created, before wasmd start | close the descriptor on supervisor restart; the source remains only while the command lease is valid |
| wasmd running, Kernel crashes | wasmd loses pre-opened fd `3` when supervisor stops it; Kernel route remains unchanged until attestation replay |
| rotation commits while old snapshot is active | old active fd remains valid; new preparations use the greater revision, and old ref becomes collectible only after drain/retired |

#### Scenario: A snapshot ref is pointed at another tuple
- **WHEN** a command supplies a valid-looking ref whose indexed record names another application, version, generation, or revision
- **THEN** supervisor refuses the fd handoff with `IWEB_SECRET_SNAPSHOT_REF_INVALID`; no wasmd process starts and no journal completion is accepted

#### Scenario: Snapshot expires during a crash recovery fd handoff
- **WHEN** the source exists but `expiresAt` is reached between ref validation and fd handoff
- **THEN** no fd is handed off, the command is rejected as `IWEB_SECRET_SNAPSHOT_EXPIRED`, and GC removes the unreferenced source after retention

### Requirement: The iweb config host interface is fixed and non-secret
The system SHALL expose exactly the v1 Component Model package `iweb:config@1.0.0`; its only declared host interface is `store`, and its complete WIT schema is:

```wit
package iweb:config@1.0.0;

interface store {
  type key = string;
  variant error {
    not-assigned,
    denied,
    snapshot-expired,
    revision-stale,
    internal,
  }
  get: func(key: key) -> result<string, error>;
}

world config {
  import store;
}
```

`key` is UTF-8, `1..128` bytes, and matches `^[a-z][a-z0-9._-]{0,127}$`; slash, whitespace, colon, NUL, non-normalized UTF-8, and case variants are rejected. `get` returns a UTF-8 `string` of `0..65536` bytes; `string` is the final v1 owner decision. The WIT call error set is exactly `IWEB_CONFIG_NOT_ASSIGNED`, `IWEB_CONFIG_DENIED`, `IWEB_CONFIG_SNAPSHOT_EXPIRED`, `IWEB_CONFIG_REVISION_STALE`, and `IWEB_CONFIG_INTERNAL`; the transport adds `IWEB_CONFIG_FD_REQUIRED` only for a missing/duplicate raw-UDS descriptor. No error includes a key or value. There is no list, prefix, write, delete, or enumeration operation. Unlike `iweb:secrets`, this interface is intended for non-secret configuration and MUST never be used to expose secret data.

For every version that imports `iweb:config/store`, Kernel persists an allowlist record exactly `{schemaVersion:1,applicationId,versionId,configRevision,keys}`; no import may run with a missing record. `configRevision:0` and `keys:[]` are the only no-assignment state, and a non-zero revision has `1..256` sorted unique keys. Owner mutation is `PUT /v1/applications/<applicationId>/config-allowlist` with exact JCS `{schemaVersion:1,expectedConfigRevision,keys,values}`. `values` is a string-valued object whose key set is exactly equal to `keys`, with `0..65536` UTF-8 bytes per value; unknown fields, missing values, extra values, duplicate keys, stale CAS, and `keys`/`values` set differences reject with `IWEB_CONFIG_WIRE_INVALID` or `CONFIG_REVISION_CONFLICT`.

The config snapshot record is exactly `{schemaVersion:1,applicationId,versionId,preparationGeneration,configRevision,keys,values,valuesDigest,expiresAt}` and uses `ConfigValuesPayloadV1 = {applicationId,versionId,preparationGeneration,configRevision,keys,values}` as its exact FD `4` payload. `valuesDigest = hex(SHA-256(UTF8("iweb-config-snapshot-v1\n" || JCS(ConfigValuesPayloadV1))))`. `ConfigSnapshotRefV1` is exactly `{schemaVersion:1,kind:"iweb-config-snapshot",ref,applicationId,versionId,preparationGeneration,configRevision,valuesDigest,expiresAt}` and uses the same ref formula with the config kind; its one-to-one index is `/data/kernel/config/snapshot-index-v1/<ref>.json` and its source file is `/data/kernel/config/snapshots/<ref>.json`. The exact raw payload is `ConfigSnapshotFdHandoffV1 = {schemaVersion:1,kind:"config",commandId,commandDigest,ref,applicationId,versionId,preparationGeneration,configRevision,valuesDigest,fdDigest,expiresAt}`; `fdDigest = hex(SHA-256(UTF8("iweb-config-snapshot-v1\n" || fdBytes)))` over the exact `JCS(ConfigValuesPayloadV1)` bytes and must equal both `valuesDigest` and `ExecutionCommand.configValuesDigest`. The opaque `configSnapshotRef` is the `ref` string and uses the independent fixed read-only `SCM_RIGHTS` fd handoff and ACL as secrets, but it is never included in the secret allowlist or secret digest. `ExecutionCommand`, its acknowledgement, readiness v2, and the activation lease echo `configRevision`, `configSnapshotRef`, and `configValuesDigest`; `configRevision:0` requires all three config fields to be `null`, and any mismatch is a stale execution fence.

Negative vectors are normative: `store.list`, `store.set`, an uppercase or slash key, an unknown WIT package/interface, a config ref with a secret snapshot kind, an expired ref, a missing allowlist key, an extra `values` key, a numeric/JSON-object value, a stale expected revision, and a config import absent from the declared closure all fail closed with the exact wire error above and never start or rebind the component.

The WIT direction vector is normative: a pinned Component Model compiler/parser must accept a component world that **imports** `iweb:config/store`, and a host implementation must satisfy that import. A world that exports `store`, a component that exports an implementation in place of the import, a package/interface/version outside `iweb:config@1.0.0`, or a host implementation whose type identity differs is `IWEB_CONFIG_WIT_DIRECTION_INVALID` and is rejected before OCI materialization. The same direction rule and vector apply to `iweb:secrets@1.0.0` with `IWEB_SECRET_WIT_DIRECTION_INVALID`.

#### Scenario: Config snapshot is absent for a declared import
- **WHEN** a component declares `iweb:config/store` but the version has no allowlist/snapshot or the ref is `null` at a non-zero revision
- **THEN** admission or preparation returns `IWEB_CONFIG_NOT_ASSIGNED`/`IWEB_CONFIG_WIRE_INVALID`, and no execution becomes ready

#### Scenario: Config and secrets are crossed
- **WHEN** a config command supplies a ref whose `kind` is `iweb-secret-snapshot`, or a secret command supplies a config ref
- **THEN** the Kernel and supervisor reject the command before fd handoff with `IWEB_CONFIG_WIRE_INVALID` or `IWEB_SECRET_SNAPSHOT_REF_INVALID`

#### Scenario: Config owner mutation races
- **WHEN** two owner replacements use the same `expectedConfigRevision`
- **THEN** exactly one revision commits; the other receives `CONFIG_REVISION_CONFLICT`, and no candidate using the losing snapshot can pass readiness

#### Scenario: Config world exports instead of importing
- **WHEN** a component or WIT world declares `export store` for `iweb:config@1.0.0`
- **THEN** component compilation/closure validation returns `IWEB_CONFIG_WIT_DIRECTION_INVALID`, no host capability is granted, and no execution starts

### Requirement: Lifecycle keeps one routed execution while allowing bounded drain
The Kernel lifecycle state machine for wasm remains `admitted -> preparing -> ready -> active -> retired`, with `failed` and `stopped` terminal until another owner/recovery command. `retiring` is a supervisor-only execution substate (`executionSubstate:"retiring"`) recorded in the wasm execution journal and never written into Kernel `LifecycleState`; Kernel writes the old version's ordinary lifecycle as `retired` only after the route CAS and its drain receipt. This deliberate boundary preserves the existing `packages/contracts/records.ts` validator and celld state vocabulary. Every activation uses the `application-sandbox` Kernel route-pointer CAS and exact readiness lease. On successful activation, the new tuple becomes the only identity that gateway accepts for **new** traffic. The previous tuple enters supervisor `retiring`; it may complete only requests that gateway recorded as admitted before the pointer flip, receives no new request, and is forcibly stopped at `drainDeadlineMs`. Health/metrics from the retiring tuple may be retained as historical diagnostics but MUST NOT be adopted as current active measurements.

If a ready candidate dies before Kernel CAS, its activation aborts and the prior active route remains. If an active execution dies or exceeds an engine limit, Kernel atomically changes the active route to unavailable, visitors receive only generic `application unavailable`, allocates a higher `preparationGeneration` for the bounded recovery preparation and then a higher `executionGeneration` for its spawn, and applies `restart.maxRestarts` within `restart.windowMs`. Exhaustion leaves the application stopped with owner-visible crash/resource category. A supervisor journal command completion followed by projection failure follows the authority/replay requirement and cannot create a half-active route.

#### Scenario: Active replacement leaves old execution alive
- **WHEN** the replacement tuple activates while the old execution still has in-flight work
- **THEN** gateway fences all new traffic to the new tuple, lets only pre-flip work drain on the old tuple until deadline, and force-stops it thereafter

#### Scenario: Active execution crashes
- **WHEN** the currently routed wasmd execution crashes
- **THEN** Kernel makes the route unavailable before recovery, increments required generation(s) for the next preparation/execution, and no stale old health or metrics can restore traffic

#### Scenario: Journal completion projection fails
- **WHEN** a prepare/start journal entry is durable but Kernel fails before its lifecycle projection or route CAS
- **THEN** replay produces one acknowledged command and Kernel either completes its own CAS or retains the old route; it never exposes two active routes or routes from journal state alone

### Requirement: Activation has a replayable Kernel control wire
The system SHALL expose activation as an owner-authorized Kernel operation over `POST /v1/wasm/activation-rpc` with the existing Bearer channel. Its raw body is JCS `ActivationRpcEnvelopeV1`:

```text
{
  protocol: "iweb-wasm-activation",
  requestId: UUIDv7,
  body: ActivationCommand | ActivationQueryV1 | ActivationReplayV1
}
```

`ActivationCommand` is exactly:

```text
{
  schemaVersion: 2,
  activationId: UUIDv7,
  applicationId: ApplicationId,
  operation: "activate"|"rollback",
  expectedRouteGeneration: u53,
  expectedControlRevision: u53,
  candidate: {
    runtimeKind: "wasm",
    sandboxId: SandboxId,
    versionId: VersionId,
    packageDigest: sha256-hex,
    runtimeBinding: RuntimeBindingIdentityV1 with hostABI "iweb-wasmd-abi@1.1.0",
    admissionProofRef: "admission-proof/" || applicationId || "/" || versionId,
    admissionProofDigest: sha256-hex,
    preparationGeneration: u53 >= 1,
    executionGeneration: u53 >= 1,
    secretRevision: u53,
    secretValuesDigest: sha256-hex,
    configRevision: u53,
    configSnapshotRef: sha256-hex|null,
    configValuesDigest: sha256-hex|null,
    leaseNonce: /^[a-f0-9]{32}$/,
    leaseDigest: sha256-hex
  },
  hostServicePolicyDigest: sha256-hex | "",
  requestedAt: RFC3339-UTC,
  commandDigest: sha256-hex
}
```

`candidate.runtimeBinding` is the service-enabled binding pinning `iweb-wasmd-abi@1.1.0`; `hostServicePolicyDigest` is the admitted policy `sha256-hex` pin or exactly the empty string for a policyless version; and `commandDigest` equals `digestV2("iweb-wasm-activation-v2", JCS(command with commandDigest omitted))`, so any overwritten field is exposed by recomputation.

The activation candidate requires `secretValuesDigest` to equal the secret snapshot ref digest. `configRevision:0` requires `configSnapshotRef:null` and `configValuesDigest:null`; a non-zero config revision requires exact non-null ref/digest equality with the readiness lease. These digest fields are part of the activation command bytes and therefore of query/replay conflict detection.

`ActivationQueryV1` is exactly `{kind:"query",activationId:UUIDv7}`. `ActivationReplayV1` is exactly `{kind:"replay",command:ActivationCommand}` and is accepted only when the command bytes are identical. A known `activationId` with a different command returns `ACTIVATION_ID_CONFLICT`; a completed command returns its stored response without another route CAS. The response is exactly `{protocol:"iweb-wasm-activation",requestId,body}` where `body` is `{kind:"result",activationId,status,event}`; `status` is `missing`, `received`, `activated`, or `rejected`, `event` is `null` only for `missing`/`received`, and an activated/rejected event is the canonical `RouteEvent` below.

`LeaseConsumeRecordV1` is exactly `{schemaVersion:1,leaseNonce,leaseDigest,activationId,applicationId,versionId,expectedRouteGeneration,consumedAt,outcome,routeGeneration}`. `outcome` is `consumed`, `already-consumed`, or `rejected`; `routeGeneration` is the new generation for `consumed`, and equals the current generation for the other outcomes. A successful consume is written in the same Kernel `controlRevision` CAS as the route pointer and route event; a nonce is never consumed by a failed or uncommitted attempt.

`RouteEvent` is exactly:

```text
{
  schemaVersion: 1,
  eventId: UUIDv7,
  activationId: UUIDv7,
  applicationId: ApplicationId,
  runtimeKind: "wasm",
  operation: "activate"|"rollback",
  expectedRouteGeneration: u53,
  previous: WasmActivePointerV1,
  next: WasmActivePointerV1,
  leaseConsume: LeaseConsumeRecordV1,
  result: "activated"|"rejected",
  reasonCode: null|/^[A-Z][A-Z0-9_]{0,63}$/,
  routeGeneration: u53,
  createdAt: RFC3339-UTC
}
```

For `result:"activated"`, `next` is the candidate, `reasonCode:null`, `leaseConsume.outcome:"consumed"`, and `routeGeneration = expectedRouteGeneration + 1`; the old pointer is `previous`. For `result:"rejected"`, `next` equals `previous`, the route generation is unchanged, and `reasonCode` is one of `ACTIVATION_ROUTE_CONFLICT`, `READINESS_LEASE_EXPIRED`, `READINESS_LEASE_MISMATCH`, `ACTIVATION_CANDIDATE_NOT_READY`, or `ACTIVATION_BINDING_REVOKED`. `ACTIVATION_ID_CONFLICT` is an envelope-level replay error and never creates a route event. Kernel checks the monotonic clock, active pointer, full candidate identity/config binding, secret/config values digests, and lease nonce/digest at the single CAS linearization point. The route event is the only record that permits the old version to enter drain; a consumed lease alone never changes lifecycle.

Recovery is deterministic: a `received` command with no event replays the same CAS; an event with `activated` and a lost response returns the same event; an event with `rejected` never retries under a changed candidate; and a control revision that contains a route pointer but lacks its event is repaired by writing the exact event from the pointer CAS before any new activation is accepted. Query/replay never increments route generation twice and never treats a supervisor journal entry as a route event.

#### Scenario: Activation response is lost after the route CAS
- **WHEN** the Kernel commits the route pointer, lease consume, and `RouteEvent` but the client loses the response
- **THEN** `ActivationQueryV1` or byte-identical replay returns the original activated event, with no second nonce consume or route-generation increment

#### Scenario: Lease consume is present without a committed route
- **WHEN** recovery observes an uncommitted/partial consume marker but no matching route event and pointer CAS
- **THEN** it discards the partial marker, leaves the lease unconsumed, and replays the command under the original `expectedRouteGeneration`; it never activates from the marker alone

### Requirement: Drain completion is a typed receipt before Kernel retirement
Every `ExecutionCommand` with `operation:"drain"` MUST produce one successful `DrainReceiptV1` or a rejected acknowledgement. `DrainReceiptV1` is exactly:

```text
{
  schemaVersion: 1,
  commandId: UUIDv7,
  applicationId: ApplicationId,
  execution: WasmExecutionIdentityV1,
  packageDigest: sha256-hex,
  runtimeBinding: RuntimeBindingIdentityV1,
  routeGeneration: u53,
  drainedRequestCount: u53,
  deadlineAt: RFC3339-UTC,
  forcedKillAt: RFC3339-UTC|null,
  result: "drained"|"forced-kill",
  completedAt: RFC3339-UTC,
  journalRevision: u53,
  receiptDigest: sha256-hex
}
```

`receiptDigest = hex(SHA-256(UTF8("iweb-drain-receipt-v1\n" || JCS(receipt with receiptDigest omitted))))`. `execution` is the complete sandbox/version/preparation/execution tuple, not merely a version ID. `routeGeneration` is the retired route generation captured before the activation pointer flip. `drainedRequestCount` counts requests admitted before that route CAS and is non-negative. `deadlineAt` is the exact drain deadline supplied by the Kernel capability record. `forcedKillAt` is non-null if and only if `result:"forced-kill"`, is at or after `deadlineAt`, and is the timestamp at which supervisor sent the kill; a normal `drained` result has `forcedKillAt:null`. The receipt is written by supervisor in the journal and projected by Kernel only after peer, command digest, route generation, and full execution identity checks.

Kernel MUST NOT write the old version's Kernel lifecycle as `retired`, release its catalog retention, or delete its snapshot until the matching receipt is durable and its projection CAS succeeds. Before that point the execution remains supervisor-only `executionSubstate:"retiring"`; it receives no new traffic but is still recoverable. Query/replay of a completed drain returns the same receipt and never counts or kills twice. A missing receipt, mismatched identity, deadline before route flip, negative/non-integer count, or `forcedKillAt` inconsistency is `DRAIN_RECEIPT_INVALID` and leaves the old lifecycle unchanged.

#### Scenario: Drain finishes before its deadline
- **WHEN** the old execution reports all pre-flip requests drained at `deadlineAt` or earlier
- **THEN** supervisor writes one `drained` receipt with the exact execution tuple and Kernel projects `retired` only after that receipt CAS

#### Scenario: Drain deadline forces a kill
- **WHEN** in-flight work remains at `deadlineAt`
- **THEN** supervisor records the non-zero or zero `drainedRequestCount`, sends the kill, writes `forced-kill` with `forcedKillAt >= deadlineAt`, and Kernel retires only after validating that receipt

#### Scenario: Old execution sends a stale receipt
- **WHEN** a receipt names an execution generation or binding lower/different than the one recorded for the retiring route
- **THEN** Kernel returns `DRAIN_RECEIPT_STALE`, does not write `retired`, and keeps the route fenced until the correct receipt or owner recovery decision arrives

### Requirement: Wasm engine metrics use a complete availability wire contract
The supervisor-to-Kernel wasm metrics payload has exactly these top-level fields: `schemaVersion`, `sandboxId`, `versionId`, `packageDigest`, `runtimeBinding`, `capabilityRecordRevision`, `capabilityRecordHash`, `secretRevision`, `configRevision`, `configSnapshotRef`, `preparationGeneration`, `executionGeneration`, `sampledAt`, `availability`, and `engine`. `schemaVersion` is literal `1`; identity/binding fields use the types above; `secretRevision` and `configRevision`/reference are the exact snapshots adopted by that execution; `sampledAt` is `RFC3339-UTC`; `availability` is exactly `available` or `unavailable`; no field is omitted. `configRevision:0` requires `configSnapshotRef:null`.

When `availability:"available"`, `engine` is exactly:

```text
{
  fuelConsumedCumulative: u53 | null,
  epochTimeoutsCumulative: u53,
  instancesLiveInstant: u53,
  instancesHighWaterCumulative: u53,
  guestMemoryBytesInstant: u53
}
```

`fuelConsumedCumulative:null` means fuel is disabled by the pinned node record and is the only representation of disabled fuel. It MUST remain null for that execution generation. All other values are non-negative integers; `engine` is `null` if and only if `availability:"unavailable"`. `unavailable` is the sole representation before the first real sample after process start/restart or when the measurement cannot be proven. Zero is valid only in an `available` sample with a proven zero. `engine` and each child must never be absent.

Kernel accepts any metrics payload only if every identity, package digest, binding, capability pin, `secretRevision`, `configRevision`/reference, and P/E pair exactly equals its current execution record. For each execution generation, the first available sample establishes the baseline. Later accepted samples need strictly later `sampledAt`; `fuelConsumedCumulative` when enabled, `epochTimeoutsCumulative`, and `instancesHighWaterCumulative` must be greater than or equal to their prior accepted values. Instantaneous live instances and guest memory may change either direction. A new execution generation may establish a fresh baseline only after Kernel has accepted its new generation fence; a delayed prior-generation payload is stale, not a reset. Unknown field, wrong schema, non-null fuel when disabled, null fuel when enabled, time regression, or counter regression is rejected.

#### Scenario: Restart has no first sample yet
- **WHEN** a new execution generation has started but has not emitted a verified engine measurement
- **THEN** Kernel projects `availability:"unavailable", engine:null` rather than zeroing counters or memory

#### Scenario: Old metrics arrive after restart
- **WHEN** a metrics payload from execution generation 4 arrives after Kernel accepted generation 5
- **THEN** Kernel rejects it as stale and it cannot alter generation-5 counters or availability

#### Scenario: Fuel is disabled
- **WHEN** the pinned node capability record sets `fuelPerRequest` to `null`
- **THEN** every available sample carries `fuelConsumedCumulative:null`; omission or a numeric value is rejected

### Requirement: Wasm publication requires a canonical kind-bound acceptance record
The system SHALL require an acceptance record v2 from the immutable trusted Kernel release at the fixed Kernel-owned path `/opt/iweb/release/wasm-sandbox-acceptance.json` before wasm publication can open. The record attests the selected digest-pinned wasmd image; it MUST NOT be read from an application package, a wasmd image/mount, a runtime-provided path, or an environment-selected alternate path. The raw record is JCS and has exactly:

```text
{
  version: 2,
  result: "passed",
  gate: "application-sandbox",
  runtimeKind: "wasm",
  runtimeImageDigest: "sha256:<64 lower hex>",
  hostABI: "iweb-wasmd-abi@1.0.0",
  world: "wasi:http/proxy@0.2.8",
  arch: "linux/amd64" | "linux/arm64",
  capabilityRecordRevision: u53 >= 1,
  capabilityRecordHash: "<64 lower hex>",
  catalogRevision: u53 >= 1,
  catalogHash: "<64 lower hex>",
  catalogEntryKey: /^[a-z][a-z0-9.-]{0,63}$/,
  evidenceDigest: "<64 lower hex>",
  recordDigest: "<64 lower hex>"
}
```

`recordDigest` is `hex(SHA-256(UTF8("iweb-wasm-acceptance-record-v2\n" || JCS(record with recordDigest omitted))))`; the supplied field must equal it. No unknown field, missing field, alternate digest prefix, upper-case hash, version 1 record, or non-JCS form is valid. The gate has two independent fixed record paths and switches: celld v1 reads `/opt/iweb/release/sandbox-acceptance.json` and requires only `IWEB_APPLICATION_PUBLICATION_ENABLED=1`; wasm v2 reads `/opt/iweb/release/wasm-sandbox-acceptance.json` and requires only `IWEB_WASM_PUBLICATION_ENABLED=1` plus the application switch. Each path is parsed only by its own kind validator. A valid celld v1 record cannot enable wasm; a valid wasm v2 record cannot enable celld; an unknown/missing kind never falls through. The wasm gate requires the canonical record digest and exact equality with the selected catalog entry/binding, current node architecture, current capability record revision/hash, current catalog revision/hash, world, ABI, and image digest. It MUST read only the fixed path for the selected kind; no environment variable may redirect either path. The records are outside the wasmd image and catalog hash input, so neither an image self-digest nor a catalog-record hash cycle is accepted.

#### Scenario: Canonical record has an unknown field
- **WHEN** an otherwise passed wasm acceptance record contains an extra field or a digest computed over a different field set
- **THEN** the gate rejects it before checking enablement and wasm publication remains closed

#### Scenario: Acceptance record does not match current node identity
- **WHEN** record catalog/capability revision or hash, architecture, entry key, image digest, ABI, or world differs from the selected node binding
- **THEN** wasm publication fails closed until a matching fixed-image v2 record exists

#### Scenario: Celld-era record is the only record
- **WHEN** the node has only a valid v1 application-sandbox acceptance record
- **THEN** celld follows its existing gate and wasm publication remains disabled

### Requirement: Runtime-kind publication gate selection is a dual-gate wire
At Kernel startup the release gate SHALL evaluate both runtime kinds independently and return one canonical `PublicationGateSetV1`:

```text
{
  schemaVersion: 1,
  celld: GateResultV1,
  wasm: GateResultV1
}

GateResultV1 = {
  schemaVersion: 1,
  runtimeKind: "celld"|"wasm",
  enabled: boolean,
  requested: boolean,
  accepted: boolean,
  reasons: [
    "publication-not-requested"|
    "sandbox-acceptance-missing"|
    "wasm-acceptance-invalid"|
    "wasm-identity-mismatch"|
    "runtime-kind-mismatch"|
    "capability-record-mismatch"|
    "catalog-mismatch"|
    "unsupported-architecture"
  ]
}
```

`reasons` is duplicate-free and in the listed stable order; a successful gate has an empty array. The runtime-kind selection entry is exactly `selectPublicationGate(runtimeKind, PublicationGateSetV1)`: `"celld"` returns the result of the existing `evaluateApplicationPublicationGate` contract (the single `/opt/iweb/release/sandbox-acceptance.json` path and `IWEB_APPLICATION_PUBLICATION_ENABLED` switch), `"wasm"` returns the v2 validator above (the fixed wasm path and `IWEB_WASM_PUBLICATION_ENABLED` switch), and any other value returns the typed `RUNTIME_KIND_UNSUPPORTED` selection error without trying either parser. The selected Kernel business record supplies `runtimeKind`; a request body, catalog entry, or supervisor message cannot override it.

The v2 gate is connected at startup in this order: (1) call the existing celld gate and preserve its `enabled/requested/accepted/reasons` semantics; (2) read and validate the fixed wasm acceptance record independently; (3) publish the immutable `PublicationGateSetV1` to the Kernel runtime selector; (4) at every publication request, select exactly one result by the Kernel record's runtime kind and require `enabled`; (5) pass the selected kind, catalog/capability pins, and record digest into the normal admission and execution fence. A malformed celld record does not make a valid wasm gate appear, and a valid v1 celld record never opens wasm. The current `kernel/application-publication-gate.js` remains the celld adapter; wasm wiring is an additional kind-specific adapter, not a new interpretation of its file or switch. There is no environment-controlled path, boolean fallback, or “try the other gate” behavior.

The gate selection response at the Kernel internal entry is exactly `{schemaVersion:1,runtimeKind,enabled,reasons}`; public publication rejection may expose only the stable reason codes and never acceptance evidence or host paths. Both gates are evaluated on every process start, so replacing an acceptance file or switch requires a restart/reconciliation before a route can open.

#### Scenario: Both runtime gates are present at startup
- **WHEN** celld v1 and wasm v2 records and their independent switches are valid and enabled
- **THEN** `PublicationGateSetV1` reports both enabled, and a celld record selects only celld while a wasm record selects only wasm

#### Scenario: The old single gate is asked to publish wasm
- **WHEN** the existing `evaluateApplicationPublicationGate` result is passed to a wasm record or only `IWEB_APPLICATION_PUBLICATION_ENABLED=1` is set
- **THEN** selection returns `wasm-acceptance-invalid`/`runtime-kind-mismatch`, and wasm publication remains closed without invoking the celld parser as a fallback

#### Scenario: Gate reasons are returned after an identity mismatch
- **WHEN** a fixed wasm acceptance record has a valid self-digest but its catalog revision, capability hash, architecture, or image digest differs from the selected binding
- **THEN** `GateResultV1.enabled` is false and the exact `wasm-identity-mismatch`/`catalog-mismatch`/`capability-record-mismatch` reason codes are returned; no runtime starts
