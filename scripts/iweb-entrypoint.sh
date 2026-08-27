#!/bin/sh
# 用户原始需求（2026-08-11，2026-08-15 更新）：一个容器协调 RustFS/RustFS 迁移期 MinIO、celld 与 Rust Kernel（自有发布入口，Caddy 已废除）。
# 不可调和的原因：三个守护进程需要共同生命周期；此入口负责启动顺序与首次存储初始化。
set -eu

: "${CELLD_NODE:?CELLD_NODE must identify this iweb installation}"
: "${IWEB_BASE_HOST:?IWEB_BASE_HOST must identify the public hostname suffix}"
: "${IWEB_API_TOKEN:?IWEB_API_TOKEN must protect the kernel API}"

# rust-kernel-rustfs-storage：容器内一切服务都是回环互访（MinIO/celld/Kernel），
# 宿主会话的代理环境经 podman --http-proxy 默认注入，会把 127.0.0.1 的 S3 请求
# 劫持到不可达的外部代理（celld object_store 与 curl 均受害）。入口处统一剥除。
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY || true

data_root=/data
# 存量节点数据目录名保留 minio（升级不迁移数据布局，§8 回滚兼容）。
minio_data="${data_root}/minio"
celld_state="${data_root}/celld"
kernel_state="${data_root}/kernel"
celld_runtime_version="v0.3.0"
# 每个 celld 应用一个独立运行时标记：谁部署过哪个运行时格式，逐应用可复现
celld_runtime_marker() { printf '%s/runtime-version-%s' "${celld_state}" "$1"; }
run_dir="${data_root}/run"
mkdir -p "${run_dir}"
minio_pid=""
celld_pids=""
kernel_pid=""

cleanup() {
  for pid in ${kernel_pid} ${celld_pids} ${minio_pid}; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
  done
  rm -f "${run_dir}"/celld-*.pid
}

trap cleanup EXIT INT TERM

mkdir -p "${minio_data}" "${celld_state}" "${kernel_state}"
# add-wasm-host-services（部署批次）：wasm 宿主服务数据面根。kernel-rs wasm_host_services
# 契约「部署层保证 wasm-data 根存在」——本入口首启创建（对照 /data 各子目录惯例；镜像层
# mkdir 会被运行时卷遮蔽，故不进 Dockerfile）。0711：root 全权、其余仅穿越——supervisor
# 以服务用户逐应用 bind-mount per-app 目录；per-app 0700 目录与 0600 SQLite/ledger 文件由
# Kernel preparation 创建，本入口绝不预建应用目录或空 SQLite 文件（缺组即 unavailable，
# 绝不静默空替，design「Decisions 3」）。
wasm_data_root="${kernel_state}/wasm-data"
mkdir -p "${wasm_data_root}"
chmod 0711 "${wasm_data_root}"
# rust-kernel-rustfs-storage §5.3：celld→Kernel 控制调用走回环控制监听器，
# 不再穿越发布入口，X-Iweb-Internal-Control 头路由已废除。
# Codex R2 阻塞项 2：控制面强制只走容器内回环控制监听器。任何非默认
# IWEB_CONTROL_ORIGIN（含任意回环端口变体）都是部署错误——fail-closed 拒绝启动，
# 且不回显其值（避免配置细节泄露与误导）。外部 celld 拓扑若将来需要，走新 spec。
if [ -n "${IWEB_CONTROL_ORIGIN:-}" ] && [ "${IWEB_CONTROL_ORIGIN}" != "http://127.0.0.1:7070" ]; then
  echo "iweb-entrypoint: refusing non-default IWEB_CONTROL_ORIGIN (control plane stays on the in-container loopback control listener)" >&2
  exit 1
fi
kernel_origin="http://127.0.0.1:7070"

# add-wasm-runtime（镜像批次）：wasm 宿主二进制随镜像静态存在（镜像完整性检查，
# 缺失即拒绝启动）；但本入口绝不启动 wasmd 或任何 wasm 应用。发布门 fail-closed
# 默认关：只有 Kernel 在固定路径 /opt/iweb/release/wasm-sandbox-acceptance.json 读到
# 合法验收记录（service-free V1 用 v2 记录；service-enabled V2 用 v3 记录，且
# IWEB_WASM_PUBLICATION_ENABLED=1（叠加现行应用开关）时才可能开；
# supervisor 侧执行通道另有 IWEB_SANDBOX_WASM_EXECUTION_ENABLED=1 显式 opt-in。
# catalog 初始 revision 与 node capability record 是 owner 实测数据（live 路径在
# /data/kernel/runtime-catalog/），镜像只携带 /opt/iweb/wasm/templates/ 填写模板：
# reserve 等数值留 null 占位，直接当 live 记录用必然校验失败——缺失值不推默认。
wasm_runtime_bin="/opt/iweb/wasmd/iweb-wasmd"
if [ ! -x "${wasm_runtime_bin}" ]; then
  echo "iweb-entrypoint: wasm runtime binary missing at ${wasm_runtime_bin} (image build defect)" >&2
  exit 1
fi
echo "iweb-entrypoint: wasm runtime present (${wasm_runtime_bin}); wasm publication stays closed without IWEB_WASM_PUBLICATION_ENABLED=1 and a valid acceptance record (v2 service-free / v3 service-enabled)"

# §6：RustFS 替换 MinIO——同端口回环 9000，凭据/桶/策略语义经 G1–G6 验证兼容。
export RUSTFS_ROOT_USER="${MINIO_ROOT_USER}" RUSTFS_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD}"
# 决策 3（owner 裁决 2026-08-20）：稳态预算 160MB 的一部分。beta.12 默认 buffer
# profile 在 celld 租约周期写下匿名内存无界增长；A/B 实测 IndustrialIoT 平坦在
# 136–140MB（WebWorkload 140–146，默认 149→167 攀升）。无条件钉死（Codex R1 阻塞项 6：
# 可覆盖的"钉死"不构成预算保证）；复测其它 profile 需改此行重建镜像。
export RUSTFS_BUFFER_PROFILE=IndustrialIoT
# console 不启用：管理走 mc/Kernel API；实测省 ~7MB RssAnon（预算线内必需）。
rustfs server "${minio_data}" --address 127.0.0.1:9000 &
minio_pid="$!"

attempt=0
until mc alias set local http://127.0.0.1:9000 "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 30 ]; then
    echo "RustFS did not become ready" >&2
    exit 1
  fi
  sleep 1
done

# 用户设计（2026-08-15）：每个应用一个独立的 celld fleet 桶。admin/mcp 是普通 celld
# 应用；notes 保持独立部署作为沙箱迁移前的 image-seeded 回滚权威。共享
# Dispatcher（iweb-cells）不再运行；旧桶保留为历史数据，任何进程不再挂载它。
mc mb --ignore-existing local/iweb-cells-admin
mc mb --ignore-existing local/iweb-cells-mcp
mc mb --ignore-existing local/iweb-cells-notes
# 实战演示站（2026-08-22 owner 实用性测试）：与 admin/mcp/notes 同级的受信
# image-seeded 过渡舰队——hello 纯静态、search D1、collab 前后端分离+DO（双实例共享桶）。
mc mb --ignore-existing local/iweb-cells-hello
mc mb --ignore-existing local/iweb-cells-search
mc mb --ignore-existing local/iweb-cells-collab
mc mb --ignore-existing local/iweb-system
# Per-application persistent data namespace (iweb-apps/<app>/data/); served only
# through the sandbox gateway data proxy with capability verification.
mc mb --ignore-existing local/iweb-apps
mc mb --ignore-existing local/iweb-workspace
# The workspace is private. Public root objects are served only through the
# Kernel public-object gateway whitelist (IWEB_PUBLIC_OBJECTS); Caddy no
# longer proxies arbitrary workspace objects and anonymous download is off.
mc anonymous set none local/iweb-workspace
mc admin user add local "${CELLD_S3_ACCESS_KEY}" "${CELLD_S3_SECRET_KEY}" || true
mc admin policy create local iweb-celld /etc/iweb/celld-policy.json || true
mc admin policy attach local iweb-celld --user "${CELLD_S3_ACCESS_KEY}"
# The pre-provisioned issuer parent: service accounts are generated under it
# with mc's own key generation (--json), so credentials never enter argv. Its
# password comes from /dev/urandom at install and is never used again. MinIO
# service-account policies only NARROW the parent's privileges, so the parent
# carries the base across version/data buckets; each issued credential is
# still scoped to exactly one bucket by its inline policy document.
mc admin user add local iweb-sandbox-issuer "$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')" || true
mc admin policy create local iweb-sandbox-issuer-base /etc/iweb/issuer-base-policy.json || true
mc admin policy attach local iweb-sandbox-issuer-base --user iweb-sandbox-issuer || true
# Per-version read-only object policies are issued by Kernel at prepare time
# (mc admin policy create iweb-sbx-<sandboxId>), scoped to exactly one version
# bucket; there is no shared wildcard policy over iweb-app-*.

if ! mc stat local/iweb-workspace/index.html >/dev/null 2>&1; then
  mc cp /opt/iweb/public/index.html local/iweb-workspace/index.html
fi

if ! mc stat local/iweb-system/routes.json >/dev/null 2>&1; then
  mc cp /opt/iweb/kernel/routes.seed.json local/iweb-system/routes.json
fi
mc cp local/iweb-system/routes.json "${kernel_state}/routes.json"

# typescript-monorepo：workspace 不再种子应用清单或代码镜像——应用身份唯一权威
# 是路由注册表；workspace 是 owner 的普通文件区（历史 volume 中的旧种子对象
# 退化为普通文件，无投影语义，不主动清理）。

# 用户设计（2026-08-15）：每个应用一个普通的 celld 部署（独立项目/桶/进程/身份）。
# deploy_celld <app> <project>：运行时格式变更或缺失指针时重新发布该项目。
deploy_celld() {
  app="$1"
  project="$2"
  marker="$(celld_runtime_marker "${app}")"
  bucket="iweb-cells-${app}"
  if [ "${IWEB_DEPLOY_ON_START:-0}" = "1" ] || ! mc stat "local/${bucket}/deploy/current.json" >/dev/null 2>&1 || [ ! -f "${marker}" ] || [ "$(cat "${marker}")" != "${celld_runtime_version}" ]; then
    AWS_ACCESS_KEY_ID="${CELLD_S3_ACCESS_KEY}" \
    AWS_SECRET_ACCESS_KEY="${CELLD_S3_SECRET_KEY}" \
    celld deploy "${project}" \
      --bucket "s3://${bucket}" \
      --endpoint http://127.0.0.1:9000 \
      --region us-east-1
    printf '%s\n' "${celld_runtime_version}" > "${marker}"
  fi
}

# run_celld <app> <public_port> <internal_port>：启动该应用的独立 celld 进程并写 pidfile。
run_celld() {
  app="$1"
  public_port="$2"
  internal_port="$3"
  bucket="${4:-iweb-cells-${app}}"
  CELLD_NODE="${CELLD_NODE}-${app}" \
  CELLD_WATCH="${celld_state}/${app}" \
  CELLD_VAR_IWEB_BASE_HOST="${IWEB_BASE_HOST}" \
  CELLD_VAR_IWEB_KERNEL_ORIGIN="${kernel_origin}" \
  AWS_ACCESS_KEY_ID="${CELLD_S3_ACCESS_KEY}" \
  AWS_SECRET_ACCESS_KEY="${CELLD_S3_SECRET_KEY}" \
  celld \
    --bucket "s3://${bucket}" \
    --endpoint http://127.0.0.1:9000 \
    --region us-east-1 \
    --listen "127.0.0.1:${public_port}" \
    --internal-listen "127.0.0.1:${internal_port}" \
    --advertise "127.0.0.1:${internal_port}" &
  pid="$!"
  celld_pids="${celld_pids} ${pid}"
  printf '%s\n' "${pid}" > "${run_dir}/celld-${app}.pid"
}

wait_celld() {
  port="$1"
  name="$2"
  attempt=0
  until curl --silent "http://127.0.0.1:${port}/" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 30 ]; then
      echo "celld ${name} did not become ready" >&2
      exit 1
    fi
    sleep 1
  done
}

deploy_celld admin /opt/iweb/apps/workers/admin
deploy_celld mcp /opt/iweb/apps/workers/mcp
deploy_celld notes /opt/iweb/apps/workers/notes
deploy_celld hello /opt/iweb/apps/workers/hello
deploy_celld search /opt/iweb/apps/workers/search
deploy_celld collab /opt/iweb/apps/workers/collab

run_celld admin 8787 8788
run_celld mcp 8797 8798
run_celld hello 8817 8818
run_celld search 8827 8828
run_celld collab 8837 8838
# collab 第二实例：同一部署桶（共享 Durable Object 命名空间）——跨实例一致性由 DO 保证。
run_celld collab-b 8847 8848 iweb-cells-collab
# notes：独立部署已就绪，但沙箱迁移前 Kernel 不向它路由流量；默认不常驻进程
# （回滚/迁移需要时以 IWEB_RUN_NOTES_CELLD=1 启动）。
if [ "${IWEB_RUN_NOTES_CELLD:-0}" = "1" ]; then
  run_celld notes 8807 8808
fi

wait_celld 8787 admin
wait_celld 8797 mcp
wait_celld 8817 hello
wait_celld 8827 search
wait_celld 8837 collab
wait_celld 8847 collab-b

# search 的 D1 数据库：迁移需要运行中的 fleet（租约存在）；幂等可重复执行。
AWS_ACCESS_KEY_ID="${CELLD_S3_ACCESS_KEY}" \
AWS_SECRET_ACCESS_KEY="${CELLD_S3_SECRET_KEY}" \
celld d1 migrations apply search /opt/iweb/apps/workers/search \
  --bucket "s3://iweb-cells-search" \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1

attempt=0
# The iweb Worker intentionally returns 404 without an application Host header.
# A successful HTTP exchange is enough to prove celld is accepting requests.
until curl --silent http://127.0.0.1:8787/ >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 30 ]; then
    echo "celld did not become ready" >&2
    exit 1
  fi
  sleep 1
done

IWEB_BASE_HOST="${IWEB_BASE_HOST}" \
IWEB_API_TOKEN="${IWEB_API_TOKEN}" \
# 容器内发布端口恒为 8080（Docker 映射负责宿主端口）；IWEB_HTTP_PORT 描述宿主侧。
IWEB_HTTP_PORT=8080 \
IWEB_ROUTES_FILE="${kernel_state}/routes.json" \
IWEB_WORKSPACE_OBJECT="local/iweb-workspace" \
IWEB_RECOVERY_WORKER="/opt/iweb/apps/workers/admin" \
IWEB_ADMIN_CELLD_BUCKET="s3://iweb-cells-admin" \
IWEB_CELLD_ENDPOINT="http://127.0.0.1:9000" \
IWEB_CELLD_REGION="us-east-1" \
IWEB_CELLD_PORTS='{"admin":8787,"mcp":8797,"notes":8807,"hello":8817,"search":8827,"collab":8837,"collab-b":8847}' \
IWEB_CELLD_PIDS_DIR="${run_dir}" \
AWS_ACCESS_KEY_ID="${CELLD_S3_ACCESS_KEY}" \
AWS_SECRET_ACCESS_KEY="${CELLD_S3_SECRET_KEY}" \
iweb-kernel &
kernel_pid="$!"

attempt=0
until curl --silent --fail http://127.0.0.1:7070/health >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 30 ]; then
    echo "iweb kernel API did not become ready" >&2
    exit 1
  fi
  sleep 1
done

# rust-kernel-rustfs-storage §5.2：Kernel 直接拥有发布端口（废 Caddy）。
# 入口探针 = Kernel /_iweb/health；回环控制面仍以 /health 就绪。
wait "${kernel_pid}"
