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
supervisor_pid=""

cleanup() {
  for pid in ${kernel_pid} ${supervisor_pid} ${celld_pids} ${minio_pid}; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
  done
  rm -f "${run_dir}"/celld-*.pid
  # R2 9.8：supervisor 的子进程（relay/wasmd）在 SIGKILL 场景会孤儿化——停机时一并
  # 信号（尽力而为，不等待）；崩溃残留由下一世代启动前的 reclaim 兜底。防御极早期
  # 退出窗口（函数尚未定义时不报错，由容器重启策略接管）。
  command -v stop_sandbox_processes >/dev/null 2>&1 && stop_sandbox_processes
}

trap cleanup EXIT INT TERM

# 停机清扫：按服务用户向 relay/wasmd 发信号（pkill 优雅路径；无 pkill 时回退
# /proc 扫描）。定义于 trap 之后但在函数调用时必然可见；cleanup 与本函数各自
# command -v 防御（后者覆盖 stop_sandbox_processes 已定义、kill_user_pattern
# 尚未定义的极窄窗口——Codex R7 非阻塞项）。
stop_sandbox_processes() {
  command -v kill_user_pattern >/dev/null 2>&1 || return 0
  kill_user_pattern iweb-sandbox iweb-snapshot-fd-relay
  kill_user_pattern iweb-sandbox iweb-wasmd
}

# --- R2 9.8/9.11 通用助手（定义先于一切使用：cleanup 的 EXIT 路径与监督循环 seeding） ---

# R2 9.8 孤儿清理：supervisor 崩溃时其子进程（relay、wasmd）会孤儿化；重启 supervisor
# 前先按服务用户清理（relay/wasmd 的 SIGTERM 均为优雅路径）。pkill 缺位时回退扫描
# /proc/<pid>/cmdline（uid 匹配 + 子串匹配）。
kill_user_pattern() {
  user="$1"
  pattern="$2"
  if command -v pkill >/dev/null 2>&1; then
    pkill -u "${user}" -f "${pattern}" 2>/dev/null || true
    return 0
  fi
  uid="$(id -u "${user}" 2>/dev/null || true)"
  [ -n "${uid}" ] || return 0
  for cmdline_path in /proc/[0-9]*/cmdline; do
    [ -r "${cmdline_path}" ] || continue
    pid="${cmdline_path#/proc/}"
    pid="${pid%/cmdline}"
    case "${pid}" in
      '' | *[!0-9]*) continue ;;
    esac
    owner="$(awk '/^Uid:/{print $2}' "/proc/${pid}/status" 2>/dev/null || true)"
    [ "${owner}" = "${uid}" ] || continue
    cmdline="$(tr '\0' ' ' < "${cmdline_path}" 2>/dev/null || true)"
    case "${cmdline}" in
      *"${pattern}"*) kill "${pid}" 2>/dev/null || true ;;
    esac
  done
  return 0
}

# 世代回收（Codex 四轮 P1 处方）：捕获精确 pid+starttime → TERM → 有限等待 →
# 仅对仍匹配（同 pid 同 starttime）者 KILL → 再等待；任何幸存者 = 回收失败，调用方
# 拒绝启动下一代（fail-closed，交给监督循环按退避重试）。全灭后才清 socket 文件，
# 保证 unlink 不会留下仍持有 listener 的旧世代。返回 0=旧世代归零，1=回收失败。
proc_start_ticks() {
  stat_text="$(cat "/proc/$1/stat" 2>/dev/null || true)"
  [ -n "${stat_text}" ] || { echo ""; return 0; }
  close="${stat_text##*)}"
  # 字段 22（starttime）：右括号后第 20 个空分字段（1=state 起）。
  echo "${close}" | awk '{print $20}'
}

# 输出形如 pid:startticks 的单 token（冒号连接——POSIX for 分词不会拆开二元组；
# Codex R5 P1：空格分隔会被拆成独立 token，把 starttime 误当 pid 发信号）。
# Codex R6 P1 加固：任一目标读不到 starttime（proc_start_ticks 空）= 身份不可证明
# → 整个枚举失败（fail-closed），绝不把「读不到」当作「已消失」。
sandbox_generation_pids() {
  uid="$(id -u iweb-sandbox 2>/dev/null || true)"
  [ -n "${uid}" ] || return 0
  for status_path in /proc/[0-9]*/status; do
    [ -r "${status_path}" ] || continue
    pid="${status_path#/proc/}"
    pid="${pid%/status}"
    case "${pid}" in '' | *[!0-9]*) continue ;; esac
    [ "$(awk '/^Uid:/{print $2}' "${status_path}" 2>/dev/null)" = "${uid}" ] || continue
    cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
    case "${cmdline}" in
      *iweb-snapshot-fd-relay* | *iweb-wasmd*)
        ticks="$(proc_start_ticks "${pid}")"
        if [ -z "${ticks}" ]; then
          echo "iweb-entrypoint: cannot read starttime of sandbox pid ${pid}; refusing reclaim (fail-closed)" >&2
          return 1
        fi
        echo "${pid}:${ticks}"
        ;;
    esac
  done
}

pid_matches_generation() {
  pid="$1"
  ticks="$2"
  [ -d "/proc/${pid}" ] || return 1
  [ -n "${ticks}" ] || return 1
  [ "$(proc_start_ticks "${pid}")" = "${ticks}" ]
}

reclaim_sandbox_generation() {
  targets="$(sandbox_generation_pids)" || return 1
  [ -z "${targets}" ] && { rm_sandbox_sockets; return 0; }
  # Codex R6 P1：token 完整性二次校验（枚举已被强制非空 ticks，这里拦截任何
  # 异常来源的残缺 token——空/非数字 pid 或 ticks 不可证明身份，拒绝回收）。
  malformed=""
  for entry in ${targets}; do
    case "${entry%%:*}" in '' | *[!0-9]*) malformed=1 ;; esac
    case "${entry#*:}" in '' | *[!0-9]*) malformed=1 ;; esac
    if [ -n "${malformed}" ]; then
      echo "iweb-entrypoint: malformed generation token '${entry}'; refusing reclaim (fail-closed)" >&2
      return 1
    fi
  done
  # TERM 与 KILL 同栅栏：发信号前重新验证 pid+starttime（捕获后、TERM 前的
  # pid 复用绝不误杀新进程；不匹配者视同已消失，交给等待阶段确认）。
  for entry in ${targets}; do
    if pid_matches_generation "${entry%%:*}" "${entry#*:}"; then
      kill -TERM "${entry%%:*}" 2>/dev/null || true
    fi
  done
  waited=0
  while [ "${waited}" -lt 50 ]; do
    survivors=""
    for entry in ${targets}; do
      if pid_matches_generation "${entry%%:*}" "${entry#*:}"; then
        survivors="${survivors:+${survivors} }${entry}"
      fi
    done
    [ -z "${survivors}" ] && { rm_sandbox_sockets; return 0; }
    targets="${survivors}"
    waited=$((waited + 1))
    sleep 0.1
  done
  # 顽固者（TERM 忽略）：仅对仍匹配同 pid+starttime 者补 KILL（绝不误杀复用者）。
  for entry in ${targets}; do
    if pid_matches_generation "${entry%%:*}" "${entry#*:}"; then
      kill -KILL "${entry%%:*}" 2>/dev/null || true
    fi
  done
  waited=0
  while [ "${waited}" -lt 100 ]; do
    survivors=""
    for entry in ${targets}; do
      if pid_matches_generation "${entry%%:*}" "${entry#*:}"; then
        survivors="${survivors:+${survivors} }${entry}"
      fi
    done
    [ -z "${survivors}" ] && { rm_sandbox_sockets; return 0; }
    targets="${survivors}"
    waited=$((waited + 1))
    sleep 0.1
  done
  echo "iweb-entrypoint: sandbox generation reclaim failed (survivors: ${targets}); refusing to start the next generation" >&2
  return 1
}

rm_sandbox_sockets() {
  rm -f /run/iweb-sandbox/supervisor.sock /run/iweb-sandbox/supervisor-internal.sock \
        /run/iweb-sandbox/snapshot-fd.sock /run/iweb-sandbox/snapshot-fd-relay.sock 2>/dev/null || true
}

# R2 9.11 按应用递增封顶退避：1,2,4,8,…,60s 封顶；进程自上次启动稳定运行 ≥300s 后
# 计数清零。POSIX sh 无关联数组——平行表 "<key>=<value>" 空格分隔 + 读写函数承载
# （key 是 app 名/"supervisor"，value 恒为无空格数字）。
restart_attempts=""
restart_starts=""

state_get() {
  # $1=表内容 $2=key → 输出 value（无记录输出空串）。
  for entry in $1; do
    if [ "${entry%%=*}" = "$2" ]; then
      printf '%s' "${entry#*=}"
      return 0
    fi
  done
  return 0
}

state_set() {
  # $1=表的全局变量名 $2=key $3=value：就地重建（同 key 覆盖，保持既有次序）。
  table_name="$1"
  key="$2"
  value="$3"
  eval "current=\"\${${table_name}}\""
  rebuilt=""
  for entry in ${current}; do
    if [ "${entry%%=*}" != "${key}" ]; then
      rebuilt="${rebuilt:+${rebuilt} }${entry}"
    fi
  done
  rebuilt="${rebuilt:+${rebuilt} }${key}=${value}"
  eval "${table_name}=\"\${rebuilt}\""
}

# restart_backoff_ready <key>：进程死亡后的每次监督轮询调用；返回 0 = 到达重启时刻
# （并落账 attempt/last_start），返回 1 = 仍在退避窗口（下轮再判）。退避参照 last_start：
# 长命运行（≥300s）清零计数，短命崩溃循环按 2^n 递增封顶 60s。
restart_backoff_ready() {
  key="$1"
  now="$(date +%s)"
  last_start="$(state_get "${restart_starts}" "${key}")"
  attempt="$(state_get "${restart_attempts}" "${key}")"
  case "${last_start}" in '' | *[!0-9]*) last_start=0 ;; esac
  case "${attempt}" in '' | *[!0-9]*) attempt=0 ;; esac
  if [ $((now - last_start)) -ge 300 ]; then
    attempt=0
  fi
  attempt=$((attempt + 1))
  delay=1
  step=1
  while [ "${step}" -lt "${attempt}" ]; do
    delay=$((delay * 2))
    if [ "${delay}" -ge 60 ]; then
      delay=60
      break
    fi
    step=$((step + 1))
  done
  if [ $((now - last_start)) -ge "${delay}" ]; then
    state_set restart_attempts "${key}" "${attempt}"
    state_set restart_starts "${key}" "${now}"
    return 0
  fi
  return 1
}

mkdir -p "${minio_data}" "${celld_state}" "${kernel_state}"
# owner-only keys/audit 目录（owner-key-management spec 要求）；但 wasm 准入面
#（admission 策略/retirements/控制态投影）按设计由 supervisor（iweb-sandbox 服务用户）
# 读取（wasm-serve KERNEL_WASM_STATE_ROOT 同根）——目录 0711：其余用户可穿越、不可列目；
# 敏感子树以自身模式保护（secrets/ 0700 root；文件层 0644 元数据不含秘密）。
chmod 0711 "${kernel_state}"
mkdir -p "${kernel_state}/secrets" 2>/dev/null || true
chmod 0700 "${kernel_state}/secrets" 2>/dev/null || true
# add-wasm-host-services（部署批次）：wasm 宿主服务数据面根。kernel-rs wasm_host_services
# 契约「部署层保证 wasm-data 根存在」——本入口首启创建（对照 /data 各子目录惯例；镜像层
# mkdir 会被运行时卷遮蔽，故不进 Dockerfile）。0711：root 全权、其余仅穿越——supervisor
# 以服务用户逐应用 bind-mount per-app 目录；per-app 0700 目录与 0600 SQLite/ledger 文件由
# wasmd host services 幂等自建，本入口绝不预建应用目录或空 SQLite 文件（缺组即 unavailable，
# 绝不静默空替，design「Decisions 3」）。
# R2 9.5：wasm 数据根统一为顶层 /data/wasm-data（0711：root 全权、服务用户仅穿越）；
# 旧 /data/kernel/wasm-data 父目录 0700 不可穿越，不再创建（存量卷遗留目录仅 chown 不使用）。
wasm_data_root="${data_root}/wasm-data"
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
# IWEB_WASM_PUBLICATION_ENABLED=1 时才可能开（单开关，owner 2026-08-29 简化）；
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
# two-tier-runtime-trust R2 9.3 凭据最小化：celld 进程环境从零构造（env -i + 显式注入）——
# owner key（IWEB_API_TOKEN）、RustFS root（MINIO_ROOT_*/RUSTFS_ROOT_*）、IWEB_BASE_HOST、
# 代理变量等一律不得进入 celld 进程；CELLD_VAR_IWEB_BASE_HOST 是应用显式需要的投影值。
run_celld() {
  app="$1"
  public_port="$2"
  internal_port="$3"
  bucket="${4:-iweb-cells-${app}}"
  env -i \
    PATH="${PATH}" \
    HOME="${HOME:-/root}" \
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

# two-tier-runtime-trust：单应用监督规格表 app:public:internal:bucket（bucket 空
# 则用 iweb-cells-<app>）。监督循环据此重启被看门狗/崩溃终止的单个应用。
celld_specs="admin:8787:8788: mcp:8797:8798: hello:8817:8818: search:8827:8828: collab:8837:8838: collab-b:8847:8848:iweb-cells-collab"
if [ "${IWEB_RUN_NOTES_CELLD:-0}" = "1" ]; then
  celld_specs="${celld_specs} notes:8807:8808:"
fi

# R2 9.11：初始启动即落账 last_start（否则首崩会被当作「稳定 300s」清零计数）。
supervision_seed_epoch="$(date +%s)"
for spec in ${celld_specs}; do
  state_set restart_attempts "${spec%%:*}" 0
  state_set restart_starts "${spec%%:*}" "${supervision_seed_epoch}"
done

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
IWEB_SANDBOX_SOCKET=/run/iweb-sandbox/supervisor.sock \
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

# two-tier-runtime-trust：wasm supervisor（含 snapshot-fd-relay 子进程）以专用非
# root 服务用户在容器内运行；socket 目录与状态目录按 SupervisorSocketAuthV1 属主
# 对齐（父目录 0700，socket 0600 由 supervisor bind 后自设）。
# R2 9.3 凭据最小化：supervisor 进程树（supervisor→relay→wasmd）的环境从零构造
# （env -i + 显式 allowlist）——owner key、RustFS root、S3 celld 凭据、IWEB_BASE_HOST
# 等绝不进入服务用户；relay/wasmd 继承该最小环境，无第二套凭据面可泄漏。
# 可选 IWEB_SANDBOX_* 配置只在容器环境显式设置时透传（空值会被 wasm-serve 的
# absolutePath/trim 判定拒绝或视为未配置，不以空串注入）。
supervisor_env() {
  set -- \
    "PATH=${PATH}" \
    "IWEB_SANDBOX_STATE_DIR=${data_root}/wasm-supervisor" \
    "IWEB_SANDBOX_SOCKET=/run/iweb-sandbox/supervisor.sock" \
    "IWEB_SANDBOX_WASM_RELAY_BIN=/usr/local/bin/iweb-snapshot-fd-relay" \
    "IWEB_SANDBOX_WASM_BIN=/opt/iweb/wasmd/iweb-wasmd" \
    "IWEB_WASM_DATA_ROOT=${data_root}/wasm-data"
  for name in \
    IWEB_SANDBOX_WASM_EXECUTION_ENABLED \
    IWEB_SANDBOX_WASM_GATEWAY_ADDRESS \
    IWEB_SANDBOX_WASM_CAPABILITY_RECORD \
    IWEB_SANDBOX_WASM_CAPABILITY_RECORD_V2 \
    IWEB_SANDBOX_WASM_POLICY_DIR \
    IWEB_SANDBOX_WASM_RETIREMENTS_FILE \
    IWEB_SANDBOX_WASM_BACKUP_DIR \
    IWEB_SANDBOX_WASM_READINESS_PROBE \
    IWEB_SANDBOX_WASM_READINESS_MAX_ATTEMPTS \
    IWEB_SANDBOX_WASM_READINESS_ATTEMPT_TIMEOUT_MS \
    IWEB_SANDBOX_WASM_READINESS_INTERVAL_MS; do
    eval "value=\"\${${name}:-}\""
    if [ -n "${value}" ]; then
      set -- "$@" "${name}=${value}"
    fi
  done
  env -i "$@" setpriv --reuid=iweb-sandbox --regid=iweb-sandbox --init-groups \
    /usr/local/bin/iweb-supervisor serve
}

start_supervisor() {
  install -d -o iweb-sandbox -g iweb-sandbox -m 0700 /run/iweb-sandbox
  # 状态目录放 /data 顶层：/data/kernel 是 Kernel 私密状态（0700 root），iweb-sandbox
  # 无法穿越；/data 顶层可穿越且与 /data/run、/data/celld 同级。
  install -d -o iweb-sandbox -g iweb-sandbox -m 0700 "${data_root}/wasm-supervisor"
  # R2 9.5 wasm-data 根统一：新顶层 /data/wasm-data（0711 root 全权、其余仅穿越——
  # Kernel（root）在其中创建 per-app 0700 目录，wasmd（iweb-sandbox）读写同根）。
  # wasmd 侧经 env IWEB_WASM_DATA_ROOT 对位（supervisor allowlist 同名透传）；
  # Kernel 侧 WASM_HOST_DATA_ROOT 的 env 化对位同一变量名，接线归 Kernel 批次。
  install -d -o iweb-sandbox -g iweb-sandbox -m 0711 "${data_root}/wasm-data"
  # 存量卷上的旧根（/data/kernel/wasm-data，父目录 0700 root 不可穿越）：chown 失败
  # 记日志继续（卷上无该目录不算错，不再吞掉）。
  if [ -d "${kernel_state}/wasm-data" ]; then
    chown -R iweb-sandbox:iweb-sandbox "${kernel_state}/wasm-data" 2>/dev/null || \
      echo "iweb-entrypoint: chown of legacy ${kernel_state}/wasm-data failed (continuing; live wasm data root is ${data_root}/wasm-data)" >&2
  fi
  supervisor_env &
  supervisor_pid="$!"
  # 世代档案：每次启动原子更新。这是审计台账——回收不读取它；世代身份以
  # /proc 实时 pid+starttime 栅栏验证（reclaim_sandbox_generation）。
  printf '%s %s\n' "${supervisor_pid}" "$(date +%s)" > "${run_dir}/wasm-supervisor.generation.tmp"
  mv -f "${run_dir}/wasm-supervisor.generation.tmp" "${run_dir}/wasm-supervisor.generation"
}

# R3（Codex 二轮阻塞 1/4）：孤儿清理必须先于启动——启动后清理会命中新实例的
# relay/wasmd（supervisor 异步拉起 relay 的窗口）；退避账目只在 restart_backoff_ready
# 里落（start_supervisor 无条件清零会让崩溃循环永远停留在 1s 退避）。
# 首启：旧世代归零失败 = 节点启动失败（fail-closed；容器重启策略接管重试）。
reclaim_sandbox_generation || exit 1
start_supervisor

# rust-kernel-rustfs-storage §5.2：Kernel 直接拥有发布端口（废 Caddy）。
# 入口探针 = Kernel /_iweb/health；回环控制面仍以 /health 就绪。
# two-tier-runtime-trust：稳态监督循环——Kernel 资源看门狗可 SIGKILL 越限的单个
# celld 进程，本循环检测其退出并按递增封顶退避（R2 9.11：1,2,4,…,60s，稳定 ≥300s
# 清零）只重启该应用（写 pidfile 复用 run_celld）；/data/run/celld-<app>.disabled
# 标记停用单应用。kernel 死亡 → exit 触发 cleanup，重启交给容器重启策略；supervisor
# 崩溃同样退避重启，且重启前先清理 relay/wasmd 孤儿（R2 9.8）。
while :; do
  sleep 2
  if ! kill -0 "${kernel_pid}" 2>/dev/null; then
    echo "iweb-kernel exited; shutting node down" >&2
    exit 1
  fi
  if [ -n "${supervisor_pid}" ] && ! kill -0 "${supervisor_pid}" 2>/dev/null; then
    echo "iweb-entrypoint: wasm supervisor exited; reclaiming the old sandbox generation before restart" >&2
    if reclaim_sandbox_generation && restart_backoff_ready supervisor; then
      start_supervisor
    fi
  fi
  for spec in ${celld_specs}; do
    app="${spec%%:*}"
    rest="${spec#*:}"
    pub="${rest%%:*}"
    rest2="${rest#*:}"
    int="${rest2%%:*}"
    bucket="${rest2#*:}"
    if [ -f "${run_dir}/celld-${app}.disabled" ]; then
      continue
    fi
    pidfile="${run_dir}/celld-${app}.pid"
    if [ ! -f "${pidfile}" ]; then
      continue
    fi
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      continue
    fi
    if ! restart_backoff_ready "${app}"; then
      continue
    fi
    echo "celld ${app} (pid ${pid:-?}) exited; restarting application" >&2
    if [ -n "${bucket}" ]; then
      run_celld "${app}" "${pub}" "${int}" "${bucket}"
    else
      run_celld "${app}" "${pub}" "${int}"
    fi
  done
done
