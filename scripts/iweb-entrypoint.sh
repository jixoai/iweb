#!/bin/sh
# 用户原始需求（2026-08-11）：一个容器协调 MinIO、celld 与 Caddy，作为一个家庭的低成本 iweb 节点。
# 不可调和的原因：三个守护进程需要共同生命周期；此入口负责启动顺序与首次存储初始化。
set -eu

: "${CELLD_NODE:?CELLD_NODE must identify this iweb installation}"

data_root=/data
minio_data="${data_root}/minio"
celld_state="${data_root}/celld"
minio_pid=""
celld_pid=""
caddy_pid=""

cleanup() {
  for pid in "${caddy_pid}" "${celld_pid}" "${minio_pid}"; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
  done
}

trap cleanup EXIT INT TERM

mkdir -p "${minio_data}" "${celld_state}"

minio server "${minio_data}" --address 127.0.0.1:9000 --console-address 127.0.0.1:9001 &
minio_pid="$!"

attempt=0
until mc alias set local http://127.0.0.1:9000 "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 30 ]; then
    echo "MinIO did not become ready" >&2
    exit 1
  fi
  sleep 1
done

mc mb --ignore-existing local/iweb-cells
mc mb --ignore-existing local/iweb-public
mc anonymous set download local/iweb-public
mc admin user add local "${CELLD_S3_ACCESS_KEY}" "${CELLD_S3_SECRET_KEY}" || true
mc admin policy create local iweb-celld /etc/iweb/celld-policy.json || true
mc admin policy attach local iweb-celld --user "${CELLD_S3_ACCESS_KEY}"

if ! mc stat local/iweb-public/index.html >/dev/null 2>&1; then
  mc cp /opt/iweb/public/index.html local/iweb-public/index.html
fi

if [ "${IWEB_DEPLOY_ON_START:-0}" = "1" ] || ! mc stat local/iweb-cells/deploy/current.json >/dev/null 2>&1; then
  AWS_ACCESS_KEY_ID="${CELLD_S3_ACCESS_KEY}" \
  AWS_SECRET_ACCESS_KEY="${CELLD_S3_SECRET_KEY}" \
  celld deploy /opt/iweb/worker \
    --bucket s3://iweb-cells \
    --endpoint http://127.0.0.1:9000 \
    --region us-east-1
fi

CELLD_NODE="${CELLD_NODE}" \
CELLD_WATCH="${celld_state}" \
AWS_ACCESS_KEY_ID="${CELLD_S3_ACCESS_KEY}" \
AWS_SECRET_ACCESS_KEY="${CELLD_S3_SECRET_KEY}" \
celld \
  --bucket s3://iweb-cells \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1 \
  --listen 127.0.0.1:8787 \
  --advertise 127.0.0.1:8787 &
celld_pid="$!"

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

caddy run --config /etc/iweb/Caddyfile --adapter caddyfile &
caddy_pid="$!"
wait "${caddy_pid}"
