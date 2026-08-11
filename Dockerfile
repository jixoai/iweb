# 用户原始需求（2026-08-11）：一个容器运行 celld、MinIO、Caddy，供单个家庭节点低成本自托管。
# 不可调和的原因：celld 发布 Worker 需要 esbuild；将其置入镜像可使首次部署不依赖宿主工具链。
FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS esbuild

RUN npm install --global esbuild@0.25.0 \
  && esbuild --version \
  && mkdir /out \
  && install -m 755 "$(find /usr/local/lib/node_modules -path '*/@esbuild/linux-*/bin/esbuild' -type f | head -n 1)" /out/esbuild

# celld publishes the current multi-architecture release as `latest`; v0.1.0
# is a Git tag but not a GHCR image tag.
FROM ghcr.io/denoland/celld@sha256:2ba7fdeb91041a7e090027cf9d922b7b628e1fa0bb83818dcde059004ab809c8

RUN apt-get update \
  && apt-get install --yes --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e /usr/bin/minio /usr/local/bin/minio
COPY --from=minio/mc@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727 /usr/bin/mc /usr/local/bin/mc
COPY --from=caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d /usr/bin/caddy /usr/local/bin/caddy
COPY --from=esbuild /out/esbuild /usr/local/bin/esbuild
COPY --from=esbuild /usr/local/bin/node /usr/local/bin/node

COPY config/Caddyfile /etc/iweb/Caddyfile
COPY config/celld-policy.json /etc/iweb/celld-policy.json
COPY kernel /opt/iweb/kernel
COPY worker /opt/iweb/worker
COPY public /opt/iweb/public
COPY scripts/iweb-entrypoint.sh /usr/local/bin/iweb-entrypoint.sh

RUN chmod 755 /usr/local/bin/iweb-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/iweb-entrypoint.sh"]
