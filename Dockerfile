# 用户原始需求（2026-08-11，2026-08-15 rust-kernel-rustfs-storage 更新）：
# 一个容器运行 celld、MinIO（RustFS 迁移期）、Rust Kernel（自有发布入口，Caddy 已废除）。
# 不可调和的原因：celld 发布 Worker 需要 esbuild；将其置入镜像可使首次部署不依赖宿主工具链。
FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS esbuild

RUN npm install --global esbuild@0.25.0 \
  && esbuild --version \
  && mkdir /out \
  && install -m 755 "$(find /usr/local/lib/node_modules -path '*/@esbuild/linux-*/bin/esbuild' -type f | head -n 1)" /out/esbuild

# §7.1/§7.2：Kernel 以 Rust 静态二进制交付（rustup 钉 1.88）。digest 钉版按**目标架构
# manifest**（arm64=93717e49…；amd64 变体见 Dockerfile.amd64）——podman 对多架构引用
# 不自动选 host arch，必须每架构一条。
# add-wasm-runtime（镜像批次）：kernel-rs workspace members 已含 wasmd，成员目录必须
# 全部在场 cargo 才能加载 workspace；-p 钉住只编 Kernel，wasmtime 大树归 wasmd-rs 阶段，
# 两棵依赖树互不失效对方的 RUN 缓存层。
FROM rust:1.88-slim-bookworm@sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d AS kernel-rs
WORKDIR /src
COPY kernel-rs/Cargo.toml kernel-rs/Cargo.lock ./
COPY kernel-rs/iweb-kernel ./iweb-kernel
COPY kernel-rs/wasmd ./wasmd
COPY packages/contracts ./contracts
RUN cargo build --release -p iweb-kernel && cp target/release/iweb-kernel /out-kernel

# add-wasm-runtime（镜像批次）：wasm 宿主薄二进制 iweb-wasmd（wasmtime 48.0.1 钉死，
# 同一 rust:1.88 工具链）。体积纪律：仅拷 release binary 出 stage，target/ 绝不进
# 最终镜像；wasmtime release binary 明显大于 Kernel（见 scripts/wasmd-acceptance-record.bun.ts 体积注记）。
FROM rust:1.88-slim-bookworm@sha256:93717e495a1029ba94b9b4a5768cf14d5376077d26cfad3354cbe70be27c2b1d AS wasmd-rs
WORKDIR /src
COPY kernel-rs/Cargo.toml kernel-rs/Cargo.lock ./
COPY kernel-rs/iweb-kernel ./iweb-kernel
COPY kernel-rs/wasmd ./wasmd
COPY packages/contracts ./contracts
RUN cargo build --release -p iweb-wasmd && cp target/release/iweb-wasmd /out-wasmd

# The Admin source stays editable as a SvelteKit project while celld receives
# its native static output inside the Wrangler deployment root.
# typescript-monorepo：bun.lock 已是 lockfileVersion 2（bun 1.4 格式）；1.3.14 无法解析
# （UnknownLockfileVersion → frozen 拒绝）。按目标架构 manifest 钉版：arm64=b707d911…；
# amd64 变体（8aac4519…）见 Dockerfile.amd64。
FROM oven/bun:1.4.0-alpine@sha256:b707d91190be7e8d5dee8dd7dbe9e7dfecfd26a632266b69335d7a9082814f8b AS admin-console

WORKDIR /opt/iweb
# typescript-monorepo：Admin builder 以 workspace 根安装（root manifest + lock +
# workspace manifests），再构建 admin-console 包。
COPY package.json bun.lock ./
COPY apps/admin-console/package.json ./apps/admin-console/
COPY packages/worker-shared/package.json ./packages/worker-shared/
COPY packages/contracts/package.json ./packages/contracts/
COPY apps/workers/admin/package.json ./apps/workers/admin/package.json
COPY apps/workers/mcp/package.json ./apps/workers/mcp/package.json
COPY apps/workers/notes/package.json ./apps/workers/notes/package.json
COPY apps/workers/search/package.json ./apps/workers/search/package.json
COPY apps/workers/collab/package.json ./apps/workers/collab/package.json
WORKDIR /opt/iweb
RUN bun install --frozen-lockfile
COPY apps/admin-console ./apps/admin-console
COPY packages ./packages
WORKDIR /opt/iweb/apps/admin-console
RUN bun run build

# celld v0.3.0 multi-architecture release, pinned to its OCI index digest
# (f47d97c2…；v0.3 变化：S3 写缓冲批量化的行为差异，CLI 旗标与 v0.2 兼容已实测)。
# The iMac resolves the arm64 manifest beneath this immutable index.
FROM ghcr.io/denoland/celld@sha256:f47d97c2980aa98aef1d9c42205a313442f48acb606c5987dbb9b32983a23aaf

RUN apt-get update \
  && apt-get install --yes --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/*

# §6/§7.2：RustFS 1.0.0-beta.12 替换 MinIO（arm64 manifest 钉版）；mc 保持（G3 已证兼容）。
COPY --from=rustfs/rustfs@sha256:186743df6fdf85c1f10ce246bbee5fb22f1d35c3ec1a73fc9058c560c5f6b505 /usr/bin/rustfs /usr/local/bin/rustfs
COPY --from=minio/mc@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727 /usr/bin/mc /usr/local/bin/mc
COPY --from=kernel-rs /out-kernel /usr/local/bin/iweb-kernel
COPY --from=wasmd-rs /out-wasmd /opt/iweb/wasmd/iweb-wasmd
COPY --from=esbuild /out/esbuild /usr/local/bin/esbuild

# §5.2：Caddyfile 与 caddy 二进制不再进入镜像；发布入口由 Kernel 拥有。
COPY config/celld-policy.json /etc/iweb/celld-policy.json
COPY config/issuer-base-policy.json /etc/iweb/issuer-base-policy.json
COPY config/sandbox-version-policy.json /etc/iweb/sandbox-version-policy.json
# add-wasm-runtime（镜像批次）：wasm 初始数据模板——只作 owner 填写骨架，固定非 live
# 路径；live 记录（/data/kernel/runtime-catalog/… 与 capability record）由 owner 按
# 实测 seal 后落盘，模板占位/null 直接使用必然校验失败（fail-closed，缺失值不推默认）。
COPY config/wasm /opt/iweb/wasm/templates
COPY apps/workers /opt/iweb/apps/workers
COPY packages /opt/iweb/packages
# §5.2：kernel JS 源码不再入镜像；仅保留 entrypoint 引用的 routes 种子。
COPY kernel/routes.seed.json /opt/iweb/kernel/routes.seed.json
COPY --from=admin-console /opt/iweb/apps/admin-console/build /opt/iweb/apps/workers/admin/admin-assets
COPY public /opt/iweb/public
COPY scripts/iweb-entrypoint.sh /usr/local/bin/iweb-entrypoint.sh

# /opt/iweb/release/ 是 Kernel 发布门固定记录目录（celld v1 sandbox-acceptance.json、
# wasm v2 wasm-sandbox-acceptance.json）；预建空目录，记录本体仅 owner 可创建。
RUN mkdir -p /opt/iweb/release \
  && chmod 755 /usr/local/bin/iweb-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/iweb-entrypoint.sh"]
