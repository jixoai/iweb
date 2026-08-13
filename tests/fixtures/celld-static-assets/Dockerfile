# 用户原始需求（2026-08-13）：fixture 在远程 Docker context 下也必须可复验。
# 正交意图：把 fixture 文件传入 Docker daemon；复用 iweb 的 pinned celld/esbuild 工具链。
ARG IWEB_FIXTURE_BASE=iweb:native-assets-work
FROM ${IWEB_FIXTURE_BASE}
COPY . /fixture
ENTRYPOINT ["celld"]
