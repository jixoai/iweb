# 用户原始需求（2026-08-14）：应用运行时镜像只含 pinned celld 二进制，不含 owner key、workspace/system-bucket/fleet/supervisor 或宿主 OCI 凭据。
# 正交意图：可执行权威唯一——镜像 ENTRYPOINT；supervisor 只追加固定参数，绝不再传 "celld"，避免组合出 "celld celld"。
# 镜像引用必须使用 immutable digest（supervisor 会拒绝浮动 tag）。
FROM ghcr.io/denoland/celld@sha256:76225bc06f15d1de90901e32aae52cb81c800e19800e695dc2774625610c22d2
ENTRYPOINT ["celld"]
