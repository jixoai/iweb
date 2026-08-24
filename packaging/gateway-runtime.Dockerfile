# 用户原始需求（2026-08-14）：gateway 镜像只含 supervisor 编译的策略网关二进制；不含任何凭据（凭据由挂载的 0600 配置注入）。
# 正交意图：pod 内第二个容器；只读 rootfs；安装器构建并 digest 固定后写入 supervisor 环境。
FROM gcr.io/distroless/base-debian12
COPY iweb-gateway /usr/local/bin/iweb-gateway
ENTRYPOINT ["/usr/local/bin/iweb-gateway"]
