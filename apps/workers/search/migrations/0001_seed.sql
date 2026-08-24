-- 用户原始需求（2026-08-22）：iweb 实用性实战 2——搜索站种子数据（幂等）。
CREATE TABLE IF NOT EXISTS cheatsheet (
  command TEXT PRIMARY KEY,
  description TEXT NOT NULL,
  category TEXT NOT NULL
);
INSERT OR IGNORE INTO cheatsheet (command, description, category) VALUES
  ('docker ps', '列出运行中的容器', 'docker'),
  ('docker logs -f iweb-local', '跟踪 iweb 节点容器日志', 'docker'),
  ('docker exec -it iweb-local sh', '进入节点容器排查', 'docker'),
  ('docker stats --no-stream', '一次性查看容器资源占用', 'docker'),
  ('docker manifest inspect', '查看多架构镜像的 manifest 摘要（首条通常是 amd64！）', 'docker'),
  ('curl --noproxy ''*''', '绕过本机代理直连回环服务', 'http'),
  ('curl -w ''%{http_code}''', '只输出响应状态码', 'http'),
  ('openssl s_client -connect', '检查服务端证书与 SAN', 'http'),
  ('git check-ignore -v', '确认某文件被哪条 ignore 规则命中', 'git'),
  ('git log --oneline -5', '查看最近五条提交', 'git'),
  ('kubectl rollout undo', '回滚一次部署', 'k8s'),
  ('ssh -L 19010:127.0.0.1:9010', '把远端节点端口转发到本地', 'ssh'),
  ('lsof -nP -iTCP:7070 -sTCP:LISTEN', '找出占用端口的进程', 'shell'),
  ('pkill -f pattern', '按命令行匹配终止进程', 'shell'),
  ('tar -czf - . | ssh host ''tar xzf -''', '不打中间文件直接远端解包', 'shell'),
  ('base64 -i script | ssh host ''base64 -d | sh -s''', '避开引号地狱执行远端脚本', 'shell'),
  ('bun test --preload', '测试前固定环境（如 no_proxy）', 'test'),
  ('cargo clippy --all-targets', 'Rust 全目标静态检查', 'rust'),
  ('cargo test -- --nocapture', '显示测试内的打印输出', 'rust'),
  ('openspec validate --all --strict', '严格校验全部规格', 'spec');
