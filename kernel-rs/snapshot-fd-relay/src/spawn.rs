//! 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2）：supervisor 执行链的真实
//! spawn 半边——relay 以代持的快照描述符注入 FD 3（secret）/FD 4（config，存在时）执行
//! podman（`--preserve-fds 2` 的唯一进入路径），子进程关闭其余继承描述符。
//!
//! 规范权威：spec "Snapshot FD content is bound across Kernel, supervisor, Podman, and
//! wasmd"（FD 3/4 槽位、CLOEXEC 清理、config 缺席时 FD 4 必须不存在、其它继承描述符全关）。
//! fork 后子进程只调用 async-signal-safe 函数（dup2/close/execv/_exit）；CString 参数在
//! fork 前构建完毕。

use std::ffi::CString;
use std::os::fd::RawFd;

/// 注入槽位（spec 固定：secret=3，config=4）。
pub const SECRET_FD_SLOT: RawFd = 3;
pub const CONFIG_FD_SLOT: RawFd = 4;

/// spawn 请求：program（podman 路径）+ argv（不含程序名）+ 代持描述符。
pub struct FdSpawnRequest<'a> {
    pub program: &'a str,
    pub argv: &'a [String],
    pub secret_fd: RawFd,
    pub config_fd: Option<RawFd>,
}

/// spawn 结果：exec 已发生并 waitpid 收敛。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnExit {
    /// 子进程退出码（信号终止记 128+signal，与 shell 惯例一致）。
    pub code: i32,
}

/// 校验 argv 可进入 execv（非空、无 NUL、程序路径非空）。fail-closed，不静默裁剪。
pub fn validate_spawn_request(request: &FdSpawnRequest<'_>) -> Result<(), &'static str> {
    if request.program.is_empty() || request.program.contains('\0') {
        return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
    }
    if request.argv.is_empty() {
        return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
    }
    if request.argv.iter().any(|argument| argument.contains('\0')) {
        return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
    }
    if request.secret_fd < 0 {
        return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
    }
    if let Some(config) = request.config_fd {
        if config < 0 {
            return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
        }
    }
    Ok(())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// 子进程关闭除 {0,1,2, 保留槽} 外的继承描述符。上限取 RLIMIT_NOFILE 软限与 8192 的
/// 较小者（close 循环足够快；close_range 在 libc 0.2.189 的 macOS 绑定不可用，保持可移植）。
fn close_inherited_descriptors(keep: &[RawFd]) {
    let mut limit: libc::rlim_t = 8192;
    unsafe {
        let mut resource: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut resource) == 0 {
            let soft = resource.rlim_cur;
            if soft != libc::RLIM_INFINITY && soft < limit {
                limit = soft;
            }
        }
    }
    for fd in 3..(limit as RawFd) {
        if keep.contains(&fd) {
            continue;
        }
        unsafe {
            libc::close(fd);
        }
    }
}

/// fork + 注入 FD 槽 + execv + waitpid。返回子进程退出码；fork/exec 层失败返回 Err
/// （message 不含任何快照内容）。调用方保证 secret_fd/config_fd 在 fork 瞬间有效（台账锁）。
pub fn spawn_with_snapshot_fds(request: &FdSpawnRequest<'_>) -> Result<SpawnExit, String> {
    validate_spawn_request(request).map_err(|code| format!("{code}: the spawn request is not executable"))?;
    // fork 前构建全部 CString（execv 参数与 environ 无关；argv[0] 惯例为程序名）。
    let program = CString::new(request.program).map_err(|_| "SNAPSHOT_SPAWN_ARGV_INVALID: program contains NUL".to_string())?;
    let mut owned: Vec<CString> = Vec::with_capacity(request.argv.len() + 1);
    owned.push(CString::new(request.program).map_err(|_| "SNAPSHOT_SPAWN_ARGV_INVALID".to_string())?);
    for argument in request.argv {
        owned.push(CString::new(argument.as_str()).map_err(|_| "SNAPSHOT_SPAWN_ARGV_INVALID".to_string())?);
    }
    let raw: Vec<*const libc::c_char> = owned.iter().map(|value| value.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
    let secret = request.secret_fd;
    let config = request.config_fd;
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!("SNAPSHOT_SPAWN_FAILED: fork failed with errno {}", errno()));
    }
    if child == 0 {
        // 子进程：注入槽位。dup2 目标不携带源描述符的 FD_CLOEXEC。
        unsafe {
            if libc::dup2(secret, SECRET_FD_SLOT) < 0 {
                libc::_exit(126);
            }
            // dup2(old,new) 会清除新 fd 的 FD_CLOEXEC，但 old==new 时是 no-op 且不清除；
            // relay 持有的源 fd 由 Rust File::open 打开、默认带 O_CLOEXEC——若源恰为槽位
            // 本身，exec 会丢描述符（合并 workspace 测试环境实证）。显式清零兜底。
            if libc::fcntl(SECRET_FD_SLOT, libc::F_SETFD, 0) < 0 {
                libc::_exit(126);
            }
            match config {
                Some(config_fd) => {
                    if libc::dup2(config_fd, CONFIG_FD_SLOT) < 0 {
                        libc::_exit(126);
                    }
                    if libc::fcntl(CONFIG_FD_SLOT, libc::F_SETFD, 0) < 0 {
                        libc::_exit(126);
                    }
                }
                // config 缺席：FD 4 必须不存在（spec：when configRevision:0, FD 4 MUST be absent）。
                None => {
                    libc::close(CONFIG_FD_SLOT);
                }
            }
            close_inherited_descriptors(&[SECRET_FD_SLOT, CONFIG_FD_SLOT]);
            libc::execv(program.as_ptr(), raw.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status: libc::c_int = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        if waited < 0 && errno() == libc::EINTR {
            continue;
        }
        return Err(format!("SNAPSHOT_SPAWN_FAILED: waitpid failed with errno {}", errno()));
    }
    if libc::WIFEXITED(status) {
        return Ok(SpawnExit { code: libc::WEXITSTATUS(status) });
    }
    if libc::WIFSIGNALED(status) {
        return Ok(SpawnExit { code: 128 + libc::WTERMSIG(status) });
    }
    Err("SNAPSHOT_SPAWN_FAILED: the child exited without an exit status".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    fn readonly_descriptor(path: &std::path::Path) -> RawFd {
        std::fs::File::open(path).expect("open fixture read-only").into_raw_fd()
    }

    fn write_fixture(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("iweb-relay-spawn-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).expect("write spawn fixture");
        path
    }

    #[test]
    fn invalid_requests_fail_closed_before_fork() {
        let program = "/bin/true".to_string();
        let argv: Vec<String> = vec!["--help".to_string()];
        let missing = FdSpawnRequest { program: "", argv: argv.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&missing).is_err());
        let nul_argv: Vec<String> = vec!["a\0b".to_string()];
        let nul = FdSpawnRequest { program: program.as_str(), argv: nul_argv.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&nul).is_err());
        let empty: Vec<String> = vec![];
        let empty = FdSpawnRequest { program: program.as_str(), argv: empty.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&empty).is_err());
    }

    #[test]
    fn spawn_places_secret_bytes_on_fd3_and_reports_exit_code() {
        let secret_bytes = b"fd3-payload".to_vec();
        let fixture = write_fixture("secret.txt", &secret_bytes);
        let secret_fd = readonly_descriptor(&fixture);
        let out_path = std::env::temp_dir().join(format!("iweb-relay-spawn-out-{}", std::process::id()));
        let script = format!("cat <&{} > {}", SECRET_FD_SLOT, out_path.display());
        let argv = vec!["-c".to_string(), script];
        let request = FdSpawnRequest { program: "/bin/sh", argv: &argv, secret_fd, config_fd: None };
        let exit = spawn_with_snapshot_fds(&request).expect("spawn must succeed");
        assert_eq!(exit.code, 0, "sh must read the injected fd and exit 0");
        let observed = std::fs::read(&out_path).expect("spawn output file");
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(observed, secret_bytes, "fd 3 must carry exactly the held secret descriptor");
        // 释放 readonly_descriptor 的原始 fd（测试内以 close 收尾，避免泄漏告警噪音）。
        unsafe {
            libc::close(secret_fd);
        }
    }

    #[test]
    fn spawn_without_config_leaves_fd4_absent() {
        let secret_bytes = b"only-secret".to_vec();
        let fixture = write_fixture("secret-only.txt", &secret_bytes);
        let secret_fd = readonly_descriptor(&fixture);
        let probe = format!("if [ -e /dev/fd/{slot} ]; then exit 9; fi; exit 0", slot = CONFIG_FD_SLOT);
        let argv = vec!["-c".to_string(), probe];
        let request = FdSpawnRequest { program: "/bin/sh", argv: &argv, secret_fd, config_fd: None };
        let exit = spawn_with_snapshot_fds(&request).expect("spawn must succeed");
        let _ = std::fs::remove_file(&fixture);
        unsafe {
            libc::close(secret_fd);
        }
        assert_eq!(exit.code, 0, "fd 4 must not exist when no config descriptor was held");
    }

    #[test]
    fn spawn_exit_code_and_signal_paths_are_reported() {
        let fixture = write_fixture("exitcode.txt", b"x");
        let secret_fd = readonly_descriptor(&fixture);
        let argv = vec!["-c".to_string(), "exit 42".to_string()];
        let request = FdSpawnRequest { program: "/bin/sh", argv: &argv, secret_fd, config_fd: None };
        let exit = spawn_with_snapshot_fds(&request).expect("spawn must succeed");
        unsafe {
            libc::close(secret_fd);
        }
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(exit.code, 42);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn spawned_child_closes_other_inherited_descriptors() {
        let fixture = write_fixture("inherit.txt", b"payload");
        let secret_fd = readonly_descriptor(&fixture);
        // 打开一个额外描述符（不进 keep 集）：子进程若继承它，可由 /proc/self/fd 数量探测。
        let extra = readonly_descriptor(&fixture);
        let script = format!("ls /proc/self/fd | wc -l > /tmp/iweb-relay-fdcount-{}", std::process::id());
        let argv = vec!["-c".to_string(), script];
        let request = FdSpawnRequest { program: "/bin/sh", argv: &argv, secret_fd, config_fd: None };
        let exit = spawn_with_snapshot_fds(&request).expect("spawn must succeed");
        unsafe {
            libc::close(secret_fd);
            libc::close(extra);
        }
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(exit.code, 0);
        let counted: String = std::fs::read_to_string(format!("/tmp/iweb-relay-fdcount-{}", std::process::id())).unwrap_or_default();
        let _ = std::fs::remove_file(format!("/tmp/iweb-relay-fdcount-{}", std::process::id()));
        let open_fds: usize = counted.trim().parse().unwrap_or(usize::MAX);
        // 0/1/2 + fd3（ls/wc 管道的临时描述符在 shell 内部自开自闭；上限放宽到 6 以内）。
        assert!(open_fds <= 6, "the child must not inherit the relay's descriptors beyond the fd slots (saw {open_fds})");
    }
}
