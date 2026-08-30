//! 用户原始需求（2026-08-26，add-wasm-runtime 归档终审阻塞 2；R2 修复轮 2026-08-30
//! tasks 9.2 去 shell 直执行）：supervisor 执行链的真实 spawn 半边——relay 以代持的
//! 快照描述符注入 FD 3（secret）/FD 4（config，存在时）后**直接 execv 目标二进制**
//! （digest-pinned iweb-wasmd）。不经过 /bin/sh、不组合 shell launcher、不接受任意
//! 参数拼接：argv 由 supervisor 在 spawn 指令 payload 里给定（含 argv[0]），relay
//! 校验 argv[0] 等于启动时固定的 `--exec` 路径后才 fork。
//!
//! 规范权威：spec "Snapshot FD content is bound across Kernel, supervisor, and wasmd"
//!（FD 3/4 槽位、CLOEXEC 清理、config 缺席时 FD 4 必须不存在、其它继承描述符全关）。
//! fork 后子进程只调用 async-signal-safe 函数（dup2/close/execv/_exit）；CString 参数
//! 在 fork 前构建完毕。父进程（relay）对子进程保持 wait/reap 关系：专用 reaper 线程
//! waitpid(-1) 回收，子退出码记录进 ChildTable，经控制 socket 的 wait 指令上报。

use std::ffi::CString;
use std::os::fd::RawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// 注入槽位（spec 固定：secret=3，config=4）。
pub const SECRET_FD_SLOT: RawFd = 3;
pub const CONFIG_FD_SLOT: RawFd = 4;
/// argv 元素数上限（wasmd argv@2 是 11 元素；留裕量，超出即 fail-closed）。
pub const SPAWN_ARGV_MAX_ELEMENTS: usize = 128;

/// spawn 请求：program（`--exec` 固定的目标二进制路径）+ argv（**含 argv[0]**，
/// supervisor 在 spawn 指令 payload 里给定；argv[0] 必须等于 program）+ 代持描述符。
pub struct FdSpawnRequest<'a> {
    pub program: &'a str,
    pub argv: &'a [String],
    pub secret_fd: RawFd,
    pub config_fd: Option<RawFd>,
}

/// spawn 产物：exec 已派发；父进程保持 wait/reap（退出码经 ChildTable 上报）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnChild {
    pub pid: i32,
}

/// 校验直执行请求（fail-closed，不静默裁剪）：program 非空无 NUL；argv 非空、
/// 无 NUL、不超上限；**argv[0] 必须逐字等于 program**（杜绝任意程序执行面）。
pub fn validate_spawn_request(request: &FdSpawnRequest<'_>) -> Result<(), &'static str> {
    if request.program.is_empty() || request.program.contains('\0') {
        return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
    }
    if request.argv.is_empty() || request.argv.len() > SPAWN_ARGV_MAX_ELEMENTS {
        return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
    }
    if request.argv.iter().any(|argument| argument.contains('\0')) {
        return Err("SNAPSHOT_SPAWN_ARGV_INVALID");
    }
    if request.argv[0] != request.program {
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

/// fork 前探测 exec 目标可执行（存在 + X_OK）：缺失/不可执行是确定性配置失败，
/// 同步拒绝（不产生子进程）。
fn require_executable(program: &CString) -> Result<(), String> {
    let code = unsafe { libc::access(program.as_ptr(), libc::X_OK) };
    if code != 0 {
        return Err(format!(
            "SNAPSHOT_EXEC_TARGET_INVALID: the exec target is not executable (errno {})",
            errno()
        ));
    }
    Ok(())
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

/// fork + 注入 FD 槽 + 直接 execv（无 shell、无参数拼接）。返回子 pid；fork/exec
/// 准备层失败返回 Err（message 不含任何快照内容）。调用方保证 secret_fd/config_fd
/// 在 fork 瞬间有效（台账锁）。fork 之后父进程立即返回——子进程退出由 reaper 线程
/// 回收并经 ChildTable 上报（wait/reap 关系；绝不留僵尸）。
pub fn spawn_exec_with_snapshot_fds(request: &FdSpawnRequest<'_>) -> Result<SpawnChild, String> {
    validate_spawn_request(request).map_err(|code| format!("{code}: the spawn request is not executable"))?;
    // fork 前构建全部 CString（execv 参数与 environ 无关；argv[0]==program 已校验，
    // 直接使用 payload argv——relay 不重组、不拼接任何参数）。
    let program = CString::new(request.program).map_err(|_| "SNAPSHOT_SPAWN_ARGV_INVALID: program contains NUL".to_string())?;
    require_executable(&program)?;
    let owned: Vec<CString> = request
        .argv
        .iter()
        .map(|argument| CString::new(argument.as_str()))
        .collect::<Result<_, _>>()
        .map_err(|_| "SNAPSHOT_SPAWN_ARGV_INVALID: argv contains NUL".to_string())?;
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
            // 直接 execv：argv 来自 payload（argv[0]==--exec 路径）；无 shell、无
            // 子进程继承 relay（进而 entrypoint 白名单）的最小环境；凭据变量结构性不可达。
            libc::execv(program.as_ptr(), raw.as_ptr());
            libc::_exit(127);
        }
    }
    // 父进程对子进程的副本无依赖（fork 复制了描述符表）：立即交还控制响应，
    // 退出状态归 reaper 线程（wait/reap 关系）。
    Ok(SpawnChild { pid: child })
}

// ---------------------------------------------------------------------------
// 子进程台账 + reaper：父进程保持 wait/reap 关系，子退出经控制 socket 上报
// ---------------------------------------------------------------------------

/// 一个已派发子进程的观测状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildStatus {
    pub pid: i32,
    /// None = 仍在运行；Some(code) = 已退出（信号终止记 128+signal，与 shell 惯例一致）。
    pub exit_code: Option<i32>,
}

/// ChildTable 的有界容量（commandId 条目；超出淘汰最旧已退出条目）。
pub const CHILD_TABLE_MAX: usize = 64;

#[derive(Default)]
struct ChildTableInner {
    entries: Vec<(String, ChildStatus)>,
}

/// commandId → 子进程状态台账（reaper 写入，wait 查询读取；Condvar 唤醒等待者）。
pub struct ChildTable {
    inner: Mutex<ChildTableInner>,
    changed: Condvar,
}

impl ChildTable {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ChildTableInner::default()),
            changed: Condvar::new(),
        }
    }

    /// spawn 派发后登记（同 commandId 重复登记 → 替换观测，但保留已记录的退出码）。
    pub fn register(&self, command_id: &str, pid: i32) {
        let mut inner = self.inner.lock().expect("child table lock");
        if let Some((_, status)) = inner.entries.iter_mut().find(|(id, _)| id == command_id) {
            if status.exit_code.is_none() {
                status.pid = pid;
            }
            return;
        }
        inner.entries.push((command_id.to_string(), ChildStatus { pid, exit_code: None }));
        Self::evict_locked(&mut inner);
    }

    /// 淘汰最旧的已退出条目（有界；运行中条目永不淘汰）。
    fn evict_locked(inner: &mut ChildTableInner) {
        while inner.entries.len() > CHILD_TABLE_MAX {
            match inner.entries.iter().position(|(_, status)| status.exit_code.is_some()) {
                Some(at) => {
                    inner.entries.remove(at);
                }
                None => break,
            }
        }
    }

    /// reaper 记录一次子退出（按 pid 定位；找不到则忽略——非本台账派发的子进程）。
    pub fn record_exit(&self, pid: i32, exit_code: i32) {
        let mut inner = self.inner.lock().expect("child table lock");
        for (_, status) in inner.entries.iter_mut() {
            if status.pid == pid && status.exit_code.is_none() {
                status.exit_code = Some(exit_code);
            }
        }
        Self::evict_locked(&mut inner);
        drop(inner);
        self.changed.notify_all();
    }

    /// wait 指令实现：限时等待 commandId 的退出；None = 未知 commandId。
    pub fn wait_for_exit(&self, command_id: &str, timeout: Duration) -> Option<ChildStatus> {
        let deadline = Instant::now() + timeout;
        let mut inner = self.inner.lock().expect("child table lock");
        loop {
            let found = inner
                .entries
                .iter()
                .find(|(id, _)| id == command_id)
                .map(|(_, status)| *status);
            match found {
                Some(status) if status.exit_code.is_some() => return Some(status),
                Some(status) => {
                    // 运行中：等待 reaper 唤醒或时限到（届时返回运行中事实）。
                    let now = Instant::now();
                    if now >= deadline {
                        return Some(status);
                    }
                    let (guard, _timeout) = self
                        .changed
                        .wait_timeout(inner, deadline - now)
                        .expect("child table lock");
                    inner = guard;
                }
                None => return None,
            }
        }
    }

    /// 丢弃条目（discard 语义：只清台账观测，不动进程——stop 由 supervisor 按 pid 决定）。
    pub fn forget(&self, command_id: &str) -> bool {
        let mut inner = self.inner.lock().expect("child table lock");
        let before = inner.entries.len();
        inner.entries.retain(|(id, _)| id != command_id);
        inner.entries.len() != before
    }
}

/// 子退出的规范编码（WIFEXITED/WIFSIGNALED 之外一律 Err——不造第二套语义）。
fn decode_wait_status(status: libc::c_int) -> Result<i32, String> {
    if libc::WIFEXITED(status) {
        return Ok(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(128 + libc::WTERMSIG(status));
    }
    Err("SNAPSHOT_SPAWN_FAILED: the child exited without an exit status".to_string())
}

/// reaper 线程体：阻塞 waitpid(-1) 循环（SIGCHLD 语义等价的显式回收；绝不留僵尸）。
/// 只处理本 relay 派发的子进程（record_exit 按 pid 匹配；未知 pid 直接丢弃）。
pub fn run_child_reaper(table: Arc<ChildTable>) {
    loop {
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        if waited > 0 {
            if let Ok(code) = decode_wait_status(status) {
                table.record_exit(waited, code);
            }
            continue;
        }
        if waited < 0 && errno() == libc::EINTR {
            continue;
        }
        // 无子进程（ECHILD）或不可恢复错误：短暂休眠后重试（spawn 会再派发子进程）。
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 启动 reaper 线程（进程内一次；生产与测试共用）。
pub fn spawn_child_reaper(table: Arc<ChildTable>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || run_child_reaper(table))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    fn readonly_descriptor(path: &std::path::Path) -> RawFd {
        std::fs::File::open(path).expect("open fixture read-only").into_raw_fd()
    }

    fn write_fixture(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "iweb-relay-spawn-{}-{}-{}",
            std::process::id(),
            name,
            line!()
        ));
        std::fs::write(&path, bytes).expect("write spawn fixture");
        path
    }

    #[test]
    fn invalid_requests_fail_closed_before_fork() {
        let program = "/bin/true".to_string();
        // 空 program / NUL program。
        let missing_argv = [program.clone()];
        let missing = FdSpawnRequest { program: "", argv: missing_argv.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&missing).is_err());
        // argv 为空。
        let empty: Vec<String> = vec![];
        let empty = FdSpawnRequest { program: program.as_str(), argv: empty.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&empty).is_err());
        // argv 含 NUL。
        let nul_argv: Vec<String> = vec![program.clone(), "a\0b".to_string()];
        let nul = FdSpawnRequest { program: program.as_str(), argv: nul_argv.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&nul).is_err());
        // **argv[0] != --exec 路径：任意程序执行面被结构性拒绝（tasks 9.2 核心）。**
        let mismatched: Vec<String> = vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()];
        let mismatch = FdSpawnRequest { program: program.as_str(), argv: mismatched.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&mismatch).is_err(), "argv[0] must equal the pinned exec path");
        // argv 超上限。
        let oversized: Vec<String> = (0..SPAWN_ARGV_MAX_ELEMENTS + 1).map(|i| if i == 0 { program.clone() } else { i.to_string() }).collect();
        let oversized = FdSpawnRequest { program: program.as_str(), argv: oversized.as_slice(), secret_fd: 0, config_fd: None };
        assert!(validate_spawn_request(&oversized).is_err());
    }

    #[test]
    fn non_executable_target_is_rejected_before_fork() {
        let fixture = write_fixture("not-executable.txt", b"x");
        let argv = vec![fixture.display().to_string()];
        let request = FdSpawnRequest { program: fixture.to_str().unwrap(), argv: argv.as_slice(), secret_fd: 0, config_fd: None };
        let error = spawn_exec_with_snapshot_fds(&request).expect_err("a non-executable target must be rejected synchronously");
        assert!(error.starts_with("SNAPSHOT_EXEC_TARGET_INVALID"), "{error}");
        let _ = std::fs::remove_file(&fixture);
    }

    /// 直执行测试的目标二进制：测试用 /bin/sh **作为 --exec 目标本体**（不是 relay
    /// 组合 launcher——relay 对任何目标只做 execv(argv)，argv[0] 必须等于该路径）。
    /// 进程级共享的测试台账 + 单一 reaper：复刻生产拓扑（一个 relay 进程恰一个
    /// ChildTable + 一个 reaper 线程）。若每个用例各起一个 reaper，并发用例的
    /// waitpid(-1) 会互收对方的子进程、把退出码记进错误（或不存在）的条目——
    /// 这是 2026-08-30 实测出的测试竞态，不是生产缺陷。
    fn shared_test_table() -> &'static Arc<ChildTable> {
        static TABLE: std::sync::OnceLock<Arc<ChildTable>> = std::sync::OnceLock::new();
        TABLE.get_or_init(|| {
            let table = Arc::new(ChildTable::new());
            spawn_child_reaper(Arc::clone(&table));
            table
        })
    }

    fn spawn_and_wait(argv: &[String], secret_fd: RawFd, config_fd: Option<RawFd>) -> (SpawnChild, ChildStatus) {
        let table = shared_test_table();
        // 共享台账下每个用例用唯一 commandId（原子序号），互不覆盖；结束即 forget。
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let command_id = format!(
            "test-command-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let request = FdSpawnRequest { program: argv[0].as_str(), argv, secret_fd, config_fd };
        let child = spawn_exec_with_snapshot_fds(&request).expect("spawn must succeed");
        table.register(&command_id, child.pid);
        let mut status = None;
        for _ in 0..200 {
            if let Some(observed) = table.wait_for_exit(&command_id, Duration::from_millis(50)) {
                if observed.exit_code.is_some() {
                    status = Some(observed);
                    break;
                }
            }
        }
        let status = status.expect("the child exit must be reaped and reported");
        table.forget(&command_id);
        (child, status)
    }

    #[test]
    fn direct_exec_places_secret_bytes_on_fd3_and_reports_exit() {
        let secret_bytes = b"fd3-payload".to_vec();
        let fixture = write_fixture("secret.txt", &secret_bytes);
        let secret_fd = readonly_descriptor(&fixture);
        let out_path = std::env::temp_dir().join(format!("iweb-relay-spawn-out-{}-{}", std::process::id(), line!()));
        // --exec 目标 = /bin/sh（测试目标本体）；argv[0] 等于该路径。
        let script = format!("cat <&{} > {}", SECRET_FD_SLOT, out_path.display());
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        let (child, status) = spawn_and_wait(&argv, secret_fd, None);
        assert!(child.pid > 0);
        assert_eq!(status.exit_code, Some(0), "the target must read the injected fd and exit 0");
        assert_eq!(status.pid, child.pid);
        let observed = std::fs::read(&out_path).expect("spawn output file");
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(observed, secret_bytes, "fd 3 must carry exactly the held secret descriptor");
        unsafe {
            libc::close(secret_fd);
        }
    }

    #[test]
    fn direct_exec_without_config_leaves_fd4_absent() {
        let secret_bytes = b"only-secret".to_vec();
        let fixture = write_fixture("secret-only.txt", &secret_bytes);
        let secret_fd = readonly_descriptor(&fixture);
        let probe = format!("if [ -e /dev/fd/{slot} ]; then exit 9; fi; exit 0", slot = CONFIG_FD_SLOT);
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), probe];
        let (_, status) = spawn_and_wait(&argv, secret_fd, None);
        unsafe {
            libc::close(secret_fd);
        }
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(status.exit_code, Some(0), "fd 4 must not exist when no config descriptor was held");
    }

    #[test]
    fn child_exit_code_and_signal_paths_are_reported_via_the_reaper() {
        let fixture = write_fixture("exitcode.txt", b"x");
        let secret_fd = readonly_descriptor(&fixture);
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "exit 42".to_string()];
        let (_, status) = spawn_and_wait(&argv, secret_fd, None);
        unsafe {
            libc::close(secret_fd);
        }
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(status.exit_code, Some(42));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn spawned_child_closes_other_inherited_descriptors() {
        let fixture = write_fixture("inherit.txt", b"payload");
        let secret_fd = readonly_descriptor(&fixture);
        // 打开一个额外描述符（不进 keep 集）：子进程若继承它，可由 /proc/self/fd 数量探测。
        let extra = readonly_descriptor(&fixture);
        let script = format!("ls /proc/self/fd | wc -l > /tmp/iweb-relay-fdcount-{}", std::process::id());
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script];
        let (_, status) = spawn_and_wait(&argv, secret_fd, None);
        unsafe {
            libc::close(secret_fd);
            libc::close(extra);
        }
        let _ = std::fs::remove_file(&fixture);
        assert_eq!(status.exit_code, Some(0));
        let counted: String = std::fs::read_to_string(format!("/tmp/iweb-relay-fdcount-{}", std::process::id())).unwrap_or_default();
        let _ = std::fs::remove_file(format!("/tmp/iweb-relay-fdcount-{}", std::process::id()));
        let open_fds: usize = counted.trim().parse().unwrap_or(usize::MAX);
        // 0/1/2 + fd3（ls/wc 管道的临时描述符在 shell 内部自开自闭；上限放宽到 6 以内）。
        assert!(open_fds <= 6, "the child must not inherit the relay's descriptors beyond the fd slots (saw {open_fds})");
    }

    #[test]
    fn child_table_wait_returns_running_then_exit_and_forgets() {
        let table = Arc::new(ChildTable::new());
        assert!(table.wait_for_exit("unknown", Duration::from_millis(1)).is_none(), "unknown commandId → None");
        table.register("c1", 4242);
        // 运行中：时限到 → 返回运行中事实（exit_code None）。
        let observed = table.wait_for_exit("c1", Duration::from_millis(10)).expect("entry exists");
        assert_eq!(observed, ChildStatus { pid: 4242, exit_code: None });
        // reaper 记录退出 → wait 立即返回退出码并唤醒等待者。
        table.record_exit(4242, 137);
        let observed = table.wait_for_exit("c1", Duration::from_millis(0)).expect("entry exists");
        assert_eq!(observed, ChildStatus { pid: 4242, exit_code: Some(137) });
        // forget：条目移除后查询为 None。
        assert!(table.forget("c1"));
        assert!(table.wait_for_exit("c1", Duration::from_millis(0)).is_none());
        assert!(!table.forget("c1"));
    }
}
