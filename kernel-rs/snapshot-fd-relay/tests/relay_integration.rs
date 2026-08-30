//! relay 集成测试（bin 级）：
//! - 非 Linux 宿主（macOS 开发机）：fd socket 绑定必须以 SNAPSHOT_TRANSPORT_UNAVAILABLE
//!   fail-closed 退出（无 AF_UNIX SOCK_SEQPACKET，实证见 wasm_snapshot_fd.rs 头注）；活
//!   relay 的 socket 用例全部 linux-gated（macOS 上 relay 无法存活）。
//! - Linux（cfg 门控）：Kernel 端（iweb-kernel connect/sendmsg/recvmsg）→ relay 接受
//!   handoff → 控制 lookup/spawn/wait/discard 的全链路。spawn 以 /bin/sh 充当 --exec
//!   目标本体（argv[0] 必须等于 --exec 路径），证明 FD 3（secret）/FD 4（config）
//!   注入与缺席语义；退出码经 wait 指令上报（R2 修复轮 9.2 直执行形态）。
#[cfg(target_os = "linux")]
use std::io::{BufRead, Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "linux")]
struct RelayChild {
    process: std::process::Child,
    control_socket: PathBuf,
    #[allow(dead_code)]
    fd_socket: PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for RelayChild {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_file(&self.control_socket);
    }
}

fn temp_socket_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iweb-relay-it-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create relay it dir");
    dir
}

#[cfg(target_os = "linux")]
fn start_relay(label: &str, kernel_peer: iweb_kernel::wasm_snapshot_fd::SnapshotSocketPeer, exec: &str) -> RelayChild {
    let dir = temp_socket_dir(label);
    let fd_socket = dir.join("snapshot-fd.sock");
    let control_socket = dir.join("relay-control.sock");
    let mut process = Command::new(env!("CARGO_BIN_EXE_snapshot-fd-relay"))
        .arg("--fd-socket")
        .arg(&fd_socket)
        .arg("--control-socket")
        .arg(&control_socket)
        .arg("--kernel-peer-uid")
        .arg(kernel_peer.uid.to_string())
        .arg("--kernel-peer-gid")
        .arg(kernel_peer.gid.to_string())
        .arg("--exec")
        .arg(exec)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the relay binary");
    // 控制就绪探测：绑定完成即可连接（有限重试）。
    for _ in 0..100 {
        if control_socket.exists() {
            return RelayChild { process, control_socket, fd_socket };
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = process.kill();
    panic!("relay did not bind its control socket in time");
}

#[cfg(target_os = "linux")]
struct ExecutionRelay {
	relay: RelayChild,
	public_socket: PathBuf,
	upstream_socket: PathBuf,
}

#[cfg(target_os = "linux")]
fn start_execution_relay(label: &str, kernel_peer: iweb_kernel::wasm_snapshot_fd::SnapshotSocketPeer) -> ExecutionRelay {
	let dir = temp_socket_dir(label);
	let directory = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).expect("temporary directory is NUL-free");
	assert_eq!(unsafe { libc::chmod(directory.as_ptr(), 0o700) }, 0, "execution relay parent must be 0700");
	let fd_socket = dir.join("snapshot-fd.sock");
	let control_socket = dir.join("relay-control.sock");
	let public_socket = dir.join("supervisor.sock");
	let upstream_socket = dir.join("supervisor-internal.sock");
	let token = "a".repeat(64);
	let mut process = Command::new(env!("CARGO_BIN_EXE_snapshot-fd-relay"))
		.arg("--fd-socket")
		.arg(&fd_socket)
		.arg("--control-socket")
		.arg(&control_socket)
		.arg("--kernel-peer-uid")
		.arg(kernel_peer.uid.to_string())
		.arg("--kernel-peer-gid")
		.arg(kernel_peer.gid.to_string())
		.arg("--exec")
		.arg("/bin/true")
		.arg("--execution-socket")
		.arg(&public_socket)
		.arg("--execution-upstream")
		.arg(&upstream_socket)
		.arg("--execution-upstream-token")
		.arg(token)
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()
		.expect("spawn relay with execution HTTP front-end");
	for _ in 0..100 {
		if control_socket.exists() && public_socket.exists() {
			return ExecutionRelay {
				relay: RelayChild { process, control_socket, fd_socket },
				public_socket,
				upstream_socket,
			};
		}
		std::thread::sleep(std::time::Duration::from_millis(20));
	}
	let _ = process.kill();
	panic!("execution relay did not bind its public socket in time");
}

#[cfg(target_os = "linux")]
fn control_round_trip(socket: &Path, request: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).expect("connect the relay control socket");
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).expect("set control read timeout");
    writeln!(stream, "{request}").expect("write control request");
    stream.flush().expect("flush control request");
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).expect("read control response");
    serde_json::from_str(line.trim()).expect("control response is JSON")
}

#[cfg(target_os = "linux")]
fn current_peer() -> iweb_kernel::wasm_snapshot_fd::SnapshotSocketPeer {
    iweb_kernel::wasm_snapshot_fd::SnapshotSocketPeer {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_hosts_fail_closed_on_the_seqpacket_listener() {
    let dir = temp_socket_dir("macos-failclosed");
    let output = Command::new(env!("CARGO_BIN_EXE_snapshot-fd-relay"))
        .arg("--fd-socket")
        .arg(dir.join("snapshot-fd.sock"))
        .arg("--control-socket")
        .arg(dir.join("relay-control.sock"))
        .output()
        .expect("run the relay binary");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!output.status.success(), "the relay must not serve without SOCK_SEQPACKET");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(iweb_kernel::wasm_snapshot_fd::SNAPSHOT_TRANSPORT_UNAVAILABLE),
        "the fail-closed exit must name SNAPSHOT_TRANSPORT_UNAVAILABLE: {stderr}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn the_relay_reclaims_stale_socket_files_left_by_a_crashed_predecessor() {
    // 恢复语义回归：supervisor/relay 崩溃（SIGKILL）残留的 socket 文件不得让重启永久
    // EADDRINUSE——journal replay 依赖 restart 可达（对位 server.ts 的 rmSync(force) 约定）。
    let peer = current_peer();
    let relay = start_relay("stale-reclaim", peer, "/bin/true");
    let control_socket = relay.control_socket.clone();
    let fd_socket = relay.fd_socket.clone();
    // 模拟崩溃：SIGKILL（不经 Drop 清理），socket 文件残留。
    relay.process.kill().expect("kill the first relay");
    let _ = relay.process.wait();
    assert!(control_socket.exists(), "a SIGKILLed relay leaves its control socket file behind");
    assert!(fd_socket.exists(), "a SIGKILLed relay leaves its fd socket file behind");
    // 第二次启动（同一路径）必须成功绑定并应答控制请求。
    let second = start_relay("stale-reclaim", peer, "/bin/true");
    let lookup = control_round_trip(&second.control_socket, "{\"op\":\"lookup\",\"commandId\":\"018f1e2c-3d4b-7a5e-9f01-23456789abcd\"}");
    assert_eq!(lookup["ok"], serde_json::json!(true));
    assert_eq!(lookup["secret"], serde_json::json!(null));
    // 第一代的 Drop 会清理 second 的 socket；fd_socket 断言已在前完成。
}

#[test]
#[cfg(target_os = "linux")]
fn control_socket_answers_lookup_and_discard_without_handoffs() {
    let relay = start_relay("control-idle", current_peer(), "/bin/true");
    let lookup = control_round_trip(&relay.control_socket, "{\"op\":\"lookup\",\"commandId\":\"018f1e2c-3d4b-7a5e-9f01-23456789abcd\"}");
    assert_eq!(lookup["ok"], serde_json::json!(true));
    assert_eq!(lookup["secret"], serde_json::json!(null));
    assert_eq!(lookup["config"], serde_json::json!(null));
    let discard = control_round_trip(&relay.control_socket, "{\"op\":\"discard\",\"commandId\":\"018f1e2c-3d4b-7a5e-9f01-23456789abcd\"}");
    assert_eq!(discard, serde_json::json!({"ok": true, "dropped": 0}));
    let invalid = control_round_trip(&relay.control_socket, "{\"op\":\"explode\"}");
    assert_eq!(invalid["ok"], serde_json::json!(false));
    assert_eq!(invalid["code"], serde_json::json!("SNAPSHOT_CONTROL_REQUEST_INVALID"));
    let missing_spawn = control_round_trip(&relay.control_socket, "{\"op\":\"spawn\",\"commandId\":\"018f1e2c-3d4b-7a5e-9f01-23456789abcd\",\"execArgv\":[\"/bin/true\"]}");
    assert_eq!(missing_spawn["ok"], serde_json::json!(false));
    assert_eq!(missing_spawn["code"], serde_json::json!("SNAPSHOT_HANDOFF_MISSING"));
}

#[test]
#[cfg(target_os = "linux")]
fn execution_http_relay_forwards_only_peer_credentialed_connections() {
	let peer = current_peer();
	let execution = start_execution_relay("execution-http-positive", peer);
	let upstream = std::os::unix::net::UnixListener::bind(&execution.upstream_socket).expect("bind private Node upstream stand-in");
	let upstream_thread = std::thread::spawn(move || {
		let (mut stream, _) = upstream.accept().expect("relay must be the only upstream client");
		let mut request = [0u8; 4096];
		let read = stream.read(&mut request).expect("read relayed request");
		let request = std::str::from_utf8(&request[..read]).expect("relayed HTTP is utf8");
		assert!(request.contains("x-iweb-relay-authorization: "), "relay must inject its private upstream credential");
		stream
			.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			.expect("write upstream response");
	});
	let mut client = UnixStream::connect(&execution.public_socket).expect("connect Kernel-facing execution socket");
	client.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("set client timeout");
	client
		.write_all(b"GET /v1/health HTTP/1.1\r\nHost: iweb-supervisor\r\nConnection: close\r\n\r\n")
		.expect("write HTTP request");
	let mut response = String::new();
	client.read_to_string(&mut response).expect("read relayed response");
	assert!(response.starts_with("HTTP/1.1 200 OK"));
	upstream_thread.join().expect("upstream thread must complete");

	// Same listener shape with a mismatched expected Kernel UID: the current
	// process reaches the socket but SO_PEERCRED fails before an HTTP header is
	// forwarded to the private Node upstream.
	let wrong_uid = if peer.uid == u32::MAX { peer.uid - 1 } else { peer.uid + 1 };
	let wrong = iweb_kernel::wasm_snapshot_fd::SnapshotSocketPeer { uid: wrong_uid, gid: peer.gid };
	let rejected = start_execution_relay("execution-http-negative", wrong);
	let upstream = std::os::unix::net::UnixListener::bind(&rejected.upstream_socket).expect("bind negative private upstream stand-in");
	upstream.set_nonblocking(true).expect("make negative upstream listener nonblocking");
	let mut client = UnixStream::connect(&rejected.public_socket).expect("connect rejected public socket");
	client.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("set rejected client timeout");
	client.write_all(b"GET /v1/health HTTP/1.1\r\nHost: iweb-supervisor\r\n\r\n").expect("write rejected HTTP request");
	let mut byte = [0u8; 1];
	let rejected_read = client.read(&mut byte);
	assert!(matches!(rejected_read, Ok(0) | Err(_)), "a rejected peer receives no HTTP response");
	for _ in 0..10 {
		if upstream.accept().is_ok() {
			panic!("a wrong SO_PEERCRED peer must not reach the private upstream");
		}
		std::thread::sleep(std::time::Duration::from_millis(20));
	}
}

#[cfg(target_os = "linux")]
mod linux_end_to_end {
    use super::*;
    use iweb_kernel::wasm_snapshot_fd::{
        compute_snapshot_fd_digest,
        connect_snapshot_socket,
        deliver_snapshot_handoff,
        receive_snapshot_ack,
        send_snapshot_frame_with_descriptor,
        ConfigSnapshotFdHandoffV1,
        SecretSnapshotFdHandoffV1,
        SnapshotDeliveryOutcome,
        SnapshotFrameKind,
        SnapshotHandoffDelivery,
        SnapshotHandoffPayload,
        SnapshotSocketPeer,
    };
    use std::os::fd::{AsFd, OwnedFd};

    fn snapshot_source(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write snapshot source");
        path
    }

    fn open_readonly(path: &Path) -> OwnedFd {
        iweb_kernel::wasm_snapshot_fd::open_snapshot_readonly(path).expect("open snapshot read-only")
    }

    fn secret_payload(command_id: &str, digest: &str) -> SecretSnapshotFdHandoffV1 {
        SecretSnapshotFdHandoffV1 {
            schema_version: 1,
            kind: "secret".to_string(),
            command_id: command_id.to_string(),
            command_digest: "1".repeat(64),
            reference: "5".repeat(64),
            application_id: "vector".to_string(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            secret_revision: 3,
            values_digest: digest.to_string(),
            fd_digest: digest.to_string(),
            expires_at: "2100-01-01T00:00:00Z".to_string(),
        }
    }

    fn config_payload(command_id: &str, digest: &str) -> ConfigSnapshotFdHandoffV1 {
        ConfigSnapshotFdHandoffV1 {
            schema_version: 1,
            kind: "config".to_string(),
            command_id: command_id.to_string(),
            command_digest: "1".repeat(64),
            reference: "7".repeat(64),
            application_id: "vector".to_string(),
            version_id: format!("{}-1", "a".repeat(64)),
            preparation_generation: 1,
            config_revision: 2,
            values_digest: digest.to_string(),
            fd_digest: digest.to_string(),
            expires_at: "2100-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn kernel_handoff_reaches_the_table_and_spawn_injects_fd3_and_fd4() {
        let peer = current_peer();
        // --exec 目标 = /bin/sh（测试目标本体；argv[0] 必须等于 --exec 路径）：
        // argv 读 FD3/FD4 内容写文件并退出 0。
        let out_dir = temp_socket_dir("e2e-out");
        let relay = start_relay("e2e", peer, "/bin/sh");
        let command_id = "018f1e2c-3d4b-7a5e-9f01-23456789abcd";

        // 母目录 mode 0700 + 属主为本用户（Kernel connect 前置检查要求；relay 子进程同 UID）。
        let source_dir = relay.fd_socket.parent().expect("fd socket parent").to_path_buf();
        let c_dir = std::ffi::CString::new(source_dir.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            libc::chmod(c_dir.as_ptr(), 0o700);
        }

        let secret_bytes = b"{\"secret\":\"bytes\"}".to_vec();
        let config_bytes = b"{\"config\":\"bytes\"}".to_vec();
        let secret_digest = compute_snapshot_fd_digest(SnapshotFrameKind::SecretRequest, &secret_bytes).unwrap();
        let config_digest = compute_snapshot_fd_digest(SnapshotFrameKind::ConfigRequest, &config_bytes).unwrap();
        let secret_source = snapshot_source(&source_dir, "secret.json", &secret_bytes);
        let config_source = snapshot_source(&source_dir, "config.json", &config_bytes);

        // Kernel 半边：connect（含路径/inode/mode/凭据复查）→ 单 sendmsg(secret) → ack。
        let secret_sock = connect_snapshot_socket(&relay.fd_socket, &peer).expect("kernel connect to the relay fd socket");
        let secret_payload = SnapshotHandoffPayload::Secret(secret_payload(command_id, &secret_digest));
        let frame = secret_payload.encode_frame().unwrap();
        let secret_fd = open_readonly(&secret_source);
        send_snapshot_frame_with_descriptor(secret_sock.as_fd(), &frame, secret_fd.as_fd()).expect("send the secret frame");
        let secret_ack = receive_snapshot_ack(secret_sock.as_fd(), &secret_payload).expect("receive the secret ack");
        assert_eq!(secret_ack.status, iweb_kernel::wasm_snapshot_fd::SnapshotAckStatus::Accepted, "{:?} / {:?}", secret_ack.failure_code, secret_ack.journal_revision);
        drop(secret_sock);

        let config_sock = connect_snapshot_socket(&relay.fd_socket, &peer).expect("kernel reconnect for the config frame");
        let config_payload = SnapshotHandoffPayload::Config(config_payload(command_id, &config_digest));
        let config_frame = config_payload.encode_frame().unwrap();
        let config_fd = open_readonly(&config_source);
        send_snapshot_frame_with_descriptor(config_sock.as_fd(), &config_frame, config_fd.as_fd()).expect("send the config frame");
        let config_ack = receive_snapshot_ack(config_sock.as_fd(), &config_payload).expect("receive the config ack");
        assert_eq!(config_ack.status, iweb_kernel::wasm_snapshot_fd::SnapshotAckStatus::Accepted);
        drop(config_sock);

        // supervisor 半边：lookup 复核（fd 字节 + 摘要链字段可见）。
        let lookup = control_round_trip(&relay.control_socket, &format!("{{\"op\":\"lookup\",\"commandId\":\"{command_id}\"}}"));
        assert_eq!(lookup["secret"]["valuesDigest"], serde_json::json!(secret_digest));
        assert_eq!(lookup["config"]["valuesDigest"], serde_json::json!(config_digest));
        assert_eq!(lookup["secret"]["descriptorReadOnly"], serde_json::json!(true));

        // spawn：sh 读 FD3/FD4 写出到文件（证明注入槽位）；立即返回 pid，退出码经 wait。
        let out3 = out_dir.join("fd3.out");
        let out4 = out_dir.join("fd4.out");
        let script = format!("cat <&3 > {}; cat <&4 > {}", out3.display(), out4.display());
        let spawn = control_round_trip(
            &relay.control_socket,
            &format!("{{\"op\":\"spawn\",\"commandId\":\"{command_id}\",\"execArgv\":[\"/bin/sh\",\"-c\",{:?}]}}", script),
        );
        assert_eq!(spawn["ok"], serde_json::json!(true), "{spawn}");
        let pid = spawn["pid"].as_i64().expect("spawn reports the child pid");
        assert!(pid > 0, "{spawn}");
        let exit = control_round_trip(
            &relay.control_socket,
            &format!("{{\"op\":\"wait\",\"commandId\":\"{command_id}\",\"timeoutMs\":10000}}"),
        );
        assert_eq!(exit["ok"], serde_json::json!(true), "{exit}");
        assert_eq!(exit["pid"], serde_json::json!(pid), "{exit}");
        assert_eq!(exit["running"], serde_json::json!(false), "{exit}");
        assert_eq!(exit["exitCode"], serde_json::json!(0), "{exit}");
        assert_eq!(std::fs::read(&out3).unwrap(), secret_bytes, "fd 3 must carry the secret snapshot bytes");
        assert_eq!(std::fs::read(&out4).unwrap(), config_bytes, "fd 4 must carry the config snapshot bytes");

        // 成功 spawn 后台账被消费。
        let after = control_round_trip(&relay.control_socket, &format!("{{\"op\":\"lookup\",\"commandId\":\"{command_id}\"}}"));
        assert_eq!(after["secret"], serde_json::json!(null));
        let _ = std::fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn digest_mismatch_is_rejected_with_values_digest_mismatch() {
        let peer = current_peer();
        let relay = start_relay("digest-mismatch", peer, "/bin/true");
        let command_id = "018f1e2c-3d4b-7a5e-9f01-23456789bcde";
        let source_dir = relay.fd_socket.parent().expect("fd socket parent").to_path_buf();
        let c_dir = std::ffi::CString::new(source_dir.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            libc::chmod(c_dir.as_ptr(), 0o700);
        }
        let secret_bytes = b"real-bytes".to_vec();
        let wrong_digest = "0".repeat(64);
        let source = snapshot_source(&source_dir, "secret-mismatch.json", &secret_bytes);
        let payload = SnapshotHandoffPayload::Secret(secret_payload(command_id, &wrong_digest));
        let delivery = SnapshotHandoffDelivery {
            socket_path: &relay.fd_socket,
            expected_owner: peer,
            handoff: payload.clone(),
            snapshot_path: &source,
        };
        match deliver_snapshot_handoff(&delivery).expect("delivery transport must complete") {
            SnapshotDeliveryOutcome::RejectedBySupervisor(ack) => {
                assert_eq!(ack.failure_code.as_deref(), Some("SNAPSHOT_VALUES_DIGEST_MISMATCH"));
            }
            other => panic!("a digest mismatch must be rejected, got {other:?}"),
        }
        let lookup = control_round_trip(&relay.control_socket, &format!("{{\"op\":\"lookup\",\"commandId\":\"{command_id}\"}}"));
        assert_eq!(lookup["secret"], serde_json::json!(null), "a rejected handoff retains no descriptor");
    }
}
