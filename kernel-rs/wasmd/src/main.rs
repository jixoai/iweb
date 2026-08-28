//! iweb-wasmd 二进制入口（add-wasm-runtime 任务 3.1-3.4）。
//! 启动序（全部 fail-closed，验证未通过不绑定 listener）：
//!   argv 解析 → snapshot FD 3/4 验证 → capability record 解析/pin 比对 →
//!   组件加载 + pre-instantiation（矩阵外 import 即拒） → listener 绑定 → 服务。
//!
//! 退出码语义（结构化；supervisor 侧归因，不打印任何秘密/请求内容）：
//! - 0：SIGTERM 优雅 drain 完成退出（含 deadline 强制退出——drained/forced-kill 的
//!   区分由 supervisor 的 DrainReceiptV1 承载，不靠退出码）；
//! - 64 (EX_USAGE)：argv fail-closed（未知标记/数量/地址文法）；
//! - 65 (EX_DATAERR)：身份/pin/record/FD digest 不匹配；
//! - 70 (EX_SOFTWARE)：内部错误（组件/引擎/listener）。
//!
//! Linux 真实双容器/SCM_RIGHTS FD 消费/Podman argv 属 5.x 实测（spec 条目
//! "Snapshot descriptors use an independent framed raw socket" 与 tasks 5.1/5.2/8.1）。

use iweb_wasmd::argv::parse_argv;
use iweb_wasmd::capability::NodeCapabilityRecordV1;
use iweb_wasmd::fd::consume_snapshot_slots;
use iweb_wasmd::gateway::GatewayEgress;
use iweb_wasmd::host::{spawn_epoch_ticker, WasmdEngine};
use iweb_wasmd::ingress::serve;
use iweb_wasmd::wire::WasmReadinessHealthV2;
use std::process::ExitCode;
use std::sync::Arc;

/// 65：数据级 fail-closed（pin/digest/record 不匹配）。
const EX_DATAERR: u8 = 65;
/// 70：内部错误。
const EX_SOFTWARE: u8 = 70;

/// 同步启动段（步骤 1-4）。必须先于 tokio runtime 构建执行：Linux 上 mio 的
/// epoll/eventfd 描述符会占用 fd 4 及以上槽位，若先建 runtime，configRevision:0
/// 时「fd 4 必须缺席」检查恒失败（远程真容器实证，add-wasm-runtime 5.x 验收缺陷 3）。
struct Prepared {
	invocation: iweb_wasmd::argv::WasmdInvocation,
	record: NodeCapabilityRecordV1,
	engine: Arc<WasmdEngine>,
	epoch_ticker: std::thread::JoinHandle<()>,
}

fn prepare() -> Result<Prepared, ExitCode> {
	// 1) 固定 argv 契约（supervisor 独占生成；未知参数 fail-closed）。
	let argv: Vec<String> = std::env::args().collect();
	let invocation = match parse_argv(&argv) {
		Ok(invocation) => invocation,
		Err(error) => {
			eprintln!("wasmd: {error}");
			return Err(ExitCode::from(64));
		}
	};

	// 2) snapshot FD 3/4（槽位/只读/regular/digest 复算 + 身份 tuple 绑定）。
	let snapshots = match consume_snapshot_slots(&invocation.identity) {
		Ok(slots) => slots,
		Err(error) => {
			eprintln!("wasmd: {error}");
			return Err(ExitCode::from(EX_DATAERR));
		}
	};

	// 3) capability record：结构/界/recordHash + capability pin 比对。
	let record_bytes = match std::fs::read(&invocation.capability_record_path) {
		Ok(bytes) => bytes,
		Err(error) => {
			eprintln!("wasmd: capability record read failed: {error}");
			return Err(ExitCode::from(EX_DATAERR));
		}
	};
	let record = match NodeCapabilityRecordV1::parse(&record_bytes) {
		Ok(record) => record,
		Err(error) => {
			eprintln!("wasmd: {error}");
			return Err(ExitCode::from(EX_DATAERR));
		}
	};
	if record.revision != invocation.identity.capability_record_revision
		|| record.record_hash != invocation.identity.capability_record_hash
	{
		eprintln!("wasmd: capability record pin mismatch (revision/recordHash differ from the identity tuple)");
		return Err(ExitCode::from(EX_DATAERR));
	}

	// 4) 组件加载 + pre-instantiation（矩阵外 import 在此失败；不绑定 listener）。
	let component_bytes = match std::fs::read(&invocation.component_path) {
		Ok(bytes) => bytes,
		Err(error) => {
			eprintln!("wasmd: component read failed: {error}");
			return Err(ExitCode::from(EX_SOFTWARE));
		}
	};
	let egress = Arc::new(GatewayEgress {
		gateway: invocation.gateway,
		http_limits: record.http.clone(),
		tls: GatewayEgress::production_tls(),
	});
	// 4b) host-service provider（argv@2 携带 host-services context 时；argv@1 恒 None）。
	// 数据目录固定派生自 /data/kernel/wasm-data/<applicationId>（design §3；无
	// caller path）。目录/权限/恢复扫描失败 → EX_DATAERR fail-closed，listener 不绑定。
	// P0-2：identity 用 argv@2 的 WasmdIdentityV2（含 applicationId）；context 与
	// identity 的 applicationId 相等交叉校验在 provider open 内执行（错绑即拒绝启动）。
	let host_services = match (&invocation.host_services, invocation.identity_v2.as_ref()) {
		(Some(context), Some(identity_v2)) => {
			match iweb_wasmd::host_services::HostServicesProvider::open(
				context,
				identity_v2,
				std::path::Path::new(iweb_wasmd::host_services::HOST_SERVICES_DATA_ROOT),
				iweb_wasmd::host_services::logging::ForwardingConfig::default(),
			) {
				Ok(provider) => Some(Arc::new(provider)),
				Err(error) => {
					eprintln!("wasmd: host-services provider open failed: {error}");
					return Err(ExitCode::from(EX_DATAERR));
				}
			}
		}
		(Some(_), None) => {
			eprintln!("wasmd: argv@2 must carry a V2 identity tuple (applicationId missing)");
			return Err(ExitCode::from(EX_DATAERR));
		}
		(None, _) => None,
	};
	let engine = match WasmdEngine::new(
		&component_bytes,
		&record,
		&invocation.binding,
		&invocation.architecture,
		invocation.resources.memory_bytes,
		snapshots,
		egress,
		host_services,
	) {
		Ok(engine) => engine,
		Err(error) => {
			eprintln!("wasmd: engine init failed: {error}");
			return Err(ExitCode::from(EX_SOFTWARE));
		}
	};
	let engine = Arc::new(engine);
	let epoch_ticker = spawn_epoch_ticker(engine.engine());
	Ok(Prepared { invocation, record, engine, epoch_ticker })
}

fn main() -> ExitCode {
	let prepared = match prepare() {
		Ok(prepared) => prepared,
		Err(code) => return code,
	};
	let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
		Ok(runtime) => runtime,
		Err(error) => {
			eprintln!("wasmd: tokio runtime init failed: {error}");
            return ExitCode::from(EX_SOFTWARE);
        }
    };
    runtime.block_on(async_main(prepared))
}

async fn async_main(prepared: Prepared) -> ExitCode {
	let Prepared { invocation, record, engine, epoch_ticker: _epoch_ticker } = prepared;

    // 5) 唯一 listener + health v2 端点。
    let health = WasmReadinessHealthV2::from_identity(&invocation.identity);
    let ingress = match serve(
        Arc::clone(&engine),
        health,
        invocation.listen,
        record.http.clone(),
    )
    .await
    {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("wasmd: {error}");
            return ExitCode::from(EX_SOFTWARE);
        }
    };

    // 启动完成（owner 可见的最小事实；无请求内容/无秘密）。
    eprintln!(
        "wasmd: serving sandbox={} version={} P={} E={} on {}",
        invocation.identity.sandbox_id,
        invocation.identity.version_id,
        invocation.identity.preparation_generation,
        invocation.identity.execution_generation,
        invocation.listen
    );

    // 6) SIGTERM → 优雅 drain（在飞至 drainDeadlineMs）→ 退出。
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            eprintln!("wasmd: signal handler init failed: {error}");
            return ExitCode::from(EX_SOFTWARE);
        }
    };
    let _ = sigterm.recv().await;
    let _drained = ingress.graceful_drain(record.drain_deadline_ms).await;
    ExitCode::SUCCESS
}
