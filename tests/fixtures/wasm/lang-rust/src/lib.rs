// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x）：Rust 一级参考语言的最小
// wasi:http@0.2.8 proxy world 组件——导出 incoming-handler，恒定返回 200 文本。
// 正交意图：唯一意图是「健康探针级 handler」；不读请求、不出网、不碰 stdio。
//
// 两个实证钉死的工具链事实（2026-08-26）：
// 1. wit-bindgen 0.57 要求未被实现直接使用的 world import 显式 `with` 映射；
//    导出 interface 的 Guest trait 位于 `exports::` 前缀下。
// 2. Rust std（1.90）会拉入 wasi_snapshot_preview1 适配层（fd_write/environ_get/
//    proc_exit），把 wasi:cli/{environment,exit}@0.2.3 与 wasi:filesystem@0.2.3 混入
//    组件 import 闭包——全部在 revision-1 能力矩阵之外。因此本 fixture 是 no_std
//    cdylib：组件 import 闭包收敛到 wasi:http/types + wasi:io/{streams,error}@0.2.8。
#![no_std]

wit_bindgen::generate!({
    world: "proxy",
    path: "wit",
    with: {
        "wasi:http/types@0.2.8": generate,
        "wasi:http/outgoing-handler@0.2.8": generate,
        "wasi:io/streams@0.2.8": generate,
        "wasi:io/error@0.2.8": generate,
        "wasi:io/poll@0.2.8": generate,
        "wasi:clocks/monotonic-clock@0.2.8": generate,
        "wasi:clocks/wall-clock@0.2.8": generate,
        "wasi:random/random@0.2.8": generate,
        "wasi:cli/stdin@0.2.8": generate,
        "wasi:cli/stdout@0.2.8": generate,
        "wasi:cli/stderr@0.2.8": generate,
    },
});

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, OutgoingBody, OutgoingResponse, ResponseOutparam};

/// 每语言 fixture 的响应体刻意互异，保证三者 packageDigest 必然不同。
const BODY: &[u8] = b"iweb lang-rust wasi-http proxy fixture\n";

/// no_std panic：fixture 永不 panic；若发生则停机（不引入 wasi:cli/exit）。
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

/// 极简 bump 分配器：仅满足 wit-bindgen canonical ABI 的 scratch 分配。
/// 组件生命周期内只增不减，无碎片问题；fixture 响应体是常量，实际分配近零。
extern crate alloc as alloc_crate;

mod bump_alloc {
    use alloc_crate::alloc::{GlobalAlloc, Layout};

    static mut HEAP: [u8; 4096] = [0; 4096];
    static mut OFFSET: usize = 0;

    pub struct Bump;

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe {
                let base = HEAP.as_ptr() as usize;
                let mut current = OFFSET;
                let aligned = (base + current + layout.align() - 1) & !(layout.align() - 1);
                let next = aligned - base + layout.size();
                if next > HEAP.len() {
                    return core::ptr::null_mut();
                }
                OFFSET = next;
                aligned as *mut u8
            }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }
}

#[global_allocator]
static ALLOC: bump_alloc::Bump = bump_alloc::Bump;

/// canonical ABI 的 cabi_realloc：no_std 关闭 wit-bindgen std 特性后需自行导出。
/// bump 分配器语义：分配新块、拷贝旧内容；旧块不回收（fixture 生命周期内分配近零）。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_realloc(
    old_ptr: *mut u8,
    old_size: usize,
    old_align: usize,
    new_size: usize,
) -> *mut u8 {
    unsafe {
        if new_size == 0 {
            return old_ptr;
        }
        let layout = alloc_crate::alloc::Layout::from_size_align(new_size, old_align.max(1)).unwrap();
        let new_ptr = alloc_crate::alloc::alloc(layout);
        if new_ptr.is_null() {
            core::arch::wasm32::unreachable();
        }
        if !old_ptr.is_null() && old_size > 0 {
            core::ptr::copy_nonoverlapping(old_ptr, new_ptr, old_size.min(new_size));
        }
        new_ptr
    }
}

struct ProxyFixture;

impl Guest for ProxyFixture {
    fn handle(
        _request: wasi::http::types::IncomingRequest,
        response_out: wasi::http::types::ResponseOutparam,
    ) {
        let response = OutgoingResponse::new(Fields::new());
        response.set_status_code(200).ok();
        let body = response.body().expect("body can be taken exactly once");
        ResponseOutparam::set(response_out, Ok(response));
        let stream = body.write().expect("stream can be taken exactly once");
        stream
            .blocking_write_and_flush(BODY)
            .expect("fixture body write must succeed");
        drop(stream);
        OutgoingBody::finish(body, None).expect("fixture response must finish cleanly");
    }
}

export!(ProxyFixture);
