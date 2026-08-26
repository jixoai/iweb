// 用户原始需求（2026-08-26，add-wasm-runtime 任务 8.x）：MoonBit 一级参考语言的最小
// wasi:http@0.2.8 proxy world 组件——导出 incoming-handler，恒定返回 200 文本。
// 正交意图：唯一意图是「健康探针级 handler」；不读请求、不出网、不碰 stdio。
//
// 放置约定：wit-bindgen moonbit 的 stub `top.mbt`（declare pub fn handle）由
// build.sh.ts 每次重新生成；本文件是唯一手写实现，构建时拷入
// gen/interface/wasi/http/incomingHandler/ 与 declare 同包链接。
// 工具链钉死：moon 0.1.20260824（dae026a）+ wit-bindgen-cli 0.57.1 + wasm-tools 1.258.0。

/// 每语言 fixture 的响应体刻意互异，保证三者 packageDigest 必然不同。
const BODY = "iweb lang-moonbit wasi-http proxy fixture\n"

/// 纯 ASCII 编码（响应体只含 ASCII）；不依赖外部编码库保证可复算。
/// moonc v0.10.10 实证：String 下标返回 Char，Char::to_int + Int::to_byte 为稳定内建。
fn ascii_bytes(text : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(text.length(), b'\x00')
  for i = 0; i < text.length(); i = i + 1 {
    out[i] = text[i].to_int().to_byte()
  }
  out
}

/// stub 声明的实现：构造 200 文本响应。Err 分支按 fixture 语义停机——
/// body 只被取一次、状态码恒合法，正常路径永不进入。
pub fn handle(_request : @types.IncomingRequest, response_out : @types.ResponseOutparam) -> Unit {
  let response = @types.OutgoingResponse::outgoing_response(@types.Fields::fields())
  match @types.OutgoingResponse::set_status_code(response, 200) {
    Ok(_) => ()
    Err(_) => abort("fixture status code must always be valid")
  }
  let body = match @types.OutgoingResponse::body(response) {
    Ok(body) => body
    Err(_) => abort("fixture body can be taken exactly once")
  }
  @types.ResponseOutparam::set(response_out, Ok(response))
  let stream = match @types.OutgoingBody::write(body) {
    Ok(stream) => stream
    Err(_) => abort("fixture stream can be taken exactly once")
  }
  match @streams.OutputStream::blocking_write_and_flush(stream, ascii_bytes(BODY)) {
    Ok(_) => ()
    Err(_) => abort("fixture body write must succeed")
  }
  match @types.OutgoingBody::finish(body, None) {
    Ok(_) => ()
    Err(_) => abort("fixture response must finish cleanly")
  }
}
