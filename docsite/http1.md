# HTTP/1.1 协议

### 基础类型（`HttpTypes`）

```cpp
struct HttpText   { const char* Data; SIZE_T Length; };
struct HttpHeader { HttpText Name; HttpText Value; };
```
同处定义堆基元 `HeapArray<T>` / `HeapObject<T>` 与非分页池分配器（见 [内存模型](memory-model.md)）。

### 请求构建（`HttpRequestBuilder::Build`）

序列化 `METHOD SP target SP HTTP/1.1\r\n` + 头 + `\r\n` + body。要点：
- 用测长 `BufferWriter`，目标缓冲不足返回 `STATUS_BUFFER_TOO_SMALL` 并写出所需长度。
- **Host 头总是首先发出**（值来自 `options.Host`，不自动推导）；随后按固定序 User-Agent、Content-Type、body 框定头、Connection、调用方额外头。
- 方法枚举包含 CONNECT，可构建 `CONNECT authority HTTP/1.1` 请求；TRACE 不支持。
- body：`ContentLength` 模式发 `Content-Length`（`IncludeContentLength` 可让 0 长 body 也发 `Content-Length: 0`）；`Chunked` 模式发 `Transfer-Encoding: chunked` 并按 `hex\r\n data \r\n ... 0\r\n` 串行化，随后写出请求 trailer（若有）再以 `\r\n` 收尾。
- **请求 trailer**：仅在 `Chunked` 且确有 chunked 框定（有 body 或 `IncludeContentLength`）时可用，经 `options.Trailers/TrailerCount` 提供；字段名须为合法 token，**禁止 trailer 字段** `Content-Length`/`Transfer-Encoding`/`Host`/`Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie` → `STATUS_NOT_SUPPORTED`；公共 API 为 `KhHttpRequestAddTrailer` / `khttp::RequestAddTrailer`。
- **禁止的额外头**：`Host`/`Content-Length`/`Connection` → `STATUS_INVALID_PARAMETER`；`Transfer-Encoding`/`TE` → `STATUS_NOT_SUPPORTED`；`Trailer` 头仅在 chunked 框定下允许（否则 `STATUS_NOT_SUPPORTED`）；`Expect: 100-continue` 且有 body → `STATUS_NOT_SUPPORTED`。
- 引擎层在无 `Accept-Encoding` 时注入默认 `gzip, deflate, br, identity`（deflate 运行时不可用则 `br, identity`）。

### 响应解析（`HttpParser::ParseResponse`）

- 需完整头块（`\r\n\r\n`），否则 `STATUS_MORE_PROCESSING_REQUIRED`；头块 >64 KiB → `STATUS_INVALID_NETWORK_RESPONSE`。
- 状态行：必须 `HTTP/`、`<major>.<minor>`，**仅接受 major==1 且 minor<=1**；状态码恰 3 位、100..599。
- 头：每行 ≤8 KiB；**拒绝 obs-fold**（行首 SP/TAB）；名须为 token；值拒绝 <0x20（除 TAB）与 0x7f（允许高位字节）；头数 ≥200 → `STATUS_BUFFER_TOO_SMALL`。
- body 框定：
  - **无 body**：`ResponseBodyForbidden`（HEAD）或状态属 1xx/204/**205**/304。
  - 多个 `Content-Length` 或 `TE`+`CL` 冲突 → `STATUS_INVALID_NETWORK_RESPONSE`。
  - chunked/TE 链 → `HttpTransferCoding::DecodeResponseBody`。
  - Content-Length 路径：不足 → `STATUS_MORE_PROCESSING_REQUIRED`。
  - close-delimited：仅当 `MessageCompleteOnConnectionClose` 且无 CL/TE。
- `206 Partial Content` 可用 `HttpResponse::IsPartialContent` 判断；`GetContentRange` 只读解析 `Content-Range: bytes ...`，不会影响 body 框定。

### chunked 解码

块数 ≤8192、chunk-size 行 ≤32；严格 chunk 扩展语法（`;name[=value|quoted]`）；终止块后解析 trailer：每行 ≤8 KiB、trailer 数 ≤256；**禁止 trailer 字段**：`Content-Length`/`Transfer-Encoding`/`Host`/`Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie` → `STATUS_INVALID_NETWORK_RESPONSE`。

### 内容编码 `Content-Encoding`（`HttpContentEncoding` + `HttpCoding`）

| coding | 实现要点 |
|--------|---------|
| `gzip` | RFC1952 头解析，校验头 CRC16、尾 CRC32、ISIZE |
| `deflate` | 自动识别 zlib 包装并校验 **Adler-32**；裸 DEFLATE 用内核 `RtlDecompressBufferEx`，附运行时探测 `DeflateRuntimeAvailable` |
| `br` | 内置 Brotli 解码 |
| `compress` | 完整 LZW（`.Z`，9–16 bit，block 模式） |
| `identity` | 跳过 |

- 链最多 **2 级**（>2 → `STATUS_NOT_SUPPORTED`），按**反序**解码。
- **解压炸弹防护**：decoded aggregate 跟随响应/调用方容量，单级膨胀比 ≤64（`MaxDecodeExpansionRatio`），超限 → `STATUS_INVALID_NETWORK_RESPONSE`。
- 未知 coding → `STATUS_NOT_SUPPORTED`。

### 传输编码 `Transfer-Encoding`（`HttpTransferCoding`）

- 识别 `chunked`/`gzip`/`deflate`/`compress`，最多 4 级；`identity` → `STATUS_INVALID_NETWORK_RESPONSE`；**`br` → `STATUS_NOT_SUPPORTED`**；带参数 token → 非法；重复 `chunked` → 非法。
- 反序解码，仅最外层 chunked 收 trailer；非最外 chunked 未吃完输入 → 非法。
