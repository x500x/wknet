# HTTP/1.1 协议 / HTTP/1.1 Protocol

命名空间 `KernelHttp::http`。客户端 HTTP/1.1 的请求构建、响应解析、内容/传输编码解码。

[English](#english) | 简体中文

---

## 简体中文

### 基础类型（`http/HttpTypes.h`）

```cpp
struct HttpText   { const char* Data; SIZE_T Length; };
struct HttpHeader { HttpText Name; HttpText Value; };
HttpText MakeText(const char*);
bool TextEqualsIgnoreCase(HttpText, HttpText);
bool HeaderValueHasToken(HttpText value, HttpText token);
```
同文件还定义堆内存基元：`HeapArray<T>`、`HeapObject<T>` 及非分页池分配器（见 [内存模型](memory-model.md)）。

### 请求构建（`http/HttpRequest.h`）

```cpp
enum class HttpMethod { Get, Post, Put, DeleteMethod, Head, Options, Patch, Custom };
enum class HttpConnectionDirective { Omit, KeepAlive, Close, Upgrade };
enum class HttpRequestBodyMode { ContentLength, Chunked };

struct HttpRequestBuildOptions {
    HttpMethod Method; HttpText CustomMethod, Path, Host, UserAgent, ContentType;
    HttpConnectionDirective Connection;
    const HttpHeader* ExtraHeaders; SIZE_T ExtraHeaderCount;
    const char* Body; SIZE_T BodyLength;
    bool IncludeContentLength; HttpRequestBodyMode BodyMode;
};
class HttpRequestBuilder {  // 静态
    static NTSTATUS Build(const HttpRequestBuildOptions&, char* dest, SIZE_T cap, SIZE_T* written);
};
```

### 响应模型（`http/HttpResponse.h`）

```cpp
enum class HttpBodyKind { None, ContentLength, Chunked, CloseDelimited };
struct HttpResponse {
    USHORT MajorVersion, MinorVersion, StatusCode;
    HttpText ReasonPhrase;
    HttpHeader* Headers; SIZE_T HeaderCount;
    HttpHeader* Trailers; SIZE_T TrailerCount;
    const char* Body; SIZE_T BodyLength;
    HttpBodyKind BodyKind; bool BodyEndsOnConnectionClose; SIZE_T BytesConsumed;
    bool FindHeader(HttpText name, const HttpHeader**) const;
    bool HasHeaderValueToken(HttpText name, HttpText token) const;
    bool HasConnectionClose() / HasConnectionKeepAlive() / HasChunkedTransferEncoding() const;
};
```

### 响应解析（`http/HttpParser.h`）

```cpp
class HttpParser {  // 静态
    static NTSTATUS ParseResponse(const char* data, SIZE_T len, const HttpParseOptions&, HttpResponse&);
    static NTSTATUS DecodeChunkedBody(...);
    static NTSTATUS DecodeChunkedBodyWithTrailers(... HttpHeader* trailers, SIZE_T trailerCap ...);
};
```
`HttpParseOptions` 提供 headers/trailers/decodedBody/scratchBody 缓冲及 `MessageCompleteOnConnectionClose`、`ResponseBodyForbidden`（用于 HEAD/无 body 状态码）。

### 内容编码（`http/HttpContentEncoding.h` + `http/HttpCoding.h`）

```cpp
enum class HttpCoding { Identity, Gzip, Deflate, Brotli, Compress };
class HttpContentEncoding {
    static NTSTATUS Decode(const HttpHeader* headers, SIZE_T count,
                           const char* body, SIZE_T len,
                           const HttpContentDecodeBuffers&, HttpContentDecodeResult&);
};
```
按 `Content-Encoding` 头解码，多重编码按反序解码（`HttpCodingCodec::DecodeChainReverse`）。`br`（Brotli）仅作为 Content-Encoding 支持；`HttpCodingCodec::DeflateRuntimeAvailable()` 报告 deflate 运行时可用性。

### 传输编码（`http/HttpTransferCoding.h`）

```cpp
constexpr SIZE_T HttpMaxTransferCodings = 4;
enum class HttpTransferCodingKind { Chunked, Gzip, Deflate, Compress };  // 无 Brotli
class HttpTransferCoding {
    static NTSTATUS Parse(const HttpHeader*, SIZE_T, HttpTransferCodingInfo&);
    static NTSTATUS DecodeResponseBody(const HttpTransferCodingInfo&, const char* wireBody, SIZE_T,
                                       bool messageCompleteOnClose, const HttpCodingDecodeBuffers&,
                                       HttpHeader* trailers, SIZE_T trailerCap, SIZE_T* trailerCount,
                                       HttpTransferDecodeResult&);
};
```
响应 `Transfer-Encoding` 链最多 4 级（如 `gzip, chunked`），先 de-chunk 再反序解 gzip/deflate/compress；记录 `FinalCodingIsChunked`。

### 行为要点

- 请求体支持 `Content-Length` 或显式 chunked（`BodyMode`）；**用户手设请求 `Transfer-Encoding` 会被拒绝**，无 request trailer。
- 响应支持 close-delimited、HEAD/101/无 body 状态码、中间 1xx 跳过。
- chunked trailer 做语法/禁止字段校验并以只读 API 暴露。
- 限制：单头行 8192、头总 64 KiB、头数 200、chunk 数 8192、trailer 256（见 [配置项](configuration.md)）。
- 非目标：proxy/CONNECT/TRACE、管线化、`Expect: 100-continue`、流式上传、obs-fold（拒绝而非规范化）。

---

## English

Namespace `KernelHttp::http`. Core types `HttpText`/`HttpHeader`; request building via `HttpRequestBuilder::Build` from `HttpRequestBuildOptions`; response model `HttpResponse` with `HttpBodyKind` and header/trailer accessors; parsing via `HttpParser::ParseResponse` / `DecodeChunkedBody[WithTrailers]`.

Content decoding (`HttpContentEncoding::Decode`) handles `Content-Encoding` gzip/deflate/br/compress/identity, decoding multiple codings in reverse (`HttpCodingCodec::DecodeChainReverse`); `br` is Content-Encoding only. Transfer decoding (`HttpTransferCoding`) handles `Transfer-Encoding` chains up to 4 (Chunked/Gzip/Deflate/Compress — no Brotli), de-chunking then reverse-decoding.

Bodies use Content-Length or explicit chunked; user-set request `Transfer-Encoding` is rejected; no request trailers. Responses support close-delimited, HEAD/101/no-body, 1xx skipping, and read-only chunked trailers. Limits: 8192-byte header line, 64 KiB header section, 200 headers, 8192 chunks, 256 trailers. Non-goals: proxy/CONNECT/TRACE, pipelining, `Expect: 100-continue`, streaming upload, obs-fold (rejected).
