# HTTP/WebSocket 协议完整性审计说明

## 结论

截至 2026-06-09，本轮整改已完成计划文档中的 Task 1-21。当前实现应描述为“面向 Windows kernel driver 的现代客户端协议子集”，覆盖 HTTP/1.1、HTTP/2、WebSocket、TLS 1.2/1.3、证书校验和 WSK TCP 主路径；它不应被宣传为完整 RFC optional 全量 HTTP/WebSocket/TLS/HTTP2 通用栈。

本轮已经修复审计中发现的高风险协议问题：redirect 敏感头泄露、非幂等请求错误重试、WebSocket 边界与协议错误关闭、WSK 超时/取消后的 socket 所有权、TLS 1.3 PSK/HRR/0-RTT 语义、HTTP/2/HPACK 严格性、证书校验的 unsupported 策略静默放行，以及 HTTP chunked trailer 校验。

仍保留的边界是明确的能力边界，而不是隐式兜底：chunked upload、trailer 暴露、proxy/CONNECT、WebSocket extensions/partial receive、TLS client cert、OCSP/CRL 完整实现、IDNA 规范化、HTTP/2 push/priority/full multiplexing 暂不作为当前内核主路径能力。

## 审计方法

- 本地代码审计：`include/`、`src/`、`tests/`、`docs/`。
- 并行子代理审计与实现：HTTP/1.1、高层 API、WebSocket、WSK、TLS、HTTP/2、HPACK、证书校验。
- 参考标准与成熟实现行为：RFC 9110、RFC 9112、RFC 6455、RFC 8446、RFC 5246、RFC 5280、RFC 9113、RFC 7541，以及 curl/libcurl WebSocket 与 redirect 策略、nghttp2、OpenSSL 分层思路。
- 内核环境复核：WSK socket 生命周期、IRQL、CNG/BCrypt PASSIVE_LEVEL、nonpaged pool 缓冲所有权、用户态测试替身与真实内核路径差异。

未运行项目禁止的 `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`。

## 已整改项

### HTTP/1.1 与高层 HTTP

- redirect `Location` 支持 RFC 3986 相对引用，包括相对 path、`..`、query-only、fragment、scheme-relative 和 absolute URL。
- redirect 方法改写按状态码收紧：301/302 默认只改写 POST，303 除 HEAD 外改写为 GET，307/308 保留原方法和 body。
- 跨源 redirect 默认清理 `Authorization`、`Cookie`、`Proxy-Authorization`，并默认拒绝 HTTPS 到 HTTP 降级。
- reused stale connection 自动重试只允许 safe/idempotent 方法，避免重放 POST/PUT/PATCH/DELETE。
- `MaxConnectionsPerHost` 已在连接池中按 host key 执行。
- chunked trailer 已做字段名、字段值与 forbidden trailer 校验，拒绝 framing/routing/auth 相关字段。
- 文档已明确 BodyCallback 当前是聚合/解码后一次回调，不是边收边流式。

### WebSocket

- client frame 编码增加 payload length 与 required size 溢出保护，拒绝超过 `2^63-1` 的长度。
- 入站 RSV、masked server frame、unknown opcode、非法控制帧、非最短长度等协议错误会发送 close code 1002 并终止连接状态。
- 输出容量不足的大帧返回 required length，并按 1009 语义关闭。
- 握手拒绝重复 `Sec-WebSocket-Accept`。
- subprotocol 请求按 token-list 校验。
- 支持 0 长度 text/binary/continuation。
- 出站 text 增加 UTF-8 校验。
- Pong 已通过接收结果暴露。

### WSK/TCP 与内核环境

- WSK connect/send/receive timeout、取消和 late completion 的 socket 所有权已明确，native socket 不再因清空指针而失去 close 路径。
- close exactly once 与 completion-owned cleanup 路径已收紧。
- 低层 `WebSocketClient`、`TlsConnection`、`Http2Connection` 的公开入口补充或文档化 `PASSIVE_LEVEL` 约束。
- WSK 传输仍保持项目方向：内核主路径不引入 WinHTTP、WinINet、SChannel。

### TLS 1.2/1.3

- TLS 1.3 ticket 记录并校验 issue time、lifetime、SNI、ALPN、cipher suite、version 与 ticket age。
- `selected_psk_identity` 校验 offered identity 数量与索引合法性。
- HRR 后 second ClientHello 使用 synthetic message_hash transcript 重新计算 PSK binder。
- 0-RTT 默认关闭；启用时要求调用方声明 replay-safe，非幂等请求不得默认走 early data。
- 用户态测试 fake hash transcript 缓冲已扩大，仅影响 `KERNEL_HTTP_USER_MODE_TEST`，真实内核 BCrypt streaming 路径不依赖该缓存。

### 证书校验

- Name Constraints、pathLen/self-issued、外部 trust anchor 约束等负向策略已补充测试与明确行为。
- IDNA 当前明确拒绝非 ASCII host，不静默做不完整匹配。
- revocation-required 在 OCSP/CRL 未完整实现时返回明确不支持，不静默放行。
- 既有 dNSName、iPAddress SAN、EKU、KeyUsage、BasicConstraints、链签名、信任锚、SPKI pin 主路径保持。

### HTTP/2 与 HPACK

- SETTINGS ACK payload 非 0 与 PING/PING ACK payload 非 8 按 connection error 处理。
- 客户端禁用 push 后收到 `PUSH_PROMISE` 触发协议错误。
- HTTP/2 response header block 增加伪头顺序、重复 `:status`、缺失 `:status`、大写字段名、connection-specific header、`TE` 非 `trailers` 等校验。
- response trailers 路径已区分 HEADERS after DATA 且 END_STREAM 的语义。
- 动态 SETTINGS 更新同步影响已有 stream window 与 HPACK table/header-list 限制。
- HPACK dynamic table size update 限制在 header block 开头，header list size 按限制统计。
- HPACK 动态表 eviction 后压缩/复用数据区，避免 long-lived nonpaged pool 被放大。
- `authorization`、`cookie`、`proxy-authorization` 等敏感头使用 never-indexed 编码。

### 文档

- `README.md`、`README_en.md`、`docs/api-overview.md`、`docs/high-level-api.md`、`docs/low-level-api.md` 已同步当前能力边界。
- 文档强调当前是内核客户端协议子集，不声明完整 RFC optional 全量。
- 文档记录 redirect、retry、0-RTT、BodyCallback、低层 API IRQL、WebSocket Pong/空消息、HTTP/2 push 等策略。

## 当前边界

- HTTP 请求侧仍不支持 chunked upload。
- HTTP response trailer 当前只校验和消费，不暴露给 API。
- BodyCallback 仍是聚合/解码后一次回调，大响应会占用 nonpaged pool，调用方应配置 `MaxResponseBytes`。
- WebSocket 当前不支持 extensions、curl 风格 frame metadata 或 partial receive。
- TLS 仍以项目已实现的 TLS 1.2/1.3 主路径为准，不宣称覆盖所有 cipher suite、客户端证书、完整 session resumption 或完整 revocation。
- IDNA 当前选择明确拒绝非 ASCII，而不是实现完整 UTS #46/IDNA2008 规范化。
- HTTP/2 不支持 server push、priority/full multiplexing 作为完整通用栈能力。

## 验证结果

已重新构建并运行全部用户态协议测试，均通过：

- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`
- `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`

已运行 Debug x64 构建，结果为 0 warning、0 error：

```powershell
pwsh -NoLogo -NoProfile -Command '$ErrorActionPreference = "Stop"; $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"; $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) { throw "Visual Studio with VC tools was not found." }; $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"; & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & msbuild.exe .\KernelHttp.sln /p:Configuration=Debug /p:Platform=x64 /m; exit $LASTEXITCODE'
```

## 参考

- RFC 9110: HTTP Semantics, https://www.rfc-editor.org/rfc/rfc9110.html
- RFC 9112: HTTP/1.1, https://www.rfc-editor.org/rfc/rfc9112.html
- RFC 6455: The WebSocket Protocol, https://www.rfc-editor.org/rfc/rfc6455.html
- RFC 8446: TLS 1.3, https://www.rfc-editor.org/rfc/rfc8446.html
- RFC 5246: TLS 1.2, https://www.rfc-editor.org/rfc/rfc5246.html
- RFC 5280: X.509 PKI certificate profile, https://www.rfc-editor.org/rfc/rfc5280.html
- RFC 9113: HTTP/2, https://www.rfc-editor.org/rfc/rfc9113.html
- RFC 7541: HPACK, https://www.rfc-editor.org/rfc/rfc7541.html
- libcurl redirect options, https://curl.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html
- libcurl unrestricted auth policy, https://curl.se/libcurl/c/CURLOPT_UNRESTRICTED_AUTH.html
- libcurl WebSocket receive/send/meta APIs, https://curl.se/libcurl/c/curl_ws_recv.html
- curl WebSocket source, https://github.com/curl/curl/blob/master/lib/ws.c
- nghttp2 documentation, https://nghttp2.org/documentation/
