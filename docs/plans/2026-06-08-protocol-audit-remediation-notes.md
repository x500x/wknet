# 协议审计整改说明

## 背景

本文档记录对当前 HTTP、WebSocket、TLS、证书验证、HTTP/2、WSK 传输和内核约束的完整性审计结果，作为后续修复任务的说明材料。它是 `docs/plans/2026-06-08-protocol-completeness-design.md` 的细化补充：前者定义整改方向，本文聚焦“发现了什么、为什么重要、后面按什么优先级修”。

当前结论不是“协议栈完整无误”，而是：项目已经具备 Windows kernel 客户端协议子集的主体路径，且主路径符合项目方向，使用 WSK、自研 TLS 和内核 CNG/BCrypt；但若按通用 HTTP/WebSocket/TLS 协议栈标准衡量，还存在会影响互通性、连接生命周期、安全语义或错误分类的问题。

## 已确认的正向基础

- 主路径未发现把 WinHTTP、WinINet、SChannel 作为内核协议实现路线。
- `src/KernelHttpLib/KernelHttpConfig.cpp:6` 已重载库内 `new/delete` 到非分页池，符合当前 lib 内存约束方向。
- `src/KernelHttpLib/net/WskSocket.cpp:124` 对 WSK 同步路径做了 `PASSIVE_LEVEL` 检查。
- `src/KernelHttpLib/KernelHttpLib.vcxproj:231` 附近保留 warning-as-error、禁异常、禁 RTTI 等 kernel C++ 约束。
- 已有用户态协议测试覆盖 HTTP parser、WebSocket frame/client、TLS record、HPACK、HTTP/2 frame/client、高层 API 等路径。

## 验证基线

本次审计输入时的测试基线如下，后续修复应保持已通过项不回退，并针对失败和缺口补充测试。

- 已通过：`http_parser_tests.exe`
- 已通过：`websocket_frame_tests.exe`
- 已通过：`websocket_client_tests.exe`
- 已通过：`http2_client_tests.exe`
- 已通过：`tls_record_tests.exe`
- 已通过：`hpack_tests.exe`
- 已通过：`http2_frame_tests.exe`
- 已通过：`high_level_api_tests.exe`
- 已失败：`khttp_tests.exe`

`khttp_tests.exe` 失败集中在 WebSocket round-trip 相关用例，例如 `WsConnect succeeds`、`connect called once`、`WsSendText succeeds`、`WsReceive succeeds`。后续修复 WebSocket 高层路径时，应把该失败作为必须收敛的验证目标之一。

## 本轮整改验证结果

截至 2026-06-08 本轮整改完成后，以下 focused tests 已通过：

- 已通过：`http_parser_tests.exe`
- 已通过：`websocket_frame_tests.exe`
- 已通过：`websocket_client_tests.exe`
- 已通过：`http2_client_tests.exe`
- 已通过：`tls_record_tests.exe`
- 已通过：`hpack_tests.exe`
- 已通过：`http2_frame_tests.exe`
- 已通过：`high_level_api_tests.exe`
- 已通过：`khttp_tests.exe`

Debug x64 `KernelHttpLib` 构建已通过，保持 `/Wall /WX`，结果为 0 warning、0 error。未运行禁止的 `tests\integration\https_smoke.ps1 -SkipDriverBuild` smoke 命令。

## 总体风险分级

### P0：会造成错误连接复用、协议状态错误或并发数据竞争

- HTTP close-delimited 响应在 EOF 后可能仍被判定为可复用连接。
- `101 Switching Protocols` 可能进入普通 HTTP 连接池。
- WebSocket 发送与接收 Ping/Pong 共享连接级 masking scratch，存在并发竞争。
- WSK 超时取消路径可能遗失 native socket 或迟到完成结果的所有权。

### P1：会造成互通失败、安全语义缺失或错误分类

- HTTP/1.0 默认非持久连接语义不足。
- WebSocket 非默认端口和 IPv6 `Host` 握手头格式不完整。
- WebSocket 未请求扩展却接受 `Sec-WebSocket-Extensions`。
- 收到 WebSocket Close 后没有自动回 Close。
- TLS 默认允许 1.2-1.3，但实际优先只走 TLS 1.3；部分失败后重试 TLS 1.2 的分类过宽。
- TLS alert、`close_notify` 和 ALPN 验证语义不完整。
- 证书 SAN 只支持 dNSName，不支持 iPAddress SAN。
- HTTP/2 超时但已有 headers/body 时可能返回半截响应。

### P2：能力边界、严格性和长期维护问题

- HTTP header、status、URL authority 解析偏宽。
- WebSocket 默认 1MB 消息限制与 16KB frame scratch 不一致。
- `AutoReplyPing=false` 没有进入真实路径。
- HTTP/2 RST_STREAM、GOAWAY、并发流生命周期语义不完整。
- OCSP/CRL 撤销检查缺失。
- EKU/KeyUsage 策略偏硬，应明确为当前策略还是可配置策略。
- CNG/BCrypt 缺少统一 IRQL guard 或 dispatch provider 策略文档。
- WSK send/receive 高频非分页池复制和全局表锁忙等自旋存在性能与延迟风险。

## HTTP/1.x 审计说明

### 1. close-delimited 响应连接复用错误

证据位置：

- `src/KernelHttpLib/http/HttpParser.cpp:552`
- `src/KernelHttpLib/engine/HttpEngine.cpp:960`
- `src/KernelHttpLib/engine/HttpEngine.cpp:1429`
- `src/KernelHttpLib/engine/ConnectionPool.cpp:380`

风险：对于没有 `Content-Length` 或 `Transfer-Encoding`、依靠连接关闭表示 body 结束的响应，EOF 本身就是消息边界。该连接不能再回到 keep-alive 池。如果 EOF 后还按可复用连接处理，后续请求会落到已经被服务器关闭或语义已结束的连接上，造成复用失败、数据错位或随机请求失败。

修复方向：

- parser 层产出“响应结束依赖连接关闭”的明确标志。
- engine 层在该标志存在时强制关闭连接，不进入连接池。
- 连接池只接收语义上可继续复用的 HTTP/1.x 连接。
- 增加 close-delimited body 后 EOF 的测试，断言连接不复用。

### 2. HTTP/1.0 默认非持久连接语义不足

证据位置：

- `src/KernelHttpLib/http/HttpParser.cpp:204`
- `src/KernelHttpLib/http/HttpResponse.cpp:46`
- `src/KernelHttpLib/engine/HttpEngine.cpp:1429`

风险：HTTP/1.0 默认关闭连接，只有明确 `Connection: keep-alive` 时才可持久连接。如果仅按 HTTP/1.1 的默认 keep-alive 语义处理，会错误复用 HTTP/1.0 响应连接。

修复方向：

- response metadata 记录响应版本。
- keep-alive 判定同时参考响应版本和 `Connection` 头。
- 对 HTTP/1.0 无 `Connection: keep-alive`、显式 keep-alive、显式 close 分别补测试。

### 3. `101 Switching Protocols` 进入普通连接池

证据位置：

- `src/KernelHttpLib/http/HttpParser.cpp:179`
- `src/KernelHttpLib/engine/HttpEngine.cpp:902`
- `tests/http_parser_tests.cpp:1632`

风险：`101` 后连接所有权已经切换到升级后的协议，例如 WebSocket 或 h2c，不能作为普通 HTTP 连接复用。如果该连接进入 HTTP pool，后续普通 HTTP 请求会和升级协议字节流混在一起。

修复方向：

- 对 `101` 响应设置 upgrade-owned 状态。
- engine 层在返回 `101` 后不释放给普通 HTTP pool。
- WebSocket/h2c 路径显式接管 socket 或连接对象。

### 4. 解析严格性偏宽

发现点：

- 非法 header name 或 CTL 字符没有全部拒绝。
- `Content-Length : 5` 这类 field-name 后带空格的输入可能被接受。
- `HTTP/2.0`、`000`、`999` 等 status-line 处理偏宽。
- URL authority 对 userinfo 等形式没有严格限制。

风险：宽松解析会掩盖服务端错误，也可能引入请求走错 authority、响应语义被误判等问题。内核协议栈应优先明确拒绝不支持或不合法的输入，而不是把异常格式修正为可用格式。

修复方向：

- 把 header field-name、status-line、URL authority 的合法性写成独立测试矩阵。
- 按 RFC 7230 / RFC 9110 的最低要求收紧 parser。
- 对项目暂不支持的形式返回明确错误码。

## WebSocket 审计说明

### 1. Host 握手头不完整

证据位置：

- `src/KernelHttpLib/engine/WsEngine.cpp:505`
- `src/KernelHttpLib/client/WebSocketClient.cpp:155`

风险：非默认端口需要写入 `Host: example.com:8443`，IPv6 literal 需要使用方括号形式，例如 `Host: [::1]:8443`。当前路径容易生成只含 host 或缺少 IPv6 bracket 的 header，导致服务端拒绝握手或连接到错误虚拟主机。

修复方向：

- 统一 authority/Host 构造函数，由 URL parser 产出 host、port、scheme、是否 IPv6 literal。
- ws 默认端口 80、wss 默认端口 443 可省略；其他端口必须带端口。
- IPv6 literal 必须 bracket。

### 2. 扩展协商语义错误

证据位置：

- `src/KernelHttpLib/client/WebSocketClient.cpp:145`
- `src/KernelHttpLib/websocket/WebSocketFrame.cpp:446`

风险：客户端未发送 `Sec-WebSocket-Extensions` 时，服务端不能单方面启用扩展。若接受未请求扩展，后续 RSV 位、压缩语义和 payload 处理都会被破坏。

修复方向：

- 当前未实现扩展时，不发送扩展请求。
- 若服务端返回任何 `Sec-WebSocket-Extensions`，握手必须失败。
- 保持 RSV 非零拒绝逻辑。

### 3. masking key scratch 存在并发竞争

证据位置：

- `include/KernelHttp/client/WebSocketClient.h:185`
- `src/KernelHttpLib/client/WebSocketClient.cpp:659`
- `src/KernelHttpLib/client/WebSocketClient.cpp:670`
- `src/KernelHttpLib/client/WebSocketClient.cpp:771`
- `src/KernelHttpLib/engine/WsEngine.cpp:729`
- `src/KernelHttpLib/engine/WsEngine.cpp:975`

风险：WebSocket 客户端发送帧需要 mask，接收 Ping 时自动发送 Pong 也会 mask。当前上层存在分开的 `SendLock` 和 `ReceiveLock`，如果两条路径共享连接级 `maskingKey_` scratch，就可能互相覆盖，生成错误 mask。

修复方向：

- masking key 改为发送函数局部变量或每次 frame build 的局部 buffer。
- 自动 Pong 发送路径复用同一个 thread-local 或局部 frame builder，不写共享 scratch。
- 添加并发发送与收到 Ping 自动 Pong 的压力测试。

### 4. Close 握手不完整

证据位置：

- `src/KernelHttpLib/client/WebSocketClient.cpp:806`
- `src/KernelHttpLib/client/WebSocketClient.cpp:838`
- `src/KernelHttpLib/client/WebSocketClient.cpp:921`

风险：RFC 6455 要求收到 Close 后，如果本端尚未发送 Close，应发送 Close 响应，然后关闭连接。当前只把 Close 返回给上层或走显式 `Close`，容易造成对端等待或关闭语义不一致。

修复方向：

- Receive 路径收到 Close 后自动发送 Close echo，除非本端已经发过 Close。
- 关闭状态机记录 sent/received close。
- 测试收到 Close 后自动发送 Close frame，且连接不再接收普通消息。

### 5. 大消息限制与 frame scratch 不一致

证据位置：

- `include/KernelHttp/engine/Engine.h:212`
- `include/KernelHttp/engine/Workspace.h:16`
- `src/KernelHttpLib/engine/WsEngine.cpp:724`
- `src/KernelHttpLib/engine/WsEngine.cpp:969`
- `src/KernelHttpLib/client/WebSocketClient.cpp:735`

风险：默认消息限制是 1MB，但实际接收路径使用 16KB frame scratch 时，未清晰区分 frame buffer、message buffer 和用户输出 buffer。大消息、分片消息和 buffer-too-small 情况容易表现不一致。

修复方向：

- 明确 frame buffer 只用于单帧读取，message limit 作用于聚合后消息。
- 用户输出 buffer 不足时返回 `STATUS_BUFFER_TOO_SMALL`，并保证连接状态可预期。
- 大消息测试覆盖单帧、分片、超限和输出 buffer 不足。

### 6. `AutoReplyPing=false` 未进入真实路径

证据位置：

- `include/KernelHttp/engine/Engine.h:213`
- `src/KernelHttpLib/engine/WsEngine.cpp:345`
- `src/KernelHttpLib/client/WebSocketClient.cpp:764`

风险：配置项存在但真实接收路径不使用，会让调用者误以为可以关闭自动 Pong。配置语义必须被执行，或者从公开配置中移除。

修复方向：

- 将 `AutoReplyPing` 传入 `WebSocketClient` 接收循环。
- false 时把 Ping 作为控制事件返回，或返回明确状态让上层处理。
- 如果当前 API 无法表达控制事件，应先调整 API 文档和结构，再实现。

### 7. wss TLS 失败后 TLS 1.2 重试过宽

证据位置：

- `src/KernelHttpLib/client/WebSocketClient.cpp:475`
- `src/KernelHttpLib/client/WebSocketClient.cpp:513`

风险：证书错误、ALPN 错误、网络错误、实现 bug 都不应触发 TLS 1.2 重试。只有确认失败是版本协商结果时，才允许选择 TLS 1.2。否则会掩盖真实错误，也可能形成非预期降级。

修复方向：

- 移除 WebSocket 层的宽泛 TLS 1.2 retry。
- 复用 TLS 层统一的版本协商分类结果。
- 对证书失败、alert、版本不支持分别测试。

## HTTP/2 审计说明

### 1. 未收到 END_STREAM 时可能返回半截响应

证据位置：

- `src/KernelHttpLib/http2/Http2Connection.cpp:466`

风险：HTTP/2 响应结束由 `END_STREAM` 表示。若超时但已经收到 headers/body 就返回成功，上层会把半截 body 当完整响应处理。

修复方向：

- `ReceiveResponseFrames` 必须记录 stream 是否收到 `END_STREAM`。
- 超时且未收到 `END_STREAM` 时返回超时或协议状态错误，而不是成功。
- 测试 headers + partial data + timeout，预期失败且 body 不被标记完整。

### 2. RST_STREAM 和 GOAWAY 语义不完整

风险：本地发现协议错误时，如果不发送合适的 `RST_STREAM` 或 `GOAWAY`，对端无法正确释放 stream 或连接状态。收到对端 RST/GOAWAY 时，也需要阻止继续在受影响 stream 或连接上发送新请求。

修复方向：

- 将 stream 局部错误和连接级错误分开。
- stream 局部错误发送 `RST_STREAM`。
- 连接级协议错误发送 `GOAWAY` 并关闭新 stream 创建。
- 已收到 GOAWAY 后，不再创建大于 last-stream-id 的新 stream。

## TLS、证书和 WSK 审计说明

### 1. WSK 超时取消所有权风险

证据位置：

- `src/KernelHttpLib/net/WskSync.h:155`
- `src/KernelHttpLib/net/WskSocket.cpp:210`
- `src/KernelHttpLib/net/WskSocket.cpp:294`
- `src/KernelHttpLib/net/WskSocket.cpp:383`
- `src/KernelHttpLib/net/WskSocket.cpp:489`

风险：超时返回后，底层 WSK IRP 仍可能迟到完成。如果 native socket 或缓冲区所有权已经被上层释放，迟到完成会造成泄漏、重复关闭或 use-after-free 风险。

修复方向：

- 为每个同步 WSK 操作定义 pending/completed/canceled/owner-released 状态机。
- 超时后要么真实取消底层 IRP 并等待完成，要么把资源所有权转移到迟到完成清理路径。
- connect 成功但调用者已超时返回时，迟到 socket 必须被关闭。

### 2. 异步取消只是合作式状态位

证据位置：

- `include/KernelHttp/engine/Async.h:76`
- `src/KernelHttpLib/engine/Async.cpp:471`

风险：仅设置取消状态不能中断正在进行的 WSK/TLS I/O。上层以为取消成功，但内核资源和网络操作仍在继续。

修复方向：

- Async cancel 传播到当前 transport operation。
- 定义取消后的 completion 语义：用户回调只收到一次最终状态。
- 覆盖取消 connect、send、receive、TLS handshake 的测试或驱动内验证。

### 3. TLS 版本协商分类不足

证据位置：

- `include/KernelHttp/client/HttpsClient.h:33`
- `src/KernelHttpLib/tls/TlsConnection.cpp:726`
- `src/KernelHttpLib/tls/TlsHandshake13.cpp:337`

风险：默认配置允许 TLS 1.2 到 TLS 1.3，但实际路径只要允许 TLS 1.3 就优先跑 TLS 1.3。若 TLS 1.3 失败后没有明确分类，TLS 1.2-only 互通和安全降级判断都会不可靠。

修复方向：

- TLS 层产出结构化 handshake failure reason。
- 只有 server alert 或 ServerHello 版本明确证明不支持 TLS 1.3 时，才允许改走 TLS 1.2。
- 证书错误、ALPN 错误、网络断开、解析错误、密钥错误不得触发 TLS 1.2 重试。

### 4. TLS alert、close_notify 和 ALPN 语义不完整

证据位置：

- `src/KernelHttpLib/tls/TlsRecord.cpp:203`
- `include/KernelHttp/tls/TlsConnection.h:64`
- `src/KernelHttpLib/tls/TlsConnection.cpp:841`
- `src/KernelHttpLib/tls/TlsConnection.cpp:1628`
- `src/KernelHttpLib/tls/TlsConnection.cpp:1879`
- `src/KernelHttpLib/tls/TlsConnection.cpp:2170`
- `src/KernelHttpLib/tls/TlsHandshake12.cpp:459`
- `src/KernelHttpLib/tls/TlsHandshake13.cpp:424`

风险：alert 级别和描述如果被折叠为普通失败，上层无法区分 close_notify、协议错误、证书错误和对端拒绝。ALPN 如果只记录服务端返回值而不验证它来自本端 offer，就可能接受未协商协议。

修复方向：

- alert parser 保留 level、description、是否 close_notify。
- TLS connection 状态区分 clean close 和 abortive close。
- ALPN 必须严格匹配本端 offer 列表。
- HTTP/2、HTTP/1.1、WebSocket 层只接受已经确认的 negotiated protocol。

### 5. TLS 1.3 0-RTT 被拒后直接失败

证据位置：

- `src/KernelHttpLib/tls/TlsConnection.cpp:1345`
- `src/KernelHttpLib/tls/TlsConnection.cpp:1639`

风险：TLS 1.3 early data 被拒是正常协商结果，不应必然导致整个握手失败。对于内核 HTTP 客户端，如果 0-RTT 语义尚未完整实现，可以禁用 early data，或在被拒时转为 1-RTT 重发安全路径。

修复方向：

- 当前阶段优先默认禁用 early data，避免半实现语义。
- 如果保留 early data，必须实现被拒后的请求重放策略，并只允许幂等请求。

### 6. 证书 SAN 与撤销能力缺口

证据位置：

- `src/KernelHttpLib/tls/CertificateValidator.cpp:31`
- `src/KernelHttpLib/tls/CertificateValidator.cpp:686`
- `include/KernelHttp/tls/CertificateValidator.h:58`

风险：IP 地址证书应使用 iPAddress SAN，而不是 dNSName 或 CN。缺少 OCSP/CRL 意味着当前验证无法发现已撤销证书。

修复方向：

- SAN parser 增加 iPAddress，IPv4 为 4 字节，IPv6 为 16 字节。
- URL host 是 IP literal 时，只匹配 iPAddress SAN。
- 撤销检查在当前阶段可明确标为未支持或可选策略，但文档不得宣称完整证书链验证。

## 后续修复顺序建议

1. 先修 HTTP/1.x 连接复用语义和 `101` 所有权，避免跨请求污染。
2. 再修 WebSocket 握手严格性、Close、mask 并发和大消息路径，收敛 `khttp_tests.exe` 失败。
3. 然后修 WSK 超时所有权和 async cancel，因为这是底层资源安全边界。
4. 接着修 TLS 版本协商、alert、ALPN、close_notify，移除宽泛 TLS 1.2 retry。
5. 补证书 iPAddress SAN 和能力说明。
6. 补 HTTP/2 END_STREAM、RST_STREAM、GOAWAY 语义。
7. 最后做 CNG/IRQL、非分页池分配、全局锁忙等的内核质量整改。

## 后续执行约束

- 所有命令使用 `pwsh`。
- 不运行禁止的 smoke 命令：`pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`。
- 修改代码后必须进入 test 和 Debug 构建验证，且保持 warning-as-error 和最高警告等级。
- 不把“兜底设计”或“临时重试”作为正式协议架构手段。
- 不提交文档或代码，除非用户明确要求提交。
