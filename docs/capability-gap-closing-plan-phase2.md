# KernelHttp 能力边界补齐计划（第二阶段）

> 第一阶段（[capability-gap-closing-plan.md](capability-gap-closing-plan.md)，里程碑 M1–M5）已完成：Ed25519/Ed448 软件验签、WS 自定义握手头、`Content-Range`/206 只读解析、请求 trailers、HTTP/2 低层多活动流基础、RFC 8441 extended CONNECT 与 HTTPS 代理 CONNECT 隧道低层基础。
>
> 本阶段针对 [能力边界矩阵](../docsite/capability-matrix.md) 中**仍残留的高层边界**与 [路线图](../docsite/roadmap.md) 的「未来改进方向」，给出按「先加固、后扩张」排序的补齐计划。
>
> 所有 `file:line` 引用为编写时（2026-06-19）的代码位置，部分经检索得出；**实施前必须逐处复核**。

## 总体原则（在第一阶段基础上补充）

1. **安全加固优先于能力扩张**——在引入并发、隧道等会扩大攻击面的能力之前，先建立与调用方容量解耦的资源硬上限。
2. **默认安全策略不回退**——新能力（代理、HTTP/2 多流、WS-over-H2）默认保守；任何兼容/危险路径必须显式 opt-in，沿用 `TlsSecurityProfile::CompatibilityExplicit` + 开关位模式。
3. **拒绝优于半实现**——每个大型项给出「实现 vs 维持拒绝」决策点；未完成路径继续显式拒绝，绝不静默降级。
4. **每项配套测试矩阵**——每个补齐项必须有 `tests/` 单元测试；线协议改动同步 interop matrix（`tests/integration/tls_matrix.ps1`）。
5. **凭据与注入零信任**——代理凭据、自定义头、隧道字节一律经校验 / 隔离，不落日志、不跨源泄漏。

---

## 当前边界 → 计划项 映射

| 能力矩阵中的当前边界 | 证据（file:line，编写时） | 计划项 |
|----------------------|---------------------------|--------|
| 库级资源上限由调用方容量驱动，无独立硬天花板；热路径无 lookaside | `engine/Workspace.h:9-46`、`khttp/Types.h:183-188,194-195`、`engine/Engine.h:169-173,183`；`WknetConfig.h:51-108`（仅 `ExAllocatePool2`，无 lookaside） | **P0** |
| 高层 `khttp` 无全局代理配置（低层 `HttpsClient` 有 CONNECT，但未接入引擎） | `client/HttpsClient.h:23-53`、`HttpsClient.cpp:305,327-370,411-443`；`HttpEngine.cpp` 不引用 `HttpsClient`；`Types.h:180-190`、`Engine.h:166-178` 无 proxy | **P1** |
| 高层 HTTP/2 仍是每调用单流，无连接池级多流复用 | `HttpEngine.cpp:1239-1252`（缓存单 `Http2Connection`）、`:1261`（阻塞单流 `SendRequest`）；低层 `Http2Connection.h:230-268` 两阶段接口无高层调用者 | **P2** |
| 高层 `kws` 默认 HTTP/1.1 Upgrade，WS-over-HTTP/2 需显式 opt-in | `ConnectConfig.AllowWebSocketOverHttp2` / `TransportMode` 控制；协商 h2 且 peer 启用 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 时走 RFC 8441，默认仍保持 HTTP/1.1 Upgrade | **P3（显式能力已完成，默认自动选择仍不做）** |
| 高层显式能力边界：h2c opt-in、显式 PING、permessage-deflate 显式 opt-in、push 拒绝、priority 显式 per-request、无在线 OCSP/CRL、WS 不跟随 redirect | 见各项 | **P4（维持/小型增量）** |

---

## P0 — 资源硬上限与热路径池化（安全加固，先做）

> 进度（截至 2026-06-19）：
>
> - 第一小步已完成：新增集中硬上限头 `include/wknet/WknetLimits.h`，并通过 `khttp_tests` 覆盖常量关系。
> - 第二小步已完成并校正：响应聚合改为 requests-like 语义，`MaxResponseBytes=0` 表示不设调用方上限；非零值才限制 buffered response 大小，旧 64 MiB 不再作为库级低位硬顶。
> - 第三小步已完成：engine 可配置响应头数量收敛到 `WKNET_HARD_MAX_HEADERS`，显式超限会话创建 fail-closed。
> - 第四小步已完成：engine 与低层 HTTP/2 header block 上限收敛到 `WKNET_HARD_MAX_HEADER_SECTION`。
> - 第五小步已完成并校正：内容解码取消固定 16 MiB 绝对顶，decoded aggregate 跟随响应/调用方容量；解压炸弹防护保留单级膨胀比限制。
> - 第六小步已完成：新增 `KhLookasideList` 固定块池封装，归还前清零，并接入 session 级 `KhWorkspace` 对象分配/释放路径；scratch buffer 内容仍按现状分配。
> - 第七小步已完成：`Http2Connection` 接入 per-connection 入站帧数、累计字节与连接级控制信令账本，越限发送 `ENHANCE_YOUR_CALM` GOAWAY；新增 HTTP/2 控制信令洪泛测试覆盖。
> - 第八小步已完成并校正：`TlsConnection`/HTTP/2 保留入站 record/frame 计数账本；连接生命周期累计字节低位硬顶关闭，避免误伤长连接和大流式响应。
> - 第九小步已完成：高层 WebSocket 连接使用的 `KhWorkspace` 创建/释放接入 session 级 lookaside，覆盖 HTTP 与 WS 两条 workspace 热路径；已通过 WebSocket client / khttp 回归与 Debug 构建。
> - 第十小步已完成：高层 WebSocket 发送 text/binary/continuation/ping/pong 与 CloseEx 复用 workspace 的独立 `WebSocketSendFrameScratch`，移除这些路径每次调用的 16 KiB frame buffer 堆分配，同时避免与接收路径 `WebSocketFrameScratch` 并发共享；已通过 WebSocket client / khttp 回归与 Debug 构建。
> - P0 当前可交付范围已完成：header/frame/message 等协议安全上限、入口 fail-closed、HTTP/2 与 TLS 连接账本、workspace lookaside 与 WS 发送热路径池化均已落地并验证。HTTP buffered response 默认按需堆增长，流式/长连接不受低位总量硬顶限制。剩余 H2/TLS 内部缓冲为连接生命周期常驻缓冲，暂不作为 P0 阻塞项；后续若继续池化需单独设计连接级池生命周期。

### 现状

- 上限基本由**调用方容量驱动**：`include/wknet/engine/Workspace.h:9-46` 定义全部 scratch 尺寸（Request/Response/DecodedBody/HttpHeaderScratch/Http2HeaderScratch/TlsHandshakeScratch/CertificateScratch/WebSocketFrame 等）；`include/wknet/http/Types.h:183-188` 的 `SessionConfig` 与 `include/wknet/engine/Engine.h:169-173` 的 `KhSessionOptions` 暴露 `RequestBufferBytes`/`MaxResponseBytes`/`MaxResponseHeaders`/`Http2MaxHeaderBlockBytes`。
- 单次调用与会话 `MaxResponseBytes` **0 = 不设调用方响应体上限**；buffered response 使用堆内存按需增长，非零值才主动限制聚合大小。
- 旧实现曾把响应体 64 MiB、decoded 16 MiB、连接累计 512 MiB 作为低位硬顶；这与通用 HTTP 客户端 / `requests` 风格不符，已校正为按需堆增长 + 协议安全边界。
- 热路径分配统一走 `include/wknet/WknetConfig.h:51-108`（`AllocateNonPagedPoolBytes` = `ExAllocatePool2`，:61），**无 lookaside**，H2 帧 / HPACK scratch / TLS 记录 / WS 帧高频分配产生碎片与开销。

### 目标

1. 建立**协议安全上限层**：header、frame、message、stream 并发、控制信号、解压膨胀比等边界不可逾越；普通响应聚合不使用低位库级总量硬顶。
2. 热路径引入 **lookaside 式固定块池**，降低 `ExAllocatePool2` 频次与碎片。

### 实施步骤

1. 新增 `include/wknet/WknetLimits.h`，集中安全边界编译期常量：`WKNET_HARD_MAX_HEADER_SECTION`、`WKNET_HARD_MAX_HEADERS`、`WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL`、per-connection 帧/控制信号计数等。`WKNET_HARD_MAX_RESPONSE_BYTES`、`WKNET_HARD_MAX_DECODED_BYTES`、`WKNET_HARD_MAX_CONNECTION_BYTES` 使用 0 表示不启用低位总量硬顶。
2. **入口语义**：`MaxResponseBytes=0` 保持不限制；非零调用方容量作为真实上限执行，超过时 fail-closed；不再把旧 64 MiB 当作正式架构上限。
3. **lookaside 封装**：新增 `KhLookasideList`（`ExInitializeLookasideListEx` / `ExAllocateFromLookasideListEx` / `ExFreeToLookasideListEx`），用于固定大小块（H2 帧头、HPACK scratch、WS 帧缓冲）；大不定块仍走 `AllocateNonPagedPoolBytes`。生命周期挂在会话 / 连接对象，PASSIVE_LEVEL 初始化与销毁。
4. **per-connection 账本**：在 `Http2Connection` 与 TLS 记录层累计「已处理字节 / 帧数 / 控制信令次数」，越限即 GOAWAY / 关闭，补强已有抗洪泛上限（CONTINUATION ≤64、记录上限等）。

### 安全护栏

- 安全边界为编译期常量；响应聚合容量由调用方非零上限或堆分配结果决定，调用方可下调，默认不使用低位总量硬顶。
- clamp 必须 fail-closed：超限返回错误而非截断，避免「看似成功的部分响应」。
- lookaside 块归还前 `RtlSecureZeroMemory`（密钥 / 凭据可能驻留），与现有密钥清零策略一致。

### 测试

`tests/khttp_tests.cpp` / `tests/http2_client_tests.cpp`：非零调用方容量被严格执行；旧 64 MiB 以上响应上限不再被拒绝；构造超大 header / 帧流验证 fail-closed；lookaside 压力下分配-归还计数平衡（无泄漏）；帧/控制信号账本越限触发 GOAWAY / 关闭。

### 风险 / 工作量

中低——改动面广但局部，无并发语义变更。**~1 周**。

---

## P1 — 高层 Session 代理（CONNECT 隧道）配置

> 进度（截至 2026-06-19）：P1 已按路线 A 完成：高层 `SessionConfig` / `KhSessionOptions` 已接入显式代理配置，引擎在 HTTPS 传输装配中对代理建 TCP、通过共享 `client::ProxyTunnel` 建立 HTTP/1.1 CONNECT 隧道，再对目标主机执行 TLS；连接池按代理身份分桶，明文 HTTP over proxy 仍作为二期能力显式拒绝。已通过 `khttp_tests`、`http2_client_tests` 与 Debug x64 构建（0 警告）。

### 现状

- 低层 `client::HttpsClient` 已支持显式 HTTP/1.1 CONNECT 隧道：`include/wknet/client/HttpsClient.h:23-53` 的 `HttpsRequestOptions`（`ProxyAddress:26`、`ProxyAuthority/Length:27-28`、`ProxyHeaders/Count:29-30`、`RemoteAddress:25` 为目标）；实现见 `HttpsClient.cpp:52-54`（`UsesProxyTunnel`）、`:58-70`（`IsValidProxyTunnelOptions`）、`:74-90`（`BuildProxyConnectRequest`）、`:305`（连接目标选择）、`:327-370`（建隧道 + 读代理响应 + 2xx 校验）、`:411-443`（对**目标**主机再次 TLS）。
- **关键事实**：`HttpsClient` **未被高层引擎调用**——`src/wknetlib/engine/HttpEngine.cpp` 走 `Http2Client`/`Http2Connection` 与自有传输 / TLS 装配路径；`HttpsClient::SendRequest` 当前仅测试调用（`tests/http2_client_tests.cpp:413-416`）。
- 高层 `SessionConfig` 已新增 `Proxy`，并由 `src/wknetlib/khttp/Session.cpp` 透传到 `KhSessionOptions`；代理地址、CONNECT authority 与 opaque `Proxy-Authorization` 头均由显式配置提供。
- 引擎路径已接入代理隧道：HTTPS 请求先连接代理地址、发送 CONNECT 并校验 2xx，再在隧道上针对目标主机执行 TLS；HTTP 明文代理转发当前显式返回 `STATUS_NOT_SUPPORTED`。
- 连接池键已纳入代理身份，避免不同代理的连接混用；每 host quota 仍按目标 host / scheme / port / address family 计数，防止通过多代理绕过目标主机上限。

### 决策点（两条路线）

- **路线 A（引擎内实现，推荐）**：在引擎的传输装配阶段（建 socket → 可选 CONNECT → TLS）插入隧道层，将 `HttpsClient.cpp:74-90` 的 CONNECT 构建 / 校验抽到**共享 helper**复用（避免维护两份实现）。与连接池 / H2 / 重定向引擎语义一致，可被池化与多流复用。
- **路线 B（高层直连 HttpsClient）**：成本低，但绕过连接池 / H2 多流 / 重定向引擎，形成第二条主路径，违背单主路径原则。**不推荐**。

### 实施步骤（路线 A）

1. **配置面（已完成）**：`SessionConfig` 增 `Proxy`（`Address`、`Authority`、`AuthHeader` opaque）；透传到 `KhSessionOptions`；翻译点 `Session.cpp` 已接入。
2. **连接池键（已完成）**：`ConnectionPool` 复用比较纳入代理身份，经不同代理的连接不可混用复用。
3. **传输装配（已完成）**：配置代理且目标为 https 时，先对 proxy 建 TCP → 发 CONNECT（共享 helper）→ 校验 2xx → 在 raw 隧道上对**目标主机** TLS（SNI / 证书校验始终针对**目标**，不是代理）。
4. **明文 over proxy（二期）**：以绝对 URI 形式经代理转发；当前实现显式拒绝，不静默降级。
5. **错误分类（已完成）**：CONNECT 407 映射 `STATUS_ACCESS_DENIED`，其他非 2xx 映射 `STATUS_INVALID_NETWORK_RESPONSE`；无效代理配置在入口拒绝。

### 安全护栏

- 代理凭据 opaque 透传、不落日志；跨重定向 / 跨源**不携带到目标请求**（呼应已有跨源清理 `Authorization`/`Cookie`/`Proxy-Authorization`）。
- CONNECT 目标 authority 经语法校验（无 CRLF 注入），复用 `HttpRequest.cpp` 的 `ValidateExtraHeaders` 思路。
- 目标 TLS 证书校验**绝不因经过代理而放松**；禁止 HTTPS→明文降级。
- 内核态无 WinHTTP，**默认不信任系统代理设置**，仅显式配置生效。

### 测试

- `tests/khttp_tests.cpp`：覆盖 `SessionConfig.Proxy` 透传到传输层、无效代理配置拒绝、明文 HTTP proxy 显式拒绝、连接池按代理身份分桶，并验证 `Proxy-Authorization` 不进入目标请求。
- `tests/http2_client_tests.cpp`：继续覆盖低层 `HttpsClient` / `client::ProxyTunnel` 既有 CONNECT 行为，防止共享 helper 回归。

### 风险 / 工作量

中——安全敏感但边界清晰。**~1–1.5 周**。

---

## P2 — 高层 HTTP/2 并发多流接入连接池（需独立详设）

> 进度（截至 2026-06-19）：P2 已完成：连接池新增 HTTP/2 stream 租约计数与延迟关闭语义，已激活的 H2 连接可在未释放时按本地 / peer 并发上限再次分配给同源请求；高层 `SendHttp2ViaTransport` 改为 `BeginRequest` + 池租约提升 + 单 reader `ReceiveResponse` 两阶段路径；`Http2Connection` 接入 PASSIVE_LEVEL 状态锁 / reader 锁，并将活动 stream 上限收敛到 `min(peer MAX_CONCURRENT_STREAMS, WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL, active table capacity)`。已通过 `http2_client_tests`、`khttp_tests`、`high_level_api_tests` 与 Debug x64 构建（0 警告）。

### 现状

- `HttpEngine.cpp:1239-1252` 已**惰性创建并缓存单个** `Http2Connection` 于 `pooledConnection.Http2`，但 `:1261` 调用**阻塞式单流** `SendRequest`；连接池把一个 `Http2Connection` 绑定到一个 `InUse` 槽（`ConnectionPool.cpp` Acquire `:399` / Release `:521`），阻止并发分发——**这是核心 gap**。
- 低层两阶段接口已就绪：`BeginRequest`（`Http2Connection.h:230-260`，`_Out_ streamId`）、`ReceiveResponse(streamId)`（`:262-268`）、活动 stream 表字段（`Http2Connection.h:450-451`），`ReserveActiveStream` 受 `peerSettings_.MaxConcurrentStreams` 限制（`Http2Connection.cpp:489-503`），帧循环按 streamId 交错分发 HEADERS/DATA/WINDOW_UPDATE/RST_STREAM。**无高层调用者**。
- 异步面 `include/wknet/engine/Async.h`：`KhAsyncOperation`(:34) 仅 `HttpSend`/`WebSocketConnect`(:15)，无 per-stream kind。
- IRQL / 串行：所有 H2/TLS/传输路径 PASSIVE_LEVEL（`HttpEngine.cpp:3346,3494,3572` 的 `CheckPassiveLevel`）；连接池由 `FAST_MUTEX`（`ConnectionPool.h:80`）串行；**`Http2Connection` 内部无锁**，当前串行化靠 `InUse` 单槽标志。

### 目标

让高层在同一 H2 连接上并发承载多个请求（多活动流），并纳入连接池复用模型。

### 前置与设计难点（**本项必须单独 EnterPlanMode 详设**，呼应第一阶段对 P2.1 的判断）

1. **并发模型**（核心难点）：`Http2Connection` 当前无内部锁。需决定锁粒度（连接级 `FAST_MUTEX` vs 更细）、帧读循环驱动方（专用 worker vs 调用方借用），以及在 PASSIVE_LEVEL 契约下的阻塞语义。
2. **流表 ↔ 连接池交互**：`KhPooledConnection` 的 `InUse` 单槽需改为「可承载 N 个并发流」，Acquire/Release 语义随之变化。
3. **异步 API 扩展**：`Async.h` 增 per-stream 操作类型与完成事件。
4. **流控账本**：per-stream + 连接级窗口在低层已具备，需在高层并发下保证账本线程安全。

### 安全护栏

- 本地并发流上限取 `min(peer MaxConcurrentStreams, WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL)`（**依赖 P0**）。
- 锁路径不得在 IRQL 提升后阻塞，维持 PASSIVE_LEVEL 契约。
- 单流错误（RST_STREAM）不得污染同连接其它流；连接级错误（GOAWAY）须干净广播给所有活动流。

### 测试

`tests/http2_multistream_tests.cpp`（扩展现有 `http2_client_tests`）：并发 N 流交错收发；单流 RST 不影响他流；GOAWAY 广播；流控账本不越界；超并发上限拒绝。

### 风险 / 工作量

高（内核并发 + 锁 + IRQL）。需独立设计。**~2–4 周**。

---

## P3 — 高层 kws 自动 / opt-in WebSocket over HTTP/2（RFC 8441，依赖 P2）

> 进度（截至 2026-06-19）：P3 已按显式 opt-in 路线完成：`wknet::websocket::ConnectConfig` / engine / 低层 `WebSocketClient` 已接入 `AllowWebSocketOverHttp2`，默认仍保持 HTTP/1.1 Upgrade；`wss` opt-in 时 TLS ALPN offer `{h2, http/1.1}`，协商到 h2 后通过 RFC 8441 extended CONNECT 建立 tunnel，peer 未启用 `ENABLE_CONNECT_PROTOCOL` 继续 fail-closed；`ws://` opt-in 明确拒绝，不引入 h2c 隐式路径。WebSocket 帧层新增 H2 专用无掩码客户端编码，H2 DATA 隧道复用现有 send/receive/close/Ping/Pong/分片状态机。已通过 `websocket_frame_tests`、`websocket_client_tests`、`http2_client_tests`、`khttp_tests` 与 Debug x64 构建（0 警告）。

### 现状

- 高层 `kws` 默认仍走 HTTP/1.1 Upgrade；`ConnectConfig.AllowWebSocketOverHttp2` / `TransportMode` 可显式选择 RFC 8441。`wss` opt-in 后会 offer `h2,http/1.1`，协商到 h2 且 peer 启用 `SETTINGS_ENABLE_CONNECT_PROTOCOL` 时走 extended CONNECT；默认自动选择仍不做。
- 低层 RFC 8441 原语就绪：`Http2Connection.cpp:102-130`（`ValidateExtendedConnectRequest`）、`:1003-1031`（校验 `peerSettings_.EnableConnectProtocol` 并置 `TunnelMode`）、`SendStreamData`/`ReceiveStreamData`（`Http2Connection.h:278-306`）。
- WS 帧编解码 transport-agnostic（`WebSocketFrame.h:37-90` 的 `WebSocketCodec`），但 `EncodeClientFrame`（:66/:71）**强制掩码**；RFC 8441 在 H2 上**禁止掩码**，需新增无掩码编码变体。

### 决策点

**自动选择 vs 显式 opt-in**：推荐**显式 opt-in 起步**（`ConnectConfig` 新增 `AllowWebSocketOverHttp2`，默认仍 http/1.1），避免行为静默变化；稳定后再评估自动选择。

### 实施步骤

1. **ALPN**：WS TLS 按配置 offer `{h2, http/1.1}`，依 `NegotiatedAlpn()` 分支——在 `WebSocketClient.cpp:901-911` 处**放开 h2 分支**而非一律拒绝。
2. **H2 握手**：经 extended CONNECT 发 `:method CONNECT` + `:protocol websocket`（先确认 method 枚举支持 CONNECT，查 `include/wknet/http1/HttpRequest.h`）；校验 peer `ENABLE_CONNECT_PROTOCOL=1`，否则按配置回退 http/1.1 或拒绝。
3. **帧层**：新增无掩码编码变体供 H2 路径（H2 上 client 帧不掩码）；接收侧解析已可复用。
4. **桥接**：收发接到 `SendStreamData`/`ReceiveStreamData` DATA 隧道；close/Ping/Pong/分片复用现有 `WebSocketCodec` 与状态机。

### 安全护栏

- 默认不改变现有 http/1.1 行为（opt-in）。
- peer 不支持 extended CONNECT 时 fail-closed 或显式回退，**绝不静默降级**安全属性。
- H2 路径维持现有 WS 安全约束（控制帧上限、UTF-8 校验、`MaxMessageBytes`）。
- 复用第一阶段 P1.1 的自定义 opening header 注入过滤。

### 测试

`tests/websocket_h2_tests.cpp`：extended CONNECT 建立；peer 无 `ENABLE_CONNECT_PROTOCOL` 时回退 / 拒绝；H2 帧不掩码；close 握手；与普通 H2 流复用（**依赖 P2**）。

### 风险 / 工作量

高（依赖 P2 + 帧层改动）。**~2–3 周**。

---

## P4 — 维持非目标 / 小型增量（建议保持现状或低优先）

> 进度（截至 2026-06-19）：P4 已完成：低层 `Http2Connection` 新增显式 `SendPing`，用于调用方主动发 HTTP/2 PING 保活 / 探测；HTTP/2 server push、WS 握手 redirect / 401 跟随、在线 OCSP/CRL 抓取、HTTP/3·QUIC、服务端 / 入站 parser 继续明确保持非目标。已通过 `http2_client_tests`、`http2_frame_tests`、`websocket_frame_tests`、`websocket_client_tests`、`khttp_tests` 与 Debug x64 构建（0 警告）。
> 后续状态更新：HTTP/1.1 pipeline、WebSocket `permessage-deflate`、HTTP/2 后台 PING 保活和 per-request priority 已从“保持拒绝/低层显式原语”迁移为显式 opt-in 能力；默认仍关闭，安全拒绝边界保持不变。

| 项目 | 建议 |
|------|------|
| 高层 `khttp` 暴露 h2c | 低价值，保持仅 `Http2Client`；如确需，作小型增量 |
| 主动 PING 保活 | 已完成：低层 `Http2Connection::SendPing` 显式发送 PING；高层 session 可通过 `Http2KeepAlive.Enabled=true` 显式开启后台保活，默认关闭 |
| permessage-deflate（RFC 7692） | 已实现显式 opt-in：默认关闭，HTTP/1.1 Upgrade 与 RFC 8441 路径共享协商，非法/未请求扩展拒绝 |
| HTTP/2 server push / PRIORITY | server push 保持拒绝；PRIORITY 已补齐显式 per-request 能力，不实现复杂本地树调度 |
| 流式响应回调 | `SendOptions.OnBody`（`Types.h:200`）已提供增量回调；真流式（不缓冲）需引擎改造，单独评估 |
| 在线 OCSP/CRL 抓取 | 内核态刻意省略，**保持**静态表 + stapling |
| WS 握手 redirect / 401 跟随 | 低价值，**保持不跟随** |
| HTTP/3·QUIC、服务端 / 入站 parser | **明确非目标，保持** |

---

## 里程碑与建议执行顺序

| 里程碑 | 工作量 | 内容 | 前置 |
|--------|--------|------|------|
| **M6（安全加固）** | ~1 周 | P0 资源硬上限层 + lookaside 池化 + per-connection 账本 | 无 |
| **M7（代理）** | ~1–1.5 周 | P1 高层 Session 代理 CONNECT（路线 A，引擎内） | M6（硬上限纳入） |
| **M8（H2 多流，需独立详设）** | ~2–4 周 | P2 高层 HTTP/2 并发多流 + 连接池改造 | M6 |
| **M9（WS-over-H2，依赖 M8）** | ~2–3 周 | P3 高层 kws opt-in WebSocket over HTTP/2 | M8 |
| 持续 | — | P4 维持非目标 / 小型增量 | — |

> **排序理由**：M6 在引入并发（M8）、隧道（M7）等扩大攻击面的能力之前先建立资源硬天花板，符合「安全加固优先于能力扩张」。M8 是 M9 的硬前置（WS-over-H2 需多流基础）；M7 与 M8 相互独立，可并行排期。

## 贯穿全程的安全护栏（重申）

- 每项落地前补单元测试；线协议改动同步 `tls_matrix.ps1` / interop 用例。
- 兼容性 / 危险能力默认关闭、显式 opt-in；新能力不静默改变既有默认行为。
- header / trailer / 代理 authority / 隧道字节统一走注入校验（CRLF、长度上限）。
- 凭据 opaque、不落日志、不跨源泄漏；密钥 / 凭据缓冲归还前 `RtlSecureZeroMemory`。
- 资源上限 fail-closed，绝不静默截断；超并发 / 超容量明确报错。
