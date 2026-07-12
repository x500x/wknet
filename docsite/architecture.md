# 架构总览

### 分层架构

```
┌─────────────────────────────────────────────────────────────┐
│            高层 API：khttp（HTTP）/ kws（WebSocket）          │
│  简洁接口、自动资源管理、适合大多数应用场景                      │
├─────────────────────────────────────────────────────────────┤
│            底层 API：engine（Kh* 前缀、ABI 稳定）            │
│  精细控制、性能优化、支持自定义测试                              │
├─────────────────────────────────────────────────────────────┤
│            客户端层 client                                    │
│  HttpClient | HttpsClient | Http2Client | WebSocketClient    │
├─────────────────────────────────────────────────────────────┤
│            核心抽象 core                                      │
│  ITransport | IScratchAllocator | TlsTransport/WskTransport  │
├─────────────────────────────────────────────────────────────┤
│            协议实现                                           │
│  HTTP/1.1 | HTTP/2 (HPACK) | WebSocket | TLS 1.2/1.3        │
├─────────────────────────────────────────────────────────────┤
│            基础设施                                           │
│  WSK 网络传输 | CNG/BCrypt 密码学 | 连接池 | Workspace        │
└─────────────────────────────────────────────────────────────┘
```

高层 `khttp`/`kws` 是对 `engine` 句柄 ABI 的薄封装（见 `khttp/Detail.h` 的转换桥接）。两层可混用。

### 请求生命周期（高层同步 GET 为例）

1. `wknet::http::SessionCreate` 创建隐藏 WSK runtime，并创建 engine session、`KhWorkspace`、`CngProviderCache`、`KhConnectionPool`。
2. `wknet::http::GetEx` / `SendEx` 接收 send handle、method、URL、headers/body/options → 解析 URL → 按 `KhConnectionPoolKey` 从连接池 acquire 连接（命中则复用，未命中则新建：WSK connect → 可选 TLS handshake → 可选 HTTP/2 init）。
3. 在 Workspace 缓冲内构建请求、发送、解析响应（解链 Transfer-Encoding / Content-Encoding）。
4. 连接按 keep-alive 规则 release 回池；`Response` 句柄独立返回。
5. `ResponseRelease` / `SessionClose` 释放。

### 核心抽象

| 抽象 | 头文件 | 作用 |
|------|--------|------|
| `core::ITransport` | `core/ITransport.h` | 字节流传输接口：`Send` / `Receive` / `ReceiveWithTimeout` |
| `core::WskTransport` | `core/WskTransport.h` | WSK 明文传输适配器（`ITransport` over `net::WskSocket`，`WSK_FLAG_NODELAY`） |
| `core::TlsTransport` | `core/TlsTransport.h` | TLS 传输适配器（`ITransport` + `tls::TlsConnection`，自动加解密） |
| `core::IScratchAllocator` | `core/IScratchAllocator.h` | 临时内存分配器接口：`Acquire` / `Release` / `EnsureBuffer` |
| `core::WorkspaceScratchAllocator` | `core/WorkspaceScratchAllocator.h` | 从 `KhWorkspace` 取定长有界缓冲（TLS 握手/证书/HTTP2 头/WS 帧），不按需分配 |
| `engine::KhWorkspace` | `engine/Workspace.h` | 会话常驻的可复用缓冲集合 |
| `engine::KhConnectionPool` | `engine/ConnectionPool.h` | 连接池：复用、每主机上限、空闲超时 |

详见 [传输层](transport-layer.md)、[内存模型](memory-model.md)、[连接池](connection-pool.md)。

### 内核约束下的设计

- **无异常、无 RTTI**；避免直接 `new/delete`（lib 内通过 `WknetConfig.cpp` 重载 `new/delete` 路由到非分页池）。
- 统一用 `HeapObject<T>` / `HeapArray<T>` 管理堆内存（`http/HttpTypes.h`）。
- **lib 内禁止栈缓冲**；高频缓冲常驻 Workspace。
- 同步路径要求 `PASSIVE_LEVEL`；异步带并发保护与 Workspace 隔离。
- 所有公开函数 `noexcept` + SAL 注解（`_In_`/`_Out_`/`_Must_inspect_result_`）。

### 目录速查

```
include/wknet/
├── Wknet.h         # 总头文件入口
├── WknetConfig.h   # 池标记、分配器、RAII、配置常量
├── client/              # HttpClient/HttpsClient/Http2Client/WebSocketClient
├── core/                # ITransport / 传输适配器 / scratch allocator
├── khttp/               # 高层 HTTP API（namespace khttp）
├── kws/                 # 高层 WebSocket API（namespace kws）
├── engine/              # 底层 API（Kh*）+ 句柄/池/Workspace/Async
├── http/                # HTTP/1.1：类型/解析/请求构建/响应/编码
├── http2/               # HTTP/2：帧/流/连接/HPACK
├── tls/                 # TLS 1.2/1.3：连接/上下文/记录/握手/证书
├── websocket/           # WebSocket 帧编解码
├── net/                 # WSK：WskClient/WskSocket/WskBuffer
└── crypto/              # CNG/BCrypt：CngProvider/Aead/KeyExchange
```
