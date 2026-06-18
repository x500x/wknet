# 架构总览 / Architecture

[English](#english) | 简体中文

---

## 简体中文

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

1. `khttp::SessionCreate` 绑定 `net::WskClient`，分配 `KhWorkspace`、`CngProviderCache`、`KhConnectionPool`。
2. `khttp::Get` → 解析 URL → 按 `KhConnectionPoolKey` 从连接池 acquire 连接（命中则复用，未命中则新建：WSK connect → 可选 TLS handshake → 可选 HTTP/2 init）。
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

- **无异常、无 RTTI**；避免直接 `new/delete`（lib 内通过 `KernelHttpConfig.cpp` 重载 `new/delete` 路由到非分页池）。
- 统一用 `HeapObject<T>` / `HeapArray<T>` 管理堆内存（`http/HttpTypes.h`）。
- **lib 内禁止栈缓冲**；高频缓冲常驻 Workspace。
- 同步路径要求 `PASSIVE_LEVEL`；异步带并发保护与 Workspace 隔离。
- 所有公开函数 `noexcept` + SAL 注解（`_In_`/`_Out_`/`_Must_inspect_result_`）。

### 目录速查

```
include/KernelHttp/
├── KernelHttp.h         # 总头文件入口
├── KernelHttpConfig.h   # 池标记、分配器、RAII、配置常量
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

---

## English

### Layered architecture

Top to bottom: high-level `khttp` (HTTP) / `kws` (WebSocket) → low-level `engine` (`Kh*`, stable ABI) → client wrappers → core abstractions → protocol implementations → infrastructure (WSK / CNG / connection pool / Workspace). The high-level layer is a thin bridge over the engine handle ABI (`khttp/Detail.h`).

### Request lifecycle (sync GET)

`SessionCreate` (binds `WskClient`, allocates Workspace + provider cache + pool) → `Get` parses URL, acquires a connection by `KhConnectionPoolKey` (reuse or build: WSK connect → optional TLS handshake → optional HTTP/2 init) → build/send/parse inside Workspace buffers (decode Transfer-/Content-Encoding) → release connection per keep-alive → return independent `Response` handle → `ResponseRelease`/`SessionClose`.

### Core abstractions

| Abstraction | Header | Role |
|-------------|--------|------|
| `core::ITransport` | `core/ITransport.h` | Byte-stream: `Send`/`Receive`/`ReceiveWithTimeout` |
| `core::WskTransport` | `core/WskTransport.h` | Plaintext WSK adapter |
| `core::TlsTransport` | `core/TlsTransport.h` | TLS adapter (auto encrypt/decrypt) |
| `core::IScratchAllocator` | `core/IScratchAllocator.h` | `Acquire`/`Release`/`EnsureBuffer` |
| `core::WorkspaceScratchAllocator` | `core/WorkspaceScratchAllocator.h` | Bounded buffers from a `KhWorkspace`, no on-demand alloc |
| `engine::KhWorkspace` | `engine/Workspace.h` | Session-resident reusable buffers |
| `engine::KhConnectionPool` | `engine/ConnectionPool.h` | Reuse, per-host cap, idle timeout |

See [Transport Layer](transport-layer.md), [Memory Model](memory-model.md), [Connection Pool](connection-pool.md).

### Kernel-constrained design

No exceptions, no RTTI; avoid raw `new/delete` (the lib overrides them to non-paged pool in `KernelHttpConfig.cpp`); heap via `HeapObject<T>`/`HeapArray<T>`; no stack buffers in the lib; hot buffers resident in the Workspace; synchronous paths at `PASSIVE_LEVEL`; all public functions `noexcept` with SAL annotations.
