<div align="center">

# KernelHttp

**面向 Windows 内核驱动的纯内核态 HTTP/HTTPS 客户端库**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20Kernel-0078d4.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
[![WDK: 10+](https://img.shields.io/badge/WDK-10%2B-green.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

[English](README_en.md) | 简体中文

</div>

---

## 📖 项目简介

KernelHttp 是一个纯内核态的 HTTP/HTTPS 客户端库，专为 Windows 内核驱动开发设计。项目从底层开始构建，实现了内核可用的客户端协议栈：HTTP/1.1、HTTP/2、WebSocket，以及 TLS 1.2/1.3 握手、记录保护和证书验证；默认安全策略和显式兼容能力在下文明确列出。

### ✨ 核心特点

- **🔒 纯内核态实现**：不依赖 WinHTTP、WinINet、SChannel 等用户态组件
- **🌐 WSK 网络传输**：使用 Windows Sockets Kernel (WSK) 进行网络通信，通过 `ITransport` 抽象接口支持 WSK 和 TLS 两种传输层
- **🔐 CNG/BCrypt 密码学**：使用内核态 CNG (Cryptography Next Generation) 进行加密操作，支持 TLS 1.2/1.3 握手
- **📡 明确的能力矩阵**：支持 HTTP/1.1、HTTP/2（含 h2c 明文升级）、WebSocket、TLS 1.2/1.3 的客户端主路径，并把默认启用能力与显式兼容能力分开记录
- **🔄 连接池管理**：内置连接池，支持连接复用、空闲超时、并发保护和自动管理
- **⚡ 异步操作**：支持异步请求，带并发保护和 Workspace 隔离，避免阻塞内核线程
- **🎯 两层 API**：提供高层简洁 API（`khttp`）和底层精细控制 API（`engine`）
- **🛡️ 证书验证**：支持证书锁定（Certificate Pinning）、信任锚（Trust Anchor）、SPKI 哈希验证和 TLS 1.3 签名方案校验
- **📦 响应编码**：支持 `Content-Encoding: gzip/deflate/br`，并支持 HTTP/1.1 响应 `Transfer-Encoding` 的 `chunked/gzip/deflate/compress` 链式解码
- **🧱 堆内存管理**：使用 `HeapObject<T>` / `HeapArray<T>` 统一管理堆内存，高频缓冲常驻 Workspace

### 协议能力边界

KernelHttp 以 Windows kernel 主路径实现协议能力，传输层优先 WSK，密码学优先 CNG/BCrypt，不依赖 WinHTTP、WinINet 或 SChannel。当前能力边界如下：

| 协议 | 已支持能力 | 当前边界 |
|------|------------|----------|
| HTTP/1.1 | `Content-Length`、显式 chunked 请求体、响应 `Transfer-Encoding` 链（`chunked`/`gzip`/`deflate`/`compress`）、close-delimited 响应、HEAD/101/无 body 状态码、中间 1xx 跳过、chunked trailer 语法/禁止字段校验与只读 API 暴露、RFC 3986 相对 redirect 解析 | 用户设置请求 `Transfer-Encoding` 会被拒绝；request trailer 暂不支持；不提供入站 request parser/server role；HTTP proxy/CONNECT/TRACE 不在当前主路径；`Range`/条件请求仅作为普通 header 透传；`Accept-Encoding` 不承诺完整 qvalue/content negotiation；`br` 仅作为 `Content-Encoding` 支持 |
| HTTP/2 | TLS ALPN、h2c prior knowledge / Upgrade、SETTINGS、HEADERS/CONTINUATION、DATA、PING、GOAWAY、WINDOW_UPDATE、HPACK、header block 语义校验、HPACK header-list/table-size 限制 | 不支持 RFC 8441 WebSocket over HTTP/2、server push、priority 和完整多流调度；收到禁用的 `PUSH_PROMISE` 视为协议错误；缺失 SETTINGS ACK 会以 `SETTINGS_TIMEOUT` 关闭；收到 GOAWAY 会终止当前单请求连接语义 |
| WebSocket | ws/wss 握手、文本/二进制发送、空消息、控制帧校验、公开 Ping/Pong/CloseEx、selected subprotocol 查询、默认接收完整消息 | 主路径是 HTTP/1.1 Upgrade；不支持自定义 opening handshake headers、扩展协商和接收分片回调；主动 close 发送 close frame 后关闭 transport，收到 peer close 时 echo 后关闭 |
| TLS | TLS 1.2/1.3、TLS 1.3 全部标准 cipher suite、TLS 1.2 ECDHE/DHE/RSA key exchange、AES-GCM/AES-CBC/ChaCha20-Poly1305、X25519/X448/NIST P curves/FFDHE、RSA-PSS/RSA-PKCS1/ECDSA/EdDSA signature scheme、SNI、ALPN、PSK/session ticket、0-RTT 显式 opt-in、KeyUpdate、record padding、客户端证书、OCSP stapling 解析、证书链重排和校验、Name Constraints、certificatePolicies、IDNA、OCSP/CRL 撤销缓存、SPKI pin | 默认策略不启用 TLS 1.2 RSA key exchange、CBC 或 renegotiation；这些只在 `TlsSecurityProfile::CompatibilityExplicit` 且相应开关显式开启时可用。库层不硬编码系统 CA，不把 WinHTTP/WinINet/SChannel 作为内核主路径；在线撤销获取由调用侧提供有界输入或缓存 |

| 未实现 optional 能力 | 当前处理 |
|----------------------|----------|
| WebSocket extensions（如 permessage-deflate） | 作为非目标，服务端返回未请求扩展时拒绝 |
| WebSocket over HTTP/2 RFC 8441 | 延期，不协商 extended CONNECT，当前 WebSocket 主路径是 HTTP/1.1 Upgrade |
| WebSocket 自定义 opening headers | 延期；Origin、Authorization、Cookie 等需要单独 header validation 和敏感头策略 |
| WebSocket 主动 close handshake | 客户端简化语义：发送 close frame 后关闭 transport；收到 peer close 时 echo 后关闭 |
| WebSocket 接收分片回调 | 默认聚合为完整消息；回调式逐分片暴露暂不支持 |
| HTTP 代理 / CONNECT / TRACE | 不在当前内核客户端主路径内 |
| HTTP 入站 request parser / server role | 非目标，当前项目定位为客户端协议栈 |
| HTTP request trailer | chunked 上传不携带 request trailer；用户手写 `Transfer-Encoding` 仍被拒绝 |
| HTTP/2 full multiplexing / server push / priority | 不提供完整多流调度；禁用 push，收到非法 `PUSH_PROMISE` 视为协议错误；priority 不作为公共调度能力 |
| RFC 9111 cache / Range / conditional request | 不提供内核缓存 API；`Range` 和条件请求字段仅普通透传，不合并或验证语义 |
| Accept-Encoding qvalue/content negotiation | 仅表达默认响应 decoder 子集；调用方可覆盖 header，但不提供完整协商语义 |
| TLS 1.2 RSA key exchange / CBC / renegotiation | 已实现但默认关闭；必须使用 `CompatibilityExplicit` policy 并分别开启 RSA、CBC、renegotiation 兼容开关 |
| TLS 1.3 0-RTT | 已实现但默认关闭；必须启用 early data，且调用方显式声明请求 replay-safe |
| 在线 OCSP/CRL 抓取 | 库层不主动递归发起在线抓取；调用方通过外部 trust/cert/revocation 数据或已缓存条目驱动强撤销判定 |

自动 redirect 默认拒绝 HTTPS 到 HTTP 降级；跨 scheme/host/port redirect 会清理 `Authorization`、`Cookie` 和 `Proxy-Authorization`；301/302 仅默认把 POST 改写为 GET，303 除 HEAD 外改写为 GET，307/308 保留方法和 body。reused stale 连接失败只对 `GET`、`HEAD`、`OPTIONS` 等安全/幂等请求自动 fresh retry，不会自动重放 POST/PUT/PATCH/DELETE。

close-delimited HTTP/1.x 响应和 `101 Switching Protocols` 升级响应不会回到普通 HTTP 连接池。同步 HTTP、WebSocket、TLS 和证书验证路径要求在 `PASSIVE_LEVEL` 调用。TLS ALPN 结果必须来自客户端 offer 列表；TLS1.2 选择只有在 TLS1.3 路径取得可验证的版本协商证据后才允许进行，不能把证书错误、ALPN mismatch、网络超时或解密失败当作 TLS1.2-only 结论。TLS 1.3 0-RTT 默认关闭；即使启用，也必须由调用方显式标记 replay-safe，否则返回 `STATUS_NOT_SUPPORTED` 且不发送 early data。
证书主机校验中，IP literal 只匹配 iPAddress SAN，不回退到 dNSName 或 CN。

---

## 🚀 快速开始

### 📋 环境要求

| 组件 | 版本要求 |
|------|---------|
| 操作系统 | Windows 10/11 或 Windows Server 2016+ |
| Visual Studio | 2022 或更高版本 |
| Windows SDK | 10.0.19041.0 或更高 |
| Windows Driver Kit (WDK) | 与 SDK 版本匹配 |

### 📦 安装与构建

#### step1：编译成静态库

1. **克隆仓库**
   ```bash
   git clone https://github.com/x500x/win_kernel_http.git
   cd kernel_http
   ```

2. **使用 Visual Studio 构建**
   
   打开 `KernelHttp.sln`，选择配置和平台：
   
   | 配置 | 说明 |
   |------|------|
   | Debug | 调试版本，包含调试符号 |
   | Release | 发布版本，优化性能 |
   
   | 平台 | 说明 |
   |------|------|
   | x64 | 64 位 Intel/AMD 处理器 |
   | ARM64 | ARM 64 位处理器 |
   
   然后按 `Ctrl+Shift+B` 构建解决方案。

3. **使用命令行构建**
   ```powershell
   # 构建 KernelHttpLib 的全部内核 ABI（x64、ARM64）
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
   
   # 只构建单个 ABI
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
   
   # 脚本会在构建前检查对应 ABI 的 MSVC/WDK 工具链
   
   # Debug 版本
   msbuild KernelHttp.sln /p:Configuration=Debug /p:Platform=x64
   
   # Release 版本
   msbuild KernelHttp.sln /p:Configuration=Release /p:Platform=x64
   ```

4. **获取库文件**
   
   构建完成后，库文件位于：
   ```
   <Platform>/<Configuration>/KernelHttpLib.lib
   ```

#### step2：集成到你的项目

1. **包含头文件**
   ```cpp
   // 总头文件入口（推荐）
   #include <KernelHttp/KernelHttp.h>
   ```

2. **链接库文件**
   在项目属性中添加：
   - 附加包含目录：`$(SolutionDir)include`
   - 附加库目录：`$(SolutionDir)src\KernelHttpLib\$(Platform)\$(Configuration)\`
   - 附加依赖项：`KernelHttpLib.lib`

3. **配置项目依赖**
   - 将 `KernelHttpLib` 项目添加到你的解决方案
   - 设置项目依赖关系，确保先编译 `KernelHttpLib`

---

## 📚 API 概览

KernelHttp 提供两层 API：

| API 层 | 命名空间 | 适用场景 |
|--------|---------|---------|
| **高层 API** | `KernelHttp::khttp` | 大多数应用场景，快速开发 |
| **底层 API** | `KernelHttp::engine` | 性能关键、特殊定制、测试调试 |

### 架构层次

```
┌─────────────────────────────────────────────────────────────┐
│                      高层 API (khttp)                        │
│  简洁接口、自动资源管理、适合大多数应用场景                      │
├─────────────────────────────────────────────────────────────┤
│                      底层 API (engine)                       │
│  精细控制、性能优化、支持自定义测试                              │
├─────────────────────────────────────────────────────────────┤
│                    客户端层 (client)                          │
│  HttpClient | HttpsClient | Http2Client | WebSocketClient    │
├─────────────────────────────────────────────────────────────┤
│                    核心抽象层 (core)                          │
│  ITransport | IScratchAllocator | Workspace                  │
├─────────────────────────────────────────────────────────────┤
│                    协议实现层                                 │
│  HTTP/1.1 | HTTP/2 (HPACK) | WebSocket | TLS 1.2/1.3        │
├─────────────────────────────────────────────────────────────┤
│                    基础设施层                                 │
│  WSK 网络传输 | CNG/BCrypt 密码学 | 连接池                    │
└─────────────────────────────────────────────────────────────┘
```

详细对比请参考 [API 概述文档](docs/api-overview.md)。

### 🔥 高层 API 示例

```cpp
#include <KernelHttp/KernelHttp.h>

// 简单的 HTTP GET 请求
NTSTATUS SimpleHttpGet(net::WskClient& wskClient) {
    // 创建会话
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 发送 GET 请求
    khttp::Response* response = nullptr;
    status = khttp::Get(session, "http://example.com/api", 22, &response);
    
    if (NT_SUCCESS(status)) {
        // 获取状态码
        ULONG statusCode = khttp::ResponseStatusCode(response);
        
        // 获取响应体
        const UCHAR* body = khttp::ResponseBody(response);
        SIZE_T bodyLength = khttp::ResponseBodyLength(response);
        
        // 处理响应...
        
        // 释放响应
        khttp::ResponseRelease(response);
    }

    // 关闭会话
    khttp::SessionClose(session);
    return status;
}
```

### 🔧 底层 API 示例

```cpp
#include <KernelHttp/KernelHttp.h>

// 精细控制的 HTTPS 请求
NTSTATUS AdvancedHttpsRequest(net::WskClient& wskClient) {
    // 创建会话（带 TLS 配置）
    KH_SESSION session = nullptr;
    KhSessionOptions sessionOptions = {};
    sessionOptions.Tls.CertificatePolicy = KhCertificatePolicy::Verify;
    sessionOptions.Tls.MinVersion = KhTlsVersion::Tls13;
    
    NTSTATUS status = KhSessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 创建请求
    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    // 配置请求
    const char* url = "https://api.example.com/data";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);
    KhHttpRequestSetHeader(request, "User-Agent", 10, "KernelHttp/1.0", 14);

    // 发送请求
    KH_RESPONSE response = nullptr;
    status = KhHttpSendSync(session, request, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        // 获取响应视图
        KhResponseView view = {};
        KhResponseGetView(response, &view);
        
        // 处理响应...
        
        KhResponseRelease(response);
    }

    // 清理资源
    KhHttpRequestRelease(request);
    KhSessionClose(session);
    return status;
}
```

---

## 🏗️ 项目结构

```
KernelHttp/
├── include/                          # 公开头文件
│   └── KernelHttp/
│       ├── KernelHttp.h             # 总头文件入口
│       ├── KernelHttpConfig.h       # 配置选项（默认超时、缓冲区大小等）
│       ├── client/                  # 客户端封装
│       │   ├── HttpClient.h         # HTTP/1.1 明文客户端
│       │   ├── HttpsClient.h        # HTTPS 客户端（TLS + ALPN 自动选择 HTTP/1.1 或 HTTP/2）
│       │   ├── Http2Client.h        # HTTP/2 客户端（支持 TLS ALPN、h2c Prior Knowledge、h2c Upgrade）
│       │   └── WebSocketClient.h    # WebSocket 客户端（支持 ws:// 和 wss://）
│       ├── core/                    # 核心抽象层
│       │   ├── ITransport.h         # 传输层抽象接口（Send/Receive/ReceiveWithTimeout）
│       │   ├── IScratchAllocator.h  # 临时内存分配器接口（TLS 握手、证书验证等）
│       │   ├── TlsTransport.h       # TLS 传输层适配器（ITransport + TlsConnection，自动加解密）
│       │   ├── WskTransport.h       # WSK 传输层适配器（ITransport + WskSocket，明文传输）
│       │   └── WorkspaceScratchAllocator.h  # 工作空间临时分配器（常驻堆内存）
│       ├── khttp/                   # 高层 API（KernelHttp::khttp）
│       │   ├── Types.h              # 句柄类型、枚举、配置结构体、回调类型
│       │   ├── Session.h            # 会话创建/关闭
│       │   ├── Request.h            # 请求构造（URL、方法、头部、正文）
│       │   ├── Http.h               # 同步快捷函数（Get/Post/Put/Patch/Delete/Head/Options）
│       │   ├── HttpAsync.h          # 异步入口（GetAsync/PostAsync/SendAsync）
│       │   ├── AsyncOp.h            # 异步操作管理（Wait/Cancel/GetResponse）
│       │   ├── Response.h           # 响应只读访问（StatusCode/Body/Header）
│       │   ├── WebSocket.h          # WebSocket 连接/收发/关闭
│       │   ├── Detail.h             # 内部桥接接口
│       │   └── Test.h               # 测试辅助
│       ├── engine/                  # 底层 API（KernelHttp::engine）
│       │   ├── Engine.h             # 完整 API 定义（Kh* 前缀）
│       │   ├── EngineImpl.h         # 引擎实现
│       │   ├── EngineInternal.h     # 内部结构（非公开）
│       │   ├── EngineUtils.h        # 工具函数
│       │   ├── ConnectionPool.h     # 连接池实现
│       │   ├── Workspace.h          # 工作空间管理
│       │   ├── Async.h              # 异步操作实现
│       │   ├── HttpEngine.h         # HTTP 引擎
│       │   ├── WsEngine.h           # WebSocket 引擎
│       │   ├── UrlParser.h          # URL 解析器
│       │   ├── HandleAlloc.h        # 句柄分配器
│       │   └── HandleTypes.h        # 句柄类型定义
│       ├── http/                    # HTTP 协议
│       │   ├── HttpTypes.h          # 基础类型（HttpText/HttpHeader/HeapArray/HeapObject）
│       │   ├── HttpParser.h         # HTTP 响应解析器
│       │   ├── HttpRequest.h        # HTTP 请求构建器
│       │   ├── HttpResponse.h       # HTTP 响应结构
│       │   ├── HttpCoding.h          # 共享编码解码（gzip/deflate/br/compress）
│       │   ├── HttpContentEncoding.h # 内容编码（gzip/deflate/br）
│       │   └── HttpTransferCoding.h  # HTTP/1.1 Transfer-Encoding 链解析
│       ├── http2/                   # HTTP/2 协议
│       │   ├── Http2Frame.h         # 帧类型、SETTINGS、帧编解码
│       │   ├── Http2Stream.h        # Stream 状态机
│       │   ├── Http2Connection.h    # 连接管理（前导、SETTINGS 交换、帧循环）
│       │   ├── Hpack.h              # HPACK 编解码器
│       │   ├── HpackHuffman.h       # Huffman 编解码表
│       │   └── HpackStaticTable.h   # 静态表 61 项
│       ├── tls/                     # TLS 协议
│       │   ├── TlsConnection.h      # TLS 连接（支持 TLS 1.2/1.3）
│       │   ├── TlsContext.h         # TLS 上下文
│       │   ├── TlsRecord.h          # TLS 记录协议
│       │   ├── TlsHandshake12.h     # TLS 1.2 握手
│       │   ├── TlsHandshake13.h     # TLS 1.3 握手（含 PSK/0-RTT）
│       │   ├── CertificateStore.h   # 证书存储（信任锚/锁定）
│       │   └── CertificateValidator.h # 证书验证器
│       ├── websocket/               # WebSocket 协议
│       │   └── WebSocketFrame.h     # 帧编解码、握手验证
│       ├── net/                     # 网络传输层 (WSK)
│       │   ├── WskClient.h          # WSK 客户端
│       │   ├── WskSocket.h          # WSK 套接字
│       │   └── WskBuffer.h          # WSK 缓冲区
│       └── crypto/                  # 密码学 (CNG/BCrypt)
│           ├── CngProvider.h        # CNG 提供者（密钥、哈希、签名）
│           └── CngProviderCache.h   # CNG 提供者缓存
├── src/                              # 源代码
│   ├── KernelHttpLib/               # 核心静态库实现
│   │   ├── client/                  # 客户端实现
│   │   ├── core/                    # 核心抽象实现
│   │   ├── crypto/                  # 密码学实现
│   │   ├── engine/                  # 底层引擎
│   │   ├── http/                    # HTTP 协议实现
│   │   ├── http2/                   # HTTP/2 协议实现
│   │   ├── khttp/                   # 高层 API 实现
│   │   ├── net/                     # 网络传输 (WSK)
│   │   ├── tls/                     # TLS 协议实现
│   │   └── websocket/               # WebSocket 实现
│   └── KernelHttpTest/              # 测试驱动项目
│       └── samples/                 # 示例代码
├── tests/                            # 测试代码
├── docs/                             # 文档
├── certs/                            # 证书相关
└── tools/                            # 工具脚本
```

---

## 📖 文档索引

| 文档 | 说明 |
|------|------|
| [API 概述](docs/api-overview.md) | 两层 API 对比和选择指南 |
| [高层 API 文档](docs/high-level-api.md) | 面向大多数场景的简洁 API |
| [底层 API 文档](docs/low-level-api.md) | 面向精细控制的 API |
| [HTTP 状态码参考](docs/http-status-codes.md) | HTTP 状态码含义说明 |
| [NTSTATUS 错误码参考](docs/ntstatus-codes.md) | 内核错误码说明 |
| [文档索引](docs/README.md) | 完整文档结构 |

---

## 🔧 配置选项

### 会话配置

```cpp
khttp::SessionConfig config = khttp::DefaultSessionConfig();

// 响应缓冲区大小（默认 1 MiB，0 表示不限制）
config.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB

// 请求构造缓冲区（默认 16 KiB；大请求体可按需增大）
config.RequestBufferBytes = 96 * 1024;

// 连接池容量（默认 8）
config.PoolCapacity = 16;

// 每主机最大连接数（默认 2）
config.MaxConnsPerHost = 4;

// 空闲超时（默认 30 秒）
config.IdleTimeoutMs = 60000;  // 60 秒

// 响应缓冲池类型（默认 NonPaged；内核路径当前要求 NonPaged）
config.ResponsePool = khttp::PoolType::NonPaged;

// TLS 配置
config.Tls.MinVersion = khttp::TlsVersion::Tls13;
config.Tls.MaxVersion = khttp::TlsVersion::Tls13;
config.Tls.Certificate = khttp::CertPolicy::Verify;
config.Tls.HandshakeTimeoutMs = 120000;  // TLS 握手超时（默认 120 秒）
```

### 连接策略

```cpp
khttp::Request* request = nullptr;
khttp::RequestCreate(session, &request);

// 连接策略
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ReuseOrCreate);  // 复用或新建（默认）
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ForceNew);       // 强制新建
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::NoPool);         // 不进连接池

// 地址族
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Any);      // 系统默认
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Ipv4);     // 仅 IPv4
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Ipv6);     // 仅 IPv6
```

---

## 🧪 测试

### 运行测试

```powershell
# 运行已构建的用户态协议测试
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_interop_matrix_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'

# 本地 TLS 互通矩阵：只使用 127.0.0.1；OpenSSL/BoringSSL 缺失时会明确 SKIP
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64

# 构建库和示例驱动
msbuild KernelHttp.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

### 测试文件

| 测试文件 | 测试内容 |
|---------|---------|
| `http_parser_tests.cpp` | HTTP 解析器 |
| `hpack_tests.cpp` | HTTP/2 HPACK 编解码 |
| `http2_frame_tests.cpp` | HTTP/2 帧处理 |
| `http2_client_tests.cpp` | HTTP/2 客户端测试 |
| `tls_crypto_tests.cpp` | TLS 密码学向量和 key exchange |
| `tls_handshake_tests.cpp` | TLS ClientHello/握手编码解析 |
| `tls_record_tests.cpp` | TLS 记录协议 |
| `tls_interop_matrix_tests.cpp` | TLS 能力/策略/互通矩阵声明 |
| `tests/integration/tls_matrix.ps1` | 本地 OpenSSL/BoringSSL 回环互通矩阵 |
| `websocket_frame_tests.cpp` | WebSocket 帧处理 |
| `khttp_tests.cpp` | 高层 API 测试 |
| `high_level_api_tests.cpp` | 高层 API 集成测试 |
| `websocket_client_tests.cpp` | WebSocket 客户端测试 |

---

## ⚠️ 错误处理

项目使用 Windows NTSTATUS 错误码。详细说明请参考 [NTSTATUS 错误码参考](docs/ntstatus-codes.md)。

### 常见错误码

| NTSTATUS | 描述 | 处理建议 |
|----------|------|----------|
| `STATUS_SUCCESS` | 操作成功 | - |
| `STATUS_INVALID_PARAMETER` | 参数无效 | 检查输入参数 |
| `STATUS_INSUFFICIENT_RESOURCES` | 资源不足 | 减少并发请求或增加资源 |
| `STATUS_IO_TIMEOUT` | 操作超时 | 增加超时时间或检查网络 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 | 重试请求 |
| `STATUS_TRUST_FAILURE` | 证书信任失败 | 检查证书配置 |

### 错误处理示例

```cpp
NTSTATUS status = khttp::Get(session, url, urlLength, &response);
if (!NT_SUCCESS(status)) {
    switch (status) {
    case STATUS_IO_TIMEOUT:
        // 超时处理：重试或报告错误
        DbgPrint("Request timed out\n");
        break;
    case STATUS_TRUST_FAILURE:
        // 证书错误：检查证书配置
        DbgPrint("Certificate verification failed\n");
        break;
    case STATUS_CONNECTION_DISCONNECTED:
        // 连接断开：重新连接
        DbgPrint("Connection lost, retrying...\n");
        break;
    default:
        // 其他错误：记录日志
        DbgPrint("Request failed: 0x%08X\n", status);
        break;
    }
}
```

---

## 🎯 最佳实践

### 1. 资源管理

```cpp
// ✅ 正确：确保在所有路径上释放资源
NTSTATUS DoRequest(khttp::Session* session) {
    khttp::Response* response = nullptr;
    NTSTATUS status = khttp::Get(session, url, urlLen, &response);
    
    // 即使失败也要释放可能已分配的响应
    if (NT_SUCCESS(status)) {
        // 处理响应...
    }
    
    khttp::ResponseRelease(response);  // 接受 nullptr，可无条件调用
    return status;
}

// ❌ 错误：失败时未释放响应
NTSTATUS DoRequestWrong(khttp::Session* session) {
    khttp::Response* response = nullptr;
    NTSTATUS status = khttp::Get(session, url, urlLen, &response);
    if (!NT_SUCCESS(status)) {
        return status;  // 泄漏！response 可能非空
    }
    // ...
    khttp::ResponseRelease(response);
    return status;
}
```

### 2. 连接复用

```cpp
// ✅ 正确：使用连接池复用连接
khttp::SessionConfig config = khttp::DefaultSessionConfig();
config.PoolCapacity = 16;        // 增加池容量
config.MaxConnsPerHost = 4;      // 增加每主机连接数
config.IdleTimeoutMs = 120000;   // 延长空闲超时

// ❌ 避免：频繁创建新连接
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ForceNew);
```

### 3. 异步操作

```cpp
// ✅ 正确：使用异步避免阻塞
khttp::AsyncOp* op = nullptr;
khttp::GetAsync(session, url, urlLen, &op);
khttp::AsyncWait(op, 30000);  // 等待 30 秒

// 处理响应...
khttp::AsyncRelease(op);

// ❌ 避免：在内核线程中长时间同步等待
khttp::Get(session, url, urlLen, &response);  // 可能阻塞很久
```

---

## 📊 性能优化

### 连接池配置

```cpp
// 根据应用需求调整连接池参数
config.PoolCapacity = 32;           // 增加池容量
config.MaxConnsPerHost = 8;         // 增加每主机连接数
config.IdleTimeoutMs = 120000;      // 延长空闲超时
```

### 缓冲区管理

```cpp
// 响应缓冲区（0 表示不限制）
config.MaxResponseBytes = 4 * 1024 * 1024;  // 4 MiB

// 请求构造缓冲区，需容纳 HTTP/1.1 请求行、请求头和请求体
config.RequestBufferBytes = 96 * 1024;

// 单次发送覆盖响应上限
khttp::SendOptions options = khttp::DefaultSendOptions();
options.MaxResponseBytes = 0;  // 0 表示不限制
```

---

## 🔐 安全考虑

### TLS 配置

```cpp
// 推荐：使用 TLS 1.3
config.Tls.MinVersion = khttp::TlsVersion::Tls13;
config.Tls.MaxVersion = khttp::TlsVersion::Tls13;

// 证书验证
config.Tls.Certificate = khttp::CertPolicy::Verify;

// TLS 握手超时（默认 120 秒）
config.Tls.HandshakeTimeoutMs = 120000;

// 自定义证书存储
tls::CertificateStore store = {};
// 添加信任锚...
config.Tls.Store = &store;
```

### TLS 1.3 安全增强

项目已实现以下 TLS 1.3 安全加固：

- **签名方案校验**：严格校验服务器证书签名算法，拒绝弱签名方案
- **降级保护**：防止 TLS 1.3 到 TLS 1.2 的协议降级攻击
- **PSK/HRR 校验**：TLS 1.3 ticket 绑定签发时间、SNI、ALPN、cipher 和版本；HelloRetryRequest 后重新计算 PSK binder
- **0-RTT 策略**：默认关闭；启用时必须由调用方声明请求 replay-safe
- **密钥清零**：会话结束后安全清零所有密钥材料
- **信任锚校验**：验证证书链到可信根的完整性

### 证书锁定

```cpp
// 使用证书锁定增强安全性
tls::CertificateTrustAnchor anchor = {};
anchor.SubjectName = rootCertSubject;
anchor.SubjectNameLength = rootCertSubjectLen;
RtlCopyMemory(anchor.SubjectPublicKeySha256, rootSpkiHash, 32);
anchor.MatchSubjectPublicKey = true;

tls::CertificatePin pin = {};
pin.HostName = "example.com";
pin.HostNameLength = 11;
RtlCopyMemory(pin.LeafSubjectPublicKeySha256, leafSpkiHash, 32);

// 创建证书存储
tls::CertificateStoreOptions storeOptions = {};
storeOptions.TrustAnchors = &anchor;
storeOptions.TrustAnchorCount = 1;
storeOptions.Pins = &pin;
storeOptions.PinCount = 1;

tls::CertificateStore store;
store.Initialize(storeOptions);

// 应用到会话
config.Tls.Store = &store;
```

### ALPN 协议协商

```cpp
// 设置 ALPN 协议（用于 HTTP/2 协商）
config.Tls.Alpn = "h2";
config.Tls.AlpnLength = 2;

// 或者同时支持 HTTP/1.1 和 HTTP/2
// 在 TlsConnection 中通过 TlsAlpnProtocol 数组设置
```

---

## 🛠️ 开发规范

### 代码风格

- 使用 C++17 特性，但遵循内核限制
- **无异常**、**无 RTTI**，避免直接 `new/delete`，优先使用项目内堆对象封装或 API 释放函数
- 使用 `namespace`、类、RAII、轻量模板
- 所有函数标记 `noexcept`
- 使用 SAL 注解（`_In_`、`_Out_`、`_Must_inspect_result_` 等）

### 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
feat: 添加新功能
fix: 修复 bug
docs: 文档更新
style: 代码格式调整
refactor: 代码重构
test: 测试相关
chore: 构建/工具相关
```

---

## 🤝 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. **Fork** 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'feat: Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 **Pull Request**

### 贡献要求

- 遵循项目代码风格
- 添加必要的测试
- 更新相关文档
- 确保所有测试通过

---

## 📄 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

---

## 🔗 相关资源

- [Windows Driver Kit (WDK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Windows Sockets Kernel (WSK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/windows-sockets-kernel)
- [Cryptography Next Generation (CNG)](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-features)

---

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 [Issue](https://github.com/x500x/win_kernel_http/issues) 到项目仓库
- 查看项目文档和示例代码
- 参考相关技术文档

---

## 🙏 致谢

感谢所有为项目做出贡献的开发者！

---

<div align="center">

**[⬆ 回到顶部](#kernelhttp)**

</div>
