# KernelHttp API 概述

KernelHttp 提供了两层 API 供开发者使用：**高层 API** 和 **底层 API**。两层 API 都面向内核驱动开发，遵循 Windows 内核编程约束（无异常、无 RTTI，避免直接 `new/delete`），传输层使用 WSK，密码学使用 CNG/BCrypt。

## API 层次结构

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

## 协议能力边界

KernelHttp 支持的是内核客户端主路径上的现代协议子集，而不是所有 RFC optional 扩展。同步 HTTP、WebSocket、TLS 和证书验证路径必须在 `PASSIVE_LEVEL` 调用。

| 协议 | 已支持能力 | 当前不支持或受限能力 |
|------|------------|----------------------|
| HTTP/1.1 | `Content-Length`、响应 `Transfer-Encoding` 链（`chunked`/`gzip`/`deflate`/`compress`）、close-delimited 响应、HEAD/101/无 body 状态码、中间 1xx 跳过 | chunked 上传、响应 trailer 暴露；用户设置请求 `Transfer-Encoding` 会返回 `STATUS_NOT_SUPPORTED`；`br` 仅作为 `Content-Encoding` 支持 |
| HTTP/2 | ALPN、h2c prior knowledge / Upgrade、SETTINGS、HEADERS/CONTINUATION、DATA、PING、GOAWAY、WINDOW_UPDATE、HPACK | server push、priority、复杂多流调度、未以 `END_STREAM`/`RST_STREAM`/`GOAWAY` 结束的半截响应 |
| WebSocket | ws/wss 握手、文本/二进制发送、控制帧校验、Ping/Pong/Close、默认完整消息接收 | extensions、接收分片回调、permessage-deflate |
| TLS/证书 | TLS 1.2/1.3、ECDHE + AES-GCM 主路径、TLS 1.3 降级保护、dNSName/iPAddress SAN、CN/EKU/KeyUsage/BasicConstraints/链签名/信任锚/SPKI pin | TLS 客户端证书、CBC、ChaCha20-Poly1305、OCSP/CRL 撤销检查、IDNA |

close-delimited HTTP/1.x 响应和 `101 Switching Protocols` 升级响应不会进入普通 HTTP 连接池。TLS ALPN 结果必须严格匹配客户端 offer 列表。TLS1.2 选择必须来自可验证的版本协商结果。证书错误、ALPN mismatch、TCP/WSK timeout、record 解密失败或 Finished 验证失败都不能被归类为 TLS1.2-only。
证书主机校验中，URL host 为 IP literal 时只匹配 iPAddress SAN，不回退到 dNSName 或 CN。
证书策略当前为硬策略：叶子证书默认要求 ServerAuth EKU、KeyUsage digitalSignature，且不能是 CA；中间/根证书要求 BasicConstraints CA 和 KeyUsage keyCertSign。OCSP/CRL 撤销检查未实现，调用方要求撤销检查时返回 `STATUS_NOT_SUPPORTED`。

### 核心抽象层说明

#### ITransport 接口

`ITransport` 是传输层的抽象接口，定义了基本的发送和接收操作：

```cpp
class ITransport {
public:
    virtual NTSTATUS Send(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept = 0;
    virtual NTSTATUS Receive(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept = 0;
    virtual NTSTATUS ReceiveWithTimeout(void* buffer, SIZE_T length, SIZE_T* bytesReceived, ULONG timeoutMs) noexcept = 0;
};
```

实现类：
- `WskTransport`：WSK 套接字传输层适配器
- `TlsTransport`：TLS 传输层适配器（组合 `ITransport` + `TlsConnection`）

#### 连接池

连接池管理 HTTP/HTTPS 连接的复用，支持：
- 可配置的池容量（`PoolCapacity`）
- 每主机最大连接数（`MaxConnsPerHost`）
- 可配置的请求构造缓冲（`RequestBufferBytes`）
- 空闲超时自动释放（`IdleTimeoutMs`）
- 连接策略：`ReuseOrCreate`（复用或新建）、`ForceNew`（强制新建）、`NoPool`（不进池）

#### 工作空间（Workspace）

工作空间提供临时内存分配，用于：
- TLS 握手缓冲区
- HTTP 解析临时存储
- 证书验证临时存储
- HTTP/2 帧编解码缓冲
- WebSocket 帧处理缓冲

工作空间使用常驻堆内存，避免频繁的内核内存分配。高频使用的缓冲区（如 HTTP header、HPACK 动态表等）在会话生命周期内保持分配状态。

#### 内存管理

项目使用 `HeapObject<T>` 和 `HeapArray<T>` 模板统一管理堆内存：

```cpp
// 单个对象
HeapObject<SomeStruct> obj;
obj.Allocate();
obj->field = value;

// 数组
HeapArray<int> arr(100);
arr[0] = 42;
```

这些模板：
- 在析构时自动释放内存
- 禁止拷贝，防止意外的内存泄漏
- 提供 `IsValid()` 检查分配状态

#### 并发安全

项目实现了以下并发保护机制：

- **连接池**：使用自旋锁保护连接的借用和归还
- **句柄释放**：原子操作确保句柄只释放一次
- **异步完成**：使用原子标志防止重复完成
- **Session drain**：等待所有异步操作完成后再关闭会话
- **Workspace 隔离**：异步路径使用独立的 Workspace，避免数据竞争

## API 对比

| 特性 | 高层 API (`khttp`) | 底层 API (`engine`) |
|------|-------------------|---------------------|
| **命名空间** | `KernelHttp::khttp` | `KernelHttp::engine` |
| **头文件位置** | `include/KernelHttp/khttp/` 或总头 `include/KernelHttp/KernelHttp.h` | `include/KernelHttp/engine/` 或总头 `include/KernelHttp/KernelHttp.h` |
| **接口风格** | 简洁、面向对象 | C 风格、函数式 |
| **资源管理** | 自动（通过 RAII 包装） | 手动（调用方负责） |
| **学习曲线** | 低 | 中 |
| **灵活性** | 中等 | 高 |
| **性能优化** | 有限 | 丰富 |
| **测试支持** | 有限 | 丰富测试钩子 |
| **适用场景** | 大多数应用 | 性能关键、特殊定制 |

## 选择指南

### 使用高层 API 的场景

✅ **大多数应用场景**：高层 API 提供了简洁的接口，适合快速开发。

✅ **快速原型开发**：高层 API 减少了样板代码，加快开发速度。

✅ **常见 HTTP/WebSocket 功能**：高层 API 覆盖了常见的 HTTP 和 WebSocket 用例。

✅ **初学者**：高层 API 更容易学习和使用。

### 使用底层 API 的场景

✅ **性能关键应用**：底层 API 提供了更精细的控制，可以进行性能优化。

✅ **特殊定制需求**：需要自定义连接池、TLS 配置或缓冲区管理。

✅ **测试和调试**：底层 API 提供了丰富的测试钩子，便于单元测试和调试。

✅ **高级功能**：需要访问内部组件或实现特殊协议。

## 核心概念对比

### 会话管理

| 高层 API | 底层 API | 描述 |
|---------|---------|------|
| `SessionCreate` | `KhSessionCreate` | 创建会话 |
| `SessionClose` | `KhSessionClose` | 关闭会话 |
| `SessionConfig` | `KhSessionOptions` | 会话配置 |

### 请求构建

| 高层 API | 底层 API | 描述 |
|---------|---------|------|
| `RequestCreate` | `KhHttpRequestCreate` | 创建请求 |
| `RequestSetUrl` | `KhHttpRequestSetUrl` | 设置 URL |
| `RequestSetMethod` | `KhHttpRequestSetMethod` | 设置 HTTP 方法 |
| `RequestSetHeader` | `KhHttpRequestSetHeader` | 添加请求头 |
| `RequestSetBody` | `KhHttpRequestSetBody` | 设置请求体 |
| `RequestRelease` | `KhHttpRequestRelease` | 释放请求 |

### 发送请求

| 高层 API | 底层 API | 描述 |
|---------|---------|------|
| `Send` | `KhHttpSendSync` | 同步发送 |
| `SendAsync` | `KhHttpSendAsync` | 异步发送 |
| `Get`/`Post`/等 | 无直接对应 | 快捷函数（高层 API 特有） |

### 响应处理

| 高层 API | 底层 API | 描述 |
|---------|---------|------|
| `ResponseStatusCode` | `KhResponseGetView` | 获取状态码 |
| `ResponseBody` | `KhResponseGetView` | 获取响应体 |
| `ResponseGetHeader` | `KhResponseGetHeader` | 获取响应头 |
| `ResponseRelease` | `KhResponseRelease` | 释放响应 |

### 异步操作

| 高层 API | 底层 API | 描述 |
|---------|---------|------|
| `AsyncWait` | `KhAsyncWait` | 等待完成 |
| `AsyncCancel` | `KhAsyncCancel` | 取消操作 |
| `AsyncGetStatus` | 无直接对应 | 获取状态（高层 API 特有） |
| `AsyncRelease` | `KhAsyncRelease` | 释放操作 |

### WebSocket

| 高层 API | 底层 API | 描述 |
|---------|---------|------|
| `WsConnect` | `KhWebSocketConnectSync` | 连接 WebSocket |
| `WsSendText` | `KhWebSocketSendTextSync` | 发送文本 |
| `WsSendBinary` | `KhWebSocketSendBinarySync` | 发送二进制 |
| `WsReceive` | `KhWebSocketReceiveSync` | 接收消息 |
| `WsClose` | `KhWebSocketCloseSync` | 关闭连接 |

## 代码示例对比

### HTTP GET 请求

#### 高层 API
```cpp
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/khttp/Response.h>

NTSTATUS PerformHttpGet(net::WskClient& wskClient) {
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    khttp::Response* response = nullptr;
    status = khttp::Get(session, "http://example.com/api", 22, &response);
    
    if (NT_SUCCESS(status)) {
        ULONG statusCode = khttp::ResponseStatusCode(response);
        const UCHAR* body = khttp::ResponseBody(response);
        SIZE_T bodyLength = khttp::ResponseBodyLength(response);
        // 处理响应...
        khttp::ResponseRelease(response);
    }

    khttp::SessionClose(session);
    return status;
}
```

#### 底层 API
```cpp
#include <KernelHttp/engine/Engine.h>

NTSTATUS PerformHttpGet(net::WskClient& wskClient) {
    KH_SESSION session = nullptr;
    KhSessionOptions sessionOptions = {};
    NTSTATUS status = KhSessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    const char* url = "http://example.com/api";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);

    KH_RESPONSE response = nullptr;
    status = KhHttpSendSync(session, request, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        KhResponseView view = {};
        KhResponseGetView(response, &view);
        // 处理响应...
        KhResponseRelease(response);
    }

    KhHttpRequestRelease(request);
    KhSessionClose(session);
    return status;
}
```

### HTTPS 请求（带 TLS 配置）

#### 高层 API
```cpp
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/khttp/Response.h>

NTSTATUS PerformHttpsRequest(net::WskClient& wskClient) {
    khttp::Session* session = nullptr;
    khttp::SessionConfig config = khttp::DefaultSessionConfig();
    config.Tls.Certificate = khttp::CertPolicy::NoVerify;
    
    NTSTATUS status = khttp::SessionCreate(&wskClient, &config, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    khttp::Response* response = nullptr;
    status = khttp::Get(session, "https://example.com/secure", 26, &response);
    
    if (NT_SUCCESS(status)) {
        // 处理响应...
        khttp::ResponseRelease(response);
    }

    khttp::SessionClose(session);
    return status;
}
```

#### 底层 API
```cpp
#include <KernelHttp/engine/Engine.h>

NTSTATUS PerformHttpsRequest(net::WskClient& wskClient) {
    KH_SESSION session = nullptr;
    KhSessionOptions sessionOptions = {};
    sessionOptions.Tls.CertificatePolicy = KhCertificatePolicy::NoVerify;
    
    NTSTATUS status = KhSessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    const char* url = "https://example.com/secure";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);

    KH_RESPONSE response = nullptr;
    status = KhHttpSendSync(session, request, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        KhResponseView view = {};
        KhResponseGetView(response, &view);
        // 处理响应...
        KhResponseRelease(response);
    }

    KhHttpRequestRelease(request);
    KhSessionClose(session);
    return status;
}
```

### 异步请求

#### 高层 API
```cpp
#include <KernelHttp/khttp/HttpAsync.h>
#include <KernelHttp/khttp/AsyncOp.h>
#include <KernelHttp/khttp/Response.h>

NTSTATUS PerformAsyncRequest(net::WskClient& wskClient) {
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    khttp::AsyncOp* op = nullptr;
    status = khttp::GetAsync(session, "http://example.com/api", 22, &op);
    
    if (NT_SUCCESS(status)) {
        status = khttp::AsyncWait(op, 30000);
        if (NT_SUCCESS(status)) {
            khttp::Response* response = nullptr;
            status = khttp::AsyncGetResponse(op, &response);
            if (NT_SUCCESS(status)) {
                // 处理响应...
                khttp::ResponseRelease(response);
            }
        }
        khttp::AsyncRelease(op);
    }

    khttp::SessionClose(session);
    return status;
}
```

#### 底层 API
```cpp
#include <KernelHttp/engine/Engine.h>

NTSTATUS PerformAsyncRequest(net::WskClient& wskClient) {
    KH_SESSION session = nullptr;
    NTSTATUS status = KhSessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    const char* url = "http://example.com/api";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);

    KH_ASYNC_OPERATION operation = nullptr;
    status = KhHttpSendAsync(session, request, nullptr, &operation);
    
    if (NT_SUCCESS(status)) {
        status = KhAsyncWait(operation, 30000);
        if (NT_SUCCESS(status)) {
            KH_RESPONSE response = nullptr;
            status = KhAsyncGetHttpResponse(operation, &response);
            if (NT_SUCCESS(status)) {
                KhResponseView view = {};
                KhResponseGetView(response, &view);
                // 处理响应...
                KhResponseRelease(response);
            }
        }
        KhAsyncRelease(operation);
    }

    KhHttpRequestRelease(request);
    KhSessionClose(session);
    return status;
}
```

## 混合使用

高层 API 和底层 API 可以在同一项目中混合使用。例如：

1. **高层 API 用于主要逻辑**：使用高层 API 处理常规 HTTP 请求。
2. **底层 API 用于特殊需求**：使用底层 API 进行性能优化或特殊定制。

```cpp
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/engine/Engine.h>

NTSTATUS MixedUsage(net::WskClient& wskClient) {
    // 使用高层 API 创建会话
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 使用高层 API 发送常规请求
    khttp::Response* response = nullptr;
    status = khttp::Get(session, "http://example.com/api", 22, &response);
    if (NT_SUCCESS(status)) {
        // 处理响应...
        khttp::ResponseRelease(response);
    }

    // 使用底层 API 进行特殊定制
    // 注意：需要访问底层会话句柄，这通常通过 khttp/Detail.h 中的内部接口实现
    // 具体实现取决于项目设计
    
    khttp::SessionClose(session);
    return status;
}
```

## 性能考虑

### 高层 API 性能特点

- **开发效率高**：减少样板代码，加快开发速度。
- **运行时开销**：可能有一些额外的抽象层开销。
- **内存管理**：自动资源管理，减少内存泄漏风险。

### 底层 API 性能特点

- **精细控制**：可以直接优化连接池、缓冲区等。
- **减少抽象层**：直接调用底层函数，减少开销。
- **手动管理**：需要手动管理资源，但可以更精确地控制。

### 性能优化建议

1. **连接复用**：使用连接池减少连接建立开销。
2. **缓冲区管理**：合理设置缓冲区大小，避免频繁分配。
3. **异步操作**：使用异步操作避免阻塞线程。
4. **TLS 配置**：合理配置 TLS 参数，平衡安全性和性能。

## 调试和测试

### 高层 API 调试

- 使用示例代码作为参考（`src/KernelHttpTest/samples/HighLevelApiSamples.cpp`）。
- 检查 `NTSTATUS` 返回值。
- 使用日志记录请求和响应。

### 底层 API 调试

- 使用测试钩子注入模拟数据。
- 监控连接池状态。
- 跟踪异步操作状态。
- 使用 IRQL 检查确保在正确的 IRQL 级别调用。

## 迁移指南

### 从高层 API 迁移到底层 API

1. **替换函数调用**：将 `khttp::` 函数替换为 `Kh` 函数。
2. **调整参数类型**：使用底层 API 的结构体类型。
3. **手动资源管理**：添加显式的资源释放代码。
4. **错误处理**：调整错误处理逻辑。

### 从底层 API 迁移到高层 API

1. **简化代码**：使用高层 API 的快捷函数。
2. **移除样板代码**：删除手动资源管理代码。
3. **调整配置**：使用高层 API 的配置结构体。

## 最佳实践

### 通用最佳实践

1. **错误处理**：始终检查 `NTSTATUS` 返回值。
2. **资源管理**：确保在所有代码路径上释放资源。
3. **超时设置**：合理设置超时时间，避免长时间阻塞。
4. **日志记录**：记录关键操作和错误信息。

### 高层 API 最佳实践

1. **使用默认配置**：使用 `DefaultSessionConfig()` 等函数获取默认配置。
2. **快捷函数**：对于简单请求，使用快捷函数（`Get`、`Post` 等）。
3. **异步操作**：对于长时间运行的操作，使用异步 API。

### 底层 API 最佳实践

1. **连接池管理**：合理配置连接池参数。
2. **TLS 配置**：在会话级别设置默认 TLS 配置，在请求级别覆盖。
3. **测试钩子**：使用测试钩子进行单元测试和调试。
4. **性能监控**：监控连接池、缓冲区等资源使用情况。

## 常见问题

### Q: 高层 API 和底层 API 可以同时使用吗？

A: 是的，可以在同一项目中混合使用。高层 API 在底层 API 之上实现，两者兼容。

### Q: 如何选择使用哪个 API？

A: 大多数情况下使用高层 API。如果需要精细控制、性能优化或特殊定制，使用底层 API。

### Q: 底层 API 是否更高效？

A: 底层 API 提供了更多优化机会，但需要开发者手动管理。对于大多数应用，高层 API 的性能已经足够。

### Q: 如何调试 API 调用问题？

A: 对于高层 API，使用示例代码作为参考。对于底层 API，使用测试钩子注入模拟数据。

## 相关文档

- [高层 API 文档](high-level-api.md)：高层 API 的详细使用说明
- [底层 API 文档](low-level-api.md)：底层 API 的详细使用说明
- [项目说明](../README.md)：项目概述和构建说明
- [AGENTS.md](../AGENTS.md)：工程约束和开发规范
