# KernelHttp API 概述

KernelHttp 提供了两层 API 供开发者使用：**高层 API** 和 **底层 API**。两层 API 都面向内核驱动开发，遵循 Windows 内核编程约束（无异常、无 RTTI、显式 `new/delete`），传输层使用 WSK，密码学使用 CNG/BCrypt。

## API 层次结构

```
┌─────────────────────────────────────────────────────────────┐
│                      高层 API (khttp)                        │
│  简洁接口、自动资源管理、适合大多数应用场景                      │
├─────────────────────────────────────────────────────────────┤
│                      底层 API (engine)                       │
│  精细控制、性能优化、支持自定义测试                              │
├─────────────────────────────────────────────────────────────┤
│                    内部组件层                                  │
│  WSK 网络传输 | TLS 连接 | CNG 密码学 | HTTP 解析              │
└─────────────────────────────────────────────────────────────┘
```

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
| **测试支持** | 有限 | 完整测试钩子 |
| **适用场景** | 大多数应用 | 性能关键、特殊定制 |

## 选择指南

### 使用高层 API 的场景

✅ **大多数应用场景**：高层 API 提供了简洁的接口，适合快速开发。

✅ **快速原型开发**：高层 API 减少了样板代码，加快开发速度。

✅ **标准 HTTP/WebSocket 功能**：高层 API 覆盖了常见的 HTTP 和 WebSocket 用例。

✅ **初学者**：高层 API 更容易学习和使用。

### 使用底层 API 的场景

✅ **性能关键应用**：底层 API 提供了更精细的控制，可以进行性能优化。

✅ **特殊定制需求**：需要自定义连接池、TLS 配置或缓冲区管理。

✅ **测试和调试**：底层 API 提供了完整的测试钩子，便于单元测试和调试。

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
| `AsyncGetStatus` | `KhAsyncGetStatus` | 获取状态 |
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

- 使用示例代码作为参考（`src/KernelHttpExample/samples/HighLevelApiSamples.cpp`）。
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
