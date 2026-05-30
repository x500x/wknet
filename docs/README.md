# KernelHttp 文档

欢迎阅读 KernelHttp 文档！本文档包含面向开发者的 API 指南和参考。

## 文档结构

### 1. [API 概述](api-overview.md)
KernelHttp 的两层 API 结构概述，包括：
- 高层 API 和底层 API 的对比
- 如何选择适合的 API
- 代码示例对比
- 性能考虑和最佳实践

### 2. [高层 API 文档](high-level-api.md)
面向使用 KernelHttp 高层接口编写驱动代码的开发者。高层 API 位于 `KernelHttp::khttp` 命名空间，提供：
- 简洁的接口设计
- 自动资源管理
- 完整的 HTTP 和 WebSocket 功能
- 异步操作支持

**适用场景**：大多数应用场景，快速开发，初学者

### 3. [底层 API 文档](low-level-api.md)
面向需要更精细控制 KernelHttp 内部机制的开发者。底层 API 位于 `KernelHttp::engine` 命名空间，提供：
- 精细的连接池、TLS 配置控制
- 直接访问内部组件和缓冲区
- 完整的测试钩子支持
- 性能优化机会

**适用场景**：性能关键应用，特殊定制需求，测试和调试

### 4. [项目说明](../README.md)
项目概述、构建说明和使用指南。

### 5. [工程约束](../AGENTS.md)
开发规范、工程约束和编码标准。

## 快速开始

### 高层 API 快速示例

```cpp
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/khttp/Response.h>

NTSTATUS SimpleHttpGet(net::WskClient& wskClient) {
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    khttp::Response* response = nullptr;
    status = khttp::Get(session, "http://example.com", 18, &response);
    
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

### 底层 API 快速示例

```cpp
#include <KernelHttp/engine/Engine.h>

NTSTATUS SimpleHttpGet(net::WskClient& wskClient) {
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

    const char* url = "http://example.com";
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

## API 选择指南

| 场景 | 推荐 API | 原因 |
|------|---------|------|
| 快速开发 | 高层 API | 接口简洁，样板代码少 |
| 初学者 | 高层 API | 易于学习和使用 |
| 标准 HTTP 功能 | 高层 API | 覆盖常见用例 |
| 性能关键应用 | 底层 API | 精细控制，优化机会多 |
| 特殊定制需求 | 底层 API | 直接访问内部组件 |
| 测试和调试 | 底层 API | 完整的测试钩子支持 |
| 自定义连接池 | 底层 API | 可配置连接池参数 |
| 自定义 TLS 配置 | 底层 API | 细粒度 TLS 控制 |

## 示例代码

### 高层 API 示例
- 会话创建和配置
- HTTP 同步/异步请求
- 各种请求体类型
- HTTPS 和 TLS 配置
- WebSocket 连接和通信

### 底层 API 示例
- 完整的 HTTP GET/POST 请求
- TLS 配置和证书管理
- 异步操作和回调
- WebSocket 连接和消息传递
- 连接池管理和优化

## 开发规范

### 错误处理
```cpp
NTSTATUS status = SomeApiCall();
if (!NT_SUCCESS(status)) {
    // 处理错误
    switch (status) {
    case STATUS_INVALID_PARAMETER:
        // 参数错误
        break;
    case STATUS_INSUFFICIENT_RESOURCES:
        // 资源不足
        break;
    case STATUS_IO_TIMEOUT:
        // 超时
        break;
    default:
        // 其他错误
        break;
    }
}
```

### 资源管理
```cpp
// 创建资源
Resource* resource = nullptr;
NTSTATUS status = CreateResource(&resource);
if (!NT_SUCCESS(status)) {
    return status;
}

// 使用资源
status = UseResource(resource);

// 释放资源（在所有代码路径上）
ReleaseResource(resource);
```

### 异步操作
```cpp
AsyncOp* op = nullptr;
NTSTATUS status = StartAsyncOperation(&op);
if (!NT_SUCCESS(status)) {
    return status;
}

// 等待完成
status = WaitForCompletion(op, timeoutMs);
if (NT_SUCCESS(status)) {
    // 获取结果
    Result* result = nullptr;
    status = GetAsyncResult(op, &result);
    if (NT_SUCCESS(status)) {
        // 使用结果
        ReleaseResult(result);
    }
}

// 释放异步操作
ReleaseAsyncOp(op);
```

## 常见问题

### Q: 如何选择高层 API 和底层 API？
A: 大多数情况下使用高层 API。如果需要精细控制、性能优化或特殊定制，使用底层 API。

### Q: 两个 API 可以同时使用吗？
A: 是的，可以在同一项目中混合使用。高层 API 在底层 API 之上实现，两者兼容。

### Q: 如何调试 API 调用问题？
A: 对于高层 API，使用示例代码作为参考。对于底层 API，使用测试钩子注入模拟数据。

### Q: 底层 API 是否更高效？
A: 底层 API 提供了更多优化机会，但需要开发者手动管理。对于大多数应用，高层 API 的性能已经足够。

### Q: 如何处理 TLS 证书问题？
A: 使用 `CertificateStore` 进行证书锁定，或设置 `CertificatePolicy::NoVerify` 跳过证书验证（仅用于测试）。

## 相关资源

- **公开头文件**：`include/KernelHttp/` 目录，推荐从 `include/KernelHttp/KernelHttp.h` 总头开始
- **核心实现**：`src/KernelHttpLib/` 目录
- **示例代码**：`src/KernelHttpExample/samples/` 目录
- **测试代码**：`tests/` 目录
- **构建工具**：`tools/` 目录

## 版本信息

- **当前版本**：1.0
- **最后更新**：2026年5月30日
- **兼容性**：Windows 内核驱动

## 联系方式

如有问题或建议，请通过以下方式联系：
- 提交 Issue 到项目仓库
- 查看项目文档和示例代码
- 参考相关技术文档

---

**注意**：本文档基于 KernelHttp 项目代码生成，所有 API 说明和示例都基于实际代码实现。如有疑问，请参考源代码中的注释和示例。
