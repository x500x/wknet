# KernelHttp

一个面向 Windows 内核驱动的 HTTP/HTTPS 客户端实现，完全在内核态运行，不依赖用户态网络组件。

## 项目简介

KernelHttp 是一个纯内核态的 HTTP/HTTPS 客户端库，专为 Windows 内核驱动开发设计。项目从底层开始构建，实现了完整的 HTTP/1.1、HTTP/2、WebSocket 协议支持，以及 TLS 1.2/1.3 握手和加密通信。

### 核心特点

- **纯内核态实现**：不依赖 WinHTTP、WinINet、SChannel 等用户态组件
- **WSK 网络传输**：使用 Windows Sockets Kernel (WSK) 进行网络通信
- **CNG/BCrypt 密码学**：使用内核态 CNG (Cryptography Next Generation) 进行加密操作
- **完整的协议栈**：支持 HTTP/1.1、HTTP/2、WebSocket、TLS 1.2/1.3
- **连接池管理**：内置连接池，支持连接复用和自动管理
- **异步操作**：支持异步请求，避免阻塞内核线程
- **两层 API**：提供高层简洁 API 和底层精细控制 API

## 主要功能

### HTTP/HTTPS 客户端
- HTTP/1.1 和 HTTP/2 协议支持
- 同步和异步请求
- 多种请求体格式：JSON、表单、Multipart、文件上传
- 自动内容解码（gzip、deflate、br）
- 连接池和连接复用

### TLS 安全通信
- TLS 1.2 和 TLS 1.3 支持
- 证书验证和证书锁定
- ALPN 协议协商
- 会话恢复和 0-RTT

### WebSocket 支持
- WebSocket 协议实现
- 文本和二进制消息
- 分片消息支持
- 自动 Ping/Pong 响应

### 密码学基础
- AES-GCM 加密
- ECDHE 密钥交换
- ECDSA/RSA 签名验证
- HKDF 密钥派生
- SHA-256/384 哈希

## 项目结构

```
KernelHttp/
├── include/                      # 公开头文件
│   └── KernelHttp/
│       └── KernelHttp.h          # 总头文件入口
├── src/                          # 源代码
│   ├── KernelHttp/              # 核心库实现源码
│   │   ├── client/              # 高层客户端 API
│   │   ├── crypto/              # 密码学实现
│   │   ├── engine/              # 底层引擎 API
│   │   ├── http/                # HTTP 协议实现
│   │   ├── http2/               # HTTP/2 协议实现
│   │   ├── khttp/               # 高层 API 包装
│   │   ├── net/                 # 网络传输层 (WSK)
│   │   ├── tls/                 # TLS 协议实现
│   │   └── websocket/           # WebSocket 协议实现
│   ├── KernelHttpLib/           # 静态库项目，生成 KernelHttpLib.lib
│   └── KernelHttpExample/       # 示例驱动项目，链接 KernelHttpLib.lib
│       └── samples/             # 示例驱动代码
├── tests/                       # 测试代码
├── docs/                        # 文档
├── certs/                       # 证书相关
├── tools/                       # 工具脚本
└── third_party/                 # 第三方依赖
```

## 快速开始

### 环境要求

- Windows 10/11 或 Windows Server 2016+
- Visual Studio 2022 或更高版本
- Windows Driver Kit (WDK)
- Windows SDK

### 构建步骤

1. **克隆仓库**
   ```bash
   git clone https://github.com/your-username/kernel_http.git
   cd kernel_http
   ```

2. **打开解决方案**
   用 Visual Studio 打开 `KernelHttp.sln`

3. **选择配置**
   - 配置：Debug 或 Release
   - 平台：x64 或 ARM64

4. **构建项目**
   - 构建解决方案 (Ctrl+Shift+B)
   - 或使用命令行：
     ```powershell
     msbuild KernelHttp.sln /p:Configuration=Debug /p:Platform=x64
     ```

### 基本使用

#### 高层 API 示例

```cpp
#include <KernelHttp/KernelHttp.h>

NTSTATUS SimpleHttpRequest(net::WskClient& wskClient) {
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
        // 处理响应
        ULONG statusCode = khttp::ResponseStatusCode(response);
        const UCHAR* body = khttp::ResponseBody(response);
        SIZE_T bodyLength = khttp::ResponseBodyLength(response);
        
        // 使用响应数据...
        
        khttp::ResponseRelease(response);
    }

    // 关闭会话
    khttp::SessionClose(session);
    return status;
}
```

#### 底层 API 示例

```cpp
#include <KernelHttp/KernelHttp.h>

NTSTATUS AdvancedHttpRequest(net::WskClient& wskClient) {
    // 创建会话
    KH_SESSION session = nullptr;
    KhSessionOptions sessionOptions = {};
    sessionOptions.Tls.CertificatePolicy = KhCertificatePolicy::Verify;
    
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
        // 获取响应
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

## 文档

详细文档位于 `docs/` 目录：

- **[API 概述](docs/api-overview.md)**：高层 API 和底层 API 的对比和选择指南
- **[高层 API 文档](docs/high-level-api.md)**：面向大多数应用场景的简洁 API
- **[底层 API 文档](docs/low-level-api.md)**：面向精细控制和性能优化的 API
- **[文档索引](docs/README.md)**：文档结构和快速开始指南

## 测试

项目包含完整的测试套件，位于 `tests/` 目录：

- `http_parser_tests.cpp`：HTTP 解析器测试
- `hpack_tests.cpp`：HTTP/2 HPACK 测试
- `http2_frame_tests.cpp`：HTTP/2 帧测试
- `tls_record_tests.cpp`：TLS 记录测试
- `websocket_frame_tests.cpp`：WebSocket 帧测试
- `khttp_tests.cpp`：高层 API 测试
- `high_level_api_tests.cpp`：高层 API 集成测试
- `websocket_client_tests.cpp`：WebSocket 客户端测试
- `integration/`：集成测试

### 运行测试

可以通过集成脚本运行宿主回归测试；默认不会加载驱动，只有显式传入 `-VmSmoke` 才会执行驱动加载烟测：

```powershell
# 运行宿主回归测试
pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild

# 构建库和示例驱动
msbuild KernelHttp.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

## 配置选项

### 会话配置

```cpp
khttp::SessionConfig config = khttp::DefaultSessionConfig();
config.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB 响应缓冲
config.PoolCapacity = 16;                    // 连接池容量
config.MaxConnsPerHost = 4;                  // 每主机最大连接数
config.IdleTimeoutMs = 60000;                // 空闲超时 60 秒
config.Tls.MinVersion = khttp::TlsVersion::Tls13;  // 最低 TLS 1.3
```

### TLS 配置

```cpp
khttp::TlsConfig tlsConfig = khttp::DefaultTlsConfig();
tlsConfig.Certificate = khttp::CertPolicy::Verify;  // 验证证书
tlsConfig.Store = &certificateStore;                 // 自定义证书存储
tlsConfig.Alpn = "h2";                              // HTTP/2 ALPN
tlsConfig.AlpnLength = 2;
```

### 连接策略

```cpp
khttp::Request* request = nullptr;
khttp::RequestCreate(session, &request);

// 连接策略选项
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ReuseOrCreate);  // 复用或新建
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ForceNew);       // 强制新建
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::NoPool);         // 不进连接池

// 地址族选项
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Ipv4);     // 仅 IPv4
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Ipv6);     // 仅 IPv6
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Any);      // 系统默认
```

## 性能优化

### 连接池

连接池是性能优化的关键，合理配置可以显著减少连接建立开销：

```cpp
// 根据应用需求调整连接池参数
config.PoolCapacity = 32;           // 增加池容量
config.MaxConnsPerHost = 8;         // 增加每主机连接数
config.IdleTimeoutMs = 120000;      // 延长空闲超时
```

### 异步操作

对于长时间运行的操作，使用异步 API 避免阻塞：

```cpp
khttp::AsyncOp* op = nullptr;
khttp::GetAsync(session, url, urlLength, &op);

// 设置完成回调
khttp::SendOptions options = khttp::DefaultSendOptions();
options.OnComplete = [](void* context, NTSTATUS status) {
    // 处理完成事件
};
khttp::SendAsync(session, request, &options, &op);

// 等待完成
khttp::AsyncWait(op, 30000);
```

### 缓冲区管理

合理设置缓冲区大小，避免频繁分配：

```cpp
// 响应缓冲区
config.MaxResponseBytes = 4 * 1024 * 1024;  // 4 MiB

// 请求缓冲区
khttp::SendOptions options = khttp::DefaultSendOptions();
options.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB
```

## 错误处理

项目使用 Windows NTSTATUS 错误码，常见错误：

| NTSTATUS | 描述 | 处理建议 |
|----------|------|----------|
| `STATUS_SUCCESS` | 操作成功 | - |
| `STATUS_INVALID_PARAMETER` | 参数无效 | 检查输入参数 |
| `STATUS_INSUFFICIENT_RESOURCES` | 资源不足 | 减少并发请求或增加资源 |
| `STATUS_IO_TIMEOUT` | 操作超时 | 增加超时时间或检查网络 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 | 重试请求 |
| `STATUS_TRUST_FAILURE` | 证书信任失败 | 检查证书配置 |
| `STATUS_NOT_SUPPORTED` | 操作不支持 | 检查协议兼容性 |

### 错误处理示例

```cpp
NTSTATUS status = khttp::Get(session, url, urlLength, &response);
if (!NT_SUCCESS(status)) {
    switch (status) {
    case STATUS_IO_TIMEOUT:
        // 超时处理：重试或报告错误
        break;
    case STATUS_TRUST_FAILURE:
        // 证书错误：检查证书配置
        break;
    case STATUS_CONNECTION_DISCONNECTED:
        // 连接断开：重新连接
        break;
    default:
        // 其他错误：记录日志
        break;
    }
}
```

## 开发规范

### 代码风格

- 使用 C++17 特性，但遵循内核限制
- 无异常、无 RTTI、显式 `new/delete`
- 使用 `namespace`、类、RAII、轻量模板
- 所有函数标记 `noexcept`
- 使用 SAL 注解（`_In_`、`_Out_`、`_Must_inspect_result_` 等）

### 错误处理

- 始终检查 `NTSTATUS` 返回值
- 使用 `NT_SUCCESS()` 宏判断成功
- 在所有代码路径上释放资源
- 使用 RAII 模式管理资源

### 内存管理

- 使用 `new/delete` 进行动态分配
- 避免内存泄漏，确保释放所有分配的资源
- 使用 `HeapArray` 模板管理数组
- 注意内核内存限制

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 提交规范

使用 Conventional Commits 规范：

```
feat: 添加新功能
fix: 修复 bug
docs: 文档更新
style: 代码格式调整
refactor: 代码重构
test: 测试相关
chore: 构建/工具相关
```

## 相关项目

- [Windows Driver Kit (WDK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Windows Sockets Kernel (WSK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/windows-sockets-kernel)
- [Cryptography Next Generation (CNG)](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-features)

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 Issue 到项目仓库
- 查看项目文档和示例代码
- 参考相关技术文档

## 致谢

感谢所有为项目做出贡献的开发者！

---

**注意**：本项目仍在积极开发中，API 可能会发生变化。请查看最新文档获取最新信息。
