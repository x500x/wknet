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

KernelHttp 是一个纯内核态的 HTTP/HTTPS 客户端库，专为 Windows 内核驱动开发设计。项目从底层开始构建，实现了完整的 HTTP/1.1、HTTP/2、WebSocket 协议支持，以及 TLS 1.2/1.3 握手和加密通信。

### ✨ 核心特点

- **🔒 纯内核态实现**：不依赖 WinHTTP、WinINet、SChannel 等用户态组件
- **🌐 WSK 网络传输**：使用 Windows Sockets Kernel (WSK) 进行网络通信
- **🔐 CNG/BCrypt 密码学**：使用内核态 CNG (Cryptography Next Generation) 进行加密操作
- **📡 完整的协议栈**：支持 HTTP/1.1、HTTP/2、WebSocket、TLS 1.2/1.3
- **🔄 连接池管理**：内置连接池，支持连接复用和自动管理
- **⚡ 异步操作**：支持异步请求，避免阻塞内核线程
- **🎯 两层 API**：提供高层简洁 API 和底层精细控制 API

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

#### 方式一：作为静态库集成

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
   # Debug 版本
   msbuild KernelHttp.sln /p:Configuration=Debug /p:Platform=x64
   
   # Release 版本
   msbuild KernelHttp.sln /p:Configuration=Release /p:Platform=x64
   ```

4. **获取库文件**
   
   构建完成后，库文件位于：
   ```
   src/KernelHttpLib/x64/Debug/KernelHttpLib.lib      # Debug x64
   src/KernelHttpLib/x64/Release/KernelHttpLib.lib    # Release x64
   ```

#### 方式二：集成到你的项目

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
│       ├── KernelHttpConfig.h       # 配置选项
│       ├── khttp/                   # 高层 API 头文件
│       ├── engine/                  # 底层 API 头文件
│       ├── http/                    # HTTP 协议
│       ├── http2/                   # HTTP/2 协议
│       ├── tls/                     # TLS 协议
│       ├── websocket/               # WebSocket 协议
│       ├── net/                     # 网络传输层
│       └── crypto/                  # 密码学
├── src/                              # 源代码
│   ├── KernelHttp/                  # 核心库实现
│   │   ├── client/                  # 客户端实现
│   │   ├── crypto/                  # 密码学实现
│   │   ├── engine/                  # 底层引擎
│   │   ├── http/                    # HTTP 协议实现
│   │   ├── http2/                   # HTTP/2 协议实现
│   │   ├── khttp/                   # 高层 API 实现
│   │   ├── net/                     # 网络传输 (WSK)
│   │   ├── tls/                     # TLS 协议实现
│   │   └── websocket/               # WebSocket 实现
│   ├── KernelHttpLib/               # 静态库项目
│   └── KernelHttpExample/           # 示例驱动项目
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

// 响应缓冲区大小（默认 1 MiB）
config.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB

// 连接池容量（默认 8）
config.PoolCapacity = 16;

// 每主机最大连接数（默认 2）
config.MaxConnsPerHost = 4;

// 空闲超时（默认 30 秒）
config.IdleTimeoutMs = 60000;  // 60 秒

// TLS 配置
config.Tls.MinVersion = khttp::TlsVersion::Tls13;
config.Tls.Certificate = khttp::CertPolicy::Verify;
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
# 运行宿主回归测试
pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild

# 构建库和示例驱动
msbuild KernelHttp.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

### 测试文件

| 测试文件 | 测试内容 |
|---------|---------|
| `http_parser_tests.cpp` | HTTP 解析器 |
| `hpack_tests.cpp` | HTTP/2 HPACK 编解码 |
| `http2_frame_tests.cpp` | HTTP/2 帧处理 |
| `tls_record_tests.cpp` | TLS 记录协议 |
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
// 响应缓冲区
config.MaxResponseBytes = 4 * 1024 * 1024;  // 4 MiB

// 请求缓冲区
khttp::SendOptions options = khttp::DefaultSendOptions();
options.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB
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

// 自定义证书存储
tls::CertificateStore store = {};
// 添加信任锚...
config.Tls.Store = &store;
```

### 证书锁定

```cpp
// 使用证书锁定增强安全性
tls::CertificateTrustAnchor anchor = {};
// 设置根证书...

tls::CertificatePin pin = {};
// 设置 SPKI 哈希...

// 创建证书存储
tls::CertificateStore store = {};
store.AddTrustAnchor(&anchor);
store.AddPin(&pin);
```

---

## 🛠️ 开发规范

### 代码风格

- 使用 C++17 特性，但遵循内核限制
- **无异常**、**无 RTTI**、**显式 `new/delete`**
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
