# NTSTATUS 错误码参考

本文档列出 KernelHttp 项目中常见的 NTSTATUS 错误码及其含义，帮助开发者进行错误处理。

[English Version](#english-version) | 简体中文

---

## 目录

- [核心状态码](#核心状态码)
- [网络相关错误](#网络相关错误)
- [TLS/证书相关错误](#tls证书相关错误)
- [资源与参数错误](#资源与参数错误)
- [其他常见状态码](#其他常见状态码)
- [在 KernelHttp 中使用](#在-kernelhttp-中使用)

---

## 核心状态码

以下是 KernelHttp 开发中最常遇到的状态码：

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0x00000000 | STATUS_SUCCESS | 操作成功完成 |
| 0x00000103 | STATUS_PENDING | 挂起状态，异步操作未完成 |
| 0xC000000D | STATUS_INVALID_PARAMETER | 无效参数 |
| 0xC0000017 | STATUS_NO_MEMORY | 内存不足 |
| 0xC0000022 | STATUS_ACCESS_DENIED | 访问被拒绝 |
| 0xC000009A | STATUS_INSUFFICIENT_RESOURCES | 资源不足 |
| 0xC00000BB | STATUS_NOT_SUPPORTED | 不支持的操作 |
| 0xC0000120 | STATUS_CANCELLED | 操作已取消 |

---

## 网络相关错误

网络传输层（WSK）相关错误，是 HTTP 请求中最常见的失败原因：

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC00000B5 | STATUS_IO_TIMEOUT | I/O 超时（请求超时） |
| 0xC000020C | STATUS_CONNECTION_DISCONNECTED | 连接已断开 |
| 0xC000020D | STATUS_CONNECTION_RESET | 连接被重置 |
| 0xC0000236 | STATUS_CONNECTION_REFUSED | 连接被拒绝 |
| 0xC000023C | STATUS_NETWORK_UNREACHABLE | 网络不可达 |
| 0xC000023D | STATUS_HOST_UNREACHABLE | 主机不可达 |
| 0xC000023E | STATUS_PROTOCOL_UNREACHABLE | 协议不可达 |
| 0xC000023F | STATUS_PORT_UNREACHABLE | 端口不可达 |
| 0xC0000241 | STATUS_CONNECTION_ABORTED | 连接已中止 |
| 0xC0000272 | STATUS_NO_MATCH | DNS/地址解析没有匹配结果 |

`KernelHttpTest` 的公网样例矩阵会把 DNS/connect/timeout/reset 类状态作为环境诊断记录，包括 `STATUS_NO_MATCH`、`STATUS_IO_TIMEOUT`、`STATUS_CONNECTION_REFUSED`、`STATUS_NETWORK_UNREACHABLE`、`STATUS_HOST_UNREACHABLE`、`STATUS_PROTOCOL_UNREACHABLE`、`STATUS_CONNECTION_DISCONNECTED`、`STATUS_CONNECTION_RESET`、`STATUS_CONNECTION_ABORTED` 和 `STATUS_DEVICE_NOT_CONNECTED`。这些状态不代表协议实现失败，也不会污染整个 load-time 样例矩阵的 aggregate status。

协议解析错误、API misuse、证书信任失败、证书签名错误和 unsupported protocol 仍是 fatal 状态。公网样例目前使用 `httpbin.dev` 覆盖 HTTPS HTTP/2、content-encoding 和 advanced httpbin-style 路径，使用 `httpbun.com` 覆盖 plain HTTP/1.1 verb echo，并仅在 h2c upgrade 或未迁移验证的 HEAD/OPTIONS 上保留 `nghttp2.org`。公网端点可能改变行为，live driver validation 应记录日期和时区、endpoint host、传输模式、HTTP 状态码或 NTSTATUS，以及结果是否计为 fatal。

---

## TLS/证书相关错误

HTTPS 请求中 TLS 握手或证书验证失败时返回：

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC0000190 | STATUS_TRUST_FAILURE | 信任失败（证书验证失败） |
| 0xC0000191 | STATUS_TRUST_NO_TRUST | 无信任（证书不受信任） |
| 0xC0000192 | STATUS_TRUST_EXPLICIT_DISTRUST | 明确不信任（证书被列入黑名单） |
| 0xC0000194 | STATUS_INVALID_SIGNATURE | 无效签名 |
| 0xC000009D | STATUS_DEVICE_NOT_CONNECTED | 设备未连接（TLS 连接未建立） |
| 0xC00000BB | STATUS_NOT_SUPPORTED | TLS policy 禁止、本地 crypto provider 不支持、ALPN 无匹配或 0-RTT 未显式 replay-safe |
| 0xC00000C3 | STATUS_INVALID_NETWORK_RESPONSE | peer alert、TLS record/handshake 编码错误、证书 DER 畸形或协议语义错误 |

TLS/证书错误的常见分类：

| 分类 | 典型 NTSTATUS | 说明 |
|------|---------------|------|
| TLS policy disabled | `STATUS_NOT_SUPPORTED` | 调用方请求了当前 policy 禁止的能力，例如默认策略下的 TLS 1.2 RSA key exchange、CBC、renegotiation，或未声明 replay-safe 的 0-RTT |
| Unsupported local provider | `STATUS_NOT_SUPPORTED` | 本地 CNG/BCrypt 或内置 provider 路径不支持所需算法、key type 或 signature scheme |
| Peer alert / protocol error | `STATUS_INVALID_NETWORK_RESPONSE` | peer 发送 fatal/warning alert，或握手/record 编码、ALPN、ServerHello 选择违反协议 |
| Revocation failure | `STATUS_TRUST_FAILURE` | OCSP/CRL 缓存条目缺失、过期、unknown 或 revoked；强撤销判定依赖调用方提供的新鲜条目 |
| Certificate policy failure | `STATUS_TRUST_FAILURE` 或 `STATUS_INVALID_NETWORK_RESPONSE` | Name Constraints、certificatePolicies/policyConstraints/inhibitAnyPolicy、EKU/KeyUsage/BasicConstraints、SAN/CN/IDNA 校验失败；畸形 DER 返回 `STATUS_INVALID_NETWORK_RESPONSE` |

`certificatePolicies`、Name Constraints 和 IDNA 会参与证书验证。公网强制 IPv4/IPv6 样例和公网 WebSocket DNS/connect 样例可能记录 `STATUS_NO_MATCH`、`STATUS_IO_TIMEOUT`、`STATUS_HOST_UNREACHABLE` 等环境状态，但这些诊断项不代表协议实现失败。

---

## 资源与参数错误

资源管理或参数传递相关错误：

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC0000005 | STATUS_ACCESS_VIOLATION | 访问违规（内存访问越界） |
| 0xC0000008 | STATUS_INVALID_HANDLE | 无效句柄 |
| 0xC0000023 | STATUS_BUFFER_TOO_SMALL | 缓冲区太小 |
| 0xC0000095 | STATUS_IO_TIMEOUT | I/O 超时 |
| 0xC00000E2 | STATUS_SHARING_VIOLATION | 共享冲突 |

---

## 其他常见状态码

其他可能遇到的状态码：

### 通用状态

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0x00000001 | STATUS_WAIT_1 | 等待对象 1 |
| 0x00000080 | STATUS_ABANDONED | 等待被放弃的对象 |
| 0x000000C0 | STATUS_USER_APC | 用户模式 APC |
| 0x00000101 | STATUS_ALERTED | 警告 |
| 0x00000104 | STATUS_REPARSE | 重解析点 |
| 0xC0000001 | STATUS_UNSUCCESSFUL | 操作不成功 |
| 0xC0000002 | STATUS_NOT_IMPLEMENTED | 未实现 |
| 0xC0000003 | STATUS_INVALID_INFO_CLASS | 无效信息类 |
| 0xC0000004 | STATUS_INFO_LENGTH_MISMATCH | 信息长度不匹配 |
| 0xC0000010 | STATUS_INVALID_DEVICE_REQUEST | 无效设备请求 |
| 0xC0000011 | STATUS_END_OF_FILE | 文件结束 |
| 0xC0000016 | STATUS_MORE_PROCESSING_REQUIRED | 需要更多处理 |
| 0xC0000018 | STATUS_CONFLICTING_ADDRESSES | 地址冲突 |
| 0xC000001D | STATUS_ILLEGAL_INSTRUCTION | 非法指令 |
| 0xC0000025 | STATUS_NONCONTINUABLE_EXCEPTION | 不可继续的异常 |
| 0xC0000135 | STATUS_DLL_NOT_FOUND | DLL 未找到 |
| 0xC0000139 | STATUS_ENTRYPOINT_NOT_FOUND | 入口点未找到 |

### 信息状态（0x4xxxxxxx）

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0x40000000 | STATUS_OBJECT_NAME_EXISTS | 对象名已存在 |
| 0x40000001 | STATUS_THREAD_WAS_SUSPENDED | 线程被挂起 |
| 0x40000003 | STATUS_IMAGE_NOT_AT_BASE | 映像不在基地址 |
| 0x40000005 | STATUS_SEGMENT_NOTIFICATION | 段通知 |

### 警告状态（0x8xxxxxxx）

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0x80000005 | STATUS_BUFFER_OVERFLOW | 缓冲区溢出 |
| 0x80000006 | STATUS_NO_MORE_FILES | 没有更多文件 |
| 0x8000000D | STATUS_PARTIAL_COPY | 部分复制 |
| 0x80000016 | STATUS_VERIFY_REQUIRED | 需要验证 |
| 0x8000001A | STATUS_NO_MORE_ENTRIES | 没有更多条目 |

---

## 在 KernelHttp 中使用

### 检查 NTSTATUS

```cpp
#include <ntddk.h>

NTSTATUS status = SomeKernelHttpFunction();

// 检查是否成功
if (NT_SUCCESS(status)) {
    // 操作成功
} else {
    // 操作失败
    DbgPrint("Failed with status: 0x%08X\n", status);
}
```

### 常见错误处理

```cpp
NTSTATUS status = KhHttpSendSync(session, request, nullptr, &response);

if (!NT_SUCCESS(status)) {
    switch (status) {
    case STATUS_IO_TIMEOUT:
        // I/O 超时 - 可重试
        DbgPrint("Request timed out\n");
        break;
        
    case STATUS_CONNECTION_DISCONNECTED:
    case STATUS_CONNECTION_RESET:
        // 连接断开 - 可重试
        DbgPrint("Connection lost\n");
        break;
        
    case STATUS_TRUST_FAILURE:
    case STATUS_INVALID_SIGNATURE:
        // TLS/证书错误 - 不可重试
        DbgPrint("TLS/Certificate error\n");
        break;
        
    case STATUS_INSUFFICIENT_RESOURCES:
    case STATUS_NO_MEMORY:
        // 资源不足 - 检查配置
        DbgPrint("Resource exhausted\n");
        break;
        
    case STATUS_INVALID_PARAMETER:
        // 参数错误 - 检查代码
        DbgPrint("Invalid parameter\n");
        break;
        
    case STATUS_CANCELLED:
        // 操作被取消
        DbgPrint("Operation cancelled\n");
        break;
        
    default:
        // 其他错误
        DbgPrint("Unknown error: 0x%08X\n", status);
        break;
    }
}
```

### 错误分类处理

```cpp
// 按类别处理错误
enum class ErrorAction { Retry, Fail, AdjustConfig };

ErrorAction ClassifyError(NTSTATUS status) {
    // 网络相关错误 - 可重试
    switch (status) {
    case STATUS_CONNECTION_DISCONNECTED:
    case STATUS_CONNECTION_RESET:
    case STATUS_IO_TIMEOUT:
    case STATUS_HOST_UNREACHABLE:
        return ErrorAction::Retry;
    }
    
    // TLS/证书相关错误 - 不可重试
    switch (status) {
    case STATUS_TRUST_FAILURE:
    case STATUS_TRUST_NO_TRUST:
    case STATUS_TRUST_EXPLICIT_DISTRUST:
    case STATUS_INVALID_SIGNATURE:
        return ErrorAction::Fail;
    }
    
    // 资源相关错误 - 可能需要调整配置
    switch (status) {
    case STATUS_INSUFFICIENT_RESOURCES:
    case STATUS_NO_MEMORY:
        return ErrorAction::AdjustConfig;
    }
    
    return ErrorAction::Fail;
}
```

### 使用宏进行检查

```cpp
#include <ntddk.h>

// 使用 NT_SUCCESS 宏检查成功
if (NT_SUCCESS(status)) {
    // 成功
}

// 使用 NT_ERROR 宏检查错误
if (NT_ERROR(status)) {
    // 错误
}

// 使用 NT_WARNING 宏检查警告
if (NT_WARNING(status)) {
    // 警告
}

// 使用 NT_INFORMATION 宏检查信息
if (NT_INFORMATION(status)) {
    // 信息
}
```

### 资源清理模式

```cpp
NTSTATUS DoOperation() {
    Resource* res1 = nullptr;
    Resource* res2 = nullptr;
    
    NTSTATUS status = CreateResource1(&res1);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = CreateResource2(&res2);
    if (!NT_SUCCESS(status)) {
        ReleaseResource1(res1);  // 释放已分配的资源
        return status;
    }
    
    // 执行操作...
    
    ReleaseResource2(res2);
    ReleaseResource1(res1);
    
    return STATUS_SUCCESS;
}
```

---

## English Version

# NTSTATUS Error Code Reference

This document lists common NTSTATUS error codes used in the KernelHttp project.

## Core Status Codes

| Value | Name | Description |
|-------|------|-------------|
| 0x00000000 | STATUS_SUCCESS | Operation completed successfully |
| 0x00000103 | STATUS_PENDING | Pending status, async operation not completed |
| 0xC000000D | STATUS_INVALID_PARAMETER | Invalid parameter |
| 0xC0000017 | STATUS_NO_MEMORY | No memory |
| 0xC0000022 | STATUS_ACCESS_DENIED | Access denied |
| 0xC000009A | STATUS_INSUFFICIENT_RESOURCES | Insufficient resources |
| 0xC00000BB | STATUS_NOT_SUPPORTED | Not supported |
| 0xC0000120 | STATUS_CANCELLED | Operation cancelled |

## Network-Related Errors

| Value | Name | Description |
|-------|------|-------------|
| 0xC00000B5 | STATUS_IO_TIMEOUT | I/O timeout (request timeout) |
| 0xC000020C | STATUS_CONNECTION_DISCONNECTED | Connection disconnected |
| 0xC000020D | STATUS_CONNECTION_RESET | Connection reset |
| 0xC0000236 | STATUS_CONNECTION_REFUSED | Connection refused |
| 0xC000023C | STATUS_NETWORK_UNREACHABLE | Network unreachable |
| 0xC000023D | STATUS_HOST_UNREACHABLE | Host unreachable |
| 0xC000023E | STATUS_PROTOCOL_UNREACHABLE | Protocol unreachable |
| 0xC000023F | STATUS_PORT_UNREACHABLE | Port unreachable |
| 0xC0000241 | STATUS_CONNECTION_ABORTED | Connection aborted |
| 0xC0000272 | STATUS_NO_MATCH | DNS/address resolution found no match |

Public endpoint samples in `KernelHttpTest` record DNS/connect/timeout/reset statuses as environment diagnostics: `STATUS_NO_MATCH`, `STATUS_IO_TIMEOUT`, `STATUS_CONNECTION_REFUSED`, `STATUS_NETWORK_UNREACHABLE`, `STATUS_HOST_UNREACHABLE`, `STATUS_PROTOCOL_UNREACHABLE`, `STATUS_CONNECTION_DISCONNECTED`, `STATUS_CONNECTION_RESET`, `STATUS_CONNECTION_ABORTED`, and `STATUS_DEVICE_NOT_CONNECTED`. These diagnostics do not poison the load-time sample aggregate. Protocol parse errors, API misuse, certificate trust/signature failures, and unsupported protocol paths remain fatal. Current public samples use `httpbin.dev` for HTTPS HTTP/2, content encoding, and advanced httpbin-style paths; `httpbun.com` for plain HTTP/1.1 verb echo; and `nghttp2.org` only where h2c upgrade or still-unmigrated HEAD/OPTIONS capability is needed.

## TLS/Certificate-Related Errors

| Value | Name | Description |
|-------|------|-------------|
| 0xC0000190 | STATUS_TRUST_FAILURE | Trust failure (certificate verification failed) |
| 0xC0000191 | STATUS_TRUST_NO_TRUST | No trust (certificate not trusted) |
| 0xC0000192 | STATUS_TRUST_EXPLICIT_DISTRUST | Explicit distrust |
| 0xC0000194 | STATUS_INVALID_SIGNATURE | Invalid signature |
| 0xC000009D | STATUS_DEVICE_NOT_CONNECTED | Device not connected (TLS connection not established) |
| 0xC00000BB | STATUS_NOT_SUPPORTED | TLS policy disabled, unsupported local crypto provider, ALPN mismatch, or 0-RTT without replay-safe opt-in |
| 0xC00000C3 | STATUS_INVALID_NETWORK_RESPONSE | Peer TLS alert, malformed TLS record/handshake, malformed certificate DER, or protocol semantic error |

Common TLS/certificate categories:

| Category | Typical NTSTATUS | Meaning |
|----------|------------------|---------|
| TLS policy disabled | `STATUS_NOT_SUPPORTED` | The requested capability is forbidden by the active policy, for example TLS 1.2 RSA key exchange, CBC, renegotiation under the default profile, or 0-RTT without replay-safe opt-in |
| Unsupported local provider | `STATUS_NOT_SUPPORTED` | The local CNG/BCrypt or in-tree provider path cannot supply the required algorithm, key type, or signature scheme |
| Peer alert / protocol error | `STATUS_INVALID_NETWORK_RESPONSE` | The peer sent an alert, or record/handshake encoding, ALPN, or ServerHello selection violates protocol rules |
| Revocation failure | `STATUS_TRUST_FAILURE` | OCSP/CRL cached data is missing, expired, unknown, or revoked; hard revocation depends on fresh entries supplied by the caller |
| Certificate policy failure | `STATUS_TRUST_FAILURE` or `STATUS_INVALID_NETWORK_RESPONSE` | Name Constraints, certificatePolicies/policyConstraints/inhibitAnyPolicy, EKU/KeyUsage/BasicConstraints, SAN/CN/IDNA validation failed; malformed DER returns `STATUS_INVALID_NETWORK_RESPONSE` |

## Resource and Parameter Errors

| Value | Name | Description |
|-------|------|-------------|
| 0xC0000005 | STATUS_ACCESS_VIOLATION | Access violation |
| 0xC0000008 | STATUS_INVALID_HANDLE | Invalid handle |
| 0xC0000023 | STATUS_BUFFER_TOO_SMALL | Buffer too small |

---

## Related Documents

- [HTTP Status Codes](http-status-codes.md)
- [API Overview](api-overview.md)
- [High-Level API](high-level-api.md)
- [Low-Level API](low-level-api.md)
