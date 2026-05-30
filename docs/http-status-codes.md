# HTTP 状态码参考

本文档列出所有标准 HTTP 状态码及其含义，帮助开发者理解服务器返回的响应状态。

[English Version](#english-version) | 简体中文

---

## 目录

- [1xx 信息响应](#1xx-信息响应)
- [2xx 成功响应](#2xx-成功响应)
- [3xx 重定向响应](#3xx-重定向响应)
- [4xx 客户端错误](#4xx-客户端错误)
- [5xx 服务器错误](#5xx-服务器错误)
- [在 KernelHttp 中使用](#在-kernelhttp-中使用)

---

## 1xx 信息响应

信息响应表示请求已被接收，服务器正在继续处理。

| 状态码 | 名称 | 描述 |
|--------|------|------|
| 100 | Continue | 服务器已收到请求头，客户端应继续发送请求体 |
| 101 | Switching Protocols | 服务器同意切换协议（如升级到 WebSocket） |
| 102 | Processing | 服务器已收到请求并正在处理，尚无响应可用（WebDAV） |
| 103 | Early Hints | 服务器在最终响应前发送一些提示（如 Link 头部） |

---

## 2xx 成功响应

成功响应表示请求被成功接收、理解并处理。

| 状态码 | 名称 | 描述 |
|--------|------|------|
| 200 | OK | 请求成功。GET 返回资源，POST 返回操作结果 |
| 201 | Created | 请求成功并创建了新资源（通常用于 POST 或 PUT） |
| 202 | Accepted | 请求已接受但尚未处理完成（异步处理） |
| 203 | Non-Authoritative Information | 返回的信息来自第三方副本而非原始服务器 |
| 204 | No Content | 请求成功但没有返回内容（常用于 DELETE） |
| 205 | Reset Content | 请求成功，客户端应重置文档视图 |
| 206 | Partial Content | 服务器返回部分内容（用于范围请求/断点续传） |
| 207 | Multi-Status | 返回多个资源的状态信息（WebDAV） |
| 208 | Already Reported | 元素已在之前的响应中报告过（WebDAV） |
| 226 | IM Used | 服务器完成了对资源的 GET 请求，响应是资源实例的表示 |

---

## 3xx 重定向响应

重定向响应表示需要进一步操作才能完成请求。

| 状态码 | 名称 | 描述 |
|--------|------|------|
| 300 | Multiple Choices | 请求有多个可能的响应，客户端应选择一个 |
| 301 | Moved Permanently | 请求的资源已永久移动到新 URL |
| 302 | Found | 请求的资源临时位于不同的 URL |
| 303 | See Other | 请求的资源可以在另一个 URL 找到（通常用于 POST 后重定向） |
| 304 | Not Modified | 资源未修改，可使用缓存版本 |
| 305 | Use Proxy | 请求的资源必须通过代理访问（已弃用） |
| 307 | Temporary Redirect | 请求的资源临时位于不同的 URL（保持请求方法不变） |
| 308 | Permanent Redirect | 请求的资源已永久移动到新 URL（保持请求方法不变） |

---

## 4xx 客户端错误

客户端错误表示请求包含错误或无法被服务器处理。

| 状态码 | 名称 | 描述 |
|--------|------|------|
| 400 | Bad Request | 请求语法错误或参数无效 |
| 401 | Unauthorized | 需要身份认证（未提供或认证失败） |
| 402 | Payment Required | 保留用于未来使用（最初为数字支付系统设计） |
| 403 | Forbidden | 服务器理解请求但拒绝执行（权限不足） |
| 404 | Not Found | 请求的资源不存在 |
| 405 | Method Not Allowed | 请求方法不被允许（如对只读资源使用 POST） |
| 406 | Not Acceptable | 服务器无法生成客户端可接受的内容 |
| 407 | Proxy Authentication Required | 需要代理身份认证 |
| 408 | Request Timeout | 服务器等待请求超时 |
| 409 | Conflict | 请求与服务器当前状态冲突（如重复创建资源） |
| 410 | Gone | 请求的资源已永久删除且不会恢复 |
| 411 | Length Required | 服务器要求 Content-Length 头部 |
| 412 | Precondition Failed | 请求的前提条件失败 |
| 413 | Payload Too Large | 请求体超过服务器限制 |
| 414 | URI Too Long | 请求的 URL 过长 |
| 415 | Unsupported Media Type | 请求的媒体类型不被支持 |
| 416 | Range Not Satisfiable | 请求的范围无法满足 |
| 417 | Expectation Failed | Expect 头部的要求无法满足 |
| 418 | I'm a Teapot | 彩蛋状态码（RFC 2324） |
| 421 | Misdirected Request | 请求被定向到无法生成响应的服务器 |
| 422 | Unprocessable Entity | 请求格式正确但语义错误（WebDAV） |
| 423 | Locked | 资源被锁定（WebDAV） |
| 424 | Failed Dependency | 前置请求失败导致当前请求失败（WebDAV） |
| 425 | Too Early | 服务器不愿意冒险处理可能重放的请求 |
| 426 | Upgrade Required | 服务器要求客户端切换协议 |
| 428 | Precondition Required | 服务器要求请求包含条件头部 |
| 429 | Too Many Requests | 客户端发送了太多请求（限流） |
| 431 | Request Header Fields Too Large | 请求头部字段过大 |
| 451 | Unavailable For Legal Reasons | 资源因法律原因不可用 |

---

## 5xx 服务器错误

服务器错误表示服务器在处理请求时发生错误。

| 状态码 | 名称 | 描述 |
|--------|------|------|
| 500 | Internal Server Error | 服务器内部错误 |
| 501 | Not Implemented | 服务器不支持请求的功能 |
| 502 | Bad Gateway | 作为网关或代理的服务器从上游服务器收到无效响应 |
| 503 | Service Unavailable | 服务器暂时无法处理请求（过载或维护） |
| 504 | Gateway Timeout | 作为网关或代理的服务器未能及时从上游服务器获取响应 |
| 505 | HTTP Version Not Supported | 服务器不支持请求的 HTTP 版本 |
| 506 | Variant Also Negotiates | 服务器存在内部配置错误 |
| 507 | Insufficient Storage | 服务器无法存储完成请求所需的内容（WebDAV） |
| 508 | Loop Detected | 服务器检测到无限循环（WebDAV） |
| 510 | Not Extended | 请求需要进一步扩展才能被服务器处理 |
| 511 | Network Authentication Required | 客户端需要进行网络认证 |

---

## 在 KernelHttp 中使用

### 获取状态码

#### 高层 API

```cpp
khttp::Response* response = nullptr;
NTSTATUS status = khttp::Get(session, url, urlLen, &response);

if (NT_SUCCESS(status)) {
    // 获取 HTTP 状态码
    ULONG statusCode = khttp::ResponseStatusCode(response);
    
    // 根据状态码处理
    switch (statusCode) {
    case 200:
        // 成功处理
        break;
    case 404:
        // 资源不存在
        break;
    case 500:
        // 服务器错误
        break;
    }
    
    khttp::ResponseRelease(response);
}
```

#### 底层 API

```cpp
KH_RESPONSE response = nullptr;
NTSTATUS status = KhHttpSendSync(session, request, nullptr, &response);

if (NT_SUCCESS(status)) {
    KhResponseView view = {};
    KhResponseGetView(response, &view);
    
    // view.StatusCode 包含 HTTP 状态码
    if (view.StatusCode >= 200 && view.StatusCode < 300) {
        // 成功响应
    } else if (view.StatusCode >= 400) {
        // 客户端或服务器错误
    }
    
    KhResponseRelease(response);
}
```

### 状态码分类处理

```cpp
NTSTATUS HandleResponse(ULONG statusCode) {
    if (statusCode >= 100 && statusCode < 200) {
        // 1xx 信息响应 - 继续处理
        return STATUS_SUCCESS;
    }
    else if (statusCode >= 200 && statusCode < 300) {
        // 2xx 成功响应
        return STATUS_SUCCESS;
    }
    else if (statusCode >= 300 && statusCode < 400) {
        // 3xx 重定向 - 处理重定向
        return STATUS_REDIRECT;
    }
    else if (statusCode >= 400 && statusCode < 500) {
        // 4xx 客户端错误
        return STATUS_INVALID_PARAMETER;
    }
    else if (statusCode >= 500 && statusCode < 600) {
        // 5xx 服务器错误
        return STATUS_UNSUCCESSFUL;
    }
    
    return STATUS_SUCCESS;
}
```

---

## English Version

# HTTP Status Code Reference

This document lists all standard HTTP status codes and their meanings.

## 1xx Informational

| Code | Name | Description |
|------|------|-------------|
| 100 | Continue | Server received request headers, client should send request body |
| 101 | Switching Protocols | Server agrees to switch protocols (e.g., upgrade to WebSocket) |
| 102 | Processing | Server received and is processing request (WebDAV) |
| 103 | Early Hints | Server sends hints before final response |

## 2xx Success

| Code | Name | Description |
|------|------|-------------|
| 200 | OK | Request succeeded |
| 201 | Created | Request succeeded and created new resource |
| 202 | Accepted | Request accepted but not yet processed |
| 203 | Non-Authoritative Information | Information from third-party copy |
| 204 | No Content | Request succeeded with no content |
| 205 | Reset Content | Client should reset document view |
| 206 | Partial Content | Server returned partial content |
| 207 | Multi-Status | Multiple status responses (WebDAV) |
| 208 | Already Reported | Element already reported (WebDAV) |
| 226 | IM Used | GET request completed with instance manipulation |

## 3xx Redirection

| Code | Name | Description |
|------|------|-------------|
| 300 | Multiple Choices | Multiple possible responses |
| 301 | Moved Permanently | Resource permanently moved |
| 302 | Found | Resource temporarily at different URL |
| 303 | See Other | Resource at another URL |
| 304 | Not Modified | Resource not modified, use cache |
| 305 | Use Proxy | Must access through proxy (deprecated) |
| 307 | Temporary Redirect | Temporary redirect (preserve method) |
| 308 | Permanent Redirect | Permanent redirect (preserve method) |

## 4xx Client Error

| Code | Name | Description |
|------|------|-------------|
| 400 | Bad Request | Invalid request syntax or parameters |
| 401 | Unauthorized | Authentication required |
| 402 | Payment Required | Reserved for future use |
| 403 | Forbidden | Server refuses to execute |
| 404 | Not Found | Resource not found |
| 405 | Method Not Allowed | Request method not allowed |
| 406 | Not Acceptable | Cannot generate acceptable content |
| 407 | Proxy Authentication Required | Proxy authentication needed |
| 408 | Request Timeout | Server timed out waiting |
| 409 | Conflict | Request conflicts with server state |
| 410 | Gone | Resource permanently deleted |
| 411 | Length Required | Content-Length header required |
| 412 | Precondition Failed | Precondition failed |
| 413 | Payload Too Large | Request body too large |
| 414 | URI Too Long | URL too long |
| 415 | Unsupported Media Type | Media type not supported |
| 416 | Range Not Satisfiable | Range cannot be satisfied |
| 417 | Expectation Failed | Expect header requirement failed |
| 418 | I'm a Teapot | Easter egg (RFC 2324) |
| 421 | Misdirected Request | Request directed to wrong server |
| 422 | Unprocessable Entity | Valid syntax but semantic errors (WebDAV) |
| 423 | Locked | Resource locked (WebDAV) |
| 424 | Failed Dependency | Previous request failed (WebDAV) |
| 425 | Too Early | Server unwilling to risk processing |
| 426 | Upgrade Required | Client should switch protocols |
| 428 | Precondition Required | Conditional header required |
| 429 | Too Many Requests | Rate limited |
| 431 | Request Header Fields Too Large | Header fields too large |
| 451 | Unavailable For Legal Reasons | Unavailable for legal reasons |

## 5xx Server Error

| Code | Name | Description |
|------|------|-------------|
| 500 | Internal Server Error | Server internal error |
| 501 | Not Implemented | Server doesn't support functionality |
| 502 | Bad Gateway | Invalid upstream response |
| 503 | Service Unavailable | Server temporarily unavailable |
| 504 | Gateway Timeout | Upserver response timeout |
| 505 | HTTP Version Not Supported | HTTP version not supported |
| 506 | Variant Also Negotiates | Server configuration error |
| 507 | Insufficient Storage | Cannot store content (WebDAV) |
| 508 | Loop Detected | Infinite loop detected (WebDAV) |
| 510 | Not Extended | Further extension required |
| 511 | Network Authentication Required | Network authentication needed |

---

## 相关文档

- [NTSTATUS 错误码参考](ntstatus-codes.md)
- [API 概述](api-overview.md)
- [高层 API 文档](high-level-api.md)
- [底层 API 文档](low-level-api.md)
