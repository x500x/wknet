# 架构总览

wknet 是 **Windows 内核态 HTTP 客户端协议栈**。公共入口是 `wknet::http` / `wknet::websocket` / `wknet::crypto` / `wknet::codec`；传输主路径为 WSK，密码学主路径为 CNG/BCrypt。不使用 WinHTTP、WinINet、SChannel，也不提供 server/入站角色。

## 分层

```text
wknet::http / websocket / crypto / codec
                    │
             http_api 薄桥
                    │
                 session
      ┌─────────────┼─────────────┐
  transport     http1/http2/http3   ws
      │              │              │
    net             tls           codec
      └──────────────┴──────────────┘
                    rtl
```

| 层 | 职责 | 调用方需知 |
|----|------|------------|
| 公共 API | opaque handle、参数映射、生命周期 | 唯一稳定入口 |
| session | 路由、重定向、代理、连接池、异步、协议编排 | 拥有策略与池 |
| transport | opaque 字节流服务 | 协议层不直接碰 WSK IRP |
| net | WSK 生命周期、解析、socket | 仅内核 socket |
| tls | 握手、记录保护、会话恢复、证书校验 | 信任锚由调用方提供 |
| http1 / http2 / http3 / ws | 协议状态机 | 不拥有池策略 |

不存在独立 client 层，也不存在第二套网络连接生命周期。

## 请求路径

```text
wknet::http::Send* / Get* / Post*
  → 公共参数映射
  → session 编排
  → 路由 / 代理 / 连接池 / Alt-Svc
  → HTTP/1.1 | HTTP/2 | HTTP/3
  → transport → WSK 或 TLS（H3 为 QUIC over Datagram）
```

- **HTTPS**：默认在 TCP TLS 上使用 HTTP/1.1 或 ALPN 协商的 `h2`。`Http3ConnectMode::Auto` 时，若已从通过证书与策略校验的响应中学到精确 `h3` Alt-Svc，后续请求可以优先走 HTTP/3。
- **WebSocket**：由 `session` 编排。`wss` 可使用 RFC 8441（HTTP/2 extended CONNECT）或 HTTP/1.1 Upgrade，与 HTTP 共用 TLS、连接与取消模型。
- **HTTP/3 适用范围**：仅 HTTPS 且未启用代理。明文 HTTP、h2c、WebSocket，以及非 HTTP 的 ALPN，均使用既有 TCP 路径。

## 所有权与缓冲

- 连接池字段由 session 池模块独占写入；池化连接携带 socket / transport / TLS / 可选 H2 或 H3 状态。
- 协议与 Workspace 缓冲使用堆内存；热路径缓冲常驻并复用。
- 同步 HTTP / WebSocket / TLS / 证书路径要求 **`PASSIVE_LEVEL`**，否则返回 `STATUS_INVALID_DEVICE_REQUEST` 或 `STATUS_INVALID_DEVICE_STATE`。
- 用过异步 API 时，在驱动卸载路径调用 `wknet::http::Destroy()`，等待异步操作结束后再释放资源。

## 调用约定一览

| 点 | 行为 |
|----|------|
| 角色 | 客户端；无入站 parser / server |
| 主路径 | 传输 WSK，密码学 CNG；不使用 WinHTTP / SChannel |
| 信任 | 信任锚、CA 包、pin、撤销证据由调用方提供；库不内置系统 CA |
| 主机名 | IP 仅匹配 iPAddress SAN；域名不回退 CN |
| 重定向 | 默认拒绝 HTTPS→HTTP；`MaxRedirects` 默认 10，用尽时返回当前 3xx |
| TRACE | 默认关闭；需要时设置 `SendFlagAllowTrace` |
| H3 Auto | 仅从通过校验的 HTTPS 响应学习 Alt-Svc；SNI、证书与 `:authority` 仍绑定原 origin |

支持范围与限制的分类见 [能力边界](capability-matrix.md)。
