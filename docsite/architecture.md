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

- **HTTPS 默认路径**：TCP TLS 上 HTTP/1.1 或 ALPN `h2`；`Http3ConnectMode::Auto`（默认）在已认证响应学习精确 `h3` Alt-Svc 后，后续请求可优先 HTTP/3。
- **WebSocket**：`session` 统一编排；`wss` 默认可选 RFC 8441（HTTP/2 extended CONNECT）或 HTTP/1.1 Upgrade，共享 TLS、连接与取消模型。
- **明文 HTTP / h2c / 代理 / WebSocket / 非 HTTP ALPN** 不进入 HTTP/3。

## 所有权与缓冲

- 连接池字段由 session 池模块独占写入；池化连接携带 socket / transport / TLS / 可选 H2 或 H3 状态。
- 协议与 Workspace 缓冲使用堆内存；热路径缓冲常驻并复用。
- 同步 HTTP / WebSocket / TLS / 证书路径要求 **`PASSIVE_LEVEL`**，否则返回 `STATUS_INVALID_DEVICE_REQUEST` 或 `STATUS_INVALID_DEVICE_STATE`。
- 卸载前：若用过异步 API，必须先 `wknet::http::Destroy()` 排空在飞操作。

## 硬约束（调用方契约）

| 约束 | 含义 |
|------|------|
| 客户端 only | 无入站 request parser / server role |
| WSK + CNG | 传输与密码学主路径；无 WinHTTP / SChannel |
| 信任锚调用方 | 库不硬编码系统 CA |
| 主机名 | IP literal 只匹配 iPAddress SAN；域名**不回退 CN** |
| 重定向 | HTTPS→HTTP 默认拒绝；`MaxRedirects` 默认 10，用尽返回当前 3xx 不报错 |
| TRACE | 默认关，需 `SendFlagAllowTrace` |
| H3 Auto | 仅从**已认证** HTTPS 响应学习 Alt-Svc；SNI / 证书 / `:authority` 绑定原 origin |

能力分类（已实现 / 默认关 / 安全拒绝 / 非目标）见 [能力账本](capability-matrix.md)。
