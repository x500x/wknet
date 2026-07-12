# 架构总览

## 分层

```text
wknet::http / websocket / crypto / codec
                    │
             http_api 薄桥
                    │
                 session
          ┌─────────┼─────────┐
       transport  http1/http2  ws
          │             │       │
        net            tls    codec
          └─────────────┴───────┘
                    rtl
```

- `http_api` 只做参数映射、opaque handle 包装和公共生命周期桥接。
- `session` 拥有路由、重定向、代理、连接池、异步和 HTTP/WebSocket 编排策略。
- `transport::ITransport` 是协议层与真实 I/O 之间的接口；协议层不直接操作 WSK IRP。
- `net` 只提供 WSK 生命周期、解析和字节流能力。
- `tls` 只处理握手、记录保护、会话恢复和证书验证。
- `http1`、`http2`、`ws` 负责协议状态机，不拥有连接池策略。

## 请求路径

```text
wknet::http::SendEx
  → http_api 参数映射
  → session::HttpSend
  → HttpRoute / HttpProxy / ConnectionPool
  → HttpH1Dispatch 或 HttpH2Dispatch
  → transport::ITransport
  → WSK 或 TLS
```

WebSocket 连接由 `session::WsConnect` 编排，HTTP/1.1 Upgrade 与 RFC 8441 共用同一 TLS、连接与取消模型。

## 所有权边界

- `ConnectionPool.cpp` 是池字段的唯一写入者。
- Workspace 与协议聚合缓冲使用堆内存；高频缓冲常驻并复用。
- `src/wknetlib` 不使用 `.inc` 实现分片，每个职责由独立 `.cpp` 编译。
- 不存在独立 client 层或第二套网络连接生命周期。
