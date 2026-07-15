# wknet

面向 Windows 内核驱动的纯内核态 HTTP/HTTPS/WebSocket 客户端库。

传输主路径为 WSK，密码学主路径为内核态 CNG/BCrypt；不依赖 WinHTTP、WinINet 或 SChannel。公共 API 为四个命名空间：`wknet::http`、`wknet::websocket`、`wknet::crypto`、`wknet::codec`。

## 定位

wknet 是内核态 HTTP/HTTPS/WebSocket **客户端**。面向需要在驱动里发起请求、并希望安全默认值明确的场景；HTTP/1.1、HTTP/2、HTTP/3 共用同一产品 API。

当前不提供 HTTP 服务端或入站 request parser，也不内置系统 CA。QUIC 迁移、WebTransport 等能力尚未支持，详见 [能力边界](capability-matrix.md)。

## 集成要点

- 同步路径在 `PASSIVE_LEVEL` 调用；公共句柄为堆对象，Create 与 Close / Release 成对使用。
- 信任锚、CA 包、pin、撤销证据由调用方提供；主机名校验不回退 CN。
- Trace 默认 `Off`；HTTP/3 默认 `Auto`，从已认证响应的 Alt-Svc 学习。

## 从这里开始

1. [构建](build.md) — 编出 `wknetlib.lib`
2. [第一个请求](first-request.md) — 最小 GET / POST
3. [集成要点](integration-checklist.md) — 链接、生命周期、信任
4. [能力边界](capability-matrix.md) — 支持范围与限制

任务范例见 [Cookbook](cookbook.md)；函数签名见 [API 总览](api/overview.md)。
