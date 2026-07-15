# wknet

面向 Windows 内核驱动的纯内核态 HTTP/HTTPS/WebSocket 客户端库。

传输走 WSK，密码学走内核态 CNG/BCrypt；不依赖 WinHTTP、WinINet 或 SChannel。公共 API 仅四个命名空间：`wknet::http`、`wknet::websocket`、`wknet::crypto`、`wknet::codec`。

## 适合 / 不适合

| 适合 | 不适合 |
|------|--------|
| 内核驱动内发起出站 HTTP(S) / WebSocket | 作为 HTTP 服务端 / 入站 parser |
| 需要明确的安全默认值与能力边界 | 依赖系统 CA 自动信任 |
| 希望 HTTP/1.1 · HTTP/2 · HTTP/3 统一产品 API | 需要 QUIC 迁移 / WebTransport 等非目标能力 |

## 硬约束（三行）

1. 同步路径要求 `PASSIVE_LEVEL`；句柄均为堆对象，成对 Create / Close·Release。
2. 信任锚、CA 包、pin、撤销证据由**调用方**提供；主机名校验不回退 CN。
3. Trace 默认 `Off`；HTTP/3 默认 `Auto`（从已认证 Alt-Svc 学习）。

## 从这里开始

1. [构建](build.md) — 编出 `wknetlib.lib`
2. [第一个请求](first-request.md) — 最小 GET / POST
3. [集成清单](integration-checklist.md) — 上线前核对
4. [能力边界](capability-matrix.md) — 已实现 / 默认关 / 拒绝 / 非目标

需要任务范例见 [Cookbook](cookbook.md)；查函数签名见 [API 总览](api/overview.md)。
