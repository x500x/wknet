# 集成要点

把库链进驱动时需要落定的几件事：构建链接、调用约定、生命周期、信任与协议选型。

## 构建与链接

- 工具链：VS 2022 + 匹配的 WDK / SDK
- 链接 `wknetlib.lib`，附加包含目录指向 `include`
- 产品代码只包含 `<wknet/Wknet.h>`（或细分公共头），不包含 `src/wknetlib` 内部头
- Debug / Release 均视警告为错误

## 调用约定

- 同步 HTTP / WebSocket / TLS / 证书路径在 `PASSIVE_LEVEL` 调用
- 公共句柄经 Create 取得，经 Close / Release 释放；失败路径可无条件 Release（接受 `nullptr`）
- `SendOptions` / `AsyncOptions` 等同为堆对象，使用对应 Create / Release
- 检查 `_Must_inspect_result_` 返回值

## 生命周期与卸载

- 同主机请求复用同一 `Session`，便于连接池命中
- `Response` 与 `Request` / `AsyncOp` 生命周期独立，分别释放
- 使用过异步 API 时，在卸载路径调用 `wknet::http::Destroy()`，再拆除 WSK 等子系统
- WebSocket：`Close` 不与同句柄上新的收发并发；常见写法是单线程 连接 → 发 → 收 → 关
- `wknet::websocket::Receive` 的 `Message.Data` 指向内部缓冲，在下次收 / 关前有效

## 信任与默认行为

- 生产使用 `CertPolicy::Verify`，并提供调用方 `CertificateStore`（信任锚 / pin）
- 发布配置中不要保留 `NoVerify`
- HTTPS→HTTP redirect 默认拒绝；跨源 redirect 会清理敏感头
- stale 连接失败时，仅 `GET` / `HEAD` / `OPTIONS` 自动重试一次；POST 等不自动重放
- 强撤销：显式 `RequireRevocationCheck`，并提供可验证的 OCSP/CRL 证据

## 诊断

- 产品路径 Trace 默认 `Off`（需要时可调到 Info）；不记录 body、Cookie、密钥、完整 URL query
- 诊断时按组件过滤；生产避免全局 Max

## 协议选型

- HTTP/3 默认 `Auto`；不需要时用 `Disabled`，prior-knowledge 用 `Required`
- h2c、pipeline、0-RTT、permessage-deflate 等默认关闭，仅在明确需要时开启
- 支持范围与限制见 [能力边界](capability-matrix.md)

日常用法见 [Cookbook](cookbook.md)；语义见 [会话与连接池](session-and-pool.md)、[异步模型](async-model.md)。
