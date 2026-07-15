# 集成清单

上线前逐项确认。任一项失败都不该进入生产路径。

## 构建与链接

- [ ] 使用匹配的 VS 2022 + WDK + SDK
- [ ] 链接 `wknetlib.lib`，附加包含目录指向 `include`
- [ ] 产品代码只 `#include <wknet/Wknet.h>`（或细分公共头），不包含 `src/wknetlib` 内部头
- [ ] Debug/Release 均视警告为错误

## 调用约定

- [ ] 同步 HTTP / WebSocket / TLS / 证书路径仅在 `PASSIVE_LEVEL`
- [ ] 所有公共句柄来自 Create，用 Close / Release 释放；失败路径无条件 Release（接受 `nullptr`）
- [ ] `SendOptions` / `AsyncOptions` 等选项对象也是堆对象，用对应 Create / Release
- [ ] 检查每一个 `_Must_inspect_result_` 返回值

## 生命周期与卸载

- [ ] 同一 `Session` 复用到同主机请求，以命中连接池
- [ ] `Response` 与 `Request` / `AsyncOp` 生命周期独立，分别释放
- [ ] 使用过异步 API 时，驱动卸载前调用 `wknet::http::Destroy()`，再拆 WSK / 其他子系统
- [ ] WebSocket：`Close` 不与同句柄上新的收发发起并发；最安全是单线程 连接→发→收→关
- [ ] `wknet::websocket::Receive` 的 `Message.Data` 指向内部缓冲，下次收/关前有效

## 安全默认

- [ ] 生产使用 `CertPolicy::Verify`，并提供调用方 `CertificateStore`（信任锚 / pin）
- [ ] 未把 `NoVerify` 留在发布配置
- [ ] 理解 HTTPS→HTTP redirect 默认拒绝；跨源 redirect 会清理敏感头
- [ ] 理解只有 `GET` / `HEAD` / `OPTIONS` 在 stale 连接失败时自动重试一次；POST 等不自动重放
- [ ] 需要强撤销时显式 `RequireRevocationCheck`，并提供可验证 OCSP/CRL 证据

## 可观测性

- [ ] 产品路径 Trace 保持默认 `Off`（或按需 Info）；不在日志中打印 body、Cookie、密钥、完整 URL query
- [ ] 需要诊断时按组件过滤；生产环境避免全局 Max

## 协议选型（按需）

- [ ] HTTP/3 默认 `Auto` 可接受；不需要时 `Disabled`，prior-knowledge 用 `Required`
- [ ] h2c / pipeline / 0-RTT / permessage-deflate 等默认关能力仅在明确需要时 opt-in
- [ ] 已读 [能力边界](capability-matrix.md)，确认非目标能力不在依赖路径上

完成清单后：日常用法见 [Cookbook](cookbook.md)，行为语义见 [会话与连接池](session-and-pool.md) 与 [异步模型](async-model.md)。
