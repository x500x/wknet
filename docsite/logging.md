# 日志与诊断

统一使用 `wknet::Trace*` 分级日志。**产品默认 `Off`**；测试与 `wknettest` 使用 `Max`。等级为包含式阈值：`Info` 同时包含 Error / Warning / Info。

| 等级 | 内容 |
|------|------|
| `Off` | 不输出（产品默认） |
| `Error` | 当前操作无法完成，或协议/安全/状态约束被破坏 |
| `Warning` | 异常但可重试、切换路径或继续收尾 |
| `Info` | 请求、连接、TLS、Session、WebSocket、SSE 的关键生命周期边界 |
| `Verbose` | 地址尝试、缓存/池决策、帧分派、协议阶段 |
| `Max` | 长度、数量、窗口、算法编号、帧头等高频元数据 |

任何等级都**禁止**输出 body、SSE 事件 data/id 原文、完整头值、Cookie、凭据、密钥、随机数、证书原文、URL query 或内核地址。

## 组件过滤

可按 RTL、Net、Transport、TLS、Crypto、Codec、HTTP/1、HTTP/2、HTTP/3、QUIC、WebSocket、Session 等组件过滤。每条事件只归属一个准确组件。

## 关联字段

跨层事件携带：

- `op`：全局唯一 64 位 OperationId
- `conn`：全局唯一 64 位 ConnectionId
- `stream`：HTTP/2 StreamId；非 HTTP/2 为 0
- `seq`：全局递增序号

事件名是稳定的小写点分标识，例如：

```text
http.request.start
tls.handshake.failed status=0xC0000001
http2.stream.reset stream_id=3 error_code=0x00000008
quic.handshake.completed
http.altsvc.stored
```

## 缓冲模型

运行时保留固定数量的常驻 trace 槽（页对齐 NonPaged），**不**为每条事件分配内存。槽全忙时丢弃并计数，不阻塞网络/协议路径。`TraceStatistics` 暴露 Emitted / DroppedBusy / FormatFailures / Truncated。

## 开发检查

每个新 `wknetlib` 功能必须补合适等级、组件与关联字段。提交前：

```powershell
pwsh -NoLogo -NoProfile -File .\tools\check-trace-events.ps1
```

检查拒绝不稳定事件名、调用方注入换行、指针格式化与明显敏感值格式化。
