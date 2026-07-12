# 日志与诊断

wknet 使用统一的 `wknet::Trace*` 分级日志。默认等级是 `Off`；测试与 `wknettest` 设置为 `Max`。等级采用包含式阈值，例如 `Info` 同时包含 `Error`、`Warning` 和 `Info`。

| 等级 | 内容 |
| --- | --- |
| `Off` | 不输出日志。产品默认值。 |
| `Error` | 当前操作无法完成，或协议、安全、状态约束被破坏。 |
| `Warning` | 已出现异常，但仍会重试、切换路径或继续收尾。 |
| `Info` | 请求、连接、TLS、Session、WebSocket 的关键开始、完成与关闭。 |
| `Verbose` | 地址尝试、缓存/连接池决策、帧分派和协议阶段推进。 |
| `Max` | 长度、数量、窗口、算法编号、帧头等高频元数据。 |

无论等级多高，都禁止输出正文、完整头值、Cookie、凭据、密钥、随机数、证书原文、URL 查询字符串或内核地址。

## 组件过滤

可以按组件过滤 RTL、Net、Transport、TLS、Crypto、Codec、HTTP/1、HTTP/2、WebSocket 和 Session 日志。每条事件只归属一个准确组件。

## 关联字段

需要跨层追踪的事件带有：

- `op`：全局唯一 64 位 OperationId；
- `conn`：全局唯一 64 位 ConnectionId；
- `stream`：HTTP/2 StreamId，非 HTTP/2 场景为 0；
- `seq`：全局递增日志序号。

事件名是稳定的小写英文点分名称，例如：

```text
http.request.start
tls.handshake.failed status=0xC0000001
http2.stream.reset stream_id=3 error_code=0x00000008
```

## 缓冲模型

运行时常驻 32 个日志槽，每槽恰好一页（4 KiB）并按页对齐，总计约 128 KiB 非分页内存。日志不进行逐条堆分配；全部槽繁忙时，当前日志被丢弃并计入统计，不阻塞网络或协议操作。

`TraceStatistics` 提供 `Emitted`、`DroppedBusy`、`FormatFailures` 和 `Truncated`。过长消息会在槽内截断并标记 `[truncated]`。

## 开发检查

新增 wknetlib 功能必须同时补充相应等级、组件和关联字段的诊断事件。提交前运行：

```powershell
pwsh -NoLogo -NoProfile -File .\tools\check-trace-events.ps1
```

该检查会拒绝不稳定事件名、调用点手写换行、指针格式和明显敏感字段。
