# wknet 日志系统

## 目标与默认行为

wknet 使用统一的 `wknet::Trace*` 分级日志。驱动和库默认等级为 `Off`，只有调用方显式设置等级后才输出；测试程序应设置为 `Max`，以覆盖所有等级和组件。

日志只服务于诊断，不参与业务控制流。日志槽繁忙、格式化失败或消息截断均不得改变请求、连接、TLS、编解码或 WebSocket 操作的返回结果。

## 日志等级

等级是包含式阈值：设置某一级时，会同时包含该级及所有更严重的级别。

| 配置等级 | 实际包含 | 应记录的内容 |
| --- | --- | --- |
| `Off` | 无 | 禁止输出。产品默认值。 |
| `Error` | `Error` | 当前操作无法完成；协议、安全或状态约束被破坏；不可继续的连接、解析、校验、加解密、收发失败。必须带 `status`、错误码或足以定位失败阶段的非敏感元数据。 |
| `Warning` | `Error`、`Warning` | 异常已经发生，但上层操作仍可重试、切换地址/协议或继续收尾；对端发送 GOAWAY/RST_STREAM/Alert 等需要关注的信号；资源繁忙导致日志丢弃以外的可恢复情况。不得把最终失败降为 Warning。 |
| `Info` | `Error`、`Warning`、`Info` | 请求、连接、握手、Session、WebSocket 等关键生命周期的开始、完成、关闭、复用和明确的协议选择。应能在不启用详细日志时还原一次操作的主链路。 |
| `Verbose` | 以上全部加 `Verbose` | 地址尝试、帧分派、记录收发、缓存/连接池决策、协议阶段推进等详细流程。用于定位“在哪一步偏离预期”，不记录载荷。 |
| `Max` | 全部等级 | 帧头、长度、计数、窗口、算法编号、证书索引、编解码阶段等高频细节。即使在 Max，也严格禁止输出秘密和正文。 |

选择等级时以“该事件对当前操作的影响”为准，而不是以代码位置或调用次数决定。最终返回失败必须有 Error；一次失败后明确继续尝试其他路径的事件通常是 Warning；成功的主要边界是 Info；可重复的内部步骤使用 Verbose/Max。

## 组件

组件过滤与等级过滤同时生效。每条日志必须只指定一个准确组件。

| 组件 | 范围 |
| --- | --- |
| `ComponentRtl` | URL、基础运行时与公共内部工具 |
| `ComponentNet` | WSK client、socket、解析与网络 I/O |
| `ComponentTransport` | WSK/TLS 传输抽象及其收发、关闭 |
| `ComponentTls` | TLS 1.2/1.3、记录层、证书校验、ALPN |
| `ComponentCrypto` | CNG、哈希、签名、AEAD 等密码学操作 |
| `ComponentCodec` | 内容解码、EXI、Pack200 等编解码链 |
| `ComponentHttp1` | HTTP/1.x 解析、传输编码和内容解码 |
| `ComponentHttp2` | HTTP/2 帧、HPACK、流和连接控制 |
| `ComponentQuic` | QUIC packet/frame、连接、流、恢复、拥塞与定时器 |
| `ComponentHttp3` | HTTP/3 与 QPACK 连接、流、frame 和压缩状态 |
| `ComponentWs` | WebSocket 连接、握手、帧与消息 |
| `ComponentSession` | 高层请求编排、异步操作、连接池、代理和生命周期 |

## 关联字段

公共文本前缀包含全局递增的 `seq`。需要跨层追踪时使用 `WKNET_TRACE_CORRELATED`，并携带：

- `op`：全局唯一 64 位 OperationId，一次高层 HTTP/WebSocket 操作保持不变。
- `conn`：全局唯一 64 位 ConnectionId，在连接池、Transport、WSK、TLS 间保持不变。
- `stream`：无符号 64 位 HTTP/2/QUIC StreamId；非流场景为 0。该字段的 ABI 已扩展为 64 位，以无损承载 QUIC 的 62 位 stream ID。

OperationId 与 ConnectionId 由日志运行时的全局关联 ID 分配器产生，不允许各子系统自行维护会重复的局部计数器。

## 事件名和字段格式

格式串必须以稳定的小写英文点分事件名开头，后续字段使用 `key=value`：

```text
http.request.start method=1 secure=1
tls.handshake.failed status=0xC0000001
http2.stream.reset stream_id=3 error_code=0x00000008
```

事件名应采用 `<domain>.<subject>.<outcome>` 或更具体的层次，不能把自然语言描述、函数名或动态文本作为事件名。事件名一旦进入事件账本，应视为诊断接口；字段可以扩充，但不得无理由改名或复用为不同语义。

日志运行时统一追加 CRLF，调用点不得自行写入 `\r\n`。禁止 `%p` 以及任何内核地址输出。

## 数据安全边界

所有等级（包括 Max）只允许元数据。禁止记录：

- 请求或响应正文、WebSocket 消息内容；
- 完整 HTTP 头值、Cookie、Authorization、Proxy-Authorization、凭据和口令；
- 密钥、派生秘密、随机数、nonce 原文；
- 证书 DER、证书原文、完整 SPKI 哈希或 pin；
- URL 查询字符串；
- 内核指针或其他可还原内核地址的信息。

允许的例子包括长度、数量、索引、枚举值、状态码、TLS/HTTP 版本、帧类型、流 ID、窗口大小、是否命中缓存，以及不含查询和凭据的布尔决策。

## 缓冲与并发模型

日志运行时常驻 32 个槽，每槽恰好一页（4 KiB）并按页对齐，总计约 128 KiB 非分页内存。单条日志占用一个槽，格式化和 Sink 调用完成后释放；不进行逐条堆分配，也不在 `wknetlib` 栈上放置 4 KiB 缓冲。

槽获取是非阻塞的。全部槽繁忙时丢弃当前日志并增加 `DroppedBusy`，不等待、不回退为其他输出路径。过长消息在槽内截断并追加 `[truncated]`。`TraceStatistics` 提供：

- `Emitted`
- `DroppedBusy`
- `FormatFailures`
- `Truncated`

## 新功能要求

新增或扩展 `wknetlib` 功能时，必须同步更新诊断事件账本，并至少检查：入口/完成、最终失败、可恢复分支、重要协议或资源决策，以及跨层关联 ID 是否连续。不得只完成功能而遗漏日志。

提交前运行：

```powershell
pwsh -NoLogo -NoProfile -File .\tools\check-trace-events.ps1
```

检查器会拒绝不稳定事件名、调用点手写 CRLF、指针格式和明显敏感字段格式。
