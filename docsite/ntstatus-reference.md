# NTSTATUS 错误码 / NTSTATUS Reference

项目统一使用 Windows NTSTATUS 错误码，用 `NT_SUCCESS()` 判断成功。下表为代码中实际使用的主要返回码及其典型来源。

[English](#english) | 简体中文

---

## 简体中文

### 通用

| NTSTATUS | 典型含义 / 来源 |
|----------|----------------|
| `STATUS_SUCCESS` | 成功 |
| `STATUS_INVALID_PARAMETER` | 参数无效；如非法 URL、禁止的头（Host/Content-Length/Connection）、配置越界 |
| `STATUS_NOT_SUPPORTED` | 能力不支持/未启用；如非 http(s)/ws(s) scheme、用户设 `Transfer-Encoding`、TE 中 `br`、ALPN 不被支持、0-RTT 未声明 replay-safe、h2 未协商、未实现或未启用的签名方案 |
| `STATUS_INSUFFICIENT_RESOURCES` | 资源不足；如异步队列满（256）、每主机连接配额满、分配失败 |
| `STATUS_INTEGER_OVERFLOW` | 大小/长度计算溢出；如 HPACK 整数、body 增长 |
| `STATUS_INVALID_DEVICE_REQUEST` | 非 `PASSIVE_LEVEL` 调用（IRQL 违规） |
| `STATUS_INVALID_DEVICE_STATE` | 句柄状态非法、WSK 未就绪、序列号溢出 |
| `STATUS_DEVICE_NOT_READY` | WSK 未初始化 / 异步运行时已停止 |

### 网络 / HTTP

| NTSTATUS | 典型含义 / 来源 |
|----------|----------------|
| `STATUS_IO_TIMEOUT` | 操作超时（WSK 收发默认 30s、TLS 握手 120s、drain） |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 / 短写 / GOAWAY 非 0 / RST_STREAM |
| `STATUS_BUFFER_TOO_SMALL` | 缓冲不足；如响应超 `MaxResponseBytes`、头/解码缓冲不够、解压超 16 MiB、WS 消息超 `MaxMessageBytes` |
| `STATUS_MORE_PROCESSING_REQUIRED` | 需更多字节（解析器内部驱动 receive 循环） |
| `STATUS_INVALID_NETWORK_RESPONSE` | 协议违规；如非法状态行/头、obs-fold、重复 CL、解压校验失败、非法帧、HPACK 错误 |
| `STATUS_RETRY` | 可重试；如干净 GOAWAY 未处理本流 |
| `STATUS_CANCELLED` | 异步操作被取消 |
| `STATUS_NOT_FOUND` | 无可用解析地址 / 无响应可取 |

### TLS / 证书

| NTSTATUS | 典型含义 / 来源 |
|----------|----------------|
| `STATUS_TRUST_FAILURE` | 证书校验失败；链/有效期/主机名/pin/信任锚/撤销(fail-closed) |
| `STATUS_INVALID_SIGNATURE` | MAC / AEAD tag / CBC MAC 校验失败 |
| `STATUS_NOT_SUPPORTED` | TLS 版本协商失败、弱算法被策略拒、未实现或未启用的签名方案、early data 不 replay-safe |

### 处理示例

```cpp
NTSTATUS s = khttp::Get(session, url, urlLen, &resp);
if (!NT_SUCCESS(s)) {
    switch (s) {
    case STATUS_IO_TIMEOUT:             /* 重试或报告 */ break;
    case STATUS_TRUST_FAILURE:          /* 检查证书配置 */ break;
    case STATUS_CONNECTION_DISCONNECTED:/* 重连 */ break;
    case STATUS_BUFFER_TOO_SMALL:       /* 调大 MaxResponseBytes */ break;
    default:                            /* 记录 0x%08X */ break;
    }
}
```

### 检查惯例

- 用 `NT_SUCCESS(status)` 判断，不要 `== STATUS_SUCCESS`（有信息性成功码）。
- 标了 `_Must_inspect_result_` 的返回值必须检查。
- Release/Close 接受 `nullptr`，失败路径也统一释放，避免泄漏。

---

## English

The project uses Windows NTSTATUS throughout; test with `NT_SUCCESS()`. The tables above list the codes actually used and their typical sources. Highlights: `STATUS_INVALID_DEVICE_REQUEST` = IRQL violation (not `PASSIVE_LEVEL`); `STATUS_NOT_SUPPORTED` = unsupported scheme / user `Transfer-Encoding` / unsupported ALPN / non-replay-safe 0-RTT / un-negotiated h2 / unsupported or disabled signature schemes; `STATUS_INVALID_NETWORK_RESPONSE` = protocol violations (bad status line/headers, obs-fold, duplicate Content-Length, decode-verification failure, illegal frames, HPACK errors); `STATUS_BUFFER_TOO_SMALL` = over `MaxResponseBytes` / decode > 16 MiB / WS over `MaxMessageBytes`; `STATUS_TRUST_FAILURE` = certificate validation failure including fail-closed revocation; `STATUS_INVALID_SIGNATURE` = MAC/AEAD/CBC-MAC/signature verification failure; `STATUS_RETRY` = retryable (e.g. clean GOAWAY); `STATUS_CANCELLED` = cancelled async op. Use `NT_SUCCESS`, honor `_Must_inspect_result_`, and release on all paths (Release/Close accept `nullptr`).
