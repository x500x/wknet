# 错误码与 FAQ

先看 `NT_SUCCESS(status)`，再按场景分支。Release/Close 接受 `nullptr`，失败路径也统一释放。

## 常用 NTSTATUS

### 通用

| NTSTATUS | 典型含义 |
|----------|----------|
| `STATUS_SUCCESS` | 成功（也可用 `NT_SUCCESS`，勿只比 `== SUCCESS`） |
| `STATUS_INVALID_PARAMETER` | 非法 URL、禁止头、配置越界、`Paged` 池类型等 |
| `STATUS_NOT_SUPPORTED` | scheme 不支持、手写 TE、0-RTT 未声明 replay-safe、WS 3xx/401/407、未启用能力 |
| `STATUS_INSUFFICIENT_RESOURCES` | 分配失败、异步队列满(256)、每主机连接配额满 |
| `STATUS_INTEGER_OVERFLOW` | 长度/大小计算溢出 |
| `STATUS_INVALID_DEVICE_REQUEST` | **非 PASSIVE_LEVEL** 调用 |
| `STATUS_INVALID_DEVICE_STATE` | 句柄状态非法、WSK 未就绪、序列号溢出 |
| `STATUS_DEVICE_NOT_READY` | WSK 未初始化 / 异步运行时已停止 |

### 网络 / HTTP

| NTSTATUS | 典型含义 |
|----------|----------|
| `STATUS_IO_TIMEOUT` | 收发/握手/等待超时 |
| `STATUS_CONNECTION_DISCONNECTED` | 对端断开、短写、GOAWAY 非 0、RST |
| `STATUS_BUFFER_TOO_SMALL` | 响应超 `MaxResponseBytes`、WS 消息超限、缓冲不足 |
| `STATUS_INVALID_NETWORK_RESPONSE` | 协议违规（状态行/头/帧/HPACK/obs-fold/解压失败等） |
| `STATUS_RETRY` | 可重试（如干净 GOAWAY 未处理本流）；高层仅对安全方法自动一次 |
| `STATUS_CANCELLED` | 异步取消完成 |
| `STATUS_NOT_FOUND` | 无解析地址 / 无响应可取 |

### TLS / 证书

| NTSTATUS | 典型含义 |
|----------|----------|
| `STATUS_TRUST_FAILURE` | 链/有效期/主机名/pin/信任锚/撤销 fail-closed |
| `STATUS_INVALID_SIGNATURE` | MAC / AEAD / CBC MAC 失败 |
| `STATUS_NOT_SUPPORTED` | 版本/策略拒绝、弱算法、0-RTT 策略 |

```cpp
NTSTATUS s = wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &resp);
if (!NT_SUCCESS(s)) {
    switch (s) {
    case STATUS_IO_TIMEOUT:              /* 超时策略 */ break;
    case STATUS_TRUST_FAILURE:           /* 检查 Store/主机名/撤销 */ break;
    case STATUS_CONNECTION_DISCONNECTED: /* 重连或换节点 */ break;
    case STATUS_BUFFER_TOO_SMALL:        /* 调大 MaxResponseBytes */ break;
    case STATUS_RETRY:                   /* 安全方法可再试 */ break;
    default:                             /* 记录 0x%08X */ break;
    }
}
```

## FAQ

**Q：为什么不用 WinHTTP / WinINet / SChannel？**  
A：定位为内核驱动可用的纯内核协议栈。传输主路径 WSK，密码学 CNG/BCrypt，TLS/HTTP 自实现。

**Q：调用 IRQL？**  
A：同步 HTTP / WebSocket / TLS / 证书路径必须 **`PASSIVE_LEVEL`**。RAII 析构同样要求（内部 Release/Close）。

**Q：支持服务端吗？**  
A：不支持。客户端 only；无入站 request parser。

**Q：代理怎么配？**  
A：`SessionConfig.Proxy`：`Host`/`Port`/`Family`/`Authority`/`AuthHeader`。HTTPS 走 CONNECT；明文 HTTP 发 absolute-form。启用代理时不走 H3 Auto。

**Q：HTTP/3 默认开吗？**  
A：`Http3ConnectMode::Auto` 为默认：首次 TCP，从**已认证** Alt-Svc 学习后后续可优先 H3。`Disabled` 关闭；`Required` 为 prior-knowledge。

**Q：POST 会自动重试吗？**  
A：不会。stale 重试仅 **GET/HEAD/OPTIONS** 一次。POST/PUT/PATCH/DELETE 不自动重放。

**Q：重定向次数用尽？**  
A：默认最多 **10** 跳；用尽**不报错**，返回当前 3xx，自行处理 `Location`。HTTPS→HTTP 默认拒绝。

**Q：证书能关吗？**  
A：存在 `CertPolicy::NoVerify`，生产严禁。库不带系统 CA，须自备信任锚。IP literal 只匹配 iPAddress SAN；域名不回退 CN。

**Q：0-RTT 为什么失败？**  
A：默认关；须 early data + 显式 `EarlyDataReplaySafe`，否则 `STATUS_NOT_SUPPORTED`。

**Q：WebSocket 命名空间？**  
A：`wknet::websocket`（`Connect`/`SendText`/`Receive`/`Close`）；Session 仍是 `wknet::http::Session`。`wss` 可走 RFC 8441 或 HTTP/1.1 Upgrade。

**Q：异步卸载要注意什么？**  
A：用过 `Async*` 后，卸载前先 `wknet::http::Destroy()` 排空 worker，再放 WSK/句柄。取消后仍要 `AsyncWait` + `AsyncRelease`。

**Q：close-delimited 响应会进池吗？**  
A：不会。close-delimited 与 **101** 永不回池。

完整能力分类见 [能力账本](capability-matrix.md)。
