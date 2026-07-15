# 能力账本

能力按四类记账，读的时候别混在一起：

1. **已实现** — 默认可用，或文档写明的默认行为  
2. **默认关** — 代码已有，须显式打开  
3. **安全拒绝** — 策略上故意挡掉  
4. **非目标** — 当前不做，也不打算用兼容层补齐  

硬约束：客户端 only；WSK + CNG；无 WinHTTP/SChannel；无独立 client 层；信任锚调用方提供；`PASSIVE_LEVEL` 同步路径。

---

## 1. 已实现

### HTTP/1.1（RFC 9110/9112）

- 请求体：`Content-Length`、库生成 chunked、流式 `BodyCreateStream` / `RequestSetBodySource`；用户手设 `Transfer-Encoding`/`TE` **安全拒绝**。
- 请求 trailer：仅 chunked 路径；禁止字段与 CRLF 注入拒绝。
- 响应：状态行仅 HTTP/1.0/1.1；头行/头段/头数有界；**拒绝 obs-fold**；多 `Content-Length` 或 `TE`+`CL` 冲突 → `STATUS_INVALID_NETWORK_RESPONSE`。
- Body 框定：CL / chunked / close-delimited；无 body：1xx、204、205、304、HEAD。
- `206` / `Content-Range` 只读解析；Range 与条件请求 helper；可选 RFC 9111 内存 cache 参与验证与 partial 合并。
- `Content-Encoding`：gzip/deflate/br/compress/zstd/dcz/aes128gcm/exi/pack200-gzip/identity（最多 2 级，反序解码；膨胀比有界）。
- 中间 1xx（除 101）吞掉重解析；自动 redirect；keep-alive 池复用。
- 代理：HTTPS **CONNECT**；明文 HTTP absolute-form；`Proxy-Authorization` 仅来自显式配置。

### HTTP/2（RFC 9113 + HPACK）

- 前导 + SETTINGS；客户端 `ENABLE_PUSH=0`；CONTINUATION 洪泛防护；流控与伪头校验。
- 连接池 stream 租约：同源 H2 多请求；DATA 按流控与 `MAX_FRAME_SIZE` 切分；请求 trailer 以 final HEADERS 发送。
- 模式：TLS ALPN `h2`；h2c prior knowledge / Upgrade 为 **opt-in**（见下节）。
- RFC 8441 extended CONNECT：对端 `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` 时可供 WebSocket。
- GOAWAY/`REFUSED_STREAM` → 可 `STATUS_RETRY`；高层仅安全方法重试一次。

### HTTP/3 + QUIC v1 + QPACK

- WSK Datagram + 内核 CNG 主路径；QUIC v1 包/帧、TLS 1.3 over QUIC、ACK/loss/PTO、流控、CID、关闭状态机。
- HTTP/3：控制/QPACK 关键单向流、SETTINGS、HEADERS/DATA、1xx、trailer、GOAWAY/取消；**server push 安全拒绝**。
- **默认 `Http3ConnectMode::Auto`**：首次 HTTPS 走 TCP；仅从**已认证**响应学习精确 `h3` Alt-Svc；alternative 只影响 DNS/UDP，SNI/证书/`authority` 绑定 origin。
- 不进入 H3：`NoVerify`、代理、明文 HTTP、h2c、WebSocket、非 HTTP ALPN、HTTP/2 priority。
- 回落 TCP：仅请求未发送或满足**一次**安全重放规则。

### WebSocket（RFC 6455）

- ws/wss；Accept **常量时间**比对；子协议；调用方 opening headers（拒绝库受控头）。
- `wss` 默认可 offer `h2,http/1.1` → RFC 8441 或回落 HTTP/1.1 Upgrade；`ws://` 不隐式 h2c。
- 分片发送/可选分片接收；自动 Pong；UTF-8/长度/控制帧上限；主动/被动 close。
- 握手 3xx/401/407 **不**自动跟随 → `STATUS_NOT_SUPPORTED`。

### TLS / 证书 / 密码学

- TLS 1.2/1.3 单版本路径；无握手内自动降级；EMS + 安全重协商指示；CBC 须 EtM。
- 证书：有界链、主机名（IP→iPAddress SAN only；**域名不回退 CN**）、离线撤销证据、SPKI pin、mTLS 回调签名（私钥不入库）。
- 密码学：CNG 优先；ChaCha20-Poly1305、X25519 等内核软件补齐；最小 RSA 2048。

### 会话行为（关键默认）

| 行为 | 默认 |
|------|------|
| `MaxRedirects` | **10**；用尽返回当前 3xx，**不报错** |
| HTTPS→HTTP redirect | **拒绝** |
| Stale retry | 仅 **GET/HEAD/OPTIONS**，恰好一次 |
| close-delimited / 101 | **不回池** |
| TRACE | **关**（`SendFlagAllowTrace`） |
| 同步 IRQL | **PASSIVE_LEVEL** |

---

## 2. 默认关闭（须显式开启）

| 能力 | 开启方式 |
|------|----------|
| `Expect: 100-continue` | `SendFlagExpectContinue` |
| HTTP/1.1 pipeline | `EnableHttp11Pipeline=true`（默认方法 GET/HEAD/OPTIONS） |
| h2c prior knowledge / Upgrade | `SendOptions.Http2CleartextMode` |
| HTTP/2 PING 保活 | `Http2KeepAlive.Enabled=true` |
| HTTP/2 per-request priority | `SendOptions.Http2Priority` |
| WebSocket permessage-deflate | `PerMessageDeflate.Enable=true` |
| TLS1.2 RSA-kx / CBC / SHA-1 / 重协商 | `CompatibilityExplicit` + 对应开关 |
| TLS1.3 0-RTT | `EnableEarlyData` + `EarlyDataReplaySafe` |
| TLS1.3 post-handshake client auth | `EnablePostHandshakeClientAuth` |
| 强撤销要求 | `RequireRevocationCheck` |
| TRACE 方法 | `SendFlagAllowTrace` |
| RFC 9111 内存 cache | 调用方创建并挂入 `SessionConfig.Cache` / 发送选项 |

---

## 3. 安全拒绝 / 策略约束

| 行为 | 处理 |
|------|------|
| 用户手写请求 `Transfer-Encoding` / `TE` | 拒绝；framing 由库生成 |
| HTTP `br` 作 Transfer-Encoding | 拒绝；`br` 仅 Content-Encoding |
| HTTP/2 `PUSH_PROMISE` | 协议错误 |
| 未请求/非法 WebSocket 扩展 | 拒绝 |
| WS 握手 redirect / 401 / 407 自动跟随 | `STATUS_NOT_SUPPORTED` |
| TLS 握手内 1.3→1.2 自动降级 | 不做；仅可验证证据后上层显式重连 |
| 证书：IP 用 dNSName/CN；域名回退 CN | 不做 |
| HTTPS→HTTP 自动 redirect | 默认拒绝 |
| 在线 OCSP/CRL 抓取 | 库从不发起 |

---

## 4. 明确非目标

| 能力 | 结论 |
|------|------|
| HTTP server / 入站 request parser | 非目标（客户端 only） |
| 磁盘持久化 HTTP cache | 非目标（仅内存 NonPaged cache 对象） |
| HTTP/2 本地 priority 树带宽调度 | 非目标 |
| 除 permessage-deflate 外的 WS 扩展 | 非目标 |
| 在线撤销抓取 | 非目标 |
| QUIC v2、H3 0-RTT 应用数据、主动迁移、多路径、ECN、DPLPMTUD、WebTransport、QUIC Datagram、WebSocket over H3 | 非目标 |
| WinHTTP / WinINet / SChannel 内核主路径 | 非目标 |
| 独立 client 层 / 第二套连接生命周期 | 非目标 |

---

## 实现策略与信任模型

- 传输：WSK。TLS/HTTP/证书：内核路径自实现。
- 密码学：CNG/BCrypt 优先，缺口由内核软件实现补齐。
- 信任：调用方显式提供锚、CA 包、撤销证据与 pin；库不硬编码系统 CA。

方向摘要见 [路线图](roadmap.md)。能力现状以本页账本为准。
