# 能力边界

本文说明 wknet 当前支持什么、默认开启什么、以及哪些行为会被拒绝。章节按状态分组，便于对照集成需求。

1. **已实现** — 当前可用；除非另有说明，按默认配置即可使用  
2. **默认关闭** — 已实现，但需显式开启  
3. **策略拒绝** — 出于协议或安全策略会拒绝的请求/响应  
4. **当前不支持** — 现阶段未提供  

定位：HTTP/HTTPS/WebSocket 客户端。传输主路径为 WSK，密码学主路径为 CNG/BCrypt；不使用 WinHTTP、WinINet 或 SChannel。信任锚、CA 包、pin 与撤销证据由调用方提供。同步路径要求 `PASSIVE_LEVEL`。

---

## 1. 已实现

### HTTP/1.1（RFC 9110/9112）

- 请求体：`Content-Length`、库生成 chunked、流式 `BodyCreateStream` / `RequestSetBodySource`；用户手设 `Transfer-Encoding`/`TE` 会被拒绝。
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
- HTTP/3：控制/QPACK 关键单向流、SETTINGS、HEADERS/DATA、1xx、trailer、GOAWAY/取消；server push 会被拒绝。
- 默认 `Http3ConnectMode::Auto`：首次 HTTPS 使用 TCP；只有通过证书与 TLS 策略校验的响应中的精确 `h3` Alt-Svc 会被缓存。DNS/UDP 可指向 alternative，SNI、证书校验与 `:authority` 仍绑定原 origin。
- 以下情况不使用 HTTP/3：`CertPolicy::NoVerify`、HTTP 代理、明文 HTTP、h2c、WebSocket、非 HTTP ALPN、带 `Http2Priority` 的请求。
- 回落 TCP 仅在请求尚未发送，或满足一次安全重放规则时允许。

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

## 2. 默认关闭

默认关闭的能力，以及对应配置字段。头文件：`Types.h`、`Cache.h`、`websocket/WebSocket.h`。

| 能力 | 配置对象 | 字段 / 用法 |
|------|----------|-------------|
| `Expect: 100-continue` | `SendOptions` | `Flags \|= SendFlagExpectContinue`；可选 `ExpectContinueTimeoutMs`（默认 1000） |
| TRACE | `SendOptions` | `Flags \|= SendFlagAllowTrace`（仍拒绝 body / trailer / 敏感头） |
| HTTP/1.1 pipeline | `SessionConfig` | `EnableHttp11Pipeline = true`；`Http11PipelineMaxDepth`（默认 4，上限 64）；`Http11PipelineMethodMask`（默认 GET\|HEAD\|OPTIONS） |
| h2c | `SendOptions` | `Http2CleartextMode = PriorKnowledge` 或 `Upgrade` |
| HTTP/2 PING 保活 | `SessionConfig` | `Http2KeepAlive.Enabled = true`；`IdleMs` / `IntervalMs` / `AckTimeoutMs`（默认各 30000 / 30000 / 5000） |
| HTTP/2 priority | `SendOptions` | `Http2Priority` 指向 `Http2Priority{ StreamDependency, Weight(1..256), Exclusive }` |
| permessage-deflate | `ConnectConfig` | `PerMessageDeflate.Enable = true`；可选 `Client/ServerNoContextTakeover`、`Client/ServerMaxWindowBits`（8..15） |
| TLS 1.2 兼容套件 / 重协商 | `TlsConfig.Policy` | `Profile = CompatibilityExplicit`，再开 `EnableTls12RsaKeyExchange` / `EnableTls12Cbc` / `EnableTls12Sha1Signatures` / `EnableTls12Renegotiation`；`TlsConfig.MaxTls12Renegotiations`（默认 1，上限 4） |
| post-handshake client auth | `TlsConfig.Policy` | `EnablePostHandshakeClientAuth = true`，并设置 `TlsConfig.ClientCredential` |
| 强撤销 | `TlsConfig.Policy` | `RequireRevocationCheck = true`；调用方提供可验证 OCSP/CRL 证据 |
| 内存 cache | `SessionConfig` / `SendOptions` | `CacheCreate` 后赋给 `SessionConfig.Cache`；单次可用 `SendFlagBypassCache` / `NoCacheStore` / `OnlyIfCached` 或 `SendOptions.Cache` |

示例：

```cpp
// 单次发送
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);
options->Flags |= wknet::http::SendFlagExpectContinue;
options->ExpectContinueTimeoutMs = 1000;
options->Flags |= wknet::http::SendFlagAllowTrace;
options->Http2CleartextMode = wknet::http::Http2CleartextMode::PriorKnowledge;

wknet::http::Http2Priority priority = {};
priority.Weight = 16;
options->Http2Priority = &priority;

wknet::http::SendEx(session, wknet::http::Method::Get,
    url, urlLen, nullptr, nullptr, options, &response);
wknet::http::SendOptionsRelease(options);

// 会话
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.EnableHttp11Pipeline = true;
config.Http11PipelineMaxDepth = 4;
config.Http11PipelineMethodMask =
    wknet::http::Http11PipelineMethodGet |
    wknet::http::Http11PipelineMethodHead |
    wknet::http::Http11PipelineMethodOptions;
config.Http2KeepAlive.Enabled = true;
config.Tls.Policy.Profile = wknet::http::TlsSecurityProfile::CompatibilityExplicit;
config.Tls.Policy.EnableTls12Cbc = true;
config.Tls.Policy.RequireRevocationCheck = true;

wknet::http::Cache* cache = nullptr;
wknet::http::CacheOptions cacheOptions = {};
cacheOptions.MaxBytes = 16 * 1024 * 1024;
cacheOptions.MaxEntries = 256;
cacheOptions.Mode = wknet::http::CacheMode::Private;
wknet::http::CacheCreate(&cacheOptions, &cache);
config.Cache = cache;

wknet::http::Session* session = nullptr;
wknet::http::SessionCreate(&config, &session);

// WebSocket
wknet::websocket::ConnectConfig cfg = wknet::websocket::DefaultConnectConfig();
cfg.Url = "wss://example.com/ws";
cfg.UrlLength = 18;
cfg.PerMessageDeflate.Enable = true;
wknet::websocket::WebSocket* ws = nullptr;
wknet::websocket::ConnectEx(session, &cfg, &ws);
```

TLS 1.3 0-RTT（`EnableEarlyData` / `EarlyDataReplaySafe`）仅存在于内部 TLS 连接选项，未映射到 `TlsConfig` / `SendOptions`，产品 HTTP API 不能开启。HTTP/3 应用数据 0-RTT 见「当前不支持」。

---

## 3. 策略拒绝

下列行为会被拒绝；这是既定策略，不表示实现缺失。

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

## 4. 当前不支持

| 能力 | 说明 |
|------|------|
| HTTP server / 入站 request parser | 客户端库，不提供服务端 |
| 磁盘持久化 HTTP cache | 仅有内存 NonPaged cache 对象 |
| HTTP/2 本地 priority 树带宽调度 | 不实现 |
| 除 permessage-deflate 外的 WS 扩展 | 不协商其它扩展 |
| 在线撤销抓取 | 库不发起 OCSP/CRL 网络请求 |
| QUIC v2、H3 0-RTT 应用数据、主动迁移、多路径、ECN、DPLPMTUD、WebTransport、QUIC Datagram、WebSocket over H3 | 当前不支持 |
| WinHTTP / WinINet / SChannel 内核主路径 | 不使用 |
| 独立 client 层 / 第二套连接生命周期 | 不提供 |

---

## 实现策略与信任模型

- 传输：WSK。TLS/HTTP/证书：内核路径自实现。
- 密码学：CNG/BCrypt 优先，缺口由内核软件实现补齐。
- 信任：调用方显式提供锚、CA 包、撤销证据与 pin；库不硬编码系统 CA。

方向摘要见 [路线图](roadmap.md)。能力现状以本页账本为准。
