# HTTP/1.1 协议指南

HTTP/1.1 是 `wknet::http` 在 TCP 上的基线协议。请求 framing 由库生成；响应解析 fail-closed；pipeline、`Expect: 100-continue` 与 TRACE 均为显式 opt-in。

公开入口见 [HTTP 同步](api/http-sync.md) / [请求与响应](api/request-response.md) / [会话配置](api/session-config.md)。

## 结论

| 主题 | 行为 |
|------|------|
| 请求体 | `Content-Length`、库生成 chunked、流式 body source |
| 请求 trailer | **仅** chunked 路径；禁止字段与 CRLF 注入被拒 |
| `Expect: 100-continue` | `SendFlagExpectContinue` 显式开启 |
| pipeline | session 默认关；FIFO；默认仅 `GET`/`HEAD`/`OPTIONS` |
| 代理 | HTTPS → CONNECT；明文 HTTP → absolute-form（不建隧道） |
| redirect | 见下；默认拒绝 HTTPS→HTTP 降级 |
| close-delimited | 无 CL/TE 且连接关闭时完成 body |
| 手写 framing 头 | `Transfer-Encoding`/`TE` 等由库控制，调用方写入被拒 |

## 请求体与 framing

- **已知长度**：发 `Content-Length`；可用内存体、文件体或 `BodyCreateStream` / `RequestSetBodySource` 按块提供。
- **未知长度**：`RequestBodyMode::Chunked`，库生成 `Transfer-Encoding: chunked` 与 chunk framing。
- **流式上传**：回调按块读；不必整包驻留内存。
- **trailer**：`BodyAddTrailer` / `RequestAddTrailer` 只在 chunked 终止块之后发送；`Content-Length`/`Transfer-Encoding`/`Host`/`Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie` 等禁止字段被拒。
- **TRACE**：需 `SendFlagAllowTrace`；带 body、trailer 或敏感头会被拒绝。

调用方不得手写 `Host`/`Content-Length`/`Connection`/`Transfer-Encoding`/`TE`；未走库选项时手写 `Expect: 100-continue` 亦拒。无 `Accept-Encoding` 时库注入默认协商列表（见 [编码与密码学](encoding-and-crypto.md)）。

## Expect 100-continue

`SendFlagExpectContinue` 显式开启，且仅在有 body 时注入：

1. 收到 `100` → 再发 body  
2. 收到 final / `417` → 不发 body  
3. 等待超时（`ExpectContinueTimeoutMs`，默认 1000 ms）→ 按 RFC 时序发送 body  

带 body 或 Expect 的请求不进入 HTTP/1.1 pipeline。

## Pipeline（默认关）

| 项 | 默认 |
|----|------|
| `SessionConfig.EnableHttp11Pipeline` | `false` |
| `Http11PipelineMaxDepth` | 4（硬上限 64） |
| `Http11PipelineMethodMask` | `GET` / `HEAD` / `OPTIONS` |

开启后同源 keep-alive 连接按发送顺序分配 sequence，**FIFO** 绑定响应。解析或传输失败关闭该 pipeline 连接并传播给后续排队请求。

**不进入 pipeline**：带请求体、`Expect: 100-continue`、会触发 redirect 重放、`NoPool`/`ForceNew`、非 mask 方法。避免响应重排与非幂等重放。

## 代理

| 目标 | 形态 |
|------|------|
| `https://` over proxy | `CONNECT` 隧道，TLS 在隧道内 |
| `http://` over proxy | absolute-form request-target，**不**建 CONNECT |
| `Proxy-Authorization` | 仅来自显式 `SessionConfig.Proxy` 配置 |

## 响应 body 框定

- **无 body**：HEAD，或状态 1xx / 204 / **205** / 304。
- **Content-Length**：长度不足 → 继续读；多个 CL 或 TE+CL 冲突 → `STATUS_INVALID_NETWORK_RESPONSE`。
- **chunked**：块数 ≤8192；严格 chunk 扩展语法；终止块后 trailer（每行 ≤8 KiB、数 ≤256）；禁止 trailer 字段同请求侧规则。
- **close-delimited**：无 CL/TE 时，以连接关闭完成消息；此类响应**不回连接池**。

头块须完整（`\r\n\r\n`），否则 `STATUS_MORE_PROCESSING_REQUIRED`；头块 >64 KiB、行 >8 KiB、≥200 个头、**obs-fold** → 失败。状态行仅接受 HTTP/1.0 与 1.1。中间 1xx（除 101）静默吞掉后重解析。

`206` / `Content-Range` 为只读语义；绑定 RFC 9111 cache 后参与验证与 partial 合并，不改变 body 框定。

## Redirect

| 状态 | 方法/body |
|------|-----------|
| 301 / 302 | 仅 POST→GET |
| 303 | 除 HEAD 外→GET |
| 307 / 308 | 保留方法与 body |

- 跨源清理 `Authorization` / `Cookie` / `Proxy-Authorization`。
- **默认拒绝 HTTPS→HTTP 降级**。
- 默认最多 10 跳（`MaxRedirects`）；**达到上限不报错，直接返回该 3xx**。
- `SendFlagDisableAutoRedirect` 关闭自动跟随。

## 与上层的关系

- 安全方法在连接关闭族 / `STATUS_RETRY` / 超时且 `ReuseOrCreate` 时，可以 `ForceNew` **恰好重试一次**（`GET`/`HEAD`/`OPTIONS`）。
- Content-Encoding 解码、解压炸弹与 TE 规则见 [编码与密码学](encoding-and-crypto.md)。
- 能力分类措辞以 [能力账本](capability-matrix.md) 为准。
