# HTTP/2 与 HPACK

### 帧与常量

```cpp
enum class Http2FrameType : UCHAR {
    Data=0x0, Headers=0x1, Priority=0x2, RstStream=0x3, Settings=0x4,
    PushPromise=0x5, Ping=0x6, GoAway=0x7, WindowUpdate=0x8, Continuation=0x9
};
```
帧头 9 字节、默认最大帧 16384、最大允许帧 2^24-1、初始窗口 65535、最大窗口 0x7fffffff、前导 `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`（24 字节）。

### 连接建立与 SETTINGS

- 发前导 + 客户端 7 项 SETTINGS（`EnablePush=0`、`MaxConcurrentStreams=100`、`InitialWindowSize=65535`、`MaxFrameSize=32768`、`HeaderTableSize=4096`、`MaxHeaderListSize=头块容量`、`EnableConnectProtocol=0`）。
- **立即发 ACK，不阻塞等服务端 ACK**（服务端常延迟到有请求才 ACK）。
- 校验对端 SETTINGS：payload 须 6 的倍数（否则 `FRAME_SIZE_ERROR`）、`ENABLE_PUSH != 0` → `PROTOCOL_ERROR`、`ENABLE_CONNECT_PROTOCOL > 1` → `PROTOCOL_ERROR`、`InitialWindowSize > 0x7fffffff` → `FLOW_CONTROL_ERROR`、`MaxFrameSize` 越界 → `PROTOCOL_ERROR`。
- 首帧必须是 stream 0 上的非 ACK SETTINGS，否则 GOAWAY。
- **SETTINGS 超时**：无独立计时器——后续读到 `STATUS_IO_TIMEOUT` 且尚未收到对端 ACK → GOAWAY `SETTINGS_TIMEOUT`。

### HEADERS / CONTINUATION

- 累计头块超头块容量（默认 32 KiB，最大 64 KiB）→ GOAWAY `ENHANCE_YOUR_CALM` + `STATUS_BUFFER_TOO_SMALL`。
- CONTINUATION 序列严格校验；**洪泛防护**：`Http2MaxContinuationFrames=64`、`Http2MaxEmptyContinuationFrames=4`，超限 GOAWAY `PROTOCOL_ERROR`（CVE-2024-27316 类）。
- HPACK 解码失败映射：`STATUS_BUFFER_TOO_SMALL`→`ENHANCE_YOUR_CALM`；压缩失败→`COMPRESSION_ERROR`。

### 头校验

- 字段名拒绝大写、控制字符、空格、内嵌 `:`；值拒绝 `\0\r\n`。
- 伪头仅 `:status`，须先于普通头、不重复、trailer 中不得出现；缺 `:status`（非 trailer）→ 非法。
- 连接专属头禁止：`connection`/`keep-alive`/`proxy-connection`/`transfer-encoding`/`upgrade`；`te` 仅允许值 `trailers`。
- 1xx interim：`:status 101` 或 interim+END_STREAM → RST_STREAM `PROTOCOL_ERROR`；其余 interim 重置块续读最终响应。

### 流控

- DATA 在 headers 前、或 body 被禁（HEAD/1xx/204/304）→ RST_STREAM `PROTOCOL_ERROR`。
- 连接级窗口越界 → GOAWAY `FLOW_CONTROL_ERROR`；**WINDOW_UPDATE 阈值 = 初始窗口一半（32767）**，达阈值补发。
- 每个活动 stream 单独维护远端窗口；对端调整 `InitialWindowSize` 时，同步 delta 到所有活动 stream，窗口越界按流控错误处理。
- 出站请求体受 `min(连接发送窗口, 流远端窗口, peer MaxFrameSize)` 限制；body source 按窗口切 DATA，窗口耗尽则刷缓冲并处理对端 WINDOW_UPDATE。

### 多活动流基础

- `Http2Connection` 维护活动 stream 表（默认容量 16，并受对端 `MAX_CONCURRENT_STREAMS` 限制）。
- `BeginRequest(...)` 只发送 HEADERS/DATA 并返回 stream id；`ReceiveResponse(streamId)` 再收该流响应，帧循环会把其它活动流的 HEADERS/DATA/WINDOW_UPDATE/RST_STREAM 暂存到对应 stream state。
- 同步 `SendRequest` 复用两阶段路径；高层 `khttp` 连接池通过 stream 租约复用同源 H2 连接，按本地/peer 并发上限分配活动流。

### 请求 body source 与 trailers

- `Http2RequestBody.Source` / 高层 body source 驱动请求 DATA，不要求完整 body 一次性驻留内存。
- 请求 trailers 不使用 HTTP/1.1 chunked；body 结束后发送 trailing HEADERS + END_STREAM。
- trailer 复用 HTTP/1.1 禁止字段规则，并额外拒绝任何 trailer 伪头。

### PRIORITY

- `Http2Priority` 使用 RFC 权重范围 1..256，支持 stream dependency 与 exclusive 标志；拒绝自依赖和非法权重。
- 单次请求可通过 `Http2RequestBody.Priority`、`Http2RequestOptions.Priority`、`KhHttpSendOptions.Http2Priority` 或 `khttp::SendOptions.Http2Priority` 显式设置。
- 首个 HEADERS 帧携带 priority 字段；底层也提供独立 PRIORITY frame 编解码。收到 peer PRIORITY 会校验长度和自依赖，不改变本地安全边界或调度策略。

### RFC 8441 extended CONNECT

- 请求头构造支持 `Method=CONNECT` + `ConnectProtocol="websocket"`，编码为 `:method: CONNECT` 与 `:protocol: websocket`。
- 发送前校验对端 `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`，否则返回 `STATUS_NOT_SUPPORTED` 且不分配 stream。
- tunnel stream 收到 `2xx` 响应头后，可用 `SendStreamData` / `ReceiveStreamData` 双向传输 DATA payload（例如 WebSocket frame bytes）。
- 这是低层 HTTP/2 tunnel primitive；高层 `kws` 在 `wss` 且显式设置 `AllowWebSocketOverHttp2` 时可走 RFC 8441，默认仍使用 HTTP/1.1 Upgrade。

### GOAWAY / RST_STREAM / PUSH_PROMISE

- GOAWAY：错误码非 0 → `STATUS_CONNECTION_DISCONNECTED`；错误码 0 但活动流 id > lastStreamId → **`STATUS_RETRY`**（该流未处理，可重试）。
- RST_STREAM：`NoError` 且已收终态响应 → 成功；否则 `STATUS_CONNECTION_DISCONNECTED`。
- 客户端 `EnablePush=0`，**任何 PUSH_PROMISE → GOAWAY `PROTOCOL_ERROR`**；错位控制帧亦然。

### h2c 模式

- **prior knowledge**：直接 `Initialize` + `SendRequest`。
- **Upgrade**：`InitializeAfterUpgrade` 跑完前导/SETTINGS 后置 `nextStreamId_=3`（保留 stream 1 给升级请求），用 `ReceiveResponse(streamId=1)`；`EncodeSettingsPayloadBase64Url` 产出 `HTTP2-Settings` 值。客户端 `Http2Client` 与高层 `SendOptions.Http2CleartextMode=Upgrade` 的 Upgrade 模式**禁止请求体**并重放 101 后残留字节。
- 高层 `khttp` 默认不对 `http://` 使用 h2c；只有单次发送显式设置 `Http2CleartextMode::PriorKnowledge` 或 `Upgrade` 才进入 h2c，连接池 key 会区分 HTTP/1.1、prior knowledge 与 Upgrade。

### HPACK

- 整数：续字节 ≤5、移位/累加溢出 → `STATUS_INTEGER_OVERFLOW`。
- Huffman：>30 bit 码 / EOS / 非全 1 padding → `STATUS_INVALID_NETWORK_RESPONSE`。
- 动态表：大小更新仅限块首且 ≤协商 `HeaderTableSize`；表项大于 max 清空全表；FIFO 驱逐。
- header-list 大小按 `name+value+32`（`HpackEntryOverhead`）计，超 `MaxHeaderListSize` → 非法。
- 静态表 61 项；**编码端对 `authorization`/`cookie`/`proxy-authorization` 强制 Never-Indexed**，不入动态表。

### 边界

高层 `khttp` 已接入同源 H2 连接池多活动流复用，低层继续提供 RFC 8441 extended CONNECT tunnel；`kws` 对 RFC 8441 为显式 opt-in，默认不自动切换。PRIORITY 为显式 per-request 能力，不实现复杂本地树调度；后台 PING 保活默认关闭，可在 session 上显式开启，低层仍提供显式 `SendPing`；不支持 server push；高层 h2c 是显式 opt-in，默认关闭。
