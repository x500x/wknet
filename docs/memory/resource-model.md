# 资源模型偏好

- HTTP 客户端的默认使用体验应接近 Python `requests`：响应聚合缓冲按需使用堆内存增长，不因为低位全局硬上限限制普通大响应。
- `MaxResponseBytes = 0` 表示不设置调用方响应体上限；非零值才表示调用方主动限制 buffered response 大小。
- 安全限制应放在协议安全和恶意输入防护边界上，例如 header section、header count、单帧、单消息、解压膨胀比、超时、取消与分配失败；不要把“临时兜底”式低位容量上限当正式架构。
- Streaming 路径应能处理大文件和长连接，不应受 buffered aggregate response 的总量上限影响。
- WebSocket 消息大小可以保留独立默认上限，不能和 HTTP 响应聚合默认值混用。
- lib禁止使用栈，请使用堆内存，如果堆内存频繁的被使用，请考虑常驻！！
- 全库不要实现任何有关json解析、构造等等功能，将来会有其它库来做
- HTTP/2 请求构造使用 `session/Http2RequestBuilder.*` 的私有堆/Workspace 缓冲，不恢复独立 client 对象和第二套连接生命周期。

- 请求头/值、trailers、WS/SSE 额外头按需堆增长（`StoredHeaderList`）；条数 hard ceiling 为 `WKNET_HARD_MAX_HEADERS`（默认 512，session `MaxResponseHeaders` 可下调），单字段顶对齐 H1 行预算（名 128 / 值 8 KiB）。不要再引入固定 16 槽或 512 字节客户端硬顶。
- 响应头条数同样受 `MaxResponseHeaders`（默认可配 hard ceiling 512）与 header section 64 KiB 约束；超限 fail-closed。
- 证书 NameConstraints / 吊销 URI 固定缓存溢出时 soft-truncate 并继续解析，禁止 `STATUS_NOT_SUPPORTED` 误伤合法对端（与 SAN 回扫语义一致）。
- Workspace HTTP/H2 header scratch 默认按 hard max 预留；发送路径仍可按 count 增长。

- Path/request-target is heap-owned and grows with the URL (hard ceiling 16 KiB), not a fixed 8000-byte array.
- SSE event queue grows on demand up to `MaxQueuedEvents` (default 32, hard ceiling 4096); full queue fails closed rather than dropping silently.
- Certificate store trust anchors / authority bundles / pins / revocation entries are heap lists with high growth ceilings, not fixed 8/16/32 arrays.
- DNS resolve cache is a pure performance table (default 256 slots).

