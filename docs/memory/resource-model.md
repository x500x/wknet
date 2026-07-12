# 资源模型偏好

- HTTP 客户端的默认使用体验应接近 Python `requests`：响应聚合缓冲按需使用堆内存增长，不因为低位全局硬上限限制普通大响应。
- `MaxResponseBytes = 0` 表示不设置调用方响应体上限；非零值才表示调用方主动限制 buffered response 大小。
- 安全限制应放在协议安全和恶意输入防护边界上，例如 header section、header count、单帧、单消息、解压膨胀比、超时、取消与分配失败；不要把“临时兜底”式低位容量上限当正式架构。
- Streaming 路径应能处理大文件和长连接，不应受 buffered aggregate response 的总量上限影响。
- WebSocket 消息大小可以保留独立默认上限，不能和 HTTP 响应聚合默认值混用。
- lib禁止使用栈，请使用堆内存，如果堆内存频繁的被使用，请考虑常驻！！
- 全库不要实现任何有关json解析、构造等等功能，将来会有其它库来做
- HTTP/2 请求构造使用 `session/Http2RequestBuilder.*` 的私有堆/Workspace 缓冲，不恢复独立 client 对象和第二套连接生命周期。
