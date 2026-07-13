# wknet 日志诊断事件账本

本账本按诊断链路记录必须长期保留的代表性事件，不机械要求每个 `.cpp` 都输出日志。具体实现可以增加更细事件，但不能缺失对应的开始、完成、最终失败或关键可恢复分支。

| 诊断域 | 组件 | 代表性事件 | 最低等级契约 | 关联要求 |
| --- | --- | --- | --- | --- |
| URL 与基础运行时 | RTL | `rtl.url.parse_request.start`、`rtl.url.parse_request.complete` | 主要边界 Info/Verbose；无效输入或解析最终失败 Error | 高层请求存在时带 op |
| 异步操作 | Session | `async.operation.created`、`async.operation.complete`、`async.operation.failed` | 创建/完成 Info，最终失败 Error | 必须带 op |
| 编解码链 | Codec | `codec.decode_chain.start`、`codec.decode_chain.complete`、`codec.decode_chain.failed` | 边界 Verbose，最终失败 Error | 由请求触发时带 op |
| EXI/Pack200 | Codec | `codec.exi.complete`、`codec.exi.failed`、`codec.pack200.complete`、`codec.pack200.failed` | 细节 Max，最终失败 Error | 由请求触发时带 op |
| AEAD | Crypto | `crypto.aead.result` | 成功 Max，失败 Error；只记录算法、长度、状态 | 不记录 key/nonce/tag 原文 |
| 名称解析 | Net | `net.resolve.failed`、`net.resolve.unspec_no_match`、`net.resolve.no_supported_address` | 可切换地址族 Warning，最终失败 Error | 可用时带 op/conn |
| WSK 生命周期 | Net | `net.wsk_socket.opened`、`net.wsk_socket.close_started`、`net.wsk_socket.close_completed` | 生命周期 Info/Verbose，收敛失败 Error | socket 绑定后带 conn |
| Socket I/O | Net | `net.socket.connect.complete`、`net.socket.send.failed`、`net.socket.receive.failed` | 成功细节 Verbose/Max，最终失败 Error | 必须带 conn |
| Datagram I/O | Net | `net.datagram.opened`、`net.datagram.close_started`、`net.datagram.close_completed`、`net.datagram.send.failed`、`net.datagram.receive.failed` | 生命周期 Info，最终 I/O 失败 Error | 必须带 conn；禁止记录地址正文、地址指针、payload 或 token |
| Transport | Transport | `transport.wsk.created`、`transport.tls.created`、`transport.send.failed`、`transport.closed` | 创建/关闭 Info，I/O 细节 Verbose/Max，失败 Error | 必须带 conn；请求路径带 op |
| TLS 握手 | TLS | `tls.handshake.start`、`tls.handshake.complete`、`tls.handshake.failed` | 开始/完成 Info，失败 Error | 必须带 conn；请求路径带 op |
| TLS 1.2 阶段 | TLS | `tls12.client_hello.send_failed`、`tls12.server_hello.parsed`、`tls12.server_finished.verify_failed` | 阶段细节 Verbose/Max，任何最终阶段失败 Error | 必须带 conn（可用时） |
| TLS 1.3 阶段 | TLS | `tls13.stage.failed`、`tls13.session_ticket.cache_skipped` | 阶段失败 Error，不可缓存票据 Warning | 必须带 conn（可用时） |
| 证书校验 | TLS | `tls.certificate.trusted_anchor_found`、`tls.certificate.host_name_failed`、`tls.certificate.revocation_validation_failed` | 成功锚点 Info，跳过无效 authority Warning，校验失败 Error | 必须带 conn（可用时） |
| HTTP/1 响应 | HTTP1 | `http1.response.parse.start`、`http1.response.parse.complete`、`http1.response.transfer_decode.failed` | 解析边界 Verbose，最终失败 Error | 必须带 op/conn |
| HTTP/2 连接 | HTTP2 | `http2.frame.received`、`http2.connection.goaway`、`http2.frame.read_failed` | 帧细节 Verbose/Max，对端控制 Warning，失败 Error | 必须带 conn；流事件带 stream |
| HTTP/2 流 | HTTP2 | `http2.stream.open`、`http2.stream.complete`、`http2.stream.reset` | 生命周期 Info/Verbose，RST_STREAM Warning/错误按操作结果补 Error | 必须带 op/conn/stream |
| HTTP 请求 | Session | `http.request.start`、`http.request.complete`、`http.request.failed` | 开始/完成 Info，最终失败 Error | 必须带 op；连接建立后带 conn |
| 缓存与连接池 | Session | `http.cache.lookup.failed`、`http.connection.retry`、`pool.connection.acquire` | 决策 Verbose，恢复性重试 Warning，导致操作失败时另记 Error | 必须带 op；池连接带 conn |
| 代理与协议确认 | Session | `session.socket.connect_attempt_failed`、`session.tls12_confirmation.completed`、`session.tls12_confirmation.failed` | 地址尝试 Warning，确认完成 Info，最终失败 Error | 必须带 op/conn（可用时） |
| WebSocket 连接 | WS | `ws.connect.start`、`ws.connect.complete`、`ws.connect.failed` | 开始/完成 Info，最终失败 Error | 必须带 op/conn |
| WebSocket 握手 | WS | `ws.handshake.request_built`、`ws.handshake.validation_failed`、`ws.alpn.unexpected` | 构建细节 Verbose，协议不匹配/失败 Error | 必须带 op/conn |
| WebSocket 帧/消息 | WS | `ws.frame.encode`、`ws.frame.decode_header`、`ws.message.receive_failed` | 帧头元数据 Max，最终收发失败 Error | 必须带 op/conn；不记录消息内容 |
| Session 生命周期 | Session | `session.created`、`session.close.start`、`session.close.complete`、`session.shutdown.session_close_stalled` | 创建/关闭 Info，扫尾未推进 Warning | 不要求 op；连接/请求事件另行关联 |

## 账本维护规则

1. 新功能在实现时同步增加代表性事件和测试，不在功能完成后补“泛化日志”。
2. Error 必须覆盖最终返回失败；如果低层已记录具体失败，高层仍应记录操作级失败并携带完整关联字段。
3. Warning 必须对应确实可继续的路径；重试全部耗尽后必须再产生 Error。
4. Info 应足以还原主要生命周期，不依赖 Verbose/Max 才能知道操作是否开始和结束。
5. Verbose/Max 只能增加元数据粒度，不能放宽安全边界。
6. 事件重命名、删除或语义变更必须同步修改本账本、测试和 docsite 文档。
