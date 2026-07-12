# wknet 产品方向

- 产品名 wknet；公共 NS：http / websocket / crypto / codec。
- 内部 NS：rtl net tls http1 http2 ws transport session detail。
- Trace 默认 Off；测试 Max。
- `wknetlib` 各子系统及未来新增功能必须同步补齐统一的分级日志：关键失败使用 Error、可恢复异常使用 Warning、关键状态与生命周期使用 Info、详细流程使用 Verbose/Max，并使用准确的 TraceComponent；不得只完成功能而遗漏日志。
- lib 堆模型、无 JSON、客户端 only、外部 CA trust 不变。
- 无兼容层；旧产品名、旧命名空间与旧前缀 API 不恢复。
- 按总计划实施时，每完成一个可独立验证的阶段应自行提交，然后直接进入下一阶段；计划文档本身仍须等待用户明确要求后才提交。
- `src/wknetlib` 的业务实现最终不得保留 `.inc` 文本实现分片；职责拆分必须落实为独立 `.cpp` 编译单元，并通过 `.h` / `.hpp` 共享声明。
- 不恢复独立 `client` 层；HTTP/HTTPS/HTTP2/WebSocket 的产品路径统一由 `session` 编排，并通过 `transport` 访问 WSK/TLS。
- `include/wknet` 仅放稳定公共 API；`session`、`transport`、`net`、`tls`、`http1`、`http2`、`ws` 的实现头保持 src-local。
- Phase 5–7 已完成：codec 独立、Trace 分级、god files 拆分、连接池字段所有权收紧、旧 client 层删除；后续文档不得再引用旧聚合实现文件或 client 类。
