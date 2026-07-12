# 传输层

### opaque `Transport` 服务

`transport/Transport.h` 只声明不完整类型 `Transport` 和服务函数：创建明文/回调传输、包装 TLS、收发、超时接收、查询状态与关闭。具体操作表和上下文位于 `TransportPrivate.hpp`，不得跨模块包含。

```cpp
Transport* transport = nullptr;
NTSTATUS status = TransportCreateCallbacks(&operations, context, &transport);
status = TransportSend(transport, data, length, &sent);
status = TransportReceiveWithTimeout(transport, buffer, capacity, &received, timeoutMs);
TransportClose(transport);
```

正式路径为：opaque `WskSocket*` → opaque `Transport*` → HTTPS 时由同一 `Transport*` 服务切换到 opaque `TlsConnection*` → HTTP/1.1、HTTP/2 或 WebSocket 协议层。已删除 `ITransport`、`WskTransport` 和 `TlsTransport`，不保留兼容层。

### Scratch allocator

Scratch 分配器属于 `rtl`。默认 `WorkspaceScratchAllocator` 从请求 Workspace 获取堆缓冲；协议聚合缓冲不使用内核栈，高频缓冲常驻并复用。

### WSK 网络层

- `WskClient.h` 仅暴露 opaque `WskClient*` 的 Create/Initialize/ResolveAll/Shutdown/Close 服务。
- `WskSocket.h` 仅暴露 opaque `WskSocket*` 的 Create/Connect/Send/Receive/Close/Destroy 服务。
- 布局分别位于 `WskClientPrivate.hpp` 与 `WskSocketPrivate.hpp`，只有 `net` 模块可包含。
- 解析缓存最多 16 条、TTL 5 分钟；`AF_UNSPEC` 无结果时显式查询 IPv4、IPv6。
- 取消、超时和在途 I/O 排空仍由 WSK 实现负责。

### 测试传输

`WKNET_USER_MODE_TEST` 使用 callback backend 注入确定性字节流。测试只依赖 `Transport` 公共内部服务，不实现或继承另一套传输接口。
