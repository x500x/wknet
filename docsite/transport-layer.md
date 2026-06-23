# 传输层

### ITransport（`core/ITransport.h`）

字节流抽象，统一明文与 TLS：
```cpp
struct ITransport {
    virtual NTSTATUS Send(const void* data, SIZE_T len, SIZE_T* sent) = 0;
    virtual NTSTATUS Receive(void* buf, SIZE_T len, SIZE_T* recv) = 0;
    virtual NTSTATUS ReceiveWithTimeout(void* buf, SIZE_T len, SIZE_T* recv, ULONG timeoutMs) = 0;
};
```

### 适配器

- **WskTransport**（`core/WskTransport.h`）：包 `net::WskSocket`，发送用 `WSK_FLAG_NODELAY`，可设取消令牌 `SetCancellation`。明文路径。
- **TlsTransport**（`core/TlsTransport.h`）：包一个底层 `ITransport` + `tls::TlsConnection`，对字节流自动加解密。`RawTransport()` / `Tls()` 取内部对象。

栈：`WskSocket` → `WskTransport`(ITransport) →（HTTPS 时）`TlsTransport`(ITransport) → 协议层。

### IScratchAllocator（`core/IScratchAllocator.h`）

```cpp
struct IScratchAllocator {
    virtual NTSTATUS Acquire(SIZE_T len, void** buf) = 0;
    virtual void     Release(void* buf) = 0;
    virtual NTSTATUS EnsureBuffer(SIZE_T len, void** buf) = 0;
};
```
默认实现 `WorkspaceScratchAllocator`（见 [内存模型](memory-model.md)）。

### WSK 网络层（`net/`）

**WskClient**（`net/WskClient.h`）— WSK 注册与 DNS 解析：
```cpp
NTSTATUS Initialize(ULONG waitTimeoutMs = 3000);  void Shutdown();  bool IsInitialized();
NTSTATUS Resolve(node, service, SOCKADDR_STORAGE*, WskAddressFamily = Any);
NTSTATUS ResolveAll(node, service, SOCKADDR_STORAGE*, cap, &count, family);  // 最多 8 个
```
`WskAddressFamily { Any, Ipv4=4, Ipv6=6 }`。
- 解析含 **16 条目、5 分钟 TTL 的缓存**（按小写 node/service+family 键，`FAST_MUTEX` 保护）。
- `AF_UNSPEC` 无结果时回退**显式先 IPv4 后 IPv6** 分别查询再合并。
- `Shutdown` 前用 `WskSyncWaitForOutstandingContexts(30000)` 排空在途 IRP。

**WskSocket**（`net/WskSocket.h`）— 连接 socket：
```cpp
NTSTATUS Connect(WskClient&, const SOCKADDR* remote, const SOCKADDR* local = nullptr, const WskCancellationToken* = nullptr);
NTSTATUS Send(...); NTSTATUS Receive(... ULONG timeoutMs = 30000 ...);
NTSTATUS Disconnect(); NTSTATUS Close(); bool IsConnected();
```
- 取消令牌 `WskCancellationToken{ IsCancellationRequested(ctx), Context }` 贯穿连接/收发，下传到 IRP；超时/取消触发取消式关闭。
- Send/Receive 用**可复用 IRP** + IO rundown 保护；Connect 默认超时 30000ms、Send 30000ms、Receive 用**调用方超时**、Disconnect/Close 用 3000ms。
- **连接终止中途收到的数据仍随 `STATUS_SUCCESS` 返回**（不丢已收字节）。

**WskBuffer**（`net/WskBuffer.h`）— MDL 支撑的池化缓冲：`Allocate`/`EnsureCapacity`/`Prepare`/`SetData`/`CopyTo`/`WskBuf()`。

### 自定义传输（测试 / 扩展）

实现 `ITransport` 即可注入自定义传输；底层 API 与测试钩子（`KhTestSetHttpTransport`）借此做确定性、无真实网络的单元测试（参见 Cookbook 的 mock transport）。
