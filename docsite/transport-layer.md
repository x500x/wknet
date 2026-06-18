# 传输层 / Transport Layer

`KernelHttp::core`（抽象与适配器）与 `KernelHttp::net`（WSK）。

[English](#english) | 简体中文

---

## 简体中文

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

**WskSocket**（`net/WskSocket.h`）— 连接 socket：
```cpp
NTSTATUS Connect(WskClient&, const SOCKADDR* remote, const SOCKADDR* local = nullptr, const WskCancellationToken* = nullptr);
NTSTATUS Send(...); NTSTATUS Receive(... ULONG timeoutMs = 30000 ...);
NTSTATUS Disconnect(); NTSTATUS Close(); bool IsConnected();
```
取消令牌 `WskCancellationToken{ IsCancellationRequested(ctx), Context }` 贯穿连接/收发，使异步取消能下传到 IRP。

**WskBuffer**（`net/WskBuffer.h`）— MDL 支撑的池化缓冲：`Allocate`/`EnsureCapacity`/`Prepare`/`SetData`/`CopyTo`/`WskBuf()`。

### 自定义传输（测试 / 扩展）

实现 `ITransport` 即可注入自定义传输；底层 API 与测试钩子（`KhTestSetHttpTransport`）借此做确定性、无真实网络的单元测试（参见 Cookbook 的 mock transport）。

---

## English

`core::ITransport` is the byte-stream abstraction (`Send`/`Receive`/`ReceiveWithTimeout`) unifying plaintext and TLS. Adapters: `WskTransport` (over `net::WskSocket`, `WSK_FLAG_NODELAY`, cancellation token) for plaintext, `TlsTransport` (wraps an inner `ITransport` + `tls::TlsConnection`) for auto encrypt/decrypt. Stack: WskSocket → WskTransport → (TlsTransport for HTTPS) → protocol layer. `IScratchAllocator` (`Acquire`/`Release`/`EnsureBuffer`) is implemented by `WorkspaceScratchAllocator`.

WSK layer: `WskClient` (register + `Resolve`/`ResolveAll` up to 8 addresses, `WskAddressFamily` Any/Ipv4/Ipv6), `WskSocket` (`Connect`/`Send`/`Receive` with 30 s default timeout/`Disconnect`/`Close`, cancellation token forwarded to IRPs), `WskBuffer` (MDL-backed pooled buffer). Implement `ITransport` to inject a custom/mock transport — used by the low-level API and test hooks (`KhTestSetHttpTransport`) for deterministic, network-free unit tests.
