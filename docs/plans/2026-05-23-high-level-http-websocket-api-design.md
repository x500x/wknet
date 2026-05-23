# 高层 HTTP(S) 与 WebSocket API 设计

**目标：** 在现有 Windows 内核 HTTP/HTTPS/WebSocket 能力之上提供一层更好用的 API：HTTP(S) 使用方式接近 Python `requests`，WebSocket 使用方式接近 Python `websockets`，同时保留内核项目需要的显式内存、IRQL、TLS、连接池和回调控制。

**架构：** 对外保持普通函数、简单结构体和 opaque handle，不暴露复杂 C++ 类层次。内部仍可使用现有 `KernelHttp::` 命名空间组织代码，但上层 API 只使用清晰的 handle、options、result、callback 和 worker 状态机。

**技术栈：** Windows kernel driver，WSK，内核 CNG/BCrypt，现有 HTTP/1.1、HTTP/2、TLS 1.2/1.3、WebSocket 编解码模块，`pwsh` 回归脚本。

---

## 设计决策

- 高层 HTTP(S)/WebSocket API 只支持 `PASSIVE_LEVEL`。
- 任意公开入口第一步检查 `KeGetCurrentIrql()`；不是 `PASSIVE_LEVEL` 时直接返回 `STATUS_INVALID_DEVICE_REQUEST`。
- 同步 API 在当前 PASSIVE 线程执行；异步 API 只负责提交任务，真实网络、TLS、CNG、证书校验和回调都在 PASSIVE worker 中运行。
- 回调只在 PASSIVE worker 调用，且不在持有连接池锁、session 锁或 request 锁时调用。
- 主驱动示例保留，但必须通过新的上层 API 跑，不再直接调用旧的 `HttpsClient`、`TlsConnection`、`WebSocketClient` 底层接口。
- 现有低层样例矩阵迁移成测试驱动/回归用例；测试用例也必须覆盖新上层 API。
- 不把 TLS 版本回退、证书 no-verify、连接重建当成兜底架构。它们必须是调用方显式配置或协议协商结果。

## 非目标

- 不引入 WinHTTP、WinINet、SChannel。
- 不引入异常、RTTI、标准库容器、复杂模板或继承式 public API。
- 不支持在 `DISPATCH_LEVEL` 或更高 IRQL 执行高层 HTTP/WebSocket 请求。
- 不提供无限制自动分配；自动容纳响应必须受调用方或 session 的最大字节数限制。

## IRQL 策略

高层 API 的统一入口策略：

```cpp
if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
    return STATUS_INVALID_DEVICE_REQUEST;
}
```

原因：

- CNG provider 打开、证书校验、WSK 同步等待、paged 响应内存和调用方回调都需要 PASSIVE 语义。
- 当前蓝屏栈显示 TLS 1.3 证书链验证深处调用 `BCryptOpenAlgorithmProvider` 后进入 CNG provider 解析，最终 double fault。新设计会把这类 CNG provider 初始化前移到 session/crypto context 初始化阶段，并强制 PASSIVE。
- 如果调用方需要从高 IRQL 触发请求，应自行把工作排到 PASSIVE worker 后再调用高层 API。

## 公开 API 形态

公开头文件建议放在 `src/KernelHttp/api/KernelHttpApi.h`。类型保持简单：

```cpp
namespace KernelHttp
{
namespace api
{
    struct KhSession;
    struct KhRequest;
    struct KhResponse;
    struct KhWebSocket;
    struct KhAsyncOperation;

    typedef KhSession* KH_SESSION;
    typedef KhRequest* KH_REQUEST;
    typedef KhResponse* KH_RESPONSE;
    typedef KhWebSocket* KH_WEBSOCKET;
    typedef KhAsyncOperation* KH_ASYNC_OPERATION;
}
}
```

句柄由 API 创建和释放。调用方不直接分配内部对象，不需要知道 TLS、HTTP/2、WebSocket 或连接池内部布局。

## Session

`KH_SESSION` 对应 `requests.Session` 的概念：

- 持有 `net::WskClient` 引用。
- 持有连接池、TLS 默认选项、证书 store、session ticket cache。
- 持有 CNG provider cache，避免在深层证书验证或 record 加解密路径反复打开 provider。
- 持有可复用 workspace，用于 TLS 握手、HTTP 解析、证书解析、HTTP/2 header、WebSocket frame 等高频临时区。

建议接口：

```cpp
NTSTATUS KhSessionCreate(
    net::WskClient* wskClient,
    const KhSessionOptions* options,
    KH_SESSION* session) noexcept;

void KhSessionClose(KH_SESSION session) noexcept;
```

`KhSessionOptions` 包含：

- 默认 pool 类型：paged / nonpaged。
- 默认自动响应上限。
- 连接池容量、每主机连接数、空闲超时。
- TLS 最小/最大版本、ALPN、证书校验开关、证书 store。
- worker 配置。

## HTTP(S) Request

`KH_REQUEST` 对应一次请求。它可以从 session 创建，也可以用一次性 helper 创建后立即发送。

核心能力：

- `KhHttpRequestCreate(session, &request)`
- `KhHttpRequestSetUrl(request, "https://example.com/path")`
- `KhHttpRequestSetMethod(request, KhHttpMethodGet)`
- `KhHttpRequestSetHeader(request, "Accept", "*/*")`
- `KhHttpRequestSetBody(request, body, bodyLength)`
- `KhHttpRequestSetTlsOptions(request, &tlsOptions)`
- `KhHttpRequestSetConnectionPolicy(request, KhConnectionReuseOrCreate / KhConnectionForceNew / KhConnectionNoPool)`

发送 API：

```cpp
NTSTATUS KhHttpSendSync(
    KH_SESSION session,
    KH_REQUEST request,
    const KhHttpSendOptions* options,
    KH_RESPONSE* response) noexcept;

NTSTATUS KhHttpSendAsync(
    KH_SESSION session,
    KH_REQUEST request,
    const KhHttpSendOptions* options,
    KH_ASYNC_OPERATION* operation) noexcept;
```

## Response 管理

默认模式下，API 自动分配足够容纳完整响应的 buffer：

- header 元数据由 response 持有。
- body 自动增长，直到完整响应结束或达到 `MaxResponseBytes`。
- pool 可选 paged/nonpaged；由于高层 API 只在 PASSIVE 执行，paged 响应允许用于低频大响应。
- 调用方通过 `KhResponseRelease(response)` 释放。

回调模式下，调用方可以像 libcurl 一样自主管理：

```cpp
typedef NTSTATUS (*KhHeaderCallback)(
    void* context,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength);

typedef NTSTATUS (*KhBodyCallback)(
    void* context,
    const UCHAR* data,
    SIZE_T dataLength,
    bool finalChunk);
```

如果设置 body callback，默认不再聚合完整 body；调用方可通过显式 flag 同时启用聚合和回调。回调返回失败时请求立即中止并返回该状态。

## TLS 选项

TLS 配置分 session 默认值和 request 覆盖值：

- 最小/最大 TLS 版本。
- 是否启用证书校验。
- 证书 store / pin。
- ALPN 偏好。
- session resumption。
- early data。

不支持的组合返回 `STATUS_NOT_SUPPORTED`。证书错误返回明确的 trust/signature/network 状态，不降级成 no-verify。

## WebSocket

`KH_WEBSOCKET` 对应 `websockets.connect()` 返回的连接对象。

建议接口：

```cpp
NTSTATUS KhWebSocketConnectSync(
    KH_SESSION session,
    const KhWebSocketConnectOptions* options,
    KH_WEBSOCKET* websocket) noexcept;

NTSTATUS KhWebSocketConnectAsync(
    KH_SESSION session,
    const KhWebSocketConnectOptions* options,
    KH_ASYNC_OPERATION* operation) noexcept;

NTSTATUS KhWebSocketSendTextSync(
    KH_WEBSOCKET websocket,
    const char* text,
    SIZE_T textLength) noexcept;

NTSTATUS KhWebSocketReceiveSync(
    KH_WEBSOCKET websocket,
    const KhWebSocketReceiveOptions* options,
    KhWebSocketMessage* message) noexcept;

NTSTATUS KhWebSocketCloseSync(KH_WEBSOCKET websocket) noexcept;
```

WebSocket receive 默认自动聚合完整消息，也支持 fragment/message callback。ping/pong 由内部处理，但必须可通过选项控制是否自动回复、超时和最大消息大小。

## 异步模型

异步 API 使用同一套协议实现，不复制状态机：

- `KhHttpSendAsync` 和 `KhWebSocketConnectAsync` 创建 `KH_ASYNC_OPERATION`。
- operation 进入 session worker 队列。
- worker 在 PASSIVE 执行同步内核逻辑。
- 完成后调用 completion callback。
- `KhAsyncCancel` 只做可取消点标记：DNS/连接/TLS/读写循环检查 cancellation 状态。
- `KhAsyncWait` 只允许 PASSIVE 调用。

## 连接池

连接池属于 session：

- key 包含 scheme、host、port、TLS 版本范围、ALPN、证书策略。
- request 可选择复用、强制新建、或禁用连接池。
- HTTP/1.1 只在 keep-alive 且响应完整消费后回池。
- HTTP/2 连接按 stream 能力复用。
- WebSocket 升级后的连接不回普通 HTTP 池。
- TLS session ticket cache 随 session 保存。

连接池不做隐式协议降级。池中连接不满足 request 的 TLS/ALPN/证书策略时直接新建或返回明确错误，取决于 request connection policy。

## 栈空间治理

新增 workspace 约束：

- 高层 session/request 持有 `KhWorkspace`。
- TLS ClientHello、HRR、transcript 临时 hash、证书链解析数组、authority bundle scratch、HTTP/2 header lower-case buffer、WebSocket frame buffer 都从 workspace 获取。
- 新代码禁止新增 KB 级局部数组。
- 旧代码逐步迁移：`TlsConnection.cpp` 中多个 2048 字节局部数组、`CertificateValidator.cpp` 中证书链数组、`HttpsClient.cpp` 中 HTTP/2 header scratch 都要移到 workspace。
- 高频小对象可以保留很小的局部变量；原则上单函数局部数组不超过 128 字节，超过时必须说明原因或放入 workspace。

## 蓝屏修复设计

当前蓝屏根因和新 API 同步处理：

- 在 session 初始化阶段打开并缓存常用 CNG provider：AES、SHA1、SHA256、SHA384、RSA、ECDSA P-256/P-384/P-521、ECDH P-256/P-384/P-521。
- `CngProvider` 增加使用 provider cache 的路径。
- `CertificateValidator` 和 `TlsConnection` 通过 workspace 与 provider cache 工作。
- 证书验证深层不再临时 `BCryptOpenAlgorithmProvider`。
- 主驱动通过新 API 跑示例，示例请求天然复用 session workspace 和 provider cache。

## 主驱动与测试驱动

主驱动：

- `DriverEntry` 初始化 WSK。
- 创建 `KH_SESSION`。
- 调用新的高层 sample runner。
- sample runner 只调用 `KhHttpSendSync`、`KhHttpSendAsync`、`KhWebSocketConnectSync/Async` 等上层 API。

测试驱动：

- 现有示例矩阵迁移成高层 API 回归用例。
- 测试驱动覆盖 GET/POST/PUT/PATCH/DELETE、HTTPS、HTTP/2、no-verify 显式配置、WebSocket echo、连接池复用、强制新连接、同步和异步。
- 回归用例禁止直接调用底层 `HttpsClient` 或 `TlsConnection`，除非是底层模块单元测试。

## 错误处理

- IRQL 不支持：`STATUS_INVALID_DEVICE_REQUEST`。
- 参数错误：`STATUS_INVALID_PARAMETER`。
- 内存不足：`STATUS_INSUFFICIENT_RESOURCES`。
- 超过自动响应上限：`STATUS_BUFFER_TOO_SMALL`。
- 协议错误：`STATUS_INVALID_NETWORK_RESPONSE`。
- TLS/算法/扩展不支持：`STATUS_NOT_SUPPORTED`。
- 证书信任失败：`STATUS_TRUST_FAILURE`。
- 回调失败：返回回调的原始失败状态。

## 测试要求

- host 单元测试覆盖 URL/request/options/response 管理、callback 中止、连接池 key、WebSocket frame/message 逻辑。
- 内核测试驱动覆盖 PASSIVE 成功路径和 raised IRQL 失败路径。
- 回归必须包含同步和异步 HTTP(S)、WebSocket、连接复用和强制新连接。
- 完成代码后运行完整 test 回归和 Debug 构建；不能只做烟测。
