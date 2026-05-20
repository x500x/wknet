# 内核 HTTP/HTTPS 实现设计

**目标：** 从零实现一个 Windows 内核驱动可用的 HTTP/HTTPS 客户端，基于 WSK 完成 TCP 传输，基于内核 CNG/BCrypt 完成 TLS 和证书相关密码学，HTTP 层自行解析和组包。

**架构：** 采用纯内核路径。驱动入口保持 `extern "C"`，内部逻辑按 `KernelHttp::` 这类 namespace 分层：`transport` 负责 WSK，`crypto` 负责 CNG 封装，`tls` 负责握手和 record，`http` 负责请求/响应编解码，`client` 负责对外统一接口。所有会阻塞、会分配较大缓冲、或者需要复杂状态切换的工作统一收敛到 PASSIVE_LEVEL 的工作线程/工作项里，避免在高 IRQL 做复杂处理。

**技术栈：** WDK / KMDF 或 NT 原生驱动模型，WSK，内核 CNG/BCrypt，C++ `/kernel` 子集，HTTP/1.1，TLS 1.2 起步，预留 TLS 1.3 扩展位。

---

## 约束与边界

- 传输层只走 WSK，不走 WinHTTP/WinINet。
- TLS 不依赖现成用户态协议栈，record、握手、密钥派生、加解密流程都自己写。
- 证书校验不依赖用户态链引擎，改为驱动内可控的信任锚或 pinning 方案。
- HTTP 首先支持常见的 `GET`/`POST`、`Content-Length`、`chunked`、`keep-alive`。
- C++ 只做组织和封装，不使用异常、RTTI、标准库重型组件。

## 参考资料

- [Introduction to Winsock Kernel](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-winsock-kernel)
- [Creating Sockets](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/creating-sockets)
- [Sending Data over a Connection-Oriented Socket](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sending-data-over-a-connection-oriented-socket)
- [PFN_WSK_RECEIVE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_receive)
- [CNG Features](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-features)
- [/kernel (Create Kernel-Mode Binary)](https://learn.microsoft.com/en-us/cpp/build/reference/kernel-create-kernel-mode-binary?view=msvc-170)
- [RFC 9112 HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc9112)
- [RFC 9110 HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
- [RFC 8446 TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

---

### Task 1: 项目骨架与编译约束

**Files:**
- Create: `KernelHttp.sln`
- Create: `src/KernelHttp/KernelHttp.vcxproj`
- Create: `src/KernelHttp/KernelHttp.inf`
- Create: `src/KernelHttp/DriverEntry.cpp`
- Create: `src/KernelHttp/KernelHttpConfig.h`

- [ ] **Step 1: 建立驱动项目骨架**

创建最小可编译的内核驱动工程，保留 C ABI 入口，内部预留 C++ namespace 分层。

- [ ] **Step 2: 固化编译约束**

启用 `/kernel`，关闭异常和 RTTI，补齐显式 `new/delete`，保证后续代码不会越过内核边界。

- [ ] **Step 3: 生成最小可加载驱动**

先让驱动能在目标环境加载，不引入网络逻辑。

### Task 2: WSK 传输层

**Files:**
- Create: `src/KernelHttp/net/WskClient.h`
- Create: `src/KernelHttp/net/WskClient.cpp`
- Create: `src/KernelHttp/net/WskSocket.h`
- Create: `src/KernelHttp/net/WskSocket.cpp`
- Create: `src/KernelHttp/net/WskBuffer.h`

- [x] **Step 1: 实现 WSK 注册与 attach**

完成 `WskRegister` / `WskCaptureProviderNPI` / `WskReleaseProviderNPI` / `WskDeregister` 的生命周期管理。

- [x] **Step 2: 实现连接型 socket 封装**

封装 `WskSocketConnect`、`WskSend`、`WskReceive`、关闭和错误传播。

- [x] **Step 3: 约束缓冲区与 IRQL**

把 socket context、MDL、buffer 都限制在 nonpaged 内存里，避免高 IRQL 访问 pageable 数据。

### Task 3: HTTP/1.1 编解码

**Files:**
- Create: `src/KernelHttp/http/HttpRequest.h`
- Create: `src/KernelHttp/http/HttpRequest.cpp`
- Create: `src/KernelHttp/http/HttpResponse.h`
- Create: `src/KernelHttp/http/HttpResponse.cpp`
- Create: `src/KernelHttp/http/HttpParser.h`
- Create: `src/KernelHttp/http/HttpParser.cpp`

- [ ] **Step 1: 写请求构造器**

支持方法、路径、Host、User-Agent、Content-Length、Connection、Content-Type 等常用字段。

- [ ] **Step 2: 写响应解析器**

支持状态行、header、body、`Content-Length`、`chunked`、连接关闭结束等边界。

- [ ] **Step 3: 跑纯解析单测**

把 HTTP 编解码逻辑做成可在宿主机跑的纯 C++ 测试，先把协议细节打稳。

### Task 4: TLS 与内核密码学

**Files:**
- Create: `src/KernelHttp/crypto/CngProvider.h`
- Create: `src/KernelHttp/crypto/CngProvider.cpp`
- Create: `src/KernelHttp/tls/TlsContext.h`
- Create: `src/KernelHttp/tls/TlsContext.cpp`
- Create: `src/KernelHttp/tls/TlsRecord.h`
- Create: `src/KernelHttp/tls/TlsRecord.cpp`
- Create: `src/KernelHttp/tls/TlsHandshake12.h`
- Create: `src/KernelHttp/tls/TlsHandshake12.cpp`

- [ ] **Step 1: 封装 kernel CNG**

封装随机数、哈希、HMAC、ECDH、RSA/ECDSA 验签、AES-GCM 等原语。

- [ ] **Step 2: 实现 TLS 1.2 record 层**

完成 record 编解码、nonce / sequence number、加解密和 alert 处理。

- [ ] **Step 3: 实现 TLS 1.2 handshake**

先落地可工作的 client-side handshake，包含 SNI、证书请求处理、密钥派生和 Finished 校验。

- [ ] **Step 4: 预留 TLS 1.3 扩展位**

把 transcript、key schedule、record 接口设计成可扩展结构，后续再补 TLS 1.3。

### Task 5: 证书校验与 HTTPS 绑定

**Files:**
- Create: `src/KernelHttp/tls/CertificateStore.h`
- Create: `src/KernelHttp/tls/CertificateStore.cpp`
- Create: `src/KernelHttp/tls/CertificateValidator.h`
- Create: `src/KernelHttp/tls/CertificateValidator.cpp`
- Create: `src/KernelHttp/client/HttpsClient.h`
- Create: `src/KernelHttp/client/HttpsClient.cpp`

- [ ] **Step 1: 设计信任锚来源**

采用可控的 root/pin 列表，不依赖用户态系统链引擎。

- [ ] **Step 2: 实现链路与主机名校验**

验证证书链、有效期、Basic Constraints、EKU、SAN/hostname。

- [ ] **Step 3: 把 TLS 和 HTTP 串起来**

完成 `HttpsClient` 的统一请求入口，做到“发请求 -> 握手 -> 发 HTTP -> 读响应”。

### Task 6: 集成测试与回归

**Files:**
- Create: `tests/http_parser_tests.cpp`
- Create: `tests/tls_record_tests.cpp`
- Create: `tests/integration/https_smoke.ps1`
- Create: `tests/testdata/` 下的证书与样例响应

- [ ] **Step 1: 先补解析类单测**

覆盖 HTTP 头解析、chunked 解码、TLS record 编解码等纯逻辑。

- [ ] **Step 2: 再补 VM 集成测试**

在虚拟机或测试机上对接本地 HTTPS 服务，验证握手、证书错误、长连接、异常断开。

- [ ] **Step 3: 固化回归命令**

把编译、加载、请求、卸载流程整理成可重复执行的测试脚本。
