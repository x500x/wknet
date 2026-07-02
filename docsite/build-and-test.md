# 构建与测试

### 构建库

```powershell
# 构建 KernelHttpLib 全部内核 ABI（x64、ARM64）
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1

# 只构建单个 ABI（脚本会先检查对应 ABI 的 MSVC/WDK 工具链）
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64

# 直接 msbuild（带 restore，构建库 + 示例驱动）
msbuild KernelHttp.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

> 约定：使用 `pwsh`，不要用 `powershell`（两者语法有差异）。Debug/Release 构建均视警告为错误并保持最高警告等级。

### 运行用户态协议测试

完整协议验证基线建议通过 `tools/build-tests.ps1` 逐项构建并运行：

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http_parser_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_frame_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test websocket_client_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_frame_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test hpack_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http2_client_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_crypto_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_handshake_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_record_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_interop_matrix_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test khttp_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test high_level_api_tests -Run
```

如果测试二进制已经构建好，也可以直接运行：

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_interop_matrix_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

### 本地 TLS 互通矩阵

```powershell
# 只使用 127.0.0.1；OpenSSL/BoringSSL 缺失时会明确 SKIP
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64
```

### 测试文件一览

| 测试文件 | 测试内容 |
|---------|---------|
| `http_parser_tests.cpp` | HTTP 解析器 |
| `hpack_tests.cpp` | HTTP/2 HPACK 编解码 |
| `http2_frame_tests.cpp` | HTTP/2 帧处理 |
| `http2_client_tests.cpp` | HTTP/2 客户端 |
| `tls_crypto_tests.cpp` | TLS 密码学向量与 key exchange |
| `tls_handshake_tests.cpp` | TLS ClientHello/握手编解析 |
| `tls_record_tests.cpp` | TLS 记录协议 |
| `tls_interop_matrix_tests.cpp` | TLS 能力/策略/互通矩阵声明 |
| `tests/integration/tls_matrix.ps1` | 本地 OpenSSL/BoringSSL 回环互通矩阵 |
| `websocket_frame_tests.cpp` | WebSocket 帧 |
| `websocket_client_tests.cpp` | WebSocket 客户端 |
| `khttp_tests.cpp` | 高层 API |
| `high_level_api_tests.cpp` | 高层 API 集成 |

> 注意：`tests/integration/https_smoke.ps1` 在某些环境会卡住，运行时建议加 `-SkipDriverBuild`。
> 项目约束：写完代码必须进入 test 与 debug 构建测试，禁止「冒烟测试」式走过场。
