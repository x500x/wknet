# 构建与测试

贡献者如何编库、跑用户态协议测试。调用方只需 [构建](build.md)。

## 编库

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
msbuild wknet.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

使用 `pwsh`。Debug/Release 均视警告为错误。

产物：`src/wknetlib/<Platform>/<Configuration>/wknetlib.lib`。

## 用户态协议测试

通过 `tools/build-tests.ps1` 逐项构建并运行：

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
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test http_api_tests -Run
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test high_level_api_tests -Run
```

已构建二进制可直接运行：`.\tests\out\bin\<name>.exe`。

## 本地 TLS 互通

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64
```

仅使用 `127.0.0.1`；缺少 OpenSSL/BoringSSL 时明确 SKIP。

> 不要用 `tests/integration/https_smoke.ps1` 作为常规路径（部分环境会卡住）。

## 样例与 API 回归

| 路径 | 用途 |
|------|------|
| `src/wknettest/samples/HighLevelApiSamples.cpp` | 产品 API 场景 |
| `src/wknettest/samples/AdvancedScenarioSamples.cpp` | 边界与错误路径 |
| `tests/high_level_api_tests.cpp` | 用户态 API 回归 |

测试钩子见 [内部边界](internals.md)。Trace 检查：

```powershell
pwsh -NoLogo -NoProfile -File .\tools\check-trace-events.ps1
```
