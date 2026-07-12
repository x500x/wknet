# Build & Test

### Build the library

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
msbuild wknet.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

Use `pwsh` (not `powershell`). Debug/Release builds treat warnings as errors at the highest warning level.

### Run user-mode protocol tests

The complete protocol validation baseline builds and runs each test through `tools/build-tests.ps1`:

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

If the binaries are already built, they can also be executed directly from `.\tests\out\bin\`.

### Local TLS interop matrix

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64
```

Uses only 127.0.0.1; SKIPs cleanly when OpenSSL/BoringSSL is missing.

> Do not use `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`; it may hang in this repository's workflow.
