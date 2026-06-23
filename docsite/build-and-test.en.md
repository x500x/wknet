# Build & Test

### Build the library

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
msbuild KernelHttp.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

Use `pwsh` (not `powershell`). Debug/Release builds treat warnings as errors at the highest warning level.

### Run user-mode protocol tests

Execute the prebuilt test binaries under `.\tests\out\bin\` (see the Chinese section for the full list): HTTP parser, HPACK, HTTP/2 frame/client, TLS crypto/handshake/record/interop matrix, WebSocket frame/client, and high-level API tests.

### Local TLS interop matrix

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64
```

Uses only 127.0.0.1; SKIPs cleanly when OpenSSL/BoringSSL is missing.

> `tests/integration/https_smoke.ps1` may hang in some environments — add `-SkipDriverBuild` when running it.
