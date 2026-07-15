# Build & test

How contributors build the library and run user-mode protocol tests. Product integrators only need [Build](build.md).

## Build the library

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
msbuild wknet.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

Use `pwsh`. Debug/Release treat warnings as errors.

Output: `src/wknetlib/<Platform>/<Configuration>/wknetlib.lib`.

## User-mode protocol tests

Build and run each suite through `tools/build-tests.ps1`:

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

Built binaries also run from `.\tests\out\bin\<name>.exe`.

## Local TLS interop

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64
```

Uses only `127.0.0.1`; SKIPs cleanly when OpenSSL/BoringSSL is missing.

> Do not use `tests/integration/https_smoke.ps1` as a regular path (it may hang in some environments).

## Samples and API regression

| Path | Purpose |
|------|---------|
| `src/wknettest/samples/HighLevelApiSamples.cpp` | Product API scenarios |
| `src/wknettest/samples/AdvancedScenarioSamples.cpp` | Edge and error paths |
| `tests/high_level_api_tests.cpp` | User-mode API regression |

Test hooks: [Internals](internals.md). Trace check:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\check-trace-events.ps1
```
