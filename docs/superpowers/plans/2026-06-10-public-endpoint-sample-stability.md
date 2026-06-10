# Public Endpoint Sample Stability Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `KernelHttpTest` load-time public-network samples distinguish real protocol regressions from public endpoint instability, and move unstable generic httpbin-style traffic away from `nghttp2.org`.

**Architecture:** Keep the kernel HTTP/TLS/HTTP2 implementation unchanged unless focused tests expose a real protocol defect. Introduce one shared sample-status classification helper, use it consistently across high-level, low-level verb, HTTP/2, and advanced public sample matrices, and replace only the endpoint categories whose current host is empirically unstable. Keep `nghttp2.org` only where its protocol capability is still needed, especially h2c upgrade.

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, custom TLS 1.2/1.3, custom X.509 validator, custom HTTP/2 and HPACK, `KernelHttpTest` sample driver, user-mode protocol tests, MSBuild via `pwsh`.

---

## Context

The pasted live kernel log ended with `KernelHttpTest 全量示例完成，但存在失败项: 0xC00000B5`. The decisive failures were the low-level `HTTPS PUT` and `HTTPS PATCH` samples in `src/KernelHttpTest/samples/HttpVerbSamples.cpp`, not the high-level forced IPv6 diagnostic sample.

Evidence gathered on 2026-06-10:

- `HTTP GET IPv6 地址族` returned `STATUS_IO_TIMEOUT`, but `HighLevelApiSamples` already records public IPv4/IPv6 environment failures without failing the aggregate.
- `HTTPS PUT` and `HTTPS PATCH` verified certificate successfully, negotiated HTTP/2, received peer SETTINGS ACK, then timed out waiting for response frames.
- `http2_client_tests.exe`, `high_level_api_tests.exe`, and `khttp_tests.exe` passed locally.
- Repeating standard .NET HTTP/2 exact requests against `https://nghttp2.org/httpbin/put` produced 5 failures in 10 attempts with a 20 second timeout.
- Repeating the same `PUT` and `PATCH` tests against `https://httpbin.dev` produced 20 successes in 20 attempts.
- `httpbin.dev` supports HTTPS HTTP/2 for GET/POST/PUT/PATCH/DELETE and returns correct `Content-Encoding` for `/gzip`, `/deflate`, and `/brotli`.
- `httpbin.dev` plain HTTP redirects to HTTPS, so it is not a drop-in replacement for plain HTTP/1.1 samples.
- `httpbun.com` and `postman-echo.com` return 200 for plain HTTP GET/POST/PUT/PATCH/DELETE.
- For h2c upgrade, `nghttp2.org` returned `HTTP/1.1 101 Switching Protocols`; `httpbin.dev`, `httpbun.com`, `postman-echo.com`, and `pie.dev` did not.

Do not run the prohibited command:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild
```

Do not git commit unless the user explicitly asks. This plan contains commit checkpoints only as optional human-approved actions.

## Endpoint Decisions

Use endpoints by capability, not by convenience:

| Scenario | Endpoint | Reason |
| --- | --- | --- |
| HTTPS HTTP/2 generic verb samples | `https://httpbin.dev/{get,post,put,patch,delete}` | Verified stable in repeated HTTP/2 exact requests. |
| HTTPS content encoding samples | `https://httpbin.dev/{gzip,deflate,brotli}` | Returns correct `Content-Encoding` for all three. |
| HTTPS advanced httpbin paths | `https://httpbin.dev/{status,redirect,anything,encoding,delay}` | Supports the needed httpbin-style paths over HTTPS HTTP/2. |
| Plain HTTP/1.1 generic verb samples | `http://httpbun.com/{get,post,put,patch,delete}` or `http://postman-echo.com/{get,post,put,patch,delete}` | Both returned 200 for plain HTTP verbs; prefer one and document it. |
| h2c prior knowledge | Prefer `http://httpbin.dev/get` if live validation remains green; otherwise keep `nghttp2.org` as a protocol diagnostic sample. | .NET h2c exact mode returned 200 for `httpbin.dev`. |
| h2c upgrade | Keep `http://nghttp2.org/httpbin/get` | It is the only tested public host that returned `101 Switching Protocols`. |
| WebSocket echo | Keep existing WebSocket hosts unless a separate WebSocket replacement task is opened. | Current log shows WebSocket samples passed or are already diagnostic on public connect failures. |

## Files

- Create: `include/KernelHttpTest/SampleStatus.h`
  - Shared user-mode/kernel-safe status classification helpers for sample aggregation.
- Modify: `src/KernelHttpTest/KernelHttpTest.vcxproj`
  - Include the new header if project filters require it.
- Modify: `src/KernelHttpTest/KernelHttpTest.vcxproj.filters`
  - Add the new header to the sample filter.
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp`
  - Replace local public-network classification with the shared helper.
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
  - Replace unstable `nghttp2.org` URLs where appropriate.
  - Use shared public-sample aggregation for public endpoint network failures.
  - Keep protocol errors fatal.
- Modify: `src/KernelHttpTest/samples/Http2VerbSamples.cpp`
  - Keep h2c upgrade on `nghttp2.org`.
  - Move h2c prior knowledge only if `httpbin.dev` is validated in live kernel.
  - Use shared public-sample aggregation for connect/timeout statuses.
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
  - Replace generic httpbin paths with stable selected endpoints.
  - Keep negative TLS/protocol samples deterministic.
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.h`
  - Add result fields only if endpoint category reporting needs to become explicit.
- Modify: `src/KernelHttpTest/samples/Http2VerbSamples.h`
  - Add result fields only if h2c diagnostic status needs to be reported separately.
- Modify: `tests/high_level_api_tests.cpp`
  - Add tests for shared status classification and low-level/public aggregation behavior.
  - Extend endpoint expectation tests for selected hosts.
- Modify if needed: `docs/high-level-api.md`, `docs/api-overview.md`, `docs/ntstatus-codes.md`
  - Document endpoint categories and diagnostic public-network statuses.

---

## Chunk 1: Shared Public Sample Status Classification

### Task 1: Add a shared classification header

**Files:**
- Create: `include/KernelHttpTest/SampleStatus.h`
- Modify: `src/KernelHttpTest/KernelHttpTest.vcxproj`
- Modify: `src/KernelHttpTest/KernelHttpTest.vcxproj.filters`

- [ ] **Step 1: Create the header with pure helpers**

Create `include/KernelHttpTest/SampleStatus.h`:

```cpp
#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace samples
{
    inline bool IsPublicNetworkEnvironmentStatus(NTSTATUS status) noexcept
    {
        return status == STATUS_CONNECTION_REFUSED ||
            status == STATUS_NETWORK_UNREACHABLE ||
            status == STATUS_HOST_UNREACHABLE ||
            status == STATUS_PROTOCOL_UNREACHABLE ||
            status == STATUS_NO_MATCH ||
            status == STATUS_IO_TIMEOUT ||
            status == STATUS_CONNECTION_DISCONNECTED ||
            status == STATUS_CONNECTION_RESET ||
            status == STATUS_CONNECTION_ABORTED ||
            status == STATUS_DEVICE_NOT_CONNECTED;
    }

    inline bool IsPublicEndpointDiagnosticStatus(NTSTATUS status) noexcept
    {
        return IsPublicNetworkEnvironmentStatus(status);
    }

    inline void MergeFatalSampleStatus(NTSTATUS& aggregate, NTSTATUS status) noexcept
    {
        if (NT_SUCCESS(aggregate) && !NT_SUCCESS(status)) {
            aggregate = status;
        }
    }

    inline void MergePublicDiagnosticSampleStatus(NTSTATUS& aggregate, NTSTATUS status) noexcept
    {
        if (NT_SUCCESS(status) || IsPublicEndpointDiagnosticStatus(status)) {
            return;
        }
        MergeFatalSampleStatus(aggregate, status);
    }
}
}
```

- [ ] **Step 2: Add project entries**

Add `include\KernelHttpTest\SampleStatus.h` to the test driver project if the project requires explicit header entries.

- [ ] **Step 3: Do not add runtime behavior yet**

At this step only the helper exists. No sample aggregation code should change yet.

### Task 2: Add user-mode tests for classification

**Files:**
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Include the helper**

Add:

```cpp
#include <KernelHttpTest/SampleStatus.h>
```

- [ ] **Step 2: Add status classification tests**

Add a test near the other load-time aggregation tests:

```cpp
void TestPublicEndpointStatusClassification() noexcept
{
    using KernelHttp::samples::IsPublicEndpointDiagnosticStatus;

    Expect(IsPublicEndpointDiagnosticStatus(STATUS_IO_TIMEOUT), "timeout is a public endpoint diagnostic status");
    Expect(IsPublicEndpointDiagnosticStatus(STATUS_NO_MATCH), "DNS no-match is a public endpoint diagnostic status");
    Expect(IsPublicEndpointDiagnosticStatus(STATUS_CONNECTION_RESET), "connection reset is a public endpoint diagnostic status");
    Expect(!IsPublicEndpointDiagnosticStatus(STATUS_INVALID_NETWORK_RESPONSE), "protocol errors remain fatal");
    Expect(!IsPublicEndpointDiagnosticStatus(STATUS_INVALID_PARAMETER), "API misuse remains fatal");
    Expect(!IsPublicEndpointDiagnosticStatus(STATUS_TRUST_FAILURE), "certificate trust failures remain fatal");
}
```

- [ ] **Step 3: Register the test**

Call `TestPublicEndpointStatusClassification()` from `main()`.

- [ ] **Step 4: Run the test**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: PASS.

### Task 3: Refactor high-level samples to use the shared helper

**Files:**
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp`

- [ ] **Step 1: Include the shared header**

Add:

```cpp
#include <KernelHttpTest/SampleStatus.h>
```

- [ ] **Step 2: Remove duplicate local classification**

Delete the local `IsPublicNetworkEnvironmentStatus` and `IsPublicWebSocketConnectEnvironmentStatus` bodies, or replace their call sites directly with `samples::IsPublicEndpointDiagnosticStatus`.

- [ ] **Step 3: Keep existing logging text**

Do not change the log strings for high-level public IPv4/IPv6 and WebSocket diagnostics unless needed by tests.

- [ ] **Step 4: Run high-level tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: PASS.

---

## Chunk 2: Low-Level HTTP Verb Sample Aggregation

### Task 4: Add low-level aggregation coverage

**Files:**
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Add a pure merge helper test**

If `MergePublicDiagnosticSampleStatus` is available through `SampleStatus.h`, add:

```cpp
void TestPublicDiagnosticMergeKeepsAggregateSuccessForEnvironmentFailures() noexcept
{
    NTSTATUS aggregate = STATUS_SUCCESS;
    KernelHttp::samples::MergePublicDiagnosticSampleStatus(aggregate, STATUS_IO_TIMEOUT);
    Expect(aggregate == STATUS_SUCCESS, "public timeout does not poison aggregate");

    KernelHttp::samples::MergePublicDiagnosticSampleStatus(aggregate, STATUS_INVALID_NETWORK_RESPONSE);
    Expect(aggregate == STATUS_INVALID_NETWORK_RESPONSE, "protocol error poisons aggregate");
}
```

- [ ] **Step 2: Register the test**

Call it from `main()`.

- [ ] **Step 3: Run the test**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: PASS.

### Task 5: Apply diagnostic aggregation to public low-level samples

**Files:**
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`

- [ ] **Step 1: Include the shared helper**

Add:

```cpp
#include <KernelHttpTest/SampleStatus.h>
```

- [ ] **Step 2: Split fatal and public diagnostic merge calls**

Use `MergeFatalSampleStatus` for deterministic local protocol demonstrations and API misuse checks.

Use `MergePublicDiagnosticSampleStatus` for public endpoint calls that can fail from DNS/connect/timeout after the request has been issued:

- HTTP/HTTPS public verb samples.
- Content-encoding public samples.
- WebSocket public echo samples only for connection-level statuses.
- Remote address-family public samples.

- [ ] **Step 3: Preserve protocol-error fatality**

Do not hide these statuses:

- `STATUS_INVALID_NETWORK_RESPONSE`
- `STATUS_INVALID_PARAMETER`
- `STATUS_NOT_SUPPORTED`
- `STATUS_TRUST_FAILURE`
- `STATUS_INVALID_SIGNATURE`
- Any certificate validation error from a verified sample.

- [ ] **Step 4: Add diagnostic logging for ignored low-level public failures**

When a low-level public sample fails with `IsPublicEndpointDiagnosticStatus(status)`, log a line like:

```cpp
kprintf("[%s] 公网端点环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
    sampleName,
    static_cast<ULONG>(status));
```

- [ ] **Step 5: Run existing local tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
```

Expected: both PASS.

---

## Chunk 3: Endpoint Replacement by Capability

### Task 6: Replace unstable HTTPS HTTP/2 verb and encoding endpoints

**Files:**
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
- Modify if needed: `src/KernelHttpTest/samples/HttpVerbSamples.h`

- [ ] **Step 1: Add endpoint constants**

Add constants near the existing `NgHttp2` constants:

```cpp
constexpr const wchar_t* HttpBinDevServerName = L"httpbin.dev";
constexpr const wchar_t* HttpBinDevHttpsServiceName = L"443";
constexpr const char* HttpBinDevTlsServerName = "httpbin.dev";
constexpr SIZE_T HttpBinDevTlsServerNameLength = sizeof("httpbin.dev") - 1;
constexpr const char* HttpBinDevHostName = "httpbin.dev";
constexpr SIZE_T HttpBinDevHostNameLength = sizeof("httpbin.dev") - 1;
```

- [ ] **Step 2: Replace HTTPS generic verb samples**

Change verified and no-verify HTTPS GET/POST/PUT/PATCH/DELETE low-level samples from:

```text
https://nghttp2.org/httpbin/...
```

to:

```text
https://httpbin.dev/...
```

For request path fields, remove the `/httpbin` prefix:

- `/get`
- `/post`
- `/put`
- `/patch`
- `/delete`

- [ ] **Step 3: Replace encoding samples**

Move content encoding samples to:

- `https://httpbin.dev/get` for identity.
- `https://httpbin.dev/gzip` for gzip.
- `https://httpbin.dev/deflate` for deflate.
- `https://httpbin.dev/brotli` for br.

Keep the existing content-decoding assertions/logging.

- [ ] **Step 4: Do not hard-code new public SPKI pins**

Do not add a new pinned leaf/intermediate for `httpbin.dev` as the formal architecture. For verified public HTTPS, prefer using the existing external CA bundle path that `RunKernelHttpTestSamples` already receives. If low-level samples cannot currently receive that bundle, add a task in Chunk 4 before enabling verified `httpbin.dev` samples.

- [ ] **Step 5: Run focused tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: both PASS.

### Task 7: Choose a plain HTTP endpoint for HTTP/1.1 samples

**Files:**
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
- Modify if needed: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`

- [ ] **Step 1: Pick one plain HTTP host**

Recommended: `httpbun.com`, because it returned 200 for plain HTTP GET/POST/PUT/PATCH/DELETE and also supports HTTPS HTTP/2 for the same verbs. `postman-echo.com` is acceptable for plain verb echo but lacks some httpbin-style paths.

- [ ] **Step 2: Add constants**

```cpp
constexpr const wchar_t* HttpBunServerName = L"httpbun.com";
constexpr const wchar_t* HttpBunServiceName = L"80";
constexpr const char* HttpBunHostName = "httpbun.com";
constexpr SIZE_T HttpBunHostNameLength = sizeof("httpbun.com") - 1;
```

- [ ] **Step 3: Replace plain HTTP low-level verb samples**

For HTTP GET/POST/PUT/PATCH/DELETE samples that currently use `http://nghttp2.org/httpbin/...`, use:

- `http://httpbun.com/get`
- `http://httpbun.com/post`
- `http://httpbun.com/put`
- `http://httpbun.com/patch`
- `http://httpbun.com/delete`

- [ ] **Step 4: Keep HEAD/OPTIONS explicit**

Before replacing HEAD/OPTIONS, verify the chosen host returns the expected status and headers. If it does not, keep HEAD/OPTIONS on a host that supports them and mark them as public diagnostic samples.

- [ ] **Step 5: Run focused tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: PASS.

### Task 8: Keep h2c upgrade on nghttp2 and document why

**Files:**
- Modify: `src/KernelHttpTest/samples/Http2VerbSamples.cpp`
- Modify if needed: `docs/api-overview.md`

- [ ] **Step 1: Leave h2c upgrade target unchanged**

Keep the h2c upgrade sample on:

```text
http://nghttp2.org/httpbin/get
```

Reason: live probing showed `nghttp2.org` returns `HTTP/1.1 101 Switching Protocols`; tested replacement hosts did not.

- [ ] **Step 2: Treat h2c upgrade public timeouts as diagnostic**

Use `MergePublicDiagnosticSampleStatus` for connect/timeout/no-match statuses.

- [ ] **Step 3: Keep protocol errors fatal**

If the server responds but the h2c upgrade response is malformed, keep `STATUS_INVALID_NETWORK_RESPONSE` fatal.

- [ ] **Step 4: Run HTTP/2 client tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'
```

Expected: PASS.

---

## Chunk 4: Verified HTTPS Store Contract for Low-Level Samples

### Task 9: Route low-level verified HTTPS through the CA bundle contract

**Files:**
- Modify: `src/KernelHttpTest/samples/KhttpSamples.cpp`
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.h`
- Modify: `src/KernelHttpTest/samples/HttpVerbSamples.cpp`
- Modify: `src/KernelHttpTest/samples/ExternalTrustStore.h`
- Modify if needed: `src/KernelHttpTest/samples/ExternalTrustStore.cpp`

- [ ] **Step 1: Extend `RunHttpVerbSamples` signature**

Change:

```cpp
NTSTATUS RunHttpVerbSamples(net::WskClient& wskClient, HttpVerbSampleResults* results) noexcept;
```

to:

```cpp
NTSTATUS RunHttpVerbSamples(
    net::WskClient& wskClient,
    const char* certificateBundlePath,
    HttpVerbSampleResults* results) noexcept;
```

- [ ] **Step 2: Pass the bundle path from `RunKernelHttpTestSamples`**

In `KhttpSamples.cpp`, pass the existing `certificateBundlePath` into `RunHttpVerbSamples`.

- [ ] **Step 3: Initialize an external trust store once per low-level matrix**

At the start of `RunHttpVerbSamples`, initialize `ExternalTrustStore` from the provided path. Use the same behavior as `RunHighLevelApiSamples`: if the path is null, use `ExternalTrustStoreDefaultBundlePath`.

- [ ] **Step 4: Use the external store for verified HTTPS public samples**

Replace `InitializeNgHttp2CertificateStore` usage in verified public HTTPS samples with the external `trustStore.Store`.

- [ ] **Step 5: Keep certificate negative samples deterministic**

Do not convert trust-failure negative samples to no-verify. If a negative sample needs a fixed failure, use a deterministic trust store mismatch rather than a public endpoint certificate pin that changes over time.

- [ ] **Step 6: Run certificate and high-level tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: both PASS.

---

## Chunk 5: Advanced Samples Endpoint Review

### Task 10: Move generic advanced httpbin paths to stable endpoints

**Files:**
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Replace generic HTTP paths only where semantics match**

Candidates:

- `RedirectUrl`: use `https://httpbin.dev/redirect/1` if redirect handling supports HTTPS in the sample path.
- `NotFoundUrl`: use `https://httpbin.dev/status/404`.
- `ServerErrorUrl`: use `https://httpbin.dev/status/500`.
- `LargeResponseUrl`: use `https://httpbin.dev/encoding/utf8`.
- `LargePostUrl`: use `https://httpbin.dev/post`.
- `DelayUrl`: use `https://httpbin.dev/delay/5`.

- [ ] **Step 2: Preserve current sample intent**

If a sample is specifically validating plain HTTP behavior, do not silently switch it to HTTPS. In that case, use the selected plain HTTP endpoint from Chunk 3 or keep the sample public-diagnostic.

- [ ] **Step 3: Update fake transport expectations**

Update `tests/high_level_api_tests.cpp` fake transport path matching if any expected path changes.

- [ ] **Step 4: Run focused tests**

Run:

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
```

Expected: both PASS.

---

## Chunk 6: Documentation

### Task 11: Document endpoint categories and diagnostic failures

**Files:**
- Modify: `docs/api-overview.md`
- Modify: `docs/high-level-api.md`
- Modify: `docs/ntstatus-codes.md`

- [ ] **Step 1: Document public sample categories**

Add a short note:

- Public endpoint samples are diagnostics, not deterministic protocol conformance tests.
- DNS/connect/timeout/reset statuses can be recorded without failing the whole load-time matrix.
- Protocol parse errors, API misuse, certificate trust failures, and unsupported protocol paths remain fatal.

- [ ] **Step 2: Document current endpoint selection**

List:

- `httpbin.dev` for stable HTTPS HTTP/2 and content-encoding samples.
- `httpbun.com` or selected plain host for plain HTTP/1.1 verb echo.
- `nghttp2.org` only for HTTP/2/h2c protocol capability that replacement hosts do not provide.

- [ ] **Step 3: Document live validation caveat**

State that public endpoints can still change behavior and live driver validation should record exact date, endpoint, status, and transport mode.

- [ ] **Step 4: Do not commit**

Stop after writing docs unless the user explicitly asks for a commit.

---

## Chunk 7: Verification

### Task 12: Run focused user-mode tests

**Files:**
- Test only.

- [ ] **Step 1: Run HTTP/2 tests**

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'
```

Expected: `HTTP2 CLIENT TESTS PASSED`.

- [ ] **Step 2: Run TLS tests**

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
```

Expected: PASS.

- [ ] **Step 3: Run high-level tests**

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'
```

Expected: `high-level API tests passed`.

- [ ] **Step 4: Run khttp tests**

```powershell
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
```

Expected: `khttp tests passed`.

### Task 13: Build Debug and Release x64

**Files:**
- Build only.

- [ ] **Step 1: Build Debug x64 with warnings as errors**

Run without artificial timeout:

```powershell
pwsh -NoLogo -NoProfile -Command '$ErrorActionPreference = "Stop"; $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"; $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) { throw "Visual Studio with VC tools was not found." }; $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"; & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & msbuild.exe .\KernelHttp.sln /p:Configuration=Debug /p:Platform=x64 /m /nr:false; exit $LASTEXITCODE'
```

Expected: 0 errors, 0 warnings.

- [ ] **Step 2: Build Release x64 with warnings as errors**

Run without artificial timeout:

```powershell
pwsh -NoLogo -NoProfile -Command '$ErrorActionPreference = "Stop"; $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"; $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) { throw "Visual Studio with VC tools was not found." }; $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"; & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & msbuild.exe .\KernelHttp.sln /p:Configuration=Release /p:Platform=x64 /m /nr:false; exit $LASTEXITCODE'
```

Expected: 0 errors, 0 warnings.

### Task 14: Live kernel validation

**Files:**
- Runtime validation only.

- [ ] **Step 1: Configure the certificate bundle path**

Set the test driver `CertificateBundlePath` to:

```text
\??\E:\work\kernel_http\certs\cacert.pem
```

- [ ] **Step 2: Load the test driver**

Use the existing debugger/driver-load workflow. Do not use the prohibited smoke script command.

- [ ] **Step 3: Verify expected log behavior**

Expected:

- `KernelHttpTest 全量示例全部完成`, or only diagnostic public endpoint failures that are explicitly logged as not counted.
- No verified HTTPS sample passes by switching to no-verify.
- `httpbin.dev` verified HTTPS samples succeed through the configured CA bundle.
- h2c upgrade remains on `nghttp2.org` and is either successful or logged as a public endpoint diagnostic on DNS/connect/timeout.
- `STATUS_INVALID_NETWORK_RESPONSE`, trust failures, malformed certificates, and API misuse still fail the aggregate.

- [ ] **Step 4: Record exact live endpoint observations**

In the final implementation notes, record:

- Date and timezone.
- Endpoint host.
- Protocol mode: HTTP/1.1, HTTPS HTTP/2, h2c prior knowledge, h2c upgrade.
- Status code or NTSTATUS.
- Whether it was counted as fatal or diagnostic.

---

## Optional Commit Checkpoints

Only run these if the user explicitly asks for commits.

1. After Chunk 1:

```text
test: add public endpoint status classification coverage
- Add shared sample status classification helpers
- Cover diagnostic and fatal status categories in user-mode tests
```

2. After Chunks 2-4:

```text
fix: keep public endpoint timeouts from failing sample matrix
- Apply shared diagnostic aggregation to public sample endpoints
- Move unstable generic HTTPS samples to capability-matched endpoints
- Route verified low-level HTTPS samples through the CA bundle contract
```

3. After Chunks 5-7:

```text
docs: document public sample endpoint stability policy
- Document endpoint categories and diagnostic network statuses
- Record verification commands for tests and Debug/Release builds
```
