# Public Network and Certificate Sample Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the load-time KernelHttp sample matrix report real product regressions instead of public-network noise, while enabling verified HTTPS with the CA bundle at `E:\work\kernel_http\certs\cacert.pem`.

**Architecture:** Keep HTTP, TLS, certificate validation, and WebSocket on the existing kernel-native path. Fix deterministic API bugs with focused unit tests first, then adjust sample aggregation so forced-address-family and public WebSocket failures are recorded without poisoning the whole matrix. Do not introduce no-verify as a pass path for certificate-verified samples.

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, custom TLS 1.2/1.3, custom X.509 validator, custom HTTP/2 header builder, khttp high-level samples, user-mode protocol tests, MSBuild via `pwsh`.

---

## Execution Status - 2026-06-10

- [x] HTTP/2 extra header names accept mixed-case input and emit lowercase wire names.
- [x] Non-critical `certificatePolicies` DER is validated and allowed to reach normal trust evaluation.
- [x] Critical or malformed `certificatePolicies` and `NameConstraints` remain rejected.
- [x] `certs\cacert.pem` is covered by user-mode external trust-store loading.
- [x] IPv4/IPv6 public address-family environment failures are recorded without failing the load-time sample aggregate.
- [x] Public WebSocket DNS/connect environment failures, including `STATUS_NO_MATCH`, are recorded without failing the load-time sample aggregate.
- [x] Advanced public WebSocket samples use the same environment-status aggregation rule.
- [x] Kernel test driver supports an explicit `CertificateBundlePath` registry value and keeps the driver-directory `cacert.pem` path as the documented default contract.
- [x] Documentation updated for certificate policy behavior, public sample aggregation, and certificate bundle path behavior.
- [x] Focused user-mode tests passed: `http2_client_tests.exe`, `tls_record_tests.exe`, `high_level_api_tests.exe`.
- [x] Debug x64 and Release x64 solution builds passed with 0 warnings and 0 errors.
- [ ] Live kernel driver-load validation was not run in this pass.

## Scope and Decisions

- The CA bundle source for this work is `E:\work\kernel_http\certs\cacert.pem`; kernel runtime paths may need `\??\E:\work\kernel_http\certs\cacert.pem` or deployment next to the test driver.
- Treat `certificatePolicies` as a certificate-policy extension, not as an automatic hard failure. Parse or minimally validate its DER structure, accept non-critical policies when no caller policy OID is required, and keep critical or malformed policies rejected unless full policy-tree processing is implemented in the same task.
- Keep `NameConstraints` explicitly unsupported until a complete DNS/IP constraint evaluator exists; do not silently ignore it.
- HTTP/2 wire header names must remain lowercase. Input APIs may accept mixed-case HTTP/1-style names if the builder lowercases them before encoding.
- Public IPv4-only, IPv6-only, and public WebSocket samples are diagnostic coverage. Network reachability failures from those samples should be recorded in result fields but should not decide the whole driver-load sample status.
- Do not run the prohibited command: `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`.
- Do not git commit unless the user explicitly asks.

## Files

- Modify: `include/KernelHttp/tls/CertificateValidator.h`
  - Add enough extension metadata to distinguish non-critical `certificatePolicies` from unsupported critical policy requirements.
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
  - Parse/validate `certificatePolicies` and adjust validation policy.
  - Preserve strict `NameConstraints` rejection.
- Modify: `tests/tls_record_tests.cpp`
  - Replace the current "reject any certificatePolicies" expectation with tests for non-critical accept, critical reject, malformed reject, and existing NameConstraints reject.
- Modify: `src/KernelHttpLib/client/Http2Client.cpp`
  - Normalize allowed mixed-case extra header names into lowercase scratch names before emitting HTTP/2 headers.
  - Continue rejecting pseudo-header injection, connection-specific headers, empty names, bad bytes, and invalid `TE`.
- Modify: `tests/http2_client_tests.cpp`
  - Update uppercase header test to assert normalized output.
  - Keep negative tests for forbidden and malformed headers.
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp`
  - Treat IPv4 public-network failures the same way IPv6 failures are already treated.
  - Ensure repeated public WebSocket resolution/connect failures do not fail the whole high-level sample matrix before at least one successful public WebSocket validation.
- Modify: `tests/high_level_api_tests.cpp`
  - Add/adjust tests for IPv4 timeout aggregation and WebSocket `STATUS_NO_MATCH` aggregation.
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
  - Make negative TLS expectations align with actual policy order, or use a deterministic fixture that produces `STATUS_TRUST_FAILURE`.
- Modify if needed: `src/KernelHttpTest/DriverEntry.cpp`
  - Ensure the kernel sample receives the intended certificate bundle path, not an accidental root-drive `\??\E:\cacert.pem` path.
- Modify if needed: `docs/high-level-api.md`, `docs/api-overview.md`, `docs/ntstatus-codes.md`
  - Document the final certificate policy behavior and sample status aggregation.

---

## Chunk 1: HTTP/2 Header Normalization

### Task 1: Add failing tests for mixed-case HTTP/2 input headers

**Files:**
- Modify: `tests/http2_client_tests.cpp`

- [ ] **Step 1: Locate current uppercase rejection test**
  - Find the block around `"BuildHttp2RequestHeaders rejects uppercase field name"`.
  - Keep the surrounding injection and forbidden-header tests intact.

- [ ] **Step 2: Rewrite the uppercase case as normalization coverage**
  - Use an extra header such as `{ http::MakeText("Accept"), http::MakeText("*/*") }`.
  - Call `BuildHttp2RequestHeaders`.
  - Expect `STATUS_SUCCESS`.
  - Assert the emitted non-pseudo header name is exactly lowercase `accept`.
  - Assert no uppercase bytes appear in emitted header names.

- [ ] **Step 3: Add a bad-name test that still fails**
  - Use a name with a colon, control byte, empty name, or overlong name.
  - Expected: `STATUS_INVALID_PARAMETER`.
  - This proves normalization does not become a generic accept-anything path.

- [ ] **Step 4: Run the focused test**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
  - Expected before implementation: FAIL on mixed-case normalization.

### Task 2: Normalize allowed extra header names in the HTTP/2 builder

**Files:**
- Modify: `src/KernelHttpLib/client/Http2Client.cpp`

- [ ] **Step 1: Split validation from lowercasing**
  - Replace the current `IsValidHttp2FieldName` precondition inside `LowercaseHeaderName` with a helper that validates an HTTP token name before HTTP/2 normalization.
  - The helper must reject null, empty, colon, control chars, spaces, DEL, and names longer than `Http2MaxHeaderNameLength`.
  - The helper may accept uppercase ASCII letters because they will be lowered before output.

- [ ] **Step 2: Keep forbidden header checks before normalization**
  - Continue rejecting `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, and `host` with case-insensitive comparison.
  - Continue rejecting `TE` unless value is exactly `trailers` case-insensitively.

- [ ] **Step 3: Emit lowercase only**
  - Lowercase `A-Z` into `a-z` while copying into `lowerHeaderNames[headerIdx]`.
  - Do not write beyond `Http2MaxHeaderNameLength`.
  - Preserve existing fixed pseudo-header names and promoted `accept-encoding`.

- [ ] **Step 4: Run the focused test again**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
  - Expected: PASS.

---

## Chunk 2: Certificate Policy Handling

### Task 3: Add certificate policy tests before changing validator behavior

**Files:**
- Modify: `tests/tls_record_tests.cpp`

- [ ] **Step 1: Replace broad rejection expectation**
  - Rename `TestCertificateValidationRejectsCertificatePoliciesExtension` to describe the new behavior, for example `TestCertificateValidationAcceptsNonCriticalCertificatePolicies`.
  - The test should no longer assert `STATUS_NOT_SUPPORTED` just because `HasCertificatePolicies` is true.

- [ ] **Step 2: Add syntax-focused policy tests**
  - Add one test where a non-critical `certificatePolicies` extension has valid DER and validation reaches normal trust evaluation.
  - Add one test where a malformed `certificatePolicies` extension returns `STATUS_INVALID_NETWORK_RESPONSE`.
  - Add one test where a critical `certificatePolicies` extension returns `STATUS_NOT_SUPPORTED` unless full policy tree processing is implemented in this same work.

- [ ] **Step 3: Keep NameConstraints negative coverage**
  - Keep `TestCertificateValidationRejectsNameConstraintsExtension`.
  - If extension metadata changes, update the test name only if needed; expected status remains `STATUS_NOT_SUPPORTED`.

- [ ] **Step 4: Run the focused TLS record tests**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
  - Expected before implementation: FAIL on non-critical policy acceptance.

### Task 4: Implement certificatePolicies parsing and validation policy

**Files:**
- Modify: `include/KernelHttp/tls/CertificateValidator.h`
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`

- [ ] **Step 1: Extend parsed metadata**
  - Add fields such as `HasCertificatePolicies` and `CertificatePoliciesCritical`.
  - Add a separate critical flag for `NameConstraints` only if it helps diagnostics; do not use it to ignore NameConstraints.

- [ ] **Step 2: Parse extension criticality**
  - In extension parsing, set `CertificatePoliciesCritical` when the policy extension critical bit is present.
  - Keep unknown critical extensions rejected.

- [ ] **Step 3: Validate certificatePolicies DER**
  - Implement a bounded parser for:
    - `certificatePolicies ::= SEQUENCE OF PolicyInformation`
    - `PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER, policyQualifiers optional }`
  - Accept policy OIDs.
  - Reject malformed DER.
  - If policy qualifiers are present and not fully parsed, return `STATUS_NOT_SUPPORTED` only when needed for critical processing; otherwise validate the outer syntax and record presence.

- [ ] **Step 4: Adjust unsupported-policy gate**
  - Replace `RejectUnsupportedCertificatePolicies` with a function that:
    - returns `STATUS_NOT_SUPPORTED` for `NameConstraints`;
    - returns `STATUS_NOT_SUPPORTED` for critical `certificatePolicies` if full policy processing is not implemented;
    - allows non-critical `certificatePolicies`.

- [ ] **Step 5: Run the focused TLS tests**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
  - Expected: PASS.

### Task 5: Verify the provided CA bundle path in user-mode tests

**Files:**
- Modify: `tests/tls_record_tests.cpp` or add a focused helper in an existing test file.

- [ ] **Step 1: Add a path-existence assertion**
  - Use the existing user-mode fixture style.
  - Assert `certs\cacert.pem` loads through `InitializeExternalTrustStore` or existing PEM bundle loading helpers.
  - The repository-relative source file is `E:\work\kernel_http\certs\cacert.pem`.

- [ ] **Step 2: Avoid public network dependency**
  - Do not make the test connect to `nghttp2.org`.
  - The test only proves that the bundle can be read, parsed as PEM bundle input, and stored in `CertificateStore`.

- [ ] **Step 3: Run certificate tests**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
  - Expected: PASS.

---

## Chunk 3: Sample Matrix Aggregation

### Task 6: Make IPv4 public failures non-fatal like IPv6 public failures

**Files:**
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write the IPv4 aggregation test**
  - Mirror `TestLoadTimeSamplesIgnoreIpv6EnvironmentFailure`.
  - Set `capture.HttpFailureAddressFamily = KernelHttp::engine::KhAddressFamily::Ipv4`.
  - Set `capture.HttpFailureStatus = STATUS_IO_TIMEOUT`.
  - Expected: `RunHighLevelApiSamples` returns success, while `results.HttpGetIpv4.Status == STATUS_IO_TIMEOUT`.

- [ ] **Step 2: Update aggregation code**
  - Change the `HTTP GET IPv4 地址族` merge call to use `MergeAddressFamilySampleStatus`.
  - Update `MergeAddressFamilySampleStatus` so both IPv4 and IPv6 public-network statuses are logged and ignored for aggregate status.
  - Keep non-network API failures fatal.

- [ ] **Step 3: Run high-level tests**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`
  - Expected: PASS.

### Task 7: Keep public WebSocket DNS/connect failures diagnostic

**Files:**
- Modify: `src/KernelHttpTest/samples/HighLevelApiSamples.cpp`
- Modify: `tests/high_level_api_tests.cpp`
- Modify if needed: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`

- [ ] **Step 1: Add STATUS_NO_MATCH WebSocket aggregation test**
  - Extend or mirror `TestLoadTimeSamplesIgnoreRepeatedPublicWebSocketConnectFailures`.
  - Use `STATUS_NO_MATCH` (`0xC0000272`) to match WSK DNS no-result behavior.
  - Expected: public WebSocket failure is recorded in the relevant result, but the aggregate remains success if all deterministic API samples pass.

- [ ] **Step 2: Update advanced scenario aggregation**
  - Decide whether `WebSocket Close` and `WebSocket FragmentSend` in advanced samples are mandatory API validation or public endpoint diagnostics.
  - For public endpoint diagnostics, use the same environment-status rule as high-level samples.
  - Do not hide protocol errors after a connection is established.

- [ ] **Step 3: Run high-level tests**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`
  - Expected: PASS.

---

## Chunk 4: TLS Negative Samples and Certificate Path

### Task 8: Make TLS negative sample expectations deterministic

**Files:**
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write a test for unsupported-policy order**
  - In the fake transport path, simulate a TLS failure status of `STATUS_NOT_SUPPORTED`.
  - Assert the negative sample records the raw status.
  - Decide whether the sample treats this as expected only for ALPN mismatch, or whether trust-failure should use a fixture that cannot hit unsupported policy first.

- [ ] **Step 2: Fix `HTTPS TrustFailure`**
  - Preferred: make the trust-failure sample use a deterministic certificate fixture or transport path that produces `STATUS_TRUST_FAILURE`.
  - Acceptable only if explicitly documented: update the sample to expect `STATUS_NOT_SUPPORTED` when the current validator rejects unsupported critical policy before trust search.
  - Do not convert certificate-verified samples to no-verify.

- [ ] **Step 3: Run high-level tests**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`
  - Expected: PASS.

### Task 9: Ensure kernel runtime uses the intended CA bundle

**Files:**
- Inspect/modify: `src/KernelHttpTest/DriverEntry.cpp`
- Inspect/modify: `src/KernelHttpTest/KernelHttpTest.inf`
- Inspect/modify if present: deployment scripts that copy `KernelHttpTest.sys` and `cacert.pem`

- [ ] **Step 1: Confirm current path construction**
  - Inspect `BuildCertificateBundlePath` and the logged runtime path.
  - Current observed log showed `\??\E:\cacert.pem`; the desired source file is `E:\work\kernel_http\certs\cacert.pem`.

- [ ] **Step 2: Choose one official runtime contract**
  - Option A: deploy `certs\cacert.pem` next to the driver image and keep the current "driver directory + cacert.pem" contract.
  - Option B: add a documented registry value such as `CertificateBundlePath` and pass its exact kernel path into `RunKernelHttpTestSamples`.
  - Recommended: Option B for local debugging, because it avoids copying bundle files into root or driver output directories and makes the logged path auditable.

- [ ] **Step 3: Implement only the chosen contract**
  - If using Option B, fail clearly when the configured path is malformed or unreadable.
  - Keep existing default only if documented as the default deployment contract, not as an error-hiding fallback.

- [ ] **Step 4: Re-run the live kernel sample**
  - Use the debugger/driver-load workflow already used for the pasted log.
  - Expected log should include `证书信任包路径: \??\E:\work\kernel_http\certs\cacert.pem` or the documented colocated driver path.

---

## Chunk 5: Documentation and Verification

### Task 10: Update docs for final behavior

**Files:**
- Modify: `docs/high-level-api.md`
- Modify: `docs/api-overview.md`
- Modify if needed: `docs/ntstatus-codes.md`

- [ ] **Step 1: Document certificatePolicies behavior**
  - State that non-critical `certificatePolicies` is accepted after DER syntax validation.
  - State that critical certificate policy processing remains unsupported unless implemented.
  - State that `NameConstraints` still returns `STATUS_NOT_SUPPORTED`.

- [ ] **Step 2: Document sample aggregation**
  - Public forced-address-family failures and public WebSocket DNS/connect failures are diagnostic results.
  - Deterministic protocol/parser/TLS implementation failures remain fatal.

### Task 11: Final verification

**Files:**
- Test/build only.

- [ ] **Step 1: Run focused user-mode tests**
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
  - Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`
  - Expected: all PASS.

- [ ] **Step 2: Build Debug x64**
  - Run: `pwsh -NoLogo -NoProfile -Command '$ErrorActionPreference = "Stop"; $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"; $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) { throw "Visual Studio with VC tools was not found." }; $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"; & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & msbuild.exe .\KernelHttp.sln /p:Configuration=Debug /p:Platform=x64 /m /nr:false; exit $LASTEXITCODE'`
  - Expected: 0 errors, 0 warnings.

- [ ] **Step 3: Build Release x64**
  - Run: `pwsh -NoLogo -NoProfile -Command '$ErrorActionPreference = "Stop"; $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"; $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath; if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsPath)) { throw "Visual Studio with VC tools was not found." }; $devShell = Join-Path $vsPath.Trim() "Common7\Tools\Launch-VsDevShell.ps1"; & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & msbuild.exe .\KernelHttp.sln /p:Configuration=Release /p:Platform=x64 /m /nr:false; exit $LASTEXITCODE'`
  - Expected: 0 errors, 0 warnings.

- [ ] **Step 4: Live kernel validation**
  - Load the test driver with the certificate bundle path set to `E:\work\kernel_http\certs\cacert.pem` through the chosen runtime contract.
  - Expected:
    - Verified HTTPS to `nghttp2.org` no longer fails at `CertificateValidator: Unsupported certificate policy failed`.
    - No-verify HTTPS remains a separate diagnostic path and is not used to make verified samples pass.
    - Forced IPv4 failures are recorded without making the whole matrix fail.
    - Public WebSocket DNS/connect failures are recorded without making the whole matrix fail.

- [ ] **Step 5: Confirm forbidden command was not run**
  - Do not run: `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`.
