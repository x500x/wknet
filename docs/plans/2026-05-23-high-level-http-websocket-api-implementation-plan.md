# High-Level HTTP and WebSocket API Implementation Plan

> **For agentic workers:** REQUIRED: Use an executing-plans workflow to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking. Do not create git commits unless the user explicitly asks for commits.

**Goal:** Add a simple high-level HTTP(S) and WebSocket API for the Windows kernel driver, with sync/async use, auto response allocation, callback streaming, TLS options, connection pooling, PASSIVE_LEVEL enforcement, and low stack usage.

**Architecture:** Add a small `api` layer with opaque handles, simple option structs, explicit release functions, and a PASSIVE worker for async calls. Keep the existing lower protocol modules as implementation details, migrate large temporary buffers into reusable heap workspaces, and route main-driver samples through the new API.

**Tech Stack:** Windows kernel driver, WSK, kernel CNG/BCrypt, existing HTTP/1.1/HTTP2/TLS/WebSocket modules, C++ namespace-only style, `pwsh` regression scripts.

---

## File Structure

- Create: `src/KernelHttp/api/KernelHttpApi.h`
  - Public high-level handle types, option structs, callbacks, sync/async HTTP and WebSocket functions.

- Create: `src/KernelHttp/api/KernelHttpApi.cpp`
  - Public entrypoint validation, IRQL checks, handle lifetime, HTTP/WebSocket facade implementation.

- Create: `src/KernelHttp/api/KernelHttpWorkspace.h`
  - Workspace structures and fixed-purpose scratch regions.

- Create: `src/KernelHttp/api/KernelHttpWorkspace.cpp`
  - Workspace allocation, reset, and release.

- Create: `src/KernelHttp/api/KernelHttpAsync.h`
  - Internal async operation and PASSIVE worker declarations.

- Create: `src/KernelHttp/api/KernelHttpAsync.cpp`
  - Worker queue, completion, cancel and wait handling.

- Create: `src/KernelHttp/api/KernelHttpConnectionPool.h`
  - Internal pooled connection records and pool key helpers.

- Create: `src/KernelHttp/api/KernelHttpConnectionPool.cpp`
  - HTTP/HTTPS connection acquire/release/close logic.

- Create: `src/KernelHttp/crypto/CngProviderCache.h`
  - Session-owned CNG algorithm provider cache.

- Create: `src/KernelHttp/crypto/CngProviderCache.cpp`
  - PASSIVE_LEVEL provider initialization and shutdown.

- Modify: `src/KernelHttp/crypto/CngProvider.h`
  - Add overloads or option structs allowing callers to use cached providers.

- Modify: `src/KernelHttp/crypto/CngProvider.cpp`
  - Use cached providers in key import, AES-GCM, hash/HMAC, ECDH and signature paths where available.

- Modify: `src/KernelHttp/tls/TlsConnection.h`
  - Accept workspace and provider cache through connection options.

- Modify: `src/KernelHttp/tls/TlsConnection.cpp`
  - Move KB-scale local buffers into workspace and use provider cache.

- Modify: `src/KernelHttp/tls/CertificateValidator.h`
  - Add validation context containing workspace and provider cache.

- Modify: `src/KernelHttp/tls/CertificateValidator.cpp`
  - Move chain parsing scratch from stack to workspace and use cached providers.

- Modify: `src/KernelHttp/client/HttpsClient.h`
  - Keep as lower implementation detail; add hooks for workspace/provider cache if still used by API layer.

- Modify: `src/KernelHttp/client/HttpsClient.cpp`
  - Remove local HTTP/2 scratch arrays or route them through workspace.

- Modify: `src/KernelHttp/client/WebSocketClient.h`
  - Keep as lower implementation detail; add workspace/provider cache hooks if still used by API layer.

- Modify: `src/KernelHttp/client/WebSocketClient.cpp`
  - Remove avoidable local buffers and expose lower send/receive behavior needed by API layer.

- Create: `src/KernelHttp/samples/HighLevelApiSamples.h`
  - Main-driver sample runner declarations.

- Create: `src/KernelHttp/samples/HighLevelApiSamples.cpp`
  - Samples using only the new high-level API.

- Modify: `src/KernelHttp/samples/HttpVerbSamples.h`
  - Mark old sample matrix as test-driver oriented or replace direct low-level sample entrypoints.

- Modify: `src/KernelHttp/samples/HttpVerbSamples.cpp`
  - Migrate sample bodies to high-level API or move low-level-only coverage into tests.

- Modify: `src/KernelHttp/DriverEntry.cpp`
  - Create a high-level session and run samples through `HighLevelApiSamples`.

- Modify: `src/KernelHttp/KernelHttp.vcxproj`
  - Add new API, workspace, async, pool, provider cache and sample files.

- Modify: `src/KernelHttp/KernelHttp.vcxproj.filters`
  - Add filters for API files.

- Create: `tests/high_level_api_tests.cpp`
  - Host tests for request/response/options/callback/pool-key behavior.

- Create: `tests/integration/high_level_api_regression.ps1`
  - Full host regression and driver build/test orchestration for the high-level API.

---

## Chunk 1: Public API skeleton and IRQL guard

### Task 1: Add public high-level API header

**Files:**
- Create: `src/KernelHttp/api/KernelHttpApi.h`
- Create: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write option validation tests**

Add host tests for invalid null session/request/response pointers, missing URL, invalid max response size, invalid callback combinations, and default option initialization.

- [ ] **Step 2: Define handle and option types**

Add opaque handle typedefs for session, request, response, websocket and async operation. Add simple structs for session options, request options, TLS options, send options, response view, callbacks and WebSocket options.

- [ ] **Step 3: Define public functions**

Declare session create/close, request create/release/setters, HTTP sync/async send, response access/release, WebSocket connect/send/receive/close, async cancel/wait/release.

- [ ] **Step 4: Add host compile wiring**

Add `tests/high_level_api_tests.cpp` to the regression script used for host tests.

### Task 2: Implement entrypoint IRQL checks

**Files:**
- Create: `src/KernelHttp/api/KernelHttpApi.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Add IRQL helper**

Add a small internal helper that returns `STATUS_INVALID_DEVICE_REQUEST` when current IRQL is not `PASSIVE_LEVEL`. In user-mode tests, stub it to PASSIVE unless a test override is set.

- [ ] **Step 2: Guard every public entrypoint first**

Each public API function must check IRQL before allocation, locking, WSK, CNG, waiting or callback handling.

- [ ] **Step 3: Add raised-IRQL kernel test plan hook**

Expose a test-only helper or test-driver case that raises IRQL and verifies public entrypoints fail immediately without touching state.

- [ ] **Step 4: Run host API tests**

Run the host regression command from the final verification section. Expected: API validation tests pass.

---

## Chunk 2: Workspace and provider cache

### Task 3: Add reusable workspace

**Files:**
- Create: `src/KernelHttp/api/KernelHttpWorkspace.h`
- Create: `src/KernelHttp/api/KernelHttpWorkspace.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write workspace tests**

Cover create/reset/release, paged vs nonpaged allocation flag selection, fixed scratch region sizes, and oversized request rejection.

- [ ] **Step 2: Implement workspace allocation**

Allocate request buffer, response buffer, decoded body buffer, HTTP/2 header scratch, TLS handshake scratch, certificate scratch and WebSocket frame scratch from heap.

- [ ] **Step 3: Add response grow helper**

Implement bounded auto-grow for response body. Growth must stop at `MaxResponseBytes` and return `STATUS_BUFFER_TOO_SMALL`.

- [ ] **Step 4: Enforce low-stack rule**

Document in code comments that KB-scale temporary arrays must use workspace. Do not add large local arrays in new code.

### Task 4: Add CNG provider cache

**Files:**
- Create: `src/KernelHttp/crypto/CngProviderCache.h`
- Create: `src/KernelHttp/crypto/CngProviderCache.cpp`
- Modify: `src/KernelHttp/crypto/CngProvider.h`
- Modify: `src/KernelHttp/crypto/CngProvider.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Add provider cache tests**

In user-mode tests, verify cache initialization state and that cached-provider code paths are selected when a cache is supplied.

- [ ] **Step 2: Implement PASSIVE provider initialization**

Open and store AES, SHA1, SHA256, SHA384, RSA, ECDSA and ECDH providers during session creation. Fail session creation if a required provider fails.

- [ ] **Step 3: Add cached-provider API paths**

Update key import, AES-GCM, hash/HMAC, ECDH and signature helpers to accept an optional cache/context and avoid deep `BCryptOpenAlgorithmProvider` calls.

- [ ] **Step 4: Preserve old lower-level behavior**

Keep existing functions available for lower tests, but high-level API must use cached-provider paths.

---

## Chunk 3: HTTP(S) sync API and connection pool

### Task 5: Implement session and request lifetime

**Files:**
- Modify: `src/KernelHttp/api/KernelHttpApi.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write lifetime tests**

Cover session create/close, request create/release, response release, double-release safety where supported, and invalid handle rejection.

- [ ] **Step 2: Implement session handle**

Store WSK client pointer, default options, workspace, provider cache, connection pool and async worker state.

- [ ] **Step 3: Implement request handle**

Store method, URL pieces, headers, body view, TLS overrides, callback options, pool policy and response allocation policy.

### Task 6: Implement connection pool

**Files:**
- Create: `src/KernelHttp/api/KernelHttpConnectionPool.h`
- Create: `src/KernelHttp/api/KernelHttpConnectionPool.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write pool key tests**

Verify scheme, host, port, TLS version range, ALPN and certificate policy participate in the pool key.

- [ ] **Step 2: Implement acquire/release**

Support reuse-or-create, force-new and no-pool request policies.

- [ ] **Step 3: Add close and eviction**

Close stale, incompatible or failed connections. Do not silently downgrade protocol or certificate settings.

### Task 7: Implement HTTP(S) sync send

**Files:**
- Modify: `src/KernelHttp/api/KernelHttpApi.cpp`
- Modify: `src/KernelHttp/client/HttpsClient.h`
- Modify: `src/KernelHttp/client/HttpsClient.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write response management tests**

Cover auto-allocated full response, callback-only response, callback plus aggregation, max response failure and header lookup.

- [ ] **Step 2: Build request through existing HTTP builder**

Use existing request builder but allocate output through workspace.

- [ ] **Step 3: Send via pooled or fresh connection**

Use existing WSK/TLS/HTTP lower modules as implementation details. Return successful keep-alive connections to the pool only after the full response is consumed.

- [ ] **Step 4: Stream data to callbacks**

Invoke header/body callbacks at PASSIVE and outside locks. Stop immediately if a callback returns failure.

---

## Chunk 4: Async HTTP and WebSocket

### Task 8: Add async worker and operation handle

**Files:**
- Create: `src/KernelHttp/api/KernelHttpAsync.h`
- Create: `src/KernelHttp/api/KernelHttpAsync.cpp`
- Modify: `src/KernelHttp/api/KernelHttpApi.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write async state tests**

Cover pending, completed, failed, canceled-before-start and release behavior with user-mode stubs.

- [ ] **Step 2: Implement PASSIVE worker queue**

Queue async HTTP/WebSocket work to a PASSIVE system worker or session-owned worker thread.

- [ ] **Step 3: Implement completion callback**

Call completion at PASSIVE after status/result is stored. Do not call completion while holding locks.

- [ ] **Step 4: Implement cancel and wait**

Cancellation is cooperative and checked at DNS, connect, TLS, send and receive boundaries. Wait is PASSIVE-only.

### Task 9: Implement WebSocket high-level API

**Files:**
- Modify: `src/KernelHttp/api/KernelHttpApi.h`
- Modify: `src/KernelHttp/api/KernelHttpApi.cpp`
- Modify: `src/KernelHttp/client/WebSocketClient.h`
- Modify: `src/KernelHttp/client/WebSocketClient.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] **Step 1: Write WebSocket API tests**

Cover connect options, send text/binary validation, receive auto-allocation options, receive callback options and close behavior with lower transport stubs.

- [ ] **Step 2: Implement sync connect/send/receive/close**

Use existing WebSocket frame codec and lower client logic, but route temporary buffers through workspace.

- [ ] **Step 3: Implement async WebSocket operations**

Use the same async worker and operation handle as HTTP.

- [ ] **Step 4: Handle ping/pong and close frames**

Auto-reply ping when configured, surface close frames clearly, and enforce max message size.

---

## Chunk 5: Stack cleanup and blue-screen fix

### Task 10: Move TLS and certificate scratch off stack

**Files:**
- Modify: `src/KernelHttp/tls/TlsConnection.h`
- Modify: `src/KernelHttp/tls/TlsConnection.cpp`
- Modify: `src/KernelHttp/tls/CertificateValidator.h`
- Modify: `src/KernelHttp/tls/CertificateValidator.cpp`
- Modify: `src/KernelHttp/client/HttpsClient.cpp`

- [ ] **Step 1: Replace TLS handshake local arrays**

Move ClientHello, HRR, transcript hash, signed input, shared secret and other KB-scale scratch buffers from local stack arrays to workspace.

- [ ] **Step 2: Replace certificate chain local arrays**

Move `ParsedCertificate` chain storage and authority bundle scratch into workspace.

- [ ] **Step 3: Replace HTTP/2 header scratch arrays**

Move request header arrays, lower-case name buffer and content-length buffer from HTTPS local stack into workspace.

- [ ] **Step 4: Use provider cache in certificate validation**

Ensure TLS 1.3 certificate validation no longer opens CNG providers deep in the validation stack.

### Task 11: Verify blue-screen path is removed

**Files:**
- Modify: `tests/high_level_api_tests.cpp`
- Modify: `tests/integration/high_level_api_regression.ps1`

- [ ] **Step 1: Add static search check**

Add a script check that flags new KB-scale local arrays in high-risk files unless explicitly allowed.

- [ ] **Step 2: Add provider-cache usage check**

Add tests or trace assertions confirming high-level TLS certificate validation uses cached provider paths.

- [ ] **Step 3: Run under WinDbg after implementation**

Load the driver, run high-level HTTPS sample, and confirm the previous stack path no longer reaches `BCryptOpenAlgorithmProvider` from `CertificateValidator::ValidateChain`.

---

## Chunk 6: Main-driver samples and test driver

### Task 12: Route main driver samples through new API

**Files:**
- Create: `src/KernelHttp/samples/HighLevelApiSamples.h`
- Create: `src/KernelHttp/samples/HighLevelApiSamples.cpp`
- Modify: `src/KernelHttp/DriverEntry.cpp`
- Modify: `src/KernelHttp/KernelHttp.vcxproj`
- Modify: `src/KernelHttp/KernelHttp.vcxproj.filters`

- [ ] **Step 1: Add high-level sample runner**

Implement GET, POST, HTTPS TLS option, HTTP/2 ALPN and WebSocket examples using only `KernelHttp::api` functions.

- [ ] **Step 2: Update DriverEntry**

Create a `KH_SESSION` after WSK initialization and run the high-level sample runner. Release all high-level handles before driver unload.

- [ ] **Step 3: Remove direct low-level sample calls**

Ensure main-driver sample path no longer calls `HttpsClient`, `TlsConnection` or `WebSocketClient` directly.

### Task 13: Move old sample matrix into test coverage

**Files:**
- Modify: `src/KernelHttp/samples/HttpVerbSamples.h`
- Modify: `src/KernelHttp/samples/HttpVerbSamples.cpp`
- Create: `tests/integration/high_level_api_regression.ps1`

- [ ] **Step 1: Convert old sample scenarios**

Represent existing HTTP verb, HTTPS, no-verify, HTTP/2 and WebSocket examples as high-level API test scenarios.

- [ ] **Step 2: Add test-driver build option**

Add a build mode or script path that builds the driver as a test driver with the full scenario matrix enabled.

- [ ] **Step 3: Keep main driver concise**

Main driver runs representative high-level examples; exhaustive scenario coverage belongs to the test driver.

---

## Final Verification

- [ ] **Run host tests**

```powershell
pwsh -NoLogo -NoProfile -File tests\integration\high_level_api_regression.ps1 -SkipDriverBuild
```

Expected: all host tests, including existing parser/TLS/HTTP2/WebSocket tests and new high-level API tests, pass.

- [ ] **Run full kernel test flow**

```powershell
pwsh -NoLogo -NoProfile -File tests\integration\high_level_api_regression.ps1 -Configuration Debug
```

Expected: Debug driver builds and the test driver scenario matrix passes. This must be a real regression run, not a smoke-only test.

- [ ] **Run Debug build directly if needed**

```powershell
msbuild.exe KernelHttp.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

Expected: Debug build succeeds with warnings as errors.

- [ ] **Check git state**

```powershell
git status --short
```

Expected: only intended source, test, project and plan files are modified. Do not commit unless the user explicitly requests it.
