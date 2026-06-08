# Auto Redirect And Accept-Encoding Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add default HTTP redirect following and default supported `Accept-Encoding` request headers with user-controlled redirect disabling and max redirect count.

**Architecture:** Extend high-level send options with a disable flag and max redirect count. Add default `Accept-Encoding` in the shared high-level request builder path. Implement redirect following in `HttpEngine.cpp` around the existing send/retry/release flow so user-mode test transport and real kernel transport share behavior.

**Tech Stack:** Windows kernel C++17 under `/kernel`, existing khttp/engine API, WSK/TLS transport, user-mode regression tests, MSBuild Debug x64.

---

## Chunk 1: API Surface

### Task 1: Add send option controls

**Files:**
- Modify: `include/KernelHttp/engine/Engine.h`
- Modify: `include/KernelHttp/khttp/Types.h`
- Modify: `src/KernelHttpLib/khttp/Http.cpp`
- Modify: `src/KernelHttpLib/khttp/HttpAsync.cpp`

- [ ] Add `KhHttpSendFlagDisableAutoRedirect = 0x00000002`.
- [ ] Add `ULONG MaxRedirects = 0` to `KhHttpSendOptions`; document that 0 means default.
- [ ] Add `SendFlagDisableAutoRedirect = 0x00000002`.
- [ ] Add `ULONG MaxRedirects = 0` to `khttp::SendOptions`.
- [ ] Copy `MaxRedirects` in both khttp send option adapter functions.

## Chunk 2: Request Header Defaults

### Task 2: Inject default Accept-Encoding

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Test: `tests/khttp_tests.cpp`

- [ ] Add a helper that checks stored headers for `Accept-Encoding`.
- [ ] In `BuildHttpRequestOptions`, append `Accept-Encoding: gzip, deflate, br, identity` when the user did not provide one.
- [ ] Return `STATUS_BUFFER_TOO_SMALL` if the request header scratch capacity is exhausted.
- [ ] Add khttp tests that inspect `KhTestHttpTransportRequest::BuiltRequest` for the default header and for a user-provided `identity` value.

## Chunk 3: Redirect Flow

### Task 3: Follow redirects in high-level send

**Files:**
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Test: `tests/khttp_tests.cpp`

- [ ] Add redirect helpers for status classification, `Location` lookup, max count selection, and relative URL composition.
- [ ] Add a request clone used only inside synchronous send, preserving the caller's original request handle.
- [ ] Move the existing build/acquire/send/stale-connection retry/release sequence into a helper that sends one request and returns parsed response data.
- [ ] Loop while redirects are enabled, the response has a supported redirect status, and attempts are below `MaxRedirects`.
- [ ] For `303` and `301/302` with non-GET/HEAD, switch the redirect clone to `GET`, clear body, and remove entity headers.
- [ ] For `307/308`, preserve method and body.
- [ ] Rebuild pool key and request bytes for each redirected URL.
- [ ] Return the final response when max redirects is reached or when no followable `Location` exists.

## Chunk 4: Driver Sample Coverage

### Task 4: Update load-time scenario samples

**Files:**
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.h`
- Modify: `src/KernelHttpTest/samples/AdvancedScenarioSamples.cpp`
- Modify: `tests/high_level_api_tests.cpp`

- [ ] Change the default redirect sample expected status from 302 to 200.
- [ ] Add a disabled-redirect sample using `SendFlagDisableAutoRedirect`, expecting 302.
- [ ] Update the user-mode sample transport to return 302 for `/httpbin/redirect/1` and 200 for `/httpbin/get`.
- [ ] Update high-level sample assertions and expected call counts for the additional follow-up request and disabled sample.

## Chunk 5: Verification

### Task 5: Run tests and Debug build

**Files:**
- No source edits.

- [ ] Run targeted user-mode tests for `khttp_tests` and `high_level_api_tests`.
- [ ] Run the repository test command that is not the forbidden smoke command, or manually compile/run the affected host tests if needed.
- [ ] Build `KernelHttp.sln` Debug x64 with warnings as errors.
- [ ] Do not commit plan docs or code unless explicitly asked.
