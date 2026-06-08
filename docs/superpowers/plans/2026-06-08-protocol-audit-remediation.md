# Protocol Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the protocol correctness gaps found in the HTTP/WebSocket/TLS/WSK audit so the project has a clearly bounded, testable Windows kernel HTTP client protocol subset.

**Architecture:** Work from the highest-risk ownership and protocol-state issues downward. Each chunk adds failing tests first, implements the narrow protocol rule in the existing layer, then runs focused tests plus Debug x64 build verification. TLS downgrade behavior must be based on explicit negotiation evidence, not broad retry logic.

**Tech Stack:** Windows kernel C++ under `/kernel`, WSK, kernel CNG/BCrypt, custom HTTP/1.x parser, custom WebSocket client/frame layer, custom TLS 1.2/1.3, custom HTTP/2 and HPACK modules, MSBuild/Gradle project commands through `pwsh`. Do not run the forbidden `tests/integration/https_smoke.ps1 -SkipDriverBuild` smoke command.

---

## Execution Rules

- Use `pwsh` for every command.
- Do not commit unless the user explicitly asks.
- Keep warning-as-error and the highest warning level enabled for Debug and Release builds.
- Do not introduce broad retry architecture or temporary compatibility paths to hide protocol errors.
- After code changes, run focused tests, then run the required test target and Debug build target for the touched area.
- Keep API behavior explicit: unsupported optional protocol features must fail clearly or be documented as unsupported.

## Reference Documents

- `docs/plans/2026-06-08-protocol-completeness-design.md`
- `docs/plans/2026-06-08-protocol-audit-remediation-notes.md`
- `docs/superpowers/plans/2026-06-08-protocol-completeness.md`

## File Map

- `src/KernelHttpLib/http/HttpParser.cpp`: HTTP/1.x status/header/body-boundary parsing.
- `src/KernelHttpLib/http/HttpResponse.cpp`: response metadata and connection semantics.
- `src/KernelHttpLib/engine/HttpEngine.cpp`: HTTP request execution, response read loop, connection pool release decisions.
- `src/KernelHttpLib/engine/ConnectionPool.cpp`: reusable connection ownership.
- `src/KernelHttpLib/client/WebSocketClient.cpp`: WebSocket handshake, send/receive, Close/Ping/Pong behavior, wss TLS path.
- `include/KernelHttp/client/WebSocketClient.h`: WebSocket client state, buffers, locks.
- `src/KernelHttpLib/engine/WsEngine.cpp`: high-level WebSocket API, workspace buffers, locks, options.
- `include/KernelHttp/engine/Engine.h`: public WebSocket and engine options.
- `include/KernelHttp/engine/Workspace.h`: workspace buffer sizes.
- `src/KernelHttpLib/websocket/WebSocketFrame.cpp`: frame validation, masking, encode/decode helpers.
- `src/KernelHttpLib/http2/Http2Connection.cpp`: HTTP/2 stream receive loop and connection error behavior.
- `src/KernelHttpLib/net/WskSync.h`: synchronous WSK completion and timeout helper.
- `src/KernelHttpLib/net/WskSocket.cpp`: WSK connect/send/receive/close operations.
- `include/KernelHttp/engine/Async.h`: async cancellation contract.
- `src/KernelHttpLib/engine/Async.cpp`: async operation cancellation and completion.
- `src/KernelHttpLib/tls/TlsConnection.cpp`: TLS handshake orchestration, alerts, ALPN, close_notify, early data.
- `include/KernelHttp/tls/TlsConnection.h`: TLS state and result metadata.
- `src/KernelHttpLib/tls/TlsRecord.cpp`: TLS record and alert parsing.
- `src/KernelHttpLib/tls/TlsHandshake12.cpp`: TLS 1.2 ClientHello extensions and negotiated values.
- `src/KernelHttpLib/tls/TlsHandshake13.cpp`: TLS 1.3 ClientHello/extensions and negotiated values.
- `src/KernelHttpLib/tls/CertificateValidator.cpp`: DER certificate parsing and host validation.
- `include/KernelHttp/tls/CertificateValidator.h`: certificate validation options and result metadata.
- `tests/http_parser_tests.cpp`: HTTP/1.x parser and response semantics tests.
- `tests/websocket_frame_tests.cpp`: WebSocket frame validation tests.
- `tests/websocket_client_tests.cpp`: WebSocket handshake and client behavior tests.
- `tests/http2_client_tests.cpp`: HTTP/2 connection behavior tests.
- `tests/tls_record_tests.cpp`: TLS record/alert behavior tests.
- `tests/high_level_api_tests.cpp`: high-level HTTP/WebSocket API behavior tests.
- `tests/khttp_tests.cpp`: integrated high-level tests; WebSocket round-trip regressions are now passing.

## Chunk 1: HTTP/1.x Connection Ownership And Strictness

### Task 1: Add failing tests for close-delimited responses

**Files:**
- Modify: `tests/http_parser_tests.cpp`
- Modify if needed: `tests/high_level_api_tests.cpp`

- [x] Add a response case with HTTP/1.1 status, body bytes, no `Content-Length`, no `Transfer-Encoding`, and EOF as the body delimiter.
- [x] Assert parser metadata marks the body as close-delimited.
- [x] Add an engine-level fake transport case where EOF completes the response and the connection is not returned to the pool.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Expected before implementation: new close-delimited reuse assertion fails.

### Task 2: Implement close-delimited no-reuse semantics

**Files:**
- Modify: `src/KernelHttpLib/http/HttpParser.cpp`
- Modify: `src/KernelHttpLib/http/HttpResponse.cpp`
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Modify: `src/KernelHttpLib/engine/ConnectionPool.cpp`
- Test: `tests/http_parser_tests.cpp`
- Test if needed: `tests/high_level_api_tests.cpp`

- [x] Add response metadata for `BodyEndsOnConnectionClose`.
- [x] Set the metadata when no length framing exists and the status/method combination allows a body.
- [x] In `HttpEngine`, when EOF completes a close-delimited response, mark the connection non-reusable.
- [x] Ensure `ConnectionPool` refuses any connection with close-delimited completion.
- [x] Re-run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Re-run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

### Task 3: Add and implement HTTP/1.0 keep-alive rules

**Files:**
- Modify: `tests/http_parser_tests.cpp`
- Modify: `src/KernelHttpLib/http/HttpParser.cpp`
- Modify: `src/KernelHttpLib/http/HttpResponse.cpp`
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`

- [x] Add tests for HTTP/1.0 without `Connection`, with `Connection: keep-alive`, and with `Connection: close`.
- [x] Record response major/minor version in response metadata if not already available at engine decision time.
- [x] Treat HTTP/1.0 as non-reusable unless `Connection: keep-alive` is present and body framing is safe.
- [x] Treat HTTP/1.1 as reusable only when not `Connection: close` and framing is safe.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`

### Task 4: Prevent `101 Switching Protocols` from entering HTTP pool

**Files:**
- Modify: `tests/http_parser_tests.cpp`
- Modify if needed: `tests/high_level_api_tests.cpp`
- Modify: `src/KernelHttpLib/engine/HttpEngine.cpp`
- Modify: `src/KernelHttpLib/engine/ConnectionPool.cpp`

- [x] Add an engine-level test for `101 Switching Protocols` asserting the upgraded connection is not released as normal HTTP reusable.
- [x] Add explicit upgraded/owned state to response or engine connection handling.
- [x] Ensure WebSocket/h2c upgrade paths take ownership explicitly.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

### Task 5: Tighten HTTP parser inputs

**Files:**
- Modify: `tests/http_parser_tests.cpp`
- Modify: `src/KernelHttpLib/http/HttpParser.cpp`

- [x] Add invalid header tests for CTL characters, invalid field-name tokens, and whitespace before colon.
- [x] Add invalid status-line tests for unsupported HTTP version such as `HTTP/2.0`, invalid status code `000`, and invalid status code `999` if the current API treats it as unsupported.
- [x] Add URL authority tests for userinfo and unsupported authority forms.
- [x] Implement strict rejection with clear status codes.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`

## Chunk 2: WebSocket Handshake And State Correctness

### Task 6: Fix WebSocket Host header construction

**Files:**
- Modify: `tests/websocket_client_tests.cpp`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify if needed: URL parser files used by the engine

- [ ] Add handshake request tests for `ws://example.com/`, `ws://example.com:8080/`, `wss://example.com/`, `wss://example.com:8443/`, `ws://[::1]/`, and `ws://[::1]:8080/`.
- [x] Expected Host values: default ports omitted, non-default ports included, IPv6 literal bracketed.
- [x] Implement one shared authority formatter for WebSocket Host header.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`

### Task 7: Reject unrequested WebSocket extensions

**Files:**
- Modify: `tests/websocket_client_tests.cpp`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/websocket/WebSocketFrame.cpp`

- [x] Add handshake test where the client sends no `Sec-WebSocket-Extensions` and server replies with `permessage-deflate`; expected failure.
- [x] Ensure the current no-extension implementation never enables RSV semantics.
- [x] Keep frame decode rejection for non-zero RSV bits.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'`

### Task 8: Remove shared masking scratch race

**Files:**
- Modify: `include/KernelHttp/client/WebSocketClient.h`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Test: `tests/websocket_client_tests.cpp`

- [ ] Add a test that sends an application frame while receive-side Ping auto-reply builds a Pong, using deterministic masking hooks if the existing tests support them.
- [x] Remove connection-level mutable `maskingKey_` scratch from send and auto-Pong paths.
- [x] Use function-local mask storage for every frame encode.
- [x] Keep existing send and receive locks, but do not rely on them to protect shared mask state.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`

### Task 9: Implement Close echo state machine

**Files:**
- Modify: `include/KernelHttp/client/WebSocketClient.h`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Test: `tests/websocket_client_tests.cpp`

- [ ] Add tests for receiving Close before local Close, receiving Close after local Close, and attempting to send data after close state begins.
- [x] Track `CloseSent` and `CloseReceived` in the client state.
- [x] On receiving Close, send a Close frame echo if `CloseSent` is false.
- [x] After Close is received, do not deliver later data frames as normal messages.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`

## Chunk 3: WebSocket Message Size And Control Options

### Task 10: Align frame buffer, message limit, and output capacity

**Files:**
- Modify: `include/KernelHttp/engine/Engine.h`
- Modify: `include/KernelHttp/engine/Workspace.h`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Test: `tests/websocket_client_tests.cpp`
- Test if needed: `tests/high_level_api_tests.cpp`

- [x] Add tests for a message larger than 16KB but smaller than default 1MB.
- [x] Add tests for a message exceeding the configured message limit.
- [x] Add tests for user output buffer smaller than message length.
- [x] Separate frame read scratch from message aggregation/output capacity.
- [x] Return `STATUS_BUFFER_TOO_SMALL` for insufficient output buffer without corrupting connection state.
- [x] Return a clear protocol or size error when the message exceeds configured limit.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

### Task 11: Make `AutoReplyPing` real or remove it from public behavior

**Files:**
- Modify: `include/KernelHttp/engine/Engine.h`
- Modify: `src/KernelHttpLib/engine/WsEngine.cpp`
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify: `docs/api-overview.md`
- Modify if needed: `docs/high-level-api.md`
- Test: `tests/websocket_client_tests.cpp`

- [x] Decide one supported behavior before coding: either implement `AutoReplyPing=false` as an observable control event path, or document that current public API always auto-replies and remove the misleading option.
- [x] If implementing false, add a receive result that lets high-level API report Ping without sending Pong automatically.
- [x] Not applicable: removing/deprecating was not chosen.
- [x] Add tests for true and false behavior matching the chosen contract.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`

### Task 12: Remove broad WebSocket TLS 1.2 retry

**Files:**
- Modify: `src/KernelHttpLib/client/WebSocketClient.cpp`
- Modify if needed: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/websocket_client_tests.cpp`

- [ ] Add tests for wss certificate failure, network failure, and TLS version negotiation failure.
- [x] Assert only explicit TLS version negotiation evidence can select TLS 1.2.
- [x] Remove WebSocket-layer broad retry after arbitrary TLS failure.
- [x] Use TLS-layer structured negotiation result from Chunk 5 when available.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`

## Chunk 4: WSK Timeout Ownership And Async Cancel

### Task 13: Define WSK timeout ownership state machine

**Files:**
- Modify: `src/KernelHttpLib/net/WskSync.h`
- Modify: `src/KernelHttpLib/net/WskSocket.cpp`
- Create or modify tests if WSK fake harness exists under `tests/`

- [x] Document states in code comments near the helper: pending, completed, timed out, cancel requested, late completion cleanup.
- [ ] Add fake WSK tests for connect timeout followed by late success; expected native socket is closed exactly once.
- [ ] Add fake send/receive timeout followed by late completion; expected buffers remain owned until completion cleanup is done.
- [x] On timeout, either cancel and wait for completion or transfer cleanup responsibility to a completion-owned context.
- [ ] Run the focused WSK fake test command used by the repository, or add it to the nearest existing user-mode test binary.

### Task 14: Propagate async cancellation to active transport operation

**Files:**
- Modify: `include/KernelHttp/engine/Async.h`
- Modify: `src/KernelHttpLib/engine/Async.cpp`
- Modify: `src/KernelHttpLib/net/WskSocket.cpp`
- Modify if needed: TLS connection operation wrappers
- Test if existing: async/high-level API tests

- [ ] Add tests for cancel during connect, send, receive, and TLS handshake when the existing harness can simulate blocking operations.
- [x] Add a cancellation callback or token bridge from async operation to active transport operation.
- [x] Guarantee user completion callback fires once with a final canceled status.
- [x] Guarantee late transport completion cannot call user completion a second time.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`

## Chunk 5: TLS Negotiation, Alert, ALPN, And Close Semantics

### Task 15: Add structured TLS handshake failure classification

**Files:**
- Modify: `include/KernelHttp/tls/TlsConnection.h`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Modify if needed: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Test: TLS handshake/client tests if present
- Alternative test target: `tests/tls_record_tests.cpp` for alert parsing pieces

- [x] Define failure categories: version_negotiation, certificate_validation, alpn_mismatch, network_io, decode_error, crypto_error, peer_alert, local_policy.
- [ ] Add tests that simulate server protocol_version alert and unsupported version ServerHello.
- [ ] Add tests that simulate certificate failure and verify it does not request TLS 1.2 retry.
- [ ] Add tests that simulate ALPN mismatch and verify it does not request TLS 1.2 retry.
- [x] Implement category propagation from handshake layer to connection caller.
- [x] Allow TLS 1.2 selection only for explicit version negotiation category.

### Task 16: Preserve TLS alert and close_notify semantics

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsRecord.cpp`
- Modify: `include/KernelHttp/tls/TlsConnection.h`
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Test: `tests/tls_record_tests.cpp`

- [x] Add alert parsing tests for warning close_notify, fatal protocol_version, fatal bad_certificate, and unknown fatal alert.
- [x] Store alert level and description in TLS result metadata.
- [x] Treat close_notify as clean TLS close in alert metadata.
- [ ] Treat EOF without close_notify according to documented policy, not as a successful clean close.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`

### Task 17: Validate ALPN against offered protocols

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake12.cpp`
- Modify: `src/KernelHttpLib/tls/TlsHandshake13.cpp`
- Test: TLS handshake/client tests if present
- Test if needed: `tests/http2_client_tests.cpp`

- [ ] Add tests where client offers `h2,http/1.1` and server returns `h2`; expected success.
- [ ] Add tests where server returns a protocol not offered; expected ALPN mismatch failure.
- [ ] Add tests where ALPN is required for HTTP/2 but missing; expected failure or HTTP/1.1 path according to the API contract.
- [x] Implement strict offered-list matching for TLS 1.2 and TLS 1.3.
- [x] Run HTTP/2 and high-level tests after implementation.

### Task 18: Disable or complete TLS 1.3 early data behavior

**Files:**
- Modify: `src/KernelHttpLib/tls/TlsConnection.cpp`
- Modify if needed: public TLS option headers
- Modify docs if public options change
- Test: TLS tests if present

- [x] Choose current supported contract: default early data disabled unless the project has complete replay-safe request policy.
- [x] If disabling, ensure ClientHello does not advertise early data by default.
- [x] Not applicable: keeping early data by default was not chosen.
- [ ] Add tests for early data rejected by server.

## Chunk 6: Certificate Validation Boundaries

### Task 19: Add iPAddress SAN parsing and matching

**Files:**
- Modify: `include/KernelHttp/tls/CertificateValidator.h`
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Test: certificate validator tests if present
- Test if needed: add focused cases to the nearest TLS/certificate test binary

- [x] Add DER SAN tests containing IPv4 iPAddress and IPv6 iPAddress.
- [x] Add host validation tests for IPv4 literal, IPv6 literal, DNS hostname, and mismatch cases.
- [x] When URL host is an IP literal, match only iPAddress SAN.
- [x] When URL host is DNS, match dNSName SAN using existing wildcard policy.
- [x] Do not fall back from IP literal to CN.

### Task 20: Document revocation, EKU, and KeyUsage policy

**Files:**
- Modify: `docs/api-overview.md`
- Modify: `docs/high-level-api.md`
- Modify if needed: `include/KernelHttp/tls/CertificateValidator.h`
- Test if policy code changes: certificate validator tests

- [x] State clearly that OCSP/CRL revocation checking is not currently implemented, unless implementing it in this task.
- [x] Decide whether EKU/KeyUsage failures are hard policy or configurable options.
- [x] Not applicable: configurable EKU/KeyUsage options were not chosen.
- [x] If hard policy, document exact required EKU/KeyUsage behavior.

## Chunk 7: HTTP/2 Stream Completion And Error Frames

### Task 21: Require END_STREAM before successful response completion

**Files:**
- Modify: `tests/http2_client_tests.cpp`
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`

- [x] Add a test where HEADERS and partial DATA arrive, then receive times out before `END_STREAM`; expected non-success.
- [x] Add a test where HEADERS arrives with `END_STREAM`; expected success with empty body.
- [x] Add a test where DATA carries `END_STREAM`; expected success with complete body.
- [x] Track per-stream end-of-stream state.
- [x] Return timeout or incomplete-response status if no `END_STREAM` arrives.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`

### Task 22: Implement RST_STREAM and GOAWAY semantics for protocol errors

**Files:**
- Modify: `src/KernelHttpLib/http2/Http2Connection.cpp`
- Modify if needed: HTTP/2 frame helper files
- Test: `tests/http2_client_tests.cpp`
- Test if needed: `tests/http2_frame_tests.cpp`

- [x] Add tests for stream-local protocol error and assert `RST_STREAM` is sent.
- [x] Add tests for connection-level protocol error and assert `GOAWAY` is sent.
- [ ] Add tests for receiving GOAWAY and refusing new streams above last-stream-id.
- [x] Separate stream errors from connection errors in code.
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`

## Chunk 8: Kernel IRQL, CNG, Allocation, And Lock Quality

### Task 23: Centralize CNG/BCrypt IRQL policy

**Files:**
- Modify: TLS/CNG helper files used by `src/KernelHttpLib/tls/`
- Modify: docs describing kernel constraints
- Test if present: TLS crypto tests

- [ ] Inventory all BCrypt/CNG calls and record required IRQL for each provider/operation.
- [x] Add shared guard helpers for PASSIVE_LEVEL-only CNG calls.
- [ ] If dispatch-level crypto is intended, explicitly open dispatch-capable providers and document the allowed path.
- [x] Ensure sync TLS and certificate validation paths fail early if called above supported IRQL.

### Task 24: Reduce high-frequency nonpaged-pool copies and busy-spin locks

**Files:**
- Modify: `src/KernelHttpLib/net/WskSocket.cpp`
- Modify: global table/connection registry files found during implementation
- Test: existing protocol tests and Debug build

- [ ] Identify send/receive paths that allocate/copy nonpaged buffers per operation.
- [ ] Reuse per-connection buffers where the protocol state already serializes access.
- [x] Replace busy-spin global table waits with bounded lock design appropriate for kernel context.
- [x] Keep memory lifetime explicit; do not introduce stack buffers in lib paths that violate project constraints.
- [x] Run focused tests for HTTP, WebSocket, TLS record, and HTTP/2 after changes.

## Chunk 9: Documentation And Final Verification

### Task 25: Update public capability documentation

**Files:**
- Modify: `README.md`
- Modify: `README_en.md`
- Modify: `docs/api-overview.md`
- Modify: `docs/high-level-api.md`
- Reference: `docs/plans/2026-06-08-protocol-audit-remediation-notes.md`

- [x] Replace broad “complete protocol support” language with supported-subset wording.
- [x] Document unsupported optional features: WebSocket extensions, HTTP/2 push, TLS client certificates, OCSP/CRL revocation, IDNA, unsupported cipher suites.
- [x] Document strict failure behavior for unrequested WebSocket extensions and ALPN mismatch.
- [x] Document connection reuse behavior for close-delimited HTTP and `101 Switching Protocols`.
- [x] Document required IRQL for synchronous networking/TLS/certificate APIs.

### Task 26: Run final focused tests and builds

**Files:**
- No source edits unless failures require fixes.

- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'`
- [x] Run: `pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'`
- [x] Run the repository's Debug x64 build command without imposing an artificial timeout.
- [x] Not applicable: Release was not requested for this pass.
- [x] Do not run: `pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild`

## Completion Criteria

- HTTP/1.x never reuses close-delimited or upgraded connections incorrectly.
- WebSocket handshake, masking, Close, Ping/Pong, size limits, and TLS retry behavior match the documented contract.
- WSK timeout and async cancel paths have explicit ownership and single-completion guarantees.
- TLS version selection, alert handling, close_notify, ALPN, and early data behavior are classified rather than hidden behind broad retries.
- Certificate validation supports iPAddress SAN or documents any remaining unsupported revocation behavior honestly.
- HTTP/2 only returns complete responses and sends appropriate RST_STREAM/GOAWAY for protocol errors.
- All focused protocol tests pass, `khttp_tests.exe` WebSocket round-trip failures are resolved, and Debug build passes with warnings treated as errors.
