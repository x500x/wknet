# wknet Opaque Module Boundaries Implementation Plan

> **For agentic workers:** REQUIRED: execute tasks in order, keep every intermediate state buildable, and do not use compatibility aliases or fallback implementations.

**Goal:** Remove public/internal layout leakage and make net, transport, TLS, HTTP/2, and pooled connections opaque across module boundaries while preserving protocol behavior.

**Architecture:** Public callers use only `wknet::http`, `wknet::websocket`, `wknet::crypto`, and `wknet::codec`. Internal modules exchange opaque handles through narrow service functions; each owning module alone defines and destroys its state. Session remains the orchestrator and connection-pool owner.

**Tech Stack:** C++17 `/kernel`, WDK/MSBuild, WSK, CNG/BCrypt, NTSTATUS, pwsh 7.

---

## Chunk 1: Public API and deterministic architecture checks

### Task 1: Add failing public-boundary checks

**Files:**
- Create: `tools/check-architecture.ps1`
- Modify: `tools/build-tests.ps1`

- [ ] Add checks for forbidden public directories and private includes.
- [ ] Add checks for `wknet::core`, old macros/names, cross-module private headers, direct pooled-field access, and missing vcxproj items.
- [ ] Run the checker and confirm it reports the current violations.
- [ ] Keep certificate data and real external repository URLs out of old-name false positives.

### Task 2: Move certificate and mTLS API to `wknet::http`

**Files:**
- Create: `include/wknet/http/Certificate.h`
- Create: `src/wknetlib/http_api/Certificate.cpp`
- Create: `src/wknetlib/tls/CertificateStore.h`
- Modify: `include/wknet/http/Types.h`
- Modify: `include/wknet/http/Http.h`
- Modify: `include/wknet/Wknet.h`
- Modify: `src/wknetlib/tls/CertificateStore.cpp`
- Modify: `src/wknetlib/tls/CertificateValidator.*`
- Modify: TLS/session/http_api call sites and tests
- Delete: `include/wknet/tls/CertificateStore.h`
- Delete: `include/wknet/tls/TlsTypes.h`

- [ ] Add public certificate, revocation, pin, credential, and signature-scheme value types under `wknet::http`.
- [ ] Add opaque `CertificateStore` lifecycle/load APIs.
- [ ] Move the concrete TLS store declaration into `src/wknetlib/tls`.
- [ ] Map public values to the internal store without aliases to `wknet::tls`.
- [ ] Update samples and tests to use only the new public API.
- [ ] Run TLS record, handshake, interop, high-level, and HTTP tests.

### Task 3: Remove WSK types from public proxy configuration

**Files:**
- Modify: `include/wknet/http/Types.h`
- Modify: `src/wknetlib/http_api/Session.cpp`
- Modify: `src/wknetlib/session/Engine*.cpp`
- Modify: `src/wknetlib/session/HttpRoute.cpp`
- Modify: `src/wknetlib/session/ConnectionPool.*`
- Modify: tests and samples using proxy configuration

- [ ] Replace `SOCKADDR_STORAGE` with host/IP text, port, and address-family fields.
- [ ] Resolve the endpoint only inside net/session routing code.
- [ ] Keep proxy pool-key identity stable and preserve absolute-form/CONNECT behavior.
- [ ] Run HTTP parser, HTTP API, proxy, and high-level tests.

### Task 4: Make the test hook public header independent

**Files:**
- Modify: `include/wknet/test/Test.h`
- Modify: `src/wknetlib/session/EngineTestHooks.cpp`
- Modify: affected user-mode tests

- [ ] Define narrow `wknet::test` request/response value types in the test header.
- [ ] Remove the include of `session/Engine.h` and all session type aliases.
- [ ] Map test values inside the implementation bridge.
- [ ] Run high-level, HTTP, and WebSocket tests.

## Chunk 2: Internal namespace and transport boundary

### Task 5: Split `wknet::core` into `rtl` and `transport`

**Files:**
- Modify: `src/wknetlib/rtl/Irql.h`
- Modify: `src/wknetlib/rtl/Lookaside.h`
- Modify: `src/wknetlib/rtl/IScratchAllocator.h`
- Modify: `src/wknetlib/rtl/WorkspaceScratchAllocator.h`
- Modify: `src/wknetlib/transport/*`
- Modify: all `core::` call sites

- [ ] Move allocation, IRQL, lookaside, and scratch symbols to `wknet::rtl`.
- [ ] Move byte-stream services to `wknet::transport`.
- [ ] Replace every `core::` reference without compatibility aliases.
- [ ] Run architecture checks and core protocol tests.

### Task 6: Replace `ITransport` with opaque `transport::Transport`

**Files:**
- Create: `src/wknetlib/transport/Transport.h`
- Create: `src/wknetlib/transport/TransportPrivate.hpp`
- Modify: `src/wknetlib/transport/WskTransport.*`
- Modify: `src/wknetlib/transport/TlsTransport.*`
- Modify: `src/wknetlib/transport/ProxyConnect.*`
- Modify: TLS, HTTP/1, HTTP/2, session, and WebSocket call sites
- Delete: `src/wknetlib/transport/ITransport.h`

- [ ] Define opaque transport lifecycle and send/receive/cancellation services.
- [ ] Implement private WSK/TLS/test function-table backends.
- [ ] Remove inheritance and direct virtual calls across module boundaries.
- [ ] Preserve timeout and cancellation semantics.
- [ ] Run HTTP, HTTP/2, TLS, and WebSocket test groups.

## Chunk 3: Opaque net, TLS, and HTTP/2 state

### Task 7: Make net runtime and sockets opaque

**Files:**
- Modify: `src/wknetlib/net/WskClient.*`
- Modify: `src/wknetlib/net/WskSocket.*`
- Create: module-private net state headers as needed
- Modify: session, transport, WebSocket, and driver test call sites

- [ ] Export only `NetRuntime*` and `Socket*` forward declarations and service functions.
- [ ] Move WSK registration, provider, socket, IRP, and rundown layouts to net-private headers.
- [ ] Ensure callers cannot invoke socket members or free socket memory directly.
- [ ] Run net-dependent HTTP/WebSocket tests and wknettest Debug build.

### Task 8: Make TLS connections opaque

**Files:**
- Create: `src/wknetlib/tls/TlsConnectionPrivate.hpp`
- Modify: `src/wknetlib/tls/TlsConnection.h`
- Modify: all `TlsConnect*`, handshake, record, post-handshake, validator, and transport files
- Modify: session and WebSocket TLS call sites

- [ ] Replace the public internal class layout with a forward-declared connection handle and services.
- [ ] Keep the shared TLS state header accessible only within `src/wknetlib/tls`.
- [ ] Add services for negotiated ALPN, version, establishment state, failure classification, cancellation, and send/receive.
- [ ] Run all TLS tests and HTTP/WebSocket TLS-path tests.

### Task 9: Make HTTP/2 connections opaque

**Files:**
- Create: `src/wknetlib/http2/Http2ConnectionPrivate.hpp`
- Modify: `src/wknetlib/http2/Http2Connection.*`
- Modify: `src/wknetlib/http2/Http2Stream.*`
- Modify: session and WebSocket HTTP/2 call sites

- [ ] Export only connection handle services and value-type request/response descriptors.
- [ ] Move stream tables, windows, settings, locks, and transport references to the HTTP/2 private state.
- [ ] Provide services for reusable state, stream release, concurrency limits, ping, GOAWAY, shutdown, and extended CONNECT.
- [ ] Run frame, HPACK, HTTP/2 client, HTTP API, and WebSocket tests.

## Chunk 4: Strict pooled-connection ownership

### Task 10: Hide `PooledConnection` layout

**Files:**
- Modify: `src/wknetlib/session/ConnectionPool.h`
- Modify: `src/wknetlib/session/ConnectionPool.cpp`
- Modify: all session dispatch, route, redirect, proxy, send, cache, and WebSocket call sites

- [ ] Move `PooledConnection` and `ConnectionPool` layouts into `ConnectionPool.cpp` or a private header included only there.
- [ ] Add borrowed-handle getters for transport, TLS, HTTP/2, and net socket services.
- [ ] Add mutators for ALPN, proxy tunnel state, connection state, adoption, release, and lease transitions.
- [ ] Remove every external direct field access.
- [ ] Run architecture checks and all connection-pool/HTTP/HTTP2/WebSocket tests.

## Chunk 5: Project cleanup, documentation, and full verification

### Task 11: Clean project metadata and old names

**Files:**
- Modify: `src/wknetlib/wknetlib.vcxproj`
- Modify: `src/wknetlib/wknetlib.vcxproj.filters`
- Modify: `src/wknettest/wknettest.vcxproj*`
- Rename/update old `Khttp` test/sample/source names
- Modify: integration scripts and wiki sync tool

- [ ] Remove every nonexistent project item.
- [ ] Align filters with actual rtl/net/tls/http1/http2/ws/transport/session/http_api directories.
- [ ] Replace old product strings and `KERNEL_HTTP_*` variables with `WKNET_*`.
- [ ] Preserve real external repository URLs unless the repository itself has moved.
- [ ] Run architecture checks.

### Task 12: Enforce maximum first-party warnings

**Files:**
- Modify: `tools/build-tests.ps1`

- [ ] Compile first-party C++ with `/Wall /WX /EHsc- /GR-`.
- [ ] Compile third-party Brotli/Zstd separately and link their objects.
- [ ] Remove blanket first-party warning suppressions by fixing diagnostics.
- [ ] Build and run representative tests before the full suite.

### Task 13: Synchronize plans, ledger, README, and docsite

**Files:**
- Modify: `docs/plans/2026-07-12-wknet-rename-map.md`
- Modify: `docs/protocol-completeness-ledger.md`
- Modify: `README.md`, `README_en.md`
- Modify: `docsite/**`, `mkdocs.yml`, wiki sync scripts as required

- [ ] Correct the old-to-new map and architecture-plan location.
- [ ] Replace obsolete implementation paths with current module paths.
- [ ] Document the opaque public certificate API, text proxy endpoint, and internal handle model.
- [ ] Keep docsite changes separable for a later `docsite:` commit.

### Task 14: Full verification

- [ ] Run `pwsh -NoLogo -NoProfile -File .\tools\check-architecture.ps1`.
- [ ] Build and run every `tests/*.cpp` target supported by `tools/build-tests.ps1`; do not run smoke scripts.
- [ ] Build wknetlib Debug and Release x64.
- [ ] Build wknettest Debug and Release x64.
- [ ] Confirm zero first-party warnings and zero errors.
- [ ] Review `git diff --check`, `git status --short`, and the complete diff.
- [ ] Do not commit plan documents; do not commit any change unless separately authorized by the user.
