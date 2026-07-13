<div align="center">

# wknet

**A Pure Kernel-Mode HTTP/HTTPS/WebSocket Client Library for Windows Kernel Drivers**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20Kernel-0078d4.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
[![WDK: 10+](https://img.shields.io/badge/WDK-10%2B-green.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

English | [简体中文](README.md)

</div>

---

## 📖 Introduction

wknet is a pure kernel-mode HTTP/HTTPS client library designed specifically for Windows kernel driver development. Built from the ground up, it implements a kernel-friendly client protocol stack: HTTP/1.1, HTTP/2, WebSocket, and TLS 1.2/1.3 handshake, record protection, and certificate validation. Default security behavior and explicit compatibility capabilities are documented below.

### ✨ Key Features

- **🔒 Pure Kernel-Mode Implementation**: No dependency on WinHTTP, WinINet, SChannel, or other user-mode components
- **🌐 WSK Network Transport**: Uses Windows Sockets Kernel (WSK) with opaque `transport::Transport*` services for plaintext and TLS byte streams
- **🔐 CNG/BCrypt Cryptography**: Uses kernel-mode CNG (Cryptography Next Generation) for cryptographic operations, supporting TLS 1.2/1.3 handshake
- **📡 Explicit Capability Matrix**: Supports the client main paths for HTTP/1.1, HTTP/2 (with h2c plaintext upgrade), WebSocket, and TLS 1.2/1.3, with default capabilities separated from explicit compatibility capabilities
- **🔄 Connection Pool Management**: Built-in connection pool with connection reuse, idle timeout, concurrency protection, and automatic management
- **⚡ Asynchronous Operations**: Supports async requests with concurrency protection and workspace isolation, avoiding blocking kernel threads
- **🎯 Single Product API Surface**: Public APIs are limited to `wknet::http` / `wknet::websocket` / `wknet::crypto` / `wknet::codec`
- **🛡️ Certificate Verification**: Supports Certificate Pinning, Trust Anchors, SPKI hash verification, and TLS 1.3 signature scheme validation
- **📦 Response Encoding**: Supports `Content-Encoding: gzip/deflate/br/compress/zstd/dcz/aes128gcm/exi/pack200-gzip/identity`; EXI covers EXI 1.0 without an external Schema, Pack200 covers Java 5–8 stable formats, and HTTP/1.1 `Transfer-Encoding` supports `chunked/gzip/deflate/compress` chains
- **🧱 Heap Memory Management**: Uses `HeapObject<T>` / `HeapArray<T>` for unified heap memory management, high-frequency buffers resident in Workspace

### Protocol Capability Ledger

wknet separates implemented behavior, default-off capabilities, security refusals, missing/non-goal capabilities, and implementation strategy. This is meant to make the actual gaps visible instead of mixing them with policy choices.

**Implemented / Verified Capabilities**

| Protocol | Current usable behavior |
|----------|-------------------------|
| HTTP/1.1 | `Content-Length`, library-generated chunked, true streaming request bodies (`BodyCreateStream` / `HttpRequestSetBodySource`), request trailers on the chunked path, `Expect: 100-continue`, explicit opt-in TRACE, typed Range/conditional request helpers, response `Transfer-Encoding` chains (`chunked`/`gzip`/`deflate`/`compress`), close-delimited responses, HEAD/101/no-body status codes, intermediate 1xx skipping, chunked trailer validation and read-only API exposure, read-only `206` / `Content-Range` parsing, RFC 3986 relative redirects, CONNECT request construction, HTTPS CONNECT proxy, plaintext HTTP proxy absolute-form, session-enabled HTTP/1.1 pipelining (off by default, FIFO response binding) |
| HTTP/2 | TLS ALPN, h2c prior knowledge / Upgrade, SETTINGS including `ENABLE_CONNECT_PROTOCOL`, HEADERS/CONTINUATION, DATA body sources, request/response trailers, explicit per-request PRIORITY, explicit `SendPing`, session-enabled background PING keepalive (off by default), GOAWAY/RST retry semantics, WINDOW_UPDATE, HPACK, header-block semantic validation, HPACK header-list/table-size limits, active-stream table, two-stage `BeginRequest` / `ReceiveResponse(streamId)`, RFC 8441 extended CONNECT DATA tunnel, high-level pooled multi-stream reuse |
| WebSocket | ws/wss handshake, constant-time accept check, caller-supplied opening handshake headers, text/binary send, empty messages, fragment send (`wknet::websocket::SendContinuation`), receive-fragment callback (`ReceiveOptions.DeliverFragments` / `OnMessage`), control-frame validation, auto-Pong, public Ping/Pong/CloseEx, selected subprotocol query, cross-fragment UTF-8 validation, complete-message aggregation by default, automatic-by-default RFC 8441 WebSocket over HTTP/2 for `wss` (`h2,http/1.1` offer; use `Http11Only` to force HTTP/1.1) |
| TLS and certificates | TLS 1.2/1.3, standard TLS 1.3 cipher suites, TLS 1.2 ECDHE/DHE plus compatibility-profile RSA key exchange, AES-GCM/AES-CBC/ChaCha20-Poly1305, X25519/X448/NIST P curves/FFDHE, RSA-PSS/RSA-PKCS1/ECDSA/Ed25519/Ed448 signature schemes, SNI, ALPN, PSK/session ticket, 0-RTT, reactive KeyUpdate, record padding, client certificates (mTLS), OCSP stapling parse, certificate chain reordering and validation, Name Constraints, certificatePolicies, IDNA, OCSP/CRL DER revocation evidence validation, revocation provider callback, SPKI pin |
| Pack200 | Java 5–8 stable formats `150.7`/`160.1`/`170.1`/`171.0`; raw/gzip, multiple segments, class/file/bytecode reconstruction, custom attribute layouts in class/field/method/code contexts, overflow indexes, constant-pool and BCI relocation; emits a semantically equivalent JAR; real corpora include SHA-256/provenance |
| EXI | W3C EXI 1.0 Second Edition streams without an external Schema; all four alignments, Options, fidelity features, built-in XML Schema datatypes, `xsi:type`, and `xsi:nil`; emits Infoset-equivalent XML; external Schema/strict grammar streams return `STATUS_NOT_SUPPORTED` |

**Default-Off / Explicit Opt-In**

These capabilities are implemented but not enabled by default; they are not missing.

| Capability | How it is enabled |
|------------|-------------------|
| `Expect: 100-continue` | `SendFlagExpectContinue` |
| TRACE method | `SendFlagAllowTrace`; bodies, trailers, and sensitive headers remain rejected |
| HTTP/1.1 pipelining | Session `EnableHttp11Pipeline=true`; depth and method mask are configurable, defaulting to `GET`/`HEAD`/`OPTIONS` only |
| h2c prior knowledge / Upgrade | `SendOptions.Http2CleartextMode`; plaintext HTTP/2 is off by default |
| HTTP/2 background PING keepalive | Session `Http2KeepAlive.Enabled=true`; idle, interval, and ACK timeout values are configurable |
| HTTP/2 per-request priority | `SendOptions.Http2Priority` / `HttpSendOptions.Http2Priority` |
| HTTP/3 prior knowledge | Set `SessionConfig.Http3.Mode=Http3ConnectMode::Required` to explicitly require H3 for an HTTPS origin; this is for known prior-knowledge/test scenarios. In M6, the default `Auto` still normalizes to `Disabled` and never selects H3 transparently |
| WebSocket permessage-deflate | `ConnectConfig.PerMessageDeflate.Enable=true`; compression is not offered by default |
| TLS 1.2 RSA key exchange / CBC / SHA-1 signatures | `CompatibilityExplicit` policy plus the matching compatibility switches |
| TLS 1.2 true renegotiation | `CompatibilityExplicit` + `EnableTls12Renegotiation`, limited by `MaxTls12Renegotiations` |
| TLS 1.3 0-RTT | Enable early data and mark the request replay-safe |
| TLS 1.3 post-handshake client auth | Enable the policy; signatures use the mTLS callback and private keys never enter the library |
| Hard revocation requirement | `RequireRevocationCheck`; missing verifiable caller-provided or provider-returned OCSP/CRL DER evidence fails closed |

**Security Refusals / Policy Constraints**

These are deliberate security or protocol choices, not missing implementation.

| Behavior | Handling |
|----------|----------|
| Caller-supplied request `Transfer-Encoding` / `TE` | Rejected; request framing is generated and validated by the library |
| HTTP/1.1 request trailers | Allowed only on the chunked request path |
| HTTP `br` Transfer-Encoding | Rejected; `br` is supported only as `Content-Encoding` |
| HTTP/2 `PUSH_PROMISE` | Server push is disabled and treated as a protocol error |
| Unexpected WebSocket extensions | Rejected; permessage-deflate is used only after explicit opt-in and successful negotiation |
| WebSocket handshake redirect / 401 / 407 | Not followed automatically; returns `STATUS_NOT_SUPPORTED` |
| TLS 1.3 to TLS 1.2 | No in-handshake automatic fallback; only verified version-negotiation evidence allows an explicit caller retry at 1.2 |
| Certificate hostname matching | IP literals match iPAddress SAN only; DNS names never fall back to CN |
| HTTPS redirect to HTTP | Rejected by default |
| RFC 9111 cache | Explicit in-memory kernel cache API; supports fresh hits, validation, `Vary`, private/shared rules, unsafe-method invalidation, and Range/206 partial combining |

**Missing / Explicit Non-Goals**

These capabilities are not provided today. Capabilities that are implemented but off by default are listed only in the previous section.

| Capability | Current conclusion |
|------------|--------------------|
| HTTP inbound request parser / server role | Non-goal; this project is a client protocol stack |
| Persistent on-disk HTTP cache | Non-goal; RFC 9111 cache is an explicit in-memory NonPaged object and is not persisted across reboot |
| Complex local HTTP/2 priority-tree scheduling | Non-goal; no local dependency tree or bandwidth scheduler is maintained |
| WebSocket extensions other than `permessage-deflate` | Non-goal; no other extensions are negotiated |
| Online OCSP/CRL fetching | Non-goal; callers provide external trust/certificate/revocation data or cached entries |
| Transparent HTTP/3 / QUIC Auto | The main path is under construction; `Required` configuration is for explicit prior-knowledge/testing, while `Auto` stays disabled until every gate passes |

**Implementation strategy and trust model**:

- The transport main path uses WSK; TLS, HTTP, and certificate validation are implemented in the kernel path.
- Cryptography uses kernel-mode CNG/BCrypt first. ChaCha20-Poly1305, AES-CCM, X25519, X448, FFDHE, and Ed25519/Ed448 verification are filled in by in-kernel software implementations.
- WinHTTP, WinINet, and SChannel are not used as the kernel main path.
- The library does not hard-code system CAs; callers explicitly provide trust anchors, CA bundles, revocation cache entries, and pins.

Automatic redirects reject HTTPS-to-HTTP downgrades by default. Cross scheme/host/port redirects strip `Authorization`, `Cookie`, and `Proxy-Authorization`. 301/302 rewrite POST to GET by default, 303 rewrites every method except HEAD to GET, and 307/308 preserve method and body. Reused stale-connection failures are retried fresh only for safe/idempotent requests such as `GET`, `HEAD`, and `OPTIONS`; POST/PUT/PATCH/DELETE are not replayed automatically.

Close-delimited HTTP/1.x responses and `101 Switching Protocols` upgrade responses are not returned to the normal HTTP connection pool. Synchronous HTTP, WebSocket, TLS, and certificate validation paths require `PASSIVE_LEVEL`. TLS ALPN results must come from the client's offered list. TLS1.2 selection after a TLS1.3 attempt is allowed only after verified version-negotiation evidence; certificate errors, ALPN mismatch, network timeout, or record decryption failure are not TLS1.2-only evidence. TLS 1.3 0-RTT is off by default; even when enabled, callers must explicitly mark the request as replay-safe, otherwise the connection returns `STATUS_NOT_SUPPORTED` without sending early data.
For certificate host validation, IP literals match only iPAddress SAN entries and do not fall back to dNSName or CN.

---

## 🚀 Quick Start

### 📋 Prerequisites

| Component | Version Requirement |
|-----------|-------------------|
| Operating System | Windows 10/11 or Windows Server 2016+ |
| Visual Studio | 2022 or later |
| Windows SDK | 10.0.19041.0 or later |
| Windows Driver Kit (WDK) | Matching SDK version |

### 📦 Installation & Build

#### step1: build Static Library

1. **Clone Repository**
   ```bash
   git clone https://github.com/x500x/wknet.git
   cd wknet
   ```

2. **Build with Visual Studio**
   
   Open `wknet.sln`, select configuration and platform:
   
   | Configuration | Description |
   |---------------|-------------|
   | Debug | Debug version with debug symbols |
   | Release | Release version with optimizations |
   
   | Platform | Description |
   |----------|-------------|
   | x64 | 64-bit Intel/AMD processors |
   | ARM64 | ARM 64-bit processors |
   
   Then press `Ctrl+Shift+B` to build the solution.

3. **Build via Command Line**
   ```powershell
   # Build wknetlib for all kernel ABIs (x64, ARM64)
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
   
   # Build a single ABI
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
   
   # The script checks the MSVC/WDK toolchain for each ABI before building
   
   # Debug version
   msbuild wknet.sln /p:Configuration=Debug /p:Platform=x64
   
   # Release version
   msbuild wknet.sln /p:Configuration=Release /p:Platform=x64
   ```

4. **Get Library Files**
   
   After building, library files are located at:
   ```
   <Platform>/<Configuration>/wknetlib.lib
   ```

#### step2: Integrate into Your Project

1. **Include Headers**
   ```cpp
   // Main header entry point (recommended)
   #include <wknet/Wknet.h>
   ```

2. **Link Library**
   Add to project properties:
   - Additional Include Directories: `$(SolutionDir)include`
   - Additional Library Directories: `$(SolutionDir)src\wknetlib\$(Platform)\$(Configuration)\`
   - Additional Dependencies: `wknetlib.lib`

3. **Configure Project Dependencies**
   - Add `wknetlib` project to your solution
   - Set project dependency to ensure `wknetlib` builds first

---

## 📚 API Overview

Common wknet entry namespaces:

| Namespace | Purpose | Use Case |
|-----------|---------|----------|
| `wknet::http` | High-level HTTP API | Most application scenarios, rapid development |
| `wknet::websocket` | High-level WebSocket API | ws/wss I/O (header `websocket/WebSocket.h`) |
| `wknet::crypto` / `wknet::codec` | Public crypto and codec APIs | Direct reuse outside HTTP sessions |

> ⚠️ All WebSocket calls are in the `wknet::websocket` namespace (e.g. `wknet::websocket::Connect`/`wknet::websocket::SendText`/`wknet::websocket::Receive`/`wknet::websocket::Close`), while the session is still `wknet::http::Session`.

### Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      Product API (wknet::http)                  │
│  Simple interface, auto resource mgmt, for most scenarios    │
├─────────────────────────────────────────────────────────────┤
│                      Internal session layer (wknet::session)                  │
│  Fine-grained control, perf optimization, test hooks         │
├─────────────────────────────────────────────────────────────┤
│                    Transport Adapters (wknet::transport)      │
│  opaque Transport services | WSK/TLS | ProxyConnect         │
├─────────────────────────────────────────────────────────────┤
│                    Protocol Implementation Layer              │
│  HTTP/1.1 | HTTP/2 (HPACK) | WebSocket | TLS 1.2/1.3        │
├─────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                       │
│  WSK Network Transport | CNG/BCrypt Crypto | Connection Pool │
└─────────────────────────────────────────────────────────────┘
```

For the full API reference, see the **[project Wiki](https://github.com/x500x/wknet/wiki)** and the **[online docs site](https://x500x.github.io/wknet/)**.

### 🔥 High-Level API Example

```cpp
#include <wknet/Wknet.h>

// Simple HTTP GET request
NTSTATUS SimpleHttpGet() {
    // Create session
    wknet::http::Session* session = nullptr;
    NTSTATUS status = wknet::http::SessionCreate(&session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Send GET request
    wknet::http::Response* response = nullptr;
    status = wknet::http::GetEx(session, "http://example.com/api", 22, nullptr, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        // Get status code
        ULONG statusCode = wknet::http::ResponseStatusCode(response);
        
        // Get response body
        const UCHAR* body = wknet::http::ResponseBody(response);
        SIZE_T bodyLength = wknet::http::ResponseBodyLength(response);
        
        // Process response...
        
        // Release response
        wknet::http::ResponseRelease(response);
    }

    // Close session
    wknet::http::SessionClose(session);
    return status;
}
```

### 🔧 Low-Level API Example

```cpp
#include <wknet/Wknet.h>

// Fine-grained HTTPS request
NTSTATUS AdvancedHttpsRequest(net::WskClient& wskClient) {
    // Create session with TLS configuration
    SessionHandle session = nullptr;
    SessionOptions sessionOptions = {};
    sessionOptions.Tls.CertificatePolicy = CertificatePolicy::Verify;
    sessionOptions.Tls.MinVersion = TlsVersion::Tls13;
    
    NTSTATUS status = SessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create request
    RequestHandle request = nullptr;
    status = HttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        SessionClose(session);
        return status;
    }

    // Configure request
    const char* url = "https://api.example.com/data";
    HttpRequestSetUrl(request, url, strlen(url));
    HttpRequestSetMethod(request, HttpMethod::Get);
    HttpRequestSetHeader(request, "User-Agent", 10, "wknet/1.0", 14);

    // Send request
    ResponseHandle response = nullptr;
    status = HttpSendSync(session, request, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        // Get response view
        ResponseView view = {};
        ResponseGetView(response, &view);
        
        // Process response...
        
        ResponseRelease(response);
    }

    // Cleanup resources
    HttpRequestRelease(request);
    SessionClose(session);
    return status;
}
```

### 🔌 WebSocket example (`wknet::websocket`)

```cpp
#include <wknet/Wknet.h>

NTSTATUS WebSocketEcho() {
    wknet::http::Session* session = nullptr;
    NTSTATUS status = wknet::http::SessionCreate(&session);
    if (!NT_SUCCESS(status)) return status;

    wknet::websocket::WebSocket* ws = nullptr;             // WebSocket handle lives in the `wknet::websocket` namespace
    status = wknet::websocket::Connect(session, "wss://echo.example/ws", 21, &ws);
    if (NT_SUCCESS(status)) {
        wknet::websocket::SendText(ws, "hello", 5);

        wknet::websocket::Message msg = {};
        if (NT_SUCCESS(wknet::websocket::Receive(ws, &msg)) && msg.Type == wknet::websocket::MsgType::Text) {
            // use msg.Data / msg.DataLength (valid until the next receive/close)
        }
        wknet::websocket::Close(ws);                        // full-duplex: never concurrent with new I/O on the same handle
    }
    wknet::http::SessionClose(session);
    return status;
}
```

> Fragment send via `wknet::websocket::SendContinuation`; receive-fragment callback via `wknet::websocket::ReceiveOptions.OnMessage`.

---

## 🏗️ Project Structure

```
wknet/
├── include/wknet/                    # Stable public API only
│   ├── Wknet.h                       # Umbrella header
│   ├── http/                         # wknet::http
│   ├── websocket/                    # wknet::websocket
│   ├── crypto/                       # wknet::crypto
│   ├── codec/                        # wknet::codec
│   └── test/                         # Narrow WKNET_USER_MODE_TEST hooks
├── src/wknetlib/                     # Kernel static-library implementation
│   ├── rtl/                          # Heap, tracing, text, URL
│   ├── net/                          # WSK lifecycle and sockets
│   ├── crypto/                       # CNG and software cryptography
│   ├── tls/                          # TLS 1.2/1.3 and certificate validation
│   ├── codec/                        # Content-Encoding, EXI, Pack200
│   ├── transport/                    # opaque Transport, WSK/TLS, proxy CONNECT
│   ├── http1/ / http2/ / ws/        # Protocol layers
│   ├── session/                      # Sessions, pool, HTTP/WS orchestration
│   └── http_api/                     # Thin public-API bridge
├── src/wknettest/                    # Kernel test driver and public-API samples
├── tests/                            # User-mode protocol and API tests
└── tools/                            # pwsh build scripts
│       └── samples/                 # Example code
├── tests/                            # Test code
├── docs/                             # Planning and audit documents
├── docsite/                          # MkDocs online documentation source
├── certs/                            # Certificate related
└── tools/                            # Tool scripts
```

---

## 📖 Documentation

Full documentation now lives in the **GitHub Wiki** and an **online docs site** (bilingual, grounded in the actual code):

- 📚 **[Project Wiki](https://github.com/x500x/wknet/wiki)** — capability matrix, architecture, HTTP/1.1, HTTP/2 & HPACK, WebSocket, TLS & certificates, cryptography, product API, transport, connection pool, async, memory, NTSTATUS, cookbook, FAQ, roadmap, glossary, and more.
- 🌐 **[Online docs site](https://x500x.github.io/wknet/)** — the same content as a MkDocs Material site with full-text search and dark mode.

| Topic | Link |
|-------|------|
| Capability Matrix | [Capability Matrix](https://github.com/x500x/wknet/wiki/Capability-Matrix) |
| Product API (http/websocket/crypto/codec) | [High-Level API](https://github.com/x500x/wknet/wiki/High-Level-API) |
| Internal session layer (wknet::session) | [Low-Level API](https://github.com/x500x/wknet/wiki/Low-Level-API) |
| TLS & Certificates | [TLS & Certificates](https://github.com/x500x/wknet/wiki/TLS-and-Certificates) |
| NTSTATUS Reference | [NTSTATUS Reference](https://github.com/x500x/wknet/wiki/NTSTATUS-Reference) |

---

## 🔧 Configuration Options

### Session Configuration

```cpp
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();

// Response buffer size (default 0 means unlimited and grows on demand from heap)
config.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB

// Request construction buffer (default 16 KiB; increase for large bodies)
config.RequestBufferBytes = 96 * 1024;

// Connection pool capacity (default 8)
config.PoolCapacity = 16;

// Max connections per host (default 2)
config.MaxConnsPerHost = 4;

// Idle timeout (default 30 seconds)
config.IdleTimeoutMs = 60000;  // 60 seconds

// HTTP/3: the public default is Auto, but M6 still normalizes it to Disabled,
// so ordinary callers keep their existing behavior. Required is only for a
// known HTTPS H3 origin or deterministic tests; it rejects plaintext HTTP,
// h2c, HTTP proxies, non-HTTP ALPN, and HTTP/2 priority.
config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
config.Http3.Race = wknet::http::Http3RaceMode::DelayedTcpFallback;
config.Http3.RaceWindowMs = 250;
config.Http3.QuicProbeTimeoutMs = 1500;
config.Http3.AltSvcMaxEntries = 64;
config.Http3.AltSvcMaxAgeSec = 604800;

// Response buffer pool type (default NonPaged; kernel path currently requires NonPaged)
config.ResponsePool = wknet::http::PoolType::NonPaged;

// TLS configuration
config.Tls.MinVersion = wknet::http::TlsVersion::Tls13;
config.Tls.MaxVersion = wknet::http::TlsVersion::Tls13;
config.Tls.Certificate = wknet::http::CertPolicy::Verify;
config.Tls.HandshakeTimeoutMs = 120000;  // TLS handshake timeout (default 120 seconds)
```

### Connection Policy

```cpp
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);

// Connection policy
options->ConnectionPolicy = wknet::http::ConnPolicy::ReuseOrCreate;  // Reuse or create (default)
options->ConnectionPolicy = wknet::http::ConnPolicy::ForceNew;       // Force new connection
options->ConnectionPolicy = wknet::http::ConnPolicy::NoPool;         // Don't use pool

// Address family
options->Family = wknet::http::AddressFamily::Any;                   // System default
options->Family = wknet::http::AddressFamily::Ipv4;                  // IPv4 only
options->Family = wknet::http::AddressFamily::Ipv6;                  // IPv6 only
wknet::http::SendOptionsRelease(options);
```

---

## 🧪 Testing

### Run Tests

```powershell
# Run built user-mode protocol tests
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_parser_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\websocket_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_frame_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\hpack_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http2_client_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_crypto_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_handshake_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_interop_matrix_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\http_api_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'

# Local TLS interop matrix: uses 127.0.0.1 only; reports explicit SKIP when OpenSSL/BoringSSL is absent
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64

# Build library and example driver
msbuild wknet.sln /m /restore /p:Configuration=Debug /p:Platform=x64
```

### Test Files

| Test File | Test Content |
|-----------|--------------|
| `http_parser_tests.cpp` | HTTP parser |
| `hpack_tests.cpp` | HTTP/2 HPACK encoding/decoding |
| `http2_frame_tests.cpp` | HTTP/2 frame processing |
| `http2_client_tests.cpp` | HTTP/2 client tests |
| `tls_crypto_tests.cpp` | TLS crypto vectors and key exchange |
| `tls_handshake_tests.cpp` | TLS ClientHello/handshake encoding and parsing |
| `tls_record_tests.cpp` | TLS record protocol |
| `tls_interop_matrix_tests.cpp` | TLS capability/policy/interop matrix manifest |
| `tests/integration/tls_matrix.ps1` | Local OpenSSL/BoringSSL loopback interop matrix |
| `websocket_frame_tests.cpp` | WebSocket frame processing |
| `http_api_tests.cpp` | Product HTTP API tests |
| `high_level_api_tests.cpp` | High-level API integration tests |
| `websocket_client_tests.cpp` | WebSocket client tests |

---

## ⚠️ Error Handling

The project uses Windows NTSTATUS error codes. For detailed information, see [NTSTATUS Code Reference](docsite/ntstatus-reference.md).

### Common Error Codes

| NTSTATUS | Description | Suggestion |
|----------|-------------|------------|
| `STATUS_SUCCESS` | Operation succeeded | - |
| `STATUS_INVALID_PARAMETER` | Invalid parameter | Check input parameters |
| `STATUS_INSUFFICIENT_RESOURCES` | Insufficient resources | Reduce concurrent requests or add resources |
| `STATUS_IO_TIMEOUT` | Operation timed out | Increase timeout or check network |
| `STATUS_CONNECTION_DISCONNECTED` | Connection disconnected | Retry request |
| `STATUS_TRUST_FAILURE` | Certificate trust failure | Check certificate configuration |

### Error Handling Example

```cpp
NTSTATUS status = wknet::http::GetEx(session, url, urlLength, nullptr, nullptr, &response);
if (!NT_SUCCESS(status)) {
    switch (status) {
    case STATUS_IO_TIMEOUT:
        // Timeout handling: retry or report error
        DbgPrint("Request timed out\n");
        break;
    case STATUS_TRUST_FAILURE:
        // Certificate error: check certificate configuration
        DbgPrint("Certificate verification failed\n");
        break;
    case STATUS_CONNECTION_DISCONNECTED:
        // Connection lost: reconnect
        DbgPrint("Connection lost, retrying...\n");
        break;
    default:
        // Other errors: log
        DbgPrint("Request failed: 0x%08X\n", status);
        break;
    }
}
```

---

## 🎯 Best Practices

### 1. Resource Management

```cpp
// ✅ Correct: Ensure resources are released on all paths
NTSTATUS DoRequest(wknet::http::Session* session) {
    wknet::http::Response* response = nullptr;
    NTSTATUS status = wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &response);
    
    // Release response even on failure
    if (NT_SUCCESS(status)) {
        // Process response...
    }
    
    wknet::http::ResponseRelease(response);  // Accepts nullptr, safe to call unconditionally
    return status;
}

// ❌ Wrong: Response not released on failure
NTSTATUS DoRequestWrong(wknet::http::Session* session) {
    wknet::http::Response* response = nullptr;
    NTSTATUS status = wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &response);
    if (!NT_SUCCESS(status)) {
        return status;  // Leak! response might be non-null
    }
    // ...
    wknet::http::ResponseRelease(response);
    return status;
}
```

### 2. Connection Reuse

```cpp
// ✅ Correct: Use connection pool for reuse
wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
config.PoolCapacity = 16;        // Increase pool capacity
config.MaxConnsPerHost = 4;      // Increase per-host connections
config.IdleTimeoutMs = 120000;   // Extend idle timeout

// ❌ Avoid: Forcing a new connection on every request
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);
options->ConnectionPolicy = wknet::http::ConnPolicy::ForceNew;
wknet::http::SendOptionsRelease(options);
```

### 3. Asynchronous Operations

```cpp
// ✅ Correct: Use async to avoid blocking
wknet::http::AsyncOp* op = nullptr;
wknet::http::AsyncGetEx(session, url, urlLen, nullptr, nullptr, &op);
wknet::http::AsyncWait(op, 30000);  // Wait 30 seconds

// Process response...
wknet::http::AsyncRelease(op);
// Driver unload path: wknet::http::Destroy();

// ❌ Avoid: Long synchronous waits in kernel thread
wknet::http::GetEx(session, url, urlLen, nullptr, nullptr, &response);  // May block for a long time
```

---

## 📊 Performance Optimization

### Connection Pool Configuration

```cpp
// Adjust connection pool parameters based on application needs
config.PoolCapacity = 32;           // Increase pool capacity
config.MaxConnsPerHost = 8;         // Increase per-host connections
config.IdleTimeoutMs = 120000;      // Extend idle timeout
```

### Buffer Management

```cpp
// Response buffer (0 means unlimited)
config.MaxResponseBytes = 4 * 1024 * 1024;  // 4 MiB

// Request construction buffer; it must hold the HTTP/1.1 request line, headers, and body
config.RequestBufferBytes = 96 * 1024;

// Per-send response limit override
wknet::http::SendOptions* options = nullptr;
wknet::http::SendOptionsCreate(&options);
options->MaxResponseBytes = 0;  // 0 means no caller-imposed response body limit
wknet::http::SendOptionsRelease(options);
```

---

## 🔐 Security Considerations

### TLS Configuration

```cpp
// Recommended: Use TLS 1.3
config.Tls.MinVersion = wknet::http::TlsVersion::Tls13;
config.Tls.MaxVersion = wknet::http::TlsVersion::Tls13;

// Certificate verification
config.Tls.Certificate = wknet::http::CertPolicy::Verify;

// TLS handshake timeout (default 120 seconds)
config.Tls.HandshakeTimeoutMs = 120000;

// Custom certificate store
wknet::http::CertificateStore* store = nullptr;
NTSTATUS status = wknet::http::CertificateStoreCreate(nullptr, &store);
config.Tls.Store = store;
```

### TLS 1.3 Security Enhancements

The project implements the following TLS 1.3 security hardening:

- **Signature Scheme Validation**: Strictly validates server certificate signature algorithms, rejecting weak schemes
- **Downgrade Protection**: Prevents protocol downgrade attacks from TLS 1.3 to TLS 1.2
- **PSK/HRR Validation**: TLS 1.3 tickets bind issue time, SNI, ALPN, cipher, and version; PSK binders are recomputed after HelloRetryRequest
- **0-RTT Policy**: Disabled by default; enabling it requires the caller to mark the request replay-safe
- **Key Zeroization**: Securely zeros all key materials after session termination
- **Trust Anchor Validation**: Validates certificate chain integrity to trusted roots

### Certificate Pinning

```cpp
// Use certificate pinning for enhanced security
wknet::http::CertificateTrustAnchor anchor = {};
anchor.SubjectName = rootCertSubject;
anchor.SubjectNameLength = rootCertSubjectLen;
RtlCopyMemory(anchor.SubjectPublicKeySha256, rootSpkiHash, 32);
anchor.MatchSubjectPublicKey = true;

wknet::http::CertificatePin pin = {};
pin.HostName = "example.com";
pin.HostNameLength = 11;
RtlCopyMemory(pin.LeafSubjectPublicKeySha256, leafSpkiHash, 32);

// Create certificate store
wknet::http::CertificateStoreOptions storeOptions = {};
storeOptions.TrustAnchors = &anchor;
storeOptions.TrustAnchorCount = 1;
storeOptions.Pins = &pin;
storeOptions.PinCount = 1;

wknet::http::CertificateStore* store = nullptr;
NTSTATUS status = wknet::http::CertificateStoreCreate(&storeOptions, &store);

// Apply to session
config.Tls.Store = store;

// Release the caller-owned store after SessionClose.
wknet::http::CertificateStoreClose(store);
```

### ALPN Protocol Negotiation

```cpp
// Set ALPN protocol (for HTTP/2 negotiation)
config.Tls.Alpn = "h2";
config.Tls.AlpnLength = 2;

// Or support both HTTP/1.1 and HTTP/2
// session derives the internal offer list from PreferHttp2 and explicit Alpn
```

---

## 🛠️ Development Guidelines

### Code Style

- Use C++17 features, but follow kernel constraints
- **No exceptions**, **No RTTI**; avoid direct `new/delete` and prefer project heap wrappers or API release functions
- Use `namespace`, classes, RAII, lightweight templates
- All functions marked `noexcept`
- Use SAL annotations (`_In_`, `_Out_`, `_Must_inspect_result_`, etc.)

### Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
feat: Add new feature
fix: Fix bug
docs: Documentation update
style: Code style adjustment
refactor: Code refactoring
test: Test related
chore: Build/tool related
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'feat: Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Create a **Pull Request**

### Contribution Requirements

- Follow project code style
- Add necessary tests
- Update related documentation
- Ensure all tests pass

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🔗 Related Resources

- [Windows Driver Kit (WDK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [Windows Sockets Kernel (WSK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/windows-sockets-kernel)
- [Cryptography Next Generation (CNG)](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-features)

---

## 📞 Contact

For questions or suggestions, please contact us through:

- Submit an [Issue](https://github.com/x500x/http/issues) to the project repository
- View project documentation and example code
- Reference related technical documentation

---

## 🙏 Acknowledgments

Thanks to all developers who have contributed to the project!

---

<div align="center">

**[⬆ Back to Top](#wknet)**

</div>
