<div align="center">

# KernelHttp

**A Pure Kernel-Mode HTTP/HTTPS Client Library for Windows Kernel Drivers**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20Kernel-0078d4.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
[![WDK: 10+](https://img.shields.io/badge/WDK-10%2B-green.svg)](https://docs.microsoft.com/en-us/windows-hardware/drivers/develop/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)

English | [简体中文](README.md)

</div>

---

## 📖 Introduction

KernelHttp is a pure kernel-mode HTTP/HTTPS client library designed specifically for Windows kernel driver development. Built from the ground up, it implements a kernel-friendly client protocol stack: HTTP/1.1, HTTP/2, WebSocket, and TLS 1.2/1.3 handshake, record protection, and certificate validation. Default security behavior and explicit compatibility capabilities are documented below.

### ✨ Key Features

- **🔒 Pure Kernel-Mode Implementation**: No dependency on WinHTTP, WinINet, SChannel, or other user-mode components
- **🌐 WSK Network Transport**: Uses Windows Sockets Kernel (WSK) for network communication, with `ITransport` abstraction supporting WSK and TLS transport layers
- **🔐 CNG/BCrypt Cryptography**: Uses kernel-mode CNG (Cryptography Next Generation) for cryptographic operations, supporting TLS 1.2/1.3 handshake
- **📡 Explicit Capability Matrix**: Supports the client main paths for HTTP/1.1, HTTP/2 (with h2c plaintext upgrade), WebSocket, and TLS 1.2/1.3, with default capabilities separated from explicit compatibility capabilities
- **🔄 Connection Pool Management**: Built-in connection pool with connection reuse, idle timeout, concurrency protection, and automatic management
- **⚡ Asynchronous Operations**: Supports async requests with concurrency protection and workspace isolation, avoiding blocking kernel threads
- **🎯 Two-Layer API**: Provides both high-level simplified API (`khttp`) and low-level fine-grained control API (`engine`)
- **🛡️ Certificate Verification**: Supports Certificate Pinning, Trust Anchors, SPKI hash verification, and TLS 1.3 signature scheme validation
- **📦 Response Encoding**: Supports `Content-Encoding: gzip/deflate/br/compress/identity` and HTTP/1.1 response `Transfer-Encoding` chains for `chunked/gzip/deflate/compress`
- **🧱 Heap Memory Management**: Uses `HeapObject<T>` / `HeapArray<T>` for unified heap memory management, high-frequency buffers resident in Workspace

### Protocol Capability Boundaries

KernelHttp implements protocol behavior on the Windows kernel path: transport uses WSK first, cryptography uses CNG/BCrypt first, and the library does not depend on WinHTTP, WinINet, or SChannel. Current boundaries:

| Protocol | Supported | Current Boundary |
|----------|-----------|------------------|
| HTTP/1.1 | `Content-Length`, explicit chunked request bodies, request trailers on the chunked path, response `Transfer-Encoding` chains (`chunked`/`gzip`/`deflate`/`compress`), close-delimited responses, HEAD/101/no-body status codes, intermediate 1xx skipping, chunked trailer syntax/forbidden-field validation and read-only API exposure, read-only `206` / `Content-Range` parsing, RFC 3986 relative redirect resolution, CONNECT request construction | User-supplied request `Transfer-Encoding`/`TE` is rejected; request trailers are chunked-only; no inbound request parser/server role is provided; `HttpsClient` supports explicit HTTP/1.1 CONNECT proxy tunneling, but session-wide high-level proxy configuration is not exposed; TRACE is unsupported; `Range`/conditional requests are pass-through headers only; `Accept-Encoding` does not promise full qvalue/content negotiation; `br` is supported only as `Content-Encoding` |
| HTTP/2 | TLS ALPN, h2c prior knowledge / Upgrade, SETTINGS (including `ENABLE_CONNECT_PROTOCOL`), HEADERS/CONTINUATION, DATA, PING, GOAWAY, WINDOW_UPDATE, HPACK, header-block semantic validation, HPACK header-list/table-size limits, active-stream table with two-stage `BeginRequest` / `ReceiveResponse(streamId)`, RFC 8441 extended CONNECT low-level DATA tunnel | High-level `khttp`/`HttpsClient` does not yet provide h2 connection-pool reuse; high-level `kws` does not automatically select RFC 8441; server push and priority are not public capabilities; disabled `PUSH_PROMISE` is a protocol error; missing SETTINGS ACK closes with `SETTINGS_TIMEOUT` |
| WebSocket | ws/wss handshake (constant-time accept check), caller-supplied opening handshake headers (controlled headers and invalid text rejected), text/binary send, empty messages, **fragment send (`kws::SendContinuation`) and receive-fragment callback (`ReceiveOptions.OnMessage`)**, control-frame validation, auto-Pong, public Ping/Pong/CloseEx, selected subprotocol query, cross-fragment UTF-8 validation, complete-message aggregation by default | High-level `kws` main path is HTTP/1.1 Upgrade; extension negotiation is unsupported (rejects `Sec-WebSocket-Extensions`); RFC 8441 exists only as low-level HTTP/2 tunnel primitives; active close sends a close frame then waits for peer close (3 s timeout), received peer close is echoed before closing |
| TLS | TLS 1.2/1.3, all standard TLS 1.3 cipher suites, TLS 1.2 ECDHE/DHE/RSA key exchange, AES-GCM/AES-CBC/ChaCha20-Poly1305, X25519/X448/NIST P curves/FFDHE, RSA-PSS/RSA-PKCS1/ECDSA/Ed25519/Ed448 signature schemes, SNI, ALPN, PSK/session ticket, explicit opt-in 0-RTT, reactive KeyUpdate, record padding, client certificates (mTLS), OCSP stapling parse, certificate chain reordering and validation, Name Constraints, certificatePolicies, IDNA, OCSP/CRL revocation cache, SPKI pin. ChaCha20-Poly1305/AES-CCM/X25519/X448/FFDHE/Ed25519/Ed448 verification are in-kernel software implementations | The default policy does not enable TLS 1.2 RSA key exchange, CBC, renegotiation, or SHA-1 signatures; those require `TlsSecurityProfile::CompatibilityExplicit` plus the matching explicit option. No hard-coded system CA; revocation is offline/table-driven and fail-closed when required-but-absent |

| Unsupported Optional Capability | Current Handling |
|---------------------------------|------------------|
| WebSocket extensions such as permessage-deflate | Out of scope; unexpected server extensions are rejected |
| High-level automatic WebSocket over HTTP/2 RFC 8441 | Deferred; low-level HTTP/2 exposes extended CONNECT tunnel primitives, while `kws` still uses HTTP/1.1 Upgrade |
| Session-wide high-level proxy configuration / TRACE | Session proxy configuration is not exposed; low-level `HttpsClient` can explicitly establish HTTP/1.1 CONNECT proxy tunnels; TRACE is unsupported |
| HTTP inbound request parser / server role | Out of scope; this project is a client protocol stack |
| High-level HTTP/2 connection-pool reuse / server push / priority | Low-level active-stream routing exists; high-level pool reuse is not wired yet; push is disabled, forbidden `PUSH_PROMISE` is a protocol error, and priority is not a public scheduling capability |
| RFC 9111 cache / Range / conditional requests | No kernel cache API is provided; `Range` and conditional request fields are pass-through only and are not semantically merged or validated; response `Content-Range` has read-only parsing |
| Accept-Encoding qvalue/content negotiation | The default header only describes the implemented response decoder subset; callers may override it, but full negotiation semantics are not provided |
| TLS 1.2 RSA key exchange / CBC / renegotiation | Implemented but disabled by default; callers must use `CompatibilityExplicit` policy and enable RSA, CBC, or renegotiation explicitly |
| TLS 1.3 0-RTT | Implemented but disabled by default; callers must enable early data and mark the request replay-safe |
| Online OCSP/CRL fetching | The library does not recursively fetch revocation data; callers provide external trust/certificate/revocation data or cached entries for hard revocation decisions |

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
   git clone https://github.com/x500x/khttp.git
   cd khttp
   ```

2. **Build with Visual Studio**
   
   Open `KernelHttp.sln`, select configuration and platform:
   
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
   # Build KernelHttpLib for all kernel ABIs (x64, ARM64)
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
   
   # Build a single ABI
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
   
   # The script checks the MSVC/WDK toolchain for each ABI before building
   
   # Debug version
   msbuild KernelHttp.sln /p:Configuration=Debug /p:Platform=x64
   
   # Release version
   msbuild KernelHttp.sln /p:Configuration=Release /p:Platform=x64
   ```

4. **Get Library Files**
   
   After building, library files are located at:
   ```
   <Platform>/<Configuration>/KernelHttpLib.lib
   ```

#### step2: Integrate into Your Project

1. **Include Headers**
   ```cpp
   // Main header entry point (recommended)
   #include <KernelHttp/KernelHttp.h>
   ```

2. **Link Library**
   Add to project properties:
   - Additional Include Directories: `$(SolutionDir)include`
   - Additional Library Directories: `$(SolutionDir)src\KernelHttpLib\$(Platform)\$(Configuration)\`
   - Additional Dependencies: `KernelHttpLib.lib`

3. **Configure Project Dependencies**
   - Add `KernelHttpLib` project to your solution
   - Set project dependency to ensure `KernelHttpLib` builds first

---

## 📚 API Overview

Common KernelHttp entry namespaces:

| Namespace | Purpose | Use Case |
|-----------|---------|----------|
| `KernelHttp::khttp` | High-level HTTP API | Most application scenarios, rapid development |
| `KernelHttp::kws` | High-level WebSocket API | ws/wss I/O (header `kws/WebSocket.h`) |
| `KernelHttp::engine` | Low-level API (`Kh*`) | Performance-critical, special customization, testing |

> ⚠️ All WebSocket calls are in the `kws` namespace (e.g. `kws::Connect`/`kws::SendText`/`kws::Receive`/`kws::Close`), while the session is still `khttp::Session`.

### Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      High-Level API (khttp)                  │
│  Simple interface, auto resource mgmt, for most scenarios    │
├─────────────────────────────────────────────────────────────┤
│                      Low-Level API (engine)                  │
│  Fine-grained control, perf optimization, test hooks         │
├─────────────────────────────────────────────────────────────┤
│                    Client Layer (client)                      │
│  HttpClient | HttpsClient | Http2Client | WebSocketClient    │
├─────────────────────────────────────────────────────────────┤
│                    Core Abstraction Layer (core)              │
│  ITransport | IScratchAllocator | Workspace                  │
├─────────────────────────────────────────────────────────────┤
│                    Protocol Implementation Layer              │
│  HTTP/1.1 | HTTP/2 (HPACK) | WebSocket | TLS 1.2/1.3        │
├─────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                       │
│  WSK Network Transport | CNG/BCrypt Crypto | Connection Pool │
└─────────────────────────────────────────────────────────────┘
```

For the full API reference, see the **[project Wiki](https://github.com/x500x/khttp/wiki)** and the **[online docs site](https://x500x.github.io/khttp/)**.

### 🔥 High-Level API Example

```cpp
#include <KernelHttp/KernelHttp.h>

// Simple HTTP GET request
NTSTATUS SimpleHttpGet(net::WskClient& wskClient) {
    // Create session
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Send GET request
    khttp::Response* response = nullptr;
    status = khttp::Get(session, "http://example.com/api", 22, &response);
    
    if (NT_SUCCESS(status)) {
        // Get status code
        ULONG statusCode = khttp::ResponseStatusCode(response);
        
        // Get response body
        const UCHAR* body = khttp::ResponseBody(response);
        SIZE_T bodyLength = khttp::ResponseBodyLength(response);
        
        // Process response...
        
        // Release response
        khttp::ResponseRelease(response);
    }

    // Close session
    khttp::SessionClose(session);
    return status;
}
```

### 🔧 Low-Level API Example

```cpp
#include <KernelHttp/KernelHttp.h>

// Fine-grained HTTPS request
NTSTATUS AdvancedHttpsRequest(net::WskClient& wskClient) {
    // Create session with TLS configuration
    KH_SESSION session = nullptr;
    KhSessionOptions sessionOptions = {};
    sessionOptions.Tls.CertificatePolicy = KhCertificatePolicy::Verify;
    sessionOptions.Tls.MinVersion = KhTlsVersion::Tls13;
    
    NTSTATUS status = KhSessionCreate(&wskClient, &sessionOptions, &session);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create request
    KH_REQUEST request = nullptr;
    status = KhHttpRequestCreate(session, &request);
    if (!NT_SUCCESS(status)) {
        KhSessionClose(session);
        return status;
    }

    // Configure request
    const char* url = "https://api.example.com/data";
    KhHttpRequestSetUrl(request, url, strlen(url));
    KhHttpRequestSetMethod(request, KhHttpMethod::Get);
    KhHttpRequestSetHeader(request, "User-Agent", 10, "KernelHttp/1.0", 14);

    // Send request
    KH_RESPONSE response = nullptr;
    status = KhHttpSendSync(session, request, nullptr, &response);
    
    if (NT_SUCCESS(status)) {
        // Get response view
        KhResponseView view = {};
        KhResponseGetView(response, &view);
        
        // Process response...
        
        KhResponseRelease(response);
    }

    // Cleanup resources
    KhHttpRequestRelease(request);
    KhSessionClose(session);
    return status;
}
```

### 🔌 WebSocket example (`kws` namespace)

```cpp
#include <KernelHttp/KernelHttp.h>

NTSTATUS WebSocketEcho(net::WskClient& wskClient) {
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&wskClient, nullptr, &session);
    if (!NT_SUCCESS(status)) return status;

    kws::WebSocket* ws = nullptr;             // WebSocket handle lives in the kws namespace
    status = kws::Connect(session, "wss://echo.example/ws", 21, &ws);
    if (NT_SUCCESS(status)) {
        kws::SendText(ws, "hello", 5);

        kws::Message msg = {};
        if (NT_SUCCESS(kws::Receive(ws, &msg)) && msg.Type == kws::MsgType::Text) {
            // use msg.Data / msg.DataLength (valid until the next receive/close)
        }
        kws::Close(ws);                        // full-duplex: never concurrent with new I/O on the same handle
    }
    khttp::SessionClose(session);
    return status;
}
```

> Fragment send via `kws::SendContinuation`; receive-fragment callback via `kws::ReceiveOptions.OnMessage`.

---

## 🏗️ Project Structure

```
KernelHttp/
├── include/                          # Public header files
│   └── KernelHttp/
│       ├── KernelHttp.h             # Main header entry point
│       ├── KernelHttpConfig.h       # Configuration options (timeouts, buffer sizes, etc.)
│       ├── client/                  # Client wrappers
│       │   ├── HttpClient.h         # HTTP/1.1 plaintext client
│       │   ├── HttpsClient.h        # HTTPS client (TLS + ALPN auto-select HTTP/1.1 or HTTP/2)
│       │   ├── Http2Client.h        # HTTP/2 client (supports TLS ALPN, h2c Prior Knowledge, h2c Upgrade)
│       │   └── WebSocketClient.h    # WebSocket client (supports ws:// and wss://)
│       ├── core/                    # Core abstraction layer
│       │   ├── ITransport.h         # Transport abstraction interface (Send/Receive/ReceiveWithTimeout)
│       │   ├── IScratchAllocator.h  # Temporary memory allocator interface (TLS handshake, cert validation, etc.)
│       │   ├── TlsTransport.h       # TLS transport adapter (ITransport + TlsConnection, auto encrypt/decrypt)
│       │   ├── WskTransport.h       # WSK transport adapter (ITransport + WskSocket, plaintext transport)
│       │   └── WorkspaceScratchAllocator.h  # Workspace temporary allocator (resident heap memory)
│       ├── khttp/                   # High-level API (KernelHttp::khttp)
│       │   ├── Types.h              # Handle types, enums, config structs, callbacks
│       │   ├── Session.h            # Session create/close
│       │   ├── Request.h            # Request construction (URL, method, headers, body)
│       │   ├── Http.h               # Sync convenience functions (Get/Post/Put/Patch/Delete/Head/Options)
│       │   ├── HttpAsync.h          # Async entry points (GetAsync/PostAsync/SendAsync)
│       │   ├── AsyncOp.h            # Async operation management (Wait/Cancel/GetResponse)
│       │   ├── Response.h           # Response read-only access (StatusCode/Body/Header)
│       │   ├── Detail.h             # Internal bridge interface
│       │   └── Test.h               # Test utilities
│       ├── kws/                     # High-level WebSocket API (KernelHttp::kws)
│       │   └── WebSocket.h          # WebSocket connect/send/fragment/receive/close (kws::Connect, ...)
│       ├── engine/                  # Low-level API (KernelHttp::engine)
│       │   ├── Engine.h             # Complete API definition (Kh* prefix)
│       │   ├── EngineImpl.h         # Engine implementation
│       │   ├── EngineInternal.h     # Internal structures (non-public)
│       │   ├── EngineUtils.h        # Utility functions
│       │   ├── ConnectionPool.h     # Connection pool implementation
│       │   ├── Workspace.h          # Workspace management
│       │   ├── Async.h              # Async operation implementation
│       │   ├── HttpEngine.h         # HTTP engine
│       │   ├── WsEngine.h           # WebSocket engine
│       │   ├── UrlParser.h          # URL parser
│       │   ├── HandleAlloc.h        # Handle allocator
│       │   └── HandleTypes.h        # Handle type definitions
│       ├── http/                    # HTTP protocol
│       │   ├── HttpTypes.h          # Base types (HttpText/HttpHeader/HeapArray/HeapObject)
│       │   ├── HttpParser.h         # HTTP response parser
│       │   ├── HttpRequest.h        # HTTP request builder
│       │   ├── HttpResponse.h       # HTTP response structure
│       │   ├── HttpCoding.h          # Shared coding decoder (gzip/deflate/br/compress)
│       │   ├── HttpContentEncoding.h # Content encoding (gzip/deflate/br)
│       │   └── HttpTransferCoding.h  # HTTP/1.1 Transfer-Encoding chain parser
│       ├── http2/                   # HTTP/2 protocol
│       │   ├── Http2Frame.h         # Frame types, SETTINGS, frame codec
│       │   ├── Http2Stream.h        # Stream state machine
│       │   ├── Http2Connection.h    # Connection management (preface, SETTINGS exchange, frame loop)
│       │   ├── Hpack.h              # HPACK codec
│       │   ├── HpackHuffman.h       # Huffman codec table
│       │   └── HpackStaticTable.h   # Static table 61 entries
│       ├── tls/                     # TLS protocol
│       │   ├── TlsConnection.h      # TLS connection (supports TLS 1.2/1.3)
│       │   ├── TlsContext.h         # TLS context
│       │   ├── TlsRecord.h          # TLS record protocol
│       │   ├── TlsHandshake12.h     # TLS 1.2 handshake
│       │   ├── TlsHandshake13.h     # TLS 1.3 handshake (with PSK/0-RTT)
│       │   ├── TlsPolicy.h          # Security policy (TlsSecurityProfile / compat switches)
│       │   ├── TlsCapabilities.h    # Capability matrix (default/optional/legacy)
│       │   ├── CertificateStore.h   # Certificate store (trust anchors/pins/revocation)
│       │   └── CertificateValidator.h # Certificate validator
│       ├── websocket/               # WebSocket protocol
│       │   └── WebSocketFrame.h     # Frame codec, handshake validation
│       ├── net/                     # Network transport layer (WSK)
│       │   ├── WskClient.h          # WSK client
│       │   ├── WskSocket.h          # WSK socket
│       │   └── WskBuffer.h          # WSK buffer
│       └── crypto/                  # Cryptography (CNG/BCrypt + in-kernel software)
│           ├── CngProvider.h        # CNG provider (keys, hashes, signatures)
│           ├── CngProviderCache.h   # CNG provider cache
│           ├── Aead.h               # AEAD (GCM/ChaCha20-Poly1305/CCM)
│           └── KeyExchange.h        # Key exchange (X25519/X448/NIST/FFDHE)
├── src/                              # Source code
│   ├── KernelHttpLib/               # Core static library implementation
│   │   ├── client/                  # Client implementation
│   │   ├── core/                    # Core abstraction implementation
│   │   ├── crypto/                  # Cryptography implementation
│   │   ├── engine/                  # Low-level engine
│   │   ├── http/                    # HTTP protocol implementation
│   │   ├── http2/                   # HTTP/2 protocol implementation
│   │   ├── khttp/                   # High-level API implementation
│   │   ├── net/                     # Network transport (WSK)
│   │   ├── tls/                     # TLS protocol implementation
│   │   └── websocket/               # WebSocket implementation
│   └── KernelHttpTest/              # Test driver project
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

- 📚 **[Project Wiki](https://github.com/x500x/khttp/wiki)** — 24 pages: capability matrix, architecture, HTTP/1.1, HTTP/2 & HPACK, WebSocket, TLS & certificates, cryptography, high/low-level API, configuration, client classes, transport layer, connection pool, async, memory, NTSTATUS, cookbook, FAQ, roadmap, glossary, and more.
- 🌐 **[Online docs site](https://x500x.github.io/khttp/)** — the same content as a MkDocs Material site with full-text search and dark mode.

| Topic | Link |
|-------|------|
| Capability Matrix | [Capability Matrix](https://github.com/x500x/khttp/wiki/Capability-Matrix) |
| High-Level API (khttp/kws) | [High-Level API](https://github.com/x500x/khttp/wiki/High-Level-API) |
| Low-Level API (engine) | [Low-Level API](https://github.com/x500x/khttp/wiki/Low-Level-API) |
| TLS & Certificates | [TLS & Certificates](https://github.com/x500x/khttp/wiki/TLS-and-Certificates) |
| NTSTATUS Reference | [NTSTATUS Reference](https://github.com/x500x/khttp/wiki/NTSTATUS-Reference) |

---

## 🔧 Configuration Options

### Session Configuration

```cpp
khttp::SessionConfig config = khttp::DefaultSessionConfig();

// Response buffer size (default 1 MiB, 0 means unlimited)
config.MaxResponseBytes = 2 * 1024 * 1024;  // 2 MiB

// Request construction buffer (default 16 KiB; increase for large bodies)
config.RequestBufferBytes = 96 * 1024;

// Connection pool capacity (default 8)
config.PoolCapacity = 16;

// Max connections per host (default 2)
config.MaxConnsPerHost = 4;

// Idle timeout (default 30 seconds)
config.IdleTimeoutMs = 60000;  // 60 seconds

// Response buffer pool type (default NonPaged; kernel path currently requires NonPaged)
config.ResponsePool = khttp::PoolType::NonPaged;

// TLS configuration
config.Tls.MinVersion = khttp::TlsVersion::Tls13;
config.Tls.MaxVersion = khttp::TlsVersion::Tls13;
config.Tls.Certificate = khttp::CertPolicy::Verify;
config.Tls.HandshakeTimeoutMs = 120000;  // TLS handshake timeout (default 120 seconds)
```

### Connection Policy

```cpp
khttp::Request* request = nullptr;
khttp::RequestCreate(session, &request);

// Connection policy
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ReuseOrCreate);  // Reuse or create (default)
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ForceNew);       // Force new connection
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::NoPool);         // Don't use pool

// Address family
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Any);      // System default
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Ipv4);     // IPv4 only
khttp::RequestSetAddressFamily(request, khttp::AddressFamily::Ipv6);     // IPv6 only
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
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'

# Local TLS interop matrix: uses 127.0.0.1 only; reports explicit SKIP when OpenSSL/BoringSSL is absent
pwsh -NoLogo -NoProfile -File .\tests\integration\tls_matrix.ps1 -Configuration Debug -Platform x64

# Build library and example driver
msbuild KernelHttp.sln /m /restore /p:Configuration=Debug /p:Platform=x64
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
| `khttp_tests.cpp` | High-level API tests |
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
NTSTATUS status = khttp::Get(session, url, urlLength, &response);
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
NTSTATUS DoRequest(khttp::Session* session) {
    khttp::Response* response = nullptr;
    NTSTATUS status = khttp::Get(session, url, urlLen, &response);
    
    // Release response even on failure
    if (NT_SUCCESS(status)) {
        // Process response...
    }
    
    khttp::ResponseRelease(response);  // Accepts nullptr, safe to call unconditionally
    return status;
}

// ❌ Wrong: Response not released on failure
NTSTATUS DoRequestWrong(khttp::Session* session) {
    khttp::Response* response = nullptr;
    NTSTATUS status = khttp::Get(session, url, urlLen, &response);
    if (!NT_SUCCESS(status)) {
        return status;  // Leak! response might be non-null
    }
    // ...
    khttp::ResponseRelease(response);
    return status;
}
```

### 2. Connection Reuse

```cpp
// ✅ Correct: Use connection pool for reuse
khttp::SessionConfig config = khttp::DefaultSessionConfig();
config.PoolCapacity = 16;        // Increase pool capacity
config.MaxConnsPerHost = 4;      // Increase per-host connections
config.IdleTimeoutMs = 120000;   // Extend idle timeout

// ❌ Avoid: Frequently creating new connections
khttp::RequestSetConnPolicy(request, khttp::ConnPolicy::ForceNew);
```

### 3. Asynchronous Operations

```cpp
// ✅ Correct: Use async to avoid blocking
khttp::AsyncOp* op = nullptr;
khttp::GetAsync(session, url, urlLen, &op);
khttp::AsyncWait(op, 30000);  // Wait 30 seconds

// Process response...
khttp::AsyncRelease(op);

// ❌ Avoid: Long synchronous waits in kernel thread
khttp::Get(session, url, urlLen, &response);  // May block for a long time
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
khttp::SendOptions options = khttp::DefaultSendOptions();
options.MaxResponseBytes = 0;  // 0 means unlimited
```

---

## 🔐 Security Considerations

### TLS Configuration

```cpp
// Recommended: Use TLS 1.3
config.Tls.MinVersion = khttp::TlsVersion::Tls13;
config.Tls.MaxVersion = khttp::TlsVersion::Tls13;

// Certificate verification
config.Tls.Certificate = khttp::CertPolicy::Verify;

// TLS handshake timeout (default 120 seconds)
config.Tls.HandshakeTimeoutMs = 120000;

// Custom certificate store
tls::CertificateStore store = {};
// Add trust anchors...
config.Tls.Store = &store;
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
tls::CertificateTrustAnchor anchor = {};
anchor.SubjectName = rootCertSubject;
anchor.SubjectNameLength = rootCertSubjectLen;
RtlCopyMemory(anchor.SubjectPublicKeySha256, rootSpkiHash, 32);
anchor.MatchSubjectPublicKey = true;

tls::CertificatePin pin = {};
pin.HostName = "example.com";
pin.HostNameLength = 11;
RtlCopyMemory(pin.LeafSubjectPublicKeySha256, leafSpkiHash, 32);

// Create certificate store
tls::CertificateStoreOptions storeOptions = {};
storeOptions.TrustAnchors = &anchor;
storeOptions.TrustAnchorCount = 1;
storeOptions.Pins = &pin;
storeOptions.PinCount = 1;

tls::CertificateStore store;
store.Initialize(storeOptions);

// Apply to session
config.Tls.Store = &store;
```

### ALPN Protocol Negotiation

```cpp
// Set ALPN protocol (for HTTP/2 negotiation)
config.Tls.Alpn = "h2";
config.Tls.AlpnLength = 2;

// Or support both HTTP/1.1 and HTTP/2
// Set via TlsAlpnProtocol array in TlsConnection
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

- Submit an [Issue](https://github.com/x500x/khttp/issues) to the project repository
- View project documentation and example code
- Reference related technical documentation

---

## 🙏 Acknowledgments

Thanks to all developers who have contributed to the project!

---

<div align="center">

**[⬆ Back to Top](#kernelhttp)**

</div>
