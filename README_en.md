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

KernelHttp is a pure kernel-mode HTTP/HTTPS client library designed specifically for Windows kernel driver development. Built from the ground up, it implements a kernel-friendly modern client protocol subset: HTTP/1.1, HTTP/2, WebSocket, and TLS 1.2/1.3 handshake and encrypted communication. Unsupported optional capabilities are documented below.

### ✨ Key Features

- **🔒 Pure Kernel-Mode Implementation**: No dependency on WinHTTP, WinINet, SChannel, or other user-mode components
- **🌐 WSK Network Transport**: Uses Windows Sockets Kernel (WSK) for network communication, with `ITransport` abstraction supporting WSK and TLS transport layers
- **🔐 CNG/BCrypt Cryptography**: Uses kernel-mode CNG (Cryptography Next Generation) for cryptographic operations, supporting TLS 1.2/1.3 handshake
- **📡 Explicit Protocol Subset**: Supports the client main paths for HTTP/1.1, HTTP/2 (with h2c plaintext upgrade), WebSocket, and TLS 1.2/1.3, with unsupported optional capabilities documented
- **🔄 Connection Pool Management**: Built-in connection pool with connection reuse, idle timeout, concurrency protection, and automatic management
- **⚡ Asynchronous Operations**: Supports async requests with concurrency protection and workspace isolation, avoiding blocking kernel threads
- **🎯 Two-Layer API**: Provides both high-level simplified API (`khttp`) and low-level fine-grained control API (`engine`)
- **🛡️ Certificate Verification**: Supports Certificate Pinning, Trust Anchors, SPKI hash verification, and TLS 1.3 signature scheme validation
- **📦 Response Encoding**: Supports `Content-Encoding: gzip/deflate/br` and HTTP/1.1 response `Transfer-Encoding` chains for `chunked/gzip/deflate/compress`
- **🧱 Heap Memory Management**: Uses `HeapObject<T>` / `HeapArray<T>` for unified heap memory management, high-frequency buffers resident in Workspace

### Protocol Capability Boundaries

KernelHttp implements protocol behavior on the Windows kernel path: transport uses WSK first, cryptography uses CNG/BCrypt first, and the library does not depend on WinHTTP, WinINet, or SChannel. Current boundaries:

| Protocol | Supported | Current Boundary |
|----------|-----------|------------------|
| HTTP/1.1 | `Content-Length`, response `Transfer-Encoding` chains (`chunked`/`gzip`/`deflate`/`compress`), close-delimited responses, HEAD/101/no-body status codes, intermediate 1xx skipping | Request bodies use `Content-Length`; user-supplied request `Transfer-Encoding` is rejected; chunked upload and response trailer exposure are not supported; `br` is supported only as `Content-Encoding` |
| HTTP/2 | TLS ALPN, h2c prior knowledge / Upgrade, SETTINGS, HEADERS/CONTINUATION, DATA, PING, GOAWAY, WINDOW_UPDATE, HPACK | Server push, priority, and complex concurrent stream scheduling are not supported; responses must end with `END_STREAM`, `RST_STREAM`, or `GOAWAY` |
| WebSocket | ws/wss handshake, text/binary send, control-frame validation, Ping/Pong/Close, complete-message receive by default | Extension negotiation and receive-fragment callbacks are not supported; the default API aggregates complete messages |
| TLS | TLS 1.2/1.3, ECDHE + AES-GCM main path, TLS 1.3 downgrade protection, certificate chain, dNSName/iPAddress SAN, and pin validation | TLS client certificates, CBC, ChaCha20-Poly1305, and OCSP/CRL revocation checks are not supported |

| Unsupported Optional Capability | Current Handling |
|---------------------------------|------------------|
| WebSocket extensions such as permessage-deflate | Out of scope; unexpected server extensions are rejected |
| WebSocket receive-fragment callback | Receive aggregates complete messages; fragment callback exposure is not supported |
| HTTP/2 server push | Push is disabled; forbidden PUSH_PROMISE is a protocol error |
| TLS client certificates | Client certificate authentication is not supported |
| TLS CBC / ChaCha20-Poly1305 | Not in the current cipher-suite subset |
| OCSP / CRL revocation checks | Requiring revocation returns `STATUS_NOT_SUPPORTED` |
| IDNA host processing | Certificate dNSName/CN matching currently uses ASCII host names |

Close-delimited HTTP/1.x responses and `101 Switching Protocols` upgrade responses are not returned to the normal HTTP connection pool. Synchronous HTTP, WebSocket, TLS, and certificate validation paths require `PASSIVE_LEVEL`. TLS ALPN results must come from the client's offered list. TLS1.2 selection after a TLS1.3 attempt is allowed only after verified version-negotiation evidence; certificate errors, ALPN mismatch, network timeout, or record decryption failure are not TLS1.2-only evidence.
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
   git clone https://github.com/x500x/win_kernel_http.git
   cd kernel_http
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

KernelHttp provides two-layer APIs:

| API Layer | Namespace | Use Case |
|-----------|-----------|----------|
| **High-Level API** | `KernelHttp::khttp` | Most application scenarios, rapid development |
| **Low-Level API** | `KernelHttp::engine` | Performance-critical, special customization, testing |

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

For detailed comparison, see [API Overview](docs/api-overview.md)。

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
│       │   ├── WebSocket.h          # WebSocket connect/send/receive/close
│       │   ├── Detail.h             # Internal bridge interface
│       │   └── Test.h               # Test utilities
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
│       │   ├── CertificateStore.h   # Certificate store (trust anchors/pins)
│       │   └── CertificateValidator.h # Certificate validator
│       ├── websocket/               # WebSocket protocol
│       │   └── WebSocketFrame.h     # Frame codec, handshake validation
│       ├── net/                     # Network transport layer (WSK)
│       │   ├── WskClient.h          # WSK client
│       │   ├── WskSocket.h          # WSK socket
│       │   └── WskBuffer.h          # WSK buffer
│       └── crypto/                  # Cryptography (CNG/BCrypt)
│           ├── CngProvider.h        # CNG provider (keys, hashes, signatures)
│           └── CngProviderCache.h   # CNG provider cache
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
├── docs/                             # Documentation
├── certs/                            # Certificate related
└── tools/                            # Tool scripts
```

---

## 📖 Documentation Index

| Document | Description |
|----------|-------------|
| [API Overview](docs/api-overview.md) | Two-layer API comparison and selection guide |
| [High-Level API](docs/high-level-api.md) | Simplified API for most scenarios |
| [Low-Level API](docs/low-level-api.md) | Fine-grained control API |
| [HTTP Status Codes](docs/http-status-codes.md) | HTTP status code reference |
| [NTSTATUS Codes](docs/ntstatus-codes.md) | Kernel error code reference |
| [Documentation Index](docs/README.md) | Complete documentation structure |

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
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\tls_record_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\khttp_tests.exe'
pwsh -NoLogo -NoProfile -Command '& .\tests\out\bin\high_level_api_tests.exe'

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
| `tls_record_tests.cpp` | TLS record protocol |
| `websocket_frame_tests.cpp` | WebSocket frame processing |
| `khttp_tests.cpp` | High-level API tests |
| `high_level_api_tests.cpp` | High-level API integration tests |
| `websocket_client_tests.cpp` | WebSocket client tests |

---

## ⚠️ Error Handling

The project uses Windows NTSTATUS error codes. For detailed information, see [NTSTATUS Code Reference](docs/ntstatus-codes.md).

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

- Submit an [Issue](https://github.com/x500x/win_kernel_http/issues) to the project repository
- View project documentation and example code
- Reference related technical documentation

---

## 🙏 Acknowledgments

Thanks to all developers who have contributed to the project!

---

<div align="center">

**[⬆ Back to Top](#kernelhttp)**

</div>
