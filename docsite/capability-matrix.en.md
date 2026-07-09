# Capability Matrix

This page is grounded in the actual `src/KernelHttpLib/` implementation.

**HTTP/1.1**: Content-Length, builder-generated chunked, and true streaming request bodies (`BodyCreateStream` / `KhHttpRequestSetBodySource`; caller `Transfer-Encoding`/`TE` are rejected; `Trailer` is allowed only with chunked request trailers); request trailers via `KhHttpRequestAddTrailer` / `khttp::RequestAddTrailer`; explicit `Expect: 100-continue` via `SendFlagExpectContinue` with 100/final/417/timeout/disconnect branches covered; explicit opt-in TRACE via `SendFlagAllowTrace`; typed Range/conditional request helpers; HTTPS proxy uses CONNECT and plaintext HTTP over proxy uses absolute-form targets; opt-in HTTP/1.1 pipelining through session `EnableHttp11Pipeline=true` with FIFO response binding, configurable depth/method mask, and default `GET`/`HEAD`/`OPTIONS` eligibility; response parsing accepts only HTTP/1.0–1.1, header line ≤8 KiB, section ≤64 KiB, ≤200 headers, rejects obs-fold, rejects duplicate Content-Length and TE+CL conflict; no-body for 1xx/204/**205**/304 and HEAD; chunked ≤8192 chunks with strict extension grammar and forbidden-trailer rejection; read-only `206` / `Content-Range` parsing; Content-Encoding gzip (CRC32/ISIZE verified), deflate (zlib autodetect + Adler-32, via kernel `RtlDecompressBufferEx` with runtime probe), br (bundled Brotli), compress (full LZW), zstd, dcz with caller-provided dictionary, aes128gcm with RFC 8188 keying material, identity, up to 2 codings reverse-decoded; `exi` and `pack200-gzip` are recognized and fail closed until complete decoders are implemented; `Accept-Encoding` qvalue preferences and response validation are enforced fail-closed; **decompression-bomb guard 64× per-step**; 1xx skipping; redirects; keep-alive pooling.

**HTTP/2**: preface + SETTINGS (7 settings including `ENABLE_CONNECT_PROTOCOL`, ACK sent immediately, not awaited), SETTINGS validation (ENABLE_PUSH!=0 rejected, ENABLE_CONNECT_PROTOCOL must be 0/1, window/frame bounds), **CONTINUATION flood guards (64 / 4 empty)**, active-stream table with two-stage `BeginRequest` / `ReceiveResponse(streamId)`, interleaved frame dispatch by stream id, high-level `khttp` pooled multi-stream reuse, connection + per-stream flow control with half-window WINDOW_UPDATE threshold, streaming request DATA from body sources, request trailers as final HEADERS + END_STREAM, explicit per-request priority via HEADERS priority fields / PRIORITY frame codec, session-enabled background PING keepalive for idle reusable pooled H2 connections (off by default; ACK timeout/protocol error closes the idle connection), GOAWAY/RST retry semantics surfaced as `STATUS_RETRY` for unprocessed safe-method retries, 1xx interim handling, PUSH_PROMISE always a protocol error, RFC 8441 extended CONNECT tunnel primitives, three modes (TLS-ALPN h2 / explicit h2c prior-knowledge / explicit h2c upgrade via `SendOptions.Http2CleartextMode` — upgrade forbids a body, replays post-101 bytes, uses stream 1). HPACK: continuation-byte ≤5, Huffman (rejects >30-bit codes/EOS/bad padding), table-size-update only at block start, **never-indexed forced for authorization/cookie/proxy-authorization**.

**WebSocket**: handshake with **constant-time** accept comparison, caller-supplied opening headers with controlled-header rejection, explicit opt-in `permessage-deflate` (off by default; unrequested/unknown/invalid extensions rejected), subprotocol negotiation; HTTP/1.1 client frames are masked, RFC 8441 over HTTP/2 frames are unmasked as required (masked server frame → 1002); high-level and low-level `wss` default to automatic RFC 8441 selection by offering `h2,http/1.1` (use `Http11Only` to force HTTP/1.1; `ws://` does not implicitly use h2c); **fragment send (`kws::SendContinuation` + `FinalFragment`)** with incremental cross-fragment UTF-8 validation; default aggregated whole-message receive or explicit wire-fragment delivery via `ReceiveOptions.DeliverFragments=true` and `ReceiveOptions.OnMessage`; auto-Pong (toggleable), ≤100 control frames per receive (1008), UTF-8 validation (1007), max-message (1009); active and passive close handshakes; opening-handshake 3xx/401/407 returns `STATUS_NOT_SUPPORTED` rather than following redirect/auth challenges.

**TLS 1.2/1.3**: single-version path (no in-handshake fallback — failures classified as `VersionNegotiation` for an explicit caller retry at 1.2); cipher/group/sig split into default / optional / legacy; TLS1.2 enforces EMS + secure-reneg indication + Encrypt-then-MAC for CBC; TLS1.3 HelloRetryRequest, reactive-only KeyUpdate, NewSessionTicket, record padding, `signature_algorithms_cert`, OCSP stapling parse; resumption bound to policy identity + SNI + ALPN + cipher + version. Certificate validation (on an expanded kernel stack): chain ≤8 with bounded candidate path search, subject/issuer plus AKI/SKI matching, cross-signed intermediates, signature/validity/basic-constraints/pathLen/KU/EKU/name-constraints/cert-policies/trust-anchor; rejects duplicate and unknown-critical extensions; hostname match with single-label wildcard, IP literals match iPAddress SAN only, **never falls back to CN**; revocation is offline + evidence-driven through stapled OCSP, static entries, or provider callback, validates OCSP/CRL DER signatures, issuer/serial, thisUpdate/nextUpdate, and status, and **fails closed** when required-but-absent or invalid; SPKI pinning (fail-open for un-pinned hosts); mTLS via caller `Sign` callback (private key never enters the library). Crypto: ChaCha20-Poly1305/AES-CCM/X25519/X448/FFDHE/Ed25519/Ed448 verification are in-kernel **software**; min RSA modulus 2048.

## Default-Off Opt-Ins

| Capability | How it is enabled |
|------------|-------------------|
| `Expect: 100-continue` | `SendFlagExpectContinue` |
| HTTP/1.1 pipelining | Session `EnableHttp11Pipeline=true`; `Http11PipelineMaxDepth` / `Http11PipelineMethodMask` are configurable and default eligibility is `GET`/`HEAD`/`OPTIONS` |
| h2c prior knowledge / Upgrade | `SendOptions.Http2CleartextMode` |
| HTTP/2 background PING keepalive | Session `Http2KeepAlive.Enabled=true` |
| HTTP/2 per-request priority | `SendOptions.Http2Priority` / `KhHttpSendOptions.Http2Priority` |
| WebSocket permessage-deflate | `ConnectConfig.PerMessageDeflate.Enable=true` |
| TLS 1.2 RSA-kx / CBC / SHA-1 | `TlsPolicy.Profile=CompatibilityExplicit` plus the matching compatibility switch |
| TLS 1.2 true renegotiation | `CompatibilityExplicit` + `EnableTls12Renegotiation`, limited by `MaxTls12Renegotiations` |
| TLS 1.3 0-RTT | `EnableEarlyData` + `EarlyDataReplaySafe`, with a ticket that advertises `max_early_data_size` |
| TLS 1.3 post-handshake client auth | `EnablePostHandshakeClientAuth`; signatures use the mTLS callback and private keys never enter the library |
| Hard revocation requirement | `RequireRevocationCheck`; missing verifiable OCSP/CRL DER evidence fails closed |

## Security Refusals / Policy Constraints

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

## Missing / Explicit Non-Goals

These capabilities are not provided today. Capabilities that are implemented but off by default are listed only in the previous section.

| Capability | Current conclusion |
|------------|--------------------|
| HTTP inbound request parser / server role | Non-goal; this project is a client protocol stack |
| Persistent on-disk HTTP cache | Non-goal; RFC 9111 cache is an explicit in-memory NonPaged object and is not persisted across reboot |
| Complex local HTTP/2 priority-tree scheduling | Non-goal; no local dependency tree or bandwidth scheduler is maintained |
| WebSocket extensions other than `permessage-deflate` | Non-goal; no other extensions are negotiated |
| Online OCSP/CRL fetching | Non-goal; callers provide external trust/certificate/revocation data or cached entries |
| HTTP/3 / QUIC | Non-goal |

## Implementation Strategy and Trust Model

- The transport main path uses WSK; TLS, HTTP, and certificate validation are implemented in the kernel path.
- Cryptography uses kernel-mode CNG/BCrypt first. ChaCha20-Poly1305, AES-CCM, X25519, X448, FFDHE, and Ed25519/Ed448 verification are filled in by in-kernel software implementations.
- WinHTTP, WinINet, and SChannel are not used as the kernel main path.
- The library does not hard-code system CAs; callers explicitly provide trust anchors, CA bundles, revocation cache entries, and pins.

See [Roadmap](roadmap.md).
