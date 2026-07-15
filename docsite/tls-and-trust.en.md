# TLS & Trust

HTTPS verifies certificates by default (`CertPolicy::Verify`). The library **does not** ship system CAs: trust anchors, intermediate CAs, SPKI pins, and revocation evidence are supplied by the caller through `CertificateStore` and related APIs. Cryptography uses kernel CNG/BCrypt (plus required in-kernel software fills) — **not SChannel**.

## Version path

- Prefer **TLS 1.3** when in range (pure 1.3 ClientHello); otherwise speak TLS 1.2 directly.
- **No in-handshake automatic downgrade**. If the peer proves it can only do 1.2, the failure may be classified as `VersionNegotiation` so session can **explicitly reconnect at 1.2**.
- A ServerHello carrying a TLS 1.3→1.2 downgrade sentinel is treated as an attack and hard-fails.
- Defaults: `MinVersion=Tls12`, `MaxVersion=Tls13`; may be tightened to TLS 1.3 only.

## Policy profile

`TlsPolicy.Profile`:

| Profile | Meaning |
|---------|---------|
| `ModernDefault` (default) | Modern ciphers/groups/signatures; accidental compatibility flags → `STATUS_INVALID_PARAMETER` |
| `CompatibilityExplicit` | Allows RSA-kx, CBC, SHA-1 signatures, and true renegotiation individually |

Default-off opt-ins: TLS 1.2 RSA-kx / CBC / SHA-1 / renegotiation, post-handshake client auth, and `RequireRevocationCheck`. How to enable: [Capability matrix · Default-off](capability-matrix.en.md#2-default-off).

TLS 1.2 hard requirements: Extended Master Secret and secure renegotiation indication; CBC requires Encrypt-then-MAC.

## Certificates and hostnames

Validation runs on an expanded kernel stack. Highlights:

- Bounded chain length; parse-time rejection of duplicate and unknown-critical extensions.
- **Hostnames**: SAN dNSName wildcards are a **single leftmost label** only; **IP literals match iPAddress SAN only**; DNS matching **never falls back to CN** (CN is not used for hostname equivalence).
- **SPKI pins**: hosts with configured pins strongly check the leaf SPKI; unpinned hosts fail open.
- **Revocation**: offline and evidence-driven (stapled OCSP, static entries, provider-returned OCSP/CRL DER). The library **never fetches online**. Under `RequireRevocationCheck` / hard modes, missing or invalid evidence **fails closed** (`STATUS_TRUST_FAILURE`).

```cpp
// Trust anchors + optional pins (sketch)
wknet::http::CertificateStoreOptions o = {};
// fill o.TrustAnchors / Pins / ...
wknet::http::CertificateStore* store = nullptr;
NTSTATUS st = wknet::http::CertificateStoreCreate(&o, &store);
config.Tls.Store = store;
config.Tls.Certificate = wknet::http::CertPolicy::Verify;
// after SessionClose: CertificateStoreClose(store);
```

Never use `CertPolicy::NoVerify` in production (skips chain and hostname checks). `NoVerify` responses also do not participate in H3 Alt-Svc learning by default.

## mTLS

`TlsClientCredential` carries the certificate chain and a `Sign` callback. Private keys remain with the caller; the library only completes signatures through the callback.

## Session resumption

- Resumption tickets bind policy identity, SNI, ALPN, cipher, and version (per-version cache caps apply).
- TLS 1.3 0-RTT early data exists only on internal connection options and is **not** exposed on `wknet::http::TlsConfig` / `SendOptions`; the product HTTP path cannot enable it through public fields.

## Boundary with HTTP

| Scenario | Behavior |
|----------|----------|
| Default HTTPS | TCP TLS + HTTP/1.1 or ALPN `h2` |
| H3 Auto | Only authenticated TLS responses may write Alt-Svc; SNI/cert/`authority` stay origin-bound |
| Proxied HTTPS | CONNECT, then TLS to the target |
| WebSocket `wss` | Same TLS config and validation model |
| HTTPS→HTTP redirect | Rejected by default |

Common failures: `STATUS_TRUST_FAILURE` (chain/host/pin/anchor/revocation), `STATUS_NOT_SUPPORTED` (policy/version/0-RTT), `STATUS_INVALID_NETWORK_RESPONSE` (record/handshake decode). More: [Errors & FAQ](errors-and-faq.en.md).
