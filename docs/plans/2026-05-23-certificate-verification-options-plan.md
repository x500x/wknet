# Certificate Verification Options Plan

## Goal

Add requests-like certificate behavior: HTTPS/TLS clients verify certificates by default when a trust store is supplied, allow callers to disable verification explicitly, and allow callers to supply externally managed CA certificates or PEM bundles.

## Design

- Keep TLS handshake certificate parsing mandatory, even when verification is disabled, because the leaf public key is needed to verify `ServerKeyExchange`.
- Add a `VerifyCertificate` boolean on TLS-facing client options. The default is `true`.
- Treat `CertificateStore` as required for verified connections. It is optional only when `VerifyCertificate == false`.
- Extend `CertificateStoreOptions` with caller-owned authority bundles loaded from external trust data.
- Support PEM bundles with multiple `-----BEGIN CERTIFICATE-----` blocks and DER bundles containing one certificate.
- Preserve existing SPKI trust anchors and host pins for callers that already use them.
- Do not compile a public CA bundle into the driver. Keep `certs/cacert.pem` as an external, replaceable data file and pass its bytes into `CertificateStoreOptions.AuthorityBundles`.

## Implementation Tasks

1. Extend `CertificateStore` with CA bundle options and read-only accessors.
2. Keep public CA bundle data outside the driver image; remove any generated in-source CA bundle file.
3. Add `certs/cacert.pem` as the external default trust data file and `tools/update-cacert.ps1` to refresh it from Python certifi.
4. Update `CertificateValidator` to:
   - parse the chain when verification is disabled and return the leaf result;
   - validate caller-supplied CA bundles as trust anchors;
   - keep existing time, hostname, EKU, chain signature, pin, and SPKI-anchor checks for verified mode.
5. Add `VerifyCertificate` to `TlsClientConnectionOptions`, `HttpsRequestOptions`, `Http2RequestOptions`, and `WebSocketConnectOptions`.
6. Relax HTTPS/HTTP2/WebSocket validation only for `VerifyCertificate == false`; verified requests still require a `CertificateStore`.
7. Add host tests for disabled verification, missing trust material, and external PEM bundle validation.
8. Run host regression tests and Debug driver build.

## Verification

- Run `pwsh -NoLogo -NoProfile -File tests/integration/https_smoke.ps1 -Configuration Debug -Platform x64`.
- Do not run VM smoke testing for this task.
