# External Trust Bundles

`cacert.pem` is an externally managed PEM trust bundle. It is intentionally not compiled into the driver image.

Callers that want requests-like default trust should load this file outside the TLS core and pass its bytes through `tls::CertificateStoreOptions::AuthorityBundles`.

Update it with:

```powershell
pwsh -NoLogo -NoProfile -File tools/update-cacert.ps1
```
