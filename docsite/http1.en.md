# HTTP/1.1 Protocol

Namespace `wknet::http`, grounded in `src/wknetlib/http/`.

**Request building** serializes the request line, headers, and body with measured output sizing. Host is emitted first. CONNECT and opt-in TRACE are supported. Bodies may use Content-Length, library-generated chunked framing, or streaming callbacks through `BodyCreateStream` / `RequestSetBodySource`; request trailers are available only on the chunked path. Caller-controlled framing headers remain rejected.

**HTTP/1.1 pipelining** is session opt-in through `SessionConfig.EnableHttp11Pipeline=true`. It is disabled by default, uses FIFO response binding, defaults to depth 4, and accepts only `GET`/`HEAD`/`OPTIONS` unless the method mask is changed.

**Response parsing** (`HttpParser::ParseResponse`): full header block required (else `STATUS_MORE_PROCESSING_REQUIRED`); >64 KiB header block rejected; status line accepts only HTTP major==1, minor<=1, 3-digit 100..599; per-line ≤8 KiB, **obs-fold rejected**, token names, value rejects <0x20 (except TAB) and 0x7f; ≥200 headers → `STATUS_BUFFER_TOO_SMALL`. No-body for HEAD/1xx/204/**205**/304; duplicate Content-Length or TE+CL conflict → `STATUS_INVALID_NETWORK_RESPONSE`; chunked ≤8192 chunks, strict extension grammar, forbidden trailers rejected; `IsPartialContent` / `GetContentRange` expose read-only 206 / Content-Range semantics.

**Content-Encoding** supports gzip (CRC16/CRC32/ISIZE verified), deflate (zlib autodetect + Adler-32, kernel `RtlDecompressBufferEx` with runtime probe), br (bundled Brotli), compress (full LZW), zstd, dcz with a caller-provided dictionary, aes128gcm with RFC 8188 keying material, exi, pack200-gzip, and identity. Chains contain at most **2** codings, are decoded in reverse order, and enforce a **64× per-step decompression-bomb guard**.

- **EXI:** W3C EXI 1.0 Second Edition streams without an external Schema; all four alignments, Options, fidelity features, built-in XML Schema datatypes, `xsi:type`, and `xsi:nil`; emits Infoset-equivalent XML. External Schema/strict grammar streams return `STATUS_NOT_SUPPORTED`.
- **Pack200:** Java 5–8 formats `150.7`/`160.1`/`170.1`/`171.0`; raw/gzip, multiple segments, class/file/bytecode reconstruction, custom attribute layouts in class/field/method/code contexts, overflow indexes, constant-pool and BCI relocation; emits a semantically equivalent JAR.
- Dedicated EXI and Pack200 tests load offline real-world corpora and verify `SHA256SUMS` plus provenance metadata.

**Transfer-Encoding** supports chunked/gzip/deflate/compress up to 4 codings (identity rejected, `br` → `STATUS_NOT_SUPPORTED`), reverse-decoded with trailers only on the outermost chunked layer.
