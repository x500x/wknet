# HTTP/1.1 Protocol Guide

HTTP/1.1 is the TCP baseline for `wknet::http`. Request framing is library-owned; response parsing is fail-closed; pipelining, `Expect: 100-continue`, and TRACE are explicit opt-ins.

Public entry points: [HTTP sync](api/http-sync.md) / [Request & response](api/request-response.md) / [Session config](api/session-config.md).

## Summary

| Topic | Behavior |
|-------|----------|
| Request body | `Content-Length`, library-generated chunked, streaming body source |
| Request trailers | **Chunked path only**; forbidden fields and CRLF injection rejected |
| `Expect: 100-continue` | Explicit `SendFlagExpectContinue` |
| Pipelining | Session default off; FIFO; default methods `GET`/`HEAD`/`OPTIONS` |
| Proxy | HTTPS → CONNECT; plaintext HTTP → absolute-form (no tunnel) |
| Redirect | See below; HTTPS→HTTP downgrade refused by default |
| Close-delimited | Body completes on connection close when no CL/TE |
| Caller framing headers | `Transfer-Encoding`/`TE` etc. are library-controlled |

## Request body and framing

- **Known length**: emit `Content-Length`; body may be in-memory, file-backed, or streamed via `BodyCreateStream` / `RequestSetBodySource`.
- **Unknown length**: `RequestBodyMode::Chunked`; the library generates `Transfer-Encoding: chunked` and chunk framing.
- **Streaming upload**: callback supplies chunks; the full body need not reside in memory.
- **Trailers**: `BodyAddTrailer` / `RequestAddTrailer` are sent only after the final chunk; forbidden fields include `Content-Length`, `Transfer-Encoding`, `Host`, `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`.
- **TRACE**: requires `SendFlagAllowTrace`; body, trailers, or sensitive headers are rejected.

Callers must not hand-write `Host`/`Content-Length`/`Connection`/`Transfer-Encoding`/`TE`. A hand-written `Expect: 100-continue` without the library flag is also rejected. When no `Accept-Encoding` is supplied, the library injects the default negotiation list (see [Encoding & crypto](encoding-and-crypto.md)).

## Expect 100-continue

`SendFlagExpectContinue` is opt-in and injects only when a body is present:

1. Receive `100` → then send the body  
2. Receive final / `417` → do not send the body  
3. Wait timeout (`ExpectContinueTimeoutMs`, default 1000 ms) → send the body per RFC timing  

Requests with a body or Expect never enter the HTTP/1.1 pipeline.

## Pipelining (off by default)

| Item | Default |
|------|---------|
| `SessionConfig.EnableHttp11Pipeline` | `false` |
| `Http11PipelineMaxDepth` | 4 (hard cap 64) |
| `Http11PipelineMethodMask` | `GET` / `HEAD` / `OPTIONS` |

When enabled, same-origin keep-alive connections assign sequences in send order and bind responses **FIFO**. Parse or transport failure closes that pipeline connection and propagates to queued requests.

**Excluded from the pipeline**: request body, `Expect: 100-continue`, redirect replay, `NoPool`/`ForceNew`, methods outside the mask. This avoids response reordering and non-idempotent replay.

## Proxy

| Target | Form |
|--------|------|
| `https://` over proxy | `CONNECT` tunnel; TLS inside the tunnel |
| `http://` over proxy | absolute-form request-target; **no** CONNECT |
| `Proxy-Authorization` | Only from explicit `SessionConfig.Proxy` |

## Response body framing

- **No body**: HEAD, or status 1xx / 204 / **205** / 304.
- **Content-Length**: incomplete length continues reading; duplicate CL or TE+CL conflict → `STATUS_INVALID_NETWORK_RESPONSE`.
- **chunked**: ≤8192 chunks; strict chunk-extension grammar; trailers after the terminal chunk (line ≤8 KiB, count ≤256); forbidden trailer fields match the request rules.
- **Close-delimited**: with neither CL nor TE, the message completes on connection close; such responses are **not returned to the pool**.

A full header block (`\r\n\r\n`) is required, else `STATUS_MORE_PROCESSING_REQUIRED`. Header block >64 KiB, line >8 KiB, ≥200 headers, or **obs-fold** fails. Status lines accept only HTTP/1.0 and 1.1. Interim 1xx (except 101) is silently consumed and the final response is re-parsed.

`206` / `Content-Range` are read-only semantics; with an RFC 9111 cache they participate in validation and partial combining without changing body framing.

## Redirect

| Status | Method / body |
|--------|----------------|
| 301 / 302 | POST→GET only |
| 303 | →GET except HEAD |
| 307 / 308 | Preserve method and body |

- Cross-origin strips `Authorization` / `Cookie` / `Proxy-Authorization`.
- **HTTPS→HTTP downgrade is refused by default**.
- Default max 10 hops (`MaxRedirects`); **hitting the cap returns that 3xx without error**.
- `SendFlagDisableAutoRedirect` disables automatic following.

## Relation to upper layers

- Safe methods may **retry exactly once** with `ForceNew` on connection-close families / `STATUS_RETRY` / timeout under `ReuseOrCreate` (`GET`/`HEAD`/`OPTIONS`).
- Content-Encoding decode, bomb guards, and TE rules: [Encoding & crypto](encoding-and-crypto.md).
- Capability wording follows the [Capability matrix](capability-matrix.md).
