# Internals

The product promises only the public ABI under `include/wknet`. `src/wknetlib` holds the in-library layering and user-mode protocol tests; it is not an installable ABI. Product drivers should not include internal headers.

## Public vs internal

| Layer | Location | Caller |
|-------|----------|--------|
| Public API | `include/wknet/http|websocket|crypto|codec` | Product drivers |
| Test hooks | `include/wknet/test/Test.h` (`WKNET_USER_MODE_TEST`) | User-mode tests only |
| Implementation | `src/wknetlib/*` | The library itself |

`Wknet.h` aggregates public headers only. It leaves out session / transport / net / tls implementation headers.

## Internal layering (contributors)

| Namespace / tree | Responsibility |
|------------------|----------------|
| `session` | Routing, proxy, pool, redirects, async, HTTP/WS/H3 orchestration |
| `transport` | Opaque TCP byte streams (cleartext / TLS wrap) |
| `net` | WSK lifetime, resolve, TCP/UDP socket services |
| `tls` | Handshake, record protection, resumption, certificate validation |
| `http1` / `http2` / `ws` | Protocol state machines |
| `quic` / `http3` / `qpack` | QUIC v1 / HTTP/3 / QPACK |
| `rtl` | Heap, Workspace, utilities |

Rules:

- Protocol layers do not write pool fields; pool policy lives only in `session`
- `transport::Transport` carries **TCP** only; UDP is `net::WskDatagramSocket`; QUIC state is `quic`
- Alt-Svc learning / racing / fallback live only in `session`
- Modules must not include another module’s `*Private.hpp` (except white-box tests)
- No parallel client layer or second network lifetime

## Test hooks

User-mode tests inject transport, IRQL, or scheduling through the narrow `WKNET_USER_MODE_TEST` surface. Hooks are not on the normal `Wknet.h` product path.

## Memory and implementation discipline

- No stack buffers in the library; heap objects plus Workspace-resident hot buffers
- No exceptions, no RTTI; functions are `noexcept`; SAL annotations required
- Implementations are standalone `.cpp` files with `.h` / `.hpp` shared declarations; no `.inc` implementation fragments

See also: [Architecture](architecture.md) · [Build & test](build-and-test.md) · [Contributing](contributing.md)
