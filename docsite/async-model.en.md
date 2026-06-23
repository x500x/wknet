# Async Model

`engine/Async.h`. Kinds `HttpSend`/`WebSocketConnect`; states `Pending→Running→Completed`. An op is created via high-level `khttp::Async*` entry points (`AsyncGet`/`AsyncPost`/`AsyncSend`) or `kws::ConnectAsync`, queued to run its worker, awaited via `AsyncWait` (or polled via `AsyncGetStatus`/`AsyncIsCompleted`), then results fetched per kind (`AsyncGetResponse` / `kws::AsyncGetWebSocket`), then `AsyncRelease`.

Reference counting: the user handle holds one reference; an internal worker holds another, keeping the object alive after the user marks it closed so it can still observe cancellation. `AsyncCancel` completes a pending op immediately and signals a running HTTP/WS worker, which forwards the flag into WSK transport waits to cancel the active IRP where supported — cancellation is cooperative, so still `AsyncWait` then `AsyncRelease`.

**After using async APIs, call `khttp::Destroy()` before driver unload** (then release WSK / close handles). Synchronous-only paths do not require it, but may call it unconditionally. Each handle carries a `volatile LONG InFlight` counter and a `KEVENT DrainEvent` so handles are not freed while operations still use them.
