# Async Model

The implementation lives in `session/Async.cpp`. Kinds are HTTP send and WebSocket connect; states move from Pending to Running to Completed. Public operations are created through `wknet::http::Async*` or `wknet::websocket::ConnectAsync`, awaited or canceled through the opaque `AsyncOp`, and finally released.

Reference counting: the user handle holds one reference; an internal worker holds another, keeping the object alive after the user marks it closed so it can still observe cancellation. `AsyncCancel` completes a pending op immediately and signals a running HTTP/WS worker, which forwards the flag into WSK transport waits to cancel the active IRP where supported — cancellation is cooperative, so still `AsyncWait` then `AsyncRelease`.

**After using async APIs, call `wknet::http::Destroy()` before driver unload** (then release WSK / close handles). Synchronous-only paths do not require it, but may call it unconditionally. Each handle carries a `volatile LONG InFlight` counter and a `KEVENT DrainEvent` so handles are not freed while operations still use them.
