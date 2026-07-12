# HTTP/2 & HPACK

Namespace `wknet::http2`, RFC 9113 + HPACK 7541, grounded in `src/wknetlib/http2/`. The internal connection has active-stream routing and interleaved frame dispatch; `wknet::http` keeps a per-request API while the pool reuses one same-origin H2 connection for multiple active streams.

The connection validates SETTINGS and header semantics, applies CONTINUATION flood guards, tracks active streams, and enforces connection and stream flow control. `BeginRequest` / `ReceiveResponse(streamId)` form the internal two-stage path. `wknet::http::SendOptions` exposes explicit priority, h2c mode, and keepalive configuration. RFC 8441 requires peer `ENABLE_CONNECT_PROTOCOL`; `wknet::websocket` uses it automatically for eligible `wss` connections. Upgrade reserves stream 1, replays post-101 bytes, and forbids a request body. Server push remains unsupported.
