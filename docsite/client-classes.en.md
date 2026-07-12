# Module Boundaries

wknet no longer exposes separate client classes. HTTP, HTTPS, HTTP/2, and WebSocket all use the same public API and the same `session` lifecycle.

| Former responsibility | Current owner |
|---|---|
| HTTP/1.1 request/response | `session/HttpH1Dispatch.cpp` |
| HTTP/2 request headers and dispatch | `session/Http2RequestBuilder.cpp`, `session/HttpH2Dispatch.cpp` |
| HTTPS connection and ALPN | `session/HttpProxy.cpp`, `session/HttpTransportDispatch.cpp`, `tls/TlsConnection.cpp` |
| Proxy CONNECT | `transport/ProxyConnect.cpp`, `session/HttpProxy.cpp` |
| WebSocket connect and I/O | `session/WsConnect.cpp`, `WsSendData.cpp`, `WsReceive.cpp`, `WsControl.cpp` |

Product callers use only `wknet::http` and `wknet::websocket`. Pooling, redirects, cancellation, TLS, proxies, and HTTP/2 multi-stream behavior therefore stay on one consistent path.
