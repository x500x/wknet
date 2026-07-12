# 模块边界

wknet 不再提供独立客户端类。HTTP、HTTPS、HTTP/2 与 WebSocket 都通过同一公共 API 和同一 `session` 生命周期运行。

| 旧职责 | 当前归属 |
|---|---|
| HTTP/1.1 请求往返 | `session/HttpH1Dispatch.cpp` |
| HTTP/2 请求头与请求往返 | `session/Http2RequestBuilder.cpp`、`session/HttpH2Dispatch.cpp` |
| HTTPS 建连与 ALPN | `session/HttpProxy.cpp`、`session/HttpTransportDispatch.cpp`、`tls/TlsConnection.cpp` |
| 代理 CONNECT | `transport/ProxyConnect.cpp`、`session/HttpProxy.cpp` |
| WebSocket 连接与收发 | `session/WsConnect.cpp`、`WsSendData.cpp`、`WsReceive.cpp`、`WsControl.cpp` |

产品调用方只使用 `wknet::http` 与 `wknet::websocket`。这样连接池、重定向、取消、TLS、代理与 HTTP/2 多流不会形成第二条行为不一致的主路径。
