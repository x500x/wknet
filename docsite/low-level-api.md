# 内部接口边界

wknet 只承诺 `include/wknet` 下的公共 API。`src/wknetlib` 中的内部接口用于库内分层和用户态协议测试，不是可安装 ABI，也不应被产品调用方包含。

## 内部服务

| 层 | 代表接口 | 用途 |
|---|---|---|
| `session` | `HttpSend`、`WsConnect`、`ConnectionPool*` | 产品策略与会话编排 |
| `transport` | opaque `Transport*` 服务、`ProxyConnect` | 明文/TLS 字节流适配与代理隧道 |
| `http1` | 请求构造、响应解析、Transfer-Encoding | HTTP/1.x 状态与纯协议逻辑 |
| `http2` | `Http2Connection`、HPACK、帧与 stream | HTTP/2 状态机 |
| `ws` | 帧、握手校验、permessage-deflate | WebSocket 协议逻辑 |
| `tls` | `TlsConnection`、record、证书验证 | TLS 与信任判断 |
| `net` | `WskClient`、`WskSocket` | WSK 能力 |

## 测试钩子

用户态测试只可通过 `WKNET_USER_MODE_TEST` 下的 `include/wknet/test/Test.h` 窄接口注入传输、IRQL 或异步调度。测试钩子不进入 `Wknet.h` 的正常产品路径。

## 约束

- 公共桥不得包含内部 `net` / `tls` / `http2` 头。
- 跨模块不得包含其他模块的 `*Private.hpp`；白盒测试除外。
- 协议层不得直接读写连接池字段。
- 内部头不得复制到 `include/wknet`。
- 不恢复旧的平行句柄 API、client 类或兼容层。
