# 内部边界

产品只承诺 `include/wknet` 下的公共 ABI。`src/wknetlib` 供库内分层和用户态协议测试使用，不构成可安装 ABI；产品驱动不要包含内部头。

## 公共 vs 内部

| 层 | 位置 | 调用方 |
|----|------|--------|
| 公共 API | `include/wknet/http|websocket|crypto|codec` | 产品驱动 |
| 测试钩子 | `include/wknet/test/Test.h`（`WKNET_USER_MODE_TEST`） | 仅用户态测试 |
| 内部实现 | `src/wknetlib/*` | 库自身 |

`Wknet.h` 只聚合公共头，不包含 session / transport / net / tls 实现头。

## 内部分层（贡献者）

| 命名空间 / 目录 | 职责 |
|-----------------|------|
| `session` | 路由、代理、连接池、重定向、异步、HTTP/WS/H3 编排 |
| `transport` | opaque TCP 字节流（明文 / TLS 包装） |
| `net` | WSK 生命周期、解析、TCP/UDP socket 服务 |
| `tls` | 握手、记录保护、会话恢复、证书验证 |
| `http1` / `http2` / `ws` | 协议状态机 |
| `quic` / `http3` / `qpack` | QUIC v1 / HTTP/3 / QPACK |
| `rtl` | 堆、Workspace、工具 |

边界规则：

- 协议层不直接读写连接池字段；池策略只在 `session`
- `transport::Transport` 只承载 **TCP** 字节流；UDP 归 `net::WskDatagramSocket`；QUIC 状态机归 `quic`
- Alt-Svc 学习 / 竞速 / 回落只在 `session`
- 跨模块不得包含其他模块的 `*Private.hpp`（白盒测试除外）
- 不恢复平行 client 层或第二套网络生命周期

## 测试钩子

用户态测试通过 `WKNET_USER_MODE_TEST` 下的窄接口注入传输、IRQL 或调度。测试钩子不进入 `Wknet.h` 正常产品路径。

## 内存与实现纪律

- 库内禁止栈缓冲；堆对象 + Workspace 常驻高频缓冲
- 无异常、无 RTTI；函数 `noexcept`；SAL 注解
- 实现用独立 `.cpp`，共享声明用 `.h` / `.hpp`；禁止 `.inc` 实现分片

相关：[架构](architecture.md) · [构建与测试](build-and-test.md) · [贡献指南](contributing.md)
