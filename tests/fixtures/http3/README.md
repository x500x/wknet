# HTTP/3 独立互操作 peer

本目录只用于测试，不参与 `wknetlib` 或 `wknettest` 产品链接。

- `aioquic_peer.py`：固定 aioquic 1.2.0 的独立 HTTP/3 server peer。
- `msquic_peer_*.cpp`：固定 MsQuic 2.5.8 的独立 HTTP/3 server peer；支持真实 Retry、VN、Key Phase
  update，以及通过本地 UDP proxy 注入的丢包和乱序。
- `aioquic-requirements.txt`：完整固定 Python wheel 版本和 SHA-256。
- `peer-manifest.psd1`：固定 aioquic 与 MsQuic 的版本、来源和哈希。
- `SHA256SUMS`：测试依赖制品哈希清单。

MsQuic 源码固定为 commit `bf10e4a60dd03c471343623eccd35b4ea671937f`，其 XDP 子模块固定为 commit
`f23b1fb4d492d9c20bcd7767bba2278f94355df8`；下载归档必须匹配 `peer-manifest.psd1` 和
`SHA256SUMS` 中的 SHA-256。MsQuic 库固定构建 Release：MsQuic 2.5.8 Debug 会在合法的 IPv4
`max_udp_payload_size=1200` 对端上触发其内部 IPv6 最小 MTU 断言；测试 peer 自有 C++ 代码仍按传入配置
构建，并始终使用 `/Wall /WX`。

两套 peer 均覆盖 handshake、GET、HEAD、POST、trailers、并发请求、GOAWAY、cancel、Retry、VN、
loss-reorder 和 key-update 共 12 个场景。测试脚本只把依赖和临时 PFX 安装或生成到
`tests/out/http3-peers`，不会修改产品工程、产品链接或运行时依赖。peer 日志只记录场景、帧类型、长度和计数，
不记录密钥、token、请求头值或请求体内容。
