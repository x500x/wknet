# TLS 与信任

HTTPS 默认 **校验证书**（`CertPolicy::Verify`）。库**不**内置系统 CA：信任锚、中间 CA、SPKI pin、撤销证据均由调用方经 `CertificateStore` / 相关 API 提供。密码学走内核 CNG/BCrypt（及必要的内核内软件实现），**不用 SChannel**。

## 版本路径

- 允许范围内优先 **TLS 1.3**（纯 1.3 ClientHello）；否则直接 TLS 1.2。
- **无握手内自动降级**。若对端证明只能 1.2，失败可分类为 `VersionNegotiation`，由 session **显式重连 1.2**。
- 带 TLS 1.3→1.2 降级哨兵的 ServerHello 视为攻击，硬失败。
- 默认 `MinVersion=Tls12`、`MaxVersion=Tls13`；可收紧为仅 1.3。

## 策略档位

`TlsPolicy.Profile`：

| Profile | 含义 |
|---------|------|
| `ModernDefault`（默认） | 现代套件/群/签名；兼容开关若误开 → `STATUS_INVALID_PARAMETER` |
| `CompatibilityExplicit` | 允许分别打开 RSA-kx、CBC、SHA-1 签名、真重协商 |

默认关闭、需显式开启：TLS 1.2 RSA-kx / CBC / SHA-1 / 重协商、post-handshake client auth、`RequireRevocationCheck`。开启方式见 [能力边界](capability-matrix.md)。

TLS 1.2 强制：Extended Master Secret、安全重协商指示；CBC 必须 Encrypt-then-MAC。

## 证书与主机名

校验在扩展内核栈上运行。要点：

- 链长度有界；解析期拒绝重复扩展与未知 critical 扩展。
- **主机名**：SAN dNSName 通配仅限**单个最左标签**；**IP literal 只匹配 iPAddress SAN**；域名匹配**从不回退 CN**（CN 不参与主机名等价判定）。
- **SPKI pin**：已配置 pin 的主机强校验叶 SPKI；未配置 pin 的主机 fail-open。
- **撤销**：纯离线、证据驱动（stapled OCSP、静态条目、provider 回调的 OCSP/CRL DER）。库**从不在线抓取**。`RequireRevocationCheck` / 强模式查不到或证据无效 → **fail-closed**（`STATUS_TRUST_FAILURE`）。

```cpp
// 信任锚 + 可选 pin（示意）
wknet::http::CertificateStoreOptions o = {};
// o.TrustAnchors / Pins / ... 由调用方填充
wknet::http::CertificateStore* store = nullptr;
NTSTATUS st = wknet::http::CertificateStoreCreate(&o, &store);
config.Tls.Store = store;
config.Tls.Certificate = wknet::http::CertPolicy::Verify;
// SessionClose 后 CertificateStoreClose(store);
```

生产环境严禁 `CertPolicy::NoVerify`（跳过链与主机校验）。`NoVerify` 响应默认也不参与 H3 Alt-Svc 学习。

## mTLS

`TlsClientCredential` 携带证书链与 `Sign` 回调。私钥留在调用方，库内只通过回调完成签名。

## 会话恢复

- 恢复票据绑定 policy 身份、SNI、ALPN、cipher、版本（各版本缓存条数有上限）。
- TLS 1.3 0-RTT early data 仅存在于内部连接选项，**未**暴露在 `wknet::http::TlsConfig` / `SendOptions`；产品 HTTP 路径不能按公共字段开启。

## 与 HTTP 层的交界

| 场景 | 行为 |
|------|------|
| 默认 HTTPS | TCP TLS + HTTP/1.1 或 ALPN `h2` |
| H3 Auto | 仅已认证 TLS 响应可写入 Alt-Svc；SNI/证书/`authority` 绑定 origin |
| 代理 HTTPS | CONNECT 后再 TLS 到目标 |
| WebSocket `wss` | 同一 TLS 配置与校验模型 |
| HTTPS→HTTP redirect | 默认拒绝降级 |

常见失败码：`STATUS_TRUST_FAILURE`（链/主机/pin/锚/撤销）、`STATUS_NOT_SUPPORTED`（策略/版本/0-RTT）、`STATUS_INVALID_NETWORK_RESPONSE`（记录/握手解码）。更多见 [错误码与 FAQ](errors-and-faq.md)。
