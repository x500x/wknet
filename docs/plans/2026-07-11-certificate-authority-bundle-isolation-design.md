# Certificate Authority Bundle Isolation Design

## 目标

修复外部 PEM CA 信任包中单个不可解析证书导致整个信任锚搜索提前失败的问题，同时保持证书校验的 fail-closed 安全语义。

## 问题

- `CertificateStore` 将外部 `cacert.pem` 保存为一个 `CertificateAuthorityBundle`。
- 信任锚搜索会按顺序解码并解析包内证书。
- 当前实现遇到任意一个无法解析或暂不支持的证书就立即返回，后续有效信任锚不会再被搜索。
- 结果是无关 CA 条目的兼容性问题被错误提升为目标服务器证书链的 `STATUS_INVALID_NETWORK_RESPONSE`。

## 设计

### 信任包集合语义

- PEM AuthorityBundle 是独立 CA 证书成员的集合。
- 单个 PEM 块边界完整，但 Base64、DER 或当前 X.509 能力无法处理时，该成员不参与信任判断，并继续搜索下一成员。
- 解析失败的成员绝不能成为信任锚，也不能降低目标证书链的验证要求。
- 如果缺失 PEM 结束边界，无法可靠确定下一成员位置，则整个 AuthorityBundle 返回格式错误。
- 单 DER AuthorityBundle 不具备可继续扫描的集合边界，解析失败仍直接返回。

### 状态分类

- 可隔离的成员错误：`STATUS_INVALID_NETWORK_RESPONSE`、`STATUS_NOT_SUPPORTED`、`STATUS_BUFFER_TOO_SMALL`。
- 必须传播的运行时错误：参数错误、内存分配失败、密码学执行失败以及其他未明确归类的状态。
- 完成全部可用成员扫描但未找到信任锚时，按正常信任失败返回 `STATUS_TRUST_FAILURE`。

### 诊断

- 对被隔离的 PEM 成员输出 bundle 内证书序号、起始偏移和 NTSTATUS。
- 日志必须明确这是“authority certificate skipped”，不能误报为目标服务器证书链损坏。

## 数据流

1. 定位下一 `BEGIN CERTIFICATE` 和对应 `END CERTIFICATE`。
2. 在确认结束边界后立即产生安全的 `nextOffset`。
3. 解码 Base64；成员级格式或容量问题可根据 `nextOffset` 隔离。
4. 解析 DER/X.509；成员级格式或能力问题被隔离。
5. 仅对成功解析的证书执行 Subject、SPKI、路径长度和签名匹配。
6. 找到匹配锚则成功；否则继续到包尾并返回未找到。

## 测试

- 无效 PEM 成员位于有效根证书之前时，后续有效根仍能建立信任。
- 信任包只有无效成员时，不产生信任并返回 `STATUS_TRUST_FAILURE`。
- 缺少 PEM 结束边界时返回 `STATUS_INVALID_NETWORK_RESPONSE`。
- 损坏的单 DER AuthorityBundle 继续严格失败。
- 使用仓库真实 `certs/cacert.pem` 完整扫描，确保无关条目不会提前返回协议解析错误。
- 运行 `tls_record_tests`，然后执行 x64 Debug 内核库构建；全程 `/W4 /WX`，不运行烟测。

## 记忆

新增 `docs/memory/certificate-trust-store.md`，记录 AuthorityBundle 的集合语义、失败分类、诊断要求和真实信任包回归测试要求。
