# 协议完整性偏好

- “协议完整性”应先定义为可审计、可测试的客户端主路径协议覆盖：HTTP/1.1、HTTP/2、TLS 1.2/1.3、证书校验、WebSocket 与代理路径都要有明确能力账本。
- 能力账本中每一项必须归类为：已实现、待补全、有意拒绝、安全边界、明确非目标；不能用“兜底设计”“临时后面删”来掩盖缺口。
- 对 RFC 中不适合内核客户端主路径的能力，应在文档中写成审计过的非目标或安全拒绝，而不是让用户看到“未完成”但不知道原因。
- 补全协议能力时继续遵循内核自实现路线：传输层优先 WSK，密码学优先内核态 CNG/BCrypt，不把 WinHTTP、WinINet、SChannel 作为内核主路径。
- 新增协议路径必须配套用户态协议测试、相关集成测试和 Debug 构建验证；禁止只做烟测。
- 协议能力账本中的实现路径必须指向当前分层文件；不得继续引用已删除的聚合引擎文件、旧 client 类或旧命名空间。
- EXI 的完整支持范围是 W3C EXI 1.0 Second Edition 中不依赖外部 Schema 的流：无 Options 流按 schema-less 处理，支持内建 XML Schema 类型、四种 alignment、Options 与保真项；依赖外部 Schema/strict grammar 的流明确安全拒绝，不扩张公开 Schema API。
- Pack200 的完整支持范围是 Java 5–8 已发布稳定格式 `150.7`、`160.1`、`170.1`、`171.0`，包括裸/gzip、多 segment、完整 class/file/attribute/bytecode 解码与 JAR 重建；不把只解析 header/band 后返回不支持视为完成。
- Pack200 自定义属性完成标准包括 class/field/method/code 四种 context、replication、union range、callable/forward/back-call、overflow indexes、常量池引用与 BCI/offset relocation；真实离线语料必须带 SHA-256 和工具链 provenance，生成工具自身的限制必须透明记录。
- EXI 输出要求 XML Infoset 等价，Pack200 输出要求 JAR 内容与元数据语义等价，不要求恢复编码前的原始 XML/JAR 字节。
