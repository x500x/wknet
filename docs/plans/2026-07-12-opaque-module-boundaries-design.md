# wknet 不透明模块边界设计

## 目标

将跨模块有状态对象改为不透明句柄，完成公共 TLS 边界、内部命名空间、连接池字段所有权、工程元数据、旧命名和测试警告等级的最终收口，同时保持现有 HTTP、TLS、HTTP/2、WebSocket、证书校验与资源默认行为不变。

## 公共 API

- 删除公共 `include/wknet/tls/`。
- 证书、撤销、pin、mTLS 值类型迁入 `wknet::http`。
- `wknet::http::CertificateStore` 为不完整类型，通过 Create/Load/Close API 管理。
- `TlsConfig` 只引用公共 `CertificateStore` 与公共 mTLS 描述。
- `ProxyConfig` 使用主机名或 IP 文本、端口和地址族，不再公开 `SOCKADDR_STORAGE` 或包含 `wsk.h`。
- `include/wknet/test/Test.h` 使用独立 `wknet::test` 窄接口，不包含 session 私有头。
- 不保留旧命名空间、类型别名或兼容层。

## 内部句柄边界

| 模块 | 不透明对象 | 对外服务 |
|---|---|---|
| `net` | `NetRuntime`、`Socket` | 创建、解析、连接、收发、取消、关闭 |
| `transport` | `Transport` | 创建 WSK/TLS 适配、收发、取消、关闭 |
| `tls` | `Connection`、内部证书存储 | 创建、握手、收发、关闭、查询协商结果 |
| `http2` | `Connection` | 创建、初始化、请求、响应、PING、关闭 |
| `session` | `PooledConnection` | 获取、接管、查询、状态更新、租约和管线操作 |

完整布局只允许出现在所属模块私有实现头或拥有该对象的 `.cpp` 中。其他模块只能保存句柄指针并调用服务函数。

`transport::Transport` 取代跨模块虚类 `ITransport`。其私有实现可使用函数表完成 WSK、TLS 和测试传输分派，但函数表不进入模块服务头。

## 所有权与失败清理

资源遵循“创建但未归属、初始化成功、连接池原子接管”的顺序：

1. 所属模块创建句柄。
2. 初始化、连接或握手完整成功。
3. `ConnectionPoolAdopt*` 取得所有权。
4. 接管失败时由调用方按相反顺序关闭。
5. 接管成功后仅连接池负责关闭。

跨模块 getter 返回 borrowed handle，不转移所有权。ALPN、代理隧道状态、连接资源和租约变化必须通过连接池服务完成。

所有接口继续返回 `NTSTATUS`；Create 失败时输出句柄保持 `nullptr`。不增加回退实现，不改变重试、重定向、证书验证、响应上限或 WebSocket 行为。

## 证书与代理数据流

公共 `CertificateStore` 持有内部 TLS 证书存储句柄。PEM bundle 继续按独立成员隔离可恢复错误；DER 解析、边界破坏、分配失败和密码学错误严格失败。

代理由公共主机名或 IP 文本和端口描述。session 将配置映射为内部路由，net 层完成解析，连接池 key 保存规范化后的 endpoint 身份。

## 架构闸门与验证

新增确定性的架构检查，验证：

- 公共头不引用内部模块，公共树不存在内部目录。
- 不存在 `wknet::core`。
- 连接池字段不在 `ConnectionPool.cpp` 外访问。
- 模块私有状态头不被其他模块包含。
- vcxproj/filters 不引用不存在文件或旧目录名。
- 排除证书数据和真实外部仓库 URL 后，不残留旧产品名和旧宏。

第一方用户态测试使用 `/Wall /WX /EHsc- /GR-`；第三方 Brotli/Zstd 单独编译。运行全部用户态测试以及 wknetlib/wknettest 的 Debug、Release x64 构建，禁止 smoke。

同步更新符号映射、协议账本、README 和 docsite。计划文档不自动提交；若后续提交，docsite 必须单独使用 `docsite:` 提交。
