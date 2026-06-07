# KernelHttpTest 全量场景示例设计

## 目标

将示例驱动从 `KernelHttpExample` 改名为 `KernelHttpTest`，并把现有示例扩展为默认运行的全量测试场景矩阵。证书信任包从 `.sys` 所在目录加载，避免固定机器路径。

## 范围

- 工程、输出、INF、服务名、测试脚本和文档引用统一改为 `KernelHttpTest`。
- `DriverEntry` 默认运行高层、底层 HTTP、HTTP/2、WebSocket、故障、负面、并发、大包和边界场景。
- 证书路径由服务 `ImagePath` 推导，加载与 `KernelHttpTest.sys` 同目录的 `cacert.pem`。
- 现有示例中的直接对象分配收敛为项目已有堆对象封装或明确堆分配 helper。
- 用户态测试更新以验证新增示例矩阵和证书路径推导。

## 架构

`DriverEntry` 负责初始化 WSK、推导驱动同目录证书路径、创建示例会话并运行统一的 `RunKernelHttpTestSamples`。该入口聚合高层 API、底层 HTTP、HTTP/2 和新增复杂场景，并将预期失败场景按“命中预期 NTSTATUS/HTTP 状态”为成功记录。

证书加载不再使用固定路径。驱动读取服务注册表 `ImagePath`，转换为 `ZwCreateFile` 可用的 NT 路径，取目录后拼接 `cacert.pem`。集成脚本在构建输出目录复制 `certs/cacert.pem`，使测试与实际 `.sys` 路径一致。

## 场景矩阵

- HTTP：redirect、4xx/5xx、错误体、HEAD/OPTIONS、chunked/compression、大响应、文件/大请求体。
- HTTPS/TLS：verify、no-verify、TLS1.3、ALPN HTTP/1.1/H2、预期证书失败、ALPN 不匹配。
- HTTP/2：TLS ALPN、h2c prior knowledge、h2c upgrade、GOAWAY、RST_STREAM、窗口/continuation 边界。
- WebSocket：文本、二进制、Ex、异步连接、回调接收、ping/pong、close、fragment。
- 运行行为：连接池复用、ForceNew、NoPool、并发异步请求、取消、超时。

## 错误处理

示例聚合结果保留每项状态。真实失败会进入聚合状态；预期失败样例只在得到预期错误时记录成功。驱动加载路径继续完成 `DriverEntry`，但会打印失败项，便于调试。

## 测试

- 用户态 host regression 覆盖新增示例矩阵和路径推导。
- Debug 和 Release 构建均保持最高警告等级和警告视为错误。
- 不运行已知会卡的 smoke 命令。
