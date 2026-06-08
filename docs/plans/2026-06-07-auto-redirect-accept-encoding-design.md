# 自动重定向与默认 Accept-Encoding 设计

## 背景

当前高层 `khttp`/engine 发送路径会透传用户设置的请求头，但不会自动声明项目已支持的响应压缩格式。高级场景样例把 HTTP redirect 当作 302 响应观察，不会默认跟随 `Location`。

## 目标

- HTTP 发送默认自动跟随重定向，除非用户通过发送参数禁用。
- 用户可自定义最大重定向跟随次数；默认值为 10。
- 请求默认添加 `Accept-Encoding: gzip, deflate, br, identity`，除非用户已经手动设置 `Accept-Encoding`。
- 用户态回归测试与驱动加载期样例测试都覆盖默认重定向、禁用重定向、自定义次数、默认 header 和用户 header 保留。

## 方案

在 `KhHttpSendOptions`/`khttp::SendOptions` 增加：

- `KhHttpSendFlagDisableAutoRedirect` / `SendFlagDisableAutoRedirect`：禁用自动重定向。
- `MaxRedirects`：最大自动重定向次数。为 0 时使用默认值 10；设置显式值时使用该值。禁用 flag 优先于该值。

在 `HttpEngine.cpp` 的高层同步发送主流程中实现重定向循环，保证用户态测试替身和真实内核 WSK/TLS 路径走同一套逻辑。每次请求都通过现有 `BuildRequestBytes` 重新构建，复用现有 header scratch、workspace、连接池和回收逻辑。重定向响应仅作为中间响应使用；最终响应才触发回调和聚合。

## 重定向语义

- 跟随状态码：`301`、`302`、`303`、`307`、`308`。
- `GET`/`HEAD` 原样跟随。
- `303` 以及 `301`/`302` 上的非 `GET`/`HEAD` 改为 `GET`，并清掉请求体和实体相关 header。
- `307`/`308` 保留方法和请求体。
- 支持绝对 `Location` 和以 `/` 开头的相对 `Location`；相对路径基于当前 scheme/host/port 合成。
- 跨 `http`/`https` 允许，TLS ServerName 在没有用户 TLS override 时随目标 host 更新。
- 超过最大跟随次数时返回最后一个 3xx 响应。

## Accept-Encoding

在 `BuildHttpRequestOptions` 组装请求 header 时检测用户 header；若没有 `Accept-Encoding`，追加 `gzip, deflate, br, identity`。HTTP/2 路径通过同一组 request headers 提取 promoted `AcceptEncoding`，避免重复。

## 测试

- `tests/khttp_tests.cpp`：覆盖默认添加 `Accept-Encoding`、用户自定义值不被覆盖、默认跟随重定向、禁用自动重定向、自定义最大次数。
- `tests/high_level_api_tests.cpp`：更新驱动样例替身，默认 redirect 样例最终为 200，并新增禁用重定向样例保持 302。
- `src/KernelHttpTest/samples/AdvancedScenarioSamples.*`：新增禁用重定向样例结果。
- 运行用户态回归测试与 Debug x64 驱动构建，保持 `/W4 /WX` 清零警告。
