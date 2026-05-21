# 驱动加载 HTTP 请求与卸载修复计划

**目标：** 驱动加载后自动执行真实 HTTP 方法请求，打印响应头和响应体；网络失败不阻止驱动加载和卸载。

**范围：** 修改日志宏、WSK 同步等待、驱动加载入口、HTTP 方法请求样例和结果输出。

## 任务

- [x] 在 KernelHttpConfig.h 增加 kprintf 调试日志宏，前缀使用 KernelHttp。
- [x] 为 WSK 同步 IRP 等待增加有限超时，避免 DNS/connect/send/receive/close 无限等待导致卸载卡住。
- [x] 扩展 HTTP 请求样例为真实多方法请求：GET、POST、PUT、PATCH、DELETE、HEAD、OPTIONS。
- [x] 在请求完成后打印每个请求的状态、响应状态行、响应头和响应体。
- [x] 在 DriverEntry 初始化 WSK 后自动运行请求，失败只打印日志，不改变加载成功结果。
- [x] 构建或运行可用测试验证改动。

## 验证

- 运行现有 HTTP parser 用户态测试，确认协议构造和解析逻辑未回归。
- 尝试构建驱动项目；若环境缺少 WDK/VS 组件，记录阻塞原因。
