# AGENTS.md

## 工作约束
- 请使用 `pwsh`，不要使用 `powershell`；注意两者语法差异。
- 回复请使用简体中文。
- Git commit 必须符合 Conventional Commits 规范，格式为 `feat/fix/chore: 简单说明`，正文用简洁条目说明变更。
- 计划文档可以写，但写完前后都不要先 git 提交；只有用户明确要求提交时才提交。
- 请在做出决策前，先读取.\docs\memory\文件夹内的内容要求，我称之为记忆；请在用户提出全局要求前（涉及这个库的大方向时），请自行写入记忆中
- 如果用户要求 git 回退，含义是：用目标提交覆盖当前工作区，丢弃当前修改，从那个提交重新开始，但不能变动git历史，也就是说：git的所有历史都不能动。
- 如果在按计划文档完成某一项task时，发现缺少了一些实现，请补全而不是忽视、降级。
- 在编写代码后最后一定要进入test（但禁止test烟测）和debug构建测试，遵循写完后就测试编译
- Debug/Release 构建必须视警告为错误，并保持最高警告等级；新增代码需清零所有警告。
- docs文件夹是作为你日常写入计划等的地方
- 关于docsite中的提交，一是要作为单独的提交（如果在既有其它的变更，又有docsite的变更，就要分为两次提交，先提交别的，再提交docsite），二是要用docsite:开头

## 禁止项
- 禁止把“兜底设计”当作正式架构手段。
- 禁止用“临时兜底后面再删”“先这样跑起来”作为引入回退方案的理由。
- 禁止test烟测
- new/delete不要用，除非在lib中重载new/delete
- lib禁止使用栈，请使用堆内存，如果堆内存频繁的被使用，请考虑常驻。lib禁止使用栈，请使用堆内存，如果堆内存频繁的被使用，请考虑常驻！！
- pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild,因为会卡

## 本项目方向
- 产品名 **wknet**，不保留旧产品名、旧命名空间或兼容层。
- 这是一个面向 Windows kernel driver 的 HTTP/HTTPS/WebSocket 客户端库。
- 公共命名空间：`wknet::http`、`wknet::websocket`、`wknet::crypto`、`wknet::codec`。
- 内部命名空间：`rtl` / `net` / `tls` / `http1` / `http2` / `ws` / `transport` / `session` / `detail`。
- 传输层优先使用 WSK；密码学优先内核态 CNG/BCrypt；不把 WinHTTP、WinINet、SChannel 作为内核主路径。
- 调试：`wknet::Trace*` 分级输出，**默认 Off**；测试/wknettest 设 Max。
- 工程：`wknet.sln`、`src/wknetlib`、`src/wknettest`、`include/wknet`；用户态测试宏 `WKNET_USER_MODE_TEST`。
- C++ 可以用来组织代码，例如 `namespace`、类、RAII、轻量模板，但必须符合 `/kernel` 的限制：无异常、无 RTTI，不要依赖内核不可用的标准库能力。
- 架构分层与调用关系见计划与 `docs/plans/2026-07-12-wknet-rename-map.md`；禁止反向依赖与公共头泄漏内部实现。
- `src/wknetlib` 禁止 `.inc` 实现分片；实现使用独立 `.cpp`，共享声明使用 `.h` / `.hpp`。
- 禁止恢复独立 `client` 层；HTTP/HTTPS/HTTP2/WebSocket 编排统一归 `session` / `transport`。
