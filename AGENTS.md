# AGENTS.md

## 工作约束
- 请使用 `pwsh`，不要使用 `powershell`；注意两者语法差异。
- 回复请使用简体中文。
- Git commit 必须符合 Conventional Commits 规范，格式为 `feat/fix/chore: 简单说明`，正文用简洁条目说明变更。
- 计划文档可以写，但写完前后都不要先 git 提交；只有用户明确要求提交时才提交。
- 如果用户要求 git 回退，含义是：用目标提交覆盖当前工作区，丢弃当前修改，从那个提交重新开始，但不能变动git历史，也就是说：git的所有历史都不能动。
- 如果在按计划文档完成某一项task时，发现缺少了一些实现，请补全而不是忽视、降级。
- 在编写代码后最后一定要进入test（但禁止test烟测）和debug构建测试，遵循写完后就测试编译
- Debug/Release 构建必须视警告为错误，并保持最高警告等级；新增代码需清零所有警告。
- docs文件夹是作为你日常写入计划等的地方

## 禁止项
- 禁止把“兜底设计”当作正式架构手段。
- 禁止用“临时兜底后面再删”“先这样跑起来”作为引入回退方案的理由。
- 禁止test烟测
- new/delete不要用，除非在lib中重载new/delete
- lib禁止使用栈，请使用堆内存，如果堆内存频繁的被使用，请考虑常驻。
- pwsh -NoLogo -NoProfile -File .\tests\integration\https_smoke.ps1 -Configuration Debug -Platform x64 -SkipDriverBuild,因为会卡

## 本项目方向
- 这是一个面向 Windows kernel driver 的 HTTP/HTTPS 实现项目。
- 传输层优先使用 WSK。
- 密码学基础优先使用内核态 CNG/BCrypt。
- HTTP/HTTPS、TLS record/handshake、证书校验都按内核自实现路线推进。
- 不把 WinHTTP、WinINet、SChannel 作为内核主路径。
- C++ 可以用来组织代码，例如 `namespace`、类、RAII、轻量模板，但必须符合 `/kernel` 的限制：无异常、无 RTTI，不要依赖内核不可用的标准库能力。
