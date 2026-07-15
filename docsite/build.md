# 构建

把 wknet 编成可链接的静态库 `wknetlib.lib`，并接到你的驱动工程。

## 环境

| 组件 | 要求 |
|------|------|
| 操作系统 | Windows 10/11 或 Windows Server 2016+ |
| Visual Studio | 2022+（含 C++ 桌面与驱动开发组件） |
| Windows SDK | 10.0.19041.0 或更高 |
| WDK | 与 SDK 版本匹配 |

使用 `pwsh`，不要用 `powershell`。

## 编库

```powershell
# 全部配置 x 全部内核 ABI（x64、ARM64）
pwsh -NoLogo -NoProfile -File .	oolsuild-lib.ps1

# 单 ABI
pwsh -NoLogo -NoProfile -File .	oolsuild-lib.ps1 -Configuration Debug -Platform x64

# 或直接 msbuild
msbuild wknet.sln /m /restore /p:Configuration=Release /p:Platform=x64
```

产物路径：

```text
src/wknetlib/<Platform>/<Configuration>/wknetlib.lib
```

例如 `src/wknetlib/x64/Release/wknetlib.lib`。

## 接到驱动工程

1. 包含总头：

```cpp
#include <wknet/Wknet.h>
```

2. 项目属性：

| 项 | 值 |
|----|-----|
| 附加包含目录 | `$(SolutionDir)include`（或你的仓库 `include`） |
| 附加库目录 | 指向含 `wknetlib.lib` 的目录 |
| 附加依赖项 | `wknetlib.lib` |

3. 把 `wknetlib` 工程加入解决方案并设为依赖，保证先编库。

`Wknet.h` 只聚合公共 `http` / `websocket` / `crypto` / `codec` 头，**不包含**内部 session、transport 或 engine 头。

## 下一步

- [第一个请求](first-request.md) — 最小 GET / POST
- [集成要点](integration-checklist.md) — IRQL、生命周期、卸载
- 贡献者测试矩阵见 [构建与测试](build-and-test.md)
