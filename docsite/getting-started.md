# 快速开始

### 环境要求

| 组件 | 版本要求 |
|------|---------|
| 操作系统 | Windows 10/11 或 Windows Server 2016+ |
| Visual Studio | 2022 或更高版本 |
| Windows SDK | 10.0.19041.0 或更高 |
| Windows Driver Kit (WDK) | 与 SDK 版本匹配 |

### Step 1：编译成静态库

1. 克隆仓库
   ```bash
   git clone https://github.com/x500x/khttp.git
   cd khttp
   ```
2. 用 Visual Studio 打开 `KernelHttp.sln`，选择配置（Debug/Release）与平台（x64/ARM64），按 `Ctrl+Shift+B` 构建。
3. 或用命令行：
   ```powershell
   # 构建 KernelHttpLib 的全部内核 ABI（x64、ARM64）
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1

   # 只构建单个 ABI
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64

   # 或直接 msbuild
   msbuild KernelHttp.sln /p:Configuration=Release /p:Platform=x64
   ```
4. 产物位于 `<Platform>/<Configuration>/KernelHttpLib.lib`。

### Step 2：集成到你的驱动项目

1. 包含总头文件：
   ```cpp
   #include <KernelHttp/KernelHttp.h>
   ```
2. 在项目属性中添加：
   - 附加包含目录：`$(SolutionDir)include`
   - 附加库目录：`$(SolutionDir)src\KernelHttpLib\$(Platform)\$(Configuration)\`
   - 附加依赖项：`KernelHttpLib.lib`
3. 把 `KernelHttpLib` 项目加入解决方案并设为依赖，确保先编译它。

### 最简示例（高层 API）

```cpp
#include <KernelHttp/KernelHttp.h>

NTSTATUS SimpleHttpGet() {
    khttp::Session* session = nullptr;
    NTSTATUS status = khttp::SessionCreate(&session);
    if (!NT_SUCCESS(status)) return status;

    khttp::Response* response = nullptr;
    status = khttp::GetEx(session, "http://example.com/api", 22, nullptr, nullptr, &response);
    if (NT_SUCCESS(status)) {
        ULONG code = khttp::ResponseStatusCode(response);
        const UCHAR* body = khttp::ResponseBody(response);
        SIZE_T len = khttp::ResponseBodyLength(response);
        // ... 处理响应 ...
        khttp::ResponseRelease(response);
    }
    khttp::SessionClose(session);
    return status;
}
```

> 下一步：阅读 [能力边界](capability-matrix.md) 了解协议支持范围，再看 [高层 API](high-level-api.md)。
