# Getting Started

### Requirements

| Component | Version |
|-----------|---------|
| OS | Windows 10/11 or Windows Server 2016+ |
| Visual Studio | 2022 or later |
| Windows SDK | 10.0.19041.0 or later |
| Windows Driver Kit (WDK) | Matching the SDK version |

### Step 1: Build the static library

1. Clone:
   ```bash
   git clone https://github.com/x500x/khttp.git
   cd khttp
   ```
2. Open `wknet.sln` in Visual Studio, pick a configuration (Debug/Release) and platform (x64/ARM64), then `Ctrl+Shift+B`.
3. Or from the command line:
   ```powershell
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1
   pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
   msbuild wknet.sln /p:Configuration=Release /p:Platform=x64
   ```
4. Output: `<Platform>/<Configuration>/wknetlib.lib`.

### Step 2: Integrate into your driver project

1. Include the umbrella header:
   ```cpp
   #include <wknet/Wknet.h>
   ```
2. In project properties add:
   - Additional include directories: `$(SolutionDir)include`
   - Additional library directories: `$(SolutionDir)src\wknetlib\$(Platform)\$(Configuration)\`
   - Additional dependencies: `wknetlib.lib`
3. Add the `wknetlib` project to your solution and set it as a build dependency.

### Minimal example (high-level API)

See the Chinese section above — the code is identical.

> Next: read the [Capability Matrix](capability-matrix.md), then the [High-Level API](high-level-api.md).
