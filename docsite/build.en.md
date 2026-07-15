# Build

Build wknet into the static library `wknetlib.lib` and link it from your driver project.

## Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Windows 10/11 or Windows Server 2016+ |
| Visual Studio | 2022+ (C++ desktop + driver workloads) |
| Windows SDK | 10.0.19041.0 or newer |
| WDK | Matching the SDK version |

Use `pwsh`, not `powershell`.

## Build the library

```powershell
# All configurations × kernel ABIs (x64, ARM64)
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1

# Single ABI
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64

# Or msbuild directly
msbuild wknet.sln /m /restore /p:Configuration=Release /p:Platform=x64
```

Output path:

```text
src/wknetlib/<Platform>/<Configuration>/wknetlib.lib
```

Example: `src/wknetlib/x64/Release/wknetlib.lib`.

## Wire into a driver project

1. Include the umbrella header:

```cpp
#include <wknet/Wknet.h>
```

2. Project settings:

| Setting | Value |
|---------|-------|
| Additional include directories | `$(SolutionDir)include` (or your repo `include`) |
| Additional library directories | Directory that contains `wknetlib.lib` |
| Additional dependencies | `wknetlib.lib` |

3. Add the `wknetlib` project to the solution and set a project dependency so the library builds first.

`Wknet.h` only aggregates the public `http` / `websocket` / `crypto` / `codec` headers. It does **not** include internal session, transport, or engine headers.

## Next

- [First request](first-request.md) — minimal GET / POST
- [Integration checklist](integration-checklist.md) — IRQL, lifetime, unload
- Contributor test matrix: [Build & test](build-and-test.md)
