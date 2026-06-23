# Contributing

### Code style (kernel C++ constraints)

- C++17 under `/kernel` limits: **no exceptions, no RTTI**, no kernel-unavailable STL.
- Organize with `namespace`, classes, RAII, lightweight templates.
- Avoid raw `new/delete` (unless overloaded in the lib); prefer heap wrappers or API release functions.
- **No stack buffers in the lib** — use heap; keep hot buffers resident in the Workspace.
- Mark all functions `noexcept`.
- Use SAL annotations (`_In_`, `_Out_`, `_Must_inspect_result_`, …).
- Debug/Release builds treat warnings as errors at the highest level; new code must be warning-free.

### Workflow constraints

- Use `pwsh`, not `powershell`.
- After writing code you must run **tests** and a **debug build** — no token "smoke testing".
- If an implementation is missing, **complete it** rather than skipping or downgrading.
- Do not treat fallback hacks as architecture, and do not justify fallbacks with "just get it running".

### Commit conventions (Conventional Commits)

`feat / fix / docs / style / refactor / test / chore:` short summary, with concise bullet points in the body.

### PR flow

Fork → branch (`feature/AmazingFeature`) → commit → push → open a Pull Request. Follow the code style, add tests, update docs, and make sure all tests pass.
