# Contributing

Follow these conventions when contributing code or docs. Product direction and naming: [Internals](internals.md).

## Code style

- C++17 under `/kernel`: **no exceptions, no RTTI**
- `namespace`, classes, RAII, and light templates are fine
- Avoid raw `new/delete` (unless overloaded in the lib); prefer heap wrappers or API Release
- **No stack buffers in the lib** — use the heap; keep hot buffers resident in Workspace
- Functions are `noexcept`; use SAL (`_In_`, `_Out_`, `_Must_inspect_result_`, …)
- Debug/Release treat warnings as errors at the highest level; new code is warning-free
- New features must add tiered Trace (Error / Warning / Info / Verbose|Max + accurate component)

## Workflow

- Use `pwsh`, not `powershell`
- After code changes, run tests and a Debug build — no token smoke passes
- If an implementation is missing, **complete it**; do not skip or downgrade
- Do not treat fallbacks or temporary shims as architecture

## Commits

Conventional Commits:

```text
feat:     feature
fix:      bug fix
docs:     documentation
style:    formatting
refactor: refactor
test:     tests
chore:    build/tooling
```

**docsite rules:**

1. Split docsite changes from code changes into **two commits**
2. Prefix docsite commits with `docsite:` (triggers one-way Wiki sync)
3. Plan docs under `docs/plans/*` are committed only when the user asks

## Pull requests

Fork → feature branch → commit → push → PR. Requirements: style match, necessary tests, related docs, green tests.

## Documentation

- Public docs SSOT is `docsite/`; capability SSOT is the [capability matrix](capability-matrix.md)
- Fields and signatures follow `include/wknet` — never copy structs from stale markdown
- Ship Chinese and English together; no English stubs
