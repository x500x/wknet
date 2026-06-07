# KernelHttpTest Scenario Matrix Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the example driver to `KernelHttpTest`, load certificates from the driver output directory, and run the full scenario matrix by default.

**Architecture:** Keep the existing sample layout but rename the project root to `src/KernelHttpTest`. Add a unified runner that aggregates high-level, low-level HTTP, HTTP/2, WebSocket, negative, fault, concurrent, and large-body scenarios. Certificate loading is driven by the service `ImagePath` and the sibling `cacert.pem` file.

**Tech Stack:** Windows kernel driver C++17 with WDK, WSK, kernel CNG, MSBuild, pwsh integration script, user-mode C++ regression tests.

---

## File Structure

- Rename: `src/KernelHttpExample/` -> `src/KernelHttpTest/`
- Rename: `src/KernelHttpTest/KernelHttpExample.vcxproj` -> `src/KernelHttpTest/KernelHttpTest.vcxproj`
- Rename: `src/KernelHttpTest/KernelHttpExample.vcxproj.filters` -> `src/KernelHttpTest/KernelHttpTest.vcxproj.filters`
- Rename: `src/KernelHttpTest/KernelHttpExample.inf` -> `src/KernelHttpTest/KernelHttpTest.inf`
- Modify: `KernelHttp.sln`
- Modify: `src/KernelHttpTest/DriverEntry.cpp`
- Modify: `src/KernelHttpTest/samples/*.h`
- Modify: `src/KernelHttpTest/samples/*.cpp`
- Modify: `tests/high_level_api_tests.cpp`
- Modify: `tests/integration/https_smoke.ps1`
- Modify: `README.md`, `README_en.md`, `docs/*.md` references

## Chunk 1: Rename Project

- [x] Move `src/KernelHttpExample` to `src/KernelHttpTest` after verifying both resolved paths.
- [x] Update project file names and internal `RootNamespace`, `TargetName`, INF include, and filter references.
- [x] Update `KernelHttp.sln` project name and project path.
- [x] Update integration script defaults: service name, include path, sample source paths, and driver binary path.
- [x] Update documentation references from `KernelHttpExample` to `KernelHttpTest`.

## Chunk 2: Certificate Path From SYS Directory

- [x] Add a small path helper in `DriverEntry.cpp` to read service `ImagePath` from `registryPath`.
- [x] Normalize supported image path forms and derive the directory.
- [x] Build a nonpaged ANSI path for sibling `cacert.pem`.
- [x] Pass that path into `RunKernelHttpTestSamples` and `InitializeExternalTrustStore`.
- [x] Update the integration script to copy `certs/cacert.pem` beside `KernelHttpTest.sys` before VM load.

## Chunk 3: Unified Scenario Runner

- [x] Replace `RunKhttpSamples` alias behavior with `RunKernelHttpTestSamples`.
- [x] Aggregate high-level, low-level HTTP, HTTP/2, and WebSocket sample results.
- [x] Remove macro gating for default complex sample execution.
- [x] Treat expected negative cases as success only when the expected status is observed.
- [x] Keep `DriverEntry` returning success after logging sample failures, matching existing load behavior.

## Chunk 4: Existing Sample Cleanup

- [x] Replace direct sample `new/delete` usage with `HeapObject`/`HeapArray` where practical.
- [x] Keep user-mode test allocation behavior compatible with existing tests.
- [x] Preserve `/kernel` constraints: no exceptions, no RTTI, no unsupported standard library use.
- [x] Keep all new buffers on heap or persistent storage.

## Chunk 5: Add Missing Scenarios

- [x] HTTP: redirect, 4xx/5xx, large response, file/large body, chunked/compression sample coverage.
- [x] Runtime behavior: connection pool reuse, ForceNew/NoPool, async concurrency, cancel, timeout.
- [x] TLS: verify/no-verify, expected trust failure, ALPN mismatch.
- [x] HTTP/2: default TLS ALPN/h2c plus GOAWAY/RST/window/continuation boundary samples.
- [x] WebSocket: ping/pong, close, fragment, binary/text callback variants.

## Chunk 6: Tests And Build

- [x] Update user-mode regression tests for renamed paths and new sample result fields.
- [ ] Add tests for `.sys` sibling certificate path derivation.
- [x] Run focused host regressions manually without invoking smoke/load flow.
- [x] Build Debug x64 with warnings as errors.
- [x] Build Release x64 with warnings as errors.
- [x] Inspect `git status --short` and summarize changed files.
