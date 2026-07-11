# Certificate Authority Bundle Isolation Implementation Plan

> **For agentic workers:** REQUIRED: Execute this plan in the current session. Steps use checkbox (`- [ ]`) syntax for tracking. Do not use subagents unless explicitly authorized.

**Goal:** 让外部 PEM CA 信任包隔离不可用成员并继续搜索有效信任锚，同时保持结构损坏和运行时错误严格失败。

**Architecture:** 在 `CertificateValidator.cpp` 的 PEM 解码与 AuthorityBundle 扫描边界实现成员级错误分类。完整 PEM 边界提供可恢复的下一偏移；只有明确的成员格式/能力错误可跳过，其他错误继续传播。

**Tech Stack:** C++17、Windows NTSTATUS、内核兼容堆内存封装、现有 `tls_record_tests`、MSVC `/W4 /WX`、WDK x64 Debug。

**Execution Status:** 已按计划完成实现、回归测试、记忆写入和 x64 Debug 构建；未执行 Git 提交或烟测。

---

## Chunk 1: 回归测试与正式语义

### Task 1: 添加失败回归测试

**Files:**
- Modify: `tests/tls_record_tests.cpp`

- [ ] **Step 1: 添加真实信任包路径和容量常量**

增加 `certs\\cacert.pem` 路径和不低于现有外部信任包 2 MiB 限制的测试容量。使用 `HeapArray<UCHAR>`，不在栈上放置信任包。

- [ ] **Step 2: 添加“无效成员后仍找到有效根”测试**

构造 `无效但边界完整的 PEM + tests/testdata/pki/root.cert.pem` AuthorityBundle，并使用现有 PKI leaf/intermediate 建链。修复前预期返回 `STATUS_INVALID_NETWORK_RESPONSE`，修复后预期 `STATUS_SUCCESS`。

- [ ] **Step 3: 添加“只有无效成员不产生信任”测试**

使用只有无效 PEM 成员的 AuthorityBundle，预期最终为 `STATUS_TRUST_FAILURE`，不能返回成功。

- [ ] **Step 4: 添加不可恢复结构损坏测试**

构造只有 `BEGIN CERTIFICATE`、没有 `END CERTIFICATE` 的 AuthorityBundle，预期 `STATUS_INVALID_NETWORK_RESPONSE`。

- [ ] **Step 5: 添加单 DER 严格失败测试**

传入损坏的单 DER AuthorityBundle，预期保留 `STATUS_INVALID_NETWORK_RESPONSE`。

- [ ] **Step 6: 添加真实 `cacert.pem` 完整扫描测试**

从堆读取仓库 `certs/cacert.pem`，使用不受其信任的 localhost 证书触发完整扫描。预期 `STATUS_TRUST_FAILURE`，并明确断言不是 `STATUS_INVALID_NETWORK_RESPONSE` 或 `STATUS_NOT_SUPPORTED`。

- [ ] **Step 7: 注册新测试并确认修复前失败**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_record_tests -Run
```

Expected: 新增的隔离测试至少一项失败，现有测试继续编译。

## Chunk 2: AuthorityBundle 成员隔离实现

### Task 2: 提供可恢复的 PEM 块边界

**Files:**
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp:2821`

- [ ] **Step 1: 在发现完整 PEM 结束标记后设置 `nextOffset`**

`DecodePemCertificate` 在开始 Base64 解码前记录结束标记后的偏移。若 Base64 内容失败，调用方仍能安全定位下一成员。

- [ ] **Step 2: 保持缺失结束边界严格失败**

没有 `END CERTIFICATE` 时不得生成恢复偏移，继续返回 `STATUS_INVALID_NETWORK_RESPONSE`。

### Task 3: 隔离明确的成员级错误

**Files:**
- Modify: `src/KernelHttpLib/tls/CertificateValidator.cpp:4930-5000`

- [ ] **Step 1: 增加成员状态分类帮助函数**

仅将以下状态归类为可隔离：

```cpp
STATUS_INVALID_NETWORK_RESPONSE
STATUS_NOT_SUPPORTED
STATUS_BUFFER_TOO_SMALL
```

- [ ] **Step 2: 调整 PEM AuthorityBundle 扫描循环**

解码或 `ParseCertificate` 返回可隔离状态且 `nextOffset` 已越过当前成员时，记录序号、起始偏移和状态，清理临时解析结果并继续。

- [ ] **Step 3: 保持运行时错误传播**

内存、参数及其他状态立即返回；签名匹配阶段的错误不允许被成员隔离逻辑吞掉。

- [ ] **Step 4: 保持单 DER 分支严格语义**

无 PEM 起始标记的 AuthorityBundle 继续作为单 DER 解析，任何失败直接返回。

- [ ] **Step 5: 运行 TLS 正式单元测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_record_tests -Run
```

Expected: 全部测试通过，编译警告为零。

## Chunk 3: 记忆与验证

### Task 4: 写入长期记忆

**Files:**
- Create: `docs/memory/certificate-trust-store.md`

- [ ] **Step 1: 记录信任包集合语义**

写明不可用成员不参与信任、不会阻止其他独立成员、不可恢复结构损坏必须失败。

- [ ] **Step 2: 记录安全与测试要求**

写明不得把跳过成员做成宽松证书校验；真实 CA bundle 必须进入用户态回归测试。

### Task 5: 最终构建验证

**Files:**
- Verify: `src/KernelHttpLib/tls/CertificateValidator.cpp`
- Verify: `tests/tls_record_tests.cpp`
- Verify: `docs/memory/certificate-trust-store.md`

- [ ] **Step 1: 再次运行 TLS 单元测试**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-tests.ps1 -Test tls_record_tests -Run
```

Expected: PASS，零警告。

- [ ] **Step 2: 构建 x64 Debug 内核库**

Run:

```powershell
pwsh -NoLogo -NoProfile -File .\tools\build-lib.ps1 -Configuration Debug -Platform x64
```

Expected: `x64\Debug\KernelHttpLib.lib` 成功生成，警告视为错误且零警告。

- [ ] **Step 3: 检查工作区差异**

Run:

```powershell
git diff --check
git status --short
```

Expected: 无空白错误；只包含本次代码、测试、记忆及未提交计划文档。禁止 Git 提交，禁止烟测。
