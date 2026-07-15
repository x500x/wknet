# 贡献指南

为 wknet 贡献代码或文档时遵守以下约定。产品方向与命名见 [内部边界](internals.md)。

## 代码风格

- C++17，符合 `/kernel`：**无异常、无 RTTI**
- 可用 `namespace`、类、RAII、轻量模板
- 避免直接 `new/delete`（除非 lib 内重载）；优先堆封装或 API Release
- **lib 内禁止栈缓冲**，用堆；高频缓冲常驻 Workspace
- 函数 `noexcept`；SAL 注解（`_In_`、`_Out_`、`_Must_inspect_result_` 等）
- Debug/Release 均视警告为错误、最高警告等级；新增代码零警告
- 新功能必须补齐分级 Trace（Error / Warning / Info / Verbose|Max + 准确组件）

## 工作流

- 使用 `pwsh`，不要用 `powershell`
- 写完代码必须跑测试与 Debug 构建；禁止「冒烟走过场」
- 发现实现缺失时**补全**，不要忽视或降级
- 禁止把兜底 / 临时回退当作正式架构

## 提交

Conventional Commits：

```text
feat:     新功能
fix:      缺陷
docs:     文档
style:    格式
refactor: 重构
test:     测试
chore:    构建/工具
```

**docsite 提交：**

1. docsite 变更与代码变更分两次提交
2. docsite 提交 message 以 `docsite:` 开头（触发 Wiki 单向同步）
3. 计划文档（`docs/plans/*`）仅在用户明确要求时提交

## PR

Fork → 功能分支 → 提交 → Push → Pull Request。要求：风格一致、必要测试、相关文档、测试通过。

## 文档

- 公开文档以 `docsite/` 为准；能力分类以 [能力边界](capability-matrix.md) 为准
- 字段与签名以 `include/wknet` 为准，勿从过时 markdown 抄结构体
- 中英同批对等；勿留英文占位 stub
