# 贡献指南

### 代码风格（内核 C++ 限制）

- 使用 C++17，但遵循 `/kernel` 限制：**无异常、无 RTTI**，不依赖内核不可用的标准库能力。
- 可用 `namespace`、类、RAII、轻量模板组织代码。
- 避免直接 `new/delete`（除非在 lib 内重载）；优先项目堆对象封装或 API 释放函数。
- **lib 内禁止使用栈缓冲**，请用堆内存；高频缓冲考虑常驻 Workspace。
- 所有函数标记 `noexcept`。
- 使用 SAL 注解（`_In_`、`_Out_`、`_Must_inspect_result_` 等）。
- Debug/Release 构建均视警告为错误、保持最高警告等级；新增代码须清零所有警告。

### 工作流约束

- 使用 `pwsh`，不要用 `powershell`。
- 写完代码必须进入 **test** 与 **debug 构建测试**，禁止「冒烟测试」式走过场。
- 发现实现缺失时**补全**，不要忽视或降级。
- 不把「兜底设计」当作正式架构手段，不以「先跑起来」为由引入回退方案。

### 提交规范（Conventional Commits）

```
feat:     添加新功能
fix:      修复 bug
docs:     文档更新
style:    代码格式调整
refactor: 代码重构
test:     测试相关
chore:    构建/工具相关
```

格式：`feat/fix/chore: 简单说明`，正文用简洁条目说明变更。

### 提交流程

1. Fork 项目
2. 创建功能分支：`git checkout -b feature/AmazingFeature`
3. 提交：`git commit -m 'feat: Add some AmazingFeature'`
4. 推送：`git push origin feature/AmazingFeature`
5. 创建 Pull Request

### 贡献要求

- 遵循项目代码风格
- 添加必要的测试
- 更新相关文档
- 确保所有测试通过
