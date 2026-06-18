# NTSTATUS 错误码 / NTSTATUS Reference

项目统一使用 Windows NTSTATUS 错误码。
The project uses Windows NTSTATUS codes throughout.

[English](#english) | 简体中文

---

## 简体中文

### 常见错误码

| NTSTATUS | 描述 | 处理建议 |
|----------|------|----------|
| `STATUS_SUCCESS` | 操作成功 | - |
| `STATUS_INVALID_PARAMETER` | 参数无效 | 检查输入参数 |
| `STATUS_INSUFFICIENT_RESOURCES` | 资源不足 | 减少并发请求或增加资源 |
| `STATUS_IO_TIMEOUT` | 操作超时 | 增加超时时间或检查网络 |
| `STATUS_CONNECTION_DISCONNECTED` | 连接断开 | 重试请求 |
| `STATUS_TRUST_FAILURE` | 证书信任失败 | 检查证书配置 |
| `STATUS_NOT_SUPPORTED` | 能力未启用/不支持 | 例如 0-RTT 未声明 replay-safe |
| `STATUS_DEVICE_NOT_READY` | WSK 未初始化 | 确认 WskClient 已初始化 |

### 处理示例

```cpp
NTSTATUS status = khttp::Get(session, url, urlLength, &response);
if (!NT_SUCCESS(status)) {
    switch (status) {
    case STATUS_IO_TIMEOUT:
        DbgPrint("Request timed out\n");
        break;
    case STATUS_TRUST_FAILURE:
        DbgPrint("Certificate verification failed\n");
        break;
    case STATUS_CONNECTION_DISCONNECTED:
        DbgPrint("Connection lost, retrying...\n");
        break;
    default:
        DbgPrint("Request failed: 0x%08X\n", status);
        break;
    }
}
```

### 检查惯例

- 用 `NT_SUCCESS(status)` 判断成功，不要直接 `== STATUS_SUCCESS`（有信息性成功码）。
- Release/Close 接受 `nullptr`，失败路径也应统一释放，避免泄漏。

---

## English

### Common codes

| NTSTATUS | Meaning | Suggested handling |
|----------|---------|--------------------|
| `STATUS_SUCCESS` | Success | - |
| `STATUS_INVALID_PARAMETER` | Invalid parameter | Check inputs |
| `STATUS_INSUFFICIENT_RESOURCES` | Out of resources | Reduce concurrency or add resources |
| `STATUS_IO_TIMEOUT` | Timed out | Increase timeout or check network |
| `STATUS_CONNECTION_DISCONNECTED` | Connection dropped | Retry |
| `STATUS_TRUST_FAILURE` | Certificate trust failure | Check certificate configuration |
| `STATUS_NOT_SUPPORTED` | Capability disabled/unsupported | e.g. 0-RTT not marked replay-safe |
| `STATUS_DEVICE_NOT_READY` | WSK not initialized | Ensure WskClient is initialized |

### Conventions

- Use `NT_SUCCESS(status)`, not `== STATUS_SUCCESS` (informational success codes exist).
- Release/Close accept `nullptr`; always release on failure paths to avoid leaks.
