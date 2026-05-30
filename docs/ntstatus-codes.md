# NTSTATUS 错误码参考

本文档列出 KernelHttp 项目中常见的 NTSTATUS 错误码及其含义，帮助开发者进行错误处理。

[English Version](#english-version) | 简体中文

---

## 目录

- [成功状态](#成功状态)
- [信息状态](#信息状态)
- [警告状态](#警告状态)
- [错误状态](#错误状态)
- [在 KernelHttp 中使用](#在-kernelhttp-中使用)
- [错误处理最佳实践](#错误处理最佳实践)

---

## 成功状态

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0x00000000 | STATUS_SUCCESS | 操作成功完成 |
| 0x00000001 | STATUS_WAIT_1 | 等待对象 1 |
| 0x00000002 | STATUS_WAIT_2 | 等待对象 2 |
| 0x00000003 | STATUS_WAIT_3 | 等待对象 3 |
| 0x0000003F | STATUS_WAIT_63 | 等待对象 63 |
| 0x00000080 | STATUS_ABANDONED | 等待被放弃的对象 |
| 0x000000BF | STATUS_ABANDONED_WAIT_63 | 等待被放弃的对象 63 |
| 0x000000C0 | STATUS_USER_APC | 用户模式 APC |
| 0x00000101 | STATUS_ALERTED | 警告 |
| 0x00000102 | STATUS_TIMEOUT | 超时 |
| 0x00000103 | STATUS_PENDING | 挂起状态，操作未完成 |
| 0x00000104 | STATUS_REPARSE | 重解析点 |
| 0x00000105 | STATUS_MORE_ENTRIES | 更多条目可用 |
| 0x00000106 | STATUS_NOT_ALL_ASSIGNED | 不是所有权限都被分配 |
| 0x00000107 | STATUS_SOME_NOT_MAPPED | 部分映射失败 |
| 0x00000108 | STATUS_OPLOCK_BREAK_IN_PROGRESS | 机会锁正在中断 |
| 0x00000109 | STATUS_VOLUME_MOUNTED | 卷已挂载 |
| 0x0000010A | STATUS_RXACT_COMMITTED | 事务已提交 |
| 0x0000010B | STATUS_NOTIFY_CLEANUP | 通知清理 |
| 0x0000010C | STATUS_NOTIFY_ENUM_DIR | 通知枚举目录 |
| 0x0000010D | STATUS_NO_QUOTAS_FOR_ACCOUNT | 账户无配额 |
| 0x0000010E | STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED | 主传输连接失败 |
| 0x00000110 | STATUS_PAGE_FAULT_TRANSITION | 页面错误转换 |
| 0x00000111 | STATUS_PAGE_FAULT_DEMAND_ZERO | 页面错误按需清零 |
| 0x00000112 | STATUS_PAGE_FAULT_COPY_ON_WRITE | 页面错误写时复制 |
| 0x00000113 | STATUS_PAGE_FAULT_PAGING_FILE | 页面错误分页文件 |
| 0x00000114 | STATUS_CACHE_PAGE_LOCKED | 缓存页面锁定 |
| 0x00000115 | STATUS_CRASH_DUMP | 崩溃转储 |
| 0x00000116 | STATUS_BUFFER_ALL_ZEROS | 缓冲区全零 |
| 0x00000117 | STATUS_REQUIRES_OBJECT_LOCATION | 需要对象位置 |
| 0x00000118 | STATUS_MORE_PROCESSING_REQUIRED | 需要更多处理 |

---

## 信息状态

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0x40000000 | STATUS_OBJECT_NAME_EXISTS | 对象名已存在 |
| 0x40000001 | STATUS_THREAD_WAS_SUSPENDED | 线程被挂起 |
| 0x40000002 | STATUS_WORKING_SET_LIMIT_RANGE | 工作集限制范围 |
| 0x40000003 | STATUS_IMAGE_NOT_AT_BASE | 映像不在基地址 |
| 0x40000004 | STATUS_RXACT_STATE_CREATED | 事务状态已创建 |
| 0x40000005 | STATUS_SEGMENT_NOTIFICATION | 段通知 |
| 0x40000006 | STATUS_LOCAL_USER_SESSION_KEY | 本地用户会话密钥 |
| 0x40000007 | STATUS_BAD_CURRENT_DIRECTORY | 错误的当前目录 |
| 0x40000008 | STATUS_SERIAL_MORE_WRITES | 串口更多写操作 |
| 0x40000009 | STATUS_REGISTRY_RECOVERED | 注册表已恢复 |
| 0x4000000A | STATUS_FT_READ_RECOVERY_FROM_BACKUP | 从备份读取恢复 |
| 0x4000000B | STATUS_FT_WRITE_RECOVERY | 写入恢复 |
| 0x4000000C | STATUS_SERIAL_COUNTER_TIMEOUT | 串口计数器超时 |
| 0x4000000D | STATUS_NULL_LM_PASSWORD | 空 LAN Manager 密码 |
| 0x4000000E | STATUS_IMAGE_MACHINE_TYPE_MISMATCH | 映像机器类型不匹配 |
| 0x4000000F | STATUS_RECEIVE_PARTIAL | 接收部分数据 |
| 0x40000010 | STATUS_RECEIVE_EXPEDITED | 接收紧急数据 |
| 0x40000011 | STATUS_RECEIVE_PARTIAL_EXPEDITED | 接收部分紧急数据 |
| 0x40000012 | STATUS_EVENT_DONE | 事件完成 |
| 0x40000013 | STATUS_EVENT_PENDING | 事件挂起 |
| 0x40000014 | STATUS_CHECKING_FILE_SYSTEM | 检查文件系统 |
| 0x40000015 | STATUS_FATAL_APP_EXIT | 应用程序致命退出 |
| 0x40000016 | STATUS_PREDEFINED_HANDLE | 预定义句柄 |
| 0x40000017 | STATUS_WAS_UNLOCKED | 已解锁 |
| 0x40000018 | STATUS_SERVICE_NOTIFICATION | 服务通知 |
| 0x40000019 | STATUS_WAS_LOCKED | 已锁定 |
| 0x4000001A | STATUS_LOG_HARD_ERROR | 日志硬错误 |
| 0x4000001B | STATUS_ALREADY_WIN32 | 已经是 Win32 错误 |
| 0x4000001C | STATUS_WX86_UNSIMULATE | Wx86 不模拟 |
| 0x4000001D | STATUS_WX86_CONTINUE | Wx86 继续 |
| 0x4000001E | STATUS_WX86_SINGLE_STEP | Wx86 单步 |
| 0x4000001F | STATUS_WX86_BREAKPOINT | Wx86 断点 |
| 0x40000020 | STATUS_WX86_EXCEPTION_CONTINUE | Wx86 异常继续 |
| 0x40000021 | STATUS_WX86_EXCEPTION_LASTCHANCE | Wx86 异常最后机会 |
| 0x40000022 | STATUS_WX86_EXCEPTION_CHAIN | Wx86 异常链 |
| 0x40000023 | STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE | 映像机器类型不匹配 EXE |
| 0x40000024 | STATUS_NO_YIELD_PERFORMED | 未执行让步 |
| 0x40000025 | STATUS_TIMER_RESUME_IGNORED | 定时器恢复忽略 |
| 0x40000026 | STATUS_ARBITRATION_UNHANDLED | 仲裁未处理 |
| 0x40000027 | STATUS_CARDBUS_NOT_SUPPORTED | CardBus 不支持 |
| 0x40000028 | STATUS_WX86_CREATEWX86TSS | Wx86 创建 Wx86 TSS |
| 0x40000029 | STATUS_MP_PROCESSOR_MISMATCH | 多处理器不匹配 |
| 0x4000002A | STATUS_HIBERNATED | 已休眠 |
| 0x4000002B | STATUS_RESUME_HIBERNATION | 恢复休眠 |
| 0x4000002C | STATUS_FIRMWARE_UPDATED | 固件已更新 |
| 0x4000002D | STATUS_DRIVERS_LEAKING_LOCKED_PAGES | 驱动程序泄漏锁定页面 |
| 0x4000002E | STATUS_MESSAGE_RETRIEVED | 消息已检索 |
| 0x4000002F | STATUS_SYSTEM_POWERSTATE_TRANSITION | 系统电源状态转换 |
| 0x40000030 | STATUS_ALPC_CHECK_COMPLETION_LIST | ALPC 检查完成列表 |
| 0x40000031 | STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION | 系统电源状态复杂转换 |
| 0x40000032 | STATUS_ACCESS_AUDIT_BY_POLICY | 按策略访问审计 |
| 0x40000033 | STATUS_ABANDON_HIBERFILE | 放弃休眠文件 |
| 0x40000034 | STATUS_BIZRULES_NOT_ENABLED | 业务规则未启用 |

---

## 警告状态

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0x80000001 | STATUS_GUARD_PAGE_VIOLATION | 守护页面违规 |
| 0x80000002 | STATUS_DATATYPE_MISALIGNMENT | 数据类型未对齐 |
| 0x80000003 | STATUS_BREAKPOINT | 断点 |
| 0x80000004 | STATUS_SINGLE_STEP | 单步执行 |
| 0x80000005 | STATUS_BUFFER_OVERFLOW | 缓冲区溢出 |
| 0x80000006 | STATUS_NO_MORE_FILES | 没有更多文件 |
| 0x80000007 | STATUS_WAKE_SYSTEM_DEBUGGER | 唤醒系统调试器 |
| 0x8000000A | STATUS_HANDLES_CLOSED | 句柄已关闭 |
| 0x8000000B | STATUS_NO_INHERITANCE | 无继承 |
| 0x8000000C | STATUS_GUID_SUBSTITUTION_MADE | GUID 替换 |
| 0x8000000D | STATUS_PARTIAL_COPY | 部分复制 |
| 0x8000000E | STATUS_DEVICE_PAPER_EMPTY | 设备纸张为空 |
| 0x8000000F | STATUS_DEVICE_POWERED_OFF | 设备已关闭 |
| 0x80000010 | STATUS_DEVICE_OFF_LINE | 设备离线 |
| 0x80000011 | STATUS_DEVICE_BUSY | 设备忙 |
| 0x80000012 | STATUS_NO_MORE_EAS | 没有更多扩展属性 |
| 0x80000013 | STATUS_INVALID_EA_NAME | 无效扩展属性名 |
| 0x80000014 | STATUS_EA_LIST_INCONSISTENT | 扩展属性列表不一致 |
| 0x80000015 | STATUS_INVALID_EA_FLAG | 无效扩展属性标志 |
| 0x80000016 | STATUS_VERIFY_REQUIRED | 需要验证 |
| 0x80000017 | STATUS_EXTRANEOUS_INFORMATION | 多余信息 |
| 0x80000018 | STATUS_RXACT_COMMIT_NECESSARY | 需要提交事务 |
| 0x8000001A | STATUS_NO_MORE_ENTRIES | 没有更多条目 |
| 0x8000001B | STATUS_FILEMARK_DETECTED | 检测到文件标记 |
| 0x8000001C | STATUS_MEDIA_CHANGED | 介质已更改 |
| 0x8000001D | STATUS_BUS_RESET | 总线重置 |
| 0x8000001E | STATUS_END_OF_MEDIA | 介质结束 |
| 0x8000001F | STATUS_BEGINNING_OF_MEDIA | 介质开始 |
| 0x80000020 | STATUS_MEDIA_CHECK | 介质检查 |
| 0x80000021 | STATUS_SETMARK_DETECTED | 检测到设置标记 |
| 0x80000022 | STATUS_NO_DATA_DETECTED | 检测到无数据 |
| 0x80000023 | STATUS_REDIRECTOR_HAS_OPEN_HANDLES | 重定向器有打开的句柄 |
| 0x80000024 | STATUS_SERVER_HAS_OPEN_HANDLES | 服务器有打开的句柄 |
| 0x80000025 | STATUS_ALREADY_DISCONNECTED | 已断开连接 |
| 0x80000026 | STATUS_LONGJUMP | 长跳转 |
| 0x80000027 | STATUS_CLEANER_CARTRIDGE_INSTALLED | 清洁器盒已安装 |
| 0x80000028 | STATUS_PLUGPLAY_QUERY_VIA | 即插即用查询 |
| 0x80000029 | STATUS_UNWIND_CONSOLIDATE | 展开合并 |
| 0x8000002A | STATUS_REGISTRY_HIVE_RECOVERED | 注册表配置单元已恢复 |
| 0x8000002B | STATUS_DLL_MIGHT_BE_INSECURE | DLL 可能不安全 |
| 0x8000002C | STATUS_DLL_MIGHT_BE_INCOMPATIBLE | DLL 可能不兼容 |
| 0x8000002D | STATUS_STOPPED_ON_SYMLINK | 在符号链接上停止 |
| 0x8000002E | STATUS_DEVICE_REQUIRES_CLEANING | 设备需要清洁 |
| 0x8000002F | STATUS_DEVICE_DOOR_OPEN | 设备门打开 |

---

## 错误状态

### 通用错误

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC0000001 | STATUS_UNSUCCESSFUL | 操作不成功 |
| 0xC0000002 | STATUS_NOT_IMPLEMENTED | 未实现 |
| 0xC0000003 | STATUS_INVALID_INFO_CLASS | 无效信息类 |
| 0xC0000004 | STATUS_INFO_LENGTH_MISMATCH | 信息长度不匹配 |
| 0xC0000005 | STATUS_ACCESS_VIOLATION | 访问违规 |
| 0xC0000006 | STATUS_IN_PAGE_ERROR | 页面错误 |
| 0xC0000007 | STATUS_PAGEFILE_QUOTA | 页面文件配额 |
| 0xC0000008 | STATUS_INVALID_HANDLE | 无效句柄 |
| 0xC0000009 | STATUS_BAD_INITIAL_STACK | 错误的初始堆栈 |
| 0xC000000A | STATUS_BAD_INITIAL_PC | 错误的初始程序计数器 |
| 0xC000000B | STATUS_INVALID_CID | 无效 CID |
| 0xC000000C | STATUS_TIMER_NOT_CANCELED | 定时器未取消 |
| 0xC000000D | STATUS_INVALID_PARAMETER | 无效参数 |
| 0xC000000E | STATUS_NO_SUCH_DEVICE | 无此设备 |
| 0xC000000F | STATUS_NO_SUCH_FILE | 无此文件 |
| 0xC0000010 | STATUS_INVALID_DEVICE_REQUEST | 无效设备请求 |
| 0xC0000011 | STATUS_END_OF_FILE | 文件结束 |
| 0xC0000012 | STATUS_WRONG_VOLUME | 错误的卷 |
| 0xC0000013 | STATUS_NO_MEDIA_IN_DEVICE | 设备中无介质 |
| 0xC0000014 | STATUS_UNRECOGNIZED_MEDIA | 无法识别的介质 |
| 0xC0000015 | STATUS_NONEXISTENT_SECTOR | 不存在的扇区 |
| 0xC0000016 | STATUS_MORE_PROCESSING_REQUIRED | 需要更多处理 |
| 0xC0000017 | STATUS_NO_MEMORY | 内存不足 |
| 0xC0000018 | STATUS_CONFLICTING_ADDRESSES | 地址冲突 |
| 0xC0000019 | STATUS_NOT_MAPPED_VIEW | 未映射视图 |
| 0xC000001A | STATUS_UNABLE_TO_FREE_VM | 无法释放虚拟内存 |
| 0xC000001B | STATUS_UNABLE_TO_DELETE_SECTION | 无法删除节 |
| 0xC000001C | STATUS_INVALID_SYSTEM_SERVICE | 无效系统服务 |
| 0xC000001D | STATUS_ILLEGAL_INSTRUCTION | 非法指令 |
| 0xC000001E | STATUS_INVALID_LOCK_SEQUENCE | 无效锁定序列 |
| 0xC000001F | STATUS_INVALID_VIEW_SIZE | 无效视图大小 |
| 0xC0000020 | STATUS_INVALID_FILE_FOR_SECTION | 无效的文件节 |
| 0xC0000021 | STATUS_ALREADY_COMMITTED | 已提交 |
| 0xC0000022 | STATUS_ACCESS_DENIED | 访问被拒绝 |
| 0xC0000023 | STATUS_BUFFER_TOO_SMALL | 缓冲区太小 |
| 0xC0000024 | STATUS_OBJECT_TYPE_MISMATCH | 对象类型不匹配 |
| 0xC0000025 | STATUS_NONCONTINUABLE_EXCEPTION | 不可继续的异常 |
| 0xC0000026 | STATUS_INVALID_DISPOSITION | 无效处置 |
| 0xC0000027 | STATUS_UNWIND | 展开 |
| 0xC0000028 | STATUS_BAD_STACK | 错误的堆栈 |
| 0xC0000029 | STATUS_INVALID_UNWIND_TARGET | 无效的展开目标 |
| 0xC000002A | STATUS_NOT_LOCKED | 未锁定 |
| 0xC000002B | STATUS_PARITY_ERROR | 奇偶校验错误 |
| 0xC000002C | STATUS_UNABLE_TO_DECOMMIT_VM | 无法取消提交虚拟内存 |
| 0xC000002D | STATUS_NOT_COMMITTED | 未提交 |
| 0xC000002E | STATUS_INVALID_PORT_ATTRIBUTES | 无效端口属性 |
| 0xC000002F | STATUS_PORT_MESSAGE_TOO_LONG | 端口消息太长 |
| 0xC0000030 | STATUS_INVALID_PARAMETER_MIX | 无效参数组合 |

### 内存相关错误

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC0000017 | STATUS_NO_MEMORY | 内存不足 |
| 0xC000009A | STATUS_INSUFFICIENT_RESOURCES | 资源不足 |
| 0xC000009B | STATUS_INSUFF_SERVER_RESOURCES | 服务器资源不足 |

### 连接相关错误

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC0000120 | STATUS_CANCELLED | 操作已取消 |
| 0xC0000121 | STATUS_CANNOT_DELETE | 无法删除 |
| 0xC0000122 | STATUS_INVALID_COMPUTER_NAME | 无效计算机名 |
| 0xC0000123 | STATUS_FILE_DELETED | 文件已删除 |
| 0xC0000124 | STATUS_SPECIAL_ACCOUNT | 特殊账户 |
| 0xC0000125 | STATUS_SPECIAL_GROUP | 特殊组 |
| 0xC0000126 | STATUS_SPECIAL_USER | 特殊用户 |
| 0xC0000127 | STATUS_MEMBERS_PRIMARY_GROUP | 成员主组 |
| 0xC0000128 | STATUS_FILE_CLOSED | 文件已关闭 |
| 0xC0000129 | STATUS_TOO_MANY_THREADS | 线程过多 |
| 0xC000012A | STATUS_THREAD_NOT_IN_PROCESS | 线程不在进程中 |
| 0xC000012B | STATUS_TOKEN_ALREADY_IN_USE | 令牌已在使用 |
| 0xC000012C | STATUS_PAGEFILE_QUOTA_EXCEEDED | 页面文件配额超出 |
| 0xC000012D | STATUS_COMMITMENT_LIMIT | 提交限制 |
| 0xC000012E | STATUS_INVALID_IMAGE_LE_FORMAT | 无效 LE 映像格式 |
| 0xC000012F | STATUS_INVALID_IMAGE_NOT_MZ | 无效映像非 MZ |
| 0xC0000130 | STATUS_INVALID_IMAGE_PROTECT | 无效映像保护 |
| 0xC0000131 | STATUS_INVALID_IMAGE_WIN_16 | 无效 Win16 映像 |
| 0xC0000132 | STATUS_LOGON_SERVER_CONFLICT | 登录服务器冲突 |
| 0xC0000133 | STATUS_TIME_DIFFERENCE_AT_DC | 时间差异 |
| 0xC0000134 | STATUS_SYNCHRONIZATION_REQUIRED | 需要同步 |
| 0xC0000135 | STATUS_DLL_NOT_FOUND | DLL 未找到 |
| 0xC0000136 | STATUS_OPEN_FAILED | 打开失败 |
| 0xC0000137 | STATUS_IO_PRIVILEGE_FAILED | I/O 权限失败 |
| 0xC0000138 | STATUS_ORDINAL_NOT_FOUND | 序数未找到 |
| 0xC0000139 | STATUS_ENTRYPOINT_NOT_FOUND | 入口点未找到 |
| 0xC000013A | STATUS_CONTROL_C_EXIT | 控制 C 退出 |

### 网络相关错误（KernelHttp 重点）

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC000020C | STATUS_CONNECTION_DISCONNECTED | 连接已断开 |
| 0xC000023D | STATUS_CONNECTION_RESET | 连接重置 |
| 0xC0000241 | STATUS_CONNECTION_ABORTED | 连接中止 |
| 0xC0000354 | STATUS_NETWORK_UNREACHABLE | 网络不可达 |
| 0xC0000355 | STATUS_HOST_UNREACHABLE | 主机不可达 |
| 0xC0000356 | STATUS_PROTOCOL_UNREACHABLE | 协议不可达 |
| 0xC0000357 | STATUS_PORT_UNREACHABLE | 端口不可达 |
| 0xC0000358 | STATUS_REQUEST_ABORTED | 请求已中止 |
| 0xC0000359 | STATUS_CONNECTION_ABORTED | 连接已中止 |
| 0xC000035A | STATUS_CONNECTION_REFUSED | 连接被拒绝 |
| 0xC000035B | STATUS_CONNECTION_RESET | 连接已重置 |
| 0xC000035C | STATUS_TRANSACTION_ABORTED | 事务已中止 |
| 0xC000035D | STATUS_TRANSACTION_TIMED_OUT | 事务超时 |
| 0xC000035E | STATUS_TRANSACTION_NO_RELEASE | 事务无释放 |
| 0xC000035F | STATUS_TRANSACTION_NO_MATCH | 事务不匹配 |
| 0xC0000360 | STATUS_TRANSACTION_RESPONDED | 事务已响应 |
| 0xC0000361 | STATUS_TRANSACTION_INVALID_ID | 无效事务 ID |
| 0xC0000362 | STATUS_TRANSACTION_INVALID_TYPE | 无效事务类型 |
| 0xC0000363 | STATUS_TRANSACTION_NOT_JOINED | 事务未加入 |
| 0xC0000364 | STATUS_TRANSACTION_SUPERIOR_EXISTS | 事务上级已存在 |
| 0xC0000365 | STATUS_TRANSACTION_NOT_REQUESTED | 事务未请求 |
| 0xC0000366 | STATUS_TRANSACTION_ALREADY_ABORTED | 事务已中止 |
| 0xC0000367 | STATUS_TRANSACTION_ALREADY_COMMITTED | 事务已提交 |
| 0xC0000368 | STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER | 无效事务编组缓冲区 |
| 0xC0000369 | STATUS_CURRENT_TRANSACTION_NOT_VALID | 当前事务无效 |
| 0xC000036A | STATUS_LOG_GROWTH_FAILED | 日志增长失败 |

### 超时相关错误

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC00000B5 | STATUS_IO_TIMEOUT | I/O 超时 |
| 0xC0000102 | STATUS_TIMEOUT | 超时 |
| 0xC000035D | STATUS_TRANSACTION_TIMED_OUT | 事务超时 |

### TLS/证书相关错误（KernelHttp 重点）

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC000006D | STATUS_LOGON_FAILURE | 登录失败 |
| 0xC000006E | STATUS_ACCOUNT_RESTRICTION | 账户限制 |
| 0xC000006F | STATUS_INVALID_LOGON_HOURS | 无效登录时间 |
| 0xC0000070 | STATUS_INVALID_WORKSTATION | 无效工作站 |
| 0xC0000071 | STATUS_PASSWORD_EXPIRED | 密码过期 |
| 0xC0000072 | STATUS_ACCOUNT_DISABLED | 账户禁用 |
| 0xC0000073 | STATUS_NONE_MAPPED | 无映射 |
| 0xC0000074 | STATUS_TOO_MANY_LUIDS_REQUESTED | 请求的 LUID 过多 |
| 0xC0000075 | STATUS_LUIDS_EXHAUSTED | LUID 耗尽 |
| 0xC0000076 | STATUS_INVALID_SUB_AUTHORITY | 无效子权限 |
| 0xC0000077 | STATUS_INVALID_ACL | 无效 ACL |
| 0xC0000078 | STATUS_INVALID_SID | 无效 SID |
| 0xC0000079 | STATUS_INVALID_SECURITY_DESCR | 无效安全描述符 |
| 0xC000007A | STATUS_PROCEDURE_NOT_FOUND | 过程未找到 |
| 0xC000007B | STATUS_INVALID_IMAGE_FORMAT | 无效映像格式 |
| 0xC000007C | STATUS_NO_TOKEN | 无令牌 |
| 0xC000007D | STATUS_BAD_INHERITANCE_ACL | 错误的继承 ACL |
| 0xC000007E | STATUS_RANGE_NOT_LOCKED | 范围未锁定 |
| 0xC000007F | STATUS_DISK_FULL | 磁盘已满 |
| 0xC0000080 | STATUS_SERVER_DISABLED | 服务器禁用 |
| 0xC0000081 | STATUS_SERVER_NOT_DISABLED | 服务器未禁用 |
| 0xC0000082 | STATUS_INVALID_ID_AUTHORITY | 无效 ID 权限 |
| 0xC0000083 | STATUS_ALLOTTED_SPACE_EXCEEDED | 分配空间超出 |
| 0xC0000084 | STATUS_INVALID_GROUP_ATTRIBUTES | 无效组属性 |
| 0xC0000085 | STATUS_BAD_IMPERSONATION_LEVEL | 错误的模拟级别 |
| 0xC0000086 | STATUS_CANT_OPEN_ANONYMOUS | 无法打开匿名 |
| 0xC0000087 | STATUS_BAD_VALIDATION_CLASS | 错误的验证类 |
| 0xC0000088 | STATUS_BAD_TOKEN_TYPE | 错误的令牌类型 |
| 0xC0000089 | STATUS_BAD_MASTER_BOOT_RECORD | 错误的主引导记录 |
| 0xC000008A | STATUS_INSTRUCTION_MISALIGNMENT | 指令未对齐 |
| 0xC000008B | STATUS_INSTANCE_NOT_AVAILABLE | 实例不可用 |
| 0xC000008C | STATUS_PIPE_NOT_AVAILABLE | 管道不可用 |
| 0xC000008D | STATUS_INVALID_PIPE_STATE | 无效管道状态 |
| 0xC000008E | STATUS_PIPE_BUSY | 管道忙 |
| 0xC000008F | STATUS_ILLEGAL_FUNCTION | 非法功能 |
| 0xC0000090 | STATUS_PIPE_DISCONNECTED | 管道已断开 |
| 0xC0000091 | STATUS_PIPE_CLOSING | 管道正在关闭 |
| 0xC0000092 | STATUS_PIPE_CONNECTED | 管道已连接 |
| 0xC0000093 | STATUS_PIPE_LISTENING | 管道正在监听 |
| 0xC0000094 | STATUS_INVALID_READ_MODE | 无效读取模式 |
| 0xC0000095 | STATUS_IO_TIMEOUT | I/O 超时 |
| 0xC0000096 | STATUS_FILE_FORCED_CLOSED | 文件强制关闭 |
| 0xC0000097 | STATUS_PROFILING_NOT_STARTED | 分析未开始 |
| 0xC0000098 | STATUS_PROFILING_NOT_STOPPED | 分析未停止 |
| 0xC0000099 | STATUS_COULD_NOT_INTERPRET | 无法解释 |
| 0xC000009A | STATUS_INSUFFICIENT_RESOURCES | 资源不足 |
| 0xC000009B | STATUS_INSUFF_SERVER_RESOURCES | 服务器资源不足 |

### 证书信任相关错误（KernelHttp 重点）

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC000009C | STATUS_DEVICE_DATA_ERROR | 设备数据错误 |
| 0xC000009D | STATUS_DEVICE_NOT_CONNECTED | 设备未连接 |
| 0xC000009E | STATUS_DEVICE_POWER_FAILURE | 设备电源故障 |
| 0xC000009F | STATUS_FREE_VM_NOT_AT_BASE | 空闲虚拟内存不在基地址 |
| 0xC00000A0 | STATUS_MEMORY_NOT_ALLOCATED | 内存未分配 |
| 0xC00000A1 | STATUS_WORKING_SET_QUOTA | 工作集配额 |
| 0xC00000A2 | STATUS_MEDIA_WRITE_PROTECTED | 介质写保护 |
| 0xC00000A3 | STATUS_DEVICE_NOT_READY | 设备未就绪 |
| 0xC00000A4 | STATUS_INVALID_GROUP_ATTRIBUTES | 无效组属性 |
| 0xC00000A5 | STATUS_BAD_IMPERSONATION_LEVEL | 错误的模拟级别 |
| 0xC00000A6 | STATUS_CANT_OPEN_ANONYMOUS | 无法打开匿名 |
| 0xC00000A7 | STATUS_BAD_VALIDATION_CLASS | 错误的验证类 |
| 0xC00000A8 | STATUS_BAD_TOKEN_TYPE | 错误的令牌类型 |
| 0xC00000B4 | STATUS_NO_LOGON_SERVERS | 无登录服务器 |
| 0xC00000B5 | STATUS_IO_TIMEOUT | I/O 超时 |
| 0xC00000B6 | STATUS_NO_SUCH_DOMAIN | 无此域 |
| 0xC00000B7 | STATUS_DOMAIN_EXISTS | 域已存在 |
| 0xC00000B8 | STATUS_DOMAIN_LIMIT_EXCEEDED | 域限制超出 |
| 0xC00000BA | STATUS_NOT_A_DIRECTORY | 不是目录 |
| 0xC00000BB | STATUS_NOT_SUPPORTED | 不支持 |
| 0xC00000BC | STATUS_BAD_NETWORK_NAME | 错误的网络名称 |
| 0xC00000BD | STATUS_NOT_EMPTY | 不为空 |
| 0xC00000BE | STATUS_NOT_SUPPORTED | 不支持 |
| 0xC00000BF | STATUS_BAD_NETWORK_PATH | 错误的网络路径 |

### TLS 相关特定错误

| NTSTATUS 值 | 名称 | 描述 |
|-------------|------|------|
| 0xC0000190 | STATUS_TRUST_FAILURE | 信任失败（证书验证失败） |
| 0xC0000191 | STATUS_TRUST_NO_TRUST | 无信任（证书不受信任） |
| 0xC0000192 | STATUS_TRUST_EXPLICIT_DISTRUST | 明确不信任 |
| 0xC0000193 | STATUS_TRUST_OTHER_TRUST | 其他信任问题 |
| 0xC0000194 | STATUS_INVALID_SIGNATURE | 无效签名 |
| 0xC0000195 | STATUS_NOT_SUPPORTED | 不支持 |

---

## 在 KernelHttp 中使用

### 检查 NTSTATUS

```cpp
#include <ntddk.h>

NTSTATUS status = SomeKernelHttpFunction();

// 检查是否成功
if (NT_SUCCESS(status)) {
    // 操作成功
} else {
    // 操作失败
    DbgPrint("Failed with status: 0x%08X\n", status);
}
```

### 常见错误处理

```cpp
NTSTATUS status = KhHttpSendSync(session, request, nullptr, &response);

if (!NT_SUCCESS(status)) {
    switch (status) {
    case STATUS_IO_TIMEOUT:
        // I/O 超时
        DbgPrint("Request timed out\n");
        break;
        
    case STATUS_CONNECTION_DISCONNECTED:
        // 连接断开
        DbgPrint("Connection disconnected\n");
        break;
        
    case STATUS_CONNECTION_RESET:
        // 连接重置
        DbgPrint("Connection reset\n");
        break;
        
    case STATUS_TRUST_FAILURE:
        // 证书信任失败
        DbgPrint("Certificate trust failure\n");
        break;
        
    case STATUS_INVALID_SIGNATURE:
        // 无效签名
        DbgPrint("Invalid signature\n");
        break;
        
    case STATUS_INSUFFICIENT_RESOURCES:
        // 资源不足
        DbgPrint("Insufficient resources\n");
        break;
        
    case STATUS_INVALID_PARAMETER:
        // 无效参数
        DbgPrint("Invalid parameter\n");
        break;
        
    case STATUS_NOT_SUPPORTED:
        // 不支持
        DbgPrint("Not supported\n");
        break;
        
    case STATUS_CANCELLED:
        // 已取消
        DbgPrint("Operation cancelled\n");
        break;
        
    default:
        // 其他错误
        DbgPrint("Unknown error: 0x%08X\n", status);
        break;
    }
}
```

### 错误分类处理

```cpp
// 按类别处理错误
NTSTATUS HandleError(NTSTATUS status) {
    // 网络相关错误 - 可重试
    if (status == STATUS_CONNECTION_DISCONNECTED ||
        status == STATUS_CONNECTION_RESET ||
        status == STATUS_IO_TIMEOUT) {
        return STATUS_RETRY;
    }
    
    // TLS/证书相关错误 - 不可重试
    if (status == STATUS_TRUST_FAILURE ||
        status == STATUS_INVALID_SIGNATURE) {
        return STATUS_FAIL;
    }
    
    // 资源相关错误 - 可能需要调整配置
    if (status == STATUS_INSUFFICIENT_RESOURCES ||
        status == STATUS_NO_MEMORY) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 其他错误
    return status;
}
```

---

## 错误处理最佳实践

### 1. 始终检查返回值

```cpp
// ✅ 正确：始终检查 NTSTATUS
NTSTATUS status = SomeFunction();
if (!NT_SUCCESS(status)) {
    // 处理错误
    return status;
}

// ❌ 错误：忽略返回值
SomeFunction();  // 可能失败但未处理
```

### 2. 使用宏进行检查

```cpp
#include <ntddk.h>

// 使用 NT_SUCCESS 宏
if (NT_SUCCESS(status)) {
    // 成功
} else {
    // 失败
}

// 使用 NT_INFORMATION 宏
if (NT_INFORMATION(status)) {
    // 信息状态
}

// 使用 NT_WARNING 宏
if (NT_WARNING(status)) {
    // 警告状态
}

// 使用 NT_ERROR 宏
if (NT_ERROR(status)) {
    // 错误状态
}
```

### 3. 资源清理

```cpp
NTSTATUS DoOperation() {
    Resource* res1 = nullptr;
    Resource* res2 = nullptr;
    
    NTSTATUS status = CreateResource1(&res1);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = CreateResource2(&res2);
    if (!NT_SUCCESS(status)) {
        // 即使失败也要释放已分配的资源
        ReleaseResource1(res1);
        return status;
    }
    
    // 执行操作...
    
    // 成功时也要释放资源
    ReleaseResource2(res2);
    ReleaseResource1(res1);
    
    return STATUS_SUCCESS;
}
```

### 4. 错误日志记录

```cpp
void LogError(NTSTATUS status, const char* context) {
    DbgPrint("[KernelHttp] Error in %s: 0x%08X\n", context, status);
    
    // 对于特定错误，提供更详细的日志
    switch (status) {
    case STATUS_IO_TIMEOUT:
        DbgPrint("[KernelHttp] Timeout details: operation exceeded time limit\n");
        break;
    case STATUS_TRUST_FAILURE:
        DbgPrint("[KernelHttp] TLS details: certificate verification failed\n");
        break;
    }
}
```

---

## English Version

# NTSTATUS Error Code Reference

This document lists common NTSTATUS error codes used in the KernelHttp project.

## Success Status

| Value | Name | Description |
|-------|------|-------------|
| 0x00000000 | STATUS_SUCCESS | Operation completed successfully |
| 0x00000102 | STATUS_TIMEOUT | Timeout |
| 0x00000103 | STATUS_PENDING | Pending status, operation not completed |

## Information Status

| Value | Name | Description |
|-------|------|-------------|
| 0x40000000 | STATUS_OBJECT_NAME_EXISTS | Object name exists |
| 0x40000005 | STATUS_SEGMENT_NOTIFICATION | Segment notification |

## Warning Status

| Value | Name | Description |
|-------|------|-------------|
| 0x80000005 | STATUS_BUFFER_OVERFLOW | Buffer overflow |
| 0x80000006 | STATUS_NO_MORE_FILES | No more files |
| 0x8000000D | STATUS_PARTIAL_COPY | Partial copy |

## Error Status

| Value | Name | Description |
|-------|------|-------------|
| 0xC0000001 | STATUS_UNSUCCESSFUL | Operation unsuccessful |
| 0xC000000D | STATUS_INVALID_PARAMETER | Invalid parameter |
| 0xC0000017 | STATUS_NO_MEMORY | No memory |
| 0xC0000022 | STATUS_ACCESS_DENIED | Access denied |
| 0xC000009A | STATUS_INSUFFICIENT_RESOURCES | Insufficient resources |
| 0xC0000095 | STATUS_IO_TIMEOUT | I/O timeout |
| 0xC000009D | STATUS_DEVICE_NOT_CONNECTED | Device not connected |
| 0xC00000BB | STATUS_NOT_SUPPORTED | Not supported |
| 0xC0000120 | STATUS_CANCELLED | Cancelled |

## Network-Related Errors

| Value | Name | Description |
|-------|------|-------------|
| 0xC000020C | STATUS_CONNECTION_DISCONNECTED | Connection disconnected |
| 0xC000023D | STATUS_CONNECTION_RESET | Connection reset |
| 0xC0000241 | STATUS_CONNECTION_ABORTED | Connection aborted |
| 0xC0000354 | STATUS_NETWORK_UNREACHABLE | Network unreachable |
| 0xC0000355 | STATUS_HOST_UNREACHABLE | Host unreachable |
| 0xC000035A | STATUS_CONNECTION_REFUSED | Connection refused |

## TLS/Certificate-Related Errors

| Value | Name | Description |
|-------|------|-------------|
| 0xC0000190 | STATUS_TRUST_FAILURE | Trust failure (certificate verification failed) |
| 0xC0000191 | STATUS_TRUST_NO_TRUST | No trust (certificate not trusted) |
| 0xC0000192 | STATUS_TRUST_EXPLICIT_DISTRUST | Explicit distrust |
| 0xC0000194 | STATUS_INVALID_SIGNATURE | Invalid signature |

---

## Related Documents

- [HTTP Status Codes](http-status-codes.md)
- [API Overview](api-overview.md)
- [High-Level API](high-level-api.md)
- [Low-Level API](low-level-api.md)
