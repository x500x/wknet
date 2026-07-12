#include <wknet/Wknet.h>

#include "WknetTestLog.h"
#include "samples/KhttpSamples.h"

extern "C" NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

namespace wknet
{
    namespace
    {
        net::WskClient* g_wskClient = nullptr;
        constexpr SIZE_T MaxDriverPathChars = 512;
        constexpr const char* CertificateBundleFileName = "cacert.pem";
        constexpr const char* TestLogFileName = "wknettest.log";
        char g_certificateBundlePath[MaxDriverPathChars] = {};
        char g_testLogPath[MaxDriverPathChars] = {};

        struct LoadHttpSamplesThreadContext
        {
            NTSTATUS Status;
            const char* CertificateBundlePath;
        };

        void LoadHttpSamplesThread(_In_ PVOID startContext) noexcept;

        SIZE_T TextLength(_In_z_ const char* text) noexcept
        {
            SIZE_T length = 0;
            while (text[length] != '\0') {
                ++length;
            }
            return length;
        }

        char LowerAscii(char ch) noexcept
        {
            if (ch >= 'A' && ch <= 'Z') {
                return static_cast<char>(ch - 'A' + 'a');
            }
            return ch;
        }

        bool StartsWithIgnoreCase(_In_z_ const char* text, _In_z_ const char* prefix) noexcept
        {
            for (SIZE_T index = 0; prefix[index] != '\0'; ++index) {
                if (LowerAscii(text[index]) != LowerAscii(prefix[index])) {
                    return false;
                }
            }
            return true;
        }

        NTSTATUS CopyText(
            _Out_writes_z_(capacity) char* destination,
            SIZE_T capacity,
            _In_reads_(sourceLength) const char* source,
            SIZE_T sourceLength) noexcept
        {
            if (destination == nullptr || source == nullptr || capacity == 0 || sourceLength >= capacity) {
                return STATUS_NAME_TOO_LONG;
            }

            RtlCopyMemory(destination, source, sourceLength);
            destination[sourceLength] = '\0';
            return STATUS_SUCCESS;
        }

        NTSTATUS AppendText(
            _Inout_updates_z_(capacity) char* destination,
            SIZE_T capacity,
            _In_z_ const char* suffix) noexcept
        {
            const SIZE_T destinationLength = TextLength(destination);
            const SIZE_T suffixLength = TextLength(suffix);
            if (destinationLength + suffixLength >= capacity) {
                return STATUS_NAME_TOO_LONG;
            }

            RtlCopyMemory(destination + destinationLength, suffix, suffixLength);
            destination[destinationLength + suffixLength] = '\0';
            return STATUS_SUCCESS;
        }

        NTSTATUS QueryDriverImagePath(
            _In_ PUNICODE_STRING registryPath,
            _Out_writes_z_(capacity) char* imagePath,
            SIZE_T capacity) noexcept
        {
            if (registryPath == nullptr || imagePath == nullptr || capacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            imagePath[0] = '\0';

            OBJECT_ATTRIBUTES objectAttributes = {};
            InitializeObjectAttributes(
                &objectAttributes,
                registryPath,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                nullptr,
                nullptr);

            HANDLE keyHandle = nullptr;
            NTSTATUS status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &objectAttributes);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            UNICODE_STRING valueName = {};
            RtlInitUnicodeString(&valueName, L"ImagePath");

            ULONG valueLength = 0;
            status = ZwQueryValueKey(
                keyHandle,
                &valueName,
                KeyValuePartialInformation,
                nullptr,
                0,
                &valueLength);
            if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
                ZwClose(keyHandle);
                return status;
            }

            auto* valueInfo = static_cast<KEY_VALUE_PARTIAL_INFORMATION*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, valueLength, PoolTag));
            if (valueInfo == nullptr) {
                ZwClose(keyHandle);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = ZwQueryValueKey(
                keyHandle,
                &valueName,
                KeyValuePartialInformation,
                valueInfo,
                valueLength,
                &valueLength);
            ZwClose(keyHandle);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return status;
            }

            if ((valueInfo->Type != REG_SZ && valueInfo->Type != REG_EXPAND_SZ) ||
                valueInfo->DataLength == 0 ||
                (valueInfo->DataLength % sizeof(WCHAR)) != 0) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return STATUS_OBJECT_TYPE_MISMATCH;
            }

            ULONG unicodeBytes = valueInfo->DataLength;
            auto* unicodeData = reinterpret_cast<WCHAR*>(valueInfo->Data);
            while (unicodeBytes >= sizeof(WCHAR) &&
                unicodeData[(unicodeBytes / sizeof(WCHAR)) - 1] == L'\0') {
                unicodeBytes -= sizeof(WCHAR);
            }
            if (unicodeBytes == 0 || unicodeBytes > static_cast<ULONG>(MAXUSHORT)) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return STATUS_NAME_TOO_LONG;
            }

            UNICODE_STRING unicodePath = {};
            unicodePath.Buffer = unicodeData;
            unicodePath.Length = static_cast<USHORT>(unicodeBytes);
            unicodePath.MaximumLength = unicodePath.Length;

            ANSI_STRING ansiPath = {};
            status = RtlUnicodeStringToAnsiString(&ansiPath, &unicodePath, TRUE);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return status;
            }

            if (ansiPath.Length >= capacity) {
                RtlFreeAnsiString(&ansiPath);
                ExFreePoolWithTag(valueInfo, PoolTag);
                return STATUS_NAME_TOO_LONG;
            }

            RtlCopyMemory(imagePath, ansiPath.Buffer, ansiPath.Length);
            imagePath[ansiPath.Length] = '\0';
            RtlFreeAnsiString(&ansiPath);
            ExFreePoolWithTag(valueInfo, PoolTag);
            return STATUS_SUCCESS;
        }

        NTSTATUS NormalizeImagePath(
            _In_z_ const char* imagePath,
            _Out_writes_z_(capacity) char* normalizedPath,
            SIZE_T capacity) noexcept
        {
            if (imagePath == nullptr || normalizedPath == nullptr || capacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            const char* start = imagePath;
            SIZE_T length = TextLength(imagePath);
            if (length >= 2 && start[0] == '"' && start[length - 1] == '"') {
                ++start;
                length -= 2;
            }

            char trimmedPath[MaxDriverPathChars] = {};
            NTSTATUS status = CopyText(trimmedPath, sizeof(trimmedPath), start, length);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            start = trimmedPath;

            normalizedPath[0] = '\0';

            if (length == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (StartsWithIgnoreCase(start, "\\??\\") ||
                StartsWithIgnoreCase(start, "\\SystemRoot\\")) {
                return CopyText(normalizedPath, capacity, start, length);
            }
            if (StartsWithIgnoreCase(start, "%SystemRoot%\\")) {
                status = CopyText(normalizedPath, capacity, "\\SystemRoot\\", TextLength("\\SystemRoot\\"));
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                return AppendText(normalizedPath, capacity, start + TextLength("%SystemRoot%\\"));
            }
            if (length >= 3 && start[1] == ':' && (start[2] == '\\' || start[2] == '/')) {
                status = CopyText(normalizedPath, capacity, "\\??\\", TextLength("\\??\\"));
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                return AppendText(normalizedPath, capacity, start);
            }
            if (StartsWithIgnoreCase(start, "System32\\") || StartsWithIgnoreCase(start, "System32/")) {
                status = CopyText(normalizedPath, capacity, "\\SystemRoot\\", TextLength("\\SystemRoot\\"));
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                return AppendText(normalizedPath, capacity, start);
            }
            if (start[0] == '\\') {
                return CopyText(normalizedPath, capacity, start, length);
            }

            return STATUS_OBJECT_PATH_SYNTAX_BAD;
        }

        NTSTATUS BuildSiblingFilePath(
            _In_z_ const char* imagePath,
            _In_z_ const char* fileName,
            _Out_writes_z_(capacity) char* filePath,
            SIZE_T capacity) noexcept
        {
            char normalizedPath[MaxDriverPathChars] = {};
            NTSTATUS status = NormalizeImagePath(imagePath, normalizedPath, sizeof(normalizedPath));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T lastSeparator = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
            for (SIZE_T index = 0; normalizedPath[index] != '\0'; ++index) {
                if (normalizedPath[index] == '\\' || normalizedPath[index] == '/') {
                    lastSeparator = index;
                }
            }

            if (lastSeparator == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                return STATUS_OBJECT_PATH_SYNTAX_BAD;
            }

            status = CopyText(filePath, capacity, normalizedPath, lastSeparator + 1);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            return AppendText(filePath, capacity, fileName);
        }

        NTSTATUS BuildCertificateBundlePath(
            _In_z_ const char* imagePath,
            _Out_writes_z_(capacity) char* certificatePath,
            SIZE_T capacity) noexcept
        {
            return BuildSiblingFilePath(imagePath, CertificateBundleFileName, certificatePath, capacity);
        }

        NTSTATUS InitializeTestLogFile(_In_ PUNICODE_STRING registryPath) noexcept
        {
            char imagePath[MaxDriverPathChars] = {};
            NTSTATUS status = QueryDriverImagePath(registryPath, imagePath, sizeof(imagePath));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = BuildSiblingFilePath(imagePath, TestLogFileName, g_testLogPath, sizeof(g_testLogPath));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            return testlog::Initialize(g_testLogPath);
        }

        NTSTATUS QueryConfiguredCertificateBundlePath(
            _In_ PUNICODE_STRING registryPath,
            _Out_writes_z_(capacity) char* certificatePath,
            SIZE_T capacity) noexcept
        {
            if (registryPath == nullptr || certificatePath == nullptr || capacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            certificatePath[0] = '\0';

            OBJECT_ATTRIBUTES objectAttributes = {};
            InitializeObjectAttributes(
                &objectAttributes,
                registryPath,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                nullptr,
                nullptr);

            HANDLE keyHandle = nullptr;
            NTSTATUS status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &objectAttributes);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            UNICODE_STRING valueName = {};
            RtlInitUnicodeString(&valueName, L"CertificateBundlePath");

            ULONG valueLength = 0;
            status = ZwQueryValueKey(
                keyHandle,
                &valueName,
                KeyValuePartialInformation,
                nullptr,
                0,
                &valueLength);
            if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
                ZwClose(keyHandle);
                return status;
            }

            auto* valueInfo = static_cast<KEY_VALUE_PARTIAL_INFORMATION*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, valueLength, PoolTag));
            if (valueInfo == nullptr) {
                ZwClose(keyHandle);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = ZwQueryValueKey(
                keyHandle,
                &valueName,
                KeyValuePartialInformation,
                valueInfo,
                valueLength,
                &valueLength);
            ZwClose(keyHandle);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return status;
            }

            if ((valueInfo->Type != REG_SZ && valueInfo->Type != REG_EXPAND_SZ) ||
                valueInfo->DataLength == 0 ||
                (valueInfo->DataLength % sizeof(WCHAR)) != 0) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return STATUS_OBJECT_TYPE_MISMATCH;
            }

            ULONG unicodeBytes = valueInfo->DataLength;
            auto* unicodeData = reinterpret_cast<WCHAR*>(valueInfo->Data);
            while (unicodeBytes >= sizeof(WCHAR) &&
                unicodeData[(unicodeBytes / sizeof(WCHAR)) - 1] == L'\0') {
                unicodeBytes -= sizeof(WCHAR);
            }
            if (unicodeBytes == 0 || unicodeBytes > static_cast<ULONG>(MAXUSHORT)) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return STATUS_NAME_TOO_LONG;
            }

            UNICODE_STRING unicodePath = {};
            unicodePath.Buffer = unicodeData;
            unicodePath.Length = static_cast<USHORT>(unicodeBytes);
            unicodePath.MaximumLength = unicodePath.Length;

            ANSI_STRING ansiPath = {};
            status = RtlUnicodeStringToAnsiString(&ansiPath, &unicodePath, TRUE);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(valueInfo, PoolTag);
                return status;
            }

            char configuredPath[MaxDriverPathChars] = {};
            if (ansiPath.Length >= sizeof(configuredPath)) {
                RtlFreeAnsiString(&ansiPath);
                ExFreePoolWithTag(valueInfo, PoolTag);
                return STATUS_NAME_TOO_LONG;
            }

            RtlCopyMemory(configuredPath, ansiPath.Buffer, ansiPath.Length);
            configuredPath[ansiPath.Length] = '\0';
            RtlFreeAnsiString(&ansiPath);
            ExFreePoolWithTag(valueInfo, PoolTag);

            return NormalizeImagePath(configuredPath, certificatePath, capacity);
        }

        NTSTATUS InitializeCertificateBundlePath(_In_ PUNICODE_STRING registryPath) noexcept
        {
            NTSTATUS status = QueryConfiguredCertificateBundlePath(
                registryPath,
                g_certificateBundlePath,
                sizeof(g_certificateBundlePath));
            if (NT_SUCCESS(status)) {
                WKNET_DBG_PRINT("证书信任包路径: %s\r\n", g_certificateBundlePath);
                return STATUS_SUCCESS;
            }
            if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND) {
                return status;
            }

            char imagePath[MaxDriverPathChars] = {};
            status = QueryDriverImagePath(registryPath, imagePath, sizeof(imagePath));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = BuildCertificateBundlePath(
                imagePath,
                g_certificateBundlePath,
                sizeof(g_certificateBundlePath));
            if (NT_SUCCESS(status)) {
                WKNET_DBG_PRINT("证书信任包路径: %s (默认驱动目录同名文件)\r\n", g_certificateBundlePath);
            }
            return status;
        }

        void ReleaseWskClient() noexcept
        {
            if (g_wskClient != nullptr) {
                g_wskClient->Shutdown();
                delete g_wskClient;
                g_wskClient = nullptr;
            }
        }

        bool IsLoadTimeWskProviderUnavailable(NTSTATUS status) noexcept
        {
            return status == STATUS_NOT_FOUND ||
                status == STATUS_OBJECT_NAME_NOT_FOUND ||
                status == STATUS_DEVICE_NOT_READY ||
                status == STATUS_IO_TIMEOUT;
        }
    }

    NTSTATUS RunLoadHttpSamples(_In_opt_z_ const char* certificateBundlePath) noexcept
    {
        NTSTATUS finalStatus = STATUS_SUCCESS;

        if (g_wskClient == nullptr || !g_wskClient->IsInitialized()) {
            return STATUS_DEVICE_NOT_READY;
        }

        samples::wknettestSampleResults khttpResults = {};
        NTSTATUS khttpStatus = samples::RunwknettestSamples(
            g_wskClient,
            certificateBundlePath,
            &khttpResults);
        if (!NT_SUCCESS(khttpStatus)) {
            WKNET_DBG_PRINT("wknettest 全量示例完成，但存在失败项: 0x%08X\r\n", static_cast<ULONG>(khttpStatus));
            finalStatus = khttpStatus;
        }
        else {
            WKNET_DBG_PRINT("wknettest 全量示例全部完成\r\n");
        }

        return finalStatus;
    }

    void LoadHttpSamplesThread(_In_ PVOID startContext) noexcept
    {
        LoadHttpSamplesThreadContext* context = static_cast<LoadHttpSamplesThreadContext*>(startContext);
        if (context == nullptr) {
            PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
            return;
        }

        context->Status = RunLoadHttpSamples(context->CertificateBundlePath);
        PsTerminateSystemThread(context->Status);
    }

    _Use_decl_annotations_
    extern "C" void DriverUnload(PDRIVER_OBJECT driverObject)
    {
        UNREFERENCED_PARAMETER(driverObject);

        if (g_wskClient != nullptr) {
            WKNET_DBG_PRINT("驱动卸载开始\r\n");
            WKNET_DBG_PRINT("驱动卸载: 开始等待异步 HTTP worker 结束\r\n");
            ::wknet::http::Destroy();
            WKNET_DBG_PRINT("驱动卸载: 异步 HTTP worker 已结束\r\n");
            WKNET_DBG_PRINT("驱动卸载: 开始关闭 active HTTP/WebSocket handle\r\n");
            session::EngineCloseActiveHandles();
            WKNET_DBG_PRINT("驱动卸载: active HTTP/WebSocket handle 已关闭\r\n");
            WKNET_DBG_PRINT("驱动卸载: 开始释放 WSK client\r\n");
            ReleaseWskClient();
            WKNET_DBG_PRINT("驱动卸载: WSK client 已释放\r\n");
            WKNET_DBG_PRINT("驱动卸载完成\r\n");
        }
        testlog::Shutdown();
    }
}

_Use_decl_annotations_
extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    // Test driver: full graded trace (library default is Off).
    wknet::TraceSetLevel(wknet::TraceLevel::Max);
    wknet::TraceSetComponents(wknet::ComponentAll);

    const NTSTATUS logStatus = wknet::InitializeTestLogFile(registryPath);
    WKNET_DBG_PRINT("DriverEntry 开始\r\n");
    if (NT_SUCCESS(logStatus)) {
        WKNET_DBG_PRINT("测试日志路径: %s\r\n", wknet::g_testLogPath);
    }
    else {
        WKNET_DBG_PRINT("测试日志文件初始化失败: 0x%08X\r\n", static_cast<ULONG>(logStatus));
    }
    driverObject->DriverUnload = wknet::DriverUnload;

    NTSTATUS status = wknet::InitializeCertificateBundlePath(registryPath);
    if (!NT_SUCCESS(status)) {
        WKNET_DBG_PRINT("证书信任包路径初始化失败: 0x%08X\r\n", static_cast<ULONG>(status));
        wknet::g_certificateBundlePath[0] = '\0';
    }

    wknet::g_wskClient = new wknet::net::WskClient();
    if (wknet::g_wskClient == nullptr) {
        WKNET_DBG_PRINT("WskClient 分配失败\r\n");
        wknet::testlog::Shutdown();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = wknet::g_wskClient->Initialize();
    if (!NT_SUCCESS(status)) {
        if (!wknet::IsLoadTimeWskProviderUnavailable(status)) {
            WKNET_DBG_PRINT("WSK 初始化失败: 0x%08X\r\n", static_cast<ULONG>(status));
            wknet::ReleaseWskClient();
            wknet::testlog::Shutdown();
            return status;
        }

        WKNET_DBG_PRINT(
            "WSK 初始化暂不可用，DriverEntry 继续完成: 0x%08X\r\n",
            static_cast<ULONG>(status));
        wknet::ReleaseWskClient();
        WKNET_DBG_PRINT("DriverEntry 完成: 0x%08X\r\n", static_cast<ULONG>(STATUS_SUCCESS));
        wknet::testlog::Shutdown();
        return STATUS_SUCCESS;
    }

    WKNET_DBG_PRINT("WSK 已初始化，开始运行 wknettest 全量场景示例\r\n");

    wknet::LoadHttpSamplesThreadContext sampleThreadContext = {
        STATUS_UNSUCCESSFUL,
        wknet::g_certificateBundlePath[0] != '\0' ? wknet::g_certificateBundlePath : nullptr
    };
    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(&objectAttributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE sampleThreadHandle = nullptr;
    status = PsCreateSystemThread(
        &sampleThreadHandle,
        THREAD_ALL_ACCESS,
        &objectAttributes,
        nullptr,
        nullptr,
        wknet::LoadHttpSamplesThread,
        &sampleThreadContext);
    if (!NT_SUCCESS(status)) {
        WKNET_DBG_PRINT("创建加载期示例线程失败: 0x%08X\r\n", static_cast<ULONG>(status));
        wknet::ReleaseWskClient();
        wknet::testlog::Shutdown();
        return status;
    }

    status = ZwWaitForSingleObject(sampleThreadHandle, FALSE, nullptr);
    ZwClose(sampleThreadHandle);
    if (!NT_SUCCESS(status)) {
        WKNET_DBG_PRINT("等待加载期示例线程失败: 0x%08X\r\n", static_cast<ULONG>(status));
        wknet::ReleaseWskClient();
        wknet::testlog::Shutdown();
        return status;
    }

    const NTSTATUS sampleStatus = sampleThreadContext.Status;
    if (!NT_SUCCESS(sampleStatus)) {
        WKNET_DBG_PRINT(
            "加载期示例存在失败项，DriverEntry 继续完成: 0x%08X\r\n",
            static_cast<ULONG>(sampleStatus));
    }

    status = STATUS_SUCCESS;
    WKNET_DBG_PRINT("DriverEntry 完成: 0x%08X\r\n", static_cast<ULONG>(status));

    return status;
}
