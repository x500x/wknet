#include "WknetTestLog.h"

#if !defined(WKNET_USER_MODE_TEST)
#include <wknet/Trace.h>
#include <ntstrsafe.h>
#include <stdarg.h>

namespace wknet
{
namespace testlog
{
namespace
{
    constexpr SIZE_T FormatBufferBytes = 64 * 1024;
    constexpr const char* LogPrefix = WKNET_DRIVER_NAME " : ";

    HANDLE g_logFileHandle = nullptr;

    SIZE_T TextLengthBounded(_In_reads_or_z_(capacity) const char* text, SIZE_T capacity) noexcept
    {
        if (text == nullptr || capacity == 0) {
            return 0;
        }

        SIZE_T length = 0;
        while (length < capacity && text[length] != '\0') {
            ++length;
        }
        return length;
    }

    int PrintLength(SIZE_T length) noexcept
    {
        constexpr SIZE_T MaxPrintLength = 0x7fffffff;
        return static_cast<int>(length > MaxPrintLength ? MaxPrintLength : length);
    }

    SIZE_T MinSize(SIZE_T left, SIZE_T right) noexcept
    {
        return left < right ? left : right;
    }

    void WriteFileBytes(_In_reads_bytes_opt_(length) const char* data, SIZE_T length) noexcept
    {
        if (g_logFileHandle == nullptr ||
            data == nullptr ||
            length == 0 ||
            KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return;
        }

        const auto* bytes = reinterpret_cast<const UCHAR*>(data);
        SIZE_T offset = 0;
        while (offset < length) {
            const SIZE_T remaining = length - offset;
            constexpr SIZE_T MaxWriteBytes = 0x7ffff000;
            const ULONG bytesToWrite = static_cast<ULONG>(MinSize(remaining, MaxWriteBytes));
            LARGE_INTEGER byteOffset = {};
            byteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;
            byteOffset.HighPart = -1;
            IO_STATUS_BLOCK ioStatus = {};
            const NTSTATUS status = ZwWriteFile(
                g_logFileHandle,
                nullptr,
                nullptr,
                nullptr,
                &ioStatus,
                const_cast<UCHAR*>(bytes + offset),
                bytesToWrite,
                &byteOffset,
                nullptr);
            if (!NT_SUCCESS(status)) {
                return;
            }

            offset += bytesToWrite;
        }
    }

    void TraceFileSink(
        _In_opt_ void* context,
        TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(component);

        if (message == nullptr) {
            return;
        }

        const SIZE_T messageLength = TextLengthBounded(message, FormatBufferBytes);
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "%s", message);
        WriteFileBytes(message, messageLength);
    }
}

_Must_inspect_result_
NTSTATUS Initialize(_In_z_ const char* path) noexcept
{
    if (path == nullptr || path[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_logFileHandle != nullptr) {
        Shutdown();
    }

    ANSI_STRING ansiPath = {};
    RtlInitAnsiString(&ansiPath, path);

    UNICODE_STRING unicodePath = {};
    NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    IO_STATUS_BLOCK ioStatus = {};
    HANDLE fileHandle = nullptr;
    status = ZwCreateFile(
        &fileHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
        nullptr,
        0);
    RtlFreeUnicodeString(&unicodePath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_logFileHandle = fileHandle;
    TraceSetSink(TraceFileSink, nullptr);
    return STATUS_SUCCESS;
}

void Shutdown() noexcept
{
    TraceSetSink(nullptr, nullptr);

    if (g_logFileHandle == nullptr) {
        return;
    }

    HANDLE fileHandle = nullptr;
    fileHandle = g_logFileHandle;
    g_logFileHandle = nullptr;

    if (fileHandle != nullptr && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        ZwClose(fileHandle);
    }
}

void Print(_In_z_ _Printf_format_string_ const char* format, ...) noexcept
{
    if (format == nullptr) {
        return;
    }

    char* message = static_cast<char*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, FormatBufferBytes, PoolTag));
    if (message == nullptr) {
        DbgPrintEx(0, 0, WKNET_DRIVER_NAME " : 日志格式化缓冲分配失败\r\n");
        return;
    }

    const SIZE_T prefixLength = TextLengthBounded(LogPrefix, FormatBufferBytes);
    RtlCopyMemory(message, LogPrefix, prefixLength);
    message[prefixLength] = '\0';

    va_list args = {};
    va_start(args, format);
    (void)RtlStringCbVPrintfA(
        message + prefixLength,
        FormatBufferBytes - prefixLength,
        format,
        args);
    va_end(args);

    const SIZE_T messageLength = TextLengthBounded(message, FormatBufferBytes);
    DbgPrintEx(0, 0, "%s", message);
    WriteFileBytes(message, messageLength);

    ExFreePoolWithTag(message, PoolTag);
}

void WriteRaw(_In_reads_bytes_opt_(length) const char* data, SIZE_T length) noexcept
{
    if (data == nullptr || length == 0) {
        return;
    }

    SIZE_T offset = 0;
    while (offset < length) {
        const SIZE_T chunkLength = MinSize(length - offset, 0x7fffffff);
        DbgPrintEx(
            0,
            0,
            WKNET_DRIVER_NAME " : %.*s",
            PrintLength(chunkLength),
            data + offset);
        offset += chunkLength;
    }

    WriteFileBytes(LogPrefix, TextLengthBounded(LogPrefix, FormatBufferBytes));
    WriteFileBytes(data, length);
}
}
}
#endif
