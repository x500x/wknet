#pragma once

#include <wknet/http1/HttpTypes.h>
#include "HttpXmlWriter.h"

namespace wknet
{
namespace http1
{
    class HttpPack200JarWriter final
    {
    public:
        HttpPack200JarWriter(_Out_writes_bytes_(capacity) char* destination, SIZE_T capacity) noexcept;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxEntries) noexcept;

        _Must_inspect_result_
        NTSTATUS AddStoredEntry(HttpXmlText name, const UCHAR* content, SIZE_T contentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS AddEntry(
            HttpXmlText name,
            const UCHAR* content,
            SIZE_T contentLength,
            bool deflate,
            ULONG unixTime) noexcept;

        _Must_inspect_result_
        NTSTATUS Finish(_Out_ SIZE_T* jarLength) noexcept;

    private:
        struct Entry final
        {
            HttpXmlText Name = {};
            ULONG Crc32 = 0;
            ULONGLONG Size = 0;
            ULONGLONG CompressedSize = 0;
            ULONGLONG LocalHeaderOffset = 0;
            USHORT Method = 0;
            USHORT DosTime = 0;
            USHORT DosDate = 0;
        };

        _Must_inspect_result_
        NTSTATUS AppendByte(UCHAR value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendBytes(const void* value, SIZE_T valueLength) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendLe16(USHORT value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendLe32(ULONG value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendLe64(ULONGLONG value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendRawDeflateStored(const UCHAR* content, SIZE_T contentLength) noexcept;

        _Must_inspect_result_
        bool IsSafeEntryName(HttpXmlText name) const noexcept;

        char* destination_ = nullptr;
        SIZE_T capacity_ = 0;
        SIZE_T length_ = 0;
        HeapArray<Entry> entries_ = {};
        SIZE_T entryCount_ = 0;
        bool finished_ = false;
    };
}
}
