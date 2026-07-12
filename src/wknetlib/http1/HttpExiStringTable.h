#pragma once

#include <wknet/http1/HttpTypes.h>
#include "HttpXmlWriter.h"

namespace wknet
{
namespace http1
{
    struct HttpExiStringTableEntry final
    {
        HttpXmlText Value = {};
    };

    class HttpExiStringTable final
    {
    public:
        HttpExiStringTable() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxEntries, SIZE_T textCapacity) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Add(HttpXmlText value, _Out_ ULONG* index) noexcept;

        _Must_inspect_result_
        bool Find(HttpXmlText value, _Out_ ULONG* index) const noexcept;

        _Must_inspect_result_
        bool Get(ULONG index, _Out_ HttpXmlText* value) const noexcept;

        _Must_inspect_result_
        SIZE_T Count() const noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS CopyText(HttpXmlText value, _Out_ HttpXmlText* stored) noexcept;

        HeapArray<HttpExiStringTableEntry> entries_ = {};
        HeapArray<char> text_ = {};
        SIZE_T entryCount_ = 0;
        SIZE_T textLength_ = 0;
    };

    struct HttpExiGlobalValueEntry final
    {
        HttpXmlText Value = {};
        SIZE_T LocalEntryIndex = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        bool Assigned = false;
    };

    struct HttpExiLocalValueEntry final
    {
        ULONG QNameId = 0xffffffffUL;
        ULONG GlobalId = 0xffffffffUL;
        bool Assigned = false;
    };

    class HttpExiValueTable final
    {
    public:
        HttpExiValueTable() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(
            SIZE_T maxLiteralEntries,
            SIZE_T textCapacity,
            ULONG valueMaxLength,
            ULONG valuePartitionCapacity) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS AddLiteral(
            ULONG qnameId,
            ULONG codePointLength,
            HttpXmlText value,
            _Out_ HttpXmlText* storedValue) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadLocal(
            _Inout_ class HttpExiBitInput* input,
            ULONG qnameId,
            _Out_ HttpXmlText* value) const noexcept;

        _Must_inspect_result_
        NTSTATUS ReadGlobal(
            _Inout_ class HttpExiBitInput* input,
            _Out_ HttpXmlText* value) const noexcept;

        _Must_inspect_result_
        SIZE_T GlobalCount() const noexcept;

    private:
        _Must_inspect_result_
        SIZE_T LocalCount(ULONG qnameId) const noexcept;

        HttpExiStringTable literals_ = {};
        HeapArray<HttpExiGlobalValueEntry> globalEntries_ = {};
        HeapArray<HttpExiLocalValueEntry> localEntries_ = {};
        SIZE_T globalCount_ = 0;
        SIZE_T nextGlobalId_ = 0;
        SIZE_T localEntryCount_ = 0;
        ULONG valueMaxLength_ = 0xffffffffUL;
        SIZE_T valuePartitionCapacity_ = 0;
    };

    struct HttpExiQNameEntry final
    {
        ULONG UriId = 0;
        ULONG LocalNameId = 0;
        ULONG PrefixId = 0xffffffffUL;
    };

    class HttpExiQNameTable final
    {
    public:
        HttpExiQNameTable() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxEntries) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Add(HttpExiQNameEntry value, _Out_ ULONG* index) noexcept;

        _Must_inspect_result_
        bool Find(HttpExiQNameEntry value, _Out_ ULONG* index) const noexcept;

        _Must_inspect_result_
        bool Get(ULONG index, _Out_ HttpExiQNameEntry* value) const noexcept;

        _Must_inspect_result_
        SIZE_T Count() const noexcept;

    private:
        HeapArray<HttpExiQNameEntry> entries_ = {};
        SIZE_T entryCount_ = 0;
    };
}
}
