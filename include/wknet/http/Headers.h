#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS HeadersCreate(_Out_ Headers** headers) noexcept;

    _Must_inspect_result_
    NTSTATUS HeadersAdd(
        _In_ Headers* headers,
        _In_z_ const char* name,
        _In_z_ const char* value) noexcept;

    _Must_inspect_result_
    NTSTATUS HeadersAddEx(
        _In_ Headers* headers,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    void HeadersRelease(_In_opt_ Headers* headers) noexcept;
}
