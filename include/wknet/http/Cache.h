#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS CacheCreate(_Out_ Cache** cache) noexcept;

    _Must_inspect_result_
    NTSTATUS CacheCreate(_In_opt_ const CacheOptions* options, _Out_ Cache** cache) noexcept;

    void CacheRelease(_In_opt_ Cache* cache) noexcept;

    _Must_inspect_result_
    NTSTATUS CacheClear(_In_ Cache* cache) noexcept;

    _Must_inspect_result_
    NTSTATUS CacheGetStats(_In_ Cache* cache, _Out_ CacheStats* stats) noexcept;
}
