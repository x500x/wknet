#include <wknet/http/Cache.h>
#include "Detail.h"
#include "session/Engine.h"

namespace wknet::http {
namespace
{
    void FillApiCacheOptions(
        const CacheOptions* options,
        ::wknet::session::KhHttpCacheOptions& apiOptions) noexcept
    {
        if (options == nullptr) {
            apiOptions = {};
            return;
        }
        apiOptions.MaxBytes = options->MaxBytes;
        apiOptions.MaxEntries = options->MaxEntries;
        apiOptions.Mode = detail::ToApiCacheMode(options->Mode);
    }

    void FillCacheStats(
        const ::wknet::session::KhHttpCacheStats& src,
        CacheStats& dst) noexcept
    {
        dst.EntryCount = src.EntryCount;
        dst.BytesUsed = src.BytesUsed;
        dst.Hits = src.Hits;
        dst.Misses = src.Misses;
        dst.Revalidations = src.Revalidations;
        dst.Stores = src.Stores;
        dst.Invalidations = src.Invalidations;
        dst.Evictions = src.Evictions;
    }
}

NTSTATUS CacheCreate(Cache** cache) noexcept
{
    return CacheCreate(nullptr, cache);
}

NTSTATUS CacheCreate(const CacheOptions* options, Cache** cache) noexcept
{
    if (cache != nullptr) {
        *cache = nullptr;
    }
    if (cache == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    auto* created = ::wknet::AllocateNonPagedObject<Cache>();
    if (created == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ::wknet::session::KhHttpCacheOptions apiOptions = {};
    FillApiCacheOptions(options, apiOptions);
    NTSTATUS status = ::wknet::session::KhHttpCacheCreate(&apiOptions, &created->Engine);
    if (!NT_SUCCESS(status)) {
        ::wknet::FreeNonPagedObject(created);
        return status;
    }

    *cache = created;
    return STATUS_SUCCESS;
}

void CacheRelease(Cache* cache) noexcept
{
    if (cache == nullptr || cache->Magic != detail::KhHighCacheMagic) {
        return;
    }
    if (cache->Engine != nullptr) {
        ::wknet::session::KhHttpCacheClose(cache->Engine);
        cache->Engine = nullptr;
    }
    cache->Magic = 0;
    ::wknet::FreeNonPagedObject(cache);
}

NTSTATUS CacheClear(Cache* cache) noexcept
{
    return ::wknet::session::KhHttpCacheClear(detail::ToApiCache(cache));
}

NTSTATUS CacheGetStats(Cache* cache, CacheStats* stats) noexcept
{
    if (stats != nullptr) {
        *stats = {};
    }
    if (stats == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    ::wknet::session::KhHttpCacheStats apiStats = {};
    NTSTATUS status = ::wknet::session::KhHttpCacheGetStats(detail::ToApiCache(cache), &apiStats);
    if (NT_SUCCESS(status)) {
        FillCacheStats(apiStats, *stats);
    }
    return status;
}
}
