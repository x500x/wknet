#include <KernelHttp/khttp/Cache.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace khttp
{
namespace
{
    void FillApiCacheOptions(
        const CacheOptions* options,
        ::KernelHttp::engine::KhHttpCacheOptions& apiOptions) noexcept
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
        const ::KernelHttp::engine::KhHttpCacheStats& src,
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

    auto* created = ::KernelHttp::AllocateNonPagedObject<Cache>();
    if (created == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ::KernelHttp::engine::KhHttpCacheOptions apiOptions = {};
    FillApiCacheOptions(options, apiOptions);
    NTSTATUS status = ::KernelHttp::engine::KhHttpCacheCreate(&apiOptions, &created->Engine);
    if (!NT_SUCCESS(status)) {
        ::KernelHttp::FreeNonPagedObject(created);
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
        ::KernelHttp::engine::KhHttpCacheClose(cache->Engine);
        cache->Engine = nullptr;
    }
    cache->Magic = 0;
    ::KernelHttp::FreeNonPagedObject(cache);
}

NTSTATUS CacheClear(Cache* cache) noexcept
{
    return ::KernelHttp::engine::KhHttpCacheClear(detail::ToApiCache(cache));
}

NTSTATUS CacheGetStats(Cache* cache, CacheStats* stats) noexcept
{
    if (stats != nullptr) {
        *stats = {};
    }
    if (stats == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    ::KernelHttp::engine::KhHttpCacheStats apiStats = {};
    NTSTATUS status = ::KernelHttp::engine::KhHttpCacheGetStats(detail::ToApiCache(cache), &apiStats);
    if (NT_SUCCESS(status)) {
        FillCacheStats(apiStats, *stats);
    }
    return status;
}
}
