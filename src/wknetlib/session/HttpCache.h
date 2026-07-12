#pragma once

#include "session/HandleTypes.h"
#include "http1/HttpCachePolicy.h"

namespace wknet
{
namespace session
{
    constexpr SIZE_T KhHttpCacheMaxVaryFields = KhMaxHeadersPerRequest;
    constexpr SIZE_T KhHttpCacheMaxPartialRanges = 16;

    struct KhHttpCacheRange final
    {
        ULONGLONG First = 0;
        ULONGLONG Last = 0;
    };

    struct KhHttpCacheVaryField final
    {
        char* Name = nullptr;
        SIZE_T NameLength = 0;
        char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct KhHttpCacheEntry;

    struct KhHttpCacheSnapshot final
    {
        USHORT StatusCode = 0;
        http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        char* HeaderNameStorage = nullptr;
        SIZE_T HeaderNameStorageLength = 0;
        char* HeaderValueStorage = nullptr;
        SIZE_T HeaderValueStorageLength = 0;
        UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
    };

    struct KhHttpCacheLookupResult final
    {
        bool Found = false;
        bool RequiresValidation = false;
        bool RangeRequest = false;
        bool SatisfiedRange = false;
        bool OnlyIfCachedMiss = false;
        KhHttpCacheSnapshot Snapshot = {};
        char IfNoneMatch[KhMaxHeaderValueLength + 1] = {};
        SIZE_T IfNoneMatchLength = 0;
        char IfModifiedSince[KhMaxHeaderValueLength + 1] = {};
        SIZE_T IfModifiedSinceLength = 0;
    };

    struct KhHttpCache
    {
        KhHandleHeader Header = { KhHandleKind::HttpCache, 0, nullptr };
        KhHttpCacheOptions Options = {};
        KhHttpCacheStats Stats = {};
        KhHttpCacheEntry* Head = nullptr;
        KhHttpCacheEntry* Tail = nullptr;
        SIZE_T EntryCount = 0;
        SIZE_T BytesUsed = 0;
#if defined(WKNET_USER_MODE_TEST)
        volatile LONG Lock = 0;
#else
        FAST_MUTEX Lock = {};
        volatile LONG LockInitialized = 0;
#endif
    };

    _Must_inspect_result_
    NTSTATUS KhHttpCacheLookup(
        _In_ KH_HTTP_CACHE cache,
        _In_ const KhRequest& request,
        _In_ const KhHttpSendOptions& options,
        _Out_ KhHttpCacheLookupResult* result) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpCacheStoreResponse(
        _In_ KH_HTTP_CACHE cache,
        _In_ const KhRequest& request,
        _In_ const KhHttpSendOptions& options,
        _In_ const http1::HttpResponse& response) noexcept;

    _Must_inspect_result_
    NTSTATUS KhHttpCacheUpdateNotModified(
        _In_ KH_HTTP_CACHE cache,
        _In_ const KhRequest& request,
        _In_ const http1::HttpResponse& response,
        _Out_ KhHttpCacheSnapshot* snapshot) noexcept;

    void KhHttpCacheInvalidateForRequest(
        _In_ KH_HTTP_CACHE cache,
        _In_ const KhRequest& request) noexcept;

    void KhHttpCacheFreeSnapshot(_Inout_ KhHttpCacheSnapshot* snapshot) noexcept;
}
}
