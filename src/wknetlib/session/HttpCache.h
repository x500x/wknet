#pragma once

#include "session/HandleTypes.h"
#include "http1/HttpCachePolicy.h"

namespace wknet
{
namespace session
{
    constexpr SIZE_T HttpCacheMaxVaryFields = MaxHeadersPerRequest;
    constexpr SIZE_T HttpCacheMaxPartialRanges = 16;

    struct HttpCacheRange final
    {
        ULONGLONG First = 0;
        ULONGLONG Last = 0;
    };

    struct HttpCacheVaryField final
    {
        char* Name = nullptr;
        SIZE_T NameLength = 0;
        char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct HttpCacheEntry;

    struct HttpCacheSnapshot final
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

    struct HttpCacheLookupResult final
    {
        bool Found = false;
        bool RequiresValidation = false;
        bool RangeRequest = false;
        bool SatisfiedRange = false;
        bool OnlyIfCachedMiss = false;
        HttpCacheSnapshot Snapshot = {};
        char IfNoneMatch[HttpCacheValidatorFieldBytes + 1] = {};
        SIZE_T IfNoneMatchLength = 0;
        char IfModifiedSince[HttpCacheValidatorFieldBytes + 1] = {};
        SIZE_T IfModifiedSinceLength = 0;
    };

    struct HttpCache
    {
        HandleHeader Header = { HandleKind::HttpCache, 0, nullptr };
        HttpCacheOptions Options = {};
        HttpCacheStats Stats = {};
        HttpCacheEntry* Head = nullptr;
        HttpCacheEntry* Tail = nullptr;
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
    NTSTATUS HttpCacheLookup(
        _In_ HttpCacheHandle cache,
        _In_ const Request& request,
        _In_ const HttpSendOptions& options,
        _Out_ HttpCacheLookupResult* result) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpCacheStoreResponse(
        _In_ HttpCacheHandle cache,
        _In_ const Request& request,
        _In_ const HttpSendOptions& options,
        _In_ const http1::HttpResponse& response) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpCacheUpdateNotModified(
        _In_ HttpCacheHandle cache,
        _In_ const Request& request,
        _In_ const http1::HttpResponse& response,
        _Out_ HttpCacheSnapshot* snapshot) noexcept;

    void HttpCacheInvalidateForRequest(
        _In_ HttpCacheHandle cache,
        _In_ const Request& request) noexcept;

    void HttpCacheFreeSnapshot(_Inout_ HttpCacheSnapshot* snapshot) noexcept;
}
}
