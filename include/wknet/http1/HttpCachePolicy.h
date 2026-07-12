#pragma once

#include <wknet/http1/HttpResponse.h>

namespace wknet
{
namespace http1
{
    enum class HttpCacheScope : UCHAR
    {
        Private = 0,
        Shared = 1
    };

    struct HttpCacheControl final
    {
        bool NoStore = false;
        bool NoCache = false;
        bool Private = false;
        bool Public = false;
        bool MustRevalidate = false;
        bool ProxyRevalidate = false;
        bool Immutable = false;
        bool OnlyIfCached = false;
        bool HasMaxAge = false;
        bool HasSharedMaxAge = false;
        bool HasMinFresh = false;
        bool HasMaxStale = false;
        bool MaxStaleAny = false;
        ULONG MaxAgeSeconds = 0;
        ULONG SharedMaxAgeSeconds = 0;
        ULONG MinFreshSeconds = 0;
        ULONG MaxStaleSeconds = 0;
    };

    struct HttpCacheMetadata final
    {
        HttpCacheControl CacheControl = {};
        bool HasDate = false;
        bool HasExpires = false;
        bool HasAge = false;
        bool HasETag = false;
        bool HasLastModified = false;
        bool HasLastModifiedSeconds = false;
        LONGLONG DateSeconds = 0;
        LONGLONG ExpiresSeconds = 0;
        LONGLONG LastModifiedSeconds = 0;
        ULONG AgeSeconds = 0;
        HttpText ETag = {};
        HttpText LastModified = {};
        HttpText Vary = {};
    };

    struct HttpByteRange final
    {
        ULONGLONG First = 0;
        ULONGLONG Last = 0;
        ULONGLONG SuffixLength = 0;
        bool Valid = false;
        bool Suffix = false;
    };

    _Must_inspect_result_
    bool ParseHttpDate(_In_ HttpText value, _Out_ LONGLONG* seconds) noexcept;

    _Must_inspect_result_
    bool ParseCacheControl(_In_ HttpText value, _Out_ HttpCacheControl* control) noexcept;

    _Must_inspect_result_
    bool ParseSingleByteRange(_In_ HttpText value, _Out_ HttpByteRange* range) noexcept;

    _Must_inspect_result_
    bool CollectCacheMetadata(_In_ const HttpResponse& response, _Out_ HttpCacheMetadata* metadata) noexcept;

    _Must_inspect_result_
    bool CollectCacheMetadata(
        _In_reads_(headersCount) const HttpHeader* headers,
        SIZE_T headersCount,
        _Out_ HttpCacheMetadata* metadata) noexcept;

    _Must_inspect_result_
    bool IsDefaultCacheableStatus(USHORT statusCode) noexcept;

    _Must_inspect_result_
    bool IsMethodSafeForCache(ULONG method) noexcept;

    _Must_inspect_result_
    bool IsUnsafeMethodForInvalidation(ULONG method) noexcept;

    _Must_inspect_result_
    bool ResponseMayBeStored(
        ULONG method,
        bool requestHasAuthorization,
        const HttpCacheControl& requestControl,
        const HttpResponse& response,
        const HttpCacheMetadata& responseMetadata,
        HttpCacheScope scope) noexcept;

    _Must_inspect_result_
    LONGLONG FreshnessLifetimeSeconds(
        const HttpCacheMetadata& metadata,
        USHORT statusCode,
        HttpCacheScope scope) noexcept;

    _Must_inspect_result_
    LONGLONG CurrentAgeSeconds(
        const HttpCacheMetadata& metadata,
        LONGLONG storedAtSeconds,
        LONGLONG nowSeconds) noexcept;

    _Must_inspect_result_
    bool CanUseStoredResponse(
        const HttpCacheMetadata& requestMetadata,
        const HttpCacheMetadata& responseMetadata,
        USHORT statusCode,
        LONGLONG storedAtSeconds,
        LONGLONG nowSeconds,
        HttpCacheScope scope,
        _Out_ bool* requiresValidation) noexcept;
}
}
