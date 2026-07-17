#pragma once

#include "session/CookieDomain.h"

namespace wknet::session
{
    constexpr SIZE_T CookieJarMaxCookies = 256;
    constexpr SIZE_T CookieJarMaxNameBytes = 256;
    constexpr SIZE_T CookieJarMaxValueBytes = 4096;
    constexpr SIZE_T CookieJarMaxDomainBytes = 253;
    constexpr SIZE_T CookieJarMaxPathBytes = 1024;
    constexpr SIZE_T CookieJarMaxTotalBytes = 256 * 1024;
    // Cookie request-header build budget (heap). Large enough for typical jars;
    // overflow returns STATUS_BUFFER_TOO_SMALL rather than growing unboundedly.
    constexpr SIZE_T CookieJarMaxHeaderBytes = 8 * 1024;

    enum class CookieSameSite : UCHAR
    {
        Lax = 0,
        Strict = 1,
        None = 2
    };

    // Large fixed fields live in heap-allocated Cookie entries (Items[]), never
    // as automatic stack locals on parse/build paths.
    struct Cookie final
    {
        char Name[CookieJarMaxNameBytes + 1] = {};
        SIZE_T NameLength = 0;
        char Value[CookieJarMaxValueBytes + 1] = {};
        SIZE_T ValueLength = 0;
        char Domain[CookieJarMaxDomainBytes + 1] = {};
        SIZE_T DomainLength = 0;
        char Path[CookieJarMaxPathBytes + 1] = {};
        SIZE_T PathLength = 0;
        bool HostOnly = true;
        bool Secure = false;
        bool HttpOnly = false;
        CookieSameSite SameSite = CookieSameSite::Lax;
        bool Persistent = false;
        ULONGLONG ExpiresAt100ns = 0; // 0 = session cookie
    };

    struct CookieJar final
    {
        Cookie* Items = nullptr;
        SIZE_T Count = 0;
        SIZE_T Capacity = 0;
        SIZE_T TotalBytes = 0;
        // Serializes jar mutation and snapshot builds so concurrent Send on the
        // same Session cannot race Items/Count during Set-Cookie / Cookie header.
        // KMUTEX (not FAST_MUTEX): library sync APIs require PASSIVE_LEVEL and
        // CheckPassiveLevel() is exact-equality; FAST_MUTEX would raise APC_LEVEL.
#if defined(WKNET_USER_MODE_TEST)
        volatile LONG Lock = 0;
#else
        KMUTEX Lock = {};
        volatile LONG LockState = 0;
#endif
    };

    _Must_inspect_result_
    NTSTATUS CookieJarInitialize(_Out_ CookieJar* jar) noexcept;

    void CookieJarClear(_Inout_ CookieJar* jar) noexcept;

    void CookieJarDestroy(_Inout_ CookieJar* jar) noexcept;

    // Parse one Set-Cookie line for requestUrl host/path/scheme.
    _Must_inspect_result_
    NTSTATUS CookieJarStoreFromSetCookie(
        _Inout_ CookieJar* jar,
        _In_reads_(urlLength) const char* requestUrl,
        SIZE_T urlLength,
        _In_reads_(lineLength) const char* setCookieLine,
        SIZE_T lineLength,
        ULONGLONG now100ns) noexcept;

    // Build Cookie header value for requestUrl into destination (name=value; ...).
    _Must_inspect_result_
    NTSTATUS CookieJarBuildHeader(
        _In_ const CookieJar* jar,
        _In_reads_(urlLength) const char* requestUrl,
        SIZE_T urlLength,
        bool isHttps,
        ULONGLONG now100ns,
        _Out_writes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;

    _Must_inspect_result_
    NTSTATUS CookieJarSet(
        _Inout_ CookieJar* jar,
        _In_ const Cookie& cookie) noexcept;
}
