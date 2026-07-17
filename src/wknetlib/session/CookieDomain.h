#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::session
{
    // RFC 6265 domain-match + Public Suffix helpers (ASCII host / punycode).
    _Must_inspect_result_
    bool CookieHostIsIpLiteral(_In_reads_(hostLength) const char* host, SIZE_T hostLength) noexcept;

    void CookieNormalizeHost(
        _In_reads_(hostLength) const char* host,
        SIZE_T hostLength,
        _Out_writes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;

    _Must_inspect_result_
    bool CookieIsPublicSuffix(_In_reads_(domainLength) const char* domain, SIZE_T domainLength) noexcept;

    // eTLD+1 registrable domain; returns false if host is a public suffix or invalid.
    _Must_inspect_result_
    bool CookieRegistrableDomain(
        _In_reads_(hostLength) const char* host,
        SIZE_T hostLength,
        _Out_writes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;

    // RFC 6265 §5.1.3 domain-match.
    _Must_inspect_result_
    bool CookieDomainMatch(
        _In_reads_(domainLength) const char* cookieDomain,
        SIZE_T domainLength,
        _In_reads_(hostLength) const char* host,
        SIZE_T hostLength) noexcept;

    // Validate Domain attribute for storage; writes normalized domain without leading dot.
    _Must_inspect_result_
    NTSTATUS CookieValidateDomainAttribute(
        _In_reads_(hostLength) const char* requestHost,
        SIZE_T hostLength,
        _In_reads_(domainLength) const char* domainAttribute,
        SIZE_T domainLength,
        _Out_writes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength,
        _Out_ bool* hostOnly) noexcept;

    // RFC 6265 §5.1.4 path-match.
    _Must_inspect_result_
    bool CookiePathMatch(
        _In_reads_(cookiePathLength) const char* cookiePath,
        SIZE_T cookiePathLength,
        _In_reads_(requestPathLength) const char* requestPath,
        SIZE_T requestPathLength) noexcept;

    void CookieDefaultPath(
        _In_reads_(requestPathLength) const char* requestPath,
        SIZE_T requestPathLength,
        _Out_writes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;
}
