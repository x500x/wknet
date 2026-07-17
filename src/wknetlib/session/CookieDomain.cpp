#include "session/CookieDomain.h"

namespace wknet::session
{
namespace
{
    char ToLowerAscii(char value) noexcept
    {
        if (value >= 'A' && value <= 'Z') {
            return static_cast<char>(value - 'A' + 'a');
        }
        return value;
    }

    bool EqualsIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right,
        SIZE_T rightLength) noexcept
    {
        if (leftLength != rightLength) {
            return false;
        }
        for (SIZE_T i = 0; i < leftLength; ++i) {
            if (ToLowerAscii(left[i]) != ToLowerAscii(right[i])) {
                return false;
            }
        }
        return true;
    }

    // Minimal embedded PSL: exact public suffixes that must reject Domain= attributes
    // when not equal to the full host. Expand via generated table in a follow-up.
    constexpr const char* kPublicSuffixes[] = {
        "com", "org", "net", "edu", "gov", "mil", "int",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "or.jp", "ne.jp",
        "com.cn", "net.cn", "org.cn",
        "com.br", "com.mx", "com.tr",
        "github.io", "blogspot.com", "herokuapp.com",
        "azurewebsites.net", "cloudfront.net",
    };

    bool IsPublicSuffixExact(const char* domain, SIZE_T domainLength) noexcept
    {
        for (const char* suffix : kPublicSuffixes) {
            SIZE_T len = 0;
            while (suffix[len] != 0) {
                ++len;
            }
            if (EqualsIgnoreCase(domain, domainLength, suffix, len)) {
                return true;
            }
        }
        return false;
    }

    bool IsDigit(char value) noexcept
    {
        return value >= '0' && value <= '9';
    }

    bool IsHex(char value) noexcept
    {
        return IsDigit(value) ||
            (value >= 'a' && value <= 'f') ||
            (value >= 'A' && value <= 'F');
    }
}

    bool CookieHostIsIpLiteral(const char* host, SIZE_T hostLength) noexcept
    {
        if (host == nullptr || hostLength == 0) {
            return false;
        }
        // IPv6 in brackets or with ':'
        if (host[0] == '[') {
            return true;
        }
        bool hasColon = false;
        bool hasDot = false;
        bool allDigitDot = true;
        for (SIZE_T i = 0; i < hostLength; ++i) {
            const char c = host[i];
            if (c == ':') {
                hasColon = true;
            } else if (c == '.') {
                hasDot = true;
            } else if (!IsDigit(c) && !IsHex(c)) {
                allDigitDot = false;
            }
        }
        if (hasColon) {
            return true;
        }
        // crude IPv4: digits and dots only with a dot
        return hasDot && allDigitDot;
    }

    void CookieNormalizeHost(
        const char* host,
        SIZE_T hostLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }
        if (destination == nullptr || destinationCapacity == 0) {
            return;
        }
        SIZE_T out = 0;
        SIZE_T start = 0;
        SIZE_T end = hostLength;
        if (host != nullptr && hostLength >= 2 && host[0] == '[' && host[hostLength - 1] == ']') {
            start = 1;
            end = hostLength - 1;
        }
        for (SIZE_T i = start; i < end && out + 1 < destinationCapacity; ++i) {
            destination[out++] = ToLowerAscii(host != nullptr ? host[i] : 0);
        }
        destination[out] = 0;
        if (destinationLength != nullptr) {
            *destinationLength = out;
        }
    }

    bool CookieIsPublicSuffix(const char* domain, SIZE_T domainLength) noexcept
    {
        if (domain == nullptr || domainLength == 0) {
            return false;
        }
        char normalized[256] = {};
        SIZE_T normalizedLength = 0;
        CookieNormalizeHost(domain, domainLength, normalized, sizeof(normalized), &normalizedLength);
        return IsPublicSuffixExact(normalized, normalizedLength);
    }

    bool CookieRegistrableDomain(
        const char* host,
        SIZE_T hostLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }
        char normalized[256] = {};
        SIZE_T nlen = 0;
        CookieNormalizeHost(host, hostLength, normalized, sizeof(normalized), &nlen);
        if (nlen == 0 || CookieHostIsIpLiteral(normalized, nlen)) {
            return false;
        }
        if (IsPublicSuffixExact(normalized, nlen)) {
            return false;
        }

        // Find longest matching public suffix; registrable = label + '.' + suffix
        SIZE_T bestSuffixLen = 0;
        for (const char* suffix : kPublicSuffixes) {
            SIZE_T slen = 0;
            while (suffix[slen] != 0) {
                ++slen;
            }
            if (slen >= nlen) {
                continue;
            }
            if (normalized[nlen - slen - 1] != '.') {
                continue;
            }
            if (EqualsIgnoreCase(normalized + (nlen - slen), slen, suffix, slen)) {
                if (slen > bestSuffixLen) {
                    bestSuffixLen = slen;
                }
            }
        }
        SIZE_T start = 0;
        if (bestSuffixLen != 0) {
            // walk back one label
            SIZE_T i = nlen - bestSuffixLen - 1; // points at '.'
            if (i == 0) {
                return false;
            }
            SIZE_T j = i;
            while (j > 0 && normalized[j - 1] != '.') {
                --j;
            }
            start = j;
        } else {
            // no known suffix: last two labels if present, else whole host
            SIZE_T dots = 0;
            for (SIZE_T i = 0; i < nlen; ++i) {
                if (normalized[i] == '.') {
                    ++dots;
                }
            }
            if (dots == 0) {
                start = 0;
            } else {
                SIZE_T seen = 0;
                for (SIZE_T i = nlen; i > 0; --i) {
                    if (normalized[i - 1] == '.') {
                        ++seen;
                        if (seen == 2) {
                            start = i;
                            break;
                        }
                    }
                }
            }
        }

        const SIZE_T outLen = nlen - start;
        if (destination == nullptr || destinationCapacity <= outLen) {
            return false;
        }
        for (SIZE_T i = 0; i < outLen; ++i) {
            destination[i] = normalized[start + i];
        }
        destination[outLen] = 0;
        if (destinationLength != nullptr) {
            *destinationLength = outLen;
        }
        return true;
    }

    bool CookieDomainMatch(
        const char* cookieDomain,
        SIZE_T domainLength,
        const char* host,
        SIZE_T hostLength) noexcept
    {
        char d[256] = {};
        char h[256] = {};
        SIZE_T dl = 0;
        SIZE_T hl = 0;
        CookieNormalizeHost(cookieDomain, domainLength, d, sizeof(d), &dl);
        CookieNormalizeHost(host, hostLength, h, sizeof(h), &hl);
        if (dl == 0 || hl == 0) {
            return false;
        }
        if (EqualsIgnoreCase(d, dl, h, hl)) {
            return true;
        }
        if (hl <= dl) {
            return false;
        }
        // host is *.cookieDomain
        if (h[hl - dl - 1] != '.') {
            return false;
        }
        return EqualsIgnoreCase(h + (hl - dl), dl, d, dl);
    }

    NTSTATUS CookieValidateDomainAttribute(
        const char* requestHost,
        SIZE_T hostLength,
        const char* domainAttribute,
        SIZE_T domainLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* destinationLength,
        bool* hostOnly) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }
        if (hostOnly != nullptr) {
            *hostOnly = true;
        }
        char host[256] = {};
        SIZE_T hlen = 0;
        CookieNormalizeHost(requestHost, hostLength, host, sizeof(host), &hlen);
        if (hlen == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (domainAttribute == nullptr || domainLength == 0) {
            if (destination == nullptr || destinationCapacity <= hlen) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            for (SIZE_T i = 0; i < hlen; ++i) {
                destination[i] = host[i];
            }
            destination[hlen] = 0;
            if (destinationLength != nullptr) {
                *destinationLength = hlen;
            }
            if (hostOnly != nullptr) {
                *hostOnly = true;
            }
            return STATUS_SUCCESS;
        }

        if (CookieHostIsIpLiteral(host, hlen)) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T start = 0;
        if (domainLength > 0 && domainAttribute[0] == '.') {
            start = 1;
        }
        char domain[256] = {};
        SIZE_T dlen = 0;
        CookieNormalizeHost(domainAttribute + start, domainLength - start, domain, sizeof(domain), &dlen);
        if (dlen == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!CookieDomainMatch(domain, dlen, host, hlen)) {
            return STATUS_INVALID_PARAMETER;
        }
        // Public suffix protection: Domain=com rejected unless host is exactly com (impossible for real hosts)
        if (IsPublicSuffixExact(domain, dlen) && !EqualsIgnoreCase(domain, dlen, host, hlen)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (destination == nullptr || destinationCapacity <= dlen) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        for (SIZE_T i = 0; i < dlen; ++i) {
            destination[i] = domain[i];
        }
        destination[dlen] = 0;
        if (destinationLength != nullptr) {
            *destinationLength = dlen;
        }
        if (hostOnly != nullptr) {
            *hostOnly = false;
        }
        return STATUS_SUCCESS;
    }

    bool CookiePathMatch(
        const char* cookiePath,
        SIZE_T cookiePathLength,
        const char* requestPath,
        SIZE_T requestPathLength) noexcept
    {
        if (cookiePath == nullptr || cookiePathLength == 0) {
            cookiePath = "/";
            cookiePathLength = 1;
        }
        if (requestPath == nullptr || requestPathLength == 0) {
            requestPath = "/";
            requestPathLength = 1;
        }
        if (requestPathLength < cookiePathLength) {
            return false;
        }
        for (SIZE_T i = 0; i < cookiePathLength; ++i) {
            if (requestPath[i] != cookiePath[i]) {
                return false;
            }
        }
        if (requestPathLength == cookiePathLength) {
            return true;
        }
        if (cookiePath[cookiePathLength - 1] == '/') {
            return true;
        }
        return requestPath[cookiePathLength] == '/';
    }

    void CookieDefaultPath(
        const char* requestPath,
        SIZE_T requestPathLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }
        if (destination == nullptr || destinationCapacity < 2) {
            return;
        }
        if (requestPath == nullptr || requestPathLength == 0 || requestPath[0] != '/') {
            destination[0] = '/';
            destination[1] = 0;
            if (destinationLength != nullptr) {
                *destinationLength = 1;
            }
            return;
        }
        // directory of path: up to last '/' excluding final segment
        SIZE_T lastSlash = 0;
        for (SIZE_T i = 0; i < requestPathLength; ++i) {
            if (requestPath[i] == '/') {
                lastSlash = i;
            }
        }
        if (lastSlash == 0) {
            destination[0] = '/';
            destination[1] = 0;
            if (destinationLength != nullptr) {
                *destinationLength = 1;
            }
            return;
        }
        if (destinationCapacity <= lastSlash) {
            return;
        }
        for (SIZE_T i = 0; i < lastSlash; ++i) {
            destination[i] = requestPath[i];
        }
        destination[lastSlash] = 0;
        if (destinationLength != nullptr) {
            *destinationLength = lastSlash;
        }
    }
}
