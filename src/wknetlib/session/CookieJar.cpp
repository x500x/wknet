#include "session/CookieJar.h"

namespace wknet::session
{
namespace
{
    char ToLower(char value) noexcept
    {
        if (value >= 'A' && value <= 'Z') {
            return static_cast<char>(value - 'A' + 'a');
        }
        return value;
    }

    bool EqualsIgnoreCase(const char* a, SIZE_T al, const char* b, SIZE_T bl) noexcept
    {
        if (al != bl) {
            return false;
        }
        for (SIZE_T i = 0; i < al; ++i) {
            if (ToLower(a[i]) != ToLower(b[i])) {
                return false;
            }
        }
        return true;
    }

    bool IsTokenChar(char value) noexcept
    {
        const unsigned char c = static_cast<unsigned char>(value);
        if (c <= 0x1F || c == 0x7F) {
            return false;
        }
        switch (value) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        case '\t':
            return false;
        default:
            return true;
        }
    }

    void CopyText(const char* src, SIZE_T len, char* dst, SIZE_T cap, SIZE_T* outLen) noexcept
    {
        if (outLen != nullptr) {
            *outLen = 0;
        }
        if (dst == nullptr || cap == 0) {
            return;
        }
        SIZE_T n = len;
        if (n + 1 > cap) {
            n = cap - 1;
        }
        for (SIZE_T i = 0; i < n; ++i) {
            dst[i] = src != nullptr ? src[i] : 0;
        }
        dst[n] = 0;
        if (outLen != nullptr) {
            *outLen = n;
        }
    }

    SIZE_T CookieBytes(const Cookie& cookie) noexcept
    {
        return cookie.NameLength + cookie.ValueLength + cookie.DomainLength + cookie.PathLength + 32;
    }

    bool ParseUrlParts(
        const char* url,
        SIZE_T urlLength,
        char* scheme,
        SIZE_T schemeCap,
        SIZE_T* schemeLen,
        char* host,
        SIZE_T hostCap,
        SIZE_T* hostLen,
        char* path,
        SIZE_T pathCap,
        SIZE_T* pathLen,
        bool* isHttps) noexcept
    {
        if (schemeLen) *schemeLen = 0;
        if (hostLen) *hostLen = 0;
        if (pathLen) *pathLen = 0;
        if (isHttps) *isHttps = false;
        if (url == nullptr || urlLength == 0) {
            return false;
        }

        // Minimal parse: scheme://host[:port]/path
        SIZE_T i = 0;
        while (i < urlLength && url[i] != ':') {
            ++i;
        }
        if (i == 0 || i + 2 >= urlLength || url[i] != ':' || url[i + 1] != '/' || url[i + 2] != '/') {
            return false;
        }
        CopyText(url, i, scheme, schemeCap, schemeLen);
        if (isHttps != nullptr && schemeLen != nullptr) {
            *isHttps = EqualsIgnoreCase(scheme, *schemeLen, "https", 5);
        }
        i += 3;
        const SIZE_T hostStart = i;
        while (i < urlLength && url[i] != '/' && url[i] != '?' && url[i] != '#') {
            ++i;
        }
        SIZE_T hostEnd = i;
        // strip port
        for (SIZE_T j = hostStart; j < hostEnd; ++j) {
            if (url[j] == ':' && url[hostStart] != '[') {
                hostEnd = j;
                break;
            }
        }
        CopyText(url + hostStart, hostEnd - hostStart, host, hostCap, hostLen);
        if (i < urlLength && url[i] == '/') {
            SIZE_T pathStart = i;
            while (i < urlLength && url[i] != '?' && url[i] != '#') {
                ++i;
            }
            CopyText(url + pathStart, i - pathStart, path, pathCap, pathLen);
        } else {
            CopyText("/", 1, path, pathCap, pathLen);
        }
        return hostLen != nullptr && *hostLen != 0;
    }

    void SkipWs(const char* s, SIZE_T n, SIZE_T* i) noexcept
    {
        while (*i < n && (s[*i] == ' ' || s[*i] == '\t')) {
            ++(*i);
        }
    }

    bool ParseULong(const char* s, SIZE_T n, ULONGLONG* value) noexcept
    {
        if (value == nullptr || n == 0) {
            return false;
        }
        ULONGLONG v = 0;
        for (SIZE_T i = 0; i < n; ++i) {
            if (s[i] < '0' || s[i] > '9') {
                return false;
            }
            v = v * 10 + static_cast<ULONGLONG>(s[i] - '0');
        }
        *value = v;
        return true;
    }
}

    NTSTATUS CookieJarInitialize(CookieJar* jar) noexcept
    {
        if (jar == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        RtlZeroMemory(jar, sizeof(*jar));
        return STATUS_SUCCESS;
    }

    void CookieJarClear(CookieJar* jar) noexcept
    {
        if (jar == nullptr) {
            return;
        }
        jar->Count = 0;
        jar->TotalBytes = 0;
        if (jar->Items != nullptr) {
            RtlZeroMemory(jar->Items, sizeof(Cookie) * jar->Capacity);
        }
    }

    void CookieJarDestroy(CookieJar* jar) noexcept
    {
        if (jar == nullptr) {
            return;
        }
        FreeNonPagedArray(jar->Items);
        RtlZeroMemory(jar, sizeof(*jar));
    }

    NTSTATUS CookieJarSet(CookieJar* jar, const Cookie& cookie) noexcept
    {
        if (jar == nullptr || cookie.NameLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        // Replace same name+domain+path
        for (SIZE_T i = 0; i < jar->Count; ++i) {
            Cookie& existing = jar->Items[i];
            if (EqualsIgnoreCase(existing.Name, existing.NameLength, cookie.Name, cookie.NameLength) &&
                EqualsIgnoreCase(existing.Domain, existing.DomainLength, cookie.Domain, cookie.DomainLength) &&
                existing.PathLength == cookie.PathLength &&
                RtlCompareMemory(existing.Path, cookie.Path, cookie.PathLength) == cookie.PathLength) {
                jar->TotalBytes -= CookieBytes(existing);
                existing = cookie;
                jar->TotalBytes += CookieBytes(existing);
                if (jar->TotalBytes > CookieJarMaxTotalBytes) {
                    // roll back by clearing this cookie
                    existing = {};
                    // compact
                    for (SIZE_T j = i + 1; j < jar->Count; ++j) {
                        jar->Items[j - 1] = jar->Items[j];
                    }
                    --jar->Count;
                    jar->TotalBytes = 0;
                    for (SIZE_T j = 0; j < jar->Count; ++j) {
                        jar->TotalBytes += CookieBytes(jar->Items[j]);
                    }
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                return STATUS_SUCCESS;
            }
        }

        if (jar->Count >= CookieJarMaxCookies) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        const SIZE_T need = CookieBytes(cookie);
        if (jar->TotalBytes + need > CookieJarMaxTotalBytes) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (jar->Count == jar->Capacity) {
            SIZE_T newCap = jar->Capacity == 0 ? 8 : jar->Capacity * 2;
            if (newCap > CookieJarMaxCookies) {
                newCap = CookieJarMaxCookies;
            }
            if (newCap <= jar->Capacity) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            auto* replacement = AllocateNonPagedArray<Cookie>(newCap);
            if (replacement == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            if (jar->Items != nullptr && jar->Count != 0) {
                RtlCopyMemory(replacement, jar->Items, sizeof(Cookie) * jar->Count);
            }
            FreeNonPagedArray(jar->Items);
            jar->Items = replacement;
            jar->Capacity = newCap;
        }

        jar->Items[jar->Count++] = cookie;
        jar->TotalBytes += need;
        return STATUS_SUCCESS;
    }

    NTSTATUS CookieJarStoreFromSetCookie(
        CookieJar* jar,
        const char* requestUrl,
        SIZE_T urlLength,
        const char* setCookieLine,
        SIZE_T lineLength,
        ULONGLONG now100ns) noexcept
    {
        if (jar == nullptr || setCookieLine == nullptr || lineLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        char scheme[16] = {};
        char host[256] = {};
        char path[CookieJarMaxPathBytes + 1] = {};
        SIZE_T schemeLen = 0, hostLen = 0, pathLen = 0;
        bool isHttps = false;
        if (!ParseUrlParts(requestUrl, urlLength, scheme, sizeof(scheme), &schemeLen, host, sizeof(host), &hostLen, path, sizeof(path), &pathLen, &isHttps)) {
            return STATUS_INVALID_PARAMETER;
        }

        // name=value
        SIZE_T i = 0;
        SkipWs(setCookieLine, lineLength, &i);
        const SIZE_T nameStart = i;
        while (i < lineLength && setCookieLine[i] != '=' && setCookieLine[i] != ';') {
            if (!IsTokenChar(setCookieLine[i])) {
                return STATUS_INVALID_PARAMETER;
            }
            ++i;
        }
        if (i == nameStart || i >= lineLength || setCookieLine[i] != '=') {
            return STATUS_INVALID_PARAMETER;
        }
        const SIZE_T nameLen = i - nameStart;
        ++i;
        const SIZE_T valueStart = i;
        while (i < lineLength && setCookieLine[i] != ';') {
            ++i;
        }
        const SIZE_T valueLen = i - valueStart;
        if (nameLen > CookieJarMaxNameBytes || valueLen > CookieJarMaxValueBytes) {
            return STATUS_INVALID_PARAMETER;
        }

        Cookie cookie = {};
        CopyText(setCookieLine + nameStart, nameLen, cookie.Name, sizeof(cookie.Name), &cookie.NameLength);
        CopyText(setCookieLine + valueStart, valueLen, cookie.Value, sizeof(cookie.Value), &cookie.ValueLength);

        bool hasDomain = false;
        char domainAttr[256] = {};
        SIZE_T domainAttrLen = 0;
        bool hasPath = false;

        while (i < lineLength) {
            if (setCookieLine[i] == ';') {
                ++i;
            }
            SkipWs(setCookieLine, lineLength, &i);
            if (i >= lineLength) {
                break;
            }
            const SIZE_T attrStart = i;
            while (i < lineLength && setCookieLine[i] != ';' && setCookieLine[i] != '=') {
                ++i;
            }
            SIZE_T attrLen = i - attrStart;
            // trim trailing space
            while (attrLen > 0 && (setCookieLine[attrStart + attrLen - 1] == ' ' || setCookieLine[attrStart + attrLen - 1] == '\t')) {
                --attrLen;
            }
            SIZE_T valStart = 0;
            SIZE_T valLen = 0;
            if (i < lineLength && setCookieLine[i] == '=') {
                ++i;
                valStart = i;
                while (i < lineLength && setCookieLine[i] != ';') {
                    ++i;
                }
                valLen = i - valStart;
            }

            if (EqualsIgnoreCase(setCookieLine + attrStart, attrLen, "Domain", 6)) {
                hasDomain = true;
                CopyText(setCookieLine + valStart, valLen, domainAttr, sizeof(domainAttr), &domainAttrLen);
            } else if (EqualsIgnoreCase(setCookieLine + attrStart, attrLen, "Path", 4)) {
                hasPath = true;
                CopyText(setCookieLine + valStart, valLen, cookie.Path, sizeof(cookie.Path), &cookie.PathLength);
            } else if (EqualsIgnoreCase(setCookieLine + attrStart, attrLen, "Secure", 6)) {
                cookie.Secure = true;
            } else if (EqualsIgnoreCase(setCookieLine + attrStart, attrLen, "HttpOnly", 8)) {
                cookie.HttpOnly = true;
            } else if (EqualsIgnoreCase(setCookieLine + attrStart, attrLen, "SameSite", 8)) {
                if (EqualsIgnoreCase(setCookieLine + valStart, valLen, "Strict", 6)) {
                    cookie.SameSite = CookieSameSite::Strict;
                } else if (EqualsIgnoreCase(setCookieLine + valStart, valLen, "None", 4)) {
                    cookie.SameSite = CookieSameSite::None;
                } else {
                    cookie.SameSite = CookieSameSite::Lax;
                }
            } else if (EqualsIgnoreCase(setCookieLine + attrStart, attrLen, "Max-Age", 7)) {
                ULONGLONG seconds = 0;
                if (ParseULong(setCookieLine + valStart, valLen, &seconds)) {
                    cookie.Persistent = true;
                    // 100ns units
                    cookie.ExpiresAt100ns = now100ns + seconds * 10000000ULL;
                }
            }
        }

        bool hostOnly = true;
        NTSTATUS status = CookieValidateDomainAttribute(
            host,
            hostLen,
            hasDomain ? domainAttr : nullptr,
            hasDomain ? domainAttrLen : 0,
            cookie.Domain,
            sizeof(cookie.Domain),
            &cookie.DomainLength,
            &hostOnly);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        cookie.HostOnly = hostOnly;

        if (!hasPath || cookie.PathLength == 0) {
            CookieDefaultPath(path, pathLen, cookie.Path, sizeof(cookie.Path), &cookie.PathLength);
        }
        if (cookie.PathLength == 0) {
            cookie.Path[0] = '/';
            cookie.PathLength = 1;
        }
        if (cookie.SameSite == CookieSameSite::None && !cookie.Secure) {
            return STATUS_INVALID_PARAMETER;
        }

        return CookieJarSet(jar, cookie);
    }

    NTSTATUS CookieJarBuildHeader(
        const CookieJar* jar,
        const char* requestUrl,
        SIZE_T urlLength,
        bool isHttps,
        ULONGLONG now100ns,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }
        if (jar == nullptr || destination == nullptr || destinationCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        char scheme[16] = {};
        char host[256] = {};
        char path[CookieJarMaxPathBytes + 1] = {};
        SIZE_T schemeLen = 0, hostLen = 0, pathLen = 0;
        bool https = isHttps;
        if (!ParseUrlParts(requestUrl, urlLength, scheme, sizeof(scheme), &schemeLen, host, sizeof(host), &hostLen, path, sizeof(path), &pathLen, &https)) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T out = 0;
        for (SIZE_T i = 0; i < jar->Count; ++i) {
            const Cookie& cookie = jar->Items[i];
            if (cookie.NameLength == 0) {
                continue;
            }
            if (cookie.Persistent && cookie.ExpiresAt100ns != 0 && now100ns >= cookie.ExpiresAt100ns) {
                continue;
            }
            if (cookie.Secure && !https) {
                continue;
            }
            if (cookie.HostOnly) {
                if (!EqualsIgnoreCase(cookie.Domain, cookie.DomainLength, host, hostLen)) {
                    continue;
                }
            } else if (!CookieDomainMatch(cookie.Domain, cookie.DomainLength, host, hostLen)) {
                continue;
            }
            if (!CookiePathMatch(cookie.Path, cookie.PathLength, path, pathLen)) {
                continue;
            }
            // SameSite: kernel client — Strict/Lax only same-site (eTLD+1 match)
            if (cookie.SameSite != CookieSameSite::None) {
                char cookieReg[256] = {};
                char hostReg[256] = {};
                SIZE_T cr = 0, hr = 0;
                const bool cookieOk = CookieRegistrableDomain(cookie.Domain, cookie.DomainLength, cookieReg, sizeof(cookieReg), &cr);
                const bool hostOk = CookieRegistrableDomain(host, hostLen, hostReg, sizeof(hostReg), &hr);
                if (!cookieOk || !hostOk || !EqualsIgnoreCase(cookieReg, cr, hostReg, hr)) {
                    continue;
                }
            }

            // append name=value
            const SIZE_T need = cookie.NameLength + 1 + cookie.ValueLength + (out == 0 ? 0 : 2);
            if (out + need + 1 > destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (out != 0) {
                destination[out++] = ';';
                destination[out++] = ' ';
            }
            for (SIZE_T j = 0; j < cookie.NameLength; ++j) {
                destination[out++] = cookie.Name[j];
            }
            destination[out++] = '=';
            for (SIZE_T j = 0; j < cookie.ValueLength; ++j) {
                destination[out++] = cookie.Value[j];
            }
        }
        destination[out] = 0;
        if (destinationLength != nullptr) {
            *destinationLength = out;
        }
        return STATUS_SUCCESS;
    }
}
