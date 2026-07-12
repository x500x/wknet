#include "session/UrlParser.h"
#include "http1/HttpTypes.h"

namespace wknet
{
namespace session
{
namespace
{
    constexpr const char PunycodePrefix[] = "xn--";

    char ToLowerAscii(char value) noexcept
    {
        return (value >= 'A' && value <= 'Z') ? static_cast<char>(value + ('a' - 'A')) : value;
    }

    bool UrlTextEqualsIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right,
        SIZE_T rightLength) noexcept
    {
        if (leftLength != rightLength) {
            return false;
        }

        if (leftLength == 0) {
            return true;
        }

        if (left == nullptr || right == nullptr) {
            return false;
        }

        for (SIZE_T index = 0; index < leftLength; ++index) {
            if (ToLowerAscii(left[index]) != ToLowerAscii(right[index])) {
                return false;
            }
        }

        return true;
    }

    bool UrlTextEqualsLiteralIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept
    {
        return UrlTextEqualsIgnoreCase(left, leftLength, right, http1::MakeText(right).Length);
    }

    bool IsDigit(char value) noexcept
    {
        return value >= '0' && value <= '9';
    }

    bool IsHexDigit(char value) noexcept
    {
        return (value >= '0' && value <= '9') ||
            (value >= 'a' && value <= 'f') ||
            (value >= 'A' && value <= 'F');
    }

    bool IsAsciiAlpha(char value) noexcept
    {
        return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
    }

    bool IsAsciiAlnum(char value) noexcept
    {
        return IsAsciiAlpha(value) || (value >= '0' && value <= '9');
    }

    bool IsValidDnsLabelByte(char value) noexcept
    {
        return IsAsciiAlnum(value) || value == '-';
    }

    char EncodePunycodeDigit(ULONG digit) noexcept
    {
        return static_cast<char>(digit < 26 ? ('a' + digit) : ('0' + (digit - 26)));
    }

    ULONG AdaptPunycodeBias(ULONG delta, ULONG numPoints, bool firstTime) noexcept
    {
        delta = firstTime ? (delta / 700) : (delta / 2);
        delta += delta / numPoints;

        ULONG k = 0;
        while (delta > (((36 - 1) * 26) / 2)) {
            delta /= 36 - 1;
            k += 36;
        }

        return k + (((36 - 1 + 1) * delta) / (delta + 38));
    }

    _Must_inspect_result_
    NTSTATUS AppendOutputChar(
        char value,
        _Out_writes_bytes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset) noexcept
    {
        if (output == nullptr || offset == nullptr || *offset >= capacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        output[*offset] = value;
        ++(*offset);
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS DecodeUtf8CodePoint(
        const char* text,
        SIZE_T length,
        SIZE_T* offset,
        ULONG* codePoint) noexcept
    {
        if (text == nullptr || offset == nullptr || codePoint == nullptr || *offset >= length) {
            return STATUS_INVALID_PARAMETER;
        }

        const unsigned char first = static_cast<unsigned char>(text[*offset]);
        if (first < 0x80) {
            *codePoint = first;
            ++(*offset);
            return STATUS_SUCCESS;
        }

        UCHAR expectedLength = 0;
        ULONG value = 0;
        if ((first & 0xe0) == 0xc0) {
            expectedLength = 2;
            value = first & 0x1f;
        }
        else if ((first & 0xf0) == 0xe0) {
            expectedLength = 3;
            value = first & 0x0f;
        }
        else if ((first & 0xf8) == 0xf0) {
            expectedLength = 4;
            value = first & 0x07;
        }
        else {
            return STATUS_INVALID_PARAMETER;
        }

        if (expectedLength > length - *offset) {
            return STATUS_INVALID_PARAMETER;
        }

        for (UCHAR index = 1; index < expectedLength; ++index) {
            const unsigned char next = static_cast<unsigned char>(text[*offset + index]);
            if ((next & 0xc0) != 0x80) {
                return STATUS_INVALID_PARAMETER;
            }

            value = (value << 6) | (next & 0x3f);
        }

        if ((expectedLength == 2 && value < 0x80) ||
            (expectedLength == 3 && value < 0x800) ||
            (expectedLength == 4 && value < 0x10000) ||
            (value >= 0xd800 && value <= 0xdfff) ||
            value > 0x10ffff) {
            return STATUS_INVALID_PARAMETER;
        }

        *offset += expectedLength;
        *codePoint = value;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS PunycodeEncodeLabel(
        const char* label,
        SIZE_T labelLength,
        char* output,
        SIZE_T outputCapacity,
        SIZE_T* outputLength) noexcept
    {
        if (outputLength != nullptr) {
            *outputLength = 0;
        }
        if (label == nullptr ||
            labelLength == 0 ||
            output == nullptr ||
            outputLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<ULONG> codePoints(labelLength);
        if (!codePoints.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T inputOffset = 0;
        SIZE_T codePointCount = 0;
        bool hasNonAscii = false;
        while (inputOffset < labelLength) {
            ULONG codePoint = 0;
            NTSTATUS status = DecodeUtf8CodePoint(label, labelLength, &inputOffset, &codePoint);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (codePoint == '.') {
                return STATUS_INVALID_PARAMETER;
            }
            if (codePoint < 0x80) {
                const char ascii = static_cast<char>(codePoint);
                if (!IsValidDnsLabelByte(ascii)) {
                    return STATUS_INVALID_PARAMETER;
                }
            }
            else {
                hasNonAscii = true;
            }

            codePoints[codePointCount++] = codePoint;
        }

        SIZE_T out = 0;
        if (!hasNonAscii) {
            for (SIZE_T index = 0; index < codePointCount; ++index) {
                NTSTATUS status = AppendOutputChar(
                    ToLowerAscii(static_cast<char>(codePoints[index])),
                    output,
                    outputCapacity,
                    &out);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            *outputLength = out;
            return out <= 63 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < sizeof(PunycodePrefix) - 1; ++index) {
            NTSTATUS status = AppendOutputChar(PunycodePrefix[index], output, outputCapacity, &out);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        SIZE_T basicCount = 0;
        for (SIZE_T index = 0; index < codePointCount; ++index) {
            if (codePoints[index] < 0x80) {
                NTSTATUS status = AppendOutputChar(
                    ToLowerAscii(static_cast<char>(codePoints[index])),
                    output,
                    outputCapacity,
                    &out);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                ++basicCount;
            }
        }

        SIZE_T handledCount = basicCount;
        if (basicCount != 0) {
            NTSTATUS status = AppendOutputChar('-', output, outputCapacity, &out);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        ULONG n = 128;
        ULONG delta = 0;
        ULONG bias = 72;
        while (handledCount < codePointCount) {
            ULONG m = 0x10ffff;
            for (SIZE_T index = 0; index < codePointCount; ++index) {
                if (codePoints[index] >= n && codePoints[index] < m) {
                    m = codePoints[index];
                }
            }

            if (m == 0x10ffff ||
                m < n ||
                (m - n) > ((0xffffffffUL - delta) / static_cast<ULONG>(handledCount + 1))) {
                return STATUS_INTEGER_OVERFLOW;
            }

            delta += (m - n) * static_cast<ULONG>(handledCount + 1);
            n = m;

            for (SIZE_T index = 0; index < codePointCount; ++index) {
                if (codePoints[index] < n) {
                    if (delta == 0xffffffffUL) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    ++delta;
                }
                else if (codePoints[index] == n) {
                    ULONG q = delta;
                    for (ULONG k = 36;; k += 36) {
                        const ULONG t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias);
                        if (q < t) {
                            break;
                        }

                        const ULONG code = t + ((q - t) % (36 - t));
                        NTSTATUS status = AppendOutputChar(EncodePunycodeDigit(code), output, outputCapacity, &out);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        q = (q - t) / (36 - t);
                    }

                    NTSTATUS status = AppendOutputChar(EncodePunycodeDigit(q), output, outputCapacity, &out);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    bias = AdaptPunycodeBias(delta, static_cast<ULONG>(handledCount + 1), handledCount == basicCount);
                    delta = 0;
                    ++handledCount;
                }
            }

            if (delta == 0xffffffffUL || n == 0x10ffff) {
                return STATUS_INTEGER_OVERFLOW;
            }
            ++delta;
            ++n;
        }

        *outputLength = out;
        return out <= 63 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    }

    _Must_inspect_result_
    NTSTATUS NormalizeDnsHost(
        const char* host,
        SIZE_T hostLength,
        char* output,
        SIZE_T outputCapacity,
        SIZE_T* outputLength) noexcept
    {
        if (outputLength != nullptr) {
            *outputLength = 0;
        }
        if (host == nullptr ||
            hostLength == 0 ||
            output == nullptr ||
            outputLength == nullptr ||
            outputCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T inputOffset = 0;
        SIZE_T out = 0;
        while (inputOffset < hostLength) {
            const SIZE_T labelStart = inputOffset;
            while (inputOffset < hostLength && host[inputOffset] != '.') {
                ++inputOffset;
            }

            const SIZE_T labelLength = inputOffset - labelStart;
            if (labelLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T written = 0;
            NTSTATUS status = PunycodeEncodeLabel(
                host + labelStart,
                labelLength,
                output + out,
                outputCapacity - out,
                &written);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            out += written;
            if (inputOffset < hostLength) {
                status = AppendOutputChar('.', output, outputCapacity, &out);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                ++inputOffset;
            }
        }

        if (out == 0 || out > 255 || out >= outputCapacity) {
            return STATUS_INVALID_PARAMETER;
        }

        output[out] = '\0';
        *outputLength = out;
        return STATUS_SUCCESS;
    }

    bool IsValidRequestTargetByte(char value) noexcept
    {
        const unsigned char ch = static_cast<unsigned char>(value);
        return ch > 0x20 && ch != 0x7f;
    }

    bool IsValidRequestTargetText(const char* text, SIZE_T textLength) noexcept
    {
        if (text == nullptr && textLength != 0) {
            return false;
        }

        for (SIZE_T index = 0; index < textLength; ++index) {
            if (!IsValidRequestTargetByte(text[index])) {
                return false;
            }

            if (text[index] == '%') {
                if (index + 2 >= textLength ||
                    !IsHexDigit(text[index + 1]) ||
                    !IsHexDigit(text[index + 2])) {
                    return false;
                }
                index += 2;
            }
        }

        return true;
    }

    bool IsValidHostText(const char* text, SIZE_T textLength, bool ipv6Literal) noexcept
    {
        if (text == nullptr || textLength == 0) {
            return false;
        }

        for (SIZE_T index = 0; index < textLength; ++index) {
            const unsigned char ch = static_cast<unsigned char>(text[index]);
            if (ch <= 0x20 || ch == 0x7f || text[index] == '%') {
                return false;
            }

            if (ipv6Literal && ch >= 0x80) {
                return false;
            }

            if (!ipv6Literal && (text[index] == '[' || text[index] == ']')) {
                return false;
            }
        }

        return true;
    }

    bool UrlTextContainsChar(const char* text, SIZE_T textLength, char needle) noexcept
    {
        if (text == nullptr) {
            return false;
        }

        for (SIZE_T index = 0; index < textLength; ++index) {
            if (text[index] == needle) {
                return true;
            }
        }

        return false;
    }

    bool AuthorityContainsUserInfo(const char* authority, SIZE_T authorityLength) noexcept
    {
        return UrlTextContainsChar(authority, authorityLength, '@');
    }

    _Must_inspect_result_
    NTSTATUS CopyLowerText(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (source == nullptr ||
            sourceLength == 0 ||
            destination == nullptr ||
            destinationLength == nullptr ||
            sourceLength >= destinationCapacity) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < sourceLength; ++index) {
            destination[index] = ToLowerAscii(source[index]);
        }
        destination[sourceLength] = '\0';
        *destinationLength = sourceLength;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS CopyNormalizedHostText(
        const char* source,
        SIZE_T sourceLength,
        bool ipv6Literal,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (ipv6Literal) {
            return CopyLowerText(source, sourceLength, destination, destinationCapacity, destinationLength);
        }

        return NormalizeDnsHost(source, sourceLength, destination, destinationCapacity, destinationLength);
    }

    _Must_inspect_result_
    NTSTATUS ParsePort(
        const char* text,
        SIZE_T textLength,
        _Out_ USHORT* port) noexcept
    {
        if (port != nullptr) {
            *port = 0;
        }

        if (text == nullptr || textLength == 0 || port == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG value = 0;
        for (SIZE_T index = 0; index < textLength; ++index) {
            if (!IsDigit(text[index])) {
                return STATUS_INVALID_PARAMETER;
            }

            value = (value * 10) + static_cast<ULONG>(text[index] - '0');
            if (value > 0xffff) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        if (value == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        *port = static_cast<USHORT>(value);
        return STATUS_SUCCESS;
    }
}

NTSTATUS ParseUrlIntoRequest(
    Request& request,
    const char* url,
    SIZE_T urlLength) noexcept
{
    WKNET_TRACE(
        ::wknet::ComponentRtl,
        ::wknet::TraceLevel::Verbose,
        "rtl.url.parse_request.start input_bytes=%Iu",
        urlLength);
    if (url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T schemeEnd = 0;
    while (schemeEnd < urlLength && url[schemeEnd] != ':') {
        ++schemeEnd;
    }

    if (schemeEnd == 0 ||
        schemeEnd + 3 > urlLength ||
        url[schemeEnd + 1] != '/' ||
        url[schemeEnd + 2] != '/') {
        return STATUS_INVALID_PARAMETER;
    }

    if (!UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "http") &&
        !UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "https")) {
        return STATUS_NOT_SUPPORTED;
    }

    const SIZE_T authorityStart = schemeEnd + 3;
    SIZE_T authorityEnd = authorityStart;
    while (authorityEnd < urlLength && url[authorityEnd] != '/' && url[authorityEnd] != '?' && url[authorityEnd] != '#') {
        ++authorityEnd;
    }

    if (authorityEnd == authorityStart) {
        return STATUS_INVALID_PARAMETER;
    }

    if (AuthorityContainsUserInfo(url + authorityStart, authorityEnd - authorityStart)) {
        return STATUS_NOT_SUPPORTED;
    }

    SIZE_T hostStart = authorityStart;
    SIZE_T hostLength = authorityEnd - authorityStart;
    SIZE_T portStart = 0;
    SIZE_T portLength = 0;
    bool ipv6Literal = false;

    if (url[authorityStart] == '[') {
        SIZE_T bracketEnd = authorityStart + 1;
        while (bracketEnd < authorityEnd && url[bracketEnd] != ']') {
            ++bracketEnd;
        }

        if (bracketEnd == authorityEnd || bracketEnd == authorityStart + 1) {
            return STATUS_INVALID_PARAMETER;
        }

        hostStart = authorityStart + 1;
        hostLength = bracketEnd - hostStart;
        ipv6Literal = true;
        if (!UrlTextContainsChar(url + hostStart, hostLength, ':')) {
            return STATUS_INVALID_PARAMETER;
        }

        if (bracketEnd + 1 < authorityEnd) {
            if (url[bracketEnd + 1] != ':') {
                return STATUS_INVALID_PARAMETER;
            }

            portStart = bracketEnd + 2;
        }
    }
    else {
        for (SIZE_T index = authorityStart; index < authorityEnd; ++index) {
            if (url[index] == ':') {
                if (portStart != 0) {
                    return STATUS_NOT_SUPPORTED;
                }

                portStart = index + 1;
                hostLength = index - authorityStart;
            }
        }
    }

    if (hostLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!IsValidHostText(url + hostStart, hostLength, ipv6Literal)) {
        return STATUS_INVALID_PARAMETER;
    }

    USHORT port = UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "https") ? 443 : 80;
    if (portStart != 0) {
        portLength = authorityEnd - portStart;
        NTSTATUS status = ParsePort(url + portStart, portLength, &port);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    SIZE_T fragmentStart = authorityEnd;
    while (fragmentStart < urlLength && url[fragmentStart] != '#') {
        ++fragmentStart;
    }

    SIZE_T pathStart = authorityEnd;
    SIZE_T pathLength = fragmentStart - authorityEnd;
    if (pathLength == 0) {
        pathStart = 0;
        pathLength = 1;
    }

    if (pathStart == 0) {
        request.Path[0] = '/';
        request.Path[1] = '\0';
        request.PathLength = 1;
    }
    else {
        const bool queryOnly = url[pathStart] == '?';
        const SIZE_T requestTargetLength = pathLength + (queryOnly ? 1 : 0);
        if (requestTargetLength > MaxPathLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T outputOffset = 0;
        if (queryOnly) {
            request.Path[outputOffset++] = '/';
        }

        if (!IsValidRequestTargetText(url + pathStart, pathLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(request.Path + outputOffset, url + pathStart, pathLength);
        request.Path[requestTargetLength] = '\0';
        request.PathLength = requestTargetLength;
    }

    NTSTATUS status = CopyLowerText(
        url,
        schemeEnd,
        request.Scheme,
        sizeof(request.Scheme),
        &request.SchemeLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = CopyNormalizedHostText(
        url + hostStart,
        hostLength,
        ipv6Literal,
        request.Host,
        sizeof(request.Host),
        &request.HostLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    request.Port = port;
    WKNET_TRACE(
        ::wknet::ComponentRtl,
        ::wknet::TraceLevel::Info,
        "rtl.url.parse_request.complete scheme_bytes=%Iu host_bytes=%Iu path_bytes=%Iu port=%u",
        request.SchemeLength,
        request.HostLength,
        request.PathLength,
        static_cast<ULONG>(request.Port));
    return STATUS_SUCCESS;
}

NTSTATUS ParseUrlParts(
    const char* url,
    SIZE_T urlLength,
    bool websocketUrl,
    char* scheme,
    SIZE_T schemeCapacity,
    SIZE_T* schemeLength,
    char* host,
    SIZE_T hostCapacity,
    SIZE_T* hostLength,
    char* path,
    SIZE_T pathCapacity,
    SIZE_T* pathLength,
    USHORT* port) noexcept
{
    if (schemeLength != nullptr) {
        *schemeLength = 0;
    }
    if (hostLength != nullptr) {
        *hostLength = 0;
    }
    if (pathLength != nullptr) {
        *pathLength = 0;
    }
    if (port != nullptr) {
        *port = 0;
    }

    if (url == nullptr ||
        urlLength == 0 ||
        scheme == nullptr ||
        schemeLength == nullptr ||
        host == nullptr ||
        hostLength == nullptr ||
        path == nullptr ||
        pathLength == nullptr ||
        port == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T schemeEnd = 0;
    while (schemeEnd < urlLength && url[schemeEnd] != ':') {
        ++schemeEnd;
    }

    if (schemeEnd == 0 ||
        schemeEnd + 3 > urlLength ||
        url[schemeEnd + 1] != '/' ||
        url[schemeEnd + 2] != '/') {
        return STATUS_INVALID_PARAMETER;
    }

    const bool supported =
        websocketUrl ?
        (UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "ws") ||
            UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "wss")) :
        (UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "http") ||
            UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "https"));
    if (!supported) {
        return STATUS_NOT_SUPPORTED;
    }

    const SIZE_T authorityStart = schemeEnd + 3;
    SIZE_T authorityEnd = authorityStart;
    while (authorityEnd < urlLength && url[authorityEnd] != '/' && url[authorityEnd] != '?' && url[authorityEnd] != '#') {
        ++authorityEnd;
    }

    if (authorityEnd == authorityStart) {
        return STATUS_INVALID_PARAMETER;
    }

    if (AuthorityContainsUserInfo(url + authorityStart, authorityEnd - authorityStart)) {
        return STATUS_NOT_SUPPORTED;
    }

    SIZE_T parsedHostStart = authorityStart;
    SIZE_T parsedHostLength = authorityEnd - authorityStart;
    SIZE_T portStart = 0;
    bool ipv6Literal = false;

    if (url[authorityStart] == '[') {
        SIZE_T bracketEnd = authorityStart + 1;
        while (bracketEnd < authorityEnd && url[bracketEnd] != ']') {
            ++bracketEnd;
        }

        if (bracketEnd == authorityEnd || bracketEnd == authorityStart + 1) {
            return STATUS_INVALID_PARAMETER;
        }

        parsedHostStart = authorityStart + 1;
        parsedHostLength = bracketEnd - parsedHostStart;
        ipv6Literal = true;
        if (!UrlTextContainsChar(url + parsedHostStart, parsedHostLength, ':')) {
            return STATUS_INVALID_PARAMETER;
        }

        if (bracketEnd + 1 < authorityEnd) {
            if (url[bracketEnd + 1] != ':') {
                return STATUS_INVALID_PARAMETER;
            }

            portStart = bracketEnd + 2;
        }
    }
    else {
        for (SIZE_T index = authorityStart; index < authorityEnd; ++index) {
            if (url[index] == ':') {
                if (portStart != 0) {
                    return STATUS_NOT_SUPPORTED;
                }

                portStart = index + 1;
                parsedHostLength = index - authorityStart;
            }
        }
    }

    if (parsedHostLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!IsValidHostText(url + parsedHostStart, parsedHostLength, ipv6Literal)) {
        return STATUS_INVALID_PARAMETER;
    }

    USHORT parsedPort =
        (UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "https") ||
            UrlTextEqualsLiteralIgnoreCase(url, schemeEnd, "wss")) ? 443 : 80;
    if (portStart != 0) {
        NTSTATUS status = ParsePort(url + portStart, authorityEnd - portStart, &parsedPort);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    SIZE_T fragmentStart = authorityEnd;
    while (fragmentStart < urlLength && url[fragmentStart] != '#') {
        ++fragmentStart;
    }

    SIZE_T targetStart = authorityEnd;
    SIZE_T targetLength = fragmentStart - authorityEnd;
    if (targetLength == 0) {
        if (pathCapacity < 2) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        path[0] = '/';
        path[1] = '\0';
        *pathLength = 1;
    }
    else {
        const bool queryOnly = url[targetStart] == '?';
        const SIZE_T requestTargetLength = targetLength + (queryOnly ? 1 : 0);
        if (requestTargetLength >= pathCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T outputOffset = 0;
        if (queryOnly) {
            path[outputOffset++] = '/';
        }

        if (!IsValidRequestTargetText(url + targetStart, targetLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(path + outputOffset, url + targetStart, targetLength);
        path[requestTargetLength] = '\0';
        *pathLength = requestTargetLength;
    }

    NTSTATUS status = CopyLowerText(url, schemeEnd, scheme, schemeCapacity, schemeLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = CopyNormalizedHostText(
        url + parsedHostStart,
        parsedHostLength,
        ipv6Literal,
        host,
        hostCapacity,
        hostLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *port = parsedPort;
    return STATUS_SUCCESS;
}
}
}
