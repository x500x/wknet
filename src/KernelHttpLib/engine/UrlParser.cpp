#include <KernelHttp/engine/UrlParser.h>
#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace engine
{
namespace
{
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
        return UrlTextEqualsIgnoreCase(left, leftLength, right, http::MakeText(right).Length);
    }

    bool IsDigit(char value) noexcept
    {
        return value >= '0' && value <= '9';
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
    KhRequest& request,
    const char* url,
    SIZE_T urlLength) noexcept
{
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

    SIZE_T hostStart = authorityStart;
    SIZE_T hostLength = authorityEnd - authorityStart;
    SIZE_T portStart = 0;
    SIZE_T portLength = 0;

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
        if (requestTargetLength > KhMaxPathLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T outputOffset = 0;
        if (queryOnly) {
            request.Path[outputOffset++] = '/';
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

    status = CopyLowerText(
        url + hostStart,
        hostLength,
        request.Host,
        sizeof(request.Host),
        &request.HostLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    request.Port = port;
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

    SIZE_T parsedHostStart = authorityStart;
    SIZE_T parsedHostLength = authorityEnd - authorityStart;
    SIZE_T portStart = 0;

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

        RtlCopyMemory(path + outputOffset, url + targetStart, targetLength);
        path[requestTargetLength] = '\0';
        *pathLength = requestTargetLength;
    }

    NTSTATUS status = CopyLowerText(url, schemeEnd, scheme, schemeCapacity, schemeLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = CopyLowerText(
        url + parsedHostStart,
        parsedHostLength,
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
