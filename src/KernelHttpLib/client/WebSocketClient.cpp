#include <KernelHttp/client/WebSocketClient.h>
#include <KernelHttp/core/Irql.h>
#include <KernelHttp/core/TlsTransport.h>
#include <KernelHttp/core/WorkspaceScratchAllocator.h>
#include <KernelHttp/core/WskTransport.h>
#include <KernelHttp/http/HttpTypes.h>
#include <KernelHttp/http/HttpRequest.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <time.h>
#endif

namespace KernelHttp
{
namespace client
{
    namespace
    {
        _Must_inspect_result_
        bool IsValidText(_In_reads_bytes_opt_(length) const char* text, SIZE_T length) noexcept
        {
            return text != nullptr && length > 0;
        }

        _Must_inspect_result_
        bool IsOptionalTextValid(_In_reads_bytes_opt_(length) const char* text, SIZE_T length) noexcept
        {
            return (text == nullptr && length == 0) || (text != nullptr && length != 0);
        }

        _Must_inspect_result_
        bool IsSubprotocolSeparator(char value) noexcept
        {
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
                return true;
            default:
                return false;
            }
        }

        _Must_inspect_result_
        bool IsValidSubprotocolToken(
            _In_reads_bytes_opt_(length) const char* token,
            SIZE_T length) noexcept
        {
            if (token == nullptr || length == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < length; ++index) {
                const unsigned char value = static_cast<unsigned char>(token[index]);
                if (value <= 0x20 || value >= 0x7f || IsSubprotocolSeparator(token[index])) {
                    return false;
                }
            }
            return true;
        }

        _Must_inspect_result_
        bool IsValidSubprotocolList(
            _In_reads_bytes_opt_(length) const char* value,
            SIZE_T length) noexcept
        {
            if (value == nullptr && length == 0) {
                return true;
            }
            if (value == nullptr || length == 0) {
                return false;
            }

            SIZE_T index = 0;
            for (;;) {
                while (index < length && (value[index] == ' ' || value[index] == '\t')) {
                    ++index;
                }
                const SIZE_T tokenStart = index;
                while (index < length && value[index] != ',') {
                    ++index;
                }
                SIZE_T tokenEnd = index;
                while (tokenEnd > tokenStart &&
                    (value[tokenEnd - 1] == ' ' || value[tokenEnd - 1] == '\t')) {
                    --tokenEnd;
                }
                if (!IsValidSubprotocolToken(value + tokenStart, tokenEnd - tokenStart)) {
                    return false;
                }
                if (index == length) {
                    break;
                }
                ++index;
                if (index == length) {
                    return false;
                }
            }
            return true;
        }

        _Must_inspect_result_
        bool TextEqualsLiteral(
            _In_reads_bytes_opt_(leftLength) const char* left,
            SIZE_T leftLength,
            _In_z_ const char* right) noexcept
        {
            const http::HttpText rightText = http::MakeText(right);
            if (leftLength != rightText.Length) {
                return false;
            }
            if (leftLength == 0) {
                return true;
            }
            if (left == nullptr || rightText.Data == nullptr) {
                return false;
            }

            return RtlCompareMemory(left, rightText.Data, leftLength) == leftLength;
        }

        constexpr const char WebSocketHttp11Alpn[] = "http/1.1";
        constexpr SIZE_T WebSocketHttp11AlpnLength = sizeof(WebSocketHttp11Alpn) - 1;
        constexpr const char WebSocketHttp2Alpn[] = "h2";
        constexpr SIZE_T WebSocketHttp2AlpnLength = sizeof(WebSocketHttp2Alpn) - 1;
        constexpr SIZE_T WebSocketHttp2BaseHeaderCount = 6;
        constexpr ULONG WebSocketDefaultHandshakeRetries = 3;
        constexpr ULONG WebSocketMaxHandshakeRetries = 10;
        constexpr SIZE_T WebSocketMaxChallengeHeaders = 8;
        constexpr USHORT WebSocketCloseProtocolError = 1002;
        constexpr USHORT WebSocketClosePolicyViolation = 1008;
        constexpr USHORT WebSocketCloseMessageTooBig = 1009;
        constexpr USHORT WebSocketCloseInvalidPayload = 1007;

        _Must_inspect_result_
        bool IsTlsProtocolAllowed(
            tls::TlsProtocol minimum,
            tls::TlsProtocol maximum,
            tls::TlsProtocol protocol) noexcept
        {
            return static_cast<UCHAR>(minimum) <= static_cast<UCHAR>(protocol) &&
                static_cast<UCHAR>(protocol) <= static_cast<UCHAR>(maximum);
        }

        _Must_inspect_result_
        bool IsTls12ConfirmationCandidate(
            const WebSocketConnectOptions& options,
            const tls::TlsHandshakeFailure& failure) noexcept
        {
            const bool failureCanConfirmTls12 =
                failure.Category == tls::TlsHandshakeFailureCategory::VersionNegotiation ||
                (failure.Category == tls::TlsHandshakeFailureCategory::NetworkIo &&
                    failure.BeforeTls13FirstServerHello &&
                    failure.Status != STATUS_IO_TIMEOUT);
            return options.UseTls &&
                IsTlsProtocolAllowed(options.MinimumTlsProtocol, options.MaximumTlsProtocol, tls::TlsProtocol::Tls12) &&
                IsTlsProtocolAllowed(options.MinimumTlsProtocol, options.MaximumTlsProtocol, tls::TlsProtocol::Tls13) &&
                failureCanConfirmTls12;
        }

        _Must_inspect_result_
        bool IsValidWebSocketTransportMode(WebSocketTransportMode mode) noexcept
        {
            return mode == WebSocketTransportMode::LegacyBoolean ||
                mode == WebSocketTransportMode::Http11Only ||
                mode == WebSocketTransportMode::Auto ||
                mode == WebSocketTransportMode::Http2Required;
        }

        _Must_inspect_result_
        bool IsValidWebSocketConnectOptions(const WebSocketConnectOptions& options) noexcept
        {
            return IsValidWebSocketTransportMode(options.TransportMode) &&
                websocket::IsValidPerMessageDeflateOptions(options.PerMessageDeflate);
        }

        _Must_inspect_result_
        bool WebSocketModeAllowsHttp2(const WebSocketConnectOptions& options) noexcept
        {
            switch (options.TransportMode) {
            case WebSocketTransportMode::Http11Only:
                return false;
            case WebSocketTransportMode::Auto:
            case WebSocketTransportMode::Http2Required:
                return true;
            case WebSocketTransportMode::LegacyBoolean:
            default:
                return options.AllowWebSocketOverHttp2;
            }
        }

        _Must_inspect_result_
        bool WebSocketModeRequiresHttp2(const WebSocketConnectOptions& options) noexcept
        {
            return options.TransportMode == WebSocketTransportMode::Http2Required;
        }

        _Must_inspect_result_
        bool WebSocketModeCanRetryHttp11(const WebSocketConnectOptions& options, NTSTATUS status) noexcept
        {
            return options.TransportMode == WebSocketTransportMode::Auto &&
                options.UseTls &&
                status == STATUS_NOT_SUPPORTED;
        }

        _Must_inspect_result_
        bool IsWebSocketHandshakeChallengeStatus(USHORT statusCode) noexcept
        {
            return (statusCode >= 300 && statusCode <= 399) ||
                statusCode == 401 ||
                statusCode == 407;
        }

        _Must_inspect_result_
        bool TextContainsChar(
            _In_reads_bytes_opt_(length) const char* text,
            SIZE_T length,
            char needle) noexcept
        {
            if (text == nullptr) {
                return false;
            }

            for (SIZE_T index = 0; index < length; ++index) {
                if (text[index] == needle) {
                    return true;
                }
            }

            return false;
        }

        _Must_inspect_result_
        NTSTATUS AppendLiteral(
            _In_z_ const char* literal,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Inout_ SIZE_T* length) noexcept
        {
            if (literal == nullptr || destination == nullptr || length == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            const http::HttpText text = http::MakeText(literal);
            if (text.Length > destinationCapacity - *length) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            RtlCopyMemory(destination + *length, text.Data, text.Length);
            *length += text.Length;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AppendWindowBits(
            UCHAR value,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Inout_ SIZE_T* length) noexcept
        {
            if (value < websocket::WebSocketDeflateMinWindowBits ||
                value > websocket::WebSocketDeflateMaxWindowBits ||
                destination == nullptr ||
                length == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (destinationCapacity - *length < 2) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (value >= 10) {
                destination[(*length)++] = static_cast<char>('0' + (value / 10));
            }
            destination[(*length)++] = static_cast<char>('0' + (value % 10));
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS BuildPerMessageDeflateOffer(
            const websocket::PerMessageDeflateOptions& options,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* length) noexcept
        {
            if (length != nullptr) {
                *length = 0;
            }
            if (destination == nullptr || length == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (!websocket::IsValidPerMessageDeflateOptions(options) || !options.Enable) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = AppendLiteral("permessage-deflate; client_max_window_bits=", destination, destinationCapacity, length);
            if (NT_SUCCESS(status)) {
                status = AppendWindowBits(options.ClientMaxWindowBits, destination, destinationCapacity, length);
            }
            if (NT_SUCCESS(status)) {
                status = AppendLiteral("; server_max_window_bits=", destination, destinationCapacity, length);
            }
            if (NT_SUCCESS(status)) {
                status = AppendWindowBits(options.ServerMaxWindowBits, destination, destinationCapacity, length);
            }
            if (NT_SUCCESS(status) && options.ClientNoContextTakeover) {
                status = AppendLiteral("; client_no_context_takeover", destination, destinationCapacity, length);
            }
            if (NT_SUCCESS(status) && options.ServerNoContextTakeover) {
                status = AppendLiteral("; server_no_context_takeover", destination, destinationCapacity, length);
            }
            return status;
        }

        _Must_inspect_result_
        bool IsDefaultWebSocketPort(bool useTls, USHORT port) noexcept
        {
            return (!useTls && port == 80) || (useTls && port == 443);
        }

        _Must_inspect_result_
        char ToLowerAscii(char value) noexcept
        {
            return (value >= 'A' && value <= 'Z') ?
                static_cast<char>(value - 'A' + 'a') :
                value;
        }

        _Must_inspect_result_
        bool IsForbiddenHttp2OpeningHeader(http::HttpText name) noexcept
        {
            return http::TextEqualsIgnoreCase(name, http::MakeText("connection")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("host")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("upgrade")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("content-length")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("transfer-encoding")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("sec-websocket-key")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("sec-websocket-version")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("sec-websocket-protocol")) ||
                http::TextEqualsIgnoreCase(name, http::MakeText("sec-websocket-extensions"));
        }

        _Must_inspect_result_
        NTSTATUS AppendDecimalPort(
            USHORT port,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Inout_ SIZE_T* length) noexcept
        {
            if (destination == nullptr || length == nullptr || *length >= destinationCapacity) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T divisor = 1;
            while ((port / divisor) >= 10) {
                divisor *= 10;
            }

            SIZE_T digitCount = 0;
            for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
                ++digitCount;
            }

            if (*length + 1 + digitCount >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[(*length)++] = ':';
            for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
                destination[(*length)++] = static_cast<char>('0' + ((port / currentDivisor) % 10));
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS BuildWebSocketHostHeader(
            _In_ const WebSocketConnectOptions& options,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* destinationLength) noexcept
        {
            if (destinationLength != nullptr) {
                *destinationLength = 0;
            }

            if (!IsValidText(options.Host, options.HostLength) ||
                destination == nullptr ||
                destinationCapacity == 0 ||
                destinationLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            const bool ipv6Literal = TextContainsChar(options.Host, options.HostLength, ':');
            const SIZE_T bracketBytes = ipv6Literal ? 2 : 0;
            if (options.HostLength + bracketBytes >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T length = 0;
            if (ipv6Literal) {
                destination[length++] = '[';
            }
            RtlCopyMemory(destination + length, options.Host, options.HostLength);
            length += options.HostLength;
            if (ipv6Literal) {
                destination[length++] = ']';
            }

            const USHORT effectivePort = options.Port != 0 ?
                options.Port :
                static_cast<USHORT>(options.UseTls ? 443 : 80);
            if (!IsDefaultWebSocketPort(options.UseTls, effectivePort)) {
                NTSTATUS status = AppendDecimalPort(effectivePort, destination, destinationCapacity, &length);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            destination[length] = '\0';
            *destinationLength = length;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsValidUtf8(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            if (data == nullptr && length != 0) {
                return false;
            }

            SIZE_T index = 0;
            while (index < length) {
                const UCHAR first = data[index++];
                if (first <= 0x7f) {
                    continue;
                }

                ULONG codePoint = 0;
                SIZE_T continuation = 0;
                if (first >= 0xc2 && first <= 0xdf) {
                    codePoint = first & 0x1f;
                    continuation = 1;
                }
                else if (first >= 0xe0 && first <= 0xef) {
                    codePoint = first & 0x0f;
                    continuation = 2;
                }
                else if (first >= 0xf0 && first <= 0xf4) {
                    codePoint = first & 0x07;
                    continuation = 3;
                }
                else {
                    return false;
                }

                if (continuation > length - index) {
                    return false;
                }

                for (SIZE_T next = 0; next < continuation; ++next) {
                    const UCHAR ch = data[index++];
                    if ((ch & 0xc0) != 0x80) {
                        return false;
                    }
                    codePoint = (codePoint << 6) | (ch & 0x3f);
                }

                if ((continuation == 2 && codePoint < 0x800) ||
                    (continuation == 3 && codePoint < 0x10000) ||
                    codePoint > 0x10ffff ||
                    (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool FinishUtf8CodePoint(ULONG codePoint, UCHAR expected) noexcept
        {
            return !((expected == 2 && codePoint < 0x800) ||
                (expected == 3 && codePoint < 0x10000) ||
                codePoint > 0x10ffff ||
                (codePoint >= 0xd800 && codePoint <= 0xdfff));
        }

        _Must_inspect_result_
        NTSTATUS AdvanceUtf8State(
            _In_reads_bytes_opt_(length) const UCHAR* data,
            SIZE_T length,
            bool finalFragment,
            _Inout_ ULONG* codePoint,
            _Inout_ UCHAR* remaining,
            _Inout_ UCHAR* expected) noexcept
        {
            if ((data == nullptr && length != 0) ||
                codePoint == nullptr ||
                remaining == nullptr ||
                expected == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < length; ++index) {
                const UCHAR ch = data[index];
                if (*remaining != 0) {
                    if ((ch & 0xc0) != 0x80) {
                        return STATUS_INVALID_PARAMETER;
                    }
                    *codePoint = (*codePoint << 6) | (ch & 0x3f);
                    --(*remaining);
                    if (*remaining == 0) {
                        if (!FinishUtf8CodePoint(*codePoint, *expected)) {
                            return STATUS_INVALID_PARAMETER;
                        }
                        *codePoint = 0;
                        *expected = 0;
                    }
                    continue;
                }

                if (ch <= 0x7f) {
                    continue;
                }

                if (ch >= 0xc2 && ch <= 0xdf) {
                    *codePoint = ch & 0x1f;
                    *remaining = 1;
                    *expected = 1;
                }
                else if (ch >= 0xe0 && ch <= 0xef) {
                    *codePoint = ch & 0x0f;
                    *remaining = 2;
                    *expected = 2;
                }
                else if (ch >= 0xf0 && ch <= 0xf4) {
                    *codePoint = ch & 0x07;
                    *remaining = 3;
                    *expected = 3;
                }
                else {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            if (finalFragment && *remaining != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsValidCloseStatus(USHORT statusCode) noexcept
        {
            if (statusCode >= 3000 && statusCode <= 4999) {
                return true;
            }

            if (statusCode < 1000 || statusCode > 1014) {
                return false;
            }

            return statusCode != 1004 &&
                statusCode != 1005 &&
                statusCode != 1006;
        }

        _Must_inspect_result_
        NTSTATUS BuildHandshakeRequest(
            _In_ const WebSocketConnectOptions& options,
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept
        {
            if (!IsValidText(options.Host, options.HostLength) ||
                !IsValidText(options.Path, options.PathLength) ||
                !IsValidText(clientKey, clientKeyLength) ||
                !IsOptionalTextValid(options.Subprotocol, options.SubprotocolLength) ||
                !IsValidSubprotocolList(options.Subprotocol, options.SubprotocolLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<char> hostHeader(options.HostLength + 9);
            if (!hostHeader.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T hostHeaderLength = 0;
            NTSTATUS status = BuildWebSocketHostHeader(
                options,
                hostHeader.Get(),
                hostHeader.Count(),
                &hostHeaderLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const SIZE_T extensionHeaderCount = options.PerMessageDeflate.Enable ? 1 : 0;
            HeapArray<char> extensionOffer;
            SIZE_T extensionOfferLength = 0;
            if (options.PerMessageDeflate.Enable) {
                status = extensionOffer.Allocate(160);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = BuildPerMessageDeflateOffer(
                    options.PerMessageDeflate,
                    extensionOffer.Get(),
                    extensionOffer.Count(),
                    &extensionOfferLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            const SIZE_T baseHeaderCount =
                (options.Subprotocol != nullptr && options.SubprotocolLength != 0 ? 4 : 3) +
                extensionHeaderCount;
            const SIZE_T headerCount = baseHeaderCount + options.ExtraHeaderCount;
            HeapArray<http::HttpHeader> headers(headerCount);
            if (!headers.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T nextHeader = 0;
            headers[nextHeader++] = { http::MakeText("Upgrade"), http::MakeText("websocket") };
            headers[nextHeader++] = { http::MakeText("Sec-WebSocket-Key"), { clientKey, clientKeyLength } };
            headers[nextHeader++] = { http::MakeText("Sec-WebSocket-Version"), http::MakeText("13") };
            if (options.Subprotocol != nullptr && options.SubprotocolLength != 0) {
                headers[nextHeader++] = {
                    http::MakeText("Sec-WebSocket-Protocol"),
                    { options.Subprotocol, options.SubprotocolLength }
                };
            }
            if (options.PerMessageDeflate.Enable) {
                headers[nextHeader++] = {
                    http::MakeText("Sec-WebSocket-Extensions"),
                    { extensionOffer.Get(), extensionOfferLength }
                };
            }

            for (SIZE_T index = 0; index < options.ExtraHeaderCount; ++index) {
                headers[nextHeader++] = options.ExtraHeaders[index];
            }

            http::HttpRequestBuildOptions request = {};
            request.Method = http::HttpMethod::Get;
            request.Path = { options.Path, options.PathLength };
            request.Host = { hostHeader.Get(), hostHeaderLength };
            request.UserAgent = http::MakeText("KernelHttp/0.1");
            request.Connection = http::HttpConnectionDirective::Upgrade;
            request.ExtraHeaders = headers.Get();
            request.ExtraHeaderCount = headerCount;

            return http::HttpRequestBuilder::Build(
                request,
                destination,
                destinationCapacity,
                bytesWritten);
        }

        _Must_inspect_result_
        NTSTATUS BuildHttp2WebSocketHeaders(
            _In_ const WebSocketConnectOptions& options,
            _In_reads_bytes_opt_(extensionOfferLength) const char* extensionOffer,
            SIZE_T extensionOfferLength,
            _Out_writes_(headerCapacity) http::HttpHeader* headers,
            SIZE_T headerCapacity,
            _Out_writes_bytes_(authorityCapacity) char* authority,
            SIZE_T authorityCapacity,
            _Out_writes_bytes_(lowerHeaderNameCapacity) char* lowerHeaderNames,
            SIZE_T lowerHeaderNameCapacity,
            _Out_ SIZE_T* headerCount) noexcept
        {
            if (headerCount != nullptr) {
                *headerCount = 0;
            }

            if (!IsValidText(options.Host, options.HostLength) ||
                !IsValidText(options.Path, options.PathLength) ||
                !IsOptionalTextValid(options.Subprotocol, options.SubprotocolLength) ||
                !IsValidSubprotocolList(options.Subprotocol, options.SubprotocolLength) ||
                headers == nullptr ||
                authority == nullptr ||
                authorityCapacity == 0 ||
                headerCount == nullptr ||
                (lowerHeaderNames == nullptr && options.ExtraHeaderCount != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T authorityLength = 0;
            NTSTATUS status = BuildWebSocketHostHeader(
                options,
                authority,
                authorityCapacity,
                &authorityLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const SIZE_T subprotocolHeaderCount =
                options.Subprotocol != nullptr && options.SubprotocolLength != 0 ? 1 : 0;
            const SIZE_T extensionHeaderCount = options.PerMessageDeflate.Enable ? 1 : 0;
            if (options.PerMessageDeflate.Enable &&
                (extensionOffer == nullptr || extensionOfferLength == 0)) {
                return STATUS_INVALID_PARAMETER;
            }
            const SIZE_T requiredHeaders =
                WebSocketHttp2BaseHeaderCount +
                subprotocolHeaderCount +
                extensionHeaderCount +
                options.ExtraHeaderCount;
            if (headerCapacity < requiredHeaders) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T lowerHeaderOffset = 0;
            SIZE_T nextHeader = 0;
            headers[nextHeader++] = { http::MakeText(":method"), http::MakeText("CONNECT") };
            headers[nextHeader++] = { http::MakeText(":scheme"), http::MakeText("https") };
            headers[nextHeader++] = { http::MakeText(":path"), { options.Path, options.PathLength } };
            headers[nextHeader++] = { http::MakeText(":authority"), { authority, authorityLength } };
            headers[nextHeader++] = { http::MakeText(":protocol"), http::MakeText("websocket") };
            headers[nextHeader++] = { http::MakeText("user-agent"), http::MakeText("KernelHttp/0.1") };
            if (options.Subprotocol != nullptr && options.SubprotocolLength != 0) {
                headers[nextHeader++] = {
                    http::MakeText("sec-websocket-protocol"),
                    { options.Subprotocol, options.SubprotocolLength }
                };
            }
            if (options.PerMessageDeflate.Enable) {
                headers[nextHeader++] = {
                    http::MakeText("sec-websocket-extensions"),
                    { extensionOffer, extensionOfferLength }
                };
            }

            for (SIZE_T index = 0; index < options.ExtraHeaderCount; ++index) {
                const http::HttpHeader& source = options.ExtraHeaders[index];
                if (source.Name.Data == nullptr ||
                    source.Name.Length == 0 ||
                    IsForbiddenHttp2OpeningHeader(source.Name)) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (source.Value.Data == nullptr && source.Value.Length != 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (source.Name.Length > lowerHeaderNameCapacity - lowerHeaderOffset) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                char* name = lowerHeaderNames + lowerHeaderOffset;
                for (SIZE_T nameIndex = 0; nameIndex < source.Name.Length; ++nameIndex) {
                    const char ch = source.Name.Data[nameIndex];
                    if (ch == ':' || ch == '\r' || ch == '\n') {
                        return STATUS_INVALID_PARAMETER;
                    }
                    name[nameIndex] = ToLowerAscii(ch);
                }
                lowerHeaderOffset += source.Name.Length;
                headers[nextHeader++] = {
                    { name, source.Name.Length },
                    source.Value
                };
            }

            *headerCount = nextHeader;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS IgnoreHttp2WebSocketResponseBody(
            _Inout_opt_ void* context,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength) noexcept
        {
            UNREFERENCED_PARAMETER(context);
            return (data == nullptr && dataLength != 0) ?
                STATUS_INVALID_PARAMETER :
                STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateHttp2WebSocketResponse(
            USHORT statusCode,
            _In_reads_(headerCount) const http::HttpHeader* headers,
            SIZE_T headerCount,
            _In_reads_bytes_opt_(requestedSubprotocolLength) const char* requestedSubprotocol,
            SIZE_T requestedSubprotocolLength,
            _Out_ http::HttpText* selectedSubprotocol,
            _In_opt_ const websocket::PerMessageDeflateOptions* perMessageDeflate,
            _Out_opt_ websocket::PerMessageDeflateNegotiation* negotiatedDeflate) noexcept
        {
            if (selectedSubprotocol != nullptr) {
                *selectedSubprotocol = {};
            }
            if (negotiatedDeflate != nullptr) {
                *negotiatedDeflate = {};
            }
            if (statusCode != 200 ||
                selectedSubprotocol == nullptr ||
                (headers == nullptr && headerCount != 0)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            NTSTATUS status = websocket::WebSocketCodec::ValidatePerMessageDeflateExtensions(
                headers,
                headerCount,
                http::MakeText("sec-websocket-extensions"),
                perMessageDeflate,
                negotiatedDeflate);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            bool selectedPresent = false;
            for (SIZE_T index = 0; index < headerCount; ++index) {
                if (!http::TextEqualsIgnoreCase(
                    headers[index].Name,
                    http::MakeText("sec-websocket-protocol"))) {
                    continue;
                }
                if (selectedPresent) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                selectedPresent = true;
                *selectedSubprotocol = headers[index].Value;
            }

            if (!selectedPresent) {
                return STATUS_SUCCESS;
            }
            if (requestedSubprotocol == nullptr || requestedSubprotocolLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (!IsValidSubprotocolToken(selectedSubprotocol->Data, selectedSubprotocol->Length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T index = 0;
            while (index < requestedSubprotocolLength) {
                while (index < requestedSubprotocolLength &&
                    (requestedSubprotocol[index] == ' ' || requestedSubprotocol[index] == '\t')) {
                    ++index;
                }
                const SIZE_T tokenStart = index;
                while (index < requestedSubprotocolLength && requestedSubprotocol[index] != ',') {
                    ++index;
                }
                SIZE_T tokenEnd = index;
                while (tokenEnd > tokenStart &&
                    (requestedSubprotocol[tokenEnd - 1] == ' ' || requestedSubprotocol[tokenEnd - 1] == '\t')) {
                    --tokenEnd;
                }
                const SIZE_T tokenLength = tokenEnd - tokenStart;
                if (tokenLength == selectedSubprotocol->Length &&
                    RtlCompareMemory(
                        requestedSubprotocol + tokenStart,
                        selectedSubprotocol->Data,
                        tokenLength) == tokenLength) {
                    return STATUS_SUCCESS;
                }
                if (index == requestedSubprotocolLength) {
                    break;
                }
                ++index;
            }

            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        NTSTATUS TryDecodeCompleteFrame(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_ websocket::WebSocketFrameHeader* header,
            _Out_ bool* headerDecoded,
            _Out_ bool* complete) noexcept
        {
            if (headerDecoded != nullptr) {
                *headerDecoded = false;
            }
            if (complete != nullptr) {
                *complete = false;
            }

            if (header == nullptr || headerDecoded == nullptr || complete == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = websocket::WebSocketCodec::DecodeFrameHeader(data, dataLength, header);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                return STATUS_SUCCESS;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (header->PayloadLength > static_cast<ULONGLONG>(static_cast<SIZE_T>(-1)) ||
                header->HeaderLength > dataLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *headerDecoded = true;
            const SIZE_T payloadLength = static_cast<SIZE_T>(header->PayloadLength);
            *complete = payloadLength <= (dataLength - header->HeaderLength);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool PayloadEquals(
            _In_reads_bytes_opt_(expectedLength) const char* expected,
            SIZE_T expectedLength,
            _In_reads_bytes_opt_(actualLength) const UCHAR* actual,
            SIZE_T actualLength) noexcept
        {
            if (expectedLength != actualLength) {
                return false;
            }
            if (expectedLength == 0) {
                return true;
            }
            if (expected == nullptr || actual == nullptr) {
                return false;
            }

            return RtlCompareMemory(actual, expected, expectedLength) == expectedLength;
        }

        _Must_inspect_result_
        bool IsConnectionTerminalStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_CONNECTION_DISCONNECTED ||
                status == STATUS_CONNECTION_RESET ||
                status == STATUS_CONNECTION_ABORTED ||
                status == STATUS_DEVICE_NOT_CONNECTED ||
                status == STATUS_IO_TIMEOUT ||
                status == STATUS_CANCELLED ||
                status == STATUS_TIMEOUT;
        }

        SIZE_T MaxPayloadForFrameBuffer(SIZE_T frameBufferLength) noexcept
        {
            return frameBufferLength > websocket::WebSocketFrameHeaderMaxLength ?
                frameBufferLength - websocket::WebSocketFrameHeaderMaxLength :
                0;
        }

        _Must_inspect_result_
        ULONGLONG CurrentMilliseconds() noexcept
        {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            return static_cast<ULONGLONG>(time(nullptr)) * 1000ULL;
#else
            LARGE_INTEGER now = {};
            KeQuerySystemTimePrecise(&now);
            return static_cast<ULONGLONG>(now.QuadPart / 10000LL);
#endif
        }

        _Must_inspect_result_
        bool AddMilliseconds(ULONGLONG value, ULONG delta, _Out_ ULONGLONG* result) noexcept
        {
            if (result == nullptr) {
                return false;
            }

            const ULONGLONG addend = static_cast<ULONGLONG>(delta);
            if (value > (~0ULL - addend)) {
                return false;
            }

            *result = value + addend;
            return true;
        }

        _Must_inspect_result_
        NTSTATUS RemainingTimeoutMilliseconds(
            ULONGLONG deadlineMilliseconds,
            _Out_ ULONG* timeoutMilliseconds) noexcept
        {
            if (timeoutMilliseconds == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            const ULONGLONG now = CurrentMilliseconds();
            if (now >= deadlineMilliseconds) {
                *timeoutMilliseconds = 0;
                return STATUS_IO_TIMEOUT;
            }

            ULONGLONG remaining = deadlineMilliseconds - now;
            if (remaining == 0) {
                *timeoutMilliseconds = 0;
                return STATUS_IO_TIMEOUT;
            }
            if (remaining > WskCloseTimeoutMilliseconds) {
                remaining = WskCloseTimeoutMilliseconds;
            }
            if (remaining > static_cast<ULONGLONG>(0xffffffffUL)) {
                remaining = 0xffffffffUL;
            }

            *timeoutMilliseconds = static_cast<ULONG>(remaining);
            if (*timeoutMilliseconds == 0) {
                *timeoutMilliseconds = 1;
            }
            return STATUS_SUCCESS;
        }
    }

    WebSocketClient::~WebSocketClient() noexcept
    {
        WebSocketIoBuffers empty = {};
        const NTSTATUS status = Close(empty);
        UNREFERENCED_PARAMETER(status);
        if (bufferedFrame_ != nullptr && bufferedFrameCapacity_ != 0) {
            RtlSecureZeroMemory(bufferedFrame_, bufferedFrameCapacity_);
        }
        FreeNonPagedArray(bufferedFrame_);
        bufferedFrame_ = nullptr;
        bufferedFrameCapacity_ = 0;
        bufferedFrameLength_ = 0;
    }

    NTSTATUS WebSocketClient::Connect(
        net::WskClient& wskClient,
        const WebSocketConnectOptions& options,
        const WebSocketIoBuffers& buffers,
        USHORT* statusCode) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            if (statusCode != nullptr) {
                *statusCode = 0;
            }
            return status;
        }

        if (statusCode != nullptr) {
            *statusCode = 0;
        }
        selectedSubprotocol_.Reset();
        selectedSubprotocolLength_ = 0;
        perMessageDeflate_ = {};
        receiveDeflate_.Release();
        sendCompressedMessage_ = false;
        receiveCompressedMessage_ = false;

        if (connected_) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (options.ServerName == nullptr ||
            options.ServerName[0] == L'\0' ||
            options.ServiceName == nullptr ||
            options.ServiceName[0] == L'\0' ||
            !IsValidText(options.Host, options.HostLength) ||
            !IsValidText(options.Path, options.PathLength) ||
            !IsOptionalTextValid(options.Subprotocol, options.SubprotocolLength) ||
            buffers.RequestBuffer == nullptr ||
            buffers.RequestBufferLength == 0 ||
            buffers.ResponseBuffer == nullptr ||
            buffers.ResponseBufferLength == 0 ||
            buffers.Headers == nullptr ||
            buffers.HeaderCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!IsValidWebSocketConnectOptions(options) ||
            (WebSocketModeRequiresHttp2(options) && !options.UseTls) ||
            (options.ChallengeCallback == nullptr && options.ChallengeContext != nullptr) ||
            options.MaxHandshakeRetries > WebSocketMaxHandshakeRetries) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options.UseTls &&
            (options.TlsServerName == nullptr ||
                options.TlsServerNameLength == 0 ||
                options.HandshakeReceiveTimeoutMilliseconds == 0 ||
                options.MaxTls12Renegotiations > tls::Tls12HardMaxRenegotiations ||
                (options.VerifyCertificate && options.CertificateStore == nullptr) ||
                !NT_SUCCESS(tls::TlsValidatePolicy(options.Policy)) ||
                static_cast<UCHAR>(options.MinimumTlsProtocol) > static_cast<UCHAR>(options.MaximumTlsProtocol))) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> clientKey(websocket::WebSocketClientKeyBase64Length);
        if (!clientKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T clientKeyLength = 0;
        status = websocket::WebSocketCodec::GenerateClientKey(
            clientKey.Get(),
            clientKey.Count(),
            &clientKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T requestLength = 0;
        status = BuildHandshakeRequest(
            options,
            clientKey.Get(),
            clientKeyLength,
            buffers.RequestBuffer,
            buffers.RequestBufferLength,
            &requestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<SOCKADDR_STORAGE> remoteAddresses(net::WskMaxResolvedAddresses);
        if (!remoteAddresses.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T remoteAddressCount = 0;
        status = wskClient.ResolveAll(
            options.ServerName,
            options.ServiceName,
            remoteAddresses.Get(),
            net::WskMaxResolvedAddresses,
            &remoteAddressCount,
            options.AddressFamily);
        if (!NT_SUCCESS(status)) {
            kprintf("WebSocketClient resolve failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        NTSTATUS lastStatus = STATUS_NOT_FOUND;
        for (SIZE_T addressIndex = 0; addressIndex < remoteAddressCount; ++addressIndex) {
            bool tls12ConfirmationCandidate = false;
            status = ConnectAddress(
                wskClient,
                reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]),
                options,
                buffers,
                clientKey.Get(),
                clientKeyLength,
                requestLength,
                statusCode,
                &tls12ConfirmationCandidate);
            if (NT_SUCCESS(status)) {
                return STATUS_SUCCESS;
            }

            lastStatus = status;
            if (WebSocketModeCanRetryHttp11(options, status)) {
                WebSocketConnectOptions http11Options = options;
                http11Options.TransportMode = WebSocketTransportMode::Http11Only;
                http11Options.AllowWebSocketOverHttp2 = false;
                if (statusCode != nullptr) {
                    *statusCode = 0;
                }

                bool ignoredConfirmationCandidate = false;
                const NTSTATUS http11Status = ConnectAddress(
                    wskClient,
                    reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]),
                    http11Options,
                    buffers,
                    clientKey.Get(),
                    clientKeyLength,
                    requestLength,
                    statusCode,
                    &ignoredConfirmationCandidate);
                if (NT_SUCCESS(http11Status)) {
                    kprintf(
                        "WebSocketClient HTTP/1.1 retry succeeded after h2 unsupported index=%Iu\r\n",
                        addressIndex);
                    return STATUS_SUCCESS;
                }
                kprintf(
                    "WebSocketClient HTTP/1.1 retry failed: 0x%08X original=0x%08X index=%Iu\r\n",
                    static_cast<ULONG>(http11Status),
                    static_cast<ULONG>(status),
                    addressIndex);
                lastStatus = http11Status;
            }
            if (tls12ConfirmationCandidate) {
                WebSocketConnectOptions tls12Options = options;
                tls12Options.MaximumTlsProtocol = tls::TlsProtocol::Tls12;
                if (statusCode != nullptr) {
                    *statusCode = 0;
                }

                bool ignoredConfirmationCandidate = false;
                const NTSTATUS confirmationStatus = ConnectAddress(
                    wskClient,
                    reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]),
                    tls12Options,
                    buffers,
                    clientKey.Get(),
                    clientKeyLength,
                    requestLength,
                    statusCode,
                    &ignoredConfirmationCandidate);
                if (NT_SUCCESS(confirmationStatus)) {
                    kprintf(
                        "WebSocketClient TLS1.2 confirmed after version negotiation index=%Iu\r\n",
                        addressIndex);
                    return STATUS_SUCCESS;
                }

                kprintf(
                    "WebSocketClient TLS1.2 confirmation failed: 0x%08X original=0x%08X index=%Iu\r\n",
                    static_cast<ULONG>(confirmationStatus),
                    static_cast<ULONG>(status),
                    addressIndex);
            }
            kprintf("WebSocketClient address attempt failed: 0x%08X index=%Iu family=%u\r\n",
                static_cast<ULONG>(status),
                addressIndex,
                static_cast<unsigned>(remoteAddresses[addressIndex].ss_family));
        }

        return lastStatus;
    }

    NTSTATUS WebSocketClient::ConnectAddress(
        net::WskClient& wskClient,
        const SOCKADDR* remoteAddress,
        const WebSocketConnectOptions& options,
        const WebSocketIoBuffers& buffers,
        const char* clientKey,
        SIZE_T clientKeyLength,
        SIZE_T requestLength,
        USHORT* statusCode,
        bool* tls12ConfirmationCandidate) noexcept
    {
        if (tls12ConfirmationCandidate != nullptr) {
            *tls12ConfirmationCandidate = false;
        }

        if (remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = socket_.Connect(wskClient, remoteAddress, nullptr, options.Cancellation);
        if (!NT_SUCCESS(status)) {
            kprintf("WebSocketClient connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }
        transportClosed_ = false;

        rawTransport_ = AllocateNonPagedObject<core::WskTransport>(socket_);
        if (rawTransport_ == nullptr) {
            const NTSTATUS closeStatus = CloseTransport();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        rawTransport_->SetCancellation(options.Cancellation);

        useTls_ = options.UseTls;
        bufferedFrameLength_ = 0;
        closeSent_ = false;
        closeReceived_ = false;
        ResetSendFragment();
        ResetReceiveFragment();
        if (useTls_) {
            core::WorkspaceScratchAllocator* handshakeScratch = nullptr;
            core::WorkspaceScratchAllocator* certificateScratch = nullptr;
            if (options.Workspace != nullptr) {
                handshakeScratch = AllocateNonPagedObject<core::WorkspaceScratchAllocator>(
                    *options.Workspace,
                    core::WorkspaceScratchAllocator::BufferKind::TlsHandshake);
                certificateScratch = AllocateNonPagedObject<core::WorkspaceScratchAllocator>(
                    *options.Workspace,
                    core::WorkspaceScratchAllocator::BufferKind::Certificate);
                if (handshakeScratch == nullptr || certificateScratch == nullptr) {
                    FreeNonPagedObject(certificateScratch);
                    FreeNonPagedObject(handshakeScratch);
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }

            tls_ = AllocateNonPagedObject<tls::TlsConnection>();
            if (tls_ == nullptr) {
                FreeNonPagedObject(certificateScratch);
                FreeNonPagedObject(handshakeScratch);
                const NTSTATUS closeStatus = CloseTransport();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            tls::TlsClientConnectionOptions tlsOptions = {};
            tlsOptions.ServerName = options.TlsServerName;
            tlsOptions.ServerNameLength = options.TlsServerNameLength;
            tlsOptions.CertificateStore = options.CertificateStore;
            tlsOptions.HandshakeScratchAllocator = handshakeScratch;
            tlsOptions.CertificateScratchAllocator = certificateScratch;
            tlsOptions.ProviderCache = options.ProviderCache;
            tlsOptions.VerifyCertificate = options.VerifyCertificate;
            tlsOptions.MinimumProtocol = options.MinimumTlsProtocol;
            tlsOptions.MaximumProtocol = options.MaximumTlsProtocol;
            tlsOptions.Policy = options.Policy;
            tlsOptions.ClientCredential = options.ClientCredential;
            tlsOptions.HandshakeReceiveTimeoutMilliseconds = options.HandshakeReceiveTimeoutMilliseconds;
            tlsOptions.MaxTls12Renegotiations = options.MaxTls12Renegotiations;

            HeapArray<tls::TlsAlpnProtocol> alpnProtocols(2);
            if (!alpnProtocols.IsValid()) {
                FreeNonPagedObject(certificateScratch);
                FreeNonPagedObject(handshakeScratch);
                const NTSTATUS closeStatus = CloseTransport();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T alpnProtocolCount = 0;
            if (WebSocketModeAllowsHttp2(options)) {
                alpnProtocols[alpnProtocolCount++] = { WebSocketHttp2Alpn, WebSocketHttp2AlpnLength };
            }
            if (!WebSocketModeRequiresHttp2(options)) {
                alpnProtocols[alpnProtocolCount++] = { WebSocketHttp11Alpn, WebSocketHttp11AlpnLength };
            }
            tlsOptions.AlpnProtocols = alpnProtocols.Get();
            tlsOptions.AlpnProtocolCount = alpnProtocolCount;

            status = tls_->Connect(*rawTransport_, tlsOptions);
            FreeNonPagedObject(certificateScratch);
            FreeNonPagedObject(handshakeScratch);

            if (!NT_SUCCESS(status)) {
                if (tls12ConfirmationCandidate != nullptr &&
                    IsTls12ConfirmationCandidate(options, tls_->LastHandshakeFailure())) {
                    *tls12ConfirmationCandidate = true;
                }
                kprintf("WebSocketClient TLS connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
                const NTSTATUS closeStatus = CloseTransport();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            const char* negotiatedAlpn = tls_->NegotiatedAlpn();
            const SIZE_T negotiatedAlpnLength = tls_->NegotiatedAlpnLength();
            if (WebSocketModeAllowsHttp2(options) &&
                TextEqualsLiteral(negotiatedAlpn, negotiatedAlpnLength, WebSocketHttp2Alpn)) {
                h2Transport_ = AllocateNonPagedObject<core::TlsTransport>(*rawTransport_, *tls_);
                h2Connection_ = AllocateNonPagedObject<http2::Http2Connection>();
                if (h2Transport_ == nullptr || h2Connection_ == nullptr) {
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                status = h2Connection_->Initialize(*h2Transport_);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }

                SIZE_T lowerHeaderNameBytes = 0;
                for (SIZE_T index = 0; index < options.ExtraHeaderCount; ++index) {
                    if (options.ExtraHeaders == nullptr) {
                        const NTSTATUS closeStatus = CloseTransport();
                        UNREFERENCED_PARAMETER(closeStatus);
                        return STATUS_INVALID_PARAMETER;
                    }
                    if (options.ExtraHeaders[index].Name.Length >
                        static_cast<SIZE_T>(-1) - lowerHeaderNameBytes) {
                        const NTSTATUS closeStatus = CloseTransport();
                        UNREFERENCED_PARAMETER(closeStatus);
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    lowerHeaderNameBytes += options.ExtraHeaders[index].Name.Length;
                }

                const SIZE_T subprotocolHeaderCount =
                    options.Subprotocol != nullptr && options.SubprotocolLength != 0 ? 1 : 0;
                const SIZE_T extensionHeaderCount = options.PerMessageDeflate.Enable ? 1 : 0;
                HeapArray<char> extensionOffer;
                SIZE_T extensionOfferLength = 0;
                if (options.PerMessageDeflate.Enable) {
                    status = extensionOffer.Allocate(160);
                    if (NT_SUCCESS(status)) {
                        status = BuildPerMessageDeflateOffer(
                            options.PerMessageDeflate,
                            extensionOffer.Get(),
                            extensionOffer.Count(),
                            &extensionOfferLength);
                    }
                    if (!NT_SUCCESS(status)) {
                        const NTSTATUS closeStatus = CloseTransport();
                        UNREFERENCED_PARAMETER(closeStatus);
                        return status;
                    }
                }
                HeapArray<http::HttpHeader> requestHeaders(
                    WebSocketHttp2BaseHeaderCount +
                    subprotocolHeaderCount +
                    extensionHeaderCount +
                    options.ExtraHeaderCount);
                HeapArray<char> authority(options.HostLength + 9);
                HeapArray<char> lowerHeaderNames;
                if (lowerHeaderNameBytes != 0) {
                    status = lowerHeaderNames.Allocate(lowerHeaderNameBytes);
                }
                if (!requestHeaders.IsValid() ||
                    !authority.IsValid() ||
                    (lowerHeaderNameBytes != 0 && !lowerHeaderNames.IsValid()) ||
                    !NT_SUCCESS(status)) {
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return !NT_SUCCESS(status) ? status : STATUS_INSUFFICIENT_RESOURCES;
                }

                SIZE_T requestHeaderCount = 0;
                status = BuildHttp2WebSocketHeaders(
                    options,
                    options.PerMessageDeflate.Enable ? extensionOffer.Get() : nullptr,
                    extensionOfferLength,
                    requestHeaders.Get(),
                    requestHeaders.Count(),
                    authority.Get(),
                    authority.Count(),
                    lowerHeaderNameBytes != 0 ? lowerHeaderNames.Get() : nullptr,
                    lowerHeaderNameBytes,
                    &requestHeaderCount);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }

                SIZE_T responseHeaderCount = 0;
                SIZE_T responseBodyLength = 0;
                USHORT h2StatusCode = 0;
                http2::Http2ResponseBodySink sink = {};
                sink.Append = IgnoreHttp2WebSocketResponseBody;
                status = h2Connection_->BeginRequest(
                    *h2Transport_,
                    requestHeaders.Get(),
                    requestHeaderCount,
                    nullptr,
                    0,
                    buffers.Headers,
                    buffers.HeaderCapacity,
                    &responseHeaderCount,
                    sink,
                    &responseBodyLength,
                    &h2StatusCode,
                    buffers.ResponseBuffer,
                    buffers.ResponseBufferLength,
                    &h2StreamId_);
                if (NT_SUCCESS(status)) {
                    status = h2Connection_->ReceiveResponseHeaders(*h2Transport_, h2StreamId_);
                }
                if (statusCode != nullptr) {
                    *statusCode = h2StatusCode;
                }
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }

                http::HttpText selectedSubprotocol = {};
                status = ValidateHttp2WebSocketResponse(
                    h2StatusCode,
                    buffers.Headers,
                    responseHeaderCount,
                    options.Subprotocol,
                    options.SubprotocolLength,
                    &selectedSubprotocol,
                    &options.PerMessageDeflate,
                    &perMessageDeflate_);
                if (NT_SUCCESS(status)) {
                    status = StoreSelectedSubprotocol(selectedSubprotocol);
                }
                if (NT_SUCCESS(status) && perMessageDeflate_.Enabled) {
                    status = receiveDeflate_.Initialize(perMessageDeflate_.ServerMaxWindowBits);
                }
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }

                connected_ = true;
                rawTransport_->SetCancellation(nullptr);
                return STATUS_SUCCESS;
            }
            if (WebSocketModeRequiresHttp2(options)) {
                const NTSTATUS closeStatus = CloseTransport();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_NOT_SUPPORTED;
            }
            if (negotiatedAlpnLength != 0 &&
                !TextEqualsLiteral(negotiatedAlpn, negotiatedAlpnLength, WebSocketHttp11Alpn)) {
                kprintf("WebSocketClient unexpected ALPN: %.*s\r\n",
                    static_cast<int>(negotiatedAlpnLength),
                    negotiatedAlpn != nullptr ? negotiatedAlpn : "");
                const NTSTATUS closeStatus = CloseTransport();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_NOT_SUPPORTED;
            }
        }

        WebSocketConnectOptions currentOptions = options;
        ULONG retryLimit = options.ChallengeCallback != nullptr ?
            (options.MaxHandshakeRetries != 0 ? options.MaxHandshakeRetries : WebSocketDefaultHandshakeRetries) :
            0;
        ULONG retryCount = 0;
        for (;;) {
            SIZE_T sent = 0;
            status = SendRaw(buffers.RequestBuffer, requestLength, &sent);
            if (NT_SUCCESS(status) && sent != requestLength) {
                status = STATUS_CONNECTION_DISCONNECTED;
            }

            if (!NT_SUCCESS(status)) {
                kprintf("WebSocketClient send handshake failed: 0x%08X\r\n", static_cast<ULONG>(status));
                const NTSTATUS closeStatus = Close(buffers);
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            http::HttpResponse response = {};
            status = ReadHandshakeResponse(
                clientKey,
                clientKeyLength,
                currentOptions.Subprotocol,
                currentOptions.SubprotocolLength,
                currentOptions.PerMessageDeflate,
                buffers,
                response);
            if (statusCode != nullptr) {
                *statusCode = response.StatusCode;
            }

            if (NT_SUCCESS(status)) {
                break;
            }

            if (status == STATUS_NOT_SUPPORTED &&
                options.ChallengeCallback != nullptr &&
                IsWebSocketHandshakeChallengeStatus(response.StatusCode) &&
                retryCount < retryLimit) {
                WebSocketHandshakeChallenge challenge = {};
                challenge.StatusCode = response.StatusCode;
                challenge.Headers = response.Headers;
                challenge.HeaderCount = response.HeaderCount;
                challenge.Redirect = response.StatusCode >= 300 && response.StatusCode <= 399;
                challenge.AuthenticationChallenge = response.StatusCode == 401 || response.StatusCode == 407;

                WebSocketHandshakeRetryAction action = {};
                status = options.ChallengeCallback(options.ChallengeContext, &challenge, &action);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS closeStatus = Close(buffers);
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }
                if ((action.RedirectPath == nullptr && action.RedirectPathLength != 0) ||
                    (action.RedirectPath != nullptr && action.RedirectPathLength == 0) ||
                    (action.Headers == nullptr && action.HeaderCount != 0) ||
                    action.HeaderCount > WebSocketMaxChallengeHeaders) {
                    const NTSTATUS closeStatus = Close(buffers);
                    UNREFERENCED_PARAMETER(closeStatus);
                    return STATUS_INVALID_PARAMETER;
                }

                const SIZE_T combinedHeaderCount = options.ExtraHeaderCount + action.HeaderCount;
                HeapArray<http::HttpHeader> combinedHeaders(combinedHeaderCount);
                if (!combinedHeaders.IsValid() && combinedHeaderCount != 0) {
                    const NTSTATUS closeStatus = Close(buffers);
                    UNREFERENCED_PARAMETER(closeStatus);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                for (SIZE_T index = 0; index < options.ExtraHeaderCount; ++index) {
                    combinedHeaders[index] = options.ExtraHeaders[index];
                }
                for (SIZE_T index = 0; index < action.HeaderCount; ++index) {
                    combinedHeaders[options.ExtraHeaderCount + index] = action.Headers[index];
                }

                currentOptions.ExtraHeaders = combinedHeaderCount != 0 ? combinedHeaders.Get() : nullptr;
                currentOptions.ExtraHeaderCount = combinedHeaderCount;
                if (action.RedirectPath != nullptr) {
                    currentOptions.Path = action.RedirectPath;
                    currentOptions.PathLength = action.RedirectPathLength;
                }
                status = BuildHandshakeRequest(
                    currentOptions,
                    clientKey,
                    clientKeyLength,
                    buffers.RequestBuffer,
                    buffers.RequestBufferLength,
                    &requestLength);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS closeStatus = Close(buffers);
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }
                ++retryCount;
                continue;
            }

            kprintf("WebSocketClient handshake failed: 0x%08X status=%u\r\n",
                static_cast<ULONG>(status),
                response.StatusCode);
            const NTSTATUS closeStatus = Close(buffers);
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        connected_ = true;
        rawTransport_->SetCancellation(nullptr);
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketClient::SendText(
        const char* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendFrame(
            websocket::WebSocketOpcode::Text,
            reinterpret_cast<const UCHAR*>(message),
            messageLength,
            buffers,
            finalFragment);
    }

    NTSTATUS WebSocketClient::SendBinary(
        const UCHAR* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendFrame(
            websocket::WebSocketOpcode::Binary,
            message,
            messageLength,
            buffers,
            finalFragment);
    }

    NTSTATUS WebSocketClient::SendContinuation(
        const UCHAR* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendFrame(
            websocket::WebSocketOpcode::Continuation,
            message,
            messageLength,
            buffers,
            finalFragment);
    }

    NTSTATUS WebSocketClient::SendPing(
        const UCHAR* payload,
        SIZE_T payloadLength,
        const WebSocketIoBuffers& buffers) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendControlFrame(websocket::WebSocketOpcode::Ping, payload, payloadLength, buffers);
    }

    NTSTATUS WebSocketClient::SendPong(
        const UCHAR* payload,
        SIZE_T payloadLength,
        const WebSocketIoBuffers& buffers) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendControlFrame(websocket::WebSocketOpcode::Pong, payload, payloadLength, buffers);
    }

    NTSTATUS WebSocketClient::SendControlFrame(
        websocket::WebSocketOpcode opcode,
        const UCHAR* payload,
        SIZE_T payloadLength,
        const WebSocketIoBuffers& buffers) noexcept
    {
        if (!connected_) {
            return (transportClosed_ || closeSent_ || closeReceived_) ?
                STATUS_CONNECTION_DISCONNECTED :
                STATUS_INVALID_PARAMETER;
        }

        if ((payload == nullptr && payloadLength != 0) ||
            payloadLength > websocket::WebSocketMaxControlPayloadLength ||
            buffers.FrameBuffer == nullptr ||
            buffers.FrameBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (opcode != websocket::WebSocketOpcode::Ping &&
            opcode != websocket::WebSocketOpcode::Pong) {
            return STATUS_INVALID_PARAMETER;
        }

        if (closeSent_ || closeReceived_) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        return EncodeAndSendFrame(opcode, payload, payloadLength, buffers, true);
    }

    NTSTATUS WebSocketClient::SendFrame(
        websocket::WebSocketOpcode opcode,
        const UCHAR* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment) noexcept
    {
        if (!connected_) {
            return (transportClosed_ || closeSent_ || closeReceived_) ?
                STATUS_CONNECTION_DISCONNECTED :
                STATUS_INVALID_PARAMETER;
        }

        if ((message == nullptr && messageLength != 0) ||
            buffers.FrameBuffer == nullptr ||
            buffers.FrameBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool continuation = opcode == websocket::WebSocketOpcode::Continuation;
        if (continuation != sendFragmentOpen_) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (!continuation &&
            opcode != websocket::WebSocketOpcode::Text &&
            opcode != websocket::WebSocketOpcode::Binary) {
            return STATUS_INVALID_PARAMETER;
        }

        if (closeSent_ || closeReceived_) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        ULONG nextUtf8CodePoint = sendTextUtf8CodePoint_;
        UCHAR nextUtf8Remaining = sendTextUtf8Remaining_;
        UCHAR nextUtf8Expected = sendTextUtf8Expected_;
        const bool textFragment =
            opcode == websocket::WebSocketOpcode::Text ||
            (continuation && sendFragmentOpcode_ == websocket::WebSocketOpcode::Text);
        if (textFragment) {
            if (opcode == websocket::WebSocketOpcode::Text) {
                nextUtf8CodePoint = 0;
                nextUtf8Remaining = 0;
                nextUtf8Expected = 0;
            }

            NTSTATUS utf8Status = AdvanceUtf8State(
                message,
                messageLength,
                finalFragment,
                &nextUtf8CodePoint,
                &nextUtf8Remaining,
                &nextUtf8Expected);
            if (!NT_SUCCESS(utf8Status)) {
                return utf8Status;
            }
        }

        const SIZE_T maxPayloadPerFrame = MaxPayloadForFrameBuffer(buffers.FrameBufferLength);
        if (messageLength != 0 && maxPayloadPerFrame == 0) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        bool sentAnyFrame = false;
        while (!sentAnyFrame || offset < messageLength) {
            const SIZE_T remaining = messageLength - offset;
            const SIZE_T chunkLength = remaining > maxPayloadPerFrame ? maxPayloadPerFrame : remaining;
            const bool lastChunk = offset + chunkLength == messageLength;
            const bool frameFinal = finalFragment && lastChunk;
            const websocket::WebSocketOpcode frameOpcode =
                sentAnyFrame ? websocket::WebSocketOpcode::Continuation : opcode;
            const UCHAR* chunk = chunkLength != 0 ? message + offset : nullptr;

            const NTSTATUS status = EncodeAndSendMessageFrame(
                frameOpcode,
                chunk,
                chunkLength,
                buffers,
                frameFinal);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            offset += chunkLength;
            sentAnyFrame = true;
        }

        if (finalFragment) {
            ResetSendFragment();
        }
        else {
            sendFragmentOpen_ = true;
            if (!continuation) {
                sendFragmentOpcode_ = opcode;
            }
            sendTextUtf8CodePoint_ = textFragment ? nextUtf8CodePoint : 0;
            sendTextUtf8Remaining_ = textFragment ? nextUtf8Remaining : 0;
            sendTextUtf8Expected_ = textFragment ? nextUtf8Expected : 0;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketClient::ReceiveMessage(
        const WebSocketIoBuffers& buffers,
        websocket::WebSocketOpcode* opcode,
        UCHAR* output,
        SIZE_T outputCapacity,
        SIZE_T* bytesReceived,
        bool autoReplyPing,
        bool deliverFragments,
        bool* finalFragment) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            if (opcode != nullptr) {
                *opcode = websocket::WebSocketOpcode::Continuation;
            }
            if (bytesReceived != nullptr) {
                *bytesReceived = 0;
            }
            if (finalFragment != nullptr) {
                *finalFragment = true;
            }
            return status;
        }

        if (opcode != nullptr) {
            *opcode = websocket::WebSocketOpcode::Continuation;
        }
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }
        if (finalFragment != nullptr) {
            *finalFragment = true;
        }

        if (!connected_) {
            return (transportClosed_ || closeSent_ || closeReceived_) ?
                STATUS_CONNECTION_DISCONNECTED :
                STATUS_INVALID_PARAMETER;
        }

        if (buffers.FrameBuffer == nullptr ||
            buffers.FrameBufferLength == 0 ||
            output == nullptr ||
            bytesReceived == nullptr ||
            opcode == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (closeReceived_) {
            return STATUS_CONNECTION_DISCONNECTED;
        }
        if (outputCapacity > static_cast<SIZE_T>(-1) - websocket::WebSocketFrameHeaderMaxLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        const SIZE_T minimumPayloadCapacity =
            outputCapacity < websocket::WebSocketMaxControlPayloadLength ?
            websocket::WebSocketMaxControlPayloadLength :
            outputCapacity;
        if (minimumPayloadCapacity > static_cast<SIZE_T>(-1) - websocket::WebSocketFrameHeaderMaxLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T receiveFrameCapacity = minimumPayloadCapacity + websocket::WebSocketFrameHeaderMaxLength;
        if (bufferedFrameLength_ > receiveFrameCapacity) {
            receiveFrameCapacity = bufferedFrameLength_;
        }

        status = EnsureBufferedFrameCapacity(receiveFrameCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (!receiveFrameHeader_.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        websocket::WebSocketFrameHeader& header = *receiveFrameHeader_.Get();
        SIZE_T controlFrameCount = 0;

        for (;;) {
            SIZE_T frameLength = bufferedFrameLength_;
            RtlZeroMemory(&header, sizeof(header));
            for (;;) {
                bool headerDecoded = false;
                bool complete = false;
                status = TryDecodeCompleteFrame(bufferedFrame_, frameLength, &header, &headerDecoded, &complete);
                if (!NT_SUCCESS(status)) {
                    if (status == STATUS_INVALID_NETWORK_RESPONSE) {
                        return FailConnectionWithClose(
                            WebSocketCloseProtocolError,
                            buffers,
                            status);
                    }
                    return status;
                }
                if (headerDecoded) {
                    const SIZE_T declaredPayloadLength = static_cast<SIZE_T>(header.PayloadLength);
                    const bool dataFrame =
                        header.Opcode == websocket::WebSocketOpcode::Text ||
                        header.Opcode == websocket::WebSocketOpcode::Binary;
                    const bool controlFrame =
                        header.Opcode == websocket::WebSocketOpcode::Ping ||
                        header.Opcode == websocket::WebSocketOpcode::Pong ||
                        header.Opcode == websocket::WebSocketOpcode::Close;
                    if (header.Rsv1 &&
                        (controlFrame ||
                            header.Opcode == websocket::WebSocketOpcode::Continuation ||
                            !perMessageDeflate_.Enabled)) {
                        return FailConnectionWithClose(
                            WebSocketCloseProtocolError,
                            buffers,
                            STATUS_INVALID_NETWORK_RESPONSE);
                    }
                    if (dataFrame && receiveFragmentOpen_) {
                        return FailConnectionWithClose(
                            WebSocketCloseProtocolError,
                            buffers,
                            STATUS_INVALID_NETWORK_RESPONSE);
                    }
                    if (header.Opcode == websocket::WebSocketOpcode::Continuation && !receiveFragmentOpen_) {
                        return FailConnectionWithClose(
                            WebSocketCloseProtocolError,
                            buffers,
                            STATUS_INVALID_NETWORK_RESPONSE);
                    }
                    if (dataFrame || header.Opcode == websocket::WebSocketOpcode::Continuation) {
                        const bool aggregateTooSmall =
                            receiveFragmentLength_ > outputCapacity ||
                            declaredPayloadLength > outputCapacity - receiveFragmentLength_;
                        const bool fragmentTooSmall =
                            deliverFragments && declaredPayloadLength > outputCapacity;
                        if (aggregateTooSmall || fragmentTooSmall) {
                            *bytesReceived =
                                declaredPayloadLength <= static_cast<SIZE_T>(-1) - receiveFragmentLength_ ?
                                receiveFragmentLength_ + declaredPayloadLength :
                                static_cast<SIZE_T>(-1);
                            return FailConnectionWithClose(
                                WebSocketCloseMessageTooBig,
                                buffers,
                                STATUS_BUFFER_TOO_SMALL);
                        }
                    }
                }
                if (complete) {
                    break;
                }

                if (frameLength >= receiveFrameCapacity) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                SIZE_T received = 0;
                status = ReceiveRaw(
                    bufferedFrame_ + frameLength,
                    receiveFrameCapacity - frameLength,
                    &received);
                if (!NT_SUCCESS(status)) {
                    if (IsConnectionTerminalStatus(status)) {
                        connected_ = false;
                        closeReceived_ = true;
                        const NTSTATUS closeStatus = CloseTransport();
                        UNREFERENCED_PARAMETER(closeStatus);
                    }
                    return status;
                }
                if (received == 0) {
                    connected_ = false;
                    closeReceived_ = true;
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return STATUS_CONNECTION_DISCONNECTED;
                }
                frameLength += received;
            }

            const SIZE_T payloadLength = static_cast<SIZE_T>(header.PayloadLength);
            const SIZE_T consumed = header.HeaderLength + payloadLength;
            const SIZE_T remaining = frameLength - consumed;

            if (header.Masked) {
                return FailConnectionWithClose(
                    WebSocketCloseProtocolError,
                    buffers,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }

            if (header.Opcode == websocket::WebSocketOpcode::Ping) {
                if (++controlFrameCount > KhWsMaxControlFramesPerReceive) {
                    return FailConnectionWithClose(
                        WebSocketClosePolicyViolation,
                        buffers,
                        STATUS_INVALID_NETWORK_RESPONSE);
                }
                if (!autoReplyPing) {
                    if (receiveFragmentOpen_) {
                        *bytesReceived = 0;
                    }
                    else {
                        status = websocket::WebSocketCodec::DecodeFramePayload(
                            header,
                            bufferedFrame_,
                            frameLength,
                            output,
                            outputCapacity,
                            bytesReceived);
                        if (!NT_SUCCESS(status)) {
                            ResetReceiveFragment();
                            return status;
                        }
                    }

                    if (remaining > 0) {
                        RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
                    }
                    bufferedFrameLength_ = remaining;
                    *opcode = header.Opcode;
                    return STATUS_SUCCESS;
                }

                status = EncodeAndSendFrame(
                    websocket::WebSocketOpcode::Pong,
                    bufferedFrame_ + header.HeaderLength,
                    payloadLength,
                    buffers,
                    true);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (remaining > 0) {
                    RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
                }
                bufferedFrameLength_ = remaining;
                continue;
            }

            if (header.Opcode == websocket::WebSocketOpcode::Pong) {
                if (++controlFrameCount > KhWsMaxControlFramesPerReceive) {
                    return FailConnectionWithClose(
                        WebSocketClosePolicyViolation,
                        buffers,
                        STATUS_INVALID_NETWORK_RESPONSE);
                }
                if (!autoReplyPing) {
                    if (receiveFragmentOpen_) {
                        *bytesReceived = 0;
                    }
                    else {
                        status = websocket::WebSocketCodec::DecodeFramePayload(
                            header,
                            bufferedFrame_,
                            frameLength,
                            output,
                            outputCapacity,
                            bytesReceived);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                }

                if (remaining > 0) {
                    RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
                }
                bufferedFrameLength_ = remaining;
                if (autoReplyPing) {
                    continue;
                }

                *opcode = header.Opcode;
                return STATUS_SUCCESS;
            }

            if (header.Opcode == websocket::WebSocketOpcode::Close) {
                const UCHAR* closePayload = bufferedFrame_ + header.HeaderLength;
                if (payloadLength == 1) {
                    return FailConnectionWithClose(
                        WebSocketCloseProtocolError,
                        buffers,
                        STATUS_INVALID_NETWORK_RESPONSE);
                }
                if (payloadLength >= 2) {
                    const USHORT closeStatus = static_cast<USHORT>(
                        (static_cast<USHORT>(closePayload[0]) << 8) | closePayload[1]);
                    if (!IsValidCloseStatus(closeStatus) ||
                        !IsValidUtf8(closePayload + 2, payloadLength - 2)) {
                        return FailConnectionWithClose(
                            WebSocketCloseProtocolError,
                            buffers,
                            STATUS_INVALID_NETWORK_RESPONSE);
                    }
                }

                ResetReceiveFragment();
                closeReceived_ = true;
                if (!closeSent_) {
                    status = SendCloseFrame(closePayload, payloadLength, buffers);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                connected_ = false;
                {
                    const NTSTATUS closeStatus = CloseTransport();
                    UNREFERENCED_PARAMETER(closeStatus);
                }
                *opcode = header.Opcode;
                *bytesReceived = payloadLength;
                if (payloadLength > outputCapacity) {
                    if (remaining > 0) {
                        RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
                    }
                    bufferedFrameLength_ = remaining;
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if (payloadLength != 0) {
                    RtlCopyMemory(output, closePayload, payloadLength);
                }
                if (remaining > 0) {
                    RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
                }
                bufferedFrameLength_ = remaining;
                return STATUS_SUCCESS;
            }

            const bool dataFrame =
                header.Opcode == websocket::WebSocketOpcode::Text ||
                header.Opcode == websocket::WebSocketOpcode::Binary;
            if (header.Rsv1 &&
                (!dataFrame || receiveFragmentOpen_ || !perMessageDeflate_.Enabled)) {
                return FailConnectionWithClose(
                    WebSocketCloseProtocolError,
                    buffers,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }
            if (dataFrame && receiveFragmentOpen_) {
                return FailConnectionWithClose(
                    WebSocketCloseProtocolError,
                    buffers,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }

            if (header.Opcode == websocket::WebSocketOpcode::Continuation && !receiveFragmentOpen_) {
                return FailConnectionWithClose(
                    WebSocketCloseProtocolError,
                    buffers,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }

            if (!dataFrame && header.Opcode != websocket::WebSocketOpcode::Continuation) {
                return FailConnectionWithClose(
                    WebSocketCloseProtocolError,
                    buffers,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }

            const bool aggregateTooSmall =
                receiveFragmentLength_ > outputCapacity ||
                payloadLength > outputCapacity - receiveFragmentLength_;
            const bool fragmentTooSmall = deliverFragments && payloadLength > outputCapacity;
            if (aggregateTooSmall || fragmentTooSmall) {
                if (bytesReceived != nullptr) {
                    *bytesReceived = payloadLength <= static_cast<SIZE_T>(-1) - receiveFragmentLength_ ?
                        receiveFragmentLength_ + payloadLength :
                        static_cast<SIZE_T>(-1);
                }
                return FailConnectionWithClose(
                    WebSocketCloseMessageTooBig,
                    buffers,
                    STATUS_BUFFER_TOO_SMALL);
            }

            SIZE_T fragmentBytes = 0;
            const SIZE_T outputOffset = deliverFragments ? 0 : receiveFragmentLength_;
            status = websocket::WebSocketCodec::DecodeFramePayload(
                header,
                bufferedFrame_,
                frameLength,
                output + outputOffset,
                outputCapacity - outputOffset,
                &fragmentBytes);
            if (!NT_SUCCESS(status)) {
                ResetReceiveFragment();
                return status;
            }

            if (!receiveFragmentOpen_) {
                receiveFragmentOpcode_ = header.Opcode;
                receiveCompressedMessage_ = header.Rsv1;
                receiveTextUtf8CodePoint_ = 0;
                receiveTextUtf8Remaining_ = 0;
                receiveTextUtf8Expected_ = 0;
            }
            receiveFragmentLength_ += fragmentBytes;

            const bool textFragment =
                receiveFragmentOpcode_ == websocket::WebSocketOpcode::Text;
            if (textFragment && !receiveCompressedMessage_) {
                status = AdvanceUtf8State(
                    output + outputOffset,
                    fragmentBytes,
                    header.Fin,
                    &receiveTextUtf8CodePoint_,
                    &receiveTextUtf8Remaining_,
                    &receiveTextUtf8Expected_);
                if (!NT_SUCCESS(status)) {
                    return FailConnectionWithClose(
                        WebSocketCloseInvalidPayload,
                        buffers,
                        STATUS_INVALID_NETWORK_RESPONSE);
                }
            }

            if (remaining > 0) {
                RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
            }
            bufferedFrameLength_ = remaining;

            if (!header.Fin) {
                receiveFragmentOpen_ = true;
                if (deliverFragments && !receiveCompressedMessage_) {
                    *opcode = header.Opcode;
                    *bytesReceived = fragmentBytes;
                    if (finalFragment != nullptr) {
                        *finalFragment = false;
                    }
                    return STATUS_SUCCESS;
                }
                continue;
            }

            if (receiveCompressedMessage_) {
                HeapArray<UCHAR> compressedCopy(receiveFragmentLength_ != 0 ? receiveFragmentLength_ : 1);
                if (!compressedCopy.IsValid()) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                if (receiveFragmentLength_ != 0) {
                    RtlCopyMemory(compressedCopy.Get(), output, receiveFragmentLength_);
                }

                SIZE_T inflatedLength = 0;
                status = receiveDeflate_.InflateMessage(
                    compressedCopy.Get(),
                    receiveFragmentLength_,
                    output,
                    outputCapacity,
                    &inflatedLength);
                if (!NT_SUCCESS(status)) {
                    return FailConnectionWithClose(
                        status == STATUS_BUFFER_TOO_SMALL ? WebSocketCloseMessageTooBig : WebSocketCloseProtocolError,
                        buffers,
                        status);
                }
                receiveFragmentLength_ = inflatedLength;
                if (perMessageDeflate_.ServerNoContextTakeover) {
                    receiveDeflate_.ResetHistory();
                }
                if (receiveFragmentOpcode_ == websocket::WebSocketOpcode::Text) {
                    if (!IsValidUtf8(output, receiveFragmentLength_)) {
                        return FailConnectionWithClose(
                            WebSocketCloseInvalidPayload,
                            buffers,
                            STATUS_INVALID_NETWORK_RESPONSE);
                    }
                }
            }

            if (!deliverFragments &&
                receiveFragmentOpcode_ == websocket::WebSocketOpcode::Text &&
                !IsValidUtf8(output, receiveFragmentLength_)) {
                return FailConnectionWithClose(
                    WebSocketCloseInvalidPayload,
                    buffers,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }

            *opcode = deliverFragments ? header.Opcode : receiveFragmentOpcode_;
            *bytesReceived = deliverFragments ? fragmentBytes : receiveFragmentLength_;
            if (finalFragment != nullptr) {
                *finalFragment = true;
            }
            ResetReceiveFragment();
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS WebSocketClient::WaitForPeerClose(const WebSocketIoBuffers& buffers) noexcept
    {
        UNREFERENCED_PARAMETER(buffers);

        if (!connected_ || closeReceived_) {
            return STATUS_SUCCESS;
        }

        const SIZE_T closeFrameCapacity =
            websocket::WebSocketFrameHeaderMaxLength + websocket::WebSocketMaxControlPayloadLength;
        NTSTATUS status = EnsureBufferedFrameCapacity(closeFrameCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (!receiveFrameHeader_.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONGLONG deadline = 0;
        if (!AddMilliseconds(CurrentMilliseconds(), WskCloseTimeoutMilliseconds, &deadline)) {
            return STATUS_IO_TIMEOUT;
        }

        websocket::WebSocketFrameHeader& header = *receiveFrameHeader_.Get();
        for (;;) {
            ULONG timeoutMilliseconds = 0;
            status = RemainingTimeoutMilliseconds(deadline, &timeoutMilliseconds);
            if (!NT_SUCCESS(status)) {
                return STATUS_SUCCESS;
            }

            bool headerDecoded = false;
            bool complete = false;
            RtlZeroMemory(&header, sizeof(header));
            status = TryDecodeCompleteFrame(
                bufferedFrame_,
                bufferedFrameLength_,
                &header,
                &headerDecoded,
                &complete);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (!headerDecoded) {
                if (bufferedFrameLength_ >= bufferedFrameCapacity_) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                SIZE_T received = 0;
                status = ReceiveRaw(
                    bufferedFrame_ + bufferedFrameLength_,
                    bufferedFrameCapacity_ - bufferedFrameLength_,
                    &received,
                    timeoutMilliseconds);
                if (!NT_SUCCESS(status)) {
                    return IsConnectionTerminalStatus(status) ? STATUS_SUCCESS : status;
                }
                if (received == 0) {
                    return STATUS_SUCCESS;
                }
                bufferedFrameLength_ += received;
                continue;
            }

            if (header.Masked || header.Rsv1) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T payloadLength = static_cast<SIZE_T>(header.PayloadLength);
            if (payloadLength > static_cast<SIZE_T>(-1) - header.HeaderLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const SIZE_T frameLength = header.HeaderLength + payloadLength;
            const bool controlFrame =
                header.Opcode == websocket::WebSocketOpcode::Ping ||
                header.Opcode == websocket::WebSocketOpcode::Pong ||
                header.Opcode == websocket::WebSocketOpcode::Close;

            if (controlFrame) {
                if (frameLength > bufferedFrameCapacity_) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                while (!complete) {
                    status = RemainingTimeoutMilliseconds(deadline, &timeoutMilliseconds);
                    if (!NT_SUCCESS(status)) {
                        return STATUS_SUCCESS;
                    }
                    if (bufferedFrameLength_ >= frameLength) {
                        complete = true;
                        break;
                    }

                    SIZE_T received = 0;
                    status = ReceiveRaw(
                        bufferedFrame_ + bufferedFrameLength_,
                        frameLength - bufferedFrameLength_,
                        &received,
                        timeoutMilliseconds);
                    if (!NT_SUCCESS(status)) {
                        return IsConnectionTerminalStatus(status) ? STATUS_SUCCESS : status;
                    }
                    if (received == 0) {
                        return STATUS_SUCCESS;
                    }
                    bufferedFrameLength_ += received;
                    complete = payloadLength <= (bufferedFrameLength_ - header.HeaderLength);
                }

                const UCHAR* payload = bufferedFrame_ + header.HeaderLength;
                if (header.Opcode == websocket::WebSocketOpcode::Close) {
                    if (payloadLength == 1) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (payloadLength >= 2) {
                        const USHORT closeStatus = static_cast<USHORT>(
                            (static_cast<USHORT>(payload[0]) << 8) | payload[1]);
                        if (!IsValidCloseStatus(closeStatus) ||
                            !IsValidUtf8(payload + 2, payloadLength - 2)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                    }

                    closeReceived_ = true;
                    connected_ = false;
                    const NTSTATUS closeStatus = CloseTransport();
                    return IsConnectionTerminalStatus(closeStatus) ? STATUS_SUCCESS : closeStatus;
                }

                const SIZE_T remaining = bufferedFrameLength_ - frameLength;
                if (remaining != 0) {
                    RtlMoveMemory(bufferedFrame_, bufferedFrame_ + frameLength, remaining);
                }
                bufferedFrameLength_ = remaining;
                continue;
            }

            const SIZE_T bufferedPayload =
                bufferedFrameLength_ > header.HeaderLength ?
                bufferedFrameLength_ - header.HeaderLength :
                0;
            if (bufferedPayload >= payloadLength) {
                const SIZE_T remaining = bufferedFrameLength_ - frameLength;
                if (remaining != 0) {
                    RtlMoveMemory(bufferedFrame_, bufferedFrame_ + frameLength, remaining);
                }
                bufferedFrameLength_ = remaining;
                continue;
            }

            SIZE_T remainingPayload = payloadLength - bufferedPayload;
            bufferedFrameLength_ = 0;
            while (remainingPayload != 0) {
                status = RemainingTimeoutMilliseconds(deadline, &timeoutMilliseconds);
                if (!NT_SUCCESS(status)) {
                    return STATUS_SUCCESS;
                }

                const SIZE_T chunk =
                    remainingPayload > bufferedFrameCapacity_ ?
                    bufferedFrameCapacity_ :
                    remainingPayload;
                SIZE_T received = 0;
                status = ReceiveRaw(bufferedFrame_, chunk, &received, timeoutMilliseconds);
                if (!NT_SUCCESS(status)) {
                    return IsConnectionTerminalStatus(status) ? STATUS_SUCCESS : status;
                }
                if (received == 0) {
                    return STATUS_SUCCESS;
                }
                if (received > remainingPayload) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                remainingPayload -= received;
            }
        }
    }

    NTSTATUS WebSocketClient::Close(const WebSocketIoBuffers& buffers) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        NTSTATUS waitStatus = STATUS_SUCCESS;
        if (connected_ &&
            !closeSent_ &&
            !closeReceived_ &&
            buffers.FrameBuffer != nullptr &&
            buffers.FrameBufferLength >= 6) {
            const NTSTATUS sendStatus = SendCloseFrame(nullptr, 0, buffers);
            UNREFERENCED_PARAMETER(sendStatus);
            if (NT_SUCCESS(sendStatus)) {
                waitStatus = WaitForPeerClose(buffers);
            }
        }

        connected_ = false;
        ResetSendFragment();
        closeSent_ = false;
        closeReceived_ = false;
        ResetReceiveFragment();
        if (bufferedFrame_ != nullptr && bufferedFrameLength_ != 0) {
            RtlSecureZeroMemory(bufferedFrame_, bufferedFrameLength_);
        }
        bufferedFrameLength_ = 0;
        const NTSTATUS closeStatus = CloseTransport();
        selectedSubprotocol_.Reset();
        selectedSubprotocolLength_ = 0;
        perMessageDeflate_ = {};
        receiveDeflate_.Release();
        sendCompressedMessage_ = false;
        receiveCompressedMessage_ = false;
        if (NT_SUCCESS(closeStatus) &&
            !NT_SUCCESS(waitStatus) &&
            !IsConnectionTerminalStatus(waitStatus) &&
            waitStatus != STATUS_IO_TIMEOUT) {
            return waitStatus;
        }
        return closeStatus;
    }

    NTSTATUS WebSocketClient::Close(
        USHORT statusCode,
        const UCHAR* reason,
        SIZE_T reasonLength,
        const WebSocketIoBuffers& buffers) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsValidCloseStatus(statusCode) ||
            (reason == nullptr && reasonLength != 0) ||
            reasonLength > websocket::WebSocketMaxControlPayloadLength - 2 ||
            !IsValidUtf8(reason, reasonLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> payload(2 + reasonLength);
        if (!payload.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        payload[0] = static_cast<UCHAR>((statusCode >> 8) & 0xff);
        payload[1] = static_cast<UCHAR>(statusCode & 0xff);
        if (reasonLength != 0) {
            RtlCopyMemory(payload.Get() + 2, reason, reasonLength);
        }

        if (connected_ && !closeSent_ && !closeReceived_) {
            status = SendCloseFrame(payload.Get(), payload.Count(), buffers);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return Close(buffers);
    }

    const char* WebSocketClient::SelectedSubprotocol(SIZE_T* subprotocolLength) const noexcept
    {
        if (subprotocolLength != nullptr) {
            *subprotocolLength = selectedSubprotocolLength_;
        }
        return selectedSubprotocolLength_ != 0 ? selectedSubprotocol_.Get() : nullptr;
    }

    NTSTATUS WebSocketClient::SendTextAndReceiveEcho(
        const char* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        WebSocketEchoResult& result) noexcept
    {
        result = {};

        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (buffers.PayloadBuffer == nullptr || buffers.PayloadBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        status = SendText(message, messageLength, buffers);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        constexpr SIZE_T MaxFramesBeforeEcho = 8;
        for (SIZE_T frameIndex = 0; frameIndex < MaxFramesBeforeEcho; ++frameIndex) {
            status = ReceiveMessage(
                buffers,
                &result.Opcode,
                buffers.PayloadBuffer,
                buffers.PayloadBufferLength,
                &result.BytesReceived);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (result.Opcode == websocket::WebSocketOpcode::Text &&
                PayloadEquals(message, messageLength, buffers.PayloadBuffer, result.BytesReceived)) {
                return STATUS_SUCCESS;
            }

            if (result.Opcode == websocket::WebSocketOpcode::Close) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
        }

        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    void WebSocketClient::ResetReceiveFragment() noexcept
    {
        receiveFragmentOpen_ = false;
        receiveCompressedMessage_ = false;
        receiveFragmentOpcode_ = websocket::WebSocketOpcode::Continuation;
        receiveFragmentLength_ = 0;
        receiveTextUtf8CodePoint_ = 0;
        receiveTextUtf8Remaining_ = 0;
        receiveTextUtf8Expected_ = 0;
    }

    void WebSocketClient::ResetSendFragment() noexcept
    {
        sendFragmentOpen_ = false;
        sendCompressedMessage_ = false;
        sendFragmentOpcode_ = websocket::WebSocketOpcode::Continuation;
        sendTextUtf8CodePoint_ = 0;
        sendTextUtf8Remaining_ = 0;
        sendTextUtf8Expected_ = 0;
    }

    NTSTATUS WebSocketClient::CloseTransport() noexcept
    {
        if (h2Connection_ != nullptr && h2Transport_ != nullptr) {
            const NTSTATUS shutdownStatus = h2Connection_->Shutdown(*h2Transport_);
            UNREFERENCED_PARAMETER(shutdownStatus);
        }
        FreeNonPagedObject(h2Connection_);
        h2Connection_ = nullptr;
        FreeNonPagedObject(h2Transport_);
        h2Transport_ = nullptr;
        h2StreamId_ = 0;

        if (tls_ != nullptr) {
            FreeNonPagedObject(tls_);
            tls_ = nullptr;
        }

        FreeNonPagedObject(rawTransport_);
        rawTransport_ = nullptr;
        useTls_ = false;

        if (transportClosed_) {
            return STATUS_SUCCESS;
        }

        transportClosed_ = true;
        const NTSTATUS closeStatus = socket_.Close();
        return IsConnectionTerminalStatus(closeStatus) ? STATUS_SUCCESS : closeStatus;
    }

    NTSTATUS WebSocketClient::EncodeAndSendFrame(
        websocket::WebSocketOpcode opcode,
        const UCHAR* payload,
        SIZE_T payloadLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment,
        bool rsv1) noexcept
    {
        if (h2Connection_ != nullptr && h2Transport_ != nullptr && h2StreamId_ != 0) {
            SIZE_T frameLength = 0;
            NTSTATUS status = websocket::WebSocketCodec::EncodeClientFrameForHttp2(
                opcode,
                finalFragment,
                rsv1,
                payload,
                payloadLength,
                buffers.FrameBuffer,
                buffers.FrameBufferLength,
                &frameLength);
            if (NT_SUCCESS(status)) {
                SIZE_T sent = 0;
                status = SendRaw(buffers.FrameBuffer, frameLength, &sent);
                if (NT_SUCCESS(status) && sent != frameLength) {
                    status = STATUS_CONNECTION_DISCONNECTED;
                }
            }
            if (!NT_SUCCESS(status) && IsConnectionTerminalStatus(status)) {
                connected_ = false;
            }
            return status;
        }

        HeapArray<UCHAR> maskingKey(websocket::WebSocketMaskingKeyLength);
        if (!maskingKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = crypto::CngProvider::GenerateRandom(
            maskingKey.Get(),
            websocket::WebSocketMaskingKeyLength);
        if (NT_SUCCESS(status)) {
            SIZE_T frameLength = 0;
            status = websocket::WebSocketCodec::EncodeClientFrame(
                opcode,
                finalFragment,
                rsv1,
                payload,
                payloadLength,
                maskingKey.Get(),
                buffers.FrameBuffer,
                buffers.FrameBufferLength,
                &frameLength);
            if (NT_SUCCESS(status)) {
                SIZE_T sent = 0;
                status = SendRaw(buffers.FrameBuffer, frameLength, &sent);
                if (NT_SUCCESS(status) && sent != frameLength) {
                    status = STATUS_CONNECTION_DISCONNECTED;
                }
            }
        }

        RtlSecureZeroMemory(maskingKey.Get(), maskingKey.Count());
        if (!NT_SUCCESS(status) && IsConnectionTerminalStatus(status)) {
            connected_ = false;
            closeReceived_ = true;
            const NTSTATUS closeStatus = CloseTransport();
            UNREFERENCED_PARAMETER(closeStatus);
        }
        return status;
    }

    NTSTATUS WebSocketClient::EncodeAndSendMessageFrame(
        websocket::WebSocketOpcode opcode,
        const UCHAR* payload,
        SIZE_T payloadLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment) noexcept
    {
        const bool dataFrame =
            opcode == websocket::WebSocketOpcode::Text ||
            opcode == websocket::WebSocketOpcode::Binary;
        const bool continuation = opcode == websocket::WebSocketOpcode::Continuation;
        const bool compressed =
            perMessageDeflate_.Enabled &&
            (dataFrame || (continuation && sendCompressedMessage_));

        if (!compressed) {
            return EncodeAndSendFrame(opcode, payload, payloadLength, buffers, finalFragment);
        }

        const SIZE_T required = websocket::WebSocketDeflateContext::MaxStoredDeflateBytes(
            payloadLength,
            finalFragment);
        if (required == static_cast<SIZE_T>(-1)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        HeapArray<UCHAR> compressedPayload(required != 0 ? required : 1);
        if (!compressedPayload.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T compressedLength = 0;
        NTSTATUS status = websocket::WebSocketDeflateContext::DeflateMessage(
            payload,
            payloadLength,
            finalFragment,
            compressedPayload.Get(),
            compressedPayload.Count(),
            &compressedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool rsv1 = dataFrame && !sendCompressedMessage_;
        status = EncodeAndSendFrame(
            opcode,
            compressedLength != 0 ? compressedPayload.Get() : nullptr,
            compressedLength,
            buffers,
            finalFragment,
            rsv1);
        if (NT_SUCCESS(status)) {
            if (finalFragment) {
                sendCompressedMessage_ = false;
            }
            else if (dataFrame) {
                sendCompressedMessage_ = true;
            }
        }
        if (perMessageDeflate_.ClientNoContextTakeover && finalFragment) {
            sendCompressedMessage_ = false;
        }
        return status;
    }

    NTSTATUS WebSocketClient::SendCloseStatus(
        USHORT statusCode,
        const WebSocketIoBuffers& buffers) noexcept
    {
        if (!connected_ || buffers.FrameBuffer == nullptr || buffers.FrameBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> payload(2);
        if (!payload.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        payload[0] = static_cast<UCHAR>((statusCode >> 8) & 0xff);
        payload[1] = static_cast<UCHAR>(statusCode & 0xff);

        return SendCloseFrame(payload.Get(), payload.Count(), buffers);
    }

    NTSTATUS WebSocketClient::FailConnectionWithClose(
        USHORT statusCode,
        const WebSocketIoBuffers& buffers,
        NTSTATUS returnStatus) noexcept
    {
        ResetSendFragment();
        ResetReceiveFragment();
        if (connected_ && !closeSent_) {
            const NTSTATUS closeStatus = SendCloseStatus(statusCode, buffers);
            UNREFERENCED_PARAMETER(closeStatus);
        }
        closeReceived_ = true;
        connected_ = false;
        const NTSTATUS closeStatus = CloseTransport();
        UNREFERENCED_PARAMETER(closeStatus);
        return returnStatus;
    }

    NTSTATUS WebSocketClient::SendCloseFrame(
        const UCHAR* payload,
        SIZE_T payloadLength,
        const WebSocketIoBuffers& buffers) noexcept
    {
        if (!connected_ ||
            (payload == nullptr && payloadLength != 0) ||
            buffers.FrameBuffer == nullptr ||
            buffers.FrameBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (closeSent_) {
            return STATUS_SUCCESS;
        }

        NTSTATUS status = EncodeAndSendFrame(
            websocket::WebSocketOpcode::Close,
            payload,
            payloadLength,
            buffers,
            true);
        if (NT_SUCCESS(status)) {
            closeSent_ = true;
        }
        return status;
    }

    NTSTATUS WebSocketClient::EnsureBufferedFrameCapacity(SIZE_T capacity) noexcept
    {
        if (capacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (bufferedFrameCapacity_ >= capacity) {
            return STATUS_SUCCESS;
        }

        UCHAR* replacement = AllocateNonPagedArray<UCHAR>(capacity);
        if (replacement == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (bufferedFrame_ != nullptr) {
            if (bufferedFrameLength_ != 0) {
                RtlCopyMemory(replacement, bufferedFrame_, bufferedFrameLength_);
            }
            RtlSecureZeroMemory(bufferedFrame_, bufferedFrameCapacity_);
        }

        FreeNonPagedArray(bufferedFrame_);
        bufferedFrame_ = replacement;
        bufferedFrameCapacity_ = capacity;
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketClient::StoreSelectedSubprotocol(const http::HttpText& subprotocol) noexcept
    {
        selectedSubprotocol_.Reset();
        selectedSubprotocolLength_ = 0;

        if (subprotocol.Length == 0) {
            return STATUS_SUCCESS;
        }
        if (subprotocol.Data == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        NTSTATUS status = selectedSubprotocol_.Allocate(subprotocol.Length + 1);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlCopyMemory(selectedSubprotocol_.Get(), subprotocol.Data, subprotocol.Length);
        selectedSubprotocol_[subprotocol.Length] = '\0';
        selectedSubprotocolLength_ = subprotocol.Length;
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketClient::SendRaw(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
    {
        if (h2Connection_ != nullptr && h2Transport_ != nullptr && h2StreamId_ != 0) {
            if (bytesSent != nullptr) {
                *bytesSent = 0;
            }
            const NTSTATUS status = h2Connection_->SendStreamData(
                *h2Transport_,
                h2StreamId_,
                static_cast<const UCHAR*>(data),
                length,
                false);
            if (NT_SUCCESS(status) && bytesSent != nullptr) {
                *bytesSent = length;
            }
            return status;
        }

        if (useTls_) {
            if (tls_ == nullptr || rawTransport_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return tls_->Send(*rawTransport_, data, length, bytesSent);
        }

        return socket_.Send(data, length, bytesSent);
    }

    NTSTATUS WebSocketClient::ReceiveRaw(
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG timeoutMilliseconds) noexcept
    {
        UNREFERENCED_PARAMETER(timeoutMilliseconds);

        if (h2Connection_ != nullptr && h2Transport_ != nullptr && h2StreamId_ != 0) {
            bool endStream = false;
            const NTSTATUS status = h2Connection_->ReceiveStreamData(
                *h2Transport_,
                h2StreamId_,
                static_cast<UCHAR*>(data),
                length,
                bytesReceived,
                &endStream);
            if (NT_SUCCESS(status) && endStream) {
                connected_ = false;
                closeReceived_ = true;
            }
            return status;
        }

        if (useTls_) {
            if (tls_ == nullptr || rawTransport_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return tls_->Receive(*rawTransport_, data, length, bytesReceived, timeoutMilliseconds);
        }

        return socket_.Receive(data, length, bytesReceived, 0, timeoutMilliseconds);
    }

    NTSTATUS WebSocketClient::ReadHandshakeResponse(
        const char* clientKey,
        SIZE_T clientKeyLength,
        const char* requestedSubprotocol,
        SIZE_T requestedSubprotocolLength,
        const websocket::PerMessageDeflateOptions& perMessageDeflate,
        const WebSocketIoBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        SIZE_T responseLength = 0;
        bufferedFrameLength_ = 0;

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = buffers.Headers;
            parseOptions.HeaderCapacity = buffers.HeaderCapacity;
            parseOptions.ResponseBodyForbidden = true;

            NTSTATUS status = http::HttpParser::ParseResponse(
                buffers.ResponseBuffer,
                responseLength,
                parseOptions,
                response);
            if (status == STATUS_SUCCESS) {
                if (response.StatusCode != 101) {
                    const bool policyRejected =
                        (response.StatusCode >= 300 && response.StatusCode <= 399) ||
                        response.StatusCode == 401 ||
                        response.StatusCode == 407;
                    return policyRejected ? STATUS_NOT_SUPPORTED : STATUS_INVALID_NETWORK_RESPONSE;
                }

                http::HttpText selectedSubprotocol = {};
                status = websocket::WebSocketCodec::ValidateServerHandshake(
                    response,
                    clientKey,
                    clientKeyLength,
                    requestedSubprotocol,
                    requestedSubprotocolLength,
                    &selectedSubprotocol,
                    &perMessageDeflate,
                    &perMessageDeflate_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = StoreSelectedSubprotocol(selectedSubprotocol);
                if (NT_SUCCESS(status) && perMessageDeflate_.Enabled) {
                    status = receiveDeflate_.Initialize(perMessageDeflate_.ServerMaxWindowBits);
                }
                if (!NT_SUCCESS(status)) {
                    response = {};
                    return status;
                }

                if (response.BytesConsumed > responseLength) {
                    response = {};
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T upgradedBytes = responseLength - response.BytesConsumed;
                if (upgradedBytes != 0) {
                    if (buffers.FrameBuffer == nullptr || buffers.FrameBufferLength < upgradedBytes) {
                        response = {};
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    status = EnsureBufferedFrameCapacity(buffers.FrameBufferLength);
                    if (!NT_SUCCESS(status)) {
                        response = {};
                        return status;
                    }

                    // Bytes after the 101 header already belong to the WebSocket stream.
                    RtlMoveMemory(
                        bufferedFrame_,
                        buffers.ResponseBuffer + response.BytesConsumed,
                        upgradedBytes);
                    bufferedFrameLength_ = upgradedBytes;
                }

                return STATUS_SUCCESS;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                response = {};
                return status;
            }

            if (responseLength >= buffers.ResponseBufferLength) {
                response = {};
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T received = 0;
            status = ReceiveRaw(
                buffers.ResponseBuffer + responseLength,
                buffers.ResponseBufferLength - responseLength,
                &received);
            if (!NT_SUCCESS(status)) {
                response = {};
                return status;
            }
            if (received == 0) {
                response = {};
                return STATUS_CONNECTION_DISCONNECTED;
            }

            responseLength += received;
        }
    }
}
}
