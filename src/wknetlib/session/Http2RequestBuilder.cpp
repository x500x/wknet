#include "session/Http2RequestBuilder.h"

namespace wknet
{
namespace session
{
    namespace
    {
        const char* HttpMethodToString(http1::HttpMethod method) noexcept
        {
            switch (method) {
            case http1::HttpMethod::Get: return "GET";
            case http1::HttpMethod::Post: return "POST";
            case http1::HttpMethod::Put: return "PUT";
            case http1::HttpMethod::Patch: return "PATCH";
            case http1::HttpMethod::DeleteMethod: return "DELETE";
            case http1::HttpMethod::Head: return "HEAD";
            case http1::HttpMethod::Options: return "OPTIONS";
            case http1::HttpMethod::Connect: return "CONNECT";
            case http1::HttpMethod::Trace: return "TRACE";
            default: return "GET";
            }
        }

        SIZE_T StringLength(_In_opt_z_ const char* text) noexcept
        {
            SIZE_T length = 0;
            if (text == nullptr) {
                return 0;
            }
            while (text[length] != '\0') {
                ++length;
            }
            return length;
        }

        bool TextEqualsIgnoreCase(http1::HttpText text, _In_z_ const char* literal) noexcept
        {
            const SIZE_T literalLength = StringLength(literal);
            if (text.Data == nullptr || text.Length != literalLength) {
                return false;
            }
            for (SIZE_T index = 0; index < literalLength; ++index) {
                char left = text.Data[index];
                char right = literal[index];
                if (left >= 'A' && left <= 'Z') left = static_cast<char>(left + 32);
                if (right >= 'A' && right <= 'Z') right = static_cast<char>(right + 32);
                if (left != right) return false;
            }
            return true;
        }

        bool IsForbiddenHttp2Header(http1::HttpText name) noexcept
        {
            return TextEqualsIgnoreCase(name, "connection") ||
                TextEqualsIgnoreCase(name, "keep-alive") ||
                TextEqualsIgnoreCase(name, "proxy-connection") ||
                TextEqualsIgnoreCase(name, "transfer-encoding") ||
                TextEqualsIgnoreCase(name, "upgrade") ||
                TextEqualsIgnoreCase(name, "host");
        }

        bool IsValidHttpHeaderInputName(http1::HttpText name) noexcept
        {
            if (name.Data == nullptr || name.Length == 0 ||
                name.Length > Http2MaxHeaderNameLength || name.Data[0] == ':') {
                return false;
            }
            for (SIZE_T index = 0; index < name.Length; ++index) {
                const UCHAR value = static_cast<UCHAR>(name.Data[index]);
                if (value <= 0x20 || value >= 0x7f || value == ':') {
                    return false;
                }
            }
            return true;
        }

        bool IsValidHttp2FieldValue(http1::HttpText value) noexcept
        {
            if (value.Data == nullptr) {
                return value.Length == 0;
            }
            if (value.Length == 0) {
                return true;
            }
            if (value.Data[0] == ' ' || value.Data[0] == '\t' ||
                value.Data[value.Length - 1] == ' ' || value.Data[value.Length - 1] == '\t') {
                return false;
            }
            for (SIZE_T index = 0; index < value.Length; ++index) {
                if (value.Data[index] == '\0' || value.Data[index] == '\r' || value.Data[index] == '\n') {
                    return false;
                }
            }
            return true;
        }

        bool LowercaseHeaderName(
            http1::HttpText name,
            _Out_writes_(capacity) char* output,
            SIZE_T capacity,
            _Out_ http1::HttpText& lowered) noexcept
        {
            if (!IsValidHttpHeaderInputName(name) || output == nullptr || name.Length > capacity) {
                return false;
            }
            for (SIZE_T index = 0; index < name.Length; ++index) {
                char value = name.Data[index];
                if (value >= 'A' && value <= 'Z') value = static_cast<char>(value + 32);
                output[index] = value;
            }
            lowered = { output, name.Length };
            return true;
        }

        bool WriteDecimal(
            SIZE_T value,
            _Out_writes_(capacity) char* output,
            SIZE_T capacity,
            _Out_ http1::HttpText& text) noexcept
        {
            if (output == nullptr || capacity == 0) {
                return false;
            }
            SIZE_T divisor = 1;
            while ((value / divisor) >= 10) {
                divisor *= 10;
            }
            SIZE_T length = 0;
            for (SIZE_T current = divisor; current != 0; current /= 10) {
                if (length >= capacity) {
                    return false;
                }
                output[length++] = static_cast<char>('0' + ((value / current) % 10));
            }
            text = { output, length };
            return true;
        }

        bool GetAuthority(const Http2RequestOptions& options, _Out_ http1::HttpText& authority) noexcept
        {
            if (options.Authority.Data != nullptr && options.Authority.Length != 0) {
                authority = options.Authority;
                return true;
            }
            if (options.ServerName != nullptr && options.ServerNameLength != 0) {
                authority = { options.ServerName, options.ServerNameLength };
                return true;
            }
            authority = {};
            return false;
        }
    }

    NTSTATUS BuildHttp2RequestHeaders(
        const Http2RequestOptions& options,
        http1::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength],
        char* contentLengthBuffer,
        SIZE_T* headerCount) noexcept
    {
        // Capacity is runtime-sized; require enough slots for reserved pseudo/promoted
        // headers plus caller extras, and never exceed the protocol hard max.
        const SIZE_T estimated =
            Http2ReservedHeaderSlots + options.ExtraHeaderCount;
        if (requestHeaders == nullptr || lowerHeaderNames == nullptr ||
            contentLengthBuffer == nullptr || headerCount == nullptr ||
            headerCapacity == 0 ||
            headerCapacity > Http2MaxRequestHeaders ||
            estimated > headerCapacity ||
            (options.ExtraHeaders == nullptr && options.ExtraHeaderCount != 0) ||
            (options.Body != nullptr && options.BodySource != nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }

        http1::HttpText authority = {};
        if (!GetAuthority(options, authority) ||
            !IsValidHttp2FieldValue(options.Path) ||
            !IsValidHttp2FieldValue(authority) ||
            !IsValidHttp2FieldValue(options.UserAgent) ||
            !IsValidHttp2FieldValue(options.ContentType) ||
            !IsValidHttp2FieldValue(options.AcceptEncoding) ||
            !IsValidHttp2FieldValue(options.ConnectProtocol)) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool extendedConnect = options.ConnectProtocol.Data != nullptr && options.ConnectProtocol.Length != 0;
        if (extendedConnect && options.Method != http1::HttpMethod::Connect) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T index = 0;
        const char* method = HttpMethodToString(options.Method);
        requestHeaders[index++] = { { ":method", 7 }, { method, StringLength(method) } };
        requestHeaders[index++] = {
            { ":scheme", 7 },
            options.TransportMode == Http2TransportMode::TlsAlpn ? http1::HttpText{ "https", 5 } : http1::HttpText{ "http", 4 }
        };
        requestHeaders[index++] = { { ":path", 5 }, options.Path };
        requestHeaders[index++] = { { ":authority", 10 }, authority };
        if (extendedConnect) requestHeaders[index++] = { { ":protocol", 9 }, options.ConnectProtocol };
        if (options.UserAgent.Data != nullptr && options.UserAgent.Length != 0) requestHeaders[index++] = { { "user-agent", 10 }, options.UserAgent };
        if (options.ContentType.Data != nullptr && options.ContentType.Length != 0) requestHeaders[index++] = { { "content-type", 12 }, options.ContentType };

        const bool sourceContentLength = options.BodySource != nullptr && options.BodySource->ContentLengthKnown;
        const SIZE_T contentLength = sourceContentLength ? options.BodySource->ContentLength : options.BodyLength;
        if ((options.Body != nullptr && options.BodyLength != 0) || sourceContentLength || options.IncludeContentLength) {
            requestHeaders[index].Name = { "content-length", 14 };
            if (!WriteDecimal(contentLength, contentLengthBuffer, Http2ContentLengthBufferLength, requestHeaders[index].Value)) {
                return STATUS_INVALID_PARAMETER;
            }
            ++index;
        }
        if (options.AcceptEncoding.Data != nullptr && options.AcceptEncoding.Length != 0) {
            requestHeaders[index++] = { { "accept-encoding", 15 }, options.AcceptEncoding };
        }

        const bool acceptEncodingPromoted = options.AcceptEncoding.Data != nullptr && options.AcceptEncoding.Length != 0;
        for (SIZE_T extraIndex = 0; extraIndex < options.ExtraHeaderCount; ++extraIndex) {
            if (index >= headerCapacity) {
                return STATUS_INVALID_PARAMETER;
            }
            const http1::HttpHeader& extra = options.ExtraHeaders[extraIndex];
            if ((TextEqualsIgnoreCase(extra.Name, "te") && !TextEqualsIgnoreCase(extra.Value, "trailers")) ||
                !IsValidHttp2FieldValue(extra.Value) || IsForbiddenHttp2Header(extra.Name) ||
                extra.Name.Data == nullptr || extra.Name.Length == 0 || extra.Name.Data[0] == ':') {
                return STATUS_INVALID_PARAMETER;
            }
            if (acceptEncodingPromoted && TextEqualsIgnoreCase(extra.Name, "accept-encoding")) {
                continue;
            }
            requestHeaders[index].Value = extra.Value;
            if (!LowercaseHeaderName(extra.Name, lowerHeaderNames[index], Http2MaxHeaderNameLength, requestHeaders[index].Name)) {
                return STATUS_INVALID_PARAMETER;
            }
            ++index;
        }

        *headerCount = index;
        return STATUS_SUCCESS;
    }
}
}
