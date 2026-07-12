#include "http1/HttpParser.h"

#include <wknet/WknetConfig.h>
#include "http1/HttpContentEncoding.h"
#include "http1/HttpTransferCoding.h"

namespace wknet
{
namespace http1
{
    namespace
    {
        constexpr SIZE_T InvalidOffset = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));

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

        UCHAR HexValue(char value) noexcept
        {
            if (value >= '0' && value <= '9') {
                return static_cast<UCHAR>(value - '0');
            }

            if (value >= 'a' && value <= 'f') {
                return static_cast<UCHAR>(10 + value - 'a');
            }

            return static_cast<UCHAR>(10 + value - 'A');
        }

        bool IsOptionalWhitespace(char value) noexcept
        {
            return value == ' ' || value == '\t';
        }

        bool ContainsChar(const char* text, SIZE_T textLength, char needle) noexcept
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

        bool IsTchar(char value) noexcept
        {
            const unsigned char ch = static_cast<unsigned char>(value);
            return (ch >= '0' && ch <= '9') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= 'a' && ch <= 'z') ||
                value == '!' ||
                value == '#' ||
                value == '$' ||
                value == '%' ||
                value == '&' ||
                value == '\'' ||
                value == '*' ||
                value == '+' ||
                value == '-' ||
                value == '.' ||
                value == '^' ||
                value == '_' ||
                value == '`' ||
                value == '|' ||
                value == '~';
        }

        bool IsQuotedPairText(char value) noexcept
        {
            const unsigned char ch = static_cast<unsigned char>(value);
            return value == '\t' || (ch >= 0x20 && ch <= 0x7e);
        }

        bool IsValidHeaderName(HttpText text) noexcept
        {
            if (text.Data == nullptr || text.Length == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < text.Length; ++index) {
                if (!IsTchar(text.Data[index])) {
                    return false;
                }
            }

            return true;
        }

        bool IsValidHeaderValue(HttpText text) noexcept
        {
            if (text.Data == nullptr && text.Length != 0) {
                return false;
            }

            for (SIZE_T index = 0; index < text.Length; ++index) {
                const unsigned char ch = static_cast<unsigned char>(text.Data[index]);
                if (text.Data[index] != '\t' && (ch < 0x20 || ch == 0x7f)) {
                    return false;
                }
            }

            return true;
        }

        bool IsValidToken(HttpText text) noexcept
        {
            if (text.Data == nullptr || text.Length == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < text.Length; ++index) {
                if (!IsTchar(text.Data[index])) {
                    return false;
                }
            }

            return true;
        }

        HttpText TrimOptionalWhitespace(HttpText text) noexcept;

        _Must_inspect_result_
        NTSTATUS ValidateSemicolonParameters(HttpText parameters) noexcept
        {
            SIZE_T cursor = 0;
            while (cursor < parameters.Length) {
                if (parameters.Data[cursor] != ';') {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                ++cursor;
                while (cursor < parameters.Length && IsOptionalWhitespace(parameters.Data[cursor])) {
                    ++cursor;
                }

                const SIZE_T nameStart = cursor;
                while (cursor < parameters.Length && IsTchar(parameters.Data[cursor])) {
                    ++cursor;
                }

                if (cursor == nameStart) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                HttpText name = { parameters.Data + nameStart, cursor - nameStart };
                if (!IsValidToken(name)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                while (cursor < parameters.Length && IsOptionalWhitespace(parameters.Data[cursor])) {
                    ++cursor;
                }

                if (cursor == parameters.Length || parameters.Data[cursor] == ';') {
                    continue;
                }

                if (parameters.Data[cursor] != '=') {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                ++cursor;
                while (cursor < parameters.Length && IsOptionalWhitespace(parameters.Data[cursor])) {
                    ++cursor;
                }

                if (cursor == parameters.Length) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (parameters.Data[cursor] == '"') {
                    ++cursor;
                    bool closed = false;
                    while (cursor < parameters.Length) {
                        const char value = parameters.Data[cursor];
                        if (value == '"') {
                            ++cursor;
                            closed = true;
                            break;
                        }

                        if (value == '\\') {
                            ++cursor;
                            if (cursor == parameters.Length || !IsQuotedPairText(parameters.Data[cursor])) {
                                return STATUS_INVALID_NETWORK_RESPONSE;
                            }
                            ++cursor;
                            continue;
                        }

                        const unsigned char ch = static_cast<unsigned char>(value);
                        if (value != '\t' && ch < 0x20) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }

                        ++cursor;
                    }

                    if (!closed) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
                else {
                    const SIZE_T valueStart = cursor;
                    while (cursor < parameters.Length && IsTchar(parameters.Data[cursor])) {
                        ++cursor;
                    }

                    if (cursor == valueStart) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }

                while (cursor < parameters.Length && IsOptionalWhitespace(parameters.Data[cursor])) {
                    ++cursor;
                }

                if (cursor < parameters.Length && parameters.Data[cursor] != ';') {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            return STATUS_SUCCESS;
        }

        bool IsForbiddenTrailerField(HttpText name) noexcept
        {
            return TextEqualsIgnoreCase(name, MakeText("Content-Length")) ||
                TextEqualsIgnoreCase(name, MakeText("Transfer-Encoding")) ||
                TextEqualsIgnoreCase(name, MakeText("Host")) ||
                TextEqualsIgnoreCase(name, MakeText("Authorization")) ||
                TextEqualsIgnoreCase(name, MakeText("Proxy-Authorization")) ||
                TextEqualsIgnoreCase(name, MakeText("Cookie")) ||
                TextEqualsIgnoreCase(name, MakeText("Set-Cookie"));
        }

        _Must_inspect_result_
        NTSTATUS ParseTrailerFieldLine(
            const char* data,
            SIZE_T lineStart,
            SIZE_T lineEnd,
            HttpHeader* trailer) noexcept
        {
            if (data == nullptr || lineEnd <= lineStart) {
                return STATUS_INVALID_PARAMETER;
            }

            if (data[lineStart] == ' ' || data[lineStart] == '\t') {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T colon = InvalidOffset;
            for (SIZE_T index = lineStart; index < lineEnd; ++index) {
                if (data[index] == ':') {
                    colon = index;
                    break;
                }
            }

            if (colon == InvalidOffset || colon == lineStart) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const HttpText name = { data + lineStart, colon - lineStart };
            HttpText value = { data + colon + 1, lineEnd - colon - 1 };
            value = TrimOptionalWhitespace(value);

            if (!IsValidHeaderName(name) ||
                !IsValidHeaderValue(value) ||
                IsForbiddenTrailerField(name)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (trailer != nullptr) {
                trailer->Name = name;
                trailer->Value = value;
            }

            return STATUS_SUCCESS;
        }

        HttpText TrimOptionalWhitespace(HttpText text) noexcept
        {
            while (text.Length > 0 && IsOptionalWhitespace(text.Data[0])) {
                ++text.Data;
                --text.Length;
            }

            while (text.Length > 0 && IsOptionalWhitespace(text.Data[text.Length - 1])) {
                --text.Length;
            }

            return text;
        }

        bool StartsWith(HttpText text, HttpText prefix) noexcept
        {
            if (text.Data == nullptr || prefix.Data == nullptr || text.Length < prefix.Length) {
                return false;
            }

            for (SIZE_T index = 0; index < prefix.Length; ++index) {
                if (text.Data[index] != prefix.Data[index]) {
                    return false;
                }
            }

            return true;
        }

        SIZE_T FindCrlf(const char* data, SIZE_T dataLength, SIZE_T start) noexcept
        {
            if (data == nullptr || start >= dataLength) {
                return InvalidOffset;
            }

            for (SIZE_T index = start; index + 1 < dataLength; ++index) {
                if (data[index] == '\r' && data[index + 1] == '\n') {
                    return index;
                }
            }

            return InvalidOffset;
        }

        SIZE_T FindHeaderEnd(const char* data, SIZE_T dataLength) noexcept
        {
            if (data == nullptr || dataLength < 4) {
                return InvalidOffset;
            }

            for (SIZE_T index = 0; index + 3 < dataLength; ++index) {
                if (data[index] == '\r' &&
                    data[index + 1] == '\n' &&
                    data[index + 2] == '\r' &&
                    data[index + 3] == '\n') {
                    return index + 4;
                }
            }

            return InvalidOffset;
        }

        _Must_inspect_result_
        NTSTATUS ParseUInt16(HttpText text, USHORT* value) noexcept
        {
            if (text.Data == nullptr || text.Length == 0 || value == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            ULONG parsed = 0;
            for (SIZE_T index = 0; index < text.Length; ++index) {
                if (!IsDigit(text.Data[index])) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                parsed = (parsed * 10) + static_cast<ULONG>(text.Data[index] - '0');
                if (parsed > 0xFFFF) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }

            *value = static_cast<USHORT>(parsed);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseSize(HttpText text, SIZE_T* value) noexcept
        {
            if (text.Data == nullptr || text.Length == 0 || value == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T parsed = 0;
            for (SIZE_T index = 0; index < text.Length; ++index) {
                if (!IsDigit(text.Data[index])) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T digit = static_cast<SIZE_T>(text.Data[index] - '0');
                if (parsed > ((static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - digit) / 10)) {
                    return STATUS_INTEGER_OVERFLOW;
                }

                parsed = (parsed * 10) + digit;
            }

            *value = parsed;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseHexSize(HttpText text, SIZE_T* value) noexcept
        {
            if (text.Data == nullptr || text.Length == 0 || value == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T parsed = 0;
            for (SIZE_T index = 0; index < text.Length; ++index) {
                if (!IsHexDigit(text.Data[index])) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T digit = HexValue(text.Data[index]);
                if (parsed > ((static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - digit) / 16)) {
                    return STATUS_INTEGER_OVERFLOW;
                }

                parsed = (parsed * 16) + digit;
            }

            *value = parsed;
            return STATUS_SUCCESS;
        }

        bool StatusCodeHasNoBody(USHORT statusCode) noexcept
        {
            return ((statusCode >= 100 && statusCode <= 199) ||
                statusCode == 204 ||
                statusCode == 205 ||
                statusCode == 304);
        }

        _Must_inspect_result_
        NTSTATUS ParseStatusLine(HttpText line, HttpResponse& response) noexcept
        {
            if (!StartsWith(line, MakeText("HTTP/"))) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T index = 5;
            const SIZE_T majorStart = index;
            while (index < line.Length && IsDigit(line.Data[index])) {
                ++index;
            }

            if (index == majorStart || index >= line.Length || line.Data[index] != '.') {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            NTSTATUS status = ParseUInt16({ line.Data + majorStart, index - majorStart }, &response.MajorVersion);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            ++index;
            const SIZE_T minorStart = index;
            while (index < line.Length && IsDigit(line.Data[index])) {
                ++index;
            }

            if (index == minorStart || index >= line.Length || line.Data[index] != ' ') {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = ParseUInt16({ line.Data + minorStart, index - minorStart }, &response.MinorVersion);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (response.MajorVersion != 1 || response.MinorVersion > 1) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            while (index < line.Length && line.Data[index] == ' ') {
                ++index;
            }

            if (index + 3 > line.Length ||
                !IsDigit(line.Data[index]) ||
                !IsDigit(line.Data[index + 1]) ||
                !IsDigit(line.Data[index + 2])) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = ParseUInt16({ line.Data + index, 3 }, &response.StatusCode);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (response.StatusCode < 100 || response.StatusCode > 599) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            index += 3;
            if (index < line.Length) {
                if (line.Data[index] != ' ') {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                ++index;
                response.ReasonPhrase = { line.Data + index, line.Length - index };
            }
            else {
                response.ReasonPhrase = {};
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseHeaders(
            const char* data,
            SIZE_T dataLength,
            SIZE_T headerStart,
            SIZE_T headerEnd,
            HttpHeader* headers,
            SIZE_T headerCapacity,
            SIZE_T* headerCount) noexcept
        {
            if (data == nullptr || headerCount == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *headerCount = 0;
            SIZE_T cursor = headerStart;
            if (headerEnd < headerStart || headerEnd - headerStart > KhHttpMaxHeaderBytes) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            while (cursor < headerEnd - 2) {
                const SIZE_T lineEnd = FindCrlf(data, dataLength, cursor);
                if (lineEnd == InvalidOffset || lineEnd > headerEnd) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (lineEnd - cursor > KhHttpMaxHeaderLineBytes) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (lineEnd == cursor) {
                    cursor += 2;
                    break;
                }

                if (data[cursor] == ' ' || data[cursor] == '\t') {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                SIZE_T colon = InvalidOffset;
                for (SIZE_T index = cursor; index < lineEnd; ++index) {
                    if (data[index] == ':') {
                        colon = index;
                        break;
                    }
                }

                if (colon == InvalidOffset || colon == cursor) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (*headerCount >= KhHttpMaxHeaders ||
                    *headerCount >= headerCapacity ||
                    headers == nullptr) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                HttpText name = { data + cursor, colon - cursor };
                HttpText value = { data + colon + 1, lineEnd - colon - 1 };
                value = TrimOptionalWhitespace(value);

                if (!IsValidHeaderName(name) || !IsValidHeaderValue(value)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                headers[*headerCount] = { name, value };
                ++(*headerCount);

                cursor = lineEnd + 2;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadContentLength(const HttpResponse& response, bool* found, SIZE_T* contentLength) noexcept
        {
            if (found == nullptr || contentLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *found = false;
            *contentLength = 0;

            for (SIZE_T index = 0; index < response.HeaderCount; ++index) {
                if (!TextEqualsIgnoreCase(response.Headers[index].Name, MakeText("Content-Length"))) {
                    continue;
                }

                SIZE_T parsed = 0;
                HttpText value = TrimOptionalWhitespace(response.Headers[index].Value);
                if (value.Length == 0 ||
                    ContainsChar(value.Data, value.Length, ',')) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (*found) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                NTSTATUS status = ParseSize(value, &parsed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                *found = true;
                *contentLength = parsed;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS CopyChunkData(
            const char* source,
            SIZE_T chunkSize,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* destinationLength) noexcept
        {
            if (source == nullptr || destinationLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (chunkSize == 0) {
                return STATUS_SUCCESS;
            }

            if (destination == nullptr || *destinationLength > destinationCapacity ||
                chunkSize > (destinationCapacity - *destinationLength)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            for (SIZE_T index = 0; index < chunkSize; ++index) {
                destination[*destinationLength + index] = source[index];
            }

            *destinationLength += chunkSize;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ApplyContentEncoding(
            const HttpParseOptions& options,
            HttpResponse& response,
            const char* body,
            SIZE_T bodyLength) noexcept
        {
            if (bodyLength == 0) {
                response.Body = nullptr;
                response.BodyLength = 0;
                return STATUS_SUCCESS;
            }

            HttpContentDecodeBuffers buffers = {};
            buffers.DecodedBody = options.DecodedBody;
            buffers.DecodedBodyCapacity = options.DecodedBodyCapacity;
            buffers.ScratchBody = options.ScratchBody;
            buffers.ScratchBodyCapacity = options.ScratchBodyCapacity;
            buffers.Materials = options.ContentCodingMaterials;

            HttpContentDecodeResult decoded = {};
            NTSTATUS status = HttpContentEncoding::Decode(
                response.Headers,
                response.HeaderCount,
                body,
                bodyLength,
                buffers,
                decoded,
                options.AcceptEncodingPolicy);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            response.Body = decoded.BodyLength == 0 ? nullptr : decoded.Body;
            response.BodyLength = decoded.BodyLength;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS HttpParser::ParseResponse(
        const char* data,
        SIZE_T dataLength,
        const HttpParseOptions& options,
        HttpResponse& response) noexcept
    {
        response = {};

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength == 0) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        const SIZE_T headerEnd = FindHeaderEnd(data, dataLength);
        if (headerEnd == InvalidOffset) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }
        if (headerEnd > KhHttpMaxHeaderBytes) {
            response = {};
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T statusLineEnd = FindCrlf(data, dataLength, 0);
        if (statusLineEnd == InvalidOffset || statusLineEnd + 2 > headerEnd) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        NTSTATUS status = ParseStatusLine({ data, statusLineEnd }, response);
        if (!NT_SUCCESS(status)) {
            response = {};
            return status;
        }

        SIZE_T headerCount = 0;
        status = ParseHeaders(
            data,
            dataLength,
            statusLineEnd + 2,
            headerEnd,
            options.Headers,
            options.HeaderCapacity,
            &headerCount);

        if (!NT_SUCCESS(status)) {
            response = {};
            return status;
        }

        response.Headers = options.Headers;
        response.HeaderCount = headerCount;
        response.Trailers = options.Trailers;
        response.TrailerCount = 0;

        if (options.ResponseBodyForbidden || StatusCodeHasNoBody(response.StatusCode)) {
            response.BodyKind = HttpBodyKind::None;
            response.Body = nullptr;
            response.BodyLength = 0;
            response.BytesConsumed = headerEnd;
            return STATUS_SUCCESS;
        }

        HttpTransferCodingInfo transferInfo = {};
        status = HttpTransferCoding::Parse(response.Headers, response.HeaderCount, transferInfo);
        if (!NT_SUCCESS(status)) {
            response = {};
            return status;
        }

        if (transferInfo.HasTransferEncoding &&
            (response.MajorVersion < 1 ||
                (response.MajorVersion == 1 && response.MinorVersion < 1))) {
            response = {};
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        bool hasContentLength = false;
        SIZE_T contentLength = 0;
        status = ReadContentLength(response, &hasContentLength, &contentLength);
        if (!NT_SUCCESS(status)) {
            response = {};
            return status;
        }

        if (transferInfo.HasTransferEncoding) {
            if (hasContentLength) {
                response = {};
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            HttpCodingDecodeBuffers buffers = {};
            buffers.DecodedBody = options.DecodedBody;
            buffers.DecodedBodyCapacity = options.DecodedBodyCapacity;
            buffers.ScratchBody = options.ScratchBody;
            buffers.ScratchBodyCapacity = options.ScratchBodyCapacity;

            HttpTransferDecodeResult decoded = {};
            SIZE_T trailerCount = 0;
            status = HttpTransferCoding::DecodeResponseBody(
                transferInfo,
                data + headerEnd,
                dataLength - headerEnd,
                options.MessageCompleteOnConnectionClose,
                buffers,
                options.Trailers,
                options.TrailerCapacity,
                &trailerCount,
                decoded);
            if (!NT_SUCCESS(status)) {
                response = {};
                return status;
            }

            response.BodyKind = decoded.BodyKind;
            response.Trailers = options.Trailers;
            response.TrailerCount = options.Trailers != nullptr ? trailerCount : 0;
            response.BodyEndsOnConnectionClose =
                transferInfo.HasTransferEncoding &&
                !transferInfo.FinalCodingIsChunked &&
                options.MessageCompleteOnConnectionClose;
            response.BytesConsumed = headerEnd + decoded.BytesConsumed;
            status = ApplyContentEncoding(options, response, decoded.Body, decoded.BodyLength);
            if (!NT_SUCCESS(status)) {
                response = {};
                return status;
            }

            return STATUS_SUCCESS;
        }

        if (hasContentLength) {
            if (contentLength > (dataLength - headerEnd)) {
                response = {};
                return STATUS_MORE_PROCESSING_REQUIRED;
            }

            response.BodyKind = contentLength == 0 ? HttpBodyKind::None : HttpBodyKind::ContentLength;
            response.BytesConsumed = headerEnd + contentLength;
            status = ApplyContentEncoding(
                options,
                response,
                contentLength == 0 ? nullptr : data + headerEnd,
                contentLength);
            if (!NT_SUCCESS(status)) {
                response = {};
                return status;
            }

            return STATUS_SUCCESS;
        }

        if (options.MessageCompleteOnConnectionClose) {
            response.BodyKind = (dataLength == headerEnd) ? HttpBodyKind::None : HttpBodyKind::CloseDelimited;
            response.BodyEndsOnConnectionClose = true;
            response.BytesConsumed = dataLength;
            status = ApplyContentEncoding(
                options,
                response,
                (dataLength == headerEnd) ? nullptr : data + headerEnd,
                dataLength - headerEnd);
            if (!NT_SUCCESS(status)) {
                response = {};
                return status;
            }

            return STATUS_SUCCESS;
        }

        response = {};
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    NTSTATUS HttpParser::DecodeChunkedBodyWithTrailers(
        const char* data,
        SIZE_T dataLength,
        char* decodedBody,
        SIZE_T decodedBodyCapacity,
        HttpHeader* trailers,
        SIZE_T trailerCapacity,
        SIZE_T* decodedBodyLength,
        SIZE_T* bytesConsumed,
        SIZE_T* trailerCount) noexcept
    {
        if (decodedBodyLength == nullptr || bytesConsumed == nullptr ||
            trailerCount == nullptr ||
            (decodedBody == nullptr && decodedBodyCapacity != 0) ||
            (trailers == nullptr && trailerCapacity != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        *decodedBodyLength = 0;
        *bytesConsumed = 0;
        *trailerCount = 0;

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T cursor = 0;
        SIZE_T chunkCount = 0;

        for (;;) {
            const SIZE_T chunkLineEnd = FindCrlf(data, dataLength, cursor);
            if (chunkLineEnd == InvalidOffset) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }
            if (chunkLineEnd - cursor > KhHttpMaxChunkSizeLineBytes) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T chunkSizeEnd = chunkLineEnd;
            for (SIZE_T index = cursor; index < chunkLineEnd; ++index) {
                if (data[index] == ';') {
                    chunkSizeEnd = index;
                    break;
                }
            }

            if (chunkSizeEnd != chunkLineEnd) {
                const NTSTATUS extensionStatus = ValidateSemicolonParameters({
                    data + chunkSizeEnd,
                    chunkLineEnd - chunkSizeEnd
                });
                if (!NT_SUCCESS(extensionStatus)) {
                    return extensionStatus;
                }
            }

            HttpText chunkSizeText = { data + cursor, chunkSizeEnd - cursor };
            chunkSizeText = TrimOptionalWhitespace(chunkSizeText);
            if (chunkSizeText.Length == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T chunkSize = 0;
            NTSTATUS status = ParseHexSize(chunkSizeText, &chunkSize);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            cursor = chunkLineEnd + 2;

            if (chunkSize == 0) {
                for (;;) {
                    const SIZE_T trailerLineEnd = FindCrlf(data, dataLength, cursor);
                    if (trailerLineEnd == InvalidOffset) {
                        return STATUS_MORE_PROCESSING_REQUIRED;
                    }
                    if (trailerLineEnd - cursor > KhHttpMaxHeaderLineBytes) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    if (trailerLineEnd == cursor) {
                        *bytesConsumed = cursor + 2;
                        return STATUS_SUCCESS;
                    }

                    HttpHeader* targetTrailer = nullptr;
                    if (*trailerCount >= KhHttpMaxTrailers) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (trailers != nullptr) {
                        if (*trailerCount >= trailerCapacity) {
                            return STATUS_BUFFER_TOO_SMALL;
                        }
                        targetTrailer = &trailers[*trailerCount];
                    }

                    const NTSTATUS trailerStatus = ParseTrailerFieldLine(
                        data,
                        cursor,
                        trailerLineEnd,
                        targetTrailer);
                    if (!NT_SUCCESS(trailerStatus)) {
                        return trailerStatus;
                    }

                    ++(*trailerCount);
                    cursor = trailerLineEnd + 2;
                }
            }

            if (++chunkCount > KhHttpMaxChunks) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (chunkSize > (dataLength - cursor)) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }

            status = CopyChunkData(
                data + cursor,
                chunkSize,
                decodedBody,
                decodedBodyCapacity,
                decodedBodyLength);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            cursor += chunkSize;

            if (cursor + 2 > dataLength) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }

            if (data[cursor] != '\r' || data[cursor + 1] != '\n') {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            cursor += 2;
        }
    }

    NTSTATUS HttpParser::DecodeChunkedBody(
        const char* data,
        SIZE_T dataLength,
        char* decodedBody,
        SIZE_T decodedBodyCapacity,
        SIZE_T* decodedBodyLength,
        SIZE_T* bytesConsumed) noexcept
    {
        SIZE_T trailerCount = 0;
        return DecodeChunkedBodyWithTrailers(
            data,
            dataLength,
            decodedBody,
            decodedBodyCapacity,
            nullptr,
            0,
            decodedBodyLength,
            bytesConsumed,
            &trailerCount);
    }
}
}
