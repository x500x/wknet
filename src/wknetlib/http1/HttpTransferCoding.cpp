#include "http1/HttpTransferCoding.h"

#include "http1/HttpParser.h"

namespace wknet
{
namespace http1
{
    namespace
    {
        bool IsOptionalWhitespace(char value) noexcept
        {
            return value == ' ' || value == '\t';
        }

        bool IsAlpha(char value) noexcept
        {
            return (value >= 'a' && value <= 'z') ||
                (value >= 'A' && value <= 'Z');
        }

        bool IsDigit(char value) noexcept
        {
            return value >= '0' && value <= '9';
        }

        bool IsTchar(char value) noexcept
        {
            return IsAlpha(value) ||
                IsDigit(value) ||
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

        _Must_inspect_result_
        bool IsValidToken(HttpText token) noexcept
        {
            if (token.Data == nullptr || token.Length == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < token.Length; ++index) {
                if (!IsTchar(token.Data[index])) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool TransferCodingToCodecCoding(HttpTransferCodingKind transferCoding, codec::Coding* coding) noexcept
        {
            if (coding == nullptr) {
                return false;
            }

            switch (transferCoding) {
            case HttpTransferCodingKind::Gzip:
                *coding = codec::Coding::Gzip;
                return true;
            case HttpTransferCodingKind::Deflate:
                *coding = codec::Coding::Deflate;
                return true;
            case HttpTransferCodingKind::Compress:
                *coding = codec::Coding::Compress;
                return true;
            default:
                return false;
            }
        }

        void CopyBytes(char* destination, const char* source, SIZE_T length) noexcept
        {
            for (SIZE_T index = 0; index < length; ++index) {
                destination[index] = source[index];
            }
        }

        void SelectDestination(
            const char* current,
            const codec::DecodeBuffers& buffers,
            char** destination,
            SIZE_T* destinationCapacity) noexcept
        {
            if (destination == nullptr || destinationCapacity == nullptr) {
                return;
            }

            *destination = nullptr;
            *destinationCapacity = 0;

            if (buffers.DecodedBody != nullptr && current != buffers.DecodedBody) {
                *destination = buffers.DecodedBody;
                *destinationCapacity = buffers.DecodedBodyCapacity;
                return;
            }

            if (buffers.ScratchBody != nullptr && current != buffers.ScratchBody) {
                *destination = buffers.ScratchBody;
                *destinationCapacity = buffers.ScratchBodyCapacity;
                return;
            }
        }

        _Must_inspect_result_
        HttpTransferCodingKind GetTransferCoding(
            const HttpTransferCodingInfo& info,
            SIZE_T index) noexcept
        {
            switch (index) {
            case 0:
                return info.Coding0;
            case 1:
                return info.Coding1;
            case 2:
                return info.Coding2;
            default:
                return info.Coding3;
            }
        }

        void SetTransferCoding(
            HttpTransferCodingInfo& info,
            SIZE_T index,
            HttpTransferCodingKind coding) noexcept
        {
            switch (index) {
            case 0:
                info.Coding0 = coding;
                return;
            case 1:
                info.Coding1 = coding;
                return;
            case 2:
                info.Coding2 = coding;
                return;
            default:
                info.Coding3 = coding;
                return;
            }
        }

        _Must_inspect_result_
        NTSTATUS AppendTransferCoding(
            HttpTransferCodingKind coding,
            HttpTransferCodingInfo& info) noexcept
        {
            if (info.CodingCount >= HttpMaxTransferCodings) {
                return STATUS_NOT_SUPPORTED;
            }

            if (coding == HttpTransferCodingKind::Chunked) {
                for (SIZE_T index = 0; index < info.CodingCount; ++index) {
                    if (GetTransferCoding(info, index) == HttpTransferCodingKind::Chunked) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
            }

            SetTransferCoding(info, info.CodingCount, coding);
            ++info.CodingCount;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseTransferCodingToken(
            HttpText member,
            HttpTransferCodingKind* coding,
            bool* hasCoding) noexcept
        {
            if (coding == nullptr || hasCoding == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *hasCoding = false;
            member = TrimOptionalWhitespace(member);
            if (member.Length == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T parameterStart = member.Length;
            for (SIZE_T index = 0; index < member.Length; ++index) {
                if (member.Data[index] == ';') {
                    parameterStart = index;
                    break;
                }
            }

            HttpText token = { member.Data, parameterStart };
            token = TrimOptionalWhitespace(token);
            if (!IsValidToken(token)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (TextEqualsIgnoreCase(token, MakeText("identity"))) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (TextEqualsIgnoreCase(token, MakeText("br"))) {
                return STATUS_NOT_SUPPORTED;
            }

            HttpTransferCodingKind parsed = {};
            if (TextEqualsIgnoreCase(token, MakeText("chunked"))) {
                parsed = HttpTransferCodingKind::Chunked;
            }
            else if (TextEqualsIgnoreCase(token, MakeText("gzip")) ||
                TextEqualsIgnoreCase(token, MakeText("x-gzip"))) {
                parsed = HttpTransferCodingKind::Gzip;
            }
            else if (TextEqualsIgnoreCase(token, MakeText("deflate"))) {
                parsed = HttpTransferCodingKind::Deflate;
            }
            else if (TextEqualsIgnoreCase(token, MakeText("compress")) ||
                TextEqualsIgnoreCase(token, MakeText("x-compress"))) {
                parsed = HttpTransferCodingKind::Compress;
            }
            else {
                return STATUS_NOT_SUPPORTED;
            }

            if (parameterStart != member.Length) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *coding = parsed;
            *hasCoding = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AppendTransferCodings(HttpText value, HttpTransferCodingInfo& info) noexcept
        {
            SIZE_T cursor = 0;
            while (cursor <= value.Length) {
                const SIZE_T tokenStart = cursor;
                while (cursor < value.Length && value.Data[cursor] != ',') {
                    ++cursor;
                }

                HttpTransferCodingKind coding = {};
                bool hasCoding = false;
                NTSTATUS status = ParseTransferCodingToken(
                    { value.Data + tokenStart, cursor - tokenStart },
                    &coding,
                    &hasCoding);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (hasCoding) {
                    status = AppendTransferCoding(coding, info);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }

                if (cursor == value.Length) {
                    return STATUS_SUCCESS;
                }

                ++cursor;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS DecodeOneTransferCoding(
            HttpTransferCodingKind transferCoding,
            const char* current,
            SIZE_T currentLength,
            const codec::DecodeBuffers& buffers,
            const char** decoded,
            SIZE_T* decodedLength,
            bool* transformed) noexcept
        {
            if (decoded == nullptr || decodedLength == nullptr || transformed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            codec::Coding coding = codec::Coding::Identity;
            if (!TransferCodingToCodecCoding(transferCoding, &coding)) {
                return STATUS_INVALID_PARAMETER;
            }

            codec::DecodeResult result = {};
            NTSTATUS status = codec::DecodeChain(
                &coding,
                1,
                current,
                currentLength,
                buffers,
                result);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *decoded = result.Body;
            *decodedLength = result.BodyLength;
            *transformed = result.AppliedCoding;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS HttpTransferCoding::Parse(
        const HttpHeader* headers,
        SIZE_T headerCount,
        HttpTransferCodingInfo& info) noexcept
    {
        info = {};
        if (headers == nullptr && headerCount != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        bool sawTransferEncodingHeader = false;
        for (SIZE_T index = 0; index < headerCount; ++index) {
            if (!TextEqualsIgnoreCase(headers[index].Name, MakeText("Transfer-Encoding"))) {
                continue;
            }

            sawTransferEncodingHeader = true;
            NTSTATUS status = AppendTransferCodings(headers[index].Value, info);
            if (!NT_SUCCESS(status)) {
                info = {};
                return status;
            }
        }

        if (!sawTransferEncodingHeader) {
            return STATUS_SUCCESS;
        }

        if (info.CodingCount == 0) {
            info = {};
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        info.HasTransferEncoding = true;
        info.FinalCodingIsChunked =
            GetTransferCoding(info, info.CodingCount - 1) == HttpTransferCodingKind::Chunked;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpTransferCoding::DecodeResponseBody(
        const HttpTransferCodingInfo& info,
        const char* wireBody,
        SIZE_T wireBodyLength,
        bool messageCompleteOnConnectionClose,
        const codec::DecodeBuffers& buffers,
        HttpHeader* trailers,
        SIZE_T trailerCapacity,
        SIZE_T* trailerCount,
        HttpTransferDecodeResult& result) noexcept
    {
        result = {};
        if (trailerCount != nullptr) {
            *trailerCount = 0;
        }
        result.Body = wireBodyLength == 0 ? nullptr : wireBody;
        result.BodyLength = wireBodyLength;

        if (!info.HasTransferEncoding || info.CodingCount == 0) {
            result.BodyKind = wireBodyLength == 0 ? HttpBodyKind::None : HttpBodyKind::CloseDelimited;
            result.BytesConsumed = wireBodyLength;
            return STATUS_SUCCESS;
        }

        if (wireBody == nullptr && wireBodyLength != 0) {
            result = {};
            return STATUS_INVALID_PARAMETER;
        }

        if (!info.FinalCodingIsChunked && !messageCompleteOnConnectionClose) {
            result = {};
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        const char* current = wireBody;
        SIZE_T currentLength = wireBodyLength;
        SIZE_T outerBytesConsumed = info.FinalCodingIsChunked ? 0 : wireBodyLength;
        bool transformed = false;

        for (SIZE_T reverseIndex = info.CodingCount; reverseIndex > 0; --reverseIndex) {
            const SIZE_T codingIndex = reverseIndex - 1;
            const HttpTransferCodingKind coding = GetTransferCoding(info, codingIndex);
            if (coding == HttpTransferCodingKind::Chunked) {
                char* destination = nullptr;
                SIZE_T destinationCapacity = 0;
                SelectDestination(current, buffers, &destination, &destinationCapacity);

                SIZE_T decodedLength = 0;
                SIZE_T consumed = 0;
                SIZE_T decodedTrailerCount = 0;
                NTSTATUS status = HttpParser::DecodeChunkedBodyWithTrailers(
                    current,
                    currentLength,
                    destination,
                    destinationCapacity,
                    (codingIndex == info.CodingCount - 1) ? trailers : nullptr,
                    (codingIndex == info.CodingCount - 1) ? trailerCapacity : 0,
                    &decodedLength,
                    &consumed,
                    &decodedTrailerCount);
                if (!NT_SUCCESS(status)) {
                    result = {};
                    return status;
                }

                if (codingIndex == info.CodingCount - 1) {
                    outerBytesConsumed = consumed;
                    if (trailerCount != nullptr) {
                        *trailerCount = decodedTrailerCount;
                    }
                }
                else if (consumed != currentLength) {
                    result = {};
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                current = decodedLength == 0 ? nullptr : destination;
                currentLength = decodedLength;
                transformed = true;
                continue;
            }

            const char* decoded = nullptr;
            SIZE_T decodedLength = 0;
            bool codingTransformed = false;
            NTSTATUS status = DecodeOneTransferCoding(
                coding,
                current,
                currentLength,
                buffers,
                &decoded,
                &decodedLength,
                &codingTransformed);
            if (!NT_SUCCESS(status)) {
                result = {};
                return status;
            }

            current = decodedLength == 0 ? nullptr : decoded;
            currentLength = decodedLength;
            transformed = transformed || codingTransformed;
        }

        if (transformed &&
            currentLength != 0 &&
            buffers.DecodedBody != nullptr &&
            current != buffers.DecodedBody) {
            if (currentLength > buffers.DecodedBodyCapacity) {
                result = {};
                return STATUS_BUFFER_TOO_SMALL;
            }

            CopyBytes(buffers.DecodedBody, current, currentLength);
            current = buffers.DecodedBody;
        }

        result.Body = currentLength == 0 ? nullptr : current;
        result.BodyLength = currentLength;
        result.BytesConsumed = outerBytesConsumed;
        result.BodyKind = info.FinalCodingIsChunked ?
            HttpBodyKind::Chunked :
            (wireBodyLength == 0 ? HttpBodyKind::None : HttpBodyKind::CloseDelimited);
        return STATUS_SUCCESS;
    }
}
}
