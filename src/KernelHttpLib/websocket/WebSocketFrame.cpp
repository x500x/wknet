#include <KernelHttp/websocket/WebSocketFrame.h>

namespace KernelHttp
{
namespace websocket
{
    namespace
    {
        constexpr const char WebSocketGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        constexpr SIZE_T WebSocketGuidLength = sizeof(WebSocketGuid) - 1;
        constexpr SIZE_T Sha1DigestLength = 20;
        constexpr ULONGLONG WebSocketMaximumPayloadLength = 0x7fffffffffffffffULL;

        _Must_inspect_result_
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const void* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        bool ConstantTimeEquals(const char* left, const char* right, SIZE_T length) noexcept
        {
            if (left == nullptr || right == nullptr) {
                return false;
            }

            UCHAR diff = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                diff = static_cast<UCHAR>(diff | (left[index] ^ right[index]));
            }
            return diff == 0;
        }

        _Must_inspect_result_
        char Base64Char(UCHAR value) noexcept
        {
            static constexpr char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            return alphabet[value & 0x3f];
        }

        _Must_inspect_result_
        NTSTATUS Base64Encode(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }

            if (!IsValidBuffer(data, dataLength) || destination == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (dataLength > ((static_cast<SIZE_T>(-1)) / 4) * 3) {
                return STATUS_INTEGER_OVERFLOW;
            }

            const SIZE_T required = ((dataLength + 2) / 3) * 4;
            if (destinationCapacity < required) {
                if (bytesWritten != nullptr) {
                    *bytesWritten = required;
                }
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T input = 0;
            SIZE_T output = 0;
            while (dataLength - input >= 3) {
                const ULONG value =
                    (static_cast<ULONG>(data[input]) << 16) |
                    (static_cast<ULONG>(data[input + 1]) << 8) |
                    static_cast<ULONG>(data[input + 2]);
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 18) & 0x3f));
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 12) & 0x3f));
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 6) & 0x3f));
                destination[output++] = Base64Char(static_cast<UCHAR>(value & 0x3f));
                input += 3;
            }

            const SIZE_T remaining = dataLength - input;
            if (remaining == 1) {
                const ULONG value = static_cast<ULONG>(data[input]) << 16;
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 18) & 0x3f));
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 12) & 0x3f));
                destination[output++] = '=';
                destination[output++] = '=';
            }
            else if (remaining == 2) {
                const ULONG value =
                    (static_cast<ULONG>(data[input]) << 16) |
                    (static_cast<ULONG>(data[input + 1]) << 8);
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 18) & 0x3f));
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 12) & 0x3f));
                destination[output++] = Base64Char(static_cast<UCHAR>((value >> 6) & 0x3f));
                destination[output++] = '=';
            }

            if (bytesWritten != nullptr) {
                *bytesWritten = output;
            }
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsKnownOpcode(UCHAR opcode) noexcept
        {
            return opcode == static_cast<UCHAR>(WebSocketOpcode::Continuation) ||
                opcode == static_cast<UCHAR>(WebSocketOpcode::Text) ||
                opcode == static_cast<UCHAR>(WebSocketOpcode::Binary) ||
                opcode == static_cast<UCHAR>(WebSocketOpcode::Close) ||
                opcode == static_cast<UCHAR>(WebSocketOpcode::Ping) ||
                opcode == static_cast<UCHAR>(WebSocketOpcode::Pong);
        }

        _Must_inspect_result_
        bool IsControlOpcode(WebSocketOpcode opcode) noexcept
        {
            return opcode == WebSocketOpcode::Close ||
                opcode == WebSocketOpcode::Ping ||
                opcode == WebSocketOpcode::Pong;
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
        bool TextEquals(http::HttpText left, http::HttpText right) noexcept
        {
            if (left.Length != right.Length ||
                (left.Data == nullptr && left.Length != 0) ||
                (right.Data == nullptr && right.Length != 0)) {
                return false;
            }

            return left.Length == 0 ||
                RtlCompareMemory(left.Data, right.Data, left.Length) == left.Length;
        }

        _Must_inspect_result_
        http::HttpText TrimOptionalWhitespace(http::HttpText text) noexcept
        {
            while (text.Length > 0 && (text.Data[0] == ' ' || text.Data[0] == '\t')) {
                ++text.Data;
                --text.Length;
            }

            while (text.Length > 0 &&
                (text.Data[text.Length - 1] == ' ' || text.Data[text.Length - 1] == '\t')) {
                --text.Length;
            }

            return text;
        }

        _Must_inspect_result_
        bool IsValidSubprotocolToken(http::HttpText token) noexcept
        {
            if (token.Data == nullptr || token.Length == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < token.Length; ++index) {
                const unsigned char value = static_cast<unsigned char>(token.Data[index]);
                if (value <= 0x20 || value >= 0x7f || IsSubprotocolSeparator(token.Data[index])) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        NTSTATUS FindSelectedSubprotocol(
            _In_ const http::HttpResponse& response,
            _Out_ bool* present,
            _Out_ http::HttpText* selected) noexcept
        {
            if (present != nullptr) {
                *present = false;
            }
            if (selected != nullptr) {
                *selected = {};
            }

            if (present == nullptr || selected == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (response.Headers == nullptr && response.HeaderCount != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T headerCount = 0;
            for (SIZE_T index = 0; index < response.HeaderCount; ++index) {
                if (!http::TextEqualsIgnoreCase(
                    response.Headers[index].Name,
                    http::MakeText("Sec-WebSocket-Protocol"))) {
                    continue;
                }

                ++headerCount;
                if (headerCount > 1) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                *present = true;
                *selected = TrimOptionalWhitespace(response.Headers[index].Value);
            }

            if (!*present) {
                return STATUS_SUCCESS;
            }

            return IsValidSubprotocolToken(*selected) ?
                STATUS_SUCCESS :
                STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        SIZE_T CountHeaders(
            _In_ const http::HttpResponse& response,
            _In_ http::HttpText name) noexcept
        {
            SIZE_T count = 0;
            if (response.Headers == nullptr && response.HeaderCount != 0) {
                return 0;
            }

            for (SIZE_T index = 0; index < response.HeaderCount; ++index) {
                if (http::TextEqualsIgnoreCase(response.Headers[index].Name, name)) {
                    ++count;
                }
            }
            return count;
        }

        _Must_inspect_result_
        NTSTATUS ValidateSelectedSubprotocol(
            _In_ http::HttpText selected,
            _In_ http::HttpText requested) noexcept
        {
            if (!IsValidSubprotocolToken(selected)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (requested.Data == nullptr || requested.Length == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            bool matched = false;
            SIZE_T index = 0;
            while (index <= requested.Length) {
                const SIZE_T tokenStart = index;
                while (index < requested.Length && requested.Data[index] != ',') {
                    ++index;
                }

                http::HttpText candidate = {
                    requested.Data + tokenStart,
                    index - tokenStart
                };
                candidate = TrimOptionalWhitespace(candidate);
                if (!IsValidSubprotocolToken(candidate)) {
                    return STATUS_INVALID_PARAMETER;
                }

                if (TextEquals(candidate, selected)) {
                    matched = true;
                }

                if (index == requested.Length) {
                    break;
                }
                ++index;
            }

            return matched ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        NTSTATUS WritePayloadLength(
            SIZE_T payloadLength,
            UCHAR* destination,
            SIZE_T destinationCapacity,
            SIZE_T* cursor) noexcept
        {
            if (destination == nullptr || cursor == nullptr || *cursor >= destinationCapacity) {
                return STATUS_INVALID_PARAMETER;
            }

            if (payloadLength <= 125) {
                destination[(*cursor)++] = static_cast<UCHAR>(0x80 | payloadLength);
                return STATUS_SUCCESS;
            }

            if (payloadLength <= 0xffff) {
                if (destinationCapacity - *cursor < 3) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                destination[(*cursor)++] = 0x80 | 126;
                destination[(*cursor)++] = static_cast<UCHAR>((payloadLength >> 8) & 0xff);
                destination[(*cursor)++] = static_cast<UCHAR>(payloadLength & 0xff);
                return STATUS_SUCCESS;
            }

            if (destinationCapacity - *cursor < 9) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[(*cursor)++] = 0x80 | 127;
            const ULONGLONG length64 = static_cast<ULONGLONG>(payloadLength);
            for (LONG shift = 56; shift >= 0; shift -= 8) {
                destination[(*cursor)++] = static_cast<UCHAR>((length64 >> shift) & 0xff);
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadExtendedLength(
            const UCHAR* data,
            SIZE_T dataLength,
            UCHAR lengthCode,
            SIZE_T* cursor,
            ULONGLONG* payloadLength) noexcept
        {
            if (data == nullptr || cursor == nullptr || payloadLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (lengthCode <= 125) {
                *payloadLength = lengthCode;
                return STATUS_SUCCESS;
            }

            if (lengthCode == 126) {
                if (dataLength - *cursor < 2) {
                    return STATUS_MORE_PROCESSING_REQUIRED;
                }

                *payloadLength =
                    (static_cast<ULONGLONG>(data[*cursor]) << 8) |
                    static_cast<ULONGLONG>(data[*cursor + 1]);
                *cursor += 2;
                if (*payloadLength <= 125) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                return STATUS_SUCCESS;
            }

            if (dataLength - *cursor < 8) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }

            ULONGLONG value = 0;
            for (SIZE_T index = 0; index < 8; ++index) {
                value = (value << 8) | data[*cursor + index];
            }
            *cursor += 8;

            if ((value & (1ULL << 63)) != 0 || value <= 0xffff) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *payloadLength = value;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS WebSocketCodec::GenerateClientKey(
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        HeapArray<UCHAR> nonce(WebSocketClientKeyLength);
        if (!nonce.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = crypto::CngProvider::GenerateRandom(nonce.Get(), nonce.Count());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = Base64Encode(nonce.Get(), nonce.Count(), destination, destinationCapacity, bytesWritten);
        RtlSecureZeroMemory(nonce.Get(), nonce.Count());
        return status;
    }

    NTSTATUS WebSocketCodec::ComputeAcceptValue(
        const char* clientKey,
        SIZE_T clientKeyLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (clientKey == nullptr || clientKeyLength == 0 || destination == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapObject<crypto::CngHashContext> hash;
        if (!hash.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = hash->Initialize(crypto::HashAlgorithm::Sha1);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = hash->Update(reinterpret_cast<const UCHAR*>(clientKey), clientKeyLength);
        if (NT_SUCCESS(status)) {
            status = hash->Update(reinterpret_cast<const UCHAR*>(WebSocketGuid), WebSocketGuidLength);
        }

        HeapArray<UCHAR> digest(Sha1DigestLength);
        if (!digest.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T digestLength = 0;
        if (NT_SUCCESS(status)) {
            status = hash->Finish(digest.Get(), digest.Count(), &digestLength);
        }

        if (NT_SUCCESS(status) && digestLength != Sha1DigestLength) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (NT_SUCCESS(status)) {
            status = Base64Encode(digest.Get(), digestLength, destination, destinationCapacity, bytesWritten);
        }

        RtlSecureZeroMemory(digest.Get(), digest.Count());
        return status;
    }

    NTSTATUS WebSocketCodec::ValidateServerHandshake(
        const http::HttpResponse& response,
        const char* clientKey,
        SIZE_T clientKeyLength,
        const char* requestedSubprotocol,
        SIZE_T requestedSubprotocolLength,
        http::HttpText* selectedSubprotocol) noexcept
    {
        if (selectedSubprotocol != nullptr) {
            *selectedSubprotocol = {};
        }

        if (response.StatusCode != 101 ||
            response.MajorVersion != 1 ||
            response.MinorVersion != 1 ||
            !response.HasHeaderValueToken(http::MakeText("Connection"), http::MakeText("Upgrade")) ||
            !response.HasHeaderValueToken(http::MakeText("Upgrade"), http::MakeText("websocket"))) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const http::HttpHeader* accept = nullptr;
        if (CountHeaders(response, http::MakeText("Sec-WebSocket-Accept")) != 1 ||
            !response.FindHeader(http::MakeText("Sec-WebSocket-Accept"), &accept) ||
            accept == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const http::HttpHeader* extensions = nullptr;
        if (response.FindHeader(http::MakeText("Sec-WebSocket-Extensions"), &extensions)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        HeapArray<char> expected(WebSocketAcceptValueLength);
        if (!expected.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T expectedLength = 0;
        NTSTATUS status = ComputeAcceptValue(
            clientKey,
            clientKeyLength,
            expected.Get(),
            expected.Count(),
            &expectedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (accept->Value.Length != expectedLength ||
            !ConstantTimeEquals(accept->Value.Data, expected.Get(), expectedLength)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        bool selectedPresent = false;
        http::HttpText negotiatedSubprotocol = {};
        status = FindSelectedSubprotocol(response, &selectedPresent, &negotiatedSubprotocol);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (selectedPresent) {
            status = ValidateSelectedSubprotocol(
                negotiatedSubprotocol,
                { requestedSubprotocol, requestedSubprotocolLength });
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (selectedSubprotocol != nullptr) {
                *selectedSubprotocol = negotiatedSubprotocol;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketCodec::EncodeClientFrame(
        WebSocketOpcode opcode,
        bool fin,
        const UCHAR* payload,
        SIZE_T payloadLength,
        const UCHAR* maskingKey,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!IsValidBuffer(payload, payloadLength) ||
            maskingKey == nullptr ||
            destination == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!IsKnownOpcode(static_cast<UCHAR>(opcode))) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsControlOpcode(opcode) && (!fin || payloadLength > WebSocketMaxControlPayloadLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (static_cast<ULONGLONG>(payloadLength) > WebSocketMaximumPayloadLength) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T headerLength = 2 + WebSocketMaskingKeyLength;
        if (payloadLength > 125 && payloadLength <= 0xffff) {
            headerLength += 2;
        }
        else if (payloadLength > 0xffff) {
            headerLength += 8;
        }

        if (payloadLength > static_cast<SIZE_T>(-1) - headerLength) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T required = headerLength + payloadLength;

        if (destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T cursor = 0;
        destination[cursor++] = static_cast<UCHAR>((fin ? 0x80 : 0x00) | static_cast<UCHAR>(opcode));

        NTSTATUS status = WritePayloadLength(payloadLength, destination, destinationCapacity, &cursor);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < WebSocketMaskingKeyLength; ++index) {
            destination[cursor++] = maskingKey[index];
        }

        for (SIZE_T index = 0; index < payloadLength; ++index) {
            destination[cursor + index] = static_cast<UCHAR>(payload[index] ^ maskingKey[index % WebSocketMaskingKeyLength]);
        }
        cursor += payloadLength;

        if (bytesWritten != nullptr) {
            *bytesWritten = cursor;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketCodec::DecodeFrameHeader(
        const UCHAR* data,
        SIZE_T dataLength,
        WebSocketFrameHeader* header) noexcept
    {
        if (header != nullptr) {
            *header = {};
        }

        if (data == nullptr || header == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength < 2) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        const UCHAR first = data[0];
        const UCHAR second = data[1];
        if ((first & 0x70) != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const UCHAR opcodeValue = static_cast<UCHAR>(first & 0x0f);
        if (!IsKnownOpcode(opcodeValue)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T cursor = 2;
        ULONGLONG payloadLength = 0;
        NTSTATUS status = ReadExtendedLength(
            data,
            dataLength,
            static_cast<UCHAR>(second & 0x7f),
            &cursor,
            &payloadLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool masked = (second & 0x80) != 0;
        if (masked) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const WebSocketOpcode opcode = static_cast<WebSocketOpcode>(opcodeValue);
        if (IsControlOpcode(opcode) && (((first & 0x80) == 0) || payloadLength > 125)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        header->Fin = (first & 0x80) != 0;
        header->Masked = masked;
        header->Opcode = opcode;
        header->PayloadLength = payloadLength;
        header->HeaderLength = cursor;
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketCodec::DecodeFramePayload(
        const WebSocketFrameHeader& header,
        const UCHAR* data,
        SIZE_T dataLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (header.PayloadLength > static_cast<ULONGLONG>(static_cast<SIZE_T>(-1))) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        const SIZE_T payloadLength = static_cast<SIZE_T>(header.PayloadLength);
        if (data == nullptr ||
            header.HeaderLength > dataLength ||
            payloadLength > dataLength - header.HeaderLength) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        if (destination == nullptr || destinationCapacity < payloadLength) {
            if (bytesWritten != nullptr) {
                *bytesWritten = payloadLength;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        const UCHAR* payload = data + header.HeaderLength;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        NT_ASSERT(!header.Masked);
#endif
        for (SIZE_T index = 0; index < payloadLength; ++index) {
            UCHAR byte = payload[index];
            if (header.Masked) {
                byte = static_cast<UCHAR>(byte ^ header.MaskingKey[index % WebSocketMaskingKeyLength]);
            }
            destination[index] = byte;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = payloadLength;
        }
        return STATUS_SUCCESS;
    }
}
}
