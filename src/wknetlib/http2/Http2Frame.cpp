#include <wknet/http2/Http2Frame.h>

namespace wknet
{
namespace http2
{
    namespace
    {
        void WriteUint24BE(UCHAR* dest, ULONG value) noexcept
        {
            dest[0] = static_cast<UCHAR>((value >> 16) & 0xff);
            dest[1] = static_cast<UCHAR>((value >> 8) & 0xff);
            dest[2] = static_cast<UCHAR>(value & 0xff);
        }

        ULONG ReadUint24BE(const UCHAR* src) noexcept
        {
            return (static_cast<ULONG>(src[0]) << 16) |
                (static_cast<ULONG>(src[1]) << 8) |
                static_cast<ULONG>(src[2]);
        }

        void WriteUint32BE(UCHAR* dest, ULONG value) noexcept
        {
            dest[0] = static_cast<UCHAR>((value >> 24) & 0xff);
            dest[1] = static_cast<UCHAR>((value >> 16) & 0xff);
            dest[2] = static_cast<UCHAR>((value >> 8) & 0xff);
            dest[3] = static_cast<UCHAR>(value & 0xff);
        }

        ULONG ReadUint32BE(const UCHAR* src) noexcept
        {
            return (static_cast<ULONG>(src[0]) << 24) |
                (static_cast<ULONG>(src[1]) << 16) |
                (static_cast<ULONG>(src[2]) << 8) |
                static_cast<ULONG>(src[3]);
        }

        void WriteUint16BE(UCHAR* dest, USHORT value) noexcept
        {
            dest[0] = static_cast<UCHAR>((value >> 8) & 0xff);
            dest[1] = static_cast<UCHAR>(value & 0xff);
        }

        USHORT ReadUint16BE(const UCHAR* src) noexcept
        {
            return static_cast<USHORT>(
                (static_cast<USHORT>(src[0]) << 8) |
                static_cast<USHORT>(src[1]));
        }

        void MemCopy(void* dst, const void* src, SIZE_T len) noexcept
        {
            auto* d = static_cast<UCHAR*>(dst);
            auto* s = static_cast<const UCHAR*>(src);
            for (SIZE_T i = 0; i < len; ++i) {
                d[i] = s[i];
            }
        }

        NTSTATUS ValidatePriority(ULONG streamId, const Http2Priority& priority) noexcept
        {
            if (streamId == 0 ||
                (streamId & 0x80000000u) != 0 ||
                (priority.StreamDependency & 0x80000000u) != 0 ||
                priority.StreamDependency == streamId ||
                priority.Weight == 0 ||
                priority.Weight > 256) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }

        void WritePriorityPayload(UCHAR* dest, const Http2Priority& priority) noexcept
        {
            ULONG dependency = priority.StreamDependency & 0x7fffffffu;
            if (priority.Exclusive) {
                dependency |= 0x80000000u;
            }
            WriteUint32BE(dest, dependency);
            dest[4] = static_cast<UCHAR>(priority.Weight - 1);
        }

        char Base64UrlChar(UCHAR value) noexcept
        {
            if (value < 26) return static_cast<char>('A' + value);
            if (value < 52) return static_cast<char>('a' + (value - 26));
            if (value < 62) return static_cast<char>('0' + (value - 52));
            return value == 62 ? '-' : '_';
        }

        NTSTATUS Base64UrlEncode(
            const UCHAR* input,
            SIZE_T inputLength,
            char* output,
            SIZE_T outputCapacity,
            SIZE_T* outputLength) noexcept
        {
            if (input == nullptr || output == nullptr || outputLength == nullptr) return STATUS_INVALID_PARAMETER;

            SIZE_T out = 0;
            SIZE_T index = 0;
            while (index + 3 <= inputLength) {
                if (out + 4 > outputCapacity) return STATUS_BUFFER_TOO_SMALL;
                const ULONG value = (static_cast<ULONG>(input[index]) << 16) |
                    (static_cast<ULONG>(input[index + 1]) << 8) |
                    static_cast<ULONG>(input[index + 2]);
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 18) & 0x3f));
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 12) & 0x3f));
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 6) & 0x3f));
                output[out++] = Base64UrlChar(static_cast<UCHAR>(value & 0x3f));
                index += 3;
            }

            const SIZE_T remaining = inputLength - index;
            if (remaining == 1) {
                if (out + 2 > outputCapacity) return STATUS_BUFFER_TOO_SMALL;
                const ULONG value = static_cast<ULONG>(input[index]) << 16;
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 18) & 0x3f));
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 12) & 0x3f));
            } else if (remaining == 2) {
                if (out + 3 > outputCapacity) return STATUS_BUFFER_TOO_SMALL;
                const ULONG value = (static_cast<ULONG>(input[index]) << 16) |
                    (static_cast<ULONG>(input[index + 1]) << 8);
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 18) & 0x3f));
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 12) & 0x3f));
                output[out++] = Base64UrlChar(static_cast<UCHAR>((value >> 6) & 0x3f));
            }

            *outputLength = out;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS Http2FrameCodec::EncodeFrameHeader(
        const Http2FrameHeader& header,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (capacity < Http2FrameHeaderLength) return STATUS_BUFFER_TOO_SMALL;
        if (header.Length > Http2MaxAllowedFrameSize) return STATUS_INVALID_PARAMETER;
        if ((header.StreamId & 0x80000000u) != 0) return STATUS_INVALID_PARAMETER;

        WriteUint24BE(dest, header.Length);
        dest[3] = static_cast<UCHAR>(header.Type);
        dest[4] = header.Flags;
        WriteUint32BE(dest + 5, header.StreamId & 0x7fffffffu);

        *bytesWritten = Http2FrameHeaderLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::DecodeFrameHeader(
        const UCHAR* src,
        SIZE_T length,
        Http2FrameHeader* header) noexcept
    {
        if (src == nullptr || header == nullptr) return STATUS_INVALID_PARAMETER;
        if (length < Http2FrameHeaderLength) return STATUS_MORE_PROCESSING_REQUIRED;

        header->Length = ReadUint24BE(src);
        header->Type = static_cast<Http2FrameType>(src[3]);
        header->Flags = src[4];
        header->StreamId = ReadUint32BE(src + 5) & 0x7fffffffu;

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeFrame(
        const Http2FrameHeader& header,
        const UCHAR* payload,
        SIZE_T payloadLen,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (payload == nullptr && payloadLen > 0) return STATUS_INVALID_PARAMETER;
        if (header.Length != static_cast<ULONG>(payloadLen)) return STATUS_INVALID_PARAMETER;

        if (capacity < Http2FrameHeaderLength + payloadLen) return STATUS_BUFFER_TOO_SMALL;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(header, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        if (payloadLen > 0) {
            MemCopy(dest + headerWritten, payload, payloadLen);
        }

        *bytesWritten = headerWritten + payloadLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeSettings(
        const Http2Settings& settings,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;

        // 7 settings, each 6 bytes (USHORT id + ULONG value) = 42 bytes payload.
        constexpr SIZE_T SettingCount = 7;
        constexpr SIZE_T SettingsPayloadLen = SettingCount * 6;
        const SIZE_T totalLen = Http2FrameHeaderLength + SettingsPayloadLen;

        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = SettingsPayloadLen;
        hdr.Type = Http2FrameType::Settings;
        hdr.Flags = 0;
        hdr.StreamId = 0;

        SIZE_T offset = 0;
        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;
        offset += headerWritten;

        const auto writeSetting = [&offset, dest](Http2SettingId id, ULONG value) noexcept {
            WriteUint16BE(dest + offset, static_cast<USHORT>(id));
            offset += 2;
            WriteUint32BE(dest + offset, value);
            offset += 4;
        };

        writeSetting(Http2SettingId::HeaderTableSize, settings.HeaderTableSize);
        writeSetting(Http2SettingId::EnablePush, settings.EnablePush);
        writeSetting(Http2SettingId::MaxConcurrentStreams, settings.MaxConcurrentStreams);
        writeSetting(Http2SettingId::InitialWindowSize, settings.InitialWindowSize);
        writeSetting(Http2SettingId::MaxFrameSize, settings.MaxFrameSize);
        writeSetting(Http2SettingId::MaxHeaderListSize, settings.MaxHeaderListSize);
        writeSetting(Http2SettingId::EnableConnectProtocol, settings.EnableConnectProtocol);

        *bytesWritten = offset;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeSettingsAck(
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (capacity < Http2FrameHeaderLength) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = 0;
        hdr.Type = Http2FrameType::Settings;
        hdr.Flags = Http2FrameFlags::Ack;
        hdr.StreamId = 0;

        return EncodeFrameHeader(hdr, dest, capacity, bytesWritten);
    }

    NTSTATUS Http2FrameCodec::EncodeSettingsPayloadBase64Url(
        const Http2Settings& settings,
        char* dest,
        SIZE_T capacity,
        SIZE_T* charsWritten) noexcept
    {
        if (dest == nullptr || charsWritten == nullptr) return STATUS_INVALID_PARAMETER;

        HeapArray<UCHAR> frame(Http2FrameHeaderLength + (7 * 6));
        if (!frame.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;

        SIZE_T frameLength = 0;
        NTSTATUS status = EncodeSettings(settings, frame.Get(), frame.Count(), &frameLength);
        if (!NT_SUCCESS(status)) return status;

        return Base64UrlEncode(
            frame.Get() + Http2FrameHeaderLength,
            frameLength - Http2FrameHeaderLength,
            dest,
            capacity,
            charsWritten);
    }

    NTSTATUS Http2FrameCodec::DecodeSettingsPayload(
        const UCHAR* payload,
        SIZE_T payloadLen,
        Http2Settings* settings) noexcept
    {
        if (settings == nullptr) return STATUS_INVALID_PARAMETER;
        if (payload == nullptr && payloadLen > 0) return STATUS_INVALID_PARAMETER;
        if ((payloadLen % 6) != 0) return STATUS_INVALID_NETWORK_RESPONSE;

        SIZE_T offset = 0;
        while (offset < payloadLen) {
            USHORT id = ReadUint16BE(payload + offset);
            offset += 2;
            ULONG value = ReadUint32BE(payload + offset);
            offset += 4;

            switch (static_cast<Http2SettingId>(id)) {
            case Http2SettingId::HeaderTableSize:
                settings->HeaderTableSize = value;
                break;
            case Http2SettingId::EnablePush:
                if (value > 1) return STATUS_INVALID_NETWORK_RESPONSE;
                settings->EnablePush = value;
                break;
            case Http2SettingId::MaxConcurrentStreams:
                settings->MaxConcurrentStreams = value;
                break;
            case Http2SettingId::InitialWindowSize:
                if (value > Http2MaxWindowSize) return STATUS_INVALID_NETWORK_RESPONSE;
                settings->InitialWindowSize = value;
                break;
            case Http2SettingId::MaxFrameSize:
                if (value < Http2DefaultMaxFrameSize || value > Http2MaxAllowedFrameSize) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                settings->MaxFrameSize = value;
                break;
            case Http2SettingId::MaxHeaderListSize:
                settings->MaxHeaderListSize = value;
                break;
            case Http2SettingId::EnableConnectProtocol:
                if (value > 1) return STATUS_INVALID_NETWORK_RESPONSE;
                settings->EnableConnectProtocol = value;
                break;
            default:
                // Unknown settings MUST be ignored (RFC 9113 Section 6.5.2)
                break;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeWindowUpdate(
        ULONG streamId,
        ULONG increment,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (increment == 0 || increment > Http2MaxWindowSize) return STATUS_INVALID_PARAMETER;

        constexpr SIZE_T PayloadLen = 4;
        const SIZE_T totalLen = Http2FrameHeaderLength + PayloadLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = PayloadLen;
        hdr.Type = Http2FrameType::WindowUpdate;
        hdr.Flags = 0;
        hdr.StreamId = streamId;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        WriteUint32BE(dest + headerWritten, increment & 0x7fffffffu);
        *bytesWritten = headerWritten + PayloadLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::DecodeWindowUpdatePayload(
        const UCHAR* payload,
        SIZE_T payloadLen,
        ULONG* increment) noexcept
    {
        if (increment == nullptr || payload == nullptr) return STATUS_INVALID_PARAMETER;
        if (payloadLen != 4) return STATUS_INVALID_NETWORK_RESPONSE;

        *increment = ReadUint32BE(payload) & 0x7fffffffu;
        if (*increment == 0) return STATUS_INVALID_NETWORK_RESPONSE;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodePing(
        const UCHAR* opaqueData,
        bool ack,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr || opaqueData == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        constexpr SIZE_T PayloadLen = 8;
        const SIZE_T totalLen = Http2FrameHeaderLength + PayloadLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = PayloadLen;
        hdr.Type = Http2FrameType::Ping;
        hdr.Flags = ack ? Http2FrameFlags::Ack : 0;
        hdr.StreamId = 0;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        MemCopy(dest + headerWritten, opaqueData, PayloadLen);
        *bytesWritten = headerWritten + PayloadLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeGoAway(
        ULONG lastStreamId,
        ULONG errorCode,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;

        constexpr SIZE_T PayloadLen = 8;
        const SIZE_T totalLen = Http2FrameHeaderLength + PayloadLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = PayloadLen;
        hdr.Type = Http2FrameType::GoAway;
        hdr.Flags = 0;
        hdr.StreamId = 0;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        WriteUint32BE(dest + headerWritten, lastStreamId & 0x7fffffffu);
        WriteUint32BE(dest + headerWritten + 4, errorCode);
        *bytesWritten = headerWritten + PayloadLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::DecodeGoAwayPayload(
        const UCHAR* payload,
        SIZE_T payloadLen,
        ULONG* lastStreamId,
        ULONG* errorCode) noexcept
    {
        if (lastStreamId == nullptr || errorCode == nullptr) return STATUS_INVALID_PARAMETER;
        if (payload == nullptr || payloadLen < 8) return STATUS_INVALID_NETWORK_RESPONSE;

        *lastStreamId = ReadUint32BE(payload) & 0x7fffffffu;
        *errorCode = ReadUint32BE(payload + 4);
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeRstStream(
        ULONG streamId,
        ULONG errorCode,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (streamId == 0) return STATUS_INVALID_PARAMETER;

        constexpr SIZE_T PayloadLen = 4;
        const SIZE_T totalLen = Http2FrameHeaderLength + PayloadLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = PayloadLen;
        hdr.Type = Http2FrameType::RstStream;
        hdr.Flags = 0;
        hdr.StreamId = streamId;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        WriteUint32BE(dest + headerWritten, errorCode);
        *bytesWritten = headerWritten + PayloadLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodePriority(
        ULONG streamId,
        const Http2Priority& priority,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        NTSTATUS status = ValidatePriority(streamId, priority);
        if (!NT_SUCCESS(status)) return status;

        constexpr SIZE_T PayloadLen = 5;
        const SIZE_T totalLen = Http2FrameHeaderLength + PayloadLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = PayloadLen;
        hdr.Type = Http2FrameType::Priority;
        hdr.Flags = 0;
        hdr.StreamId = streamId;

        SIZE_T headerWritten = 0;
        status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        WritePriorityPayload(dest + headerWritten, priority);
        *bytesWritten = headerWritten + PayloadLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::DecodePriorityPayload(
        ULONG streamId,
        const UCHAR* payload,
        SIZE_T payloadLen,
        Http2Priority* priority) noexcept
    {
        if (payload == nullptr || priority == nullptr) return STATUS_INVALID_PARAMETER;
        if (streamId == 0 || (streamId & 0x80000000u) != 0) return STATUS_INVALID_PARAMETER;
        if (payloadLen != 5) return STATUS_INVALID_NETWORK_RESPONSE;

        const ULONG dependency = ReadUint32BE(payload);
        priority->Exclusive = (dependency & 0x80000000u) != 0;
        priority->StreamDependency = dependency & 0x7fffffffu;
        priority->Weight = static_cast<USHORT>(payload[4] + 1);
        if (priority->StreamDependency == streamId) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::DecodeRstStreamPayload(
        const UCHAR* payload,
        SIZE_T payloadLen,
        ULONG* errorCode) noexcept
    {
        if (errorCode == nullptr || payload == nullptr) return STATUS_INVALID_PARAMETER;
        if (payloadLen != 4) return STATUS_INVALID_NETWORK_RESPONSE;

        *errorCode = ReadUint32BE(payload);
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeHeaders(
        ULONG streamId,
        const UCHAR* headerBlock,
        SIZE_T headerBlockLen,
        bool endStream,
        bool endHeaders,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (streamId == 0) return STATUS_INVALID_PARAMETER;
        if (headerBlock == nullptr && headerBlockLen > 0) return STATUS_INVALID_PARAMETER;
        if (headerBlockLen > Http2MaxAllowedFrameSize) return STATUS_INVALID_PARAMETER;

        const SIZE_T totalLen = Http2FrameHeaderLength + headerBlockLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = static_cast<ULONG>(headerBlockLen);
        hdr.Type = Http2FrameType::Headers;
        hdr.Flags = 0;
        if (endStream) hdr.Flags |= Http2FrameFlags::EndStream;
        if (endHeaders) hdr.Flags |= Http2FrameFlags::EndHeaders;
        hdr.StreamId = streamId;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        if (headerBlockLen > 0) {
            MemCopy(dest + headerWritten, headerBlock, headerBlockLen);
        }

        *bytesWritten = headerWritten + headerBlockLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeHeadersWithPriority(
        ULONG streamId,
        const UCHAR* headerBlock,
        SIZE_T headerBlockLen,
        const Http2Priority& priority,
        bool endStream,
        bool endHeaders,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        NTSTATUS status = ValidatePriority(streamId, priority);
        if (!NT_SUCCESS(status)) return status;
        if (headerBlock == nullptr && headerBlockLen > 0) return STATUS_INVALID_PARAMETER;
        constexpr SIZE_T PriorityFieldLength = 5;
        if (headerBlockLen > Http2MaxAllowedFrameSize - PriorityFieldLength) return STATUS_INVALID_PARAMETER;

        const SIZE_T payloadLen = PriorityFieldLength + headerBlockLen;
        const SIZE_T totalLen = Http2FrameHeaderLength + payloadLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = static_cast<ULONG>(payloadLen);
        hdr.Type = Http2FrameType::Headers;
        hdr.Flags = Http2FrameFlags::Priority;
        if (endStream) hdr.Flags |= Http2FrameFlags::EndStream;
        if (endHeaders) hdr.Flags |= Http2FrameFlags::EndHeaders;
        hdr.StreamId = streamId;

        SIZE_T headerWritten = 0;
        status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        WritePriorityPayload(dest + headerWritten, priority);
        if (headerBlockLen > 0) {
            MemCopy(dest + headerWritten + PriorityFieldLength, headerBlock, headerBlockLen);
        }

        *bytesWritten = headerWritten + payloadLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeContinuation(
        ULONG streamId,
        const UCHAR* block,
        SIZE_T blockLen,
        bool endHeaders,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (streamId == 0) return STATUS_INVALID_PARAMETER;
        if (block == nullptr && blockLen > 0) return STATUS_INVALID_PARAMETER;
        if (blockLen > Http2MaxAllowedFrameSize) return STATUS_INVALID_PARAMETER;

        const SIZE_T totalLen = Http2FrameHeaderLength + blockLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = static_cast<ULONG>(blockLen);
        hdr.Type = Http2FrameType::Continuation;
        hdr.Flags = endHeaders ? Http2FrameFlags::EndHeaders : 0;
        hdr.StreamId = streamId;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        if (blockLen > 0) {
            MemCopy(dest + headerWritten, block, blockLen);
        }

        *bytesWritten = headerWritten + blockLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::EncodeData(
        ULONG streamId,
        const UCHAR* data,
        SIZE_T dataLen,
        bool endStream,
        UCHAR* dest,
        SIZE_T capacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (dest == nullptr || bytesWritten == nullptr) return STATUS_INVALID_PARAMETER;
        if (streamId == 0) return STATUS_INVALID_PARAMETER;
        if (data == nullptr && dataLen > 0) return STATUS_INVALID_PARAMETER;
        if (dataLen > Http2MaxAllowedFrameSize) return STATUS_INVALID_PARAMETER;

        const SIZE_T totalLen = Http2FrameHeaderLength + dataLen;
        if (capacity < totalLen) return STATUS_BUFFER_TOO_SMALL;

        Http2FrameHeader hdr = {};
        hdr.Length = static_cast<ULONG>(dataLen);
        hdr.Type = Http2FrameType::Data;
        hdr.Flags = endStream ? Http2FrameFlags::EndStream : 0;
        hdr.StreamId = streamId;

        SIZE_T headerWritten = 0;
        NTSTATUS status = EncodeFrameHeader(hdr, dest, capacity, &headerWritten);
        if (!NT_SUCCESS(status)) return status;

        if (dataLen > 0) {
            MemCopy(dest + headerWritten, data, dataLen);
        }

        *bytesWritten = headerWritten + dataLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::StripPadding(
        UCHAR flags,
        const UCHAR* payload,
        SIZE_T payloadLen,
        const UCHAR** content,
        SIZE_T* contentLen) noexcept
    {
        if (content == nullptr || contentLen == nullptr) return STATUS_INVALID_PARAMETER;
        if (payload == nullptr && payloadLen > 0) return STATUS_INVALID_PARAMETER;

        if ((flags & Http2FrameFlags::Padded) == 0) {
            *content = payload;
            *contentLen = payloadLen;
            return STATUS_SUCCESS;
        }

        if (payloadLen < 1) return STATUS_INVALID_NETWORK_RESPONSE;
        UCHAR padLength = payload[0];
        if (static_cast<SIZE_T>(padLength) >= payloadLen) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        *content = payload + 1;
        *contentLen = payloadLen - 1 - padLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2FrameCodec::StripPriority(
        UCHAR flags,
        const UCHAR* payload,
        SIZE_T payloadLen,
        const UCHAR** content,
        SIZE_T* contentLen) noexcept
    {
        if (content == nullptr || contentLen == nullptr) return STATUS_INVALID_PARAMETER;
        if (payload == nullptr && payloadLen > 0) return STATUS_INVALID_PARAMETER;

        if ((flags & Http2FrameFlags::Priority) == 0) {
            *content = payload;
            *contentLen = payloadLen;
            return STATUS_SUCCESS;
        }

        // Priority field: 4 bytes stream dependency + 1 byte weight = 5 bytes
        if (payloadLen < 5) return STATUS_INVALID_NETWORK_RESPONSE;
        *content = payload + 5;
        *contentLen = payloadLen - 5;
        return STATUS_SUCCESS;
    }
}
}
