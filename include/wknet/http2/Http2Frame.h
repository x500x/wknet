#pragma once

#include <wknet/http1/HttpTypes.h>

namespace wknet
{
namespace http2
{
    constexpr SIZE_T Http2FrameHeaderLength = 9;
    constexpr ULONG Http2DefaultMaxFrameSize = 16384;
    constexpr ULONG Http2MaxAllowedFrameSize = 16777215;
    constexpr ULONG Http2InitialWindowSize = 65535;
    constexpr ULONG Http2MaxWindowSize = 0x7fffffff;

    // Connection preface (RFC 9113 Section 3.4)
    constexpr const char* Http2ConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    constexpr SIZE_T Http2ConnectionPrefaceLength = 24;

    enum class Http2FrameType : UCHAR
    {
        Data = 0x0,
        Headers = 0x1,
        Priority = 0x2,
        RstStream = 0x3,
        Settings = 0x4,
        PushPromise = 0x5,
        Ping = 0x6,
        GoAway = 0x7,
        WindowUpdate = 0x8,
        Continuation = 0x9
    };

    namespace Http2FrameFlags
    {
        constexpr UCHAR EndStream = 0x01;
        constexpr UCHAR Ack = 0x01;          // SETTINGS / PING
        constexpr UCHAR EndHeaders = 0x04;
        constexpr UCHAR Padded = 0x08;
        constexpr UCHAR Priority = 0x20;
    }

    enum class Http2ErrorCode : ULONG
    {
        NoError = 0x0,
        ProtocolError = 0x1,
        InternalError = 0x2,
        FlowControlError = 0x3,
        SettingsTimeout = 0x4,
        StreamClosed = 0x5,
        FrameSizeError = 0x6,
        RefusedStream = 0x7,
        Cancel = 0x8,
        CompressionError = 0x9,
        ConnectError = 0xa,
        EnhanceYourCalm = 0xb,
        InadequateSecurity = 0xc,
        Http11Required = 0xd
    };

    enum class Http2SettingId : USHORT
    {
        HeaderTableSize = 0x1,
        EnablePush = 0x2,
        MaxConcurrentStreams = 0x3,
        InitialWindowSize = 0x4,
        MaxFrameSize = 0x5,
        MaxHeaderListSize = 0x6,
        EnableConnectProtocol = 0x8
    };

    struct Http2Settings final
    {
        ULONG HeaderTableSize = 4096;
        ULONG EnablePush = 0;             // Client always sends 0
        ULONG MaxConcurrentStreams = 100;
        ULONG InitialWindowSize = 65535;
        ULONG MaxFrameSize = 16384;
        ULONG MaxHeaderListSize = 65536;
        ULONG EnableConnectProtocol = 0;
    };

    struct Http2FrameHeader final
    {
        ULONG Length = 0;            // payload length (24 bits)
        Http2FrameType Type = Http2FrameType::Data;
        UCHAR Flags = 0;
        ULONG StreamId = 0;          // 31 bits
    };

    struct Http2Priority final
    {
        ULONG StreamDependency = 0;   // 31 bits; 0 means root dependency.
        USHORT Weight = 16;           // RFC weight range: 1..256.
        bool Exclusive = false;
    };

    class Http2FrameCodec final
    {
    public:
        Http2FrameCodec() = delete;

        _Must_inspect_result_
        static NTSTATUS EncodeFrameHeader(
            _In_ const Http2FrameHeader& header,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeFrameHeader(
            _In_reads_bytes_(length) const UCHAR* src,
            SIZE_T length,
            _Out_ Http2FrameHeader* header) noexcept;

        // Encode complete frame: header + payload
        _Must_inspect_result_
        static NTSTATUS EncodeFrame(
            _In_ const Http2FrameHeader& header,
            _In_reads_bytes_opt_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        // SETTINGS frame
        _Must_inspect_result_
        static NTSTATUS EncodeSettings(
            _In_ const Http2Settings& settings,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeSettingsAck(
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        // Parse SETTINGS payload: array of (USHORT id, ULONG value) pairs
        // Updates settings with received values
        _Must_inspect_result_
        static NTSTATUS EncodeSettingsPayloadBase64Url(
            _In_ const Http2Settings& settings,
            _Out_writes_bytes_(capacity) char* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* charsWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeSettingsPayload(
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Inout_ Http2Settings* settings) noexcept;

        // WINDOW_UPDATE
        _Must_inspect_result_
        static NTSTATUS EncodeWindowUpdate(
            ULONG streamId,
            ULONG increment,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeWindowUpdatePayload(
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Out_ ULONG* increment) noexcept;

        // PING
        _Must_inspect_result_
        static NTSTATUS EncodePing(
            _In_reads_bytes_(8) const UCHAR* opaqueData,
            bool ack,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        // GOAWAY
        _Must_inspect_result_
        static NTSTATUS EncodeGoAway(
            ULONG lastStreamId,
            ULONG errorCode,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeGoAwayPayload(
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Out_ ULONG* lastStreamId,
            _Out_ ULONG* errorCode) noexcept;

        // RST_STREAM
        _Must_inspect_result_
        static NTSTATUS EncodeRstStream(
            ULONG streamId,
            ULONG errorCode,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        // PRIORITY frame
        _Must_inspect_result_
        static NTSTATUS EncodePriority(
            ULONG streamId,
            _In_ const Http2Priority& priority,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodePriorityPayload(
            ULONG streamId,
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Out_ Http2Priority* priority) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeRstStreamPayload(
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Out_ ULONG* errorCode) noexcept;

        // HEADERS frame (single frame, caller must ensure headerBlockLen <= maxFrameSize)
        // For multi-frame HEADERS (with CONTINUATION), caller orchestrates fragmentation
        _Must_inspect_result_
        static NTSTATUS EncodeHeaders(
            ULONG streamId,
            _In_reads_bytes_(headerBlockLen) const UCHAR* headerBlock,
            SIZE_T headerBlockLen,
            bool endStream,
            bool endHeaders,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeHeadersWithPriority(
            ULONG streamId,
            _In_reads_bytes_(headerBlockLen) const UCHAR* headerBlock,
            SIZE_T headerBlockLen,
            _In_ const Http2Priority& priority,
            bool endStream,
            bool endHeaders,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        // CONTINUATION frame
        _Must_inspect_result_
        static NTSTATUS EncodeContinuation(
            ULONG streamId,
            _In_reads_bytes_(blockLen) const UCHAR* block,
            SIZE_T blockLen,
            bool endHeaders,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        // DATA frame (single frame)
        _Must_inspect_result_
        static NTSTATUS EncodeData(
            ULONG streamId,
            _In_reads_bytes_opt_(dataLen) const UCHAR* data,
            SIZE_T dataLen,
            bool endStream,
            _Out_writes_bytes_(capacity) UCHAR* dest,
            SIZE_T capacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        // Strip padding from a DATA or HEADERS frame payload if Padded flag is set.
        // Returns pointer into payload and adjusted length.
        _Must_inspect_result_
        static NTSTATUS StripPadding(
            UCHAR flags,
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Out_ const UCHAR** content,
            _Out_ SIZE_T* contentLen) noexcept;

        // Strip optional priority field from a HEADERS frame payload.
        // Caller should call after StripPadding.
        _Must_inspect_result_
        static NTSTATUS StripPriority(
            UCHAR flags,
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Out_ const UCHAR** content,
            _Out_ SIZE_T* contentLen) noexcept;
    };
}
}
