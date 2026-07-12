#pragma once

#include <wknet/crypto/CngProvider.h>
#include <wknet/http1/HttpResponse.h>
#include <wknet/ws/WebSocketDeflate.h>

namespace wknet
{
namespace ws
{
    constexpr SIZE_T WebSocketClientKeyLength = 16;
    constexpr SIZE_T WebSocketClientKeyBase64Length = 24;
    constexpr SIZE_T WebSocketAcceptValueLength = 28;
    constexpr SIZE_T WebSocketMaskingKeyLength = 4;
    constexpr SIZE_T WebSocketFrameHeaderMaxLength = 14;
    constexpr SIZE_T WebSocketMaxControlPayloadLength = 125;

    enum class WebSocketOpcode : UCHAR
    {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA
    };

    struct WebSocketFrameHeader final
    {
        bool Fin = false;
        bool Rsv1 = false;
        bool Masked = false;
        WebSocketOpcode Opcode = WebSocketOpcode::Continuation;
        ULONGLONG PayloadLength = 0;
        UCHAR MaskingKey[WebSocketMaskingKeyLength] = {};
        SIZE_T HeaderLength = 0;
    };

    class WebSocketCodec final
    {
    public:
        WebSocketCodec() = delete;

        _Must_inspect_result_
        static NTSTATUS GenerateClientKey(
            _Out_writes_bytes_(WebSocketClientKeyBase64Length) char* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS ComputeAcceptValue(
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            _Out_writes_bytes_(WebSocketAcceptValueLength) char* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS ValidateServerHandshake(
            _In_ const http1::HttpResponse& response,
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            _In_reads_bytes_opt_(requestedSubprotocolLength) const char* requestedSubprotocol = nullptr,
            SIZE_T requestedSubprotocolLength = 0,
            _Out_opt_ http1::HttpText* selectedSubprotocol = nullptr,
            _In_opt_ const PerMessageDeflateOptions* perMessageDeflate = nullptr,
            _Out_opt_ PerMessageDeflateNegotiation* negotiatedDeflate = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS ValidatePerMessageDeflateExtensions(
            _In_reads_opt_(headerCount) const http1::HttpHeader* headers,
            SIZE_T headerCount,
            _In_ http1::HttpText headerName,
            _In_opt_ const PerMessageDeflateOptions* perMessageDeflate,
            _Out_opt_ PerMessageDeflateNegotiation* negotiatedDeflate) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeClientFrame(
            WebSocketOpcode opcode,
            bool fin,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_reads_bytes_(WebSocketMaskingKeyLength) const UCHAR* maskingKey,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeClientFrame(
            WebSocketOpcode opcode,
            bool fin,
            bool rsv1,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_reads_bytes_(WebSocketMaskingKeyLength) const UCHAR* maskingKey,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeClientFrameForHttp2(
            WebSocketOpcode opcode,
            bool fin,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeClientFrameForHttp2(
            WebSocketOpcode opcode,
            bool fin,
            bool rsv1,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeFrameHeader(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_ WebSocketFrameHeader* header) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeFramePayload(
            _In_ const WebSocketFrameHeader& header,
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) noexcept;
    };
}
}
