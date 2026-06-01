#pragma once

#include <KernelHttp/core/ITransport.h>
#include <KernelHttp/http2/Http2Frame.h>
#include <KernelHttp/http2/Hpack.h>
#include <KernelHttp/http2/Http2Stream.h>

namespace KernelHttp
{
namespace http2
{
    class Http2Transport
    {
    public:
        virtual ~Http2Transport() noexcept = default;

        _Must_inspect_result_
        virtual NTSTATUS Send(
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept = 0;

        _Must_inspect_result_
        virtual NTSTATUS Receive(
            _Out_writes_bytes_(length) UCHAR* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept = 0;
    };

    class Http2ITransportAdapter final : public Http2Transport
    {
    public:
        explicit Http2ITransportAdapter(_Inout_ core::ITransport& transport) noexcept
            : transport_(transport)
        {
        }

        _Must_inspect_result_
        NTSTATUS Send(
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept override
        {
            SIZE_T totalSent = 0;
            while (totalSent < length) {
                SIZE_T sent = 0;
                NTSTATUS status = transport_.Send(data + totalSent, length - totalSent, &sent);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (sent == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }
                totalSent += sent;
            }
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS Receive(
            _Out_writes_bytes_(length) UCHAR* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept override
        {
            return transport_.Receive(data, length, bytesReceived);
        }

    private:
        core::ITransport& transport_;
    };

    class Http2Connection final
    {
    public:
        Http2Connection() noexcept = default;
        ~Http2Connection() noexcept;

        Http2Connection(const Http2Connection&) = delete;
        Http2Connection& operator=(const Http2Connection&) = delete;

        NTSTATUS Initialize(_Inout_ Http2Transport& transport) noexcept;

        NTSTATUS Initialize(_Inout_ core::ITransport& transport) noexcept;

        NTSTATUS SendRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _Out_writes_bytes_(responseBodyCapacity) char* responseBody,
            SIZE_T responseBodyCapacity,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ core::ITransport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _Out_writes_bytes_(responseBodyCapacity) char* responseBody,
            SIZE_T responseBodyCapacity,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS Shutdown(_Inout_ Http2Transport& transport) noexcept;

        NTSTATUS Shutdown(_Inout_ core::ITransport& transport) noexcept;

    private:
        // Send raw bytes through transport
        NTSTATUS SendRaw(
            _Inout_ Http2Transport& transport,
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept;

        // Read exactly 'length' bytes from transport into buffer
        NTSTATUS ReadExact(
            _Inout_ Http2Transport& transport,
            _Out_writes_bytes_(length) UCHAR* buffer,
            SIZE_T length) noexcept;

        // Read next frame header + payload
        NTSTATUS ReadFrame(
            _Inout_ Http2Transport& transport,
            _Out_ Http2FrameHeader* header,
            _Out_writes_bytes_(payloadCapacity) UCHAR* payload,
            SIZE_T payloadCapacity,
            _Out_ SIZE_T* payloadLength) noexcept;

        // Handle connection-level frames (SETTINGS, PING, GOAWAY, WINDOW_UPDATE on stream 0)
        NTSTATUS HandleConnectionFrame(
            _Inout_ Http2Transport& transport,
            _In_ const Http2FrameHeader& header,
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen) noexcept;

        // Send WINDOW_UPDATE for connection and/or stream
        NTSTATUS SendWindowUpdateIfNeeded(
            _Inout_ Http2Transport& transport,
            ULONG streamId,
            ULONG consumed) noexcept;

        ULONG AllocateStreamId() noexcept;

        // Parse :status from decoded headers
        static USHORT ExtractStatusCode(
            _In_reads_(headerCount) const http::HttpHeader* headers,
            SIZE_T headerCount) noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureBuffers() noexcept;

        Http2Settings localSettings_ = {};
        Http2Settings peerSettings_ = {};
        ULONG nextStreamId_ = 1;
        LONG connectionSendWindow_ = Http2InitialWindowSize;
        LONG connectionRecvWindow_ = Http2InitialWindowSize;
        ULONG connectionRecvConsumed_ = 0;
        bool goAwaySent_ = false;
        bool goAwayReceived_ = false;
        ULONG goAwayLastStreamId_ = 0;
        bool settingsAckReceived_ = false;

        HpackEncoder encoder_ = {};
        HpackDecoder decoder_ = {};
        UCHAR* sendBuffer_ = nullptr;
        UCHAR* framePayload_ = nullptr;
        UCHAR* headerBlock_ = nullptr;
        UCHAR* responseHeaderBlock_ = nullptr;
    };
}
}
