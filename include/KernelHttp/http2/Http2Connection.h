#pragma once

#include <KernelHttp/http2/Http2Frame.h>
#include <KernelHttp/http2/Hpack.h>
#include <KernelHttp/http2/Http2Stream.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/TlsConnection.h>

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

    class Http2TlsTransport final : public Http2Transport
    {
    public:
        Http2TlsTransport(_Inout_ net::WskSocket& socket, _Inout_ tls::TlsConnection& tls) noexcept;

        _Must_inspect_result_
        NTSTATUS Send(
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept override;

        _Must_inspect_result_
        NTSTATUS Receive(
            _Out_writes_bytes_(length) UCHAR* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept override;

    private:
        net::WskSocket& socket_;
        tls::TlsConnection& tls_;
    };

    class Http2PlainTransport final : public Http2Transport
    {
    public:
        explicit Http2PlainTransport(_Inout_ net::WskSocket& socket) noexcept;

        _Must_inspect_result_
        NTSTATUS Send(
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept override;

        _Must_inspect_result_
        NTSTATUS Receive(
            _Out_writes_bytes_(length) UCHAR* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived) noexcept override;

    private:
        net::WskSocket& socket_;
    };

    class Http2Connection final
    {
    public:
        Http2Connection() noexcept = default;
        ~Http2Connection() noexcept;

        Http2Connection(const Http2Connection&) = delete;
        Http2Connection& operator=(const Http2Connection&) = delete;

        NTSTATUS Initialize(_Inout_ Http2Transport& transport) noexcept;

        // Establish HTTP/2 connection:
        // Send connection preface + initial SETTINGS, receive peer SETTINGS and ACK
        _Must_inspect_result_
        NTSTATUS Initialize(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls) noexcept;

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

        // Send a single request and read the response (synchronous, single stream)
        _Must_inspect_result_
        NTSTATUS SendRequest(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls,
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

        // Graceful shutdown (send GOAWAY)
        NTSTATUS Shutdown(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls) noexcept;

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
