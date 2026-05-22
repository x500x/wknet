#pragma once

#include "http2/Http2Frame.h"
#include "http2/Hpack.h"
#include "http2/Http2Stream.h"
#include "net/WskSocket.h"
#include "tls/TlsConnection.h"

namespace KernelHttp
{
namespace http2
{
    class Http2Connection final
    {
    public:
        Http2Connection() noexcept = default;
        ~Http2Connection() noexcept;

        Http2Connection(const Http2Connection&) = delete;
        Http2Connection& operator=(const Http2Connection&) = delete;

        // Establish HTTP/2 connection:
        // Send connection preface + initial SETTINGS, receive peer SETTINGS and ACK
        _Must_inspect_result_
        NTSTATUS Initialize(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls) noexcept;

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

        // Graceful shutdown (send GOAWAY)
        NTSTATUS Shutdown(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls) noexcept;

    private:
        // Send raw bytes through TLS
        NTSTATUS SendRaw(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls,
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept;

        // Read exactly 'length' bytes from TLS into buffer
        NTSTATUS ReadExact(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls,
            _Out_writes_bytes_(length) UCHAR* buffer,
            SIZE_T length) noexcept;

        // Read next frame header + payload
        NTSTATUS ReadFrame(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls,
            _Out_ Http2FrameHeader* header,
            _Out_writes_bytes_(payloadCapacity) UCHAR* payload,
            SIZE_T payloadCapacity,
            _Out_ SIZE_T* payloadLength) noexcept;

        // Handle connection-level frames (SETTINGS, PING, GOAWAY, WINDOW_UPDATE on stream 0)
        NTSTATUS HandleConnectionFrame(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls,
            _In_ const Http2FrameHeader& header,
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen) noexcept;

        // Send WINDOW_UPDATE for connection and/or stream
        NTSTATUS SendWindowUpdateIfNeeded(
            _Inout_ net::WskSocket& socket,
            _Inout_ tls::TlsConnection& tls,
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
