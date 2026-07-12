#pragma once

#include <wknet/WknetLimits.h>
#include "transport/Transport.h"
#include "http2/Http2Frame.h"
#include "http2/Hpack.h"
#include "http2/Http2Stream.h"

namespace wknet
{
namespace http2
{
    constexpr SIZE_T Http2DefaultHeaderBlockCapacity = 32 * 1024;
    constexpr SIZE_T Http2MaxHeaderBlockCapacity = WKNET_HARD_MAX_HEADER_SECTION;

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

        _Must_inspect_result_
        virtual NTSTATUS ReceiveWithTimeout(
            _Out_writes_bytes_(length) UCHAR* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept = 0;
    };

    class Http2TransportAdapter final : public Http2Transport
    {
    public:
        explicit Http2TransportAdapter(_Inout_ transport::Transport* transport) noexcept
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
                NTSTATUS status = transport::TransportSend(
                    transport_, data + totalSent, length - totalSent, &sent);
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
            return transport::TransportReceive(transport_, data, length, bytesReceived);
        }

        _Must_inspect_result_
        NTSTATUS ReceiveWithTimeout(
            _Out_writes_bytes_(length) UCHAR* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override
        {
            return transport::TransportReceiveWithTimeout(
                transport_, data, length, bytesReceived, timeoutMilliseconds);
        }

    private:
        transport::Transport* transport_;
    };

    typedef NTSTATUS (*Http2ResponseBodyAppendCallback)(
        _Inout_opt_ void* context,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength);

    struct Http2ResponseBodySink final
    {
        Http2ResponseBodyAppendCallback Append = nullptr;
        void* Context = nullptr;
    };

    typedef NTSTATUS (*Http2RequestBodyReadCallback)(
        _Inout_opt_ void* context,
        _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
        SIZE_T bufferCapacity,
        _Out_ SIZE_T* bytesRead,
        _Out_ bool* endOfBody);

    struct Http2RequestBodySource final
    {
        Http2RequestBodyReadCallback Read = nullptr;
        void* Context = nullptr;
        SIZE_T ContentLength = 0;
        bool ContentLengthKnown = false;
    };

    struct Http2RequestBody final
    {
        _In_reads_bytes_opt_(DataLength) const UCHAR* Data = nullptr;
        SIZE_T DataLength = 0;
        const Http2RequestBodySource* Source = nullptr;
        _In_reads_opt_(TrailerCount) const http1::HttpHeader* Trailers = nullptr;
        SIZE_T TrailerCount = 0;
        const Http2Priority* Priority = nullptr;
        bool HasBody = false;
    };

    struct Http2ResponseFrameState final
    {
        bool StreamClosed = false;
        bool TerminalResponseReceived = false;
        bool ResponseHeadersReceived = false;
        bool ResponseDataReceived = false;
        bool ResponseContentLengthPresent = false;
        ULONGLONG ResponseContentLength = 0;
        bool RequestForbidsResponseBody = false;
        bool ResponseBodyForbidden = false;
        bool TunnelMode = false;
        bool ExpectingContinuation = false;
        bool PendingHeaderEndStream = false;
        ULONG ContinuationStreamId = 0;
        ULONG ContinuationFrames = 0;
        ULONG EmptyContinuationFrames = 0;
        UCHAR* ResponseHeaderBlock = nullptr;
        SIZE_T ResponseHeaderBlockCapacity = 0;
        SIZE_T ResponseHeaderBlockLen = 0;
        http1::HttpHeader* ResponseHeaders = nullptr;
        SIZE_T ResponseHeaderCapacity = 0;
        SIZE_T* ResponseHeaderCount = nullptr;
        Http2ResponseBodySink ResponseBodySink = {};
        SIZE_T* ResponseBodyLength = nullptr;
        USHORT* StatusCode = nullptr;
        char* NameValueBuffer = nullptr;
        SIZE_T NameValueCapacity = 0;
        SIZE_T BodyLength = 0;
    };

    struct Http2ActiveStream final
    {
        bool InUse = false;
        Http2Stream Stream = {};
        Http2ResponseFrameState ResponseState = {};
    };

    class Http2Connection;

    NTSTATUS Http2ConnectionCreate(_Out_ Http2Connection** connection) noexcept;
    void Http2ConnectionClose(_Inout_opt_ Http2Connection* connection) noexcept;
    NTSTATUS Http2ConnectionInitialize(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;
    NTSTATUS Http2ConnectionInitializeAfterUpgrade(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;
    NTSTATUS Http2ConnectionBeginRequest(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _In_ const Http2RequestBody* requestBody,
        _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        _Out_ SIZE_T* responseHeaderCount,
        _In_ const Http2ResponseBodySink* responseBodySink,
        _Out_ SIZE_T* responseBodyLength,
        _Out_ USHORT* statusCode,
        _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        _Out_ ULONG* streamId) noexcept;
    NTSTATUS Http2ConnectionReceiveResponse(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        ULONG streamId) noexcept;
    NTSTATUS Http2ConnectionReceiveResponseDetailed(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        ULONG streamId,
        _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        _Out_ SIZE_T* responseHeaderCount,
        _In_ const Http2ResponseBodySink* responseBodySink,
        _Out_ SIZE_T* responseBodyLength,
        _Out_ USHORT* statusCode,
        _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept;
    NTSTATUS Http2ConnectionReceiveResponseHeaders(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        ULONG streamId) noexcept;
    NTSTATUS Http2ConnectionSendStreamData(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        ULONG streamId,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        bool endStream) noexcept;
    NTSTATUS Http2ConnectionReceiveStreamData(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        ULONG streamId,
        _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
        SIZE_T bufferCapacity,
        _Out_ SIZE_T* bytesReceived,
        _Out_ bool* endStream) noexcept;
    NTSTATUS Http2ConnectionSendPingAndWaitForAck(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport,
        _In_reads_bytes_(8) const UCHAR* opaqueData,
        ULONG ackTimeoutMilliseconds) noexcept;
    NTSTATUS Http2ConnectionShutdown(
        _Inout_ Http2Connection* connection,
        _Inout_ transport::Transport* transport) noexcept;
    bool Http2ConnectionIsReusable(_In_opt_ const Http2Connection* connection) noexcept;
    ULONG Http2ConnectionMaxConcurrentStreams(_Inout_ Http2Connection* connection) noexcept;
    void Http2ConnectionReleaseStream(_Inout_opt_ Http2Connection* connection, ULONG streamId) noexcept;
}
}
