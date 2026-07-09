#pragma once

#include <KernelHttp/KernelHttpLimits.h>
#include <KernelHttp/core/ITransport.h>
#include <KernelHttp/http2/Http2Frame.h>
#include <KernelHttp/http2/Hpack.h>
#include <KernelHttp/http2/Http2Stream.h>

namespace KernelHttp
{
namespace http2
{
    constexpr SIZE_T Http2DefaultHeaderBlockCapacity = 32 * 1024;
    constexpr SIZE_T Http2MaxHeaderBlockCapacity = KH_HARD_MAX_HEADER_SECTION;

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
        _In_reads_opt_(TrailerCount) const http::HttpHeader* Trailers = nullptr;
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
        http::HttpHeader* ResponseHeaders = nullptr;
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

    class Http2Connection final
    {
    public:
        Http2Connection() noexcept;
        ~Http2Connection() noexcept;

        Http2Connection(const Http2Connection&) = delete;
        Http2Connection& operator=(const Http2Connection&) = delete;

        NTSTATUS Initialize(
            _Inout_ Http2Transport& transport,
            SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;

        NTSTATUS Initialize(
            _Inout_ core::ITransport& transport,
            SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;

        NTSTATUS InitializeAfterUpgrade(
            _Inout_ Http2Transport& transport,
            SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;

        NTSTATUS InitializeAfterUpgrade(
            _Inout_ core::ITransport& transport,
            SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
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
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ core::ITransport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
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

        NTSTATUS SendRequest(
            _Inout_ core::ITransport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
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
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ Http2Transport& transport,
            ULONG streamId,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _Out_writes_bytes_(responseBodyCapacity) char* responseBody,
            SIZE_T responseBodyCapacity,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ Http2Transport& transport,
            ULONG streamId,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ core::ITransport& transport,
            ULONG streamId,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _Out_writes_bytes_(responseBodyCapacity) char* responseBody,
            SIZE_T responseBodyCapacity,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ core::ITransport& transport,
            ULONG streamId,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS BeginRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity,
            _Out_ ULONG* streamId) noexcept;

        NTSTATUS BeginRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity,
            _Out_ ULONG* streamId) noexcept;

        NTSTATUS BeginRequest(
            _Inout_ core::ITransport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity,
            _Out_ ULONG* streamId) noexcept;

        NTSTATUS BeginRequest(
            _Inout_ core::ITransport& transport,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity,
            _Out_ ULONG* streamId) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ Http2Transport& transport,
            ULONG streamId) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ core::ITransport& transport,
            ULONG streamId) noexcept;

        NTSTATUS ReceiveResponseHeaders(
            _Inout_ Http2Transport& transport,
            ULONG streamId) noexcept;

        NTSTATUS ReceiveResponseHeaders(
            _Inout_ core::ITransport& transport,
            ULONG streamId) noexcept;

        NTSTATUS SendStreamData(
            _Inout_ Http2Transport& transport,
            ULONG streamId,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            bool endStream) noexcept;

        NTSTATUS SendStreamData(
            _Inout_ core::ITransport& transport,
            ULONG streamId,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            bool endStream) noexcept;

        NTSTATUS ReceiveStreamData(
            _Inout_ Http2Transport& transport,
            ULONG streamId,
            _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
            SIZE_T bufferCapacity,
            _Out_ SIZE_T* bytesReceived,
            _Out_ bool* endStream) noexcept;

        NTSTATUS ReceiveStreamData(
            _Inout_ core::ITransport& transport,
            ULONG streamId,
            _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
            SIZE_T bufferCapacity,
            _Out_ SIZE_T* bytesReceived,
            _Out_ bool* endStream) noexcept;

        NTSTATUS SendPing(
            _Inout_ Http2Transport& transport,
            _In_reads_bytes_(8) const UCHAR* opaqueData) noexcept;

        NTSTATUS SendPing(
            _Inout_ core::ITransport& transport,
            _In_reads_bytes_(8) const UCHAR* opaqueData) noexcept;

        NTSTATUS Shutdown(_Inout_ Http2Transport& transport) noexcept;

        NTSTATUS Shutdown(_Inout_ core::ITransport& transport) noexcept;

        bool IsReusable() const noexcept;

        ULONG MaxConcurrentStreams() noexcept;

        void ReleaseStream(ULONG streamId) noexcept;

    private:
        class ScopedStateLock final
        {
        public:
            explicit ScopedStateLock(_Inout_ Http2Connection& connection) noexcept
                : connection_(connection)
            {
                connection_.LockState();
            }

            ~ScopedStateLock() noexcept
            {
                connection_.UnlockState();
            }

            ScopedStateLock(const ScopedStateLock&) = delete;
            ScopedStateLock& operator=(const ScopedStateLock&) = delete;

        private:
            Http2Connection& connection_;
        };

        class ScopedReceiveLock final
        {
        public:
            explicit ScopedReceiveLock(_Inout_ Http2Connection& connection, bool enabled = true) noexcept
                : connection_(connection),
                  enabled_(enabled)
            {
                if (enabled_) {
                    connection_.LockReceive();
                }
            }

            ~ScopedReceiveLock() noexcept
            {
                if (enabled_) {
                    connection_.UnlockReceive();
                }
            }

            ScopedReceiveLock(const ScopedReceiveLock&) = delete;
            ScopedReceiveLock& operator=(const ScopedReceiveLock&) = delete;

        private:
            Http2Connection& connection_;
            bool enabled_ = false;
        };

        void InitializeLocks() noexcept;
        void LockState() noexcept;
        void UnlockState() noexcept;
        void LockReceive() noexcept;
        void UnlockReceive() noexcept;

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
            SIZE_T payloadLen,
            _Inout_opt_ Http2Stream* activeStream) noexcept;

        // Send WINDOW_UPDATE for connection and/or stream
        NTSTATUS SendWindowUpdateIfNeeded(
            _Inout_ Http2Transport& transport,
            _Inout_opt_ Http2Stream* stream,
            ULONG consumed) noexcept;

        NTSTATUS SendGoAway(
            _Inout_ Http2Transport& transport,
            ULONG errorCode) noexcept;

        NTSTATUS SendRstStream(
            _Inout_ Http2Transport& transport,
            ULONG streamId,
            ULONG errorCode) noexcept;

        NTSTATUS ReceiveResponseFrames(
            _Inout_ Http2Transport& transport,
            _Inout_ Http2Stream& stream,
            bool requestForbidsResponseBody,
            _Out_writes_(responseHeaderCapacity) http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS ReceiveResponseFramesWithState(
            _Inout_ Http2Transport& transport,
            _Inout_ Http2Stream& stream,
            _Inout_ Http2ResponseFrameState& state) noexcept;

        NTSTATUS ProcessResponseFrame(
            _Inout_ Http2Transport& transport,
            _Inout_ Http2Stream& stream,
            _In_ const Http2FrameHeader& header,
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Inout_ Http2ResponseFrameState& state) noexcept;

        NTSTATUS SendRequestFrames(
            _Inout_ Http2Transport& transport,
            _Inout_ Http2Stream& stream,
            _Inout_ Http2ResponseFrameState& responseFrameState,
            _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody) noexcept;

        NTSTATUS SendRequestBodyFrames(
            _Inout_ Http2Transport& transport,
            _Inout_ Http2Stream& stream,
            _Inout_ Http2ResponseFrameState& responseFrameState,
            _In_ const Http2RequestBody& requestBody) noexcept;

        NTSTATUS SendRequestTrailingHeaders(
            _Inout_ Http2Transport& transport,
            _Inout_ Http2Stream& stream,
            _In_reads_(trailerCount) const http::HttpHeader* trailers,
            SIZE_T trailerCount) noexcept;

        NTSTATUS DispatchNextFrame(
            _Inout_ Http2Transport& transport,
            _Inout_opt_ Http2Stream* activeStream = nullptr) noexcept;

        NTSTATUS DispatchFrame(
            _Inout_ Http2Transport& transport,
            _In_ const Http2FrameHeader& header,
            _In_reads_bytes_(payloadLen) const UCHAR* payload,
            SIZE_T payloadLen,
            _Inout_opt_ Http2Stream* activeStream = nullptr) noexcept;

        Http2ActiveStream* FindActiveStream(ULONG streamId) noexcept;
        Http2ActiveStream* FindContinuationStream() noexcept;
        Http2ActiveStream* ReserveActiveStream() noexcept;
        void ReleaseActiveStream(ULONG streamId) noexcept;
        NTSTATUS AdjustActiveStreamRemoteWindows(long long delta) noexcept;

        ULONG AllocateStreamId() noexcept;

        NTSTATUS HandleReadFrameFailure(
            _Inout_ Http2Transport& transport,
            NTSTATUS status) noexcept;

        NTSTATUS RecordReceivedFrame(
            _In_ const Http2FrameHeader& header) noexcept;

        NTSTATUS RecordConnectionControlSignal() noexcept;

        // Parse :status from decoded headers
        static USHORT ExtractStatusCode(
            _In_reads_(headerCount) const http::HttpHeader* headers,
            SIZE_T headerCount) noexcept;

        static NTSTATUS ValidateResponseHeaderBlock(
            _In_reads_(headerCount) const http::HttpHeader* headers,
            SIZE_T headerCount,
            bool trailers,
            _Out_opt_ USHORT* statusCode,
            _Out_opt_ bool* contentLengthPresent = nullptr,
            _Out_opt_ ULONGLONG* contentLength = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureBuffers() noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureDecodedHeaderScratch(SIZE_T responseHeaderCapacity) noexcept;

        ULONG MaxConcurrentStreamsLocked() const noexcept;

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        KMUTEX stateLock_ = {};
        KMUTEX receiveLock_ = {};
        bool locksInitialized_ = false;
#endif
        Http2Settings localSettings_ = {};
        Http2Settings peerSettings_ = {};
        ULONG nextStreamId_ = 1;
        LONG connectionSendWindow_ = Http2InitialWindowSize;
        LONG connectionRecvWindow_ = Http2InitialWindowSize;
        ULONG connectionRecvConsumed_ = 0;
        ULONGLONG connectionBytesRead_ = 0;
        ULONG connectionFramesRead_ = 0;
        ULONG connectionControlSignals_ = 0;
        bool goAwaySent_ = false;
        bool goAwayReceived_ = false;
        ULONG goAwayLastStreamId_ = 0;
        bool settingsAckReceived_ = false;
        ULONG readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::NoError);
        SIZE_T framePayloadCapacity_ = 0;
        SIZE_T headerBlockCapacity_ = Http2DefaultHeaderBlockCapacity;

        HpackEncoder encoder_ = {};
        HpackDecoder decoder_ = {};
        UCHAR* sendBuffer_ = nullptr;
        UCHAR* framePayload_ = nullptr;
        UCHAR* headerBlock_ = nullptr;
        UCHAR* responseHeaderBlock_ = nullptr;
        http::HttpHeader* decodedHeaderScratch_ = nullptr;
        SIZE_T decodedHeaderScratchCapacity_ = 0;
        http::HttpHeader trailerHeaders_[16] = {};
        Http2ActiveStream* activeStreams_ = nullptr;
        SIZE_T activeStreamCapacity_ = 0;
    };
}
}
