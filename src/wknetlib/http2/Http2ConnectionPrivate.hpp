#pragma once

#include "http2/Http2Connection.h"

namespace wknet
{
namespace http2
{
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
            _Inout_ transport::Transport* transport,
            SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;

        NTSTATUS InitializeAfterUpgrade(
            _Inout_ Http2Transport& transport,
            SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;

        NTSTATUS InitializeAfterUpgrade(
            _Inout_ transport::Transport* transport,
            SIZE_T maxHeaderBlockBytes = Http2DefaultHeaderBlockCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
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
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
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
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ transport::Transport* transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _Out_writes_bytes_(responseBodyCapacity) char* responseBody,
            SIZE_T responseBodyCapacity,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ transport::Transport* transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _Out_writes_bytes_(responseBodyCapacity) char* responseBody,
            SIZE_T responseBodyCapacity,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ transport::Transport* transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS SendRequest(
            _Inout_ transport::Transport* transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
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
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
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
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ transport::Transport* transport,
            ULONG streamId,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _Out_writes_bytes_(responseBodyCapacity) char* responseBody,
            SIZE_T responseBodyCapacity,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS ReceiveResponse(
            _Inout_ transport::Transport* transport,
            ULONG streamId,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity) noexcept;

        NTSTATUS BeginRequest(
            _Inout_ Http2Transport& transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
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
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity,
            _Out_ ULONG* streamId) noexcept;

        NTSTATUS BeginRequest(
            _Inout_ transport::Transport* transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_ const Http2RequestBody& requestBody,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            _Out_ SIZE_T* responseHeaderCount,
            _In_ const Http2ResponseBodySink& responseBodySink,
            _Out_ SIZE_T* responseBodyLength,
            _Out_ USHORT* statusCode,
            _Out_writes_bytes_(nameValueCapacity) char* nameValueBuffer,
            SIZE_T nameValueCapacity,
            _Out_ ULONG* streamId) noexcept;

        NTSTATUS BeginRequest(
            _Inout_ transport::Transport* transport,
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
            SIZE_T requestHeaderCount,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
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
            _Inout_ transport::Transport* transport,
            ULONG streamId) noexcept;

        NTSTATUS ReceiveResponseHeaders(
            _Inout_ Http2Transport& transport,
            ULONG streamId) noexcept;

        NTSTATUS ReceiveResponseHeaders(
            _Inout_ transport::Transport* transport,
            ULONG streamId) noexcept;

        NTSTATUS SendStreamData(
            _Inout_ Http2Transport& transport,
            ULONG streamId,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            bool endStream) noexcept;

        NTSTATUS SendStreamData(
            _Inout_ transport::Transport* transport,
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
            _Inout_ transport::Transport* transport,
            ULONG streamId,
            _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
            SIZE_T bufferCapacity,
            _Out_ SIZE_T* bytesReceived,
            _Out_ bool* endStream) noexcept;

        NTSTATUS SendPing(
            _Inout_ Http2Transport& transport,
            _In_reads_bytes_(8) const UCHAR* opaqueData) noexcept;

        NTSTATUS SendPing(
            _Inout_ transport::Transport* transport,
            _In_reads_bytes_(8) const UCHAR* opaqueData) noexcept;

        NTSTATUS SendPingAndWaitForAck(
            _Inout_ Http2Transport& transport,
            _In_reads_bytes_(8) const UCHAR* opaqueData,
            ULONG ackTimeoutMilliseconds) noexcept;

        NTSTATUS SendPingAndWaitForAck(
            _Inout_ transport::Transport* transport,
            _In_reads_bytes_(8) const UCHAR* opaqueData,
            ULONG ackTimeoutMilliseconds) noexcept;

        NTSTATUS Shutdown(_Inout_ Http2Transport& transport) noexcept;

        NTSTATUS Shutdown(_Inout_ transport::Transport* transport) noexcept;

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

        NTSTATUS ReadExactWithTimeout(
            _Inout_ Http2Transport& transport,
            _Out_writes_bytes_(length) UCHAR* buffer,
            SIZE_T length,
            ULONG timeoutMilliseconds) noexcept;

        // Read next frame header + payload
        NTSTATUS ReadFrame(
            _Inout_ Http2Transport& transport,
            _Out_ Http2FrameHeader* header,
            _Out_writes_bytes_(payloadCapacity) UCHAR* payload,
            SIZE_T payloadCapacity,
            _Out_ SIZE_T* payloadLength) noexcept;

        NTSTATUS ReadFrameWithTimeout(
            _Inout_ Http2Transport& transport,
            _Out_ Http2FrameHeader* header,
            _Out_writes_bytes_(payloadCapacity) UCHAR* payload,
            SIZE_T payloadCapacity,
            _Out_ SIZE_T* payloadLength,
            ULONG timeoutMilliseconds) noexcept;

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
            _Out_writes_(responseHeaderCapacity) http1::HttpHeader* responseHeaders,
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
            _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
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
            _In_reads_(trailerCount) const http1::HttpHeader* trailers,
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
            _In_reads_(headerCount) const http1::HttpHeader* headers,
            SIZE_T headerCount) noexcept;

        static NTSTATUS ValidateResponseHeaderBlock(
            _In_reads_(headerCount) const http1::HttpHeader* headers,
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

#if !defined(WKNET_USER_MODE_TEST)
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
        http1::HttpHeader* decodedHeaderScratch_ = nullptr;
        SIZE_T decodedHeaderScratchCapacity_ = 0;
        http1::HttpHeader trailerHeaders_[16] = {};
        Http2ActiveStream* activeStreams_ = nullptr;
        SIZE_T activeStreamCapacity_ = 0;
    };
}
}
