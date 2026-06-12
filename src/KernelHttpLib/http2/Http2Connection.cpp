#include <KernelHttp/http2/Http2Connection.h>

namespace KernelHttp
{
namespace http2
{
    namespace
    {
        constexpr SIZE_T HeaderBlockCapacity = 16384;
        constexpr SIZE_T SendBufferCapacity = 32768;
        constexpr ULONG LocalMaxFramePayloadSize = 32768;

        // Window update threshold: send WINDOW_UPDATE when half consumed
        constexpr ULONG WindowUpdateThreshold = Http2InitialWindowSize / 2;
        constexpr ULONG Http2MaxContinuationFrames = 64;
        constexpr ULONG Http2MaxEmptyContinuationFrames = 4;

        void MemCopy(void* dst, const void* src, SIZE_T len) noexcept
        {
            auto* d = static_cast<UCHAR*>(dst);
            auto* s = static_cast<const UCHAR*>(src);
            for (SIZE_T i = 0; i < len; ++i) d[i] = s[i];
        }

        struct FixedResponseBodySinkContext final
        {
            char* Buffer = nullptr;
            SIZE_T Capacity = 0;
            SIZE_T Length = 0;
        };

        bool AddWouldOverflow(SIZE_T left, SIZE_T right) noexcept
        {
            return left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right;
        }

        void LogRequestBodyFlowControlFailure(
            NTSTATUS status,
            SIZE_T bodyOffset,
            SIZE_T bodyLength,
            LONG connectionWindow,
            LONG streamWindow) noexcept
        {
            kprintf(
                "Http2Connection request body flow-control failed: status=0x%08X bodyOffset=%Iu bodyLength=%Iu connWindow=%ld streamWindow=%ld\r\n",
                static_cast<ULONG>(status),
                bodyOffset,
                bodyLength,
                connectionWindow,
                streamWindow);
        }

        NTSTATUS AppendFixedResponseBody(
            void* context,
            const UCHAR* data,
            SIZE_T dataLength) noexcept
        {
            auto* fixed = static_cast<FixedResponseBodySinkContext*>(context);
            if (fixed == nullptr || (data == nullptr && dataLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            if (dataLength == 0) {
                return STATUS_SUCCESS;
            }

            if (AddWouldOverflow(fixed->Length, dataLength)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            const SIZE_T requiredLength = fixed->Length + dataLength;
            if (fixed->Buffer == nullptr || requiredLength > fixed->Capacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            MemCopy(fixed->Buffer + fixed->Length, data, dataLength);
            fixed->Length = requiredLength;
            return STATUS_SUCCESS;
        }

        bool TextEquals(const char* a, SIZE_T aLen, const char* b, SIZE_T bLen) noexcept
        {
            if (aLen != bLen) return false;
            for (SIZE_T i = 0; i < aLen; ++i) {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        USHORT ParseStatusCode(const char* data, SIZE_T len) noexcept
        {
            if (len != 3) return 0;
            USHORT code = 0;
            for (SIZE_T i = 0; i < 3; ++i) {
                if (data[i] < '0' || data[i] > '9') return 0;
                code = static_cast<USHORT>(code * 10 + (data[i] - '0'));
            }
            return code;
        }

        bool ParseUnsignedDecimal(const char* data, SIZE_T len, ULONGLONG* value) noexcept
        {
            if (data == nullptr || len == 0 || value == nullptr) {
                return false;
            }

            ULONGLONG parsed = 0;
            constexpr ULONGLONG MaxValue = static_cast<ULONGLONG>(~0ULL);
            for (SIZE_T i = 0; i < len; ++i) {
                if (data[i] < '0' || data[i] > '9') {
                    return false;
                }
                const ULONGLONG digit = static_cast<ULONGLONG>(data[i] - '0');
                if (parsed > (MaxValue - digit) / 10ULL) {
                    return false;
                }
                parsed = (parsed * 10ULL) + digit;
            }

            *value = parsed;
            return true;
        }

        bool TextContainsUppercase(const char* data, SIZE_T len) noexcept
        {
            if (data == nullptr && len != 0) return true;
            for (SIZE_T i = 0; i < len; ++i) {
                if (data[i] >= 'A' && data[i] <= 'Z') return true;
            }
            return false;
        }

        bool TextEqualsAsciiInsensitive(const char* a, SIZE_T aLen, const char* b, SIZE_T bLen) noexcept
        {
            if (aLen != bLen) return false;
            if ((a == nullptr && aLen != 0) || (b == nullptr && bLen != 0)) return false;
            for (SIZE_T i = 0; i < aLen; ++i) {
                char ca = a[i];
                char cb = b[i];
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca + 32);
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb + 32);
                if (ca != cb) return false;
            }
            return true;
        }

        bool IsConnectionSpecificHeaderName(const char* name, SIZE_T nameLen) noexcept
        {
            return TextEquals(name, nameLen, "connection", 10) ||
                TextEquals(name, nameLen, "keep-alive", 10) ||
                TextEquals(name, nameLen, "proxy-connection", 16) ||
                TextEquals(name, nameLen, "transfer-encoding", 17) ||
                TextEquals(name, nameLen, "upgrade", 7);
        }

        ULONG ReadUint32BE(const UCHAR* p) noexcept
        {
            return (static_cast<ULONG>(p[0]) << 24) |
                (static_cast<ULONG>(p[1]) << 16) |
                (static_cast<ULONG>(p[2]) << 8) |
                static_cast<ULONG>(p[3]);
        }

        USHORT ReadUint16BE(const UCHAR* p) noexcept
        {
            return static_cast<USHORT>(
                (static_cast<USHORT>(p[0]) << 8) |
                static_cast<USHORT>(p[1]));
        }

        ULONG SettingsErrorCodeForPayload(const UCHAR* payload, SIZE_T payloadLen) noexcept
        {
            if (payload == nullptr && payloadLen != 0) {
                return static_cast<ULONG>(Http2ErrorCode::ProtocolError);
            }
            if ((payloadLen % 6) != 0) {
                return static_cast<ULONG>(Http2ErrorCode::FrameSizeError);
            }

            for (SIZE_T offset = 0; offset < payloadLen; offset += 6) {
                const USHORT id = ReadUint16BE(payload + offset);
                const ULONG value = ReadUint32BE(payload + offset + 2);
                switch (static_cast<Http2SettingId>(id)) {
                case Http2SettingId::EnablePush:
                    if (value != 0) {
                        return static_cast<ULONG>(Http2ErrorCode::ProtocolError);
                    }
                    break;
                case Http2SettingId::InitialWindowSize:
                    if (value > Http2MaxWindowSize) {
                        return static_cast<ULONG>(Http2ErrorCode::FlowControlError);
                    }
                    break;
                case Http2SettingId::MaxFrameSize:
                    if (value < Http2DefaultMaxFrameSize || value > Http2MaxAllowedFrameSize) {
                        return static_cast<ULONG>(Http2ErrorCode::ProtocolError);
                    }
                    break;
                default:
                    break;
                }
            }

            return static_cast<ULONG>(Http2ErrorCode::ProtocolError);
        }

        bool IsValidFrameTarget(const Http2FrameHeader& header) noexcept
        {
            switch (header.Type) {
            case Http2FrameType::Data:
            case Http2FrameType::Headers:
            case Http2FrameType::Priority:
            case Http2FrameType::RstStream:
            case Http2FrameType::Continuation:
                return header.StreamId != 0;
            case Http2FrameType::Settings:
            case Http2FrameType::Ping:
            case Http2FrameType::GoAway:
                return header.StreamId == 0;
            case Http2FrameType::PushPromise:
                return header.StreamId != 0;
            case Http2FrameType::WindowUpdate:
                return true;
            default:
                return true;
            }
        }

        bool IsHpackCompressionFailure(NTSTATUS status) noexcept
        {
            return status == STATUS_INVALID_NETWORK_RESPONSE ||
                status == STATUS_INTEGER_OVERFLOW ||
                status == STATUS_MORE_PROCESSING_REQUIRED;
        }

        bool IsValidHttp2FieldName(const char* data, SIZE_T len) noexcept
        {
            if (data == nullptr || len == 0) {
                return false;
            }

            const bool pseudo = data[0] == ':';
            if (pseudo && len == 1) {
                return false;
            }

            for (SIZE_T i = pseudo ? 1 : 0; i < len; ++i) {
                const UCHAR c = static_cast<UCHAR>(data[i]);
                if (c <= 0x20 || c >= 0x7f || c == ':' ||
                    (c >= static_cast<UCHAR>('A') && c <= static_cast<UCHAR>('Z'))) {
                    return false;
                }
            }

            return true;
        }

        bool IsValidHttp2FieldValue(const char* data, SIZE_T len) noexcept
        {
            if (data == nullptr && len != 0) {
                return false;
            }
            for (SIZE_T i = 0; i < len; ++i) {
                if (data[i] == '\0' || data[i] == '\r' || data[i] == '\n') {
                    return false;
                }
            }
            return true;
        }

        bool RequestForbidsResponseBody(
            const http::HttpHeader* headers,
            SIZE_T headerCount) noexcept
        {
            if (headers == nullptr && headerCount != 0) {
                return false;
            }
            for (SIZE_T i = 0; i < headerCount; ++i) {
                if (TextEquals(headers[i].Name.Data, headers[i].Name.Length, ":method", 7) &&
                    TextEquals(headers[i].Value.Data, headers[i].Value.Length, "HEAD", 4)) {
                    return true;
                }
            }
            return false;
        }

        bool StatusForbidsResponseBody(USHORT statusCode) noexcept
        {
            return (statusCode >= 100 && statusCode < 200) ||
                statusCode == 204 ||
                statusCode == 304;
        }

        NTSTATUS CopyRegularResponseHeaders(
            const http::HttpHeader* decodedHeaders,
            SIZE_T decodedHeaderCount,
            http::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCapacity,
            SIZE_T* responseHeaderCount) noexcept
        {
            if (responseHeaders == nullptr ||
                responseHeaderCount == nullptr ||
                (decodedHeaders == nullptr && decodedHeaderCount != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T regularHeaderCount = 0;
            for (SIZE_T index = 0; index < decodedHeaderCount; ++index) {
                const http::HttpHeader& header = decodedHeaders[index];
                if (header.Name.Data != nullptr &&
                    header.Name.Length != 0 &&
                    header.Name.Data[0] == ':') {
                    continue;
                }

                if (regularHeaderCount >= responseHeaderCapacity) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                responseHeaders[regularHeaderCount] = header;
                ++regularHeaderCount;
            }

            *responseHeaderCount = regularHeaderCount;
            return STATUS_SUCCESS;
        }

        ULONG OutboundPayloadLimit(ULONG peerMaxFrameSize) noexcept
        {
            const ULONG sendBufferPayload =
                static_cast<ULONG>(SendBufferCapacity - Http2FrameHeaderLength);
            ULONG limit = peerMaxFrameSize;
            if (limit > sendBufferPayload) {
                limit = sendBufferPayload;
            }
            return limit;
        }
    }

    Http2Connection::~Http2Connection() noexcept
    {
        FreeNonPagedArray(sendBuffer_);
        FreeNonPagedArray(framePayload_);
        FreeNonPagedArray(headerBlock_);
        FreeNonPagedArray(responseHeaderBlock_);
        FreeNonPagedArray(decodedHeaderScratch_);
        sendBuffer_ = nullptr;
        framePayload_ = nullptr;
        headerBlock_ = nullptr;
        responseHeaderBlock_ = nullptr;
        decodedHeaderScratch_ = nullptr;
        framePayloadCapacity_ = 0;
        decodedHeaderScratchCapacity_ = 0;
    }

    NTSTATUS Http2Connection::EnsureBuffers() noexcept
    {
        if (sendBuffer_ == nullptr) {
            sendBuffer_ = AllocateNonPagedArray<UCHAR>(SendBufferCapacity);
            if (sendBuffer_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (framePayload_ == nullptr) {
            framePayload_ = AllocateNonPagedArray<UCHAR>(LocalMaxFramePayloadSize);
            if (framePayload_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
            framePayloadCapacity_ = LocalMaxFramePayloadSize;
        }
        if (headerBlock_ == nullptr) {
            headerBlock_ = AllocateNonPagedArray<UCHAR>(HeaderBlockCapacity);
            if (headerBlock_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (responseHeaderBlock_ == nullptr) {
            responseHeaderBlock_ = AllocateNonPagedArray<UCHAR>(HeaderBlockCapacity);
            if (responseHeaderBlock_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::EnsureDecodedHeaderScratch(SIZE_T responseHeaderCapacity) noexcept
    {
        if (responseHeaderCapacity == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
            return STATUS_INTEGER_OVERFLOW;
        }

        const SIZE_T requiredCapacity = responseHeaderCapacity + 1;
        if (decodedHeaderScratch_ != nullptr &&
            decodedHeaderScratchCapacity_ >= requiredCapacity) {
            return STATUS_SUCCESS;
        }

        http::HttpHeader* scratch = AllocateNonPagedArray<http::HttpHeader>(requiredCapacity);
        if (scratch == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        FreeNonPagedArray(decodedHeaderScratch_);
        decodedHeaderScratch_ = scratch;
        decodedHeaderScratchCapacity_ = requiredCapacity;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::Initialize(Http2Transport& transport) noexcept
    {
        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        localSettings_.MaxFrameSize = LocalMaxFramePayloadSize;

        // Initialize HPACK encoder/decoder
        status = encoder_.Initialize(localSettings_.HeaderTableSize);
        if (!NT_SUCCESS(status)) return status;

        status = decoder_.Initialize(localSettings_.HeaderTableSize);
        if (!NT_SUCCESS(status)) return status;

        // Build and send connection preface + SETTINGS
        UCHAR* sendBuf = sendBuffer_;
        SIZE_T sendOffset = 0;

        // Connection preface
        MemCopy(sendBuf, Http2ConnectionPreface, Http2ConnectionPrefaceLength);
        sendOffset += Http2ConnectionPrefaceLength;

        // Client SETTINGS
        SIZE_T settingsWritten = 0;
        status = Http2FrameCodec::EncodeSettings(
            localSettings_, sendBuf + sendOffset,
            SendBufferCapacity - sendOffset, &settingsWritten);
        if (!NT_SUCCESS(status)) return status;
        sendOffset += settingsWritten;

        // Send preface + SETTINGS
        status = SendRaw(transport, sendBuf, sendOffset);
        if (!NT_SUCCESS(status)) return status;

        // Read peer's SETTINGS (must be the first frame from server)
        UCHAR* framePayload = framePayload_;
        Http2FrameHeader frameHeader = {};
        SIZE_T payloadLen = 0;

        status = ReadFrame(transport, &frameHeader, framePayload, framePayloadCapacity_, &payloadLen);
        if (!NT_SUCCESS(status)) return HandleReadFrameFailure(transport, status);

        if (frameHeader.Type != Http2FrameType::Settings ||
            (frameHeader.Flags & Http2FrameFlags::Ack) != 0 ||
            frameHeader.StreamId != 0) {
            const ULONG errorCode =
                frameHeader.Type == Http2FrameType::Settings &&
                (frameHeader.Flags & Http2FrameFlags::Ack) != 0 &&
                payloadLen != 0
                    ? static_cast<ULONG>(Http2ErrorCode::FrameSizeError)
                    : static_cast<ULONG>(Http2ErrorCode::ProtocolError);
            const NTSTATUS goAwayStatus = SendGoAway(transport, errorCode);
            UNREFERENCED_PARAMETER(goAwayStatus);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = Http2FrameCodec::DecodeSettingsPayload(framePayload, payloadLen, &peerSettings_);
        if (!NT_SUCCESS(status) || peerSettings_.EnablePush != 0) {
            const ULONG errorCode = SettingsErrorCodeForPayload(framePayload, payloadLen);
            const NTSTATUS goAwayStatus = SendGoAway(transport, errorCode);
            UNREFERENCED_PARAMETER(goAwayStatus);
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        encoder_.UpdateMaxTableSize(peerSettings_.HeaderTableSize);

        // Send SETTINGS ACK. Do not block here waiting for the peer ACK to our
        // SETTINGS: servers may wait until request frames arrive before sending
        // their ACK, and request-with-body samples would otherwise time out
        // before HEADERS/DATA are sent. Later ReadFrame loops handle the ACK as
        // a normal connection-level SETTINGS frame.
        UCHAR* ackBuf = sendBuffer_;
        SIZE_T ackWritten = 0;
        status = Http2FrameCodec::EncodeSettingsAck(ackBuf, Http2FrameHeaderLength, &ackWritten);
        if (!NT_SUCCESS(status)) return status;

        status = SendRaw(transport, ackBuf, ackWritten);
        if (!NT_SUCCESS(status)) return status;

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::Initialize(core::ITransport& transport) noexcept
    {
        Http2ITransportAdapter adapter(transport);
        return Initialize(adapter);
    }

    NTSTATUS Http2Connection::InitializeAfterUpgrade(Http2Transport& transport) noexcept
    {
        NTSTATUS status = Initialize(transport);
        if (!NT_SUCCESS(status)) return status;

        nextStreamId_ = 3;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::InitializeAfterUpgrade(core::ITransport& transport) noexcept
    {
        Http2ITransportAdapter adapter(transport);
        return InitializeAfterUpgrade(adapter);
    }

    NTSTATUS Http2Connection::SendRequest(
        Http2Transport& transport,
        const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        if (responseBody == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        FixedResponseBodySinkContext fixedBody = {};
        fixedBody.Buffer = responseBody;
        fixedBody.Capacity = responseBodyCapacity;

        Http2ResponseBodySink sink = {};
        sink.Append = AppendFixedResponseBody;
        sink.Context = &fixedBody;

        return SendRequest(
            transport,
            requestHeaders,
            requestHeaderCount,
            body,
            bodyLength,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            sink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::SendRequest(
        Http2Transport& transport,
        const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        if (requestHeaders == nullptr || responseHeaders == nullptr ||
            responseHeaderCount == nullptr || responseBodySink.Append == nullptr ||
            responseBodyLength == nullptr || statusCode == nullptr ||
            nameValueBuffer == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *responseHeaderCount = 0;
        *responseBodyLength = 0;
        *statusCode = 0;

        ULONG streamId = AllocateStreamId();
        Http2Stream stream;
        stream.Initialize(streamId, localSettings_.InitialWindowSize, peerSettings_.InitialWindowSize);

        // Encode request headers with HPACK
        UCHAR* headerBlock = headerBlock_;
        SIZE_T headerBlockLen = 0;
        status = encoder_.Encode(requestHeaders, requestHeaderCount,
            headerBlock, HeaderBlockCapacity, &headerBlockLen);
        if (!NT_SUCCESS(status)) return status;

        // Send HEADERS frame(s)
        bool endStream = (body == nullptr || bodyLength == 0);
        UCHAR* sendBuf = sendBuffer_;
        SIZE_T sendOffset = 0;

        // Fragment header block if needed
        SIZE_T blockOffset = 0;
        ULONG maxPayload = OutboundPayloadLimit(peerSettings_.MaxFrameSize);
        bool firstFrame = true;

        while (blockOffset < headerBlockLen) {
            SIZE_T chunkLen = headerBlockLen - blockOffset;
            if (chunkLen > maxPayload) chunkLen = maxPayload;
            bool lastChunk = (blockOffset + chunkLen >= headerBlockLen);

            if (Http2FrameHeaderLength + chunkLen > SendBufferCapacity) return STATUS_BUFFER_TOO_SMALL;
            if (sendOffset + Http2FrameHeaderLength + chunkLen > SendBufferCapacity) {
                status = SendRaw(transport, sendBuf, sendOffset);
                if (!NT_SUCCESS(status)) return status;
                sendOffset = 0;
            }

            SIZE_T written = 0;
            const bool isFirstHeaderFrame = firstFrame;
            if (isFirstHeaderFrame) {
                status = Http2FrameCodec::EncodeHeaders(
                    streamId, headerBlock + blockOffset, chunkLen,
                    endStream, lastChunk,
                    sendBuf + sendOffset, SendBufferCapacity - sendOffset, &written);
                firstFrame = false;
            } else {
                status = Http2FrameCodec::EncodeContinuation(
                    streamId, headerBlock + blockOffset, chunkLen,
                    lastChunk,
                    sendBuf + sendOffset, SendBufferCapacity - sendOffset, &written);
            }
            if (!NT_SUCCESS(status)) return status;
            if (isFirstHeaderFrame) {
                status = stream.SendHeaders(endStream);
                if (!NT_SUCCESS(status)) return status;
            }
            sendOffset += written;
            blockOffset += chunkLen;
        }

        if (!endStream) {
            status = SendRaw(transport, sendBuf, sendOffset);
            if (!NT_SUCCESS(status)) {
                kprintf("Http2Connection send HEADERS failed: 0x%08X stream=%u bytes=%Iu\r\n",
                    static_cast<ULONG>(status),
                    streamId,
                    sendOffset);
                return status;
            }
            sendOffset = 0;
        }

        // Send DATA frame(s) if body present
        SIZE_T bodyOffset = 0;
        if (!endStream && body != nullptr && bodyLength > 0) {
            while (bodyOffset < bodyLength) {
                SIZE_T chunkLen = bodyLength - bodyOffset;
                if (chunkLen > maxPayload) chunkLen = maxPayload;

                // Check send windows
                LONG available = connectionSendWindow_ < stream.RemoteWindow()
                    ? connectionSendWindow_
                    : stream.RemoteWindow();
                if (available <= 0) {
                    if (sendOffset != 0) {
                        status = SendRaw(transport, sendBuf, sendOffset);
                        if (!NT_SUCCESS(status)) {
                            LogRequestBodyFlowControlFailure(
                                status,
                                bodyOffset,
                                bodyLength,
                                connectionSendWindow_,
                                stream.RemoteWindow());
                            return status;
                        }
                        sendOffset = 0;
                    }

                    // Need to read WINDOW_UPDATE from peer
                    Http2FrameHeader fh = {};
                    UCHAR* fp = framePayload_;
                    SIZE_T fpLen = 0;
                    status = ReadFrame(transport, &fh, fp, framePayloadCapacity_, &fpLen);
                    if (!NT_SUCCESS(status)) {
                        status = HandleReadFrameFailure(transport, status);
                        LogRequestBodyFlowControlFailure(
                            status,
                            bodyOffset,
                            bodyLength,
                            connectionSendWindow_,
                            stream.RemoteWindow());
                        return status;
                    }
                    if (!IsValidFrameTarget(fh)) {
                        const NTSTATUS goAwayStatus = SendGoAway(
                            transport,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(goAwayStatus);
                        LogRequestBodyFlowControlFailure(
                            STATUS_INVALID_NETWORK_RESPONSE,
                            bodyOffset,
                            bodyLength,
                            connectionSendWindow_,
                            stream.RemoteWindow());
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (fh.Type == Http2FrameType::WindowUpdate && fh.StreamId == streamId) {
                        ULONG increment = 0;
                        status = Http2FrameCodec::DecodeWindowUpdatePayload(fp, fpLen, &increment);
                        if (!NT_SUCCESS(status)) {
                            const NTSTATUS rstStatus = SendRstStream(
                                transport,
                                fh.StreamId,
                                fpLen == 4
                                    ? static_cast<ULONG>(Http2ErrorCode::ProtocolError)
                                    : static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                            UNREFERENCED_PARAMETER(rstStatus);
                            LogRequestBodyFlowControlFailure(
                                status,
                                bodyOffset,
                                bodyLength,
                                connectionSendWindow_,
                                stream.RemoteWindow());
                            return status;
                        }
                        status = stream.IncreaseRemoteWindow(increment);
                        if (!NT_SUCCESS(status)) {
                            const NTSTATUS rstStatus = SendRstStream(
                                transport,
                                fh.StreamId,
                                static_cast<ULONG>(Http2ErrorCode::FlowControlError));
                            UNREFERENCED_PARAMETER(rstStatus);
                            LogRequestBodyFlowControlFailure(
                                status,
                                bodyOffset,
                                bodyLength,
                                connectionSendWindow_,
                                stream.RemoteWindow());
                            return status;
                        }
                    }
                    else if (fh.Type == Http2FrameType::WindowUpdate && fh.StreamId != 0) {
                        ULONG ignoredIncrement = 0;
                        status = Http2FrameCodec::DecodeWindowUpdatePayload(fp, fpLen, &ignoredIncrement);
                        if (!NT_SUCCESS(status)) {
                            const NTSTATUS rstStatus = SendRstStream(
                                transport,
                                fh.StreamId,
                                fpLen == 4
                                    ? static_cast<ULONG>(Http2ErrorCode::ProtocolError)
                                    : static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                            UNREFERENCED_PARAMETER(rstStatus);
                            LogRequestBodyFlowControlFailure(
                                status,
                                bodyOffset,
                                bodyLength,
                                connectionSendWindow_,
                                stream.RemoteWindow());
                            return status;
                        }
                    }
                    else {
                        status = HandleConnectionFrame(transport, fh, fp, fpLen, &stream);
                        if (!NT_SUCCESS(status)) {
                            LogRequestBodyFlowControlFailure(
                                status,
                                bodyOffset,
                                bodyLength,
                                connectionSendWindow_,
                                stream.RemoteWindow());
                            return status;
                        }
                    }
                    continue;
                }

                if (chunkLen > static_cast<SIZE_T>(available)) {
                    chunkLen = static_cast<SIZE_T>(available);
                }

                bool lastData = (bodyOffset + chunkLen >= bodyLength);

                if (Http2FrameHeaderLength + chunkLen > SendBufferCapacity) return STATUS_BUFFER_TOO_SMALL;
                if (sendOffset + Http2FrameHeaderLength + chunkLen > SendBufferCapacity) {
                    status = SendRaw(transport, sendBuf, sendOffset);
                    if (!NT_SUCCESS(status)) {
                        LogRequestBodyFlowControlFailure(
                            status,
                            bodyOffset,
                            bodyLength,
                            connectionSendWindow_,
                            stream.RemoteWindow());
                        return status;
                    }
                    sendOffset = 0;
                }

                SIZE_T written = 0;
                status = Http2FrameCodec::EncodeData(
                    streamId, body + bodyOffset, chunkLen, lastData,
                    sendBuf + sendOffset, SendBufferCapacity - sendOffset, &written);
                if (!NT_SUCCESS(status)) {
                    LogRequestBodyFlowControlFailure(
                        status,
                        bodyOffset,
                        bodyLength,
                        connectionSendWindow_,
                        stream.RemoteWindow());
                    return status;
                }
                status = stream.SendData(chunkLen, lastData);
                if (!NT_SUCCESS(status)) {
                    LogRequestBodyFlowControlFailure(
                        status,
                        bodyOffset,
                        bodyLength,
                        connectionSendWindow_,
                        stream.RemoteWindow());
                    return status;
                }
                sendOffset += written;
                bodyOffset += chunkLen;
                connectionSendWindow_ -= static_cast<LONG>(chunkLen);
            }
        }

        // Flush all buffered frames
        status = SendRaw(transport, sendBuf, sendOffset);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Connection send request body failed: 0x%08X stream=%u bytes=%Iu\r\n",
                static_cast<ULONG>(status),
                streamId,
                sendOffset);
            if (bodyLength > 0) {
                LogRequestBodyFlowControlFailure(
                    status,
                    bodyOffset,
                    bodyLength,
                    connectionSendWindow_,
                    stream.RemoteWindow());
            }
            return status;
        }

        return ReceiveResponseFrames(
            transport,
            stream,
            RequestForbidsResponseBody(requestHeaders, requestHeaderCount),
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBodySink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::ReceiveResponse(
        Http2Transport& transport,
        ULONG streamId,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        if (streamId == 0 || (streamId & 1u) == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        Http2Stream stream;
        stream.Initialize(streamId, localSettings_.InitialWindowSize, peerSettings_.InitialWindowSize);

        // h2c Upgrade maps the initiating HTTP/1.1 request to stream 1.
        // The client side is already closed when we start reading the HTTP/2 response.
        status = stream.SendHeaders(true);
        if (!NT_SUCCESS(status)) return status;

        if (responseBody == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        FixedResponseBodySinkContext fixedBody = {};
        fixedBody.Buffer = responseBody;
        fixedBody.Capacity = responseBodyCapacity;

        Http2ResponseBodySink sink = {};
        sink.Append = AppendFixedResponseBody;
        sink.Context = &fixedBody;

        return ReceiveResponseFrames(
            transport,
            stream,
            false,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            sink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::ReceiveResponse(
        core::ITransport& transport,
        ULONG streamId,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2ITransportAdapter adapter(transport);
        return ReceiveResponse(
            adapter,
            streamId,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBody,
            responseBodyCapacity,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::ReceiveResponseFrames(
        Http2Transport& transport,
        Http2Stream& stream,
        bool requestForbidsResponseBody,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        if (responseHeaders == nullptr ||
            responseHeaderCount == nullptr ||
            responseBodySink.Append == nullptr ||
            responseBodyLength == nullptr ||
            statusCode == nullptr ||
            nameValueBuffer == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *responseHeaderCount = 0;
        *responseBodyLength = 0;
        *statusCode = 0;

        NTSTATUS status = EnsureDecodedHeaderScratch(responseHeaderCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        bool streamClosed = false;
        bool responseHeadersReceived = false;
        bool responseDataReceived = false;
        bool responseContentLengthPresent = false;
        ULONGLONG responseContentLength = 0;
        bool responseBodyForbidden = requestForbidsResponseBody;
        bool expectingContinuation = false;
        bool pendingHeaderEndStream = false;
        ULONG continuationStreamId = 0;
        ULONG continuationFrames = 0;
        ULONG emptyContinuationFrames = 0;
        UCHAR* responseHeaderBlock = responseHeaderBlock_;
        SIZE_T responseHeaderBlockLen = 0;
        SIZE_T bodyLen = 0;

        while (!streamClosed) {
            Http2FrameHeader fh = {};
            UCHAR* fp = framePayload_;
            SIZE_T fpLen = 0;

            status = ReadFrame(transport, &fh, fp, framePayloadCapacity_, &fpLen);
            if (!NT_SUCCESS(status)) {
                kprintf("Http2Connection ReadFrame failed: 0x%08X stream=%u headers=%u body=%Iu\r\n",
                    static_cast<ULONG>(status),
                    stream.StreamId(),
                    responseHeadersReceived ? 1u : 0u,
                    bodyLen);
                return HandleReadFrameFailure(transport, status);
            }

            kprintf("Http2Connection frame type=%u flags=0x%02X stream=%u length=%u target=%u\r\n",
                static_cast<unsigned>(fh.Type),
                static_cast<unsigned>(fh.Flags),
                fh.StreamId,
                fh.Length,
                stream.StreamId());

            if (!IsValidFrameTarget(fh)) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (fh.Type == Http2FrameType::Continuation) {
                if (!expectingContinuation || fh.StreamId != continuationStreamId) {
                    const NTSTATUS goAwayStatus = SendGoAway(
                        transport,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(goAwayStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (++continuationFrames > Http2MaxContinuationFrames) {
                    const NTSTATUS goAwayStatus = SendGoAway(
                        transport,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(goAwayStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (fh.Length == 0) {
                    if (++emptyContinuationFrames > Http2MaxEmptyContinuationFrames) {
                        const NTSTATUS goAwayStatus = SendGoAway(
                            transport,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(goAwayStatus);
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
                else {
                    emptyContinuationFrames = 0;
                }
            }
            else if (expectingContinuation) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            // Connection-level frame
            if (fh.StreamId == 0) {
                status = HandleConnectionFrame(transport, fh, fp, fpLen, &stream);
                if (!NT_SUCCESS(status)) return status;
                if (goAwayReceived_) {
                    kprintf("Http2Connection GOAWAY received lastStream=%u target=%u\r\n",
                        goAwayLastStreamId_,
                        stream.StreamId());
                    return STATUS_CONNECTION_DISCONNECTED;
                }
                continue;
            }

            if (fh.Type == Http2FrameType::Settings ||
                fh.Type == Http2FrameType::Ping ||
                fh.Type == Http2FrameType::GoAway) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (fh.Type == Http2FrameType::PushPromise) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            // Stream-level frame
            if (fh.StreamId != stream.StreamId()) {
                // Unexpected stream - ignore or RST
                continue;
            }

            switch (fh.Type) {
            case Http2FrameType::Headers:
            case Http2FrameType::Continuation:
            {
                const UCHAR* content = fp;
                SIZE_T contentLen = fpLen;

                if (fh.Type == Http2FrameType::Headers) {
                    pendingHeaderEndStream = (fh.Flags & Http2FrameFlags::EndStream) != 0;
                    // Strip padding if present
                    status = Http2FrameCodec::StripPadding(fh.Flags, fp, fpLen, &content, &contentLen);
                    if (!NT_SUCCESS(status)) return status;
                    // Strip priority if present
                    status = Http2FrameCodec::StripPriority(fh.Flags, content, contentLen, &content, &contentLen);
                    if (!NT_SUCCESS(status)) return status;
                }

                // Accumulate header block
                if (responseHeaderBlockLen + contentLen > HeaderBlockCapacity) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                MemCopy(responseHeaderBlock + responseHeaderBlockLen, content, contentLen);
                responseHeaderBlockLen += contentLen;

                if ((fh.Flags & Http2FrameFlags::EndHeaders) != 0) {
                    expectingContinuation = false;
                    continuationStreamId = 0;
                    continuationFrames = 0;
                    emptyContinuationFrames = 0;
                    status = stream.ReceiveHeaders(pendingHeaderEndStream);
                    if (!NT_SUCCESS(status)) {
                        const NTSTATUS rstStatus = SendRstStream(
                            transport,
                            fh.StreamId,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(rstStatus);
                        return status;
                    }
                    const bool trailers = responseHeadersReceived;
                    if (trailers && (!responseDataReceived || !pendingHeaderEndStream)) {
                        const NTSTATUS rstStatus = SendRstStream(
                            transport,
                            fh.StreamId,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(rstStatus);
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    if (trailers) {
                        RtlZeroMemory(trailerHeaders_, sizeof(trailerHeaders_));
                    }
                    http::HttpHeader* decodedHeaders = trailers ? trailerHeaders_ : decodedHeaderScratch_;
                    const SIZE_T decodedHeaderCapacity = trailers ? 16 : decodedHeaderScratchCapacity_;
                    char* decodedNameValueBuffer = trailers ?
                        reinterpret_cast<char*>(headerBlock_) :
                        nameValueBuffer;
                    const SIZE_T decodedNameValueCapacity = trailers ?
                        HeaderBlockCapacity :
                        nameValueCapacity;
                    SIZE_T decodedHeaderCount = 0;
                    SIZE_T nvUsed = 0;
                    status = decoder_.Decode(
                        responseHeaderBlock, responseHeaderBlockLen,
                        decodedHeaders, decodedHeaderCapacity,
                        &decodedHeaderCount,
                        decodedNameValueBuffer, decodedNameValueCapacity, &nvUsed,
                        localSettings_.MaxHeaderListSize);
                    if (!NT_SUCCESS(status)) {
                        kprintf("Http2Connection HPACK decode failed: 0x%08X block=%Iu stream=%u\r\n",
                            static_cast<ULONG>(status),
                            responseHeaderBlockLen,
                            stream.StreamId());
                        if (IsHpackCompressionFailure(status)) {
                            const NTSTATUS goAwayStatus = SendGoAway(
                                transport,
                                static_cast<ULONG>(Http2ErrorCode::CompressionError));
                            UNREFERENCED_PARAMETER(goAwayStatus);
                        }
                        return status;
                    }

                    USHORT decodedStatusCode = 0;
                    bool decodedContentLengthPresent = false;
                    ULONGLONG decodedContentLength = 0;
                    status = ValidateResponseHeaderBlock(
                        decodedHeaders,
                        decodedHeaderCount,
                        trailers,
                        &decodedStatusCode,
                        trailers ? nullptr : &decodedContentLengthPresent,
                        trailers ? nullptr : &decodedContentLength);
                    if (!NT_SUCCESS(status)) {
                        const NTSTATUS rstStatus = SendRstStream(
                            transport,
                            fh.StreamId,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(rstStatus);
                        return status;
                    }

                    if (!trailers && decodedStatusCode >= 100 && decodedStatusCode < 200) {
                        if (decodedStatusCode == 101 || pendingHeaderEndStream) {
                            const NTSTATUS rstStatus = SendRstStream(
                                transport,
                                fh.StreamId,
                                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                            UNREFERENCED_PARAMETER(rstStatus);
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        responseHeaderBlockLen = 0;
                        pendingHeaderEndStream = false;
                        break;
                    }

                    if (!trailers) {
                        status = CopyRegularResponseHeaders(
                            decodedHeaders,
                            decodedHeaderCount,
                            responseHeaders,
                            responseHeaderCapacity,
                            responseHeaderCount);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        *statusCode = decodedStatusCode;
                        responseContentLengthPresent = decodedContentLengthPresent;
                        responseContentLength = decodedContentLength;
                        responseBodyForbidden =
                            requestForbidsResponseBody ||
                            StatusForbidsResponseBody(decodedStatusCode);
                        if (responseBodyForbidden &&
                            responseContentLengthPresent &&
                            responseContentLength != 0) {
                            const NTSTATUS rstStatus = SendRstStream(
                                transport,
                                fh.StreamId,
                                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                            UNREFERENCED_PARAMETER(rstStatus);
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        responseHeadersReceived = true;
                    }
                    responseHeaderBlockLen = 0;
                    if (pendingHeaderEndStream) {
                        if (responseContentLengthPresent &&
                            static_cast<ULONGLONG>(bodyLen) != responseContentLength) {
                            const NTSTATUS rstStatus = SendRstStream(
                                transport,
                                fh.StreamId,
                                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                            UNREFERENCED_PARAMETER(rstStatus);
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        streamClosed = true;
                    }
                    pendingHeaderEndStream = false;
                }
                else if (fh.Type == Http2FrameType::Headers) {
                    expectingContinuation = true;
                    continuationStreamId = fh.StreamId;
                    continuationFrames = 0;
                    emptyContinuationFrames = 0;
                }
                break;
            }

            case Http2FrameType::Data:
            {
                if (!responseHeadersReceived) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const UCHAR* content = fp;
                SIZE_T contentLen = fpLen;

                // Strip padding
                status = Http2FrameCodec::StripPadding(fh.Flags, fp, fpLen, &content, &contentLen);
                if (!NT_SUCCESS(status)) return status;

                const bool dataEndsStream = (fh.Flags & Http2FrameFlags::EndStream) != 0;
                if (responseBodyForbidden) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                status = stream.ReceiveData(fpLen, dataEndsStream);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        static_cast<ULONG>(Http2ErrorCode::FlowControlError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return status;
                }

                if (connectionRecvWindow_ < 0 ||
                    fpLen > static_cast<SIZE_T>(connectionRecvWindow_)) {
                    const NTSTATUS goAwayStatus = SendGoAway(
                        transport,
                        static_cast<ULONG>(Http2ErrorCode::FlowControlError));
                    UNREFERENCED_PARAMETER(goAwayStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                connectionRecvWindow_ -= static_cast<LONG>(fpLen);

                if (AddWouldOverflow(bodyLen, contentLen)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                const SIZE_T nextBodyLen = bodyLen + contentLen;
                if (responseContentLengthPresent &&
                    static_cast<ULONGLONG>(nextBodyLen) > responseContentLength) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                status = responseBodySink.Append(
                    responseBodySink.Context,
                    content,
                    contentLen);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                bodyLen = nextBodyLen;
                responseDataReceived = true;

                // Update flow control
                connectionRecvConsumed_ += static_cast<ULONG>(fpLen);
                status = SendWindowUpdateIfNeeded(
                    transport,
                    dataEndsStream ? nullptr : &stream,
                    static_cast<ULONG>(fpLen));
                if (!NT_SUCCESS(status)) return status;

                if ((fh.Flags & Http2FrameFlags::EndStream) != 0) {
                    if (responseContentLengthPresent &&
                        static_cast<ULONGLONG>(bodyLen) != responseContentLength) {
                        const NTSTATUS rstStatus = SendRstStream(
                            transport,
                            fh.StreamId,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(rstStatus);
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    streamClosed = true;
                }
                break;
            }

            case Http2FrameType::RstStream:
            {
                ULONG errorCode = 0;
                status = Http2FrameCodec::DecodeRstStreamPayload(fp, fpLen, &errorCode);
                if (!NT_SUCCESS(status)) return status;
                kprintf("Http2Connection RST_STREAM stream=%u error=0x%08X\r\n",
                    fh.StreamId,
                    errorCode);
                stream.Reset();
                streamClosed = true;
                return STATUS_CONNECTION_DISCONNECTED;
            }

            case Http2FrameType::WindowUpdate:
            {
                ULONG increment = 0;
                status = Http2FrameCodec::DecodeWindowUpdatePayload(fp, fpLen, &increment);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        fpLen == 4
                            ? static_cast<ULONG>(Http2ErrorCode::ProtocolError)
                            : static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return status;
                }
                status = stream.IncreaseRemoteWindow(increment);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        static_cast<ULONG>(Http2ErrorCode::FlowControlError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return status;
                }
                break;
            }

            default:
                // Ignore unknown frame types on stream (RFC 9113 Section 4.1)
                break;
            }
        }

        *responseBodyLength = bodyLen;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::SendRequest(
        core::ITransport& transport,
        const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2ITransportAdapter adapter(transport);
        return SendRequest(
            adapter,
            requestHeaders,
            requestHeaderCount,
            body,
            bodyLength,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBody,
            responseBodyCapacity,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::SendRequest(
        core::ITransport& transport,
        const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2ITransportAdapter adapter(transport);
        return SendRequest(
            adapter,
            requestHeaders,
            requestHeaderCount,
            body,
            bodyLength,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBodySink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::Shutdown(Http2Transport& transport) noexcept
    {
        if (goAwaySent_) return STATUS_SUCCESS;

        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        UCHAR* buf = sendBuffer_;
        SIZE_T written = 0;
        status = Http2FrameCodec::EncodeGoAway(
            0, static_cast<ULONG>(Http2ErrorCode::NoError),
            buf, Http2FrameHeaderLength + 8, &written);
        if (!NT_SUCCESS(status)) return status;

        goAwaySent_ = true;
        return SendRaw(transport, buf, written);
    }

    NTSTATUS Http2Connection::Shutdown(core::ITransport& transport) noexcept
    {
        Http2ITransportAdapter adapter(transport);
        return Shutdown(adapter);
    }

    NTSTATUS Http2Connection::SendRaw(
        Http2Transport& transport,
        const UCHAR* data,
        SIZE_T length) noexcept
    {
        return transport.Send(data, length);
    }

    NTSTATUS Http2Connection::ReadExact(
        Http2Transport& transport,
        UCHAR* buffer,
        SIZE_T length) noexcept
    {
        SIZE_T totalRead = 0;
        while (totalRead < length) {
            SIZE_T received = 0;
            NTSTATUS status = transport.Receive(
                buffer + totalRead, length - totalRead, &received);
            if (!NT_SUCCESS(status)) return status;
            if (received == 0) return STATUS_CONNECTION_DISCONNECTED;
            totalRead += received;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::ReadFrame(
        Http2Transport& transport,
        Http2FrameHeader* header,
        UCHAR* payload,
        SIZE_T payloadCapacity,
        SIZE_T* payloadLength) noexcept
    {
        readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::NoError);

        // Read 9-byte frame header
        UCHAR* headerBuf = sendBuffer_;
        NTSTATUS status = ReadExact(transport, headerBuf, Http2FrameHeaderLength);
        if (!NT_SUCCESS(status)) return status;

        status = Http2FrameCodec::DecodeFrameHeader(headerBuf, Http2FrameHeaderLength, header);
        if (!NT_SUCCESS(status)) return status;

        if (header->Length > localSettings_.MaxFrameSize) {
            readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::FrameSizeError);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (header->Length > payloadCapacity) return STATUS_BUFFER_TOO_SMALL;

        // Read payload
        if (header->Length > 0) {
            status = ReadExact(transport, payload, header->Length);
            if (!NT_SUCCESS(status)) return status;
        }

        *payloadLength = header->Length;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::HandleReadFrameFailure(
        Http2Transport& transport,
        NTSTATUS status) noexcept
    {
        if (status == STATUS_INVALID_NETWORK_RESPONSE &&
            readFrameErrorCode_ != static_cast<ULONG>(Http2ErrorCode::NoError)) {
            const NTSTATUS goAwayStatus = SendGoAway(transport, readFrameErrorCode_);
            UNREFERENCED_PARAMETER(goAwayStatus);
        }
        else if (status == STATUS_IO_TIMEOUT && !settingsAckReceived_) {
            const NTSTATUS goAwayStatus = SendGoAway(
                transport,
                static_cast<ULONG>(Http2ErrorCode::SettingsTimeout));
            UNREFERENCED_PARAMETER(goAwayStatus);
        }

        return status;
    }

    NTSTATUS Http2Connection::HandleConnectionFrame(
        Http2Transport& transport,
        const Http2FrameHeader& header,
        const UCHAR* payload,
        SIZE_T payloadLen,
        Http2Stream* activeStream) noexcept
    {
        if (!IsValidFrameTarget(header)) {
            const NTSTATUS goAwayStatus = SendGoAway(
                transport,
                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
            UNREFERENCED_PARAMETER(goAwayStatus);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        switch (header.Type) {
        case Http2FrameType::Settings:
        {
            if ((header.Flags & Http2FrameFlags::Ack) != 0) {
                if (payloadLen != 0) {
                    const NTSTATUS goAwayStatus = SendGoAway(
                        transport,
                        static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                    UNREFERENCED_PARAMETER(goAwayStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                settingsAckReceived_ = true;
                return STATUS_SUCCESS;
            }
            // Peer sent new SETTINGS
            const Http2Settings previousSettings = peerSettings_;
            if ((payloadLen % 6) != 0) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            NTSTATUS status = Http2FrameCodec::DecodeSettingsPayload(payload, payloadLen, &peerSettings_);
            if (!NT_SUCCESS(status) || peerSettings_.EnablePush != 0) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    SettingsErrorCodeForPayload(payload, payloadLen));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            encoder_.UpdateMaxTableSize(peerSettings_.HeaderTableSize);
            if (activeStream != nullptr &&
                peerSettings_.InitialWindowSize != previousSettings.InitialWindowSize) {
                const long long delta =
                    static_cast<long long>(peerSettings_.InitialWindowSize) -
                    static_cast<long long>(previousSettings.InitialWindowSize);
                status = activeStream->AdjustRemoteWindow(delta);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS goAwayStatus = SendGoAway(
                        transport,
                        static_cast<ULONG>(Http2ErrorCode::FlowControlError));
                    UNREFERENCED_PARAMETER(goAwayStatus);
                    return status;
                }
            }

            // ACK
            UCHAR* ackBuf = sendBuffer_;
            SIZE_T ackWritten = 0;
            status = Http2FrameCodec::EncodeSettingsAck(ackBuf, Http2FrameHeaderLength, &ackWritten);
            if (!NT_SUCCESS(status)) return status;
            return SendRaw(transport, ackBuf, ackWritten);
        }

        case Http2FrameType::Ping:
        {
            if (payloadLen != 8) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if ((header.Flags & Http2FrameFlags::Ack) != 0) {
                return STATUS_SUCCESS; // PING ACK, ignore
            }
            // Send PING ACK
            UCHAR* pingBuf = sendBuffer_;
            SIZE_T written = 0;
            NTSTATUS status = Http2FrameCodec::EncodePing(payload, true, pingBuf, Http2FrameHeaderLength + 8, &written);
            if (!NT_SUCCESS(status)) return status;
            return SendRaw(transport, pingBuf, written);
        }

        case Http2FrameType::GoAway:
        {
            ULONG lastStreamId = 0;
            ULONG errorCode = 0;
            NTSTATUS status = Http2FrameCodec::DecodeGoAwayPayload(payload, payloadLen, &lastStreamId, &errorCode);
            if (!NT_SUCCESS(status)) return status;
            kprintf("Http2Connection GOAWAY error=0x%08X lastStream=%u\r\n",
                errorCode,
                lastStreamId);
            goAwayReceived_ = true;
            goAwayLastStreamId_ = lastStreamId;
            return STATUS_SUCCESS;
        }

        case Http2FrameType::WindowUpdate:
        {
            ULONG increment = 0;
            NTSTATUS status = Http2FrameCodec::DecodeWindowUpdatePayload(payload, payloadLen, &increment);
            if (!NT_SUCCESS(status)) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    payloadLen == 4
                        ? static_cast<ULONG>(Http2ErrorCode::ProtocolError)
                        : static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return status;
            }
            if (connectionSendWindow_ >
                static_cast<LONG>(Http2MaxWindowSize) - static_cast<LONG>(increment)) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::FlowControlError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE; // Flow control error
            }
            connectionSendWindow_ += static_cast<LONG>(increment);
            return STATUS_SUCCESS;
        }

        case Http2FrameType::PushPromise:
            // We set ENABLE_PUSH=0, receiving PUSH_PROMISE is a protocol error
            {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
            }
            return STATUS_INVALID_NETWORK_RESPONSE;

        case Http2FrameType::Data:
        case Http2FrameType::Headers:
        case Http2FrameType::RstStream:
        {
            const NTSTATUS goAwayStatus = SendGoAway(
                transport,
                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
            UNREFERENCED_PARAMETER(goAwayStatus);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        default:
            // Unknown frame types on stream 0 must be ignored
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS Http2Connection::SendWindowUpdateIfNeeded(
        Http2Transport& transport,
        Http2Stream* stream,
        ULONG consumed) noexcept
    {
        // Connection-level window update
        if (connectionRecvConsumed_ >= WindowUpdateThreshold) {
            UCHAR* buf = sendBuffer_;
            SIZE_T written = 0;
            NTSTATUS status = Http2FrameCodec::EncodeWindowUpdate(
                0, connectionRecvConsumed_, buf, Http2FrameHeaderLength + 4, &written);
            if (!NT_SUCCESS(status)) return status;
            status = SendRaw(transport, buf, written);
            if (!NT_SUCCESS(status)) return status;
            connectionRecvWindow_ += static_cast<LONG>(connectionRecvConsumed_);
            connectionRecvConsumed_ = 0;
        }

        // Stream-level window update
        if (stream != nullptr && consumed > 0) {
            UCHAR* buf = sendBuffer_;
            SIZE_T written = 0;
            NTSTATUS status = Http2FrameCodec::EncodeWindowUpdate(
                stream->StreamId(), consumed, buf, Http2FrameHeaderLength + 4, &written);
            if (!NT_SUCCESS(status)) return status;
            status = SendRaw(transport, buf, written);
            if (!NT_SUCCESS(status)) return status;
            return stream->IncreaseLocalWindow(consumed);
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::SendGoAway(Http2Transport& transport, ULONG errorCode) noexcept
    {
        if (goAwaySent_) {
            return STATUS_SUCCESS;
        }

        const ULONG lastStreamId = nextStreamId_ > 2 ? nextStreamId_ - 2 : 0;
        UCHAR* buf = sendBuffer_;
        SIZE_T written = 0;
        NTSTATUS status = Http2FrameCodec::EncodeGoAway(
            lastStreamId,
            errorCode,
            buf,
            Http2FrameHeaderLength + 8,
            &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendRaw(transport, buf, written);
        if (NT_SUCCESS(status)) {
            goAwaySent_ = true;
        }
        return status;
    }

    NTSTATUS Http2Connection::SendRstStream(
        Http2Transport& transport,
        ULONG streamId,
        ULONG errorCode) noexcept
    {
        if (streamId == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        UCHAR* buf = sendBuffer_;
        SIZE_T written = 0;
        NTSTATUS status = Http2FrameCodec::EncodeRstStream(
            streamId,
            errorCode,
            buf,
            Http2FrameHeaderLength + 4,
            &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendRaw(transport, buf, written);
    }

    ULONG Http2Connection::AllocateStreamId() noexcept
    {
        ULONG id = nextStreamId_;
        nextStreamId_ += 2; // Client uses odd stream IDs
        return id;
    }

    NTSTATUS Http2Connection::ValidateResponseHeaderBlock(
        const http::HttpHeader* headers,
        SIZE_T headerCount,
        bool trailers,
        USHORT* statusCode,
        bool* contentLengthPresent,
        ULONGLONG* contentLength) noexcept
    {
        if (contentLengthPresent != nullptr) {
            *contentLengthPresent = false;
        }
        if (contentLength != nullptr) {
            *contentLength = 0;
        }

        if (headers == nullptr && headerCount != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        bool regularHeaderSeen = false;
        bool statusSeen = false;
        bool contentLengthSeen = false;
        ULONGLONG parsedContentLength = 0;
        USHORT parsedStatus = 0;

        for (SIZE_T i = 0; i < headerCount; ++i) {
            const http::HttpHeader& header = headers[i];
            if (header.Name.Data == nullptr || header.Name.Length == 0 ||
                (header.Value.Data == nullptr && header.Value.Length != 0)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!IsValidHttp2FieldName(header.Name.Data, header.Name.Length) ||
                !IsValidHttp2FieldValue(header.Value.Data, header.Value.Length) ||
                TextContainsUppercase(header.Name.Data, header.Name.Length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (header.Name.Data[0] == ':') {
                if (trailers || regularHeaderSeen ||
                    !TextEquals(header.Name.Data, header.Name.Length, ":status", 7) ||
                    statusSeen) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                parsedStatus = ParseStatusCode(header.Value.Data, header.Value.Length);
                if (parsedStatus == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                statusSeen = true;
                continue;
            }

            regularHeaderSeen = true;
            if (IsConnectionSpecificHeaderName(header.Name.Data, header.Name.Length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (TextEquals(header.Name.Data, header.Name.Length, "te", 2) &&
                !TextEqualsAsciiInsensitive(header.Value.Data, header.Value.Length, "trailers", 8)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (!trailers && TextEquals(header.Name.Data, header.Name.Length, "content-length", 14)) {
                ULONGLONG currentLength = 0;
                if (!ParseUnsignedDecimal(header.Value.Data, header.Value.Length, &currentLength)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (contentLengthSeen && currentLength != parsedContentLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                contentLengthSeen = true;
                parsedContentLength = currentLength;
            }
        }

        if (!trailers && !statusSeen) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (statusCode != nullptr) {
            *statusCode = trailers ? 0 : parsedStatus;
        }
        if (contentLengthPresent != nullptr) {
            *contentLengthPresent = !trailers && contentLengthSeen;
        }
        if (contentLength != nullptr) {
            *contentLength = !trailers && contentLengthSeen ? parsedContentLength : 0;
        }
        return STATUS_SUCCESS;
    }

    USHORT Http2Connection::ExtractStatusCode(
        const http::HttpHeader* headers,
        SIZE_T headerCount) noexcept
    {
        for (SIZE_T i = 0; i < headerCount; ++i) {
            if (TextEquals(headers[i].Name.Data, headers[i].Name.Length, ":status", 7)) {
                return ParseStatusCode(headers[i].Value.Data, headers[i].Value.Length);
            }
        }
        return 0;
    }
}
}
