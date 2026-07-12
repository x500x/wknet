#include "http2/Http2ConnectionPrivate.hpp"

namespace wknet
{
namespace http2
{
    namespace
    {
        constexpr SIZE_T SendBufferCapacity = 32768;
        constexpr ULONG LocalMaxFramePayloadSize = 32768;
        constexpr SIZE_T DefaultActiveStreamCapacity = WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL;

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

        Http2RequestBody MakeFixedRequestBody(const UCHAR* body, SIZE_T bodyLength) noexcept
        {
            Http2RequestBody requestBody = {};
            requestBody.Data = body;
            requestBody.DataLength = bodyLength;
            requestBody.HasBody = body != nullptr && bodyLength != 0;
            return requestBody;
        }

        bool AddWouldOverflow(SIZE_T left, SIZE_T right) noexcept
        {
            return left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right;
        }

        bool IsConnectionControlSignal(Http2FrameType type) noexcept
        {
            return type == Http2FrameType::Settings ||
                type == Http2FrameType::Ping ||
                type == Http2FrameType::GoAway ||
                type == Http2FrameType::WindowUpdate;
        }

        void LogRequestBodyFlowControlFailure(
            NTSTATUS status,
            SIZE_T bodyOffset,
            SIZE_T bodyLength,
            LONG connectionWindow,
            LONG streamWindow) noexcept
        {
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error,
                "http2.request_body.flow_control_failed status=0x%08X body_offset=%Iu body_length=%Iu connection_window=%ld stream_window=%ld",
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

        bool HeaderNameEqualsLiteral(http1::HttpText text, const char* literal, SIZE_T literalLength) noexcept
        {
            return text.Data != nullptr &&
                TextEquals(text.Data, text.Length, literal, literalLength);
        }

        bool HeaderValueEqualsLiteral(http1::HttpText text, const char* literal, SIZE_T literalLength) noexcept
        {
            return text.Data != nullptr &&
                TextEquals(text.Data, text.Length, literal, literalLength);
        }

        NTSTATUS ValidateExtendedConnectRequest(
            const http1::HttpHeader* headers,
            SIZE_T headerCount,
            bool* usesExtendedConnect) noexcept
        {
            if (usesExtendedConnect == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *usesExtendedConnect = false;
            bool methodIsConnect = false;
            for (SIZE_T index = 0; index < headerCount; ++index) {
                if (HeaderNameEqualsLiteral(headers[index].Name, ":method", 7)) {
                    methodIsConnect = HeaderValueEqualsLiteral(headers[index].Value, "CONNECT", 7);
                }
                else if (HeaderNameEqualsLiteral(headers[index].Name, ":protocol", 9)) {
                    if (headers[index].Value.Data == nullptr || headers[index].Value.Length == 0) {
                        return STATUS_INVALID_PARAMETER;
                    }
                    *usesExtendedConnect = true;
                }
            }

            if (*usesExtendedConnect && !methodIsConnect) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
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
                case Http2SettingId::EnableConnectProtocol:
                    if (value > 1) {
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
            const http1::HttpHeader* headers,
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
            const http1::HttpHeader* decodedHeaders,
            SIZE_T decodedHeaderCount,
            http1::HttpHeader* responseHeaders,
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
                const http1::HttpHeader& header = decodedHeaders[index];
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

        bool RequestBodyHasData(const Http2RequestBody& requestBody) noexcept
        {
            return (requestBody.Data != nullptr && requestBody.DataLength != 0) ||
                requestBody.Source != nullptr ||
                requestBody.HasBody;
        }

        NTSTATUS ValidateRequestBodyDescriptor(const Http2RequestBody& requestBody) noexcept
        {
            if (requestBody.Data == nullptr && requestBody.DataLength != 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (requestBody.Data != nullptr && requestBody.Source != nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (requestBody.Source != nullptr && requestBody.Source->Read == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (requestBody.Trailers == nullptr && requestBody.TrailerCount != 0) {
                return STATUS_INVALID_PARAMETER;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS ValidateRequestPriority(ULONG streamId, const Http2Priority* priority) noexcept
        {
            if (priority == nullptr) {
                return STATUS_SUCCESS;
            }

            if ((priority->StreamDependency & 0x80000000u) != 0 ||
                priority->StreamDependency == streamId ||
                priority->Weight == 0 ||
                priority->Weight > 256) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS ValidateRequestTrailers(
            const http1::HttpHeader* trailers,
            SIZE_T trailerCount) noexcept
        {
            if (trailers == nullptr && trailerCount != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < trailerCount; ++index) {
                const http1::HttpHeader& trailer = trailers[index];
                if (trailer.Name.Data == nullptr ||
                    trailer.Name.Length == 0 ||
                    trailer.Name.Data[0] == ':' ||
                    (trailer.Value.Data == nullptr && trailer.Value.Length != 0)) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (!IsValidHttp2FieldName(trailer.Name.Data, trailer.Name.Length) ||
                    !IsValidHttp2FieldValue(trailer.Value.Data, trailer.Value.Length) ||
                    TextContainsUppercase(trailer.Name.Data, trailer.Name.Length) ||
                    IsConnectionSpecificHeaderName(trailer.Name.Data, trailer.Name.Length) ||
                    TextEquals(trailer.Name.Data, trailer.Name.Length, "content-length", 14) ||
                    TextEquals(trailer.Name.Data, trailer.Name.Length, "host", 4)) {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            return STATUS_SUCCESS;
        }
    }

    Http2Connection::Http2Connection() noexcept
    {
        InitializeLocks();
    }

    void Http2Connection::InitializeLocks() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        if (!locksInitialized_) {
            KeInitializeMutex(&stateLock_, 0);
            KeInitializeMutex(&receiveLock_, 0);
            locksInitialized_ = true;
        }
#endif
    }

    void Http2Connection::LockState() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        InitializeLocks();
        (void)KeWaitForSingleObject(
            &stateLock_,
            Executive,
            KernelMode,
            FALSE,
            nullptr);
#endif
    }

    void Http2Connection::UnlockState() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        KeReleaseMutex(&stateLock_, FALSE);
#endif
    }

    void Http2Connection::LockReceive() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        InitializeLocks();
        (void)KeWaitForSingleObject(
            &receiveLock_,
            Executive,
            KernelMode,
            FALSE,
            nullptr);
#endif
    }

    void Http2Connection::UnlockReceive() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        KeReleaseMutex(&receiveLock_, FALSE);
#endif
    }

    Http2Connection::~Http2Connection() noexcept
    {
        FreeNonPagedArray(sendBuffer_);
        FreeNonPagedArray(framePayload_);
        FreeNonPagedArray(headerBlock_);
        FreeNonPagedArray(responseHeaderBlock_);
        FreeNonPagedArray(decodedHeaderScratch_);
        FreeNonPagedArray(activeStreams_);
        sendBuffer_ = nullptr;
        framePayload_ = nullptr;
        headerBlock_ = nullptr;
        responseHeaderBlock_ = nullptr;
        decodedHeaderScratch_ = nullptr;
        activeStreams_ = nullptr;
        framePayloadCapacity_ = 0;
        headerBlockCapacity_ = Http2DefaultHeaderBlockCapacity;
        decodedHeaderScratchCapacity_ = 0;
        activeStreamCapacity_ = 0;
    }

    ULONG Http2Connection::MaxConcurrentStreamsLocked() const noexcept
    {
        ULONG limit = peerSettings_.MaxConcurrentStreams;
        if (limit > WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL) {
            limit = WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL;
        }
        if (activeStreamCapacity_ != 0 &&
            limit > static_cast<ULONG>(activeStreamCapacity_)) {
            limit = static_cast<ULONG>(activeStreamCapacity_);
        }
        return limit;
    }

    ULONG Http2Connection::MaxConcurrentStreams() noexcept
    {
        ScopedStateLock lock(*this);
        return MaxConcurrentStreamsLocked();
    }

    void Http2Connection::ReleaseStream(ULONG streamId) noexcept
    {
        ScopedStateLock lock(*this);
        ReleaseActiveStream(streamId);
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
            headerBlock_ = AllocateNonPagedArray<UCHAR>(headerBlockCapacity_);
            if (headerBlock_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (responseHeaderBlock_ == nullptr) {
            responseHeaderBlock_ = AllocateNonPagedArray<UCHAR>(headerBlockCapacity_);
            if (responseHeaderBlock_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (activeStreams_ == nullptr) {
            activeStreams_ = AllocateNonPagedArray<Http2ActiveStream>(DefaultActiveStreamCapacity);
            if (activeStreams_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
            activeStreamCapacity_ = DefaultActiveStreamCapacity;
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

        http1::HttpHeader* scratch = AllocateNonPagedArray<http1::HttpHeader>(requiredCapacity);
        if (scratch == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        FreeNonPagedArray(decodedHeaderScratch_);
        decodedHeaderScratch_ = scratch;
        decodedHeaderScratchCapacity_ = requiredCapacity;
        return STATUS_SUCCESS;
    }

    Http2ActiveStream* Http2Connection::FindActiveStream(ULONG streamId) noexcept
    {
        if (activeStreams_ == nullptr || streamId == 0) {
            return nullptr;
        }

        for (SIZE_T index = 0; index < activeStreamCapacity_; ++index) {
            if (activeStreams_[index].InUse &&
                activeStreams_[index].Stream.StreamId() == streamId) {
                return activeStreams_ + index;
            }
        }

        return nullptr;
    }

    Http2ActiveStream* Http2Connection::FindContinuationStream() noexcept
    {
        if (activeStreams_ == nullptr) {
            return nullptr;
        }

        for (SIZE_T index = 0; index < activeStreamCapacity_; ++index) {
            if (activeStreams_[index].InUse &&
                activeStreams_[index].ResponseState.ExpectingContinuation) {
                return activeStreams_ + index;
            }
        }

        return nullptr;
    }

    Http2ActiveStream* Http2Connection::ReserveActiveStream() noexcept
    {
        if (activeStreams_ == nullptr) {
            return nullptr;
        }

        SIZE_T activeCount = 0;
        for (SIZE_T index = 0; index < activeStreamCapacity_; ++index) {
            if (activeStreams_[index].InUse) {
                ++activeCount;
                continue;
            }
        }

        if (activeCount >= MaxConcurrentStreamsLocked()) {
            return nullptr;
        }

        for (SIZE_T index = 0; index < activeStreamCapacity_; ++index) {
            if (!activeStreams_[index].InUse) {
                activeStreams_[index] = {};
                activeStreams_[index].InUse = true;
                return activeStreams_ + index;
            }
        }

        return nullptr;
    }

    void Http2Connection::ReleaseActiveStream(ULONG streamId) noexcept
    {
        Http2ActiveStream* active = FindActiveStream(streamId);
        if (active == nullptr) {
            return;
        }

        *active = {};
    }

    NTSTATUS Http2Connection::AdjustActiveStreamRemoteWindows(long long delta) noexcept
    {
        if (activeStreams_ == nullptr || delta == 0) {
            return STATUS_SUCCESS;
        }

        for (SIZE_T index = 0; index < activeStreamCapacity_; ++index) {
            if (!activeStreams_[index].InUse) {
                continue;
            }

            NTSTATUS status = activeStreams_[index].Stream.AdjustRemoteWindow(delta);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::Initialize(Http2Transport& transport, SIZE_T maxHeaderBlockBytes) noexcept
    {
        if (maxHeaderBlockBytes == 0 ||
            maxHeaderBlockBytes > Http2MaxHeaderBlockCapacity ||
            maxHeaderBlockBytes > static_cast<SIZE_T>(0xffffffffUL)) {
            return STATUS_INVALID_PARAMETER;
        }

        headerBlockCapacity_ = maxHeaderBlockBytes;
        localSettings_.MaxHeaderListSize = static_cast<ULONG>(headerBlockCapacity_);

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

    NTSTATUS Http2Connection::Initialize(transport::Transport* transport, SIZE_T maxHeaderBlockBytes) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return Initialize(adapter, maxHeaderBlockBytes);
    }

    NTSTATUS Http2Connection::InitializeAfterUpgrade(
        Http2Transport& transport,
        SIZE_T maxHeaderBlockBytes) noexcept
    {
        NTSTATUS status = Initialize(transport, maxHeaderBlockBytes);
        if (!NT_SUCCESS(status)) return status;

        nextStreamId_ = 3;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::InitializeAfterUpgrade(
        transport::Transport* transport,
        SIZE_T maxHeaderBlockBytes) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return InitializeAfterUpgrade(adapter, maxHeaderBlockBytes);
    }

    NTSTATUS Http2Connection::DispatchNextFrame(
        Http2Transport& transport,
        Http2Stream* activeStream) noexcept
    {
        Http2FrameHeader fh = {};
        UCHAR* fp = framePayload_;
        SIZE_T fpLen = 0;

        NTSTATUS status = ReadFrame(transport, &fh, fp, framePayloadCapacity_, &fpLen);
        if (!NT_SUCCESS(status)) {
            return HandleReadFrameFailure(transport, status);
        }

        return DispatchFrame(transport, fh, fp, fpLen, activeStream);
    }

    NTSTATUS Http2Connection::DispatchFrame(
        Http2Transport& transport,
        const Http2FrameHeader& fh,
        const UCHAR* fp,
        SIZE_T fpLen,
        Http2Stream* activeStream) noexcept
    {
        NTSTATUS status = STATUS_SUCCESS;

        WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Verbose, "http2.frame.dispatched type=%u flags=0x%02X stream_id=%u length=%u",
            static_cast<unsigned>(fh.Type),
            static_cast<unsigned>(fh.Flags),
            fh.StreamId,
            fh.Length);

        if (!IsValidFrameTarget(fh)) {
            const NTSTATUS goAwayStatus = SendGoAway(
                transport,
                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
            UNREFERENCED_PARAMETER(goAwayStatus);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        Http2ActiveStream* continuationStream = FindContinuationStream();
        if (continuationStream != nullptr) {
            if (fh.Type != Http2FrameType::Continuation ||
                fh.StreamId != continuationStream->Stream.StreamId()) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else if (fh.Type == Http2FrameType::Continuation) {
            const NTSTATUS goAwayStatus = SendGoAway(
                transport,
                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
            UNREFERENCED_PARAMETER(goAwayStatus);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (fh.StreamId == 0) {
            return HandleConnectionFrame(transport, fh, fp, fpLen, activeStream);
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

        Http2ActiveStream* active = FindActiveStream(fh.StreamId);
        if (active == nullptr) {
            if (fh.Type == Http2FrameType::WindowUpdate) {
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
                    return status;
                }
            }
            return STATUS_SUCCESS;
        }

        return ProcessResponseFrame(
            transport,
            active->Stream,
            fh,
            fp,
            fpLen,
            active->ResponseState);
    }

    NTSTATUS Http2Connection::SendRequestFrames(
        Http2Transport& transport,
        Http2Stream& stream,
        Http2ResponseFrameState& responseFrameState,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody& requestBody) noexcept
    {
        NTSTATUS status = ValidateRequestBodyDescriptor(requestBody);
        if (!NT_SUCCESS(status)) return status;
        status = ValidateRequestTrailers(requestBody.Trailers, requestBody.TrailerCount);
        if (!NT_SUCCESS(status)) return status;

        UCHAR* headerBlock = headerBlock_;
        SIZE_T headerBlockLen = 0;
        status = encoder_.Encode(
            requestHeaders,
            requestHeaderCount,
            headerBlock,
            headerBlockCapacity_,
            &headerBlockLen);
        if (!NT_SUCCESS(status)) return status;

        const ULONG streamId = stream.StreamId();
        const bool endStream =
            !responseFrameState.TunnelMode &&
            !RequestBodyHasData(requestBody) &&
            requestBody.TrailerCount == 0;
        status = ValidateRequestPriority(streamId, requestBody.Priority);
        if (!NT_SUCCESS(status)) return status;

        UCHAR* sendBuf = sendBuffer_;
        SIZE_T sendOffset = 0;
        SIZE_T blockOffset = 0;
        ULONG maxPayload = OutboundPayloadLimit(peerSettings_.MaxFrameSize);
        bool firstFrame = true;

        while (blockOffset < headerBlockLen) {
            SIZE_T chunkLen = headerBlockLen - blockOffset;
            ULONG framePayloadLimit = maxPayload;
            if (firstFrame && requestBody.Priority != nullptr) {
                constexpr ULONG PriorityFieldLength = 5;
                if (framePayloadLimit <= PriorityFieldLength) return STATUS_BUFFER_TOO_SMALL;
                framePayloadLimit -= PriorityFieldLength;
            }
            if (chunkLen > framePayloadLimit) chunkLen = framePayloadLimit;
            const bool lastChunk = (blockOffset + chunkLen >= headerBlockLen);

            const SIZE_T priorityBytes = (firstFrame && requestBody.Priority != nullptr) ? 5 : 0;
            if (Http2FrameHeaderLength + priorityBytes + chunkLen > SendBufferCapacity) return STATUS_BUFFER_TOO_SMALL;
            if (sendOffset + Http2FrameHeaderLength + priorityBytes + chunkLen > SendBufferCapacity) {
                status = SendRaw(transport, sendBuf, sendOffset);
                if (!NT_SUCCESS(status)) return status;
                sendOffset = 0;
            }

            SIZE_T written = 0;
            const bool isFirstHeaderFrame = firstFrame;
            if (isFirstHeaderFrame) {
                if (requestBody.Priority != nullptr) {
                    status = Http2FrameCodec::EncodeHeadersWithPriority(
                        streamId,
                        headerBlock + blockOffset,
                        chunkLen,
                        *requestBody.Priority,
                        endStream,
                        lastChunk,
                        sendBuf + sendOffset,
                        SendBufferCapacity - sendOffset,
                        &written);
                }
                else {
                    status = Http2FrameCodec::EncodeHeaders(
                        streamId,
                        headerBlock + blockOffset,
                        chunkLen,
                        endStream,
                        lastChunk,
                        sendBuf + sendOffset,
                        SendBufferCapacity - sendOffset,
                        &written);
                }
                firstFrame = false;
            }
            else {
                status = Http2FrameCodec::EncodeContinuation(
                    streamId,
                    headerBlock + blockOffset,
                    chunkLen,
                    lastChunk,
                    sendBuf + sendOffset,
                    SendBufferCapacity - sendOffset,
                    &written);
            }
            if (!NT_SUCCESS(status)) return status;
            if (isFirstHeaderFrame) {
                status = stream.SendHeaders(endStream);
                if (!NT_SUCCESS(status)) return status;
            }
            sendOffset += written;
            blockOffset += chunkLen;
        }

        if (sendOffset != 0) {
            status = SendRaw(transport, sendBuf, sendOffset);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "http2.headers.send_failed status=0x%08X stream_id=%u bytes=%Iu",
                    static_cast<ULONG>(status),
                    streamId,
                    sendOffset);
                return status;
            }
            sendOffset = 0;
        }

        if (!endStream && RequestBodyHasData(requestBody)) {
            status = SendRequestBodyFrames(
                transport,
                stream,
                responseFrameState,
                requestBody);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (!responseFrameState.TerminalResponseReceived &&
            !responseFrameState.StreamClosed) {
            if (requestBody.TrailerCount != 0) {
                return SendRequestTrailingHeaders(
                    transport,
                    stream,
                    requestBody.Trailers,
                    requestBody.TrailerCount);
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::SendRequestBodyFrames(
        Http2Transport& transport,
        Http2Stream& stream,
        Http2ResponseFrameState& responseFrameState,
        const Http2RequestBody& requestBody) noexcept
    {
        const ULONG streamId = stream.StreamId();
        const ULONG maxPayload = OutboundPayloadLimit(peerSettings_.MaxFrameSize);
        const bool hasTrailers = requestBody.TrailerCount != 0;
        SIZE_T bodyOffset = 0;
        SIZE_T sourceTotalRead = 0;
        bool sourceEnded = requestBody.Source == nullptr;
        bool sentAnyData = false;

        for (;;) {
            if (responseFrameState.TerminalResponseReceived ||
                responseFrameState.StreamClosed) {
                return STATUS_SUCCESS;
            }

            SIZE_T chunkLen = 0;
            const UCHAR* chunkData = nullptr;
            bool endOfBody = false;

            if (requestBody.Source != nullptr) {
                LONG available = connectionSendWindow_ < stream.RemoteWindow()
                    ? connectionSendWindow_
                    : stream.RemoteWindow();
                if (available <= 0) {
                    NTSTATUS status = DispatchNextFrame(transport, &stream);
                    if (!NT_SUCCESS(status)) {
                        LogRequestBodyFlowControlFailure(
                            status,
                            sourceTotalRead,
                            requestBody.Source->ContentLength,
                            connectionSendWindow_,
                            stream.RemoteWindow());
                        return status;
                    }
                    continue;
                }

                SIZE_T readCapacity = static_cast<SIZE_T>(available);
                if (readCapacity > maxPayload) {
                    readCapacity = maxPayload;
                }
                if (readCapacity > SendBufferCapacity - Http2FrameHeaderLength) {
                    readCapacity = SendBufferCapacity - Http2FrameHeaderLength;
                }

                SIZE_T bytesRead = 0;
                bool sourceEnd = false;
                NTSTATUS status = requestBody.Source->Read(
                    requestBody.Source->Context,
                    sendBuffer_ + Http2FrameHeaderLength,
                    readCapacity,
                    &bytesRead,
                    &sourceEnd);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (bytesRead > readCapacity ||
                    (bytesRead == 0 && !sourceEnd)) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (requestBody.Source->ContentLengthKnown &&
                    bytesRead > requestBody.Source->ContentLength - sourceTotalRead) {
                    return STATUS_INVALID_PARAMETER;
                }

                chunkLen = bytesRead;
                chunkData = chunkLen != 0 ? sendBuffer_ + Http2FrameHeaderLength : nullptr;
                sourceTotalRead += bytesRead;
                sourceEnded = sourceEnd;
                endOfBody = sourceEnd;
                if (requestBody.Source->ContentLengthKnown &&
                    sourceTotalRead == requestBody.Source->ContentLength) {
                    endOfBody = true;
                    sourceEnded = true;
                }
                if (requestBody.Source->ContentLengthKnown &&
                    sourceEnded &&
                    sourceTotalRead != requestBody.Source->ContentLength) {
                    return STATUS_INVALID_PARAMETER;
                }
            }
            else {
                if (bodyOffset >= requestBody.DataLength) {
                    endOfBody = true;
                    if (sentAnyData || !requestBody.HasBody) {
                        break;
                    }
                }
                else {
                    chunkLen = requestBody.DataLength - bodyOffset;
                    if (chunkLen > maxPayload) {
                        chunkLen = maxPayload;
                    }

                    LONG available = connectionSendWindow_ < stream.RemoteWindow()
                        ? connectionSendWindow_
                        : stream.RemoteWindow();
                    if (available <= 0) {
                        NTSTATUS status = DispatchNextFrame(transport, &stream);
                        if (!NT_SUCCESS(status)) {
                            LogRequestBodyFlowControlFailure(
                                status,
                                bodyOffset,
                                requestBody.DataLength,
                                connectionSendWindow_,
                                stream.RemoteWindow());
                            return status;
                        }
                        continue;
                    }
                    if (chunkLen > static_cast<SIZE_T>(available)) {
                        chunkLen = static_cast<SIZE_T>(available);
                    }
                    chunkData = requestBody.Data + bodyOffset;
                    endOfBody = bodyOffset + chunkLen >= requestBody.DataLength;
                }
            }

            const bool frameEndStream = endOfBody && !hasTrailers;
            if (chunkLen == 0 && !frameEndStream) {
                if (endOfBody) {
                    break;
                }
                continue;
            }

            SIZE_T written = 0;
            NTSTATUS status = Http2FrameCodec::EncodeData(
                streamId,
                chunkData,
                chunkLen,
                frameEndStream,
                sendBuffer_,
                SendBufferCapacity,
                &written);
            if (!NT_SUCCESS(status)) {
                LogRequestBodyFlowControlFailure(
                    status,
                    requestBody.Source != nullptr ? sourceTotalRead : bodyOffset,
                    requestBody.Source != nullptr ? requestBody.Source->ContentLength : requestBody.DataLength,
                    connectionSendWindow_,
                    stream.RemoteWindow());
                return status;
            }

            status = stream.SendData(chunkLen, frameEndStream);
            if (!NT_SUCCESS(status)) {
                LogRequestBodyFlowControlFailure(
                    status,
                    requestBody.Source != nullptr ? sourceTotalRead : bodyOffset,
                    requestBody.Source != nullptr ? requestBody.Source->ContentLength : requestBody.DataLength,
                    connectionSendWindow_,
                    stream.RemoteWindow());
                return status;
            }

            status = SendRaw(transport, sendBuffer_, written);
            if (!NT_SUCCESS(status)) {
                LogRequestBodyFlowControlFailure(
                    status,
                    requestBody.Source != nullptr ? sourceTotalRead : bodyOffset,
                    requestBody.Source != nullptr ? requestBody.Source->ContentLength : requestBody.DataLength,
                    connectionSendWindow_,
                    stream.RemoteWindow());
                return status;
            }

            connectionSendWindow_ -= static_cast<LONG>(chunkLen);
            sentAnyData = true;
            if (requestBody.Source == nullptr) {
                bodyOffset += chunkLen;
            }

            if (endOfBody) {
                break;
            }
        }

        if (requestBody.Source != nullptr &&
            requestBody.Source->ContentLengthKnown &&
            sourceTotalRead != requestBody.Source->ContentLength) {
            return STATUS_INVALID_PARAMETER;
        }
        if (requestBody.Source != nullptr && !sourceEnded) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::SendRequestTrailingHeaders(
        Http2Transport& transport,
        Http2Stream& stream,
        const http1::HttpHeader* trailers,
        SIZE_T trailerCount) noexcept
    {
        NTSTATUS status = ValidateRequestTrailers(trailers, trailerCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UCHAR* headerBlock = headerBlock_;
        SIZE_T headerBlockLen = 0;
        status = encoder_.Encode(
            trailers,
            trailerCount,
            headerBlock,
            headerBlockCapacity_,
            &headerBlockLen);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const ULONG streamId = stream.StreamId();
        UCHAR* sendBuf = sendBuffer_;
        SIZE_T sendOffset = 0;
        SIZE_T blockOffset = 0;
        const ULONG maxPayload = OutboundPayloadLimit(peerSettings_.MaxFrameSize);
        bool firstFrame = true;

        while (blockOffset < headerBlockLen || (headerBlockLen == 0 && firstFrame)) {
            SIZE_T chunkLen = headerBlockLen - blockOffset;
            if (chunkLen > maxPayload) {
                chunkLen = maxPayload;
            }
            const bool lastChunk = blockOffset + chunkLen >= headerBlockLen;

            SIZE_T written = 0;
            if (firstFrame) {
                status = Http2FrameCodec::EncodeHeaders(
                    streamId,
                    chunkLen != 0 ? headerBlock + blockOffset : nullptr,
                    chunkLen,
                    true,
                    lastChunk,
                    sendBuf + sendOffset,
                    SendBufferCapacity - sendOffset,
                    &written);
                firstFrame = false;
            }
            else {
                status = Http2FrameCodec::EncodeContinuation(
                    streamId,
                    headerBlock + blockOffset,
                    chunkLen,
                    lastChunk,
                    sendBuf + sendOffset,
                    SendBufferCapacity - sendOffset,
                    &written);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (sendOffset + written > SendBufferCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            sendOffset += written;
            blockOffset += chunkLen;

            if (sendOffset + Http2FrameHeaderLength + maxPayload > SendBufferCapacity) {
                status = SendRaw(transport, sendBuf, sendOffset);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                sendOffset = 0;
            }

            if (headerBlockLen == 0) {
                break;
            }
        }

        status = stream.SendHeaders(true);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendRaw(transport, sendBuf, sendOffset);
    }

    NTSTATUS Http2Connection::BeginRequest(
        Http2Transport& transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody& requestBody,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        ULONG* streamId) noexcept
    {
        ScopedReceiveLock receiveLock(*this, RequestBodyHasData(requestBody));
        ScopedStateLock stateLock(*this);

        if (streamId != nullptr) {
            *streamId = 0;
        }

        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        if (requestHeaders == nullptr || responseHeaders == nullptr ||
            responseHeaderCount == nullptr || responseBodySink.Append == nullptr ||
            responseBodyLength == nullptr || statusCode == nullptr ||
            nameValueBuffer == nullptr || streamId == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *responseHeaderCount = 0;
        *responseBodyLength = 0;
        *statusCode = 0;

        status = EnsureDecodedHeaderScratch(responseHeaderCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        bool usesExtendedConnect = false;
        status = ValidateExtendedConnectRequest(
            requestHeaders,
            requestHeaderCount,
            &usesExtendedConnect);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (usesExtendedConnect && peerSettings_.EnableConnectProtocol != 1) {
            return STATUS_NOT_SUPPORTED;
        }

        Http2ActiveStream* active = ReserveActiveStream();
        if (active == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const ULONG allocatedStreamId = AllocateStreamId();
        active->Stream.Initialize(
            allocatedStreamId,
            localSettings_.InitialWindowSize,
            peerSettings_.InitialWindowSize);

        Http2ResponseFrameState& responseFrameState = active->ResponseState;
        responseFrameState = {};
        responseFrameState.RequestForbidsResponseBody =
            RequestForbidsResponseBody(requestHeaders, requestHeaderCount);
        responseFrameState.ResponseBodyForbidden = responseFrameState.RequestForbidsResponseBody;
        responseFrameState.TunnelMode = usesExtendedConnect;
        responseFrameState.ResponseHeaderBlock = responseHeaderBlock_;
        responseFrameState.ResponseHeaderBlockCapacity = headerBlockCapacity_;
        responseFrameState.ResponseHeaders = responseHeaders;
        responseFrameState.ResponseHeaderCapacity = responseHeaderCapacity;
        responseFrameState.ResponseHeaderCount = responseHeaderCount;
        responseFrameState.ResponseBodySink = responseBodySink;
        responseFrameState.ResponseBodyLength = responseBodyLength;
        responseFrameState.StatusCode = statusCode;
        responseFrameState.NameValueBuffer = nameValueBuffer;
        responseFrameState.NameValueCapacity = nameValueCapacity;

        status = SendRequestFrames(
            transport,
            active->Stream,
            responseFrameState,
            requestHeaders,
            requestHeaderCount,
            requestBody);
        if (!NT_SUCCESS(status)) {
            ReleaseActiveStream(allocatedStreamId);
            return status;
        }

        *streamId = allocatedStreamId;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::BeginRequest(
        Http2Transport& transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        ULONG* streamId) noexcept
    {
        const Http2RequestBody requestBody = MakeFixedRequestBody(body, bodyLength);
        return BeginRequest(
            transport,
            requestHeaders,
            requestHeaderCount,
            requestBody,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBodySink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity,
            streamId);
    }

    NTSTATUS Http2Connection::BeginRequest(
        transport::Transport* transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody& requestBody,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        ULONG* streamId) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return BeginRequest(
            adapter,
            requestHeaders,
            requestHeaderCount,
            requestBody,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBodySink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity,
            streamId);
    }

    NTSTATUS Http2Connection::BeginRequest(
        transport::Transport* transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        ULONG* streamId) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return BeginRequest(
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
            nameValueCapacity,
            streamId);
    }

    NTSTATUS Http2Connection::ReceiveResponse(
        Http2Transport& transport,
        ULONG streamId) noexcept
    {
        ScopedReceiveLock receiveLock(*this);
        NTSTATUS status = STATUS_SUCCESS;
        bool streamObserved = false;
        for (;;) {
            {
                ScopedStateLock stateLock(*this);
                Http2ActiveStream* active = FindActiveStream(streamId);
                if (active == nullptr) {
                    return streamObserved ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
                }
                streamObserved = true;

                if (active->ResponseState.StreamClosed) {
                    *active->ResponseState.ResponseBodyLength = active->ResponseState.BodyLength;
                    ReleaseActiveStream(streamId);
                    return STATUS_SUCCESS;
                }
            }

            UCHAR* headerBuffer = nullptr;
            {
                ScopedStateLock stateLock(*this);
                if (framePayload_ == nullptr || framePayloadCapacity_ < Http2FrameHeaderLength) {
                    return STATUS_INVALID_DEVICE_STATE;
                }
                headerBuffer = framePayload_;
                readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::NoError);
            }
            status = ReadExact(transport, headerBuffer, Http2FrameHeaderLength);
            if (!NT_SUCCESS(status)) {
                ScopedStateLock stateLock(*this);
                return HandleReadFrameFailure(transport, status);
            }

            Http2FrameHeader fh = {};
            status = Http2FrameCodec::DecodeFrameHeader(headerBuffer, Http2FrameHeaderLength, &fh);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            UCHAR* fp = nullptr;
            SIZE_T fpCapacity = 0;
            ULONG maxFrameSize = 0;
            {
                ScopedStateLock stateLock(*this);
                fp = framePayload_;
                fpCapacity = framePayloadCapacity_;
                maxFrameSize = localSettings_.MaxFrameSize;
            }

            if (fh.Length > maxFrameSize) {
                ScopedStateLock stateLock(*this);
                readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::FrameSizeError);
                return HandleReadFrameFailure(transport, STATUS_INVALID_NETWORK_RESPONSE);
            }
            if (fh.Length > fpCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (fh.Length != 0 && fp == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            const SIZE_T fpLen = fh.Length;
            if (fh.Length != 0) {
                status = ReadExact(transport, fp, fh.Length);
                if (!NT_SUCCESS(status)) {
                    ScopedStateLock stateLock(*this);
                    return HandleReadFrameFailure(transport, status);
                }
            }

            {
                ScopedStateLock stateLock(*this);
                status = RecordReceivedFrame(fh);
                if (!NT_SUCCESS(status)) {
                    return HandleReadFrameFailure(transport, status);
                }
                Http2ActiveStream* active = FindActiveStream(streamId);
                if (active == nullptr) {
                    return streamObserved ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
                }
                status = DispatchFrame(transport, fh, fp, fpLen, &active->Stream);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }
    }

    NTSTATUS Http2Connection::ReceiveResponse(
        transport::Transport* transport,
        ULONG streamId) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return ReceiveResponse(adapter, streamId);
    }

    NTSTATUS Http2Connection::ReceiveResponseHeaders(
        Http2Transport& transport,
        ULONG streamId) noexcept
    {
        Http2ActiveStream* active = FindActiveStream(streamId);
        if (active == nullptr || !active->ResponseState.TunnelMode) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        while (!active->ResponseState.TerminalResponseReceived &&
            !active->ResponseState.StreamClosed) {
            status = DispatchNextFrame(transport);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            active = FindActiveStream(streamId);
            if (active == nullptr) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
        }

        if (active->ResponseState.StreamClosed) {
            ReleaseActiveStream(streamId);
            return STATUS_CONNECTION_DISCONNECTED;
        }

        *active->ResponseState.ResponseBodyLength = active->ResponseState.BodyLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::ReceiveResponseHeaders(
        transport::Transport* transport,
        ULONG streamId) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return ReceiveResponseHeaders(adapter, streamId);
    }

    NTSTATUS Http2Connection::SendStreamData(
        Http2Transport& transport,
        ULONG streamId,
        const UCHAR* data,
        SIZE_T dataLength,
        bool endStream) noexcept
    {
        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        Http2ActiveStream* active = FindActiveStream(streamId);
        if (active == nullptr ||
            !active->ResponseState.TunnelMode ||
            !active->ResponseState.TerminalResponseReceived ||
            (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        UCHAR* sendBuf = sendBuffer_;
        SIZE_T sendOffset = 0;
        SIZE_T dataOffset = 0;
        const ULONG maxPayload = OutboundPayloadLimit(peerSettings_.MaxFrameSize);

        while (dataOffset < dataLength || (dataLength == 0 && sendOffset == 0)) {
            SIZE_T chunkLen = dataLength - dataOffset;
            if (chunkLen > maxPayload) chunkLen = maxPayload;

            const LONG available = connectionSendWindow_ < active->Stream.RemoteWindow()
                ? connectionSendWindow_
                : active->Stream.RemoteWindow();
            if (available <= 0) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (chunkLen > static_cast<SIZE_T>(available)) {
                chunkLen = static_cast<SIZE_T>(available);
            }

            const bool lastData =
                (dataOffset + chunkLen >= dataLength) ||
                dataLength == 0;
            const bool frameEndStream = endStream && lastData;

            if (Http2FrameHeaderLength + chunkLen > SendBufferCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (sendOffset + Http2FrameHeaderLength + chunkLen > SendBufferCapacity) {
                status = SendRaw(transport, sendBuf, sendOffset);
                if (!NT_SUCCESS(status)) return status;
                sendOffset = 0;
            }

            SIZE_T written = 0;
            status = Http2FrameCodec::EncodeData(
                streamId,
                dataLength == 0 ? nullptr : data + dataOffset,
                chunkLen,
                frameEndStream,
                sendBuf + sendOffset,
                SendBufferCapacity - sendOffset,
                &written);
            if (!NT_SUCCESS(status)) return status;

            status = active->Stream.SendData(chunkLen, frameEndStream);
            if (!NT_SUCCESS(status)) return status;

            sendOffset += written;
            dataOffset += chunkLen;
            connectionSendWindow_ -= static_cast<LONG>(chunkLen);

            if (dataLength == 0) {
                break;
            }
        }

        status = SendRaw(transport, sendBuf, sendOffset);
        if (NT_SUCCESS(status) && endStream) {
            ReleaseActiveStream(streamId);
        }
        return status;
    }

    NTSTATUS Http2Connection::SendStreamData(
        transport::Transport* transport,
        ULONG streamId,
        const UCHAR* data,
        SIZE_T dataLength,
        bool endStream) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return SendStreamData(adapter, streamId, data, dataLength, endStream);
    }

    NTSTATUS Http2Connection::ReceiveStreamData(
        Http2Transport& transport,
        ULONG streamId,
        UCHAR* buffer,
        SIZE_T bufferCapacity,
        SIZE_T* bytesReceived,
        bool* endStream) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }
        if (endStream != nullptr) {
            *endStream = false;
        }

        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        Http2ActiveStream* active = FindActiveStream(streamId);
        if (active == nullptr ||
            !active->ResponseState.TunnelMode ||
            !active->ResponseState.TerminalResponseReceived ||
            buffer == nullptr ||
            bytesReceived == nullptr ||
            endStream == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        for (;;) {
            Http2FrameHeader fh = {};
            UCHAR* fp = framePayload_;
            SIZE_T fpLen = 0;
            status = ReadFrame(transport, &fh, fp, framePayloadCapacity_, &fpLen);
            if (!NT_SUCCESS(status)) {
                return HandleReadFrameFailure(transport, status);
            }

            if (!IsValidFrameTarget(fh)) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (fh.StreamId == 0) {
                status = HandleConnectionFrame(transport, fh, fp, fpLen, &active->Stream);
                if (!NT_SUCCESS(status)) return status;
                continue;
            }

            if (fh.StreamId != streamId) {
                Http2ActiveStream* other = FindActiveStream(fh.StreamId);
                if (other != nullptr) {
                    status = ProcessResponseFrame(
                        transport,
                        other->Stream,
                        fh,
                        fp,
                        fpLen,
                        other->ResponseState);
                    if (!NT_SUCCESS(status)) return status;
                }
                continue;
            }

            switch (fh.Type) {
            case Http2FrameType::Data:
            {
                const UCHAR* content = fp;
                SIZE_T contentLen = fpLen;
                status = Http2FrameCodec::StripPadding(fh.Flags, fp, fpLen, &content, &contentLen);
                if (!NT_SUCCESS(status)) return status;
                if (contentLen > bufferCapacity) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                const bool frameEndStream = (fh.Flags & Http2FrameFlags::EndStream) != 0;
                status = active->Stream.ReceiveData(fpLen, frameEndStream);
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
                connectionRecvConsumed_ += static_cast<ULONG>(fpLen);

                for (SIZE_T index = 0; index < contentLen; ++index) {
                    buffer[index] = content[index];
                }
                *bytesReceived = contentLen;
                *endStream = frameEndStream;

                status = SendWindowUpdateIfNeeded(
                    transport,
                    frameEndStream ? nullptr : &active->Stream,
                    static_cast<ULONG>(fpLen));
                if (!NT_SUCCESS(status)) return status;

                if (frameEndStream) {
                    ReleaseActiveStream(streamId);
                }
                return STATUS_SUCCESS;
            }

            case Http2FrameType::WindowUpdate:
            case Http2FrameType::RstStream:
                status = ProcessResponseFrame(
                    transport,
                    active->Stream,
                    fh,
                    fp,
                    fpLen,
                    active->ResponseState);
                if (!NT_SUCCESS(status)) return status;
                if (active->ResponseState.StreamClosed) {
                    ReleaseActiveStream(streamId);
                    return STATUS_CONNECTION_DISCONNECTED;
                }
                break;

            case Http2FrameType::Headers:
            case Http2FrameType::Continuation:
            {
                const NTSTATUS rstStatus = SendRstStream(
                    transport,
                    streamId,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(rstStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            default:
                break;
            }
        }
    }

    NTSTATUS Http2Connection::ReceiveStreamData(
        transport::Transport* transport,
        ULONG streamId,
        UCHAR* buffer,
        SIZE_T bufferCapacity,
        SIZE_T* bytesReceived,
        bool* endStream) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return ReceiveStreamData(
            adapter,
            streamId,
            buffer,
            bufferCapacity,
            bytesReceived,
            endStream);
    }

    NTSTATUS Http2Connection::SendRequest(
        Http2Transport& transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody& requestBody,
        http1::HttpHeader* responseHeaders,
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
            requestBody,
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
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        const Http2RequestBody requestBody = MakeFixedRequestBody(body, bodyLength);
        return SendRequest(
            transport,
            requestHeaders,
            requestHeaderCount,
            requestBody,
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
        Http2Transport& transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody& requestBody,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        ULONG streamId = 0;
        NTSTATUS status = BeginRequest(
            transport,
            requestHeaders,
            requestHeaderCount,
            requestBody,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBodySink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity,
            &streamId);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReceiveResponse(transport, streamId);
        if (!NT_SUCCESS(status)) {
            ReleaseStream(streamId);
        }
        return status;
    }

    NTSTATUS Http2Connection::SendRequest(
        Http2Transport& transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        const Http2RequestBody requestBody = MakeFixedRequestBody(body, bodyLength);
        return SendRequest(
            transport,
            requestHeaders,
            requestHeaderCount,
            requestBody,
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
        http1::HttpHeader* responseHeaders,
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

        if (streamId == 0 || (streamId & 1u) == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        Http2Stream stream;
        stream.Initialize(streamId, localSettings_.InitialWindowSize, peerSettings_.InitialWindowSize);

        // h2c Upgrade maps the initiating HTTP/1.1 request to stream 1.
        // The client side is already closed when we start reading the HTTP/2 response.
        status = stream.SendHeaders(true);
        if (!NT_SUCCESS(status)) return status;

        if (responseBodySink.Append == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        return ReceiveResponseFrames(
            transport,
            stream,
            false,
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
        http1::HttpHeader* responseHeaders,
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

        return ReceiveResponse(
            transport,
            streamId,
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
        transport::Transport* transport,
        ULONG streamId,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2TransportAdapter adapter(transport);
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

    NTSTATUS Http2Connection::ReceiveResponse(
        transport::Transport* transport,
        ULONG streamId,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return ReceiveResponse(
            adapter,
            streamId,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBodySink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::ProcessResponseFrame(
        Http2Transport& transport,
        Http2Stream& stream,
        const Http2FrameHeader& fh,
        const UCHAR* fp,
        SIZE_T fpLen,
        Http2ResponseFrameState& state) noexcept
    {
        if (state.ResponseHeaderBlock == nullptr ||
            state.ResponseHeaderCount == nullptr ||
            state.ResponseBodySink.Append == nullptr ||
            state.ResponseBodyLength == nullptr ||
            state.StatusCode == nullptr ||
            state.NameValueBuffer == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        if (fh.Type == Http2FrameType::Continuation) {
            if (!state.ExpectingContinuation || fh.StreamId != state.ContinuationStreamId) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (++state.ContinuationFrames > Http2MaxContinuationFrames) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (fh.Length == 0) {
                if (++state.EmptyContinuationFrames > Http2MaxEmptyContinuationFrames) {
                    const NTSTATUS goAwayStatus = SendGoAway(
                        transport,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(goAwayStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            else {
                state.EmptyContinuationFrames = 0;
            }
        }
        else if (state.ExpectingContinuation) {
            const NTSTATUS goAwayStatus = SendGoAway(
                transport,
                static_cast<ULONG>(Http2ErrorCode::ProtocolError));
            UNREFERENCED_PARAMETER(goAwayStatus);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        switch (fh.Type) {
        case Http2FrameType::Priority:
        {
            Http2Priority priority = {};
            status = Http2FrameCodec::DecodePriorityPayload(fh.StreamId, fp, fpLen, &priority);
            if (!NT_SUCCESS(status)) {
                const NTSTATUS rstStatus = SendRstStream(
                    transport,
                    fh.StreamId,
                    fpLen == 5
                        ? static_cast<ULONG>(Http2ErrorCode::ProtocolError)
                        : static_cast<ULONG>(Http2ErrorCode::FrameSizeError));
                UNREFERENCED_PARAMETER(rstStatus);
                return status;
            }

            return STATUS_SUCCESS;
        }

        case Http2FrameType::Headers:
        case Http2FrameType::Continuation:
        {
            const UCHAR* content = fp;
            SIZE_T contentLen = fpLen;

            if (fh.Type == Http2FrameType::Headers) {
                state.PendingHeaderEndStream = (fh.Flags & Http2FrameFlags::EndStream) != 0;
                status = Http2FrameCodec::StripPadding(fh.Flags, fp, fpLen, &content, &contentLen);
                if (!NT_SUCCESS(status)) return status;
                status = Http2FrameCodec::StripPriority(fh.Flags, content, contentLen, &content, &contentLen);
                if (!NT_SUCCESS(status)) return status;
            }

            if (contentLen > state.ResponseHeaderBlockCapacity ||
                state.ResponseHeaderBlockLen > state.ResponseHeaderBlockCapacity - contentLen) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::EnhanceYourCalm));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return STATUS_BUFFER_TOO_SMALL;
            }
            MemCopy(state.ResponseHeaderBlock + state.ResponseHeaderBlockLen, content, contentLen);
            state.ResponseHeaderBlockLen += contentLen;

            if ((fh.Flags & Http2FrameFlags::EndHeaders) != 0) {
                state.ExpectingContinuation = false;
                state.ContinuationStreamId = 0;
                state.ContinuationFrames = 0;
                state.EmptyContinuationFrames = 0;
                status = stream.ReceiveHeaders(state.PendingHeaderEndStream);
                if (!NT_SUCCESS(status)) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return status;
                }

                const bool trailers = state.ResponseHeadersReceived;
                if (trailers && (!state.ResponseDataReceived || !state.PendingHeaderEndStream)) {
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
                http1::HttpHeader* decodedHeaders = trailers ? trailerHeaders_ : decodedHeaderScratch_;
                const SIZE_T decodedHeaderCapacity = trailers ? 16 : decodedHeaderScratchCapacity_;
                char* decodedNameValueBuffer = trailers ?
                    reinterpret_cast<char*>(headerBlock_) :
                    state.NameValueBuffer;
                const SIZE_T decodedNameValueCapacity = trailers ?
                    headerBlockCapacity_ :
                    state.NameValueCapacity;
                SIZE_T decodedHeaderCount = 0;
                SIZE_T nvUsed = 0;
                status = decoder_.Decode(
                    state.ResponseHeaderBlock,
                    state.ResponseHeaderBlockLen,
                    decodedHeaders,
                    decodedHeaderCapacity,
                    &decodedHeaderCount,
                    decodedNameValueBuffer,
                    decodedNameValueCapacity,
                    &nvUsed,
                    localSettings_.MaxHeaderListSize);
                if (!NT_SUCCESS(status)) {
                    WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "http2.hpack.decode_failed status=0x%08X block_bytes=%Iu stream_id=%u",
                        static_cast<ULONG>(status),
                        state.ResponseHeaderBlockLen,
                        stream.StreamId());
                    if (status == STATUS_BUFFER_TOO_SMALL) {
                        const NTSTATUS goAwayStatus = SendGoAway(
                            transport,
                            static_cast<ULONG>(Http2ErrorCode::EnhanceYourCalm));
                        UNREFERENCED_PARAMETER(goAwayStatus);
                    }
                    else if (IsHpackCompressionFailure(status)) {
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
                    if (decodedStatusCode == 101 || state.PendingHeaderEndStream) {
                        const NTSTATUS rstStatus = SendRstStream(
                            transport,
                            fh.StreamId,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(rstStatus);
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    state.ResponseHeaderBlockLen = 0;
                    state.PendingHeaderEndStream = false;
                    break;
                }

                if (!trailers) {
                    status = CopyRegularResponseHeaders(
                        decodedHeaders,
                        decodedHeaderCount,
                        state.ResponseHeaders,
                        state.ResponseHeaderCapacity,
                        state.ResponseHeaderCount);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    *state.StatusCode = decodedStatusCode;
                    state.ResponseContentLengthPresent = decodedContentLengthPresent;
                    state.ResponseContentLength = decodedContentLength;
                    state.ResponseBodyForbidden =
                        state.RequestForbidsResponseBody ||
                        StatusForbidsResponseBody(decodedStatusCode);
                    if (state.ResponseBodyForbidden &&
                        state.ResponseContentLengthPresent &&
                        state.ResponseContentLength != 0) {
                        const NTSTATUS rstStatus = SendRstStream(
                            transport,
                            fh.StreamId,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(rstStatus);
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    state.ResponseHeadersReceived = true;
                    state.TerminalResponseReceived = true;
                }

                state.ResponseHeaderBlockLen = 0;
                if (state.PendingHeaderEndStream) {
                    if (state.ResponseContentLengthPresent &&
                        static_cast<ULONGLONG>(state.BodyLength) != state.ResponseContentLength) {
                        const NTSTATUS rstStatus = SendRstStream(
                            transport,
                            fh.StreamId,
                            static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                        UNREFERENCED_PARAMETER(rstStatus);
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    state.StreamClosed = true;
                }
                state.PendingHeaderEndStream = false;
            }
            else if (fh.Type == Http2FrameType::Headers) {
                state.ExpectingContinuation = true;
                state.ContinuationStreamId = fh.StreamId;
                state.ContinuationFrames = 0;
                state.EmptyContinuationFrames = 0;
            }
            break;
        }

        case Http2FrameType::Data:
        {
            if (!state.ResponseHeadersReceived) {
                const NTSTATUS rstStatus = SendRstStream(
                    transport,
                    fh.StreamId,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(rstStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const UCHAR* content = fp;
            SIZE_T contentLen = fpLen;
            status = Http2FrameCodec::StripPadding(fh.Flags, fp, fpLen, &content, &contentLen);
            if (!NT_SUCCESS(status)) return status;

            const bool dataEndsStream = (fh.Flags & Http2FrameFlags::EndStream) != 0;
            if (state.ResponseBodyForbidden) {
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

            if (AddWouldOverflow(state.BodyLength, contentLen)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            const SIZE_T nextBodyLen = state.BodyLength + contentLen;
            if (state.ResponseContentLengthPresent &&
                static_cast<ULONGLONG>(nextBodyLen) > state.ResponseContentLength) {
                const NTSTATUS rstStatus = SendRstStream(
                    transport,
                    fh.StreamId,
                    static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                UNREFERENCED_PARAMETER(rstStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = state.ResponseBodySink.Append(
                state.ResponseBodySink.Context,
                content,
                contentLen);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            state.BodyLength = nextBodyLen;
            state.ResponseDataReceived = true;

            connectionRecvConsumed_ += static_cast<ULONG>(fpLen);
            status = SendWindowUpdateIfNeeded(
                transport,
                dataEndsStream ? nullptr : &stream,
                static_cast<ULONG>(fpLen));
            if (!NT_SUCCESS(status)) return status;

            if ((fh.Flags & Http2FrameFlags::EndStream) != 0) {
                if (state.ResponseContentLengthPresent &&
                    static_cast<ULONGLONG>(state.BodyLength) != state.ResponseContentLength) {
                    const NTSTATUS rstStatus = SendRstStream(
                        transport,
                        fh.StreamId,
                        static_cast<ULONG>(Http2ErrorCode::ProtocolError));
                    UNREFERENCED_PARAMETER(rstStatus);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                state.StreamClosed = true;
            }
            break;
        }

        case Http2FrameType::RstStream:
        {
            ULONG errorCode = 0;
            status = Http2FrameCodec::DecodeRstStreamPayload(fp, fpLen, &errorCode);
            if (!NT_SUCCESS(status)) return status;
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Warning, "http2.stream.reset stream_id=%u error_code=0x%08X",
                fh.StreamId,
                errorCode);
            stream.Reset();
            state.StreamClosed = true;
            if (errorCode == static_cast<ULONG>(Http2ErrorCode::NoError) &&
                state.TerminalResponseReceived) {
                return STATUS_SUCCESS;
            }
            if (errorCode == static_cast<ULONG>(Http2ErrorCode::RefusedStream)) {
                return STATUS_RETRY;
            }
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
            break;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::ReceiveResponseFrames(
        Http2Transport& transport,
        Http2Stream& stream,
        bool requestForbidsResponseBody,
        http1::HttpHeader* responseHeaders,
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

        Http2ResponseFrameState frameState = {};
        frameState.RequestForbidsResponseBody = requestForbidsResponseBody;
        frameState.ResponseBodyForbidden = requestForbidsResponseBody;
        frameState.ResponseHeaderBlock = responseHeaderBlock_;
        frameState.ResponseHeaderBlockCapacity = headerBlockCapacity_;
        frameState.ResponseHeaders = responseHeaders;
        frameState.ResponseHeaderCapacity = responseHeaderCapacity;
        frameState.ResponseHeaderCount = responseHeaderCount;
        frameState.ResponseBodySink = responseBodySink;
        frameState.ResponseBodyLength = responseBodyLength;
        frameState.StatusCode = statusCode;
        frameState.NameValueBuffer = nameValueBuffer;
        frameState.NameValueCapacity = nameValueCapacity;

        status = ReceiveResponseFramesWithState(transport, stream, frameState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *responseBodyLength = frameState.BodyLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::ReceiveResponseFramesWithState(
        Http2Transport& transport,
        Http2Stream& stream,
        Http2ResponseFrameState& frameState) noexcept
    {
        NTSTATUS status = STATUS_SUCCESS;
        while (!frameState.StreamClosed) {
            Http2FrameHeader fh = {};
            UCHAR* fp = framePayload_;
            SIZE_T fpLen = 0;

            status = ReadFrame(transport, &fh, fp, framePayloadCapacity_, &fpLen);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "http2.frame.read_failed status=0x%08X stream_id=%u headers_complete=%u body_bytes=%Iu",
                    static_cast<ULONG>(status),
                    stream.StreamId(),
                    frameState.ResponseHeadersReceived ? 1u : 0u,
                    frameState.BodyLength);
                return HandleReadFrameFailure(transport, status);
            }

            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Verbose, "http2.frame.received type=%u flags=0x%02X stream_id=%u length=%u target_stream_id=%u",
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

            if ((fh.Type == Http2FrameType::Continuation &&
                    (!frameState.ExpectingContinuation || fh.StreamId != frameState.ContinuationStreamId)) ||
                (frameState.ExpectingContinuation && fh.Type != Http2FrameType::Continuation)) {
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

            status = ProcessResponseFrame(transport, stream, fh, fp, fpLen, frameState);
            if (!NT_SUCCESS(status)) return status;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::SendRequest(
        transport::Transport* transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody& requestBody,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return SendRequest(
            adapter,
            requestHeaders,
            requestHeaderCount,
            requestBody,
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
        transport::Transport* transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        char* responseBody,
        SIZE_T responseBodyCapacity,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2TransportAdapter adapter(transport);
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
        transport::Transport* transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody& requestBody,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return SendRequest(
            adapter,
            requestHeaders,
            requestHeaderCount,
            requestBody,
            responseHeaders,
            responseHeaderCapacity,
            responseHeaderCount,
            responseBodySink,
            responseBodyLength,
            statusCode,
            nameValueBuffer,
            nameValueCapacity);
    }

    NTSTATUS Http2Connection::SendRequest(
        transport::Transport* transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const UCHAR* body,
        SIZE_T bodyLength,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink& responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        Http2TransportAdapter adapter(transport);
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

    NTSTATUS Http2Connection::SendPing(
        Http2Transport& transport,
        const UCHAR* opaqueData) noexcept
    {
        if (opaqueData == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ScopedStateLock lock(*this);
        if (goAwaySent_ || goAwayReceived_) {
            return STATUS_CONNECTION_DISCONNECTED;
        }

        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        UCHAR* pingBuf = sendBuffer_;
        SIZE_T written = 0;
        status = Http2FrameCodec::EncodePing(
            opaqueData,
            false,
            pingBuf,
            Http2FrameHeaderLength + 8,
            &written);
        if (!NT_SUCCESS(status)) return status;

        return SendRaw(transport, pingBuf, written);
    }

    NTSTATUS Http2Connection::SendPing(
        transport::Transport* transport,
        const UCHAR* opaqueData) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return SendPing(adapter, opaqueData);
    }

    NTSTATUS Http2Connection::SendPingAndWaitForAck(
        Http2Transport& transport,
        const UCHAR* opaqueData,
        ULONG ackTimeoutMilliseconds) noexcept
    {
        if (opaqueData == nullptr || ackTimeoutMilliseconds == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        ScopedReceiveLock receiveLock(*this);

        NTSTATUS status = SendPing(transport, opaqueData);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = EnsureBuffers();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (;;) {
            Http2FrameHeader header = {};
            SIZE_T payloadLength = 0;
            status = ReadFrameWithTimeout(
                transport,
                &header,
                framePayload_,
                framePayloadCapacity_,
                &payloadLength,
                ackTimeoutMilliseconds);
            if (!NT_SUCCESS(status)) {
                return status == STATUS_INVALID_NETWORK_RESPONSE ?
                    HandleReadFrameFailure(transport, status) :
                    status;
            }

            if (header.Type == Http2FrameType::Ping &&
                (header.Flags & Http2FrameFlags::Ack) != 0 &&
                payloadLength == 8 &&
                RtlCompareMemory(framePayload_, opaqueData, 8) == 8) {
                return STATUS_SUCCESS;
            }

            status = DispatchFrame(transport, header, framePayload_, payloadLength, nullptr);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
    }

    NTSTATUS Http2Connection::SendPingAndWaitForAck(
        transport::Transport* transport,
        const UCHAR* opaqueData,
        ULONG ackTimeoutMilliseconds) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return SendPingAndWaitForAck(adapter, opaqueData, ackTimeoutMilliseconds);
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

    NTSTATUS Http2Connection::Shutdown(transport::Transport* transport) noexcept
    {
        Http2TransportAdapter adapter(transport);
        return Shutdown(adapter);
    }

    bool Http2Connection::IsReusable() const noexcept
    {
        return !goAwaySent_ &&
            !goAwayReceived_ &&
            nextStreamId_ <= 0x7ffffffdUL;
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

    NTSTATUS Http2Connection::ReadExactWithTimeout(
        Http2Transport& transport,
        UCHAR* buffer,
        SIZE_T length,
        ULONG timeoutMilliseconds) noexcept
    {
        SIZE_T totalRead = 0;
        while (totalRead < length) {
            SIZE_T received = 0;
            NTSTATUS status = transport.ReceiveWithTimeout(
                buffer + totalRead,
                length - totalRead,
                &received,
                timeoutMilliseconds);
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

        status = RecordReceivedFrame(*header);
        if (!NT_SUCCESS(status)) return status;

        // Read payload
        if (header->Length > 0) {
            status = ReadExact(transport, payload, header->Length);
            if (!NT_SUCCESS(status)) return status;
        }

        *payloadLength = header->Length;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::ReadFrameWithTimeout(
        Http2Transport& transport,
        Http2FrameHeader* header,
        UCHAR* payload,
        SIZE_T payloadCapacity,
        SIZE_T* payloadLength,
        ULONG timeoutMilliseconds) noexcept
    {
        readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::NoError);

        UCHAR* headerBuf = sendBuffer_;
        NTSTATUS status = ReadExactWithTimeout(
            transport,
            headerBuf,
            Http2FrameHeaderLength,
            timeoutMilliseconds);
        if (!NT_SUCCESS(status)) return status;

        status = Http2FrameCodec::DecodeFrameHeader(headerBuf, Http2FrameHeaderLength, header);
        if (!NT_SUCCESS(status)) return status;

        if (header->Length > localSettings_.MaxFrameSize) {
            readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::FrameSizeError);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (header->Length > payloadCapacity) return STATUS_BUFFER_TOO_SMALL;

        status = RecordReceivedFrame(*header);
        if (!NT_SUCCESS(status)) return status;

        if (header->Length > 0) {
            status = ReadExactWithTimeout(
                transport,
                payload,
                header->Length,
                timeoutMilliseconds);
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

    NTSTATUS Http2Connection::RecordReceivedFrame(
        const Http2FrameHeader& header) noexcept
    {
        const ULONGLONG frameBytes =
            static_cast<ULONGLONG>(Http2FrameHeaderLength) +
            static_cast<ULONGLONG>(header.Length);

        if (connectionFramesRead_ >= WKNET_HARD_MAX_CONNECTION_FRAMES ||
            (WKNET_HARD_MAX_CONNECTION_BYTES != 0 &&
                (frameBytes > WKNET_HARD_MAX_CONNECTION_BYTES ||
                    connectionBytesRead_ > WKNET_HARD_MAX_CONNECTION_BYTES - frameBytes))) {
            readFrameErrorCode_ = static_cast<ULONG>(Http2ErrorCode::EnhanceYourCalm);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ++connectionFramesRead_;
        connectionBytesRead_ += frameBytes;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::RecordConnectionControlSignal() noexcept
    {
        if (connectionControlSignals_ >= WKNET_HARD_MAX_CONNECTION_CONTROL_SIGNALS) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ++connectionControlSignals_;
        return STATUS_SUCCESS;
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

        if (IsConnectionControlSignal(header.Type)) {
            const NTSTATUS status = RecordConnectionControlSignal();
            if (!NT_SUCCESS(status)) {
                const NTSTATUS goAwayStatus = SendGoAway(
                    transport,
                    static_cast<ULONG>(Http2ErrorCode::EnhanceYourCalm));
                UNREFERENCED_PARAMETER(goAwayStatus);
                return status;
            }
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
            if (peerSettings_.InitialWindowSize != previousSettings.InitialWindowSize) {
                const long long delta =
                    static_cast<long long>(peerSettings_.InitialWindowSize) -
                    static_cast<long long>(previousSettings.InitialWindowSize);
                status = AdjustActiveStreamRemoteWindows(delta);
                if (NT_SUCCESS(status) &&
                    activeStreams_ == nullptr &&
                    activeStream != nullptr) {
                    status = activeStream->AdjustRemoteWindow(delta);
                }
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
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Warning, "http2.connection.goaway error_code=0x%08X last_stream_id=%u",
                errorCode,
                lastStreamId);
            goAwayReceived_ = true;
            goAwayLastStreamId_ = lastStreamId;
            if (errorCode != static_cast<ULONG>(Http2ErrorCode::NoError)) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
            if (activeStream != nullptr && activeStream->StreamId() > lastStreamId) {
                return STATUS_RETRY;
            }
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
        const http1::HttpHeader* headers,
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
            const http1::HttpHeader& header = headers[i];
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
        const http1::HttpHeader* headers,
        SIZE_T headerCount) noexcept
    {
        for (SIZE_T i = 0; i < headerCount; ++i) {
            if (TextEquals(headers[i].Name.Data, headers[i].Name.Length, ":status", 7)) {
                return ParseStatusCode(headers[i].Value.Data, headers[i].Value.Length);
            }
        }
        return 0;
    }
    NTSTATUS Http2ConnectionCreate(Http2Connection** connection) noexcept
    {
        if (connection != nullptr) {
            *connection = nullptr;
        }
        if (connection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        auto* created = AllocateNonPagedObject<Http2Connection>();
        if (created == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        *connection = created;
        return STATUS_SUCCESS;
    }

    void Http2ConnectionClose(Http2Connection* connection) noexcept
    {
        FreeNonPagedObject(connection);
    }

    NTSTATUS Http2ConnectionInitialize(
        Http2Connection* connection, transport::Transport* transport, SIZE_T maxHeaderBlockBytes) noexcept
    {
        return connection != nullptr
            ? connection->Initialize(transport, maxHeaderBlockBytes)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionInitializeAfterUpgrade(
        Http2Connection* connection, transport::Transport* transport, SIZE_T maxHeaderBlockBytes) noexcept
    {
        return connection != nullptr
            ? connection->InitializeAfterUpgrade(transport, maxHeaderBlockBytes)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionBeginRequest(
        Http2Connection* connection,
        transport::Transport* transport,
        const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        const Http2RequestBody* requestBody,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink* responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity,
        ULONG* streamId) noexcept
    {
        return connection != nullptr && requestBody != nullptr && responseBodySink != nullptr
            ? connection->BeginRequest(
                transport,
                requestHeaders,
                requestHeaderCount,
                *requestBody,
                responseHeaders,
                responseHeaderCapacity,
                responseHeaderCount,
                *responseBodySink,
                responseBodyLength,
                statusCode,
                nameValueBuffer,
                nameValueCapacity,
                streamId)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionReceiveResponse(
        Http2Connection* connection, transport::Transport* transport, ULONG streamId) noexcept
    {
        return connection != nullptr
            ? connection->ReceiveResponse(transport, streamId)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionReceiveResponseDetailed(
        Http2Connection* connection,
        transport::Transport* transport,
        ULONG streamId,
        http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCapacity,
        SIZE_T* responseHeaderCount,
        const Http2ResponseBodySink* responseBodySink,
        SIZE_T* responseBodyLength,
        USHORT* statusCode,
        char* nameValueBuffer,
        SIZE_T nameValueCapacity) noexcept
    {
        return connection != nullptr && responseBodySink != nullptr
            ? connection->ReceiveResponse(
                transport,
                streamId,
                responseHeaders,
                responseHeaderCapacity,
                responseHeaderCount,
                *responseBodySink,
                responseBodyLength,
                statusCode,
                nameValueBuffer,
                nameValueCapacity)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionReceiveResponseHeaders(
        Http2Connection* connection, transport::Transport* transport, ULONG streamId) noexcept
    {
        return connection != nullptr
            ? connection->ReceiveResponseHeaders(transport, streamId)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionSendStreamData(
        Http2Connection* connection,
        transport::Transport* transport,
        ULONG streamId,
        const UCHAR* data,
        SIZE_T dataLength,
        bool endStream) noexcept
    {
        return connection != nullptr
            ? connection->SendStreamData(transport, streamId, data, dataLength, endStream)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionReceiveStreamData(
        Http2Connection* connection,
        transport::Transport* transport,
        ULONG streamId,
        UCHAR* buffer,
        SIZE_T bufferCapacity,
        SIZE_T* bytesReceived,
        bool* endStream) noexcept
    {
        return connection != nullptr
            ? connection->ReceiveStreamData(
                transport, streamId, buffer, bufferCapacity, bytesReceived, endStream)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionSendPingAndWaitForAck(
        Http2Connection* connection,
        transport::Transport* transport,
        const UCHAR* opaqueData,
        ULONG ackTimeoutMilliseconds) noexcept
    {
        return connection != nullptr
            ? connection->SendPingAndWaitForAck(transport, opaqueData, ackTimeoutMilliseconds)
            : STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Http2ConnectionShutdown(
        Http2Connection* connection, transport::Transport* transport) noexcept
    {
        return connection != nullptr ? connection->Shutdown(transport) : STATUS_SUCCESS;
    }

    bool Http2ConnectionIsReusable(const Http2Connection* connection) noexcept
    {
        return connection != nullptr && connection->IsReusable();
    }

    ULONG Http2ConnectionMaxConcurrentStreams(Http2Connection* connection) noexcept
    {
        return connection != nullptr ? connection->MaxConcurrentStreams() : 0;
    }

    void Http2ConnectionReleaseStream(Http2Connection* connection, ULONG streamId) noexcept
    {
        if (connection != nullptr) {
            connection->ReleaseStream(streamId);
        }
    }
}
}
