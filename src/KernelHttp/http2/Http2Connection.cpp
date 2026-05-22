#include "http2/Http2Connection.h"

namespace KernelHttp
{
namespace http2
{
    namespace
    {
        constexpr SIZE_T HeaderBlockCapacity = 16384;
        constexpr SIZE_T SendBufferCapacity = 32768;

        // Window update threshold: send WINDOW_UPDATE when half consumed
        constexpr ULONG WindowUpdateThreshold = Http2InitialWindowSize / 2;

        void MemCopy(void* dst, const void* src, SIZE_T len) noexcept
        {
            auto* d = static_cast<UCHAR*>(dst);
            auto* s = static_cast<const UCHAR*>(src);
            for (SIZE_T i = 0; i < len; ++i) d[i] = s[i];
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
    }

    Http2Connection::~Http2Connection() noexcept
    {
        delete[] sendBuffer_;
        delete[] framePayload_;
        delete[] headerBlock_;
        delete[] responseHeaderBlock_;
        sendBuffer_ = nullptr;
        framePayload_ = nullptr;
        headerBlock_ = nullptr;
        responseHeaderBlock_ = nullptr;
    }

    NTSTATUS Http2Connection::EnsureBuffers() noexcept
    {
        if (sendBuffer_ == nullptr) {
            sendBuffer_ = new UCHAR[SendBufferCapacity];
            if (sendBuffer_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (framePayload_ == nullptr) {
            framePayload_ = new UCHAR[Http2DefaultMaxFrameSize];
            if (framePayload_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (headerBlock_ == nullptr) {
            headerBlock_ = new UCHAR[HeaderBlockCapacity];
            if (headerBlock_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (responseHeaderBlock_ == nullptr) {
            responseHeaderBlock_ = new UCHAR[HeaderBlockCapacity];
            if (responseHeaderBlock_ == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::Initialize(
        net::WskSocket& socket,
        tls::TlsConnection& tls) noexcept
    {
        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

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
        status = SendRaw(socket, tls, sendBuf, sendOffset);
        if (!NT_SUCCESS(status)) return status;

        // Read peer's SETTINGS (must be the first frame from server)
        UCHAR* framePayload = framePayload_;
        Http2FrameHeader frameHeader = {};
        SIZE_T payloadLen = 0;

        status = ReadFrame(socket, tls, &frameHeader, framePayload, Http2DefaultMaxFrameSize, &payloadLen);
        if (!NT_SUCCESS(status)) return status;

        if (frameHeader.Type != Http2FrameType::Settings ||
            (frameHeader.Flags & Http2FrameFlags::Ack) != 0 ||
            frameHeader.StreamId != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = Http2FrameCodec::DecodeSettingsPayload(framePayload, payloadLen, &peerSettings_);
        if (!NT_SUCCESS(status)) return status;

        // Update send window based on peer's initial window size
        connectionSendWindow_ = static_cast<LONG>(peerSettings_.InitialWindowSize);

        // Send SETTINGS ACK
        UCHAR ackBuf[Http2FrameHeaderLength] = {};
        SIZE_T ackWritten = 0;
        status = Http2FrameCodec::EncodeSettingsAck(ackBuf, sizeof(ackBuf), &ackWritten);
        if (!NT_SUCCESS(status)) return status;

        status = SendRaw(socket, tls, ackBuf, ackWritten);
        if (!NT_SUCCESS(status)) return status;

        // Read until we get SETTINGS ACK from peer (may get WINDOW_UPDATE etc first)
        for (int attempts = 0; attempts < 10; ++attempts) {
            status = ReadFrame(socket, tls, &frameHeader, framePayload, Http2DefaultMaxFrameSize, &payloadLen);
            if (!NT_SUCCESS(status)) return status;

            if (frameHeader.Type == Http2FrameType::Settings &&
                (frameHeader.Flags & Http2FrameFlags::Ack) != 0) {
                settingsAckReceived_ = true;
                break;
            }

            // Handle other connection-level frames
            status = HandleConnectionFrame(socket, tls, frameHeader, framePayload, payloadLen);
            if (!NT_SUCCESS(status)) return status;
        }

        if (!settingsAckReceived_) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::SendRequest(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
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
        NTSTATUS status = EnsureBuffers();
        if (!NT_SUCCESS(status)) return status;

        if (requestHeaders == nullptr || responseHeaders == nullptr ||
            responseHeaderCount == nullptr || responseBody == nullptr ||
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
        ULONG maxPayload = peerSettings_.MaxFrameSize;
        bool firstFrame = true;

        while (blockOffset < headerBlockLen) {
            SIZE_T chunkLen = headerBlockLen - blockOffset;
            if (chunkLen > maxPayload) chunkLen = maxPayload;
            bool lastChunk = (blockOffset + chunkLen >= headerBlockLen);

            if (Http2FrameHeaderLength + chunkLen > SendBufferCapacity) return STATUS_BUFFER_TOO_SMALL;
            if (sendOffset + Http2FrameHeaderLength + chunkLen > SendBufferCapacity) {
                status = SendRaw(socket, tls, sendBuf, sendOffset);
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

        // Send DATA frame(s) if body present
        if (!endStream && body != nullptr && bodyLength > 0) {
            SIZE_T bodyOffset = 0;
            while (bodyOffset < bodyLength) {
                SIZE_T chunkLen = bodyLength - bodyOffset;
                if (chunkLen > maxPayload) chunkLen = maxPayload;

                // Check send windows
                LONG available = connectionSendWindow_ < stream.RemoteWindow()
                    ? connectionSendWindow_
                    : stream.RemoteWindow();
                if (available <= 0) {
                    // Need to read WINDOW_UPDATE from peer
                    Http2FrameHeader fh = {};
                    UCHAR* fp = framePayload_;
                    SIZE_T fpLen = 0;
                    status = ReadFrame(socket, tls, &fh, fp, Http2DefaultMaxFrameSize, &fpLen);
                    if (!NT_SUCCESS(status)) return status;
                    if (fh.Type == Http2FrameType::WindowUpdate && fh.StreamId == streamId) {
                        ULONG increment = 0;
                        status = Http2FrameCodec::DecodeWindowUpdatePayload(fp, fpLen, &increment);
                        if (!NT_SUCCESS(status)) return status;
                        status = stream.IncreaseRemoteWindow(increment);
                        if (!NT_SUCCESS(status)) return status;
                    }
                    else {
                        status = HandleConnectionFrame(socket, tls, fh, fp, fpLen);
                        if (!NT_SUCCESS(status)) return status;
                    }
                    continue;
                }

                if (chunkLen > static_cast<SIZE_T>(available)) {
                    chunkLen = static_cast<SIZE_T>(available);
                }

                bool lastData = (bodyOffset + chunkLen >= bodyLength);

                if (Http2FrameHeaderLength + chunkLen > SendBufferCapacity) return STATUS_BUFFER_TOO_SMALL;
                if (sendOffset + Http2FrameHeaderLength + chunkLen > SendBufferCapacity) {
                    status = SendRaw(socket, tls, sendBuf, sendOffset);
                    if (!NT_SUCCESS(status)) return status;
                    sendOffset = 0;
                }

                SIZE_T written = 0;
                status = Http2FrameCodec::EncodeData(
                    streamId, body + bodyOffset, chunkLen, lastData,
                    sendBuf + sendOffset, SendBufferCapacity - sendOffset, &written);
                if (!NT_SUCCESS(status)) return status;
                status = stream.SendData(chunkLen, lastData);
                if (!NT_SUCCESS(status)) return status;
                sendOffset += written;
                bodyOffset += chunkLen;
                connectionSendWindow_ -= static_cast<LONG>(chunkLen);
            }
        }

        // Flush all buffered frames
        status = SendRaw(socket, tls, sendBuf, sendOffset);
        if (!NT_SUCCESS(status)) return status;

        // Read response frames
        bool streamClosed = false;
        UCHAR* responseHeaderBlock = responseHeaderBlock_;
        SIZE_T responseHeaderBlockLen = 0;
        SIZE_T bodyLen = 0;

        while (!streamClosed) {
            Http2FrameHeader fh = {};
            UCHAR* fp = framePayload_;
            SIZE_T fpLen = 0;

            status = ReadFrame(socket, tls, &fh, fp, Http2DefaultMaxFrameSize, &fpLen);
            if (!NT_SUCCESS(status)) return status;

            // Connection-level frame
            if (fh.StreamId == 0) {
                status = HandleConnectionFrame(socket, tls, fh, fp, fpLen);
                if (!NT_SUCCESS(status)) return status;
                if (goAwayReceived_) return STATUS_CONNECTION_DISCONNECTED;
                continue;
            }

            // Stream-level frame
            if (fh.StreamId != streamId) {
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
                    status = stream.ReceiveHeaders((fh.Flags & Http2FrameFlags::EndStream) != 0);
                    if (!NT_SUCCESS(status)) return status;
                    // Decode HPACK
                    SIZE_T nvUsed = 0;
                    status = decoder_.Decode(
                        responseHeaderBlock, responseHeaderBlockLen,
                        responseHeaders, responseHeaderCapacity,
                        responseHeaderCount,
                        nameValueBuffer, nameValueCapacity, &nvUsed);
                    if (!NT_SUCCESS(status)) return status;

                    *statusCode = ExtractStatusCode(responseHeaders, *responseHeaderCount);
                }

                if ((fh.Flags & Http2FrameFlags::EndStream) != 0) {
                    streamClosed = true;
                }
                break;
            }

            case Http2FrameType::Data:
            {
                const UCHAR* content = fp;
                SIZE_T contentLen = fpLen;

                // Strip padding
                status = Http2FrameCodec::StripPadding(fh.Flags, fp, fpLen, &content, &contentLen);
                if (!NT_SUCCESS(status)) return status;

                status = stream.ReceiveData(contentLen, (fh.Flags & Http2FrameFlags::EndStream) != 0);
                if (!NT_SUCCESS(status)) return status;

                if (bodyLen + contentLen > responseBodyCapacity) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                MemCopy(responseBody + bodyLen, content, contentLen);
                bodyLen += contentLen;

                // Update flow control
                connectionRecvConsumed_ += static_cast<ULONG>(fpLen);
                status = SendWindowUpdateIfNeeded(socket, tls, streamId, static_cast<ULONG>(fpLen));
                if (!NT_SUCCESS(status)) return status;

                if ((fh.Flags & Http2FrameFlags::EndStream) != 0) {
                    streamClosed = true;
                }
                break;
            }

            case Http2FrameType::RstStream:
            {
                stream.Reset();
                streamClosed = true;
                break;
            }

            case Http2FrameType::WindowUpdate:
            {
                ULONG increment = 0;
                status = Http2FrameCodec::DecodeWindowUpdatePayload(fp, fpLen, &increment);
                if (!NT_SUCCESS(status)) return status;
                status = stream.IncreaseRemoteWindow(increment);
                if (!NT_SUCCESS(status)) return status;
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

    NTSTATUS Http2Connection::Shutdown(
        net::WskSocket& socket,
        tls::TlsConnection& tls) noexcept
    {
        if (goAwaySent_) return STATUS_SUCCESS;

        UCHAR buf[Http2FrameHeaderLength + 8] = {};
        SIZE_T written = 0;
        NTSTATUS status = Http2FrameCodec::EncodeGoAway(
            0, static_cast<ULONG>(Http2ErrorCode::NoError),
            buf, sizeof(buf), &written);
        if (!NT_SUCCESS(status)) return status;

        goAwaySent_ = true;
        return SendRaw(socket, tls, buf, written);
    }

    NTSTATUS Http2Connection::SendRaw(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        const UCHAR* data,
        SIZE_T length) noexcept
    {
        SIZE_T sent = 0;
        NTSTATUS status = tls.Send(socket, data, length, &sent);
        if (!NT_SUCCESS(status)) return status;
        if (sent != length) return STATUS_CONNECTION_DISCONNECTED;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::ReadExact(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        UCHAR* buffer,
        SIZE_T length) noexcept
    {
        SIZE_T totalRead = 0;
        while (totalRead < length) {
            SIZE_T received = 0;
            NTSTATUS status = tls.Receive(socket,
                buffer + totalRead, length - totalRead, &received);
            if (!NT_SUCCESS(status)) return status;
            if (received == 0) return STATUS_CONNECTION_DISCONNECTED;
            totalRead += received;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::ReadFrame(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        Http2FrameHeader* header,
        UCHAR* payload,
        SIZE_T payloadCapacity,
        SIZE_T* payloadLength) noexcept
    {
        // Read 9-byte frame header
        UCHAR headerBuf[Http2FrameHeaderLength] = {};
        NTSTATUS status = ReadExact(socket, tls, headerBuf, Http2FrameHeaderLength);
        if (!NT_SUCCESS(status)) return status;

        status = Http2FrameCodec::DecodeFrameHeader(headerBuf, Http2FrameHeaderLength, header);
        if (!NT_SUCCESS(status)) return status;

        if (header->Length > payloadCapacity) return STATUS_BUFFER_TOO_SMALL;
        if (header->Length > peerSettings_.MaxFrameSize && header->Length > Http2DefaultMaxFrameSize) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        // Read payload
        if (header->Length > 0) {
            status = ReadExact(socket, tls, payload, header->Length);
            if (!NT_SUCCESS(status)) return status;
        }

        *payloadLength = header->Length;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Connection::HandleConnectionFrame(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        const Http2FrameHeader& header,
        const UCHAR* payload,
        SIZE_T payloadLen) noexcept
    {
        switch (header.Type) {
        case Http2FrameType::Settings:
        {
            if ((header.Flags & Http2FrameFlags::Ack) != 0) {
                settingsAckReceived_ = true;
                return STATUS_SUCCESS;
            }
            // Peer sent new SETTINGS
            NTSTATUS status = Http2FrameCodec::DecodeSettingsPayload(payload, payloadLen, &peerSettings_);
            if (!NT_SUCCESS(status)) return status;

            // ACK
            UCHAR ackBuf[Http2FrameHeaderLength] = {};
            SIZE_T ackWritten = 0;
            status = Http2FrameCodec::EncodeSettingsAck(ackBuf, sizeof(ackBuf), &ackWritten);
            if (!NT_SUCCESS(status)) return status;
            return SendRaw(socket, tls, ackBuf, ackWritten);
        }

        case Http2FrameType::Ping:
        {
            if ((header.Flags & Http2FrameFlags::Ack) != 0) {
                return STATUS_SUCCESS; // PING ACK, ignore
            }
            if (payloadLen != 8) return STATUS_INVALID_NETWORK_RESPONSE;
            // Send PING ACK
            UCHAR pingBuf[Http2FrameHeaderLength + 8] = {};
            SIZE_T written = 0;
            NTSTATUS status = Http2FrameCodec::EncodePing(payload, true, pingBuf, sizeof(pingBuf), &written);
            if (!NT_SUCCESS(status)) return status;
            return SendRaw(socket, tls, pingBuf, written);
        }

        case Http2FrameType::GoAway:
        {
            ULONG lastStreamId = 0;
            ULONG errorCode = 0;
            NTSTATUS status = Http2FrameCodec::DecodeGoAwayPayload(payload, payloadLen, &lastStreamId, &errorCode);
            if (!NT_SUCCESS(status)) return status;
            goAwayReceived_ = true;
            goAwayLastStreamId_ = lastStreamId;
            return STATUS_SUCCESS;
        }

        case Http2FrameType::WindowUpdate:
        {
            ULONG increment = 0;
            NTSTATUS status = Http2FrameCodec::DecodeWindowUpdatePayload(payload, payloadLen, &increment);
            if (!NT_SUCCESS(status)) return status;
            connectionSendWindow_ += static_cast<LONG>(increment);
            if (connectionSendWindow_ > static_cast<LONG>(Http2MaxWindowSize)) {
                return STATUS_INVALID_NETWORK_RESPONSE; // Flow control error
            }
            return STATUS_SUCCESS;
        }

        case Http2FrameType::PushPromise:
            // We set ENABLE_PUSH=0, receiving PUSH_PROMISE is a protocol error
            return STATUS_INVALID_NETWORK_RESPONSE;

        default:
            // Unknown frame types on stream 0 must be ignored
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS Http2Connection::SendWindowUpdateIfNeeded(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        ULONG streamId,
        ULONG consumed) noexcept
    {
        // Connection-level window update
        if (connectionRecvConsumed_ >= WindowUpdateThreshold) {
            UCHAR buf[Http2FrameHeaderLength + 4] = {};
            SIZE_T written = 0;
            NTSTATUS status = Http2FrameCodec::EncodeWindowUpdate(
                0, connectionRecvConsumed_, buf, sizeof(buf), &written);
            if (!NT_SUCCESS(status)) return status;
            status = SendRaw(socket, tls, buf, written);
            if (!NT_SUCCESS(status)) return status;
            connectionRecvWindow_ += static_cast<LONG>(connectionRecvConsumed_);
            connectionRecvConsumed_ = 0;
        }

        // Stream-level window update
        if (consumed > 0) {
            UCHAR buf[Http2FrameHeaderLength + 4] = {};
            SIZE_T written = 0;
            NTSTATUS status = Http2FrameCodec::EncodeWindowUpdate(
                streamId, consumed, buf, sizeof(buf), &written);
            if (!NT_SUCCESS(status)) return status;
            return SendRaw(socket, tls, buf, written);
        }

        return STATUS_SUCCESS;
    }

    ULONG Http2Connection::AllocateStreamId() noexcept
    {
        ULONG id = nextStreamId_;
        nextStreamId_ += 2; // Client uses odd stream IDs
        return id;
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
