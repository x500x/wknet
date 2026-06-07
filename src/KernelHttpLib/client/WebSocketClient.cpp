#include <KernelHttp/client/WebSocketClient.h>
#include <KernelHttp/core/WorkspaceScratchAllocator.h>
#include <KernelHttp/core/WskTransport.h>
#include <KernelHttp/http/HttpRequest.h>

namespace KernelHttp
{
namespace client
{
    namespace
    {
        _Must_inspect_result_
        bool IsValidText(_In_reads_bytes_opt_(length) const char* text, SIZE_T length) noexcept
        {
            return text != nullptr && length > 0;
        }

        _Must_inspect_result_
        bool IsOptionalTextValid(_In_reads_bytes_opt_(length) const char* text, SIZE_T length) noexcept
        {
            return (text == nullptr && length == 0) || (text != nullptr && length != 0);
        }

        _Must_inspect_result_
        bool TextEqualsLiteral(
            _In_reads_bytes_opt_(leftLength) const char* left,
            SIZE_T leftLength,
            _In_z_ const char* right) noexcept
        {
            const http::HttpText rightText = http::MakeText(right);
            if (leftLength != rightText.Length) {
                return false;
            }
            if (leftLength == 0) {
                return true;
            }
            if (left == nullptr || rightText.Data == nullptr) {
                return false;
            }

            return RtlCompareMemory(left, rightText.Data, leftLength) == leftLength;
        }

        constexpr const char WebSocketHttp11Alpn[] = "http/1.1";
        constexpr SIZE_T WebSocketHttp11AlpnLength = sizeof(WebSocketHttp11Alpn) - 1;

        _Must_inspect_result_
        bool IsValidUtf8(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            if (data == nullptr && length != 0) {
                return false;
            }

            SIZE_T index = 0;
            while (index < length) {
                const UCHAR first = data[index++];
                if (first <= 0x7f) {
                    continue;
                }

                ULONG codePoint = 0;
                SIZE_T continuation = 0;
                if (first >= 0xc2 && first <= 0xdf) {
                    codePoint = first & 0x1f;
                    continuation = 1;
                }
                else if (first >= 0xe0 && first <= 0xef) {
                    codePoint = first & 0x0f;
                    continuation = 2;
                }
                else if (first >= 0xf0 && first <= 0xf4) {
                    codePoint = first & 0x07;
                    continuation = 3;
                }
                else {
                    return false;
                }

                if (continuation > length - index) {
                    return false;
                }

                for (SIZE_T next = 0; next < continuation; ++next) {
                    const UCHAR ch = data[index++];
                    if ((ch & 0xc0) != 0x80) {
                        return false;
                    }
                    codePoint = (codePoint << 6) | (ch & 0x3f);
                }

                if ((continuation == 2 && codePoint < 0x800) ||
                    (continuation == 3 && codePoint < 0x10000) ||
                    codePoint > 0x10ffff ||
                    (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool IsValidCloseStatus(USHORT statusCode) noexcept
        {
            if (statusCode >= 3000 && statusCode <= 4999) {
                return true;
            }

            if (statusCode < 1000 || statusCode > 1014) {
                return false;
            }

            return statusCode != 1004 &&
                statusCode != 1005 &&
                statusCode != 1006;
        }

        _Must_inspect_result_
        NTSTATUS BuildHandshakeRequest(
            _In_ const WebSocketConnectOptions& options,
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept
        {
            if (!IsValidText(options.Host, options.HostLength) ||
                !IsValidText(options.Path, options.PathLength) ||
                !IsValidText(clientKey, clientKeyLength) ||
                !IsOptionalTextValid(options.Subprotocol, options.SubprotocolLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            const SIZE_T headerCount =
                options.Subprotocol != nullptr && options.SubprotocolLength != 0 ? 5 : 4;
            HeapArray<http::HttpHeader> headers(headerCount);
            if (!headers.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T nextHeader = 0;
            headers[nextHeader++] = { http::MakeText("Upgrade"), http::MakeText("websocket") };
            headers[nextHeader++] = { http::MakeText("Connection"), http::MakeText("Upgrade") };
            headers[nextHeader++] = { http::MakeText("Sec-WebSocket-Key"), { clientKey, clientKeyLength } };
            headers[nextHeader++] = { http::MakeText("Sec-WebSocket-Version"), http::MakeText("13") };
            if (options.Subprotocol != nullptr && options.SubprotocolLength != 0) {
                headers[nextHeader++] = {
                    http::MakeText("Sec-WebSocket-Protocol"),
                    { options.Subprotocol, options.SubprotocolLength }
                };
            }

            http::HttpRequestBuildOptions request = {};
            request.Method = http::HttpMethod::Get;
            request.Path = { options.Path, options.PathLength };
            request.Host = { options.Host, options.HostLength };
            request.UserAgent = http::MakeText("KernelHttp/0.1");
            request.ExtraHeaders = headers.Get();
            request.ExtraHeaderCount = headerCount;

            return http::HttpRequestBuilder::Build(
                request,
                destination,
                destinationCapacity,
                bytesWritten);
        }

        _Must_inspect_result_
        NTSTATUS TryDecodeCompleteFrame(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_ websocket::WebSocketFrameHeader* header,
            _Out_ bool* complete) noexcept
        {
            if (complete != nullptr) {
                *complete = false;
            }

            if (header == nullptr || complete == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = websocket::WebSocketCodec::DecodeFrameHeader(data, dataLength, header);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                return STATUS_SUCCESS;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (header->PayloadLength > static_cast<ULONGLONG>(static_cast<SIZE_T>(-1)) ||
                header->HeaderLength > dataLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T payloadLength = static_cast<SIZE_T>(header->PayloadLength);
            *complete = payloadLength <= (dataLength - header->HeaderLength);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS GenerateAndEncodeControlFrame(
            websocket::WebSocketOpcode opcode,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _Out_writes_bytes_(websocket::WebSocketMaskingKeyLength) UCHAR* maskingKey,
            _In_ const WebSocketIoBuffers& buffers,
            _Out_ SIZE_T* frameLength) noexcept
        {
            if (frameLength != nullptr) {
                *frameLength = 0;
            }

            if (maskingKey == nullptr || buffers.FrameBuffer == nullptr || frameLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = crypto::CngProvider::GenerateRandom(
                maskingKey,
                websocket::WebSocketMaskingKeyLength);
            if (NT_SUCCESS(status)) {
                status = websocket::WebSocketCodec::EncodeClientFrame(
                    opcode,
                    true,
                    payload,
                    payloadLength,
                    maskingKey,
                    buffers.FrameBuffer,
                    buffers.FrameBufferLength,
                    frameLength);
            }

            RtlSecureZeroMemory(maskingKey, websocket::WebSocketMaskingKeyLength);
            return status;
        }

        _Must_inspect_result_
        bool PayloadEquals(
            _In_reads_bytes_opt_(expectedLength) const char* expected,
            SIZE_T expectedLength,
            _In_reads_bytes_opt_(actualLength) const UCHAR* actual,
            SIZE_T actualLength) noexcept
        {
            if (expectedLength != actualLength) {
                return false;
            }
            if (expectedLength == 0) {
                return true;
            }
            if (expected == nullptr || actual == nullptr) {
                return false;
            }

            return RtlCompareMemory(actual, expected, expectedLength) == expectedLength;
        }

        _Must_inspect_result_
        bool IsConnectionTerminalStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_CONNECTION_DISCONNECTED ||
                status == STATUS_CONNECTION_RESET ||
                status == STATUS_CONNECTION_ABORTED;
        }
    }

    WebSocketClient::~WebSocketClient() noexcept
    {
        WebSocketIoBuffers empty = {};
        const NTSTATUS status = Close(empty);
        UNREFERENCED_PARAMETER(status);
        delete[] maskingKey_;
        maskingKey_ = nullptr;
        if (bufferedFrame_ != nullptr && bufferedFrameCapacity_ != 0) {
            RtlSecureZeroMemory(bufferedFrame_, bufferedFrameCapacity_);
        }
        delete[] bufferedFrame_;
        bufferedFrame_ = nullptr;
        bufferedFrameCapacity_ = 0;
        bufferedFrameLength_ = 0;
    }

    NTSTATUS WebSocketClient::Connect(
        net::WskClient& wskClient,
        const WebSocketConnectOptions& options,
        const WebSocketIoBuffers& buffers,
        USHORT* statusCode) noexcept
    {
        if (statusCode != nullptr) {
            *statusCode = 0;
        }

        if (connected_) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (options.ServerName == nullptr ||
            options.ServerName[0] == L'\0' ||
            options.ServiceName == nullptr ||
            options.ServiceName[0] == L'\0' ||
            !IsValidText(options.Host, options.HostLength) ||
            !IsValidText(options.Path, options.PathLength) ||
            !IsOptionalTextValid(options.Subprotocol, options.SubprotocolLength) ||
            buffers.RequestBuffer == nullptr ||
            buffers.RequestBufferLength == 0 ||
            buffers.ResponseBuffer == nullptr ||
            buffers.ResponseBufferLength == 0 ||
            buffers.Headers == nullptr ||
            buffers.HeaderCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options.UseTls &&
            (options.TlsServerName == nullptr ||
                options.TlsServerNameLength == 0 ||
                options.HandshakeReceiveTimeoutMilliseconds == 0 ||
                (options.VerifyCertificate && options.CertificateStore == nullptr) ||
                static_cast<UCHAR>(options.MinimumTlsProtocol) > static_cast<UCHAR>(options.MaximumTlsProtocol))) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> clientKey(websocket::WebSocketClientKeyBase64Length);
        if (!clientKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T clientKeyLength = 0;
        NTSTATUS status = websocket::WebSocketCodec::GenerateClientKey(
            clientKey.Get(),
            clientKey.Count(),
            &clientKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T requestLength = 0;
        status = BuildHandshakeRequest(
            options,
            clientKey.Get(),
            clientKeyLength,
            buffers.RequestBuffer,
            buffers.RequestBufferLength,
            &requestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<SOCKADDR_STORAGE> remoteAddresses(net::WskMaxResolvedAddresses);
        if (!remoteAddresses.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T remoteAddressCount = 0;
        status = wskClient.ResolveAll(
            options.ServerName,
            options.ServiceName,
            remoteAddresses.Get(),
            net::WskMaxResolvedAddresses,
            &remoteAddressCount,
            options.AddressFamily);
        if (!NT_SUCCESS(status)) {
            kprintf("WebSocketClient resolve failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        NTSTATUS lastStatus = STATUS_NOT_FOUND;
        for (SIZE_T addressIndex = 0; addressIndex < remoteAddressCount; ++addressIndex) {
            status = ConnectAddress(
                wskClient,
                reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]),
                options,
                buffers,
                clientKey.Get(),
                clientKeyLength,
                requestLength,
                statusCode);
            if (NT_SUCCESS(status)) {
                return STATUS_SUCCESS;
            }

            lastStatus = status;
            kprintf("WebSocketClient address attempt failed: 0x%08X index=%Iu family=%u\r\n",
                static_cast<ULONG>(status),
                addressIndex,
                static_cast<unsigned>(remoteAddresses[addressIndex].ss_family));
        }

        return lastStatus;
    }

    NTSTATUS WebSocketClient::ConnectAddress(
        net::WskClient& wskClient,
        const SOCKADDR* remoteAddress,
        const WebSocketConnectOptions& options,
        const WebSocketIoBuffers& buffers,
        const char* clientKey,
        SIZE_T clientKeyLength,
        SIZE_T requestLength,
        USHORT* statusCode) noexcept
    {
        if (remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = socket_.Connect(wskClient, remoteAddress);
        if (!NT_SUCCESS(status)) {
            kprintf("WebSocketClient connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        rawTransport_ = new core::WskTransport(socket_);
        if (rawTransport_ == nullptr) {
            const NTSTATUS closeStatus = socket_.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        useTls_ = options.UseTls;
        bufferedFrameLength_ = 0;
        if (useTls_) {
            core::WorkspaceScratchAllocator* handshakeScratch = nullptr;
            core::WorkspaceScratchAllocator* certificateScratch = nullptr;
            if (options.Workspace != nullptr) {
                handshakeScratch = new core::WorkspaceScratchAllocator(
                    *options.Workspace,
                    core::WorkspaceScratchAllocator::BufferKind::TlsHandshake);
                certificateScratch = new core::WorkspaceScratchAllocator(
                    *options.Workspace,
                    core::WorkspaceScratchAllocator::BufferKind::Certificate);
                if (handshakeScratch == nullptr || certificateScratch == nullptr) {
                    delete certificateScratch;
                    delete handshakeScratch;
                    delete rawTransport_;
                    rawTransport_ = nullptr;
                    const NTSTATUS closeStatus = socket_.Close();
                    UNREFERENCED_PARAMETER(closeStatus);
                    useTls_ = false;
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }

            tls_ = new tls::TlsConnection();
            if (tls_ == nullptr) {
                delete certificateScratch;
                delete handshakeScratch;
                delete rawTransport_;
                rawTransport_ = nullptr;
                const NTSTATUS closeStatus = socket_.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                useTls_ = false;
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            tls::TlsClientConnectionOptions tlsOptions = {};
            tlsOptions.ServerName = options.TlsServerName;
            tlsOptions.ServerNameLength = options.TlsServerNameLength;
            tlsOptions.CertificateStore = options.CertificateStore;
            tlsOptions.HandshakeScratchAllocator = handshakeScratch;
            tlsOptions.CertificateScratchAllocator = certificateScratch;
            tlsOptions.ProviderCache = options.ProviderCache;
            tlsOptions.VerifyCertificate = options.VerifyCertificate;
            tlsOptions.MinimumProtocol = options.MinimumTlsProtocol;
            tlsOptions.MaximumProtocol = options.MaximumTlsProtocol;
            tlsOptions.HandshakeReceiveTimeoutMilliseconds = options.HandshakeReceiveTimeoutMilliseconds;

            tls::TlsAlpnProtocol alpn = {};
            alpn.Name = WebSocketHttp11Alpn;
            alpn.NameLength = WebSocketHttp11AlpnLength;
            tlsOptions.AlpnProtocols = &alpn;
            tlsOptions.AlpnProtocolCount = 1;

            status = tls_->Connect(*rawTransport_, tlsOptions);
            if (!NT_SUCCESS(status) &&
                (status == STATUS_INVALID_NETWORK_RESPONSE ||
                 status == STATUS_CONNECTION_RESET ||
                 status == STATUS_CONNECTION_ABORTED) &&
                tlsOptions.MinimumProtocol <= tls::TlsProtocol::Tls12 &&
                tlsOptions.MaximumProtocol >= tls::TlsProtocol::Tls13) {
                delete tls_;
                tls_ = nullptr;
                delete rawTransport_;
                rawTransport_ = nullptr;
                const NTSTATUS reconnectClose = socket_.Close();
                UNREFERENCED_PARAMETER(reconnectClose);

                status = socket_.Connect(wskClient, remoteAddress);
                if (NT_SUCCESS(status)) {
                    rawTransport_ = new core::WskTransport(socket_);
                    if (rawTransport_ == nullptr) {
                        delete certificateScratch;
                        delete handshakeScratch;
                        useTls_ = false;
                        const NTSTATUS retryClose = socket_.Close();
                        UNREFERENCED_PARAMETER(retryClose);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    tls_ = new tls::TlsConnection();
                    if (tls_ == nullptr) {
                        delete certificateScratch;
                        delete handshakeScratch;
                        delete rawTransport_;
                        rawTransport_ = nullptr;
                        useTls_ = false;
                        const NTSTATUS retryClose = socket_.Close();
                        UNREFERENCED_PARAMETER(retryClose);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    tlsOptions.MaximumProtocol = tls::TlsProtocol::Tls12;
                    status = tls_->Connect(*rawTransport_, tlsOptions);
                }
            }
            delete certificateScratch;
            delete handshakeScratch;

            if (!NT_SUCCESS(status)) {
                kprintf("WebSocketClient TLS connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
                delete tls_;
                tls_ = nullptr;
                useTls_ = false;
                delete rawTransport_;
                rawTransport_ = nullptr;
                const NTSTATUS closeStatus = socket_.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            const char* negotiatedAlpn = tls_->NegotiatedAlpn();
            const SIZE_T negotiatedAlpnLength = tls_->NegotiatedAlpnLength();
            if (negotiatedAlpnLength != 0 &&
                !TextEqualsLiteral(negotiatedAlpn, negotiatedAlpnLength, WebSocketHttp11Alpn)) {
                kprintf("WebSocketClient unexpected ALPN: %.*s\r\n",
                    static_cast<int>(negotiatedAlpnLength),
                    negotiatedAlpn != nullptr ? negotiatedAlpn : "");
                delete tls_;
                tls_ = nullptr;
                useTls_ = false;
                delete rawTransport_;
                rawTransport_ = nullptr;
                const NTSTATUS closeStatus = socket_.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_NOT_SUPPORTED;
            }
        }

        SIZE_T sent = 0;
        status = SendRaw(buffers.RequestBuffer, requestLength, &sent);
        if (NT_SUCCESS(status) && sent != requestLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }

        if (!NT_SUCCESS(status)) {
            kprintf("WebSocketClient send handshake failed: 0x%08X\r\n", static_cast<ULONG>(status));
            const NTSTATUS closeStatus = Close(buffers);
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        http::HttpResponse response = {};
        status = ReadHandshakeResponse(clientKey, clientKeyLength, buffers, response);
        if (statusCode != nullptr) {
            *statusCode = response.StatusCode;
        }

        if (!NT_SUCCESS(status)) {
            kprintf("WebSocketClient handshake failed: 0x%08X status=%u\r\n",
                static_cast<ULONG>(status),
                response.StatusCode);
            const NTSTATUS closeStatus = Close(buffers);
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        connected_ = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketClient::SendText(
        const char* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment) noexcept
    {
        if (!connected_ ||
            (message == nullptr && messageLength != 0) ||
            buffers.FrameBuffer == nullptr ||
            buffers.FrameBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = EnsureMaskingKeyScratch();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = crypto::CngProvider::GenerateRandom(maskingKey_, websocket::WebSocketMaskingKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T frameLength = 0;
        status = websocket::WebSocketCodec::EncodeClientFrame(
            websocket::WebSocketOpcode::Text,
            finalFragment,
            reinterpret_cast<const UCHAR*>(message),
            messageLength,
            maskingKey_,
            buffers.FrameBuffer,
            buffers.FrameBufferLength,
            &frameLength);
        RtlSecureZeroMemory(maskingKey_, websocket::WebSocketMaskingKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T sent = 0;
        status = SendRaw(buffers.FrameBuffer, frameLength, &sent);
        if (NT_SUCCESS(status) && sent != frameLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }
        return status;
    }

    NTSTATUS WebSocketClient::SendBinary(
        const UCHAR* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        bool finalFragment) noexcept
    {
        if (!connected_ ||
            (message == nullptr && messageLength != 0) ||
            buffers.FrameBuffer == nullptr ||
            buffers.FrameBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = EnsureMaskingKeyScratch();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = crypto::CngProvider::GenerateRandom(maskingKey_, websocket::WebSocketMaskingKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T frameLength = 0;
        status = websocket::WebSocketCodec::EncodeClientFrame(
            websocket::WebSocketOpcode::Binary,
            finalFragment,
            message,
            messageLength,
            maskingKey_,
            buffers.FrameBuffer,
            buffers.FrameBufferLength,
            &frameLength);
        RtlSecureZeroMemory(maskingKey_, websocket::WebSocketMaskingKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T sent = 0;
        status = SendRaw(buffers.FrameBuffer, frameLength, &sent);
        if (NT_SUCCESS(status) && sent != frameLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }
        return status;
    }

    NTSTATUS WebSocketClient::ReceiveMessage(
        const WebSocketIoBuffers& buffers,
        websocket::WebSocketOpcode* opcode,
        UCHAR* output,
        SIZE_T outputCapacity,
        SIZE_T* bytesReceived) noexcept
    {
        if (opcode != nullptr) {
            *opcode = websocket::WebSocketOpcode::Continuation;
        }
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (!connected_ ||
            buffers.FrameBuffer == nullptr ||
            buffers.FrameBufferLength == 0 ||
            output == nullptr ||
            bytesReceived == nullptr ||
            opcode == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (bufferedFrameLength_ > buffers.FrameBufferLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        NTSTATUS status = EnsureBufferedFrameCapacity(buffers.FrameBufferLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (;;) {
            SIZE_T frameLength = bufferedFrameLength_;
            websocket::WebSocketFrameHeader header = {};
            for (;;) {
                bool complete = false;
                status = TryDecodeCompleteFrame(bufferedFrame_, frameLength, &header, &complete);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (complete) {
                    break;
                }

                if (frameLength >= buffers.FrameBufferLength) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                SIZE_T received = 0;
                status = ReceiveRaw(
                    bufferedFrame_ + frameLength,
                    buffers.FrameBufferLength - frameLength,
                    &received);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (received == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }
                frameLength += received;
            }

            if (header.Masked || !header.Fin || header.Opcode == websocket::WebSocketOpcode::Continuation) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T payloadLength = static_cast<SIZE_T>(header.PayloadLength);
            const SIZE_T consumed = header.HeaderLength + payloadLength;
            const SIZE_T remaining = frameLength - consumed;

            if (header.Opcode == websocket::WebSocketOpcode::Ping) {
                SIZE_T pongLength = 0;
                status = EnsureMaskingKeyScratch();
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = GenerateAndEncodeControlFrame(
                    websocket::WebSocketOpcode::Pong,
                    bufferedFrame_ + header.HeaderLength,
                    payloadLength,
                    maskingKey_,
                    buffers,
                    &pongLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T sent = 0;
                status = SendRaw(buffers.FrameBuffer, pongLength, &sent);
                if (NT_SUCCESS(status) && sent != pongLength) {
                    status = STATUS_CONNECTION_DISCONNECTED;
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (remaining > 0) {
                    RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
                }
                bufferedFrameLength_ = remaining;
                continue;
            }

            status = websocket::WebSocketCodec::DecodeFramePayload(
                header,
                bufferedFrame_,
                frameLength,
                output,
                outputCapacity,
                bytesReceived);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (header.Opcode == websocket::WebSocketOpcode::Text &&
                !IsValidUtf8(output, *bytesReceived)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (header.Opcode == websocket::WebSocketOpcode::Close) {
                if (*bytesReceived == 1) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (*bytesReceived >= 2) {
                    const USHORT closeStatus = static_cast<USHORT>(
                        (static_cast<USHORT>(output[0]) << 8) | output[1]);
                    if (!IsValidCloseStatus(closeStatus) ||
                        !IsValidUtf8(output + 2, *bytesReceived - 2)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
            }

            if (remaining > 0) {
                RtlMoveMemory(bufferedFrame_, bufferedFrame_ + consumed, remaining);
            }
            bufferedFrameLength_ = remaining;
            *opcode = header.Opcode;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS WebSocketClient::Close(const WebSocketIoBuffers& buffers) noexcept
    {
        if (connected_ && buffers.FrameBuffer != nullptr && buffers.FrameBufferLength >= 6) {
            SIZE_T frameLength = 0;
            if (NT_SUCCESS(EnsureMaskingKeyScratch()) &&
                NT_SUCCESS(GenerateAndEncodeControlFrame(
                websocket::WebSocketOpcode::Close,
                nullptr,
                0,
                maskingKey_,
                buffers,
                &frameLength))) {
                SIZE_T sent = 0;
                const NTSTATUS sendStatus = SendRaw(buffers.FrameBuffer, frameLength, &sent);
                UNREFERENCED_PARAMETER(sendStatus);
                UNREFERENCED_PARAMETER(sent);
            }
        }

        connected_ = false;
        if (bufferedFrame_ != nullptr && bufferedFrameLength_ != 0) {
            RtlSecureZeroMemory(bufferedFrame_, bufferedFrameLength_);
        }
        bufferedFrameLength_ = 0;

        if (tls_ != nullptr) {
            delete tls_;
            tls_ = nullptr;
        }

        delete rawTransport_;
        rawTransport_ = nullptr;

        useTls_ = false;
        const NTSTATUS closeStatus = socket_.Close();
        return IsConnectionTerminalStatus(closeStatus) ? STATUS_SUCCESS : closeStatus;
    }

    NTSTATUS WebSocketClient::SendTextAndReceiveEcho(
        const char* message,
        SIZE_T messageLength,
        const WebSocketIoBuffers& buffers,
        WebSocketEchoResult& result) noexcept
    {
        result = {};

        if (buffers.PayloadBuffer == nullptr || buffers.PayloadBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = SendText(message, messageLength, buffers);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        constexpr SIZE_T MaxFramesBeforeEcho = 8;
        for (SIZE_T frameIndex = 0; frameIndex < MaxFramesBeforeEcho; ++frameIndex) {
            status = ReceiveMessage(
                buffers,
                &result.Opcode,
                buffers.PayloadBuffer,
                buffers.PayloadBufferLength,
                &result.BytesReceived);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (result.Opcode == websocket::WebSocketOpcode::Text &&
                PayloadEquals(message, messageLength, buffers.PayloadBuffer, result.BytesReceived)) {
                return STATUS_SUCCESS;
            }

            if (result.Opcode == websocket::WebSocketOpcode::Close) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
        }

        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    NTSTATUS WebSocketClient::EnsureMaskingKeyScratch() noexcept
    {
        if (maskingKey_ != nullptr) {
            return STATUS_SUCCESS;
        }

        maskingKey_ = new UCHAR[websocket::WebSocketMaskingKeyLength]();
        return maskingKey_ != nullptr ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS WebSocketClient::EnsureBufferedFrameCapacity(SIZE_T capacity) noexcept
    {
        if (capacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (bufferedFrameCapacity_ >= capacity) {
            return STATUS_SUCCESS;
        }

        UCHAR* replacement = new UCHAR[capacity]();
        if (replacement == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (bufferedFrame_ != nullptr) {
            if (bufferedFrameLength_ != 0) {
                RtlCopyMemory(replacement, bufferedFrame_, bufferedFrameLength_);
            }
            RtlSecureZeroMemory(bufferedFrame_, bufferedFrameCapacity_);
        }

        delete[] bufferedFrame_;
        bufferedFrame_ = replacement;
        bufferedFrameCapacity_ = capacity;
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketClient::SendRaw(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
    {
        if (useTls_) {
            if (tls_ == nullptr || rawTransport_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return tls_->Send(*rawTransport_, data, length, bytesSent);
        }

        return socket_.Send(data, length, bytesSent);
    }

    NTSTATUS WebSocketClient::ReceiveRaw(void* data, SIZE_T length, SIZE_T* bytesReceived) noexcept
    {
        if (useTls_) {
            if (tls_ == nullptr || rawTransport_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return tls_->Receive(*rawTransport_, data, length, bytesReceived);
        }

        return socket_.Receive(data, length, bytesReceived);
    }

    NTSTATUS WebSocketClient::ReadHandshakeResponse(
        const char* clientKey,
        SIZE_T clientKeyLength,
        const WebSocketIoBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        SIZE_T responseLength = 0;
        bufferedFrameLength_ = 0;

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = buffers.Headers;
            parseOptions.HeaderCapacity = buffers.HeaderCapacity;
            parseOptions.ResponseBodyForbidden = true;

            NTSTATUS status = http::HttpParser::ParseResponse(
                buffers.ResponseBuffer,
                responseLength,
                parseOptions,
                response);
            if (status == STATUS_SUCCESS) {
                status = websocket::WebSocketCodec::ValidateServerHandshake(
                    response,
                    clientKey,
                    clientKeyLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (response.BytesConsumed > responseLength) {
                    response = {};
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T upgradedBytes = responseLength - response.BytesConsumed;
                if (upgradedBytes != 0) {
                    if (buffers.FrameBuffer == nullptr || buffers.FrameBufferLength < upgradedBytes) {
                        response = {};
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    status = EnsureBufferedFrameCapacity(buffers.FrameBufferLength);
                    if (!NT_SUCCESS(status)) {
                        response = {};
                        return status;
                    }

                    // Bytes after the 101 header already belong to the WebSocket stream.
                    RtlMoveMemory(
                        bufferedFrame_,
                        buffers.ResponseBuffer + response.BytesConsumed,
                        upgradedBytes);
                    bufferedFrameLength_ = upgradedBytes;
                }

                return STATUS_SUCCESS;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                response = {};
                return status;
            }

            if (responseLength >= buffers.ResponseBufferLength) {
                response = {};
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T received = 0;
            status = ReceiveRaw(
                buffers.ResponseBuffer + responseLength,
                buffers.ResponseBufferLength - responseLength,
                &received);
            if (!NT_SUCCESS(status)) {
                response = {};
                return status;
            }
            if (received == 0) {
                response = {};
                return STATUS_CONNECTION_DISCONNECTED;
            }

            responseLength += received;
        }
    }
}
}
