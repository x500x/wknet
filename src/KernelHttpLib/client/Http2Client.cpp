#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/core/Irql.h>
#include <KernelHttp/core/TlsTransport.h>
#include <KernelHttp/core/WskTransport.h>
#include <KernelHttp/tls/TlsConnection.h>

namespace KernelHttp
{
namespace client
{
    namespace
    {
        const char* HttpMethodToString(http::HttpMethod method) noexcept
        {
            switch (method) {
            case http::HttpMethod::Get: return "GET";
            case http::HttpMethod::Post: return "POST";
            case http::HttpMethod::Put: return "PUT";
            case http::HttpMethod::Patch: return "PATCH";
            case http::HttpMethod::DeleteMethod: return "DELETE";
            case http::HttpMethod::Head: return "HEAD";
            case http::HttpMethod::Options: return "OPTIONS";
            case http::HttpMethod::Connect: return "CONNECT";
            default: return "GET";
            }
        }

        SIZE_T StringLen(const char* s) noexcept
        {
            SIZE_T len = 0;
            if (s == nullptr) return 0;
            while (s[len] != '\0') ++len;
            return len;
        }

        bool AlpnEquals(const char* a, SIZE_T aLen, const char* b, SIZE_T bLen) noexcept
        {
            if (aLen != bLen) return false;
            for (SIZE_T i = 0; i < aLen; ++i) {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        void MemCopy(void* dst, const void* src, SIZE_T len) noexcept
        {
            auto* d = static_cast<char*>(dst);
            auto* s = static_cast<const char*>(src);
            for (SIZE_T i = 0; i < len; ++i) d[i] = s[i];
        }

        bool TextEqualsIgnoreCase(http::HttpText text, const char* literal) noexcept
        {
            const SIZE_T literalLength = StringLen(literal);
            if (text.Length != literalLength || text.Data == nullptr) return false;
            for (SIZE_T i = 0; i < literalLength; ++i) {
                char left = text.Data[i];
                char right = literal[i];
                if (left >= 'A' && left <= 'Z') left = static_cast<char>(left + 32);
                if (right >= 'A' && right <= 'Z') right = static_cast<char>(right + 32);
                if (left != right) return false;
            }
            return true;
        }

        bool IsForbiddenHttp2Header(http::HttpText name) noexcept
        {
            return TextEqualsIgnoreCase(name, "connection") ||
                TextEqualsIgnoreCase(name, "keep-alive") ||
                TextEqualsIgnoreCase(name, "proxy-connection") ||
                TextEqualsIgnoreCase(name, "transfer-encoding") ||
                TextEqualsIgnoreCase(name, "upgrade") ||
                TextEqualsIgnoreCase(name, "host");
        }

        bool IsValidHttpHeaderInputName(http::HttpText name) noexcept
        {
            if (name.Data == nullptr || name.Length == 0) {
                return false;
            }
            if (name.Length > Http2MaxHeaderNameLength) {
                return false;
            }
            if (name.Data[0] == ':') {
                return false;
            }

            for (SIZE_T i = 0; i < name.Length; ++i) {
                const UCHAR c = static_cast<UCHAR>(name.Data[i]);
                if (c <= 0x20 || c >= 0x7f || c == ':') {
                    return false;
                }
            }

            return true;
        }

        bool IsValidHttp2FieldValue(http::HttpText value) noexcept
        {
            if (value.Data == nullptr && value.Length != 0) {
                return false;
            }
            if (value.Length == 0) {
                return true;
            }
            if (value.Data[0] == ' ' || value.Data[0] == '\t' ||
                value.Data[value.Length - 1] == ' ' || value.Data[value.Length - 1] == '\t') {
                return false;
            }
            for (SIZE_T i = 0; i < value.Length; ++i) {
                if (value.Data[i] == '\0' || value.Data[i] == '\r' || value.Data[i] == '\n') {
                    return false;
                }
            }
            return true;
        }

        bool LowercaseHeaderName(http::HttpText name, char* output, SIZE_T capacity, http::HttpText& lowered) noexcept
        {
            if (!IsValidHttpHeaderInputName(name) || output == nullptr || name.Length > capacity) {
                return false;
            }

            for (SIZE_T i = 0; i < name.Length; ++i) {
                char c = name.Data[i];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
                output[i] = c;
            }
            lowered.Data = output;
            lowered.Length = name.Length;
            return true;
        }

        bool WriteDecimal(SIZE_T value, char* output, SIZE_T capacity, http::HttpText& text) noexcept
        {
            if (output == nullptr || capacity == 0) return false;

            SIZE_T divisor = 1;
            while ((value / divisor) >= 10) {
                divisor *= 10;
            }

            SIZE_T length = 0;
            for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
                if (length >= capacity) return false;
                output[length++] = static_cast<char>('0' + ((value / currentDivisor) % 10));
            }

            text.Data = output;
            text.Length = length;
            return true;
        }

        bool IsTlsMode(Http2TransportMode mode) noexcept
        {
            return mode == Http2TransportMode::TlsAlpn;
        }

        class ReplayTransport final : public core::ITransport
        {
        public:
            ReplayTransport(
                _Inout_ core::ITransport& inner,
                _In_reads_bytes_opt_(replayLength) const UCHAR* replayBytes,
                SIZE_T replayLength) noexcept
                : inner_(inner),
                  replayBytes_(replayBytes),
                  replayLength_(replayLength)
            {
            }

            NTSTATUS Send(
                _In_reads_bytes_(length) const void* data,
                SIZE_T length,
                _Out_opt_ SIZE_T* bytesSent) noexcept override
            {
                return inner_.Send(data, length, bytesSent);
            }

            NTSTATUS Receive(
                _Out_writes_bytes_(length) void* buffer,
                SIZE_T length,
                _Out_opt_ SIZE_T* bytesReceived) noexcept override
            {
                NTSTATUS status = ReceiveReplay(buffer, length, bytesReceived);
                if (status != STATUS_MORE_PROCESSING_REQUIRED) return status;
                return inner_.Receive(buffer, length, bytesReceived);
            }

            NTSTATUS ReceiveWithTimeout(
                _Out_writes_bytes_(length) void* buffer,
                SIZE_T length,
                _Out_opt_ SIZE_T* bytesReceived,
                ULONG timeoutMilliseconds) noexcept override
            {
                NTSTATUS status = ReceiveReplay(buffer, length, bytesReceived);
                if (status != STATUS_MORE_PROCESSING_REQUIRED) return status;
                return inner_.ReceiveWithTimeout(buffer, length, bytesReceived, timeoutMilliseconds);
            }

        private:
            NTSTATUS ReceiveReplay(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
            {
                if (bytesReceived != nullptr) {
                    *bytesReceived = 0;
                }

                if (buffer == nullptr || length == 0) {
                    return STATUS_INVALID_PARAMETER;
                }

                if (replayOffset_ >= replayLength_) {
                    return STATUS_MORE_PROCESSING_REQUIRED;
                }

                if (replayBytes_ == nullptr) {
                    return STATUS_INVALID_PARAMETER;
                }

                SIZE_T available = replayLength_ - replayOffset_;
                SIZE_T toCopy = length < available ? length : available;
                MemCopy(buffer, replayBytes_ + replayOffset_, toCopy);
                replayOffset_ += toCopy;
                if (bytesReceived != nullptr) {
                    *bytesReceived = toCopy;
                }
                return STATUS_SUCCESS;
            }

            core::ITransport& inner_;
            const UCHAR* replayBytes_ = nullptr;
            SIZE_T replayLength_ = 0;
            SIZE_T replayOffset_ = 0;
        };

        bool GetAuthority(const Http2RequestOptions& options, http::HttpText& authority) noexcept
        {
            if (options.Authority.Data != nullptr && options.Authority.Length > 0) {
                authority = options.Authority;
                return true;
            }

            if (options.ServerName != nullptr && options.ServerNameLength > 0) {
                authority = { options.ServerName, options.ServerNameLength };
                return true;
            }

            authority = {};
            return false;
        }

        SIZE_T FindHeaderEnd(const char* data, SIZE_T length) noexcept
        {
            if (data == nullptr || length < 4) return static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
            for (SIZE_T i = 0; i + 3 < length; ++i) {
                if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                    return i + 4;
                }
            }
            return static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        }

        NTSTATUS BuildHttp2SettingsHeader(char* output, SIZE_T outputCapacity, http::HttpText& value) noexcept
        {
            if (output == nullptr) return STATUS_INVALID_PARAMETER;

            http2::Http2Settings settings = {};
            NTSTATUS status = http2::Http2FrameCodec::EncodeSettingsPayloadBase64Url(
                settings,
                output,
                outputCapacity,
                &value.Length);
            if (!NT_SUCCESS(status)) return status;

            value.Data = output;
            return STATUS_SUCCESS;
        }

        NTSTATUS AppendText(char* output, SIZE_T capacity, SIZE_T& offset, http::HttpText text) noexcept
        {
            if (output == nullptr || text.Data == nullptr || offset > capacity || text.Length > capacity - offset) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            MemCopy(output + offset, text.Data, text.Length);
            offset += text.Length;
            return STATUS_SUCCESS;
        }

        NTSTATUS AppendLiteral(char* output, SIZE_T capacity, SIZE_T& offset, const char* literal) noexcept
        {
            return AppendText(output, capacity, offset, { literal, StringLen(literal) });
        }

        NTSTATUS BuildH2cUpgradeRequest(
            const Http2RequestOptions& options,
            char* output,
            SIZE_T outputCapacity,
            SIZE_T* outputLength) noexcept
        {
            if (output == nullptr || outputLength == nullptr) return STATUS_INVALID_PARAMETER;

            http::HttpText authority = {};
            if (!GetAuthority(options, authority)) return STATUS_INVALID_PARAMETER;

            HeapArray<char> settingsValue(128);
            if (!settingsValue.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;

            http::HttpText settingsText = {};
            NTSTATUS status = BuildHttp2SettingsHeader(settingsValue.Get(), settingsValue.Count(), settingsText);
            if (!NT_SUCCESS(status)) return status;

            SIZE_T offset = 0;
            status = AppendLiteral(output, outputCapacity, offset, HttpMethodToString(options.Method));
            if (!NT_SUCCESS(status)) return status;
            status = AppendLiteral(output, outputCapacity, offset, " ");
            if (!NT_SUCCESS(status)) return status;
            status = AppendText(output, outputCapacity, offset, options.Path);
            if (!NT_SUCCESS(status)) return status;
            status = AppendLiteral(output, outputCapacity, offset, " HTTP/1.1\r\nHost: ");
            if (!NT_SUCCESS(status)) return status;
            status = AppendText(output, outputCapacity, offset, authority);
            if (!NT_SUCCESS(status)) return status;
            status = AppendLiteral(output, outputCapacity, offset,
                "\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: ");
            if (!NT_SUCCESS(status)) return status;
            status = AppendText(output, outputCapacity, offset, settingsText);
            if (!NT_SUCCESS(status)) return status;
            status = AppendLiteral(output, outputCapacity, offset, "\r\n\r\n");
            if (!NT_SUCCESS(status)) return status;

            *outputLength = offset;
            return STATUS_SUCCESS;
        }

        bool HeaderContainsToken(const char* data, SIZE_T length, const char* headerName, const char* token) noexcept
        {
            const SIZE_T nameLength = StringLen(headerName);
            const SIZE_T tokenLength = StringLen(token);
            for (SIZE_T i = 0; i + nameLength < length; ++i) {
                http::HttpText name = { data + i, nameLength };
                if (!TextEqualsIgnoreCase(name, headerName) || data[i + nameLength] != ':') continue;
                SIZE_T lineEnd = i + nameLength + 1;
                while (lineEnd + 1 < length && !(data[lineEnd] == '\r' && data[lineEnd + 1] == '\n')) ++lineEnd;
                for (SIZE_T j = i + nameLength + 1; j + tokenLength <= lineEnd; ++j) {
                    if (TextEqualsIgnoreCase({ data + j, tokenLength }, token)) return true;
                }
            }
            return false;
        }

        NTSTATUS ValidateH2cUpgradeResponse(const char* data, SIZE_T length) noexcept
        {
            if (data == nullptr || length < 12) return STATUS_INVALID_NETWORK_RESPONSE;
            if (data[0] != 'H' || data[1] != 'T' || data[2] != 'T' || data[3] != 'P' || data[4] != '/') {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            SIZE_T index = 5;
            while (index < length && data[index] != ' ') ++index;
            if (index + 4 >= length || data[index] != ' ') return STATUS_INVALID_NETWORK_RESPONSE;
            if (data[index + 1] != '1' || data[index + 2] != '0' || data[index + 3] != '1') {
                return STATUS_NOT_SUPPORTED;
            }
            if (!HeaderContainsToken(data, length, "upgrade", "h2c")) return STATUS_NOT_SUPPORTED;
            return STATUS_SUCCESS;
        }

        NTSTATUS PerformH2cUpgrade(
            net::WskSocket& socket,
            const Http2RequestOptions& options,
            UCHAR* replayBytes,
            SIZE_T replayCapacity,
            SIZE_T* replayLength) noexcept
        {
            if (replayLength == nullptr) return STATUS_INVALID_PARAMETER;
            *replayLength = 0;
            if (options.Body != nullptr ||
                options.BodyLength != 0 ||
                options.BodySource != nullptr ||
                options.TrailerCount != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<char> request(1024);
            if (!request.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;

            SIZE_T requestLength = 0;
            NTSTATUS status = BuildH2cUpgradeRequest(options, request.Get(), request.Count(), &requestLength);
            if (!NT_SUCCESS(status)) return status;

            SIZE_T sent = 0;
            status = socket.Send(request.Get(), requestLength, &sent);
            if (!NT_SUCCESS(status)) return status;
            if (sent != requestLength) return STATUS_CONNECTION_DISCONNECTED;

            HeapArray<char> response(2048);
            if (!response.IsValid()) return STATUS_INSUFFICIENT_RESOURCES;

            SIZE_T responseLength = 0;
            for (;;) {
                const SIZE_T headerEnd = FindHeaderEnd(response.Get(), responseLength);
                if (headerEnd != static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                    status = ValidateH2cUpgradeResponse(response.Get(), headerEnd);
                    if (!NT_SUCCESS(status)) return status;

                    const SIZE_T extraLength = responseLength - headerEnd;
                    if (extraLength != 0) {
                        if (replayBytes == nullptr || extraLength > replayCapacity) {
                            return STATUS_BUFFER_TOO_SMALL;
                        }
                        MemCopy(replayBytes, response.Get() + headerEnd, extraLength);
                    }

                    *replayLength = extraLength;
                    return STATUS_SUCCESS;
                }
                if (responseLength >= response.Count()) return STATUS_BUFFER_TOO_SMALL;
                SIZE_T received = 0;
                status = socket.Receive(response.Get() + responseLength, response.Count() - responseLength, &received);
                if (!NT_SUCCESS(status)) return status;
                if (received == 0) return STATUS_CONNECTION_DISCONNECTED;
                responseLength += received;
            }
        }

    }

    NTSTATUS BuildHttp2RequestHeaders(
        const Http2RequestOptions& options,
        http::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength],
        char* contentLengthBuffer,
        SIZE_T* headerCount) noexcept
    {
        if (requestHeaders == nullptr ||
            lowerHeaderNames == nullptr ||
            contentLengthBuffer == nullptr ||
            headerCount == nullptr ||
            headerCapacity < Http2MaxRequestHeaders ||
            (options.ExtraHeaders == nullptr && options.ExtraHeaderCount != 0) ||
            (options.Body != nullptr && options.BodySource != nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }

        http::HttpText authority = {};
        if (!GetAuthority(options, authority)) return STATUS_INVALID_PARAMETER;
        if (!IsValidHttp2FieldValue(options.Path) ||
            !IsValidHttp2FieldValue(authority) ||
            !IsValidHttp2FieldValue(options.UserAgent) ||
            !IsValidHttp2FieldValue(options.ContentType) ||
            !IsValidHttp2FieldValue(options.AcceptEncoding) ||
            !IsValidHttp2FieldValue(options.ConnectProtocol)) {
            return STATUS_INVALID_PARAMETER;
        }
        const bool usesExtendedConnect =
            options.ConnectProtocol.Data != nullptr &&
            options.ConnectProtocol.Length > 0;
        if (usesExtendedConnect && options.Method != http::HttpMethod::Connect) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T headerIdx = 0;
        const char* methodStr = HttpMethodToString(options.Method);
        requestHeaders[headerIdx].Name = { ":method", 7 };
        requestHeaders[headerIdx].Value = { methodStr, StringLen(methodStr) };
        ++headerIdx;

        requestHeaders[headerIdx].Name = { ":scheme", 7 };
        requestHeaders[headerIdx].Value = IsTlsMode(options.TransportMode) ? http::HttpText{ "https", 5 } : http::HttpText{ "http", 4 };
        ++headerIdx;

        requestHeaders[headerIdx].Name = { ":path", 5 };
        requestHeaders[headerIdx].Value = options.Path;
        ++headerIdx;

        requestHeaders[headerIdx].Name = { ":authority", 10 };
        requestHeaders[headerIdx].Value = authority;
        ++headerIdx;

        if (usesExtendedConnect) {
            requestHeaders[headerIdx].Name = { ":protocol", 9 };
            requestHeaders[headerIdx].Value = options.ConnectProtocol;
            ++headerIdx;
        }

        if (options.UserAgent.Data != nullptr && options.UserAgent.Length > 0) {
            requestHeaders[headerIdx].Name = { "user-agent", 10 };
            requestHeaders[headerIdx].Value = options.UserAgent;
            ++headerIdx;
        }

        if (options.ContentType.Data != nullptr && options.ContentType.Length > 0) {
            requestHeaders[headerIdx].Name = { "content-type", 12 };
            requestHeaders[headerIdx].Value = options.ContentType;
            ++headerIdx;
        }

        const bool sourceContentLength =
            options.BodySource != nullptr && options.BodySource->ContentLengthKnown;
        const SIZE_T contentLengthValue = sourceContentLength ?
            options.BodySource->ContentLength :
            options.BodyLength;
        if ((options.Body != nullptr && options.BodyLength > 0) ||
            sourceContentLength ||
            options.IncludeContentLength) {
            requestHeaders[headerIdx].Name = { "content-length", 14 };
            if (!WriteDecimal(
                contentLengthValue,
                contentLengthBuffer,
                Http2ContentLengthBufferLength,
                requestHeaders[headerIdx].Value)) {
                return STATUS_INVALID_PARAMETER;
            }
            ++headerIdx;
        }

        if (options.AcceptEncoding.Data != nullptr && options.AcceptEncoding.Length > 0) {
            requestHeaders[headerIdx].Name = { "accept-encoding", 15 };
            requestHeaders[headerIdx].Value = options.AcceptEncoding;
            ++headerIdx;
        }

        const bool acceptEncodingPromoted =
            options.AcceptEncoding.Data != nullptr &&
            options.AcceptEncoding.Length > 0;
        for (SIZE_T i = 0; i < options.ExtraHeaderCount; ++i) {
            if (headerIdx >= Http2MaxRequestHeaders) {
                return STATUS_INVALID_PARAMETER;
            }
            if (TextEqualsIgnoreCase(options.ExtraHeaders[i].Name, "te") &&
                !TextEqualsIgnoreCase(options.ExtraHeaders[i].Value, "trailers")) {
                return STATUS_INVALID_PARAMETER;
            }
            if (!IsValidHttp2FieldValue(options.ExtraHeaders[i].Value)) {
                return STATUS_INVALID_PARAMETER;
            }
            if (IsForbiddenHttp2Header(options.ExtraHeaders[i].Name) ||
                options.ExtraHeaders[i].Name.Data == nullptr ||
                options.ExtraHeaders[i].Name.Length == 0 ||
                options.ExtraHeaders[i].Name.Data[0] == ':') {
                return STATUS_INVALID_PARAMETER;
            }
            if (acceptEncodingPromoted && TextEqualsIgnoreCase(options.ExtraHeaders[i].Name, "accept-encoding")) {
                continue;
            }
            requestHeaders[headerIdx].Value = options.ExtraHeaders[i].Value;
            if (!LowercaseHeaderName(
                options.ExtraHeaders[i].Name,
                lowerHeaderNames[headerIdx],
                Http2MaxHeaderNameLength,
                requestHeaders[headerIdx].Name)) {
                return STATUS_INVALID_PARAMETER;
            }
            ++headerIdx;
        }

        *headerCount = headerIdx;
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Client::SendRequest(
        net::WskClient& wskClient,
        const Http2RequestOptions& options,
        const Http2ResponseBuffers& buffers,
        Http2Response& response) noexcept
    {
        response = {};

        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http::HttpText authority = {};
        if (options.RemoteAddress == nullptr ||
            options.Path.Data == nullptr ||
            options.Path.Length == 0 ||
            buffers.Headers == nullptr ||
            buffers.HeaderCapacity == 0 ||
            buffers.NameValueBuffer == nullptr ||
            buffers.NameValueBufferLength == 0 ||
            buffers.BodyBuffer == nullptr ||
            buffers.BodyBufferLength == 0 ||
            !GetAuthority(options, authority)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsTlsMode(options.TransportMode) &&
            (options.ServerName == nullptr ||
                options.ServerNameLength == 0 ||
                (options.VerifyCertificate && options.CertificateStore == nullptr) ||
                !NT_SUCCESS(tls::TlsValidatePolicy(options.Policy)))) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapObject<net::WskSocket> socket;
        if (!socket.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = socket->Connect(wskClient, options.RemoteAddress);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Client connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        auto* h2conn = AllocateNonPagedObject<http2::Http2Connection>();
        if (h2conn == nullptr) {
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tls::TlsConnection* tlsConnection = nullptr;
        auto* rawTransport = AllocateNonPagedObject<core::WskTransport>(*socket.Get());
        if (rawTransport == nullptr) {
            FreeNonPagedObject(h2conn);
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        core::ITransport* transport = rawTransport;
        core::TlsTransport* tlsTransport = nullptr;
        const bool isH2cUpgrade = options.TransportMode == Http2TransportMode::H2cUpgrade;
        HeapArray<UCHAR> upgradeReplay;
        SIZE_T upgradeReplayLength = 0;
        if (isH2cUpgrade) {
            status = upgradeReplay.Allocate(2048);
        }
        if (!NT_SUCCESS(status)) {
            FreeNonPagedObject(rawTransport);
            FreeNonPagedObject(h2conn);
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        if (IsTlsMode(options.TransportMode)) {
            tlsConnection = AllocateNonPagedObject<tls::TlsConnection>();
            if (tlsConnection == nullptr) {
                FreeNonPagedObject(h2conn);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            static const tls::TlsAlpnProtocol alpnProtocols[] = {
                { "h2", 2 },
                { "http/1.1", 8 }
            };

            tls::TlsClientConnectionOptions tlsOptions = {};
            tlsOptions.ServerName = options.ServerName;
            tlsOptions.ServerNameLength = options.ServerNameLength;
            tlsOptions.CertificateStore = options.CertificateStore;
            tlsOptions.VerifyCertificate = options.VerifyCertificate;
            tlsOptions.Policy = options.Policy;
            tlsOptions.ClientCredential = options.ClientCredential;
            tlsOptions.AlpnProtocols = alpnProtocols;
            tlsOptions.AlpnProtocolCount = 2;

            status = tlsConnection->Connect(*rawTransport, tlsOptions);
            if (!NT_SUCCESS(status)) {
                kprintf("Http2Client TLS connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
                FreeNonPagedObject(tlsConnection);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(h2conn);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            const char* alpn = tlsConnection->NegotiatedAlpn();
            SIZE_T alpnLen = tlsConnection->NegotiatedAlpnLength();
            if (alpnLen > 0 && alpnLen < sizeof(response.NegotiatedAlpn)) {
                MemCopy(response.NegotiatedAlpn, alpn, alpnLen);
                response.NegotiatedAlpn[alpnLen] = '\0';
                response.NegotiatedAlpnLength = alpnLen;
            }

            if (alpn == nullptr || !AlpnEquals(alpn, alpnLen, "h2", 2)) {
                kprintf("Http2Client ALPN not h2: %.*s\r\n",
                    static_cast<int>(alpnLen), alpn != nullptr ? alpn : "(null)");
                FreeNonPagedObject(tlsConnection);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(h2conn);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_NOT_SUPPORTED;
            }

            tlsTransport = AllocateNonPagedObject<core::TlsTransport>(*rawTransport, *tlsConnection);
            if (tlsTransport == nullptr) {
                FreeNonPagedObject(tlsConnection);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(h2conn);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            transport = tlsTransport;
        } else {
            if (isH2cUpgrade) {
                status = PerformH2cUpgrade(
                    *socket.Get(),
                    options,
                    upgradeReplay.Get(),
                    upgradeReplay.Count(),
                    &upgradeReplayLength);
                if (!NT_SUCCESS(status)) {
                    FreeNonPagedObject(rawTransport);
                    FreeNonPagedObject(h2conn);
                    const NTSTATUS closeStatus = socket->Close();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }
            }
        }

        ReplayTransport replayTransport(*transport, upgradeReplay.Get(), upgradeReplayLength);
        core::ITransport* activeTransport = isH2cUpgrade ? static_cast<core::ITransport*>(&replayTransport) : transport;

        status = isH2cUpgrade ?
            h2conn->InitializeAfterUpgrade(*activeTransport) :
            h2conn->Initialize(*activeTransport);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Client H2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
            FreeNonPagedObject(tlsTransport);
            FreeNonPagedObject(tlsConnection);
            FreeNonPagedObject(rawTransport);
            FreeNonPagedObject(h2conn);
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        HeapArray<http::HttpHeader> requestHeaders;
        HeapArray<char> lowerHeaderNames;
        HeapArray<char> contentLengthBuffer;
        if (!isH2cUpgrade) {
            status = requestHeaders.Allocate(Http2MaxRequestHeaders);
            if (NT_SUCCESS(status)) {
                status = lowerHeaderNames.Allocate(Http2MaxRequestHeaders * Http2MaxHeaderNameLength);
            }
            if (NT_SUCCESS(status)) {
                status = contentLengthBuffer.Allocate(Http2ContentLengthBufferLength);
            }
        }

        if (!NT_SUCCESS(status)) {
            h2conn->Shutdown(*activeTransport);
            FreeNonPagedObject(tlsTransport);
            FreeNonPagedObject(tlsConnection);
            FreeNonPagedObject(rawTransport);
            FreeNonPagedObject(h2conn);
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        SIZE_T headerCount = 0;
        if (!isH2cUpgrade) {
            auto lowerHeaderNameRows =
                reinterpret_cast<char (*)[Http2MaxHeaderNameLength]>(lowerHeaderNames.Get());
            status = BuildHttp2RequestHeaders(
                options,
                requestHeaders.Get(),
                Http2MaxRequestHeaders,
                lowerHeaderNameRows,
                contentLengthBuffer.Get(),
                &headerCount);
            if (!NT_SUCCESS(status)) {
                h2conn->Shutdown(*activeTransport);
                FreeNonPagedObject(tlsTransport);
                FreeNonPagedObject(tlsConnection);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(h2conn);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }
        }

        SIZE_T respHeaderCount = 0;
        SIZE_T respBodyLen = 0;
        USHORT respStatusCode = 0;

        if (isH2cUpgrade) {
            status = h2conn->ReceiveResponse(
                *activeTransport,
                1,
                buffers.Headers, buffers.HeaderCapacity,
                &respHeaderCount,
                buffers.BodyBuffer, buffers.BodyBufferLength,
                &respBodyLen,
                &respStatusCode,
                buffers.NameValueBuffer, buffers.NameValueBufferLength);
        } else {
            http2::Http2RequestBody requestBody = {};
            requestBody.Data = options.Body;
            requestBody.DataLength = options.BodyLength;
            requestBody.Source = options.BodySource;
            requestBody.Trailers = options.Trailers;
            requestBody.TrailerCount = options.TrailerCount;
            requestBody.HasBody =
                options.IncludeContentLength ||
                options.BodySource != nullptr ||
                (options.Body != nullptr && options.BodyLength != 0);
            status = h2conn->SendRequest(
                *activeTransport,
                requestHeaders.Get(), headerCount,
                requestBody,
                buffers.Headers, buffers.HeaderCapacity,
                &respHeaderCount,
                buffers.BodyBuffer, buffers.BodyBufferLength,
                &respBodyLen,
                &respStatusCode,
                buffers.NameValueBuffer, buffers.NameValueBufferLength);
        }

        if (NT_SUCCESS(status)) {
            response.StatusCode = respStatusCode;
            response.Headers = buffers.Headers;
            response.HeaderCount = respHeaderCount;
            response.Body = buffers.BodyBuffer;
            response.BodyLength = respBodyLen;
        } else {
            kprintf("Http2Client SendRequest failed: 0x%08X\r\n", static_cast<ULONG>(status));
        }

        h2conn->Shutdown(*activeTransport);

        FreeNonPagedObject(tlsTransport);
        FreeNonPagedObject(tlsConnection);
        FreeNonPagedObject(rawTransport);
        FreeNonPagedObject(h2conn);
        const NTSTATUS closeStatus = socket->Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }
}
}
