#include "client/Http2Client.h"

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
                TextEqualsIgnoreCase(name, "upgrade");
        }

        bool LowercaseHeaderName(http::HttpText name, char* output, SIZE_T capacity, http::HttpText& lowered) noexcept
        {
            if (name.Data == nullptr || name.Length == 0 || output == nullptr || name.Length > capacity) {
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

            HeapArray<char> temp(32);
            if (!temp.IsValid()) return false;

            SIZE_T tempLen = 0;
            do {
                if (tempLen >= temp.Count()) return false;
                temp[tempLen++] = static_cast<char>('0' + (value % 10));
                value /= 10;
            } while (value != 0);

            if (tempLen > capacity) return false;
            for (SIZE_T i = 0; i < tempLen; ++i) {
                output[i] = temp[tempLen - i - 1];
            }
            text.Data = output;
            text.Length = tempLen;
            return true;
        }

        bool IsTlsMode(Http2TransportMode mode) noexcept
        {
            return mode == Http2TransportMode::TlsAlpn;
        }

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

        NTSTATUS PerformH2cUpgrade(net::WskSocket& socket, const Http2RequestOptions& options) noexcept
        {
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
                    return ValidateH2cUpgradeResponse(response.Get(), headerEnd);
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
            headerCapacity < Http2MaxRequestHeaders) {
            return STATUS_INVALID_PARAMETER;
        }

        http::HttpText authority = {};
        if (!GetAuthority(options, authority)) return STATUS_INVALID_PARAMETER;

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

        if ((options.Body != nullptr && options.BodyLength > 0) || options.IncludeContentLength) {
            requestHeaders[headerIdx].Name = { "content-length", 14 };
            if (!WriteDecimal(
                options.BodyLength,
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
        for (SIZE_T i = 0; i < options.ExtraHeaderCount && headerIdx < Http2MaxRequestHeaders; ++i) {
            if (IsForbiddenHttp2Header(options.ExtraHeaders[i].Name) ||
                (acceptEncodingPromoted && TextEqualsIgnoreCase(options.ExtraHeaders[i].Name, "accept-encoding"))) {
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
                (options.VerifyCertificate && options.CertificateStore == nullptr))) {
            return STATUS_INVALID_PARAMETER;
        }

        net::WskSocket socket;
        NTSTATUS status = socket.Connect(wskClient, options.RemoteAddress);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Client connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        auto* h2conn = new http2::Http2Connection();
        if (h2conn == nullptr) {
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tls::TlsConnection* tlsConnection = nullptr;
        http2::Http2Transport* transport = nullptr;
        http2::Http2PlainTransport plainTransport(socket);

        if (IsTlsMode(options.TransportMode)) {
            tlsConnection = new tls::TlsConnection();
            if (tlsConnection == nullptr) {
                delete h2conn;
                const NTSTATUS closeStatus = socket.Close();
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
            tlsOptions.AlpnProtocols = alpnProtocols;
            tlsOptions.AlpnProtocolCount = 2;

            status = tlsConnection->Connect(socket, tlsOptions);
            if (!NT_SUCCESS(status)) {
                kprintf("Http2Client TLS connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
                delete tlsConnection;
                delete h2conn;
                const NTSTATUS closeStatus = socket.Close();
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
                delete tlsConnection;
                delete h2conn;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_NOT_SUPPORTED;
            }

            auto* tlsTransport = new http2::Http2TlsTransport(socket, *tlsConnection);
            if (tlsTransport == nullptr) {
                delete tlsConnection;
                delete h2conn;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            transport = tlsTransport;
        } else {
            if (options.TransportMode == Http2TransportMode::H2cUpgrade) {
                status = PerformH2cUpgrade(socket, options);
                if (!NT_SUCCESS(status)) {
                    delete h2conn;
                    const NTSTATUS closeStatus = socket.Close();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return status;
                }
            }
            transport = &plainTransport;
        }

        status = h2conn->Initialize(*transport);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Client H2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
            if (IsTlsMode(options.TransportMode)) delete transport;
            delete tlsConnection;
            delete h2conn;
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        HeapArray<http::HttpHeader> requestHeaders(Http2MaxRequestHeaders);
        HeapArray<char> lowerHeaderNames(Http2MaxRequestHeaders * Http2MaxHeaderNameLength);
        HeapArray<char> contentLengthBuffer(Http2ContentLengthBufferLength);
        if (!requestHeaders.IsValid() || !lowerHeaderNames.IsValid() || !contentLengthBuffer.IsValid()) {
            h2conn->Shutdown(*transport);
            if (IsTlsMode(options.TransportMode)) delete transport;
            delete tlsConnection;
            delete h2conn;
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        auto lowerHeaderNameRows =
            reinterpret_cast<char (*)[Http2MaxHeaderNameLength]>(lowerHeaderNames.Get());
        SIZE_T headerCount = 0;
        status = BuildHttp2RequestHeaders(
            options,
            requestHeaders.Get(),
            Http2MaxRequestHeaders,
            lowerHeaderNameRows,
            contentLengthBuffer.Get(),
            &headerCount);
        if (!NT_SUCCESS(status)) {
            h2conn->Shutdown(*transport);
            if (IsTlsMode(options.TransportMode)) delete transport;
            delete tlsConnection;
            delete h2conn;
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        SIZE_T respHeaderCount = 0;
        SIZE_T respBodyLen = 0;
        USHORT respStatusCode = 0;

        status = h2conn->SendRequest(
            *transport,
            requestHeaders.Get(), headerCount,
            options.Body, options.BodyLength,
            buffers.Headers, buffers.HeaderCapacity,
            &respHeaderCount,
            buffers.BodyBuffer, buffers.BodyBufferLength,
            &respBodyLen,
            &respStatusCode,
            buffers.NameValueBuffer, buffers.NameValueBufferLength);

        if (NT_SUCCESS(status)) {
            response.StatusCode = respStatusCode;
            response.Headers = buffers.Headers;
            response.HeaderCount = respHeaderCount;
            response.Body = buffers.BodyBuffer;
            response.BodyLength = respBodyLen;
        } else {
            kprintf("Http2Client SendRequest failed: 0x%08X\r\n", static_cast<ULONG>(status));
        }

        h2conn->Shutdown(*transport);

        if (IsTlsMode(options.TransportMode)) delete transport;
        delete tlsConnection;
        delete h2conn;
        const NTSTATUS closeStatus = socket.Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }
}
}
