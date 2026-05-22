#include "client/Http2Client.h"

namespace KernelHttp
{
namespace client
{
    namespace
    {
        constexpr SIZE_T MaxRequestHeaders = 16;

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

            char temp[32] = {};
            SIZE_T tempLen = 0;
            do {
                if (tempLen >= sizeof(temp)) return false;
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
    }

    NTSTATUS Http2Client::SendRequest(
        net::WskClient& wskClient,
        const Http2RequestOptions& options,
        const Http2ResponseBuffers& buffers,
        Http2Response& response) noexcept
    {
        response = {};

        if (options.RemoteAddress == nullptr ||
            options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            options.CertificateStore == nullptr ||
            options.Path.Data == nullptr ||
            options.Path.Length == 0 ||
            buffers.Headers == nullptr ||
            buffers.HeaderCapacity == 0 ||
            buffers.NameValueBuffer == nullptr ||
            buffers.NameValueBufferLength == 0 ||
            buffers.BodyBuffer == nullptr ||
            buffers.BodyBufferLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        // Connect TCP
        net::WskSocket socket;
        NTSTATUS status = socket.Connect(wskClient, options.RemoteAddress);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Client connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        // TLS handshake with ALPN
        auto* tlsConnection = new tls::TlsConnection();
        if (tlsConnection == nullptr) {
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tls::TlsAlpnProtocol alpnProtocols[] = {
            { "h2", 2 },
            { "http/1.1", 8 }
        };

        tls::TlsClientConnectionOptions tlsOptions = {};
        tlsOptions.ServerName = options.ServerName;
        tlsOptions.ServerNameLength = options.ServerNameLength;
        tlsOptions.CertificateStore = options.CertificateStore;
        tlsOptions.AlpnProtocols = alpnProtocols;
        tlsOptions.AlpnProtocolCount = 2;

        status = tlsConnection->Connect(socket, tlsOptions);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Client TLS connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            delete tlsConnection;
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        // Check ALPN result
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
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_NOT_SUPPORTED;
        }

        // Initialize HTTP/2 connection
        auto* h2conn = new http2::Http2Connection();
        if (h2conn == nullptr) {
            delete tlsConnection;
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = h2conn->Initialize(socket, *tlsConnection);
        if (!NT_SUCCESS(status)) {
            kprintf("Http2Client H2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
            delete h2conn;
            delete tlsConnection;
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        // Build request pseudo-headers + headers
        http::HttpHeader requestHeaders[MaxRequestHeaders] = {};
        char lowerHeaderNames[MaxRequestHeaders][64] = {};
        char contentLengthBuffer[32] = {};
        SIZE_T headerIdx = 0;

        // :method
        const char* methodStr = HttpMethodToString(options.Method);
        requestHeaders[headerIdx].Name = { ":method", 7 };
        requestHeaders[headerIdx].Value = { methodStr, StringLen(methodStr) };
        ++headerIdx;

        // :scheme
        requestHeaders[headerIdx].Name = { ":scheme", 7 };
        requestHeaders[headerIdx].Value = { "https", 5 };
        ++headerIdx;

        // :path
        requestHeaders[headerIdx].Name = { ":path", 5 };
        requestHeaders[headerIdx].Value = options.Path;
        ++headerIdx;

        // :authority
        if (options.Authority.Data != nullptr && options.Authority.Length > 0) {
            requestHeaders[headerIdx].Name = { ":authority", 10 };
            requestHeaders[headerIdx].Value = options.Authority;
            ++headerIdx;
        } else {
            requestHeaders[headerIdx].Name = { ":authority", 10 };
            requestHeaders[headerIdx].Value = { options.ServerName, options.ServerNameLength };
            ++headerIdx;
        }

        // user-agent
        if (options.UserAgent.Data != nullptr && options.UserAgent.Length > 0) {
            requestHeaders[headerIdx].Name = { "user-agent", 10 };
            requestHeaders[headerIdx].Value = options.UserAgent;
            ++headerIdx;
        }

        // content-type
        if (options.ContentType.Data != nullptr && options.ContentType.Length > 0) {
            requestHeaders[headerIdx].Name = { "content-type", 12 };
            requestHeaders[headerIdx].Value = options.ContentType;
            ++headerIdx;
        }

        // content-length
        if (options.Body != nullptr && options.BodyLength > 0) {
            requestHeaders[headerIdx].Name = { "content-length", 14 };
            if (!WriteDecimal(options.BodyLength, contentLengthBuffer, sizeof(contentLengthBuffer), requestHeaders[headerIdx].Value)) {
                h2conn->Shutdown(socket, *tlsConnection);
                delete h2conn;
                delete tlsConnection;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INVALID_PARAMETER;
            }
            ++headerIdx;
        }

        // accept-encoding
        if (options.AcceptEncoding.Data != nullptr && options.AcceptEncoding.Length > 0) {
            requestHeaders[headerIdx].Name = { "accept-encoding", 15 };
            requestHeaders[headerIdx].Value = options.AcceptEncoding;
            ++headerIdx;
        }

        // Extra headers (up to capacity)
        for (SIZE_T i = 0; i < options.ExtraHeaderCount && headerIdx < MaxRequestHeaders; ++i) {
            if (IsForbiddenHttp2Header(options.ExtraHeaders[i].Name)) {
                continue;
            }
            requestHeaders[headerIdx].Value = options.ExtraHeaders[i].Value;
            if (!LowercaseHeaderName(
                options.ExtraHeaders[i].Name,
                lowerHeaderNames[headerIdx],
                sizeof(lowerHeaderNames[headerIdx]),
                requestHeaders[headerIdx].Name)) {
                h2conn->Shutdown(socket, *tlsConnection);
                delete h2conn;
                delete tlsConnection;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INVALID_PARAMETER;
            }
            ++headerIdx;
        }

        // Send request
        SIZE_T respHeaderCount = 0;
        SIZE_T respBodyLen = 0;
        USHORT respStatusCode = 0;

        status = h2conn->SendRequest(
            socket, *tlsConnection,
            requestHeaders, headerIdx,
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

        // Graceful shutdown
        h2conn->Shutdown(socket, *tlsConnection);

        delete h2conn;
        delete tlsConnection;
        const NTSTATUS closeStatus = socket.Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }
}
}