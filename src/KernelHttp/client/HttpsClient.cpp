#include "client/HttpsClient.h"
#include "http2/Http2Connection.h"

namespace KernelHttp
{
namespace client
{
    namespace
    {
        bool AlpnIsH2(const char* alpn, SIZE_T len) noexcept
        {
            return len == 2 && alpn != nullptr && alpn[0] == 'h' && alpn[1] == '2';
        }

        SIZE_T StringLen(const char* value) noexcept
        {
            SIZE_T length = 0;
            if (value == nullptr) return 0;
            while (value[length] != '\0') ++length;
            return length;
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

    NTSTATUS HttpsClient::SendRequest(
        net::WskClient& wskClient,
        const HttpsRequestOptions& options,
        const HttpsResponseBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        response = {};

        if (options.RemoteAddress == nullptr ||
            options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            options.CertificateStore == nullptr ||
            buffers.RequestBuffer == nullptr ||
            buffers.RequestBufferLength == 0 ||
            buffers.ResponseBuffer == nullptr ||
            buffers.ResponseBufferLength == 0 ||
            buffers.Headers == nullptr ||
            buffers.HeaderCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T requestLength = 0;
        NTSTATUS status = http::HttpRequestBuilder::Build(
            options.Request,
            buffers.RequestBuffer,
            buffers.RequestBufferLength,
            &requestLength);
        if (!NT_SUCCESS(status)) {
            kprintf("HttpsClient build request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        net::WskSocket socket;
        status = socket.Connect(wskClient, options.RemoteAddress);
        if (!NT_SUCCESS(status)) {
            kprintf("HttpsClient connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

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
        if (options.PreferHttp2) {
            tlsOptions.AlpnProtocols = alpnProtocols;
            tlsOptions.AlpnProtocolCount = 2;
        }

        status = tlsConnection->Connect(socket, tlsOptions);
        if (!NT_SUCCESS(status)) {
            kprintf("HttpsClient TLS connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            delete tlsConnection;
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        // Check ALPN negotiation result
        const char* alpn = tlsConnection->NegotiatedAlpn();
        SIZE_T alpnLen = tlsConnection->NegotiatedAlpnLength();

        if (options.PreferHttp2 && AlpnIsH2(alpn, alpnLen)) {
            // HTTP/2 path
            auto* h2conn = new http2::Http2Connection();
            if (h2conn == nullptr) {
                delete tlsConnection;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = h2conn->Initialize(socket, *tlsConnection);
            if (!NT_SUCCESS(status)) {
                kprintf("HttpsClient H2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
                delete h2conn;
                delete tlsConnection;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            // Build HTTP/2 pseudo-headers + headers from the HTTP/1.1 request options
            constexpr SIZE_T MaxH2Headers = 16;
            http::HttpHeader h2Headers[MaxH2Headers] = {};
            char lowerHeaderNames[MaxH2Headers][64] = {};
            char contentLengthBuffer[32] = {};
            SIZE_T h2Idx = 0;

            const char* methodStr = "GET";
            switch (options.Request.Method) {
            case http::HttpMethod::Post: methodStr = "POST"; break;
            case http::HttpMethod::Put: methodStr = "PUT"; break;
            case http::HttpMethod::Patch: methodStr = "PATCH"; break;
            case http::HttpMethod::DeleteMethod: methodStr = "DELETE"; break;
            case http::HttpMethod::Head: methodStr = "HEAD"; break;
            case http::HttpMethod::Options: methodStr = "OPTIONS"; break;
            default: break;
            }

            SIZE_T methodLen = 0;
            while (methodStr[methodLen] != '\0') ++methodLen;

            h2Headers[h2Idx].Name = { ":method", 7 };
            h2Headers[h2Idx].Value = { methodStr, methodLen };
            ++h2Idx;

            h2Headers[h2Idx].Name = { ":scheme", 7 };
            h2Headers[h2Idx].Value = { "https", 5 };
            ++h2Idx;

            h2Headers[h2Idx].Name = { ":path", 5 };
            h2Headers[h2Idx].Value = options.Request.Path;
            ++h2Idx;

            h2Headers[h2Idx].Name = { ":authority", 10 };
            h2Headers[h2Idx].Value = options.Request.Host;
            ++h2Idx;

            if (options.Request.UserAgent.Data != nullptr && options.Request.UserAgent.Length > 0) {
                h2Headers[h2Idx].Name = { "user-agent", 10 };
                h2Headers[h2Idx].Value = options.Request.UserAgent;
                ++h2Idx;
            }

            if (options.Request.ContentType.Data != nullptr && options.Request.ContentType.Length > 0) {
                h2Headers[h2Idx].Name = { "content-type", 12 };
                h2Headers[h2Idx].Value = options.Request.ContentType;
                ++h2Idx;
            }

            if (options.Request.Body != nullptr && options.Request.BodyLength > 0) {
                h2Headers[h2Idx].Name = { "content-length", 14 };
                if (!WriteDecimal(options.Request.BodyLength, contentLengthBuffer, sizeof(contentLengthBuffer), h2Headers[h2Idx].Value)) {
                    delete h2conn;
                    delete tlsConnection;
                    const NTSTATUS closeStatus = socket.Close();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return STATUS_INVALID_PARAMETER;
                }
                ++h2Idx;
            }

            for (SIZE_T i = 0; i < options.Request.ExtraHeaderCount && h2Idx < MaxH2Headers; ++i) {
                if (IsForbiddenHttp2Header(options.Request.ExtraHeaders[i].Name)) {
                    continue;
                }
                h2Headers[h2Idx].Value = options.Request.ExtraHeaders[i].Value;
                if (!LowercaseHeaderName(
                    options.Request.ExtraHeaders[i].Name,
                    lowerHeaderNames[h2Idx],
                    sizeof(lowerHeaderNames[h2Idx]),
                    h2Headers[h2Idx].Name)) {
                    delete h2conn;
                    delete tlsConnection;
                    const NTSTATUS closeStatus = socket.Close();
                    UNREFERENCED_PARAMETER(closeStatus);
                    return STATUS_INVALID_PARAMETER;
                }
                ++h2Idx;
            }

            // Use response buffer as name-value scratch space for HPACK decoding
            SIZE_T respHeaderCount = 0;
            SIZE_T respBodyLen = 0;
            USHORT respStatusCode = 0;

            status = h2conn->SendRequest(
                socket, *tlsConnection,
                h2Headers, h2Idx,
                reinterpret_cast<const UCHAR*>(options.Request.Body),
                options.Request.BodyLength,
                buffers.Headers, buffers.HeaderCapacity,
                &respHeaderCount,
                buffers.ResponseBuffer, buffers.ResponseBufferLength,
                &respBodyLen,
                &respStatusCode,
                buffers.DecodedBodyBuffer,
                buffers.DecodedBodyBufferLength);

            if (NT_SUCCESS(status)) {
                response.MajorVersion = 2;
                response.MinorVersion = 0;
                response.StatusCode = respStatusCode;
                response.Headers = buffers.Headers;
                response.HeaderCount = respHeaderCount;
                response.Body = buffers.ResponseBuffer;
                response.BodyLength = respBodyLen;
                response.BodyKind = http::HttpBodyKind::ContentLength;
            } else {
                kprintf("HttpsClient H2 request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            }

            h2conn->Shutdown(socket, *tlsConnection);
            delete h2conn;
        } else {
            // HTTP/1.1 path (original behavior)
            SIZE_T sent = 0;
            status = tlsConnection->Send(socket, buffers.RequestBuffer, requestLength, &sent);
            if (NT_SUCCESS(status) && sent != requestLength) {
                status = STATUS_CONNECTION_DISCONNECTED;
            }
            if (!NT_SUCCESS(status)) {
                kprintf("HttpsClient TLS send failed: 0x%08X sent=%Iu expected=%Iu\r\n",
                    static_cast<ULONG>(status),
                    sent,
                    requestLength);
            }

            if (NT_SUCCESS(status)) {
                status = ReadHttpResponse(socket, *tlsConnection, options.ResponseBodyForbidden, buffers, response);
                if (!NT_SUCCESS(status)) {
                    kprintf("HttpsClient read response failed: 0x%08X\r\n", static_cast<ULONG>(status));
                }
            }
        }

        delete tlsConnection;
        const NTSTATUS closeStatus = socket.Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }

    NTSTATUS HttpsClient::ReadHttpResponse(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        bool responseBodyForbidden,
        const HttpsResponseBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        SIZE_T responseLength = 0;

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = buffers.Headers;
            parseOptions.HeaderCapacity = buffers.HeaderCapacity;
            parseOptions.DecodedBody = buffers.DecodedBodyBuffer;
            parseOptions.DecodedBodyCapacity = buffers.DecodedBodyBufferLength;
            parseOptions.ScratchBody = buffers.ScratchBodyBuffer;
            parseOptions.ScratchBodyCapacity = buffers.ScratchBodyBufferLength;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;

            NTSTATUS status = http::HttpParser::ParseResponse(
                buffers.ResponseBuffer,
                responseLength,
                parseOptions,
                response);
            if (status == STATUS_SUCCESS) {
                return STATUS_SUCCESS;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                kprintf("HttpsClient parse response failed: 0x%08X bytes=%Iu\r\n",
                    static_cast<ULONG>(status),
                    responseLength);
                return status;
            }

            if (responseLength >= buffers.ResponseBufferLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T received = 0;
            status = tls.Receive(
                socket,
                buffers.ResponseBuffer + responseLength,
                buffers.ResponseBufferLength - responseLength,
                &received);
            if (!NT_SUCCESS(status)) {
                if (status != STATUS_CONNECTION_DISCONNECTED) {
                    kprintf("HttpsClient receive failed: 0x%08X bytes=%Iu\r\n",
                        static_cast<ULONG>(status),
                        responseLength);
                    return status;
                }

                parseOptions.MessageCompleteOnConnectionClose = true;
                return http::HttpParser::ParseResponse(
                    buffers.ResponseBuffer,
                    responseLength,
                    parseOptions,
                    response);
            }

            if (received == 0) {
                parseOptions.MessageCompleteOnConnectionClose = true;
                return http::HttpParser::ParseResponse(
                    buffers.ResponseBuffer,
                    responseLength,
                    parseOptions,
                    response);
            }

            responseLength += received;
        }
    }
}
}
