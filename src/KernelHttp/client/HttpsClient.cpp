#include "client/HttpsClient.h"
#include "api/KernelHttpWorkspace.h"
#include "client/Http2Client.h"
#include "http/HttpContentEncoding.h"
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

        http::HttpText FindHeaderValue(const http::HttpHeader* headers, SIZE_T headerCount, http::HttpText name) noexcept
        {
            if (headers == nullptr) {
                return {};
            }

            for (SIZE_T index = 0; index < headerCount; ++index) {
                if (http::TextEqualsIgnoreCase(headers[index].Name, name)) {
                    return headers[index].Value;
                }
            }

            return {};
        }

        struct Http2HeaderScratch final
        {
            http::HttpHeader* Headers = nullptr;
            char (*LowerHeaderNames)[Http2MaxHeaderNameLength] = nullptr;
            char* ContentLengthBuffer = nullptr;
            UCHAR* Owned = nullptr;
            SIZE_T OwnedLength = 0;
        };

        void ReleaseHttp2HeaderScratch(_Inout_ Http2HeaderScratch& scratch) noexcept
        {
            if (scratch.Owned != nullptr) {
                RtlSecureZeroMemory(scratch.Owned, scratch.OwnedLength);
                delete[] scratch.Owned;
            }

            scratch = {};
        }

        _Must_inspect_result_
        NTSTATUS PrepareHttp2HeaderScratch(
            _In_opt_ api::KhWorkspace* workspace,
            _Out_ Http2HeaderScratch& scratch) noexcept
        {
            scratch = {};

            constexpr SIZE_T headersBytes = sizeof(http::HttpHeader) * Http2MaxRequestHeaders;
            constexpr SIZE_T lowerNamesBytes = Http2MaxRequestHeaders * Http2MaxHeaderNameLength;
            constexpr SIZE_T totalBytes = headersBytes + lowerNamesBytes + Http2ContentLengthBufferLength;

            UCHAR* base = nullptr;
            SIZE_T capacity = 0;
            if (workspace != nullptr) {
                base = workspace->Http2HeaderScratch.Data;
                capacity = workspace->Http2HeaderScratch.Length;
                if (base == nullptr || capacity < totalBytes) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
            }
            else {
                base = new UCHAR[totalBytes];
                if (base == nullptr) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                capacity = totalBytes;
                scratch.Owned = base;
                scratch.OwnedLength = capacity;
            }

            RtlZeroMemory(base, capacity);
            scratch.Headers = reinterpret_cast<http::HttpHeader*>(base);
            scratch.LowerHeaderNames =
                reinterpret_cast<char (*)[Http2MaxHeaderNameLength]>(base + headersBytes);
            scratch.ContentLengthBuffer =
                reinterpret_cast<char*>(base + headersBytes + lowerNamesBytes);
            return STATUS_SUCCESS;
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
            (options.VerifyCertificate && options.CertificateStore == nullptr) ||
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
        tlsOptions.VerifyCertificate = options.VerifyCertificate;
        tlsOptions.MinimumProtocol = options.MinimumTlsProtocol;
        tlsOptions.MaximumProtocol = options.MaximumTlsProtocol;
        tlsOptions.SessionCache = options.SessionCache;
        tlsOptions.Workspace = options.Workspace;
        tlsOptions.ProviderCache = options.ProviderCache;
        tlsOptions.EnableSessionResumption = options.EnableSessionResumption;
        tlsOptions.EnableEarlyData = options.EnableEarlyData;
        if (options.EnableEarlyData && !options.PreferHttp2) {
            tlsOptions.EarlyData = reinterpret_cast<const UCHAR*>(buffers.RequestBuffer);
            tlsOptions.EarlyDataLength = requestLength;
        }
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
            http2::Http2TlsTransport transport(socket, *tlsConnection);
            http2::Http2Connection h2conn;

            status = h2conn.Initialize(transport);
            if (!NT_SUCCESS(status)) {
                kprintf("HttpsClient H2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
                delete tlsConnection;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            Http2RequestOptions h2Options = {};
            h2Options.TransportMode = Http2TransportMode::TlsAlpn;
            h2Options.ServerName = options.ServerName;
            h2Options.ServerNameLength = options.ServerNameLength;
            h2Options.Method = options.Request.Method;
            h2Options.Path = options.Request.Path;
            h2Options.Authority = options.Request.Host;
            h2Options.UserAgent = options.Request.UserAgent;
            h2Options.ContentType = options.Request.ContentType;
            h2Options.AcceptEncoding = FindHeaderValue(
                options.Request.ExtraHeaders,
                options.Request.ExtraHeaderCount,
                http::MakeText("Accept-Encoding"));
            h2Options.ExtraHeaders = options.Request.ExtraHeaders;
            h2Options.ExtraHeaderCount = options.Request.ExtraHeaderCount;
            h2Options.Body = reinterpret_cast<const UCHAR*>(options.Request.Body);
            h2Options.BodyLength = options.Request.BodyLength;

            Http2HeaderScratch h2Scratch = {};
            status = PrepareHttp2HeaderScratch(options.Workspace, h2Scratch);
            if (!NT_SUCCESS(status)) {
                h2conn.Shutdown(transport);
                delete tlsConnection;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }
            SIZE_T h2HeaderCount = 0;

            status = BuildHttp2RequestHeaders(
                h2Options,
                h2Scratch.Headers,
                Http2MaxRequestHeaders,
                h2Scratch.LowerHeaderNames,
                h2Scratch.ContentLengthBuffer,
                &h2HeaderCount);
            if (!NT_SUCCESS(status)) {
                ReleaseHttp2HeaderScratch(h2Scratch);
                h2conn.Shutdown(transport);
                delete tlsConnection;
                const NTSTATUS closeStatus = socket.Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            SIZE_T respHeaderCount = 0;
            SIZE_T respBodyLen = 0;
            USHORT respStatusCode = 0;

            status = h2conn.SendRequest(
                transport,
                h2Scratch.Headers, h2HeaderCount,
                reinterpret_cast<const UCHAR*>(options.Request.Body),
                options.Request.BodyLength,
                buffers.Headers, buffers.HeaderCapacity,
                &respHeaderCount,
                buffers.ResponseBuffer, buffers.ResponseBufferLength,
                &respBodyLen,
                &respStatusCode,
                buffers.DecodedBodyBuffer,
                buffers.DecodedBodyBufferLength);

            http::HttpContentDecodeResult decoded = {};
            if (NT_SUCCESS(status)) {
                http::HttpContentDecodeBuffers decodeBuffers = {};
                decodeBuffers.DecodedBody = buffers.DecodedBodyBuffer;
                decodeBuffers.DecodedBodyCapacity = buffers.DecodedBodyBufferLength;
                decodeBuffers.ScratchBody = buffers.ScratchBodyBuffer;
                decodeBuffers.ScratchBodyCapacity = buffers.ScratchBodyBufferLength;

                status = http::HttpContentEncoding::Decode(
                    buffers.Headers,
                    respHeaderCount,
                    buffers.ResponseBuffer,
                    respBodyLen,
                    decodeBuffers,
                    decoded);
                if (!NT_SUCCESS(status)) {
                    kprintf("HttpsClient H2 content decode failed: 0x%08X\r\n", static_cast<ULONG>(status));
                }
            }

            if (NT_SUCCESS(status)) {
                response.MajorVersion = 2;
                response.MinorVersion = 0;
                response.StatusCode = respStatusCode;
                response.Headers = buffers.Headers;
                response.HeaderCount = respHeaderCount;
                response.Body = decoded.Body;
                response.BodyLength = decoded.BodyLength;
                response.BytesConsumed = respBodyLen;
                response.BodyKind = http::HttpBodyKind::ContentLength;
            } else {
                kprintf("HttpsClient H2 request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            }

            ReleaseHttp2HeaderScratch(h2Scratch);
            h2conn.Shutdown(transport);
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
