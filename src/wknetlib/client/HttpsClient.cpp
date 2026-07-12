#include "client/HttpsClient.h"
#include "transport/ProxyConnect.h"
#include "rtl/Irql.h"
#include "transport/TlsTransport.h"
#include "rtl/WorkspaceScratchAllocator.h"
#include "transport/WskTransport.h"
#include "session/Workspace.h"
#include "client/Http2Client.h"
#include "http1/HttpContentEncoding.h"
#include "http2/Http2Connection.h"

namespace wknet
{
namespace client
{
    namespace
    {
        bool AlpnIsH2(const char* alpn, SIZE_T len) noexcept
        {
            return len == 2 && alpn != nullptr && alpn[0] == 'h' && alpn[1] == '2';
        }

        _Must_inspect_result_
        bool IsTlsProtocolAllowed(
            tls::TlsProtocol minimum,
            tls::TlsProtocol maximum,
            tls::TlsProtocol protocol) noexcept
        {
            return static_cast<UCHAR>(minimum) <= static_cast<UCHAR>(protocol) &&
                static_cast<UCHAR>(protocol) <= static_cast<UCHAR>(maximum);
        }

        _Must_inspect_result_
        bool IsTls12ConfirmationCandidate(
            const HttpsRequestOptions& options,
            const tls::TlsHandshakeFailure& failure) noexcept
        {
            const bool failureCanConfirmTls12 =
                failure.Category == tls::TlsHandshakeFailureCategory::VersionNegotiation ||
                (failure.Category == tls::TlsHandshakeFailureCategory::NetworkIo &&
                    failure.BeforeTls13FirstServerHello &&
                    failure.Status != STATUS_IO_TIMEOUT);
            return IsTlsProtocolAllowed(options.MinimumTlsProtocol, options.MaximumTlsProtocol, tls::TlsProtocol::Tls12) &&
                IsTlsProtocolAllowed(options.MinimumTlsProtocol, options.MaximumTlsProtocol, tls::TlsProtocol::Tls13) &&
                failureCanConfirmTls12;
        }

        bool IsOrderlyConnectionCloseStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_CONNECTION_DISCONNECTED;
        }

        bool UsesProxyTunnel(const HttpsRequestOptions& options) noexcept
        {
            return options.ProxyAddress != nullptr;
        }

        _Must_inspect_result_
        bool IsValidProxyTunnelOptions(const HttpsRequestOptions& options) noexcept
        {
            if (!UsesProxyTunnel(options)) {
                return options.ProxyAuthority == nullptr &&
                    options.ProxyAuthorityLength == 0 &&
                    options.ProxyHeaders == nullptr &&
                    options.ProxyHeaderCount == 0;
            }

            return options.ProxyAuthority != nullptr &&
                options.ProxyAuthorityLength != 0 &&
                (options.ProxyHeaders != nullptr || options.ProxyHeaderCount == 0) &&
                (options.ProxyHeaders == nullptr || options.ProxyHeaderCount != 0);
        }

        _Must_inspect_result_
        bool IsNonFinalInformationalResponse(const http1::HttpResponse& response) noexcept
        {
            return response.StatusCode >= 100 &&
                response.StatusCode < 200 &&
                response.StatusCode != 101;
        }

        _Must_inspect_result_
        NTSTATUS DiscardNonFinalInformationalResponse(
            _Inout_updates_bytes_(*responseLength) char* responseBuffer,
            _Inout_ SIZE_T* responseLength,
            _Inout_ http1::HttpResponse& response,
            _Out_ bool* skipped) noexcept
        {
            if (skipped != nullptr) {
                *skipped = false;
            }
            if (responseBuffer == nullptr || responseLength == nullptr || skipped == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (!IsNonFinalInformationalResponse(response)) {
                return STATUS_SUCCESS;
            }
            if (response.BytesConsumed > *responseLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T remaining = *responseLength - response.BytesConsumed;
            if (remaining != 0) {
                RtlMoveMemory(responseBuffer, responseBuffer + response.BytesConsumed, remaining);
            }
            *responseLength = remaining;
            response = {};
            *skipped = true;
            return STATUS_SUCCESS;
        }

        http1::HttpText FindHeaderValue(const http1::HttpHeader* headers, SIZE_T headerCount, http1::HttpText name) noexcept
        {
            if (headers == nullptr) {
                return {};
            }

            for (SIZE_T index = 0; index < headerCount; ++index) {
                if (http1::TextEqualsIgnoreCase(headers[index].Name, name)) {
                    return headers[index].Value;
                }
            }

            return {};
        }

        struct Http2HeaderScratch final
        {
            http1::HttpHeader* Headers = nullptr;
            char (*LowerHeaderNames)[Http2MaxHeaderNameLength] = nullptr;
            char* ContentLengthBuffer = nullptr;
            UCHAR* Owned = nullptr;
            SIZE_T OwnedLength = 0;
        };

        void ReleaseHttp2HeaderScratch(_Inout_ Http2HeaderScratch& scratch) noexcept
        {
            if (scratch.Owned != nullptr) {
                RtlSecureZeroMemory(scratch.Owned, scratch.OwnedLength);
                FreeNonPagedArray(scratch.Owned);
            }

            scratch = {};
        }

        _Must_inspect_result_
        NTSTATUS PrepareHttp2HeaderScratch(
            _In_opt_ session::Workspace* workspace,
            _Out_ Http2HeaderScratch& scratch) noexcept
        {
            scratch = {};

            constexpr SIZE_T headersBytes = sizeof(http1::HttpHeader) * Http2MaxRequestHeaders;
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
                base = AllocateNonPagedArray<UCHAR>(totalBytes);
                if (base == nullptr) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                capacity = totalBytes;
                scratch.Owned = base;
                scratch.OwnedLength = capacity;
            }

            RtlZeroMemory(base, capacity);
            scratch.Headers = reinterpret_cast<http1::HttpHeader*>(base);
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
        http1::HttpResponse& response) noexcept
    {
        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            response = {};
            return status;
        }

        bool tls12ConfirmationCandidate = false;
        status = SendRequestOnce(
            wskClient,
            options,
            buffers,
            response,
            &tls12ConfirmationCandidate);
        if (NT_SUCCESS(status) || !tls12ConfirmationCandidate) {
            return status;
        }

        const NTSTATUS originalStatus = status;
        HttpsRequestOptions tls12Options = options;
        tls12Options.MaximumTlsProtocol = tls::TlsProtocol::Tls12;
        tls12Options.EnableEarlyData = false;
        tls12Options.EarlyDataReplaySafe = false;
        response = {};

        status = SendRequestOnce(
            wskClient,
            tls12Options,
            buffers,
            response,
            nullptr);
        if (NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Info, "HttpsClient TLS1.2 confirmed after version negotiation\r\n");
            return STATUS_SUCCESS;
        }

        WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error,
            "HttpsClient TLS1.2 confirmation failed: 0x%08X original=0x%08X\r\n",
            static_cast<ULONG>(status),
            static_cast<ULONG>(originalStatus));
        response = {};
        return originalStatus;
    }

    NTSTATUS HttpsClient::SendRequestOnce(
        net::WskClient& wskClient,
        const HttpsRequestOptions& options,
        const HttpsResponseBuffers& buffers,
        http1::HttpResponse& response,
        bool* tls12ConfirmationCandidate) noexcept
    {
        response = {};
        if (tls12ConfirmationCandidate != nullptr) {
            *tls12ConfirmationCandidate = false;
        }

        if (options.RemoteAddress == nullptr ||
            options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            (options.VerifyCertificate && options.CertificateStore == nullptr) ||
            buffers.RequestBuffer == nullptr ||
            buffers.RequestBufferLength == 0 ||
            buffers.ResponseBuffer == nullptr ||
            buffers.ResponseBufferLength == 0 ||
            buffers.Headers == nullptr ||
            buffers.HeaderCapacity == 0 ||
            (options.AlpnProtocols == nullptr && options.AlpnProtocolCount != 0) ||
            (options.AlpnProtocols != nullptr && options.AlpnProtocolCount == 0) ||
            options.MaxTls12Renegotiations > tls::Tls12HardMaxRenegotiations ||
            !IsValidProxyTunnelOptions(options)) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T requestLength = 0;
        NTSTATUS status = http1::HttpRequestBuilder::Build(
            options.Request,
            buffers.RequestBuffer,
            buffers.RequestBufferLength,
            &requestLength);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient build request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapObject<net::WskSocket> socket;
        if (!socket.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const SOCKADDR* connectAddress =
            UsesProxyTunnel(options) ? options.ProxyAddress : options.RemoteAddress;
        status = socket->Connect(wskClient, connectAddress);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        auto* tlsConnection = AllocateNonPagedObject<tls::TlsConnection>();
        if (tlsConnection == nullptr) {
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        auto* rawTransport = AllocateNonPagedObject<core::WskTransport>(*socket.Get());
        if (rawTransport == nullptr) {
            FreeNonPagedObject(tlsConnection);
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (UsesProxyTunnel(options)) {
            SIZE_T connectRequestLength = 0;
            transport::ProxyConnectRequestOptions connectOptions = {};
            connectOptions.Authority = { options.ProxyAuthority, options.ProxyAuthorityLength };
            connectOptions.UserAgent = options.Request.UserAgent;
            connectOptions.Headers = options.ProxyHeaders;
            connectOptions.HeaderCount = options.ProxyHeaderCount;
            status = transport::BuildProxyConnectRequest(
                connectOptions,
                buffers.RequestBuffer,
                buffers.RequestBufferLength,
                &connectRequestLength);
            if (!NT_SUCCESS(status)) {
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            SIZE_T sent = 0;
            status = rawTransport->Send(
                buffers.RequestBuffer,
                connectRequestLength,
                &sent);
            if (!NT_SUCCESS(status) || sent != connectRequestLength) {
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return NT_SUCCESS(status) ? STATUS_CONNECTION_DISCONNECTED : status;
            }

            http1::HttpResponse proxyResponse = {};
            status = ReadHttpResponse(*rawTransport, true, buffers, proxyResponse);
            if (!NT_SUCCESS(status)) {
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }
            if (!transport::IsSuccessfulProxyConnectResponse(proxyResponse)) {
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = http1::HttpRequestBuilder::Build(
                options.Request,
                buffers.RequestBuffer,
                buffers.RequestBufferLength,
                &requestLength);
            if (!NT_SUCCESS(status)) {
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }
        }

        core::WorkspaceScratchAllocator* handshakeScratch = nullptr;
        core::WorkspaceScratchAllocator* certificateScratch = nullptr;
        if (options.Workspace != nullptr) {
            handshakeScratch = AllocateNonPagedObject<core::WorkspaceScratchAllocator>(
                *options.Workspace,
                core::WorkspaceScratchAllocator::BufferKind::TlsHandshake);
            certificateScratch = AllocateNonPagedObject<core::WorkspaceScratchAllocator>(
                *options.Workspace,
                core::WorkspaceScratchAllocator::BufferKind::Certificate);
            if (handshakeScratch == nullptr || certificateScratch == nullptr) {
                FreeNonPagedObject(certificateScratch);
                FreeNonPagedObject(handshakeScratch);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
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
        tlsOptions.MinimumProtocol = options.MinimumTlsProtocol;
        tlsOptions.MaximumProtocol = options.MaximumTlsProtocol;
        tlsOptions.Policy = options.Policy;
        tlsOptions.SessionCache = options.SessionCache;
        tlsOptions.Tls12SessionCache = options.Tls12SessionCache;
        tlsOptions.ClientCredential = options.ClientCredential;
        tlsOptions.HandshakeScratchAllocator = handshakeScratch;
        tlsOptions.CertificateScratchAllocator = certificateScratch;
        tlsOptions.ProviderCache = options.ProviderCache;
        tlsOptions.EnableSessionResumption = options.EnableSessionResumption;
        tlsOptions.MaxTls12Renegotiations = options.MaxTls12Renegotiations;
        tlsOptions.EnableEarlyData = options.EnableEarlyData;
        tlsOptions.EarlyDataReplaySafe = options.EarlyDataReplaySafe;
        tlsOptions.EarlyDataBytesSent = options.EarlyDataBytesSent;
        tlsOptions.EarlyDataAccepted = options.EarlyDataAccepted;
        if (options.EnableEarlyData && !options.PreferHttp2) {
            tlsOptions.EarlyData = reinterpret_cast<const UCHAR*>(buffers.RequestBuffer);
            tlsOptions.EarlyDataLength = requestLength;
        }
        if (options.AlpnProtocols != nullptr && options.AlpnProtocolCount != 0) {
            tlsOptions.AlpnProtocols = options.AlpnProtocols;
            tlsOptions.AlpnProtocolCount = options.AlpnProtocolCount;
        }
        else if (options.PreferHttp2) {
            tlsOptions.AlpnProtocols = alpnProtocols;
            tlsOptions.AlpnProtocolCount = 2;
        }

        status = tlsConnection->Connect(*rawTransport, tlsOptions);
        FreeNonPagedObject(certificateScratch);
        FreeNonPagedObject(handshakeScratch);
        if (!NT_SUCCESS(status)) {
            if (tls12ConfirmationCandidate != nullptr &&
                IsTls12ConfirmationCandidate(options, tlsConnection->LastHandshakeFailure())) {
                *tls12ConfirmationCandidate = true;
            }
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient TLS connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            FreeNonPagedObject(rawTransport);
            FreeNonPagedObject(tlsConnection);
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        auto* tlsTransport = AllocateNonPagedObject<core::TlsTransport>(*rawTransport, *tlsConnection);
        if (tlsTransport == nullptr) {
            FreeNonPagedObject(rawTransport);
            FreeNonPagedObject(tlsConnection);
            const NTSTATUS closeStatus = socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Check ALPN negotiation result
        const char* alpn = tlsConnection->NegotiatedAlpn();
        SIZE_T alpnLen = tlsConnection->NegotiatedAlpnLength();

        if (options.PreferHttp2 && AlpnIsH2(alpn, alpnLen)) {
            if (buffers.HeaderNameValueBuffer == nullptr ||
                buffers.HeaderNameValueBufferLength == 0) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient H2 missing header name/value buffer\r\n");
                FreeNonPagedObject(tlsTransport);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INVALID_PARAMETER;
            }

            auto* h2conn = AllocateNonPagedObject<http2::Http2Connection>();
            if (h2conn == nullptr) {
                FreeNonPagedObject(tlsTransport);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = h2conn->Initialize(*tlsTransport);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient H2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
                FreeNonPagedObject(h2conn);
                FreeNonPagedObject(tlsTransport);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
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
                http1::MakeText("Accept-Encoding"));
            h2Options.ExtraHeaders = options.Request.ExtraHeaders;
            h2Options.ExtraHeaderCount = options.Request.ExtraHeaderCount;
            h2Options.Body = reinterpret_cast<const UCHAR*>(options.Request.Body);
            h2Options.BodyLength = options.Request.BodyLength;
            h2Options.IncludeContentLength = options.Request.IncludeContentLength;

            HeapObject<Http2HeaderScratch> h2Scratch;
            if (!h2Scratch.IsValid()) {
                h2conn->Shutdown(*tlsTransport);
                FreeNonPagedObject(h2conn);
                FreeNonPagedObject(tlsTransport);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = PrepareHttp2HeaderScratch(options.Workspace, *h2Scratch.Get());
            if (!NT_SUCCESS(status)) {
                h2conn->Shutdown(*tlsTransport);
                FreeNonPagedObject(h2conn);
                FreeNonPagedObject(tlsTransport);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }
            SIZE_T h2HeaderCount = 0;

            status = BuildHttp2RequestHeaders(
                h2Options,
                h2Scratch->Headers,
                Http2MaxRequestHeaders,
                h2Scratch->LowerHeaderNames,
                h2Scratch->ContentLengthBuffer,
                &h2HeaderCount);
            if (!NT_SUCCESS(status)) {
                ReleaseHttp2HeaderScratch(*h2Scratch.Get());
                h2conn->Shutdown(*tlsTransport);
                FreeNonPagedObject(h2conn);
                FreeNonPagedObject(tlsTransport);
                FreeNonPagedObject(rawTransport);
                FreeNonPagedObject(tlsConnection);
                const NTSTATUS closeStatus = socket->Close();
                UNREFERENCED_PARAMETER(closeStatus);
                return status;
            }

            SIZE_T respHeaderCount = 0;
            SIZE_T respBodyLen = 0;
            USHORT respStatusCode = 0;

            status = h2conn->SendRequest(
                *tlsTransport,
                h2Scratch->Headers, h2HeaderCount,
                reinterpret_cast<const UCHAR*>(options.Request.Body),
                options.Request.BodyLength,
                buffers.Headers, buffers.HeaderCapacity,
                &respHeaderCount,
                buffers.ResponseBuffer, buffers.ResponseBufferLength,
                &respBodyLen,
                &respStatusCode,
                buffers.HeaderNameValueBuffer,
                buffers.HeaderNameValueBufferLength);

            http1::HttpContentDecodeResult decoded = {};
            if (NT_SUCCESS(status)) {
                http1::HttpContentDecodeBuffers decodeBuffers = {};
                decodeBuffers.DecodedBody = buffers.DecodedBodyBuffer;
                decodeBuffers.DecodedBodyCapacity = buffers.DecodedBodyBufferLength;
                decodeBuffers.ScratchBody = buffers.ScratchBodyBuffer;
                decodeBuffers.ScratchBodyCapacity = buffers.ScratchBodyBufferLength;

                status = http1::HttpContentEncoding::Decode(
                    buffers.Headers,
                    respHeaderCount,
                    buffers.ResponseBuffer,
                    respBodyLen,
                    decodeBuffers,
                    decoded);
                if (!NT_SUCCESS(status)) {
                    WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient H2 content decode failed: 0x%08X\r\n", static_cast<ULONG>(status));
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
                response.BodyKind = http1::HttpBodyKind::ContentLength;
            } else {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient H2 request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            }

            ReleaseHttp2HeaderScratch(*h2Scratch.Get());
            h2conn->Shutdown(*tlsTransport);
            FreeNonPagedObject(h2conn);
        } else {
            SIZE_T sent = 0;
            status = tlsConnection->Send(*rawTransport, buffers.RequestBuffer, requestLength, &sent);
            if (NT_SUCCESS(status) && sent != requestLength) {
                status = STATUS_CONNECTION_DISCONNECTED;
            }
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient TLS send failed: 0x%08X sent=%Iu expected=%Iu\r\n",
                    static_cast<ULONG>(status),
                    sent,
                    requestLength);
            }

            if (NT_SUCCESS(status)) {
                status = ReadHttpResponse(*tlsTransport, options.ResponseBodyForbidden, buffers, response);
                if (!NT_SUCCESS(status)) {
                    WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient read response failed: 0x%08X\r\n", static_cast<ULONG>(status));
                }
            }
        }

        FreeNonPagedObject(tlsTransport);
        FreeNonPagedObject(rawTransport);
        FreeNonPagedObject(tlsConnection);
        const NTSTATUS closeStatus = socket->Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }

    NTSTATUS HttpsClient::ReadHttpResponse(
        core::ITransport& transport,
        bool responseBodyForbidden,
        const HttpsResponseBuffers& buffers,
        http1::HttpResponse& response) noexcept
    {
        SIZE_T responseLength = 0;

        for (;;) {
            http1::HttpParseOptions parseOptions = {};
            parseOptions.Headers = buffers.Headers;
            parseOptions.HeaderCapacity = buffers.HeaderCapacity;
            parseOptions.DecodedBody = buffers.DecodedBodyBuffer;
            parseOptions.DecodedBodyCapacity = buffers.DecodedBodyBufferLength;
            parseOptions.ScratchBody = buffers.ScratchBodyBuffer;
            parseOptions.ScratchBodyCapacity = buffers.ScratchBodyBufferLength;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;

            NTSTATUS status = http1::HttpParser::ParseResponse(
                buffers.ResponseBuffer,
                responseLength,
                parseOptions,
                response);
            if (status == STATUS_SUCCESS) {
                bool skippedInformational = false;
                status = DiscardNonFinalInformationalResponse(
                    buffers.ResponseBuffer,
                    &responseLength,
                    response,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (skippedInformational) {
                    continue;
                }
                return STATUS_SUCCESS;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient parse response failed: 0x%08X bytes=%Iu\r\n",
                    static_cast<ULONG>(status),
                    responseLength);
                return status;
            }

            if (responseLength >= buffers.ResponseBufferLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T received = 0;
            status = transport.Receive(
                buffers.ResponseBuffer + responseLength,
                buffers.ResponseBufferLength - responseLength,
                &received);
            if (!NT_SUCCESS(status)) {
                if (!IsOrderlyConnectionCloseStatus(status)) {
                    WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "HttpsClient receive failed: 0x%08X bytes=%Iu\r\n",
                        static_cast<ULONG>(status),
                        responseLength);
                    return status;
                }

                parseOptions.MessageCompleteOnConnectionClose = true;
                for (;;) {
                    status = http1::HttpParser::ParseResponse(
                        buffers.ResponseBuffer,
                        responseLength,
                        parseOptions,
                        response);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        buffers.ResponseBuffer,
                        &responseLength,
                        response,
                        &skippedInformational);
                    if (!NT_SUCCESS(status) || !skippedInformational) {
                        return status;
                    }
                }
            }

            if (received == 0) {
                parseOptions.MessageCompleteOnConnectionClose = true;
                for (;;) {
                    status = http1::HttpParser::ParseResponse(
                        buffers.ResponseBuffer,
                        responseLength,
                        parseOptions,
                        response);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        buffers.ResponseBuffer,
                        &responseLength,
                        response,
                        &skippedInformational);
                    if (!NT_SUCCESS(status) || !skippedInformational) {
                        return status;
                    }
                }
            }

            responseLength += received;
        }
    }
}
}
