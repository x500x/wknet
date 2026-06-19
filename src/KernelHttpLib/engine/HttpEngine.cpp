#include <KernelHttp/engine/HttpEngine.h>
#include <KernelHttp/client/ProxyTunnel.h>
#include <KernelHttp/core/TlsTransport.h>
#include <KernelHttp/core/WorkspaceScratchAllocator.h>
#include <KernelHttp/core/WskTransport.h>
#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/engine/EngineImpl.h>
#include <KernelHttp/engine/HandleAlloc.h>
#include <KernelHttp/http/HttpCoding.h>
#include <KernelHttp/http/HttpContentEncoding.h>
#include <KernelHttp/http/HttpParser.h>
#include <KernelHttp/http/HttpRequest.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/TlsConnection.h>

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
#include <ws2ipdef.h>
#endif

namespace KernelHttp
{
namespace engine
{
    constexpr SIZE_T KhHttpRequestHeaderScratchBytes =
        sizeof(http::HttpHeader) * KhMaxHeadersPerRequest;
    constexpr SIZE_T KhHttpRequestTrailerScratchBytes =
        sizeof(http::HttpHeader) * KhMaxHeadersPerRequest;
    constexpr SIZE_T KhHttpResponseHeaderScratchBytes =
        sizeof(http::HttpHeader) * KhMaxHeadersPerResponse;
    constexpr SIZE_T KhHttpResponseTrailerScratchBytes =
        sizeof(http::HttpHeader) * KhMaxTrailersPerResponse;
    constexpr SIZE_T KhHttpHostHeaderScratchBytes =
        KhMaxHostHeaderLength;
    constexpr SIZE_T KhHttpHeaderScratchRequiredBytes =
        KhHttpRequestHeaderScratchBytes +
        KhHttpRequestTrailerScratchBytes +
        KhHttpResponseHeaderScratchBytes +
        KhHttpResponseTrailerScratchBytes +
        KhHttpHostHeaderScratchBytes;
    constexpr char KhDefaultAcceptEncoding[] = "gzip, deflate, br, identity";
    constexpr char KhDeflateUnavailableAcceptEncoding[] = "br, identity";
    constexpr SIZE_T KhWorkspaceCacheMaxRetainedBytes = 256 * 1024;

    constexpr SIZE_T KhHttp2HeaderScratchBytes =
        sizeof(http::HttpHeader) * client::Http2MaxRequestHeaders;
    constexpr SIZE_T KhHttp2ExtraHeaderScratchBytes =
        sizeof(http::HttpHeader) * client::Http2MaxRequestHeaders;
    constexpr SIZE_T KhHttp2LowerHeaderScratchBytes =
        client::Http2MaxRequestHeaders * client::Http2MaxHeaderNameLength;
    constexpr SIZE_T KhHttp2RequestScratchBytes =
        KhHttp2HeaderScratchBytes +
        KhHttp2ExtraHeaderScratchBytes +
        KhHttp2LowerHeaderScratchBytes +
        client::Http2ContentLengthBufferLength;

    struct ApiHttp2Scratch final
    {
        http::HttpHeader* Headers = nullptr;
        http::HttpHeader* ExtraHeaders = nullptr;
        char (*LowerHeaderNames)[client::Http2MaxHeaderNameLength] = nullptr;
        char* ContentLengthBuffer = nullptr;
        char* AuthorityBuffer = nullptr;
        SIZE_T AuthorityCapacity = 0;
    };

    struct ApiHttpHeaderScratch final
    {
        http::HttpHeader* RequestHeaders = nullptr;
        http::HttpHeader* RequestTrailers = nullptr;
        http::HttpHeader* ResponseHeaders = nullptr;
        http::HttpHeader* ResponseTrailers = nullptr;
        char* HostHeader = nullptr;
        SIZE_T HostHeaderCapacity = 0;
    };

    struct RedirectOriginSnapshot final
    {
        char Scheme[KhMaxSchemeLength + 1] = {};
        char Host[KhMaxHostLength + 1] = {};
    };

    _Must_inspect_result_
    NTSTATUS GrowDecodedBodyAfterBufferTooSmall(_Inout_ KhWorkspace& workspace) noexcept;

    http::HttpText DefaultAcceptEncoding() noexcept
    {
        return http::MakeText(
            http::HttpCodingCodec::DeflateRuntimeAvailable() ?
                KhDefaultAcceptEncoding :
                KhDeflateUnavailableAcceptEncoding);
    }

    _Ret_maybenull_
    KhWorkspace* ExchangeSessionWorkspace(_In_ KH_SESSION session, _In_opt_ KhWorkspace* workspace) noexcept
    {
        if (session == nullptr) {
            return nullptr;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        KhWorkspace* previous = session->Workspace;
        session->Workspace = workspace;
        return previous;
#else
        return static_cast<KhWorkspace*>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&session->Workspace),
            workspace));
#endif
    }

    _Ret_maybenull_
    KhWorkspace* CompareExchangeSessionWorkspace(
        _In_ KH_SESSION session,
        _In_opt_ KhWorkspace* workspace,
        _In_opt_ KhWorkspace* expected) noexcept
    {
        if (session == nullptr) {
            return nullptr;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        KhWorkspace* previous = session->Workspace;
        if (previous == expected) {
            session->Workspace = workspace;
        }
        return previous;
#else
        return static_cast<KhWorkspace*>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&session->Workspace),
            workspace,
            expected));
#endif
    }

    SIZE_T WorkspaceRetainedBytes(_In_ const KhWorkspace& workspace) noexcept
    {
        return workspace.Request.Length +
            workspace.Response.Length +
            workspace.DecodedBody.Length +
            workspace.HttpHeaderScratch.Length +
            workspace.Http2HeaderScratch.Length +
            workspace.TlsHandshakeScratch.Length +
            workspace.CertificateScratch.Length +
            workspace.WebSocketFrameScratch.Length +
            workspace.WebSocketSendFrameScratch.Length +
            workspace.WebSocketPayloadScratch.Length;
    }

    bool CanCacheRequestWorkspace(
        _In_ const KhWorkspace& workspace,
        SIZE_T requestBufferBytes) noexcept
    {
        return workspace.PoolType == KhPoolType::NonPaged &&
            workspace.Request.Length >= requestBufferBytes &&
            WorkspaceRetainedBytes(workspace) <= KhWorkspaceCacheMaxRetainedBytes;
    }

    NTSTATUS AcquireRequestWorkspace(
        _In_ KH_SESSION session,
        SIZE_T maxResponseBytes,
        _Outptr_ KhWorkspace** workspace) noexcept
    {
        if (session == nullptr || workspace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *workspace = nullptr;

        KhWorkspace* cached = ExchangeSessionWorkspace(session, nullptr);
        if (cached != nullptr) {
            if (cached->Request.Length >= session->Options.RequestBufferBytes) {
                cached->MaxResponseBytes = maxResponseBytes;
                KhWorkspaceReset(cached);
                *workspace = cached;
                return STATUS_SUCCESS;
            }

            KhWorkspaceReleaseToLookaside(cached, &session->WorkspaceLookaside);
        }

        KhWorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = KhPoolType::NonPaged;
        workspaceOptions.RequestBufferBytes = session->Options.RequestBufferBytes;
        workspaceOptions.MaxResponseBytes = maxResponseBytes;
        return KhWorkspaceCreateFromLookaside(
            &workspaceOptions,
            &session->WorkspaceLookaside,
            workspace);
    }

    void ReleaseRequestWorkspace(_In_ KH_SESSION session, _In_opt_ KhWorkspace* workspace) noexcept
    {
        if (workspace == nullptr) {
            return;
        }

        if (session == nullptr ||
            !CanCacheRequestWorkspace(*workspace, session->Options.RequestBufferBytes)) {
            KhWorkspaceReleaseToLookaside(workspace, session != nullptr ? &session->WorkspaceLookaside : nullptr);
            return;
        }

        workspace->MaxResponseBytes = session->Options.MaxResponseBytes;
        KhWorkspaceReset(workspace);

        if (CompareExchangeSessionWorkspace(session, workspace, nullptr) != nullptr) {
            KhWorkspaceReleaseToLookaside(workspace, &session->WorkspaceLookaside);
        }
    }

    class WorkspaceGuard final
    {
    public:
        WorkspaceGuard() noexcept = default;

        ~WorkspaceGuard() noexcept
        {
            Reset();
        }

        WorkspaceGuard(const WorkspaceGuard&) = delete;
        WorkspaceGuard& operator=(const WorkspaceGuard&) = delete;

        _Must_inspect_result_
        NTSTATUS Create(SIZE_T maxResponseBytes, SIZE_T requestBufferBytes) noexcept
        {
            Reset();

            KhWorkspaceOptions workspaceOptions = {};
            workspaceOptions.PoolType = KhPoolType::NonPaged;
            workspaceOptions.RequestBufferBytes = requestBufferBytes;
            workspaceOptions.MaxResponseBytes = maxResponseBytes;
            return KhWorkspaceCreate(&workspaceOptions, &workspace_);
        }

        _Must_inspect_result_
        NTSTATUS CreateForSession(_In_ KH_SESSION session, SIZE_T maxResponseBytes) noexcept
        {
            Reset();
            session_ = session;
            return AcquireRequestWorkspace(session, maxResponseBytes, &workspace_);
        }

        void Reset() noexcept
        {
            if (session_ != nullptr) {
                ReleaseRequestWorkspace(session_, workspace_);
            }
            else {
                KhWorkspaceRelease(workspace_);
            }
            workspace_ = nullptr;
            session_ = nullptr;
        }

        _Ret_maybenull_
        KhWorkspace* Get() noexcept
        {
            return workspace_;
        }

        _Must_inspect_result_
        bool IsValid() const noexcept
        {
            return workspace_ != nullptr;
        }

    private:
        KH_SESSION session_ = nullptr;
        KhWorkspace* workspace_ = nullptr;
    };

    _Must_inspect_result_
    NTSTATUS PrepareApiHttpHeaderScratch(
        _Inout_ KhWorkspace& workspace,
        _Out_ ApiHttpHeaderScratch* scratch) noexcept
    {
        if (scratch == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *scratch = {};
        if (workspace.HttpHeaderScratch.Data == nullptr ||
            workspace.HttpHeaderScratch.Length < KhHttpHeaderScratchRequiredBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(workspace.HttpHeaderScratch.Data, workspace.HttpHeaderScratch.Length);
        scratch->RequestHeaders = reinterpret_cast<http::HttpHeader*>(
            workspace.HttpHeaderScratch.Data);
        scratch->RequestTrailers = reinterpret_cast<http::HttpHeader*>(
            workspace.HttpHeaderScratch.Data + KhHttpRequestHeaderScratchBytes);
        scratch->ResponseHeaders = reinterpret_cast<http::HttpHeader*>(
            workspace.HttpHeaderScratch.Data +
            KhHttpRequestHeaderScratchBytes +
            KhHttpRequestTrailerScratchBytes);
        scratch->ResponseTrailers = reinterpret_cast<http::HttpHeader*>(
            workspace.HttpHeaderScratch.Data +
            KhHttpRequestHeaderScratchBytes +
            KhHttpRequestTrailerScratchBytes +
            KhHttpResponseHeaderScratchBytes);
        scratch->HostHeader = reinterpret_cast<char*>(
            workspace.HttpHeaderScratch.Data +
            KhHttpRequestHeaderScratchBytes +
            KhHttpRequestTrailerScratchBytes +
            KhHttpResponseHeaderScratchBytes +
            KhHttpResponseTrailerScratchBytes);
        scratch->HostHeaderCapacity = KhHttpHostHeaderScratchBytes;
        return STATUS_SUCCESS;
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS PrepareApiHttp2Scratch(
        _Inout_ KhWorkspace& workspace,
        _Out_ ApiHttp2Scratch* scratch) noexcept
    {
        if (scratch == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *scratch = {};
        if (workspace.Http2HeaderScratch.Data == nullptr ||
            workspace.Http2HeaderScratch.Length < KhHttp2RequestScratchBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(workspace.Http2HeaderScratch.Data, workspace.Http2HeaderScratch.Length);
        scratch->Headers = reinterpret_cast<http::HttpHeader*>(workspace.Http2HeaderScratch.Data);
        scratch->ExtraHeaders = reinterpret_cast<http::HttpHeader*>(
            workspace.Http2HeaderScratch.Data + KhHttp2HeaderScratchBytes);
        scratch->LowerHeaderNames = reinterpret_cast<char (*)[client::Http2MaxHeaderNameLength]>(
            workspace.Http2HeaderScratch.Data + KhHttp2HeaderScratchBytes + KhHttp2ExtraHeaderScratchBytes);
        scratch->ContentLengthBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data +
            KhHttp2HeaderScratchBytes +
            KhHttp2ExtraHeaderScratchBytes +
            KhHttp2LowerHeaderScratchBytes);
        scratch->AuthorityBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data + KhHttp2RequestScratchBytes);
        scratch->AuthorityCapacity = workspace.Http2HeaderScratch.Length - KhHttp2RequestScratchBytes;
        return STATUS_SUCCESS;
    }
#endif

    http::HttpMethod ToHttpMethod(KhHttpMethod method) noexcept
    {
        switch (method) {
        case KhHttpMethod::Post:
            return http::HttpMethod::Post;
        case KhHttpMethod::Put:
            return http::HttpMethod::Put;
        case KhHttpMethod::Patch:
            return http::HttpMethod::Patch;
        case KhHttpMethod::Delete:
            return http::HttpMethod::DeleteMethod;
        case KhHttpMethod::Head:
            return http::HttpMethod::Head;
        case KhHttpMethod::Options:
            return http::HttpMethod::Options;
        case KhHttpMethod::Connect:
            return http::HttpMethod::Connect;
        case KhHttpMethod::Get:
        default:
            return http::HttpMethod::Get;
        }
    }

    _Must_inspect_result_
    NTSTATUS BuildHostHeaderValue(
        const KhRequest& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (destination == nullptr ||
            destinationCapacity == 0 ||
            destinationLength == nullptr ||
            request.HostLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool ipv6Literal = TextContainsChar(request.Host, request.HostLength, ':');
        const SIZE_T bracketBytes = ipv6Literal ? 2 : 0;
        if (request.HostLength + bracketBytes >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T length = 0;
        if (ipv6Literal) {
            destination[length++] = '[';
        }
        RtlCopyMemory(destination + length, request.Host, request.HostLength);
        length += request.HostLength;
        if (ipv6Literal) {
            destination[length++] = ']';
        }

        if (!IsDefaultPort(request.Scheme, request.SchemeLength, request.Port)) {
            if (length + 1 >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[length++] = ':';

            SIZE_T divisor = 1;
            while ((request.Port / divisor) >= 10) {
                divisor *= 10;
            }

            SIZE_T digitCount = 0;
            for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
                ++digitCount;
            }

            if (length + digitCount >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
                destination[length++] = static_cast<char>('0' + ((request.Port / currentDivisor) % 10));
            }
        }

        destination[length] = '\0';
        *destinationLength = length;
        return STATUS_SUCCESS;
    }

    bool HeaderNameEquals(const KhStoredHeader& header, const char* name) noexcept
    {
        return TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, name);
    }

    bool IsSupportedHttpAlpn(const char* alpn, SIZE_T alpnLength) noexcept
    {
        return TextEqualsLiteral(alpn, alpnLength, "h2") ||
            TextEqualsLiteral(alpn, alpnLength, "http/1.1");
    }

    bool IsHttpsRequest(const KhRequest& request) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https");
    }

    bool IsAutomaticHttpAlpnMode(const KhRequest& request) noexcept
    {
        return IsHttpsRequest(request) &&
            request.Tls.PreferHttp2 &&
            request.Tls.Alpn == nullptr &&
            request.Tls.AlpnLength == 0;
    }

    void RefreshResponseParseDecodedBuffers(
        _In_ const KhWorkspace& workspace,
        _Inout_ http::HttpParseOptions& parseOptions) noexcept
    {
        parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
    }

    bool IsTlsVersionAllowed(
        KhTlsVersion minimum,
        KhTlsVersion maximum,
        KhTlsVersion protocol) noexcept
    {
        return static_cast<USHORT>(minimum) <= static_cast<USHORT>(protocol) &&
            static_cast<USHORT>(protocol) <= static_cast<USHORT>(maximum);
    }

    bool IsHttpTls12ConfirmationCandidate(
        const KhRequest& request,
        const tls::TlsHandshakeFailure& failure) noexcept
    {
        const bool failureCanConfirmTls12 =
            failure.Category == tls::TlsHandshakeFailureCategory::VersionNegotiation ||
            (failure.Category == tls::TlsHandshakeFailureCategory::NetworkIo &&
                failure.BeforeTls13FirstServerHello &&
                failure.Status != STATUS_IO_TIMEOUT);
        return IsTlsVersionAllowed(request.Tls.MinVersion, request.Tls.MaxVersion, KhTlsVersion::Tls12) &&
            IsTlsVersionAllowed(request.Tls.MinVersion, request.Tls.MaxVersion, KhTlsVersion::Tls13) &&
            failureCanConfirmTls12;
    }

    bool IsSafeFreshConnectionRetryMethod(KhHttpMethod method) noexcept
    {
        return method == KhHttpMethod::Get ||
            method == KhHttpMethod::Head ||
            method == KhHttpMethod::Options;
    }

    bool IsFreshConnectionRetryStatus(NTSTATUS status) noexcept
    {
        return IsConnectionCloseStatus(status) ||
            status == STATUS_RETRY ||
            status == STATUS_IO_TIMEOUT;
    }

    bool ShouldRetryWithFreshConnection(
        _In_ const KhRequest& request,
        NTSTATUS status,
        bool reusedConnection) noexcept
    {
        return !NT_SUCCESS(status) &&
            reusedConnection &&
            request.ConnectionPolicy == KhConnectionPolicy::ReuseOrCreate &&
            IsSafeFreshConnectionRetryMethod(request.Method) &&
            IsFreshConnectionRetryStatus(status);
    }

    _Must_inspect_result_
    NTSTATUS BuildHttpRequestOptions(
        const KhRequest& request,
        _Out_writes_bytes_(hostCapacity) char* host,
        SIZE_T hostCapacity,
        _Out_ http::HttpHeader* headers,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* trailers,
        SIZE_T trailerCapacity,
        _Out_ http::HttpRequestBuildOptions* options,
        _Out_opt_ SIZE_T* requestHeaderCount = nullptr) noexcept
    {
        if (requestHeaderCount != nullptr) {
            *requestHeaderCount = 0;
        }

        if (host == nullptr || headers == nullptr || options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request.TrailerCount != 0 &&
            (trailers == nullptr || request.TrailerCount > trailerCapacity)) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(headers, sizeof(http::HttpHeader) * headerCapacity);
        if (trailers != nullptr && trailerCapacity != 0) {
            RtlZeroMemory(trailers, sizeof(http::HttpHeader) * trailerCapacity);
        }
        RtlZeroMemory(options, sizeof(*options));

        SIZE_T hostLength = 0;
        NTSTATUS status = BuildHostHeaderValue(request, host, hostCapacity, &hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T extraHeaderCount = 0;
        bool hasAcceptEncoding = false;
        const bool chunkedRequest = request.BodyMode == KhRequestBodyMode::Chunked;
        for (SIZE_T index = 0; index < request.HeaderCount; ++index) {
            const KhStoredHeader& header = request.Headers[index];
            if (HeaderNameEquals(header, "Transfer-Encoding")) {
                return STATUS_NOT_SUPPORTED;
            }

            if (HeaderNameEquals(header, "TE")) {
                return STATUS_NOT_SUPPORTED;
            }

            // `Trailer` declares which trailer fields will follow; only meaningful
            // when the request emits chunked framing (see KhHttpRequestAddTrailer).
            if (HeaderNameEquals(header, "Trailer") && !chunkedRequest) {
                return STATUS_NOT_SUPPORTED;
            }

            if (request.BodyLength != 0 &&
                HeaderNameEquals(header, "Expect") &&
                http::HeaderValueHasToken(
                    { header.Value, header.ValueLength },
                    http::MakeText("100-continue"))) {
                return STATUS_NOT_SUPPORTED;
            }

            if (HeaderNameEquals(header, "Host") ||
                HeaderNameEquals(header, "Content-Length") ||
                HeaderNameEquals(header, "Connection")) {
                return STATUS_INVALID_PARAMETER;
            }

            if (HeaderNameEquals(header, "Accept-Encoding")) {
                hasAcceptEncoding = true;
            }

            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = { header.Name, header.NameLength };
            headers[extraHeaderCount].Value = { header.Value, header.ValueLength };
            ++extraHeaderCount;
        }

        if (!hasAcceptEncoding) {
            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = http::MakeText("Accept-Encoding");
            headers[extraHeaderCount].Value = DefaultAcceptEncoding();
            ++extraHeaderCount;
        }

        options->Method = ToHttpMethod(request.Method);
        options->Path = { request.Path, request.PathLength };
        options->Host = { host, hostLength };
        options->Connection = request.ConnectionPolicy == KhConnectionPolicy::ReuseOrCreate ?
            http::HttpConnectionDirective::KeepAlive :
            http::HttpConnectionDirective::Close;
        options->ExtraHeaders = headers;
        options->ExtraHeaderCount = extraHeaderCount;
        options->Body = reinterpret_cast<const char*>(request.Body);
        options->BodyLength = request.BodyLength;
        options->IncludeContentLength = request.HasBody;
        options->BodyMode = request.BodyMode == KhRequestBodyMode::Chunked ?
            http::HttpRequestBodyMode::Chunked :
            http::HttpRequestBodyMode::ContentLength;

        if (request.TrailerCount != 0) {
            for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
                const KhStoredHeader& trailer = request.Trailers[index];
                trailers[index].Name = { trailer.Name, trailer.NameLength };
                trailers[index].Value = { trailer.Value, trailer.ValueLength };
            }
            options->Trailers = trailers;
            options->TrailerCount = request.TrailerCount;
        }

        if (requestHeaderCount != nullptr) {
            *requestHeaderCount = extraHeaderCount;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BuildPoolKey(
        const KhRequest& request,
        const KhProxyOptions& proxy,
        _Out_ KhConnectionPoolKey* key) noexcept
    {
        if (key == nullptr || request.SchemeLength == 0 || request.HostLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(key, sizeof(*key));
        NTSTATUS status = CopyExactText(
            request.Scheme,
            request.SchemeLength,
            key->Scheme,
            sizeof(key->Scheme),
            &key->SchemeLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = CopyExactText(
            request.Host,
            request.HostLength,
            key->Host,
            sizeof(key->Host),
            &key->HostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        key->Port = request.Port;
        key->AddressFamily = ToWskAddressFamily(request.AddressFamily);
        key->MinTlsVersion = request.Tls.MinVersion;
        key->MaxTlsVersion = request.Tls.MaxVersion;
        key->CertificatePolicy = request.Tls.CertificatePolicy;
        key->CertificateStore = request.Tls.CertificateStore;
        key->ClientCredential = request.Tls.ClientCredential;
        key->Policy = request.Tls.Policy;
        key->AutomaticAlpn = IsAutomaticHttpAlpnMode(request);
        const bool useTlsIdentity = IsHttpsRequest(request);
        const char* tlsServerName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        const SIZE_T tlsServerNameLength = request.Tls.ServerName != nullptr ?
            request.Tls.ServerNameLength :
            request.HostLength;
        if (useTlsIdentity && tlsServerName != nullptr && tlsServerNameLength != 0) {
            status = CopyExactText(
                tlsServerName,
                tlsServerNameLength,
                key->TlsServerName,
                sizeof(key->TlsServerName),
                &key->TlsServerNameLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            status = CopyExactText(
                request.Tls.Alpn,
                request.Tls.AlpnLength,
                key->Alpn,
                sizeof(key->Alpn),
                &key->AlpnLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (proxy.Enabled) {
            key->ProxyEnabled = true;
            key->ProxyAddress = proxy.Address;
            status = CopyExactText(
                proxy.Authority,
                proxy.AuthorityLength,
                key->ProxyAuthority,
                sizeof(key->ProxyAuthority),
                &key->ProxyAuthorityLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS CreateOwnedResponse(
        const http::HttpResponse& parsed,
        const char* rawResponse,
        SIZE_T rawResponseLength,
        _Out_ KH_RESPONSE* response) noexcept
    {
        if (response != nullptr) {
            *response = nullptr;
        }

        if (response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        KH_RESPONSE newResponse = AllocateResponseHandle();
        if (newResponse == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newResponse->Header = { KhHandleKind::Response, 0, nullptr };
        newResponse->StatusCode = parsed.StatusCode;
        newResponse->InFlight = 0;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        KeInitializeEvent(&newResponse->DrainEvent, NotificationEvent, TRUE);
#endif

        if (rawResponse != nullptr && rawResponseLength != 0) {
            newResponse->RawResponse = AllocateTextCopy(rawResponse, rawResponseLength);
            if (newResponse->RawResponse == nullptr) {
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newResponse->RawResponseLength = rawResponseLength;
        }

        if (parsed.Body != nullptr && parsed.BodyLength != 0) {
            newResponse->Body = AllocateBytesCopy(
                reinterpret_cast<const UCHAR*>(parsed.Body),
                parsed.BodyLength);
            if (newResponse->Body == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newResponse->BodyLength = parsed.BodyLength;
        }

        if (parsed.HeaderCount != 0) {
            newResponse->Headers = static_cast<http::HttpHeader*>(
                AllocateApiMemory(sizeof(http::HttpHeader) * parsed.HeaderCount));
            if (newResponse->Headers == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T nameStorageLength = 0;
            SIZE_T valueStorageLength = 0;
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                nameStorageLength += parsed.Headers[index].Name.Length;
                valueStorageLength += parsed.Headers[index].Value.Length;
            }

            if (nameStorageLength != 0) {
                newResponse->HeaderNameStorage = static_cast<char*>(AllocateApiMemory(nameStorageLength));
                if (newResponse->HeaderNameStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->HeaderNameStorageLength = nameStorageLength;
            }

            if (valueStorageLength != 0) {
                newResponse->HeaderValueStorage = static_cast<char*>(AllocateApiMemory(valueStorageLength));
                if (newResponse->HeaderValueStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->HeaderValueStorageLength = valueStorageLength;
            }

            SIZE_T nameOffset = 0;
            SIZE_T valueOffset = 0;
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                const http::HttpHeader& source = parsed.Headers[index];
                if (source.Name.Length != 0) {
                    RtlCopyMemory(
                        newResponse->HeaderNameStorage + nameOffset,
                        source.Name.Data,
                        source.Name.Length);
                    newResponse->Headers[index].Name.Data = newResponse->HeaderNameStorage + nameOffset;
                    newResponse->Headers[index].Name.Length = source.Name.Length;
                    nameOffset += source.Name.Length;
                }

                if (source.Value.Length != 0) {
                    RtlCopyMemory(
                        newResponse->HeaderValueStorage + valueOffset,
                        source.Value.Data,
                        source.Value.Length);
                    newResponse->Headers[index].Value.Data = newResponse->HeaderValueStorage + valueOffset;
                    newResponse->Headers[index].Value.Length = source.Value.Length;
                    valueOffset += source.Value.Length;
                }
            }
            newResponse->HeaderCount = parsed.HeaderCount;
        }

        if (parsed.TrailerCount != 0) {
            newResponse->Trailers = static_cast<http::HttpHeader*>(
                AllocateApiMemory(sizeof(http::HttpHeader) * parsed.TrailerCount));
            if (newResponse->Trailers == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T nameStorageLength = 0;
            SIZE_T valueStorageLength = 0;
            for (SIZE_T index = 0; index < parsed.TrailerCount; ++index) {
                nameStorageLength += parsed.Trailers[index].Name.Length;
                valueStorageLength += parsed.Trailers[index].Value.Length;
            }

            if (nameStorageLength != 0) {
                newResponse->TrailerNameStorage = static_cast<char*>(AllocateApiMemory(nameStorageLength));
                if (newResponse->TrailerNameStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->TrailerNameStorageLength = nameStorageLength;
            }

            if (valueStorageLength != 0) {
                newResponse->TrailerValueStorage = static_cast<char*>(AllocateApiMemory(valueStorageLength));
                if (newResponse->TrailerValueStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->TrailerValueStorageLength = valueStorageLength;
            }

            SIZE_T nameOffset = 0;
            SIZE_T valueOffset = 0;
            for (SIZE_T index = 0; index < parsed.TrailerCount; ++index) {
                const http::HttpHeader& source = parsed.Trailers[index];
                if (source.Name.Length != 0) {
                    RtlCopyMemory(
                        newResponse->TrailerNameStorage + nameOffset,
                        source.Name.Data,
                        source.Name.Length);
                    newResponse->Trailers[index].Name.Data = newResponse->TrailerNameStorage + nameOffset;
                    newResponse->Trailers[index].Name.Length = source.Name.Length;
                    nameOffset += source.Name.Length;
                }

                if (source.Value.Length != 0) {
                    RtlCopyMemory(
                        newResponse->TrailerValueStorage + valueOffset,
                        source.Value.Data,
                        source.Value.Length);
                    newResponse->Trailers[index].Value.Data = newResponse->TrailerValueStorage + valueOffset;
                    newResponse->Trailers[index].Value.Length = source.Value.Length;
                    valueOffset += source.Value.Length;
                }
            }
            newResponse->TrailerCount = parsed.TrailerCount;
        }

        NTSTATUS status = RegisterActiveResponseHandle(newResponse);
        if (!NT_SUCCESS(status)) {
            ReleaseResponseStorage(*newResponse);
            FreeHandle(newResponse);
            return status;
        }

        *response = newResponse;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS InvokeResponseCallbacks(
        const KhHttpSendOptions& options,
        const http::HttpResponse& parsed) noexcept
    {
        if (options.HeaderCallback != nullptr) {
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                const http::HttpHeader& header = parsed.Headers[index];
                NTSTATUS status = options.HeaderCallback(
                    options.CallbackContext,
                    header.Name.Data,
                    header.Name.Length,
                    header.Value.Data,
                    header.Value.Length);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }

        if (options.BodyCallback != nullptr) {
            return options.BodyCallback(
                options.CallbackContext,
                reinterpret_cast<const UCHAR*>(parsed.Body),
                parsed.BodyLength,
                true);
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool IsNonFinalInformationalResponse(const http::HttpResponse& parsed) noexcept
    {
        return parsed.StatusCode >= 100 &&
            parsed.StatusCode < 200 &&
            parsed.StatusCode != 101;
    }

    _Must_inspect_result_
    NTSTATUS DiscardNonFinalInformationalResponse(
        _Inout_updates_bytes_(*responseLength) UCHAR* responseBuffer,
        _Inout_ SIZE_T* responseLength,
        _Inout_ http::HttpResponse& parsed,
        _Out_ bool* skipped) noexcept
    {
        if (skipped != nullptr) {
            *skipped = false;
        }
        if (responseBuffer == nullptr || responseLength == nullptr || skipped == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!IsNonFinalInformationalResponse(parsed)) {
            return STATUS_SUCCESS;
        }
        if (parsed.BytesConsumed > *responseLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T remaining = *responseLength - parsed.BytesConsumed;
        if (remaining != 0) {
            RtlMoveMemory(responseBuffer, responseBuffer + parsed.BytesConsumed, remaining);
        }
        *responseLength = remaining;
        parsed = {};
        *skipped = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseResponseBytes(
        KhWorkspace& workspace,
        SIZE_T responseLength,
        bool messageCompleteOnConnectionClose,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* headers,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* trailers,
        SIZE_T trailerCapacity) noexcept
    {
        if (parsed == nullptr || headers == nullptr || trailers == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        http::HttpParseOptions parseOptions = {};
        parseOptions.Headers = headers;
        parseOptions.HeaderCapacity = headerCapacity;
        parseOptions.Trailers = trailers;
        parseOptions.TrailerCapacity = trailerCapacity;
        parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
        parseOptions.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
        parseOptions.ScratchBodyCapacity = workspace.Request.Length;
        parseOptions.MessageCompleteOnConnectionClose = messageCompleteOnConnectionClose;

        SIZE_T parseLength = responseLength;
        for (;;) {
            NTSTATUS status = http::HttpParser::ParseResponse(
                reinterpret_cast<const char*>(workspace.Response.Data),
                parseLength,
                parseOptions,
                *parsed);
            if (status == STATUS_BUFFER_TOO_SMALL) {
                status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                if (!NT_SUCCESS(status)) {
                    workspace.ResponseLength = parseLength;
                    return status;
                }
                RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                continue;
            }
            if (status != STATUS_SUCCESS) {
                workspace.ResponseLength = parseLength;
                return status;
            }

            bool skipped = false;
            status = DiscardNonFinalInformationalResponse(
                workspace.Response.Data,
                &parseLength,
                *parsed,
                &skipped);
            if (!NT_SUCCESS(status)) {
                workspace.ResponseLength = parseLength;
                return status;
            }
            if (!skipped) {
                workspace.ResponseLength = parseLength;
                return STATUS_SUCCESS;
            }
        }
    }

    bool IsHttpConnectionReusable(
        _In_ const http::HttpResponse& parsed,
        SIZE_T rawResponseLength) noexcept
    {
        if (parsed.StatusCode == 101 ||
            parsed.BodyEndsOnConnectionClose ||
            parsed.HasConnectionClose() ||
            parsed.BytesConsumed != rawResponseLength ||
            parsed.MajorVersion != 1) {
            return false;
        }

        if (parsed.MinorVersion == 0) {
            return parsed.HasConnectionKeepAlive();
        }

        return parsed.MinorVersion == 1;
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS BuildHttp2OptionsFromRequest(
        const KhRequest& request,
        _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        http::HttpText authority,
        _Out_writes_(extraHeaderCapacity) http::HttpHeader* extraHeaders,
        SIZE_T extraHeaderCapacity,
        _Out_ client::Http2RequestOptions* options) noexcept
    {
        if (requestHeaders == nullptr || extraHeaders == nullptr || options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (authority.Data == nullptr || authority.Length == 0 || request.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request.BodyMode == KhRequestBodyMode::Chunked) {
            return STATUS_NOT_SUPPORTED;
        }

        *options = {};
        options->TransportMode = client::Http2TransportMode::TlsAlpn;
        options->ServerName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        options->ServerNameLength = request.Tls.ServerName != nullptr ?
            request.Tls.ServerNameLength :
            request.HostLength;
        options->Method = ToHttpMethod(request.Method);
        options->Path = { request.Path, request.PathLength };
        options->Authority = authority;
        options->Body = request.Body;
        options->BodyLength = request.BodyLength;
        options->IncludeContentLength = request.HasBody;
        options->CertificateStore = request.Tls.CertificateStore;
        options->VerifyCertificate = request.Tls.CertificatePolicy == KhCertificatePolicy::Verify;
        options->Policy = request.Tls.Policy;
        options->ClientCredential = request.Tls.ClientCredential;

        SIZE_T extraHeaderCount = 0;
        for (SIZE_T index = 0; index < requestHeaderCount; ++index) {
            const http::HttpHeader& header = requestHeaders[index];
            if (http::TextEqualsIgnoreCase(header.Name, http::MakeText("Host"))) {
                continue;
            }
            if (http::TextEqualsIgnoreCase(header.Name, http::MakeText("User-Agent"))) {
                options->UserAgent = header.Value;
                continue;
            }
            if (http::TextEqualsIgnoreCase(header.Name, http::MakeText("Content-Type"))) {
                options->ContentType = header.Value;
                continue;
            }
            if (http::TextEqualsIgnoreCase(header.Name, http::MakeText("Accept-Encoding"))) {
                options->AcceptEncoding = header.Value;
                continue;
            }
            if (extraHeaderCount >= extraHeaderCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            extraHeaders[extraHeaderCount++] = header;
        }

        options->ExtraHeaders = extraHeaders;
        options->ExtraHeaderCount = extraHeaderCount;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS AppendHttp2ResponseBodyToWorkspace(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        auto* workspace = static_cast<KhWorkspace*>(context);
        if (workspace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        return KhWorkspaceAppendResponse(workspace, data, dataLength);
    }

    _Must_inspect_result_
    NTSTATUS DecodeContentWithWorkspace(
        _In_reads_(responseHeaderCount) const http::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCount,
        _In_reads_bytes_(responseBodyLength) const char* responseBody,
        SIZE_T responseBodyLength,
        _Inout_ KhWorkspace& workspace,
        _Out_ http::HttpContentDecodeResult* decoded) noexcept
    {
        if (decoded == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *decoded = {};

        for (;;) {
            http::HttpContentDecodeBuffers decodeBuffers = {};
            decodeBuffers.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
            decodeBuffers.DecodedBodyCapacity = workspace.DecodedBody.Length;
            decodeBuffers.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
            decodeBuffers.ScratchBodyCapacity = workspace.Request.Length;

            NTSTATUS status = http::HttpContentEncoding::Decode(
                responseHeaders,
                responseHeaderCount,
                responseBody,
                responseBodyLength,
                decodeBuffers,
                *decoded);
            if (status != STATUS_BUFFER_TOO_SMALL) {
                if (NT_SUCCESS(status) &&
                    workspace.MaxResponseBytes != 0 &&
                    decoded->BodyLength > workspace.MaxResponseBytes) {
                    *decoded = {};
                    return STATUS_BUFFER_TOO_SMALL;
                }
                return status;
            }

            status = GrowDecodedBodyAfterBufferTooSmall(workspace);
            if (!NT_SUCCESS(status)) {
                *decoded = {};
                return status;
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS SendHttp2ViaTransport(
        const KhRequest& request,
        KhWorkspace& workspace,
        _Inout_ KhPooledConnection& pooledConnection,
        SIZE_T maxHeaderBlockBytes,
        _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr ||
            responseHeaders == nullptr ||
            rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *parsed = {};
        *rawResponseLength = 0;
        workspace.ResponseLength = 0;

        ApiHttp2Scratch h2Scratch = {};
        NTSTATUS status = PrepareApiHttp2Scratch(workspace, &h2Scratch);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T authorityLength = 0;
        status = BuildHostHeaderValue(
            request,
            h2Scratch.AuthorityBuffer,
            h2Scratch.AuthorityCapacity,
            &authorityLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        client::Http2RequestOptions h2Options = {};
        status = BuildHttp2OptionsFromRequest(
            request,
            requestHeaders,
            requestHeaderCount,
            { h2Scratch.AuthorityBuffer, authorityLength },
            h2Scratch.ExtraHeaders,
            client::Http2MaxRequestHeaders,
            &h2Options);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T h2HeaderCount = 0;
        status = client::BuildHttp2RequestHeaders(
            h2Options,
            h2Scratch.Headers,
            client::Http2MaxRequestHeaders,
            h2Scratch.LowerHeaderNames,
            h2Scratch.ContentLengthBuffer,
            &h2HeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (pooledConnection.Transport == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (pooledConnection.Http2 == nullptr) {
            auto* h2Connection = AllocateNonPagedObject<http2::Http2Connection>();
            if (h2Connection == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = h2Connection->Initialize(*pooledConnection.Transport, maxHeaderBlockBytes);
            if (!NT_SUCCESS(status)) {
                kprintf("High-level HTTP/2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
                FreeNonPagedObject(h2Connection);
                return status;
            }
            pooledConnection.Http2 = h2Connection;
        }

        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        http2::Http2ResponseBodySink responseBodySink = {};
        responseBodySink.Append = AppendHttp2ResponseBodyToWorkspace;
        responseBodySink.Context = &workspace;

        status = pooledConnection.Http2->SendRequest(
            *pooledConnection.Transport,
            h2Scratch.Headers,
            h2HeaderCount,
            request.Body,
            request.BodyLength,
            responseHeaders,
            headerCapacity,
            &responseHeaderCount,
            responseBodySink,
            &responseBodyLength,
            &statusCode,
            reinterpret_cast<char*>(workspace.Http2HeaderScratch.Data),
            workspace.Http2HeaderScratch.Length);

        if (!NT_SUCCESS(status)) {
            kprintf("High-level HTTP/2 request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        http::HttpContentDecodeResult decoded = {};
        status = DecodeContentWithWorkspace(
            responseHeaders,
            responseHeaderCount,
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseBodyLength,
            workspace,
            &decoded);
        if (!NT_SUCCESS(status)) {
            kprintf("High-level HTTP/2 content decode failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        parsed->MajorVersion = 2;
        parsed->MinorVersion = 0;
        parsed->StatusCode = statusCode;
        parsed->Headers = responseHeaders;
        parsed->HeaderCount = responseHeaderCount;
        parsed->Body = decoded.Body;
        parsed->BodyLength = decoded.BodyLength;
        parsed->BytesConsumed = responseBodyLength;
        parsed->BodyKind = http::HttpBodyKind::ContentLength;
        workspace.ResponseLength = responseBodyLength;
        *rawResponseLength = responseBodyLength;
        return STATUS_SUCCESS;
    }
#endif

    _Must_inspect_result_
    NTSTATUS GrowDecodedBodyAfterBufferTooSmall(_Inout_ KhWorkspace& workspace) noexcept
    {
        const SIZE_T currentLength = workspace.DecodedBody.Length;
        if (workspace.MaxResponseBytes != 0 && currentLength >= workspace.MaxResponseBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T requiredCapacity = currentLength == 0 ?
            KhWorkspaceDecodedBodyBytes :
            currentLength * 2;
        if (currentLength != 0 &&
            requiredCapacity < currentLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (workspace.MaxResponseBytes != 0 &&
            requiredCapacity > workspace.MaxResponseBytes) {
            requiredCapacity = workspace.MaxResponseBytes;
        }

        if (requiredCapacity <= currentLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return KhWorkspaceEnsureDecodedBodyCapacity(&workspace, requiredCapacity);
    }

    _Must_inspect_result_
    NTSTATUS BuildRequestBytes(
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Out_writes_bytes_(hostHeaderCapacity) char* hostHeader,
        SIZE_T hostHeaderCapacity,
        _Out_writes_(headerCapacity) http::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* requestTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* requestLength,
        _Out_opt_ SIZE_T* requestHeaderCount = nullptr) noexcept
    {
        if (requestLength != nullptr) {
            *requestLength = 0;
        }
        if (requestHeaderCount != nullptr) {
            *requestHeaderCount = 0;
        }

        if (requestLength == nullptr ||
            requestHeaders == nullptr ||
            hostHeader == nullptr ||
            hostHeaderCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        http::HttpRequestBuildOptions buildOptions = {};
        NTSTATUS status = BuildHttpRequestOptions(
            request,
            hostHeader,
            hostHeaderCapacity,
            requestHeaders,
            headerCapacity,
            requestTrailers,
            trailerCapacity,
            &buildOptions,
            requestHeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return http::HttpRequestBuilder::Build(
            buildOptions,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            requestLength);
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    ULONGLONG MakeResponseReadDeadline() noexcept
    {
        return KeQueryInterruptTime() +
            (static_cast<ULONGLONG>(WskOperationTimeoutMilliseconds) * 10000ULL);
    }

    _Must_inspect_result_
    bool TryGetRemainingResponseReadTimeout(
        ULONGLONG deadline,
        _Out_ ULONG* timeoutMilliseconds) noexcept
    {
        if (timeoutMilliseconds == nullptr) {
            return false;
        }

        const ULONGLONG now = KeQueryInterruptTime();
        if (now >= deadline) {
            *timeoutMilliseconds = 0;
            return false;
        }

        const ULONGLONG remaining100ns = deadline - now;
        ULONGLONG remainingMilliseconds = (remaining100ns + 9999ULL) / 10000ULL;
        if (remainingMilliseconds == 0) {
            remainingMilliseconds = 1;
        }
        if (remainingMilliseconds > 0xffffffffULL) {
            remainingMilliseconds = 0xffffffffULL;
        }

        *timeoutMilliseconds = static_cast<ULONG>(remainingMilliseconds);
        return true;
    }

    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocket(
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        bool responseBodyForbidden,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr ||
            rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *rawResponseLength = 0;
        SIZE_T responseLength = 0;
        const ULONGLONG responseReadDeadline = MakeResponseReadDeadline();

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = responseHeaders;
            parseOptions.HeaderCapacity = headerCapacity;
            parseOptions.Trailers = responseTrailers;
            parseOptions.TrailerCapacity = trailerCapacity;
            parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
            parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
            parseOptions.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
            parseOptions.ScratchBodyCapacity = workspace.Request.Length;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;

            NTSTATUS status = http::HttpParser::ParseResponse(
                reinterpret_cast<const char*>(workspace.Response.Data),
                responseLength,
                parseOptions,
                *parsed);
            if (status == STATUS_SUCCESS) {
                bool skippedInformational = false;
                status = DiscardNonFinalInformationalResponse(
                    workspace.Response.Data,
                    &responseLength,
                    *parsed,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (skippedInformational) {
                    workspace.ResponseLength = responseLength;
                    continue;
                }

                *rawResponseLength = responseLength;
                return STATUS_SUCCESS;
            }

            // Content decoding (gzip/deflate/br) and chunked transfer-decoding write into the
            // workspace DecodedBody buffer, which starts at KhWorkspaceDecodedBodyBytes. A decoded
            // body larger than the current buffer surfaces as STATUS_BUFFER_TOO_SMALL here. Grow the
            // buffer (bounded by MaxResponseBytes) and re-parse, mirroring the HTTP/2 decode path.
            if (status == STATUS_BUFFER_TOO_SMALL) {
                status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                continue;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }

            if (workspace.MaxResponseBytes != 0 && responseLength >= workspace.MaxResponseBytes) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            if (responseLength == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            status = KhWorkspaceEnsureResponseCapacity(&workspace, responseLength + 1);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T received = 0;
            ULONG receiveTimeoutMilliseconds = WskOperationTimeoutMilliseconds;
            if (!TryGetRemainingResponseReadTimeout(responseReadDeadline, &receiveTimeoutMilliseconds)) {
                return STATUS_IO_TIMEOUT;
            }

            status = transport.ReceiveWithTimeout(
                workspace.Response.Data + responseLength,
                workspace.Response.Length - responseLength,
                &received,
                receiveTimeoutMilliseconds);

            if (!NT_SUCCESS(status)) {
                if (!IsOrderlyConnectionCloseStatus(status)) {
                    return status;
                }
                if (responseLength == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                for (;;) {
                    parseOptions.MessageCompleteOnConnectionClose = true;
                    status = http::HttpParser::ParseResponse(
                        reinterpret_cast<const char*>(workspace.Response.Data),
                        responseLength,
                        parseOptions,
                        *parsed);
                    if (status == STATUS_BUFFER_TOO_SMALL) {
                        status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                        continue;
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        workspace.Response.Data,
                        &responseLength,
                        *parsed,
                        &skippedInformational);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (!skippedInformational) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
                    }
                }
            }

            if (received == 0) {
                if (responseLength == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                for (;;) {
                    parseOptions.MessageCompleteOnConnectionClose = true;
                    status = http::HttpParser::ParseResponse(
                        reinterpret_cast<const char*>(workspace.Response.Data),
                        responseLength,
                        parseOptions,
                        *parsed);
                    if (status == STATUS_BUFFER_TOO_SMALL) {
                        status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                        continue;
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        workspace.Response.Data,
                        &responseLength,
                        *parsed,
                        &skippedInformational);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (!skippedInformational) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
                    }
                }
            }

            responseLength += received;
            workspace.ResponseLength = responseLength;
        }
    }
#endif

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS CopyAsciiToWide(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept
    {
        if (source == nullptr ||
            sourceLength == 0 ||
            destination == nullptr ||
            sourceLength >= destinationCapacity) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < sourceLength; ++index) {
            destination[index] = static_cast<unsigned char>(source[index]);
        }
        destination[sourceLength] = L'\0';
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS FormatServiceName(
        USHORT port,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept
    {
        if (port == 0 || destination == nullptr || destinationCapacity < 2) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T divisor = 1;
        while ((port / divisor) >= 10) {
            divisor *= 10;
        }

        SIZE_T digitCount = 0;
        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            ++digitCount;
        }

        if (digitCount >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            destination[offset++] = static_cast<wchar_t>(L'0' + ((port / currentDivisor) % 10));
        }
        destination[digitCount] = L'\0';
        return STATUS_SUCCESS;
    }

    tls::TlsProtocol ToTlsProtocol(KhTlsVersion version) noexcept
    {
        return version == KhTlsVersion::Tls13 ? tls::TlsProtocol::Tls13 : tls::TlsProtocol::Tls12;
    }

    SIZE_T DecimalDigitCount(USHORT value) noexcept
    {
        SIZE_T divisor = 1;
        while ((value / divisor) >= 10) {
            divisor *= 10;
        }

        SIZE_T digitCount = 0;
        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            ++digitCount;
        }
        return digitCount;
    }

    NTSTATUS AppendDecimalPort(
        USHORT value,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* destinationLength) noexcept
    {
        if (destination == nullptr || destinationLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T divisor = 1;
        while ((value / divisor) >= 10) {
            divisor *= 10;
        }

        SIZE_T length = *destinationLength;
        const SIZE_T digitCount = DecimalDigitCount(value);
        if (length + digitCount >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            destination[length++] = static_cast<char>('0' + ((value / currentDivisor) % 10));
        }

        *destinationLength = length;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BuildProxyConnectAuthority(
        const KhRequest& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (destination == nullptr ||
            destinationCapacity == 0 ||
            destinationLength == nullptr ||
            request.HostLength == 0 ||
            request.Port == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool ipv6Literal = TextContainsChar(request.Host, request.HostLength, ':');
        const SIZE_T bracketBytes = ipv6Literal ? 2 : 0;
        const SIZE_T digitCount = DecimalDigitCount(request.Port);
        if (request.HostLength + bracketBytes + 1 + digitCount >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T length = 0;
        if (ipv6Literal) {
            destination[length++] = '[';
        }
        RtlCopyMemory(destination + length, request.Host, request.HostLength);
        length += request.HostLength;
        if (ipv6Literal) {
            destination[length++] = ']';
        }
        destination[length++] = ':';

        NTSTATUS status = AppendDecimalPort(request.Port, destination, destinationCapacity, &length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        destination[length] = '\0';
        *destinationLength = length;
        return STATUS_SUCCESS;
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    static bool IsHttpAsyncCancellationRequested(_In_opt_ void* context) noexcept;

    void ReleaseHttp2Layer(_Inout_ KhPooledConnection& connection) noexcept
    {
        if (connection.Http2 == nullptr) {
            return;
        }

        if (connection.Transport != nullptr) {
            const NTSTATUS shutdownStatus = connection.Http2->Shutdown(*connection.Transport);
            UNREFERENCED_PARAMETER(shutdownStatus);
        }
        FreeNonPagedObject(connection.Http2);
        connection.Http2 = nullptr;
    }

    void ReleaseTlsLayer(_Inout_ KhPooledConnection& connection) noexcept
    {
        ReleaseHttp2Layer(connection);
        if (connection.Transport != nullptr && connection.Transport != connection.RawTransport) {
            FreeNonPagedObject(connection.Transport);
            connection.Transport = connection.RawTransport;
        }
        if (connection.Tls != nullptr) {
            FreeNonPagedObject(connection.Tls);
            connection.Tls = nullptr;
        }
    }

    void ClosePooledTransportResources(_Inout_ KhPooledConnection& connection) noexcept
    {
        ReleaseTlsLayer(connection);

        if (connection.RawTransport != nullptr) {
            FreeNonPagedObject(connection.RawTransport);
            connection.RawTransport = nullptr;
            connection.Transport = nullptr;
        }
        if (connection.Socket != nullptr) {
            const NTSTATUS closeStatus = connection.Socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            FreeNonPagedObject(connection.Socket);
            connection.Socket = nullptr;
        }

        connection.LastUsedTime = 0;
        connection.ProxyTunnelEstablished = false;
    }
#endif

    _Must_inspect_result_
    NTSTATUS ConnectSocketToAddress(
        _In_ KH_SESSION session,
        _In_ const SOCKADDR* remoteAddress,
        _Inout_ KhPooledConnection& connection,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (session == nullptr || remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        auto* socket = AllocateNonPagedObject<net::WskSocket>();
        if (socket == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
        }

        NTSTATUS status = socket->Connect(
            *session->WskClient,
            remoteAddress,
            nullptr,
            cancellation.IsCancellationRequested != nullptr ? &cancellation : nullptr);
        if (!NT_SUCCESS(status)) {
            FreeNonPagedObject(socket);
            return status;
        }

        connection.Socket = socket;
        connection.RawTransport = AllocateNonPagedObject<core::WskTransport>(*connection.Socket);
        if (connection.RawTransport == nullptr) {
            const NTSTATUS closeStatus = connection.Socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            FreeNonPagedObject(connection.Socket);
            connection.Socket = nullptr;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        connection.Transport = connection.RawTransport;
        connection.ProxyTunnelEstablished = false;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS EstablishProxyTunnel(
        _In_ KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Inout_ KhPooledConnection& connection,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (session == nullptr || !session->Options.Proxy.Enabled) {
            return STATUS_SUCCESS;
        }
        if (connection.ProxyTunnelEstablished) {
            return STATUS_SUCCESS;
        }
        if (connection.RawTransport == nullptr ||
            workspace.Response.Data == nullptr ||
            workspace.Response.Length == 0 ||
            workspace.DecodedBody.Data == nullptr ||
            workspace.DecodedBody.Length == 0 ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T authorityLength = 0;
        NTSTATUS status = BuildProxyConnectAuthority(
            request,
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            workspace.DecodedBody.Length,
            &authorityLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http::HttpHeader proxyAuthHeader = {};
        client::ProxyConnectRequestOptions connectOptions = {};
        connectOptions.Authority = {
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            authorityLength
        };
        if (session->Options.Proxy.AuthHeader != nullptr) {
            proxyAuthHeader.Name = http::MakeText("Proxy-Authorization");
            proxyAuthHeader.Value = {
                session->Options.Proxy.AuthHeader,
                session->Options.Proxy.AuthHeaderLength
            };
            connectOptions.Headers = &proxyAuthHeader;
            connectOptions.HeaderCount = 1;
        }

        SIZE_T connectRequestLength = 0;
        status = client::BuildProxyConnectRequest(
            connectOptions,
            reinterpret_cast<char*>(workspace.Response.Data),
            workspace.Response.Length,
            &connectRequestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
            connection.RawTransport->SetCancellation(&cancellation);
        }

        SIZE_T sent = 0;
        status = connection.RawTransport->Send(
            workspace.Response.Data,
            connectRequestLength,
            &sent);
        if (cancellationOperation != nullptr) {
            connection.RawTransport->SetCancellation(nullptr);
        }
        if (NT_SUCCESS(status) && sent != connectRequestLength) {
            return STATUS_CONNECTION_DISCONNECTED;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http::HttpResponse proxyResponse = {};
        SIZE_T proxyRawResponseLength = 0;
        workspace.ResponseLength = 0;
        status = ReadHttpResponseFromSocket(
            *connection.RawTransport,
            workspace,
            true,
            &proxyResponse,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            &proxyRawResponseLength);
        UNREFERENCED_PARAMETER(proxyRawResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (proxyResponse.StatusCode == 407) {
            return STATUS_ACCESS_DENIED;
        }
        if (!client::IsSuccessfulProxyConnectResponse(proxyResponse)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        workspace.ResponseLength = 0;
        connection.ProxyTunnelEstablished = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS EnsureSocketConnected(
        _In_ KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhPooledConnection& connection,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (session == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (connection.Socket != nullptr && connection.Socket->IsConnected()) {
            return STATUS_SUCCESS;
        }

        if (connection.Transport != nullptr && connection.Transport != connection.RawTransport) {
            ReleaseHttp2Layer(connection);
            FreeNonPagedObject(connection.Transport);
            connection.Transport = nullptr;
        }
        if (connection.Tls != nullptr) {
            ReleaseHttp2Layer(connection);
            FreeNonPagedObject(connection.Tls);
            connection.Tls = nullptr;
        }
        if (connection.RawTransport != nullptr) {
            ReleaseHttp2Layer(connection);
            FreeNonPagedObject(connection.RawTransport);
            connection.RawTransport = nullptr;
        }
        if (connection.Socket != nullptr) {
            FreeNonPagedObject(connection.Socket);
            connection.Socket = nullptr;
        }
        connection.ProxyTunnelEstablished = false;

        if (session->Options.Proxy.Enabled) {
            return ConnectSocketToAddress(
                session,
                reinterpret_cast<const SOCKADDR*>(&session->Options.Proxy.Address),
                connection,
                cancellationOperation);
        }

        HeapArray<wchar_t> serverName(KhMaxHostLength + 1);
        HeapArray<wchar_t> serviceName(KhMaxServiceNameLength + 1);
        if (!serverName.IsValid() || !serviceName.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = CopyAsciiToWide(request.Host, request.HostLength, serverName.Get(), serverName.Count());
        if (NT_SUCCESS(status)) {
            status = FormatServiceName(request.Port, serviceName.Get(), serviceName.Count());
        }

        HeapArray<SOCKADDR_STORAGE> remoteAddresses(net::WskMaxResolvedAddresses);
        if (!remoteAddresses.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T remoteAddressCount = 0;
        if (NT_SUCCESS(status)) {
            status = session->WskClient->ResolveAll(
                serverName.Get(),
                serviceName.Get(),
                remoteAddresses.Get(),
                net::WskMaxResolvedAddresses,
                &remoteAddressCount,
                ToWskAddressFamily(request.AddressFamily));
        }

        NTSTATUS lastStatus = status;
        if (NT_SUCCESS(status)) {
            lastStatus = STATUS_NOT_FOUND;
            for (SIZE_T addressIndex = 0; addressIndex < remoteAddressCount; ++addressIndex) {
                status = ConnectSocketToAddress(
                    session,
                    reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]),
                    connection,
                    cancellationOperation);
                if (NT_SUCCESS(status)) {
                    return STATUS_SUCCESS;
                }
                if (status == STATUS_INSUFFICIENT_RESOURCES) {
                    return status;
                }

                lastStatus = status;
                kprintf("HttpEngine socket connect attempt failed: 0x%08X index=%Iu family=%u\r\n",
                    static_cast<ULONG>(status),
                    addressIndex,
                    static_cast<unsigned>(remoteAddresses[addressIndex].ss_family));
            }
        }

        if (!NT_SUCCESS(lastStatus)) {
            return lastStatus;
        }

        return STATUS_NOT_FOUND;
    }

    _Must_inspect_result_
    NTSTATUS ConnectTlsOnExistingSocket(
        _In_ KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Inout_ KhPooledConnection& connection,
        KhTlsVersion maximumTlsVersion,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation,
        _Out_opt_ tls::TlsHandshakeFailure* failure) noexcept
    {
        if (failure != nullptr) {
            *failure = {};
        }
        if (session == nullptr || connection.Socket == nullptr || connection.RawTransport == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        auto* tlsConnection = AllocateNonPagedObject<tls::TlsConnection>();
        if (tlsConnection == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tls::TlsAlpnProtocol explicitAlpn = {};
        static const tls::TlsAlpnProtocol automaticAlpnProtocols[] = {
            { "h2", 2 },
            { "http/1.1", 8 }
        };
        tls::TlsClientConnectionOptions tlsOptions = {};
        core::WorkspaceScratchAllocator* handshakeScratch = nullptr;
        core::WorkspaceScratchAllocator* certificateScratch = nullptr;
        handshakeScratch = AllocateNonPagedObject<core::WorkspaceScratchAllocator>(
            workspace,
            core::WorkspaceScratchAllocator::BufferKind::TlsHandshake);
        certificateScratch = AllocateNonPagedObject<core::WorkspaceScratchAllocator>(
            workspace,
            core::WorkspaceScratchAllocator::BufferKind::Certificate);
        if (handshakeScratch == nullptr || certificateScratch == nullptr) {
            FreeNonPagedObject(certificateScratch);
            FreeNonPagedObject(handshakeScratch);
            FreeNonPagedObject(tlsConnection);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tlsOptions.ServerName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        tlsOptions.ServerNameLength = request.Tls.ServerName != nullptr ?
            request.Tls.ServerNameLength :
            request.HostLength;
        tlsOptions.CertificateStore = request.Tls.CertificateStore;
        tlsOptions.VerifyCertificate = request.Tls.CertificatePolicy == KhCertificatePolicy::Verify;
        tlsOptions.MinimumProtocol = ToTlsProtocol(request.Tls.MinVersion);
        tlsOptions.MaximumProtocol = ToTlsProtocol(maximumTlsVersion);
        tlsOptions.Policy = request.Tls.Policy;
        tlsOptions.ClientCredential = request.Tls.ClientCredential;
        tlsOptions.HandshakeReceiveTimeoutMilliseconds = request.Tls.HandshakeReceiveTimeoutMilliseconds;
        tlsOptions.HandshakeScratchAllocator = handshakeScratch;
        tlsOptions.CertificateScratchAllocator = certificateScratch;
        tlsOptions.ProviderCache = session->ProviderCache;
        tlsOptions.EnableSessionResumption = true;

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            explicitAlpn.Name = request.Tls.Alpn;
            explicitAlpn.NameLength = request.Tls.AlpnLength;
            tlsOptions.AlpnProtocols = &explicitAlpn;
            tlsOptions.AlpnProtocolCount = 1;
        }
        else if (IsAutomaticHttpAlpnMode(request)) {
            tlsOptions.AlpnProtocols = automaticAlpnProtocols;
            tlsOptions.AlpnProtocolCount =
                sizeof(automaticAlpnProtocols) / sizeof(automaticAlpnProtocols[0]);
        }

        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
            connection.RawTransport->SetCancellation(&cancellation);
        }

        NTSTATUS status = tlsConnection->Connect(*connection.RawTransport, tlsOptions);
        if (cancellationOperation != nullptr) {
            connection.RawTransport->SetCancellation(nullptr);
        }

        if (!NT_SUCCESS(status)) {
            if (failure != nullptr) {
                *failure = tlsConnection->LastHandshakeFailure();
            }
            FreeNonPagedObject(tlsConnection);
            FreeNonPagedObject(certificateScratch);
            FreeNonPagedObject(handshakeScratch);
            return status;
        }

        auto* tlsTransport = AllocateNonPagedObject<core::TlsTransport>(*connection.RawTransport, *tlsConnection);
        if (tlsTransport == nullptr) {
            FreeNonPagedObject(tlsConnection);
            FreeNonPagedObject(certificateScratch);
            FreeNonPagedObject(handshakeScratch);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        FreeNonPagedObject(certificateScratch);
        FreeNonPagedObject(handshakeScratch);
        connection.Tls = tlsConnection;
        connection.Transport = tlsTransport;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS EnsureTlsConnected(
        _In_ KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Inout_ KhPooledConnection& connection,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (session == nullptr || connection.Socket == nullptr || connection.RawTransport == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (connection.Tls != nullptr &&
            connection.Tls->IsEstablished() &&
            connection.Transport != nullptr &&
            connection.Transport != connection.RawTransport) {
            return STATUS_SUCCESS;
        }

        ReleaseTlsLayer(connection);

        tls::TlsHandshakeFailure failure = {};
        NTSTATUS status = EstablishProxyTunnel(
            session,
            request,
            workspace,
            connection,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            cancellationOperation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ConnectTlsOnExistingSocket(
            session,
            request,
            workspace,
            connection,
            request.Tls.MaxVersion,
            cancellationOperation,
            &failure);
        if (NT_SUCCESS(status) || !IsHttpTls12ConfirmationCandidate(request, failure)) {
            return status;
        }

        const NTSTATUS originalStatus = status;
        ClosePooledTransportResources(connection);

        status = EnsureSocketConnected(session, request, connection, cancellationOperation);
        if (!NT_SUCCESS(status)) {
            kprintf(
                "HttpEngine TLS1.2 confirmation reconnect failed: 0x%08X original=0x%08X\r\n",
                static_cast<ULONG>(status),
                static_cast<ULONG>(originalStatus));
            return originalStatus;
        }

        status = EstablishProxyTunnel(
            session,
            request,
            workspace,
            connection,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            cancellationOperation);
        if (!NT_SUCCESS(status)) {
            kprintf(
                "HttpEngine TLS1.2 confirmation proxy CONNECT failed: 0x%08X original=0x%08X\r\n",
                static_cast<ULONG>(status),
                static_cast<ULONG>(originalStatus));
            return originalStatus;
        }

        status = ConnectTlsOnExistingSocket(
            session,
            request,
            workspace,
            connection,
            KhTlsVersion::Tls12,
            cancellationOperation,
            nullptr);
        if (NT_SUCCESS(status)) {
            kprintf("HttpEngine TLS1.2 confirmed after version negotiation\r\n");
            return STATUS_SUCCESS;
        }

        kprintf(
            "HttpEngine TLS1.2 confirmation failed: 0x%08X original=0x%08X\r\n",
            static_cast<ULONG>(status),
            static_cast<ULONG>(originalStatus));
        ClosePooledTransportResources(connection);
        return originalStatus;
    }
#endif

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    class WskCancellationScope final
    {
    public:
        WskCancellationScope(
            _In_opt_ core::WskTransport* transport,
            _In_opt_ KH_ASYNC_OPERATION operation) noexcept :
            transport_(transport)
        {
            if (transport_ == nullptr || operation == nullptr) {
                return;
            }

            token_.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            token_.Context = operation;
            transport_->SetCancellation(&token_);
        }

        ~WskCancellationScope() noexcept
        {
            if (transport_ != nullptr) {
                transport_->SetCancellation(nullptr);
            }
        }

        WskCancellationScope(const WskCancellationScope&) = delete;
        WskCancellationScope& operator=(const WskCancellationScope&) = delete;

    private:
        core::WskTransport* transport_ = nullptr;
        net::WskCancellationToken token_ = {};
    };
#endif

    _Must_inspect_result_
    NTSTATUS SendViaTransport(
        KH_SESSION session,
        const KhRequest& request,
        KhWorkspace& workspace,
        KhPooledConnection* pooledConnection,
        bool reusedConnection,
        SIZE_T builtRequestLength,
        _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength,
        _Out_ bool* connectionReusable,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (connectionReusable != nullptr) {
            *connectionReusable = false;
        }

        if (session == nullptr ||
            parsed == nullptr ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr ||
            rawResponseLength == nullptr ||
            connectionReusable == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsHttpsRequest(request) &&
            request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            !IsSupportedHttpAlpn(request.Tls.Alpn, request.Tls.AlpnLength)) {
            return STATUS_NOT_SUPPORTED;
        }
        if (session->Options.Proxy.Enabled && !IsHttpsRequest(request)) {
            return STATUS_NOT_SUPPORTED;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(requestHeaders);
        UNREFERENCED_PARAMETER(requestHeaderCount);
        UNREFERENCED_PARAMETER(cancellationOperation);

        if (g_testHttpTransport == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        KhTestHttpTransportRequest testRequest = {};
        testRequest.Scheme = request.Scheme;
        testRequest.SchemeLength = request.SchemeLength;
        testRequest.Host = request.Host;
        testRequest.HostLength = request.HostLength;
        testRequest.Port = request.Port;
        testRequest.AddressFamily = request.AddressFamily;
        testRequest.BuiltRequest = reinterpret_cast<const char*>(workspace.Request.Data);
        testRequest.BuiltRequestLength = builtRequestLength;
        testRequest.ConnectionPolicy = request.ConnectionPolicy;
        testRequest.CertificatePolicy = request.Tls.CertificatePolicy;
        testRequest.CertificateStore = request.Tls.CertificateStore;
        testRequest.ClientCredential = request.Tls.ClientCredential;
        testRequest.Alpn = request.Tls.Alpn;
        testRequest.AlpnLength = request.Tls.AlpnLength;
        if (IsAutomaticHttpAlpnMode(request)) {
            testRequest.OfferedAlpn = "h2,http/1.1";
            testRequest.OfferedAlpnLength = 11;
        }
        else if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            testRequest.OfferedAlpn = request.Tls.Alpn;
            testRequest.OfferedAlpnLength = request.Tls.AlpnLength;
        }
        testRequest.Policy = request.Tls.Policy;
        testRequest.ProxyEnabled = session->Options.Proxy.Enabled;
        testRequest.ProxyAddress = session->Options.Proxy.Address;
        testRequest.ProxyAuthority = session->Options.Proxy.Authority;
        testRequest.ProxyAuthorityLength = session->Options.Proxy.AuthorityLength;
        testRequest.ProxyAuthHeader = session->Options.Proxy.AuthHeader;
        testRequest.ProxyAuthHeaderLength = session->Options.Proxy.AuthHeaderLength;
        testRequest.PoolableConnection = request.ConnectionPolicy != KhConnectionPolicy::NoPool;
        testRequest.ReusedConnection = reusedConnection;
        testRequest.ConnectionId = pooledConnection != nullptr ? pooledConnection->Id : 0;

        KhTestHttpTransportResponse testResponse = {};
        NTSTATUS status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (TextEqualsLiteral(testResponse.NegotiatedAlpn, testResponse.NegotiatedAlpnLength, "h2")) {
            parsed->MajorVersion = 2;
            parsed->MinorVersion = 0;
            parsed->StatusCode = 200;
            workspace.ResponseLength = 0;
            *rawResponseLength = 0;
            *connectionReusable = false;
            return STATUS_SUCCESS;
        }

        if (request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "h2") &&
            !TextEqualsLiteral(testResponse.NegotiatedAlpn, testResponse.NegotiatedAlpnLength, "h2")) {
            return STATUS_NOT_SUPPORTED;
        }

        if (testResponse.RawResponse == nullptr || testResponse.RawResponseLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = KhWorkspaceEnsureResponseCapacity(&workspace, testResponse.RawResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlCopyMemory(workspace.Response.Data, testResponse.RawResponse, testResponse.RawResponseLength);
        workspace.ResponseLength = testResponse.RawResponseLength;

        status = ParseResponseBytes(
            workspace,
            workspace.ResponseLength,
            !testResponse.ConnectionReusable,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *rawResponseLength = workspace.ResponseLength;
        *connectionReusable =
            testResponse.ConnectionReusable &&
            IsHttpConnectionReusable(*parsed, *rawResponseLength);
        return STATUS_SUCCESS;
#else
        UNREFERENCED_PARAMETER(reusedConnection);

        if (pooledConnection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsHttpsRequest(request)) {
            if (request.Tls.CertificatePolicy == KhCertificatePolicy::Verify &&
                request.Tls.CertificateStore == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        else if (!TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "http")) {
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS status = EnsureSocketConnected(session, request, *pooledConnection, cancellationOperation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        tls::TlsConnection* tlsConnection = nullptr;
        if (IsHttpsRequest(request)) {
            status = EnsureTlsConnected(
                session,
                request,
                workspace,
                *pooledConnection,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                cancellationOperation);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            tlsConnection = pooledConnection->Tls;
        }

        if (tlsConnection != nullptr && IsAutomaticHttpAlpnMode(request)) {
            const char* negotiatedAlpn = tlsConnection->NegotiatedAlpn();
            const SIZE_T negotiatedAlpnLength = tlsConnection->NegotiatedAlpnLength();
            if (negotiatedAlpnLength != 0) {
                NTSTATUS keyStatus = CopyExactText(
                    negotiatedAlpn,
                    negotiatedAlpnLength,
                    pooledConnection->Key.Alpn,
                    sizeof(pooledConnection->Key.Alpn),
                    &pooledConnection->Key.AlpnLength);
                if (!NT_SUCCESS(keyStatus)) {
                    return keyStatus;
                }
            }
        }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        WskCancellationScope cancellationScope(pooledConnection->RawTransport, cancellationOperation);
#else
        UNREFERENCED_PARAMETER(cancellationOperation);
#endif

        const bool h2ExplicitlyRequested =
            request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "h2");
        const bool h2Negotiated =
            tlsConnection != nullptr &&
            TextEqualsLiteral(
                tlsConnection->NegotiatedAlpn(),
                tlsConnection->NegotiatedAlpnLength(),
                "h2");

        if (h2Negotiated || h2ExplicitlyRequested) {
            if (pooledConnection->Transport == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            const char* negotiatedAlpn = tlsConnection->NegotiatedAlpn();
            const SIZE_T negotiatedAlpnLength = tlsConnection->NegotiatedAlpnLength();
            if (!TextEqualsLiteral(negotiatedAlpn, negotiatedAlpnLength, "h2")) {
                kprintf("High-level HTTP/2 ALPN not negotiated: %.*s\r\n",
                    static_cast<int>(negotiatedAlpnLength),
                    negotiatedAlpn != nullptr ? negotiatedAlpn : "");
                return STATUS_NOT_SUPPORTED;
            }

            status = SendHttp2ViaTransport(
                request,
                workspace,
                *pooledConnection,
                session->Options.Http2MaxHeaderBlockBytes,
                requestHeaders,
                requestHeaderCount,
                parsed,
                responseHeaders,
                headerCapacity,
                rawResponseLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *connectionReusable =
                pooledConnection->Http2 != nullptr &&
                pooledConnection->Http2->IsReusable();
            return STATUS_SUCCESS;
        }

        SIZE_T sent = 0;
        if (pooledConnection->Transport == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        status = pooledConnection->Transport->Send(
            workspace.Request.Data,
            builtRequestLength,
            &sent);

        if (NT_SUCCESS(status) && sent != builtRequestLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadHttpResponseFromSocket(
            *pooledConnection->Transport,
            workspace,
            request.Method == KhHttpMethod::Head,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *connectionReusable = IsHttpConnectionReusable(*parsed, *rawResponseLength);
        return STATUS_SUCCESS;
#endif
    }

    SIZE_T LiteralLength(_In_z_ const char* text) noexcept
    {
        SIZE_T length = 0;
        if (text == nullptr) {
            return 0;
        }

        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    char HttpRedirectToLowerAscii(char value) noexcept
    {
        return value >= 'A' && value <= 'Z' ?
            static_cast<char>(value - 'A' + 'a') :
            value;
    }

    bool StartsWithLiteralIgnoreCase(
        const char* value,
        SIZE_T valueLength,
        _In_z_ const char* literal) noexcept
    {
        const SIZE_T literalLength = LiteralLength(literal);
        if (value == nullptr || literal == nullptr || literalLength > valueLength) {
            return false;
        }

        for (SIZE_T index = 0; index < literalLength; ++index) {
            if (HttpRedirectToLowerAscii(value[index]) != HttpRedirectToLowerAscii(literal[index])) {
                return false;
            }
        }
        return true;
    }

    bool IsRedirectStatus(USHORT statusCode) noexcept
    {
        return statusCode == 301 ||
            statusCode == 302 ||
            statusCode == 303 ||
            statusCode == 307 ||
            statusCode == 308;
    }

    bool ShouldRewriteRedirectToGet(USHORT statusCode, KhHttpMethod method) noexcept
    {
        if (statusCode == 303) {
            return method != KhHttpMethod::Head;
        }

        if (statusCode != 301 && statusCode != 302) {
            return false;
        }

        return method == KhHttpMethod::Post;
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    static bool IsHttpAsyncCancellationRequested(_In_opt_ void* context) noexcept
    {
        return context != nullptr &&
            KhAsyncOperationIsCanceled(static_cast<KH_ASYNC_OPERATION>(context));
    }
#endif

    bool RedirectsEnabled(const KhHttpSendOptions& options) noexcept
    {
        return (options.Flags & KhHttpSendFlagDisableAutoRedirect) == 0;
    }

    ULONG EffectiveMaxRedirects(const KhHttpSendOptions& options) noexcept
    {
        return options.MaxRedirects != 0 ? options.MaxRedirects : KhDefaultMaxRedirects;
    }

    http::HttpText FindLocationHeader(const http::HttpResponse& response) noexcept
    {
        const http::HttpHeader* header = nullptr;
        if (response.FindHeader(http::MakeText("Location"), &header) && header != nullptr) {
            return header->Value;
        }

        return {};
    }

    bool IsAbsoluteHttpLocation(http::HttpText location) noexcept
    {
        return StartsWithLiteralIgnoreCase(location.Data, location.Length, "http://") ||
            StartsWithLiteralIgnoreCase(location.Data, location.Length, "https://");
    }

    http::HttpText TrimRedirectLocation(http::HttpText location) noexcept
    {
        while (location.Length != 0 &&
            (location.Data[0] == ' ' || location.Data[0] == '\t')) {
            ++location.Data;
            --location.Length;
        }

        while (location.Length != 0 &&
            (location.Data[location.Length - 1] == ' ' ||
                location.Data[location.Length - 1] == '\t')) {
            --location.Length;
        }
        return location;
    }

    bool IsUriSchemeChar(char value, bool first) noexcept
    {
        if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')) {
            return true;
        }
        if (first) {
            return false;
        }
        return (value >= '0' && value <= '9') ||
            value == '+' ||
            value == '-' ||
            value == '.';
    }

    bool HasUriScheme(http::HttpText location) noexcept
    {
        if (location.Data == nullptr || location.Length == 0) {
            return false;
        }

        for (SIZE_T index = 0; index < location.Length; ++index) {
            const char value = location.Data[index];
            if (value == ':' && index != 0) {
                for (SIZE_T schemeIndex = 0; schemeIndex < index; ++schemeIndex) {
                    if (!IsUriSchemeChar(location.Data[schemeIndex], schemeIndex == 0)) {
                        return false;
                    }
                }
                return true;
            }
            if (value == '/' || value == '?' || value == '#') {
                return false;
            }
        }
        return false;
    }

    bool IsSchemeRelativeLocation(http::HttpText location) noexcept
    {
        return location.Data != nullptr &&
            location.Length >= 2 &&
            location.Data[0] == '/' &&
            location.Data[1] == '/';
    }

    bool IsPathAbsoluteLocation(http::HttpText location) noexcept
    {
        return location.Data != nullptr &&
            location.Length >= 1 &&
            location.Data[0] == '/';
    }

    _Must_inspect_result_
    NTSTATUS AppendRedirectText(
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* offset,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength) noexcept
    {
        if (destination == nullptr ||
            offset == nullptr ||
            (text == nullptr && textLength != 0) ||
            *offset > destinationCapacity ||
            textLength > destinationCapacity - *offset) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (textLength != 0) {
            RtlCopyMemory(destination + *offset, text, textLength);
            *offset += textLength;
        }
        return STATUS_SUCCESS;
    }

    void RemovePreviousRedirectPathSegment(
        _Inout_updates_(*pathLength) char* path,
        _Inout_ SIZE_T* pathLength) noexcept
    {
        if (path == nullptr || pathLength == nullptr || *pathLength == 0) {
            return;
        }

        SIZE_T end = *pathLength;
        if (end > 1 && path[end - 1] == '/') {
            --end;
        }

        while (end > 0 && path[end - 1] != '/') {
            --end;
        }

        *pathLength = end == 0 ? 0 : end;
        if (*pathLength == 0) {
            path[(*pathLength)++] = '/';
        }
    }

    void RemoveRedirectDotSegments(
        _Inout_updates_(*pathLength) char* path,
        _Inout_ SIZE_T* pathLength) noexcept
    {
        if (path == nullptr || pathLength == nullptr || *pathLength == 0) {
            return;
        }

        const SIZE_T inputLength = *pathLength;
        SIZE_T read = 0;
        SIZE_T write = 0;
        while (read < inputLength) {
            if (path[read] == '/') {
                path[write++] = path[read++];
                continue;
            }

            const SIZE_T segmentStart = read;
            while (read < inputLength && path[read] != '/') {
                ++read;
            }
            const SIZE_T segmentLength = read - segmentStart;

            if (segmentLength == 1 && path[segmentStart] == '.') {
                if (read < inputLength && path[read] == '/') {
                    ++read;
                }
                continue;
            }

            if (segmentLength == 2 &&
                path[segmentStart] == '.' &&
                path[segmentStart + 1] == '.') {
                RemovePreviousRedirectPathSegment(path, &write);
                if (read < inputLength && path[read] == '/') {
                    ++read;
                }
                continue;
            }

            if (write != segmentStart) {
                RtlMoveMemory(path + write, path + segmentStart, segmentLength);
            }
            write += segmentLength;
        }

        if (write == 0) {
            path[write++] = '/';
        }
        *pathLength = write;
    }

    SIZE_T FindRedirectChar(
        _In_reads_bytes_opt_(textLength) const char* text,
        SIZE_T textLength,
        char needle) noexcept
    {
        if (text == nullptr) {
            return textLength;
        }
        for (SIZE_T index = 0; index < textLength; ++index) {
            if (text[index] == needle) {
                return index;
            }
        }
        return textLength;
    }

    http::HttpText BaseRequestFragment(const KhRequest& request) noexcept
    {
        if (request.Url == nullptr || request.UrlLength == 0) {
            return {};
        }

        const SIZE_T fragment = FindRedirectChar(request.Url, request.UrlLength, '#');
        if (fragment == request.UrlLength) {
            return {};
        }
        return { request.Url + fragment, request.UrlLength - fragment };
    }

    _Must_inspect_result_
    NTSTATUS AppendRedirectOrigin(
        const KhRequest& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* offset) noexcept
    {
        NTSTATUS status = AppendRedirectText(
            destination,
            destinationCapacity,
            offset,
            request.Scheme,
            request.SchemeLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendRedirectText(destination, destinationCapacity, offset, "://", 3);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T authorityLength = 0;
        status = BuildHostHeaderValue(
            request,
            destination + *offset,
            destinationCapacity - *offset,
            &authorityLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        *offset += authorityLength;
        return STATUS_SUCCESS;
    }

    void SplitRedirectReference(
        http::HttpText location,
        _Out_ http::HttpText* path,
        _Out_ http::HttpText* query,
        _Out_ http::HttpText* fragment,
        _Out_ bool* hasQuery,
        _Out_ bool* hasFragment) noexcept
    {
        if (path != nullptr) {
            *path = {};
        }
        if (query != nullptr) {
            *query = {};
        }
        if (fragment != nullptr) {
            *fragment = {};
        }
        if (hasQuery != nullptr) {
            *hasQuery = false;
        }
        if (hasFragment != nullptr) {
            *hasFragment = false;
        }

        if (location.Data == nullptr) {
            return;
        }

        const SIZE_T fragmentIndex = FindRedirectChar(location.Data, location.Length, '#');
        const SIZE_T queryIndex = FindRedirectChar(location.Data, fragmentIndex, '?');
        if (path != nullptr) {
            *path = { location.Data, queryIndex };
        }
        if (queryIndex < fragmentIndex) {
            if (hasQuery != nullptr) {
                *hasQuery = true;
            }
            if (query != nullptr) {
                *query = { location.Data + queryIndex, fragmentIndex - queryIndex };
            }
        }
        if (fragmentIndex < location.Length) {
            if (hasFragment != nullptr) {
                *hasFragment = true;
            }
            if (fragment != nullptr) {
                *fragment = { location.Data + fragmentIndex, location.Length - fragmentIndex };
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS AppendRedirectPathAndSuffix(
        const KhRequest& request,
        http::HttpText location,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* offset) noexcept
    {
        http::HttpText referencePath = {};
        http::HttpText referenceQuery = {};
        http::HttpText referenceFragment = {};
        bool hasReferenceQuery = false;
        bool hasReferenceFragment = false;
        SplitRedirectReference(
            location,
            &referencePath,
            &referenceQuery,
            &referenceFragment,
            &hasReferenceQuery,
            &hasReferenceFragment);

        const SIZE_T baseQueryIndex = FindRedirectChar(request.Path, request.PathLength, '?');
        const http::HttpText basePath = { request.Path, baseQueryIndex };
        const http::HttpText baseQuery =
            baseQueryIndex < request.PathLength ?
            http::HttpText{ request.Path + baseQueryIndex, request.PathLength - baseQueryIndex } :
            http::HttpText{};

        const SIZE_T pathStartOffset = *offset;
        NTSTATUS status = STATUS_SUCCESS;
        if (referencePath.Length == 0) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                basePath.Data,
                basePath.Length);
        }
        else if (referencePath.Data[0] == '/') {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                referencePath.Data,
                referencePath.Length);
        }
        else {
            SIZE_T baseDirectoryLength = basePath.Length;
            while (baseDirectoryLength != 0 && basePath.Data[baseDirectoryLength - 1] != '/') {
                --baseDirectoryLength;
            }
            if (baseDirectoryLength == 0) {
                status = AppendRedirectText(destination, destinationCapacity, offset, "/", 1);
            }
            else {
                status = AppendRedirectText(
                    destination,
                    destinationCapacity,
                    offset,
                    basePath.Data,
                    baseDirectoryLength);
            }
            if (NT_SUCCESS(status)) {
                status = AppendRedirectText(
                    destination,
                    destinationCapacity,
                    offset,
                    referencePath.Data,
                    referencePath.Length);
            }
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T normalizedPathLength = *offset - pathStartOffset;
        RemoveRedirectDotSegments(destination + pathStartOffset, &normalizedPathLength);
        *offset = pathStartOffset + normalizedPathLength;

        if (hasReferenceQuery) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                referenceQuery.Data,
                referenceQuery.Length);
        }
        else if (referencePath.Length == 0 && baseQuery.Data != nullptr) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                baseQuery.Data,
                baseQuery.Length);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const http::HttpText fragmentToAppend =
            hasReferenceFragment ? referenceFragment : BaseRequestFragment(request);
        if (fragmentToAppend.Data != nullptr && fragmentToAppend.Length != 0) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                fragmentToAppend.Data,
                fragmentToAppend.Length);
        }
        return status;
    }

    void ReleaseStoredRedirectHeader(_Inout_ KhStoredHeader& header) noexcept
    {
        FreeApiMemory(header.Name);
        FreeApiMemory(header.Value);
        header = {};
    }

    void RemoveRedirectSensitiveHeaders(_Inout_ KhRequest& request) noexcept
    {
        SIZE_T index = 0;
        while (index < request.HeaderCount) {
            const KhStoredHeader& header = request.Headers[index];
            const bool sensitive =
                TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, "Authorization") ||
                TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, "Cookie") ||
                TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, "Proxy-Authorization");
            if (!sensitive) {
                ++index;
                continue;
            }

            ReleaseStoredRedirectHeader(request.Headers[index]);
            for (SIZE_T moveIndex = index + 1; moveIndex < request.HeaderCount; ++moveIndex) {
                request.Headers[moveIndex - 1] = request.Headers[moveIndex];
            }
            --request.HeaderCount;
            request.Headers[request.HeaderCount] = {};
        }
    }

    bool IsCrossOriginRedirect(
        const char* oldScheme,
        SIZE_T oldSchemeLength,
        const char* oldHost,
        SIZE_T oldHostLength,
        USHORT oldPort,
        const KhRequest& redirected) noexcept
    {
        return oldPort != redirected.Port ||
            !TextEqualsIgnoreCase(oldScheme, oldSchemeLength, redirected.Scheme, redirected.SchemeLength) ||
            !TextEqualsIgnoreCase(oldHost, oldHostLength, redirected.Host, redirected.HostLength);
    }

    bool IsHttpsDowngradeRedirect(
        const KhRequest& request,
        http::HttpText redirectUrl) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https") &&
            StartsWithLiteralIgnoreCase(redirectUrl.Data, redirectUrl.Length, "http://");
    }

    _Must_inspect_result_
    NTSTATUS BuildRedirectUrl(
        const KhRequest& request,
        http::HttpText location,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        location = TrimRedirectLocation(location);
        if (location.Data == nullptr ||
            location.Length == 0 ||
            destination == nullptr ||
            destinationLength == nullptr ||
            request.SchemeLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsAbsoluteHttpLocation(location)) {
            SIZE_T offset = 0;
            NTSTATUS status = AppendRedirectText(
                destination,
                destinationCapacity,
                &offset,
                location.Data,
                location.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (FindRedirectChar(location.Data, location.Length, '#') == location.Length) {
                const http::HttpText baseFragment = BaseRequestFragment(request);
                if (baseFragment.Data != nullptr && baseFragment.Length != 0) {
                    status = AppendRedirectText(
                        destination,
                        destinationCapacity,
                        &offset,
                        baseFragment.Data,
                        baseFragment.Length);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }

            *destinationLength = offset;
            return STATUS_SUCCESS;
        }

        if (HasUriScheme(location)) {
            return STATUS_NOT_SUPPORTED;
        }

        SIZE_T offset = 0;
        if (IsSchemeRelativeLocation(location)) {
            NTSTATUS status = AppendRedirectText(
                destination,
                destinationCapacity,
                &offset,
                request.Scheme,
                request.SchemeLength);
            if (NT_SUCCESS(status)) {
                status = AppendRedirectText(destination, destinationCapacity, &offset, ":", 1);
            }
            if (NT_SUCCESS(status)) {
                status = AppendRedirectText(
                    destination,
                    destinationCapacity,
                    &offset,
                    location.Data,
                    location.Length);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            *destinationLength = offset;
            return STATUS_SUCCESS;
        }

        NTSTATUS status = AppendRedirectOrigin(request, destination, destinationCapacity, &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendRedirectPathAndSuffix(
            request,
            location,
            destination,
            destinationCapacity,
            &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        *destinationLength = offset;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ApplyRedirectToRequest(
        _Inout_ KhRequest& request,
        USHORT statusCode,
        http::HttpText location,
        _Inout_ KhWorkspace& workspace) noexcept
    {
        HeapObject<RedirectOriginSnapshot> oldOrigin;
        if (!oldOrigin.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        const SIZE_T oldSchemeLength = request.SchemeLength;
        const SIZE_T oldHostLength = request.HostLength;
        const USHORT oldPort = request.Port;
        const bool hadTlsOverride = request.HasTlsOverride;
        const bool tlsServerNameMatchedOldHost =
            request.Tls.ServerName == nullptr ||
            TextEqualsIgnoreCase(
                request.Tls.ServerName,
                request.Tls.ServerNameLength,
                request.Host,
                request.HostLength);
        RtlCopyMemory(oldOrigin->Scheme, request.Scheme, sizeof(oldOrigin->Scheme));
        RtlCopyMemory(oldOrigin->Host, request.Host, sizeof(oldOrigin->Host));

        SIZE_T redirectUrlLength = 0;
        NTSTATUS status = BuildRedirectUrl(
            request,
            location,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            &redirectUrlLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const char* redirectUrl = reinterpret_cast<const char*>(workspace.Request.Data);

        if (IsHttpsDowngradeRedirect(request, { redirectUrl, redirectUrlLength })) {
            return STATUS_NOT_SUPPORTED;
        }

        status = KhHttpRequestSetUrl(&request, redirectUrl, redirectUrlLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (IsCrossOriginRedirect(
            oldOrigin->Scheme,
            oldSchemeLength,
            oldOrigin->Host,
            oldHostLength,
            oldPort,
            request)) {
            if (hadTlsOverride && !tlsServerNameMatchedOldHost) {
                return STATUS_NOT_SUPPORTED;
            }
            if (TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https")) {
                FreeApiMemory(request.OwnedTlsServerName);
                request.OwnedTlsServerName = nullptr;
                request.Tls.ServerName = request.Host;
                request.Tls.ServerNameLength = request.HostLength;
            }
            RemoveRedirectSensitiveHeaders(request);
        }

        if (ShouldRewriteRedirectToGet(statusCode, request.Method)) {
            status = KhHttpRequestSetMethod(&request, KhHttpMethod::Get);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = KhHttpRequestClearBody(&request);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SendSingleHttpRequest(
        KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Inout_ ApiHttpHeaderScratch& headerScratch,
        _Out_ http::HttpResponse* parsed,
        _Out_ SIZE_T* rawResponseLength,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (parsed != nullptr) {
            *parsed = {};
        }
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (session == nullptr || parsed == nullptr || rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        KhWorkspaceReset(&workspace);

        NTSTATUS status = PrepareApiHttpHeaderScratch(workspace, &headerScratch);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T builtRequestLength = 0;
        SIZE_T requestHeaderCount = 0;
        status = BuildRequestBytes(
            request,
            workspace,
            headerScratch.HostHeader,
            headerScratch.HostHeaderCapacity,
            headerScratch.RequestHeaders,
            KhMaxHeadersPerRequest,
            headerScratch.RequestTrailers,
            KhMaxHeadersPerRequest,
            &builtRequestLength,
            &requestHeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapObject<KhConnectionPoolKey> poolKey;
        if (!poolKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = BuildPoolKey(request, session->Options.Proxy, poolKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        KhPooledConnection* pooledConnection = nullptr;
        bool reusedConnection = false;
        status = KhConnectionPoolAcquire(
            &session->ConnectionPool,
            *poolKey.Get(),
            request.ConnectionPolicy,
            &pooledConnection,
            &reusedConnection);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        bool connectionReusable = false;
        const SIZE_T responseHeaderCapacity = session->Options.MaxResponseHeaders;
        status = SendViaTransport(
            session,
            request,
            workspace,
            pooledConnection,
            reusedConnection,
            builtRequestLength,
            headerScratch.RequestHeaders,
            requestHeaderCount,
            parsed,
            headerScratch.ResponseHeaders,
            responseHeaderCapacity,
            headerScratch.ResponseTrailers,
            KhMaxTrailersPerResponse,
            rawResponseLength,
            &connectionReusable,
            cancellationOperation);

        const bool shouldRetryWithFreshConnection =
            ShouldRetryWithFreshConnection(request, status, reusedConnection);

        if (shouldRetryWithFreshConnection) {
            KhConnectionPoolClose(&session->ConnectionPool, pooledConnection);
            pooledConnection = nullptr;

            KhPooledConnection* retryConnection = nullptr;
            bool retryReused = false;
            NTSTATUS retryStatus = KhConnectionPoolAcquire(
                &session->ConnectionPool,
                *poolKey.Get(),
                KhConnectionPolicy::ForceNew,
                &retryConnection,
                &retryReused);
            if (NT_SUCCESS(retryStatus) && !retryReused) {
                KhWorkspaceReset(&workspace);
                retryStatus = PrepareApiHttpHeaderScratch(workspace, &headerScratch);
                if (NT_SUCCESS(retryStatus)) {
                    retryStatus = BuildRequestBytes(
                        request,
                        workspace,
                        headerScratch.HostHeader,
                        headerScratch.HostHeaderCapacity,
                        headerScratch.RequestHeaders,
                        KhMaxHeadersPerRequest,
                        headerScratch.RequestTrailers,
                        KhMaxHeadersPerRequest,
                        &builtRequestLength,
                        &requestHeaderCount);
                }
                if (!NT_SUCCESS(retryStatus)) {
                    KhConnectionPoolRelease(&session->ConnectionPool, retryConnection, false);
                    return retryStatus;
                }

                *parsed = {};
                *rawResponseLength = 0;
                connectionReusable = false;
                status = SendViaTransport(
                    session,
                    request,
                    workspace,
                    retryConnection,
                    retryReused,
                    builtRequestLength,
                    headerScratch.RequestHeaders,
                    requestHeaderCount,
                    parsed,
                    headerScratch.ResponseHeaders,
                    responseHeaderCapacity,
                    headerScratch.ResponseTrailers,
                    KhMaxTrailersPerResponse,
                    rawResponseLength,
                    &connectionReusable,
                    cancellationOperation);

                if (!NT_SUCCESS(status)) {
                    KhConnectionPoolRelease(&session->ConnectionPool, retryConnection, false);
                    retryConnection = nullptr;
                }
                else {
                    pooledConnection = retryConnection;
                }
            }
        }

        const bool canReturnToPool =
            NT_SUCCESS(status) &&
            connectionReusable &&
            request.ConnectionPolicy == KhConnectionPolicy::ReuseOrCreate;
        KhConnectionPoolRelease(&session->ConnectionPool, pooledConnection, canReturnToPool);
        return status;
    }


    struct KhAsyncHttpContext final
    {
        KH_SESSION Session = nullptr;
        KH_REQUEST Request = nullptr;
        KhHttpSendOptions Options = {};
        KH_RESPONSE Response = nullptr;
        volatile LONG SessionOperationEnded = 0;
    };

    _Ret_maybenull_
    KH_RESPONSE TakeAsyncHttpResponse(_Inout_ KhAsyncHttpContext* context) noexcept
    {
        if (context == nullptr) {
            return nullptr;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        KH_RESPONSE response = context->Response;
        context->Response = nullptr;
        return response;
#else
        return static_cast<KH_RESPONSE>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&context->Response),
            nullptr));
#endif
    }

    void EndAsyncHttpSessionOperation(_Inout_ KhAsyncHttpContext* context) noexcept
    {
        if (context == nullptr || context->Session == nullptr) {
            return;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (context->SessionOperationEnded != 0) {
            return;
        }
        context->SessionOperationEnded = 1;
#else
        if (InterlockedCompareExchange(&context->SessionOperationEnded, 1, 0) != 0) {
            return;
        }
#endif
        KhSessionEndOperation(context->Session);
    }


    _Ret_maybenull_
    KhAsyncHttpContext* AllocateAsyncHttpContext() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhAsyncHttpContext*>(calloc(1, sizeof(KhAsyncHttpContext)));
#else
        return AllocateNonPagedObject<KhAsyncHttpContext>();
#endif
    }

    void FreeAsyncHttpContext(_In_opt_ KhAsyncHttpContext* context) noexcept
    {
        if (context == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(context);
#else
        FreeNonPagedObject(context);
#endif
    }


    void CleanupAsyncHttpContext(void* context) noexcept
    {
        auto* httpContext = static_cast<KhAsyncHttpContext*>(context);
        if (httpContext == nullptr) {
            return;
        }

        EndAsyncHttpSessionOperation(httpContext);

        KH_RESPONSE response = TakeAsyncHttpResponse(httpContext);
        if (response != nullptr) {
            KhResponseRelease(response);
        }

        if (httpContext->Request != nullptr) {
            KhHttpRequestRelease(httpContext->Request);
            httpContext->Request = nullptr;
        }
        FreeAsyncHttpContext(httpContext);
    }

    _Must_inspect_result_
    NTSTATUS KhHttpSendSyncImpl(
        _In_ KH_SESSION session,
        _In_ KH_REQUEST request,
        _In_opt_ const KhHttpSendOptions* options,
        KH_RESPONSE* response,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept;

    NTSTATUS RunHttpAsyncOperation(KH_ASYNC_OPERATION operation, void* context) noexcept
    {
        auto* httpContext = static_cast<KhAsyncHttpContext*>(context);
        if (httpContext == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        if (KhAsyncOperationIsCanceled(operation)) {
            status = STATUS_CANCELLED;
            EndAsyncHttpSessionOperation(httpContext);
            return status;
        }

        KH_RESPONSE response = nullptr;
        KH_RESPONSE* responseOutput = nullptr;
        const bool bodyCallbackOnly =
            httpContext->Options.BodyCallback != nullptr &&
            ((httpContext->Options.Flags & KhHttpSendFlagAggregateWithCallbacks) == 0);
        if (!bodyCallbackOnly) {
            responseOutput = &response;
        }

        status = KhHttpSendSyncImpl(
            httpContext->Session,
            httpContext->Request,
            &httpContext->Options,
            responseOutput,
            operation);
        if (NT_SUCCESS(status)) {
            httpContext->Response = response;
        }
        else if (response != nullptr) {
            KhResponseRelease(response);
        }

        if (KhAsyncOperationIsCanceled(operation) && status == STATUS_SUCCESS) {
            status = STATUS_CANCELLED;
        }

        EndAsyncHttpSessionOperation(httpContext);
        return status;
    }


    NTSTATUS KhHttpSendSyncImpl(
        KH_SESSION session,
        KH_REQUEST request,
        const KhHttpSendOptions* options,
        KH_RESPONSE* response,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (response != nullptr) {
            *response = nullptr;
        }

        KhSessionOperationScope sessionScope(session);
        if (!sessionScope.IsActive()) {
            return STATUS_INVALID_PARAMETER;
        }

        KhRequestOperationScope requestScope(request);
        if (!requestScope.IsActive() || request->Session != session) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request->Url == nullptr || request->UrlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (TextEqualsLiteralIgnoreCase(request->Scheme, request->SchemeLength, "https") &&
            request->Tls.Alpn != nullptr &&
            request->Tls.AlpnLength != 0 &&
            !IsSupportedHttpAlpn(request->Tls.Alpn, request->Tls.AlpnLength)) {
            return STATUS_NOT_SUPPORTED;
        }

        KhHttpSendOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidSendOptions(effectiveOptions, *session)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (effectiveOptions.BodyCallback != nullptr &&
            response == nullptr &&
            ((effectiveOptions.Flags & KhHttpSendFlagAggregateWithCallbacks) != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool bodyCallbackOnly =
            effectiveOptions.BodyCallback != nullptr &&
            ((effectiveOptions.Flags & KhHttpSendFlagAggregateWithCallbacks) == 0);
        const bool shouldAggregate = !bodyCallbackOnly;
        if (shouldAggregate && response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T maxResponseBytes =
            EffectiveMaxResponseBytes(options, session->Options.MaxResponseBytes);
        WorkspaceGuard requestWorkspace;
        status = requestWorkspace.CreateForSession(session, maxResponseBytes);
        if (!NT_SUCCESS(status) || !requestWorkspace.IsValid()) {
            return !NT_SUCCESS(status) ? status : STATUS_INSUFFICIENT_RESOURCES;
        }
        KhWorkspace& workspace = *requestWorkspace.Get();

        HeapObject<ApiHttpHeaderScratch> headerScratch;
        if (!headerScratch.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        http::HttpResponse parsed = {};
        SIZE_T rawResponseLength = 0;
        KH_REQUEST redirectRequest = nullptr;
        KhRequest* currentRequest = request;
        const bool followRedirects = RedirectsEnabled(effectiveOptions);
        const ULONG maxRedirects = EffectiveMaxRedirects(effectiveOptions);
        ULONG redirectCount = 0;

        for (;;) {
            if (cancellationOperation != nullptr && KhAsyncOperationIsCanceled(cancellationOperation)) {
                status = STATUS_CANCELLED;
                break;
            }

            status = SendSingleHttpRequest(
                session,
                *currentRequest,
                workspace,
                *headerScratch.Get(),
                &parsed,
                &rawResponseLength,
                cancellationOperation);
            if (!NT_SUCCESS(status)) {
                break;
            }

            if (!followRedirects ||
                !IsRedirectStatus(parsed.StatusCode) ||
                redirectCount >= maxRedirects) {
                break;
            }

            const http::HttpText location = FindLocationHeader(parsed);
            if (location.Data == nullptr || location.Length == 0) {
                break;
            }

            if (redirectRequest == nullptr) {
                status = CloneRequestForAsync(*currentRequest, &redirectRequest);
                if (!NT_SUCCESS(status)) {
                    break;
                }
                currentRequest = redirectRequest;
            }

            status = ApplyRedirectToRequest(*currentRequest, parsed.StatusCode, location, workspace);
            if (status == STATUS_NOT_FOUND || status == STATUS_INVALID_PARAMETER) {
                status = STATUS_SUCCESS;
                break;
            }
            if (!NT_SUCCESS(status)) {
                break;
            }

            ++redirectCount;
        }

        if (NT_SUCCESS(status)) {
            status = InvokeResponseCallbacks(effectiveOptions, parsed);
        }

        if (NT_SUCCESS(status) && shouldAggregate) {
            status = CreateOwnedResponse(
                parsed,
                reinterpret_cast<const char*>(workspace.Response.Data),
                rawResponseLength,
                response);
        }

        if (redirectRequest != nullptr) {
            KhHttpRequestRelease(redirectRequest);
        }
        return status;
    }

    NTSTATUS KhHttpSendAsyncImpl(
        KH_SESSION session,
        KH_REQUEST request,
        const KhHttpSendOptions* options,
        KH_ASYNC_OPERATION* operation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (operation != nullptr) {
            *operation = nullptr;
        }

        if (!KhSessionBeginOperation(session)) {
            return STATUS_INVALID_PARAMETER;
        }

        KhRequestOperationScope requestScope(request);
        if (!requestScope.IsActive() || operation == nullptr || request->Session != session) {
            KhSessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }

        if (request->Url == nullptr || request->UrlLength == 0) {
            KhSessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }

        KhHttpSendOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidSendOptions(effectiveOptions, *session)) {
            KhSessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }

        auto* context = AllocateAsyncHttpContext();
        if (context == nullptr) {
            KhSessionEndOperation(session);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        context->Session = session;
        context->Options = effectiveOptions;
        context->Response = nullptr;
        context->SessionOperationEnded = 0;

        status = CloneRequestForAsync(*request, &context->Request);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncHttpContext(context);
            return status;
        }

        KhAsyncCreateOptions createOptions = {};
        createOptions.Kind = KhAsyncOperationKind::HttpSend;
        createOptions.WorkerRoutine = RunHttpAsyncOperation;
        createOptions.CleanupRoutine = CleanupAsyncHttpContext;
        createOptions.Context = context;
        createOptions.CompletionCallback = effectiveOptions.CompletionCallback;
        createOptions.CompletionContext = effectiveOptions.CompletionContext;
        createOptions.StartSuspended = true;

        status = KhAsyncOperationCreate(createOptions, operation);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncHttpContext(context);
            return status;
        }

        status = KhAsyncOperationQueue(*operation);
        if (!NT_SUCCESS(status)) {
            KhAsyncOperationRelease(*operation);
            *operation = nullptr;
        }

        return status;
    }


    NTSTATUS KhAsyncGetHttpResponse(KH_ASYNC_OPERATION operation, KH_RESPONSE* response) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (response != nullptr) {
            *response = nullptr;
        }

        if (!KhAsyncOperationIsValid(operation) ||
            response == nullptr ||
            KhAsyncOperationGetKind(operation) != KhAsyncOperationKind::HttpSend) {
            return STATUS_INVALID_PARAMETER;
        }

        status = KhAsyncOperationStatus(operation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* context = static_cast<KhAsyncHttpContext*>(KhAsyncOperationContext(operation));
        KH_RESPONSE asyncResponse = TakeAsyncHttpResponse(context);
        if (asyncResponse == nullptr) {
            return STATUS_NOT_FOUND;
        }

        *response = asyncResponse;
        return STATUS_SUCCESS;
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    bool KhTestIsHttpTls12ConfirmationCandidate(
        KhTlsVersion minVersion,
        KhTlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept
    {
        KhRequest request = {};
        request.Tls.MinVersion = minVersion;
        request.Tls.MaxVersion = maxVersion;
        tls::TlsHandshakeFailure failure = {};
        failure.Category = static_cast<tls::TlsHandshakeFailureCategory>(category);
        failure.Status = status;
        failure.BeforeTls13FirstServerHello = beforeTls13FirstServerHello;
        return IsHttpTls12ConfirmationCandidate(request, failure);
    }
#endif

NTSTATUS KhHttpSendSync(
    KH_SESSION session,
    KH_REQUEST request,
    const KhHttpSendOptions* options,
    KH_RESPONSE* response) noexcept
{
    return KhHttpSendSyncImpl(session, request, options, response, nullptr);
}

NTSTATUS KhHttpSendAsync(
    KH_SESSION session,
    KH_REQUEST request,
    const KhHttpSendOptions* options,
    KH_ASYNC_OPERATION* operation) noexcept
{
    return KhHttpSendAsyncImpl(session, request, options, operation);
}
}
}
