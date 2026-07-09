#include <KernelHttp/engine/HttpEngine.h>
#include <KernelHttp/client/ProxyTunnel.h>
#include <KernelHttp/core/TlsTransport.h>
#include <KernelHttp/core/WorkspaceScratchAllocator.h>
#include <KernelHttp/core/WskTransport.h>
#include <KernelHttp/engine/HttpCache.h>
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
    constexpr SIZE_T KhHttpRequestTargetScratchBytes =
        KhMaxSchemeLength + 3 + KhMaxHostHeaderLength + KhMaxPathLength;
    constexpr SIZE_T KhHttpHeaderScratchRequiredBytes =
        KhHttpRequestHeaderScratchBytes +
        KhHttpRequestTrailerScratchBytes +
        KhHttpResponseHeaderScratchBytes +
        KhHttpResponseTrailerScratchBytes +
        KhHttpHostHeaderScratchBytes +
        KhHttpRequestTargetScratchBytes;
    constexpr char KhDefaultAcceptEncoding[] = "gzip, deflate, br, identity";
    constexpr char KhDeflateUnavailableAcceptEncoding[] = "br, identity";
    constexpr SIZE_T KhWorkspaceCacheMaxRetainedBytes = 256 * 1024;

    constexpr SIZE_T KhHttp2HeaderScratchBytes =
        sizeof(http::HttpHeader) * client::Http2MaxRequestHeaders;
    constexpr SIZE_T KhHttp2ExtraHeaderScratchBytes =
        sizeof(http::HttpHeader) * client::Http2MaxRequestHeaders;
    constexpr SIZE_T KhHttp2TrailerScratchBytes =
        sizeof(http::HttpHeader) * client::Http2MaxRequestTrailers;
    constexpr SIZE_T KhHttp2LowerHeaderScratchBytes =
        client::Http2MaxRequestHeaders * client::Http2MaxHeaderNameLength;
    constexpr SIZE_T KhHttp2LowerTrailerScratchBytes =
        client::Http2MaxRequestTrailers * client::Http2MaxHeaderNameLength;
    constexpr SIZE_T KhHttp2RequestScratchBytes =
        KhHttp2HeaderScratchBytes +
        KhHttp2ExtraHeaderScratchBytes +
        KhHttp2TrailerScratchBytes +
        KhHttp2LowerHeaderScratchBytes +
        KhHttp2LowerTrailerScratchBytes +
        client::Http2ContentLengthBufferLength;

    struct ApiHttp2Scratch final
    {
        http::HttpHeader* Headers = nullptr;
        http::HttpHeader* ExtraHeaders = nullptr;
        http::HttpHeader* Trailers = nullptr;
        char (*LowerHeaderNames)[client::Http2MaxHeaderNameLength] = nullptr;
        char (*LowerTrailerNames)[client::Http2MaxHeaderNameLength] = nullptr;
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
        char* RequestTarget = nullptr;
        SIZE_T RequestTargetCapacity = 0;
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

    _Must_inspect_result_
    NTSTATUS BuildEffectiveAcceptEncoding(
        _In_ const KhHttpSendOptions& sendOptions,
        _Inout_ KhWorkspace& workspace,
        _Out_ http::HttpText* value) noexcept
    {
        if (value != nullptr) {
            *value = {};
        }
        if (value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (sendOptions.AcceptEncodingPreferenceCount == 0) {
            *value = DefaultAcceptEncoding();
            return STATUS_SUCCESS;
        }
        if (workspace.DecodedBody.Data == nullptr || workspace.DecodedBody.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return http::HttpContentEncoding::BuildAcceptEncodingHeader(
            sendOptions.AcceptEncodingPreferences,
            sendOptions.AcceptEncodingPreferenceCount,
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            workspace.DecodedBody.Length,
            value);
    }

    http::HttpAcceptEncodingPolicy AcceptEncodingPolicyFromOptions(
        _In_ const KhHttpSendOptions& sendOptions) noexcept
    {
        http::HttpAcceptEncodingPolicy policy = {};
        policy.Preferences = sendOptions.AcceptEncodingPreferences;
        policy.PreferenceCount = sendOptions.AcceptEncodingPreferenceCount;
        return policy;
    }

    bool RequestHasHeader(_In_ const KhRequest& request, _In_z_ const char* name) noexcept
    {
        if (name == nullptr) {
            return false;
        }
        for (SIZE_T index = 0; index < request.HeaderCount; ++index) {
            if (TextEqualsLiteralIgnoreCase(
                request.Headers[index].Name,
                request.Headers[index].NameLength,
                name)) {
                return true;
            }
        }
        return false;
    }

    void FillParsedFromCacheSnapshot(
        const KhHttpCacheSnapshot& snapshot,
        _Out_ http::HttpResponse* parsed) noexcept
    {
        if (parsed == nullptr) {
            return;
        }
        *parsed = {};
        parsed->MajorVersion = 1;
        parsed->MinorVersion = 1;
        parsed->StatusCode = snapshot.StatusCode;
        parsed->Headers = snapshot.Headers;
        parsed->HeaderCount = snapshot.HeaderCount;
        parsed->Body = reinterpret_cast<const char*>(snapshot.Body);
        parsed->BodyLength = snapshot.BodyLength;
        parsed->BodyKind = http::HttpBodyKind::ContentLength;
        parsed->BytesConsumed = snapshot.BodyLength;
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
        scratch->RequestTarget = reinterpret_cast<char*>(
            workspace.HttpHeaderScratch.Data +
            KhHttpRequestHeaderScratchBytes +
            KhHttpRequestTrailerScratchBytes +
            KhHttpResponseHeaderScratchBytes +
            KhHttpResponseTrailerScratchBytes +
            KhHttpHostHeaderScratchBytes);
        scratch->RequestTargetCapacity = KhHttpRequestTargetScratchBytes;
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
        scratch->Trailers = reinterpret_cast<http::HttpHeader*>(
            workspace.Http2HeaderScratch.Data +
            KhHttp2HeaderScratchBytes +
            KhHttp2ExtraHeaderScratchBytes);
        scratch->LowerHeaderNames = reinterpret_cast<char (*)[client::Http2MaxHeaderNameLength]>(
            workspace.Http2HeaderScratch.Data +
            KhHttp2HeaderScratchBytes +
            KhHttp2ExtraHeaderScratchBytes +
            KhHttp2TrailerScratchBytes);
        scratch->LowerTrailerNames = reinterpret_cast<char (*)[client::Http2MaxHeaderNameLength]>(
            workspace.Http2HeaderScratch.Data +
            KhHttp2HeaderScratchBytes +
            KhHttp2ExtraHeaderScratchBytes +
            KhHttp2TrailerScratchBytes +
            KhHttp2LowerHeaderScratchBytes);
        scratch->ContentLengthBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data +
            KhHttp2HeaderScratchBytes +
            KhHttp2ExtraHeaderScratchBytes +
            KhHttp2TrailerScratchBytes +
            KhHttp2LowerHeaderScratchBytes +
            KhHttp2LowerTrailerScratchBytes);
        scratch->AuthorityBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data + KhHttp2RequestScratchBytes);
        scratch->AuthorityCapacity = workspace.Http2HeaderScratch.Length - KhHttp2RequestScratchBytes;
        return STATUS_SUCCESS;
    }

    bool LowercaseHttp2HeaderName(
        http::HttpText name,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity,
        _Out_ http::HttpText* lowered) noexcept
    {
        if (lowered != nullptr) {
            *lowered = {};
        }
        if (name.Data == nullptr ||
            name.Length == 0 ||
            name.Length > client::Http2MaxHeaderNameLength ||
            output == nullptr ||
            lowered == nullptr ||
            name.Length > capacity ||
            name.Data[0] == ':') {
            return false;
        }

        for (SIZE_T index = 0; index < name.Length; ++index) {
            const UCHAR value = static_cast<UCHAR>(name.Data[index]);
            if (value <= 0x20 || value >= 0x7f || value == ':') {
                return false;
            }

            char loweredValue = name.Data[index];
            if (loweredValue >= 'A' && loweredValue <= 'Z') {
                loweredValue = static_cast<char>(loweredValue + 32);
            }
            output[index] = loweredValue;
        }

        lowered->Data = output;
        lowered->Length = name.Length;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS BuildHttp2TrailersFromRequest(
        const KhRequest& request,
        _Out_writes_(trailerCapacity) http::HttpHeader* trailers,
        SIZE_T trailerCapacity,
        char lowerTrailerNames[client::Http2MaxRequestTrailers][client::Http2MaxHeaderNameLength],
        _Out_ SIZE_T* trailerCount) noexcept
    {
        if (trailerCount != nullptr) {
            *trailerCount = 0;
        }
        if (trailerCount == nullptr ||
            (request.TrailerCount != 0 && (trailers == nullptr || lowerTrailerNames == nullptr)) ||
            request.TrailerCount > trailerCapacity ||
            request.TrailerCount > client::Http2MaxRequestTrailers) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
            const KhStoredHeader& trailer = request.Trailers[index];
            http::HttpText loweredName = {};
            if (!LowercaseHttp2HeaderName(
                { trailer.Name, trailer.NameLength },
                lowerTrailerNames[index],
                client::Http2MaxHeaderNameLength,
                &loweredName) ||
                (trailer.Value == nullptr && trailer.ValueLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            trailers[index].Name = loweredName;
            trailers[index].Value = { trailer.Value, trailer.ValueLength };
        }

        *trailerCount = request.TrailerCount;
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
        case KhHttpMethod::Trace:
            return http::HttpMethod::Trace;
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

    _Must_inspect_result_
    NTSTATUS BuildProxyAbsoluteFormTarget(
        const KhRequest& request,
        http::HttpText hostHeader,
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
            request.SchemeLength == 0 ||
            hostHeader.Data == nullptr ||
            hostHeader.Length == 0 ||
            request.Path == nullptr ||
            request.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        constexpr SIZE_T schemeSeparatorLength = 3;
        const SIZE_T required =
            request.SchemeLength +
            schemeSeparatorLength +
            hostHeader.Length +
            request.PathLength;
        if (required >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T length = 0;
        RtlCopyMemory(destination + length, request.Scheme, request.SchemeLength);
        length += request.SchemeLength;
        RtlCopyMemory(destination + length, "://", schemeSeparatorLength);
        length += schemeSeparatorLength;
        RtlCopyMemory(destination + length, hostHeader.Data, hostHeader.Length);
        length += hostHeader.Length;
        RtlCopyMemory(destination + length, request.Path, request.PathLength);
        length += request.PathLength;
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

    bool IsPlainHttpRequest(const KhRequest& request) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "http");
    }

    bool IsAutomaticHttpAlpnMode(const KhRequest& request) noexcept
    {
        return IsHttpsRequest(request) &&
            request.Tls.PreferHttp2 &&
            request.Tls.Alpn == nullptr &&
            request.Tls.AlpnLength == 0;
    }

    NTSTATUS EffectiveHttp2CleartextMode(
        _In_ const KhHttpSendOptions& options,
        _In_ const KhRequest& request,
        _Out_ KhHttp2CleartextMode* mode) noexcept
    {
        if (mode == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *mode = KhHttp2CleartextMode::Disabled;
        if (options.Http2CleartextMode == KhHttp2CleartextMode::Disabled) {
            return STATUS_SUCCESS;
        }

        if (!IsPlainHttpRequest(request)) {
            return STATUS_NOT_SUPPORTED;
        }

        *mode = options.Http2CleartextMode;
        return STATUS_SUCCESS;
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

    bool IsTraceSensitiveHeader(const KhStoredHeader& header) noexcept
    {
        return HeaderNameEquals(header, "Authorization") ||
            HeaderNameEquals(header, "Proxy-Authorization") ||
            HeaderNameEquals(header, "Cookie");
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
            request.ConnectionPolicy == KhConnectionPolicy::ReuseOrCreate &&
            IsSafeFreshConnectionRetryMethod(request.Method) &&
            (status == STATUS_RETRY ||
                (reusedConnection && IsFreshConnectionRetryStatus(status)));
    }

    bool RequestUsesExpectContinue(
        _In_ const KhHttpSendOptions& options,
        _In_ const KhRequest& request) noexcept;

    ULONG Http11PipelineMethodBit(KhHttpMethod method) noexcept
    {
        switch (method) {
        case KhHttpMethod::Get:
            return KhHttp11PipelineMethodGet;
        case KhHttpMethod::Post:
            return KhHttp11PipelineMethodPost;
        case KhHttpMethod::Put:
            return KhHttp11PipelineMethodPut;
        case KhHttpMethod::Patch:
            return KhHttp11PipelineMethodPatch;
        case KhHttpMethod::Delete:
            return KhHttp11PipelineMethodDelete;
        case KhHttpMethod::Head:
            return KhHttp11PipelineMethodHead;
        case KhHttpMethod::Options:
            return KhHttp11PipelineMethodOptions;
        case KhHttpMethod::Connect:
            return KhHttp11PipelineMethodConnect;
        case KhHttpMethod::Trace:
            return KhHttp11PipelineMethodTrace;
        default:
            return 0;
        }
    }

    bool IsHttp11PipelineTlsModeEligible(_In_ const KhRequest& request) noexcept
    {
        if (!IsHttpsRequest(request)) {
            return true;
        }

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            return TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "http/1.1");
        }

        return !request.Tls.PreferHttp2;
    }

    bool IsHttp11PipelineCandidate(
        _In_ const KhSession& session,
        _In_ const KhRequest& request,
        _In_ const KhHttpSendOptions& options,
        KhHttp2CleartextMode http2CleartextMode) noexcept
    {
        if (!session.Options.EnableHttp11Pipeline ||
            request.ConnectionPolicy != KhConnectionPolicy::ReuseOrCreate ||
            http2CleartextMode != KhHttp2CleartextMode::Disabled ||
            RequestUsesExpectContinue(options, request) ||
            !IsHttp11PipelineTlsModeEligible(request) ||
            request.HasBody ||
            request.BodyLength != 0 ||
            request.BodySourceCallback != nullptr ||
            request.TrailerCount != 0) {
            return false;
        }

        const ULONG methodBit = Http11PipelineMethodBit(request.Method);
        return methodBit != 0 && (session.Options.Http11PipelineMethodMask & methodBit) != 0;
    }

    bool RequestUsesExpectContinue(
        _In_ const KhHttpSendOptions& options,
        _In_ const KhRequest& request) noexcept
    {
        return ((options.Flags & KhHttpSendFlagExpectContinue) != 0) && request.HasBody;
    }

    ULONG EffectiveExpectContinueTimeoutMilliseconds(
        _In_ const KhHttpSendOptions& options) noexcept
    {
        return options.ExpectContinueTimeoutMilliseconds != 0 ?
            options.ExpectContinueTimeoutMilliseconds :
            KhDefaultExpectContinueTimeoutMilliseconds;
    }

    bool TryReadRawResponseStatusCode(
        _In_reads_bytes_(rawResponseLength) const char* rawResponse,
        SIZE_T rawResponseLength,
        _Out_ USHORT* statusCode) noexcept
    {
        if (statusCode != nullptr) {
            *statusCode = 0;
        }
        if (rawResponse == nullptr || statusCode == nullptr || rawResponseLength < 12) {
            return false;
        }

        SIZE_T cursor = 0;
        while (cursor < rawResponseLength &&
            rawResponse[cursor] != ' ' &&
            rawResponse[cursor] != '\r' &&
            rawResponse[cursor] != '\n') {
            ++cursor;
        }

        if (cursor >= rawResponseLength || rawResponse[cursor] != ' ') {
            return false;
        }
        ++cursor;

        if (cursor + 3 > rawResponseLength) {
            return false;
        }

        USHORT parsed = 0;
        for (SIZE_T index = 0; index < 3; ++index) {
            const char value = rawResponse[cursor + index];
            if (value < '0' || value > '9') {
                return false;
            }
            parsed = static_cast<USHORT>((parsed * 10) + static_cast<USHORT>(value - '0'));
        }

        *statusCode = parsed;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS BuildHttpRequestOptions(
        const KhRequest& request,
        bool addExpectContinue,
        bool allowTrace,
        bool useProxyAbsoluteForm,
        const KhProxyOptions& proxy,
        http::HttpText acceptEncoding,
        _Out_writes_bytes_(hostCapacity) char* host,
        SIZE_T hostCapacity,
        _Out_writes_bytes_(requestTargetCapacity) char* requestTarget,
        SIZE_T requestTargetCapacity,
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
        if (useProxyAbsoluteForm &&
            (requestTarget == nullptr || requestTargetCapacity == 0)) {
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
        const bool traceMethod = request.Method == KhHttpMethod::Trace;

        if (traceMethod && !allowTrace) {
            return STATUS_NOT_SUPPORTED;
        }

        if (traceMethod &&
            (request.HasBody ||
                request.BodyLength != 0 ||
                request.BodySourceCallback != nullptr ||
                request.TrailerCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (traceMethod &&
            proxy.Enabled &&
            proxy.AuthHeader != nullptr &&
            proxy.AuthHeaderLength != 0) {
            return STATUS_NOT_SUPPORTED;
        }

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

            if (request.HasBody &&
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

            if (traceMethod && IsTraceSensitiveHeader(header)) {
                return STATUS_NOT_SUPPORTED;
            }

            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = { header.Name, header.NameLength };
            headers[extraHeaderCount].Value = { header.Value, header.ValueLength };
            ++extraHeaderCount;
        }

        const bool emitExpectContinue = addExpectContinue && request.HasBody;
        if (!hasAcceptEncoding) {
            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = http::MakeText("Accept-Encoding");
            headers[extraHeaderCount].Value = acceptEncoding;
            ++extraHeaderCount;
        }

        if (emitExpectContinue) {
            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = http::MakeText("Expect");
            headers[extraHeaderCount].Value = http::MakeText("100-continue");
            ++extraHeaderCount;
        }

        if (useProxyAbsoluteForm && proxy.AuthHeader != nullptr && proxy.AuthHeaderLength != 0) {
            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = http::MakeText("Proxy-Authorization");
            headers[extraHeaderCount].Value = { proxy.AuthHeader, proxy.AuthHeaderLength };
            ++extraHeaderCount;
        }

        http::HttpText requestPath = { request.Path, request.PathLength };
        if (useProxyAbsoluteForm) {
            SIZE_T requestTargetLength = 0;
            status = BuildProxyAbsoluteFormTarget(
                request,
                { host, hostLength },
                requestTarget,
                requestTargetCapacity,
                &requestTargetLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            requestPath = { requestTarget, requestTargetLength };
        }

        options->Method = ToHttpMethod(request.Method);
        options->Path = requestPath;
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
        options->AllowExpectContinue = emitExpectContinue;
        options->AllowTrace = allowTrace;

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
        KhHttp2CleartextMode http2CleartextMode,
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
        key->MaxTls12Renegotiations = request.Tls.MaxTls12Renegotiations;
        key->AutomaticAlpn = IsAutomaticHttpAlpnMode(request);
        key->Http2CleartextMode = http2CleartextMode;
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
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
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
        parseOptions.AcceptEncodingPolicy = acceptPolicy;

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

    _Must_inspect_result_
    NTSTATUS LoadHttp1PipelineBufferedBytes(
        _Inout_ KhConnectionPool* connectionPool,
        _Inout_ KhPooledConnection* pooledConnection,
        _Inout_ KhWorkspace& workspace) noexcept
    {
        if (connectionPool == nullptr || pooledConnection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        workspace.ResponseLength = 0;
        SIZE_T bufferedLength = 0;
        NTSTATUS status = KhConnectionPoolHttp1PipelineBufferedLength(
            connectionPool,
            pooledConnection,
            &bufferedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (bufferedLength == 0) {
            return STATUS_SUCCESS;
        }

        status = KhWorkspaceEnsureResponseCapacity(&workspace, bufferedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T copied = 0;
        status = KhConnectionPoolTakeHttp1PipelineBufferedBytes(
            connectionPool,
            pooledConnection,
            workspace.Response.Data,
            workspace.Response.Length,
            &copied);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        workspace.ResponseLength = copied;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS PreserveHttp1PipelineTrailingBytes(
        _Inout_ KhConnectionPool* connectionPool,
        _Inout_ KhPooledConnection* pooledConnection,
        _Inout_ KhWorkspace& workspace,
        _In_ const http::HttpResponse& parsed,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (connectionPool == nullptr ||
            pooledConnection == nullptr ||
            rawResponseLength == nullptr ||
            parsed.BytesConsumed > workspace.ResponseLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T consumed = parsed.BytesConsumed;
        const SIZE_T trailingLength = workspace.ResponseLength - consumed;
        if (trailingLength != 0) {
            NTSTATUS status = KhConnectionPoolStoreHttp1PipelineBufferedBytes(
                connectionPool,
                pooledConnection,
                workspace.Response.Data + consumed,
                trailingLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        workspace.ResponseLength = consumed;
        *rawResponseLength = consumed;
        return STATUS_SUCCESS;
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
        _In_opt_ const http2::Http2RequestBodySource* bodySource,
        _Out_writes_(trailerCapacity) http::HttpHeader* trailers,
        SIZE_T trailerCapacity,
        char lowerTrailerNames[client::Http2MaxRequestTrailers][client::Http2MaxHeaderNameLength],
        _Out_ client::Http2RequestOptions* options) noexcept
    {
        if (requestHeaders == nullptr || extraHeaders == nullptr || options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (authority.Data == nullptr || authority.Length == 0 || request.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request.BodySourceCallback != nullptr && bodySource == nullptr) {
            return STATUS_INVALID_PARAMETER;
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
        options->Body = request.BodySourceCallback == nullptr ? request.Body : nullptr;
        options->BodyLength = request.BodySourceCallback == nullptr ? request.BodyLength : 0;
        options->BodySource = bodySource;
        options->IncludeContentLength =
            request.HasBody &&
            request.BodyMode == KhRequestBodyMode::ContentLength;
        options->CertificateStore = request.Tls.CertificateStore;
        options->VerifyCertificate = request.Tls.CertificatePolicy == KhCertificatePolicy::Verify;
        options->Policy = request.Tls.Policy;
        options->ClientCredential = request.Tls.ClientCredential;
        options->MaxTls12Renegotiations = request.Tls.MaxTls12Renegotiations;

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
        SIZE_T trailerCount = 0;
        NTSTATUS status = BuildHttp2TrailersFromRequest(
            request,
            trailers,
            trailerCapacity,
            lowerTrailerNames,
            &trailerCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        options->Trailers = trailerCount != 0 ? trailers : nullptr;
        options->TrailerCount = trailerCount;
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
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
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
                *decoded,
                acceptPolicy);
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
        _In_ const KhHttpSendOptions& sendOptions,
        _Inout_ KhConnectionPool* connectionPool,
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
            connectionPool == nullptr ||
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

        http2::Http2RequestBodySource h2BodySource = {};
        const http2::Http2RequestBodySource* h2BodySourcePtr = nullptr;
        if (request.BodySourceCallback != nullptr) {
            h2BodySource.Read = request.BodySourceCallback;
            h2BodySource.Context = request.BodySourceContext;
            h2BodySource.ContentLength = request.BodySourceContentLength;
            h2BodySource.ContentLengthKnown = request.BodySourceContentLengthKnown;
            h2BodySourcePtr = &h2BodySource;
        }

        client::Http2RequestOptions h2Options = {};
        status = BuildHttp2OptionsFromRequest(
            request,
            requestHeaders,
            requestHeaderCount,
            { h2Scratch.AuthorityBuffer, authorityLength },
            h2Scratch.ExtraHeaders,
            client::Http2MaxRequestHeaders,
            h2BodySourcePtr,
            h2Scratch.Trailers,
            client::Http2MaxRequestTrailers,
            h2Scratch.LowerTrailerNames,
            &h2Options);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        h2Options.Priority = sendOptions.Http2Priority;

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

        const bool h2LeaseAlreadyHeld =
            KhConnectionPoolHasHttp2StreamLease(&pooledConnection);
        ULONG streamId = 0;
        http2::Http2RequestBody requestBody = {};
        requestBody.Data = h2Options.Body;
        requestBody.DataLength = h2Options.BodyLength;
        requestBody.Source = h2Options.BodySource;
        requestBody.Trailers = h2Options.Trailers;
        requestBody.TrailerCount = h2Options.TrailerCount;
        requestBody.Priority = h2Options.Priority;
        requestBody.HasBody =
            request.HasBody ||
            h2Options.BodySource != nullptr ||
            h2Options.TrailerCount != 0 ||
            (h2Options.Body != nullptr && h2Options.BodyLength != 0);
        status = pooledConnection.Http2->BeginRequest(
            *pooledConnection.Transport,
            h2Scratch.Headers,
            h2HeaderCount,
            requestBody,
            responseHeaders,
            headerCapacity,
            &responseHeaderCount,
            responseBodySink,
            &responseBodyLength,
            &statusCode,
            reinterpret_cast<char*>(workspace.Http2HeaderScratch.Data),
            workspace.Http2HeaderScratch.Length,
            &streamId);

        if (!NT_SUCCESS(status)) {
            kprintf("High-level HTTP/2 request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (!h2LeaseAlreadyHeld) {
            status = KhConnectionPoolPromoteHttp2StreamLease(
                connectionPool,
                &pooledConnection,
                pooledConnection.Http2->MaxConcurrentStreams());
            if (!NT_SUCCESS(status)) {
                pooledConnection.Http2->ReleaseStream(streamId);
                return status;
            }
        }

        status = pooledConnection.Http2->ReceiveResponse(
            *pooledConnection.Transport,
            streamId);
        if (!NT_SUCCESS(status)) {
            pooledConnection.Http2->ReleaseStream(streamId);
            if (status == STATUS_BUFFER_TOO_SMALL && workspace.MaxResponseBytes != 0) {
                kprintf(
                    "High-level HTTP/2 response reached MaxResponseBytes limit: status=0x%08X MaxResponseBytes=%Iu\r\n",
                    static_cast<ULONG>(status),
                    workspace.MaxResponseBytes);
            }
            else {
                kprintf("High-level HTTP/2 response failed: 0x%08X\r\n", static_cast<ULONG>(status));
            }
            return status;
        }

        http::HttpContentDecodeResult decoded = {};
        http::HttpAcceptEncodingPolicy acceptPolicy = AcceptEncodingPolicyFromOptions(sendOptions);
        status = DecodeContentWithWorkspace(
            responseHeaders,
            responseHeaderCount,
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseBodyLength,
            workspace,
            &acceptPolicy,
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

    class H2cReplayTransport final : public core::ITransport
    {
    public:
        H2cReplayTransport() noexcept = default;

        NTSTATUS Initialize(
            _Inout_ core::ITransport* inner,
            _In_reads_bytes_opt_(replayLength) const UCHAR* replayBytes,
            SIZE_T replayLength) noexcept
        {
            if (inner == nullptr || (replayBytes == nullptr && replayLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            inner_ = inner;
            replayBytes_ = replayBytes;
            replayLength_ = replayLength;
            replayOffset_ = 0;
            return STATUS_SUCCESS;
        }

        NTSTATUS Send(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept override
        {
            if (inner_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return inner_->Send(data, length, bytesSent);
        }

        NTSTATUS Receive(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept override
        {
            NTSTATUS status = ReceiveReplay(buffer, length, bytesReceived);
            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }
            if (inner_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return inner_->Receive(buffer, length, bytesReceived);
        }

        NTSTATUS ReceiveWithTimeout(
            void* buffer,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override
        {
            NTSTATUS status = ReceiveReplay(buffer, length, bytesReceived);
            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }
            if (inner_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return inner_->ReceiveWithTimeout(buffer, length, bytesReceived, timeoutMilliseconds);
        }

    private:
        NTSTATUS ReceiveReplay(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
        {
            if (bytesReceived != nullptr) {
                *bytesReceived = 0;
            }
            if (replayOffset_ >= replayLength_) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }
            if (buffer == nullptr || length == 0 || replayBytes_ == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T available = replayLength_ - replayOffset_;
            SIZE_T toCopy = length < available ? length : available;
            RtlCopyMemory(buffer, replayBytes_ + replayOffset_, toCopy);
            replayOffset_ += toCopy;
            if (bytesReceived != nullptr) {
                *bytesReceived = toCopy;
            }
            return STATUS_SUCCESS;
        }

        core::ITransport* inner_ = nullptr;
        const UCHAR* replayBytes_ = nullptr;
        SIZE_T replayLength_ = 0;
        SIZE_T replayOffset_ = 0;
    };

    SIZE_T H2cLiteralLength(_In_z_ const char* text) noexcept
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

    http::HttpText KhHttpMethodText(KhHttpMethod method) noexcept
    {
        switch (method) {
        case KhHttpMethod::Post:
            return http::MakeText("POST");
        case KhHttpMethod::Put:
            return http::MakeText("PUT");
        case KhHttpMethod::Patch:
            return http::MakeText("PATCH");
        case KhHttpMethod::Delete:
            return http::MakeText("DELETE");
        case KhHttpMethod::Head:
            return http::MakeText("HEAD");
        case KhHttpMethod::Options:
            return http::MakeText("OPTIONS");
        case KhHttpMethod::Connect:
            return http::MakeText("CONNECT");
        case KhHttpMethod::Trace:
            return http::MakeText("TRACE");
        case KhHttpMethod::Get:
        default:
            return http::MakeText("GET");
        }
    }

    NTSTATUS AppendH2cText(
        _Out_writes_bytes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset,
        http::HttpText text) noexcept
    {
        if (output == nullptr ||
            offset == nullptr ||
            *offset > capacity ||
            (text.Data == nullptr && text.Length != 0) ||
            text.Length > capacity - *offset) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (text.Length != 0) {
            RtlCopyMemory(output + *offset, text.Data, text.Length);
            *offset += text.Length;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS AppendH2cLiteral(
        _Out_writes_bytes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset,
        _In_z_ const char* literal) noexcept
    {
        return AppendH2cText(output, capacity, offset, { literal, H2cLiteralLength(literal) });
    }

    bool IsH2cUpgradeControlledHeader(http::HttpText name) noexcept
    {
        return http::TextEqualsIgnoreCase(name, http::MakeText("Connection")) ||
            http::TextEqualsIgnoreCase(name, http::MakeText("Upgrade")) ||
            http::TextEqualsIgnoreCase(name, http::MakeText("HTTP2-Settings")) ||
            http::TextEqualsIgnoreCase(name, http::MakeText("Host")) ||
            http::TextEqualsIgnoreCase(name, http::MakeText("Content-Length")) ||
            http::TextEqualsIgnoreCase(name, http::MakeText("Transfer-Encoding"));
    }

    _Must_inspect_result_
    NTSTATUS BuildH2cUpgradeRequest(
        const KhRequest& request,
        http::HttpText authority,
        _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_writes_bytes_(outputCapacity) char* output,
        SIZE_T outputCapacity,
        _Out_ SIZE_T* outputLength) noexcept
    {
        if (outputLength != nullptr) {
            *outputLength = 0;
        }
        if (authority.Data == nullptr ||
            authority.Length == 0 ||
            request.Path == nullptr ||
            request.PathLength == 0 ||
            (requestHeaders == nullptr && requestHeaderCount != 0) ||
            output == nullptr ||
            outputLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> settingsValue(128);
        if (!settingsValue.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        http2::Http2Settings settings = {};
        http::HttpText settingsText = {};
        NTSTATUS status = http2::Http2FrameCodec::EncodeSettingsPayloadBase64Url(
            settings,
            settingsValue.Get(),
            settingsValue.Count(),
            &settingsText.Length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        settingsText.Data = settingsValue.Get();

        SIZE_T offset = 0;
        status = AppendH2cText(output, outputCapacity, &offset, KhHttpMethodText(request.Method));
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, " ");
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cText(output, outputCapacity, &offset, { request.Path, request.PathLength });
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, " HTTP/1.1\r\nHost: ");
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cText(output, outputCapacity, &offset, authority);
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, "\r\n");
        if (!NT_SUCCESS(status)) return status;

        for (SIZE_T index = 0; index < requestHeaderCount; ++index) {
            const http::HttpHeader& header = requestHeaders[index];
            if (header.Name.Data == nullptr ||
                header.Name.Length == 0 ||
                (header.Value.Data == nullptr && header.Value.Length != 0) ||
                IsH2cUpgradeControlledHeader(header.Name)) {
                return STATUS_INVALID_PARAMETER;
            }

            status = AppendH2cText(output, outputCapacity, &offset, header.Name);
            if (!NT_SUCCESS(status)) return status;
            status = AppendH2cLiteral(output, outputCapacity, &offset, ": ");
            if (!NT_SUCCESS(status)) return status;
            status = AppendH2cText(output, outputCapacity, &offset, header.Value);
            if (!NT_SUCCESS(status)) return status;
            status = AppendH2cLiteral(output, outputCapacity, &offset, "\r\n");
            if (!NT_SUCCESS(status)) return status;
        }

        status = AppendH2cLiteral(
            output,
            outputCapacity,
            &offset,
            "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: ");
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cText(output, outputCapacity, &offset, settingsText);
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, "\r\n\r\n");
        if (!NT_SUCCESS(status)) return status;

        *outputLength = offset;
        return STATUS_SUCCESS;
    }

    SIZE_T FindH2cHeaderEnd(_In_reads_bytes_(length) const UCHAR* data, SIZE_T length) noexcept
    {
        if (data == nullptr || length < 4) {
            return static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        }
        for (SIZE_T index = 0; index <= length - 4; ++index) {
            if (data[index] == '\r' &&
                data[index + 1] == '\n' &&
                data[index + 2] == '\r' &&
                data[index + 3] == '\n') {
                return index + 4;
            }
        }
        return static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
    }

    bool H2cHeaderBlockHasToken(
        _In_reads_bytes_(length) const char* data,
        SIZE_T length,
        http::HttpText headerName,
        http::HttpText token) noexcept
    {
        if (data == nullptr) {
            return false;
        }

        SIZE_T lineStart = 0;
        while (lineStart + 1 < length) {
            SIZE_T lineEnd = lineStart;
            while (lineEnd + 1 < length &&
                !(data[lineEnd] == '\r' && data[lineEnd + 1] == '\n')) {
                ++lineEnd;
            }

            SIZE_T colon = lineStart;
            while (colon < lineEnd && data[colon] != ':') {
                ++colon;
            }
            if (colon < lineEnd) {
                http::HttpText name = { data + lineStart, colon - lineStart };
                http::HttpText value = { data + colon + 1, lineEnd - colon - 1 };
                if (http::TextEqualsIgnoreCase(name, headerName) &&
                    http::HeaderValueHasToken(value, token)) {
                    return true;
                }
            }

            if (lineEnd + 1 >= length) {
                break;
            }
            lineStart = lineEnd + 2;
        }

        return false;
    }

    _Must_inspect_result_
    NTSTATUS ValidateH2cUpgradeResponse(
        _In_reads_bytes_(headerLength) const char* data,
        SIZE_T headerLength) noexcept
    {
        if (data == nullptr || headerLength < 12) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (data[0] != 'H' || data[1] != 'T' || data[2] != 'T' || data[3] != 'P' || data[4] != '/') {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T cursor = 5;
        while (cursor < headerLength && data[cursor] != ' ') {
            ++cursor;
        }
        if (cursor + 4 >= headerLength || data[cursor] != ' ') {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (data[cursor + 1] != '1' || data[cursor + 2] != '0' || data[cursor + 3] != '1') {
            return STATUS_NOT_SUPPORTED;
        }

        if (!H2cHeaderBlockHasToken(
                data,
                headerLength,
                http::MakeText("Upgrade"),
                http::MakeText("h2c")) ||
            !H2cHeaderBlockHasToken(
                data,
                headerLength,
                http::MakeText("Connection"),
                http::MakeText("Upgrade"))) {
            return STATUS_NOT_SUPPORTED;
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadH2cUpgradeResponse(
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        _Inout_ HeapArray<UCHAR>& replayBytes,
        _Out_ SIZE_T* replayLength) noexcept
    {
        if (replayLength != nullptr) {
            *replayLength = 0;
        }
        if (workspace.Response.Data == nullptr ||
            workspace.Response.Length == 0 ||
            replayLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        workspace.ResponseLength = 0;
        for (;;) {
            const SIZE_T headerEnd = FindH2cHeaderEnd(workspace.Response.Data, workspace.ResponseLength);
            if (headerEnd != static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                NTSTATUS status = ValidateH2cUpgradeResponse(
                    reinterpret_cast<const char*>(workspace.Response.Data),
                    headerEnd);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                const SIZE_T extraLength = workspace.ResponseLength - headerEnd;
                if (extraLength != 0) {
                    status = replayBytes.Allocate(extraLength);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    RtlCopyMemory(replayBytes.Get(), workspace.Response.Data + headerEnd, extraLength);
                }

                *replayLength = extraLength;
                workspace.ResponseLength = 0;
                return STATUS_SUCCESS;
            }

            if (workspace.ResponseLength == workspace.Response.Length) {
                NTSTATUS status = KhWorkspaceEnsureResponseCapacity(&workspace, workspace.ResponseLength + 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            SIZE_T received = 0;
            NTSTATUS status = transport.Receive(
                workspace.Response.Data + workspace.ResponseLength,
                workspace.Response.Length - workspace.ResponseLength,
                &received);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (received == 0) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
            workspace.ResponseLength += received;
        }
    }

    _Must_inspect_result_
    NTSTATUS SendH2cUpgradeViaTransport(
        const KhRequest& request,
        KhWorkspace& workspace,
        _Inout_ KhPooledConnection& pooledConnection,
        _In_ const KhHttpSendOptions& sendOptions,
        SIZE_T maxHeaderBlockBytes,
        _In_reads_(requestHeaderCount) const http::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr || responseHeaders == nullptr || rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (request.HasBody ||
            request.BodyLength != 0 ||
            request.BodySourceCallback != nullptr ||
            request.TrailerCount != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (pooledConnection.Transport == nullptr || pooledConnection.Http2 != nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
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

        SIZE_T upgradeRequestLength = 0;
        status = BuildH2cUpgradeRequest(
            request,
            { h2Scratch.AuthorityBuffer, authorityLength },
            requestHeaders,
            requestHeaderCount,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            &upgradeRequestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T sent = 0;
        status = pooledConnection.Transport->Send(
            workspace.Request.Data,
            upgradeRequestLength,
            &sent);
        if (NT_SUCCESS(status) && sent != upgradeRequestLength) {
            return STATUS_CONNECTION_DISCONNECTED;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> replayBytes;
        SIZE_T replayLength = 0;
        status = ReadH2cUpgradeResponse(
            *pooledConnection.Transport,
            workspace,
            replayBytes,
            &replayLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* h2Connection = AllocateNonPagedObject<http2::Http2Connection>();
        if (h2Connection == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        HeapObject<H2cReplayTransport> replayTransport;
        if (!replayTransport.IsValid()) {
            FreeNonPagedObject(h2Connection);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        core::ITransport* activeTransport = pooledConnection.Transport;
        if (replayLength != 0) {
            status = replayTransport->Initialize(
                pooledConnection.Transport,
                replayBytes.Get(),
                replayLength);
            if (!NT_SUCCESS(status)) {
                FreeNonPagedObject(h2Connection);
                return status;
            }
            activeTransport = replayTransport.Get();
        }

        status = h2Connection->InitializeAfterUpgrade(*activeTransport, maxHeaderBlockBytes);
        if (!NT_SUCCESS(status)) {
            kprintf("High-level h2c Upgrade init failed: 0x%08X\r\n", static_cast<ULONG>(status));
            FreeNonPagedObject(h2Connection);
            return status;
        }
        pooledConnection.Http2 = h2Connection;

        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        http2::Http2ResponseBodySink responseBodySink = {};
        responseBodySink.Append = AppendHttp2ResponseBodyToWorkspace;
        responseBodySink.Context = &workspace;

        status = pooledConnection.Http2->ReceiveResponse(
            *activeTransport,
            1,
            responseHeaders,
            headerCapacity,
            &responseHeaderCount,
            responseBodySink,
            &responseBodyLength,
            &statusCode,
            reinterpret_cast<char*>(workspace.Http2HeaderScratch.Data),
            workspace.Http2HeaderScratch.Length);
        if (!NT_SUCCESS(status)) {
            kprintf("High-level h2c Upgrade stream 1 failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        http::HttpContentDecodeResult decoded = {};
        http::HttpAcceptEncodingPolicy acceptPolicy = AcceptEncodingPolicyFromOptions(sendOptions);
        status = DecodeContentWithWorkspace(
            responseHeaders,
            responseHeaderCount,
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseBodyLength,
            workspace,
            &acceptPolicy,
            &decoded);
        if (!NT_SUCCESS(status)) {
            kprintf("High-level h2c Upgrade content decode failed: 0x%08X\r\n", static_cast<ULONG>(status));
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
        bool addExpectContinue,
        bool allowTrace,
        bool useProxyAbsoluteForm,
        const KhProxyOptions& proxy,
        _Inout_ KhWorkspace& workspace,
        _In_ const KhHttpSendOptions& sendOptions,
        _Out_writes_bytes_(hostHeaderCapacity) char* hostHeader,
        SIZE_T hostHeaderCapacity,
        _Out_writes_bytes_(requestTargetCapacity) char* requestTarget,
        SIZE_T requestTargetCapacity,
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

        http::HttpText acceptEncoding = {};
        NTSTATUS status = BuildEffectiveAcceptEncoding(sendOptions, workspace, &acceptEncoding);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http::HttpRequestBuildOptions buildOptions = {};
        status = BuildHttpRequestOptions(
            request,
            addExpectContinue,
            allowTrace,
            useProxyAbsoluteForm,
            proxy,
            acceptEncoding,
            hostHeader,
            hostHeaderCapacity,
            requestTarget,
            requestTargetCapacity,
            requestHeaders,
            headerCapacity,
            requestTrailers,
            trailerCapacity,
            &buildOptions,
            requestHeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (request.BodySourceCallback != nullptr) {
            return http::HttpRequestBuilder::BuildHeaders(
                buildOptions,
                reinterpret_cast<char*>(workspace.Request.Data),
                workspace.Request.Length,
                requestLength);
        }

        return http::HttpRequestBuilder::Build(
            buildOptions,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            requestLength);
    }

    _Must_inspect_result_
    bool FindHttpRequestBodyOffset(
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        _Out_ SIZE_T* bodyOffset) noexcept
    {
        if (bodyOffset != nullptr) {
            *bodyOffset = 0;
        }
        if (requestBytes == nullptr || bodyOffset == nullptr || requestLength < 4) {
            return false;
        }

        for (SIZE_T index = 0; index <= requestLength - 4; ++index) {
            if (requestBytes[index] == '\r' &&
                requestBytes[index + 1] == '\n' &&
                requestBytes[index + 2] == '\r' &&
                requestBytes[index + 3] == '\n') {
                *bodyOffset = index + 4;
                return true;
            }
        }

        return false;
    }

    _Must_inspect_result_
    NTSTATUS SendTransportSegment(
        _Inout_ core::ITransport& transport,
        _In_reads_bytes_opt_(length) const UCHAR* data,
        SIZE_T length) noexcept
    {
        if (length == 0) {
            return STATUS_SUCCESS;
        }
        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T totalSent = 0;
        while (totalSent < length) {
            SIZE_T sent = 0;
            NTSTATUS status = transport.Send(data + totalSent, length - totalSent, &sent);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (sent == 0) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
            totalSent += sent;
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBuffer(
        _Inout_ core::ITransport& transport,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength) noexcept
    {
        SIZE_T bodyOffset = 0;
        if (!FindHttpRequestBodyOffset(requestBytes, requestLength, &bodyOffset)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = SendTransportSegment(transport, requestBytes, bodyOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendTransportSegment(
            transport,
            requestBytes + bodyOffset,
            requestLength - bodyOffset);
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocket(
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        bool responseBodyForbidden,
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp1PipelineRequestBuffer(
        _Inout_ KhConnectionPool* connectionPool,
        _Inout_ KhPooledConnection* pooledConnection,
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        bool responseBodyForbidden,
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength,
        _Out_ bool* connectionReusable) noexcept
    {
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (connectionReusable != nullptr) {
            *connectionReusable = false;
        }
        if (connectionPool == nullptr ||
            pooledConnection == nullptr ||
            parsed == nullptr ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr ||
            rawResponseLength == nullptr ||
            connectionReusable == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG sequence = 0;
        NTSTATUS status = KhConnectionPoolBeginHttp1PipelineSend(
            connectionPool,
            pooledConnection,
            &sequence);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendHttp1RequestBuffer(transport, requestBytes, requestLength);
        KhConnectionPoolEndHttp1PipelineSend(pooledConnection);
        if (!NT_SUCCESS(status)) {
            KhConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        status = KhConnectionPoolWaitHttp1PipelineReceiveTurn(
            connectionPool,
            pooledConnection,
            sequence);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = LoadHttp1PipelineBufferedBytes(connectionPool, pooledConnection, workspace);
        if (!NT_SUCCESS(status)) {
            KhConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        status = ReadHttpResponseFromSocket(
            transport,
            workspace,
            responseBodyForbidden,
            acceptPolicy,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
        if (!NT_SUCCESS(status)) {
            KhConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        status = PreserveHttp1PipelineTrailingBytes(
            connectionPool,
            pooledConnection,
            workspace,
            *parsed,
            rawResponseLength);
        if (!NT_SUCCESS(status)) {
            KhConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        const bool reusable =
            IsHttpConnectionReusable(*parsed, *rawResponseLength) &&
            parsed->MajorVersion == 1 &&
            parsed->MinorVersion == 1;
        if (reusable) {
            KhConnectionPoolCompleteHttp1PipelineReceive(
                connectionPool,
                pooledConnection,
                sequence);
        }
        else {
            KhConnectionPoolFailHttp1Pipeline(
                connectionPool,
                pooledConnection,
                STATUS_CONNECTION_DISCONNECTED);
        }

        *connectionReusable = reusable;
        return STATUS_SUCCESS;
    }
#endif

    _Must_inspect_result_
    bool FormatChunkPrefix(
        _Out_writes_bytes_(capacity) UCHAR* destination,
        SIZE_T capacity,
        SIZE_T value,
        _Out_ SIZE_T* length) noexcept
    {
        if (length != nullptr) {
            *length = 0;
        }
        if (destination == nullptr || length == nullptr || capacity < 3) {
            return false;
        }

        SIZE_T shift = (sizeof(SIZE_T) * 8) - 4;
        bool wroteDigit = false;
        SIZE_T cursor = 0;
        for (;;) {
            const SIZE_T digit = (value >> shift) & 0x0f;
            if (digit != 0 || wroteDigit || shift == 0) {
                if (cursor >= capacity) {
                    return false;
                }
                static constexpr char hex[] = "0123456789abcdef";
                destination[cursor++] = static_cast<UCHAR>(hex[digit]);
                wroteDigit = true;
            }

            if (shift == 0) {
                break;
            }
            shift -= 4;
        }

        if (cursor + 2 > capacity) {
            return false;
        }
        destination[cursor++] = '\r';
        destination[cursor++] = '\n';
        *length = cursor;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestTrailers(
        _Inout_ core::ITransport& transport,
        _In_ const KhRequest& request) noexcept
    {
        NTSTATUS status = SendTransportSegment(
            transport,
            reinterpret_cast<const UCHAR*>("0\r\n"),
            sizeof("0\r\n") - 1);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
            const KhStoredHeader& trailer = request.Trailers[index];
            status = SendTransportSegment(
                transport,
                reinterpret_cast<const UCHAR*>(trailer.Name),
                trailer.NameLength);
            if (NT_SUCCESS(status)) {
                status = SendTransportSegment(
                    transport,
                    reinterpret_cast<const UCHAR*>(": "),
                    sizeof(": ") - 1);
            }
            if (NT_SUCCESS(status)) {
                status = SendTransportSegment(
                    transport,
                    reinterpret_cast<const UCHAR*>(trailer.Value),
                    trailer.ValueLength);
            }
            if (NT_SUCCESS(status)) {
                status = SendTransportSegment(
                    transport,
                    reinterpret_cast<const UCHAR*>("\r\n"),
                    sizeof("\r\n") - 1);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return SendTransportSegment(
            transport,
            reinterpret_cast<const UCHAR*>("\r\n"),
            sizeof("\r\n") - 1);
    }

    _Must_inspect_result_
    NTSTATUS ReadRequestBodySource(
        _In_ const KhRequest& request,
        _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
        SIZE_T bufferCapacity,
        _Out_ SIZE_T* bytesRead,
        _Out_ bool* endOfBody) noexcept
    {
        if (request.BodySourceCallback == nullptr ||
            buffer == nullptr ||
            bufferCapacity == 0 ||
            bytesRead == nullptr ||
            endOfBody == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *bytesRead = 0;
        *endOfBody = false;
        NTSTATUS status = request.BodySourceCallback(
            request.BodySourceContext,
            buffer,
            bufferCapacity,
            bytesRead,
            endOfBody);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (*bytesRead > bufferCapacity) {
            return STATUS_INVALID_PARAMETER;
        }
        if (*bytesRead == 0 && !*endOfBody) {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBodySource(
        _Inout_ core::ITransport& transport,
        _In_ const KhRequest& request,
        _Inout_ KhWorkspace& workspace) noexcept
    {
        if (request.BodySourceCallback == nullptr ||
            workspace.Request.Data == nullptr ||
            workspace.Request.Length <= 32) {
            return STATUS_INVALID_PARAMETER;
        }

        constexpr SIZE_T prefixCapacity = 32;
        UCHAR* chunkPrefix = workspace.Request.Data;
        UCHAR* bodyBuffer = workspace.Request.Data + prefixCapacity;
        const SIZE_T bodyBufferCapacity = workspace.Request.Length - prefixCapacity;
        SIZE_T totalSent = 0;

        for (;;) {
            SIZE_T bytesRead = 0;
            bool endOfBody = false;
            NTSTATUS status = ReadRequestBodySource(
                request,
                bodyBuffer,
                bodyBufferCapacity,
                &bytesRead,
                &endOfBody);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (request.BodyMode == KhRequestBodyMode::ContentLength) {
                if (!request.BodySourceContentLengthKnown) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (bytesRead > request.BodySourceContentLength - totalSent) {
                    return STATUS_INVALID_PARAMETER;
                }
                status = SendTransportSegment(transport, bodyBuffer, bytesRead);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                totalSent += bytesRead;
                if (totalSent == request.BodySourceContentLength) {
                    return STATUS_SUCCESS;
                }
                if (endOfBody) {
                    return STATUS_INVALID_PARAMETER;
                }
                continue;
            }

            if (bytesRead != 0) {
                SIZE_T prefixLength = 0;
                if (!FormatChunkPrefix(chunkPrefix, prefixCapacity, bytesRead, &prefixLength)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                status = SendTransportSegment(transport, chunkPrefix, prefixLength);
                if (NT_SUCCESS(status)) {
                    status = SendTransportSegment(transport, bodyBuffer, bytesRead);
                }
                if (NT_SUCCESS(status)) {
                    status = SendTransportSegment(
                        transport,
                        reinterpret_cast<const UCHAR*>("\r\n"),
                        sizeof("\r\n") - 1);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (endOfBody) {
                return SendHttp1RequestTrailers(transport, request);
            }
        }
    }

    _Must_inspect_result_
    bool AddSizeChecked(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
    {
        if (result == nullptr) {
            return false;
        }
        if (left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right) {
            return false;
        }
        *result = left + right;
        return true;
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS SimulateHttp1RequestBodySourceForTest(
        _In_ const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Out_ SIZE_T* bodyBytesLength) noexcept
    {
        if (bodyBytesLength != nullptr) {
            *bodyBytesLength = 0;
        }
        if (request.BodySourceCallback == nullptr || bodyBytesLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (workspace.DecodedBody.Data == nullptr || workspace.DecodedBody.Length <= 32) {
            return STATUS_INVALID_PARAMETER;
        }

        constexpr SIZE_T prefixCapacity = 32;
        UCHAR* chunkPrefix = workspace.DecodedBody.Data;
        UCHAR* bodyBuffer = workspace.DecodedBody.Data + prefixCapacity;
        const SIZE_T bodyBufferCapacity = workspace.DecodedBody.Length - prefixCapacity;
        SIZE_T totalBodyBytes = 0;
        SIZE_T totalPayloadBytes = 0;

        for (;;) {
            SIZE_T bytesRead = 0;
            bool endOfBody = false;
            NTSTATUS status = ReadRequestBodySource(
                request,
                bodyBuffer,
                bodyBufferCapacity,
                &bytesRead,
                &endOfBody);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (request.BodyMode == KhRequestBodyMode::ContentLength) {
                if (!request.BodySourceContentLengthKnown) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (bytesRead > request.BodySourceContentLength - totalPayloadBytes) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (!AddSizeChecked(totalPayloadBytes, bytesRead, &totalPayloadBytes)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (totalPayloadBytes == request.BodySourceContentLength) {
                    *bodyBytesLength = totalPayloadBytes;
                    return STATUS_SUCCESS;
                }
                if (endOfBody) {
                    return STATUS_INVALID_PARAMETER;
                }
                continue;
            }

            if (bytesRead != 0) {
                SIZE_T prefixLength = 0;
                if (!FormatChunkPrefix(chunkPrefix, prefixCapacity, bytesRead, &prefixLength)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                SIZE_T next = 0;
                if (!AddSizeChecked(totalBodyBytes, prefixLength, &next) ||
                    !AddSizeChecked(next, bytesRead, &next) ||
                    !AddSizeChecked(next, sizeof("\r\n") - 1, &next)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                totalBodyBytes = next;
            }

            if (endOfBody) {
                SIZE_T next = 0;
                if (!AddSizeChecked(totalBodyBytes, sizeof("0\r\n") - 1, &next)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
                    const KhStoredHeader& trailer = request.Trailers[index];
                    if (!AddSizeChecked(next, trailer.NameLength, &next) ||
                        !AddSizeChecked(next, sizeof(": ") - 1, &next) ||
                        !AddSizeChecked(next, trailer.ValueLength, &next) ||
                        !AddSizeChecked(next, sizeof("\r\n") - 1, &next)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                }
                if (!AddSizeChecked(next, sizeof("\r\n") - 1, &next)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                *bodyBytesLength = next;
                return STATUS_SUCCESS;
            }
        }
    }
#endif

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    ULONGLONG MakeResponseReadDeadline(ULONG timeoutMilliseconds) noexcept
    {
        return KeQueryInterruptTime() +
            (static_cast<ULONGLONG>(timeoutMilliseconds) * 10000ULL);
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
    NTSTATUS ReadHttpResponseFromSocketEx(
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        bool responseBodyForbidden,
        bool preserveInformationalResponses,
        ULONG readTimeoutMilliseconds,
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
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
        SIZE_T responseLength = workspace.ResponseLength;
        const ULONGLONG responseReadDeadline = MakeResponseReadDeadline(readTimeoutMilliseconds);

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
            parseOptions.AcceptEncodingPolicy = acceptPolicy;

            NTSTATUS status = http::HttpParser::ParseResponse(
                reinterpret_cast<const char*>(workspace.Response.Data),
                responseLength,
                parseOptions,
                *parsed);
            if (status == STATUS_SUCCESS) {
                if (preserveInformationalResponses) {
                    workspace.ResponseLength = responseLength;
                    *rawResponseLength = responseLength;
                    return STATUS_SUCCESS;
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
            // buffer (bounded only when MaxResponseBytes is nonzero) and re-parse, mirroring the
            // HTTP/2 decode path.
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

                    if (preserveInformationalResponses) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
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

                    if (preserveInformationalResponses) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
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

    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocket(
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        bool responseBodyForbidden,
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        return ReadHttpResponseFromSocketEx(
            transport,
            workspace,
            responseBodyForbidden,
            false,
            WskOperationTimeoutMilliseconds,
            acceptPolicy,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBufferWithExpect(
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        ULONG expectContinueTimeoutMilliseconds,
        bool responseBodyForbidden,
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        SIZE_T bodyOffset = 0;
        if (!FindHttpRequestBodyOffset(requestBytes, requestLength, &bodyOffset)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = SendTransportSegment(transport, requestBytes, bodyOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        workspace.ResponseLength = 0;
        ULONG informationalCount = 0;
        for (;;) {
            status = ReadHttpResponseFromSocketEx(
                transport,
                workspace,
                responseBodyForbidden,
                true,
                expectContinueTimeoutMilliseconds,
                acceptPolicy,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength);

            if (!NT_SUCCESS(status) || !IsNonFinalInformationalResponse(*parsed) || parsed->StatusCode == 100) {
                break;
            }

            if (informationalCount >= 16) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++informationalCount;

            bool skippedInformational = false;
            SIZE_T bufferedLength = workspace.ResponseLength;
            status = DiscardNonFinalInformationalResponse(
                workspace.Response.Data,
                &bufferedLength,
                *parsed,
                &skippedInformational);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!skippedInformational) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            workspace.ResponseLength = bufferedLength;
            *parsed = {};
            *rawResponseLength = 0;
        }

        if (NT_SUCCESS(status)) {
            if (parsed->StatusCode == 100) {
                bool skippedInformational = false;
                SIZE_T bufferedLength = workspace.ResponseLength;
                status = DiscardNonFinalInformationalResponse(
                    workspace.Response.Data,
                    &bufferedLength,
                    *parsed,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (!skippedInformational) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                workspace.ResponseLength = bufferedLength;
                *parsed = {};
                *rawResponseLength = 0;

                status = SendTransportSegment(
                    transport,
                    requestBytes + bodyOffset,
                    requestLength - bodyOffset);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return ReadHttpResponseFromSocket(
                    transport,
                    workspace,
                    responseBodyForbidden,
                    acceptPolicy,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }

            return STATUS_SUCCESS;
        }

        if (status != STATUS_IO_TIMEOUT) {
            return status;
        }

        status = SendTransportSegment(
            transport,
            requestBytes + bodyOffset,
            requestLength - bodyOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *parsed = {};
        *rawResponseLength = 0;
        return ReadHttpResponseFromSocket(
            transport,
            workspace,
            responseBodyForbidden,
            acceptPolicy,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestSourceWithExpect(
        _Inout_ core::ITransport& transport,
        _Inout_ KhWorkspace& workspace,
        _In_ const KhRequest& request,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        ULONG expectContinueTimeoutMilliseconds,
        bool responseBodyForbidden,
        _In_opt_ const http::HttpAcceptEncodingPolicy* acceptPolicy,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        NTSTATUS status = SendTransportSegment(transport, requestBytes, requestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        workspace.ResponseLength = 0;
        ULONG informationalCount = 0;
        for (;;) {
            status = ReadHttpResponseFromSocketEx(
                transport,
                workspace,
                responseBodyForbidden,
                true,
                expectContinueTimeoutMilliseconds,
                acceptPolicy,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength);

            if (!NT_SUCCESS(status) || !IsNonFinalInformationalResponse(*parsed) || parsed->StatusCode == 100) {
                break;
            }

            if (informationalCount >= 16) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++informationalCount;

            bool skippedInformational = false;
            SIZE_T bufferedLength = workspace.ResponseLength;
            status = DiscardNonFinalInformationalResponse(
                workspace.Response.Data,
                &bufferedLength,
                *parsed,
                &skippedInformational);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!skippedInformational) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            workspace.ResponseLength = bufferedLength;
            *parsed = {};
            *rawResponseLength = 0;
        }

        if (NT_SUCCESS(status)) {
            if (parsed->StatusCode == 100) {
                bool skippedInformational = false;
                SIZE_T bufferedLength = workspace.ResponseLength;
                status = DiscardNonFinalInformationalResponse(
                    workspace.Response.Data,
                    &bufferedLength,
                    *parsed,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (!skippedInformational) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                workspace.ResponseLength = bufferedLength;
                *parsed = {};
                *rawResponseLength = 0;

                status = SendHttp1RequestBodySource(transport, request, workspace);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return ReadHttpResponseFromSocket(
                    transport,
                    workspace,
                    responseBodyForbidden,
                    acceptPolicy,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }

            return STATUS_SUCCESS;
        }

        if (status != STATUS_IO_TIMEOUT) {
            return status;
        }

        status = SendHttp1RequestBodySource(transport, request, workspace);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *parsed = {};
        *rawResponseLength = 0;
        return ReadHttpResponseFromSocket(
            transport,
            workspace,
            responseBodyForbidden,
            acceptPolicy,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
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
            nullptr,
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
        tlsOptions.MaxTls12Renegotiations = request.Tls.MaxTls12Renegotiations;
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    void PopulateTestHttpTransportRequest(
        const KhRequest& request,
        const KhSession& session,
        KhPooledConnection* pooledConnection,
        bool reusedConnection,
        _In_reads_bytes_opt_(builtRequestLength) const char* builtRequest,
        SIZE_T builtRequestLength,
        SIZE_T headerBytesLength,
        SIZE_T bodyBytesLength,
        bool expectContinueEnabled,
        bool expectContinueBodySent,
        _Out_ KhTestHttpTransportRequest* testRequest,
        KhHttp2CleartextMode http2CleartextMode = KhHttp2CleartextMode::Disabled,
        bool usedHttp2 = false,
        bool http11PipelineEnabled = false,
        bool http11PipelineLease = false,
        ULONG http11PipelineSequence = 0) noexcept
    {
        if (testRequest == nullptr) {
            return;
        }

        RtlZeroMemory(testRequest, sizeof(*testRequest));
        testRequest->Scheme = request.Scheme;
        testRequest->SchemeLength = request.SchemeLength;
        testRequest->Host = request.Host;
        testRequest->HostLength = request.HostLength;
        testRequest->Port = request.Port;
        testRequest->AddressFamily = request.AddressFamily;
        testRequest->BuiltRequest = builtRequest;
        testRequest->BuiltRequestLength = builtRequestLength;
        testRequest->HeaderBytesLength = headerBytesLength;
        testRequest->BodyBytesLength = bodyBytesLength;
        testRequest->ExpectContinueEnabled = expectContinueEnabled;
        testRequest->ExpectContinueBodySent = expectContinueBodySent;
        testRequest->ConnectionPolicy = request.ConnectionPolicy;
        testRequest->CertificatePolicy = request.Tls.CertificatePolicy;
        testRequest->CertificateStore = request.Tls.CertificateStore;
        testRequest->ClientCredential = request.Tls.ClientCredential;
        testRequest->Alpn = request.Tls.Alpn;
        testRequest->AlpnLength = request.Tls.AlpnLength;
        if (IsAutomaticHttpAlpnMode(request)) {
            testRequest->OfferedAlpn = "h2,http/1.1";
            testRequest->OfferedAlpnLength = 11;
        }
        else if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            testRequest->OfferedAlpn = request.Tls.Alpn;
            testRequest->OfferedAlpnLength = request.Tls.AlpnLength;
        }
        testRequest->Policy = request.Tls.Policy;
        testRequest->MaxTls12Renegotiations = request.Tls.MaxTls12Renegotiations;
        testRequest->ProxyEnabled = session.Options.Proxy.Enabled;
        testRequest->ProxyAddress = session.Options.Proxy.Address;
        testRequest->ProxyAuthority = session.Options.Proxy.Authority;
        testRequest->ProxyAuthorityLength = session.Options.Proxy.AuthorityLength;
        testRequest->ProxyAuthHeader = session.Options.Proxy.AuthHeader;
        testRequest->ProxyAuthHeaderLength = session.Options.Proxy.AuthHeaderLength;
        testRequest->PoolableConnection = request.ConnectionPolicy != KhConnectionPolicy::NoPool;
        testRequest->ReusedConnection = reusedConnection;
        testRequest->ConnectionId = pooledConnection != nullptr ? pooledConnection->Id : 0;
        testRequest->Http11PipelineEnabled = http11PipelineEnabled;
        testRequest->Http11PipelineLease = http11PipelineLease;
        testRequest->Http11PipelineSequence = http11PipelineSequence;
        testRequest->Http2CleartextMode = http2CleartextMode;
        testRequest->UsedHttp2 = usedHttp2;
    }
#endif

    _Must_inspect_result_
    NTSTATUS SendViaTransport(
        KH_SESSION session,
        const KhRequest& request,
        const KhHttpSendOptions& sendOptions,
        KhWorkspace& workspace,
        KhPooledConnection* pooledConnection,
        bool reusedConnection,
        bool allowHttp11Pipeline,
        ULONG http11PipelineMaxDepth,
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
        _Out_opt_ bool* usedHttp11Pipeline,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (connectionReusable != nullptr) {
            *connectionReusable = false;
        }
        if (usedHttp11Pipeline != nullptr) {
            *usedHttp11Pipeline = false;
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
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(requestHeaders);
        UNREFERENCED_PARAMETER(requestHeaderCount);
        UNREFERENCED_PARAMETER(cancellationOperation);

        if (g_testHttpTransport == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        SIZE_T headerBytesLength = 0;
        if (!FindHttpRequestBodyOffset(workspace.Request.Data, builtRequestLength, &headerBytesLength)) {
            return STATUS_INVALID_PARAMETER;
        }
        SIZE_T bodyBytesLength = builtRequestLength - headerBytesLength;
        const bool useExpectContinue = RequestUsesExpectContinue(sendOptions, request);
        KhHttp2CleartextMode http2CleartextMode = KhHttp2CleartextMode::Disabled;
        NTSTATUS status = EffectiveHttp2CleartextMode(
            sendOptions,
            request,
            &http2CleartextMode);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const bool useHttp2Cleartext =
            http2CleartextMode != KhHttp2CleartextMode::Disabled;
        if (useHttp2Cleartext && useExpectContinue) {
            return STATUS_NOT_SUPPORTED;
        }
        if (http2CleartextMode == KhHttp2CleartextMode::Upgrade &&
            (request.HasBody || request.BodySourceCallback != nullptr || request.TrailerCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool h2ExplicitlyRequestedForTest =
            request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "h2");
        bool testHttp11PipelineLease = false;
        ULONG testHttp11PipelineSequence = 0;

        KhTestHttpTransportResponse testResponse = {};
        status = STATUS_SUCCESS;
        KhTestHttpTransportRequest testRequest = {};
        if (useExpectContinue) {
            PopulateTestHttpTransportRequest(
                request,
                *session,
                pooledConnection,
                reusedConnection,
                reinterpret_cast<const char*>(workspace.Request.Data),
                headerBytesLength,
                headerBytesLength,
                bodyBytesLength,
                true,
                false,
                &testRequest,
                http2CleartextMode,
                useHttp2Cleartext);
            status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);

            USHORT firstStatusCode = 0;
            const bool receivedContinue =
                NT_SUCCESS(status) &&
                TryReadRawResponseStatusCode(
                    testResponse.RawResponse,
                    testResponse.RawResponseLength,
                    &firstStatusCode) &&
                firstStatusCode == 100;

            if (status == STATUS_IO_TIMEOUT || receivedContinue) {
                if (request.BodySourceCallback != nullptr) {
                    status = SimulateHttp1RequestBodySourceForTest(request, workspace, &bodyBytesLength);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                testResponse = {};
                PopulateTestHttpTransportRequest(
                    request,
                    *session,
                    pooledConnection,
                    reusedConnection,
                    reinterpret_cast<const char*>(workspace.Request.Data + headerBytesLength),
                    bodyBytesLength,
                    headerBytesLength,
                    bodyBytesLength,
                    true,
                    true,
                    &testRequest,
                    http2CleartextMode,
                    useHttp2Cleartext);
                status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);
            }
        }
        else {
            if (request.BodySourceCallback != nullptr) {
                status = SimulateHttp1RequestBodySourceForTest(request, workspace, &bodyBytesLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            const bool canUseTestHttp11Pipeline =
                allowHttp11Pipeline &&
                pooledConnection != nullptr &&
                !useHttp2Cleartext &&
                !h2ExplicitlyRequestedForTest;
            if (canUseTestHttp11Pipeline) {
                if (!KhConnectionPoolHasHttp1PipelineLease(pooledConnection)) {
                    status = KhConnectionPoolPromoteHttp1PipelineLease(
                        &session->ConnectionPool,
                        pooledConnection,
                        http11PipelineMaxDepth);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }

                status = KhConnectionPoolBeginHttp1PipelineSend(
                    &session->ConnectionPool,
                    pooledConnection,
                    &testHttp11PipelineSequence);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                testHttp11PipelineLease = true;
                if (usedHttp11Pipeline != nullptr) {
                    *usedHttp11Pipeline = true;
                }
            }
            PopulateTestHttpTransportRequest(
                request,
                *session,
                pooledConnection,
                reusedConnection,
                reinterpret_cast<const char*>(workspace.Request.Data),
                builtRequestLength,
                headerBytesLength,
                bodyBytesLength,
                false,
                false,
                &testRequest,
                http2CleartextMode,
                useHttp2Cleartext,
                allowHttp11Pipeline,
                testHttp11PipelineLease,
                testHttp11PipelineSequence);
            status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);
            if (testHttp11PipelineLease) {
                KhConnectionPoolEndHttp1PipelineSend(pooledConnection);
            }
        }
        if (!NT_SUCCESS(status)) {
            if (testHttp11PipelineLease) {
                KhConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
            }
            return status;
        }

        if (useHttp2Cleartext) {
            if (testHttp11PipelineLease) {
                KhConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_NOT_SUPPORTED);
                return STATUS_NOT_SUPPORTED;
            }
            parsed->MajorVersion = 2;
            parsed->MinorVersion = 0;
            parsed->StatusCode = 200;
            workspace.ResponseLength = 0;
            *rawResponseLength = 0;
            *connectionReusable = false;
            return STATUS_SUCCESS;
        }

        if (TextEqualsLiteral(testResponse.NegotiatedAlpn, testResponse.NegotiatedAlpnLength, "h2")) {
            if (testHttp11PipelineLease) {
                KhConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_NOT_SUPPORTED);
                return STATUS_NOT_SUPPORTED;
            }
            if (useExpectContinue) {
                return STATUS_NOT_SUPPORTED;
            }
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
            if (testHttp11PipelineLease) {
                KhConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (testHttp11PipelineLease) {
            status = KhConnectionPoolWaitHttp1PipelineReceiveTurn(
                &session->ConnectionPool,
                pooledConnection,
                testHttp11PipelineSequence);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = KhWorkspaceEnsureResponseCapacity(&workspace, testResponse.RawResponseLength);
        if (!NT_SUCCESS(status)) {
            if (testHttp11PipelineLease) {
                KhConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
            }
            return status;
        }

        RtlCopyMemory(workspace.Response.Data, testResponse.RawResponse, testResponse.RawResponseLength);
        workspace.ResponseLength = testResponse.RawResponseLength;

        http::HttpAcceptEncodingPolicy acceptPolicy = AcceptEncodingPolicyFromOptions(sendOptions);
        status = ParseResponseBytes(
            workspace,
            workspace.ResponseLength,
            !testResponse.ConnectionReusable,
            &acceptPolicy,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity);
        if (!NT_SUCCESS(status)) {
            if (testHttp11PipelineLease) {
                KhConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
            }
            return status;
        }

        if (testHttp11PipelineLease) {
            status = PreserveHttp1PipelineTrailingBytes(
                &session->ConnectionPool,
                pooledConnection,
                workspace,
                *parsed,
                rawResponseLength);
            if (!NT_SUCCESS(status)) {
                KhConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
                return status;
            }

            *connectionReusable =
                testResponse.ConnectionReusable &&
                IsHttpConnectionReusable(*parsed, *rawResponseLength) &&
                parsed->MajorVersion == 1 &&
                parsed->MinorVersion == 1;
            if (*connectionReusable) {
                KhConnectionPoolCompleteHttp1PipelineReceive(
                    &session->ConnectionPool,
                    pooledConnection,
                    testHttp11PipelineSequence);
            }
            else {
                KhConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_CONNECTION_DISCONNECTED);
            }
        }
        else {
            *rawResponseLength = workspace.ResponseLength;
            *connectionReusable =
                testResponse.ConnectionReusable &&
                IsHttpConnectionReusable(*parsed, *rawResponseLength);
        }
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

        const bool useExpectContinue = RequestUsesExpectContinue(sendOptions, request);
        KhHttp2CleartextMode http2CleartextMode = KhHttp2CleartextMode::Disabled;
        NTSTATUS status = EffectiveHttp2CleartextMode(
            sendOptions,
            request,
            &http2CleartextMode);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool useHttp2Cleartext =
            http2CleartextMode != KhHttp2CleartextMode::Disabled;
        if (useHttp2Cleartext && session->Options.Proxy.Enabled) {
            return STATUS_NOT_SUPPORTED;
        }
        if (useHttp2Cleartext && useExpectContinue) {
            return STATUS_NOT_SUPPORTED;
        }
        if (http2CleartextMode == KhHttp2CleartextMode::Upgrade &&
            (request.HasBody || request.BodySourceCallback != nullptr || request.TrailerCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = EnsureSocketConnected(session, request, *pooledConnection, cancellationOperation);
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

        if (useHttp2Cleartext) {
            if (pooledConnection->Transport == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            if (http2CleartextMode == KhHttp2CleartextMode::Upgrade &&
                pooledConnection->Http2 == nullptr) {
                status = SendH2cUpgradeViaTransport(
                    request,
                    workspace,
                    *pooledConnection,
                    sendOptions,
                    session->Options.Http2MaxHeaderBlockBytes,
                    requestHeaders,
                    requestHeaderCount,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    rawResponseLength);
            }
            else {
                status = SendHttp2ViaTransport(
                    request,
                    workspace,
                    sendOptions,
                    &session->ConnectionPool,
                    *pooledConnection,
                    session->Options.Http2MaxHeaderBlockBytes,
                    requestHeaders,
                    requestHeaderCount,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    rawResponseLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *connectionReusable =
                pooledConnection->Http2 != nullptr &&
                pooledConnection->Http2->IsReusable();
            return STATUS_SUCCESS;
        }

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
            if (useExpectContinue) {
                return STATUS_NOT_SUPPORTED;
            }

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
                sendOptions,
                &session->ConnectionPool,
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

        if (pooledConnection->Transport == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        http::HttpAcceptEncodingPolicy acceptPolicy = AcceptEncodingPolicyFromOptions(sendOptions);
        if (allowHttp11Pipeline) {
            if (!KhConnectionPoolHasHttp1PipelineLease(pooledConnection)) {
                status = KhConnectionPoolPromoteHttp1PipelineLease(
                    &session->ConnectionPool,
                    pooledConnection,
                    http11PipelineMaxDepth);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (usedHttp11Pipeline != nullptr) {
                *usedHttp11Pipeline = true;
            }

            return SendHttp1PipelineRequestBuffer(
                &session->ConnectionPool,
                pooledConnection,
                *pooledConnection->Transport,
                workspace,
                workspace.Request.Data,
                builtRequestLength,
                request.Method == KhHttpMethod::Head,
                &acceptPolicy,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength,
                connectionReusable);
        }

        if (useExpectContinue) {
            if (request.BodySourceCallback != nullptr) {
                status = SendHttp1RequestSourceWithExpect(
                    *pooledConnection->Transport,
                    workspace,
                    request,
                    workspace.Request.Data,
                    builtRequestLength,
                    EffectiveExpectContinueTimeoutMilliseconds(sendOptions),
                    request.Method == KhHttpMethod::Head,
                    &acceptPolicy,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }
            else {
                status = SendHttp1RequestBufferWithExpect(
                    *pooledConnection->Transport,
                    workspace,
                    workspace.Request.Data,
                    builtRequestLength,
                    EffectiveExpectContinueTimeoutMilliseconds(sendOptions),
                    request.Method == KhHttpMethod::Head,
                    &acceptPolicy,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }
        }
        else {
            status = SendHttp1RequestBuffer(
                *pooledConnection->Transport,
                workspace.Request.Data,
                builtRequestLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (request.BodySourceCallback != nullptr) {
                status = SendHttp1RequestBodySource(
                    *pooledConnection->Transport,
                    request,
                    workspace);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            status = ReadHttpResponseFromSocket(
                *pooledConnection->Transport,
                workspace,
                request.Method == KhHttpMethod::Head,
                &acceptPolicy,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength);
        }
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
        const KhHttpSendOptions& sendOptions,
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
        const bool useExpectContinue = RequestUsesExpectContinue(sendOptions, request);
        const bool allowTrace = (sendOptions.Flags & KhHttpSendFlagAllowTrace) != 0;
        const bool useProxyAbsoluteForm = session->Options.Proxy.Enabled && !IsHttpsRequest(request);
        status = BuildRequestBytes(
            request,
            useExpectContinue,
            allowTrace,
            useProxyAbsoluteForm,
            session->Options.Proxy,
            workspace,
            sendOptions,
            headerScratch.HostHeader,
            headerScratch.HostHeaderCapacity,
            headerScratch.RequestTarget,
            headerScratch.RequestTargetCapacity,
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

        KhHttp2CleartextMode http2CleartextMode = KhHttp2CleartextMode::Disabled;
        status = EffectiveHttp2CleartextMode(sendOptions, request, &http2CleartextMode);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildPoolKey(request, session->Options.Proxy, http2CleartextMode, poolKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool allowHttp11Pipeline =
            IsHttp11PipelineCandidate(*session, request, sendOptions, http2CleartextMode);
        KhPooledConnection* pooledConnection = nullptr;
        bool reusedConnection = false;
        if (allowHttp11Pipeline) {
            status = KhConnectionPoolAcquireHttp1Pipeline(
                &session->ConnectionPool,
                *poolKey.Get(),
                request.ConnectionPolicy,
                session->Options.Http11PipelineMaxDepth,
                &pooledConnection,
                &reusedConnection);
        }
        else {
            status = KhConnectionPoolAcquire(
                &session->ConnectionPool,
                *poolKey.Get(),
                request.ConnectionPolicy,
                &pooledConnection,
                &reusedConnection);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        bool connectionReusable = false;
        bool usedHttp11Pipeline = false;
        const SIZE_T responseHeaderCapacity = session->Options.MaxResponseHeaders;
        status = SendViaTransport(
            session,
            request,
            sendOptions,
            workspace,
            pooledConnection,
            reusedConnection,
            allowHttp11Pipeline,
            session->Options.Http11PipelineMaxDepth,
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
            &usedHttp11Pipeline,
            cancellationOperation);

        const bool shouldRetryWithFreshConnection =
            !usedHttp11Pipeline &&
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
                        useExpectContinue,
                        allowTrace,
                        useProxyAbsoluteForm,
                        session->Options.Proxy,
                        workspace,
                        sendOptions,
                        headerScratch.HostHeader,
                        headerScratch.HostHeaderCapacity,
                        headerScratch.RequestTarget,
                        headerScratch.RequestTargetCapacity,
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
                    sendOptions,
                    workspace,
                    retryConnection,
                    retryReused,
                    false,
                    session->Options.Http11PipelineMaxDepth,
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
                    &usedHttp11Pipeline,
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
        http::HttpAcceptEncodingPreference AcceptEncodingPreferences[http::HttpMaxAcceptEncodingPreferences] = {};
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

        KH_HTTP_CACHE effectiveCache = effectiveOptions.Cache != nullptr ? effectiveOptions.Cache : session->Cache;
        KhHttpCacheLookupResult cacheLookup = {};
        KhHttpCacheSnapshot activeCacheSnapshot = {};
        bool activeCacheSnapshotValid = false;
        KH_REQUEST redirectRequest = nullptr;
        KhRequest* currentRequest = request;

        if (effectiveCache != nullptr) {
            status = KhHttpCacheLookup(effectiveCache, *currentRequest, effectiveOptions, &cacheLookup);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (cacheLookup.OnlyIfCachedMiss) {
                return STATUS_NOT_FOUND;
            }
            if (cacheLookup.Found && !cacheLookup.RequiresValidation) {
                http::HttpResponse cachedParsed = {};
                FillParsedFromCacheSnapshot(cacheLookup.Snapshot, &cachedParsed);
                status = InvokeResponseCallbacks(effectiveOptions, cachedParsed);
                if (NT_SUCCESS(status) && shouldAggregate) {
                    status = CreateOwnedResponse(cachedParsed, nullptr, 0, response);
                }
                KhHttpCacheFreeSnapshot(&cacheLookup.Snapshot);
                return status;
            }
            if (cacheLookup.Found && cacheLookup.RequiresValidation) {
                if ((effectiveOptions.Flags & KhHttpSendFlagOnlyIfCached) != 0) {
                    return STATUS_NOT_FOUND;
                }
                status = CloneRequestForAsync(*currentRequest, &redirectRequest);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                currentRequest = redirectRequest;
                if (cacheLookup.IfNoneMatchLength != 0 &&
                    !RequestHasHeader(*currentRequest, "If-None-Match")) {
                    status = KhHttpRequestSetHeader(
                        currentRequest,
                        "If-None-Match",
                        sizeof("If-None-Match") - 1,
                        cacheLookup.IfNoneMatch,
                        cacheLookup.IfNoneMatchLength);
                }
                else if (cacheLookup.IfModifiedSinceLength != 0 &&
                    !RequestHasHeader(*currentRequest, "If-Modified-Since")) {
                    status = KhHttpRequestSetHeader(
                        currentRequest,
                        "If-Modified-Since",
                        sizeof("If-Modified-Since") - 1,
                        cacheLookup.IfModifiedSince,
                        cacheLookup.IfModifiedSinceLength);
                }
                if (!NT_SUCCESS(status)) {
                    KhHttpRequestRelease(redirectRequest);
                    return status;
                }
            }
        }

        const SIZE_T maxResponseBytes = bodyCallbackOnly ?
            0 :
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
                effectiveOptions,
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

        if (NT_SUCCESS(status) &&
            effectiveCache != nullptr &&
            parsed.StatusCode == 304) {
            status = KhHttpCacheUpdateNotModified(
                effectiveCache,
                *currentRequest,
                parsed,
                &activeCacheSnapshot);
            if (NT_SUCCESS(status)) {
                FillParsedFromCacheSnapshot(activeCacheSnapshot, &parsed);
                rawResponseLength = 0;
                activeCacheSnapshotValid = true;
            }
            else if (status == STATUS_NOT_FOUND) {
                status = STATUS_SUCCESS;
            }
        }

        if (NT_SUCCESS(status)) {
            status = InvokeResponseCallbacks(effectiveOptions, parsed);
        }

        if (NT_SUCCESS(status) &&
            effectiveCache != nullptr &&
            parsed.StatusCode != 304 &&
            !activeCacheSnapshotValid) {
            if (http::IsUnsafeMethodForInvalidation(static_cast<ULONG>(currentRequest->Method)) &&
                parsed.StatusCode >= 200 &&
                parsed.StatusCode < 400) {
                KhHttpCacheInvalidateForRequest(effectiveCache, *currentRequest);
            }
            else {
                NTSTATUS cacheStatus = KhHttpCacheStoreResponse(
                    effectiveCache,
                    *currentRequest,
                    effectiveOptions,
                    parsed);
                if (!NT_SUCCESS(cacheStatus)) {
                    status = cacheStatus;
                }
            }
        }

        if (NT_SUCCESS(status) && shouldAggregate) {
            status = CreateOwnedResponse(
                parsed,
                activeCacheSnapshotValid ? nullptr : reinterpret_cast<const char*>(workspace.Response.Data),
                activeCacheSnapshotValid ? 0 : rawResponseLength,
                response);
        }

        if (activeCacheSnapshotValid) {
            KhHttpCacheFreeSnapshot(&activeCacheSnapshot);
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
        if (effectiveOptions.AcceptEncodingPreferenceCount != 0) {
            RtlCopyMemory(
                context->AcceptEncodingPreferences,
                effectiveOptions.AcceptEncodingPreferences,
                sizeof(context->AcceptEncodingPreferences[0]) * effectiveOptions.AcceptEncodingPreferenceCount);
            context->Options.AcceptEncodingPreferences = context->AcceptEncodingPreferences;
        }
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
