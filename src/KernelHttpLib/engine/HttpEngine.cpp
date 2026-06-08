#include <KernelHttp/engine/HttpEngine.h>
#include <KernelHttp/core/TlsTransport.h>
#include <KernelHttp/core/WorkspaceScratchAllocator.h>
#include <KernelHttp/core/WskTransport.h>
#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/engine/EngineImpl.h>
#include <KernelHttp/engine/HandleAlloc.h>
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
    constexpr SIZE_T KhHttpResponseHeaderScratchBytes =
        sizeof(http::HttpHeader) * KhMaxHeadersPerResponse;
    constexpr SIZE_T KhHttpHostHeaderScratchBytes =
        KhMaxHostHeaderLength;
    constexpr SIZE_T KhHttpHeaderScratchRequiredBytes =
        KhHttpRequestHeaderScratchBytes +
        KhHttpResponseHeaderScratchBytes +
        KhHttpHostHeaderScratchBytes;
    constexpr char KhDefaultAcceptEncoding[] = "gzip, deflate, br, identity";

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
        http::HttpHeader* ResponseHeaders = nullptr;
        char* HostHeader = nullptr;
        SIZE_T HostHeaderCapacity = 0;
    };

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

        void Reset() noexcept
        {
            KhWorkspaceRelease(workspace_);
            workspace_ = nullptr;
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
        scratch->ResponseHeaders = reinterpret_cast<http::HttpHeader*>(
            workspace.HttpHeaderScratch.Data + KhHttpRequestHeaderScratchBytes);
        scratch->HostHeader = reinterpret_cast<char*>(
            workspace.HttpHeaderScratch.Data +
            KhHttpRequestHeaderScratchBytes +
            KhHttpResponseHeaderScratchBytes);
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

    bool IsSafeFreshConnectionRetryMethod(KhHttpMethod method) noexcept
    {
        return method == KhHttpMethod::Get ||
            method == KhHttpMethod::Head ||
            method == KhHttpMethod::Options;
    }

    bool IsFreshConnectionRetryStatus(NTSTATUS status) noexcept
    {
        return IsConnectionCloseStatus(status) ||
            status == STATUS_IO_TIMEOUT;
    }

    _Must_inspect_result_
    NTSTATUS BuildHttpRequestOptions(
        const KhRequest& request,
        _Out_writes_bytes_(hostCapacity) char* host,
        SIZE_T hostCapacity,
        _Out_ http::HttpHeader* headers,
        SIZE_T headerCapacity,
        _Out_ http::HttpRequestBuildOptions* options,
        _Out_opt_ SIZE_T* requestHeaderCount = nullptr) noexcept
    {
        if (requestHeaderCount != nullptr) {
            *requestHeaderCount = 0;
        }

        if (host == nullptr || headers == nullptr || options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(headers, sizeof(http::HttpHeader) * headerCapacity);
        RtlZeroMemory(options, sizeof(*options));

        SIZE_T hostLength = 0;
        NTSTATUS status = BuildHostHeaderValue(request, host, hostCapacity, &hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T extraHeaderCount = 0;
        bool hasAcceptEncoding = false;
        for (SIZE_T index = 0; index < request.HeaderCount; ++index) {
            const KhStoredHeader& header = request.Headers[index];
            if (HeaderNameEquals(header, "Transfer-Encoding")) {
                return STATUS_NOT_SUPPORTED;
            }

            if (HeaderNameEquals(header, "Host") ||
                HeaderNameEquals(header, "Content-Length") ||
                HeaderNameEquals(header, "Connection")) {
                continue;
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
            headers[extraHeaderCount].Value = http::MakeText(KhDefaultAcceptEncoding);
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
        if (requestHeaderCount != nullptr) {
            *requestHeaderCount = extraHeaderCount;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BuildPoolKey(const KhRequest& request, _Out_ KhConnectionPoolKey* key) noexcept
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
    NTSTATUS ParseResponseBytes(
        KhWorkspace& workspace,
        SIZE_T responseLength,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* headers,
        SIZE_T headerCapacity) noexcept
    {
        if (parsed == nullptr || headers == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        http::HttpParseOptions parseOptions = {};
        parseOptions.Headers = headers;
        parseOptions.HeaderCapacity = headerCapacity;
        parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
        parseOptions.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
        parseOptions.ScratchBodyCapacity = workspace.Request.Length;
        parseOptions.MessageCompleteOnConnectionClose = true;

        return http::HttpParser::ParseResponse(
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseLength,
            parseOptions,
            *parsed);
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
    NTSTATUS SendHttp2ViaTransport(
        const KhRequest& request,
        KhWorkspace& workspace,
        _Inout_ core::ITransport& transport,
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

        auto* h2Connection = new http2::Http2Connection();
        if (h2Connection == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = h2Connection->Initialize(transport);
        if (!NT_SUCCESS(status)) {
            kprintf("High-level HTTP/2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
            delete h2Connection;
            return status;
        }

        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        status = h2Connection->SendRequest(
            transport,
            h2Scratch.Headers,
            h2HeaderCount,
            request.Body,
            request.BodyLength,
            responseHeaders,
            headerCapacity,
            &responseHeaderCount,
            reinterpret_cast<char*>(workspace.Response.Data),
            workspace.Response.Length,
            &responseBodyLength,
            &statusCode,
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            workspace.DecodedBody.Length);

        if (!NT_SUCCESS(status)) {
            kprintf("High-level HTTP/2 request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            const NTSTATUS shutdownStatus = h2Connection->Shutdown(transport);
            UNREFERENCED_PARAMETER(shutdownStatus);
            delete h2Connection;
            return status;
        }

        http::HttpContentDecodeBuffers decodeBuffers = {};
        decodeBuffers.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        decodeBuffers.DecodedBodyCapacity = workspace.DecodedBody.Length;
        decodeBuffers.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
        decodeBuffers.ScratchBodyCapacity = workspace.Request.Length;

        http::HttpContentDecodeResult decoded = {};
        status = http::HttpContentEncoding::Decode(
            responseHeaders,
            responseHeaderCount,
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseBodyLength,
            decodeBuffers,
            decoded);
        if (!NT_SUCCESS(status)) {
            kprintf("High-level HTTP/2 content decode failed: 0x%08X\r\n", static_cast<ULONG>(status));
            const NTSTATUS shutdownStatus = h2Connection->Shutdown(transport);
            UNREFERENCED_PARAMETER(shutdownStatus);
            delete h2Connection;
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

        const NTSTATUS shutdownStatus = h2Connection->Shutdown(transport);
        UNREFERENCED_PARAMETER(shutdownStatus);
        delete h2Connection;
        return STATUS_SUCCESS;
    }
#endif

    _Must_inspect_result_
    NTSTATUS BuildRequestBytes(
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Out_writes_bytes_(hostHeaderCapacity) char* hostHeader,
        SIZE_T hostHeaderCapacity,
        _Out_writes_(headerCapacity) http::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
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
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr || responseHeaders == nullptr || rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *rawResponseLength = 0;
        SIZE_T responseLength = 0;
        const ULONGLONG responseReadDeadline = MakeResponseReadDeadline();

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = responseHeaders;
            parseOptions.HeaderCapacity = headerCapacity;
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
                if (parsed->StatusCode >= 100 &&
                    parsed->StatusCode < 200 &&
                    parsed->StatusCode != 101) {
                    if (parsed->BytesConsumed > responseLength) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    const SIZE_T remaining = responseLength - parsed->BytesConsumed;
                    if (remaining != 0) {
                        RtlMoveMemory(
                            workspace.Response.Data,
                            workspace.Response.Data + parsed->BytesConsumed,
                            remaining);
                    }
                    responseLength = remaining;
                    workspace.ResponseLength = responseLength;
                    *parsed = {};
                    continue;
                }

                *rawResponseLength = responseLength;
                return STATUS_SUCCESS;
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
                if (!IsConnectionCloseStatus(status)) {
                    return status;
                }

                parseOptions.MessageCompleteOnConnectionClose = true;
                status = http::HttpParser::ParseResponse(
                    reinterpret_cast<const char*>(workspace.Response.Data),
                    responseLength,
                    parseOptions,
                    *parsed);
                if (NT_SUCCESS(status)) {
                    *rawResponseLength = responseLength;
                }
                return status;
            }

            if (received == 0) {
                parseOptions.MessageCompleteOnConnectionClose = true;
                status = http::HttpParser::ParseResponse(
                    reinterpret_cast<const char*>(workspace.Response.Data),
                    responseLength,
                    parseOptions,
                    *parsed);
                if (NT_SUCCESS(status)) {
                    *rawResponseLength = responseLength;
                }
                return status;
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

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    static bool IsHttpAsyncCancellationRequested(_In_opt_ void* context) noexcept;
#endif

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
            delete connection.Transport;
            connection.Transport = nullptr;
        }
        if (connection.Tls != nullptr) {
            delete connection.Tls;
            connection.Tls = nullptr;
        }
        if (connection.RawTransport != nullptr) {
            delete connection.RawTransport;
            connection.RawTransport = nullptr;
        }
        if (connection.Socket != nullptr) {
            delete connection.Socket;
            connection.Socket = nullptr;
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
                auto* socket = new net::WskSocket();
                if (socket == nullptr) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                net::WskCancellationToken cancellation = {};
                if (cancellationOperation != nullptr) {
                    cancellation.IsCancellationRequested = IsHttpAsyncCancellationRequested;
                    cancellation.Context = cancellationOperation;
                }

                status = socket->Connect(
                    *session->WskClient,
                    reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]),
                    nullptr,
                    cancellation.IsCancellationRequested != nullptr ? &cancellation : nullptr);
                if (NT_SUCCESS(status)) {
                    connection.Socket = socket;
                    connection.RawTransport = new core::WskTransport(*connection.Socket);
                    if (connection.RawTransport == nullptr) {
                        delete connection.Socket;
                        connection.Socket = nullptr;
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    connection.Transport = connection.RawTransport;
                    return STATUS_SUCCESS;
                }

                lastStatus = status;
                kprintf("HttpEngine socket connect attempt failed: 0x%08X index=%Iu family=%u\r\n",
                    static_cast<ULONG>(status),
                    addressIndex,
                    static_cast<unsigned>(remoteAddresses[addressIndex].ss_family));
                delete socket;
            }
        }

        if (!NT_SUCCESS(lastStatus)) {
            return lastStatus;
        }

        return STATUS_NOT_FOUND;
    }

    _Must_inspect_result_
    NTSTATUS EnsureTlsConnected(
        _In_ KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Inout_ KhPooledConnection& connection) noexcept
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

        if (connection.Transport != nullptr && connection.Transport != connection.RawTransport) {
            delete connection.Transport;
            connection.Transport = connection.RawTransport;
        }
        if (connection.Tls != nullptr) {
            delete connection.Tls;
            connection.Tls = nullptr;
        }

        auto* tlsConnection = new tls::TlsConnection();
        if (tlsConnection == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tls::TlsAlpnProtocol alpn = {};
        tls::TlsClientConnectionOptions tlsOptions = {};
        core::WorkspaceScratchAllocator* handshakeScratch = nullptr;
        core::WorkspaceScratchAllocator* certificateScratch = nullptr;
        handshakeScratch = new core::WorkspaceScratchAllocator(
            workspace,
            core::WorkspaceScratchAllocator::BufferKind::TlsHandshake);
        certificateScratch = new core::WorkspaceScratchAllocator(
            workspace,
            core::WorkspaceScratchAllocator::BufferKind::Certificate);
        if (handshakeScratch == nullptr || certificateScratch == nullptr) {
            delete certificateScratch;
            delete handshakeScratch;
            delete tlsConnection;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        tlsOptions.ServerName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        tlsOptions.ServerNameLength = request.Tls.ServerName != nullptr ?
            request.Tls.ServerNameLength :
            request.HostLength;
        tlsOptions.CertificateStore = request.Tls.CertificateStore;
        tlsOptions.VerifyCertificate = request.Tls.CertificatePolicy == KhCertificatePolicy::Verify;
        tlsOptions.MinimumProtocol = ToTlsProtocol(request.Tls.MinVersion);
        tlsOptions.MaximumProtocol = ToTlsProtocol(request.Tls.MaxVersion);
        tlsOptions.HandshakeReceiveTimeoutMilliseconds = request.Tls.HandshakeReceiveTimeoutMilliseconds;
        tlsOptions.HandshakeScratchAllocator = handshakeScratch;
        tlsOptions.CertificateScratchAllocator = certificateScratch;
        tlsOptions.ProviderCache = session->ProviderCache;
        tlsOptions.EnableSessionResumption = true;

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            alpn.Name = request.Tls.Alpn;
            alpn.NameLength = request.Tls.AlpnLength;
            tlsOptions.AlpnProtocols = &alpn;
            tlsOptions.AlpnProtocolCount = 1;
        }

        NTSTATUS status = tlsConnection->Connect(*connection.RawTransport, tlsOptions);

        if (!NT_SUCCESS(status)) {
            delete tlsConnection;
            delete certificateScratch;
            delete handshakeScratch;
            return status;
        }

        auto* tlsTransport = new core::TlsTransport(*connection.RawTransport, *tlsConnection);
        if (tlsTransport == nullptr) {
            delete tlsConnection;
            delete certificateScratch;
            delete handshakeScratch;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        delete certificateScratch;
        delete handshakeScratch;
        connection.Tls = tlsConnection;
        connection.Transport = tlsTransport;
        return STATUS_SUCCESS;
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
            rawResponseLength == nullptr ||
            connectionReusable == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https") &&
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
        testRequest.Alpn = request.Tls.Alpn;
        testRequest.AlpnLength = request.Tls.AlpnLength;
        testRequest.PoolableConnection = request.ConnectionPolicy != KhConnectionPolicy::NoPool;
        testRequest.ReusedConnection = reusedConnection;
        testRequest.ConnectionId = pooledConnection != nullptr ? pooledConnection->Id : 0;

        KhTestHttpTransportResponse testResponse = {};
        NTSTATUS status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);
        if (!NT_SUCCESS(status)) {
            return status;
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

        status = ParseResponseBytes(workspace, workspace.ResponseLength, parsed, responseHeaders, headerCapacity);
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

        if (TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https")) {
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

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        WskCancellationScope cancellationScope(pooledConnection->RawTransport, cancellationOperation);
#else
        UNREFERENCED_PARAMETER(cancellationOperation);
#endif

        tls::TlsConnection* tlsConnection = nullptr;
        if (TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https")) {
            status = EnsureTlsConnected(
                session,
                request,
                workspace,
                *pooledConnection);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            tlsConnection = pooledConnection->Tls;
        }

        if (tlsConnection != nullptr &&
            TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "h2")) {
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
                *pooledConnection->Transport,
                requestHeaders,
                requestHeaderCount,
                parsed,
                responseHeaders,
                headerCapacity,
                rawResponseLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *connectionReusable = false;
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
        if (method == KhHttpMethod::Get || method == KhHttpMethod::Head) {
            return false;
        }

        return statusCode == 301 || statusCode == 302 || statusCode == 303;
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

        if (location.Data == nullptr ||
            location.Length == 0 ||
            destination == nullptr ||
            destinationLength == nullptr ||
            request.SchemeLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsAbsoluteHttpLocation(location)) {
            *destinationLength = location.Length;
            return STATUS_SUCCESS;
        }

        if (!IsPathAbsoluteLocation(location)) {
            return STATUS_NOT_FOUND;
        }

        SIZE_T offset = 0;
        if (request.SchemeLength > destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(destination, request.Scheme, request.SchemeLength);
        offset += request.SchemeLength;

        if (IsSchemeRelativeLocation(location)) {
            if (offset + 1 > destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            destination[offset++] = ':';
        }
        else {
            if (offset + 3 > destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            destination[offset++] = ':';
            destination[offset++] = '/';
            destination[offset++] = '/';

            SIZE_T authorityLength = 0;
            NTSTATUS status = BuildHostHeaderValue(
                request,
                destination + offset,
                destinationCapacity - offset,
                &authorityLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            offset += authorityLength;
        }

        if (location.Length > destinationCapacity - offset) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(destination + offset, location.Data, location.Length);
        offset += location.Length;
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
        const char* redirectUrl = location.Data;
        SIZE_T redirectUrlLength = location.Length;
        NTSTATUS status = STATUS_SUCCESS;

        if (!IsAbsoluteHttpLocation(location)) {
            status = BuildRedirectUrl(
                request,
                location,
                reinterpret_cast<char*>(workspace.Request.Data),
                workspace.Request.Length,
                &redirectUrlLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            redirectUrl = reinterpret_cast<const char*>(workspace.Request.Data);
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

        return KhHttpRequestSetUrl(&request, redirectUrl, redirectUrlLength);
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
            &builtRequestLength,
            &requestHeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapObject<KhConnectionPoolKey> poolKey;
        if (!poolKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = BuildPoolKey(request, poolKey.Get());
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
            KhMaxHeadersPerResponse,
            rawResponseLength,
            &connectionReusable,
            cancellationOperation);

        const bool shouldRetryWithFreshConnection =
            !NT_SUCCESS(status) &&
            request.ConnectionPolicy == KhConnectionPolicy::ReuseOrCreate &&
            (reusedConnection ||
                (IsSafeFreshConnectionRetryMethod(request.Method) &&
                    IsFreshConnectionRetryStatus(status)));

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
                    KhMaxHeadersPerResponse,
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
        return new KhAsyncHttpContext();
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
        delete context;
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

        if (!IsRequestHandle(request) || request->Session != session) {
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
        status = requestWorkspace.Create(maxResponseBytes, session->Options.RequestBufferBytes);
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

        if (!IsRequestHandle(request) || operation == nullptr || request->Session != session) {
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
