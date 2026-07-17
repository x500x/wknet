#pragma once

#include "session/HttpEngine.h"
#include "transport/ProxyConnect.h"
#include "transport/Transport.h"
#include "rtl/WorkspaceScratchAllocator.h"
#include "session/HttpCache.h"
#include "session/Http2RequestBuilder.h"
#include "session/EngineImpl.h"
#include "session/HandleAlloc.h"
#include "session/HttpSessionWorkspace.hpp"
#include "session/HttpAcceptEncodingHelpers.hpp"
#include <wknet/codec/Codec.h>
#include "http1/HttpContentEncoding.h"
#include "http1/HttpParser.h"
#include "http1/HttpRequest.h"
#include "http2/Http2Connection.h"
#include "net/WskSocket.h"
#include "tls/TlsConnection.h"

#if !defined(WKNET_USER_MODE_TEST)
#include <ws2ipdef.h>
#endif

namespace wknet
{
namespace quic
{
class QuicConnection;
struct QuicStreamApplicationEventSink;
} // namespace quic

namespace http3
{
class Http3Connection;
}

namespace session
{
    constexpr SIZE_T HttpRequestHeaderScratchBytes =
        sizeof(http1::HttpHeader) * MaxHeadersPerRequest;
    constexpr SIZE_T HttpRequestTrailerScratchBytes =
        sizeof(http1::HttpHeader) * MaxHeadersPerRequest;
    constexpr SIZE_T HttpResponseHeaderScratchBytes =
        sizeof(http1::HttpHeader) * MaxHeadersPerResponse;
    constexpr SIZE_T HttpResponseTrailerScratchBytes =
        sizeof(http1::HttpHeader) * MaxTrailersPerResponse;
    constexpr SIZE_T HttpHostHeaderScratchBytes =
        MaxHostHeaderLength;
    constexpr SIZE_T HttpRequestTargetScratchBytes =
        MaxSchemeLength + 3 + MaxHostHeaderLength + MaxPathLength;
    constexpr SIZE_T HttpHeaderScratchRequiredBytes =
        HttpRequestHeaderScratchBytes +
        HttpRequestTrailerScratchBytes +
        HttpResponseHeaderScratchBytes +
        HttpResponseTrailerScratchBytes +
        HttpHostHeaderScratchBytes +
        HttpRequestTargetScratchBytes;

    constexpr SIZE_T Http2HeaderScratchBytes =
        sizeof(http1::HttpHeader) * Http2MaxRequestHeaders;
    constexpr SIZE_T Http2ExtraHeaderScratchBytes =
        sizeof(http1::HttpHeader) * Http2MaxRequestHeaders;
    constexpr SIZE_T Http2TrailerScratchBytes =
        sizeof(http1::HttpHeader) * Http2MaxRequestTrailers;
    constexpr SIZE_T Http2LowerHeaderScratchBytes =
        Http2MaxRequestHeaders * Http2MaxHeaderNameLength;
    constexpr SIZE_T Http2LowerTrailerScratchBytes =
        Http2MaxRequestTrailers * Http2MaxHeaderNameLength;
    constexpr SIZE_T Http2RequestScratchBytes =
        Http2HeaderScratchBytes +
        Http2ExtraHeaderScratchBytes +
        Http2TrailerScratchBytes +
        Http2LowerHeaderScratchBytes +
        Http2LowerTrailerScratchBytes +
        Http2ContentLengthBufferLength;

    struct ApiHttp2Scratch final
    {
        http1::HttpHeader* Headers = nullptr;
        http1::HttpHeader* ExtraHeaders = nullptr;
        http1::HttpHeader* Trailers = nullptr;
        char (*LowerHeaderNames)[Http2MaxHeaderNameLength] = nullptr;
        char (*LowerTrailerNames)[Http2MaxHeaderNameLength] = nullptr;
        char* ContentLengthBuffer = nullptr;
        char* AuthorityBuffer = nullptr;
        SIZE_T AuthorityCapacity = 0;
    };

    struct ApiHttpHeaderScratch final
    {
        http1::HttpHeader* RequestHeaders = nullptr;
        http1::HttpHeader* RequestTrailers = nullptr;
        http1::HttpHeader* ResponseHeaders = nullptr;
        http1::HttpHeader* ResponseTrailers = nullptr;
        char* HostHeader = nullptr;
        SIZE_T HostHeaderCapacity = 0;
        char* RequestTarget = nullptr;
        SIZE_T RequestTargetCapacity = 0;
    };

    struct RedirectOriginSnapshot final
    {
        char Scheme[MaxSchemeLength + 1] = {};
        char Host[MaxHostLength + 1] = {};
    };

    _Must_inspect_result_
    NTSTATUS GrowDecodedBodyAfterBufferTooSmall(_Inout_ Workspace& workspace) noexcept;

    // Full-buffer Content-Encoding decode into workspace.DecodedBody, growing as needed.
    // Shared by H1 streaming CE path and H2/H3 aggregate decode.
    _Must_inspect_result_
    NTSTATUS DecodeContentWithWorkspace(
        _In_reads_(responseHeaderCount) const http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCount,
        _In_reads_bytes_(responseBodyLength) const char* responseBody,
        SIZE_T responseBodyLength,
        _Inout_ Workspace& workspace,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpContentDecodeResult* decoded) noexcept;

    inline bool RequestHasHeader(_In_ const Request& request, _In_z_ const char* name) noexcept
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

    inline void FillParsedFromCacheSnapshot(
        const HttpCacheSnapshot& snapshot,
        _Out_ http1::HttpResponse* parsed) noexcept
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
        parsed->BodyKind = http1::HttpBodyKind::ContentLength;
        parsed->BytesConsumed = snapshot.BodyLength;
    }


    _Must_inspect_result_
    inline NTSTATUS PrepareApiHttpHeaderScratch(
        _Inout_ Workspace& workspace,
        _Out_ ApiHttpHeaderScratch* scratch) noexcept
    {
        if (scratch == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *scratch = {};
        if (workspace.HttpHeaderScratch.Data == nullptr ||
            workspace.HttpHeaderScratch.Length < HttpHeaderScratchRequiredBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(workspace.HttpHeaderScratch.Data, workspace.HttpHeaderScratch.Length);
        scratch->RequestHeaders = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data);
        scratch->RequestTrailers = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data + HttpRequestHeaderScratchBytes);
        scratch->ResponseHeaders = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes);
        scratch->ResponseTrailers = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes +
            HttpResponseHeaderScratchBytes);
        scratch->HostHeader = reinterpret_cast<char*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes +
            HttpResponseHeaderScratchBytes +
            HttpResponseTrailerScratchBytes);
        scratch->HostHeaderCapacity = HttpHostHeaderScratchBytes;
        scratch->RequestTarget = reinterpret_cast<char*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes +
            HttpResponseHeaderScratchBytes +
            HttpResponseTrailerScratchBytes +
            HttpHostHeaderScratchBytes);
        scratch->RequestTargetCapacity = HttpRequestTargetScratchBytes;
        return STATUS_SUCCESS;
    }

#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    inline NTSTATUS PrepareApiHttp2Scratch(
        _Inout_ Workspace& workspace,
        _Out_ ApiHttp2Scratch* scratch) noexcept
    {
        if (scratch == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *scratch = {};
        if (workspace.Http2HeaderScratch.Data == nullptr ||
            workspace.Http2HeaderScratch.Length < Http2RequestScratchBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(workspace.Http2HeaderScratch.Data, workspace.Http2HeaderScratch.Length);
        scratch->Headers = reinterpret_cast<http1::HttpHeader*>(workspace.Http2HeaderScratch.Data);
        scratch->ExtraHeaders = reinterpret_cast<http1::HttpHeader*>(
            workspace.Http2HeaderScratch.Data + Http2HeaderScratchBytes);
        scratch->Trailers = reinterpret_cast<http1::HttpHeader*>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes);
        scratch->LowerHeaderNames = reinterpret_cast<char (*)[Http2MaxHeaderNameLength]>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes +
            Http2TrailerScratchBytes);
        scratch->LowerTrailerNames = reinterpret_cast<char (*)[Http2MaxHeaderNameLength]>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes +
            Http2TrailerScratchBytes +
            Http2LowerHeaderScratchBytes);
        scratch->ContentLengthBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes +
            Http2TrailerScratchBytes +
            Http2LowerHeaderScratchBytes +
            Http2LowerTrailerScratchBytes);
        scratch->AuthorityBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data + Http2RequestScratchBytes);
        scratch->AuthorityCapacity = workspace.Http2HeaderScratch.Length - Http2RequestScratchBytes;
        return STATUS_SUCCESS;
    }

    inline bool LowercaseHttp2HeaderName(
        http1::HttpText name,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity,
        _Out_ http1::HttpText* lowered) noexcept
    {
        if (lowered != nullptr) {
            *lowered = {};
        }
        if (name.Data == nullptr ||
            name.Length == 0 ||
            name.Length > Http2MaxHeaderNameLength ||
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
    inline NTSTATUS BuildHttp2TrailersFromRequest(
        const Request& request,
        _Out_writes_(trailerCapacity) http1::HttpHeader* trailers,
        SIZE_T trailerCapacity,
        char lowerTrailerNames[Http2MaxRequestTrailers][Http2MaxHeaderNameLength],
        _Out_ SIZE_T* trailerCount) noexcept
    {
        if (trailerCount != nullptr) {
            *trailerCount = 0;
        }
        if (trailerCount == nullptr ||
            (request.TrailerCount != 0 && (trailers == nullptr || lowerTrailerNames == nullptr)) ||
            request.TrailerCount > trailerCapacity ||
            request.TrailerCount > Http2MaxRequestTrailers) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
            const StoredHeader& trailer = request.Trailers[index];
            http1::HttpText loweredName = {};
            if (!LowercaseHttp2HeaderName(
                { trailer.Name, trailer.NameLength },
                lowerTrailerNames[index],
                Http2MaxHeaderNameLength,
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

    inline http1::HttpMethod ToHttpMethod(HttpMethod method) noexcept
    {
        switch (method) {
        case HttpMethod::Post:
            return http1::HttpMethod::Post;
        case HttpMethod::Put:
            return http1::HttpMethod::Put;
        case HttpMethod::Patch:
            return http1::HttpMethod::Patch;
        case HttpMethod::Delete:
            return http1::HttpMethod::DeleteMethod;
        case HttpMethod::Head:
            return http1::HttpMethod::Head;
        case HttpMethod::Options:
            return http1::HttpMethod::Options;
        case HttpMethod::Connect:
            return http1::HttpMethod::Connect;
        case HttpMethod::Trace:
            return http1::HttpMethod::Trace;
        case HttpMethod::Get:
        default:
            return http1::HttpMethod::Get;
        }
    }

    _Must_inspect_result_
    inline NTSTATUS BuildHostHeaderValue(
        const Request& request,
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
    inline NTSTATUS BuildProxyAbsoluteFormTarget(
        const Request& request,
        http1::HttpText hostHeader,
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

    inline bool HeaderNameEquals(const StoredHeader& header, const char* name) noexcept
    {
        return TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, name);
    }

    inline bool IsSupportedHttpAlpn(const char* alpn, SIZE_T alpnLength) noexcept
    {
        return TextEqualsLiteral(alpn, alpnLength, "h2") ||
            TextEqualsLiteral(alpn, alpnLength, "http/1.1");
    }

    inline bool IsHttpsRequest(const Request& request) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https");
    }

    inline bool IsPlainHttpRequest(const Request& request) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "http");
    }

    inline bool IsAutomaticHttpAlpnMode(const Request& request) noexcept
    {
        return IsHttpsRequest(request) &&
            request.Tls.PreferHttp2 &&
            request.Tls.Alpn == nullptr &&
            request.Tls.AlpnLength == 0;
    }

    inline NTSTATUS EffectiveHttp2CleartextMode(
        _In_ const HttpSendOptions& options,
        _In_ const Request& request,
        _Out_ Http2CleartextMode* mode) noexcept
    {
        if (mode == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *mode = Http2CleartextMode::Disabled;
        if (options.Http2CleartextMode == Http2CleartextMode::Disabled) {
            return STATUS_SUCCESS;
        }

        if (!IsPlainHttpRequest(request)) {
            return STATUS_NOT_SUPPORTED;
        }

        *mode = options.Http2CleartextMode;
        return STATUS_SUCCESS;
    }

    inline void RefreshResponseParseDecodedBuffers(
        _In_ const Workspace& workspace,
        _Inout_ http1::HttpParseOptions& parseOptions) noexcept
    {
        parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
    }

    inline bool IsTlsVersionAllowed(
        TlsVersion minimum,
        TlsVersion maximum,
        TlsVersion protocol) noexcept
    {
        return static_cast<USHORT>(minimum) <= static_cast<USHORT>(protocol) &&
            static_cast<USHORT>(protocol) <= static_cast<USHORT>(maximum);
    }

    inline bool IsHttpTls12ConfirmationCandidate(
        const Request& request,
        const tls::TlsHandshakeFailure& failure) noexcept
    {
        const bool failureCanConfirmTls12 =
            failure.Category == tls::TlsHandshakeFailureCategory::VersionNegotiation ||
            (failure.Category == tls::TlsHandshakeFailureCategory::NetworkIo &&
                failure.BeforeTls13FirstServerHello &&
                failure.Status != STATUS_IO_TIMEOUT);
        return IsTlsVersionAllowed(request.Tls.MinVersion, request.Tls.MaxVersion, TlsVersion::Tls12) &&
            IsTlsVersionAllowed(request.Tls.MinVersion, request.Tls.MaxVersion, TlsVersion::Tls13) &&
            failureCanConfirmTls12;
    }

    inline bool IsSafeFreshConnectionRetryMethod(HttpMethod method) noexcept
    {
        return method == HttpMethod::Get ||
            method == HttpMethod::Head ||
            method == HttpMethod::Options;
    }

    inline bool IsTraceSensitiveHeader(const StoredHeader& header) noexcept
    {
        return HeaderNameEquals(header, "Authorization") ||
            HeaderNameEquals(header, "Proxy-Authorization") ||
            HeaderNameEquals(header, "Cookie");
    }

    inline bool IsFreshConnectionRetryStatus(NTSTATUS status) noexcept
    {
        return IsConnectionCloseStatus(status) ||
            status == STATUS_RETRY ||
            status == STATUS_IO_TIMEOUT;
    }

    inline bool ShouldRetryWithFreshConnection(
        _In_ const Request& request,
        NTSTATUS status,
        bool reusedConnection) noexcept
    {
        return !NT_SUCCESS(status) &&
            request.ConnectionPolicy == ConnectionPolicy::ReuseOrCreate &&
            IsSafeFreshConnectionRetryMethod(request.Method) &&
            (status == STATUS_RETRY ||
                (reusedConnection && IsFreshConnectionRetryStatus(status)));
    }

    bool RequestUsesExpectContinue(
        _In_ const HttpSendOptions& options,
        _In_ const Request& request) noexcept;

    inline ULONG Http11PipelineMethodBit(HttpMethod method) noexcept
    {
        switch (method) {
        case HttpMethod::Get:
            return Http11PipelineMethodGet;
        case HttpMethod::Post:
            return Http11PipelineMethodPost;
        case HttpMethod::Put:
            return Http11PipelineMethodPut;
        case HttpMethod::Patch:
            return Http11PipelineMethodPatch;
        case HttpMethod::Delete:
            return Http11PipelineMethodDelete;
        case HttpMethod::Head:
            return Http11PipelineMethodHead;
        case HttpMethod::Options:
            return Http11PipelineMethodOptions;
        case HttpMethod::Connect:
            return Http11PipelineMethodConnect;
        case HttpMethod::Trace:
            return Http11PipelineMethodTrace;
        default:
            return 0;
        }
    }

    inline bool IsHttp11PipelineTlsModeEligible(_In_ const Request& request) noexcept
    {
        if (!IsHttpsRequest(request)) {
            return true;
        }

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            return TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "http/1.1");
        }

        return !request.Tls.PreferHttp2;
    }

    inline bool IsHttp11PipelineCandidate(
        _In_ const Session& session,
        _In_ const Request& request,
        _In_ const HttpSendOptions& options,
        Http2CleartextMode http2CleartextMode) noexcept
    {
        if (!session.Options.EnableHttp11Pipeline ||
            request.ConnectionPolicy != ConnectionPolicy::ReuseOrCreate ||
            http2CleartextMode != Http2CleartextMode::Disabled ||
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

    inline bool RequestUsesExpectContinue(
        _In_ const HttpSendOptions& options,
        _In_ const Request& request) noexcept
    {
        return ((options.Flags & HttpSendFlagExpectContinue) != 0) && request.HasBody;
    }

    inline ULONG EffectiveExpectContinueTimeoutMilliseconds(
        _In_ const HttpSendOptions& options) noexcept
    {
        return options.ExpectContinueTimeoutMilliseconds != 0 ?
            options.ExpectContinueTimeoutMilliseconds :
            DefaultExpectContinueTimeoutMilliseconds;
    }

    inline bool TryReadRawResponseStatusCode(
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
        const Request& request,
        bool addExpectContinue,
        bool allowTrace,
        bool useProxyAbsoluteForm,
        const ProxyOptions& proxy,
        http1::HttpText acceptEncoding,
        _Out_writes_bytes_(hostCapacity) char* host,
        SIZE_T hostCapacity,
        _Out_writes_bytes_(requestTargetCapacity) char* requestTarget,
        SIZE_T requestTargetCapacity,
        _Out_ http1::HttpHeader* headers,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* trailers,
        SIZE_T trailerCapacity,
        _Out_ http1::HttpRequestBuildOptions* options,
        _Out_opt_ SIZE_T* requestHeaderCount) noexcept;

    _Must_inspect_result_
    NTSTATUS BuildRequestBytes(
        const Request& request,
        bool addExpectContinue,
        bool allowTrace,
        bool useProxyAbsoluteForm,
        const ProxyOptions& proxy,
        _Inout_ Workspace& workspace,
        _In_ const HttpSendOptions& sendOptions,
        _Out_writes_bytes_(hostHeaderCapacity) char* hostHeader,
        SIZE_T hostHeaderCapacity,
        _Out_writes_bytes_(requestTargetCapacity) char* requestTarget,
        SIZE_T requestTargetCapacity,
        _Out_writes_(headerCapacity) http1::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* requestTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* requestLength,
        _Out_opt_ SIZE_T* requestHeaderCount) noexcept;

    _Must_inspect_result_
    NTSTATUS BuildPoolKey(
        const Request& request,
        const ProxyOptions& proxy,
        Http2CleartextMode http2CleartextMode,
        _Out_ ConnectionPoolKey* key) noexcept;

    _Must_inspect_result_
    NTSTATUS SendViaTransport(
        SessionHandle session,
        const Request& request,
        const HttpSendOptions& sendOptions,
        Workspace& workspace,
        PooledConnection* pooledConnection,
        bool reusedConnection,
        bool allowHttp11Pipeline,
        ULONG http11PipelineMaxDepth,
        SIZE_T builtRequestLength,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength,
        _Out_ bool* connectionReusable,
        _Out_opt_ bool* usedHttp11Pipeline,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept;

    constexpr ULONGLONG HttpH3UnsetStreamId = ~0ULL;
    constexpr ULONGLONG HttpH3MaximumStreamId = (1ULL << 62) - 1;

    enum class HttpH3RequestState : ULONG
    {
        NoStream = 0,
        StreamCreated = 1,
        HeadersQueued = 2,
        HeadersCommitted = 3,
        RequestPartiallySent = 4,
        RequestFullySent = 5,
        ResponseStarted = 6,
        Completed = 7,
        Cancelled = 8
    };

    enum class HttpH3CancelResult : ULONG
    {
        AlreadyTerminal = 0,
        LocalOnly = 1,
        CancelQueuedAndFence = 2,
        ResetAndStop = 3
    };

    enum class HttpH3GoawayResult : ULONG
    {
        NoActiveStream = 0,
        StreamRejected = 1,
        StreamMayHaveBeenProcessed = 2
    };

    struct HttpH3DispatchContext;
    struct AltSvcCandidateSnapshot;

    using HttpH3PeerDestroy = void (*)(void *context) noexcept;
    using HttpH3PeerAttachRequest = NTSTATUS (*)(void *context, _Inout_ HttpH3DispatchContext *dispatch) noexcept;
    using HttpH3PeerBindStream = NTSTATUS (*)(void *context, _Inout_ HttpH3DispatchContext *dispatch,
                                              ULONGLONG streamId) noexcept;

    struct HttpH3Peer final
    {
        void *Context = nullptr;
        quic::QuicConnection *Quic = nullptr;
        http3::Http3Connection *Http3 = nullptr;
        HttpH3PeerAttachRequest AttachRequest = nullptr;
        HttpH3PeerBindStream BindStream = nullptr;
        HttpH3PeerDestroy Destroy = nullptr;
    };

    struct HttpH3PeerCreateOptions final
    {
        SessionHandle Session = nullptr;
        const Request *RequestObject = nullptr;
        const HttpSendOptions *SendOptions = nullptr;
        HttpH3DispatchContext *Dispatch = nullptr;
        const AltSvcCandidateSnapshot *Alternative = nullptr;
        ULONG ProbeTimeoutMilliseconds = 0;
        ULONGLONG AttemptGeneration = 0;
    };

    using HttpH3PeerCreate = NTSTATUS (*)(void *context, _In_ const HttpH3PeerCreateOptions *options,
                                          _Out_ HttpH3Peer *peer) noexcept;

    struct HttpH3PeerFactory final
    {
        void *Context = nullptr;
        HttpH3PeerCreate Create = nullptr;
    };

    struct HttpH3DispatchStartOptions final
    {
        SessionHandle Session = nullptr;
        const Request *RequestObject = nullptr;
        const HttpSendOptions *SendOptions = nullptr;
        const HttpH3PeerFactory *PeerFactory = nullptr;
        Workspace *ResponseWorkspace = nullptr;
        http1::HttpResponse *ParsedResponse = nullptr;
        http1::HttpHeader *ResponseHeaders = nullptr;
        SIZE_T ResponseHeaderCapacity = 0;
        http1::HttpHeader *ResponseTrailers = nullptr;
        SIZE_T ResponseTrailerCapacity = 0;
        SIZE_T *RawResponseLength = nullptr;
        AsyncOperationHandle CancellationOperation = nullptr;
        const AltSvcCandidateSnapshot *Alternative = nullptr;
        ULONG ProbeTimeoutMilliseconds = 0;
        ULONGLONG AttemptGeneration = 0;
        bool DirectCallbacks = false;
    };

    struct HttpH3DispatchContext final
    {
        const Request *RequestObject = nullptr;
        const HttpSendOptions *SendOptions = nullptr;
        SessionHandle Session = nullptr;
        HttpH3Peer Peer = {};
        void *ResponseAccumulator = nullptr;
        http1::HttpResponse *ParsedResponse = nullptr;
        void *CompletionFence = nullptr;
        HttpH3RequestState State = HttpH3RequestState::NoStream;
        HttpH3RequestState LastProgressState = HttpH3RequestState::NoStream;
        ULONGLONG AttemptGeneration = 0;
        ULONGLONG StreamId = HttpH3UnsetStreamId;
        ULONGLONG LastGoawayId = HttpH3MaximumStreamId;
        ULONGLONG ApplicationError = 0;
        SIZE_T BodyOffset = 0;
        ULONG BodyReadCount = 0;
        ULONG ResponseStatusCode = 0;
        NTSTATUS TerminalStatus = STATUS_PENDING;
        volatile LONG CancelRequested = 0;
        volatile LONG CompletionClaim = 0;
        bool PeerCreated = false;
        bool CompletionDelivered = false;
        bool BodyFinalDelivered = false;
        bool GoawayReceived = false;
        bool DirectCallbacks = false;
        HttpH3GoawayResult GoawayResult = HttpH3GoawayResult::NoActiveStream;
    };

    _Must_inspect_result_ NTSTATUS HttpH3DispatchInitialize(_Out_ HttpH3DispatchContext *context,
                                                            _In_ const HttpH3DispatchStartOptions *options) noexcept;

    _Must_inspect_result_ NTSTATUS HttpH3DispatchRequired(_Inout_ HttpH3DispatchContext *context,
                                                          _In_ const HttpH3DispatchStartOptions *options) noexcept;

    _Must_inspect_result_ NTSTATUS HttpH3DispatchWait(_Inout_ HttpH3DispatchContext *context,
                                                      _In_opt_ AsyncOperationHandle cancellationOperation) noexcept;

    void HttpH3DispatchRelease(_Inout_opt_ HttpH3DispatchContext *context) noexcept;

    _Must_inspect_result_ NTSTATUS HttpH3DispatchAdvanceState(_Inout_ HttpH3DispatchContext *context,
                                                              HttpH3RequestState target, ULONGLONG streamId,
                                                              NTSTATUS terminalStatus) noexcept;

    _Must_inspect_result_ NTSTATUS HttpH3DispatchRequestCancel(_Inout_ HttpH3DispatchContext *context,
                                                               _Out_ HttpH3CancelResult *result) noexcept;

    _Must_inspect_result_ NTSTATUS HttpH3DispatchProcessGoaway(_Inout_ HttpH3DispatchContext *context,
                                                               ULONGLONG goawayId,
                                                               _Out_ HttpH3GoawayResult *result) noexcept;

    void HttpH3DispatchNotifyResponseStarted(_Inout_ HttpH3DispatchContext *context, ULONG statusCode) noexcept;

    _Must_inspect_result_ NTSTATUS HttpH3DispatchNotifyHeader(_Inout_ HttpH3DispatchContext *context,
                                                              _In_reads_bytes_(nameLength) const char *name,
                                                              SIZE_T nameLength,
                                                              _In_reads_bytes_(valueLength) const char *value,
                                                              SIZE_T valueLength, bool trailers) noexcept;

    _Must_inspect_result_ NTSTATUS HttpH3DispatchNotifyBody(_Inout_ HttpH3DispatchContext *context,
                                                            _In_reads_bytes_opt_(dataLength) const UCHAR *data,
                                                            SIZE_T dataLength, bool finalChunk) noexcept;

    void HttpH3DispatchNotifyComplete(_Inout_ HttpH3DispatchContext *context, NTSTATUS status,
                                      ULONGLONG applicationError) noexcept;

    bool HttpH3DispatchDefinitelyUnsent(_In_ const HttpH3DispatchContext *context) noexcept;
    bool HttpH3DispatchResponseStarted(_In_ const HttpH3DispatchContext *context) noexcept;

    void HttpH3GetProductionPeerFactory(SessionHandle session, _Out_ HttpH3PeerFactory *factory) noexcept;

    _Must_inspect_result_
    NTSTATUS InvokeResponseCallbacks(
        const HttpSendOptions& options,
        const http1::HttpResponse& parsed) noexcept;

    // When bodyAlreadyDelivered is true, only OnHeader runs (body was streamed).
    _Must_inspect_result_
    NTSTATUS InvokeResponseCallbacks(
        const HttpSendOptions& options,
        const http1::HttpResponse& parsed,
        bool bodyAlreadyDelivered) noexcept;

    _Must_inspect_result_
    NTSTATUS CreateOwnedResponse(
        const http1::HttpResponse& parsed,
        const char* rawResponse,
        SIZE_T rawResponseLength,
        _Out_ ResponseHandle* response) noexcept;

    bool RedirectsEnabled(const HttpSendOptions& options) noexcept;
    ULONG EffectiveMaxRedirects(const HttpSendOptions& options) noexcept;
    bool IsRedirectStatus(USHORT statusCode) noexcept;
    http1::HttpText FindLocationHeader(const http1::HttpResponse& response) noexcept;

    _Must_inspect_result_
    NTSTATUS ApplyRedirectToRequest(
        _Inout_ Request& request,
        USHORT statusCode,
        http1::HttpText location,
        _Inout_ Workspace& workspace) noexcept;

    _Must_inspect_result_
    bool FindHttpRequestBodyOffset(
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        _Out_ SIZE_T* bodyOffset) noexcept;

    _Must_inspect_result_
    NTSTATUS SimulateHttp1RequestBodySourceForTest(
        _In_ const Request& request,
        _Inout_ Workspace& workspace,
        _Out_ SIZE_T* bodyBytesLength) noexcept;

    _Must_inspect_result_
    NTSTATUS ParseResponseBytes(
        Workspace& workspace,
        SIZE_T responseLength,
        bool messageCompleteOnConnectionClose,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* headers,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* trailers,
        SIZE_T trailerCapacity) noexcept;

    _Must_inspect_result_
    NTSTATUS PreserveHttp1PipelineTrailingBytes(
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection* pooledConnection,
        _Inout_ Workspace& workspace,
        _In_ const http1::HttpResponse& parsed,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    bool IsHttpConnectionReusable(
        _In_ const http1::HttpResponse& parsed,
        SIZE_T rawResponseLength) noexcept;

    _Must_inspect_result_
    bool IsNonFinalInformationalResponse(const http1::HttpResponse& parsed) noexcept;

    _Must_inspect_result_
    NTSTATUS DiscardNonFinalInformationalResponse(
        _Inout_updates_bytes_(*responseLength) UCHAR* responseBuffer,
        _Inout_ SIZE_T* responseLength,
        _Inout_ http1::HttpResponse& parsed,
        _Out_ bool* skipped) noexcept;

    _Must_inspect_result_
    NTSTATUS LoadHttp1PipelineBufferedBytes(
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection* pooledConnection,
        _Inout_ Workspace& workspace) noexcept;

#if !defined(WKNET_USER_MODE_TEST)
    bool IsHttpAsyncCancellationRequested(_In_opt_ void* context) noexcept;

    class WskCancellationScope final
    {
    public:
        WskCancellationScope(
            _In_opt_ transport::Transport* transport,
            _In_opt_ AsyncOperationHandle operation) noexcept :
            transport_(transport)
        {
            if (transport_ == nullptr || operation == nullptr) {
                return;
            }

            token_.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            token_.Context = operation;
            transport::TransportSetCancellation(transport_, &token_);
        }

        ~WskCancellationScope() noexcept
        {
            if (transport_ != nullptr) {
                transport::TransportSetCancellation(transport_, nullptr);
            }
        }

        WskCancellationScope(const WskCancellationScope&) = delete;
        WskCancellationScope& operator=(const WskCancellationScope&) = delete;

    private:
        transport::Transport* transport_ = nullptr;
        net::WskCancellationToken token_ = {};
    };

    _Must_inspect_result_
    NTSTATUS EnsureSocketConnected(
        _In_ SessionHandle session,
        const Request& request,
        _Inout_ PooledConnection& connection,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept;

    _Must_inspect_result_
    NTSTATUS EnsureTlsConnected(
        _In_ SessionHandle session,
        const Request& request,
        _Inout_ Workspace& workspace,
        _Inout_ PooledConnection& connection,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp2ViaTransport(
        const Request& request,
        Workspace& workspace,
        _In_ const HttpSendOptions& sendOptions,
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection& pooledConnection,
        SIZE_T maxHeaderBlockBytes,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendH2cUpgradeViaTransport(
        const Request& request,
        Workspace& workspace,
        _Inout_ PooledConnection& pooledConnection,
        _In_ const HttpSendOptions& sendOptions,
        SIZE_T maxHeaderBlockBytes,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBuffer(
        _Inout_ transport::Transport* transport,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp1PipelineRequestBuffer(
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection* pooledConnection,
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength,
        _Out_ bool* connectionReusable) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBodySource(
        _Inout_ transport::Transport* transport,
        _In_ const Request& request,
        _Inout_ Workspace& workspace) noexcept;

    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocket(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    // Streaming H1 response reader: delivers body via BodyCallback incrementally.
    // When aggregateBody is true, also materializes parsed.Body (subject to MaxResponseBytes).
    // Non-identity Content-Encoding is supported by buffering the transfer-decoded body,
    // full-buffer CE decoding, then delivering the plaintext to callbacks (no incremental inflate).
    // Sets *bodyDelivered via callbacks when BodyCallback is non-null.
    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocketStreaming(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        ULONG bodyReadTimeoutMilliseconds,
        ULONG bodyIdleTimeoutMilliseconds,
        bool aggregateBody,
        _In_opt_ ResponseStartCallback responseStartCallback,
        _In_opt_ HeaderCallback headerCallback,
        _In_opt_ BodyCallback bodyCallback,
        _In_opt_ void* callbackContext,
        _Out_ bool* bodyDelivered,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBufferWithExpect(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        ULONG expectContinueTimeoutMilliseconds,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestSourceWithExpect(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        _In_ const Request& request,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        ULONG expectContinueTimeoutMilliseconds,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;
#endif
}
}
