#include "session/HttpEngineInternal.hpp"

namespace wknet
{
namespace session
{
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

        RtlZeroMemory(headers, sizeof(http1::HttpHeader) * headerCapacity);
        if (trailers != nullptr && trailerCapacity != 0) {
            RtlZeroMemory(trailers, sizeof(http1::HttpHeader) * trailerCapacity);
        }
        RtlZeroMemory(options, sizeof(*options));

        SIZE_T hostLength = 0;
        NTSTATUS status = BuildHostHeaderValue(request, host, hostCapacity, &hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T extraHeaderCount = 0;
        bool hasAcceptEncoding = false;
        const bool chunkedRequest = request.BodyMode == RequestBodyMode::Chunked;
        const bool traceMethod = request.Method == HttpMethod::Trace;

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
            const StoredHeader& header = request.Headers[index];
            if (HeaderNameEquals(header, "Transfer-Encoding")) {
                return STATUS_NOT_SUPPORTED;
            }

            if (HeaderNameEquals(header, "TE")) {
                return STATUS_NOT_SUPPORTED;
            }

            // `Trailer` declares which trailer fields will follow; only meaningful
            // when the request emits chunked framing (see HttpRequestAddTrailer).
            if (HeaderNameEquals(header, "Trailer") && !chunkedRequest) {
                return STATUS_NOT_SUPPORTED;
            }

            if (request.HasBody &&
                HeaderNameEquals(header, "Expect") &&
                http1::HeaderValueHasToken(
                    { header.Value, header.ValueLength },
                    http1::MakeText("100-continue"))) {
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

            headers[extraHeaderCount].Name = http1::MakeText("Accept-Encoding");
            headers[extraHeaderCount].Value = acceptEncoding;
            ++extraHeaderCount;
        }

        if (emitExpectContinue) {
            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = http1::MakeText("Expect");
            headers[extraHeaderCount].Value = http1::MakeText("100-continue");
            ++extraHeaderCount;
        }

        if (useProxyAbsoluteForm && proxy.AuthHeader != nullptr && proxy.AuthHeaderLength != 0) {
            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = http1::MakeText("Proxy-Authorization");
            headers[extraHeaderCount].Value = { proxy.AuthHeader, proxy.AuthHeaderLength };
            ++extraHeaderCount;
        }

        http1::HttpText requestPath = { request.Path, request.PathLength };
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
        options->Connection = request.ConnectionPolicy == ConnectionPolicy::ReuseOrCreate ?
            http1::HttpConnectionDirective::KeepAlive :
            http1::HttpConnectionDirective::Close;
        options->ExtraHeaders = headers;
        options->ExtraHeaderCount = extraHeaderCount;
        options->Body = reinterpret_cast<const char*>(request.Body);
        options->BodyLength = request.BodyLength;
        options->IncludeContentLength = request.HasBody;
        options->BodyMode = request.BodyMode == RequestBodyMode::Chunked ?
            http1::HttpRequestBodyMode::Chunked :
            http1::HttpRequestBodyMode::ContentLength;
        options->AllowExpectContinue = emitExpectContinue;
        options->AllowTrace = allowTrace;

        if (request.TrailerCount != 0) {
            for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
                const StoredHeader& trailer = request.Trailers[index];
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
        const Request& request,
        const ProxyOptions& proxy,
        Http2CleartextMode http2CleartextMode,
        _Out_ ConnectionPoolKey* key) noexcept
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
        key->CertificateStoreIdentity =
            reinterpret_cast<SIZE_T>(request.Tls.CertificateStore);
        key->ClientCredentialIdentity =
            reinterpret_cast<SIZE_T>(request.Tls.ClientCredential);
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
            status = CopyExactText(
                proxy.Host,
                proxy.HostLength,
                key->ProxyHost,
                sizeof(key->ProxyHost),
                &key->ProxyHostLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            key->ProxyPort = proxy.Port;
            key->ProxyFamily = proxy.Family;
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

}
}
