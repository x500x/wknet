#pragma once

#include "http1/HttpRequest.h"
#include "http1/HttpTypes.h"
#include "http2/Http2Connection.h"

namespace wknet
{
namespace session
{
    constexpr SIZE_T Http2MaxRequestHeaders = 16;
    constexpr SIZE_T Http2MaxRequestTrailers = 16;
    constexpr SIZE_T Http2MaxHeaderNameLength = 64;
    constexpr SIZE_T Http2ContentLengthBufferLength = 32;

    enum class Http2TransportMode : UCHAR
    {
        TlsAlpn,
        H2cPriorKnowledge,
        H2cUpgrade
    };

    struct Http2RequestOptions final
    {
        Http2TransportMode TransportMode = Http2TransportMode::TlsAlpn;
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        http1::HttpMethod Method = http1::HttpMethod::Get;
        http1::HttpText Path = {};
        http1::HttpText Authority = {};
        http1::HttpText UserAgent = {};
        http1::HttpText ContentType = {};
        http1::HttpText AcceptEncoding = {};
        http1::HttpText ConnectProtocol = {};
        const http1::HttpHeader* ExtraHeaders = nullptr;
        SIZE_T ExtraHeaderCount = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        const http2::Http2RequestBodySource* BodySource = nullptr;
        const http1::HttpHeader* Trailers = nullptr;
        SIZE_T TrailerCount = 0;
        const http2::Http2Priority* Priority = nullptr;
        bool IncludeContentLength = false;
    };

    _Must_inspect_result_
    NTSTATUS BuildHttp2RequestHeaders(
        _In_ const Http2RequestOptions& options,
        _Out_writes_(headerCapacity) http1::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        _Out_writes_all_(Http2MaxRequestHeaders) char lowerHeaderNames[Http2MaxRequestHeaders][Http2MaxHeaderNameLength],
        _Out_writes_(Http2ContentLengthBufferLength) char* contentLengthBuffer,
        _Out_ SIZE_T* headerCount) noexcept;
}
}
