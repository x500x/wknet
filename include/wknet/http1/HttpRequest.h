#pragma once

#include <wknet/http1/HttpTypes.h>

namespace wknet
{
namespace http1
{
    enum class HttpMethod : UCHAR
    {
        Get,
        Post,
        Put,
        DeleteMethod,
        Head,
        Options,
        Patch,
        Connect,
        Trace,
        Custom
    };

    enum class HttpConnectionDirective : UCHAR
    {
        Omit,
        KeepAlive,
        Close,
        Upgrade
    };

    enum class HttpRequestBodyMode : UCHAR
    {
        ContentLength,
        Chunked
    };

    struct HttpRequestBuildOptions final
    {
        HttpMethod Method = HttpMethod::Get;
        HttpText CustomMethod = {};
        HttpText Path = {};
        HttpText Host = {};
        HttpText UserAgent = {};
        HttpText ContentType = {};
        HttpConnectionDirective Connection = HttpConnectionDirective::Omit;
        const HttpHeader* ExtraHeaders = nullptr;
        SIZE_T ExtraHeaderCount = 0;
        // Request trailers are only valid with BodyMode::Chunked. Each trailer's
        // field name must be a valid token and must not be a forbidden trailer
        // field (framing/auth/cookie headers); otherwise Build returns an error.
        const HttpHeader* Trailers = nullptr;
        SIZE_T TrailerCount = 0;
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool IncludeContentLength = false;
        HttpRequestBodyMode BodyMode = HttpRequestBodyMode::ContentLength;
        // Library-controlled opt-in for emitting Expect: 100-continue.
        // Callers that pass the header without this flag are rejected.
        bool AllowExpectContinue = false;
        // TRACE is disabled unless the higher layer explicitly opts in.
        bool AllowTrace = false;
    };

    class HttpRequestBuilder final
    {
    public:
        HttpRequestBuilder() = delete;

        _Must_inspect_result_
        static NTSTATUS Build(
            _In_ const HttpRequestBuildOptions& options,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS BuildHeaders(
            _In_ const HttpRequestBuildOptions& options,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS BuildBody(
            _In_ const HttpRequestBuildOptions& options,
            _Out_writes_bytes_(destinationCapacity) char* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;
    };
}
}
