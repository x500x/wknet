#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace http
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
        Custom
    };

    enum class HttpConnectionDirective : UCHAR
    {
        Omit,
        KeepAlive,
        Close
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
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        bool IncludeContentLength = false;
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
    };
}
}
