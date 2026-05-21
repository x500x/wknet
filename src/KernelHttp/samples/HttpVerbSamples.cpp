#include "samples/HttpVerbSamples.h"

#include "client/HttpClient.h"

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr SIZE_T SampleRequestBufferLength = 1024;
        constexpr SIZE_T SampleResponseBufferLength = 16384;
        constexpr SIZE_T SampleDecodedBodyBufferLength = 8192;
        constexpr SIZE_T SampleHeaderCapacity = 32;

        struct SampleIoBuffers final
        {
            char Request[SampleRequestBufferLength] = {};
            char Response[SampleResponseBufferLength] = {};
            char DecodedBody[SampleDecodedBodyBufferLength] = {};
            http::HttpHeader Headers[SampleHeaderCapacity] = {};
        };

        _Must_inspect_result_
        NTSTATUS SendSampleRequest(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const wchar_t* serverName,
            _In_ const http::HttpRequestBuildOptions& request,
            _Out_ HttpVerbSampleResult& result) noexcept
        {
            result = {};

            auto* buffers = new SampleIoBuffers();
            if (buffers == nullptr) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            client::HttpResponseBuffers responseBuffers = {};
            responseBuffers.RequestBuffer = buffers->Request;
            responseBuffers.RequestBufferLength = sizeof(buffers->Request);
            responseBuffers.ResponseBuffer = buffers->Response;
            responseBuffers.ResponseBufferLength = sizeof(buffers->Response);
            responseBuffers.DecodedBodyBuffer = buffers->DecodedBody;
            responseBuffers.DecodedBodyBufferLength = sizeof(buffers->DecodedBody);
            responseBuffers.Headers = buffers->Headers;
            responseBuffers.HeaderCapacity = SampleHeaderCapacity;

            client::HttpRequestOptions options = {};
            options.ServerName = serverName;
            options.ServiceName = L"80";
            options.Request = request;

            http::HttpResponse response = {};
            client::HttpClient client;
            result.Status = client.SendRequest(wskClient, options, responseBuffers, response);
            if (NT_SUCCESS(result.Status)) {
                result.StatusCode = response.StatusCode;
                result.BodyLength = response.BodyLength;
            }

            delete buffers;
            return result.Status;
        }

        _Must_inspect_result_
        NTSTATUS MergeSampleStatus(NTSTATUS current, NTSTATUS next) noexcept
        {
            return NT_SUCCESS(current) ? next : current;
        }
    }

    NTSTATUS RunHttpVerbSamples(
        net::WskClient& wskClient,
        HttpVerbSampleResults* results) noexcept
    {
        if (results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};

        const http::HttpHeader baiduHeaders[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") }
        };

        http::HttpRequestBuildOptions getBaidu = {};
        getBaidu.Method = http::HttpMethod::Get;
        getBaidu.Path = http::MakeText("/");
        getBaidu.Host = http::MakeText("www.baidu.com");
        getBaidu.UserAgent = http::MakeText("KernelHttp/0.1");
        getBaidu.Connection = http::HttpConnectionDirective::Close;
        getBaidu.ExtraHeaders = baiduHeaders;
        getBaidu.ExtraHeaderCount = sizeof(baiduHeaders) / sizeof(baiduHeaders[0]);

        NTSTATUS status = SendSampleRequest(
            wskClient,
            L"www.baidu.com",
            getBaidu,
            results->GetBaidu);

        const char postBody[] = "{\"source\":\"kernel-http\",\"method\":\"POST\"}";
        http::HttpRequestBuildOptions postHttpBin = {};
        postHttpBin.Method = http::HttpMethod::Post;
        postHttpBin.Path = http::MakeText("/post");
        postHttpBin.Host = http::MakeText("httpbin.org");
        postHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        postHttpBin.ContentType = http::MakeText("application/json");
        postHttpBin.Connection = http::HttpConnectionDirective::Close;
        postHttpBin.Body = postBody;
        postHttpBin.BodyLength = sizeof(postBody) - 1;

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                L"httpbin.org",
                postHttpBin,
                results->PostHttpBin));

        const char putBody[] = "{\"source\":\"kernel-http\",\"method\":\"PUT\"}";
        http::HttpRequestBuildOptions putHttpBin = {};
        putHttpBin.Method = http::HttpMethod::Put;
        putHttpBin.Path = http::MakeText("/put");
        putHttpBin.Host = http::MakeText("httpbin.org");
        putHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        putHttpBin.ContentType = http::MakeText("application/json");
        putHttpBin.Connection = http::HttpConnectionDirective::Close;
        putHttpBin.Body = putBody;
        putHttpBin.BodyLength = sizeof(putBody) - 1;

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                L"httpbin.org",
                putHttpBin,
                results->PutHttpBin));

        return status;
    }
}
}
