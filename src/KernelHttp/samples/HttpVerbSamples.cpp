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
        constexpr SIZE_T SampleLogChunkLength = 384;

        struct SampleIoBuffers final
        {
            char Request[SampleRequestBufferLength] = {};
            char Response[SampleResponseBufferLength] = {};
            char DecodedBody[SampleDecodedBodyBufferLength] = {};
            http::HttpHeader Headers[SampleHeaderCapacity] = {};
        };

        void LogHttpText(_In_opt_ const char* label, http::HttpText value) noexcept
        {
            if (label != nullptr) {
                kprintf("%s%.*s\r\n", label, static_cast<int>(value.Length), value.Data != nullptr ? value.Data : "");
            }
            else {
                kprintf("%.*s\r\n", static_cast<int>(value.Length), value.Data != nullptr ? value.Data : "");
            }
        }

        void LogBody(const char* body, SIZE_T bodyLength) noexcept
        {
            if (body == nullptr || bodyLength == 0) {
                kprintf("[body]\r\n<empty>\r\n");
                return;
            }

            kprintf("[body]\r\n");
            for (SIZE_T offset = 0; offset < bodyLength; offset += SampleLogChunkLength) {
                const SIZE_T remaining = bodyLength - offset;
                const SIZE_T chunkLength = remaining < SampleLogChunkLength ? remaining : SampleLogChunkLength;
                kprintf("%.*s\r\n", static_cast<int>(chunkLength), body + offset);
            }
        }

        void LogResponse(const char* methodName, const http::HttpResponse& response) noexcept
        {
            kprintf("[%s] status=%u version=%u.%u bodyKind=%u bodyLength=%Iu consumed=%Iu\r\n",
                methodName,
                response.StatusCode,
                response.MajorVersion,
                response.MinorVersion,
                static_cast<unsigned>(response.BodyKind),
                response.BodyLength,
                response.BytesConsumed);

            LogHttpText("[status-line] reason=", response.ReasonPhrase);

            for (SIZE_T index = 0; index < response.HeaderCount; ++index) {
                const http::HttpHeader& header = response.Headers[index];
                kprintf("[header] %.*s: %.*s\r\n",
                    static_cast<int>(header.Name.Length),
                    header.Name.Data != nullptr ? header.Name.Data : "",
                    static_cast<int>(header.Value.Length),
                    header.Value.Data != nullptr ? header.Value.Data : "");
            }

            LogBody(response.Body, response.BodyLength);
        }

        _Must_inspect_result_
        NTSTATUS SendSampleRequest(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const wchar_t* serverName,
            _In_ const wchar_t* serviceName,
            _In_ const char* methodName,
            _In_ const http::HttpRequestBuildOptions& request,
            bool responseBodyForbidden,
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
            options.ServiceName = serviceName;
            options.Request = request;
            options.ResponseBodyForbidden = responseBodyForbidden;

            http::HttpResponse response = {};
            client::HttpClient client;
            result.Status = client.SendRequest(wskClient, options, responseBuffers, response);
            if (NT_SUCCESS(result.Status)) {
                result.StatusCode = response.StatusCode;
                result.HeaderCount = response.HeaderCount;
                result.BodyLength = response.BodyLength;
                LogResponse(methodName, response);
            }
            else {
                kprintf("[%s] request failed: 0x%08X\r\n", methodName, static_cast<ULONG>(result.Status));
            }

            delete buffers;
            return result.Status;
        }

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

        const http::HttpHeader commonHeaders[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") }
        };

        http::HttpRequestBuildOptions getHttpBin = {};
        getHttpBin.Method = http::HttpMethod::Get;
        getHttpBin.Path = http::MakeText("/get");
        getHttpBin.Host = http::MakeText("httpbin.org");
        getHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        getHttpBin.Connection = http::HttpConnectionDirective::Close;
        getHttpBin.ExtraHeaders = commonHeaders;
        getHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        NTSTATUS status = SendSampleRequest(
            wskClient,
            L"httpbin.org",
            L"80",
            "GET",
            getHttpBin,
            false,
            results->GetHttpBin);

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
                L"80",
                "POST",
                postHttpBin,
                false,
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
                L"80",
                "PUT",
                putHttpBin,
                false,
                results->PutHttpBin));

        const char patchBody[] = "{\"source\":\"kernel-http\",\"method\":\"PATCH\"}";
        http::HttpRequestBuildOptions patchHttpBin = {};
        patchHttpBin.Method = http::HttpMethod::Patch;
        patchHttpBin.Path = http::MakeText("/patch");
        patchHttpBin.Host = http::MakeText("httpbin.org");
        patchHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        patchHttpBin.ContentType = http::MakeText("application/json");
        patchHttpBin.Connection = http::HttpConnectionDirective::Close;
        patchHttpBin.Body = patchBody;
        patchHttpBin.BodyLength = sizeof(patchBody) - 1;

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                L"httpbin.org",
                L"80",
                "PATCH",
                patchHttpBin,
                false,
                results->PatchHttpBin));

        const char deleteBody[] = "{\"source\":\"kernel-http\",\"method\":\"DELETE\"}";
        http::HttpRequestBuildOptions deleteHttpBin = {};
        deleteHttpBin.Method = http::HttpMethod::DeleteMethod;
        deleteHttpBin.Path = http::MakeText("/delete");
        deleteHttpBin.Host = http::MakeText("httpbin.org");
        deleteHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        deleteHttpBin.ContentType = http::MakeText("application/json");
        deleteHttpBin.Connection = http::HttpConnectionDirective::Close;
        deleteHttpBin.Body = deleteBody;
        deleteHttpBin.BodyLength = sizeof(deleteBody) - 1;

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                L"httpbin.org",
                L"80",
                "DELETE",
                deleteHttpBin,
                false,
                results->DeleteHttpBin));

        http::HttpRequestBuildOptions headHttpBin = {};
        headHttpBin.Method = http::HttpMethod::Head;
        headHttpBin.Path = http::MakeText("/get");
        headHttpBin.Host = http::MakeText("httpbin.org");
        headHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        headHttpBin.Connection = http::HttpConnectionDirective::Close;
        headHttpBin.ExtraHeaders = commonHeaders;
        headHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                L"httpbin.org",
                L"80",
                "HEAD",
                headHttpBin,
                true,
                results->HeadHttpBin));

        http::HttpRequestBuildOptions optionsHttpBin = {};
        optionsHttpBin.Method = http::HttpMethod::Options;
        optionsHttpBin.Path = http::MakeText("/");
        optionsHttpBin.Host = http::MakeText("httpbin.org");
        optionsHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        optionsHttpBin.Connection = http::HttpConnectionDirective::Close;
        optionsHttpBin.ExtraHeaders = commonHeaders;
        optionsHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                L"httpbin.org",
                L"80",
                "OPTIONS",
                optionsHttpBin,
                false,
                results->OptionsHttpBin));

        return status;
    }
}
}
