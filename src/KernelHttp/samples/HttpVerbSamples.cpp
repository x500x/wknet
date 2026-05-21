#include "samples/HttpVerbSamples.h"

#include "client/HttpClient.h"
#include "client/HttpsClient.h"

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr SIZE_T SampleRequestBufferLength = 1024;
        constexpr SIZE_T SampleResponseBufferLength = 16384;
        constexpr SIZE_T SampleDecodedBodyBufferLength = 8192;
        constexpr SIZE_T SampleScratchBodyBufferLength = 8192;
        constexpr SIZE_T SampleHeaderCapacity = 32;
        constexpr SIZE_T SampleLogChunkLength = 384;
        constexpr const wchar_t* HttpBinServerName = L"httpbin.org";
        constexpr const wchar_t* HttpBinServiceName = L"80";
        constexpr const wchar_t* HttpBinHttpsServiceName = L"443";
        constexpr const char* HttpBinTlsServerName = "httpbin.org";
        constexpr SIZE_T HttpBinTlsServerNameLength = sizeof("httpbin.org") - 1;
        constexpr UCHAR HttpBinLeafSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0xE4, 0x15, 0x98, 0x36, 0xD3, 0xF1, 0xBE, 0x3B,
            0x25, 0xFA, 0xA8, 0x50, 0x2F, 0x1A, 0x37, 0x8F,
            0x3D, 0xD9, 0x68, 0xAE, 0xF8, 0xC7, 0x21, 0xD3,
            0xFD, 0x07, 0x4E, 0x84, 0x10, 0x74, 0xEE, 0x2D
        };
        constexpr UCHAR HttpBinAmazonRootCa1SpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0xFB, 0xE3, 0x01, 0x80, 0x31, 0xF9, 0x58, 0x6B,
            0xCB, 0xF4, 0x17, 0x27, 0xE4, 0x17, 0xB7, 0xD1,
            0xC4, 0x5C, 0x2F, 0x47, 0xF9, 0x3B, 0xE3, 0x72,
            0xA1, 0x7B, 0x96, 0xB5, 0x07, 0x57, 0xD5, 0xA2
        };
        constexpr const wchar_t* LocalHttpsServerName = L"127.0.0.1";
        constexpr const wchar_t* LocalHttpsServiceName = L"8443";
        constexpr const char* LocalHttpsHostName = "localhost";
        constexpr SIZE_T LocalHttpsHostNameLength = sizeof("localhost") - 1;
        constexpr UCHAR LocalHttpsLeafSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x81, 0xB9, 0xD8, 0x37, 0x08, 0x5E, 0x67, 0x1D,
            0x85, 0xA5, 0x16, 0xBC, 0xDE, 0x17, 0x07, 0xCA,
            0x65, 0x5C, 0x2D, 0xDB, 0x01, 0xAC, 0xC1, 0x67,
            0xE9, 0xE6, 0xAC, 0xF4, 0xC8, 0x96, 0xB5, 0x71
        };

        struct SampleIoBuffers final
        {
            char Request[SampleRequestBufferLength] = {};
            char Response[SampleResponseBufferLength] = {};
            char DecodedBody[SampleDecodedBodyBufferLength] = {};
            char ScratchBody[SampleScratchBodyBufferLength] = {};
            http::HttpHeader Headers[SampleHeaderCapacity] = {};
        };

        void LogHttpText(_In_opt_ const char* label, http::HttpText value) noexcept
        {
            UNREFERENCED_PARAMETER(label);
            UNREFERENCED_PARAMETER(value);

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
                UNREFERENCED_PARAMETER(chunkLength);

                kprintf("%.*s\r\n", static_cast<int>(chunkLength), body + offset);
            }
        }

        void LogResponse(const char* methodName, const http::HttpResponse& response) noexcept
        {
            UNREFERENCED_PARAMETER(methodName);
            UNREFERENCED_PARAMETER(response);

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
                UNREFERENCED_PARAMETER(header);

                kprintf("[header] %.*s: %.*s\r\n",
                    static_cast<int>(header.Name.Length),
                    header.Name.Data != nullptr ? header.Name.Data : "",
                    static_cast<int>(header.Value.Length),
                    header.Value.Data != nullptr ? header.Value.Data : "");
            }

            LogBody(response.Body, response.BodyLength);
        }

        void LogRequestStart(
            const char* sampleName,
            http::HttpText path,
            http::HttpText acceptEncoding) noexcept
        {
            UNREFERENCED_PARAMETER(sampleName);
            UNREFERENCED_PARAMETER(path);
            UNREFERENCED_PARAMETER(acceptEncoding);

            kprintf("[%s] request path=%.*s accept-encoding=%.*s\r\n",
                sampleName,
                static_cast<int>(path.Length),
                path.Data != nullptr ? path.Data : "",
                static_cast<int>(acceptEncoding.Length),
                acceptEncoding.Data != nullptr ? acceptEncoding.Data : "");
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
            responseBuffers.ScratchBodyBuffer = buffers->ScratchBody;
            responseBuffers.ScratchBodyBufferLength = sizeof(buffers->ScratchBody);
            responseBuffers.Headers = buffers->Headers;
            responseBuffers.HeaderCapacity = SampleHeaderCapacity;

            client::HttpRequestOptions options = {};
            options.ServerName = serverName;
            options.ServiceName = serviceName;
            options.Request = request;
            options.ResponseBodyForbidden = responseBodyForbidden;

            http::HttpResponse response = {};
            client::HttpClient client;
            http::HttpText acceptEncoding = {};
            const http::HttpHeader* acceptEncodingHeader = nullptr;
            for (SIZE_T index = 0; index < request.ExtraHeaderCount; ++index) {
                if (http::TextEqualsIgnoreCase(request.ExtraHeaders[index].Name, http::MakeText("Accept-Encoding"))) {
                    acceptEncodingHeader = &request.ExtraHeaders[index];
                    break;
                }
            }
            if (acceptEncodingHeader != nullptr) {
                acceptEncoding = acceptEncodingHeader->Value;
            }

            LogRequestStart(methodName, request.Path, acceptEncoding);
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

        _Must_inspect_result_
        NTSTATUS SendHttpsSampleRequest(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const wchar_t* serverName,
            _In_ const wchar_t* serviceName,
            _In_ const char* tlsServerName,
            SIZE_T tlsServerNameLength,
            _In_ const char* methodName,
            _In_ const http::HttpRequestBuildOptions& request,
            bool responseBodyForbidden,
            _In_ const tls::CertificateStore& certificateStore,
            _Out_ HttpVerbSampleResult& result) noexcept
        {
            result = {};

            auto* buffers = new SampleIoBuffers();
            if (buffers == nullptr) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            SOCKADDR_STORAGE remoteAddress = {};
            result.Status = wskClient.Resolve(serverName, serviceName, &remoteAddress);
            if (!NT_SUCCESS(result.Status)) {
                kprintf("[%s] HTTPS resolve failed: 0x%08X\r\n",
                    methodName,
                    static_cast<ULONG>(result.Status));
                delete buffers;
                return result.Status;
            }

            client::HttpsResponseBuffers responseBuffers = {};
            responseBuffers.RequestBuffer = buffers->Request;
            responseBuffers.RequestBufferLength = sizeof(buffers->Request);
            responseBuffers.ResponseBuffer = buffers->Response;
            responseBuffers.ResponseBufferLength = sizeof(buffers->Response);
            responseBuffers.DecodedBodyBuffer = buffers->DecodedBody;
            responseBuffers.DecodedBodyBufferLength = sizeof(buffers->DecodedBody);
            responseBuffers.ScratchBodyBuffer = buffers->ScratchBody;
            responseBuffers.ScratchBodyBufferLength = sizeof(buffers->ScratchBody);
            responseBuffers.Headers = buffers->Headers;
            responseBuffers.HeaderCapacity = SampleHeaderCapacity;

            client::HttpsRequestOptions options = {};
            options.RemoteAddress = reinterpret_cast<const SOCKADDR*>(&remoteAddress);
            options.ServerName = tlsServerName;
            options.ServerNameLength = tlsServerNameLength;
            options.Request = request;
            options.ResponseBodyForbidden = responseBodyForbidden;
            options.CertificateStore = &certificateStore;

            http::HttpResponse response = {};
            client::HttpsClient client;

            LogRequestStart(methodName, request.Path, {});
            result.Status = client.SendRequest(wskClient, options, responseBuffers, response);
            if (NT_SUCCESS(result.Status)) {
                result.StatusCode = response.StatusCode;
                result.HeaderCount = response.HeaderCount;
                result.BodyLength = response.BodyLength;
                LogResponse(methodName, response);
            }
            else {
                kprintf("[%s] HTTPS request failed: 0x%08X\r\n", methodName, static_cast<ULONG>(result.Status));
            }

            delete buffers;
            return result.Status;
        }

        NTSTATUS MergeSampleStatus(NTSTATUS current, NTSTATUS next) noexcept
        {
            return NT_SUCCESS(current) ? next : current;
        }

        _Must_inspect_result_
        NTSTATUS SendHttpBinGet(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const char* sampleName,
            _In_ http::HttpText path,
            _In_ http::HttpText acceptEncoding,
            _Out_ HttpVerbSampleResult& result) noexcept
        {
            const http::HttpHeader headers[] = {
                { http::MakeText("Accept"), http::MakeText("*/*") },
                { http::MakeText("Accept-Encoding"), acceptEncoding }
            };

            http::HttpRequestBuildOptions request = {};
            request.Method = http::HttpMethod::Get;
            request.Path = path;
            request.Host = http::MakeText("httpbin.org");
            request.UserAgent = http::MakeText("KernelHttp/0.1");
            request.Connection = http::HttpConnectionDirective::Close;
            request.ExtraHeaders = headers;
            request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

            return SendSampleRequest(
                wskClient,
                HttpBinServerName,
                HttpBinServiceName,
                sampleName,
                request,
                false,
                result);
        }

        _Must_inspect_result_
        NTSTATUS InitializePinnedCertificateStore(
            _In_reads_bytes_(anchorSpkiSha256Length) const UCHAR* anchorSpkiSha256,
            SIZE_T anchorSpkiSha256Length,
            _In_reads_bytes_(leafSpkiSha256Length) const UCHAR* leafSpkiSha256,
            SIZE_T leafSpkiSha256Length,
            _In_reads_(hostNameLength) const char* hostName,
            SIZE_T hostNameLength,
            _Out_ tls::CertificateStore& certificateStore,
            _Out_ tls::CertificateTrustAnchor& anchor,
            _Out_ tls::CertificatePin& pin) noexcept
        {
            if (anchorSpkiSha256 == nullptr ||
                anchorSpkiSha256Length != tls::CertificateSha256ThumbprintLength ||
                leafSpkiSha256 == nullptr ||
                leafSpkiSha256Length != tls::CertificateSha256ThumbprintLength ||
                hostName == nullptr ||
                hostNameLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            anchor = {};
            RtlCopyMemory(anchor.SubjectPublicKeySha256, anchorSpkiSha256, anchorSpkiSha256Length);
            anchor.MatchSubjectPublicKey = true;

            pin = {};
            pin.HostName = hostName;
            pin.HostNameLength = hostNameLength;
            RtlCopyMemory(pin.LeafSubjectPublicKeySha256, leafSpkiSha256, leafSpkiSha256Length);

            tls::CertificateStoreOptions storeOptions = {};
            storeOptions.TrustAnchors = &anchor;
            storeOptions.TrustAnchorCount = 1;
            storeOptions.Pins = &pin;
            storeOptions.PinCount = 1;

            return certificateStore.Initialize(storeOptions);
        }
    }

    NTSTATUS RunLocalHttpsSmokeSample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};

        tls::CertificateTrustAnchor anchor = {};
        tls::CertificatePin pin = {};
        tls::CertificateStore certificateStore;
        NTSTATUS status = InitializePinnedCertificateStore(
            LocalHttpsLeafSpkiSha256,
            sizeof(LocalHttpsLeafSpkiSha256),
            LocalHttpsLeafSpkiSha256,
            sizeof(LocalHttpsLeafSpkiSha256),
            LocalHttpsHostName,
            LocalHttpsHostNameLength,
            certificateStore,
            anchor,
            pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/sample_response_body.txt");
        request.Host = http::MakeText("localhost:8443");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            LocalHttpsServerName,
            LocalHttpsServiceName,
            LocalHttpsHostName,
            LocalHttpsHostNameLength,
            "HTTPS LOCAL",
            request,
            false,
            certificateStore,
            *result);
    }

    NTSTATUS RunHttpsDeleteHttpBinSample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};

        tls::CertificateTrustAnchor anchor = {};
        tls::CertificatePin pin = {};
        tls::CertificateStore certificateStore;
        NTSTATUS status = InitializePinnedCertificateStore(
            HttpBinAmazonRootCa1SpkiSha256,
            sizeof(HttpBinAmazonRootCa1SpkiSha256),
            HttpBinLeafSpkiSha256,
            sizeof(HttpBinLeafSpkiSha256),
            HttpBinTlsServerName,
            HttpBinTlsServerNameLength,
            certificateStore,
            anchor,
            pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader commonHeaders[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char deleteBody[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS DELETE\"}";
        http::HttpRequestBuildOptions deleteHttpBin = {};
        deleteHttpBin.Method = http::HttpMethod::DeleteMethod;
        deleteHttpBin.Path = http::MakeText("/delete");
        deleteHttpBin.Host = http::MakeText("httpbin.org");
        deleteHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        deleteHttpBin.ContentType = http::MakeText("application/json");
        deleteHttpBin.Connection = http::HttpConnectionDirective::Close;
        deleteHttpBin.Body = deleteBody;
        deleteHttpBin.BodyLength = sizeof(deleteBody) - 1;
        deleteHttpBin.ExtraHeaders = commonHeaders;
        deleteHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        return SendHttpsSampleRequest(
            wskClient,
            HttpBinServerName,
            HttpBinHttpsServiceName,
            HttpBinTlsServerName,
            HttpBinTlsServerNameLength,
            "HTTPS DELETE",
            deleteHttpBin,
            false,
            certificateStore,
            *result);
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
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        NTSTATUS status = SendHttpBinGet(
            wskClient,
            "ENCODING identity",
            http::MakeText("/get"),
            http::MakeText("identity"),
            results->IdentityEncoding);

        status = MergeSampleStatus(
            status,
            SendHttpBinGet(
                wskClient,
                "ENCODING gzip",
                http::MakeText("/gzip"),
                http::MakeText("gzip"),
                results->GzipEncoding));

        status = MergeSampleStatus(
            status,
            SendHttpBinGet(
                wskClient,
                "ENCODING deflate",
                http::MakeText("/deflate"),
                http::MakeText("deflate"),
                results->DeflateEncoding));

        status = MergeSampleStatus(
            status,
            SendHttpBinGet(
                wskClient,
                "ENCODING br",
                http::MakeText("/brotli"),
                http::MakeText("br"),
                results->BrotliEncoding));

        http::HttpRequestBuildOptions getHttpBin = {};
        getHttpBin.Method = http::HttpMethod::Get;
        getHttpBin.Path = http::MakeText("/get");
        getHttpBin.Host = http::MakeText("httpbin.org");
        getHttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        getHttpBin.Connection = http::HttpConnectionDirective::Close;
        getHttpBin.ExtraHeaders = commonHeaders;
        getHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                HttpBinServerName,
                HttpBinServiceName,
                "GET",
                getHttpBin,
                false,
                results->GetHttpBin));

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
        postHttpBin.ExtraHeaders = commonHeaders;
        postHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                HttpBinServerName,
                HttpBinServiceName,
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
        putHttpBin.ExtraHeaders = commonHeaders;
        putHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                HttpBinServerName,
                HttpBinServiceName,
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
        patchHttpBin.ExtraHeaders = commonHeaders;
        patchHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                HttpBinServerName,
                HttpBinServiceName,
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
        deleteHttpBin.ExtraHeaders = commonHeaders;
        deleteHttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                HttpBinServerName,
                HttpBinServiceName,
                "DELETE",
                deleteHttpBin,
                false,
                results->DeleteHttpBin));

        status = MergeSampleStatus(
            status,
            RunHttpsDeleteHttpBinSample(wskClient, &results->HttpsDeleteHttpBin));

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
                HttpBinServerName,
                HttpBinServiceName,
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
                HttpBinServerName,
                HttpBinServiceName,
                "OPTIONS",
                optionsHttpBin,
                false,
                results->OptionsHttpBin));

#if defined(KERNEL_HTTP_ENABLE_LOCAL_HTTPS_SAMPLE) || defined(KERNEL_HTTP_LOCAL_HTTPS_SMOKE_ONLY)
        status = MergeSampleStatus(
            status,
            RunLocalHttpsSmokeSample(wskClient, &results->LocalHttpsSmoke));
#endif

        return status;
    }
}
}
