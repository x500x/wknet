#include "samples/Http2VerbSamples.h"

#include "client/Http2Client.h"

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr SIZE_T Http2SampleHeaderCapacity = 32;
        constexpr SIZE_T Http2SampleNameValueBufferLength = 8192;
        constexpr SIZE_T Http2SampleBodyBufferLength = 16384;
        constexpr const wchar_t* HttpBinServerName = L"httpbin.org";
        constexpr const wchar_t* HttpBinHttpsServiceName = L"443";
        constexpr const char* HttpBinTlsServerName = "httpbin.org";
        constexpr SIZE_T HttpBinTlsServerNameLength = sizeof("httpbin.org") - 1;

        // Pin values reused from HttpVerbSamples.cpp. These values match the current
        // httpbin.org chain used by the existing HTTPS samples in this project.
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

        struct Http2SampleBuffers final
        {
            http::HttpHeader Headers[Http2SampleHeaderCapacity] = {};
            char NameValueBuffer[Http2SampleNameValueBufferLength] = {};
            char BodyBuffer[Http2SampleBodyBufferLength] = {};
        };

        NTSTATUS InitializePinnedCertificateStore(
            _Out_ tls::CertificateStore& certificateStore,
            _Out_ tls::CertificateTrustAnchor& anchor,
            _Out_ tls::CertificatePin& pin) noexcept
        {
            anchor = {};
            RtlCopyMemory(anchor.SubjectPublicKeySha256,
                HttpBinAmazonRootCa1SpkiSha256,
                sizeof(HttpBinAmazonRootCa1SpkiSha256));
            anchor.MatchSubjectPublicKey = true;

            pin = {};
            pin.HostName = HttpBinTlsServerName;
            pin.HostNameLength = HttpBinTlsServerNameLength;
            RtlCopyMemory(pin.LeafSubjectPublicKeySha256,
                HttpBinLeafSpkiSha256,
                sizeof(HttpBinLeafSpkiSha256));

            tls::CertificateStoreOptions storeOptions = {};
            storeOptions.TrustAnchors = &anchor;
            storeOptions.TrustAnchorCount = 1;
            storeOptions.Pins = &pin;
            storeOptions.PinCount = 1;

            return certificateStore.Initialize(storeOptions);
        }

        NTSTATUS SendHttp2SampleRequest(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const char* sampleName,
            http::HttpMethod method,
            http::HttpText path,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            http::HttpText contentType,
            _Out_ Http2VerbSampleResult& result) noexcept
        {
            result = {};

            auto* buffers = new Http2SampleBuffers();
            if (buffers == nullptr) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            SOCKADDR_STORAGE remoteAddress = {};
            result.Status = wskClient.Resolve(HttpBinServerName, HttpBinHttpsServiceName, &remoteAddress);
            if (!NT_SUCCESS(result.Status)) {
                kprintf("[%s] HTTP/2 resolve failed: 0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(result.Status));
                delete buffers;
                return result.Status;
            }

            tls::CertificateTrustAnchor anchor = {};
            tls::CertificatePin pin = {};
            tls::CertificateStore certificateStore;
            result.Status = InitializePinnedCertificateStore(certificateStore, anchor, pin);
            if (!NT_SUCCESS(result.Status)) {
                delete buffers;
                return result.Status;
            }

            client::Http2ResponseBuffers responseBuffers = {};
            responseBuffers.Headers = buffers->Headers;
            responseBuffers.HeaderCapacity = Http2SampleHeaderCapacity;
            responseBuffers.NameValueBuffer = buffers->NameValueBuffer;
            responseBuffers.NameValueBufferLength = sizeof(buffers->NameValueBuffer);
            responseBuffers.BodyBuffer = buffers->BodyBuffer;
            responseBuffers.BodyBufferLength = sizeof(buffers->BodyBuffer);

            const http::HttpHeader extraHeaders[] = {
                { http::MakeText("accept"), http::MakeText("*/*") },
                { http::MakeText("accept-encoding"), http::MakeText("identity") }
            };

            client::Http2RequestOptions options = {};
            options.RemoteAddress = reinterpret_cast<const SOCKADDR*>(&remoteAddress);
            options.ServerName = HttpBinTlsServerName;
            options.ServerNameLength = HttpBinTlsServerNameLength;
            options.CertificateStore = &certificateStore;
            options.Method = method;
            options.Path = path;
            options.Authority = http::MakeText("httpbin.org");
            options.UserAgent = http::MakeText("KernelHttp/0.1");
            options.ContentType = contentType;
            options.ExtraHeaders = extraHeaders;
            options.ExtraHeaderCount = sizeof(extraHeaders) / sizeof(extraHeaders[0]);
            options.Body = body;
            options.BodyLength = bodyLength;

            client::Http2Response response = {};
            client::Http2Client client;

            kprintf("[%s] HTTP/2 request path=%.*s\r\n",
                sampleName,
                static_cast<int>(path.Length),
                path.Data != nullptr ? path.Data : "");

            result.Status = client.SendRequest(wskClient, options, responseBuffers, response);
            if (NT_SUCCESS(result.Status)) {
                result.StatusCode = response.StatusCode;
                result.HeaderCount = response.HeaderCount;
                result.BodyLength = response.BodyLength;
                if (response.NegotiatedAlpnLength < sizeof(result.NegotiatedAlpn)) {
                    RtlCopyMemory(result.NegotiatedAlpn,
                        response.NegotiatedAlpn,
                        response.NegotiatedAlpnLength);
                    result.NegotiatedAlpn[response.NegotiatedAlpnLength] = '\0';
                }

                kprintf("[%s] HTTP/2 status=%u alpn=%.*s headers=%Iu body=%Iu\r\n",
                    sampleName,
                    result.StatusCode,
                    static_cast<int>(response.NegotiatedAlpnLength),
                    response.NegotiatedAlpn,
                    result.HeaderCount,
                    result.BodyLength);
            }
            else {
                kprintf("[%s] HTTP/2 request failed: 0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(result.Status));
            }

            delete buffers;
            return result.Status;
        }

        NTSTATUS MergeSampleStatus(NTSTATUS current, NTSTATUS next) noexcept
        {
            return NT_SUCCESS(current) ? next : current;
        }
    }

    NTSTATUS RunHttp2VerbSamples(
        net::WskClient& wskClient,
        Http2VerbSampleResults* results) noexcept
    {
        if (results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};

        NTSTATUS status = SendHttp2SampleRequest(
            wskClient,
            "HTTP2 GET",
            http::HttpMethod::Get,
            http::MakeText("/get"),
            nullptr,
            0,
            {},
            results->Http2GetHttpBin);

        const UCHAR postBody[] = "{\"source\":\"kernel-http\",\"method\":\"HTTP2 POST\"}";
        status = MergeSampleStatus(status, SendHttp2SampleRequest(
            wskClient,
            "HTTP2 POST",
            http::HttpMethod::Post,
            http::MakeText("/post"),
            postBody,
            sizeof(postBody) - 1,
            http::MakeText("application/json"),
            results->Http2PostHttpBin));

        return status;
    }
}
}
