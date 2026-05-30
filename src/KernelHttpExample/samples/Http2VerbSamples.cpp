#include "samples/Http2VerbSamples.h"

#include <KernelHttp/client/Http2Client.h>

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr SIZE_T Http2SampleHeaderCapacity = 32;
        constexpr SIZE_T Http2SampleNameValueBufferLength = 8192;
        constexpr SIZE_T Http2SampleBodyBufferLength = 16384;
        constexpr const wchar_t* NgHttp2ServerName = L"nghttp2.org";
        constexpr const wchar_t* NgHttp2HttpsServiceName = L"443";
        constexpr const wchar_t* NgHttp2HttpServiceName = L"80";
        constexpr const char* NgHttp2TlsServerName = "nghttp2.org";
        constexpr SIZE_T NgHttp2TlsServerNameLength = sizeof("nghttp2.org") - 1;

        // Pin values for nghttp2.org's current Let's Encrypt E8 chain.
        constexpr UCHAR NgHttp2LeafSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x6A, 0x61, 0x41, 0x3D, 0xDF, 0xF5, 0x7B, 0x64,
            0x3D, 0x10, 0x6D, 0x23, 0x5C, 0x6C, 0x3B, 0xA9,
            0x39, 0x46, 0xE1, 0xC5, 0xDC, 0xDF, 0xEB, 0x5A,
            0xB4, 0x69, 0x0C, 0xDC, 0xEB, 0x8D, 0x9D, 0xF7
        };
        constexpr UCHAR NgHttp2LetsEncryptE8SpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x88, 0x5B, 0xF0, 0x57, 0x22, 0x52, 0xC6, 0x74,
            0x1D, 0xC9, 0xA5, 0x2F, 0x50, 0x44, 0x48, 0x7F,
            0xEF, 0x2A, 0x93, 0xB8, 0x11, 0xCD, 0xED, 0xFA,
            0xD7, 0x62, 0x4C, 0xC2, 0x83, 0xB7, 0xCD, 0xD5
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
                NgHttp2LetsEncryptE8SpkiSha256,
                sizeof(NgHttp2LetsEncryptE8SpkiSha256));
            anchor.MatchSubjectPublicKey = true;

            pin = {};
            pin.HostName = NgHttp2TlsServerName;
            pin.HostNameLength = NgHttp2TlsServerNameLength;
            RtlCopyMemory(pin.LeafSubjectPublicKeySha256,
                NgHttp2LeafSpkiSha256,
                sizeof(NgHttp2LeafSpkiSha256));

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
            client::Http2TransportMode transportMode,
            http::HttpMethod method,
            http::HttpText path,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            http::HttpText contentType,
            _Out_ Http2VerbSampleResult& result) noexcept
        {
            UNREFERENCED_PARAMETER(sampleName);
            result = {};

            auto* buffers = new Http2SampleBuffers();
            if (buffers == nullptr) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            SOCKADDR_STORAGE remoteAddress = {};
            result.Status = wskClient.Resolve(
                NgHttp2ServerName,
                transportMode == client::Http2TransportMode::TlsAlpn ? NgHttp2HttpsServiceName : NgHttp2HttpServiceName,
                &remoteAddress);
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
            if (transportMode == client::Http2TransportMode::TlsAlpn) {
                result.Status = InitializePinnedCertificateStore(certificateStore, anchor, pin);
                if (!NT_SUCCESS(result.Status)) {
                    delete buffers;
                    return result.Status;
                }
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
            options.TransportMode = transportMode;
            options.RemoteAddress = reinterpret_cast<const SOCKADDR*>(&remoteAddress);
            options.ServerName = NgHttp2TlsServerName;
            options.ServerNameLength = NgHttp2TlsServerNameLength;
            options.CertificateStore = transportMode == client::Http2TransportMode::TlsAlpn ? &certificateStore : nullptr;
            options.Method = method;
            options.Path = path;
            options.Authority = http::MakeText("nghttp2.org");
            options.UserAgent = http::MakeText("KernelHttp/0.1");
            options.ContentType = contentType;
            options.ExtraHeaders = extraHeaders;
            options.ExtraHeaderCount = sizeof(extraHeaders) / sizeof(extraHeaders[0]);
            options.Body = body;
            options.BodyLength = bodyLength;

            client::Http2Response response = {};
            auto* client = new client::Http2Client();
            if (client == nullptr) {
                delete buffers;
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            kprintf("[%s] HTTP/2 request mode=%u path=%.*s\r\n",
                sampleName,
                static_cast<unsigned>(transportMode),
                static_cast<int>(path.Length),
                path.Data != nullptr ? path.Data : "");

            result.Status = client->SendRequest(wskClient, options, responseBuffers, response);
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

            delete client;
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
            client::Http2TransportMode::TlsAlpn,
            http::HttpMethod::Get,
            http::MakeText("/httpbin/get"),
            nullptr,
            0,
            {},
            results->Http2GetHttpBin);

        const UCHAR postBody[] = "{\"source\":\"kernel-http\",\"method\":\"HTTP2 POST\"}";
        status = MergeSampleStatus(status, SendHttp2SampleRequest(
            wskClient,
            "HTTP2 POST",
            client::Http2TransportMode::TlsAlpn,
            http::HttpMethod::Post,
            http::MakeText("/httpbin/post"),
            postBody,
            sizeof(postBody) - 1,
            http::MakeText("application/json"),
            results->Http2PostHttpBin));

        status = MergeSampleStatus(status, SendHttp2SampleRequest(
            wskClient,
            "H2C prior knowledge GET",
            client::Http2TransportMode::H2cPriorKnowledge,
            http::HttpMethod::Get,
            http::MakeText("/httpbin/get"),
            nullptr,
            0,
            {},
            results->H2cPriorKnowledgeGet));

        status = MergeSampleStatus(status, SendHttp2SampleRequest(
            wskClient,
            "H2C upgrade GET",
            client::Http2TransportMode::H2cUpgrade,
            http::HttpMethod::Get,
            http::MakeText("/httpbin/get"),
            nullptr,
            0,
            {},
            results->H2cUpgradeGet));

        return status;
    }
}
}
