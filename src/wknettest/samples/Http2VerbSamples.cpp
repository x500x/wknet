#include "samples/Http2VerbSamples.h"

#include "samples/ExternalTrustStore.h"

#include <wknet/WknetConfig.h>
#include <wknet/client/Http2Client.h>
#include <wknet/http2/Http2Frame.h>
#include <wknettest/SampleStatus.h>
#include "wknettestLog.h"

namespace wknet
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

        // Pin values for nghttp2.org's current Let's Encrypt YE chain.
        constexpr UCHAR NgHttp2LeafSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x6A, 0x61, 0x41, 0x3D, 0xDF, 0xF5, 0x7B, 0x64,
            0x3D, 0x10, 0x6D, 0x23, 0x5C, 0x6C, 0x3B, 0xA9,
            0x39, 0x46, 0xE1, 0xC5, 0xDC, 0xDF, 0xEB, 0x5A,
            0xB4, 0x69, 0x0C, 0xDC, 0xEB, 0x8D, 0x9D, 0xF7
        };
        constexpr UCHAR NgHttp2IsrgRootYeSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0xB0, 0x29, 0x2A, 0xE5, 0x45, 0x97, 0x8E, 0x0F,
            0xBB, 0x98, 0xAB, 0xBD, 0x94, 0xC8, 0x61, 0x60,
            0x5E, 0x5B, 0x18, 0xBB, 0x32, 0xED, 0x52, 0x3F,
            0x50, 0xD5, 0xB7, 0xB5, 0xC7, 0x1D, 0x47, 0xBC
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
                NgHttp2IsrgRootYeSpkiSha256,
                sizeof(NgHttp2IsrgRootYeSpkiSha256));
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
            _In_opt_ const tls::CertificateStore* externalCertificateStore,
            _Out_ Http2VerbSampleResult& result) noexcept
        {
            UNREFERENCED_PARAMETER(sampleName);
            result = {};

            HeapObject<Http2SampleBuffers> buffers;
            if (!buffers.IsValid()) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            SOCKADDR_STORAGE remoteAddress = {};
            result.Status = wskClient.Resolve(
                NgHttp2ServerName,
                transportMode == client::Http2TransportMode::TlsAlpn ? NgHttp2HttpsServiceName : NgHttp2HttpServiceName,
                &remoteAddress);
            if (!NT_SUCCESS(result.Status)) {
                WKNET_DBG_PRINT("[%s] HTTP/2 resolve failed: 0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(result.Status));
                return result.Status;
            }

            tls::CertificateTrustAnchor anchor = {};
            tls::CertificatePin pin = {};
            tls::CertificateStore certificateStore;
            const tls::CertificateStore* effectiveCertificateStore = externalCertificateStore;
            if (transportMode == client::Http2TransportMode::TlsAlpn) {
                if (effectiveCertificateStore == nullptr) {
                    result.Status = InitializePinnedCertificateStore(certificateStore, anchor, pin);
                    if (!NT_SUCCESS(result.Status)) {
                        return result.Status;
                    }
                    effectiveCertificateStore = &certificateStore;
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
            options.CertificateStore =
                transportMode == client::Http2TransportMode::TlsAlpn ? effectiveCertificateStore : nullptr;
            options.Method = method;
            options.Path = path;
            options.Authority = http::MakeText("nghttp2.org");
            options.UserAgent = http::MakeText("wknet/0.1");
            options.ContentType = contentType;
            options.ExtraHeaders = extraHeaders;
            options.ExtraHeaderCount = sizeof(extraHeaders) / sizeof(extraHeaders[0]);
            options.Body = body;
            options.BodyLength = bodyLength;

            client::Http2Response response = {};
            HeapObject<client::Http2Client> client;
            if (!client.IsValid()) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            WKNET_DBG_PRINT("[%s] HTTP/2 request mode=%u path=%.*s\r\n",
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

                WKNET_DBG_PRINT("[%s] HTTP/2 status=%u alpn=%.*s headers=%Iu body=%Iu\r\n",
                    sampleName,
                    result.StatusCode,
                    static_cast<int>(response.NegotiatedAlpnLength),
                    response.NegotiatedAlpn,
                    result.HeaderCount,
                    result.BodyLength);
            }
            else {
                WKNET_DBG_PRINT("[%s] HTTP/2 request failed: 0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(result.Status));
            }

            return result.Status;
        }

        NTSTATUS MergeSampleStatus(NTSTATUS current, NTSTATUS next) noexcept
        {
            NTSTATUS aggregate = current;
            MergeFatalSampleStatus(aggregate, next);
            return aggregate;
        }

        NTSTATUS MergePublicSampleStatus(
            NTSTATUS current,
            _In_z_ const char* sampleName,
            NTSTATUS next) noexcept
        {
            if (!NT_SUCCESS(next) && IsPublicEndpointDiagnosticStatus(next)) {
                WKNET_DBG_PRINT("[%s] 公网端点环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(next));
                return current;
            }

            return MergeSampleStatus(current, next);
        }

        void CaptureFrameSampleResult(
            _Out_ Http2VerbSampleResult& result,
            NTSTATUS status,
            USHORT frameCount,
            SIZE_T bytesWritten) noexcept
        {
            result.Status = status;
            result.StatusCode = frameCount;
            result.HeaderCount = frameCount;
            result.BodyLength = bytesWritten;
        }

        NTSTATUS ValidateFrameHeader(
            _In_reads_bytes_(frameLength) const UCHAR* frame,
            SIZE_T frameLength,
            http2::Http2FrameType expectedType,
            ULONG expectedStreamId,
            _Out_ http2::Http2FrameHeader* header) noexcept
        {
            if (frame == nullptr || header == nullptr || frameLength < http2::Http2FrameHeaderLength) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = http2::Http2FrameCodec::DecodeFrameHeader(
                frame,
                frameLength,
                header);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (header->Type != expectedType || header->StreamId != expectedStreamId ||
                frameLength < http2::Http2FrameHeaderLength + header->Length) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS RunGoAwayFrameSample(_Out_ Http2VerbSampleResult& result) noexcept
        {
            result = {};
            HeapArray<UCHAR> frame(http2::Http2FrameHeaderLength + 8);
            if (!frame.IsValid()) {
                CaptureFrameSampleResult(result, STATUS_INSUFFICIENT_RESOURCES, 0, 0);
                return result.Status;
            }

            SIZE_T written = 0;
            NTSTATUS status = http2::Http2FrameCodec::EncodeGoAway(
                3,
                static_cast<ULONG>(http2::Http2ErrorCode::NoError),
                frame.Get(),
                frame.Count(),
                &written);

            http2::Http2FrameHeader header = {};
            ULONG lastStreamId = 0;
            ULONG errorCode = 0;
            if (NT_SUCCESS(status)) {
                status = ValidateFrameHeader(
                    frame.Get(),
                    written,
                    http2::Http2FrameType::GoAway,
                    0,
                    &header);
            }
            if (NT_SUCCESS(status)) {
                status = http2::Http2FrameCodec::DecodeGoAwayPayload(
                    frame.Get() + http2::Http2FrameHeaderLength,
                    header.Length,
                    &lastStreamId,
                    &errorCode);
            }
            if (NT_SUCCESS(status) &&
                (lastStreamId != 3 || errorCode != static_cast<ULONG>(http2::Http2ErrorCode::NoError))) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureFrameSampleResult(result, status, 1, written);
            return status;
        }

        NTSTATUS RunRstStreamFrameSample(_Out_ Http2VerbSampleResult& result) noexcept
        {
            result = {};
            HeapArray<UCHAR> frame(http2::Http2FrameHeaderLength + 4);
            if (!frame.IsValid()) {
                CaptureFrameSampleResult(result, STATUS_INSUFFICIENT_RESOURCES, 0, 0);
                return result.Status;
            }

            SIZE_T written = 0;
            NTSTATUS status = http2::Http2FrameCodec::EncodeRstStream(
                1,
                static_cast<ULONG>(http2::Http2ErrorCode::Cancel),
                frame.Get(),
                frame.Count(),
                &written);

            http2::Http2FrameHeader header = {};
            ULONG errorCode = 0;
            if (NT_SUCCESS(status)) {
                status = ValidateFrameHeader(
                    frame.Get(),
                    written,
                    http2::Http2FrameType::RstStream,
                    1,
                    &header);
            }
            if (NT_SUCCESS(status)) {
                status = http2::Http2FrameCodec::DecodeRstStreamPayload(
                    frame.Get() + http2::Http2FrameHeaderLength,
                    header.Length,
                    &errorCode);
            }
            if (NT_SUCCESS(status) && errorCode != static_cast<ULONG>(http2::Http2ErrorCode::Cancel)) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureFrameSampleResult(result, status, 1, written);
            return status;
        }

        NTSTATUS RunWindowUpdateFrameSample(_Out_ Http2VerbSampleResult& result) noexcept
        {
            result = {};
            HeapArray<UCHAR> frame(http2::Http2FrameHeaderLength + 4);
            if (!frame.IsValid()) {
                CaptureFrameSampleResult(result, STATUS_INSUFFICIENT_RESOURCES, 0, 0);
                return result.Status;
            }

            constexpr ULONG WindowIncrement = 32768;
            SIZE_T written = 0;
            NTSTATUS status = http2::Http2FrameCodec::EncodeWindowUpdate(
                0,
                WindowIncrement,
                frame.Get(),
                frame.Count(),
                &written);

            http2::Http2FrameHeader header = {};
            ULONG increment = 0;
            if (NT_SUCCESS(status)) {
                status = ValidateFrameHeader(
                    frame.Get(),
                    written,
                    http2::Http2FrameType::WindowUpdate,
                    0,
                    &header);
            }
            if (NT_SUCCESS(status)) {
                status = http2::Http2FrameCodec::DecodeWindowUpdatePayload(
                    frame.Get() + http2::Http2FrameHeaderLength,
                    header.Length,
                    &increment);
            }
            if (NT_SUCCESS(status) && increment != WindowIncrement) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureFrameSampleResult(result, status, 1, written);
            return status;
        }

        NTSTATUS RunContinuationFrameSample(_Out_ Http2VerbSampleResult& result) noexcept
        {
            result = {};
            static const UCHAR HeaderBlock[] = {
                0x88, 0x5f, 0x87, 0x49,
                0x7c, 0xa5, 0x8a, 0xe8
            };

            HeapArray<UCHAR> headers(http2::Http2FrameHeaderLength + 4);
            HeapArray<UCHAR> continuation(http2::Http2FrameHeaderLength + 4);
            if (!headers.IsValid() || !continuation.IsValid()) {
                CaptureFrameSampleResult(result, STATUS_INSUFFICIENT_RESOURCES, 0, 0);
                return result.Status;
            }

            SIZE_T headersWritten = 0;
            NTSTATUS status = http2::Http2FrameCodec::EncodeHeaders(
                1,
                HeaderBlock,
                4,
                false,
                false,
                headers.Get(),
                headers.Count(),
                &headersWritten);

            SIZE_T continuationWritten = 0;
            if (NT_SUCCESS(status)) {
                status = http2::Http2FrameCodec::EncodeContinuation(
                    1,
                    HeaderBlock + 4,
                    sizeof(HeaderBlock) - 4,
                    true,
                    continuation.Get(),
                    continuation.Count(),
                    &continuationWritten);
            }

            http2::Http2FrameHeader headersFrame = {};
            http2::Http2FrameHeader continuationFrame = {};
            if (NT_SUCCESS(status)) {
                status = ValidateFrameHeader(
                    headers.Get(),
                    headersWritten,
                    http2::Http2FrameType::Headers,
                    1,
                    &headersFrame);
            }
            if (NT_SUCCESS(status)) {
                status = ValidateFrameHeader(
                    continuation.Get(),
                    continuationWritten,
                    http2::Http2FrameType::Continuation,
                    1,
                    &continuationFrame);
            }
            if (NT_SUCCESS(status) &&
                ((headersFrame.Flags & http2::Http2FrameFlags::EndHeaders) != 0 ||
                    (continuationFrame.Flags & http2::Http2FrameFlags::EndHeaders) == 0 ||
                    headersFrame.Length + continuationFrame.Length != sizeof(HeaderBlock))) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureFrameSampleResult(result, status, 2, headersWritten + continuationWritten);
            return status;
        }
    }

    NTSTATUS RunHttp2VerbSamples(
        net::WskClient& wskClient,
        Http2VerbSampleResults* results) noexcept
    {
        return RunHttp2VerbSamples(wskClient, ExternalTrustStoreDefaultBundlePath, results);
    }

    NTSTATUS RunHttp2VerbSamples(
        net::WskClient& wskClient,
        const char* certificateBundlePath,
        Http2VerbSampleResults* results) noexcept
    {
        if (results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};

        ExternalTrustStore trustStore = {};
        NTSTATUS status = InitializeExternalTrustStore(
            trustStore,
            certificateBundlePath != nullptr ? certificateBundlePath : ExternalTrustStoreDefaultBundlePath);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = STATUS_SUCCESS;
        NTSTATUS sampleStatus = SendHttp2SampleRequest(
            wskClient,
            "HTTP2 GET",
            client::Http2TransportMode::TlsAlpn,
            http::HttpMethod::Get,
            http::MakeText("/httpbin/get"),
            nullptr,
            0,
            {},
            nullptr,
            results->Http2GetHttpBin);
        status = MergePublicSampleStatus(status, "HTTP2 GET", sampleStatus);

        const UCHAR postBody[] = "{\"source\":\"kernel-http\",\"method\":\"HTTP2 POST\"}";
        sampleStatus = SendHttp2SampleRequest(
            wskClient,
            "HTTP2 POST",
            client::Http2TransportMode::TlsAlpn,
            http::HttpMethod::Post,
            http::MakeText("/httpbin/post"),
            postBody,
            sizeof(postBody) - 1,
            http::MakeText("application/json"),
            nullptr,
            results->Http2PostHttpBin);
        status = MergePublicSampleStatus(status, "HTTP2 POST", sampleStatus);

        sampleStatus = SendHttp2SampleRequest(
            wskClient,
            "HTTP2 GET external-trust",
            client::Http2TransportMode::TlsAlpn,
            http::HttpMethod::Get,
            http::MakeText("/httpbin/get"),
            nullptr,
            0,
            {},
            &trustStore.Store,
            results->Http2GetHttpBinExternalTrust);
        status = MergePublicSampleStatus(status, "HTTP2 GET external-trust", sampleStatus);

        sampleStatus = SendHttp2SampleRequest(
            wskClient,
            "HTTP2 POST external-trust",
            client::Http2TransportMode::TlsAlpn,
            http::HttpMethod::Post,
            http::MakeText("/httpbin/post"),
            postBody,
            sizeof(postBody) - 1,
            http::MakeText("application/json"),
            &trustStore.Store,
            results->Http2PostHttpBinExternalTrust);
        status = MergePublicSampleStatus(status, "HTTP2 POST external-trust", sampleStatus);

        sampleStatus = SendHttp2SampleRequest(
            wskClient,
            "H2C prior knowledge GET",
            client::Http2TransportMode::H2cPriorKnowledge,
            http::HttpMethod::Get,
            http::MakeText("/httpbin/get"),
            nullptr,
            0,
            {},
            nullptr,
            results->H2cPriorKnowledgeGet);
        status = MergePublicSampleStatus(status, "H2C prior knowledge GET", sampleStatus);

        sampleStatus = SendHttp2SampleRequest(
            wskClient,
            "H2C upgrade GET",
            client::Http2TransportMode::H2cUpgrade,
            http::HttpMethod::Get,
            http::MakeText("/httpbin/get"),
            nullptr,
            0,
            {},
            nullptr,
            results->H2cUpgradeGet);
        status = MergePublicSampleStatus(status, "H2C upgrade GET", sampleStatus);

        status = MergeSampleStatus(status, RunGoAwayFrameSample(results->GoAwayFrame));
        status = MergeSampleStatus(status, RunRstStreamFrameSample(results->RstStreamFrame));
        status = MergeSampleStatus(status, RunWindowUpdateFrameSample(results->WindowUpdateFrame));
        status = MergeSampleStatus(status, RunContinuationFrameSample(results->ContinuationFrame));

        ResetExternalTrustStore(trustStore);
        return status;
    }
}
}
