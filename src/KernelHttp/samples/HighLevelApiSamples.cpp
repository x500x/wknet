#include "samples/HighLevelApiSamples.h"

#include "tls/CertificateStore.h"

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr const char* UserAgentName = "User-Agent";
        constexpr const char* UserAgentValue = "KernelHttp/0.1";
        constexpr const char* AcceptName = "Accept";
        constexpr const char* AcceptValue = "*/*";
        constexpr const char* AcceptEncodingName = "Accept-Encoding";
        constexpr const char* AcceptEncodingValue = "identity";
        constexpr const char* ContentTypeName = "Content-Type";
        constexpr const char* JsonContentType = "application/json";
        constexpr const char* H2Alpn = "h2";

        constexpr const char* HttpGetUrl = "http://httpbin.org/get";
        constexpr const char* HttpPostUrl = "http://httpbin.org/post";
        constexpr const char* HttpPutUrl = "http://httpbin.org/put";
        constexpr const char* HttpPatchUrl = "http://httpbin.org/patch";
        constexpr const char* HttpDeleteUrl = "http://httpbin.org/delete";
        constexpr const char* HttpHeadUrl = "http://httpbin.org/get";
        constexpr const char* HttpOptionsUrl = "http://httpbin.org/";
        constexpr const char* HttpsGetUrl = "https://nghttp2.org/httpbin/get";
        constexpr const char* HttpsPostUrl = "https://nghttp2.org/httpbin/post";
        constexpr const char* HttpsPutUrl = "https://nghttp2.org/httpbin/put";
        constexpr const char* HttpsPatchUrl = "https://nghttp2.org/httpbin/patch";
        constexpr const char* HttpsDeleteUrl = "https://nghttp2.org/httpbin/delete";
        constexpr const char* WebSocketEchoUrl = "wss://echo.websocket.org/";
        constexpr const char* LocalHttpsUrl = "https://127.0.0.1:8443/sample_response_body.txt";
        constexpr const char* LocalHttpsHostName = "localhost";
        constexpr SIZE_T LocalHttpsHostNameLength = sizeof("localhost") - 1;
        constexpr const char* NgHttp2TlsServerName = "nghttp2.org";
        constexpr SIZE_T NgHttp2TlsServerNameLength = sizeof("nghttp2.org") - 1;
        constexpr const char* WebSocketEchoTlsServerName = "echo.websocket.org";
        constexpr SIZE_T WebSocketEchoTlsServerNameLength = sizeof("echo.websocket.org") - 1;

        constexpr UCHAR WebSocketEchoLeafSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x63, 0x87, 0xC0, 0xAC, 0xD8, 0x7F, 0x2A, 0xAF,
            0xA8, 0x1A, 0x1A, 0x08, 0xF4, 0xBC, 0x44, 0xDB,
            0x43, 0x84, 0x59, 0xC6, 0xFC, 0x0D, 0x11, 0x8E,
            0x59, 0xE9, 0x58, 0xF8, 0x02, 0xF4, 0x0C, 0xBE
        };
        constexpr UCHAR WebSocketEchoLetsEncryptE8SpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x88, 0x5B, 0xF0, 0x57, 0x22, 0x52, 0xC6, 0x74,
            0x1D, 0xC9, 0xA5, 0x2F, 0x50, 0x44, 0x48, 0x7F,
            0xEF, 0x2A, 0x93, 0xB8, 0x11, 0xCD, 0xED, 0xFA,
            0xD7, 0x62, 0x4C, 0xC2, 0x83, 0xB7, 0xCD, 0xD5
        };
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
        constexpr UCHAR LocalHttpsLeafSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x81, 0xB9, 0xD8, 0x37, 0x08, 0x5E, 0x67, 0x1D,
            0x85, 0xA5, 0x16, 0xBC, 0xDE, 0x17, 0x07, 0xCA,
            0x65, 0x5C, 0x2D, 0xDB, 0x01, 0xAC, 0xC1, 0x67,
            0xE9, 0xE6, 0xAC, 0xF4, 0xC8, 0x96, 0xB5, 0x71
        };

        _Must_inspect_result_
        SIZE_T LiteralLength(_In_z_ const char* value) noexcept
        {
            SIZE_T length = 0;
            if (value == nullptr) {
                return 0;
            }

            while (value[length] != '\0') {
                ++length;
            }

            return length;
        }

        _Must_inspect_result_
        NTSTATUS MergeSampleStatus(NTSTATUS current, NTSTATUS next) noexcept
        {
            return NT_SUCCESS(current) ? next : current;
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

        _Must_inspect_result_
        NTSTATUS InitializeNgHttp2CertificateStore(
            _Out_ tls::CertificateStore& certificateStore,
            _Out_ tls::CertificateTrustAnchor& anchor,
            _Out_ tls::CertificatePin& pin) noexcept
        {
            return InitializePinnedCertificateStore(
                NgHttp2LetsEncryptE8SpkiSha256,
                sizeof(NgHttp2LetsEncryptE8SpkiSha256),
                NgHttp2LeafSpkiSha256,
                sizeof(NgHttp2LeafSpkiSha256),
                NgHttp2TlsServerName,
                NgHttp2TlsServerNameLength,
                certificateStore,
                anchor,
                pin);
        }

        _Must_inspect_result_
        NTSTATUS InitializeWebSocketEchoCertificateStore(
            _Out_ tls::CertificateStore& certificateStore,
            _Out_ tls::CertificateTrustAnchor& anchor,
            _Out_ tls::CertificatePin& pin) noexcept
        {
            return InitializePinnedCertificateStore(
                WebSocketEchoLetsEncryptE8SpkiSha256,
                sizeof(WebSocketEchoLetsEncryptE8SpkiSha256),
                WebSocketEchoLeafSpkiSha256,
                sizeof(WebSocketEchoLeafSpkiSha256),
                WebSocketEchoTlsServerName,
                WebSocketEchoTlsServerNameLength,
                certificateStore,
                anchor,
                pin);
        }

        _Must_inspect_result_
        NTSTATUS InitializeLocalHttpsCertificateStore(
            _Out_ tls::CertificateStore& certificateStore,
            _Out_ tls::CertificateTrustAnchor& anchor,
            _Out_ tls::CertificatePin& pin) noexcept
        {
            return InitializePinnedCertificateStore(
                LocalHttpsLeafSpkiSha256,
                sizeof(LocalHttpsLeafSpkiSha256),
                LocalHttpsLeafSpkiSha256,
                sizeof(LocalHttpsLeafSpkiSha256),
                LocalHttpsHostName,
                LocalHttpsHostNameLength,
                certificateStore,
                anchor,
                pin);
        }

        _Must_inspect_result_
        NTSTATUS SetHeaderLiteral(
            _In_ api::KH_REQUEST request,
            _In_z_ const char* name,
            _In_z_ const char* value) noexcept
        {
            return api::KhHttpRequestSetHeader(
                request,
                name,
                LiteralLength(name),
                value,
                LiteralLength(value));
        }

        _Must_inspect_result_
        NTSTATUS SetCommonHeaders(_In_ api::KH_REQUEST request) noexcept
        {
            NTSTATUS status = SetHeaderLiteral(request, UserAgentName, UserAgentValue);
            if (NT_SUCCESS(status)) {
                status = SetHeaderLiteral(request, AcceptName, AcceptValue);
            }
            if (NT_SUCCESS(status)) {
                status = SetHeaderLiteral(request, AcceptEncodingName, AcceptEncodingValue);
            }
            return status;
        }

        void LogHttpSampleResult(_In_z_ const char* sampleName, const HighLevelApiSampleResult& result) noexcept
        {
            if (NT_SUCCESS(result.Status)) {
                kprintf(
                    "[high-level %s] status=%u bodyLength=%Iu\r\n",
                    sampleName,
                    result.StatusCode,
                    result.BodyLength);
            }
            else {
                kprintf(
                    "[high-level %s] failed: 0x%08X status=%u bodyLength=%Iu\r\n",
                    sampleName,
                    static_cast<ULONG>(result.Status),
                    result.StatusCode,
                    result.BodyLength);
            }
        }

        _Must_inspect_result_
        NTSTATUS RunHttpSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _In_opt_ const api::KhTlsOptions* tlsOptions,
            api::KhConnectionPolicy connectionPolicy,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (session == nullptr || sampleName == nullptr || url == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};

            api::KH_REQUEST request = nullptr;
            NTSTATUS status = api::KhHttpRequestCreate(session, &request);
            if (NT_SUCCESS(status)) {
                status = api::KhHttpRequestSetUrl(request, url, LiteralLength(url));
            }
            if (NT_SUCCESS(status)) {
                status = api::KhHttpRequestSetMethod(request, method);
            }
            if (NT_SUCCESS(status)) {
                status = SetCommonHeaders(request);
            }
            if (NT_SUCCESS(status) && bodyLength != 0) {
                status = SetHeaderLiteral(request, ContentTypeName, JsonContentType);
            }
            if (NT_SUCCESS(status) && (body != nullptr || bodyLength != 0)) {
                status = api::KhHttpRequestSetBody(request, body, bodyLength);
            }
            if (NT_SUCCESS(status) && tlsOptions != nullptr) {
                status = api::KhHttpRequestSetTlsOptions(request, tlsOptions);
            }
            if (NT_SUCCESS(status) && connectionPolicy != api::KhConnectionPolicy::ReuseOrCreate) {
                status = api::KhHttpRequestSetConnectionPolicy(request, connectionPolicy);
            }

            api::KH_RESPONSE response = nullptr;
            if (NT_SUCCESS(status)) {
                status = api::KhHttpSendSync(session, request, nullptr, &response);
            }

            if (NT_SUCCESS(status)) {
                api::KhResponseView view = {};
                status = api::KhResponseGetView(response, &view);
                if (NT_SUCCESS(status)) {
                    result->StatusCode = view.StatusCode;
                    result->BodyLength = view.BodyLength;
                }
            }

            api::KhResponseRelease(response);
            api::KhHttpRequestRelease(request);
            result->Status = status;
            LogHttpSampleResult(sampleName, *result);
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunVerifiedNgHttp2Sample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            bool forceHttp2Alpn,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            tls::CertificateTrustAnchor anchor = {};
            tls::CertificatePin pin = {};
            tls::CertificateStore certificateStore;
            NTSTATUS status = InitializeNgHttp2CertificateStore(certificateStore, anchor, pin);
            if (!NT_SUCCESS(status)) {
                if (result != nullptr) {
                    *result = {};
                    result->Status = status;
                }
                return status;
            }

            api::KhTlsOptions tlsOptions = {};
            tlsOptions.CertificateStore = &certificateStore;
            tlsOptions.CertificatePolicy = api::KhCertificatePolicy::Verify;
            if (forceHttp2Alpn) {
                tlsOptions.Alpn = H2Alpn;
                tlsOptions.AlpnLength = sizeof("h2") - 1;
            }

            return RunHttpSample(
                session,
                sampleName,
                method,
                url,
                body,
                bodyLength,
                &tlsOptions,
                api::KhConnectionPolicy::ReuseOrCreate,
                result);
        }

        _Must_inspect_result_
        NTSTATUS RunNoVerifyHttpsSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            api::KhTlsOptions tlsOptions = {};
            tlsOptions.CertificatePolicy = api::KhCertificatePolicy::NoVerify;
            return RunHttpSample(
                session,
                sampleName,
                method,
                url,
                body,
                bodyLength,
                &tlsOptions,
                api::KhConnectionPolicy::ForceNew,
                result);
        }

        _Must_inspect_result_
        NTSTATUS RunWebSocketEchoSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            bool verifyCertificate,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (session == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};

            tls::CertificateTrustAnchor anchor = {};
            tls::CertificatePin pin = {};
            tls::CertificateStore certificateStore;
            api::KhTlsOptions tlsOptions = {};
            if (verifyCertificate) {
                NTSTATUS status = InitializeWebSocketEchoCertificateStore(certificateStore, anchor, pin);
                if (!NT_SUCCESS(status)) {
                    result->Status = status;
                    return status;
                }
                tlsOptions.CertificateStore = &certificateStore;
                tlsOptions.CertificatePolicy = api::KhCertificatePolicy::Verify;
            }
            else {
                tlsOptions.CertificatePolicy = api::KhCertificatePolicy::NoVerify;
            }

            api::KhWebSocketConnectOptions connectOptions = {};
            connectOptions.Url = WebSocketEchoUrl;
            connectOptions.UrlLength = sizeof("wss://echo.websocket.org/") - 1;
            connectOptions.Tls = tlsOptions;
            connectOptions.MaxMessageBytes = 4096;
            connectOptions.AutoReplyPing = true;

            api::KH_WEBSOCKET websocket = nullptr;
            NTSTATUS status = api::KhWebSocketConnectSync(session, &connectOptions, &websocket);

            const char message[] = "kernel-http high-level websocket echo";
            if (NT_SUCCESS(status)) {
                status = api::KhWebSocketSendTextSync(websocket, message, sizeof(message) - 1, nullptr);
            }

            api::KhWebSocketMessage received = {};
            if (NT_SUCCESS(status)) {
                status = api::KhWebSocketReceiveSync(websocket, nullptr, &received);
            }

            if (NT_SUCCESS(status)) {
                result->BodyLength = received.DataLength;
                if (received.Type != api::KhWebSocketMessageType::Text ||
                    received.Data == nullptr ||
                    received.DataLength != sizeof(message) - 1 ||
                    RtlCompareMemory(received.Data, message, sizeof(message) - 1) != sizeof(message) - 1) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            const NTSTATUS closeStatus = api::KhWebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(closeStatus);

            result->Status = status;
            LogHttpSampleResult(sampleName, *result);
            return status;
        }
    }

    NTSTATUS RunHighLevelLocalHttpsSmokeSample(
        api::KH_SESSION session,
        HighLevelApiSampleResult* result) noexcept
    {
        tls::CertificateTrustAnchor anchor = {};
        tls::CertificatePin pin = {};
        tls::CertificateStore certificateStore;
        NTSTATUS status = InitializeLocalHttpsCertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            if (result != nullptr) {
                *result = {};
                result->Status = status;
            }
            return status;
        }

        api::KhTlsOptions tlsOptions = {};
        tlsOptions.CertificateStore = &certificateStore;
        tlsOptions.CertificatePolicy = api::KhCertificatePolicy::Verify;
        tlsOptions.ServerName = LocalHttpsHostName;
        tlsOptions.ServerNameLength = LocalHttpsHostNameLength;

        return RunHttpSample(
            session,
            "LOCAL HTTPS",
            api::KhHttpMethod::Get,
            LocalHttpsUrl,
            nullptr,
            0,
            &tlsOptions,
            api::KhConnectionPolicy::NoPool,
            result);
    }

    NTSTATUS RunHighLevelApiSamples(
        api::KH_SESSION session,
        HighLevelApiSampleResults* results) noexcept
    {
        if (session == nullptr || results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};

        const UCHAR postBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"POST\"}";
        NTSTATUS status = RunHttpSample(
            session,
            "HTTP GET",
            api::KhHttpMethod::Get,
            HttpGetUrl,
            nullptr,
            0,
            nullptr,
            api::KhConnectionPolicy::ReuseOrCreate,
            &results->HttpGet);

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                "HTTP POST",
                api::KhHttpMethod::Post,
                HttpPostUrl,
                postBody,
                sizeof(postBody) - 1,
                nullptr,
                api::KhConnectionPolicy::ReuseOrCreate,
                &results->HttpPost));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                "HTTPS TLS options",
                api::KhHttpMethod::Get,
                HttpsGetUrl,
                nullptr,
                0,
                false,
                &results->HttpsTlsOptions));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                "HTTP/2 ALPN",
                api::KhHttpMethod::Get,
                HttpsGetUrl,
                nullptr,
                0,
                true,
                &results->Http2Alpn));

        status = MergeSampleStatus(
            status,
            RunWebSocketEchoSample(
                session,
                "WEBSOCKET ECHO",
                true,
                &results->WebSocketEcho));

        return status;
    }

    NTSTATUS RunHighLevelApiTestDriverSamples(
        api::KH_SESSION session,
        HighLevelApiSampleResults* results) noexcept
    {
        if (session == nullptr || results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = RunHighLevelApiSamples(session, results);

        const UCHAR putBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"PUT\"}";
        const UCHAR patchBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"PATCH\"}";
        const UCHAR deleteBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"DELETE\"}";
        const UCHAR httpsPostBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS POST\"}";
        const UCHAR httpsPutBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS PUT\"}";
        const UCHAR httpsPatchBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS PATCH\"}";
        const UCHAR httpsDeleteBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS DELETE\"}";

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                "HTTP PUT",
                api::KhHttpMethod::Put,
                HttpPutUrl,
                putBody,
                sizeof(putBody) - 1,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                &results->HttpPut));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                "HTTP PATCH",
                api::KhHttpMethod::Patch,
                HttpPatchUrl,
                patchBody,
                sizeof(patchBody) - 1,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                &results->HttpPatch));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                "HTTP DELETE",
                api::KhHttpMethod::Delete,
                HttpDeleteUrl,
                deleteBody,
                sizeof(deleteBody) - 1,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                &results->HttpDelete));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                "HTTP HEAD",
                api::KhHttpMethod::Head,
                HttpHeadUrl,
                nullptr,
                0,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                &results->HttpHead));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                "HTTP OPTIONS",
                api::KhHttpMethod::Options,
                HttpOptionsUrl,
                nullptr,
                0,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                &results->HttpOptions));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                "HTTPS POST",
                api::KhHttpMethod::Post,
                HttpsPostUrl,
                httpsPostBody,
                sizeof(httpsPostBody) - 1,
                false,
                &results->HttpsPost));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                "HTTPS PUT",
                api::KhHttpMethod::Put,
                HttpsPutUrl,
                httpsPutBody,
                sizeof(httpsPutBody) - 1,
                false,
                &results->HttpsPut));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                "HTTPS PATCH",
                api::KhHttpMethod::Patch,
                HttpsPatchUrl,
                httpsPatchBody,
                sizeof(httpsPatchBody) - 1,
                false,
                &results->HttpsPatch));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                "HTTPS DELETE",
                api::KhHttpMethod::Delete,
                HttpsDeleteUrl,
                httpsDeleteBody,
                sizeof(httpsDeleteBody) - 1,
                false,
                &results->HttpsDelete));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                "HTTPS no-verify",
                api::KhHttpMethod::Get,
                HttpsGetUrl,
                nullptr,
                0,
                &results->HttpsNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                "HTTPS POST no-verify",
                api::KhHttpMethod::Post,
                HttpsPostUrl,
                httpsPostBody,
                sizeof(httpsPostBody) - 1,
                &results->HttpsPostNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                "HTTPS PUT no-verify",
                api::KhHttpMethod::Put,
                HttpsPutUrl,
                httpsPutBody,
                sizeof(httpsPutBody) - 1,
                &results->HttpsPutNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                "HTTPS PATCH no-verify",
                api::KhHttpMethod::Patch,
                HttpsPatchUrl,
                httpsPatchBody,
                sizeof(httpsPatchBody) - 1,
                &results->HttpsPatchNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                "HTTPS DELETE no-verify",
                api::KhHttpMethod::Delete,
                HttpsDeleteUrl,
                httpsDeleteBody,
                sizeof(httpsDeleteBody) - 1,
                &results->HttpsDeleteNoVerify));

        status = MergeSampleStatus(
            status,
            RunWebSocketEchoSample(
                session,
                "WEBSOCKET ECHO no-verify",
                false,
                &results->WebSocketEchoNoVerify));

#if defined(KERNEL_HTTP_ENABLE_LOCAL_HTTPS_SAMPLE) || defined(KERNEL_HTTP_LOCAL_HTTPS_SMOKE_ONLY)
        status = MergeSampleStatus(
            status,
            RunHighLevelLocalHttpsSmokeSample(session, &results->LocalHttpsSmoke));
#endif

        return status;
    }
}
}
