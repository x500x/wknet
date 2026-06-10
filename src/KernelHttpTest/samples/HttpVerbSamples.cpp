#include "samples/HttpVerbSamples.h"

#include <KernelHttp/KernelHttpConfig.h>
#include <KernelHttp/client/HttpClient.h>
#include <KernelHttp/client/HttpsClient.h>
#include <KernelHttp/client/WebSocketClient.h>
#include <KernelHttpTest/SampleStatus.h>

#include "samples/ExternalTrustStore.h"

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
        constexpr const wchar_t* NgHttp2ServerName = L"nghttp2.org";
        constexpr const wchar_t* NgHttp2ServiceName = L"80";
        constexpr const char* NgHttp2HostName = "nghttp2.org";
        constexpr SIZE_T NgHttp2HostNameLength = sizeof("nghttp2.org") - 1;
        constexpr const wchar_t* HttpBinDevServerName = L"httpbin.dev";
        constexpr const wchar_t* HttpBinDevHttpsServiceName = L"443";
        constexpr const char* HttpBinDevTlsServerName = "httpbin.dev";
        constexpr SIZE_T HttpBinDevTlsServerNameLength = sizeof("httpbin.dev") - 1;
        constexpr const char* HttpBinDevHostName = "httpbin.dev";
        constexpr SIZE_T HttpBinDevHostNameLength = sizeof("httpbin.dev") - 1;
        constexpr const wchar_t* HttpBunServerName = L"httpbun.com";
        constexpr const wchar_t* HttpBunServiceName = L"80";
        constexpr const char* HttpBunHostName = "httpbun.com";
        constexpr const wchar_t* WebSocketEchoServerName = L"ws.postman-echo.com";
        constexpr const wchar_t* WebSocketEchoServiceName = L"443";
        constexpr const char* WebSocketEchoTlsServerName = "ws.postman-echo.com";
        constexpr SIZE_T WebSocketEchoTlsServerNameLength = sizeof("ws.postman-echo.com") - 1;
        constexpr const char* WebSocketEchoHostName = "ws.postman-echo.com";
        constexpr SIZE_T WebSocketEchoHostNameLength = sizeof("ws.postman-echo.com") - 1;
        constexpr UCHAR WebSocketEchoLeafSpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0xE2, 0x65, 0x15, 0x6D, 0x50, 0x18, 0x34, 0xDD,
            0x6F, 0xF4, 0x19, 0xE7, 0x13, 0x85, 0x26, 0x34,
            0xB5, 0x9F, 0xA2, 0x55, 0x0F, 0xC2, 0x3E, 0x31,
            0xF3, 0xB3, 0xEB, 0x77, 0x2E, 0x63, 0x67, 0x24
        };
        constexpr UCHAR WebSocketEchoAmazonRsaM04SpkiSha256[tls::CertificateSha256ThumbprintLength] = {
            0x1B, 0xD2, 0xCD, 0x34, 0x0A, 0xA5, 0xF3, 0xDE,
            0xDE, 0x81, 0x8B, 0x1A, 0x6D, 0xAB, 0x21, 0x93,
            0x35, 0x02, 0x4C, 0x42, 0x64, 0x58, 0x1C, 0xE0,
            0xA0, 0x4B, 0x64, 0xF1, 0x7F, 0xFA, 0xEF, 0xC7
        };
        struct SampleIoBuffers final
        {
            char Request[SampleRequestBufferLength] = {};
            char Response[SampleResponseBufferLength] = {};
            char DecodedBody[SampleDecodedBodyBufferLength] = {};
            char ScratchBody[SampleScratchBodyBufferLength] = {};
            http::HttpHeader Headers[SampleHeaderCapacity] = {};
        };

        struct WebSocketSampleIoBuffers final
        {
            char Request[SampleRequestBufferLength] = {};
            char Response[SampleResponseBufferLength] = {};
            UCHAR Frame[SampleResponseBufferLength] = {};
            UCHAR Payload[SampleDecodedBodyBufferLength] = {};
            http::HttpHeader Headers[SampleHeaderCapacity] = {};
        };

        http::HttpText FindHeaderValue(
            _In_reads_(headerCount) const http::HttpHeader* headers,
            SIZE_T headerCount,
            http::HttpText name) noexcept
        {
            if (headers == nullptr) {
                return {};
            }

            for (SIZE_T index = 0; index < headerCount; ++index) {
                if (http::TextEqualsIgnoreCase(headers[index].Name, name)) {
                    return headers[index].Value;
                }
            }

            return {};
        }

        bool RequestPrefersHttp2(_In_ const http::HttpRequestBuildOptions& request) noexcept
        {
            if (request.Host.Data == nullptr) {
                return false;
            }

            return (request.Host.Length == NgHttp2HostNameLength &&
                http::TextEqualsIgnoreCase(request.Host, http::MakeText(NgHttp2HostName))) ||
                (request.Host.Length == HttpBinDevHostNameLength &&
                    http::TextEqualsIgnoreCase(request.Host, http::MakeText(HttpBinDevHostName)));
        }

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

            kprintf("[body]\r\n%.*s\r\n", static_cast<int>(bodyLength), body);
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

            HeapObject<SampleIoBuffers> buffers;
            if (!buffers.IsValid()) {
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
            HeapObject<client::HttpClient> client;
            if (!client.IsValid()) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            const http::HttpText acceptEncoding = FindHeaderValue(
                request.ExtraHeaders,
                request.ExtraHeaderCount,
                http::MakeText("Accept-Encoding"));

            LogRequestStart(methodName, request.Path, acceptEncoding);
            result.Status = client->SendRequest(wskClient, options, responseBuffers, response);
            if (NT_SUCCESS(result.Status)) {
                result.StatusCode = response.StatusCode;
                result.HeaderCount = response.HeaderCount;
                result.BodyLength = response.BodyLength;
                LogResponse(methodName, response);
            }
            else {
                kprintf("[%s] request failed: 0x%08X\r\n", methodName, static_cast<ULONG>(result.Status));
            }

            return result.Status;
        }

        _Must_inspect_result_
        NTSTATUS SendHttpsSampleRequestWithTlsVersion(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const wchar_t* serverName,
            _In_ const wchar_t* serviceName,
            _In_ const char* tlsServerName,
            SIZE_T tlsServerNameLength,
            _In_ const char* methodName,
            _In_ const http::HttpRequestBuildOptions& request,
            bool responseBodyForbidden,
            _In_opt_ const tls::CertificateStore* certificateStore,
            bool verifyCertificate,
            tls::TlsProtocol minimumProtocol,
            tls::TlsProtocol maximumProtocol,
            net::WskAddressFamily addressFamily,
            bool preferHttp2,
            _Out_ HttpVerbSampleResult& result) noexcept;

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
            _In_opt_ const tls::CertificateStore* certificateStore,
            bool verifyCertificate,
            _Out_ HttpVerbSampleResult& result) noexcept
        {
            return SendHttpsSampleRequestWithTlsVersion(
                wskClient,
                serverName,
                serviceName,
                tlsServerName,
                tlsServerNameLength,
                methodName,
                request,
                responseBodyForbidden,
                certificateStore,
                verifyCertificate,
                tls::TlsProtocol::Tls12,
                tls::TlsProtocol::Tls13,
                net::WskAddressFamily::Any,
                RequestPrefersHttp2(request),
                result);
        }

        _Must_inspect_result_
        NTSTATUS SendHttpsSampleRequestWithTlsVersion(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const wchar_t* serverName,
            _In_ const wchar_t* serviceName,
            _In_ const char* tlsServerName,
            SIZE_T tlsServerNameLength,
            _In_ const char* methodName,
            _In_ const http::HttpRequestBuildOptions& request,
            bool responseBodyForbidden,
            _In_opt_ const tls::CertificateStore* certificateStore,
            bool verifyCertificate,
            tls::TlsProtocol minimumProtocol,
            tls::TlsProtocol maximumProtocol,
            net::WskAddressFamily addressFamily,
            bool preferHttp2,
            _Out_ HttpVerbSampleResult& result) noexcept
        {
            result = {};

            HeapObject<SampleIoBuffers> buffers;
            if (!buffers.IsValid()) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            HeapArray<SOCKADDR_STORAGE> remoteAddresses(net::WskMaxResolvedAddresses);
            if (!remoteAddresses.IsValid()) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            SIZE_T remoteAddressCount = 0;
            result.Status = wskClient.ResolveAll(
                serverName,
                serviceName,
                remoteAddresses.Get(),
                net::WskMaxResolvedAddresses,
                &remoteAddressCount,
                addressFamily);
            if (!NT_SUCCESS(result.Status)) {
                kprintf("[%s] HTTPS resolve failed: 0x%08X\r\n",
                    methodName,
                    static_cast<ULONG>(result.Status));
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
            options.ServerName = tlsServerName;
            options.ServerNameLength = tlsServerNameLength;
            options.Request = request;
            options.ResponseBodyForbidden = responseBodyForbidden;
            options.CertificateStore = certificateStore;
            options.VerifyCertificate = verifyCertificate;
            options.MinimumTlsProtocol = minimumProtocol;
            options.MaximumTlsProtocol = maximumProtocol;
            options.PreferHttp2 = preferHttp2;

            http::HttpResponse response = {};
            HeapObject<client::HttpsClient> client;
            if (!client.IsValid()) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            const http::HttpText acceptEncoding = FindHeaderValue(
                request.ExtraHeaders,
                request.ExtraHeaderCount,
                http::MakeText("Accept-Encoding"));

            kprintf("[%s] HTTPS verify=%s\r\n", methodName, verifyCertificate ? "on" : "off");
            LogRequestStart(methodName, request.Path, acceptEncoding);

            NTSTATUS lastStatus = STATUS_NOT_FOUND;
            for (SIZE_T addressIndex = 0; addressIndex < remoteAddressCount; ++addressIndex) {
                options.RemoteAddress = reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]);
                response = {};

                result.Status = client->SendRequest(wskClient, options, responseBuffers, response);
                if (NT_SUCCESS(result.Status)) {
                    result.StatusCode = response.StatusCode;
                    result.HeaderCount = response.HeaderCount;
                    result.BodyLength = response.BodyLength;
                    LogResponse(methodName, response);
                    return result.Status;
                }

                lastStatus = result.Status;
                kprintf("[%s] HTTPS address attempt failed: 0x%08X index=%Iu family=%u\r\n",
                    methodName,
                    static_cast<ULONG>(result.Status),
                    addressIndex,
                    static_cast<unsigned>(remoteAddresses[addressIndex].ss_family));
            }

            result.Status = lastStatus;
            kprintf("[%s] HTTPS request failed: 0x%08X\r\n", methodName, static_cast<ULONG>(result.Status));
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
                kprintf("[%s] 公网端点环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(next));
                return current;
            }

            return MergeSampleStatus(current, next);
        }

        NTSTATUS MergePublicConnectSampleStatus(
            NTSTATUS current,
            _In_z_ const char* sampleName,
            NTSTATUS next,
            const HttpVerbSampleResult& result) noexcept
        {
            if (!NT_SUCCESS(next) &&
                result.StatusCode == 0 &&
                IsPublicEndpointDiagnosticStatus(next)) {
                kprintf("[%s] 公网端点连接环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(next));
                return current;
            }

            return MergeSampleStatus(current, next);
        }

        _Must_inspect_result_
        NTSTATUS SendHttpBinDevHttpsGet(
            _Inout_ net::WskClient& wskClient,
            _In_z_ const char* sampleName,
            _In_ http::HttpText path,
            _In_ http::HttpText acceptEncoding,
            _In_opt_ const tls::CertificateStore* certificateStore,
            _Out_ HttpVerbSampleResult& result) noexcept
        {
            const http::HttpHeader headers[] = {
                { http::MakeText("Accept"), http::MakeText("*/*") },
                { http::MakeText("Accept-Encoding"), acceptEncoding }
            };

            http::HttpRequestBuildOptions request = {};
            request.Method = http::HttpMethod::Get;
            request.Path = path;
            request.Host = http::MakeText(HttpBinDevHostName);
            request.UserAgent = http::MakeText("KernelHttp/0.1");
            request.Connection = http::HttpConnectionDirective::Close;
            request.ExtraHeaders = headers;
            request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

            return SendHttpsSampleRequest(
                wskClient,
                HttpBinDevServerName,
                HttpBinDevHttpsServiceName,
                HttpBinDevTlsServerName,
                HttpBinDevTlsServerNameLength,
                sampleName,
                request,
                false,
                certificateStore,
                true,
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

        _Must_inspect_result_
        NTSTATUS InitializeWebSocketEchoCertificateStore(
            _Out_ tls::CertificateStore& certificateStore,
            _Out_ tls::CertificateTrustAnchor& anchor,
            _Out_ tls::CertificatePin& pin) noexcept
        {
            return InitializePinnedCertificateStore(
                WebSocketEchoAmazonRsaM04SpkiSha256,
                sizeof(WebSocketEchoAmazonRsaM04SpkiSha256),
                WebSocketEchoLeafSpkiSha256,
                sizeof(WebSocketEchoLeafSpkiSha256),
                WebSocketEchoTlsServerName,
                WebSocketEchoTlsServerNameLength,
                certificateStore,
                anchor,
                pin);
        }
    }

    NTSTATUS RunWebSocketEchoSampleInternal(
        net::WskClient& wskClient,
        _In_z_ const char* sampleName,
        bool verifyCertificate,
        _In_opt_ const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
#if !defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(sampleName);
#endif
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};

        HeapObject<WebSocketSampleIoBuffers> buffers;
        if (!buffers.IsValid()) {
            result->Status = STATUS_INSUFFICIENT_RESOURCES;
            return result->Status;
        }

        client::WebSocketIoBuffers io = {};
        io.RequestBuffer = buffers->Request;
        io.RequestBufferLength = sizeof(buffers->Request);
        io.ResponseBuffer = buffers->Response;
        io.ResponseBufferLength = sizeof(buffers->Response);
        io.FrameBuffer = buffers->Frame;
        io.FrameBufferLength = sizeof(buffers->Frame);
        io.PayloadBuffer = buffers->Payload;
        io.PayloadBufferLength = sizeof(buffers->Payload);
        io.Headers = buffers->Headers;
        io.HeaderCapacity = SampleHeaderCapacity;

        client::WebSocketConnectOptions options = {};
        options.ServerName = WebSocketEchoServerName;
        options.ServiceName = WebSocketEchoServiceName;
        options.TlsServerName = WebSocketEchoTlsServerName;
        options.TlsServerNameLength = WebSocketEchoTlsServerNameLength;
        options.Host = WebSocketEchoHostName;
        options.HostLength = WebSocketEchoHostNameLength;
        options.Path = "/raw";
        options.PathLength = sizeof("/raw") - 1;
        options.CertificateStore = certificateStore;
        options.MinimumTlsProtocol = tls::TlsProtocol::Tls12;
        options.MaximumTlsProtocol = tls::TlsProtocol::Tls12;
        options.UseTls = true;
        options.VerifyCertificate = verifyCertificate;

        HeapObject<client::WebSocketClient> webSocket;
        if (!webSocket.IsValid()) {
            result->Status = STATUS_INSUFFICIENT_RESOURCES;
            return result->Status;
        }

        USHORT handshakeStatusCode = 0;
        NTSTATUS status = webSocket->Connect(wskClient, options, io, &handshakeStatusCode);
        result->StatusCode = handshakeStatusCode;

        if (NT_SUCCESS(status)) {
            const char message[] = "kernel-http websocket echo";
            client::WebSocketEchoResult echo = {};

            kprintf("[%s] send bytes=%Iu data=%.*s\r\n",
                sampleName,
                sizeof(message) - 1,
                static_cast<int>(sizeof(message) - 1),
                message);

            status = webSocket->SendTextAndReceiveEcho(message, sizeof(message) - 1, io, echo);
            if (NT_SUCCESS(status)) {
                result->HeaderCount = 1;
                result->BodyLength = echo.BytesReceived;

                kprintf("[%s] recv opcode=%u bytes=%Iu data=%.*s\r\n",
                    sampleName,
                    static_cast<unsigned>(echo.Opcode),
                    echo.BytesReceived,
                    static_cast<int>(echo.BytesReceived),
                    buffers->Payload);

                if (echo.Opcode != websocket::WebSocketOpcode::Text ||
                    echo.BytesReceived != sizeof(message) - 1 ||
                    RtlCompareMemory(buffers->Payload, message, sizeof(message) - 1) != sizeof(message) - 1) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }

        const NTSTATUS closeStatus = webSocket->Close(io);
        UNREFERENCED_PARAMETER(closeStatus);
        result->Status = status;
        if (NT_SUCCESS(status)) {
            kprintf("[%s] status=%u echoed=%Iu verify=%s\r\n",
                sampleName,
                result->StatusCode,
                result->BodyLength,
                verifyCertificate ? "on" : "off");
        }
        else {
            kprintf("[%s] failed: 0x%08X status=%u echoed=%Iu verify=%s\r\n",
                sampleName,
                static_cast<ULONG>(status),
                result->StatusCode,
                result->BodyLength,
                verifyCertificate ? "on" : "off");
        }

        return status;
    }

    NTSTATUS RunWebSocketEchoSample(
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
        NTSTATUS status = InitializeWebSocketEchoCertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        return RunWebSocketEchoSampleInternal(
            wskClient,
            "WEBSOCKET ECHO",
            true,
            &certificateStore,
            result);
    }

    NTSTATUS RunWebSocketEchoNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        return RunWebSocketEchoSampleInternal(
            wskClient,
            "WEBSOCKET ECHO no-verify",
            false,
            nullptr,
            result);
    }

    NTSTATUS RunRemoteHttpsAddressFamilySamples(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResults* results) noexcept
    {
        if (results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        results->RemoteHttpsIpv4 = {};
        results->RemoteHttpsIpv6 = {};

        if (certificateStore == nullptr) {
            results->RemoteHttpsIpv4.Status = STATUS_INVALID_PARAMETER;
            results->RemoteHttpsIpv6.Status = STATUS_INVALID_PARAMETER;
            return STATUS_INVALID_PARAMETER;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/get");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        NTSTATUS status = STATUS_SUCCESS;
        NTSTATUS sampleStatus = SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "HTTPS REMOTE IPv4",
            request,
            false,
            certificateStore,
            true,
            tls::TlsProtocol::Tls12,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Ipv4,
            RequestPrefersHttp2(request),
            results->RemoteHttpsIpv4);
        status = MergePublicSampleStatus(status, "HTTPS REMOTE IPv4", sampleStatus);

        sampleStatus = SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "HTTPS REMOTE IPv6",
            request,
            false,
            certificateStore,
            true,
            tls::TlsProtocol::Tls12,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Ipv6,
            RequestPrefersHttp2(request),
            results->RemoteHttpsIpv6);
        status = MergePublicSampleStatus(
            status,
            "HTTPS REMOTE IPv6",
            sampleStatus);

        return status;
    }

    NTSTATUS RunHttpsGetNgHttp2HttpBinSample(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};
        if (certificateStore == nullptr) {
            result->Status = STATUS_INVALID_PARAMETER;
            return result->Status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/get");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "HTTPS GET",
            request,
            false,
            certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsPostNgHttp2HttpBinSample(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};
        if (certificateStore == nullptr) {
            result->Status = STATUS_INVALID_PARAMETER;
            return result->Status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS POST\"}";
        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Post;
        request.Path = http::MakeText("/post");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = http::MakeText("application/json");
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = sizeof(body) - 1;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "HTTPS POST",
            request,
            false,
            certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsPutNgHttp2HttpBinSample(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};
        if (certificateStore == nullptr) {
            result->Status = STATUS_INVALID_PARAMETER;
            return result->Status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS PUT\"}";
        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Put;
        request.Path = http::MakeText("/put");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = http::MakeText("application/json");
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = sizeof(body) - 1;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "HTTPS PUT",
            request,
            false,
            certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsPatchNgHttp2HttpBinSample(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};
        if (certificateStore == nullptr) {
            result->Status = STATUS_INVALID_PARAMETER;
            return result->Status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS PATCH\"}";
        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Patch;
        request.Path = http::MakeText("/patch");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = http::MakeText("application/json");
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = sizeof(body) - 1;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "HTTPS PATCH",
            request,
            false,
            certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsDeleteNgHttp2HttpBinSample(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};
        if (certificateStore == nullptr) {
            result->Status = STATUS_INVALID_PARAMETER;
            return result->Status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::DeleteMethod;
        request.Path = http::MakeText("/delete");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "HTTPS DELETE",
            request,
            false,
            certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsNgHttp2HttpBinNoVerifySample(
        net::WskClient& wskClient,
        _In_z_ const char* sampleName,
        http::HttpMethod method,
        http::HttpText path,
        http::HttpText contentType,
        _In_reads_bytes_opt_(bodyLength) const char* body,
        SIZE_T bodyLength,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = method;
        request.Path = path;
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = contentType;
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = bodyLength;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            sampleName,
            request,
            false,
            nullptr,
            false,
            *result);
    }

    NTSTATUS RunHttpsGetNgHttp2HttpBinNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        return RunHttpsNgHttp2HttpBinNoVerifySample(
            wskClient,
            "HTTPS GET no-verify",
            http::HttpMethod::Get,
            http::MakeText("/get"),
            {},
            nullptr,
            0,
            result);
    }

    NTSTATUS RunHttpsPostNgHttp2HttpBinNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS POST no-verify\"}";

        return RunHttpsNgHttp2HttpBinNoVerifySample(
            wskClient,
            "HTTPS POST no-verify",
            http::HttpMethod::Post,
            http::MakeText("/post"),
            http::MakeText("application/json"),
            body,
            sizeof(body) - 1,
            result);
    }

    NTSTATUS RunHttpsPutNgHttp2HttpBinNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS PUT no-verify\"}";

        return RunHttpsNgHttp2HttpBinNoVerifySample(
            wskClient,
            "HTTPS PUT no-verify",
            http::HttpMethod::Put,
            http::MakeText("/put"),
            http::MakeText("application/json"),
            body,
            sizeof(body) - 1,
            result);
    }

    NTSTATUS RunHttpsPatchNgHttp2HttpBinNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS PATCH no-verify\"}";

        return RunHttpsNgHttp2HttpBinNoVerifySample(
            wskClient,
            "HTTPS PATCH no-verify",
            http::HttpMethod::Patch,
            http::MakeText("/patch"),
            http::MakeText("application/json"),
            body,
            sizeof(body) - 1,
            result);
    }

    NTSTATUS RunHttpsDeleteNgHttp2HttpBinNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        return RunHttpsNgHttp2HttpBinNoVerifySample(
            wskClient,
            "HTTPS DELETE no-verify",
            http::HttpMethod::DeleteMethod,
            http::MakeText("/delete"),
            {},
            nullptr,
            0,
            result);
    }

    NTSTATUS RunTls13HttpsGetSample(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};
        if (certificateStore == nullptr) {
            result->Status = STATUS_INVALID_PARAMETER;
            return result->Status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/get");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "TLS1.3 HTTPS GET",
            request,
            false,
            certificateStore,
            true,
            tls::TlsProtocol::Tls13,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Any,
            false,
            *result);
    }

    NTSTATUS RunTls13Http2GetSample(
        net::WskClient& wskClient,
        const tls::CertificateStore* certificateStore,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *result = {};
        if (certificateStore == nullptr) {
            result->Status = STATUS_INVALID_PARAMETER;
            return result->Status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/get");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "TLS1.3 HTTP/2 GET",
            request,
            false,
            certificateStore,
            true,
            tls::TlsProtocol::Tls13,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Any,
            true,
            *result);
    }

    NTSTATUS RunTls13HttpsGetNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        if (result == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/get");
        request.Host = http::MakeText(HttpBinDevHostName);
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            HttpBinDevServerName,
            HttpBinDevHttpsServiceName,
            HttpBinDevTlsServerName,
            HttpBinDevTlsServerNameLength,
            "TLS1.3 HTTPS GET no-verify",
            request,
            false,
            nullptr,
            false,
            tls::TlsProtocol::Tls13,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Any,
            false,
            *result);
    }

    NTSTATUS RunHttpVerbSamples(
        net::WskClient& wskClient,
        const char* certificateBundlePath,
        HttpVerbSampleResults* results) noexcept
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

        const http::HttpHeader commonHeaders[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        NTSTATUS sampleStatus = SendHttpBinDevHttpsGet(
            wskClient,
            "ENCODING identity",
            http::MakeText("/get"),
            http::MakeText("identity"),
            &trustStore.Store,
            results->IdentityEncoding);
        status = MergePublicSampleStatus(status, "ENCODING identity", sampleStatus);

        sampleStatus = SendHttpBinDevHttpsGet(
            wskClient,
            "ENCODING gzip",
            http::MakeText("/gzip"),
            http::MakeText("gzip"),
            &trustStore.Store,
            results->GzipEncoding);
        status = MergePublicSampleStatus(
            status,
            "ENCODING gzip",
            sampleStatus);

        sampleStatus = SendHttpBinDevHttpsGet(
            wskClient,
            "ENCODING deflate",
            http::MakeText("/deflate"),
            http::MakeText("deflate"),
            &trustStore.Store,
            results->DeflateEncoding);
        status = MergePublicSampleStatus(
            status,
            "ENCODING deflate",
            sampleStatus);

        sampleStatus = SendHttpBinDevHttpsGet(
            wskClient,
            "ENCODING br",
            http::MakeText("/brotli"),
            http::MakeText("br"),
            &trustStore.Store,
            results->BrotliEncoding);
        status = MergePublicSampleStatus(
            status,
            "ENCODING br",
            sampleStatus);

        http::HttpRequestBuildOptions getNgHttp2HttpBin = {};
        getNgHttp2HttpBin.Method = http::HttpMethod::Get;
        getNgHttp2HttpBin.Path = http::MakeText("/get");
        getNgHttp2HttpBin.Host = http::MakeText(HttpBunHostName);
        getNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        getNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        getNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        getNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        sampleStatus = SendSampleRequest(
            wskClient,
            HttpBunServerName,
            HttpBunServiceName,
            "GET",
            getNgHttp2HttpBin,
            false,
            results->GetNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "GET", sampleStatus);

        const char postBody[] = "{\"source\":\"kernel-http\",\"method\":\"POST\"}";
        http::HttpRequestBuildOptions postNgHttp2HttpBin = {};
        postNgHttp2HttpBin.Method = http::HttpMethod::Post;
        postNgHttp2HttpBin.Path = http::MakeText("/post");
        postNgHttp2HttpBin.Host = http::MakeText(HttpBunHostName);
        postNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        postNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        postNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        postNgHttp2HttpBin.Body = postBody;
        postNgHttp2HttpBin.BodyLength = sizeof(postBody) - 1;
        postNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        postNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        sampleStatus = SendSampleRequest(
            wskClient,
            HttpBunServerName,
            HttpBunServiceName,
            "POST",
            postNgHttp2HttpBin,
            false,
            results->PostNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "POST", sampleStatus);

        const char putBody[] = "{\"source\":\"kernel-http\",\"method\":\"PUT\"}";
        http::HttpRequestBuildOptions putNgHttp2HttpBin = {};
        putNgHttp2HttpBin.Method = http::HttpMethod::Put;
        putNgHttp2HttpBin.Path = http::MakeText("/put");
        putNgHttp2HttpBin.Host = http::MakeText(HttpBunHostName);
        putNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        putNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        putNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        putNgHttp2HttpBin.Body = putBody;
        putNgHttp2HttpBin.BodyLength = sizeof(putBody) - 1;
        putNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        putNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        sampleStatus = SendSampleRequest(
            wskClient,
            HttpBunServerName,
            HttpBunServiceName,
            "PUT",
            putNgHttp2HttpBin,
            false,
            results->PutNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "PUT", sampleStatus);

        const char patchBody[] = "{\"source\":\"kernel-http\",\"method\":\"PATCH\"}";
        http::HttpRequestBuildOptions patchNgHttp2HttpBin = {};
        patchNgHttp2HttpBin.Method = http::HttpMethod::Patch;
        patchNgHttp2HttpBin.Path = http::MakeText("/patch");
        patchNgHttp2HttpBin.Host = http::MakeText(HttpBunHostName);
        patchNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        patchNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        patchNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        patchNgHttp2HttpBin.Body = patchBody;
        patchNgHttp2HttpBin.BodyLength = sizeof(patchBody) - 1;
        patchNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        patchNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        sampleStatus = SendSampleRequest(
            wskClient,
            HttpBunServerName,
            HttpBunServiceName,
            "PATCH",
            patchNgHttp2HttpBin,
            false,
            results->PatchNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "PATCH", sampleStatus);

        const char deleteBody[] = "{\"source\":\"kernel-http\",\"method\":\"DELETE\"}";
        http::HttpRequestBuildOptions deleteNgHttp2HttpBin = {};
        deleteNgHttp2HttpBin.Method = http::HttpMethod::DeleteMethod;
        deleteNgHttp2HttpBin.Path = http::MakeText("/delete");
        deleteNgHttp2HttpBin.Host = http::MakeText(HttpBunHostName);
        deleteNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        deleteNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        deleteNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        deleteNgHttp2HttpBin.Body = deleteBody;
        deleteNgHttp2HttpBin.BodyLength = sizeof(deleteBody) - 1;
        deleteNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        deleteNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        sampleStatus = SendSampleRequest(
            wskClient,
            HttpBunServerName,
            HttpBunServiceName,
            "DELETE",
            deleteNgHttp2HttpBin,
            false,
            results->DeleteNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "DELETE", sampleStatus);

        sampleStatus = RunHttpsGetNgHttp2HttpBinSample(
            wskClient,
            &trustStore.Store,
            &results->HttpsGetNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "HTTPS GET", sampleStatus);

        sampleStatus = RunHttpsPostNgHttp2HttpBinSample(
            wskClient,
            &trustStore.Store,
            &results->HttpsPostNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "HTTPS POST", sampleStatus);

        sampleStatus = RunHttpsPutNgHttp2HttpBinSample(
            wskClient,
            &trustStore.Store,
            &results->HttpsPutNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "HTTPS PUT", sampleStatus);

        sampleStatus = RunHttpsPatchNgHttp2HttpBinSample(
            wskClient,
            &trustStore.Store,
            &results->HttpsPatchNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "HTTPS PATCH", sampleStatus);

        sampleStatus = RunHttpsDeleteNgHttp2HttpBinSample(
            wskClient,
            &trustStore.Store,
            &results->HttpsDeleteNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "HTTPS DELETE", sampleStatus);

        sampleStatus = RunHttpsGetNgHttp2HttpBinNoVerifySample(
            wskClient,
            &results->HttpsGetNgHttp2HttpBinNoVerify);
        status = MergePublicSampleStatus(status, "HTTPS GET no-verify", sampleStatus);

        sampleStatus = RunHttpsPostNgHttp2HttpBinNoVerifySample(
            wskClient,
            &results->HttpsPostNgHttp2HttpBinNoVerify);
        status = MergePublicSampleStatus(status, "HTTPS POST no-verify", sampleStatus);

        sampleStatus = RunHttpsPutNgHttp2HttpBinNoVerifySample(
            wskClient,
            &results->HttpsPutNgHttp2HttpBinNoVerify);
        status = MergePublicSampleStatus(status, "HTTPS PUT no-verify", sampleStatus);

        sampleStatus = RunHttpsPatchNgHttp2HttpBinNoVerifySample(
            wskClient,
            &results->HttpsPatchNgHttp2HttpBinNoVerify);
        status = MergePublicSampleStatus(status, "HTTPS PATCH no-verify", sampleStatus);

        sampleStatus = RunHttpsDeleteNgHttp2HttpBinNoVerifySample(
            wskClient,
            &results->HttpsDeleteNgHttp2HttpBinNoVerify);
        status = MergePublicSampleStatus(status, "HTTPS DELETE no-verify", sampleStatus);

        sampleStatus = RunTls13HttpsGetSample(
            wskClient,
            &trustStore.Store,
            &results->Tls13HttpsGet);
        status = MergePublicSampleStatus(status, "TLS1.3 HTTPS GET", sampleStatus);

        sampleStatus = RunTls13Http2GetSample(
            wskClient,
            &trustStore.Store,
            &results->Tls13Http2Get);
        status = MergePublicSampleStatus(status, "TLS1.3 HTTP/2 GET", sampleStatus);

        sampleStatus = RunTls13HttpsGetNoVerifySample(
            wskClient,
            &results->Tls13HttpsGetNoVerify);
        status = MergePublicSampleStatus(status, "TLS1.3 HTTPS GET no-verify", sampleStatus);

        http::HttpRequestBuildOptions headNgHttp2HttpBin = {};
        headNgHttp2HttpBin.Method = http::HttpMethod::Head;
        headNgHttp2HttpBin.Path = http::MakeText("/httpbin/get");
        headNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        headNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        headNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        headNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        headNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        sampleStatus = SendSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2ServiceName,
            "HEAD",
            headNgHttp2HttpBin,
            true,
            results->HeadNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "HEAD", sampleStatus);

        http::HttpRequestBuildOptions optionsNgHttp2HttpBin = {};
        optionsNgHttp2HttpBin.Method = http::HttpMethod::Options;
        optionsNgHttp2HttpBin.Path = http::MakeText("/httpbin/");
        optionsNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        optionsNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        optionsNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        optionsNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        optionsNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        sampleStatus = SendSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2ServiceName,
            "OPTIONS",
            optionsNgHttp2HttpBin,
            false,
            results->OptionsNgHttp2HttpBin);
        status = MergePublicSampleStatus(status, "OPTIONS", sampleStatus);

        sampleStatus = RunWebSocketEchoSample(wskClient, &results->WebSocketEcho);
        status = MergePublicConnectSampleStatus(
            status,
            "WEBSOCKET ECHO",
            sampleStatus,
            results->WebSocketEcho);

        sampleStatus = RunWebSocketEchoNoVerifySample(wskClient, &results->WebSocketEchoNoVerify);
        status = MergePublicConnectSampleStatus(
            status,
            "WEBSOCKET ECHO no-verify",
            sampleStatus,
            results->WebSocketEchoNoVerify);

        sampleStatus = RunRemoteHttpsAddressFamilySamples(wskClient, &trustStore.Store, results);
        status = MergeSampleStatus(status, sampleStatus);

        ResetExternalTrustStore(trustStore);
        return status;
    }
}
}
