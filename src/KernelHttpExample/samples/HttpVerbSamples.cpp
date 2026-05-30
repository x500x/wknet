#include "samples/HttpVerbSamples.h"

#include <KernelHttp/client/HttpClient.h>
#include <KernelHttp/client/HttpsClient.h>
#include <KernelHttp/client/WebSocketClient.h>

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
        constexpr SIZE_T SampleLogChunkLength = 120;
        constexpr const wchar_t* NgHttp2ServerName = L"nghttp2.org";
        constexpr const wchar_t* NgHttp2ServiceName = L"80";
        constexpr const wchar_t* NgHttp2HttpsServiceName = L"443";
        constexpr const char* NgHttp2TlsServerName = "nghttp2.org";
        constexpr SIZE_T NgHttp2TlsServerNameLength = sizeof("nghttp2.org") - 1;
        constexpr const char* NgHttp2HostName = "nghttp2.org";
        constexpr SIZE_T NgHttp2HostNameLength = sizeof("nghttp2.org") - 1;
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
            auto* client = new client::HttpClient();
            if (client == nullptr) {
                delete buffers;
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

            delete client;
            delete buffers;
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
            _Out_ HttpVerbSampleResult& result) noexcept
        {
            result = {};

            auto* buffers = new SampleIoBuffers();
            if (buffers == nullptr) {
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            SOCKADDR_STORAGE remoteAddress = {};
            result.Status = wskClient.Resolve(serverName, serviceName, &remoteAddress, addressFamily);
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
            options.CertificateStore = certificateStore;
            options.VerifyCertificate = verifyCertificate;
            options.MinimumTlsProtocol = minimumProtocol;
            options.MaximumTlsProtocol = maximumProtocol;
            options.PreferHttp2 = request.Host.Data != nullptr &&
                request.Host.Length == NgHttp2HostNameLength &&
                http::TextEqualsIgnoreCase(request.Host, http::MakeText("nghttp2.org"));

            http::HttpResponse response = {};
            auto* client = new client::HttpsClient();
            if (client == nullptr) {
                delete buffers;
                result.Status = STATUS_INSUFFICIENT_RESOURCES;
                return result.Status;
            }

            const http::HttpText acceptEncoding = FindHeaderValue(
                request.ExtraHeaders,
                request.ExtraHeaderCount,
                http::MakeText("Accept-Encoding"));

            kprintf("[%s] HTTPS verify=%s\r\n", methodName, verifyCertificate ? "on" : "off");
            LogRequestStart(methodName, request.Path, acceptEncoding);
            result.Status = client->SendRequest(wskClient, options, responseBuffers, response);
            if (NT_SUCCESS(result.Status)) {
                result.StatusCode = response.StatusCode;
                result.HeaderCount = response.HeaderCount;
                result.BodyLength = response.BodyLength;
                LogResponse(methodName, response);
            }
            else {
                kprintf("[%s] HTTPS request failed: 0x%08X\r\n", methodName, static_cast<ULONG>(result.Status));
            }

            delete client;
            delete buffers;
            return result.Status;
        }

        NTSTATUS MergeSampleStatus(NTSTATUS current, NTSTATUS next) noexcept
        {
            return NT_SUCCESS(current) ? next : current;
        }

        _Must_inspect_result_
        NTSTATUS SendNgHttp2HttpBinGet(
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
            request.Host = http::MakeText("nghttp2.org");
            request.UserAgent = http::MakeText("KernelHttp/0.1");
            request.Connection = http::HttpConnectionDirective::Close;
            request.ExtraHeaders = headers;
            request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

            return SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
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

        auto* buffers = new WebSocketSampleIoBuffers();
        if (buffers == nullptr) {
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

        auto* webSocket = new client::WebSocketClient();
        if (webSocket == nullptr) {
            delete buffers;
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
        delete webSocket;

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

        delete buffers;
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
        HttpVerbSampleResults* results) noexcept
    {
        if (results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};

        tls::CertificateTrustAnchor anchor = {};
        tls::CertificatePin pin = {};
        tls::CertificateStore certificateStore;
        NTSTATUS status = InitializeNgHttp2CertificateStore(
            certificateStore,
            anchor,
            pin);
        if (!NT_SUCCESS(status)) {
            results->RemoteHttpsIpv4.Status = status;
            results->RemoteHttpsIpv6.Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/httpbin/get");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        status = SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "HTTPS REMOTE IPv4",
            request,
            false,
            &certificateStore,
            true,
            tls::TlsProtocol::Tls12,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Ipv4,
            results->RemoteHttpsIpv4);

        status = MergeSampleStatus(
            status,
            SendHttpsSampleRequestWithTlsVersion(
                wskClient,
                NgHttp2ServerName,
                NgHttp2HttpsServiceName,
                NgHttp2TlsServerName,
                NgHttp2TlsServerNameLength,
                "HTTPS REMOTE IPv6",
                request,
                false,
                &certificateStore,
                true,
                tls::TlsProtocol::Tls12,
                tls::TlsProtocol::Tls13,
                net::WskAddressFamily::Ipv6,
                results->RemoteHttpsIpv6));

        return status;
    }

    NTSTATUS RunHttpsGetNgHttp2HttpBinSample(
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
        NTSTATUS status = InitializeNgHttp2CertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/httpbin/get");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "HTTPS GET",
            request,
            false,
            &certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsPostNgHttp2HttpBinSample(
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
        NTSTATUS status = InitializeNgHttp2CertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS POST\"}";
        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Post;
        request.Path = http::MakeText("/httpbin/post");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = http::MakeText("application/json");
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = sizeof(body) - 1;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "HTTPS POST",
            request,
            false,
            &certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsPutNgHttp2HttpBinSample(
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
        NTSTATUS status = InitializeNgHttp2CertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS PUT\"}";
        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Put;
        request.Path = http::MakeText("/httpbin/put");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = http::MakeText("application/json");
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = sizeof(body) - 1;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "HTTPS PUT",
            request,
            false,
            &certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsPatchNgHttp2HttpBinSample(
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
        NTSTATUS status = InitializeNgHttp2CertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS PATCH\"}";
        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Patch;
        request.Path = http::MakeText("/httpbin/patch");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = http::MakeText("application/json");
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = sizeof(body) - 1;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "HTTPS PATCH",
            request,
            false,
            &certificateStore,
            true,
            *result);
    }

    NTSTATUS RunHttpsDeleteNgHttp2HttpBinSample(
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
        NTSTATUS status = InitializeNgHttp2CertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS DELETE\"}";
        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::DeleteMethod;
        request.Path = http::MakeText("/httpbin/delete");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = http::MakeText("application/json");
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = sizeof(body) - 1;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "HTTPS DELETE",
            request,
            false,
            &certificateStore,
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
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.ContentType = contentType;
        request.Connection = http::HttpConnectionDirective::Close;
        request.Body = body;
        request.BodyLength = bodyLength;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequest(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
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
            http::MakeText("/httpbin/get"),
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
            http::MakeText("/httpbin/post"),
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
            http::MakeText("/httpbin/put"),
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
            http::MakeText("/httpbin/patch"),
            http::MakeText("application/json"),
            body,
            sizeof(body) - 1,
            result);
    }

    NTSTATUS RunHttpsDeleteNgHttp2HttpBinNoVerifySample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        const char body[] = "{\"source\":\"kernel-http\",\"method\":\"HTTPS DELETE no-verify\"}";

        return RunHttpsNgHttp2HttpBinNoVerifySample(
            wskClient,
            "HTTPS DELETE no-verify",
            http::HttpMethod::DeleteMethod,
            http::MakeText("/httpbin/delete"),
            http::MakeText("application/json"),
            body,
            sizeof(body) - 1,
            result);
    }

    NTSTATUS RunTls13HttpsGetSample(
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
        NTSTATUS status = InitializeNgHttp2CertificateStore(certificateStore, anchor, pin);
        if (!NT_SUCCESS(status)) {
            result->Status = status;
            return status;
        }

        const http::HttpHeader headers[] = {
            { http::MakeText("Accept"), http::MakeText("*/*") },
            { http::MakeText("Accept-Encoding"), http::MakeText("gzip, deflate, br, identity") }
        };

        http::HttpRequestBuildOptions request = {};
        request.Method = http::HttpMethod::Get;
        request.Path = http::MakeText("/httpbin/get");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "TLS1.3 HTTPS GET",
            request,
            false,
            &certificateStore,
            true,
            tls::TlsProtocol::Tls13,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Any,
            *result);
    }

    NTSTATUS RunTls13Http2GetSample(
        net::WskClient& wskClient,
        HttpVerbSampleResult* result) noexcept
    {
        return RunTls13HttpsGetSample(wskClient, result);
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
        request.Path = http::MakeText("/httpbin/get");
        request.Host = http::MakeText("nghttp2.org");
        request.UserAgent = http::MakeText("KernelHttp/0.1");
        request.Connection = http::HttpConnectionDirective::Close;
        request.ExtraHeaders = headers;
        request.ExtraHeaderCount = sizeof(headers) / sizeof(headers[0]);

        return SendHttpsSampleRequestWithTlsVersion(
            wskClient,
            NgHttp2ServerName,
            NgHttp2HttpsServiceName,
            NgHttp2TlsServerName,
            NgHttp2TlsServerNameLength,
            "TLS1.3 HTTPS GET no-verify",
            request,
            false,
            nullptr,
            false,
            tls::TlsProtocol::Tls13,
            tls::TlsProtocol::Tls13,
            net::WskAddressFamily::Any,
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

        NTSTATUS status = SendNgHttp2HttpBinGet(
            wskClient,
            "ENCODING identity",
            http::MakeText("/httpbin/get"),
            http::MakeText("identity"),
            results->IdentityEncoding);

        status = MergeSampleStatus(
            status,
            SendNgHttp2HttpBinGet(
                wskClient,
                "ENCODING gzip",
                http::MakeText("/httpbin/gzip"),
                http::MakeText("gzip"),
                results->GzipEncoding));

        status = MergeSampleStatus(
            status,
            SendNgHttp2HttpBinGet(
                wskClient,
                "ENCODING deflate",
                http::MakeText("/httpbin/deflate"),
                http::MakeText("deflate"),
                results->DeflateEncoding));

        status = MergeSampleStatus(
            status,
            SendNgHttp2HttpBinGet(
                wskClient,
                "ENCODING br",
                http::MakeText("/httpbin/brotli"),
                http::MakeText("br"),
                results->BrotliEncoding));

        http::HttpRequestBuildOptions getNgHttp2HttpBin = {};
        getNgHttp2HttpBin.Method = http::HttpMethod::Get;
        getNgHttp2HttpBin.Path = http::MakeText("/httpbin/get");
        getNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        getNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        getNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        getNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        getNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
                "GET",
                getNgHttp2HttpBin,
                false,
                results->GetNgHttp2HttpBin));

        const char postBody[] = "{\"source\":\"kernel-http\",\"method\":\"POST\"}";
        http::HttpRequestBuildOptions postNgHttp2HttpBin = {};
        postNgHttp2HttpBin.Method = http::HttpMethod::Post;
        postNgHttp2HttpBin.Path = http::MakeText("/httpbin/post");
        postNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        postNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        postNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        postNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        postNgHttp2HttpBin.Body = postBody;
        postNgHttp2HttpBin.BodyLength = sizeof(postBody) - 1;
        postNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        postNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
                "POST",
                postNgHttp2HttpBin,
                false,
                results->PostNgHttp2HttpBin));

        const char putBody[] = "{\"source\":\"kernel-http\",\"method\":\"PUT\"}";
        http::HttpRequestBuildOptions putNgHttp2HttpBin = {};
        putNgHttp2HttpBin.Method = http::HttpMethod::Put;
        putNgHttp2HttpBin.Path = http::MakeText("/httpbin/put");
        putNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        putNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        putNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        putNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        putNgHttp2HttpBin.Body = putBody;
        putNgHttp2HttpBin.BodyLength = sizeof(putBody) - 1;
        putNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        putNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
                "PUT",
                putNgHttp2HttpBin,
                false,
                results->PutNgHttp2HttpBin));

        const char patchBody[] = "{\"source\":\"kernel-http\",\"method\":\"PATCH\"}";
        http::HttpRequestBuildOptions patchNgHttp2HttpBin = {};
        patchNgHttp2HttpBin.Method = http::HttpMethod::Patch;
        patchNgHttp2HttpBin.Path = http::MakeText("/httpbin/patch");
        patchNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        patchNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        patchNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        patchNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        patchNgHttp2HttpBin.Body = patchBody;
        patchNgHttp2HttpBin.BodyLength = sizeof(patchBody) - 1;
        patchNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        patchNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
                "PATCH",
                patchNgHttp2HttpBin,
                false,
                results->PatchNgHttp2HttpBin));

        const char deleteBody[] = "{\"source\":\"kernel-http\",\"method\":\"DELETE\"}";
        http::HttpRequestBuildOptions deleteNgHttp2HttpBin = {};
        deleteNgHttp2HttpBin.Method = http::HttpMethod::DeleteMethod;
        deleteNgHttp2HttpBin.Path = http::MakeText("/httpbin/delete");
        deleteNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        deleteNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        deleteNgHttp2HttpBin.ContentType = http::MakeText("application/json");
        deleteNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        deleteNgHttp2HttpBin.Body = deleteBody;
        deleteNgHttp2HttpBin.BodyLength = sizeof(deleteBody) - 1;
        deleteNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        deleteNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
                "DELETE",
                deleteNgHttp2HttpBin,
                false,
                results->DeleteNgHttp2HttpBin));

        status = MergeSampleStatus(
            status,
            RunHttpsGetNgHttp2HttpBinSample(wskClient, &results->HttpsGetNgHttp2HttpBin));

        status = MergeSampleStatus(
            status,
            RunHttpsPostNgHttp2HttpBinSample(wskClient, &results->HttpsPostNgHttp2HttpBin));

        status = MergeSampleStatus(
            status,
            RunHttpsPutNgHttp2HttpBinSample(wskClient, &results->HttpsPutNgHttp2HttpBin));

        status = MergeSampleStatus(
            status,
            RunHttpsPatchNgHttp2HttpBinSample(wskClient, &results->HttpsPatchNgHttp2HttpBin));

        status = MergeSampleStatus(
            status,
            RunHttpsDeleteNgHttp2HttpBinSample(wskClient, &results->HttpsDeleteNgHttp2HttpBin));

        status = MergeSampleStatus(
            status,
            RunHttpsGetNgHttp2HttpBinNoVerifySample(wskClient, &results->HttpsGetNgHttp2HttpBinNoVerify));

        status = MergeSampleStatus(
            status,
            RunHttpsPostNgHttp2HttpBinNoVerifySample(wskClient, &results->HttpsPostNgHttp2HttpBinNoVerify));

        status = MergeSampleStatus(
            status,
            RunHttpsPutNgHttp2HttpBinNoVerifySample(wskClient, &results->HttpsPutNgHttp2HttpBinNoVerify));

        status = MergeSampleStatus(
            status,
            RunHttpsPatchNgHttp2HttpBinNoVerifySample(wskClient, &results->HttpsPatchNgHttp2HttpBinNoVerify));

        status = MergeSampleStatus(
            status,
            RunHttpsDeleteNgHttp2HttpBinNoVerifySample(wskClient, &results->HttpsDeleteNgHttp2HttpBinNoVerify));

        status = MergeSampleStatus(
            status,
            RunTls13HttpsGetSample(wskClient, &results->Tls13HttpsGet));

        status = MergeSampleStatus(
            status,
            RunTls13Http2GetSample(wskClient, &results->Tls13Http2Get));

        status = MergeSampleStatus(
            status,
            RunTls13HttpsGetNoVerifySample(wskClient, &results->Tls13HttpsGetNoVerify));

        http::HttpRequestBuildOptions headNgHttp2HttpBin = {};
        headNgHttp2HttpBin.Method = http::HttpMethod::Head;
        headNgHttp2HttpBin.Path = http::MakeText("/httpbin/get");
        headNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        headNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        headNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        headNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        headNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
                "HEAD",
                headNgHttp2HttpBin,
                true,
                results->HeadNgHttp2HttpBin));

        http::HttpRequestBuildOptions optionsNgHttp2HttpBin = {};
        optionsNgHttp2HttpBin.Method = http::HttpMethod::Options;
        optionsNgHttp2HttpBin.Path = http::MakeText("/httpbin/");
        optionsNgHttp2HttpBin.Host = http::MakeText("nghttp2.org");
        optionsNgHttp2HttpBin.UserAgent = http::MakeText("KernelHttp/0.1");
        optionsNgHttp2HttpBin.Connection = http::HttpConnectionDirective::Close;
        optionsNgHttp2HttpBin.ExtraHeaders = commonHeaders;
        optionsNgHttp2HttpBin.ExtraHeaderCount = sizeof(commonHeaders) / sizeof(commonHeaders[0]);

        status = MergeSampleStatus(
            status,
            SendSampleRequest(
                wskClient,
                NgHttp2ServerName,
                NgHttp2ServiceName,
                "OPTIONS",
                optionsNgHttp2HttpBin,
                false,
                results->OptionsNgHttp2HttpBin));

        status = MergeSampleStatus(
            status,
            RunWebSocketEchoSample(wskClient, &results->WebSocketEcho));

        status = MergeSampleStatus(
            status,
            RunWebSocketEchoNoVerifySample(wskClient, &results->WebSocketEchoNoVerify));

#if defined(KERNEL_HTTP_ENABLE_REMOTE_HTTPS_ADDRESS_FAMILY_SAMPLE) || defined(KERNEL_HTTP_REMOTE_HTTPS_ADDRESS_FAMILY_ONLY)
        status = MergeSampleStatus(
            status,
            RunRemoteHttpsAddressFamilySamples(wskClient, results));
#endif

        return status;
    }
}
}
