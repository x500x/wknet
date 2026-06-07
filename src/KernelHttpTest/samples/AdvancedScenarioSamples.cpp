#include "samples/AdvancedScenarioSamples.h"

#include <KernelHttp/KernelHttpConfig.h>
#include <KernelHttp/khttp/AsyncOp.h>
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/khttp/HttpAsync.h>
#include <KernelHttp/khttp/Request.h>
#include <KernelHttp/khttp/Response.h>
#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/khttp/WebSocket.h>
#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <KernelHttp/khttp/Test.h>
#endif

#include "samples/ExternalTrustStore.h"

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr const char* RedirectUrl = "http://nghttp2.org/httpbin/redirect/1";
        constexpr const char* NotFoundUrl = "http://nghttp2.org/httpbin/status/404";
        constexpr const char* ServerErrorUrl = "http://nghttp2.org/httpbin/status/500";
        constexpr const char* LargeResponseUrl = "http://nghttp2.org/httpbin/bytes/65536";
        constexpr const char* LargePostUrl = "http://nghttp2.org/httpbin/post";
        constexpr const char* DelayUrl = "http://nghttp2.org/httpbin/delay/5";
        constexpr const char* SelfSignedUrl = "https://self-signed.badssl.com/";
        constexpr const char* HttpsGetUrl = "https://nghttp2.org/httpbin/get";
        constexpr const char* WebSocketUrl = "wss://ws.postman-echo.com/raw";
        constexpr const char* WebSocketText = "kernel-http advanced websocket";
        constexpr SIZE_T LargeBodyBytes = 64 * 1024;
        constexpr ULONG AsyncWaitImmediateMs = 0;

        SIZE_T LiteralLength(_In_z_ const char* text) noexcept
        {
            SIZE_T length = 0;
            while (text[length] != '\0') {
                ++length;
            }
            return length;
        }

        void MergeSampleStatus(_Inout_ NTSTATUS& aggregate, NTSTATUS status) noexcept
        {
            if (NT_SUCCESS(aggregate) && !NT_SUCCESS(status)) {
                aggregate = status;
            }
        }

        void CaptureStatus(
            _Out_ HighLevelApiSampleResult& result,
            NTSTATUS status,
            ULONG statusCode,
            SIZE_T bodyLength) noexcept
        {
            result.Status = status;
            result.StatusCode = statusCode;
            result.BodyLength = bodyLength;
        }

        NTSTATUS ValidateStatusCode(
            khttp::Session* session,
            const char* url,
            ULONG expectedCode,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            khttp::Response* response = nullptr;
            NTSTATUS status = khttp::Get(session, url, LiteralLength(url), &response);
            ULONG statusCode = 0;
            SIZE_T bodyLength = 0;
            if (response != nullptr) {
                statusCode = khttp::ResponseStatusCode(response);
                bodyLength = khttp::ResponseBodyLength(response);
            }
            if (NT_SUCCESS(status) && statusCode != expectedCode) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            CaptureStatus(result, status, statusCode, bodyLength);
            khttp::ResponseRelease(response);
            return status;
        }

        NTSTATUS RunLargeResponseSample(
            khttp::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            khttp::Request* request = nullptr;
            NTSTATUS status = khttp::RequestCreate(session, &request);
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetUrl(request, LargeResponseUrl, LiteralLength(LargeResponseUrl));
            }
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetMethod(request, khttp::Method::Get);
            }

            khttp::SendOptions options = khttp::DefaultSendOptions();
            options.MaxResponseBytes = 128 * 1024;

            khttp::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = khttp::Send(session, request, &options, &response);
            }

            ULONG statusCode = response != nullptr ? khttp::ResponseStatusCode(response) : 0;
            SIZE_T bodyLength = response != nullptr ? khttp::ResponseBodyLength(response) : 0;
            if (NT_SUCCESS(status) && (statusCode != 200 || bodyLength == 0)) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureStatus(result, status, statusCode, bodyLength);
            khttp::ResponseRelease(response);
            khttp::RequestRelease(request);
            return status;
        }

        NTSTATUS RunResponseLimitSample(
            khttp::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            khttp::Request* request = nullptr;
            NTSTATUS status = khttp::RequestCreate(session, &request);
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetUrl(request, LargeResponseUrl, LiteralLength(LargeResponseUrl));
            }
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetMethod(request, khttp::Method::Get);
            }

            khttp::SendOptions options = khttp::DefaultSendOptions();
            options.MaxResponseBytes = 64;

            khttp::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = khttp::Send(session, request, &options, &response);
            }

            const bool expected = status == STATUS_BUFFER_TOO_SMALL;
            CaptureStatus(result, expected ? STATUS_SUCCESS : status, 0, 64);
            khttp::ResponseRelease(response);
            khttp::RequestRelease(request);
            return result.Status;
        }

        NTSTATUS RunLargePostSample(
            khttp::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            HeapArray<UCHAR> body(LargeBodyBytes);
            if (!body.IsValid()) {
                CaptureStatus(result, STATUS_INSUFFICIENT_RESOURCES, 0, 0);
                return result.Status;
            }
            for (SIZE_T index = 0; index < body.Count(); ++index) {
                body[index] = static_cast<UCHAR>('A' + (index % 26));
            }

            khttp::Response* response = nullptr;
            NTSTATUS status = khttp::Post(
                session,
                LargePostUrl,
                LiteralLength(LargePostUrl),
                body.Get(),
                body.Count(),
                &response);

            const ULONG statusCode = response != nullptr ? khttp::ResponseStatusCode(response) : 0;
            const SIZE_T bodyLength = response != nullptr ? khttp::ResponseBodyLength(response) : 0;
            if (NT_SUCCESS(status) && statusCode != 200) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureStatus(result, status, statusCode, bodyLength);
            khttp::ResponseRelease(response);
            return status;
        }

        NTSTATUS RunConcurrentAsyncSample(
            khttp::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            constexpr SIZE_T OperationCount = 3;
            const char* urls[OperationCount] = {
                "http://nghttp2.org/httpbin/get?sample=concurrent-1",
                "http://nghttp2.org/httpbin/get?sample=concurrent-2",
                "http://nghttp2.org/httpbin/get?sample=concurrent-3"
            };
            khttp::AsyncOp* operations[OperationCount] = {};

            NTSTATUS status = STATUS_SUCCESS;
            SIZE_T completed = 0;
            for (SIZE_T index = 0; index < OperationCount; ++index) {
                status = khttp::GetAsync(session, urls[index], LiteralLength(urls[index]), &operations[index]);
                if (!NT_SUCCESS(status)) {
                    break;
                }
            }

            for (SIZE_T index = 0; index < OperationCount; ++index) {
                if (operations[index] == nullptr) {
                    continue;
                }
                NTSTATUS waitStatus = khttp::AsyncWait(operations[index], 60000);
                if (NT_SUCCESS(status) && !NT_SUCCESS(waitStatus)) {
                    status = waitStatus;
                }
                khttp::Response* response = nullptr;
                NTSTATUS responseStatus = khttp::AsyncGetResponse(operations[index], &response);
                if (NT_SUCCESS(responseStatus)) {
                    ++completed;
                }
                if (NT_SUCCESS(status) && !NT_SUCCESS(responseStatus)) {
                    status = responseStatus;
                }
                khttp::ResponseRelease(response);
                khttp::AsyncRelease(operations[index]);
            }

            if (NT_SUCCESS(status) && completed != OperationCount) {
                status = STATUS_UNSUCCESSFUL;
            }

            CaptureStatus(result, status, static_cast<ULONG>(completed), 0);
            return status;
        }

        NTSTATUS RunAsyncWaitTimeoutSample(
            khttp::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            khttp::test::SetAsyncAutoRun(false);
#endif
            khttp::AsyncOp* operation = nullptr;
            NTSTATUS status = khttp::GetAsync(session, DelayUrl, LiteralLength(DelayUrl), &operation);
            NTSTATUS waitStatus = status;
            if (NT_SUCCESS(status)) {
                waitStatus = khttp::AsyncWait(operation, AsyncWaitImmediateMs);
                if (waitStatus == STATUS_TIMEOUT ||
                    waitStatus == STATUS_PENDING ||
                    waitStatus == STATUS_MORE_PROCESSING_REQUIRED) {
                    status = STATUS_SUCCESS;
                    (void)khttp::AsyncCancel(operation);
                }
                else if (NT_SUCCESS(waitStatus)) {
                    status = STATUS_UNSUCCESSFUL;
                }
                else {
                    status = waitStatus;
                }
            }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            if (operation != nullptr) {
                (void)khttp::test::RunAsyncOperation(operation);
            }
            khttp::test::SetAsyncAutoRun(true);
#endif
            khttp::AsyncRelease(operation);
            CaptureStatus(result, status, static_cast<ULONG>(waitStatus), 0);
            return status;
        }

        NTSTATUS RunExpectedTlsFailure(
            khttp::Session* session,
            const char* url,
            const khttp::TlsConfig& tlsConfig,
            NTSTATUS expectedStatus,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            khttp::Request* request = nullptr;
            NTSTATUS status = khttp::RequestCreate(session, &request);
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetUrl(request, url, LiteralLength(url));
            }
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetMethod(request, khttp::Method::Get);
            }
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetTls(request, &tlsConfig);
            }

            khttp::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = khttp::Send(session, request, nullptr, &response);
            }

            const bool expected = status == expectedStatus;
            CaptureStatus(result, expected ? STATUS_SUCCESS : status, static_cast<ULONG>(status), 0);
            khttp::ResponseRelease(response);
            khttp::RequestRelease(request);
            return result.Status;
        }

        NTSTATUS RunWebSocketCloseSample(
            khttp::Session* session,
            const khttp::TlsConfig& tlsConfig,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            khttp::WsConnectConfig config = khttp::DefaultWsConnectConfig();
            config.Url = WebSocketUrl;
            config.UrlLength = LiteralLength(WebSocketUrl);
            config.Tls = tlsConfig;

            khttp::WebSocket* websocket = nullptr;
            NTSTATUS status = khttp::WsConnectEx(session, &config, &websocket);
            if (NT_SUCCESS(status)) {
                status = khttp::WsClose(websocket);
                websocket = nullptr;
            }
            CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, 0);
            khttp::WsClose(websocket);
            return status;
        }

        NTSTATUS RunWebSocketFragmentSample(
            khttp::Session* session,
            const khttp::TlsConfig& tlsConfig,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            khttp::WsConnectConfig config = khttp::DefaultWsConnectConfig();
            config.Url = WebSocketUrl;
            config.UrlLength = LiteralLength(WebSocketUrl);
            config.Tls = tlsConfig;

            khttp::WebSocket* websocket = nullptr;
            NTSTATUS status = khttp::WsConnectEx(session, &config, &websocket);
            if (NT_SUCCESS(status)) {
                khttp::WsSendOptions sendOptions = {};
                sendOptions.FinalFragment = false;
                status = khttp::WsSendTextEx(
                    websocket,
                    WebSocketText,
                    LiteralLength(WebSocketText),
                    &sendOptions);
            }

            CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, LiteralLength(WebSocketText));
            khttp::WsClose(websocket);
            return status;
        }
    }

    NTSTATUS RunAdvancedScenarioSamples(
        net::WskClient* wskClient,
        const char* certificateBundlePath,
        AdvancedScenarioSampleResults* results) noexcept
    {
        if (wskClient == nullptr || results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};
        NTSTATUS aggregate = STATUS_SUCCESS;

        ExternalTrustStore trustStore = {};
        NTSTATUS status = InitializeExternalTrustStore(
            trustStore,
            certificateBundlePath != nullptr ? certificateBundlePath : ExternalTrustStoreDefaultBundlePath);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        khttp::SessionConfig config = khttp::DefaultSessionConfig();
        config.RequestBufferBytes = 96 * 1024;
        config.MaxResponseBytes = 128 * 1024;
        config.PoolCapacity = 8;
        config.MaxConnsPerHost = 3;
        config.Tls.Store = &trustStore.Store;

        khttp::Session* session = nullptr;
        status = khttp::SessionCreate(wskClient, &config, &session);
        if (!NT_SUCCESS(status)) {
            ResetExternalTrustStore(trustStore);
            return status;
        }

        status = ValidateStatusCode(session, RedirectUrl, 302, results->HttpRedirect);
        MergeSampleStatus(aggregate, status);
        status = ValidateStatusCode(session, NotFoundUrl, 404, results->HttpNotFound);
        MergeSampleStatus(aggregate, status);
        status = ValidateStatusCode(session, ServerErrorUrl, 500, results->HttpServerError);
        MergeSampleStatus(aggregate, status);
        status = RunLargeResponseSample(session, results->HttpLargeResponse);
        MergeSampleStatus(aggregate, status);
        status = RunResponseLimitSample(session, results->HttpResponseLimit);
        MergeSampleStatus(aggregate, status);
        status = RunLargePostSample(session, results->HttpLargePost);
        MergeSampleStatus(aggregate, status);
        status = RunConcurrentAsyncSample(session, results->HttpConcurrentAsync);
        MergeSampleStatus(aggregate, status);
        status = RunAsyncWaitTimeoutSample(session, results->HttpAsyncWaitTimeout);
        MergeSampleStatus(aggregate, status);

        khttp::TlsConfig trustFailureTls = khttp::DefaultTlsConfig();
        trustFailureTls.Store = &trustStore.Store;
        status = RunExpectedTlsFailure(
            session,
            SelfSignedUrl,
            trustFailureTls,
            STATUS_TRUST_FAILURE,
            results->HttpsTrustFailure);
        MergeSampleStatus(aggregate, status);

        khttp::TlsConfig alpnMismatchTls = khttp::DefaultTlsConfig();
        alpnMismatchTls.Store = &trustStore.Store;
        alpnMismatchTls.Alpn = "kernel-http-test";
        alpnMismatchTls.AlpnLength = LiteralLength(alpnMismatchTls.Alpn);
        status = RunExpectedTlsFailure(
            session,
            HttpsGetUrl,
            alpnMismatchTls,
            STATUS_NOT_SUPPORTED,
            results->HttpsAlpnMismatch);
        MergeSampleStatus(aggregate, status);

        khttp::TlsConfig webSocketTls = khttp::DefaultTlsConfig();
        webSocketTls.Store = &trustStore.Store;
        webSocketTls.MaxVersion = khttp::TlsVersion::Tls12;
        status = RunWebSocketCloseSample(session, webSocketTls, results->WebSocketClose);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketFragmentSample(session, webSocketTls, results->WebSocketFragmentSend);
        MergeSampleStatus(aggregate, status);

        khttp::SessionClose(session);
        ResetExternalTrustStore(trustStore);
        return aggregate;
    }
}
}
