#include "samples/AdvancedScenarioSamples.h"

#include "KernelHttpTestLog.h"

#include <KernelHttp/KernelHttpConfig.h>
#include <KernelHttp/khttp/AsyncOp.h>
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/khttp/HttpAsync.h>
#include <KernelHttp/khttp/Request.h>
#include <KernelHttp/khttp/Response.h>
#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/kws/WebSocket.h>
#include <KernelHttpTest/SampleStatus.h>
#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <KernelHttp/khttp/Test.h>
#endif

#include "samples/ExternalTrustStore.h"

#ifndef STATUS_CONNECTION_REFUSED
#define STATUS_CONNECTION_REFUSED ((NTSTATUS)0xC0000236L)
#endif

#ifndef STATUS_NETWORK_UNREACHABLE
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xC000023CL)
#endif

#ifndef STATUS_HOST_UNREACHABLE
#define STATUS_HOST_UNREACHABLE ((NTSTATUS)0xC000023DL)
#endif

#ifndef STATUS_PROTOCOL_UNREACHABLE
#define STATUS_PROTOCOL_UNREACHABLE ((NTSTATUS)0xC000023EL)
#endif

#ifndef STATUS_NO_MATCH
#define STATUS_NO_MATCH ((NTSTATUS)0xC0000272L)
#endif

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr const char* RedirectUrl = "https://httpbin.dev/redirect/1";
        constexpr const char* NotFoundUrl = "https://httpbin.dev/status/404";
        constexpr const char* ServerErrorUrl = "https://httpbin.dev/status/500";
        constexpr const char* LargeResponseUrl = "https://httpbin.dev/encoding/utf8";
        constexpr const char* LargePostUrl = "https://httpbin.dev/post";
        constexpr const char* DelayUrl = "https://httpbin.dev/delay/5";
        constexpr const char* TrustFailureUrl = "https://httpbin.dev/status/204";
        constexpr const char* HttpsGetUrl = "https://httpbin.dev/get";
        constexpr const char* WebSocketUrl = "wss://websocket-echo.com";
        constexpr const char* WebSocketText = "kernel-http advanced websocket";
        constexpr SIZE_T LargeBodyBytes = 64 * 1024;
        constexpr SIZE_T LargePostMaxResponseBytes = 256 * 1024;
        constexpr ULONG AsyncWaitImmediateMs = 0;
        constexpr ULONG AsyncWaitForeverMs = 0xffffffffUL;

        SIZE_T LiteralLength(_In_z_ const char* text) noexcept
        {
            SIZE_T length = 0;
            while (text[length] != '\0') {
                ++length;
            }
            return length;
        }

        void MergeSampleStatus(
            _Inout_ NTSTATUS& aggregate,
            _In_z_ const char* sampleName,
            NTSTATUS status) noexcept
        {
            if (!NT_SUCCESS(status)) {
                kprintf(
                    "[高级场景] 示例=%s 失败 NTSTATUS=0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(status));
            }
            if (NT_SUCCESS(aggregate) && !NT_SUCCESS(status)) {
                aggregate = status;
            }
        }

        void MergePublicDiagnosticSampleStatus(
            _Inout_ NTSTATUS& aggregate,
            _In_z_ const char* sampleName,
            NTSTATUS status) noexcept
        {
            if (!NT_SUCCESS(status) && IsPublicEndpointDiagnosticStatus(status)) {
                kprintf(
                    "[高级场景] 示例=%s 公网连接环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(status));
                return;
            }

            MergeSampleStatus(aggregate, sampleName, status);
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

        NTSTATUS RunDisabledRedirectSample(
            khttp::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            khttp::Request* request = nullptr;
            NTSTATUS status = khttp::RequestCreate(session, &request);
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetUrl(request, RedirectUrl, LiteralLength(RedirectUrl));
            }
            if (NT_SUCCESS(status)) {
                status = khttp::RequestSetMethod(request, khttp::Method::Get);
            }

            khttp::SendOptions options = khttp::DefaultSendOptions();
            options.Flags = khttp::SendFlagDisableAutoRedirect;

            khttp::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = khttp::Send(session, request, &options, &response);
            }

            ULONG statusCode = 0;
            SIZE_T bodyLength = 0;
            if (response != nullptr) {
                statusCode = khttp::ResponseStatusCode(response);
                bodyLength = khttp::ResponseBodyLength(response);
            }
            if (NT_SUCCESS(status) && statusCode != 302) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureStatus(result, status, statusCode, bodyLength);
            khttp::ResponseRelease(response);
            khttp::RequestRelease(request);
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
            kprintf(
                "[高级场景] 负面样本=HTTP ResponseLimit %s 实际=0x%08X 预期=0x%08X MaxResponseBytes=%Iu\r\n",
                expected ? "命中预期，按通过处理" : "未命中预期，按失败处理",
                static_cast<ULONG>(status),
                static_cast<ULONG>(STATUS_BUFFER_TOO_SMALL),
                options.MaxResponseBytes);
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
                "https://httpbin.dev/get?sample=concurrent-1",
                "https://httpbin.dev/get?sample=concurrent-2",
                "https://httpbin.dev/get?sample=concurrent-3"
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
            NTSTATUS completionStatus = status;
            if (NT_SUCCESS(status)) {
                waitStatus = khttp::AsyncWait(operation, AsyncWaitImmediateMs);
                if (waitStatus == STATUS_TIMEOUT ||
                    waitStatus == STATUS_PENDING ||
                    waitStatus == STATUS_MORE_PROCESSING_REQUIRED) {
                    const NTSTATUS cancelStatus = khttp::AsyncCancel(operation);
                    status = cancelStatus;
                    if (NT_SUCCESS(cancelStatus)) {
                        completionStatus = khttp::AsyncWait(operation, AsyncWaitForeverMs);
                        if (khttp::AsyncIsCompleted(operation)) {
                            status = STATUS_SUCCESS;
                        }
                        else {
                            status = completionStatus;
                        }
                    }
                }
                else if (NT_SUCCESS(waitStatus)) {
                    status = STATUS_UNSUCCESSFUL;
                    completionStatus = waitStatus;
                }
                else {
                    status = waitStatus;
                    completionStatus = waitStatus;
                }
            }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            if (operation != nullptr) {
                (void)khttp::test::RunAsyncOperation(operation);
            }
            khttp::test::SetAsyncAutoRun(true);
#endif
            const bool terminalObserved = operation != nullptr && khttp::AsyncIsCompleted(operation);
            khttp::AsyncRelease(operation);
            CaptureStatus(
                result,
                status,
                static_cast<ULONG>(waitStatus),
                terminalObserved ? 1 : 0);
            return status;
        }

        NTSTATUS RunExpectedTlsFailure(
            khttp::Session* session,
            const char* sampleName,
            const char* url,
            const khttp::TlsConfig& tlsConfig,
            NTSTATUS expectedStatus,
            _Out_ HighLevelApiSampleResult& result,
            bool allowPublicEndpointDiagnostic = false) noexcept
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
            const bool publicEndpointDiagnostic =
                !expected &&
                allowPublicEndpointDiagnostic &&
                IsPublicEndpointDiagnosticStatus(status);
            CaptureStatus(result, expected ? STATUS_SUCCESS : status, static_cast<ULONG>(status), 0);
            kprintf(
                "[高级场景] 负面样本=%s %s 实际=0x%08X 预期=0x%08X\r\n",
                sampleName,
                expected ? "命中预期，按通过处理" :
                    (publicEndpointDiagnostic ? "公网环境失败，按诊断记录" : "未命中预期，按失败处理"),
                static_cast<ULONG>(status),
                static_cast<ULONG>(expectedStatus));
            khttp::ResponseRelease(response);
            khttp::RequestRelease(request);
            return result.Status;
        }

        NTSTATUS RunWebSocketCloseSample(
            khttp::Session* session,
            const khttp::TlsConfig& tlsConfig,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            kws::ConnectConfig config = kws::DefaultConnectConfig();
            config.Url = WebSocketUrl;
            config.UrlLength = LiteralLength(WebSocketUrl);
            config.Tls = tlsConfig;
            kprintf("[高级场景] WebSocket Close TLS策略=ModernDefault SHA1签名=关闭\r\n");

            kws::WebSocket* websocket = nullptr;
            NTSTATUS status = kws::ConnectEx(session, &config, &websocket);
            if (NT_SUCCESS(status)) {
                status = kws::Close(websocket);
                websocket = nullptr;
            }
            CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, 0);
            kws::Close(websocket);
            return status;
        }

        NTSTATUS RunWebSocketFragmentSample(
            khttp::Session* session,
            const khttp::TlsConfig& tlsConfig,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            kws::ConnectConfig config = kws::DefaultConnectConfig();
            config.Url = WebSocketUrl;
            config.UrlLength = LiteralLength(WebSocketUrl);
            config.Tls = tlsConfig;
            kprintf("[高级场景] WebSocket FragmentSend TLS策略=ModernDefault SHA1签名=关闭\r\n");

            kws::WebSocket* websocket = nullptr;
            NTSTATUS status = kws::ConnectEx(session, &config, &websocket);
            if (NT_SUCCESS(status)) {
                kws::SendOptions sendOptions = {};
                sendOptions.FinalFragment = false;
                constexpr SIZE_T FirstFragmentLength = 12;
                const SIZE_T messageLength = LiteralLength(WebSocketText);
                status = kws::SendTextEx(
                    websocket,
                    WebSocketText,
                    FirstFragmentLength,
                    &sendOptions);
                if (NT_SUCCESS(status) && FirstFragmentLength < messageLength) {
                    kws::SendOptions continuationOptions = {};
                    continuationOptions.FinalFragment = true;
                    status = kws::SendContinuationEx(
                        websocket,
                        reinterpret_cast<const UCHAR*>(WebSocketText + FirstFragmentLength),
                        messageLength - FirstFragmentLength,
                        &continuationOptions);
                }
            }

            kws::Message message = {};
            if (NT_SUCCESS(status)) {
                status = kws::Receive(websocket, &message);
            }
            if (NT_SUCCESS(status)) {
                const SIZE_T messageLength = LiteralLength(WebSocketText);
                if (message.Type != kws::MsgType::Text ||
                    !message.FinalFragment ||
                    message.DataLength != messageLength ||
                    message.Data == nullptr ||
                    RtlCompareMemory(message.Data, WebSocketText, messageLength) != messageLength) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, message.DataLength);
            kws::Close(websocket);
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
        config.MaxResponseBytes = LargePostMaxResponseBytes;
        config.PoolCapacity = 8;
        config.MaxConnsPerHost = 3;
        config.Tls.Store = &trustStore.Store;

        khttp::Session* session = nullptr;
        status = khttp::SessionCreate(wskClient, &config, &session);
        if (!NT_SUCCESS(status)) {
            ResetExternalTrustStore(trustStore);
            return status;
        }

        status = ValidateStatusCode(session, RedirectUrl, 200, results->HttpRedirect);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP Redirect 200", status);
        status = RunDisabledRedirectSample(session, results->HttpRedirectDisabled);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP RedirectDisabled 302", status);
        status = ValidateStatusCode(session, NotFoundUrl, 404, results->HttpNotFound);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP NotFound 404", status);
        status = ValidateStatusCode(session, ServerErrorUrl, 500, results->HttpServerError);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP ServerError 500", status);
        status = RunLargeResponseSample(session, results->HttpLargeResponse);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP LargeResponse", status);
        status = RunResponseLimitSample(session, results->HttpResponseLimit);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP ResponseLimit", status);
        status = RunLargePostSample(session, results->HttpLargePost);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP LargePost", status);
        status = RunConcurrentAsyncSample(session, results->HttpConcurrentAsync);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP ConcurrentAsync", status);
        status = RunAsyncWaitTimeoutSample(session, results->HttpAsyncWaitTimeout);
        MergePublicDiagnosticSampleStatus(aggregate, "HTTP AsyncWaitTimeout", status);

        HeapObject<tls::CertificateStore> emptyTrustStore;
        if (!emptyTrustStore.IsValid()) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            CaptureStatus(results->HttpsTrustFailure, status, static_cast<ULONG>(status), 0);
        }
        else {
            tls::CertificateStoreOptions emptyStoreOptions = {};
            status = emptyTrustStore->Initialize(emptyStoreOptions);
            if (!NT_SUCCESS(status)) {
                CaptureStatus(results->HttpsTrustFailure, status, static_cast<ULONG>(status), 0);
            }
            else {
                khttp::TlsConfig trustFailureTls = khttp::DefaultTlsConfig();
                trustFailureTls.Store = emptyTrustStore.Get();
                status = RunExpectedTlsFailure(
                    session,
                    "HTTPS TrustFailure",
                    TrustFailureUrl,
                    trustFailureTls,
                    STATUS_TRUST_FAILURE,
                    results->HttpsTrustFailure,
                    true);
            }
        }
        MergePublicDiagnosticSampleStatus(aggregate, "HTTPS TrustFailure", status);

        khttp::TlsConfig alpnMismatchTls = khttp::DefaultTlsConfig();
        alpnMismatchTls.Store = &trustStore.Store;
        alpnMismatchTls.Alpn = "kernel-http-test";
        alpnMismatchTls.AlpnLength = LiteralLength(alpnMismatchTls.Alpn);
        status = RunExpectedTlsFailure(
            session,
            "HTTPS ALPN Mismatch",
            HttpsGetUrl,
            alpnMismatchTls,
            STATUS_NOT_SUPPORTED,
            results->HttpsAlpnMismatch);
        MergeSampleStatus(aggregate, "HTTPS ALPN Mismatch", status);

        khttp::TlsConfig webSocketTls = khttp::DefaultTlsConfig();
        webSocketTls.Store = &trustStore.Store;
        webSocketTls.MinVersion = khttp::TlsVersion::Tls12;
        webSocketTls.MaxVersion = khttp::TlsVersion::Tls13;
        status = RunWebSocketCloseSample(session, webSocketTls, results->WebSocketClose);
        MergePublicDiagnosticSampleStatus(aggregate, "WebSocket Close", status);
        status = RunWebSocketFragmentSample(session, webSocketTls, results->WebSocketFragmentSend);
        MergePublicDiagnosticSampleStatus(aggregate, "WebSocket FragmentSend", status);

        khttp::SessionClose(session);
        ResetExternalTrustStore(trustStore);
        return aggregate;
    }
}
}
