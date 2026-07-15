#include "samples/AdvancedScenarioSamples.h"

#include <wknet/WknetConfig.h>
#include <wknet/http/AsyncOp.h>
#include <wknet/http/Http.h>
#include <wknet/http/HttpAsync.h>
#include <wknet/http/Request.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknet/websocket/WebSocket.h>
#include <wknettest/SampleStatus.h>
#if defined(WKNET_USER_MODE_TEST)
#include <wknet/test/Test.h>
#endif

#include "samples/ExternalTrustStore.h"
#include "WknetTestLog.h"

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

namespace wknet
{
namespace samples
{
    namespace
    {
        // Keep request-target paths stable for user-mode sample mocks, but host the
        // live driver samples on postman-echo (dual-stack, more reliable than httpbin.dev).
        constexpr const char* RedirectUrl = "https://postman-echo.com/redirect-to?url=/get";
        constexpr const char* NotFoundUrl = "https://postman-echo.com/status/404";
        constexpr const char* ServerErrorUrl = "https://postman-echo.com/status/500";
        constexpr const char* LargeResponseUrl = "https://postman-echo.com/encoding/utf8";
        constexpr const char* LargePostUrl = "https://postman-echo.com/post";
        constexpr const char* DelayUrl = "https://postman-echo.com/delay/5";
        constexpr const char* TrustFailureUrl = "https://postman-echo.com/status/204";
        constexpr const char* HttpsGetUrl = "https://postman-echo.com/get";
        constexpr const char* WebSocketUrl = "wss://websocket-echo.com";
        constexpr const char* WebSocketText = "kernel-http advanced websocket";
        constexpr SIZE_T LargeBodyBytes = 64 * 1024;
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
                WKNET_SAMPLE_LOG(
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
                WKNET_SAMPLE_LOG(
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
            wknet::http::Session* session,
            const char* url,
            ULONG expectedCode,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            wknet::http::Response* response = nullptr;
            NTSTATUS status = wknet::http::GetEx(session, url, LiteralLength(url), nullptr, nullptr, &response);
            ULONG statusCode = 0;
            SIZE_T bodyLength = 0;
            if (response != nullptr) {
                statusCode = wknet::http::ResponseStatusCode(response);
                bodyLength = wknet::http::ResponseBodyLength(response);
            }
            if (NT_SUCCESS(status) && statusCode != expectedCode) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            CaptureStatus(result, status, statusCode, bodyLength);
            wknet::http::ResponseRelease(response);
            return status;
        }

        NTSTATUS RunDisabledRedirectSample(
            wknet::http::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            wknet::http::SendOptions* options = nullptr;
            NTSTATUS status = wknet::http::SendOptionsCreate(&options);
            if (NT_SUCCESS(status)) {
                options->Flags = wknet::http::SendFlagDisableAutoRedirect;
            }

            wknet::http::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = wknet::http::SendEx(
                    session,
                    wknet::http::Method::Get,
                    RedirectUrl,
                    LiteralLength(RedirectUrl),
                    nullptr,
                    nullptr,
                    options,
                    &response);
            }

            ULONG statusCode = 0;
            SIZE_T bodyLength = 0;
            if (response != nullptr) {
                statusCode = wknet::http::ResponseStatusCode(response);
                bodyLength = wknet::http::ResponseBodyLength(response);
            }
            if (NT_SUCCESS(status) && statusCode != 302) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureStatus(result, status, statusCode, bodyLength);
            wknet::http::ResponseRelease(response);
            wknet::http::SendOptionsRelease(options);
            return status;
        }

        NTSTATUS RunLargeResponseSample(
            wknet::http::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            wknet::http::SendOptions* options = nullptr;
            NTSTATUS status = wknet::http::SendOptionsCreate(&options);
            if (NT_SUCCESS(status)) {
                options->MaxResponseBytes = 0;
            }

            wknet::http::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = wknet::http::SendEx(
                    session,
                    wknet::http::Method::Get,
                    LargeResponseUrl,
                    LiteralLength(LargeResponseUrl),
                    nullptr,
                    nullptr,
                    options,
                    &response);
            }

            ULONG statusCode = response != nullptr ? wknet::http::ResponseStatusCode(response) : 0;
            SIZE_T bodyLength = response != nullptr ? wknet::http::ResponseBodyLength(response) : 0;
            if (NT_SUCCESS(status) && (statusCode != 200 || bodyLength == 0)) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureStatus(result, status, statusCode, bodyLength);
            wknet::http::ResponseRelease(response);
            wknet::http::SendOptionsRelease(options);
            return status;
        }

        NTSTATUS RunResponseLimitSample(
            wknet::http::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            wknet::http::SendOptions* options = nullptr;
            NTSTATUS status = wknet::http::SendOptionsCreate(&options);
            if (NT_SUCCESS(status)) {
                options->MaxResponseBytes = 64;
            }

            wknet::http::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = wknet::http::SendEx(
                    session,
                    wknet::http::Method::Get,
                    LargeResponseUrl,
                    LiteralLength(LargeResponseUrl),
                    nullptr,
                    nullptr,
                    options,
                    &response);
            }

            const bool expected = status == STATUS_BUFFER_TOO_SMALL;
            CaptureStatus(result, expected ? STATUS_SUCCESS : status, 0, 64);
            WKNET_SAMPLE_LOG(
                "[高级场景] 预期限制样本=HTTP ResponseLimit %s 实际=0x%08X 预期=0x%08X MaxResponseBytes=%Iu（非零值主动限制响应体聚合）\r\n",
                expected ? "命中预期，按通过处理" : "未命中预期，按失败处理",
                static_cast<ULONG>(status),
                static_cast<ULONG>(STATUS_BUFFER_TOO_SMALL),
                options != nullptr ? options->MaxResponseBytes : 0);
            wknet::http::ResponseRelease(response);
            wknet::http::SendOptionsRelease(options);
            return result.Status;
        }

        NTSTATUS RunLargePostSample(
            wknet::http::Session* session,
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

            wknet::http::Body* requestBody = nullptr;
            NTSTATUS status = wknet::http::BodyCreateBytes(body.Get(), body.Count(), &requestBody);
            wknet::http::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = wknet::http::PostEx(
                    session,
                    LargePostUrl,
                    LiteralLength(LargePostUrl),
                    nullptr,
                    requestBody,
                    nullptr,
                    &response);
            }

            const ULONG statusCode = response != nullptr ? wknet::http::ResponseStatusCode(response) : 0;
            const SIZE_T bodyLength = response != nullptr ? wknet::http::ResponseBodyLength(response) : 0;
            if (NT_SUCCESS(status) && statusCode != 200) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            CaptureStatus(result, status, statusCode, bodyLength);
            wknet::http::ResponseRelease(response);
            wknet::http::BodyRelease(requestBody);
            return status;
        }

        NTSTATUS RunConcurrentAsyncSample(
            wknet::http::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            constexpr SIZE_T OperationCount = 3;
            const char* urls[OperationCount] = {
                "https://postman-echo.com/get?sample=concurrent-1",
                "https://postman-echo.com/get?sample=concurrent-2",
                "https://postman-echo.com/get?sample=concurrent-3"
            };
            wknet::http::AsyncOp* operations[OperationCount] = {};

            NTSTATUS status = STATUS_SUCCESS;
            SIZE_T completed = 0;
            for (SIZE_T index = 0; index < OperationCount; ++index) {
                status = wknet::http::AsyncGetEx(
                    session,
                    urls[index],
                    LiteralLength(urls[index]),
                    nullptr,
                    nullptr,
                    &operations[index]);
                if (!NT_SUCCESS(status)) {
                    break;
                }
            }

            for (SIZE_T index = 0; index < OperationCount; ++index) {
                if (operations[index] == nullptr) {
                    continue;
                }
                NTSTATUS waitStatus = wknet::http::AsyncWait(operations[index], 60000);
                if (NT_SUCCESS(status) && !NT_SUCCESS(waitStatus)) {
                    status = waitStatus;
                }
                wknet::http::Response* response = nullptr;
                NTSTATUS responseStatus = wknet::http::AsyncGetResponse(operations[index], &response);
                if (NT_SUCCESS(responseStatus)) {
                    ++completed;
                }
                if (NT_SUCCESS(status) && !NT_SUCCESS(responseStatus)) {
                    status = responseStatus;
                }
                wknet::http::ResponseRelease(response);
                wknet::http::AsyncRelease(operations[index]);
            }

            if (NT_SUCCESS(status) && completed != OperationCount) {
                status = STATUS_UNSUCCESSFUL;
            }

            CaptureStatus(result, status, static_cast<ULONG>(completed), 0);
            return status;
        }

        NTSTATUS RunAsyncWaitTimeoutSample(
            wknet::http::Session* session,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            wknet::http::test::SetAsyncAutoRun(false);
#endif
            wknet::http::AsyncOp* operation = nullptr;
            NTSTATUS status = wknet::http::AsyncGetEx(
                session,
                DelayUrl,
                LiteralLength(DelayUrl),
                nullptr,
                nullptr,
                &operation);
            NTSTATUS waitStatus = status;
            NTSTATUS completionStatus = status;
            if (NT_SUCCESS(status)) {
                waitStatus = wknet::http::AsyncWait(operation, AsyncWaitImmediateMs);
                if (waitStatus == STATUS_TIMEOUT ||
                    waitStatus == STATUS_PENDING ||
                    waitStatus == STATUS_MORE_PROCESSING_REQUIRED) {
                    const NTSTATUS cancelStatus = wknet::http::AsyncCancel(operation);
                    status = cancelStatus;
                    if (NT_SUCCESS(cancelStatus)) {
                        completionStatus = wknet::http::AsyncWait(operation, AsyncWaitForeverMs);
                        if (wknet::http::AsyncIsCompleted(operation)) {
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
#if defined(WKNET_USER_MODE_TEST)
            if (operation != nullptr) {
                (void)wknet::http::test::RunAsyncOperation(operation);
            }
            wknet::http::test::SetAsyncAutoRun(true);
#endif
            const bool terminalObserved = operation != nullptr && wknet::http::AsyncIsCompleted(operation);
            wknet::http::AsyncRelease(operation);
            CaptureStatus(
                result,
                status,
                static_cast<ULONG>(waitStatus),
                terminalObserved ? 1 : 0);
            return status;
        }

        NTSTATUS RunExpectedTlsFailure(
            wknet::http::Session* session,
            const char* sampleName,
            const char* url,
            const wknet::http::TlsConfig& tlsConfig,
            NTSTATUS expectedStatus,
            _Out_ HighLevelApiSampleResult& result,
            bool allowPublicEndpointDiagnostic = false) noexcept
        {
            wknet::http::SendOptions* options = nullptr;
            NTSTATUS status = wknet::http::SendOptionsCreate(&options);
            if (NT_SUCCESS(status)) {
                options->Tls = tlsConfig;
                options->HasTlsOverride = true;
            }

            wknet::http::Response* response = nullptr;
            if (NT_SUCCESS(status)) {
                status = wknet::http::SendEx(
                    session,
                    wknet::http::Method::Get,
                    url,
                    LiteralLength(url),
                    nullptr,
                    nullptr,
                    options,
                    &response);
            }

            const bool expected = status == expectedStatus;
            const bool publicEndpointDiagnostic =
                !expected &&
                allowPublicEndpointDiagnostic &&
                IsPublicEndpointDiagnosticStatus(status);
            CaptureStatus(result, expected ? STATUS_SUCCESS : status, static_cast<ULONG>(status), 0);
            WKNET_SAMPLE_LOG(
                "[高级场景] 负面样本=%s %s 实际=0x%08X 预期=0x%08X\r\n",
                sampleName,
                expected ? "命中预期，按通过处理" :
                    (publicEndpointDiagnostic ? "公网环境失败，按诊断记录" : "未命中预期，按失败处理"),
                static_cast<ULONG>(status),
                static_cast<ULONG>(expectedStatus));
            wknet::http::ResponseRelease(response);
            wknet::http::SendOptionsRelease(options);
            return result.Status;
        }

        NTSTATUS RunWebSocketCloseSample(
            wknet::http::Session* session,
            const wknet::http::TlsConfig& tlsConfig,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            wknet::websocket::ConnectConfig config = wknet::websocket::DefaultConnectConfig();
            config.Url = WebSocketUrl;
            config.UrlLength = LiteralLength(WebSocketUrl);
            config.Tls = tlsConfig;
            WKNET_SAMPLE_LOG("[高级场景] WebSocket Close TLS策略=ModernDefault SHA1签名=关闭\r\n");

            wknet::websocket::WebSocket* websocket = nullptr;
            NTSTATUS status = wknet::websocket::ConnectEx(session, &config, &websocket);
            if (NT_SUCCESS(status)) {
                status = wknet::websocket::Close(websocket);
                websocket = nullptr;
            }
            CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, 0);
            wknet::websocket::Close(websocket);
            return status;
        }

        NTSTATUS RunWebSocketFragmentSample(
            wknet::http::Session* session,
            const wknet::http::TlsConfig& tlsConfig,
            _Out_ HighLevelApiSampleResult& result) noexcept
        {
            wknet::websocket::ConnectConfig config = wknet::websocket::DefaultConnectConfig();
            config.Url = WebSocketUrl;
            config.UrlLength = LiteralLength(WebSocketUrl);
            config.Tls = tlsConfig;
            WKNET_SAMPLE_LOG("[高级场景] WebSocket FragmentSend TLS策略=ModernDefault SHA1签名=关闭\r\n");

            wknet::websocket::WebSocket* websocket = nullptr;
            NTSTATUS status = wknet::websocket::ConnectEx(session, &config, &websocket);
            if (NT_SUCCESS(status)) {
                wknet::websocket::SendOptions sendOptions = {};
                sendOptions.FinalFragment = false;
                constexpr SIZE_T FirstFragmentLength = 12;
                const SIZE_T messageLength = LiteralLength(WebSocketText);
                status = wknet::websocket::SendTextEx(
                    websocket,
                    WebSocketText,
                    FirstFragmentLength,
                    &sendOptions);
                if (NT_SUCCESS(status) && FirstFragmentLength < messageLength) {
                    wknet::websocket::SendOptions continuationOptions = {};
                    continuationOptions.FinalFragment = true;
                    status = wknet::websocket::SendContinuationEx(
                        websocket,
                        reinterpret_cast<const UCHAR*>(WebSocketText + FirstFragmentLength),
                        messageLength - FirstFragmentLength,
                        &continuationOptions);
                }
            }

            wknet::websocket::Message message = {};
            if (NT_SUCCESS(status)) {
                status = wknet::websocket::Receive(websocket, &message);
            }
            if (NT_SUCCESS(status)) {
                const SIZE_T messageLength = LiteralLength(WebSocketText);
                if (message.Type != wknet::websocket::MsgType::Text ||
                    !message.FinalFragment ||
                    message.DataLength != messageLength ||
                    message.Data == nullptr ||
                    RtlCompareMemory(message.Data, WebSocketText, messageLength) != messageLength) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, message.DataLength);
            wknet::websocket::Close(websocket);
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

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.RequestBufferBytes = 96 * 1024;
        config.MaxResponseBytes = 0;
        config.PoolCapacity = 8;
        config.MaxConnsPerHost = 3;
        config.Tls.Store = trustStore.Store;

        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
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

        http::CertificateStore* emptyTrustStore = nullptr;
        status = http::CertificateStoreCreate(nullptr, &emptyTrustStore);
        if (!NT_SUCCESS(status)) {
            CaptureStatus(results->HttpsTrustFailure, status, static_cast<ULONG>(status), 0);
        }
        else {
                wknet::http::TlsConfig trustFailureTls = wknet::http::DefaultTlsConfig();
                trustFailureTls.Store = emptyTrustStore;
                status = RunExpectedTlsFailure(
                    session,
                    "HTTPS TrustFailure",
                    TrustFailureUrl,
                    trustFailureTls,
                    STATUS_TRUST_FAILURE,
                    results->HttpsTrustFailure,
                    true);
            http::CertificateStoreClose(emptyTrustStore);
        }
        MergePublicDiagnosticSampleStatus(aggregate, "HTTPS TrustFailure", status);

        wknet::http::TlsConfig alpnMismatchTls = wknet::http::DefaultTlsConfig();
        alpnMismatchTls.Store = trustStore.Store;
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

        wknet::http::TlsConfig webSocketTls = wknet::http::DefaultTlsConfig();
        webSocketTls.Store = trustStore.Store;
        webSocketTls.MinVersion = wknet::http::TlsVersion::Tls12;
        webSocketTls.MaxVersion = wknet::http::TlsVersion::Tls13;
        status = RunWebSocketCloseSample(session, webSocketTls, results->WebSocketClose);
        MergePublicDiagnosticSampleStatus(aggregate, "WebSocket Close", status);
        status = RunWebSocketFragmentSample(session, webSocketTls, results->WebSocketFragmentSend);
        MergePublicDiagnosticSampleStatus(aggregate, "WebSocket FragmentSend", status);

        wknet::http::SessionClose(session);
        ResetExternalTrustStore(trustStore);
        return aggregate;
    }
}
}
