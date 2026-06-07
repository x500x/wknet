#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/khttp/Test.h>

#include "samples/AdvancedScenarioSamples.h"
#include "samples/HighLevelApiSamples.h"

#include <string.h>
#include <stdio.h>

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    bool TextEqualsLiteral(const char* value, SIZE_T valueLength, const char* literal) noexcept
    {
        if (value == nullptr || literal == nullptr) {
            return false;
        }

        for (SIZE_T index = 0; index < valueLength; ++index) {
            if (literal[index] == '\0' || value[index] != literal[index]) {
                return false;
            }
        }
        return literal[valueLength] == '\0';
    }

    bool BufferContainsLiteral(const char* value, SIZE_T valueLength, const char* literal) noexcept
    {
        if (value == nullptr || literal == nullptr) {
            return false;
        }

        SIZE_T literalLength = 0;
        while (literal[literalLength] != '\0') {
            ++literalLength;
        }
        if (literalLength == 0 || literalLength > valueLength) {
            return false;
        }

        for (SIZE_T offset = 0; offset + literalLength <= valueLength; ++offset) {
            if (memcmp(value + offset, literal, literalLength) == 0) {
                return true;
            }
        }
        return false;
    }

    struct SampleCapture final
    {
        static constexpr SIZE_T MaxWebSocketPayload = 64;

        SIZE_T HttpCalls = 0;
        SIZE_T HttpIpv4Calls = 0;
        SIZE_T HttpIpv6Calls = 0;
        SIZE_T HttpAnyCalls = 0;
        SIZE_T HttpReuseCalls = 0;
        SIZE_T HttpNoPoolCalls = 0;
        SIZE_T HttpForceNewCalls = 0;
        SIZE_T HttpsVerifyCalls = 0;
        SIZE_T HttpsVerifyWithStoreCalls = 0;
        SIZE_T HttpsNoVerifyCalls = 0;
        SIZE_T HttpsNoVerifyWithoutStoreCalls = 0;
        SIZE_T HttpsHttp11AlpnCalls = 0;
        SIZE_T HttpsHttp2AlpnCalls = 0;
        SIZE_T HttpsUnsupportedAlpnCalls = 0;
        SIZE_T WebSocketConnectCalls = 0;
        SIZE_T WebSocketIpv4Calls = 0;
        SIZE_T WebSocketAnyCalls = 0;
        SIZE_T WebSocketPlainCalls = 0;
        SIZE_T WebSocketSecureCalls = 0;
        SIZE_T WebSocketEchoHostCalls = 0;
        SIZE_T WebSocketBinaryEchoHostCalls = 0;
        SIZE_T WebSocketVerifyCalls = 0;
        SIZE_T WebSocketVerifyWithStoreCalls = 0;
        SIZE_T WebSocketTls12MaxCalls = 0;
        SIZE_T WebSocketSendCalls = 0;
        SIZE_T WebSocketTextSendCalls = 0;
        SIZE_T WebSocketBinarySendCalls = 0;
        SIZE_T WebSocketNonFinalSendCalls = 0;
        SIZE_T WebSocketReceiveCalls = 0;
        SIZE_T WebSocketCloseCalls = 0;
        bool FailHttpByAddressFamily = false;
        KernelHttp::engine::KhAddressFamily HttpFailureAddressFamily = KernelHttp::engine::KhAddressFamily::Any;
        NTSTATUS HttpFailureStatus = STATUS_UNSUCCESSFUL;
        UCHAR WebSocketEcho[32] = {};
        SIZE_T WebSocketEchoLength = 0;
        KernelHttp::engine::KhWebSocketMessageType LastWebSocketSendType = KernelHttp::engine::KhWebSocketMessageType::Text;
        UCHAR LastWebSocketSendData[MaxWebSocketPayload] = {};
        UCHAR LastWebSocketReceiveData[MaxWebSocketPayload] = {};
        SIZE_T LastWebSocketSendLength = 0;
        bool HasLastWebSocketSend = false;
        bool WebSocketGreetingBeforeEcho = false;
        bool PendingWebSocketGreeting = false;
    };

    NTSTATUS HttpTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<SampleCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->HttpCalls;
        if (request->AddressFamily == KernelHttp::engine::KhAddressFamily::Ipv4) {
            ++capture->HttpIpv4Calls;
        }
        if (request->AddressFamily == KernelHttp::engine::KhAddressFamily::Ipv6) {
            ++capture->HttpIpv6Calls;
        }
        if (request->AddressFamily == KernelHttp::engine::KhAddressFamily::Any) {
            ++capture->HttpAnyCalls;
        }

        if (capture->FailHttpByAddressFamily &&
            request->AddressFamily == capture->HttpFailureAddressFamily) {
            return capture->HttpFailureStatus;
        }

        if (request->ConnectionPolicy == KernelHttp::engine::KhConnectionPolicy::ReuseOrCreate) {
            ++capture->HttpReuseCalls;
        }
        if (request->ConnectionPolicy == KernelHttp::engine::KhConnectionPolicy::NoPool) {
            ++capture->HttpNoPoolCalls;
        }
        if (request->ConnectionPolicy == KernelHttp::engine::KhConnectionPolicy::ForceNew) {
            ++capture->HttpForceNewCalls;
        }

        const bool isHttps = TextEqualsLiteral(request->Scheme, request->SchemeLength, "https");
        if (isHttps &&
            request->CertificatePolicy == KernelHttp::engine::KhCertificatePolicy::Verify) {
            ++capture->HttpsVerifyCalls;
            if (request->CertificateStore != nullptr) {
                ++capture->HttpsVerifyWithStoreCalls;
            }
        }
        if (isHttps &&
            request->CertificatePolicy == KernelHttp::engine::KhCertificatePolicy::NoVerify) {
            ++capture->HttpsNoVerifyCalls;
            if (request->CertificateStore == nullptr) {
                ++capture->HttpsNoVerifyWithoutStoreCalls;
            }
        }
        if (isHttps && TextEqualsLiteral(request->Alpn, request->AlpnLength, "http/1.1")) {
            ++capture->HttpsHttp11AlpnCalls;
        }
        if (isHttps && TextEqualsLiteral(request->Alpn, request->AlpnLength, "h2")) {
            ++capture->HttpsHttp2AlpnCalls;
        }
        if (isHttps && TextEqualsLiteral(request->Host, request->HostLength, "self-signed.badssl.com")) {
            return STATUS_TRUST_FAILURE;
        }
        if (isHttps && TextEqualsLiteral(request->Alpn, request->AlpnLength, "kernel-http-test")) {
            ++capture->HttpsUnsupportedAlpnCalls;
            return STATUS_NOT_SUPPORTED;
        }

        static const char redirectResponse[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: /httpbin/get\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char notFoundResponse[] =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 9\r\n"
            "Connection: close\r\n"
            "\r\n"
            "not found";
        static const char serverErrorResponse[] =
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 12\r\n"
            "Connection: close\r\n"
            "\r\n"
            "server error";
        static const char largeResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 96\r\n"
            "Connection: close\r\n"
            "\r\n"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            "cccccccccccccccccccccccccccccccc";

        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /httpbin/redirect/1 ")) {
            response->RawResponse = redirectResponse;
            response->RawResponseLength = sizeof(redirectResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }
        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /httpbin/status/404 ")) {
            response->RawResponse = notFoundResponse;
            response->RawResponseLength = sizeof(notFoundResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }
        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /httpbin/status/500 ")) {
            response->RawResponse = serverErrorResponse;
            response->RawResponseLength = sizeof(serverErrorResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }
        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /httpbin/bytes/65536 ")) {
            response->RawResponse = largeResponse;
            response->RawResponseLength = sizeof(largeResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }

        static const char rawResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "X-KernelHttp-Test: high-level\r\n"
            "Connection: close\r\n"
            "\r\n";
        response->RawResponse = rawResponse;
        response->RawResponseLength = sizeof(rawResponse) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketConnect(
        void* context,
        const KernelHttp::engine::KhTestWebSocketConnectRequest* request) noexcept
    {
        auto* capture = static_cast<SampleCapture*>(context);
        if (capture == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->WebSocketConnectCalls;
        if (request->AddressFamily == KernelHttp::engine::KhAddressFamily::Ipv4) {
            ++capture->WebSocketIpv4Calls;
        }
        if (request->AddressFamily == KernelHttp::engine::KhAddressFamily::Any) {
            ++capture->WebSocketAnyCalls;
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "ws")) {
            ++capture->WebSocketPlainCalls;
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "wss")) {
            ++capture->WebSocketSecureCalls;
        }
        if (TextEqualsLiteral(request->Host, request->HostLength, "ws.postman-echo.com")) {
            ++capture->WebSocketEchoHostCalls;
        }
        if (TextEqualsLiteral(request->Host, request->HostLength, "websocket-echo.com")) {
            ++capture->WebSocketBinaryEchoHostCalls;
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "wss") &&
            request->CertificatePolicy == KernelHttp::engine::KhCertificatePolicy::Verify) {
            ++capture->WebSocketVerifyCalls;
            if (request->CertificateStore != nullptr) {
                ++capture->WebSocketVerifyWithStoreCalls;
            }
            if (request->MaxTlsVersion == KernelHttp::engine::KhTlsVersion::Tls12) {
                ++capture->WebSocketTls12MaxCalls;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketSend(
        void* context,
        KernelHttp::engine::KH_WEBSOCKET websocket,
        KernelHttp::engine::KhWebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);

        auto* capture = static_cast<SampleCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if ((data == nullptr && dataLength != 0) ||
            dataLength > sizeof(capture->LastWebSocketSendData)) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->WebSocketSendCalls;
        if (type == KernelHttp::engine::KhWebSocketMessageType::Text) {
            ++capture->WebSocketTextSendCalls;
        }
        if (type == KernelHttp::engine::KhWebSocketMessageType::Binary) {
            ++capture->WebSocketBinarySendCalls;
        }
        if (!finalFragment) {
            ++capture->WebSocketNonFinalSendCalls;
        }
        capture->LastWebSocketSendType = type;
        capture->LastWebSocketSendLength = dataLength;
        if (dataLength != 0) {
            memcpy(capture->LastWebSocketSendData, data, dataLength);
        }
        capture->HasLastWebSocketSend = true;
        capture->PendingWebSocketGreeting = capture->WebSocketGreetingBeforeEcho;
        return STATUS_SUCCESS;
    }

    NTSTATUS WebSocketReceive(
        void* context,
        KernelHttp::engine::KH_WEBSOCKET websocket,
        KernelHttp::engine::KhTestWebSocketMessage* message) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<SampleCapture*>(context);
        if (capture == nullptr || message == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->WebSocketReceiveCalls;
        if (!capture->HasLastWebSocketSend) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (capture->PendingWebSocketGreeting) {
            static const UCHAR greeting[] = "Request served by high-level-test";
            capture->PendingWebSocketGreeting = false;
            message->Type = KernelHttp::engine::KhWebSocketMessageType::Text;
            message->Data = greeting;
            message->DataLength = sizeof(greeting) - 1;
            message->FinalFragment = true;
            return STATUS_SUCCESS;
        }

        if (capture->LastWebSocketSendLength > SampleCapture::MaxWebSocketPayload) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (capture->LastWebSocketSendLength != 0) {
            memcpy(
                capture->LastWebSocketReceiveData,
                capture->LastWebSocketSendData,
                capture->LastWebSocketSendLength);
        }

        message->Type = capture->LastWebSocketSendType;
        message->Data = capture->LastWebSocketReceiveData;
        message->DataLength = capture->LastWebSocketSendLength;
        message->FinalFragment = true;
        capture->HasLastWebSocketSend = false;
        return STATUS_SUCCESS;
    }

    void WebSocketClose(void* context, KernelHttp::engine::KH_WEBSOCKET websocket) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<SampleCapture*>(context);
        if (capture != nullptr) {
            ++capture->WebSocketCloseCalls;
        }
    }

    void TestLoadTimeSamplesCoverHighLevelSurface() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }
        capture.WebSocketGreetingBeforeEcho = true;

        KernelHttp::khttp::test::SetAsyncAutoRun(true);
        KernelHttp::khttp::test::SetHttpTransport(HttpTransport, &capture);
        KernelHttp::khttp::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        KernelHttp::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = KernelHttp::samples::RunHighLevelApiSamples(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &results);

        Expect(NT_SUCCESS(status), "load-time high-level samples succeed under test transport");
        Expect(NT_SUCCESS(results.SessionDefaultConfig.Status), "default session sample succeeds");
        Expect(NT_SUCCESS(results.SessionCustomConfig.Status), "custom session sample succeeds");
        Expect(capture.HttpCalls == 38, "all HTTP/HTTPS high-level samples are issued");
        Expect(capture.HttpIpv4Calls == 1, "dedicated HTTP IPv4 sample forces IPv4");
        Expect(capture.HttpIpv6Calls == 1, "IPv6 HTTP sample is issued");
        Expect(capture.HttpAnyCalls == 36, "general HTTP/HTTPS samples use default address family");
        Expect(capture.HttpNoPoolCalls >= 11, "no-pool connection policy samples are issued");
        Expect(capture.HttpForceNewCalls >= 1, "force-new connection policy sample is issued");
        Expect(capture.HttpsVerifyCalls == 4, "verified HTTPS samples are issued");
        Expect(
            capture.HttpsVerifyWithStoreCalls == capture.HttpsVerifyCalls,
            "verified HTTPS samples provide a certificate store");
        Expect(capture.HttpsNoVerifyCalls == 1, "no-verify HTTPS sample is issued");
        Expect(
            capture.HttpsNoVerifyWithoutStoreCalls == capture.HttpsNoVerifyCalls,
            "no-verify HTTPS sample does not require a certificate store");
        Expect(capture.HttpsHttp11AlpnCalls == 1, "HTTPS HTTP/1.1 ALPN sample is issued");
        Expect(capture.HttpsHttp2AlpnCalls == 1, "HTTPS HTTP/2 ALPN sample is issued");

        Expect(capture.WebSocketConnectCalls == 10, "all websocket connect variants are issued");
        Expect(capture.WebSocketIpv4Calls == 0, "websocket samples do not force IPv4");
        Expect(capture.WebSocketAnyCalls == 10, "websocket samples use system default address family");
        Expect(capture.WebSocketPlainCalls == 0, "plain ws URL samples are not part of the success matrix");
        Expect(capture.WebSocketSecureCalls == 10, "secure wss samples are issued");
        Expect(capture.WebSocketEchoHostCalls == 8, "websocket text samples use the Postman raw echo endpoint");
        Expect(capture.WebSocketBinaryEchoHostCalls == 2, "websocket binary samples use the binary echo endpoint");
        Expect(capture.WebSocketVerifyCalls == 10, "verified websocket samples are issued");
        Expect(capture.WebSocketVerifyWithStoreCalls == 10, "verified websocket samples provide a certificate store");
        Expect(capture.WebSocketTls12MaxCalls == 8, "explicit websocket secure samples cap TLS at 1.2 for endpoint compatibility");
        Expect(capture.WebSocketSendCalls == 7, "websocket send variants are issued");
        Expect(capture.WebSocketTextSendCalls == 5, "websocket text send variants are issued");
        Expect(capture.WebSocketBinarySendCalls == 2, "websocket binary send variants are issued");
        Expect(capture.WebSocketNonFinalSendCalls == 0, "websocket Ex send options keep sample messages complete");
        Expect(capture.WebSocketReceiveCalls == 14, "websocket receive skips greeting frames and reads echo frames");
        Expect(capture.WebSocketCloseCalls == 10, "each websocket connect path closes its handle");
        Expect(results.WebSocketEcho.BodyLength == capture.WebSocketEchoLength, "websocket echo sample receives body");
        Expect(results.WebSocketBinary.BodyLength == 4, "websocket binary sample receives binary echo body");
        Expect(NT_SUCCESS(results.WebSocketBinary.Status), "websocket binary sample validates binary echo body");
        Expect(results.WebSocketBinaryEx.BodyLength == 4, "websocket binary Ex sample receives binary echo body");
        Expect(NT_SUCCESS(results.WebSocketBinaryEx.Status), "websocket binary Ex sample validates binary echo body");
        Expect(results.WebSocketReceiveEx.BodyLength == capture.WebSocketEchoLength, "websocket receive callback records body");
        Expect(results.HttpAsyncCancel.StatusCode == 1, "async cancel sample marks operation canceled");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesReportIpv6Failure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        capture.FailHttpByAddressFamily = true;
        capture.HttpFailureAddressFamily = KernelHttp::engine::KhAddressFamily::Ipv6;
        capture.HttpFailureStatus = STATUS_UNSUCCESSFUL;

        KernelHttp::khttp::test::SetAsyncAutoRun(true);
        KernelHttp::khttp::test::SetHttpTransport(HttpTransport, &capture);
        KernelHttp::khttp::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        KernelHttp::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = KernelHttp::samples::RunHighLevelApiSamples(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &results);

        Expect(!NT_SUCCESS(status), "load-time high-level samples report IPv6 HTTP sample failure");
        Expect(results.HttpGetIpv6.Status == STATUS_UNSUCCESSFUL, "IPv6 HTTP sample stores failure status");
        Expect(NT_SUCCESS(results.HttpGetAny.Status), "Any address-family HTTP sample still runs after IPv6 failure");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestAdvancedScenarioSamplesCoverMissingSurface() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "advanced-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        KernelHttp::khttp::test::SetAsyncAutoRun(true);
        KernelHttp::khttp::test::SetHttpTransport(HttpTransport, &capture);
        KernelHttp::khttp::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        KernelHttp::samples::AdvancedScenarioSampleResults results = {};
        NTSTATUS status = KernelHttp::samples::RunAdvancedScenarioSamples(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            "certs\\cacert.pem",
            &results);

        Expect(NT_SUCCESS(status), "advanced scenario samples succeed under test transport");
        Expect(results.HttpRedirect.StatusCode == 302, "redirect sample observes 302");
        Expect(results.HttpNotFound.StatusCode == 404, "404 sample observes 404");
        Expect(results.HttpServerError.StatusCode == 500, "500 sample observes 500");
        Expect(results.HttpLargeResponse.BodyLength == 96, "large response sample records body");
        Expect(NT_SUCCESS(results.HttpResponseLimit.Status), "response limit sample treats buffer limit as expected");
        Expect(results.HttpLargePost.StatusCode == 200, "large POST sample succeeds");
        Expect(results.HttpConcurrentAsync.StatusCode == 3, "concurrent async sample completes all operations");
        Expect(NT_SUCCESS(results.HttpAsyncWaitTimeout.Status), "async wait timeout sample observes timeout");
        Expect(NT_SUCCESS(results.HttpsTrustFailure.Status), "trust failure sample treats STATUS_TRUST_FAILURE as expected");
        Expect(NT_SUCCESS(results.HttpsAlpnMismatch.Status), "ALPN mismatch sample treats STATUS_NOT_SUPPORTED as expected");
        Expect(capture.HttpsUnsupportedAlpnCalls == 0, "unsupported ALPN is rejected before transport");
        Expect(NT_SUCCESS(results.WebSocketClose.Status), "websocket close sample succeeds");
        Expect(NT_SUCCESS(results.WebSocketFragmentSend.Status), "websocket fragment send sample succeeds");
        Expect(capture.WebSocketNonFinalSendCalls == 1, "websocket fragment sample sends a non-final frame");
        Expect(capture.WebSocketCloseCalls >= 2, "advanced websocket samples close handles");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }
}

int main() noexcept
{
    KernelHttp::khttp::test::ResetCurrentIrql();
    TestLoadTimeSamplesCoverHighLevelSurface();
    TestLoadTimeSamplesReportIpv6Failure();
    TestAdvancedScenarioSamplesCoverMissingSurface();

    if (g_failed) {
        printf("high-level API tests FAILED\n");
        return 1;
    }

    printf("high-level API tests passed\n");
    return 0;
}
