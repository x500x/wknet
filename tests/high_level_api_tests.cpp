#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/khttp/Session.h"
#include "../src/KernelHttp/khttp/Test.h"
#include "../src/KernelHttp/samples/HighLevelApiSamples.h"

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

    struct SampleCapture final
    {
        SIZE_T HttpCalls = 0;
        SIZE_T HttpIpv4Calls = 0;
        SIZE_T HttpAnyCalls = 0;
        SIZE_T HttpsVerifyCalls = 0;
        SIZE_T HttpsVerifyWithStoreCalls = 0;
        SIZE_T HttpsNoVerifyCalls = 0;
        SIZE_T HttpsNoVerifyWithoutStoreCalls = 0;
        SIZE_T WebSocketConnectCalls = 0;
        SIZE_T WebSocketIpv4Calls = 0;
        SIZE_T WebSocketAnyCalls = 0;
        SIZE_T WebSocketVerifyCalls = 0;
        SIZE_T WebSocketVerifyWithStoreCalls = 0;
        SIZE_T WebSocketTls12MaxCalls = 0;
        UCHAR WebSocketEcho[32] = {};
        SIZE_T WebSocketEchoLength = 0;
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
        if (request->AddressFamily == KernelHttp::engine::KhAddressFamily::Any) {
            ++capture->HttpAnyCalls;
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

        static const char rawResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
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
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(websocket);
        UNREFERENCED_PARAMETER(type);
        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(dataLength);
        UNREFERENCED_PARAMETER(finalFragment);
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

        message->Type = KernelHttp::engine::KhWebSocketMessageType::Text;
        message->Data = capture->WebSocketEcho;
        message->DataLength = capture->WebSocketEchoLength;
        message->FinalFragment = true;
        return STATUS_SUCCESS;
    }

    void WebSocketClose(void* context, KernelHttp::engine::KH_WEBSOCKET websocket) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(websocket);
    }

    void TestLoadTimeSamplesForceIpv4() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-khttp";
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

        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        KernelHttp::samples::HighLevelApiSampleResults results = {};
        if (NT_SUCCESS(status)) {
            status = KernelHttp::samples::RunHighLevelApiSamples(session, &results);
        }

        Expect(NT_SUCCESS(status), "load-time high-level samples succeed under test transport");
        Expect(capture.HttpCalls != 0, "HTTP/HTTPS sample requests are issued");
        Expect(capture.HttpIpv4Calls == capture.HttpCalls, "all HTTP/HTTPS samples force IPv4");
        Expect(capture.HttpAnyCalls == 0, "HTTP/HTTPS samples do not use Any address family");
        Expect(capture.HttpsVerifyCalls == 2, "verified HTTPS samples are issued");
        Expect(
            capture.HttpsVerifyWithStoreCalls == capture.HttpsVerifyCalls,
            "verified HTTPS samples provide a certificate store");
        Expect(capture.HttpsNoVerifyCalls == 1, "no-verify HTTPS sample is issued");
        Expect(
            capture.HttpsNoVerifyWithoutStoreCalls == capture.HttpsNoVerifyCalls,
            "no-verify HTTPS sample does not require a certificate store");
        Expect(capture.WebSocketConnectCalls == 1, "websocket sample connects once");
        Expect(capture.WebSocketIpv4Calls == 1, "websocket sample forces IPv4");
        Expect(capture.WebSocketAnyCalls == 0, "websocket sample does not use Any address family");
        Expect(capture.WebSocketVerifyCalls == 1, "verified websocket sample is issued");
        Expect(capture.WebSocketVerifyWithStoreCalls == 1, "verified websocket sample provides a certificate store");
        Expect(capture.WebSocketTls12MaxCalls == 1, "websocket sample caps TLS at 1.2 for endpoint compatibility");
        Expect(results.WebSocketEcho.BodyLength == capture.WebSocketEchoLength, "websocket sample receives echo body");

        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }
}

int main() noexcept
{
    KernelHttp::khttp::test::ResetCurrentIrql();
    TestLoadTimeSamplesForceIpv4();

    if (g_failed) {
        printf("high-level API tests FAILED\n");
        return 1;
    }

    printf("high-level API tests passed\n");
    return 0;
}
