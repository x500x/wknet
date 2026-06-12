#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/khttp/Test.h>
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/khttp/Request.h>
#include <KernelHttp/khttp/Response.h>
#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/khttp/WebSocket.h>
#include <KernelHttpTest/SampleStatus.h>

#include "samples/AdvancedScenarioSamples.h"
#include "samples/ExternalTrustStore.h"
#include "samples/HighLevelApiSamples.h"

#include <string.h>
#include <stdio.h>

#ifndef STATUS_HOST_UNREACHABLE
#define STATUS_HOST_UNREACHABLE ((NTSTATUS)0xC000023DL)
#endif

#ifndef STATUS_IO_TIMEOUT
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xC00000B5L)
#endif

#ifndef STATUS_NO_MATCH
#define STATUS_NO_MATCH ((NTSTATUS)0xC0000272L)
#endif

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
        SIZE_T HttpsDefaultAlpnOfferCalls = 0;
        SIZE_T HttpsNoAlpnOfferCalls = 0;
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
        SIZE_T WebSocketPostmanSha1CompatibilityCalls = 0;
        SIZE_T WebSocketBinaryModernPolicyCalls = 0;
        SIZE_T WebSocketSendCalls = 0;
        SIZE_T WebSocketTextSendCalls = 0;
        SIZE_T WebSocketBinarySendCalls = 0;
        SIZE_T WebSocketContinuationSendCalls = 0;
        SIZE_T WebSocketNonFinalSendCalls = 0;
        SIZE_T WebSocketReceiveCalls = 0;
        SIZE_T WebSocketCloseCalls = 0;
        bool FailHttpByAddressFamily = false;
        KernelHttp::engine::KhAddressFamily HttpFailureAddressFamily = KernelHttp::engine::KhAddressFamily::Any;
        NTSTATUS HttpFailureStatus = STATUS_UNSUCCESSFUL;
        bool FailWebSocketConnectFromCall = false;
        SIZE_T WebSocketConnectFailureStartCall = 0;
        NTSTATUS WebSocketConnectFailureStatus = STATUS_HOST_UNREACHABLE;
        UCHAR WebSocketEcho[32] = {};
        SIZE_T WebSocketEchoLength = 0;
        KernelHttp::engine::KhWebSocketMessageType LastWebSocketSendType = KernelHttp::engine::KhWebSocketMessageType::Text;
        KernelHttp::engine::KhWebSocketMessageType PendingWebSocketFragmentType =
            KernelHttp::engine::KhWebSocketMessageType::Text;
        UCHAR LastWebSocketSendData[MaxWebSocketPayload] = {};
        UCHAR LastWebSocketReceiveData[MaxWebSocketPayload] = {};
        UCHAR PendingWebSocketFragmentData[MaxWebSocketPayload] = {};
        SIZE_T LastWebSocketSendLength = 0;
        SIZE_T PendingWebSocketFragmentLength = 0;
        bool HasLastWebSocketSend = false;
        bool HasPendingWebSocketFragment = false;
        bool WebSocketGreetingBeforeEcho = false;
        bool PendingWebSocketGreeting = false;
    };

    constexpr SIZE_T LargePostBodyLength = 180 * 1024;

    SIZE_T BuildLargePostResponse(char* buffer, SIZE_T capacity) noexcept
    {
        static const char header[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 184320\r\n"
            "Connection: close\r\n"
            "\r\n";
        const SIZE_T headerLength = sizeof(header) - 1;
        if (buffer == nullptr || capacity < headerLength + LargePostBodyLength) {
            return 0;
        }

        memcpy(buffer, header, headerLength);
        for (SIZE_T index = 0; index < LargePostBodyLength; ++index) {
            buffer[headerLength + index] = static_cast<char>('a' + (index % 26));
        }
        return headerLength + LargePostBodyLength;
    }

    NTSTATUS SetLargePostResponse(KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        if (response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        static char rawResponse[LargePostBodyLength + 128] = {};
        static SIZE_T rawResponseLength = 0;
        if (rawResponseLength == 0) {
            rawResponseLength = BuildLargePostResponse(rawResponse, sizeof(rawResponse));
            if (rawResponseLength == 0) {
                return STATUS_BUFFER_TOO_SMALL;
            }
        }

        response->RawResponse = rawResponse;
        response->RawResponseLength = rawResponseLength;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    bool IsAdvancedLargePostRequest(const KernelHttp::engine::KhTestHttpTransportRequest* request) noexcept
    {
        return request != nullptr &&
            BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "POST /post ") &&
            BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "Content-Length: 65536\r\n");
    }

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
        if (isHttps && TextEqualsLiteral(request->OfferedAlpn, request->OfferedAlpnLength, "h2,http/1.1")) {
            ++capture->HttpsDefaultAlpnOfferCalls;
        }
        if (isHttps && request->OfferedAlpnLength == 0) {
            ++capture->HttpsNoAlpnOfferCalls;
        }
        if (isHttps &&
            BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /status/204 ")) {
            return STATUS_TRUST_FAILURE;
        }
        if (isHttps && TextEqualsLiteral(request->Alpn, request->AlpnLength, "kernel-http-test")) {
            ++capture->HttpsUnsupportedAlpnCalls;
            return STATUS_NOT_SUPPORTED;
        }

        static const char redirectResponse[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: /get\r\n"
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

        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /redirect/1 ")) {
            response->RawResponse = redirectResponse;
            response->RawResponseLength = sizeof(redirectResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }
        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /status/404 ")) {
            response->RawResponse = notFoundResponse;
            response->RawResponseLength = sizeof(notFoundResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }
        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /status/500 ")) {
            response->RawResponse = serverErrorResponse;
            response->RawResponseLength = sizeof(serverErrorResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }
        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /encoding/utf8 ")) {
            response->RawResponse = largeResponse;
            response->RawResponseLength = sizeof(largeResponse) - 1;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }
        if (IsAdvancedLargePostRequest(request)) {
            return SetLargePostResponse(response);
        }

        if (isHttps && TextEqualsLiteral(request->Alpn, request->AlpnLength, "h2")) {
            response->NegotiatedAlpn = "h2";
            response->NegotiatedAlpnLength = 2;
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

    NTSTATUS LargePostHttpTransport(
        void*,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        if (request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "POST /post ")) {
            return STATUS_INVALID_PARAMETER;
        }

        return SetLargePostResponse(response);
    }

    // The decoded body is far larger than the 16 KiB initial workspace DecodedBody buffer,
    // so chunked transfer-decoding exercises the same DecodedBody grow-retry path that a
    // gzip/deflate response over HTTP/1.1 hits on the public httpbin endpoint.
    constexpr SIZE_T ChunkedLargeBodyLength = 32 * 1024;
    constexpr SIZE_T CloseDelimitedLargeBodyLength = 32 * 1024;

    SIZE_T BuildChunkedLargeResponse(char* buffer, SIZE_T capacity) noexcept
    {
        static const char header[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n";
        const SIZE_T headerLength = sizeof(header) - 1;

        // One chunk: hex size line + body + CRLF, then the terminating 0-length chunk.
        char chunkSizeLine[16] = {};
        const int chunkSizeLineLength = snprintf(
            chunkSizeLine,
            sizeof(chunkSizeLine),
            "%zx\r\n",
            static_cast<size_t>(ChunkedLargeBodyLength));
        if (chunkSizeLineLength <= 0) {
            return 0;
        }

        static const char chunkTrailer[] = "\r\n0\r\n\r\n";
        const SIZE_T chunkTrailerLength = sizeof(chunkTrailer) - 1;
        const SIZE_T total = headerLength +
            static_cast<SIZE_T>(chunkSizeLineLength) +
            ChunkedLargeBodyLength +
            chunkTrailerLength;
        if (buffer == nullptr || capacity < total) {
            return 0;
        }

        SIZE_T cursor = 0;
        memcpy(buffer + cursor, header, headerLength);
        cursor += headerLength;
        memcpy(buffer + cursor, chunkSizeLine, static_cast<SIZE_T>(chunkSizeLineLength));
        cursor += static_cast<SIZE_T>(chunkSizeLineLength);
        for (SIZE_T index = 0; index < ChunkedLargeBodyLength; ++index) {
            buffer[cursor + index] = static_cast<char>('a' + (index % 26));
        }
        cursor += ChunkedLargeBodyLength;
        memcpy(buffer + cursor, chunkTrailer, chunkTrailerLength);
        cursor += chunkTrailerLength;
        return cursor;
    }

    NTSTATUS ChunkedLargeResponseHttpTransport(
        void*,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        if (request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        static char rawResponse[ChunkedLargeBodyLength + 256] = {};
        static SIZE_T rawResponseLength = 0;
        if (rawResponseLength == 0) {
            rawResponseLength = BuildChunkedLargeResponse(rawResponse, sizeof(rawResponse));
            if (rawResponseLength == 0) {
                return STATUS_BUFFER_TOO_SMALL;
            }
        }

        response->RawResponse = rawResponse;
        response->RawResponseLength = rawResponseLength;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    SIZE_T BuildCloseDelimitedLargeResponse(char* buffer, SIZE_T capacity) noexcept
    {
        static const char header[] =
            "HTTP/1.1 200 OK\r\n"
            "Connection: close\r\n"
            "\r\n";
        const SIZE_T headerLength = sizeof(header) - 1;
        if (buffer == nullptr || capacity < headerLength + CloseDelimitedLargeBodyLength) {
            return 0;
        }

        memcpy(buffer, header, headerLength);
        for (SIZE_T index = 0; index < CloseDelimitedLargeBodyLength; ++index) {
            buffer[headerLength + index] = static_cast<char>('A' + (index % 26));
        }
        return headerLength + CloseDelimitedLargeBodyLength;
    }

    NTSTATUS CloseDelimitedLargeResponseHttpTransport(
        void*,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        if (request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        static char rawResponse[CloseDelimitedLargeBodyLength + 128] = {};
        static SIZE_T rawResponseLength = 0;
        if (rawResponseLength == 0) {
            rawResponseLength = BuildCloseDelimitedLargeResponse(rawResponse, sizeof(rawResponse));
            if (rawResponseLength == 0) {
                return STATUS_BUFFER_TOO_SMALL;
            }
        }

        response->RawResponse = rawResponse;
        response->RawResponseLength = rawResponseLength;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    struct ProtocolAutodetectCapture final
    {
        SIZE_T Calls = 0;
        SIZE_T DefaultOfferCalls = 0;
        SIZE_T NoOfferCalls = 0;
        SIZE_T ExplicitHttp11Calls = 0;
        const char* NegotiatedAlpn = nullptr;
        SIZE_T NegotiatedAlpnLength = 0;
    };

    NTSTATUS ProtocolAutodetectTransport(
        void* context,
        const KernelHttp::engine::KhTestHttpTransportRequest* request,
        KernelHttp::engine::KhTestHttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<ProtocolAutodetectCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->Calls;
        if (TextEqualsLiteral(request->OfferedAlpn, request->OfferedAlpnLength, "h2,http/1.1")) {
            ++capture->DefaultOfferCalls;
        }
        if (request->OfferedAlpnLength == 0) {
            ++capture->NoOfferCalls;
        }
        if (TextEqualsLiteral(request->OfferedAlpn, request->OfferedAlpnLength, "http/1.1")) {
            ++capture->ExplicitHttp11Calls;
        }

        response->NegotiatedAlpn = capture->NegotiatedAlpn;
        response->NegotiatedAlpnLength = capture->NegotiatedAlpnLength;
        if (TextEqualsLiteral(capture->NegotiatedAlpn, capture->NegotiatedAlpnLength, "h2")) {
            return STATUS_SUCCESS;
        }

        static const char rawResponse[] =
            "HTTP/1.1 204 No Content\r\n"
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
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "ws")) {
            ++capture->WebSocketPlainCalls;
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "wss")) {
            ++capture->WebSocketSecureCalls;
        }
        if (TextEqualsLiteral(request->Host, request->HostLength, "ws.postman-echo.com")) {
            ++capture->WebSocketEchoHostCalls;
            if (request->Policy.Profile == KernelHttp::tls::TlsSecurityProfile::CompatibilityExplicit &&
                request->Policy.EnableTls12Sha1Signatures) {
                ++capture->WebSocketPostmanSha1CompatibilityCalls;
            }
        }
        if (TextEqualsLiteral(request->Host, request->HostLength, "websocket-echo.com")) {
            ++capture->WebSocketBinaryEchoHostCalls;
            if (request->Policy.Profile == KernelHttp::tls::TlsSecurityProfile::ModernDefault &&
                !request->Policy.EnableTls12Sha1Signatures) {
                ++capture->WebSocketBinaryModernPolicyCalls;
            }
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

        if (capture->FailWebSocketConnectFromCall &&
            capture->WebSocketConnectCalls >= capture->WebSocketConnectFailureStartCall) {
            return capture->WebSocketConnectFailureStatus;
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
        if (type == KernelHttp::engine::KhWebSocketMessageType::Continuation) {
            ++capture->WebSocketContinuationSendCalls;
        }
        if (!finalFragment) {
            ++capture->WebSocketNonFinalSendCalls;
        }

        if (type == KernelHttp::engine::KhWebSocketMessageType::Continuation) {
            if (!capture->HasPendingWebSocketFragment ||
                dataLength > SampleCapture::MaxWebSocketPayload - capture->PendingWebSocketFragmentLength) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            if (dataLength != 0) {
                memcpy(
                    capture->PendingWebSocketFragmentData + capture->PendingWebSocketFragmentLength,
                    data,
                    dataLength);
            }
            capture->PendingWebSocketFragmentLength += dataLength;

            if (finalFragment) {
                capture->LastWebSocketSendType = capture->PendingWebSocketFragmentType;
                capture->LastWebSocketSendLength = capture->PendingWebSocketFragmentLength;
                if (capture->LastWebSocketSendLength != 0) {
                    memcpy(
                        capture->LastWebSocketSendData,
                        capture->PendingWebSocketFragmentData,
                        capture->LastWebSocketSendLength);
                }
                capture->HasLastWebSocketSend = true;
                capture->HasPendingWebSocketFragment = false;
                capture->PendingWebSocketFragmentLength = 0;
                capture->PendingWebSocketGreeting = capture->WebSocketGreetingBeforeEcho;
            }
            return STATUS_SUCCESS;
        }

        if (capture->HasPendingWebSocketFragment) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (!finalFragment) {
            capture->PendingWebSocketFragmentType = type;
            capture->PendingWebSocketFragmentLength = dataLength;
            if (dataLength != 0) {
                memcpy(capture->PendingWebSocketFragmentData, data, dataLength);
            }
            capture->HasPendingWebSocketFragment = true;
            capture->HasLastWebSocketSend = false;
            return STATUS_SUCCESS;
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
        Expect(capture.HttpsDefaultAlpnOfferCalls >= 2, "HTTPS default samples offer h2 and HTTP/1.1 automatically");

        Expect(capture.WebSocketConnectCalls == 10, "all websocket connect variants are issued");
        Expect(capture.WebSocketIpv4Calls == 0, "websocket samples do not force IPv4");
        Expect(capture.WebSocketAnyCalls == 10, "websocket samples use system default address family");
        Expect(capture.WebSocketPlainCalls == 0, "plain ws URL samples are not part of the success matrix");
        Expect(capture.WebSocketSecureCalls == 10, "secure wss samples are issued");
        Expect(capture.WebSocketEchoHostCalls == 8, "websocket text samples use the Postman raw echo endpoint");
        Expect(capture.WebSocketBinaryEchoHostCalls == 2, "websocket binary samples use the binary echo endpoint");
        Expect(
            capture.WebSocketPostmanSha1CompatibilityCalls == capture.WebSocketEchoHostCalls,
            "Postman websocket samples pass explicit TLS 1.2 SHA1 signature compatibility policy");
        Expect(
            capture.WebSocketBinaryModernPolicyCalls == capture.WebSocketBinaryEchoHostCalls,
            "non-Postman websocket samples keep modern TLS policy");
        Expect(capture.WebSocketVerifyCalls == 10, "verified websocket samples are issued");
        Expect(capture.WebSocketVerifyWithStoreCalls == 10, "verified websocket samples provide a certificate store");
        Expect(capture.WebSocketTls12MaxCalls == 8, "explicit websocket secure samples cap TLS at 1.2 for endpoint compatibility");
        Expect(capture.WebSocketSendCalls == 7, "websocket send variants are issued");
        Expect(capture.WebSocketTextSendCalls == 5, "websocket text send variants are issued");
        Expect(capture.WebSocketBinarySendCalls == 2, "websocket binary send variants are issued");
        Expect(capture.WebSocketContinuationSendCalls == 0, "regular websocket samples do not need continuation frames");
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
        Expect(results.HttpAsyncCancel.BodyLength == 1, "async cancel sample waits for terminal operation state");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestExternalTrustStoreLoadsRepositoryBundle() noexcept
    {
        KernelHttp::samples::ExternalTrustStore trustStore = {};
        const NTSTATUS status = KernelHttp::samples::InitializeExternalTrustStore(
            trustStore,
            "certs\\cacert.pem");

        Expect(NT_SUCCESS(status), "external trust store loads repository cacert.pem");
        Expect(trustStore.BundleData != nullptr, "external trust store owns bundle data");
        Expect(trustStore.BundleDataLength != 0, "external trust store records bundle length");
        Expect(trustStore.Store.AuthorityBundleCount() == 1, "external trust store registers one authority bundle");
        KernelHttp::samples::ResetExternalTrustStore(trustStore);
    }

    void TestPublicEndpointStatusClassification() noexcept
    {
        using KernelHttp::samples::IsPublicEndpointDiagnosticStatus;

        Expect(IsPublicEndpointDiagnosticStatus(STATUS_IO_TIMEOUT), "timeout is a public endpoint diagnostic status");
        Expect(IsPublicEndpointDiagnosticStatus(STATUS_NO_MATCH), "DNS no-match is a public endpoint diagnostic status");
        Expect(
            IsPublicEndpointDiagnosticStatus(STATUS_CONNECTION_RESET),
            "connection reset is a public endpoint diagnostic status");
        Expect(
            !IsPublicEndpointDiagnosticStatus(STATUS_INVALID_NETWORK_RESPONSE),
            "protocol errors remain fatal");
        Expect(!IsPublicEndpointDiagnosticStatus(STATUS_INVALID_PARAMETER), "API misuse remains fatal");
        Expect(!IsPublicEndpointDiagnosticStatus(STATUS_TRUST_FAILURE), "certificate trust failures remain fatal");
    }

    void TestPublicDiagnosticMergeKeepsAggregateSuccessForEnvironmentFailures() noexcept
    {
        NTSTATUS aggregate = STATUS_SUCCESS;
        KernelHttp::samples::MergePublicDiagnosticSampleStatus(aggregate, STATUS_IO_TIMEOUT);
        Expect(aggregate == STATUS_SUCCESS, "public timeout does not poison aggregate");

        KernelHttp::samples::MergePublicDiagnosticSampleStatus(aggregate, STATUS_INVALID_NETWORK_RESPONSE);
        Expect(aggregate == STATUS_INVALID_NETWORK_RESPONSE, "protocol error poisons aggregate");
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

    void TestLoadTimeSamplesIgnoreIpv4EnvironmentFailure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        capture.FailHttpByAddressFamily = true;
        capture.HttpFailureAddressFamily = KernelHttp::engine::KhAddressFamily::Ipv4;
        capture.HttpFailureStatus = STATUS_IO_TIMEOUT;

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

        Expect(NT_SUCCESS(status), "load-time high-level samples ignore IPv4 environment timeout");
        Expect(results.HttpGetIpv4.Status == STATUS_IO_TIMEOUT, "IPv4 HTTP sample records environment timeout");
        Expect(NT_SUCCESS(results.HttpGetAny.Status), "Any address-family HTTP sample still runs after IPv4 timeout");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnoreIpv6EnvironmentFailure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        capture.FailHttpByAddressFamily = true;
        capture.HttpFailureAddressFamily = KernelHttp::engine::KhAddressFamily::Ipv6;
        capture.HttpFailureStatus = STATUS_IO_TIMEOUT;

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

        Expect(NT_SUCCESS(status), "load-time high-level samples ignore IPv6 environment timeout");
        Expect(results.HttpGetIpv6.Status == STATUS_IO_TIMEOUT, "IPv6 HTTP sample records environment timeout");
        Expect(NT_SUCCESS(results.HttpGetAny.Status), "Any address-family HTTP sample still runs after IPv6 timeout");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnoreRepeatedPublicWebSocketConnectFailures() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }
        capture.FailWebSocketConnectFromCall = true;
        capture.WebSocketConnectFailureStartCall = 2;
        capture.WebSocketConnectFailureStatus = STATUS_HOST_UNREACHABLE;

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

        Expect(NT_SUCCESS(status), "load-time samples keep succeeding after one public websocket success");
        Expect(NT_SUCCESS(results.WebSocketEcho.Status), "first websocket sample succeeds");
        Expect(
            results.WebSocketUrlConnect.Status == STATUS_HOST_UNREACHABLE,
            "repeated websocket URL connect stores transient failure");
        Expect(
            results.WebSocketConnectEx.Status == STATUS_HOST_UNREACHABLE,
            "repeated websocket ConnectEx stores transient failure");
        Expect(capture.WebSocketConnectCalls == 10, "all websocket connect samples are still issued");
        Expect(capture.WebSocketSendCalls == 1, "only validated websocket sample sends a message");
        Expect(capture.WebSocketCloseCalls == 1, "only validated websocket sample closes a live handle");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnorePublicWebSocketNoMatchFailures() noexcept
    {
        SampleCapture capture = {};
        capture.FailWebSocketConnectFromCall = true;
        capture.WebSocketConnectFailureStartCall = 1;
        capture.WebSocketConnectFailureStatus = STATUS_NO_MATCH;

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

        Expect(NT_SUCCESS(status), "load-time samples treat public websocket DNS misses as diagnostic");
        Expect(results.WebSocketEcho.Status == STATUS_NO_MATCH, "first websocket sample records DNS no-match");
        Expect(results.WebSocketUrlConnect.Status == STATUS_NO_MATCH, "URL websocket sample records DNS no-match");
        Expect(results.WebSocketConnectEx.Status == STATUS_NO_MATCH, "ConnectEx websocket sample records DNS no-match");
        Expect(capture.WebSocketConnectCalls == 10, "all websocket connect samples are still issued after DNS no-match");
        Expect(capture.WebSocketSendCalls == 0, "websocket DNS no-match samples do not send messages");
        Expect(capture.WebSocketCloseCalls == 0, "websocket DNS no-match samples do not close absent handles");

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
        Expect(results.HttpRedirect.StatusCode == 200, "redirect sample follows to 200");
        Expect(results.HttpRedirectDisabled.StatusCode == 302, "disabled redirect sample observes 302");
        Expect(results.HttpNotFound.StatusCode == 404, "404 sample observes 404");
        Expect(results.HttpServerError.StatusCode == 500, "500 sample observes 500");
        Expect(results.HttpLargeResponse.BodyLength == 96, "large response sample records body");
        Expect(NT_SUCCESS(results.HttpResponseLimit.Status), "response limit sample treats buffer limit as expected");
        Expect(results.HttpLargePost.StatusCode == 200, "large POST sample succeeds");
        Expect(results.HttpLargePost.BodyLength == LargePostBodyLength, "large POST sample records bounded response body");
        Expect(results.HttpConcurrentAsync.StatusCode == 3, "concurrent async sample completes all operations");
        Expect(NT_SUCCESS(results.HttpAsyncWaitTimeout.Status), "async wait timeout sample observes timeout");
        Expect(results.HttpAsyncWaitTimeout.BodyLength == 1, "async wait timeout sample drains canceled operation");
        Expect(NT_SUCCESS(results.HttpsTrustFailure.Status), "trust failure sample treats STATUS_TRUST_FAILURE as expected");
        Expect(
            results.HttpsTrustFailure.StatusCode == static_cast<ULONG>(STATUS_TRUST_FAILURE),
            "trust failure sample records raw STATUS_TRUST_FAILURE");
        Expect(NT_SUCCESS(results.HttpsAlpnMismatch.Status), "ALPN mismatch sample treats STATUS_NOT_SUPPORTED as expected");
        Expect(
            results.HttpsAlpnMismatch.StatusCode == static_cast<ULONG>(STATUS_NOT_SUPPORTED),
            "ALPN mismatch sample records raw STATUS_NOT_SUPPORTED");
        Expect(capture.HttpsUnsupportedAlpnCalls == 0, "unsupported ALPN is rejected before transport");
        Expect(NT_SUCCESS(results.WebSocketClose.Status), "websocket close sample succeeds");
        Expect(NT_SUCCESS(results.WebSocketFragmentSend.Status), "websocket fragment send sample succeeds");
        Expect(
            capture.WebSocketPostmanSha1CompatibilityCalls == 2,
            "advanced Postman websocket samples pass explicit TLS 1.2 SHA1 signature compatibility policy");
        Expect(capture.WebSocketNonFinalSendCalls == 1, "websocket fragment sample sends a non-final frame");
        Expect(capture.WebSocketContinuationSendCalls == 1, "websocket fragment sample completes with a continuation frame");
        Expect(capture.WebSocketCloseCalls >= 2, "advanced websocket samples close handles");

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestHighLevelPostLargeResponseHonorsMaxResponseBytes() noexcept
    {
        KernelHttp::khttp::test::SetAsyncAutoRun(true);
        KernelHttp::khttp::test::SetHttpTransport(LargePostHttpTransport, nullptr);

        static const char url[] = "https://httpbin.dev/post";
        static const UCHAR requestBody[] = { 'x' };

        KernelHttp::khttp::SessionConfig config = KernelHttp::khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 256 * 1024;
        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for large POST response");

        KernelHttp::khttp::Response* response = nullptr;
        status = KernelHttp::khttp::Post(
            session,
            url,
            sizeof(url) - 1,
            requestBody,
            sizeof(requestBody),
            &response);
        Expect(NT_SUCCESS(status), "khttp::Post aggregates large response within MaxResponseBytes");
        Expect(
            KernelHttp::khttp::ResponseBodyLength(response) == LargePostBodyLength,
            "khttp::Post large response body length matches");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        config = KernelHttp::khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 64 * 1024;
        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for limited large POST response");

        response = nullptr;
        status = KernelHttp::khttp::Post(
            session,
            url,
            sizeof(url) - 1,
            requestBody,
            sizeof(requestBody),
            &response);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "khttp::Post rejects large response above MaxResponseBytes");
        Expect(response == nullptr, "limited khttp::Post leaves response null");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttp11DecodedBodyGrowsBeyondInitialBuffer() noexcept
    {
        KernelHttp::khttp::test::SetAsyncAutoRun(true);
        KernelHttp::khttp::test::SetHttpTransport(ChunkedLargeResponseHttpTransport, nullptr);

        static const char url[] = "https://httpbin.dev/get";

        KernelHttp::khttp::SessionConfig config = KernelHttp::khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 256 * 1024;
        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTP/1.1 decoded-body grow test");

        KernelHttp::khttp::Response* response = nullptr;
        status = KernelHttp::khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            NT_SUCCESS(status),
            "khttp::Get grows DecodedBody for HTTP/1.1 chunked response larger than initial buffer");
        Expect(
            KernelHttp::khttp::ResponseBodyLength(response) == ChunkedLargeBodyLength,
            "khttp::Get HTTP/1.1 decoded body length matches the chunked payload");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        config = KernelHttp::khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 16 * 1024;
        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for limited HTTP/1.1 decoded-body test");

        response = nullptr;
        status = KernelHttp::khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            status == STATUS_BUFFER_TOO_SMALL,
            "khttp::Get rejects HTTP/1.1 decoded body above MaxResponseBytes");
        Expect(response == nullptr, "limited HTTP/1.1 decoded-body request leaves response null");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttp11CloseDelimitedDecodedBodyGrowsBeyondInitialBuffer() noexcept
    {
        KernelHttp::khttp::test::SetAsyncAutoRun(true);
        KernelHttp::khttp::test::SetHttpTransport(CloseDelimitedLargeResponseHttpTransport, nullptr);

        static const char url[] = "http://example.test/close-delimited";

        KernelHttp::khttp::SessionConfig config = KernelHttp::khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 256 * 1024;
        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for close-delimited decoded-body grow test");

        KernelHttp::khttp::Response* response = nullptr;
        status = KernelHttp::khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            NT_SUCCESS(status),
            "khttp::Get grows DecodedBody for HTTP/1.1 close-delimited response");
        Expect(
            KernelHttp::khttp::ResponseBodyLength(response) == CloseDelimitedLargeBodyLength,
            "khttp::Get close-delimited decoded body length matches payload");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttpsProtocolAutodetectUsesNegotiatedAlpn() noexcept
    {
        KernelHttp::khttp::test::SetAsyncAutoRun(true);

        static const char url[] = "https://example.test/get";

        ProtocolAutodetectCapture capture = {};
        capture.NegotiatedAlpn = "h2";
        capture.NegotiatedAlpnLength = 2;
        KernelHttp::khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        KernelHttp::khttp::SessionConfig config = KernelHttp::khttp::DefaultSessionConfig();
        KernelHttp::khttp::Session* session = nullptr;
        NTSTATUS status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTPS autodetect h2 test");

        KernelHttp::khttp::Response* response = nullptr;
        status = KernelHttp::khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "default HTTPS request succeeds when h2 is negotiated");
        Expect(KernelHttp::khttp::ResponseStatusCode(response) == 200, "h2 negotiated response returns success status");
        Expect(capture.DefaultOfferCalls == 1, "default HTTPS request offers h2 and HTTP/1.1");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        capture = {};
        capture.NegotiatedAlpn = "http/1.1";
        capture.NegotiatedAlpnLength = 8;
        KernelHttp::khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTPS autodetect HTTP/1.1 test");

        response = nullptr;
        status = KernelHttp::khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "default HTTPS request falls back to HTTP/1.1 when negotiated");
        Expect(KernelHttp::khttp::ResponseStatusCode(response) == 204, "HTTP/1.1 negotiated response is parsed");
        Expect(capture.DefaultOfferCalls == 1, "HTTP/1.1 fallback still uses default ALPN offer");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        capture = {};
        capture.NegotiatedAlpn = "http/1.1";
        capture.NegotiatedAlpnLength = 8;
        KernelHttp::khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for explicit HTTP/1.1 ALPN test");

        KernelHttp::khttp::Request* request = nullptr;
        status = KernelHttp::khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for explicit HTTP/1.1 ALPN test");
        KernelHttp::khttp::TlsConfig tls = KernelHttp::khttp::DefaultTlsConfig();
        tls.Alpn = "http/1.1";
        tls.AlpnLength = 8;
        if (NT_SUCCESS(status)) {
            status = KernelHttp::khttp::RequestSetUrl(request, url, sizeof(url) - 1);
        }
        if (NT_SUCCESS(status)) {
            status = KernelHttp::khttp::RequestSetTls(request, &tls);
        }
        response = nullptr;
        if (NT_SUCCESS(status)) {
            status = KernelHttp::khttp::Send(session, request, &response);
        }
        Expect(NT_SUCCESS(status), "explicit HTTP/1.1 ALPN request succeeds");
        Expect(capture.ExplicitHttp11Calls == 1, "explicit HTTP/1.1 request offers only HTTP/1.1");
        Expect(capture.DefaultOfferCalls == 0, "explicit HTTP/1.1 request does not use automatic ALPN list");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::RequestRelease(request);
        KernelHttp::khttp::SessionClose(session);

        config = KernelHttp::khttp::DefaultSessionConfig();
        config.Tls.PreferHttp2 = false;
        capture = {};
        capture.NegotiatedAlpn = nullptr;
        capture.NegotiatedAlpnLength = 0;
        KernelHttp::khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = KernelHttp::khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds when PreferHttp2 is disabled");

        response = nullptr;
        status = KernelHttp::khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "HTTPS request succeeds without automatic ALPN offer when disabled");
        Expect(capture.NoOfferCalls == 1, "PreferHttp2=false sends no automatic ALPN offer");
        KernelHttp::khttp::ResponseRelease(response);
        KernelHttp::khttp::SessionClose(session);

        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelTlsVersionFallbackPolicy() noexcept
    {
        using KernelHttp::engine::KhTlsVersion;
        constexpr ULONG TlsFailureVersionNegotiation = 1;
        constexpr ULONG TlsFailurePeerAlert = 7;

        Expect(
            KernelHttp::khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls13,
                TlsFailureVersionNegotiation),
            "default TLS 1.2-1.3 policy treats version negotiation as TLS 1.2 confirmation candidate");
        Expect(
            !KernelHttp::khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls13,
                KhTlsVersion::Tls13,
                TlsFailureVersionNegotiation),
            "TLS 1.3-only policy does not trigger TLS 1.2 fallback");
        Expect(
            !KernelHttp::khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls13,
                TlsFailurePeerAlert),
            "non-version TLS failures do not trigger TLS 1.2 fallback");
    }

    void TestWebSocketReceiveHonorsPerCallMessageLimit() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "message-limit";
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for websocket receive limit test");

        KernelHttp::khttp::WebSocket* ws = nullptr;
        KernelHttp::khttp::WsConnectConfig wsConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        wsConfig.Url = "wss://ws.postman-echo.com/raw";
        wsConfig.UrlLength = strlen(wsConfig.Url);
        status = KernelHttp::khttp::WsConnect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for websocket receive limit test");

        status = KernelHttp::khttp::WsSendText(ws, echo, sizeof(echo) - 1);
        Expect(NT_SUCCESS(status), "WsSendText succeeds for websocket receive limit test");

        KernelHttp::khttp::WsMessage message = {};
        KernelHttp::khttp::WsReceiveOptions receiveOptions = {};
        receiveOptions.MaxMessageBytes = 4;
        status = KernelHttp::khttp::WsReceiveEx(ws, &receiveOptions, &message);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "WsReceiveEx rejects message above per-call MaxMessageBytes");

        KernelHttp::khttp::WsClose(ws);
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestHighLevelWebSocketPublicValidation() noexcept
    {
        SampleCapture capture = {};
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
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for high-level websocket validation");

        KernelHttp::khttp::WebSocket* ws = nullptr;
        KernelHttp::khttp::WsConnectConfig invalidConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        invalidConfig.Url = "wss://ws.postman-echo.com/raw";
        invalidConfig.UrlLength = strlen(invalidConfig.Url);
        invalidConfig.Subprotocol = "bad token";
        invalidConfig.SubprotocolLength = strlen(invalidConfig.Subprotocol);
        status = KernelHttp::khttp::WsConnect(session, &invalidConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsConnect rejects invalid subprotocol");
        Expect(ws == nullptr, "high-level invalid subprotocol leaves websocket null");
        Expect(capture.WebSocketConnectCalls == 0, "high-level invalid subprotocol does not hit transport");

        KernelHttp::khttp::WsConnectConfig validConfig = KernelHttp::khttp::DefaultWsConnectConfig();
        validConfig.Url = "wss://ws.postman-echo.com/raw";
        validConfig.UrlLength = strlen(validConfig.Url);
        status = KernelHttp::khttp::WsConnect(session, &validConfig, &ws);
        Expect(NT_SUCCESS(status), "high-level WsConnect succeeds for validation");

        const unsigned char invalidText[] = { 0xc3, 0x28 };
        status = KernelHttp::khttp::WsSendText(
            ws,
            reinterpret_cast<const char*>(invalidText),
            sizeof(invalidText));
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsSendText rejects invalid UTF-8");
        Expect(capture.WebSocketSendCalls == 0, "high-level invalid text does not hit transport");

        const UCHAR invalidReason[] = { 0xc3, 0x28 };
        status = KernelHttp::khttp::WsCloseEx(ws, 1000, invalidReason, sizeof(invalidReason));
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsCloseEx rejects invalid UTF-8 reason");
        Expect(capture.WebSocketCloseCalls == 0, "high-level invalid close reason does not close transport");

        KernelHttp::khttp::WsClose(ws);
        Expect(capture.WebSocketCloseCalls == 1, "high-level cleanup close reaches transport once");
        KernelHttp::khttp::SessionClose(session);
        KernelHttp::khttp::test::SetHttpTransport(nullptr, nullptr);
        KernelHttp::khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }
}

int main() noexcept
{
    KernelHttp::khttp::test::ResetCurrentIrql();
    TestExternalTrustStoreLoadsRepositoryBundle();
    TestPublicEndpointStatusClassification();
    TestPublicDiagnosticMergeKeepsAggregateSuccessForEnvironmentFailures();
    TestLoadTimeSamplesCoverHighLevelSurface();
    TestLoadTimeSamplesReportIpv6Failure();
    TestLoadTimeSamplesIgnoreIpv4EnvironmentFailure();
    TestLoadTimeSamplesIgnoreIpv6EnvironmentFailure();
    TestLoadTimeSamplesIgnoreRepeatedPublicWebSocketConnectFailures();
    TestLoadTimeSamplesIgnorePublicWebSocketNoMatchFailures();
    TestAdvancedScenarioSamplesCoverMissingSurface();
    TestHighLevelPostLargeResponseHonorsMaxResponseBytes();
    TestHighLevelHttp11DecodedBodyGrowsBeyondInitialBuffer();
    TestHighLevelHttp11CloseDelimitedDecodedBodyGrowsBeyondInitialBuffer();
    TestHighLevelHttpsProtocolAutodetectUsesNegotiatedAlpn();
    TestHighLevelTlsVersionFallbackPolicy();
    TestWebSocketReceiveHonorsPerCallMessageLimit();
    TestHighLevelWebSocketPublicValidation();

    if (g_failed) {
        printf("high-level API tests FAILED\n");
        return 1;
    }

    printf("high-level API tests passed\n");
    return 0;
}
