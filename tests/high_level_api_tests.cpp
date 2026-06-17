#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/khttp/Test.h>
#include <KernelHttp/khttp/Http.h>
#include <KernelHttp/khttp/Request.h>
#include <KernelHttp/khttp/Response.h>
#include <KernelHttp/khttp/Session.h>
#include <KernelHttp/kws/WebSocket.h>
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
        SIZE_T WebSocketVerifyCalls = 0;
        SIZE_T WebSocketVerifyWithStoreCalls = 0;
        SIZE_T WebSocketTls12ToTls13Calls = 0;
        SIZE_T WebSocketTls13OnlyCalls = 0;
        SIZE_T WebSocketSha1CompatibilityCalls = 0;
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
        bool FailHttpsTrustFailureRequest = false;
        NTSTATUS HttpsTrustFailureRequestStatus = STATUS_NO_MATCH;
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
            if (capture->FailHttpsTrustFailureRequest) {
                return capture->HttpsTrustFailureRequestStatus;
            }
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
        if (TextEqualsLiteral(request->Host, request->HostLength, "websocket-echo.com")) {
            ++capture->WebSocketEchoHostCalls;
            if (request->Policy.Profile == KernelHttp::tls::TlsSecurityProfile::ModernDefault &&
                !request->Policy.EnableTls12Sha1Signatures) {
                ++capture->WebSocketBinaryModernPolicyCalls;
            }
            if (request->Policy.EnableTls12Sha1Signatures) {
                ++capture->WebSocketSha1CompatibilityCalls;
            }
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "wss") &&
            request->CertificatePolicy == KernelHttp::engine::KhCertificatePolicy::Verify) {
            ++capture->WebSocketVerifyCalls;
            if (request->CertificateStore != nullptr) {
                ++capture->WebSocketVerifyWithStoreCalls;
            }
            if (TextEqualsLiteral(request->Host, request->HostLength, "websocket-echo.com") &&
                request->MinTlsVersion == KernelHttp::engine::KhTlsVersion::Tls12 &&
                request->MaxTlsVersion == KernelHttp::engine::KhTlsVersion::Tls13) {
                ++capture->WebSocketTls12ToTls13Calls;
            }
            if (TextEqualsLiteral(request->Host, request->HostLength, "websocket-echo.com") &&
                request->MinTlsVersion == KernelHttp::engine::KhTlsVersion::Tls13 &&
                request->MaxTlsVersion == KernelHttp::engine::KhTlsVersion::Tls13) {
                ++capture->WebSocketTls13OnlyCalls;
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

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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

        Expect(capture.WebSocketConnectCalls == 11, "all websocket connect variants are issued");
        Expect(capture.WebSocketIpv4Calls == 0, "websocket samples do not force IPv4");
        Expect(capture.WebSocketAnyCalls == 11, "websocket samples use system default address family");
        Expect(capture.WebSocketPlainCalls == 0, "plain ws URL samples are not part of the success matrix");
        Expect(capture.WebSocketSecureCalls == 11, "secure wss samples are issued");
        Expect(capture.WebSocketEchoHostCalls == 11, "websocket samples use the modern echo endpoint");
        Expect(
            capture.WebSocketSha1CompatibilityCalls == 0,
            "websocket samples do not enable endpoint-specific SHA1 compatibility");
        Expect(
            capture.WebSocketTls12ToTls13Calls == 10,
            "websocket samples keep the default TLS 1.2 through 1.3 range except the TLS 1.3-only case");
        Expect(
            capture.WebSocketBinaryModernPolicyCalls == capture.WebSocketEchoHostCalls,
            "websocket samples keep modern TLS policy");
        Expect(capture.WebSocketTls13OnlyCalls == 1, "TLS 1.3-only websocket sample targets a TLS 1.3-capable endpoint");
        Expect(capture.WebSocketVerifyCalls == 11, "verified websocket samples are issued");
        Expect(capture.WebSocketVerifyWithStoreCalls == 11, "verified websocket samples provide a certificate store");
        Expect(capture.WebSocketSendCalls == 8, "websocket send variants are issued");
        Expect(capture.WebSocketTextSendCalls == 6, "websocket text send variants are issued");
        Expect(capture.WebSocketBinarySendCalls == 2, "websocket binary send variants are issued");
        Expect(capture.WebSocketContinuationSendCalls == 0, "regular websocket samples do not need continuation frames");
        Expect(capture.WebSocketNonFinalSendCalls == 0, "websocket Ex send options keep sample messages complete");
        Expect(capture.WebSocketReceiveCalls == 16, "websocket receive skips greeting frames and reads echo frames");
        Expect(capture.WebSocketCloseCalls == 11, "each websocket connect path closes its handle");
        Expect(results.WebSocketEcho.BodyLength == capture.WebSocketEchoLength, "websocket echo sample receives body");
        Expect(results.WebSocketBinary.BodyLength == 4, "websocket binary sample receives binary echo body");
        Expect(NT_SUCCESS(results.WebSocketBinary.Status), "websocket binary sample validates binary echo body");
        Expect(results.WebSocketBinaryEx.BodyLength == 4, "websocket binary Ex sample receives binary echo body");
        Expect(NT_SUCCESS(results.WebSocketBinaryEx.Status), "websocket binary Ex sample validates binary echo body");
        Expect(results.WebSocketTls13Only.BodyLength == capture.WebSocketEchoLength, "TLS 1.3 websocket sample receives text echo body");
        Expect(NT_SUCCESS(results.WebSocketTls13Only.Status), "TLS 1.3 websocket sample validates text echo body");
        Expect(results.WebSocketReceiveEx.BodyLength == capture.WebSocketEchoLength, "websocket receive callback records body");
        Expect(results.HttpAsyncCancel.StatusCode == 1, "async cancel sample marks operation canceled");
        Expect(results.HttpAsyncCancel.BodyLength == 1, "async cancel sample waits for terminal operation state");

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
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

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
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

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
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

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
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

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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
        Expect(capture.WebSocketConnectCalls == 11, "all websocket connect samples are still issued");
        Expect(capture.WebSocketSendCalls == 1, "only validated websocket sample sends a message");
        Expect(capture.WebSocketCloseCalls == 1, "only validated websocket sample closes a live handle");

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnorePublicWebSocketNoMatchFailures() noexcept
    {
        SampleCapture capture = {};
        capture.FailWebSocketConnectFromCall = true;
        capture.WebSocketConnectFailureStartCall = 1;
        capture.WebSocketConnectFailureStatus = STATUS_NO_MATCH;

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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
        Expect(capture.WebSocketConnectCalls == 11, "all websocket connect samples are still issued after DNS no-match");
        Expect(capture.WebSocketSendCalls == 0, "websocket DNS no-match samples do not send messages");
        Expect(capture.WebSocketCloseCalls == 0, "websocket DNS no-match samples do not close absent handles");

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestAdvancedScenarioSamplesCoverMissingSurface() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "advanced-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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
            capture.WebSocketBinaryModernPolicyCalls == 2,
            "advanced websocket samples keep modern TLS policy");
        Expect(capture.WebSocketSha1CompatibilityCalls == 0, "advanced websocket samples do not enable SHA1 compatibility");
        Expect(capture.WebSocketNonFinalSendCalls == 1, "websocket fragment sample sends a non-final frame");
        Expect(capture.WebSocketContinuationSendCalls == 1, "websocket fragment sample completes with a continuation frame");
        Expect(capture.WebSocketCloseCalls >= 2, "advanced websocket samples close handles");

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestAdvancedScenarioSamplesIgnoreTrustFailureEndpointEnvironmentFailure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "advanced-khttp";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }
        capture.FailHttpsTrustFailureRequest = true;
        capture.HttpsTrustFailureRequestStatus = STATUS_NO_MATCH;

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
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

        Expect(
            NT_SUCCESS(status),
            "advanced scenario samples treat trust-failure endpoint DNS misses as diagnostic");
        Expect(
            results.HttpsTrustFailure.Status == STATUS_NO_MATCH,
            "trust failure sample records DNS miss before certificate validation");
        Expect(
            results.HttpsTrustFailure.StatusCode == static_cast<ULONG>(STATUS_NO_MATCH),
            "trust failure sample records raw DNS miss status code");

        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestHighLevelPostLargeResponseHonorsMaxResponseBytes() noexcept
    {
        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(LargePostHttpTransport, nullptr);

        static const char url[] = "https://httpbin.dev/post";
        static const UCHAR requestBody[] = { 'x' };

        khttp::SessionConfig config = khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 256 * 1024;
        khttp::Session* session = nullptr;
        NTSTATUS status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for large POST response");

        khttp::Response* response = nullptr;
        status = khttp::Post(
            session,
            url,
            sizeof(url) - 1,
            requestBody,
            sizeof(requestBody),
            &response);
        Expect(NT_SUCCESS(status), "khttp::Post aggregates large response within MaxResponseBytes");
        Expect(
            khttp::ResponseBodyLength(response) == LargePostBodyLength,
            "khttp::Post large response body length matches");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        config = khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 64 * 1024;
        session = nullptr;
        status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for limited large POST response");

        response = nullptr;
        status = khttp::Post(
            session,
            url,
            sizeof(url) - 1,
            requestBody,
            sizeof(requestBody),
            &response);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "khttp::Post rejects large response above MaxResponseBytes");
        Expect(response == nullptr, "limited khttp::Post leaves response null");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttp11DecodedBodyGrowsBeyondInitialBuffer() noexcept
    {
        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(ChunkedLargeResponseHttpTransport, nullptr);

        static const char url[] = "https://httpbin.dev/get";

        khttp::SessionConfig config = khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 256 * 1024;
        khttp::Session* session = nullptr;
        NTSTATUS status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTP/1.1 decoded-body grow test");

        khttp::Response* response = nullptr;
        status = khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            NT_SUCCESS(status),
            "khttp::Get grows DecodedBody for HTTP/1.1 chunked response larger than initial buffer");
        Expect(
            khttp::ResponseBodyLength(response) == ChunkedLargeBodyLength,
            "khttp::Get HTTP/1.1 decoded body length matches the chunked payload");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        config = khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 16 * 1024;
        session = nullptr;
        status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for limited HTTP/1.1 decoded-body test");

        response = nullptr;
        status = khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            status == STATUS_BUFFER_TOO_SMALL,
            "khttp::Get rejects HTTP/1.1 decoded body above MaxResponseBytes");
        Expect(response == nullptr, "limited HTTP/1.1 decoded-body request leaves response null");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttp11CloseDelimitedDecodedBodyGrowsBeyondInitialBuffer() noexcept
    {
        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(CloseDelimitedLargeResponseHttpTransport, nullptr);

        static const char url[] = "http://example.test/close-delimited";

        khttp::SessionConfig config = khttp::DefaultSessionConfig();
        config.MaxResponseBytes = 256 * 1024;
        khttp::Session* session = nullptr;
        NTSTATUS status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for close-delimited decoded-body grow test");

        khttp::Response* response = nullptr;
        status = khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            NT_SUCCESS(status),
            "khttp::Get grows DecodedBody for HTTP/1.1 close-delimited response");
        Expect(
            khttp::ResponseBodyLength(response) == CloseDelimitedLargeBodyLength,
            "khttp::Get close-delimited decoded body length matches payload");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttpsProtocolAutodetectUsesNegotiatedAlpn() noexcept
    {
        khttp::test::SetAsyncAutoRun(true);

        static const char url[] = "https://example.test/get";

        ProtocolAutodetectCapture capture = {};
        capture.NegotiatedAlpn = "h2";
        capture.NegotiatedAlpnLength = 2;
        khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        khttp::SessionConfig config = khttp::DefaultSessionConfig();
        khttp::Session* session = nullptr;
        NTSTATUS status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTPS autodetect h2 test");

        khttp::Response* response = nullptr;
        status = khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "default HTTPS request succeeds when h2 is negotiated");
        Expect(khttp::ResponseStatusCode(response) == 200, "h2 negotiated response returns success status");
        Expect(capture.DefaultOfferCalls == 1, "default HTTPS request offers h2 and HTTP/1.1");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        capture = {};
        capture.NegotiatedAlpn = "http/1.1";
        capture.NegotiatedAlpnLength = 8;
        khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTPS autodetect HTTP/1.1 test");

        response = nullptr;
        status = khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "default HTTPS request falls back to HTTP/1.1 when negotiated");
        Expect(khttp::ResponseStatusCode(response) == 204, "HTTP/1.1 negotiated response is parsed");
        Expect(capture.DefaultOfferCalls == 1, "HTTP/1.1 fallback still uses default ALPN offer");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        capture = {};
        capture.NegotiatedAlpn = "http/1.1";
        capture.NegotiatedAlpnLength = 8;
        khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for explicit HTTP/1.1 ALPN test");

        khttp::Request* request = nullptr;
        status = khttp::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for explicit HTTP/1.1 ALPN test");
        khttp::TlsConfig tls = khttp::DefaultTlsConfig();
        tls.Alpn = "http/1.1";
        tls.AlpnLength = 8;
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetUrl(request, url, sizeof(url) - 1);
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetTls(request, &tls);
        }
        response = nullptr;
        if (NT_SUCCESS(status)) {
            status = khttp::Send(session, request, &response);
        }
        Expect(NT_SUCCESS(status), "explicit HTTP/1.1 ALPN request succeeds");
        Expect(capture.ExplicitHttp11Calls == 1, "explicit HTTP/1.1 request offers only HTTP/1.1");
        Expect(capture.DefaultOfferCalls == 0, "explicit HTTP/1.1 request does not use automatic ALPN list");
        khttp::ResponseRelease(response);
        khttp::RequestRelease(request);
        khttp::SessionClose(session);

        config = khttp::DefaultSessionConfig();
        config.Tls.PreferHttp2 = false;
        capture = {};
        capture.NegotiatedAlpn = nullptr;
        capture.NegotiatedAlpnLength = 0;
        khttp::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            &config,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds when PreferHttp2 is disabled");

        response = nullptr;
        status = khttp::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "HTTPS request succeeds without automatic ALPN offer when disabled");
        Expect(capture.NoOfferCalls == 1, "PreferHttp2=false sends no automatic ALPN offer");
        khttp::ResponseRelease(response);
        khttp::SessionClose(session);

        khttp::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelTlsVersionFallbackPolicy() noexcept
    {
        using KernelHttp::engine::KhTlsVersion;
        constexpr ULONG TlsFailureVersionNegotiation = 1;
        constexpr ULONG TlsFailureNetworkIo = 4;
        constexpr ULONG TlsFailurePeerAlert = 7;

        Expect(
            khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls13,
                TlsFailureVersionNegotiation,
                STATUS_NOT_SUPPORTED,
                false),
            "default TLS 1.2-1.3 policy treats version negotiation as TLS 1.2 confirmation candidate");
        Expect(
            khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls13,
                TlsFailureNetworkIo,
                STATUS_CONNECTION_DISCONNECTED,
                true),
            "TLS 1.3 first ServerHello network failure can confirm TLS 1.2 when both versions are allowed");
        Expect(
            !khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls13,
                TlsFailureNetworkIo,
                STATUS_IO_TIMEOUT,
                true),
            "TLS 1.3 first ServerHello timeout does not trigger TLS 1.2 confirmation");
        Expect(
            !khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls13,
                TlsFailureNetworkIo,
                STATUS_CONNECTION_DISCONNECTED,
                false),
            "generic network I/O failure does not trigger TLS 1.2 confirmation");
        Expect(
            !khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls13,
                KhTlsVersion::Tls13,
                TlsFailureVersionNegotiation,
                STATUS_NOT_SUPPORTED,
                false),
            "TLS 1.3-only policy does not trigger TLS 1.2 fallback");
        Expect(
            !khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls12,
                TlsFailureNetworkIo,
                STATUS_CONNECTION_DISCONNECTED,
                true),
            "TLS 1.2-only policy does not need TLS 1.2 confirmation");
        Expect(
            !khttp::test::IsHttpTls12ConfirmationCandidate(
                KhTlsVersion::Tls12,
                KhTlsVersion::Tls13,
                TlsFailurePeerAlert,
                STATUS_INVALID_NETWORK_RESPONSE,
                true),
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

        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        khttp::Session* session = nullptr;
        NTSTATUS status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for websocket receive limit test");

        kws::WebSocket* ws = nullptr;
        kws::ConnectConfig wsConfig = kws::DefaultConnectConfig();
        wsConfig.Url = "wss://websocket-echo.com";
        wsConfig.UrlLength = strlen(wsConfig.Url);
        status = kws::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for websocket receive limit test");

        status = kws::SendText(ws, echo, sizeof(echo) - 1);
        Expect(NT_SUCCESS(status), "WsSendText succeeds for websocket receive limit test");

        kws::Message message = {};
        kws::ReceiveOptions receiveOptions = {};
        receiveOptions.MaxMessageBytes = 4;
        status = kws::ReceiveEx(ws, &receiveOptions, &message);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "WsReceiveEx rejects message above per-call MaxMessageBytes");

        kws::Close(ws);
        khttp::SessionClose(session);
        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestHighLevelWebSocketPublicValidation() noexcept
    {
        SampleCapture capture = {};
        khttp::test::SetAsyncAutoRun(true);
        khttp::test::SetHttpTransport(HttpTransport, &capture);
        khttp::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        khttp::Session* session = nullptr;
        NTSTATUS status = khttp::SessionCreate(
            reinterpret_cast<KernelHttp::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for high-level websocket validation");

        kws::WebSocket* ws = nullptr;
        kws::ConnectConfig invalidConfig = kws::DefaultConnectConfig();
        invalidConfig.Url = "wss://websocket-echo.com";
        invalidConfig.UrlLength = strlen(invalidConfig.Url);
        invalidConfig.Subprotocol = "bad token";
        invalidConfig.SubprotocolLength = strlen(invalidConfig.Subprotocol);
        status = kws::Connect(session, &invalidConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsConnect rejects invalid subprotocol");
        Expect(ws == nullptr, "high-level invalid subprotocol leaves websocket null");
        Expect(capture.WebSocketConnectCalls == 0, "high-level invalid subprotocol does not hit transport");

        kws::ConnectConfig validConfig = kws::DefaultConnectConfig();
        validConfig.Url = "wss://websocket-echo.com";
        validConfig.UrlLength = strlen(validConfig.Url);
        status = kws::Connect(session, &validConfig, &ws);
        Expect(NT_SUCCESS(status), "high-level WsConnect succeeds for validation");

        const unsigned char invalidText[] = { 0xc3, 0x28 };
        status = kws::SendText(
            ws,
            reinterpret_cast<const char*>(invalidText),
            sizeof(invalidText));
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsSendText rejects invalid UTF-8");
        Expect(capture.WebSocketSendCalls == 0, "high-level invalid text does not hit transport");

        const UCHAR invalidReason[] = { 0xc3, 0x28 };
        status = kws::CloseEx(ws, 1000, invalidReason, sizeof(invalidReason));
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsCloseEx rejects invalid UTF-8 reason");
        Expect(capture.WebSocketCloseCalls == 0, "high-level invalid close reason does not close transport");

        kws::Close(ws);
        Expect(capture.WebSocketCloseCalls == 1, "high-level cleanup close reaches transport once");
        khttp::SessionClose(session);
        khttp::test::SetHttpTransport(nullptr, nullptr);
        khttp::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }
}

int main() noexcept
{
    khttp::test::ResetCurrentIrql();
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
    TestAdvancedScenarioSamplesIgnoreTrustFailureEndpointEnvironmentFailure();
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
