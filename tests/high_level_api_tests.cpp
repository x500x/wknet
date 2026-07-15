#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/test/Test.h>
#include <wknet/http/Http.h>
#include <wknet/http/Request.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknet/websocket/WebSocket.h>
#include <wknettest/SampleStatus.h>

#include "http3/Http3Types.h"
#include "rtl/ProtocolFailureInjection.h"
#include "samples/AdvancedScenarioSamples.h"
#include "samples/ExternalTrustStore.h"
#include "samples/HighLevelApiSamples.h"
#include "session/AltSvcCache.h"
#include "session/HttpH3TestHooks.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <thread>

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

    struct RequiredHttp3Capture final
    {
        std::mutex Lock;
        std::condition_variable Event;
        wknet::session::HttpH3DispatchContext *Dispatch = nullptr;
        ULONG CreateCount = 0;
        NTSTATUS CreateStatus = STATUS_SUCCESS;
        char AlternativeHost[wknet::WKNET_HARD_MAX_ALT_SVC_HOST_BYTES + 1] = {};
        SIZE_T AlternativeHostLength = 0;
        USHORT AlternativePort = 0;
    };

    NTSTATUS CreateRequiredHttp3Peer(void *context, const wknet::session::HttpH3PeerCreateOptions *options,
                                     wknet::session::HttpH3Peer *peer) noexcept
    {
        RequiredHttp3Capture *capture = static_cast<RequiredHttp3Capture *>(context);
        if (capture != nullptr)
        {
            {
                std::lock_guard<std::mutex> lock(capture->Lock);
                capture->Dispatch = options->Dispatch;
                ++capture->CreateCount;
                if (options->Alternative != nullptr)
                {
                    capture->AlternativeHostLength = options->Alternative->HostLength;
                    memcpy(capture->AlternativeHost, options->Alternative->Host,
                           options->Alternative->HostLength);
                    capture->AlternativePort = options->Alternative->Port;
                }
            }
            capture->Event.notify_all();
            if (!NT_SUCCESS(capture->CreateStatus))
            {
                return capture->CreateStatus;
            }
        }
        return wknet::session::HttpH3TestCreateInMemoryPeer(options, peer);
    }

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

    struct AutoHttp3TransportCapture final
    {
        ULONG Calls = 0;
        ULONG AdvertiseOnCall = 1;
    };

    NTSTATUS AutoHttp3Transport(
        void *context,
        const wknet::http::test::HttpTransportRequest *,
        wknet::http::test::HttpTransportResponse *response) noexcept
    {
        AutoHttp3TransportCapture *capture = static_cast<AutoHttp3TransportCapture *>(context);
        if (capture == nullptr || response == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        ++capture->Calls;
        static const char advertised[] =
            "HTTP/1.1 200 OK\r\n"
            "Alt-Svc: h3=\"alt.example:443\"; ma=60\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "seed";
        static const char ordinary[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 8\r\n"
            "Connection: close\r\n"
            "\r\n"
            "fallback";
        response->RawResponse = capture->Calls == capture->AdvertiseOnCall ? advertised : ordinary;
        response->RawResponseLength = capture->Calls == capture->AdvertiseOnCall
                                          ? sizeof(advertised) - 1
                                          : sizeof(ordinary) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    struct AutoHttp3RedirectTransportCapture final
    {
        ULONG Calls = 0;
        ULONG OriginCalls = 0;
        ULONG RedirectCalls = 0;
    };

    NTSTATUS AutoHttp3RedirectTransport(
        void *context,
        const wknet::http::test::HttpTransportRequest *request,
        wknet::http::test::HttpTransportResponse *response) noexcept
    {
        AutoHttp3RedirectTransportCapture *capture =
            static_cast<AutoHttp3RedirectTransportCapture *>(context);
        if (capture == nullptr || request == nullptr || response == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->Calls;
        static const char redirect[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: https://redirect.example/final\r\n"
            "Alt-Svc: h3=\"origin-alt.example:443\"; ma=60\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char success[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        const bool origin = request->HostLength == strlen("origin.example") &&
                            memcmp(request->Host, "origin.example", request->HostLength) == 0;
        const bool redirected = request->HostLength == strlen("redirect.example") &&
                                memcmp(request->Host, "redirect.example", request->HostLength) == 0;
        if (origin)
        {
            ++capture->OriginCalls;
        }
        if (redirected)
        {
            ++capture->RedirectCalls;
        }
        response->RawResponse = origin && capture->OriginCalls == 1 ? redirect : success;
        response->RawResponseLength = origin && capture->OriginCalls == 1
                                          ? sizeof(redirect) - 1
                                          : sizeof(success) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
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
        wknet::http::AddressFamily HttpFailureAddressFamily = wknet::http::AddressFamily::Any;
        NTSTATUS HttpFailureStatus = STATUS_UNSUCCESSFUL;
        bool FailHttpsTrustFailureRequest = false;
        NTSTATUS HttpsTrustFailureRequestStatus = STATUS_NO_MATCH;
        bool FailWebSocketConnectFromCall = false;
        SIZE_T WebSocketConnectFailureStartCall = 0;
        NTSTATUS WebSocketConnectFailureStatus = STATUS_HOST_UNREACHABLE;
        UCHAR WebSocketEcho[32] = {};
        SIZE_T WebSocketEchoLength = 0;
        wknet::websocket::MsgType LastWebSocketSendType = wknet::websocket::MsgType::Text;
        wknet::websocket::MsgType PendingWebSocketFragmentType =
            wknet::websocket::MsgType::Text;
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

    NTSTATUS SetLargePostResponse(wknet::http::test::HttpTransportResponse* response) noexcept
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

    bool IsAdvancedLargePostRequest(const wknet::http::test::HttpTransportRequest* request) noexcept
    {
        return request != nullptr &&
            BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "POST /post ") &&
            BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "Content-Length: 65536\r\n");
    }

    NTSTATUS HttpTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<SampleCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->HttpCalls;
        if (request->AddressFamily == wknet::http::AddressFamily::Ipv4) {
            ++capture->HttpIpv4Calls;
        }
        if (request->AddressFamily == wknet::http::AddressFamily::Ipv6) {
            ++capture->HttpIpv6Calls;
        }
        if (request->AddressFamily == wknet::http::AddressFamily::Any) {
            ++capture->HttpAnyCalls;
        }

        if (capture->FailHttpByAddressFamily &&
            request->AddressFamily == capture->HttpFailureAddressFamily) {
            return capture->HttpFailureStatus;
        }

        if (request->ConnectionPolicy == wknet::http::ConnPolicy::ReuseOrCreate) {
            ++capture->HttpReuseCalls;
        }
        if (request->ConnectionPolicy == wknet::http::ConnPolicy::NoPool) {
            ++capture->HttpNoPoolCalls;
        }
        if (request->ConnectionPolicy == wknet::http::ConnPolicy::ForceNew) {
            ++capture->HttpForceNewCalls;
        }

        const bool isHttps = TextEqualsLiteral(request->Scheme, request->SchemeLength, "https");
        if (isHttps &&
            request->CertificatePolicy == wknet::http::CertPolicy::Verify) {
            ++capture->HttpsVerifyCalls;
            if (request->CertificateStore != nullptr) {
                ++capture->HttpsVerifyWithStoreCalls;
            }
        }
        if (isHttps &&
            request->CertificatePolicy == wknet::http::CertPolicy::NoVerify) {
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

        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /redirect-to?url=/get ") ||
            BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, "GET /redirect/1 ")) {
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
            "X-Wknet-Test: high-level\r\n"
            "Connection: close\r\n"
            "\r\n";
        response->RawResponse = rawResponse;
        response->RawResponseLength = sizeof(rawResponse) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS LargePostHttpTransport(
        void*,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
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
    // gzip/deflate response over HTTP/1.1 hits on the public echo endpoint.
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
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
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
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
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
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
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
        const wknet::http::test::WebSocketConnectRequest* request) noexcept
    {
        auto* capture = static_cast<SampleCapture*>(context);
        if (capture == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->WebSocketConnectCalls;
        if (request->AddressFamily == wknet::http::AddressFamily::Ipv4) {
            ++capture->WebSocketIpv4Calls;
        }
        if (request->AddressFamily == wknet::http::AddressFamily::Any) {
            ++capture->WebSocketAnyCalls;
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "ws")) {
            ++capture->WebSocketPlainCalls;
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "wss")) {
            ++capture->WebSocketSecureCalls;
        }
        if (TextEqualsLiteral(request->Host, request->HostLength, "ws.ifelse.io")) {
            ++capture->WebSocketEchoHostCalls;
            if (request->Policy.Profile == wknet::http::TlsSecurityProfile::ModernDefault &&
                !request->Policy.EnableTls12Sha1Signatures) {
                ++capture->WebSocketBinaryModernPolicyCalls;
            }
            if (request->Policy.EnableTls12Sha1Signatures) {
                ++capture->WebSocketSha1CompatibilityCalls;
            }
        }
        if (TextEqualsLiteral(request->Scheme, request->SchemeLength, "wss") &&
            request->CertificatePolicy == wknet::http::CertPolicy::Verify) {
            ++capture->WebSocketVerifyCalls;
            if (request->CertificateStore != nullptr) {
                ++capture->WebSocketVerifyWithStoreCalls;
            }
            if (TextEqualsLiteral(request->Host, request->HostLength, "ws.ifelse.io") &&
                request->MinTlsVersion == wknet::http::TlsVersion::Tls12 &&
                request->MaxTlsVersion == wknet::http::TlsVersion::Tls13) {
                ++capture->WebSocketTls12ToTls13Calls;
            }
            if (TextEqualsLiteral(request->Host, request->HostLength, "ws.ifelse.io") &&
                request->MinTlsVersion == wknet::http::TlsVersion::Tls13 &&
                request->MaxTlsVersion == wknet::http::TlsVersion::Tls13) {
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
        wknet::websocket::WebSocket* websocket,
        wknet::websocket::MsgType type,
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
        if (type == wknet::websocket::MsgType::Text) {
            ++capture->WebSocketTextSendCalls;
        }
        if (type == wknet::websocket::MsgType::Binary) {
            ++capture->WebSocketBinarySendCalls;
        }
        if (type == wknet::websocket::MsgType::Continuation) {
            ++capture->WebSocketContinuationSendCalls;
        }
        if (!finalFragment) {
            ++capture->WebSocketNonFinalSendCalls;
        }

        if (type == wknet::websocket::MsgType::Continuation) {
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
        wknet::websocket::WebSocket* websocket,
        wknet::http::test::WebSocketMessage* message) noexcept
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
            message->Type = wknet::websocket::MsgType::Text;
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

    void WebSocketClose(void* context, wknet::websocket::WebSocket* websocket) noexcept
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
        static const char echo[] = "hello-from-wknet";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }
        capture.WebSocketGreetingBeforeEcho = true;

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = wknet::samples::RunHighLevelApiSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &results);

        Expect(NT_SUCCESS(status), "load-time high-level samples succeed under test transport");
        Expect(NT_SUCCESS(results.SessionDefaultConfig.Status), "default session sample succeeds");
        Expect(NT_SUCCESS(results.SessionCustomConfig.Status), "custom session sample succeeds");
        Expect(capture.HttpCalls == 38, "all HTTP/HTTPS high-level samples are issued");
        Expect(capture.HttpIpv4Calls == 1, "dedicated HTTP IPv4 sample forces IPv4");
        Expect(capture.HttpIpv6Calls == 1, "IPv6 HTTP sample is issued");
        Expect(capture.HttpAnyCalls == 36, "general HTTP/HTTPS samples use default address family");
        Expect(capture.HttpNoPoolCalls >= 10, "no-pool connection policy samples are issued");
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

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestExternalTrustStoreLoadsRepositoryBundle() noexcept
    {
        wknet::samples::ExternalTrustStore trustStore = {};
        const NTSTATUS status = wknet::samples::InitializeExternalTrustStore(
            trustStore,
            "certs\\cacert.pem");

        Expect(NT_SUCCESS(status), "external trust store loads repository cacert.pem");
        Expect(trustStore.Store != nullptr, "external trust store creates a public certificate store");
        wknet::samples::ResetExternalTrustStore(trustStore);
    }

    void TestPublicEndpointStatusClassification() noexcept
    {
        using wknet::samples::IsPublicEndpointDiagnosticStatus;

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
        wknet::samples::MergePublicDiagnosticSampleStatus(aggregate, STATUS_IO_TIMEOUT);
        Expect(aggregate == STATUS_SUCCESS, "public timeout does not poison aggregate");

        wknet::samples::MergePublicDiagnosticSampleStatus(aggregate, STATUS_INVALID_NETWORK_RESPONSE);
        Expect(aggregate == STATUS_INVALID_NETWORK_RESPONSE, "protocol error poisons aggregate");
    }

    void TestLoadTimeSamplesReportIpv6Failure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-wknet";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        capture.FailHttpByAddressFamily = true;
        capture.HttpFailureAddressFamily = wknet::http::AddressFamily::Ipv6;
        capture.HttpFailureStatus = STATUS_UNSUCCESSFUL;

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = wknet::samples::RunHighLevelApiSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &results);

        Expect(!NT_SUCCESS(status), "load-time high-level samples report IPv6 HTTP sample failure");
        Expect(results.HttpGetIpv6.Status == STATUS_UNSUCCESSFUL, "IPv6 HTTP sample stores failure status");
        Expect(NT_SUCCESS(results.HttpGetAny.Status), "Any address-family HTTP sample still runs after IPv6 failure");

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnoreIpv4EnvironmentFailure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-wknet";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        capture.FailHttpByAddressFamily = true;
        capture.HttpFailureAddressFamily = wknet::http::AddressFamily::Ipv4;
        capture.HttpFailureStatus = STATUS_IO_TIMEOUT;

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = wknet::samples::RunHighLevelApiSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &results);

        Expect(NT_SUCCESS(status), "load-time high-level samples ignore IPv4 environment timeout");
        Expect(results.HttpGetIpv4.Status == STATUS_IO_TIMEOUT, "IPv4 HTTP sample records environment timeout");
        Expect(NT_SUCCESS(results.HttpGetAny.Status), "Any address-family HTTP sample still runs after IPv4 timeout");

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnoreIpv6EnvironmentFailure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-wknet";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        capture.FailHttpByAddressFamily = true;
        capture.HttpFailureAddressFamily = wknet::http::AddressFamily::Ipv6;
        capture.HttpFailureStatus = STATUS_IO_TIMEOUT;

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = wknet::samples::RunHighLevelApiSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &results);

        Expect(NT_SUCCESS(status), "load-time high-level samples ignore IPv6 environment timeout");
        Expect(results.HttpGetIpv6.Status == STATUS_IO_TIMEOUT, "IPv6 HTTP sample records environment timeout");
        Expect(NT_SUCCESS(results.HttpGetAny.Status), "Any address-family HTTP sample still runs after IPv6 timeout");

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnoreRepeatedPublicWebSocketConnectFailures() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "hello-from-wknet";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }
        capture.FailWebSocketConnectFromCall = true;
        capture.WebSocketConnectFailureStartCall = 2;
        capture.WebSocketConnectFailureStatus = STATUS_HOST_UNREACHABLE;

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = wknet::samples::RunHighLevelApiSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
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

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestLoadTimeSamplesIgnorePublicWebSocketNoMatchFailures() noexcept
    {
        SampleCapture capture = {};
        capture.FailWebSocketConnectFromCall = true;
        capture.WebSocketConnectFailureStartCall = 1;
        capture.WebSocketConnectFailureStatus = STATUS_NO_MATCH;

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = wknet::samples::RunHighLevelApiSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &results);

        Expect(NT_SUCCESS(status), "load-time samples treat public websocket DNS misses as diagnostic");
        Expect(results.WebSocketEcho.Status == STATUS_NO_MATCH, "first websocket sample records DNS no-match");
        Expect(results.WebSocketUrlConnect.Status == STATUS_NO_MATCH, "URL websocket sample records DNS no-match");
        Expect(results.WebSocketConnectEx.Status == STATUS_NO_MATCH, "ConnectEx websocket sample records DNS no-match");
        Expect(capture.WebSocketConnectCalls == 11, "all websocket connect samples are still issued after DNS no-match");
        Expect(capture.WebSocketSendCalls == 0, "websocket DNS no-match samples do not send messages");
        Expect(capture.WebSocketCloseCalls == 0, "websocket DNS no-match samples do not close absent handles");

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestAdvancedScenarioSamplesCoverMissingSurface() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "advanced-wknet";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::AdvancedScenarioSampleResults results = {};
        NTSTATUS status = wknet::samples::RunAdvancedScenarioSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
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
        Expect(results.HttpLargePost.BodyLength == LargePostBodyLength, "large POST sample records full response body");
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

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestAdvancedScenarioSamplesIgnoreTrustFailureEndpointEnvironmentFailure() noexcept
    {
        SampleCapture capture = {};
        static const char echo[] = "advanced-wknet";
        capture.WebSocketEchoLength = sizeof(echo) - 1;
        for (SIZE_T index = 0; index < capture.WebSocketEchoLength; ++index) {
            capture.WebSocketEcho[index] = static_cast<UCHAR>(echo[index]);
        }
        capture.FailHttpsTrustFailureRequest = true;
        capture.HttpsTrustFailureRequestStatus = STATUS_NO_MATCH;

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::samples::AdvancedScenarioSampleResults results = {};
        NTSTATUS status = wknet::samples::RunAdvancedScenarioSamples(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
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

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestHighLevelPostLargeResponseHonorsMaxResponseBytes() noexcept
    {
        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(LargePostHttpTransport, nullptr);

        static const char url[] = "https://postman-echo.com/post";
        static const UCHAR requestBody[] = { 'x' };

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = 0;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for unlimited large POST response");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Post(
            session,
            url,
            sizeof(url) - 1,
            requestBody,
            sizeof(requestBody),
            &response);
        Expect(NT_SUCCESS(status), "wknet::http::Post aggregates large response with unlimited MaxResponseBytes");
        Expect(
            wknet::http::ResponseBodyLength(response) == LargePostBodyLength,
            "wknet::http::Post large response body length matches");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = 64 * 1024;
        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for limited large POST response");

        response = nullptr;
        status = wknet::http::Post(
            session,
            url,
            sizeof(url) - 1,
            requestBody,
            sizeof(requestBody),
            &response);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "wknet::http::Post rejects large response above MaxResponseBytes");
        Expect(response == nullptr, "limited wknet::http::Post leaves response null");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttp11DecodedBodyGrowsBeyondInitialBuffer() noexcept
    {
        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(ChunkedLargeResponseHttpTransport, nullptr);

        static const char url[] = "https://postman-echo.com/get";

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = 0;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTP/1.1 decoded-body grow test");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            NT_SUCCESS(status),
            "wknet::http::Get grows DecodedBody for HTTP/1.1 chunked response larger than initial buffer");
        Expect(
            wknet::http::ResponseBodyLength(response) == ChunkedLargeBodyLength,
            "wknet::http::Get HTTP/1.1 decoded body length matches the chunked payload");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = 16 * 1024;
        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for limited HTTP/1.1 decoded-body test");

        response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            status == STATUS_BUFFER_TOO_SMALL,
            "wknet::http::Get rejects HTTP/1.1 decoded body above MaxResponseBytes");
        Expect(response == nullptr, "limited HTTP/1.1 decoded-body request leaves response null");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttp11CloseDelimitedDecodedBodyGrowsBeyondInitialBuffer() noexcept
    {
        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(CloseDelimitedLargeResponseHttpTransport, nullptr);

        static const char url[] = "http://example.test/close-delimited";

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = 0;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for close-delimited decoded-body grow test");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(
            NT_SUCCESS(status),
            "wknet::http::Get grows DecodedBody for HTTP/1.1 close-delimited response");
        Expect(
            wknet::http::ResponseBodyLength(response) == CloseDelimitedLargeBodyLength,
            "wknet::http::Get close-delimited decoded body length matches payload");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelHttpsProtocolAutodetectUsesNegotiatedAlpn() noexcept
    {
        wknet::http::test::SetAsyncAutoRun(true);

        static const char url[] = "https://example.test/get";

        ProtocolAutodetectCapture capture = {};
        capture.NegotiatedAlpn = "h2";
        capture.NegotiatedAlpnLength = 2;
        wknet::http::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTPS autodetect h2 test");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "default HTTPS request succeeds when h2 is negotiated");
        Expect(wknet::http::ResponseStatusCode(response) == 200, "h2 negotiated response returns success status");
        Expect(capture.DefaultOfferCalls == 1, "default HTTPS request offers h2 and HTTP/1.1");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        capture = {};
        capture.NegotiatedAlpn = "http/1.1";
        capture.NegotiatedAlpnLength = 8;
        wknet::http::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTPS autodetect HTTP/1.1 test");

        response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "default HTTPS request falls back to HTTP/1.1 when negotiated");
        Expect(wknet::http::ResponseStatusCode(response) == 204, "HTTP/1.1 negotiated response is parsed");
        Expect(capture.DefaultOfferCalls == 1, "HTTP/1.1 fallback still uses default ALPN offer");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        capture = {};
        capture.NegotiatedAlpn = "http/1.1";
        capture.NegotiatedAlpnLength = 8;
        wknet::http::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for explicit HTTP/1.1 ALPN test");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for explicit HTTP/1.1 ALPN test");
        wknet::http::TlsConfig tls = wknet::http::DefaultTlsConfig();
        tls.Alpn = "http/1.1";
        tls.AlpnLength = 8;
        if (NT_SUCCESS(status)) {
            status = wknet::http::RequestSetUrl(request, url, sizeof(url) - 1);
        }
        if (NT_SUCCESS(status)) {
            status = wknet::http::RequestSetTls(request, &tls);
        }
        response = nullptr;
        if (NT_SUCCESS(status)) {
            status = wknet::http::Send(session, request, &response);
        }
        Expect(NT_SUCCESS(status), "explicit HTTP/1.1 ALPN request succeeds");
        Expect(capture.ExplicitHttp11Calls == 1, "explicit HTTP/1.1 request offers only HTTP/1.1");
        Expect(capture.DefaultOfferCalls == 0, "explicit HTTP/1.1 request does not use automatic ALPN list");
        wknet::http::ResponseRelease(response);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);

        config = wknet::http::DefaultSessionConfig();
        config.Tls.PreferHttp2 = false;
        capture = {};
        capture.NegotiatedAlpn = nullptr;
        capture.NegotiatedAlpnLength = 0;
        wknet::http::test::SetHttpTransport(ProtocolAutodetectTransport, &capture);

        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds when PreferHttp2 is disabled");

        response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status), "HTTPS request succeeds without automatic ALPN offer when disabled");
        Expect(capture.NoOfferCalls == 1, "PreferHttp2=false sends no automatic ALPN offer");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHighLevelTlsVersionFallbackPolicy() noexcept
    {
        using wknet::http::TlsVersion;
        constexpr ULONG TlsFailureVersionNegotiation = 1;
        constexpr ULONG TlsFailureNetworkIo = 4;
        constexpr ULONG TlsFailurePeerAlert = 7;

        Expect(
            wknet::http::test::IsHttpTls12ConfirmationCandidate(
                TlsVersion::Tls12,
                TlsVersion::Tls13,
                TlsFailureVersionNegotiation,
                STATUS_NOT_SUPPORTED,
                false),
            "default TLS 1.2-1.3 policy treats version negotiation as TLS 1.2 confirmation candidate");
        Expect(
            wknet::http::test::IsHttpTls12ConfirmationCandidate(
                TlsVersion::Tls12,
                TlsVersion::Tls13,
                TlsFailureNetworkIo,
                STATUS_CONNECTION_DISCONNECTED,
                true),
            "TLS 1.3 first ServerHello network failure can confirm TLS 1.2 when both versions are allowed");
        Expect(
            !wknet::http::test::IsHttpTls12ConfirmationCandidate(
                TlsVersion::Tls12,
                TlsVersion::Tls13,
                TlsFailureNetworkIo,
                STATUS_IO_TIMEOUT,
                true),
            "TLS 1.3 first ServerHello timeout does not trigger TLS 1.2 confirmation");
        Expect(
            !wknet::http::test::IsHttpTls12ConfirmationCandidate(
                TlsVersion::Tls12,
                TlsVersion::Tls13,
                TlsFailureNetworkIo,
                STATUS_CONNECTION_DISCONNECTED,
                false),
            "generic network I/O failure does not trigger TLS 1.2 confirmation");
        Expect(
            !wknet::http::test::IsHttpTls12ConfirmationCandidate(
                TlsVersion::Tls13,
                TlsVersion::Tls13,
                TlsFailureVersionNegotiation,
                STATUS_NOT_SUPPORTED,
                false),
            "TLS 1.3-only policy does not trigger TLS 1.2 fallback");
        Expect(
            !wknet::http::test::IsHttpTls12ConfirmationCandidate(
                TlsVersion::Tls12,
                TlsVersion::Tls12,
                TlsFailureNetworkIo,
                STATUS_CONNECTION_DISCONNECTED,
                true),
            "TLS 1.2-only policy does not need TLS 1.2 confirmation");
        Expect(
            !wknet::http::test::IsHttpTls12ConfirmationCandidate(
                TlsVersion::Tls12,
                TlsVersion::Tls13,
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

        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for websocket receive limit test");

        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = "wss://ws.ifelse.io/";
        wsConfig.UrlLength = strlen(wsConfig.Url);
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for websocket receive limit test");

        status = wknet::websocket::SendText(ws, echo, sizeof(echo) - 1);
        Expect(NT_SUCCESS(status), "WsSendText succeeds for websocket receive limit test");

        wknet::websocket::Message message = {};
        wknet::websocket::ReceiveOptions receiveOptions = {};
        receiveOptions.MaxMessageBytes = 4;
        status = wknet::websocket::ReceiveEx(ws, &receiveOptions, &message);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "WsReceiveEx rejects message above per-call MaxMessageBytes");

        wknet::websocket::Close(ws);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestHighLevelWebSocketPublicValidation() noexcept
    {
        SampleCapture capture = {};
        wknet::http::test::SetAsyncAutoRun(true);
        wknet::http::test::SetHttpTransport(HttpTransport, &capture);
        wknet::http::test::SetWebSocketTransport(
            WebSocketConnect,
            WebSocketSend,
            WebSocketReceive,
            WebSocketClose,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for high-level websocket validation");

        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig invalidConfig = wknet::websocket::DefaultConnectConfig();
        invalidConfig.Url = "wss://ws.ifelse.io/";
        invalidConfig.UrlLength = strlen(invalidConfig.Url);
        invalidConfig.Subprotocol = "bad token";
        invalidConfig.SubprotocolLength = strlen(invalidConfig.Subprotocol);
        status = wknet::websocket::Connect(session, &invalidConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsConnect rejects invalid subprotocol");
        Expect(ws == nullptr, "high-level invalid subprotocol leaves websocket null");
        Expect(capture.WebSocketConnectCalls == 0, "high-level invalid subprotocol does not hit transport");

        wknet::websocket::ConnectConfig validConfig = wknet::websocket::DefaultConnectConfig();
        validConfig.Url = "wss://ws.ifelse.io/";
        validConfig.UrlLength = strlen(validConfig.Url);
        status = wknet::websocket::Connect(session, &validConfig, &ws);
        Expect(NT_SUCCESS(status), "high-level WsConnect succeeds for validation");

        const unsigned char invalidText[] = { 0xc3, 0x28 };
        status = wknet::websocket::SendText(
            ws,
            reinterpret_cast<const char*>(invalidText),
            sizeof(invalidText));
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsSendText rejects invalid UTF-8");
        Expect(capture.WebSocketSendCalls == 0, "high-level invalid text does not hit transport");

        const UCHAR invalidReason[] = { 0xc3, 0x28 };
        status = wknet::websocket::CloseEx(ws, 1000, invalidReason, sizeof(invalidReason));
        Expect(status == STATUS_INVALID_PARAMETER, "high-level WsCloseEx rejects invalid UTF-8 reason");
        Expect(capture.WebSocketCloseCalls == 0, "high-level invalid close reason does not close transport");

        wknet::websocket::Close(ws);
        Expect(capture.WebSocketCloseCalls == 1, "high-level cleanup close reaches transport once");
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestAutoHttp3LearnsAlternativeAndFallsBackSafely() noexcept
    {
        wknet::session::HttpH3TestReset();
        AutoHttp3TransportCapture transport = {};
        wknet::http::test::SetHttpTransport(AutoHttp3Transport, &transport);

        RequiredHttp3Capture h3 = {};
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Context = &h3;
        factory.Create = CreateRequiredHttp3Peer;
        wknet::session::HttpH3TestSetPeerFactory(&factory);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
        config.Http3.RaceWindowMs = 50;
        wknet::http::Session *session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "Auto H3 session creation succeeds");

        constexpr char url[] = "https://origin.example/auto";
        wknet::http::Response *response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status) && response != nullptr && transport.Calls == 1 && h3.CreateCount == 0,
               "first Auto request uses TCP and learns authenticated Alt-Svc");
        wknet::http::ResponseRelease(response);

        response = nullptr;
        NTSTATUS sendStatus = STATUS_PENDING;
        std::thread sender([&]() noexcept {
            sendStatus = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        });

        wknet::session::HttpH3DispatchContext *dispatch = nullptr;
        {
            std::unique_lock<std::mutex> lock(h3.Lock);
            (void)h3.Event.wait_for(lock, std::chrono::seconds(2), [&h3]() noexcept {
                return h3.CreateCount >= 1;
            });
            dispatch = h3.Dispatch;
        }
        Expect(dispatch != nullptr, "second Auto request creates one H3 dispatch");
        Expect(h3.AlternativeHostLength == strlen("alt.example") &&
                   memcmp(h3.AlternativeHost, "alt.example", h3.AlternativeHostLength) == 0 &&
                   h3.AlternativePort == 443,
               "Auto H3 uses the alternative endpoint only for QUIC connection routing");
        Expect(dispatch != nullptr && dispatch->RequestObject != nullptr &&
                   dispatch->RequestObject->HostLength == strlen("origin.example") &&
                   memcmp(dispatch->RequestObject->Host, "origin.example",
                          dispatch->RequestObject->HostLength) == 0,
               "Auto H3 preserves the original HTTP authority and TLS identity");

        wknet::session::HttpH3TestSnapshot autoSnapshot = {};
        for (ULONG attempt = 0; attempt < 1000; ++attempt)
        {
            wknet::session::HttpH3TestGetSnapshot(&autoSnapshot);
            if (autoSnapshot.StreamId != wknet::session::HttpH3UnsetStreamId &&
                autoSnapshot.RequestState >= wknet::session::HttpH3RequestState::RequestFullySent)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        Expect(autoSnapshot.StreamId == 0,
               "Auto H3 request reaches its bound stream before response delivery");

        if (dispatch != nullptr)
        {
            wknet::session::HttpH3TestInjectResponseStarted(dispatch, 200);
            const UCHAR body[] = {'a', 'u', 't', 'o'};
            status = wknet::session::HttpH3TestInjectBody(dispatch, body, sizeof(body), true);
            Expect(NT_SUCCESS(status), "Auto H3 response body is accepted");
            wknet::session::HttpH3TestInjectCompletion(
                dispatch,
                STATUS_SUCCESS,
                wknet::http3::H3_NO_ERROR);
        }
        sender.join();
        Expect(NT_SUCCESS(sendStatus) && response != nullptr && transport.Calls == 1,
               "learned Alt-Svc sends the next request only once through H3");
        wknet::http::ResponseRelease(response);

        {
            std::lock_guard<std::mutex> lock(h3.Lock);
            h3.CreateStatus = STATUS_IO_TIMEOUT;
            h3.Dispatch = nullptr;
        }
        response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        Expect(NT_SUCCESS(status) && response != nullptr && transport.Calls == 2 &&
                   wknet::http::ResponseBodyLength(response) == 8 &&
                   memcmp(wknet::http::ResponseBody(response), "fallback", 8) == 0,
               "unsent failed H3 probe safely falls back to one TCP request");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        transport = {};
        h3.CreateStatus = STATUS_SUCCESS;
        h3.CreateCount = 0;
        h3.Dispatch = nullptr;
        config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
        config.Tls.Certificate = wknet::http::CertPolicy::NoVerify;
        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "NoVerify Auto session creation succeeds");
        response = nullptr;
        status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = NT_SUCCESS(status) ? wknet::http::Get(session, url, sizeof(url) - 1, &response) : status;
        Expect(NT_SUCCESS(status) && transport.Calls == 2 && h3.CreateCount == 0,
               "NoVerify responses neither learn nor automatically use Alt-Svc");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::session::HttpH3TestSetPeerFactory(nullptr);
        wknet::session::HttpH3TestReset();
    }

    void TestAutoHttp3RedirectSourceAndProxyIsolation() noexcept
    {
        wknet::session::HttpH3TestReset();
        AutoHttp3RedirectTransportCapture redirectTransport = {};
        wknet::http::test::SetHttpTransport(AutoHttp3RedirectTransport, &redirectTransport);

        RequiredHttp3Capture h3 = {};
        h3.CreateStatus = STATUS_IO_TIMEOUT;
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Context = &h3;
        factory.Create = CreateRequiredHttp3Peer;
        wknet::session::HttpH3TestSetPeerFactory(&factory);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
        wknet::http::Session *session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "redirect-source Auto session creation succeeds");

        constexpr char originUrl[] = "https://origin.example/start";
        constexpr char redirectUrl[] = "https://redirect.example/direct";
        wknet::http::Response *response = nullptr;
        status = wknet::http::Get(session, originUrl, sizeof(originUrl) - 1, &response);
        Expect(NT_SUCCESS(status) && response != nullptr && redirectTransport.Calls == 2 &&
                   redirectTransport.OriginCalls == 1 && redirectTransport.RedirectCalls == 1 &&
                   h3.CreateCount == 0,
               "redirect follows by TCP without applying the source origin Alt-Svc to the target origin");
        wknet::http::ResponseRelease(response);

        response = nullptr;
        status = wknet::http::Get(session, redirectUrl, sizeof(redirectUrl) - 1, &response);
        Expect(NT_SUCCESS(status) && response != nullptr && redirectTransport.RedirectCalls == 2 &&
                   h3.CreateCount == 0,
               "direct redirected-origin request still has no borrowed Alt-Svc candidate");
        wknet::http::ResponseRelease(response);

        response = nullptr;
        status = wknet::http::Get(session, originUrl, sizeof(originUrl) - 1, &response);
        Expect(NT_SUCCESS(status) && response != nullptr && h3.CreateCount == 1 &&
                   h3.AlternativeHostLength == strlen("origin-alt.example") &&
                   memcmp(h3.AlternativeHost, "origin-alt.example", h3.AlternativeHostLength) == 0,
               "the authenticated redirect response keeps Alt-Svc bound to its original origin");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        AutoHttp3TransportCapture proxyTransport = {};
        wknet::http::test::SetHttpTransport(AutoHttp3Transport, &proxyTransport);
        h3.CreateCount = 0;
        h3.CreateStatus = STATUS_SUCCESS;
        h3.Dispatch = nullptr;
        config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Auto;
        config.Proxy.Enabled = true;
        config.Proxy.Host = "proxy.example";
        config.Proxy.HostLength = strlen("proxy.example");
        config.Proxy.Port = 8080;
        config.Proxy.Family = wknet::http::AddressFamily::Ipv4;
        config.Proxy.Authority = "proxy.example:8080";
        config.Proxy.AuthorityLength = strlen("proxy.example:8080");
        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "proxy Auto session creation succeeds");
        response = nullptr;
        status = wknet::http::Get(session, originUrl, sizeof(originUrl) - 1, &response);
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = NT_SUCCESS(status)
                     ? wknet::http::Get(session, originUrl, sizeof(originUrl) - 1, &response)
                     : status;
        Expect(NT_SUCCESS(status) && response != nullptr && proxyTransport.Calls == 2 &&
                   h3.CreateCount == 0,
               "HTTP proxy mode neither learns nor automatically uses Alt-Svc");
        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);

        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::session::HttpH3TestSetPeerFactory(nullptr);
        wknet::session::HttpH3TestReset();
    }

    void TestRequiredHttp3UsesSingleH3Dispatch() noexcept
    {
        wknet::session::HttpH3TestReset();
        RequiredHttp3Capture capture = {};
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Context = &capture;
        factory.Create = CreateRequiredHttp3Peer;
        wknet::session::HttpH3TestSetPeerFactory(&factory);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        wknet::http::Session *session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "Required H3 session creation succeeds");

        wknet::http::Response *response = nullptr;
        NTSTATUS sendStatus = STATUS_PENDING;
        constexpr char url[] = "https://example.com/required-h3";
        std::thread sender([&]() noexcept { sendStatus = wknet::http::Get(session, url, sizeof(url) - 1, &response); });

        wknet::session::HttpH3DispatchContext *dispatch = nullptr;
        {
            std::unique_lock<std::mutex> lock(capture.Lock);
            (void)capture.Event.wait_for(lock, std::chrono::seconds(2),
                                         [&capture]() noexcept { return capture.Dispatch != nullptr; });
            dispatch = capture.Dispatch;
        }
        Expect(dispatch != nullptr, "Required H3 factory receives the active dispatch");

        wknet::session::HttpH3TestSnapshot snapshot = {};
        for (ULONG attempt = 0; attempt < 1000; ++attempt)
        {
            wknet::session::HttpH3TestGetSnapshot(&snapshot);
            if (snapshot.StreamId != wknet::session::HttpH3UnsetStreamId)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        Expect(snapshot.StreamId == 0, "Required H3 opens exactly the first client request stream");

        if (dispatch != nullptr)
        {
            wknet::session::HttpH3TestInjectResponseStarted(dispatch, 200);
            status = wknet::session::HttpH3TestInjectHeader(dispatch, "content-type", sizeof("content-type") - 1,
                                                            "text/plain", sizeof("text/plain") - 1, false);
            Expect(NT_SUCCESS(status), "Required H3 response header is accepted");
            const UCHAR body[] = {'h', '3', '-', 'o', 'k'};
            status = wknet::session::HttpH3TestInjectBody(dispatch, body, sizeof(body), true);
            Expect(NT_SUCCESS(status), "Required H3 response body is accepted");
            wknet::session::HttpH3TestInjectCompletion(dispatch, STATUS_SUCCESS, wknet::http3::H3_NO_ERROR);
        }
        sender.join();

        Expect(NT_SUCCESS(sendStatus), "Required H3 request completes successfully");
        Expect(response != nullptr && wknet::http::ResponseStatusCode(response) == 200,
               "Required H3 response status maps to the public response");
        Expect(response != nullptr && wknet::http::ResponseBodyLength(response) == 5 &&
                   memcmp(wknet::http::ResponseBody(response), "h3-ok", 5) == 0,
               "Required H3 DATA maps to the public response body");
        wknet::session::HttpH3TestGetSnapshot(&snapshot);
        Expect(snapshot.H3DispatchCount == 1 && snapshot.H1DispatchCount == 0 && snapshot.H2DispatchCount == 0,
               "Required mode selects one H3 dispatch without TCP fallback");
        Expect(snapshot.BodyReadCount == 0 && snapshot.CompletionCount == 1,
               "Required H3 body source and completion are delivered exactly once");

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        wknet::session::HttpH3TestSetPeerFactory(nullptr);
        wknet::session::HttpH3TestReset();
    }

    void TestRequiredHttp3FailureInjection() noexcept
    {
        wknet::session::HttpH3TestReset();
        wknet::rtl::ProtocolFailureInjectionReset();
        RequiredHttp3Capture capture = {};
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Context = &capture;
        factory.Create = CreateRequiredHttp3Peer;
        wknet::session::HttpH3TestSetPeerFactory(&factory);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        wknet::http::Session *session = nullptr;
        Expect(NT_SUCCESS(wknet::http::SessionCreate(&config, &session)),
               "Required H3 failure-injection session creation succeeds");

        constexpr wknet::rtl::ProtocolAllocationSite sites[] = {
            wknet::rtl::ProtocolAllocationSite::SessionHttp3CompletionFence,
            wknet::rtl::ProtocolAllocationSite::SessionHttp3ResponseAccumulator,
            wknet::rtl::ProtocolAllocationSite::SessionHttp3PeerRouter,
            wknet::rtl::ProtocolAllocationSite::SessionHttp3CertificateScratch,
            wknet::rtl::ProtocolAllocationSite::SessionHttp3PeerLease};
        constexpr char url[] = "https://example.com/failure-injection";
        for (const auto site : sites)
        {
            wknet::rtl::ProtocolFailureInjectionSetFailAlways(site, true);
            wknet::http::Response *response = nullptr;
            const NTSTATUS status = wknet::http::Get(session, url, sizeof(url) - 1, &response);
            Expect(status == STATUS_INSUFFICIENT_RESOURCES && response == nullptr,
                   "Required H3 allocation failpoint is propagated without fallback");
            Expect(wknet::rtl::ProtocolFailureInjectionLiveCount(site) == 0,
                   "failed Required H3 allocation has no live resource");
            wknet::rtl::ProtocolFailureInjectionSetFailAlways(site, false);
        }

        wknet::http::SessionClose(session);
        Expect(wknet::rtl::ProtocolFailureInjectionTotalLiveCount() == 0,
               "Required H3 failure sweep releases pool and request resources");
        wknet::session::HttpH3TestSetPeerFactory(nullptr);
        wknet::session::HttpH3TestReset();
    }

    void TestRequiredHttp3RetriesRejectedSafeRequestOnce() noexcept
    {
        wknet::session::HttpH3TestReset();
        RequiredHttp3Capture capture = {};
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Context = &capture;
        factory.Create = CreateRequiredHttp3Peer;
        wknet::session::HttpH3TestSetPeerFactory(&factory);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        wknet::http::Session *session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "Required H3 GOAWAY session creation succeeds");

        wknet::http::Response *response = nullptr;
        NTSTATUS sendStatus = STATUS_PENDING;
        constexpr char url[] = "https://example.com/goaway-retry";
        std::thread sender([&]() noexcept { sendStatus = wknet::http::Get(session, url, sizeof(url) - 1, &response); });

        wknet::session::HttpH3DispatchContext *firstDispatch = nullptr;
        {
            std::unique_lock<std::mutex> lock(capture.Lock);
            (void)capture.Event.wait_for(lock, std::chrono::seconds(2),
                                         [&capture]() noexcept { return capture.CreateCount >= 1; });
            firstDispatch = capture.Dispatch;
        }

        wknet::session::HttpH3TestSnapshot snapshot = {};
        for (ULONG attempt = 0; attempt < 200; ++attempt)
        {
            wknet::session::HttpH3TestGetSnapshot(&snapshot);
            if (snapshot.AttemptGeneration == 1 && snapshot.StreamId != wknet::session::HttpH3UnsetStreamId)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        wknet::session::HttpH3GoawayResult goawayResult = wknet::session::HttpH3GoawayResult::NoActiveStream;
        if (firstDispatch != nullptr)
        {
            status = wknet::session::HttpH3TestInjectGoaway(firstDispatch, 0, &goawayResult);
            Expect(NT_SUCCESS(status) && goawayResult == wknet::session::HttpH3GoawayResult::StreamRejected,
                   "GOAWAY rejects the first safe request stream");
            wknet::session::HttpH3TestInjectCompletion(firstDispatch, STATUS_RETRY, wknet::http3::H3_REQUEST_REJECTED);
        }

        wknet::session::HttpH3DispatchContext *secondDispatch = nullptr;
        {
            std::unique_lock<std::mutex> lock(capture.Lock);
            (void)capture.Event.wait_for(lock, std::chrono::seconds(2),
                                         [&capture]() noexcept { return capture.CreateCount >= 2; });
            secondDispatch = capture.Dispatch;
        }
        for (ULONG attempt = 0; attempt < 200; ++attempt)
        {
            wknet::session::HttpH3TestGetSnapshot(&snapshot);
            if (snapshot.AttemptGeneration == 2 && snapshot.StreamId != wknet::session::HttpH3UnsetStreamId)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (secondDispatch != nullptr)
        {
            wknet::session::HttpH3TestInjectResponseStarted(secondDispatch, 204);
            status = wknet::session::HttpH3TestInjectBody(secondDispatch, nullptr, 0, true);
            Expect(NT_SUCCESS(status), "retried H3 response final body marker is accepted");
            wknet::session::HttpH3TestInjectCompletion(secondDispatch, STATUS_SUCCESS, wknet::http3::H3_NO_ERROR);
        }
        sender.join();

        Expect(NT_SUCCESS(sendStatus) && response != nullptr && wknet::http::ResponseStatusCode(response) == 204,
               "safe GOAWAY-rejected GET retries once on a new H3 connection");
        wknet::session::HttpH3TestGetSnapshot(&snapshot);
        Expect(capture.CreateCount == 2 && snapshot.H3DispatchCount == 2,
               "GOAWAY safe retry creates exactly two serial H3 attempts");

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        wknet::session::HttpH3TestSetPeerFactory(nullptr);
        wknet::session::HttpH3TestReset();
    }

    void TestRequiredHttp3CancelResetsActiveStream() noexcept
    {
        wknet::session::HttpH3TestReset();
        RequiredHttp3Capture capture = {};
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Context = &capture;
        factory.Create = CreateRequiredHttp3Peer;
        wknet::session::HttpH3TestSetPeerFactory(&factory);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        wknet::http::Session *session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "Required H3 async-cancel session creation succeeds");

        wknet::http::Response *response = nullptr;
        NTSTATUS sendStatus = STATUS_PENDING;
        constexpr char url[] = "https://example.com/cancel-h3";
        std::thread sender([&]() noexcept { sendStatus = wknet::http::Get(session, url, sizeof(url) - 1, &response); });

        wknet::session::HttpH3DispatchContext *dispatch = nullptr;
        {
            std::unique_lock<std::mutex> lock(capture.Lock);
            (void)capture.Event.wait_for(lock, std::chrono::seconds(2),
                                         [&capture]() noexcept { return capture.CreateCount >= 1; });
            dispatch = capture.Dispatch;
        }
        wknet::session::HttpH3TestSnapshot snapshot = {};
        for (ULONG attempt = 0; attempt < 1000; ++attempt)
        {
            wknet::session::HttpH3TestGetSnapshot(&snapshot);
            if (snapshot.StreamId != wknet::session::HttpH3UnsetStreamId)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        wknet::session::HttpH3CancelResult cancelResult = wknet::session::HttpH3CancelResult::AlreadyTerminal;
        status = wknet::session::HttpH3DispatchRequestCancel(dispatch, &cancelResult);
        Expect(NT_SUCCESS(status) && cancelResult == wknet::session::HttpH3CancelResult::ResetAndStop,
               "Required H3 cancellation resets and stops an active request stream");
        sender.join();
        Expect(sendStatus == STATUS_CANCELLED && response == nullptr,
               "cancelled Required H3 request exposes no response");
        wknet::session::HttpH3TestGetSnapshot(&snapshot);
        Expect(snapshot.RequestState == wknet::session::HttpH3RequestState::Cancelled && snapshot.CompletionCount == 1,
               "Required H3 cancellation reaches one terminal request state");

        wknet::http::SessionClose(session);
        wknet::session::HttpH3TestSetPeerFactory(nullptr);
        wknet::session::HttpH3TestReset();
    }
}

int main() noexcept
{
    wknet::http::test::ResetCurrentIrql();
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
    TestAutoHttp3LearnsAlternativeAndFallsBackSafely();
    TestAutoHttp3RedirectSourceAndProxyIsolation();
    TestRequiredHttp3UsesSingleH3Dispatch();
    TestRequiredHttp3FailureInjection();
    TestRequiredHttp3RetriesRejectedSafeRequestOnce();
    TestRequiredHttp3CancelResetsActiveStream();

    if (g_failed) {
        printf("high-level API tests FAILED\n");
        return 1;
    }

    printf("high-level API tests passed\n");
    return 0;
}
