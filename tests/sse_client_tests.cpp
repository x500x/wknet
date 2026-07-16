#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "session/detail/HttpHandles.h"
#include "session/Engine.h"
#include "session/Async.h"
#include <wknet/Wknet.h>
#include <wknet/test/Test.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

    SIZE_T Length(const char* text) noexcept
    {
        return text == nullptr ? 0 : strlen(text);
    }

    struct TransportState final
    {
        const char* Response = nullptr;
        SIZE_T ResponseLength = 0;
        char CapturedRequest[4096] = {};
        SIZE_T CapturedRequestLength = 0;
        ULONG CallCount = 0;
        bool RequireLastEventId = false;
        const char* ExpectedLastEventId = nullptr;
        // Second response for reconnect simulation.
        const char* Response2 = nullptr;
        SIZE_T Response2Length = 0;
    };

    NTSTATUS SseTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* state = static_cast<TransportState*>(context);
        if (state == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++state->CallCount;
        if (request->BuiltRequest != nullptr && request->BuiltRequestLength != 0) {
            const SIZE_T copy = request->BuiltRequestLength < sizeof(state->CapturedRequest) - 1 ?
                request->BuiltRequestLength :
                sizeof(state->CapturedRequest) - 1;
            memcpy(state->CapturedRequest, request->BuiltRequest, copy);
            state->CapturedRequest[copy] = 0;
            state->CapturedRequestLength = copy;
        }

        if (state->RequireLastEventId && state->ExpectedLastEventId != nullptr) {
            const bool found = strstr(state->CapturedRequest, state->ExpectedLastEventId) != nullptr &&
                strstr(state->CapturedRequest, "Last-Event-ID:") != nullptr;
            if (!found) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        if (state->CallCount == 1) {
            response->RawResponse = state->Response;
            response->RawResponseLength = state->ResponseLength;
        }
        else {
            response->RawResponse = state->Response2 != nullptr ? state->Response2 : state->Response;
            response->RawResponseLength =
                state->Response2 != nullptr ? state->Response2Length : state->ResponseLength;
        }
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    void TestConnectReceiveClose() noexcept
    {
        printf("TestConnectReceiveClose\n");
        TransportState transport = {};
        const char response[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n"
            "id: 42\n"
            "event: update\n"
            "data: hello\n"
            "data: world\n"
            "\n"
            "data: only-data\n"
            "\n";
        transport.Response = response;
        transport.ResponseLength = sizeof(response) - 1;

        wknet::http::test::SetHttpTransport(SseTransport, &transport);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(nullptr, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");
        Expect(session != nullptr, "session non-null");

        wknet::sse::ConnectConfig config = wknet::sse::DefaultConnectConfig();
        config.Url = "http://sse.test/events";
        config.UrlLength = Length(config.Url);
        config.AutoReconnect = false;
        config.ConnectTimeoutMs = 5000;
        config.ReceiveTimeoutMs = 5000;
        config.Tls.Certificate = wknet::http::CertPolicy::NoVerify;

        wknet::sse::SseClient* client = nullptr;
        status = wknet::sse::ConnectEx(session, &config, &client);
        Expect(NT_SUCCESS(status), "Sse ConnectEx succeeds");
        Expect(client != nullptr, "client non-null");
        Expect(transport.CallCount >= 1, "transport invoked");
        Expect(strstr(transport.CapturedRequest, "Accept: text/event-stream") != nullptr,
            "request has Accept event-stream");
        Expect(strstr(transport.CapturedRequest, "Cache-Control: no-cache") != nullptr,
            "request has Cache-Control no-cache");

        wknet::sse::Event event = {};
        status = wknet::sse::Receive(client, &event);
        Expect(NT_SUCCESS(status), "first Receive succeeds");
        Expect(event.TypeLength == 6 && event.Type != nullptr && memcmp(event.Type, "update", 6) == 0,
            "first event type update");
        Expect(event.DataLength == 11 && event.Data != nullptr && memcmp(event.Data, "hello\nworld", 11) == 0,
            "first event data joined with newline");
        Expect(event.IdLength == 2 && event.Id != nullptr && memcmp(event.Id, "42", 2) == 0,
            "first event id 42");

        const char* lastId = nullptr;
        SIZE_T lastIdLength = 0;
        status = wknet::sse::GetLastEventId(client, &lastId, &lastIdLength);
        Expect(NT_SUCCESS(status), "GetLastEventId succeeds");
        Expect(lastIdLength == 2 && lastId != nullptr && memcmp(lastId, "42", 2) == 0,
            "tracked last event id is 42");

        status = wknet::sse::Receive(client, &event);
        Expect(NT_SUCCESS(status), "second Receive succeeds");
        Expect(event.TypeLength == 7 && event.Type != nullptr && memcmp(event.Type, "message", 7) == 0,
            "second event default type message");
        Expect(event.DataLength == 9 && event.Data != nullptr && memcmp(event.Data, "only-data", 9) == 0,
            "second event data");

        status = wknet::sse::Receive(client, &event);
        Expect(!NT_SUCCESS(status), "third Receive ends stream without reconnect");

        status = wknet::sse::Close(client);
        Expect(NT_SUCCESS(status), "Close succeeds");
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRejectBadContentType() noexcept
    {
        printf("TestRejectBadContentType\n");
        TransportState transport = {};
        const char response[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            "data: no\n"
            "\n";
        transport.Response = response;
        transport.ResponseLength = sizeof(response) - 1;
        wknet::http::test::SetHttpTransport(SseTransport, &transport);

        wknet::http::Session* session = nullptr;
        Expect(NT_SUCCESS(wknet::http::SessionCreate(nullptr, &session)), "session create");

        wknet::sse::ConnectConfig config = wknet::sse::DefaultConnectConfig();
        config.Url = "http://sse.test/bad";
        config.UrlLength = Length(config.Url);
        config.AutoReconnect = false;
        config.ConnectTimeoutMs = 3000;
        config.Tls.Certificate = wknet::http::CertPolicy::NoVerify;

        wknet::sse::SseClient* client = nullptr;
        const NTSTATUS status = wknet::sse::ConnectEx(session, &config, &client);
        Expect(!NT_SUCCESS(status), "bad content-type rejected");
        Expect(client == nullptr, "no client on failure");

        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestReject4xxNoReconnect() noexcept
    {
        printf("TestReject4xxNoReconnect\n");
        TransportState transport = {};
        const char response[] =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/event-stream\r\n"
            "\r\n";
        transport.Response = response;
        transport.ResponseLength = sizeof(response) - 1;
        wknet::http::test::SetHttpTransport(SseTransport, &transport);

        wknet::http::Session* session = nullptr;
        Expect(NT_SUCCESS(wknet::http::SessionCreate(nullptr, &session)), "session create");

        wknet::sse::ConnectConfig config = wknet::sse::DefaultConnectConfig();
        config.Url = "http://sse.test/missing";
        config.UrlLength = Length(config.Url);
        config.AutoReconnect = true;
        config.MaxReconnectAttempts = 3;
        config.ConnectTimeoutMs = 3000;
        config.Tls.Certificate = wknet::http::CertPolicy::NoVerify;

        wknet::sse::SseClient* client = nullptr;
        const NTSTATUS status = wknet::sse::ConnectEx(session, &config, &client);
        Expect(!NT_SUCCESS(status), "4xx open fails");
        Expect(transport.CallCount == 1, "4xx does not reconnect during Connect");

        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSeedLastEventIdHeader() noexcept
    {
        printf("TestSeedLastEventIdHeader\n");
        TransportState transport = {};
        const char response[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "\r\n"
            "data: ok\n"
            "\n";
        transport.Response = response;
        transport.ResponseLength = sizeof(response) - 1;
        transport.RequireLastEventId = true;
        transport.ExpectedLastEventId = "seed-7";
        wknet::http::test::SetHttpTransport(SseTransport, &transport);

        wknet::http::Session* session = nullptr;
        Expect(NT_SUCCESS(wknet::http::SessionCreate(nullptr, &session)), "session create");

        wknet::sse::ConnectConfig config = wknet::sse::DefaultConnectConfig();
        config.Url = "http://sse.test/resume";
        config.UrlLength = Length(config.Url);
        config.LastEventId = "seed-7";
        config.LastEventIdLength = Length(config.LastEventId);
        config.AutoReconnect = false;
        config.ConnectTimeoutMs = 3000;
        config.ReceiveTimeoutMs = 3000;
        config.Tls.Certificate = wknet::http::CertPolicy::NoVerify;

        wknet::sse::SseClient* client = nullptr;
        NTSTATUS status = wknet::sse::ConnectEx(session, &config, &client);
        Expect(NT_SUCCESS(status), "connect with seed last-event-id");
        Expect(strstr(transport.CapturedRequest, "Last-Event-ID: seed-7") != nullptr,
            "request injects Last-Event-ID");

        wknet::sse::Event event = {};
        status = wknet::sse::Receive(client, &event);
        Expect(NT_SUCCESS(status), "receive after seed");

        (void)wknet::sse::Close(client);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }
}

int main()
{
    TestConnectReceiveClose();
    TestRejectBadContentType();
    TestReject4xxNoReconnect();
    TestSeedLastEventIdHeader();

    if (g_failed) {
        printf("sse_client_tests: FAILED\n");
        return 1;
    }
    printf("sse_client_tests: PASS\n");
    return 0;
}
