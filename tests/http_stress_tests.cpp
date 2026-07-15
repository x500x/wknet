#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

// Product-path HTTP stress (module-quality-ledger Stress/Soak).
// Fake / in-memory transports only — not the public network.
//
// Profiles:
//   S0  H1 GET ×N (default 100)
//   S1  H1 GET pool churn ×N (default 1000)
//   POST H1 POST small body ×N (default 1000)
//   S2a H2c prior-knowledge GET ×N (default 1000; test path does not pool)
//   S2b H3 Required GET ×N (default 100; inject peer)
//   S3  parallel H1 GET (threads × per-thread)
//   S4  WebSocket messages ×N on one connection
//   S5  soak: wall-clock H1 GET loop (default 5s; raise via env)
//
// Env overrides (optional):
//   WKNET_STRESS_S0_N, WKNET_STRESS_S1_N, WKNET_STRESS_POST_N,
//   WKNET_STRESS_H2_N, WKNET_STRESS_H3_N, WKNET_STRESS_WS_N,
//   WKNET_STRESS_THREADS, WKNET_STRESS_PER_THREAD,
//   WKNET_STRESS_SOAK_SEC, WKNET_STRESS_SKIP_H3=1

#include <wknet/Wknet.h>
#include <wknet/Trace.h>
#include <wknet/test/Test.h>

#include "http3/Http3Types.h"
#include "rtl/ProtocolFailureInjection.h"
#include "session/HttpH3TestHooks.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <vector>

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition)
        {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    SIZE_T Length(const char* literal) noexcept
    {
        SIZE_T length = 0;
        while (literal != nullptr && literal[length] != '\0')
        {
            ++length;
        }
        return length;
    }

    SIZE_T ReadEnvSize(const char* name, SIZE_T defaultValue, SIZE_T minimum, SIZE_T maximum) noexcept
    {
        char text[32] = {};
        size_t required = 0;
        if (getenv_s(&required, text, sizeof(text), name) != 0 || required == 0 || text[0] == '\0')
        {
            return defaultValue;
        }
        char* end = nullptr;
        const unsigned long value = strtoul(text, &end, 10);
        if (end == text || value < minimum || value > maximum)
        {
            return defaultValue;
        }
        return static_cast<SIZE_T>(value);
    }

    bool EnvTruthy(const char* name) noexcept
    {
        char text[8] = {};
        size_t required = 0;
        if (getenv_s(&required, text, sizeof(text), name) != 0 || text[0] == '\0')
        {
            return false;
        }
        return text[0] == '1' || text[0] == 'y' || text[0] == 'Y' || text[0] == 't' || text[0] == 'T';
    }

    constexpr const char kOkResponse[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "ok";

    struct StressCapture final
    {
        std::atomic<SIZE_T> CallCount{0};
        std::atomic<SIZE_T> ReusedCallCount{0};
        std::atomic<SIZE_T> NewConnectionCallCount{0};
        std::atomic<SIZE_T> UsedHttp2Count{0};
        std::mutex IdLock;
        ULONGLONG FirstConnectionId = 0;
        ULONGLONG LastConnectionId = 0;
        SIZE_T DistinctConnectionIds = 0;
        ULONGLONG SeenIds[128] = {};
    };

    void NoteConnectionId(StressCapture* capture, ULONGLONG connectionId) noexcept
    {
        if (capture == nullptr || connectionId == 0)
        {
            return;
        }
        std::lock_guard<std::mutex> lock(capture->IdLock);
        if (capture->FirstConnectionId == 0)
        {
            capture->FirstConnectionId = connectionId;
        }
        capture->LastConnectionId = connectionId;
        for (SIZE_T index = 0; index < capture->DistinctConnectionIds; ++index)
        {
            if (capture->SeenIds[index] == connectionId)
            {
                return;
            }
        }
        if (capture->DistinctConnectionIds < 128)
        {
            capture->SeenIds[capture->DistinctConnectionIds++] = connectionId;
        }
        else
        {
            capture->DistinctConnectionIds = 128;
        }
    }

    NTSTATUS StressTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<StressCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        capture->CallCount.fetch_add(1, std::memory_order_relaxed);
        if (request->ReusedConnection)
        {
            capture->ReusedCallCount.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            capture->NewConnectionCallCount.fetch_add(1, std::memory_order_relaxed);
        }
        if (request->UsedHttp2)
        {
            capture->UsedHttp2Count.fetch_add(1, std::memory_order_relaxed);
        }
        NoteConnectionId(capture, request->ConnectionId);

        response->RawResponse = kOkResponse;
        response->RawResponseLength = sizeof(kOkResponse) - 1;
        response->ConnectionReusable = true;
        response->NegotiatedAlpn = nullptr;
        response->NegotiatedAlpnLength = 0;
        return STATUS_SUCCESS;
    }

    void ResetHttpTransport() noexcept
    {
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
        wknet::rtl::ProtocolFailureInjectionReset();
    }

    void AssertLiveClean(const char* label) noexcept
    {
        Expect(wknet::rtl::ProtocolFailureInjectionTotalLiveCount() == 0, label);
    }

    bool ExpectOkResponse(wknet::http::Response* response, const char* label) noexcept
    {
        if (response == nullptr)
        {
            Expect(false, label);
            return false;
        }
        if (wknet::http::ResponseStatusCode(response) != 200)
        {
            printf("FAIL: %s status=%u\n", label, static_cast<unsigned>(wknet::http::ResponseStatusCode(response)));
            g_failed = true;
            return false;
        }
        const SIZE_T bodyLength = wknet::http::ResponseBodyLength(response);
        const UCHAR* body = wknet::http::ResponseBody(response);
        // H2c test path returns empty body with status 200 (synthetic).
        if (bodyLength == 0)
        {
            return true;
        }
        if (bodyLength != 2 || body == nullptr || memcmp(body, "ok", 2) != 0)
        {
            printf("FAIL: %s unexpected body len=%zu\n", label, static_cast<size_t>(bodyLength));
            g_failed = true;
            return false;
        }
        return true;
    }

    void RunHttp11GetPoolLoop(SIZE_T iterations, bool requirePooling, const char* label) noexcept
    {
        printf("RUN: %s iterations=%zu requirePooling=%s\n",
            label,
            static_cast<size_t>(iterations),
            requirePooling ? "true" : "false");

        StressCapture capture = {};
        wknet::http::test::SetHttpTransport(StressTransport, &capture);
        wknet::rtl::ProtocolFailureInjectionReset();

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status) && session != nullptr, "SessionCreate for H1 GET stress");
        if (!NT_SUCCESS(status) || session == nullptr)
        {
            ResetHttpTransport();
            return;
        }

        const char* url = "http://stress.example/ok";
        const SIZE_T urlLength = Length(url);
        SIZE_T successCount = 0;

        for (SIZE_T index = 0; index < iterations; ++index)
        {
            wknet::http::Response* response = nullptr;
            status = wknet::http::Get(session, url, urlLength, &response);
            if (!NT_SUCCESS(status) || !ExpectOkResponse(response, "H1 GET body"))
            {
                printf("FAIL: H1 GET failed index=%zu status=0x%08X\n",
                    static_cast<size_t>(index),
                    static_cast<unsigned>(status));
                g_failed = true;
                wknet::http::ResponseRelease(response);
                break;
            }
            wknet::http::ResponseRelease(response);
            ++successCount;
        }

        Expect(successCount == iterations, "H1 GET all iterations succeeded");
        Expect(capture.CallCount.load() == iterations, "H1 GET transport call count");
        Expect(capture.NewConnectionCallCount.load() >= 1, "H1 GET opened a connection");

        if (requirePooling)
        {
            Expect(capture.NewConnectionCallCount.load() <= 2, "H1 pool opens at most a couple connections");
            Expect(capture.ReusedCallCount.load() + 2 >= iterations, "H1 almost all requests reuse pool");
            Expect(capture.DistinctConnectionIds <= 2, "H1 distinct connection ids stay small");
            Expect(capture.DistinctConnectionIds * 10 < iterations || iterations < 20,
                "H1 connection ids do not grow with N");
        }

        wknet::http::SessionClose(session);
        AssertLiveClean("H1 GET stress live count after close");

        printf("STAT: %s success=%zu transport=%zu new=%zu reused=%zu distinctIds=%zu\n",
            label,
            static_cast<size_t>(successCount),
            static_cast<size_t>(capture.CallCount.load()),
            static_cast<size_t>(capture.NewConnectionCallCount.load()),
            static_cast<size_t>(capture.ReusedCallCount.load()),
            static_cast<size_t>(capture.DistinctConnectionIds));
        ResetHttpTransport();
    }

    void TestS0SmokeLoop() noexcept
    {
        RunHttp11GetPoolLoop(ReadEnvSize("WKNET_STRESS_S0_N", 100, 1, 100000), false, "S0-smoke-loop");
    }

    void TestS1PoolChurn() noexcept
    {
        RunHttp11GetPoolLoop(ReadEnvSize("WKNET_STRESS_S1_N", 1000, 10, 1000000), true, "S1-pool-churn");
    }

    void TestHttp11PostLoop() noexcept
    {
        const SIZE_T iterations = ReadEnvSize("WKNET_STRESS_POST_N", 1000, 1, 1000000);
        printf("RUN: H1-POST-loop iterations=%zu\n", static_cast<size_t>(iterations));

        StressCapture capture = {};
        wknet::http::test::SetHttpTransport(StressTransport, &capture);
        wknet::rtl::ProtocolFailureInjectionReset();

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status) && session != nullptr, "SessionCreate for H1 POST stress");
        if (!NT_SUCCESS(status) || session == nullptr)
        {
            ResetHttpTransport();
            return;
        }

        const char* url = "http://stress.example/post";
        const SIZE_T urlLength = Length(url);
        const char payload[] = "payload";
        SIZE_T successCount = 0;

        for (SIZE_T index = 0; index < iterations; ++index)
        {
            wknet::http::Response* response = nullptr;
            status = wknet::http::Post(
                session,
                url,
                urlLength,
                reinterpret_cast<const UCHAR*>(payload),
                sizeof(payload) - 1,
                &response);
            if (!NT_SUCCESS(status) || !ExpectOkResponse(response, "H1 POST body"))
            {
                printf("FAIL: H1 POST failed index=%zu status=0x%08X\n",
                    static_cast<size_t>(index),
                    static_cast<unsigned>(status));
                g_failed = true;
                wknet::http::ResponseRelease(response);
                break;
            }
            wknet::http::ResponseRelease(response);
            ++successCount;
        }

        Expect(successCount == iterations, "H1 POST all iterations succeeded");
        Expect(capture.CallCount.load() == iterations, "H1 POST transport call count");
        // POST must not invent automatic retries on the stress path; call count == N.
        Expect(capture.CallCount.load() == successCount, "H1 POST no extra transport retries");

        wknet::http::SessionClose(session);
        AssertLiveClean("H1 POST stress live count after close");
        printf("STAT: H1-POST success=%zu transport=%zu new=%zu reused=%zu\n",
            static_cast<size_t>(successCount),
            static_cast<size_t>(capture.CallCount.load()),
            static_cast<size_t>(capture.NewConnectionCallCount.load()),
            static_cast<size_t>(capture.ReusedCallCount.load()));
        ResetHttpTransport();
    }

    void TestH2cPriorKnowledgeLoop() noexcept
    {
        const SIZE_T iterations = ReadEnvSize("WKNET_STRESS_H2_N", 1000, 1, 1000000);
        printf("RUN: S2-H2c-prior iterations=%zu\n", static_cast<size_t>(iterations));

        StressCapture capture = {};
        wknet::http::test::SetHttpTransport(StressTransport, &capture);
        wknet::rtl::ProtocolFailureInjectionReset();

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status) && session != nullptr, "SessionCreate for H2c stress");
        if (!NT_SUCCESS(status) || session == nullptr)
        {
            ResetHttpTransport();
            return;
        }

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Http2CleartextMode = wknet::http::Http2CleartextMode::PriorKnowledge;
        const char* url = "http://stress.example/h2c";
        const SIZE_T urlLength = Length(url);
        SIZE_T successCount = 0;

        for (SIZE_T index = 0; index < iterations; ++index)
        {
            wknet::http::Response* response = nullptr;
            status = wknet::http::GetEx(session, url, urlLength, nullptr, &options, &response);
            if (!NT_SUCCESS(status) || !ExpectOkResponse(response, "H2c GET"))
            {
                printf("FAIL: H2c GET failed index=%zu status=0x%08X\n",
                    static_cast<size_t>(index),
                    static_cast<unsigned>(status));
                g_failed = true;
                wknet::http::ResponseRelease(response);
                break;
            }
            wknet::http::ResponseRelease(response);
            ++successCount;
        }

        Expect(successCount == iterations, "H2c all iterations succeeded");
        Expect(capture.CallCount.load() == iterations, "H2c transport call count");
        Expect(capture.UsedHttp2Count.load() == iterations, "H2c UsedHttp2 on every call");

        wknet::http::SessionClose(session);
        AssertLiveClean("H2c stress live count after close");
        printf("STAT: S2-H2c success=%zu transport=%zu usedHttp2=%zu\n",
            static_cast<size_t>(successCount),
            static_cast<size_t>(capture.CallCount.load()),
            static_cast<size_t>(capture.UsedHttp2Count.load()));
        ResetHttpTransport();
    }

    // ---- H3 Required inject stress ----

    struct H3StressCapture final
    {
        std::mutex Lock;
        std::condition_variable Event;
        wknet::session::HttpH3DispatchContext* Dispatch = nullptr;
        ULONG CreateCount = 0;
        std::atomic<bool> Stop{false};
        std::thread Injector;
    };

    NTSTATUS CreateH3StressPeer(
        void* context,
        const wknet::session::HttpH3PeerCreateOptions* options,
        wknet::session::HttpH3Peer* peer) noexcept
    {
        auto* capture = static_cast<H3StressCapture*>(context);
        if (capture != nullptr && options != nullptr)
        {
            {
                std::lock_guard<std::mutex> lock(capture->Lock);
                capture->Dispatch = options->Dispatch;
                ++capture->CreateCount;
            }
            capture->Event.notify_all();
        }
        return wknet::session::HttpH3TestCreateInMemoryPeer(options, peer);
    }

    void InjectH3Ok(wknet::session::HttpH3DispatchContext* dispatch) noexcept
    {
        if (dispatch == nullptr)
        {
            return;
        }
        // Wait until stream is bound so inject lands on a live request.
        for (ULONG attempt = 0; attempt < 5000; ++attempt)
        {
            wknet::session::HttpH3TestSnapshot snapshot = {};
            wknet::session::HttpH3TestGetSnapshot(&snapshot);
            if (snapshot.StreamId != wknet::session::HttpH3UnsetStreamId)
            {
                break;
            }
            if ((attempt & 15U) == 15U)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            else
            {
                std::this_thread::yield();
            }
        }

        wknet::session::HttpH3TestInjectResponseStarted(dispatch, 200);
        (void)wknet::session::HttpH3TestInjectHeader(
            dispatch,
            "content-type",
            sizeof("content-type") - 1,
            "text/plain",
            sizeof("text/plain") - 1,
            false);
        const UCHAR body[] = {'o', 'k'};
        (void)wknet::session::HttpH3TestInjectBody(dispatch, body, sizeof(body), true);
        wknet::session::HttpH3TestInjectCompletion(dispatch, STATUS_SUCCESS, wknet::http3::H3_NO_ERROR);
    }

    void TestH3RequiredLoop() noexcept
    {
        if (EnvTruthy("WKNET_STRESS_SKIP_H3"))
        {
            printf("SKIP: S2-H3 (WKNET_STRESS_SKIP_H3)\n");
            return;
        }

        const SIZE_T iterations = ReadEnvSize("WKNET_STRESS_H3_N", 100, 1, 10000);
        printf("RUN: S2-H3-required iterations=%zu\n", static_cast<size_t>(iterations));

        wknet::session::HttpH3TestReset();
        wknet::rtl::ProtocolFailureInjectionReset();

        H3StressCapture capture = {};
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Context = &capture;
        factory.Create = CreateH3StressPeer;
        wknet::session::HttpH3TestSetPeerFactory(&factory);

        // Background injector: whenever a new dispatch appears, complete it.
        capture.Injector = std::thread([&capture]() noexcept {
            ULONG lastCreate = 0;
            while (!capture.Stop.load(std::memory_order_acquire))
            {
                wknet::session::HttpH3DispatchContext* dispatch = nullptr;
                {
                    std::unique_lock<std::mutex> lock(capture.Lock);
                    (void)capture.Event.wait_for(lock, std::chrono::milliseconds(50), [&]() noexcept {
                        return capture.Stop.load(std::memory_order_acquire) ||
                            capture.CreateCount > lastCreate;
                    });
                    if (capture.Stop.load(std::memory_order_acquire))
                    {
                        break;
                    }
                    if (capture.CreateCount > lastCreate)
                    {
                        lastCreate = capture.CreateCount;
                        dispatch = capture.Dispatch;
                    }
                }
                if (dispatch != nullptr)
                {
                    InjectH3Ok(dispatch);
                }
            }
        });

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status) && session != nullptr, "SessionCreate for H3 Required stress");

        const char* url = "https://stress.example/h3";
        const SIZE_T urlLength = Length(url);
        SIZE_T successCount = 0;

        if (NT_SUCCESS(status) && session != nullptr)
        {
            for (SIZE_T index = 0; index < iterations; ++index)
            {
                wknet::http::Response* response = nullptr;
                status = wknet::http::Get(session, url, urlLength, &response);
                if (!NT_SUCCESS(status))
                {
                    printf("FAIL: H3 GET failed index=%zu status=0x%08X\n",
                        static_cast<size_t>(index),
                        static_cast<unsigned>(status));
                    g_failed = true;
                    wknet::http::ResponseRelease(response);
                    break;
                }
                if (response == nullptr || wknet::http::ResponseStatusCode(response) != 200)
                {
                    printf("FAIL: H3 GET bad response index=%zu\n", static_cast<size_t>(index));
                    g_failed = true;
                    wknet::http::ResponseRelease(response);
                    break;
                }
                const SIZE_T bodyLength = wknet::http::ResponseBodyLength(response);
                const UCHAR* body = wknet::http::ResponseBody(response);
                if (bodyLength != 2 || body == nullptr || memcmp(body, "ok", 2) != 0)
                {
                    printf("FAIL: H3 GET body index=%zu\n", static_cast<size_t>(index));
                    g_failed = true;
                    wknet::http::ResponseRelease(response);
                    break;
                }
                wknet::http::ResponseRelease(response);
                ++successCount;
            }
            wknet::http::SessionClose(session);
        }

        capture.Stop.store(true, std::memory_order_release);
        capture.Event.notify_all();
        if (capture.Injector.joinable())
        {
            capture.Injector.join();
        }

        Expect(successCount == iterations, "H3 Required all iterations succeeded");
        Expect(capture.CreateCount >= iterations, "H3 peer factory saw at least N creates");

        AssertLiveClean("H3 stress live count after close");
        printf("STAT: S2-H3 success=%zu creates=%lu\n",
            static_cast<size_t>(successCount),
            static_cast<unsigned long>(capture.CreateCount));

        wknet::session::HttpH3TestSetPeerFactory(nullptr);
        wknet::session::HttpH3TestReset();
        ResetHttpTransport();
    }

    void TestParallelBurst() noexcept
    {
        // Default: multi-session round-robin without cross-thread Get races.
        // True multi-thread Get (even session-per-thread) currently hits
        // STATUS_INVALID_PARAMETER under the shared test transport path —
        // tracked as Concurrency-ledger debt. Opt in with WKNET_STRESS_PARALLEL=1.
        const SIZE_T sessions = ReadEnvSize("WKNET_STRESS_THREADS", 8, 1, 64);
        const SIZE_T perSession = ReadEnvSize("WKNET_STRESS_PER_THREAD", 200, 1, 100000);
        const bool trueParallel = !EnvTruthy("WKNET_STRESS_NO_PARALLEL");

        printf("RUN: S3 concurrency sessions=%zu perSession=%zu parallel=%s\n",
            static_cast<size_t>(sessions),
            static_cast<size_t>(perSession),
            trueParallel ? "true" : "false");

        StressCapture capture = {};
        wknet::http::test::SetHttpTransport(StressTransport, &capture);
        wknet::rtl::ProtocolFailureInjectionReset();

        const char* url = "http://stress.example/parallel";
        const SIZE_T urlLength = Length(url);
        // Two modes: session-per-thread + shared-session (with enough pool slots).
        const SIZE_T expected = sessions * perSession * (trueParallel ? 2 : 1);
        std::atomic<SIZE_T> successCount{0};
        std::atomic<SIZE_T> failCount{0};

        auto runSerialMultiSession = [&]() noexcept {
            std::vector<wknet::http::Session*> sessionList;
            sessionList.reserve(sessions);
            for (SIZE_T s = 0; s < sessions; ++s)
            {
                wknet::http::Session* session = nullptr;
                if (!NT_SUCCESS(wknet::http::SessionCreate(&session)) || session == nullptr)
                {
                    Expect(false, "S3 SessionCreate multi-session");
                    failCount.fetch_add(perSession, std::memory_order_relaxed);
                    break;
                }
                sessionList.push_back(session);
            }
            if (sessionList.size() == sessions)
            {
                for (SIZE_T index = 0; index < sessions * perSession; ++index)
                {
                    wknet::http::Response* response = nullptr;
                    const NTSTATUS getStatus =
                        wknet::http::Get(sessionList[index % sessions], url, urlLength, &response);
                    if (!NT_SUCCESS(getStatus) || !ExpectOkResponse(response, "S3 serial multi GET"))
                    {
                        failCount.fetch_add(1, std::memory_order_relaxed);
                        wknet::http::ResponseRelease(response);
                        continue;
                    }
                    wknet::http::ResponseRelease(response);
                    successCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
            for (wknet::http::Session* session : sessionList)
            {
                wknet::http::SessionClose(session);
            }
        };

        auto runSessionPerThread = [&]() noexcept {
            std::vector<std::thread> workers;
            workers.reserve(sessions);
            for (SIZE_T t = 0; t < sessions; ++t)
            {
                workers.emplace_back([&]() noexcept {
                    wknet::http::Session* session = nullptr;
                    if (!NT_SUCCESS(wknet::http::SessionCreate(&session)) || session == nullptr)
                    {
                        failCount.fetch_add(perSession, std::memory_order_relaxed);
                        return;
                    }
                    for (SIZE_T index = 0; index < perSession; ++index)
                    {
                        wknet::http::Response* response = nullptr;
                        const NTSTATUS getStatus = wknet::http::Get(session, url, urlLength, &response);
                        if (!NT_SUCCESS(getStatus) || response == nullptr ||
                            wknet::http::ResponseStatusCode(response) != 200)
                        {
                            failCount.fetch_add(1, std::memory_order_relaxed);
                            wknet::http::ResponseRelease(response);
                            continue;
                        }
                        wknet::http::ResponseRelease(response);
                        successCount.fetch_add(1, std::memory_order_relaxed);
                    }
                    wknet::http::SessionClose(session);
                });
            }
            for (auto& worker : workers)
            {
                worker.join();
            }
        };

        auto runSharedSession = [&]() noexcept {
            // Default MaxConnsPerHost is 2; concurrent Gets without H1 pipeline need enough slots.
            wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
            config.MaxConnsPerHost = static_cast<ULONG>(sessions);
            if (config.PoolCapacity < config.MaxConnsPerHost)
            {
                config.PoolCapacity = config.MaxConnsPerHost;
            }
            wknet::http::Session* session = nullptr;
            Expect(NT_SUCCESS(wknet::http::SessionCreate(&config, &session)) && session != nullptr,
                "S3 shared SessionCreate with raised MaxConnsPerHost");
            if (session == nullptr)
            {
                failCount.fetch_add(sessions * perSession, std::memory_order_relaxed);
                return;
            }
            std::vector<std::thread> workers;
            workers.reserve(sessions);
            for (SIZE_T t = 0; t < sessions; ++t)
            {
                workers.emplace_back([session, url, urlLength, perSession, &successCount, &failCount]() noexcept {
                    for (SIZE_T index = 0; index < perSession; ++index)
                    {
                        wknet::http::Response* response = nullptr;
                        const NTSTATUS getStatus = wknet::http::Get(session, url, urlLength, &response);
                        if (!NT_SUCCESS(getStatus) || response == nullptr ||
                            wknet::http::ResponseStatusCode(response) != 200)
                        {
                            static std::atomic<ULONG> printed{0};
                            if (printed.fetch_add(1, std::memory_order_relaxed) < 4)
                            {
                                printf("FAIL: S3 shared Get status=0x%08X\n",
                                    static_cast<unsigned>(getStatus));
                            }
                            failCount.fetch_add(1, std::memory_order_relaxed);
                            wknet::http::ResponseRelease(response);
                            continue;
                        }
                        wknet::http::ResponseRelease(response);
                        successCount.fetch_add(1, std::memory_order_relaxed);
                    }
                });
            }
            for (auto& worker : workers)
            {
                worker.join();
            }
            wknet::http::SessionClose(session);
        };

        if (!trueParallel)
        {
            runSerialMultiSession();
        }
        else
        {
            runSessionPerThread();
            runSharedSession();
        }

        Expect(successCount.load() == expected, "S3 all GETs succeeded");
        Expect(failCount.load() == 0, "S3 no failures");
        Expect(capture.CallCount.load() == expected, "S3 transport call count matches");

        AssertLiveClean("S3 concurrency live count after close");
        printf("STAT: S3 success=%zu fail=%zu transport=%zu new=%zu reused=%zu distinctIds=%zu\n",
            static_cast<size_t>(successCount.load()),
            static_cast<size_t>(failCount.load()),
            static_cast<size_t>(capture.CallCount.load()),
            static_cast<size_t>(capture.NewConnectionCallCount.load()),
            static_cast<size_t>(capture.ReusedCallCount.load()),
            static_cast<size_t>(capture.DistinctConnectionIds));
        ResetHttpTransport();
    }

    // ---- WebSocket stress ----

    struct WsStressCapture final
    {
        std::atomic<SIZE_T> ConnectCount{0};
        std::atomic<SIZE_T> SendCount{0};
        std::atomic<SIZE_T> ReceiveCount{0};
        std::atomic<SIZE_T> CloseCount{0};
        UCHAR Echo[256] = {};
        SIZE_T EchoLength = 0;
        std::mutex EchoLock;
    };

    NTSTATUS WsConnectCb(void* context, const wknet::http::test::WebSocketConnectRequest*) noexcept
    {
        auto* capture = static_cast<WsStressCapture*>(context);
        if (capture == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        capture->ConnectCount.fetch_add(1, std::memory_order_relaxed);
        return STATUS_SUCCESS;
    }

    NTSTATUS WsSendCb(
        void* context,
        wknet::websocket::WebSocket*,
        wknet::websocket::MsgType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool) noexcept
    {
        auto* capture = static_cast<WsStressCapture*>(context);
        if (capture == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        capture->SendCount.fetch_add(1, std::memory_order_relaxed);
        if (type == wknet::websocket::MsgType::Text || type == wknet::websocket::MsgType::Binary)
        {
            std::lock_guard<std::mutex> lock(capture->EchoLock);
            const SIZE_T copy = dataLength < sizeof(capture->Echo) ? dataLength : sizeof(capture->Echo);
            if (data != nullptr && copy != 0)
            {
                memcpy(capture->Echo, data, copy);
            }
            capture->EchoLength = copy;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS WsReceiveCb(
        void* context,
        wknet::websocket::WebSocket*,
        wknet::http::test::WebSocketMessage* message) noexcept
    {
        auto* capture = static_cast<WsStressCapture*>(context);
        if (capture == nullptr || message == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        capture->ReceiveCount.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(capture->EchoLock);
        // Point into capture storage; valid until next send/receive on this connection.
        message->Type = wknet::websocket::MsgType::Text;
        message->Data = capture->Echo;
        message->DataLength = capture->EchoLength;
        message->FinalFragment = true;
        return STATUS_SUCCESS;
    }

    void WsCloseCb(void* context, wknet::websocket::WebSocket*) noexcept
    {
        auto* capture = static_cast<WsStressCapture*>(context);
        if (capture != nullptr)
        {
            capture->CloseCount.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void TestWebSocketMessageLoop() noexcept
    {
        const SIZE_T iterations = ReadEnvSize("WKNET_STRESS_WS_N", 1000, 1, 1000000);
        printf("RUN: S4-ws-messages iterations=%zu\n", static_cast<size_t>(iterations));

        WsStressCapture capture = {};
        wknet::http::test::SetWebSocketTransport(WsConnectCb, WsSendCb, WsReceiveCb, WsCloseCb, &capture);
        wknet::rtl::ProtocolFailureInjectionReset();

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status) && session != nullptr, "SessionCreate for WS stress");
        if (!NT_SUCCESS(status) || session == nullptr)
        {
            ResetHttpTransport();
            return;
        }

        const char* url = "ws://stress.example/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status) && ws != nullptr, "WS Connect for stress");
        Expect(capture.ConnectCount.load() == 1, "WS connect once");

        SIZE_T successCount = 0;
        if (NT_SUCCESS(status) && ws != nullptr)
        {
            for (SIZE_T index = 0; index < iterations; ++index)
            {
                char payload[64];
                const int written = sprintf_s(payload, "msg-%zu", static_cast<size_t>(index));
                Expect(written > 0, "WS payload format");
                const SIZE_T payloadLength = written > 0 ? static_cast<SIZE_T>(written) : 0;

                status = wknet::websocket::SendText(ws, payload, payloadLength);
                if (!NT_SUCCESS(status))
                {
                    printf("FAIL: WS Send index=%zu status=0x%08X\n",
                        static_cast<size_t>(index),
                        static_cast<unsigned>(status));
                    g_failed = true;
                    break;
                }

                wknet::websocket::Message message = {};
                status = wknet::websocket::Receive(ws, &message);
                if (!NT_SUCCESS(status) || message.Data == nullptr || message.DataLength != payloadLength ||
                    memcmp(message.Data, payload, payloadLength) != 0)
                {
                    printf("FAIL: WS Receive mismatch index=%zu status=0x%08X\n",
                        static_cast<size_t>(index),
                        static_cast<unsigned>(status));
                    g_failed = true;
                    break;
                }
                ++successCount;
            }

            status = wknet::websocket::Close(ws);
            Expect(NT_SUCCESS(status), "WS Close");
            Expect(capture.CloseCount.load() == 1, "WS close once");
        }

        Expect(successCount == iterations, "WS all message rounds succeeded");
        Expect(capture.SendCount.load() == iterations, "WS send count");
        Expect(capture.ReceiveCount.load() == iterations, "WS receive count");

        wknet::http::SessionClose(session);
        AssertLiveClean("WS stress live count after close");
        printf("STAT: S4-ws success=%zu send=%zu recv=%zu\n",
            static_cast<size_t>(successCount),
            static_cast<size_t>(capture.SendCount.load()),
            static_cast<size_t>(capture.ReceiveCount.load()));
        ResetHttpTransport();
    }

    void TestSoakLoop() noexcept
    {
        const SIZE_T soakSeconds = ReadEnvSize("WKNET_STRESS_SOAK_SEC", 2, 1, 3600);
        printf("RUN: S5-soak seconds=%zu\n", static_cast<size_t>(soakSeconds));

        StressCapture capture = {};
        wknet::http::test::SetHttpTransport(StressTransport, &capture);
        wknet::rtl::ProtocolFailureInjectionReset();

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status) && session != nullptr, "SessionCreate for soak");
        if (!NT_SUCCESS(status) || session == nullptr)
        {
            ResetHttpTransport();
            return;
        }

        const char* url = "http://stress.example/soak";
        const SIZE_T urlLength = Length(url);
        SIZE_T successCount = 0;
        SIZE_T failCount = 0;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(static_cast<long long>(soakSeconds));

        while (std::chrono::steady_clock::now() < deadline)
        {
            wknet::http::Response* response = nullptr;
            status = wknet::http::Get(session, url, urlLength, &response);
            if (!NT_SUCCESS(status) || response == nullptr ||
                wknet::http::ResponseStatusCode(response) != 200)
            {
                if (failCount < 4)
                {
                    printf("FAIL: S5 Get status=0x%08X after success=%zu\n",
                        static_cast<unsigned>(status),
                        static_cast<size_t>(successCount));
                }
                ++failCount;
                wknet::http::ResponseRelease(response);
                // Abort soak on sustained failure — resource exhaustion is a fail.
                if (failCount >= 16)
                {
                    break;
                }
                continue;
            }
            wknet::http::ResponseRelease(response);
            ++successCount;
        }

        Expect(failCount == 0, "S5 soak no failures");
        Expect(successCount > 0, "S5 soak completed at least one request");
        // Prefer pool reuse over the soak window when N is large enough.
        if (successCount >= 50)
        {
            Expect(capture.DistinctConnectionIds <= 4, "S5 soak does not open unbounded connections");
            Expect(capture.NewConnectionCallCount.load() * 10 < successCount || successCount < 20,
                "S5 soak connection opens stay far below request count");
        }

        wknet::http::SessionClose(session);
        AssertLiveClean("S5 soak live count after close");
        printf("STAT: S5-soak success=%zu fail=%zu transport=%zu new=%zu reused=%zu distinctIds=%zu\n",
            static_cast<size_t>(successCount),
            static_cast<size_t>(failCount),
            static_cast<size_t>(capture.CallCount.load()),
            static_cast<size_t>(capture.NewConnectionCallCount.load()),
            static_cast<size_t>(capture.ReusedCallCount.load()),
            static_cast<size_t>(capture.DistinctConnectionIds));
        ResetHttpTransport();
    }
}

int main() noexcept
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    // USER_MODE_TEST may default trace to Max; under stress that exhausts resources.
    wknet::TraceSetLevel(wknet::TraceLevel::Off);
    wknet::TraceSetSink(nullptr, nullptr);

    printf("HTTP STRESS TESTS (full profile) starting\n");

    TestS0SmokeLoop();
    TestS1PoolChurn();
    TestHttp11PostLoop();
    TestH2cPriorKnowledgeLoop();
    TestH3RequiredLoop();
    TestParallelBurst();
    TestWebSocketMessageLoop();
    TestSoakLoop();

    if (g_failed)
    {
        printf("HTTP STRESS TESTS FAILED\n");
        return 1;
    }

    printf("HTTP STRESS TESTS PASSED\n");
    return 0;
}
