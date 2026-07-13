#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/Trace.h>
#include <wknet/codec/Codec.h>
#include <wknet/crypto/Aead.h>
#include "http1/HttpParser.h"
#include "quic/QuicAttemptValidation.h"
#include "quic/QuicCrypto.h"
#include "quic/QuicPacket.h"
#include "qpack/QpackDecoder.h"
#include "qpack/QpackDynamicTable.h"
#include "rtl/TraceInternal.h"
#include "session/Async.h"
#include "session/HandleTypes.h"
#include "session/UrlParser.h"
#include "tls/TlsConnection.h"
#include "transport/Transport.h"
#include "ws/WebSocketFrame.h"

#include <atomic>
#include <stdio.h>
#include <string.h>
#include <thread>

namespace
{
    bool g_failed = false;
    ULONG g_sinkCalls = 0;
    wknet::TraceLevel g_lastLevel = wknet::TraceLevel::Off;
    ULONG g_lastComponent = wknet::ComponentNone;
    char g_lastMessage[8192] = {};
    ULONG g_recursiveDepth = 0;
    constexpr ULONG SinkContextMagicA = 0x54524341;
    constexpr ULONG SinkContextMagicB = 0x54524342;

    struct SinkContext final
    {
        ULONG Magic = 0;
        std::atomic<ULONG> Calls = 0;
    };

    SinkContext g_contextA = { SinkContextMagicA };
    SinkContext g_contextB = { SinkContextMagicB };
    std::atomic<bool> g_badSinkContext = false;
    std::atomic<bool> g_startConcurrentWriter = false;
    char g_longMessage[8192] = {};
    ULONG g_seenBusinessEvents = 0;
    bool g_sensitiveValueLeaked = false;

    constexpr ULONG SeenRtl = 1u << 0;
    constexpr ULONG SeenCodec = 1u << 1;
    constexpr ULONG SeenCrypto = 1u << 2;
    constexpr ULONG SeenHttp1 = 1u << 3;
    constexpr ULONG SeenWs = 1u << 4;
    constexpr ULONG SeenTransport = 1u << 5;
    constexpr ULONG SeenTls = 1u << 6;
    constexpr ULONG SeenSession = 1u << 7;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void ResetCapture() noexcept
    {
        g_sinkCalls = 0;
        g_lastLevel = wknet::TraceLevel::Off;
        g_lastComponent = wknet::ComponentNone;
        g_lastMessage[0] = '\0';
    }

    void CaptureTrace(
        _In_opt_ void* context,
        wknet::TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        ++g_sinkCalls;
        g_lastLevel = level;
        g_lastComponent = component;
        (void)strncpy_s(g_lastMessage, message, _TRUNCATE);
        if (strstr(message, "rtl.url.parse_request.") != nullptr) g_seenBusinessEvents |= SeenRtl;
        if (strstr(message, "codec.decode_one.") != nullptr) g_seenBusinessEvents |= SeenCodec;
        if (strstr(message, "crypto.aead.") != nullptr) g_seenBusinessEvents |= SeenCrypto;
        if (strstr(message, "http1.response.parse.") != nullptr) g_seenBusinessEvents |= SeenHttp1;
        if (strstr(message, "ws.frame.") != nullptr) g_seenBusinessEvents |= SeenWs;
        if (strstr(message, "transport.") != nullptr) g_seenBusinessEvents |= SeenTransport;
        if (strstr(message, "tls.handshake.") != nullptr) g_seenBusinessEvents |= SeenTls;
        if (strstr(message, "async.operation.") != nullptr) g_seenBusinessEvents |= SeenSession;
        if (strstr(message, "Bearer-secret") != nullptr ||
            strstr(message, "cookie-secret") != nullptr ||
            strstr(message, "body-secret") != nullptr ||
            strstr(message, "key-secret") != nullptr ||
            strstr(message, "query-secret") != nullptr) {
            g_sensitiveValueLeaked = true;
        }
    }

    void RecursiveTraceSink(
        _In_opt_ void* context,
        wknet::TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(component);
        UNREFERENCED_PARAMETER(message);

        ++g_recursiveDepth;
        if (g_recursiveDepth < 40) {
            WKNET_TRACE(
                wknet::ComponentRtl,
                wknet::TraceLevel::Max,
                "trace.recursive depth=%u",
                g_recursiveDepth);
        }
        --g_recursiveDepth;
    }

    void ContextCheckingSink(
        _In_opt_ void* context,
        wknet::TraceLevel level,
        ULONG component,
        _In_z_ const char* message) noexcept
    {
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(component);
        UNREFERENCED_PARAMETER(message);

        auto* sinkContext = static_cast<SinkContext*>(context);
        if (sinkContext == nullptr ||
            (sinkContext->Magic != SinkContextMagicA && sinkContext->Magic != SinkContextMagicB)) {
            g_badSinkContext.store(true, std::memory_order_release);
            return;
        }
        (void)sinkContext->Calls.fetch_add(1, std::memory_order_acq_rel);
    }

    void ConcurrentTraceWriter() noexcept
    {
        while (!g_startConcurrentWriter.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }

        for (ULONG index = 0; index < 20000; ++index) {
            WKNET_TRACE(
                wknet::ComponentRtl,
                wknet::TraceLevel::Max,
                "trace.concurrent index=%u",
                index);
        }
    }

    NTSTATUS TestTransportSend(void*, const void*, SIZE_T length, SIZE_T* bytesSent) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = length;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TestTransportReceive(void*, void*, SIZE_T, SIZE_T* bytesReceived) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TestAsyncWorker(wknet::session::AsyncOperationHandle, void*) noexcept
    {
        return STATUS_SUCCESS;
    }

    void TestBusinessEventCoverage() noexcept
    {
        g_seenBusinessEvents = 0;
        g_sensitiveValueLeaked = false;
        wknet::TraceSetSink(CaptureTrace, nullptr);
        wknet::TraceSetComponents(wknet::ComponentAll);
        wknet::TraceSetLevel(wknet::TraceLevel::Max);

        wknet::session::Request request = {};
        const char url[] = "https://example.test/path?token=query-secret";
        (void)wknet::session::ParseUrlIntoRequest(request, url, sizeof(url) - 1);

        const char body[] = "body-secret";
        char decoded[32] = {};
        SIZE_T decodedLength = 0;
        (void)wknet::codec::DecodeOne(
            wknet::codec::Coding::Identity,
            body,
            sizeof(body) - 1,
            decoded,
            sizeof(decoded),
            &decodedLength);

        const UCHAR keyBytes[] = "key-secret";
        wknet::crypto::AeadKey key = {};
        key.Algorithm = wknet::crypto::AeadAlgorithm::Aes128Gcm;
        key.Key = keyBytes;
        key.KeyLength = sizeof(keyBytes) - 1;
        wknet::crypto::AeadParameters aeadParameters = {};
        UCHAR ciphertext[32] = {};
        UCHAR tag[16] = {};
        (void)wknet::crypto::Aead::Encrypt(
            nullptr,
            key,
            aeadParameters,
            reinterpret_cast<const UCHAR*>(body),
            sizeof(body) - 1,
            ciphertext,
            sizeof(ciphertext),
            tag,
            sizeof(tag),
            nullptr);

        const char responseText[] =
            "HTTP/1.1 200 OK\r\n"
            "Authorization: Bearer-secret\r\n"
            "Set-Cookie: cookie-secret\r\n"
            "Content-Length: 11\r\n"
            "\r\n"
            "body-secret";
        wknet::http1::HttpHeader headers[8] = {};
        wknet::http1::HttpResponse response = {};
        wknet::http1::HttpParseOptions parseOptions = {};
        parseOptions.Headers = headers;
        parseOptions.HeaderCapacity = sizeof(headers) / sizeof(headers[0]);
        (void)wknet::http1::HttpParser::ParseResponse(
            responseText,
            sizeof(responseText) - 1,
            parseOptions,
            response);

        const UCHAR framePayload[] = "body-secret";
        const UCHAR maskingKey[4] = { 1, 2, 3, 4 };
        UCHAR frame[64] = {};
        SIZE_T frameLength = 0;
        (void)wknet::ws::WebSocketCodec::EncodeClientFrame(
            wknet::ws::WebSocketOpcode::Text,
            true,
            framePayload,
            sizeof(framePayload) - 1,
            maskingKey,
            frame,
            sizeof(frame),
            &frameLength);

        wknet::transport::TransportCallbacks callbacks = {};
        callbacks.Send = TestTransportSend;
        callbacks.Receive = TestTransportReceive;
        wknet::transport::Transport* transport = nullptr;
        if (NT_SUCCESS(wknet::transport::TransportCreateCallbacks(&callbacks, nullptr, &transport))) {
            wknet::transport::TransportSetConnectionId(transport, 9001);
            SIZE_T sent = 0;
            (void)wknet::transport::TransportSend(
                transport,
                body,
                sizeof(body) - 1,
                &sent);
            wknet::transport::TransportClose(transport);
        }

        wknet::tls::TlsConnection* tlsConnection = nullptr;
        if (NT_SUCCESS(wknet::tls::TlsConnectionCreate(&tlsConnection))) {
            wknet::tls::TlsConnectionSetConnectionId(tlsConnection, 9002);
            wknet::tls::TlsClientConnectionOptions tlsOptions = {};
            tlsOptions.ServerName = "secret.example";
            tlsOptions.ServerNameLength = sizeof("secret.example") - 1;
            tlsOptions.VerifyCertificate = true;
            tlsOptions.CertificateStore = nullptr;
            (void)wknet::tls::TlsConnectionConnect(tlsConnection, nullptr, &tlsOptions);
            wknet::tls::TlsConnectionClose(tlsConnection);
        }

        wknet::session::AsyncCreateOptions asyncOptions = {};
        asyncOptions.WorkerRoutine = TestAsyncWorker;
        asyncOptions.StartSuspended = true;
        wknet::session::AsyncOperationHandle operation = nullptr;
        if (NT_SUCCESS(wknet::session::AsyncOperationCreate(asyncOptions, &operation))) {
            (void)wknet::session::TestRunAsyncOperation(operation);
            wknet::session::AsyncOperationRelease(operation);
        }

        const ULONG expected = SeenRtl | SeenCodec | SeenCrypto | SeenHttp1 |
            SeenWs | SeenTransport | SeenTls | SeenSession;
        Expect((g_seenBusinessEvents & expected) == expected,
            "representative events cover every major logging component");
        Expect(!g_sensitiveValueLeaked,
            "representative business logs never expose sensitive values");
    }

    void TestLevelThresholds() noexcept
    {
        const wknet::TraceLevel configuredLevels[] = {
            wknet::TraceLevel::Off,
            wknet::TraceLevel::Error,
            wknet::TraceLevel::Warning,
            wknet::TraceLevel::Info,
            wknet::TraceLevel::Verbose,
            wknet::TraceLevel::Max
        };
        const wknet::TraceLevel eventLevels[] = {
            wknet::TraceLevel::Error,
            wknet::TraceLevel::Warning,
            wknet::TraceLevel::Info,
            wknet::TraceLevel::Verbose,
            wknet::TraceLevel::Max
        };

        for (SIZE_T configured = 0; configured < sizeof(configuredLevels) / sizeof(configuredLevels[0]); ++configured) {
            ResetCapture();
            wknet::TraceSetLevel(configuredLevels[configured]);
            for (SIZE_T event = 0; event < sizeof(eventLevels) / sizeof(eventLevels[0]); ++event) {
                WKNET_TRACE(
                    wknet::ComponentTls,
                    eventLevels[event],
                    "trace.level configured=%Iu event=%Iu",
                    configured,
                    event);
            }
            Expect(g_sinkCalls == configured, "configured level includes every more severe level");
        }
    }

    void TestQuicAttemptTraceEvents() noexcept
    {
        wknet::TraceSetSink(CaptureTrace, nullptr);
        wknet::TraceSetComponents(wknet::ComponentQuic);
        wknet::TraceSetLevel(wknet::TraceLevel::Max);
        const UCHAR odcid[] = { 5, 6, 7, 8 };
        const UCHAR scid[] = { 1, 2, 3, 4 };
        const UCHAR versions[] = { 0x6b, 0x33, 0x43, 0xcf };
        wknet::quic::QuicPacketHeader vn = {};
        vn.Type = wknet::quic::QuicPacketType::VersionNegotiation;
        vn.DestinationConnectionId = { scid, sizeof(scid) };
        vn.SourceConnectionId = { odcid, sizeof(odcid) };
        vn.VersionList = { versions, sizeof(versions) };
        wknet::quic::QuicAttemptValidation attempt;
        (void)attempt.Initialize(wknet::quic::QuicVersion1,
            { odcid, sizeof(odcid) }, { scid, sizeof(scid) });
        const ULONG supported[] = { wknet::quic::QuicVersion1 };
        ResetCapture();
        (void)attempt.ValidateVersionNegotiation(vn, supported, 1, nullptr);
        Expect(g_lastLevel == wknet::TraceLevel::Info &&
            strstr(g_lastMessage, "quic.version_negotiation.accepted") != nullptr,
            "valid VN emits the frozen accepted event");
        Expect(strstr(g_lastMessage, "05060708") == nullptr,
            "VN trace does not expose CID bytes");

        const UCHAR retryPrefix[] = {
            0xff,0,0,0,1,0,8,0xf0,0x67,0xa5,0x50,0x2a,0x42,0x62,
            0x74,0x6f,0x6b,0x65,0x6e
        };
        UCHAR retry[sizeof(retryPrefix) + wknet::quic::QuicRetryIntegrityTagLength] = {};
        RtlCopyMemory(retry, retryPrefix, sizeof(retryPrefix));
        (void)wknet::quic::QuicComputeRetryIntegrityTag(
            { odcid, sizeof(odcid) }, retry, sizeof(retryPrefix), retry + sizeof(retryPrefix));
        wknet::quic::QuicPacketHeader retryHeader = {};
        (void)wknet::quic::QuicParsePacketHeader(retry, sizeof(retry), 0, &retryHeader);
        wknet::quic::QuicAttemptValidation retryAttempt;
        (void)retryAttempt.Initialize(wknet::quic::QuicVersion1,
            { odcid, sizeof(odcid) }, { nullptr, 0 });
        ResetCapture();
        (void)retryAttempt.ValidateRetry(retryHeader, retry, sizeof(retry));
        Expect(g_lastLevel == wknet::TraceLevel::Info &&
            strstr(g_lastMessage, "quic.retry.accepted") != nullptr,
            "valid Retry emits the frozen accepted event");
        Expect(strstr(g_lastMessage, "token") == nullptr,
            "Retry trace does not expose token fields");
        wknet::TraceSetComponents(wknet::ComponentAll);
    }

    void TestQpackTraceEvents() noexcept
    {
        wknet::TraceSetSink(CaptureTrace, nullptr);
        wknet::TraceSetComponents(wknet::ComponentHttp3);
        wknet::TraceSetLevel(wknet::TraceLevel::Max);

        wknet::qpack::QpackDynamicTable table;
        Expect(NT_SUCCESS(table.Initialize(128, 128)), "QPACK trace table initializes");
        const UCHAR name[] = "authorization";
        const UCHAR value[] = "Bearer-secret";
        ResetCapture();
        Expect(NT_SUCCESS(table.Insert(name, sizeof(name) - 1, value, sizeof(value) - 1)),
            "QPACK trace table insert succeeds");
        Expect(g_lastComponent == wknet::ComponentHttp3 &&
            g_lastLevel == wknet::TraceLevel::Verbose &&
            strstr(g_lastMessage, "qpack.dynamic_table.updated") != nullptr,
            "QPACK dynamic table emits the frozen update event");
        Expect(strstr(g_lastMessage, "authorization") == nullptr &&
            strstr(g_lastMessage, "Bearer-secret") == nullptr,
            "QPACK dynamic table trace omits field names and values");

        wknet::qpack::QpackDecoder decoder;
        Expect(NT_SUCCESS(decoder.Initialize(128, 1, 128, 4)), "QPACK trace decoder initializes");
        const UCHAR invalidSection[] = { 0xff };
        wknet::qpack::QpackFieldView fields[1] = {};
        UCHAR fieldBuffer[128] = {};
        UCHAR instruction[16] = {};
        SIZE_T fieldCount = 0;
        SIZE_T fieldBufferUsed = 0;
        SIZE_T instructionLength = 0;
        ULONGLONG applicationError = 0;
        ResetCapture();
        Expect(decoder.DecodeFieldSection(
            4,
            invalidSection,
            sizeof(invalidSection),
            fields,
            sizeof(fields) / sizeof(fields[0]),
            &fieldCount,
            fieldBuffer,
            sizeof(fieldBuffer),
            &fieldBufferUsed,
            instruction,
            sizeof(instruction),
            &instructionLength,
            &applicationError) == STATUS_INVALID_NETWORK_RESPONSE,
            "malformed QPACK field section is rejected");
        Expect(g_lastComponent == wknet::ComponentHttp3 &&
            g_lastLevel == wknet::TraceLevel::Error &&
            strstr(g_lastMessage, "qpack.decode.failed") != nullptr,
            "QPACK decode failure emits the frozen failure event");
        Expect(strstr(g_lastMessage, "Bearer-secret") == nullptr,
            "QPACK failure trace omits field values");
        wknet::TraceSetComponents(wknet::ComponentAll);
    }
}

int main()
{
    wknet::TraceSetSink(CaptureTrace, nullptr);
    wknet::TraceSetComponents(wknet::ComponentTls);
    wknet::TraceSetLevel(wknet::TraceLevel::Off);
    wknet::TraceResetStatistics();

    int formattingSideEffect = 0;
    WKNET_TRACE(
        wknet::ComponentTls,
        wknet::TraceLevel::Error,
        "trace.off side_effect=%d",
        ++formattingSideEffect);
    Expect(g_sinkCalls == 0, "Off level suppresses sink delivery");
    Expect(formattingSideEffect == 0, "Off level suppresses argument evaluation");

    TestLevelThresholds();

    ResetCapture();
    wknet::TraceSetLevel(wknet::TraceLevel::Max);
    wknet::TraceSetComponents(wknet::ComponentTls);
    WKNET_TRACE(wknet::ComponentHttp1, wknet::TraceLevel::Error, "trace.filtered");
    Expect(g_sinkCalls == 0, "component mask suppresses disabled components");

    WKNET_TRACE(wknet::ComponentTls, wknet::TraceLevel::Info, "tls.negotiated version=%u", 13u);
    Expect(g_sinkCalls == 1, "enabled trace reaches the registered sink");
    Expect(g_lastLevel == wknet::TraceLevel::Info, "sink receives the trace level");
    Expect(g_lastComponent == wknet::ComponentTls, "sink receives the trace component");
    Expect(strstr(g_lastMessage, "[TLS][INF]") != nullptr, "formatted trace identifies component and level");
    Expect(strstr(g_lastMessage, "[seq=") != nullptr, "formatted trace contains the event sequence");
    Expect(strstr(g_lastMessage, "tls.negotiated version=13") != nullptr, "formatted trace contains the event payload");
    const SIZE_T messageLength = strlen(g_lastMessage);
    Expect(messageLength >= 2 && g_lastMessage[messageLength - 2] == '\r' && g_lastMessage[messageLength - 1] == '\n',
        "trace runtime owns the CRLF line ending");

    ResetCapture();
    wknet::TraceCorrelation correlation = {};
    correlation.OperationId = 101;
    correlation.ConnectionId = 202;
    correlation.StreamId = (1ULL << 61) + 3ULL;
    WKNET_TRACE_CORRELATED(
        wknet::ComponentTransport,
        wknet::TraceLevel::Verbose,
        &correlation,
        "transport.send bytes=%u",
        512u);
    Expect(g_sinkCalls == 0, "correlated trace still honors the component mask");
    wknet::TraceSetComponents(wknet::ComponentTransport);
    WKNET_TRACE_CORRELATED(
        wknet::ComponentTransport,
        wknet::TraceLevel::Verbose,
        &correlation,
        "transport.send bytes=%u",
        512u);
    Expect(g_sinkCalls == 1, "correlated trace reaches the sink");
    Expect(strstr(g_lastMessage, "[TRANSPORT][VRB]") != nullptr, "transport component has a stable name");
    Expect(
        strstr(g_lastMessage, "[op=101][conn=202][stream=2305843009213693955]") != nullptr,
        "62-bit stream correlation identifier is formatted without truncation");

    Expect(wknet::rtl::TraceTestSlotSize() == wknet::rtl::TracePageBytes, "each trace slot occupies one page");
    Expect(wknet::rtl::TraceTestSlotAlignment() == wknet::rtl::TracePageBytes, "each trace slot is page aligned");

    for (SIZE_T index = 0; index + 1 < sizeof(g_longMessage); ++index) {
        g_longMessage[index] = 'X';
    }
    g_longMessage[sizeof(g_longMessage) - 1] = '\0';
    ResetCapture();
    wknet::TraceResetStatistics();
    WKNET_TRACE(wknet::ComponentTransport, wknet::TraceLevel::Max, "trace.long value=%s", g_longMessage);
    wknet::TraceStatistics statistics = {};
    wknet::TraceGetStatistics(&statistics);
    Expect(g_sinkCalls == 1, "truncated trace is still emitted");
    Expect(strstr(g_lastMessage, "[truncated]\r\n") != nullptr, "truncated trace is explicitly marked");
    Expect(statistics.Truncated == 1, "truncation is counted");
    Expect(statistics.Emitted == 1, "emitted trace is counted");

    wknet::TraceSetComponents(wknet::ComponentRtl);
    wknet::TraceSetSink(RecursiveTraceSink, nullptr);
    wknet::TraceResetStatistics();
    WKNET_TRACE(wknet::ComponentRtl, wknet::TraceLevel::Max, "trace.recursive depth=0");
    wknet::TraceGetStatistics(&statistics);
    Expect(statistics.DroppedBusy > 0, "recursive sink exhaustion drops instead of blocking");
    Expect(g_recursiveDepth == 0, "recursive sink unwinds cleanly");

    g_contextA.Calls.store(0, std::memory_order_release);
    g_contextB.Calls.store(0, std::memory_order_release);
    g_badSinkContext.store(false, std::memory_order_release);
    g_startConcurrentWriter.store(false, std::memory_order_release);
    wknet::TraceSetSink(ContextCheckingSink, &g_contextA);
    std::thread writerA(ConcurrentTraceWriter);
    std::thread writerB(ConcurrentTraceWriter);
    g_startConcurrentWriter.store(true, std::memory_order_release);
    for (ULONG index = 0; index < 2000; ++index) {
        wknet::TraceSetSink(ContextCheckingSink, (index & 1) == 0 ?
            static_cast<void*>(&g_contextA) : static_cast<void*>(&g_contextB));
    }
    writerA.join();
    writerB.join();
    Expect(!g_badSinkContext.load(std::memory_order_acquire), "concurrent sink replacement never exposes a mismatched context");
    Expect(g_contextA.Calls.load(std::memory_order_acquire) + g_contextB.Calls.load(std::memory_order_acquire) > 0,
        "concurrent writers reach installed sinks");

    TestBusinessEventCoverage();
    TestQuicAttemptTraceEvents();
    TestQpackTraceEvents();

    Expect(wknet::TraceGetLevel() == wknet::TraceLevel::Max, "trace level getter reports Max");
    Expect(wknet::TraceGetComponents() == wknet::ComponentAll, "component getter reports the active mask");

    wknet::TraceSetSink(nullptr, nullptr);
    wknet::TraceSetComponents(wknet::ComponentAll);
    wknet::TraceSetLevel(wknet::TraceLevel::Max);

    if (g_failed) {
        printf("TRACE TESTS FAILED\n");
        return 1;
    }

    printf("TRACE TESTS PASSED\n");
    return 0;
}
