#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "http3/Http3Connection.h"
#include "net/WskClient.h"
#include "net/WskDatagramSocketTest.h"
#include "quic/QuicClock.h"
#include "quic/QuicConnection.h"
#include "quic/QuicVarInt.h"

#include <wknet/crypto/CngProviderCache.h>

#include <chrono>
#include <condition_variable>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mutex>
#include <thread>

namespace
{
    constexpr ULONG InteropTimeoutMilliseconds = 10000;
    constexpr SIZE_T InteropBodyCapacity = 4096;
    constexpr SIZE_T InteropMaximumResponses = 4;

    bool g_failed = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition)
        {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    USHORT HostToNetwork16(USHORT value) noexcept
    {
        return static_cast<USHORT>((value >> 8) | (value << 8));
    }

    wknet::qpack::QpackStringView StringView(const UCHAR* data, SIZE_T length) noexcept
    {
        wknet::qpack::QpackStringView view = {};
        view.Data = data;
        view.Length = length;
        return view;
    }

    struct InteropResponse final
    {
        ULONGLONG StreamId = 0;
        NTSTATUS CompletionStatus = STATUS_PENDING;
        ULONGLONG ApplicationError = 0;
        ULONG StatusCode = 0;
        SIZE_T HeaderCount = 0;
        SIZE_T TrailerCount = 0;
        SIZE_T BodyLength = 0;
        UCHAR Body[InteropBodyCapacity] = {};
        bool Complete = false;
    };

    struct InteropCapture final
    {
        std::mutex Lock;
        std::condition_variable Event;
        wknet::http3::Http3Connection* Http3 = nullptr;
        InteropResponse Responses[InteropMaximumResponses] = {};
        SIZE_T ResponseCount = 0;
        SIZE_T CompletedCount = 0;
        ULONGLONG ConnectionApplicationError = 0;
        NTSTATUS ConnectionStatus = STATUS_PENDING;
        ULONGLONG GoawayId = wknet::quic::QuicVarIntMaximum;
        bool GoawayReceived = false;
        bool ConnectionError = false;
    };

    InteropResponse* FindResponse(InteropCapture* capture, ULONGLONG streamId) noexcept
    {
        for (SIZE_T index = 0; index < capture->ResponseCount; ++index)
        {
            if (capture->Responses[index].StreamId == streamId)
            {
                return &capture->Responses[index];
            }
        }
        return nullptr;
    }

    ULONG ParseStatus(const wknet::qpack::QpackFieldView* fields, SIZE_T fieldCount) noexcept
    {
        static const UCHAR statusName[] = ":status";
        for (SIZE_T index = 0; index < fieldCount; ++index)
        {
            const wknet::qpack::QpackFieldView& field = fields[index];
            if (field.Name.Length != sizeof(statusName) - 1 || field.Value.Length != 3 ||
                memcmp(field.Name.Data, statusName, sizeof(statusName) - 1) != 0)
            {
                continue;
            }
            ULONG status = 0;
            for (SIZE_T digit = 0; digit < 3; ++digit)
            {
                if (field.Value.Data[digit] < '0' || field.Value.Data[digit] > '9')
                {
                    return 0;
                }
                status = (status * 10) + static_cast<ULONG>(field.Value.Data[digit] - '0');
            }
            return status;
        }
        return 0;
    }

    void OnHeaders(void* context, ULONGLONG streamId, const wknet::qpack::QpackFieldView* fields, SIZE_T fieldCount,
                   bool trailers) noexcept
    {
        InteropCapture* capture = static_cast<InteropCapture*>(context);
        std::lock_guard<std::mutex> guard(capture->Lock);
        InteropResponse* response = FindResponse(capture, streamId);
        if (response == nullptr)
        {
            return;
        }
        if (trailers)
        {
            response->TrailerCount += fieldCount;
        }
        else
        {
            response->HeaderCount += fieldCount;
            const ULONG status = ParseStatus(fields, fieldCount);
            if (status != 0)
            {
                response->StatusCode = status;
            }
        }
    }

    void OnData(void* context, ULONGLONG streamId, const UCHAR* data, SIZE_T length) noexcept
    {
        InteropCapture* capture = static_cast<InteropCapture*>(context);
        std::lock_guard<std::mutex> guard(capture->Lock);
        InteropResponse* response = FindResponse(capture, streamId);
        if (response == nullptr || data == nullptr || length > InteropBodyCapacity - response->BodyLength)
        {
            return;
        }
        RtlCopyMemory(response->Body + response->BodyLength, data, length);
        response->BodyLength += length;
    }

    void OnComplete(void* context, ULONGLONG streamId, NTSTATUS status, ULONGLONG applicationError) noexcept
    {
        InteropCapture* capture = static_cast<InteropCapture*>(context);
        {
            std::lock_guard<std::mutex> guard(capture->Lock);
            InteropResponse* response = FindResponse(capture, streamId);
            if (response == nullptr)
            {
                return;
            }
            response->CompletionStatus = status;
            response->ApplicationError = applicationError;
            if (!response->Complete)
            {
                response->Complete = true;
                ++capture->CompletedCount;
            }
        }
        capture->Event.notify_all();
    }

    void OnGoaway(void* context, ULONGLONG streamId) noexcept
    {
        InteropCapture* capture = static_cast<InteropCapture*>(context);
        {
            std::lock_guard<std::mutex> guard(capture->Lock);
            capture->GoawayId = streamId;
            capture->GoawayReceived = true;
        }
        capture->Event.notify_all();
    }

    void OnConnectionError(void* context, NTSTATUS status, ULONGLONG applicationError) noexcept
    {
        InteropCapture* capture = static_cast<InteropCapture*>(context);
        {
            std::lock_guard<std::mutex> guard(capture->Lock);
            capture->ConnectionStatus = status;
            capture->ConnectionApplicationError = applicationError;
            capture->ConnectionError = true;
        }
        capture->Event.notify_all();
    }

    struct SubmitRequestContext final
    {
        InteropCapture* Capture = nullptr;
        const char* Scenario = nullptr;
    };

    NTSTATUS SubmitRequest(void* context, wknet::quic::QuicConnection* connection) noexcept
    {
        UNREFERENCED_PARAMETER(connection);
        SubmitRequestContext* submit = static_cast<SubmitRequestContext*>(context);
        if (submit == nullptr || submit->Capture == nullptr || submit->Capture->Http3 == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        static const UCHAR getMethod[] = "GET";
        static const UCHAR headMethod[] = "HEAD";
        static const UCHAR postMethod[] = "POST";
        static const UCHAR scheme[] = "https";
        static const UCHAR authority[] = "localhost";
        static const UCHAR path[] = "/interop";
        static const UCHAR postBody[] = "wknet-http3-post-body";

        const bool requestHead = strcmp(submit->Scenario, "head-no-body") == 0;
        const bool requestPost = strcmp(submit->Scenario, "post-request-body") == 0;
        const bool concurrent = strcmp(submit->Scenario, "concurrent") == 0;
        const bool cancel = strcmp(submit->Scenario, "cancel") == 0;
        const UCHAR* method = requestHead ? headMethod : (requestPost ? postMethod : getMethod);
        const SIZE_T methodLength =
            requestHead ? sizeof(headMethod) - 1 : (requestPost ? sizeof(postMethod) - 1 : sizeof(getMethod) - 1);

        wknet::http3::Http3RequestOpenOptions open = {};
        open.Fields.Method = StringView(method, methodLength);
        open.Fields.Scheme = StringView(scheme, sizeof(scheme) - 1);
        open.Fields.Authority = StringView(authority, sizeof(authority) - 1);
        open.Fields.Path = StringView(path, sizeof(path) - 1);
        open.RequestWasHead = requestHead;
        const SIZE_T requestCount = concurrent ? InteropMaximumResponses : 1;
        for (SIZE_T index = 0; index < requestCount; ++index)
        {
            ULONGLONG streamId = 0;
            NTSTATUS status = wknet::http3::Http3ConnectionWorkerOpenRequest(submit->Capture->Http3, open, &streamId);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            InteropResponse& response = submit->Capture->Responses[submit->Capture->ResponseCount];
            response.StreamId = streamId;
            ++submit->Capture->ResponseCount;

            if (cancel)
            {
                return wknet::http3::Http3ConnectionWorkerCancelRequest(submit->Capture->Http3, streamId,
                                                                        wknet::http3::H3_REQUEST_CANCELLED);
            }

            status = wknet::http3::Http3ConnectionWorkerWriteRequestData(submit->Capture->Http3, streamId,
                                                                         requestPost ? postBody : nullptr,
                                                                         requestPost ? sizeof(postBody) - 1 : 0, true);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS SubmitRequestAfterGoaway(void* context, wknet::quic::QuicConnection* connection) noexcept
    {
        UNREFERENCED_PARAMETER(connection);
        InteropCapture* capture = static_cast<InteropCapture*>(context);
        static const UCHAR getMethod[] = "GET";
        static const UCHAR scheme[] = "https";
        static const UCHAR authority[] = "localhost";
        static const UCHAR path[] = "/after-goaway";
        wknet::http3::Http3RequestOpenOptions open = {};
        open.Fields.Method = StringView(getMethod, sizeof(getMethod) - 1);
        open.Fields.Scheme = StringView(scheme, sizeof(scheme) - 1);
        open.Fields.Authority = StringView(authority, sizeof(authority) - 1);
        open.Fields.Path = StringView(path, sizeof(path) - 1);
        ULONGLONG streamId = 0;
        return wknet::http3::Http3ConnectionWorkerOpenRequest(capture->Http3, open, &streamId);
    }

    NTSTATUS StartHttp3(void* context, wknet::quic::QuicConnection* connection) noexcept
    {
        UNREFERENCED_PARAMETER(connection);
        return wknet::http3::Http3ConnectionWorkerStart(static_cast<wknet::http3::Http3Connection*>(context));
    }

    NTSTATUS CheckHttp3Ready(void* context, wknet::quic::QuicConnection* connection) noexcept
    {
        UNREFERENCED_PARAMETER(connection);
        return wknet::http3::Http3ConnectionPeerSettingsReceived(static_cast<wknet::http3::Http3Connection*>(context))
                   ? STATUS_SUCCESS
                   : STATUS_DEVICE_NOT_READY;
    }

    NTSTATUS WaitForHttp3Ready(wknet::quic::QuicConnection* quic, wknet::http3::Http3Connection* http3) noexcept
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(InteropTimeoutMilliseconds);
        for (;;)
        {
            wknet::quic::QuicOperation check = {};
            wknet::quic::QuicOperationInitialize(&check);
            NTSTATUS status = wknet::quic::QuicConnectionExecuteApplication(quic, CheckHttp3Ready, http3, &check);
            if (NT_SUCCESS(status))
            {
                status = wknet::quic::QuicOperationWait(&check, InteropTimeoutMilliseconds);
            }
            if (NT_SUCCESS(status) || status != STATUS_DEVICE_NOT_READY)
            {
                return status;
            }
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return STATUS_IO_TIMEOUT;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void CloseConnections(wknet::http3::Http3Connection* http3, wknet::quic::QuicConnection* quic) noexcept
    {
        if (http3 != nullptr)
        {
            wknet::http3::Http3ConnectionBeginShutdown(http3);
        }
        if (quic != nullptr)
        {
            wknet::quic::QuicOperation close = {};
            wknet::quic::QuicOperationInitialize(&close);
            if (NT_SUCCESS(wknet::quic::QuicConnectionCloseApplicationAsync(quic, wknet::http3::H3_NO_ERROR, &close)))
            {
                (void)wknet::quic::QuicOperationWait(&close, InteropTimeoutMilliseconds);
            }
            wknet::quic::QuicConnectionDestroy(quic);
        }
        wknet::http3::Http3ConnectionDestroy(http3);
    }

    bool RunInteropScenario(USHORT port, const char* scenario) noexcept
    {
        const bool expectVersionNegotiation = strcmp(scenario, "vn") == 0;
        const bool expectGoaway = strcmp(scenario, "goaway") == 0;
        const bool expectCancel = strcmp(scenario, "cancel") == 0;
        wknet::net::test::ResetProvider();
        wknet::quic::QuicTestClockUseSystem(true);
        if (!wknet::net::test::EnableNativeUdpProvider())
        {
            printf("FAIL: native UDP provider could not start\n");
            wknet::quic::QuicTestClockUseSystem(false);
            return false;
        }

        wknet::crypto::CngProviderCache providerCache;
        wknet::net::WskClient* client = nullptr;
        wknet::http3::Http3Connection* http3 = nullptr;
        wknet::quic::QuicConnection* quic = nullptr;
        bool success = false;

        NTSTATUS status = providerCache.Initialize();
        if (NT_SUCCESS(status))
        {
            status = wknet::net::WskClientCreate(&client);
        }
        if (NT_SUCCESS(status))
        {
            status = wknet::net::WskClientInitialize(client);
        }

        InteropCapture capture = {};
        wknet::http3::Http3ConnectionCreateOptions http3Options = {};
        http3Options.Callbacks.Context = &capture;
        http3Options.Callbacks.Headers = OnHeaders;
        http3Options.Callbacks.Data = OnData;
        http3Options.Callbacks.StreamComplete = OnComplete;
        http3Options.Callbacks.Goaway = OnGoaway;
        http3Options.Callbacks.ConnectionError = OnConnectionError;
        if (NT_SUCCESS(status))
        {
            status = wknet::http3::Http3ConnectionCreate(http3Options, &http3);
            capture.Http3 = http3;
        }

        SOCKADDR_IN remoteAddress = {};
        remoteAddress.sin_family = AF_INET;
        remoteAddress.sin_port = HostToNetwork16(port);
        remoteAddress.sin_addr = 0x0100007fUL;
        UCHAR destinationConnectionId[8] = {0x77, 0x6b, 0x6e, 0x65, 0x74, 0x01, 0x02, 0x03};
        UCHAR sourceConnectionId[8] = {0x68, 0x74, 0x74, 0x70, 0x33, 0x04, 0x05, 0x06};
        static const char serverName[] = "localhost";

        if (NT_SUCCESS(status))
        {
            wknet::quic::QuicConnectionCreateOptions quicOptions = {};
            quicOptions.DatagramClient = client;
            quicOptions.RemoteAddress = reinterpret_cast<const SOCKADDR*>(&remoteAddress);
            quicOptions.RemoteAddressLength = sizeof(remoteAddress);
            quicOptions.ServerName = serverName;
            quicOptions.ServerNameLength = sizeof(serverName) - 1;
            quicOptions.InitialDestinationConnectionId = {destinationConnectionId, sizeof(destinationConnectionId)};
            quicOptions.InitialSourceConnectionId = {sourceConnectionId, sizeof(sourceConnectionId)};
            quicOptions.ProviderCache = &providerCache;
            quicOptions.ApplicationEventSink = wknet::http3::Http3ConnectionApplicationSink(http3);
            quicOptions.VerifyCertificate = false;
            status = wknet::quic::QuicConnectionCreate(quicOptions, &quic);
        }

        wknet::quic::QuicOperation connect = {};
        if (NT_SUCCESS(status))
        {
            wknet::quic::QuicOperationInitialize(&connect);
            status = wknet::quic::QuicConnectionConnect(quic, &connect);
        }
        if (NT_SUCCESS(status))
        {
            status = wknet::quic::QuicOperationWait(&connect, InteropTimeoutMilliseconds);
        }

        wknet::quic::QuicOperation established = {};
        if (NT_SUCCESS(status))
        {
            wknet::quic::QuicOperationInitialize(&established);
            status = wknet::quic::QuicConnectionWaitEstablishedAsync(quic, &established);
        }
        if (NT_SUCCESS(status))
        {
            status = wknet::quic::QuicOperationWait(&established, InteropTimeoutMilliseconds);
        }
        if (!expectVersionNegotiation && NT_SUCCESS(status))
        {
            status = wknet::http3::Http3ConnectionBindQuic(http3, quic);
        }
        wknet::quic::QuicOperation start = {};
        if (!expectVersionNegotiation && NT_SUCCESS(status))
        {
            wknet::quic::QuicOperationInitialize(&start);
            status = wknet::quic::QuicConnectionExecuteApplication(quic, StartHttp3, http3, &start);
        }
        if (!expectVersionNegotiation && NT_SUCCESS(status))
        {
            status = wknet::quic::QuicOperationWait(&start, InteropTimeoutMilliseconds);
        }
        if (!expectVersionNegotiation && NT_SUCCESS(status))
        {
            status = WaitForHttp3Ready(quic, http3);
        }

        SubmitRequestContext submit = {};
        submit.Capture = &capture;
        submit.Scenario = scenario;
        wknet::quic::QuicOperation request = {};
        if (!expectVersionNegotiation && NT_SUCCESS(status))
        {
            wknet::quic::QuicOperationInitialize(&request);
            status = wknet::quic::QuicConnectionExecuteApplication(quic, SubmitRequest, &submit, &request);
        }
        if (!expectVersionNegotiation && NT_SUCCESS(status))
        {
            status = wknet::quic::QuicOperationWait(&request, InteropTimeoutMilliseconds);
        }
        if (!expectVersionNegotiation && NT_SUCCESS(status))
        {
            std::unique_lock<std::mutex> lock(capture.Lock);
            const bool completed = capture.Event.wait_for(lock, std::chrono::milliseconds(InteropTimeoutMilliseconds),
                                                          [&capture, expectGoaway]() noexcept
                                                          {
                                                              return capture.ConnectionError ||
                                                                     (capture.ResponseCount != 0 &&
                                                                      capture.CompletedCount == capture.ResponseCount &&
                                                                      (!expectGoaway || capture.GoawayReceived));
                                                          });
            if (!completed)
            {
                status = STATUS_IO_TIMEOUT;
            }
            else if (capture.ConnectionError)
            {
                status = capture.ConnectionStatus;
            }
            else if (!expectCancel)
            {
                for (SIZE_T index = 0; index < capture.ResponseCount; ++index)
                {
                    if (!NT_SUCCESS(capture.Responses[index].CompletionStatus))
                    {
                        status = capture.Responses[index].CompletionStatus;
                        break;
                    }
                }
            }
        }

        NTSTATUS goawayOpenStatus = STATUS_SUCCESS;
        if (expectGoaway && NT_SUCCESS(status))
        {
            wknet::quic::QuicOperation afterGoaway = {};
            wknet::quic::QuicOperationInitialize(&afterGoaway);
            goawayOpenStatus =
                wknet::quic::QuicConnectionExecuteApplication(quic, SubmitRequestAfterGoaway, &capture, &afterGoaway);
            if (NT_SUCCESS(goawayOpenStatus))
            {
                goawayOpenStatus = wknet::quic::QuicOperationWait(&afterGoaway, InteropTimeoutMilliseconds);
            }
        }

        if (expectVersionNegotiation)
        {
            success = status == STATUS_NOT_SUPPORTED || capture.ConnectionStatus == STATUS_NOT_SUPPORTED;
        }
        else if (!NT_SUCCESS(status))
        {
            printf("interop status=0x%08X application_error=0x%llX connection_error=%u\n",
                   static_cast<unsigned int>(status),
                   static_cast<unsigned long long>(capture.ConnectionApplicationError),
                   capture.ConnectionError ? 1U : 0U);
            for (SIZE_T index = 0; index < capture.ResponseCount; ++index)
            {
                const InteropResponse& response = capture.Responses[index];
                printf("partial_response stream=%llu status=%u headers=%zu trailers=%zu body_bytes=%zu\n",
                       static_cast<unsigned long long>(response.StreamId),
                       static_cast<unsigned int>(response.StatusCode), response.HeaderCount, response.TrailerCount,
                       response.BodyLength);
            }
        }
        else if (expectCancel)
        {
            const InteropResponse& response = capture.Responses[0];
            success = capture.ResponseCount == 1 && capture.CompletedCount == 1 &&
                      response.CompletionStatus == STATUS_CANCELLED &&
                      response.ApplicationError == wknet::http3::H3_REQUEST_CANCELLED;
        }
        else
        {
            const bool head = strcmp(scenario, "head-no-body") == 0;
            const bool post = strcmp(scenario, "post-request-body") == 0;
            const bool concurrent = strcmp(scenario, "concurrent") == 0;
            const bool lossReorder = strcmp(scenario, "loss-reorder") == 0;
            const char* expectedBody = post ? "received:21" : "wknet-http3-aioquic";
            const SIZE_T expectedLength = head ? 0 : (lossReorder ? 3000 : strlen(expectedBody));
            const SIZE_T expectedResponses = concurrent ? InteropMaximumResponses : 1;
            success = capture.ResponseCount == expectedResponses && capture.CompletedCount == expectedResponses;
            for (SIZE_T index = 0; success && index < capture.ResponseCount; ++index)
            {
                const InteropResponse& response = capture.Responses[index];
                const bool bodyMatches =
                    head || (lossReorder ? response.BodyLength == expectedLength && response.Body[0] == 'L' &&
                                               response.Body[expectedLength - 1] == 'L'
                                         : response.BodyLength == expectedLength &&
                                               memcmp(response.Body, expectedBody, expectedLength) == 0);
                success = response.StatusCode == 200 && response.BodyLength == expectedLength && bodyMatches;
            }
            if (strcmp(scenario, "trailers") == 0)
            {
                success = success && capture.Responses[0].TrailerCount != 0;
            }
            if (expectGoaway)
            {
                success = success && capture.GoawayReceived && capture.GoawayId == 4 &&
                          goawayOpenStatus == STATUS_DEVICE_NOT_READY;
            }
            if (!success)
            {
                for (SIZE_T index = 0; index < capture.ResponseCount; ++index)
                {
                    const InteropResponse& response = capture.Responses[index];
                    printf("response stream=%llu status=%u completion=0x%08X headers=%zu trailers=%zu body_bytes=%zu\n",
                           static_cast<unsigned long long>(response.StreamId),
                           static_cast<unsigned int>(response.StatusCode),
                           static_cast<unsigned int>(response.CompletionStatus), response.HeaderCount,
                           response.TrailerCount, response.BodyLength);
                }
                printf("goaway received=%u id=%llu next_open=0x%08X\n", capture.GoawayReceived ? 1U : 0U,
                       static_cast<unsigned long long>(capture.GoawayId), static_cast<unsigned int>(goawayOpenStatus));
            }
        }

        CloseConnections(http3, quic);
        wknet::net::WskClientClose(client);
        providerCache.Shutdown();
        wknet::net::test::DisableNativeUdpProvider();
        wknet::quic::QuicTestClockUseSystem(false);
        return success;
    }
} // namespace

int main()
{
    char portText[16] = {};
    char scenario[64] = {};
    SIZE_T portLength = 0;
    SIZE_T scenarioLength = 0;
    const errno_t portStatus = getenv_s(&portLength, portText, sizeof(portText), "WKNET_HTTP3_INTEROP_PORT");
    const errno_t scenarioStatus =
        getenv_s(&scenarioLength, scenario, sizeof(scenario), "WKNET_HTTP3_INTEROP_SCENARIO");
    if (portStatus != 0 || scenarioStatus != 0 || portLength <= 1 || scenarioLength <= 1)
    {
        printf("HTTP3 INTEROP TEST REQUIRES WKNET_HTTP3_INTEROP_PORT AND WKNET_HTTP3_INTEROP_SCENARIO\n");
        return 2;
    }

    const unsigned long parsedPort = strtoul(portText, nullptr, 10);
    Expect(parsedPort != 0 && parsedPort <= 65535, "interop port is valid");
    if (!g_failed)
    {
        Expect(RunInteropScenario(static_cast<USHORT>(parsedPort), scenario), "real HTTP/3 peer scenario passes");
    }

    if (g_failed)
    {
        return 1;
    }
    printf("HTTP3 INTEROP TESTS PASSED scenario=%s\n", scenario);
    return 0;
}
