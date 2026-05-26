#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/api/KernelHttpApi.h"
#include "../src/KernelHttp/api/KernelHttpConnectionPool.h"
#include "../src/KernelHttp/api/KernelHttpWorkspace.h"
#include "../src/KernelHttp/crypto/CngProviderCache.h"
#include "../src/KernelHttp/samples/ExternalTrustStore.h"
#include "../src/KernelHttp/samples/HighLevelApiSamples.h"

#include <stdio.h>
#include <string.h>

using KernelHttp::api::KH_ASYNC_OPERATION;
using KernelHttp::api::KH_REQUEST;
using KernelHttp::api::KH_RESPONSE;
using KernelHttp::api::KH_SESSION;
using KernelHttp::api::KH_WEBSOCKET;
using KernelHttp::api::KhAsyncCancel;
using KernelHttp::api::KhAsyncGetHttpResponse;
using KernelHttp::api::KhAsyncGetWebSocket;
using KernelHttp::api::KhAsyncRelease;
using KernelHttp::api::KhAsyncWait;
using KernelHttp::api::KhAddressFamily;
using KernelHttp::api::KhCertificatePolicy;
using KernelHttp::api::KhConnectionPool;
using KernelHttp::api::KhConnectionPoolAcquire;
using KernelHttp::api::KhConnectionPoolClose;
using KernelHttp::api::KhConnectionPoolInitialize;
using KernelHttp::api::KhConnectionPoolKey;
using KernelHttp::api::KhConnectionPoolKeysEqual;
using KernelHttp::api::KhConnectionPoolRelease;
using KernelHttp::api::KhConnectionPoolShutdown;
using KernelHttp::api::KhConnectionPolicy;
using KernelHttp::api::KhDefaultConnectionPoolCapacity;
using KernelHttp::api::KhDefaultConnectionsPerHost;
using KernelHttp::api::KhDefaultIdleTimeoutMilliseconds;
using KernelHttp::api::KhDefaultMaxResponseBytes;
using KernelHttp::api::KhHttpMethod;
using KernelHttp::api::KhHttpRequestClearBody;
using KernelHttp::api::KhHttpRequestCreate;
using KernelHttp::api::KhHttpRequestRelease;
using KernelHttp::api::KhHttpRequestSetBody;
using KernelHttp::api::KhHttpRequestSetConnectionPolicy;
using KernelHttp::api::KhHttpRequestSetFileBody;
using KernelHttp::api::KhHttpRequestSetHeader;
using KernelHttp::api::KhHttpRequestSetMethod;
using KernelHttp::api::KhHttpRequestSetMultipartFormDataBody;
using KernelHttp::api::KhHttpRequestSetRawBody;
using KernelHttp::api::KhHttpRequestSetTextBody;
using KernelHttp::api::KhHttpRequestSetTlsOptions;
using KernelHttp::api::KhHttpRequestSetUrl;
using KernelHttp::api::KhHttpRequestSetUrlEncodedBody;
using KernelHttp::api::KhHttpRequestSetAddressFamily;
using KernelHttp::api::KhResponseGetHeader;
using KernelHttp::api::KhHttpSendAsync;
using KernelHttp::api::KhHttpSendFlagAggregateWithCallbacks;
using KernelHttp::api::KhHttpSendOptions;
using KernelHttp::api::KhMultipartFormDataPart;
using KernelHttp::api::KhNameValuePair;
using KernelHttp::api::KhTestSessionHasProviderCache;
using KernelHttp::api::KhTestSessionHasWorkspace;
using KernelHttp::api::KhHttpSendSync;
using KernelHttp::api::KhPoolType;
using KernelHttp::api::KhRequestBodyPartKind;
using KernelHttp::api::KhResponseGetView;
using KernelHttp::api::KhResponseRelease;
using KernelHttp::api::KhResponseView;
using KernelHttp::api::KhSessionClose;
using KernelHttp::api::KhSessionCreate;
using KernelHttp::api::KhSessionOptions;
using KernelHttp::api::KhTestAsyncIsCanceled;
using KernelHttp::api::KhTestAsyncIsCompleted;
using KernelHttp::api::KhTestAsyncStatus;
using KernelHttp::api::KhTestRunAsyncOperation;
using KernelHttp::api::KhTestSetAsyncAutoRun;
using KernelHttp::api::KhTestResetCurrentIrql;
using KernelHttp::api::KhTestHttpTransportRequest;
using KernelHttp::api::KhTestHttpTransportResponse;
using KernelHttp::api::KhTestSetHttpTransport;
using KernelHttp::api::KhTestSetCurrentIrql;
using KernelHttp::api::KhTestSetWebSocketTransport;
using KernelHttp::api::KhTestWebSocketConnectRequest;
using KernelHttp::api::KhTestWebSocketMessage;
using KernelHttp::api::KhTlsOptions;
using KernelHttp::api::KhTlsVersion;
using KernelHttp::api::KhWebSocketCloseSync;
using KernelHttp::api::KhWebSocketConnectAsync;
using KernelHttp::api::KhWebSocketConnectOptions;
using KernelHttp::api::KhWebSocketConnectSync;
using KernelHttp::api::KhWebSocketMessage;
using KernelHttp::api::KhWebSocketReceiveOptions;
using KernelHttp::api::KhWebSocketReceiveSync;
using KernelHttp::api::KhWebSocketSendBinarySync;
using KernelHttp::api::KhWebSocketSendTextSync;
using KernelHttp::api::KhWebSocketSendOptions;
using KernelHttp::api::KhWorkspace;
using KernelHttp::api::KhWorkspaceAppendResponse;
using KernelHttp::api::KhWorkspaceCertificateScratchBytes;
using KernelHttp::api::KhWorkspaceCreate;
using KernelHttp::api::KhWorkspaceDecodedBodyBytes;
using KernelHttp::api::KhWorkspaceEnsureResponseCapacity;
using KernelHttp::api::KhWorkspaceHttp2HeaderScratchBytes;
using KernelHttp::api::KhWorkspaceOptions;
using KernelHttp::api::KhWorkspaceRelease;
using KernelHttp::api::KhWorkspaceRequestBufferBytes;
using KernelHttp::api::KhWorkspaceReset;
using KernelHttp::api::KhWorkspaceResponseInitialBytes;
using KernelHttp::api::KhWorkspaceTlsHandshakeScratchBytes;
using KernelHttp::api::KhWorkspaceWebSocketFrameScratchBytes;
using KernelHttp::crypto::AesGcmKey;
using KernelHttp::crypto::AesGcmParameters;
using KernelHttp::crypto::CngKey;
using KernelHttp::crypto::CngProvider;
using KernelHttp::crypto::CngProviderCache;
using KernelHttp::crypto::EcCurve;
using KernelHttp::crypto::HashAlgorithm;
using KernelHttp::crypto::SignatureAlgorithm;
using KernelHttp::net::WskClient;
using KernelHttp::samples::ExternalTrustStore;
using KernelHttp::samples::ExternalTrustStoreDefaultBundlePath;
using KernelHttp::samples::InitializeExternalTrustStore;
using KernelHttp::samples::ResetExternalTrustStore;

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message)
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    NTSTATUS TestBodyCallback(void* context, const UCHAR* data, SIZE_T dataLength, bool finalChunk)
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(dataLength);
        UNREFERENCED_PARAMETER(finalChunk);
        return STATUS_SUCCESS;
    }

    NTSTATUS TestHeaderCallback(
        void* context,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength)
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(name);
        UNREFERENCED_PARAMETER(nameLength);
        UNREFERENCED_PARAMETER(value);
        UNREFERENCED_PARAMETER(valueLength);
        return STATUS_SUCCESS;
    }

    struct HeaderCapture
    {
        SIZE_T Count = 0;
        char LastName[32] = {};
        SIZE_T LastNameLength = 0;
        char LastValue[64] = {};
        SIZE_T LastValueLength = 0;
    };

    struct BodyCapture
    {
        SIZE_T Count = 0;
        UCHAR Data[128] = {};
        SIZE_T DataLength = 0;
        bool FinalChunk = false;
        NTSTATUS ReturnStatus = STATUS_SUCCESS;
    };

    NTSTATUS TestMessageCallback(
        void* context,
        KernelHttp::api::KhWebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment)
    {
        auto* capture = static_cast<BodyCapture*>(context);
        UNREFERENCED_PARAMETER(type);
        if (capture != nullptr) {
            ++capture->Count;
            capture->DataLength = dataLength < sizeof(capture->Data) ? dataLength : sizeof(capture->Data);
            if (capture->DataLength != 0) {
                RtlCopyMemory(capture->Data, data, capture->DataLength);
            }
            capture->FinalChunk = finalFragment;
            return capture->ReturnStatus;
        }

        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(dataLength);
        UNREFERENCED_PARAMETER(finalFragment);
        return STATUS_SUCCESS;
    }

    struct CompletionCapture
    {
        SIZE_T Count = 0;
        KH_ASYNC_OPERATION Operation = nullptr;
        NTSTATUS Status = STATUS_PENDING;
    };

    struct WebSocketCapture
    {
        static constexpr SIZE_T MaxQueuedMessages = 8;

        SIZE_T ConnectCount = 0;
        SIZE_T SendCount = 0;
        SIZE_T ReceiveCount = 0;
        SIZE_T CloseCount = 0;
        char LastScheme[8] = {};
        char LastHost[64] = {};
        char LastPath[128] = {};
        char LastSubprotocol[32] = {};
        USHORT LastPort = 0;
        SIZE_T LastMaxMessageBytes = 0;
        KhCertificatePolicy LastCertificatePolicy = KhCertificatePolicy::Verify;
        KhTlsVersion LastMinTlsVersion = KhTlsVersion::Tls12;
        KhTlsVersion LastMaxTlsVersion = KhTlsVersion::Tls13;
        bool LastAutoReplyPing = false;
        KernelHttp::api::KhWebSocketMessageType LastSendType = KernelHttp::api::KhWebSocketMessageType::Binary;
        UCHAR LastSendData[128] = {};
        SIZE_T LastSendLength = 0;
        bool LastSendFinal = false;
        NTSTATUS ConnectStatus = STATUS_SUCCESS;
        NTSTATUS SendStatus = STATUS_SUCCESS;
        NTSTATUS ReceiveStatus = STATUS_SUCCESS;
        KhTestWebSocketMessage NextMessage = {};
        KhTestWebSocketMessage Messages[MaxQueuedMessages] = {};
        SIZE_T MessageCount = 0;
        bool RepeatMessages = false;
    };

    struct TransportContext
    {
        SIZE_T CallCount = 0;
        ULONG LastConnectionId = 0;
        bool LastReused = false;
        KhConnectionPolicy LastPolicy = KhConnectionPolicy::ReuseOrCreate;
        KhCertificatePolicy LastCertificatePolicy = KhCertificatePolicy::Verify;
        KhAddressFamily LastAddressFamily = KhAddressFamily::Any;
        SIZE_T H2AlpnCount = 0;
        SIZE_T NoVerifyCount = 0;
        SIZE_T Ipv4Count = 0;
        SIZE_T Ipv6Count = 0;
        SIZE_T VerifiedHttpsForceNewCount = 0;
        SIZE_T VerifiedHttpsReuseCount = 0;
        bool SawGet = false;
        bool SawPost = false;
        bool SawPut = false;
        bool SawPatch = false;
        bool SawDelete = false;
        bool SawHead = false;
        bool SawOptions = false;
        bool LastPoolable = false;
        char LastHost[64] = {};
        USHORT LastPort = 0;
        char LastRequest[4096] = {};
        SIZE_T LastRequestLength = 0;
        const char* Response = nullptr;
        SIZE_T ResponseLength = 0;
        bool ConnectionReusable = true;
    };

    NTSTATUS CapturingHeaderCallback(
        void* context,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength)
    {
        auto* capture = static_cast<HeaderCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->Count;
        capture->LastNameLength = nameLength < sizeof(capture->LastName) ? nameLength : sizeof(capture->LastName);
        capture->LastValueLength = valueLength < sizeof(capture->LastValue) ? valueLength : sizeof(capture->LastValue);
        RtlCopyMemory(capture->LastName, name, capture->LastNameLength);
        RtlCopyMemory(capture->LastValue, value, capture->LastValueLength);
        return STATUS_SUCCESS;
    }

    NTSTATUS CapturingBodyCallback(void* context, const UCHAR* data, SIZE_T dataLength, bool finalChunk)
    {
        auto* capture = static_cast<BodyCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->Count;
        capture->DataLength = dataLength < sizeof(capture->Data) ? dataLength : sizeof(capture->Data);
        if (capture->DataLength != 0) {
            RtlCopyMemory(capture->Data, data, capture->DataLength);
        }
        capture->FinalChunk = finalChunk;
        return capture->ReturnStatus;
    }

    NTSTATUS TestHttpTransport(
        void* context,
        const KhTestHttpTransportRequest* request,
        KhTestHttpTransportResponse* response)
    {
        auto* transport = static_cast<TransportContext*>(context);
        if (transport == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++transport->CallCount;
        transport->LastConnectionId = request->ConnectionId;
        transport->LastReused = request->ReusedConnection;
        transport->LastPolicy = request->ConnectionPolicy;
        transport->LastCertificatePolicy = request->CertificatePolicy;
        transport->LastAddressFamily = request->AddressFamily;
        transport->LastPoolable = request->PoolableConnection;
        transport->LastPort = request->Port;
        if (request->AddressFamily == KhAddressFamily::Ipv4) {
            ++transport->Ipv4Count;
        }
        if (request->AddressFamily == KhAddressFamily::Ipv6) {
            ++transport->Ipv6Count;
        }
        if (request->CertificatePolicy == KhCertificatePolicy::NoVerify) {
            ++transport->NoVerifyCount;
        }
        if (request->SchemeLength == 5 &&
            request->Scheme != nullptr &&
            memcmp(request->Scheme, "https", 5) == 0 &&
            request->CertificatePolicy == KhCertificatePolicy::Verify) {
            if (request->ConnectionPolicy == KhConnectionPolicy::ForceNew) {
                ++transport->VerifiedHttpsForceNewCount;
            }
            if (request->ConnectionPolicy == KhConnectionPolicy::ReuseOrCreate) {
                ++transport->VerifiedHttpsReuseCount;
            }
        }
        if (request->AlpnLength == 2 &&
            request->Alpn != nullptr &&
            memcmp(request->Alpn, "h2", 2) == 0) {
            ++transport->H2AlpnCount;
        }

        const SIZE_T hostLength = request->HostLength < sizeof(transport->LastHost) - 1 ?
            request->HostLength :
            sizeof(transport->LastHost) - 1;
        if (hostLength != 0) {
            RtlCopyMemory(transport->LastHost, request->Host, hostLength);
        }
        transport->LastHost[hostLength] = '\0';

        transport->LastRequestLength = request->BuiltRequestLength < sizeof(transport->LastRequest) - 1 ?
            request->BuiltRequestLength :
            sizeof(transport->LastRequest) - 1;
        if (transport->LastRequestLength != 0) {
            RtlCopyMemory(transport->LastRequest, request->BuiltRequest, transport->LastRequestLength);
        }
        transport->LastRequest[transport->LastRequestLength] = '\0';
        transport->SawGet = transport->SawGet || strstr(transport->LastRequest, "GET ") == transport->LastRequest;
        transport->SawPost = transport->SawPost || strstr(transport->LastRequest, "POST ") == transport->LastRequest;
        transport->SawPut = transport->SawPut || strstr(transport->LastRequest, "PUT ") == transport->LastRequest;
        transport->SawPatch = transport->SawPatch || strstr(transport->LastRequest, "PATCH ") == transport->LastRequest;
        transport->SawDelete = transport->SawDelete || strstr(transport->LastRequest, "DELETE ") == transport->LastRequest;
        transport->SawHead = transport->SawHead || strstr(transport->LastRequest, "HEAD ") == transport->LastRequest;
        transport->SawOptions = transport->SawOptions || strstr(transport->LastRequest, "OPTIONS ") == transport->LastRequest;

        response->RawResponse = transport->Response;
        response->RawResponseLength = transport->ResponseLength;
        response->ConnectionReusable = transport->ConnectionReusable;
        return STATUS_SUCCESS;
    }

    void TestCompletionCallback(void* context, KH_ASYNC_OPERATION operation, NTSTATUS status)
    {
        auto* capture = static_cast<CompletionCapture*>(context);
        if (capture == nullptr) {
            return;
        }

        ++capture->Count;
        capture->Operation = operation;
        capture->Status = status;
    }

    NTSTATUS TestWebSocketConnectTransport(void* context, const KhTestWebSocketConnectRequest* request)
    {
        auto* capture = static_cast<WebSocketCapture*>(context);
        if (capture == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->ConnectCount;
        capture->LastPort = request->Port;
        capture->LastMaxMessageBytes = request->MaxMessageBytes;
        capture->LastCertificatePolicy = request->CertificatePolicy;
        capture->LastMinTlsVersion = request->MinTlsVersion;
        capture->LastMaxTlsVersion = request->MaxTlsVersion;
        capture->LastAutoReplyPing = request->AutoReplyPing;

        const SIZE_T schemeLength = request->SchemeLength < sizeof(capture->LastScheme) - 1 ?
            request->SchemeLength :
            sizeof(capture->LastScheme) - 1;
        if (schemeLength != 0) {
            RtlCopyMemory(capture->LastScheme, request->Scheme, schemeLength);
        }
        capture->LastScheme[schemeLength] = '\0';

        const SIZE_T hostLength = request->HostLength < sizeof(capture->LastHost) - 1 ?
            request->HostLength :
            sizeof(capture->LastHost) - 1;
        if (hostLength != 0) {
            RtlCopyMemory(capture->LastHost, request->Host, hostLength);
        }
        capture->LastHost[hostLength] = '\0';

        const SIZE_T pathLength = request->PathLength < sizeof(capture->LastPath) - 1 ?
            request->PathLength :
            sizeof(capture->LastPath) - 1;
        if (pathLength != 0) {
            RtlCopyMemory(capture->LastPath, request->Path, pathLength);
        }
        capture->LastPath[pathLength] = '\0';

        const SIZE_T subprotocolLength = request->SubprotocolLength < sizeof(capture->LastSubprotocol) - 1 ?
            request->SubprotocolLength :
            sizeof(capture->LastSubprotocol) - 1;
        if (subprotocolLength != 0) {
            RtlCopyMemory(capture->LastSubprotocol, request->Subprotocol, subprotocolLength);
        }
        capture->LastSubprotocol[subprotocolLength] = '\0';

        return capture->ConnectStatus;
    }

    NTSTATUS TestWebSocketSendTransport(
        void* context,
        KH_WEBSOCKET websocket,
        KernelHttp::api::KhWebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment)
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WebSocketCapture*>(context);
        if (capture == nullptr || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->SendCount;
        capture->LastSendType = type;
        capture->LastSendLength = dataLength < sizeof(capture->LastSendData) ? dataLength : sizeof(capture->LastSendData);
        if (capture->LastSendLength != 0) {
            RtlCopyMemory(capture->LastSendData, data, capture->LastSendLength);
        }
        capture->LastSendFinal = finalFragment;
        return capture->SendStatus;
    }

    NTSTATUS TestWebSocketReceiveTransport(void* context, KH_WEBSOCKET websocket, KhTestWebSocketMessage* message)
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WebSocketCapture*>(context);
        if (capture == nullptr || message == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->ReceiveCount;
        if (capture->MessageCount != 0) {
            const SIZE_T receiveIndex = capture->ReceiveCount - 1;
            const SIZE_T index = capture->RepeatMessages ?
                receiveIndex % capture->MessageCount :
                (receiveIndex < capture->MessageCount ? receiveIndex : capture->MessageCount - 1);
            *message = capture->Messages[index];
        }
        else {
            *message = capture->NextMessage;
        }
        return capture->ReceiveStatus;
    }

    void TestWebSocketCloseTransport(void* context, KH_WEBSOCKET websocket)
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WebSocketCapture*>(context);
        if (capture != nullptr) {
            ++capture->CloseCount;
        }
    }

    WskClient* FakeWskClient()
    {
        alignas(WskClient) static UCHAR storage[sizeof(WskClient)] = {};
        return reinterpret_cast<WskClient*>(storage);
    }

    KH_SESSION CreateValidSession(WskClient* wskClient)
    {
        KH_SESSION session = nullptr;
        const NTSTATUS status = KhSessionCreate(wskClient, nullptr, &session);
        Expect(status == STATUS_SUCCESS, "session create succeeds with defaults");
        Expect(session != nullptr, "session create returns handle");
        return session;
    }

    KH_REQUEST CreateValidRequest(KH_SESSION session)
    {
        KH_REQUEST request = nullptr;
        NTSTATUS status = KhHttpRequestCreate(session, &request);
        Expect(status == STATUS_SUCCESS, "request create succeeds");
        Expect(request != nullptr, "request create returns handle");

        const char url[] = "https://example.com/path";
        status = KhHttpRequestSetUrl(request, url, strlen(url));
        Expect(status == STATUS_SUCCESS, "request url sets");
        return request;
    }

    void TestExternalTrustStore()
    {
        ExternalTrustStore trustStore = {};
        NTSTATUS status = InitializeExternalTrustStore(trustStore, ExternalTrustStoreDefaultBundlePath);
        Expect(status == STATUS_SUCCESS, "external trust store loads default cacert bundle");
        Expect(trustStore.BundleData != nullptr, "external trust store owns bundle bytes");
        Expect(trustStore.BundleDataLength != 0, "external trust store records bundle length");
        Expect(trustStore.AuthorityBundle.Data == trustStore.BundleData, "external trust store points authority bundle at loaded bytes");
        Expect(trustStore.AuthorityBundle.DataLength == trustStore.BundleDataLength, "external trust store authority bundle length matches loaded bytes");
        Expect(trustStore.Store.AuthorityBundleCount() == 1, "external trust store exposes one authority bundle");
        ResetExternalTrustStore(trustStore);
        Expect(trustStore.BundleData == nullptr, "external trust store reset clears bundle bytes");
        Expect(trustStore.Store.AuthorityBundleCount() == 0, "external trust store reset clears certificate store");

        status = InitializeExternalTrustStore(trustStore, "tests\\testdata\\missing-cacert.pem");
        Expect(status == STATUS_NOT_FOUND, "external trust store reports missing bundle file");
        ResetExternalTrustStore(trustStore);
    }

    void TestDefaultOptions()
    {
        KhSessionOptions sessionOptions = {};
        Expect(sessionOptions.ResponsePoolType == KhPoolType::NonPaged, "default response pool is nonpaged");
        Expect(sessionOptions.MaxResponseBytes == KhDefaultMaxResponseBytes, "default max response bytes is set");
        Expect(sessionOptions.ConnectionPoolCapacity == KhDefaultConnectionPoolCapacity, "default pool capacity is set");
        Expect(sessionOptions.MaxConnectionsPerHost == KhDefaultConnectionsPerHost, "default per-host limit is set");
        Expect(sessionOptions.IdleTimeoutMilliseconds == KhDefaultIdleTimeoutMilliseconds, "default idle timeout is set");
        Expect(sessionOptions.Tls.MinVersion == KhTlsVersion::Tls12, "default min TLS version is 1.2");
        Expect(sessionOptions.Tls.MaxVersion == KhTlsVersion::Tls13, "default max TLS version is 1.3");
        Expect(sessionOptions.Tls.CertificatePolicy == KhCertificatePolicy::Verify, "default certificate policy verifies");

        KhHttpSendOptions sendOptions = {};
        Expect(sendOptions.MaxResponseBytes == 0, "send options inherit max response by default");
        Expect(sendOptions.HeaderCallback == nullptr, "send options header callback is null by default");
        Expect(sendOptions.BodyCallback == nullptr, "send options body callback is null by default");

        KhWebSocketConnectOptions websocketOptions = {};
        Expect(websocketOptions.MaxMessageBytes == KhDefaultMaxResponseBytes, "websocket connect max defaults");
        Expect(websocketOptions.AutoReplyPing, "websocket connect auto-replies ping by default");
    }

    void TestSessionValidation()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = nullptr;

        NTSTATUS status = KhSessionCreate(nullptr, nullptr, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "session create rejects null WSK client");
        Expect(session == nullptr, "session remains null after null WSK client");

        status = KhSessionCreate(wskClient, nullptr, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "session create rejects null output");

        KhSessionOptions options = {};
        options.MaxResponseBytes = 0;
        status = KhSessionCreate(wskClient, &options, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "session create rejects zero max response bytes");

        options = {};
        options.ConnectionPoolCapacity = 0;
        status = KhSessionCreate(wskClient, &options, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "session create rejects zero pool capacity");

        options = {};
        options.Tls.MinVersion = KhTlsVersion::Tls13;
        options.Tls.MaxVersion = KhTlsVersion::Tls12;
        status = KhSessionCreate(wskClient, &options, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "session create rejects reversed TLS range");

        session = CreateValidSession(wskClient);
        Expect(KhTestSessionHasWorkspace(session), "session create initializes workspace");
        Expect(KhTestSessionHasProviderCache(session), "session create initializes provider cache");
        KhSessionClose(session);
        KhSessionClose(nullptr);
    }

    void TestWorkspaceLifecycle()
    {
        KhWorkspace* workspace = reinterpret_cast<KhWorkspace*>(static_cast<size_t>(1));
        NTSTATUS status = KhWorkspaceCreate(nullptr, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "workspace create rejects null output");

        KhWorkspaceOptions options = {};
        options.MaxResponseBytes = 0;
        status = KhWorkspaceCreate(&options, &workspace);
        Expect(status == STATUS_INVALID_PARAMETER, "workspace create rejects zero max response");
        Expect(workspace == nullptr, "workspace create clears output on invalid options");

        options = {};
        options.PoolType = KhPoolType::Paged;
        options.MaxResponseBytes = KhWorkspaceResponseInitialBytes + 64;
        status = KhWorkspaceCreate(&options, &workspace);
        Expect(status == STATUS_SUCCESS, "workspace create accepts paged option");
        Expect(workspace != nullptr, "workspace create returns object");
        Expect(workspace->PoolType == KhPoolType::Paged, "workspace records paged pool selection");
        Expect(workspace->MaxResponseBytes == options.MaxResponseBytes, "workspace records response limit");
        Expect(workspace->Request.Length == KhWorkspaceRequestBufferBytes, "workspace request buffer size is fixed");
        Expect(workspace->Response.Length == KhWorkspaceResponseInitialBytes, "workspace response starts at fixed initial size");
        Expect(workspace->DecodedBody.Length == KhWorkspaceDecodedBodyBytes, "workspace decoded body size is fixed");
        Expect(workspace->Http2HeaderScratch.Length == KhWorkspaceHttp2HeaderScratchBytes, "workspace http2 scratch size is fixed");
        Expect(workspace->TlsHandshakeScratch.Length == KhWorkspaceTlsHandshakeScratchBytes, "workspace tls scratch size is fixed");
        Expect(workspace->CertificateScratch.Length == KhWorkspaceCertificateScratchBytes, "workspace cert scratch size is fixed");
        Expect(workspace->WebSocketFrameScratch.Length == KhWorkspaceWebSocketFrameScratchBytes, "workspace websocket scratch size is fixed");

        const UCHAR payload[] = { 'a', 'b', 'c', 'd' };
        status = KhWorkspaceAppendResponse(workspace, payload, sizeof(payload));
        Expect(status == STATUS_SUCCESS, "workspace appends response data");
        Expect(workspace->ResponseLength == sizeof(payload), "workspace tracks response length");
        Expect(memcmp(workspace->Response.Data, payload, sizeof(payload)) == 0, "workspace copies response bytes");

        status = KhWorkspaceEnsureResponseCapacity(workspace, KhWorkspaceResponseInitialBytes + 1);
        Expect(status == STATUS_SUCCESS, "workspace grows response within max");
        Expect(workspace->Response.Length >= KhWorkspaceResponseInitialBytes + 1, "workspace response grew");

        status = KhWorkspaceEnsureResponseCapacity(workspace, options.MaxResponseBytes + 1);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "workspace rejects oversized response grow");
        Expect(workspace->ResponseLength == sizeof(payload), "workspace keeps response length after rejected grow");

        KhWorkspaceReset(workspace);
        Expect(workspace->ResponseLength == 0, "workspace reset clears response length");
        Expect(workspace->Response.Data[0] == 0, "workspace reset clears response bytes");

        KhWorkspaceRelease(workspace);
        KhWorkspaceRelease(nullptr);
    }

    void TestProviderCache()
    {
        CngProviderCache cache;
        Expect(!cache.IsInitialized(), "provider cache starts uninitialized");
        NTSTATUS status = cache.Initialize();
        Expect(status == STATUS_SUCCESS, "provider cache initializes");
        Expect(cache.IsInitialized(), "provider cache reports initialized");
        Expect(cache.Aes() != nullptr, "provider cache has AES provider");
        Expect(cache.Hash(HashAlgorithm::Sha1) != nullptr, "provider cache has SHA1 provider");
        Expect(cache.Hash(HashAlgorithm::Sha256) != nullptr, "provider cache has SHA256 provider");
        Expect(cache.Hash(HashAlgorithm::Sha384) != nullptr, "provider cache has SHA384 provider");
        Expect(cache.Hmac(HashAlgorithm::Sha256) != nullptr, "provider cache has HMAC provider");
        Expect(cache.Rsa() != nullptr, "provider cache has RSA provider");
        Expect(cache.Ecdsa(EcCurve::P256) != nullptr, "provider cache has ECDSA provider");
        Expect(cache.Ecdh(EcCurve::P256) != nullptr, "provider cache has ECDH provider");

        UCHAR output[64] = {};
        SIZE_T bytesWritten = 0;
        const UCHAR data[] = { 1, 2, 3 };
        const UCHAR key[] = { 4, 5, 6, 7 };
        const ULONG initialUseCount = cache.CachedProviderUseCountForTest();

        status = CngProvider::Hash(&cache, HashAlgorithm::Sha256, data, sizeof(data), output, sizeof(output), &bytesWritten);
        Expect(status == STATUS_SUCCESS, "cached hash succeeds");
        Expect(bytesWritten == 32, "cached hash writes digest length");

        status = CngProvider::Hmac(&cache, HashAlgorithm::Sha256, key, sizeof(key), data, sizeof(data), output, sizeof(output), &bytesWritten);
        Expect(status == STATUS_SUCCESS, "cached hmac succeeds");

        UCHAR ciphertext[sizeof(data)] = {};
        UCHAR plaintext[sizeof(data)] = {};
        UCHAR tag[16] = {};
        const UCHAR nonce[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        AesGcmKey aesKey = { key, sizeof(key) };
        AesGcmParameters encryptParams = {};
        encryptParams.Nonce.Data = nonce;
        encryptParams.Nonce.Length = sizeof(nonce);
        status = CngProvider::AesGcmEncrypt(
            &cache,
            aesKey,
            encryptParams,
            data,
            sizeof(data),
            ciphertext,
            sizeof(ciphertext),
            tag,
            sizeof(tag),
            &bytesWritten);
        Expect(status == STATUS_SUCCESS, "cached AES-GCM encrypt succeeds");

        AesGcmParameters decryptParams = encryptParams;
        decryptParams.Tag.Data = tag;
        decryptParams.Tag.Length = sizeof(tag);
        status = CngProvider::AesGcmDecrypt(
            &cache,
            aesKey,
            decryptParams,
            ciphertext,
            sizeof(ciphertext),
            plaintext,
            sizeof(plaintext),
            &bytesWritten);
        Expect(status == STATUS_SUCCESS, "cached AES-GCM decrypt succeeds");

        CngKey privateKey;
        CngKey ecdhPublicKey;
        CngKey ecdsaPublicKey;
        CngKey rsaPublicKey;
        UCHAR point[65] = {};
        point[0] = 4;
        status = CngProvider::GenerateEcdhKeyPair(&cache, EcCurve::P256, privateKey);
        Expect(status == STATUS_SUCCESS, "cached ECDH key generation succeeds");
        status = CngProvider::ImportEcdhPublicKey(&cache, EcCurve::P256, point, sizeof(point), ecdhPublicKey);
        Expect(status == STATUS_SUCCESS, "cached ECDH public import succeeds");
        status = CngProvider::ImportEcdsaPublicKey(&cache, EcCurve::P256, point, sizeof(point), ecdsaPublicKey);
        Expect(status == STATUS_SUCCESS, "cached ECDSA public import succeeds");

        const UCHAR exponent[] = { 1, 0, 1 };
        const UCHAR modulus[] = { 0xA1, 0xB2, 0xC3, 0xD4 };
        status = CngProvider::ImportRsaPublicKey(&cache, exponent, sizeof(exponent), modulus, sizeof(modulus), rsaPublicKey);
        Expect(status == STATUS_SUCCESS, "cached RSA public import succeeds");

        status = CngProvider::VerifySignature(
            &cache,
            SignatureAlgorithm::EcdsaSha256,
            ecdsaPublicKey,
            output,
            32,
            data,
            sizeof(data));
        Expect(status == STATUS_SUCCESS, "cached signature helper succeeds");

        UCHAR secret[32] = {};
        status = CngProvider::DeriveEcdhSecret(&cache, privateKey, ecdhPublicKey, secret, sizeof(secret), &bytesWritten);
        Expect(status == STATUS_SUCCESS, "cached ECDH secret derive succeeds");

        Expect(cache.CachedProviderUseCountForTest() > initialUseCount, "cached provider paths are selected");
        cache.Shutdown();
        Expect(!cache.IsInitialized(), "provider cache shutdown clears initialized state");
    }

    void TestRequestValidation()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_REQUEST request = nullptr;

        NTSTATUS status = KhHttpRequestCreate(nullptr, &request);
        Expect(status == STATUS_INVALID_PARAMETER, "request create rejects null session");
        status = KhHttpRequestCreate(session, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "request create rejects null output");

        status = KhHttpRequestCreate(session, &request);
        Expect(status == STATUS_SUCCESS, "request create succeeds for setter tests");

        const char url[] = "https://example.com/";
        status = KhHttpRequestSetUrl(nullptr, url, strlen(url));
        Expect(status == STATUS_INVALID_PARAMETER, "set url rejects null request");
        status = KhHttpRequestSetUrl(request, nullptr, strlen(url));
        Expect(status == STATUS_INVALID_PARAMETER, "set url rejects null url");
        status = KhHttpRequestSetUrl(request, url, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "set url rejects empty url");
        status = KhHttpRequestSetUrl(request, url, strlen(url));
        Expect(status == STATUS_SUCCESS, "set url accepts valid url");

        status = KhHttpRequestSetMethod(request, static_cast<KhHttpMethod>(99));
        Expect(status == STATUS_INVALID_PARAMETER, "set method rejects unknown method");
        status = KhHttpRequestSetMethod(request, KhHttpMethod::Post);
        Expect(status == STATUS_SUCCESS, "set method accepts POST");

        status = KhHttpRequestSetHeader(request, nullptr, 4, "x", 1);
        Expect(status == STATUS_INVALID_PARAMETER, "set header rejects null name");
        status = KhHttpRequestSetHeader(request, "Name", 0, "x", 1);
        Expect(status == STATUS_INVALID_PARAMETER, "set header rejects empty name");
        status = KhHttpRequestSetHeader(request, "Name", 4, nullptr, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "set header rejects null value");
        status = KhHttpRequestSetHeader(request, "Name", 4, "", 0);
        Expect(status == STATUS_INVALID_PARAMETER, "set header rejects empty value");
        status = KhHttpRequestSetHeader(request, "Name", 4, "Value", 5);
        Expect(status == STATUS_SUCCESS, "set header stores valid header");

        const UCHAR body[] = { 'o', 'k' };
        status = KhHttpRequestSetBody(request, nullptr, sizeof(body));
        Expect(status == STATUS_INVALID_PARAMETER, "set body rejects null non-empty body");
        status = KhHttpRequestSetBody(request, body, sizeof(body));
        Expect(status == STATUS_SUCCESS, "set body accepts valid body");
        status = KhHttpRequestSetTextBody(request, nullptr, sizeof(body), nullptr, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "set text body rejects null non-empty text");
        status = KhHttpRequestSetRawBody(request, nullptr, sizeof(body), nullptr, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "set raw body rejects null non-empty data");
        KhNameValuePair invalidPair = {};
        status = KhHttpRequestSetUrlEncodedBody(request, &invalidPair, 1);
        Expect(status == STATUS_INVALID_PARAMETER, "set urlencoded body rejects invalid pair");
        KhMultipartFormDataPart invalidPart = {};
        status = KhHttpRequestSetMultipartFormDataBody(request, &invalidPart, 1);
        Expect(status == STATUS_INVALID_PARAMETER, "set multipart body rejects invalid part");
        status = KhHttpRequestSetFileBody(request, nullptr, 1, nullptr, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "set file body rejects null path");
        status = KhHttpRequestClearBody(request);
        Expect(status == STATUS_SUCCESS, "clear body accepts request");

        KhTlsOptions tlsOptions = {};
        tlsOptions.MinVersion = KhTlsVersion::Tls13;
        tlsOptions.MaxVersion = KhTlsVersion::Tls12;
        status = KhHttpRequestSetTlsOptions(request, &tlsOptions);
        Expect(status == STATUS_INVALID_PARAMETER, "set TLS rejects reversed range");
        tlsOptions = {};
        status = KhHttpRequestSetTlsOptions(request, &tlsOptions);
        Expect(status == STATUS_SUCCESS, "set TLS accepts defaults");

        status = KhHttpRequestSetConnectionPolicy(request, static_cast<KhConnectionPolicy>(99));
        Expect(status == STATUS_INVALID_PARAMETER, "set connection policy rejects unknown policy");
        status = KhHttpRequestSetConnectionPolicy(request, KhConnectionPolicy::ForceNew);
        Expect(status == STATUS_SUCCESS, "set connection policy accepts force-new");
        status = KhHttpRequestSetAddressFamily(request, static_cast<KhAddressFamily>(99));
        Expect(status == STATUS_INVALID_PARAMETER, "set address family rejects unknown family");
        status = KhHttpRequestSetAddressFamily(request, KhAddressFamily::Ipv6);
        Expect(status == STATUS_SUCCESS, "set address family accepts IPv6");

        KhHttpRequestRelease(request);
        KhSessionClose(session);
    }

    void TestHttpSendValidation()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_REQUEST request = nullptr;

        NTSTATUS status = KhHttpRequestCreate(session, &request);
        Expect(status == STATUS_SUCCESS, "request create succeeds for send validation");

        KH_RESPONSE response = reinterpret_cast<KH_RESPONSE>(static_cast<size_t>(1));
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_INVALID_PARAMETER, "send sync rejects request without URL");
        Expect(response == nullptr, "send sync clears response output on validation failure");

        const char url[] = "https://example.com/";
        status = KhHttpRequestSetUrl(request, url, strlen(url));
        Expect(status == STATUS_SUCCESS, "send validation request URL sets");

        status = KhHttpSendSync(nullptr, request, nullptr, &response);
        Expect(status == STATUS_INVALID_PARAMETER, "send sync rejects null session");
        status = KhHttpSendSync(session, nullptr, nullptr, &response);
        Expect(status == STATUS_INVALID_PARAMETER, "send sync rejects null request");

        KhHttpSendOptions options = {};
        options.MaxResponseBytes = 0;
        options.CallbackContext = &options;
        status = KhHttpSendSync(session, request, &options, &response);
        Expect(status == STATUS_INVALID_PARAMETER, "send sync rejects callback context without callbacks");

        options = {};
        options.Flags = KhHttpSendFlagAggregateWithCallbacks;
        status = KhHttpSendSync(session, request, &options, &response);
        Expect(status == STATUS_INVALID_PARAMETER, "send sync rejects aggregate-with-callbacks without body callback");

        options.BodyCallback = TestBodyCallback;
        status = KhHttpSendSync(session, request, &options, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "send sync rejects aggregate callback mode without response output");

        options = {};
        options.BodyCallback = TestBodyCallback;
        options.CallbackContext = &options;
        status = KhHttpSendSync(session, request, &options, nullptr);
        Expect(status == STATUS_NOT_SUPPORTED, "send sync reports not-supported when no test transport is installed");

        options = {};
        options.HeaderCallback = TestHeaderCallback;
        status = KhHttpSendSync(session, request, &options, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "send sync rejects aggregation without response output");

        KhTestSetAsyncAutoRun(false);
        KH_ASYNC_OPERATION operation = reinterpret_cast<KH_ASYNC_OPERATION>(static_cast<size_t>(1));
        status = KhHttpSendAsync(session, request, nullptr, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "send async rejects null operation output");
        status = KhHttpSendAsync(session, request, nullptr, &operation);
        Expect(status == STATUS_SUCCESS, "send async accepts valid inputs before worker runs");
        Expect(operation != nullptr, "send async returns operation when validation succeeds");
        if (operation != nullptr) {
            Expect(!KhTestAsyncIsCompleted(operation), "send async stays pending under test control");
            KhAsyncRelease(operation);
        }
        KhTestSetAsyncAutoRun(true);

        KhHttpRequestRelease(request);
        KhSessionClose(session);
    }

    void TestConnectionPoolKeys()
    {
        KhConnectionPoolKey first = {};
        RtlCopyMemory(first.Scheme, "https", 5);
        first.SchemeLength = 5;
        RtlCopyMemory(first.Host, "example.com", 11);
        first.HostLength = 11;
        first.Port = 443;
        first.MinTlsVersion = KhTlsVersion::Tls12;
        first.MaxTlsVersion = KhTlsVersion::Tls13;
        first.CertificatePolicy = KhCertificatePolicy::Verify;
        RtlCopyMemory(first.Alpn, "h2", 2);
        first.AlpnLength = 2;

        KhConnectionPoolKey second = first;
        Expect(KhConnectionPoolKeysEqual(first, second), "pool keys match when all dimensions match");

        second = first;
        RtlCopyMemory(second.Scheme, "http", 4);
        second.SchemeLength = 4;
        Expect(!KhConnectionPoolKeysEqual(first, second), "pool key includes scheme");

        second = first;
        RtlCopyMemory(second.Host, "other.test", 10);
        second.HostLength = 10;
        Expect(!KhConnectionPoolKeysEqual(first, second), "pool key includes host");

        second = first;
        second.Port = 8443;
        Expect(!KhConnectionPoolKeysEqual(first, second), "pool key includes port");

        second = first;
        second.AddressFamily = KernelHttp::net::WskAddressFamily::Ipv6;
        Expect(!KhConnectionPoolKeysEqual(first, second), "pool key includes address family");

        second = first;
        second.MinTlsVersion = KhTlsVersion::Tls13;
        Expect(!KhConnectionPoolKeysEqual(first, second), "pool key includes min TLS version");

        second = first;
        second.CertificatePolicy = KhCertificatePolicy::NoVerify;
        Expect(!KhConnectionPoolKeysEqual(first, second), "pool key includes certificate policy");

        second = first;
        RtlCopyMemory(second.Alpn, "http/1.1", 8);
        second.AlpnLength = 8;
        Expect(!KhConnectionPoolKeysEqual(first, second), "pool key includes ALPN");
    }

    void TestConnectionPoolAcquireRelease()
    {
        KhConnectionPool pool = {};
        NTSTATUS status = KhConnectionPoolInitialize(&pool, 2);
        Expect(status == STATUS_SUCCESS, "connection pool initializes");

        KhConnectionPoolKey key = {};
        RtlCopyMemory(key.Scheme, "https", 5);
        key.SchemeLength = 5;
        RtlCopyMemory(key.Host, "example.com", 11);
        key.HostLength = 11;
        key.Port = 443;

        KernelHttp::api::KhPooledConnection* first = nullptr;
        bool reused = true;
        status = KhConnectionPoolAcquire(&pool, key, KhConnectionPolicy::ReuseOrCreate, &first, &reused);
        Expect(status == STATUS_SUCCESS, "pool acquire creates first connection");
        Expect(first != nullptr && !reused, "pool acquire reports new connection");
        const ULONG firstId = first != nullptr ? first->Id : 0;
        KhConnectionPoolRelease(&pool, first, true);

        KernelHttp::api::KhPooledConnection* second = nullptr;
        status = KhConnectionPoolAcquire(&pool, key, KhConnectionPolicy::ReuseOrCreate, &second, &reused);
        Expect(status == STATUS_SUCCESS, "pool acquire reuses compatible connection");
        Expect(second == first && reused, "pool returns same compatible idle connection");
        Expect(second != nullptr && second->Id == firstId, "reused connection keeps identity");
        KhConnectionPoolRelease(&pool, second, true);

        KernelHttp::api::KhPooledConnection* forced = nullptr;
        status = KhConnectionPoolAcquire(&pool, key, KhConnectionPolicy::ForceNew, &forced, &reused);
        Expect(status == STATUS_SUCCESS, "pool force-new creates distinct connection");
        Expect(forced != nullptr && forced != first && !reused, "force-new bypasses idle reuse");
        KhConnectionPoolRelease(&pool, forced, false);

        KernelHttp::api::KhPooledConnection* noPool = nullptr;
        status = KhConnectionPoolAcquire(&pool, key, KhConnectionPolicy::NoPool, &noPool, &reused);
        Expect(status == STATUS_SUCCESS, "pool no-pool creates fresh connection record");
        Expect(noPool != nullptr && !reused, "no-pool never reports reuse");
        KhConnectionPoolRelease(&pool, noPool, false);

        KhConnectionPoolShutdown(&pool);
    }

    void TestHttpSyncSendResponseManagement()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_REQUEST request = CreateValidRequest(session);

        const char rawResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "X-Test: yes\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

        TransportContext transport = {};
        transport.Response = rawResponse;
        transport.ResponseLength = strlen(rawResponse);
        KhTestSetHttpTransport(TestHttpTransport, &transport);

        NTSTATUS status = KhHttpRequestSetHeader(request, "Accept", 6, "text/plain", 10);
        Expect(status == STATUS_SUCCESS, "request stores accept header for sync send");

        KH_RESPONSE response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "send sync aggregates full response");
        Expect(response != nullptr, "send sync returns response handle");
        Expect(transport.CallCount == 1, "transport called once");
        Expect(transport.LastPort == 443, "url parser applies HTTPS default port");
        Expect(strcmp(transport.LastHost, "example.com") == 0, "transport receives parsed host");
        Expect(strstr(transport.LastRequest, "GET /path HTTP/1.1\r\n") != nullptr, "request builder emits parsed path");
        Expect(strstr(transport.LastRequest, "Host: example.com\r\n") != nullptr, "request builder emits host");
        Expect(strstr(transport.LastRequest, "Accept: text/plain\r\n") != nullptr, "request builder emits stored header");

        KhResponseView view = {};
        status = KhResponseGetView(response, &view);
        Expect(status == STATUS_SUCCESS, "response view succeeds");
        Expect(view.StatusCode == 200, "response view exposes status code");
        Expect(view.BodyLength == 5 && memcmp(view.Body, "hello", 5) == 0, "response view exposes body");

        const char* headerValue = nullptr;
        SIZE_T headerValueLength = 0;
        status = KhResponseGetHeader(response, "x-test", 6, &headerValue, &headerValueLength);
        Expect(status == STATUS_SUCCESS, "response header lookup is case-insensitive");
        Expect(headerValueLength == 3 && memcmp(headerValue, "yes", 3) == 0, "response header lookup returns value");
        KhResponseRelease(response);

        BodyCapture bodyCapture = {};
        KhHttpSendOptions callbackOptions = {};
        callbackOptions.BodyCallback = CapturingBodyCallback;
        callbackOptions.CallbackContext = &bodyCapture;
        status = KhHttpSendSync(session, request, &callbackOptions, nullptr);
        Expect(status == STATUS_SUCCESS, "callback-only body response succeeds without response handle");
        Expect(bodyCapture.Count == 1, "body callback invoked once");
        Expect(bodyCapture.FinalChunk, "body callback marks final chunk");
        Expect(bodyCapture.DataLength == 5 && memcmp(bodyCapture.Data, "hello", 5) == 0, "body callback receives body");

        bodyCapture = {};
        callbackOptions = {};
        callbackOptions.BodyCallback = CapturingBodyCallback;
        callbackOptions.CallbackContext = &bodyCapture;
        callbackOptions.Flags = KhHttpSendFlagAggregateWithCallbacks;
        response = nullptr;
        status = KhHttpSendSync(session, request, &callbackOptions, &response);
        Expect(status == STATUS_SUCCESS, "callback plus aggregation succeeds");
        Expect(response != nullptr, "callback plus aggregation returns response");
        Expect(bodyCapture.Count == 1, "callback plus aggregation invokes body callback");
        KhResponseRelease(response);

        HeaderCapture headerCapture = {};
        callbackOptions = {};
        callbackOptions.HeaderCallback = CapturingHeaderCallback;
        callbackOptions.CallbackContext = &headerCapture;
        response = nullptr;
        status = KhHttpSendSync(session, request, &callbackOptions, &response);
        Expect(status == STATUS_SUCCESS, "header callback with aggregation succeeds");
        Expect(headerCapture.Count > 0, "header callback is invoked");
        KhResponseRelease(response);

        KhHttpSendOptions maxOptions = {};
        maxOptions.MaxResponseBytes = 8;
        response = nullptr;
        status = KhHttpSendSync(session, request, &maxOptions, &response);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "send sync enforces max response bytes");
        Expect(response == nullptr, "oversized response does not return handle");

        bodyCapture = {};
        bodyCapture.ReturnStatus = STATUS_ACCESS_DENIED;
        callbackOptions = {};
        callbackOptions.BodyCallback = CapturingBodyCallback;
        callbackOptions.CallbackContext = &bodyCapture;
        status = KhHttpSendSync(session, request, &callbackOptions, nullptr);
        Expect(status == STATUS_ACCESS_DENIED, "send sync returns callback failure");

        KhTestSetHttpTransport(nullptr, nullptr);
        KhHttpRequestRelease(request);
        KhSessionClose(session);
    }

    void TestHighLevelRequestBodyTypes()
    {
        const char rawResponse[] =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_REQUEST request = CreateValidRequest(session);

        TransportContext transport = {};
        transport.Response = rawResponse;
        transport.ResponseLength = strlen(rawResponse);
        KhTestSetHttpTransport(TestHttpTransport, &transport);

        NTSTATUS status = KhHttpRequestSetMethod(request, KhHttpMethod::Post);
        Expect(status == STATUS_SUCCESS, "body tests set POST method");
        KhResponseView view = {};
        KH_RESPONSE response = nullptr;

        const char textBody[] = "plain text";
        status = KhHttpRequestSetTextBody(request, textBody, strlen(textBody), nullptr, 0);
        Expect(status == STATUS_SUCCESS, "text body setter succeeds");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "text body send succeeds");
        Expect(strstr(transport.LastRequest, "Content-Type: text/plain; charset=utf-8\r\n") != nullptr, "text body sets default content type");
        Expect(strstr(transport.LastRequest, "Content-Length: 10\r\n") != nullptr, "text body sets content length");
        Expect(strstr(transport.LastRequest, "\r\n\r\nplain text") != nullptr, "text body is appended");
        if (response != nullptr) {
            status = KhResponseGetView(response, &view);
            Expect(status == STATUS_SUCCESS && view.StatusCode == 204, "text body response is readable");
            KhResponseRelease(response);
        }

        const UCHAR rawBody[] = { 0x00, 'R', 'A', 'W' };
        status = KhHttpRequestSetRawBody(request, rawBody, sizeof(rawBody), "application/octet-stream", strlen("application/octet-stream"));
        Expect(status == STATUS_SUCCESS, "raw body setter succeeds");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "raw body send succeeds");
        Expect(strstr(transport.LastRequest, "Content-Type: application/octet-stream\r\n") != nullptr, "raw body sets supplied content type");
        Expect(strstr(transport.LastRequest, "Content-Length: 4\r\n") != nullptr, "raw body sets content length");
        const char* rawSeparator = strstr(transport.LastRequest, "\r\n\r\n");
        Expect(rawSeparator != nullptr && rawSeparator[4] == '\0' && rawSeparator[5] == 'R', "raw body preserves leading zero byte");
        KhResponseRelease(response);

        KhNameValuePair pairs[2] = {};
        pairs[0].Name = "a b";
        pairs[0].NameLength = strlen(pairs[0].Name);
        pairs[0].Value = "x+y";
        pairs[0].ValueLength = strlen(pairs[0].Value);
        pairs[1].Name = "sym";
        pairs[1].NameLength = strlen(pairs[1].Name);
        pairs[1].Value = "%";
        pairs[1].ValueLength = strlen(pairs[1].Value);
        status = KhHttpRequestSetUrlEncodedBody(request, pairs, 2);
        Expect(status == STATUS_SUCCESS, "urlencoded body setter succeeds");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "urlencoded body send succeeds");
        Expect(strstr(transport.LastRequest, "Content-Type: application/x-www-form-urlencoded\r\n") != nullptr, "urlencoded body sets content type");
        Expect(strstr(transport.LastRequest, "\r\n\r\na+b=x%2By&sym=%25") != nullptr, "urlencoded body encodes fields");
        KhResponseRelease(response);

        KhMultipartFormDataPart parts[2] = {};
        parts[0].Kind = KhRequestBodyPartKind::Field;
        parts[0].Name = "field";
        parts[0].NameLength = strlen(parts[0].Name);
        parts[0].Value = "value";
        parts[0].ValueLength = strlen(parts[0].Value);
        const UCHAR fileBytes[] = "bytes-file";
        parts[1].Kind = KhRequestBodyPartKind::FileBytes;
        parts[1].Name = "upload";
        parts[1].NameLength = strlen(parts[1].Name);
        parts[1].Data = fileBytes;
        parts[1].DataLength = sizeof(fileBytes) - 1;
        parts[1].FileName = "upload.bin";
        parts[1].FileNameLength = strlen(parts[1].FileName);
        parts[1].ContentType = "application/octet-stream";
        parts[1].ContentTypeLength = strlen(parts[1].ContentType);
        status = KhHttpRequestSetMultipartFormDataBody(request, parts, 2);
        Expect(status == STATUS_SUCCESS, "multipart body setter succeeds");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "multipart body send succeeds");
        Expect(strstr(transport.LastRequest, "Content-Type: multipart/form-data; boundary=----KernelHttpBoundary") != nullptr, "multipart body sets boundary content type");
        Expect(strstr(transport.LastRequest, "Content-Disposition: form-data; name=\"field\"") != nullptr, "multipart body contains field part");
        Expect(strstr(transport.LastRequest, "Content-Disposition: form-data; name=\"upload\"; filename=\"upload.bin\"") != nullptr, "multipart body contains file part");
        Expect(strstr(transport.LastRequest, "\r\n\r\nbytes-file\r\n") != nullptr, "multipart body contains file bytes");
        KhResponseRelease(response);

        KhMultipartFormDataPart filePathPart = {};
        filePathPart.Kind = KhRequestBodyPartKind::FilePath;
        filePathPart.Name = "file";
        filePathPart.NameLength = strlen(filePathPart.Name);
        filePathPart.FilePath = "tests\\testdata\\request_body_file.txt";
        filePathPart.FilePathLength = strlen(filePathPart.FilePath);
        filePathPart.ContentType = "text/plain";
        filePathPart.ContentTypeLength = strlen(filePathPart.ContentType);
        status = KhHttpRequestSetMultipartFormDataBody(request, &filePathPart, 1);
        Expect(status == STATUS_SUCCESS, "multipart file path body setter succeeds");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "multipart file path body send succeeds");
        Expect(strstr(transport.LastRequest, "filename=\"request_body_file.txt\"") != nullptr, "multipart file path derives filename");
        Expect(strstr(transport.LastRequest, "file-body-from-testdata") != nullptr, "multipart file path reads file body");
        KhResponseRelease(response);

        status = KhHttpRequestSetFileBody(
            request,
            "tests\\testdata\\request_body_file.txt",
            strlen("tests\\testdata\\request_body_file.txt"),
            nullptr,
            0);
        Expect(status == STATUS_SUCCESS, "file body setter succeeds");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "file body send succeeds");
        Expect(strstr(transport.LastRequest, "Content-Type: application/octet-stream\r\n") != nullptr, "file body sets default content type");
        Expect(strstr(transport.LastRequest, "\r\n\r\nfile-body-from-testdata") != nullptr, "file body reads file contents");
        KhResponseRelease(response);

        status = KhHttpRequestClearBody(request);
        Expect(status == STATUS_SUCCESS, "clear body succeeds");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "clear body send succeeds");
        Expect(strstr(transport.LastRequest, "Content-Length:") == nullptr, "clear body omits content length");
        Expect(strstr(transport.LastRequest, "Content-Type:") == nullptr, "clear body removes generated content type");
        KhResponseRelease(response);

        KhTestSetHttpTransport(nullptr, nullptr);
        KhHttpRequestRelease(request);
        KhSessionClose(session);
    }

    void TestHttpSyncConnectionPolicies()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_REQUEST request = CreateValidRequest(session);

        const char rawResponse[] =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        TransportContext transport = {};
        transport.Response = rawResponse;
        transport.ResponseLength = strlen(rawResponse);
        transport.ConnectionReusable = true;
        KhTestSetHttpTransport(TestHttpTransport, &transport);

        KH_RESPONSE response = nullptr;
        NTSTATUS status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "first pooled request succeeds");
        const ULONG firstConnectionId = transport.LastConnectionId;
        Expect(firstConnectionId != 0, "first request obtains connection id");
        Expect(!transport.LastReused, "first request is not reused");
        Expect(strstr(transport.LastRequest, "Connection: keep-alive\r\n") != nullptr, "pooled request asks for keep-alive");
        KhResponseRelease(response);

        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "second pooled request succeeds");
        Expect(transport.LastConnectionId == firstConnectionId, "second request reuses same connection id");
        Expect(transport.LastReused, "second request reports reuse");
        KhResponseRelease(response);

        status = KhHttpRequestSetConnectionPolicy(request, KhConnectionPolicy::ForceNew);
        Expect(status == STATUS_SUCCESS, "request sets force-new policy");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "force-new request succeeds");
        Expect(transport.LastConnectionId != firstConnectionId, "force-new request gets different connection id");
        Expect(!transport.LastReused, "force-new request does not reuse");
        Expect(strstr(transport.LastRequest, "Connection: close\r\n") != nullptr, "force-new request asks server to close");
        KhResponseRelease(response);

        status = KhHttpRequestSetConnectionPolicy(request, KhConnectionPolicy::NoPool);
        Expect(status == STATUS_SUCCESS, "request sets no-pool policy");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "no-pool request succeeds");
        Expect(!transport.LastPoolable, "no-pool request tells transport it is not poolable");
        Expect(strstr(transport.LastRequest, "Connection: close\r\n") != nullptr, "no-pool request asks server to close");
        KhResponseRelease(response);

        KhTestSetHttpTransport(nullptr, nullptr);
        KhHttpRequestRelease(request);
        KhSessionClose(session);
    }

    void TestHttpAsyncState()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_REQUEST request = CreateValidRequest(session);

        const char rawResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "async";
        TransportContext transport = {};
        transport.Response = rawResponse;
        transport.ResponseLength = strlen(rawResponse);
        KhTestSetHttpTransport(TestHttpTransport, &transport);

        CompletionCapture completion = {};
        KhHttpSendOptions options = {};
        options.CompletionCallback = TestCompletionCallback;
        options.CompletionContext = &completion;

        KH_ASYNC_OPERATION operation = nullptr;
        NTSTATUS status = KhHttpSendAsync(session, request, &options, &operation);
        Expect(status == STATUS_SUCCESS, "send async queues and completes HTTP operation");
        Expect(operation != nullptr, "send async returns operation handle");
        Expect(completion.Count == 1, "send async invokes completion callback");
        Expect(completion.Operation == operation, "completion receives operation handle");
        Expect(completion.Status == STATUS_SUCCESS, "completion receives success status");
        Expect(KhTestAsyncIsCompleted(operation), "send async marks operation completed");
        Expect(KhAsyncWait(operation, 0) == STATUS_SUCCESS, "send async wait returns stored status");

        KH_RESPONSE response = nullptr;
        status = KhAsyncGetHttpResponse(operation, &response);
        Expect(status == STATUS_SUCCESS, "send async exposes owned response");
        KhResponseView view = {};
        status = KhResponseGetView(response, &view);
        Expect(status == STATUS_SUCCESS, "send async response view succeeds");
        Expect(view.BodyLength == 5 && memcmp(view.Body, "async", 5) == 0, "send async response body matches");
        KhResponseRelease(response);
        KhAsyncRelease(operation);

        KhTestSetAsyncAutoRun(false);
        operation = nullptr;
        status = KhHttpSendAsync(session, request, nullptr, &operation);
        Expect(status == STATUS_SUCCESS, "send async can remain pending under test control");
        Expect(operation != nullptr, "pending send async returns operation");
        Expect(!KhTestAsyncIsCompleted(operation), "pending send async is not completed before worker runs");
        Expect(KhAsyncWait(operation, 0) == STATUS_PENDING, "pending send async wait returns pending");
        status = KhTestRunAsyncOperation(operation);
        Expect(status == STATUS_SUCCESS, "test worker runs pending HTTP operation");
        Expect(KhTestAsyncIsCompleted(operation), "pending send async completes after worker run");
        KhAsyncRelease(operation);

        operation = nullptr;
        status = KhHttpSendAsync(session, request, nullptr, &operation);
        Expect(status == STATUS_SUCCESS, "send async creates operation for cancel-before-start");
        status = KhAsyncCancel(operation);
        Expect(status == STATUS_SUCCESS, "async cancel succeeds before worker start");
        Expect(KhTestAsyncIsCanceled(operation), "async cancel marks operation canceled");
        Expect(KhTestAsyncIsCompleted(operation), "cancel-before-start completes operation");
        Expect(KhAsyncWait(operation, 0) == STATUS_CANCELLED, "cancel-before-start wait returns canceled");
        status = KhTestRunAsyncOperation(operation);
        Expect(status == STATUS_CANCELLED, "worker preserves canceled status");
        KhAsyncRelease(operation);
        KhTestSetAsyncAutoRun(true);

        KhTestSetHttpTransport(nullptr, nullptr);
        KhHttpRequestRelease(request);
        KhSessionClose(session);
    }

    void TestHttpUrlRequestTargetParsing()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_REQUEST request = nullptr;
        NTSTATUS status = KhHttpRequestCreate(session, &request);
        Expect(status == STATUS_SUCCESS, "request create succeeds for URL target parsing");

        const char rawResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        TransportContext transport = {};
        transport.Response = rawResponse;
        transport.ResponseLength = strlen(rawResponse);
        KhTestSetHttpTransport(TestHttpTransport, &transport);

        const char queryOnlyUrl[] = "http://Example.com?x=1#frag";
        status = KhHttpRequestSetUrl(request, queryOnlyUrl, strlen(queryOnlyUrl));
        Expect(status == STATUS_SUCCESS, "set URL accepts query-only target with fragment");

        KH_RESPONSE response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "query-only URL send succeeds");
        Expect(strstr(transport.LastRequest, "GET /?x=1 HTTP/1.1\r\n") != nullptr, "query-only URL adds slash and strips fragment");
        Expect(strstr(transport.LastRequest, "Host: example.com\r\n") != nullptr, "URL parser lowercases host");
        KhResponseRelease(response);

        const char explicitPortUrl[] = "http://example.com:8080/path";
        status = KhHttpRequestSetUrl(request, explicitPortUrl, strlen(explicitPortUrl));
        Expect(status == STATUS_SUCCESS, "set URL accepts explicit port");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "explicit port URL send succeeds");
        Expect(transport.LastPort == 8080, "URL parser captures explicit port");
        Expect(strstr(transport.LastRequest, "Host: example.com:8080\r\n") != nullptr, "host header includes non-default port");
        KhResponseRelease(response);

        const char ipv6Url[] = "https://[::1]:8443/sample_response_body.txt";
        status = KhHttpRequestSetUrl(request, ipv6Url, strlen(ipv6Url));
        Expect(status == STATUS_SUCCESS, "set URL accepts bracketed IPv6 literal with explicit port");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "IPv6 literal URL send succeeds");
        Expect(strcmp(transport.LastHost, "::1") == 0, "transport receives IPv6 literal without URL brackets");
        Expect(transport.LastPort == 8443, "URL parser captures IPv6 literal explicit port");
        Expect(strstr(transport.LastRequest, "Host: [::1]:8443\r\n") != nullptr, "host header brackets IPv6 literal with non-default port");
        KhResponseRelease(response);

        const char unsupportedUrl[] = "ftp://example.com/";
        status = KhHttpRequestSetUrl(request, unsupportedUrl, strlen(unsupportedUrl));
        Expect(status == STATUS_NOT_SUPPORTED, "set URL rejects unsupported scheme");

        KhTestSetHttpTransport(nullptr, nullptr);
        KhHttpRequestRelease(request);
        KhSessionClose(session);
    }

    void TestResponseValidation()
    {
        KhResponseView view = {};
        NTSTATUS status = KhResponseGetView(nullptr, &view);
        Expect(status == STATUS_INVALID_PARAMETER, "response view rejects null response");
        status = KhResponseGetView(nullptr, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "response view rejects null output");
        const char* value = reinterpret_cast<const char*>(static_cast<size_t>(1));
        SIZE_T valueLength = 1;
        status = KhResponseGetHeader(nullptr, "X-Test", 6, &value, &valueLength);
        Expect(status == STATUS_INVALID_PARAMETER, "response header lookup rejects null response");
        Expect(value == nullptr && valueLength == 0, "response header lookup clears outputs on invalid response");
        KhResponseRelease(nullptr);
    }

    void TestWebSocketValidation()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);
        KH_WEBSOCKET websocket = nullptr;
        KhWebSocketConnectOptions connectOptions = {};

        NTSTATUS status = KhWebSocketConnectSync(nullptr, &connectOptions, &websocket);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket connect rejects null session");
        status = KhWebSocketConnectSync(session, nullptr, &websocket);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket connect rejects null options");
        status = KhWebSocketConnectSync(session, &connectOptions, &websocket);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket connect rejects missing URL");

        const char url[] = "wss://example.com/socket";
        connectOptions.Url = url;
        connectOptions.UrlLength = strlen(url);
        connectOptions.MaxMessageBytes = 0;
        status = KhWebSocketConnectSync(session, &connectOptions, &websocket);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket connect rejects zero max message bytes");

        connectOptions.MaxMessageBytes = 4096;
        status = KhWebSocketConnectSync(session, &connectOptions, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket connect rejects null output");
        status = KhWebSocketConnectSync(session, &connectOptions, &websocket);
        Expect(status == STATUS_NOT_SUPPORTED, "websocket connect validates before transport chunk");

        KH_ASYNC_OPERATION operation = reinterpret_cast<KH_ASYNC_OPERATION>(static_cast<size_t>(1));
        status = KhWebSocketConnectAsync(session, &connectOptions, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket connect async rejects null operation output");
        KhTestSetAsyncAutoRun(false);
        status = KhWebSocketConnectAsync(session, &connectOptions, &operation);
        Expect(status == STATUS_SUCCESS, "websocket connect async accepts valid inputs before worker runs");
        Expect(operation != nullptr, "websocket connect async returns operation handle");
        if (operation != nullptr) {
            Expect(!KhTestAsyncIsCompleted(operation), "websocket connect async remains pending under test control");
            KhAsyncRelease(operation);
        }
        KhTestSetAsyncAutoRun(true);

        const char text[] = "hello";
        KhWebSocketSendOptions sendOptions = {};
        status = KhWebSocketSendTextSync(nullptr, text, strlen(text), &sendOptions);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket send text rejects null websocket");

        const UCHAR data[] = { 1, 2, 3 };
        status = KhWebSocketSendBinarySync(nullptr, data, sizeof(data), &sendOptions);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket send binary rejects null websocket");

        KhWebSocketReceiveOptions receiveOptions = {};
        KhWebSocketMessage message = {};
        receiveOptions.AutoAllocate = false;
        receiveOptions.MessageCallback = TestMessageCallback;
        status = KhWebSocketReceiveSync(nullptr, &receiveOptions, &message);
        Expect(status == STATUS_INVALID_PARAMETER, "websocket receive rejects null websocket");

        status = KhWebSocketCloseSync(nullptr);
        Expect(status == STATUS_SUCCESS, "websocket close accepts null");

        KhSessionClose(session);
    }

    void TestWebSocketApiBehavior()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);

        WebSocketCapture capture = {};
        const UCHAR receivedData[] = { 'p', 'o', 'n', 'g' };
        capture.NextMessage.Type = KernelHttp::api::KhWebSocketMessageType::Text;
        capture.NextMessage.Data = receivedData;
        capture.NextMessage.DataLength = sizeof(receivedData);
        capture.NextMessage.FinalFragment = true;
        KhTestSetWebSocketTransport(
            TestWebSocketConnectTransport,
            TestWebSocketSendTransport,
            TestWebSocketReceiveTransport,
            TestWebSocketCloseTransport,
            &capture);

        const char url[] = "wss://Example.com:9443/socket?x=1#fragment";
        const char subprotocol[] = "chat";
        KhWebSocketConnectOptions connectOptions = {};
        connectOptions.Url = url;
        connectOptions.UrlLength = strlen(url);
        connectOptions.Subprotocol = subprotocol;
        connectOptions.SubprotocolLength = strlen(subprotocol);
        connectOptions.Tls.CertificatePolicy = KhCertificatePolicy::NoVerify;
        connectOptions.Tls.MinVersion = KhTlsVersion::Tls12;
        connectOptions.Tls.MaxVersion = KhTlsVersion::Tls12;
        connectOptions.MaxMessageBytes = 16;
        connectOptions.AutoReplyPing = false;

        KH_WEBSOCKET websocket = nullptr;
        NTSTATUS status = KhWebSocketConnectSync(session, &connectOptions, &websocket);
        Expect(status == STATUS_SUCCESS, "websocket connect sync succeeds through test transport");
        Expect(websocket != nullptr, "websocket connect sync returns handle");
        Expect(capture.ConnectCount == 1, "websocket connect transport called once");
        Expect(strcmp(capture.LastScheme, "wss") == 0, "websocket parser lowercases scheme");
        Expect(strcmp(capture.LastHost, "example.com") == 0, "websocket parser lowercases host");
        Expect(strcmp(capture.LastPath, "/socket?x=1") == 0, "websocket parser strips fragment");
        Expect(strcmp(capture.LastSubprotocol, "chat") == 0, "websocket connect passes subprotocol");
        Expect(capture.LastPort == 9443, "websocket parser captures explicit port");
        Expect(capture.LastMaxMessageBytes == 16, "websocket connect passes max message bytes");
        Expect(capture.LastCertificatePolicy == KhCertificatePolicy::NoVerify, "websocket connect passes certificate policy");
        Expect(capture.LastMinTlsVersion == KhTlsVersion::Tls12, "websocket connect passes minimum TLS version");
        Expect(capture.LastMaxTlsVersion == KhTlsVersion::Tls12, "websocket connect passes maximum TLS version");
        Expect(!capture.LastAutoReplyPing, "websocket connect passes ping option");

        const char text[] = "ping";
        KhWebSocketSendOptions sendOptions = {};
        sendOptions.FinalFragment = false;
        status = KhWebSocketSendTextSync(websocket, text, strlen(text), &sendOptions);
        Expect(status == STATUS_SUCCESS, "websocket send text succeeds");
        Expect(capture.SendCount == 1, "websocket send transport called for text");
        Expect(capture.LastSendType == KernelHttp::api::KhWebSocketMessageType::Text, "websocket send text type recorded");
        Expect(capture.LastSendLength == 4 && memcmp(capture.LastSendData, "ping", 4) == 0, "websocket send text data recorded");
        Expect(!capture.LastSendFinal, "websocket send passes final-fragment option");

        const UCHAR binary[] = { 1, 2, 3 };
        status = KhWebSocketSendBinarySync(websocket, binary, sizeof(binary), nullptr);
        Expect(status == STATUS_SUCCESS, "websocket send binary succeeds");
        Expect(capture.SendCount == 2, "websocket send transport called for binary");
        Expect(capture.LastSendType == KernelHttp::api::KhWebSocketMessageType::Binary, "websocket send binary type recorded");

        KhWebSocketMessage message = {};
        status = KhWebSocketReceiveSync(websocket, nullptr, &message);
        Expect(status == STATUS_SUCCESS, "websocket receive auto-allocates message");
        Expect(capture.ReceiveCount == 1, "websocket receive transport called");
        Expect(message.Type == KernelHttp::api::KhWebSocketMessageType::Text, "websocket receive preserves message type");
        Expect(message.DataLength == sizeof(receivedData) && memcmp(message.Data, receivedData, sizeof(receivedData)) == 0, "websocket receive exposes message data");

        BodyCapture callbackCapture = {};
        KhWebSocketReceiveOptions receiveOptions = {};
        receiveOptions.AutoAllocate = false;
        receiveOptions.MessageCallback = TestMessageCallback;
        receiveOptions.CallbackContext = &callbackCapture;
        status = KhWebSocketReceiveSync(websocket, &receiveOptions, nullptr);
        Expect(status == STATUS_SUCCESS, "websocket receive callback-only succeeds");
        Expect(capture.ReceiveCount == 2, "websocket receive callback path calls transport");
        Expect(callbackCapture.Count == 1, "websocket receive callback is invoked");
        Expect(callbackCapture.DataLength == sizeof(receivedData) && memcmp(callbackCapture.Data, receivedData, sizeof(receivedData)) == 0, "websocket receive callback data matches");

        receiveOptions = {};
        receiveOptions.MaxMessageBytes = 2;
        status = KhWebSocketReceiveSync(websocket, &receiveOptions, &message);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "websocket receive enforces per-call max message size");

        status = KhWebSocketCloseSync(websocket);
        Expect(status == STATUS_SUCCESS, "websocket close succeeds");
        Expect(capture.CloseCount == 1, "websocket close transport called");

        KhTestSetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
        KhSessionClose(session);
    }

    void TestWebSocketAsyncBehavior()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);

        WebSocketCapture capture = {};
        KhTestSetWebSocketTransport(
            TestWebSocketConnectTransport,
            TestWebSocketSendTransport,
            TestWebSocketReceiveTransport,
            TestWebSocketCloseTransport,
            &capture);

        const char url[] = "ws://example.com/socket";
        KhWebSocketConnectOptions connectOptions = {};
        connectOptions.Url = url;
        connectOptions.UrlLength = strlen(url);
        connectOptions.MaxMessageBytes = 64;

        KH_ASYNC_OPERATION operation = nullptr;
        NTSTATUS status = KhWebSocketConnectAsync(session, &connectOptions, &operation);
        Expect(status == STATUS_SUCCESS, "websocket connect async succeeds");
        Expect(operation != nullptr, "websocket connect async returns operation");
        Expect(KhTestAsyncIsCompleted(operation), "websocket connect async completes with auto-run");
        Expect(KhAsyncWait(operation, 0) == STATUS_SUCCESS, "websocket connect async wait succeeds");
        KH_WEBSOCKET websocket = nullptr;
        status = KhAsyncGetWebSocket(operation, &websocket);
        Expect(status == STATUS_SUCCESS, "websocket connect async exposes websocket handle");
        Expect(websocket != nullptr, "websocket connect async returns websocket handle");
        KhWebSocketCloseSync(websocket);
        KhAsyncRelease(operation);

        KhTestSetAsyncAutoRun(false);
        operation = nullptr;
        status = KhWebSocketConnectAsync(session, &connectOptions, &operation);
        Expect(status == STATUS_SUCCESS, "websocket connect async can remain pending");
        Expect(!KhTestAsyncIsCompleted(operation), "pending websocket operation is not completed");
        status = KhAsyncCancel(operation);
        Expect(status == STATUS_SUCCESS, "websocket async cancel succeeds before start");
        Expect(KhAsyncWait(operation, 0) == STATUS_CANCELLED, "websocket cancel-before-start waits canceled");
        KhAsyncRelease(operation);
        KhTestSetAsyncAutoRun(true);

        KhTestSetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
        KhSessionClose(session);
    }

    void TestHighLevelSampleRunners()
    {
        const char rawResponse[] =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        const UCHAR echoData[] = "kernel-http high-level websocket echo";
        const UCHAR bannerData[] = "Request served by test transport";

        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = CreateValidSession(wskClient);

        TransportContext transport = {};
        transport.Response = rawResponse;
        transport.ResponseLength = strlen(rawResponse);
        KhTestSetHttpTransport(TestHttpTransport, &transport);

        WebSocketCapture capture = {};
        capture.MessageCount = 2;
        capture.RepeatMessages = true;
        capture.Messages[0].Type = KernelHttp::api::KhWebSocketMessageType::Text;
        capture.Messages[0].Data = bannerData;
        capture.Messages[0].DataLength = sizeof(bannerData) - 1;
        capture.Messages[0].FinalFragment = true;
        capture.Messages[1].Type = KernelHttp::api::KhWebSocketMessageType::Text;
        capture.Messages[1].Data = echoData;
        capture.Messages[1].DataLength = sizeof(echoData) - 1;
        capture.Messages[1].FinalFragment = true;
        KhTestSetWebSocketTransport(
            TestWebSocketConnectTransport,
            TestWebSocketSendTransport,
            TestWebSocketReceiveTransport,
            TestWebSocketCloseTransport,
            &capture);

        KernelHttp::samples::HighLevelApiSampleResults results = {};
        NTSTATUS status = KernelHttp::samples::RunHighLevelApiSamples(session, &results);
        Expect(status == STATUS_SUCCESS, "main high-level sample runner succeeds through API test transports");
        Expect(results.HttpGet.Status == STATUS_SUCCESS, "main samples include HTTP GET");
        Expect(results.HttpGetAsync.Status == STATUS_SUCCESS, "main samples include async HTTP GET");
        Expect(results.HttpPost.Status == STATUS_SUCCESS, "main samples include HTTP POST");
        Expect(results.HttpPut.Status == STATUS_SUCCESS, "main samples include HTTP PUT");
        Expect(results.HttpPatch.Status == STATUS_SUCCESS, "main samples include HTTP PATCH");
        Expect(results.HttpDelete.Status == STATUS_SUCCESS, "main samples include HTTP DELETE");
        Expect(results.HttpHead.Status == STATUS_SUCCESS, "main samples include HTTP HEAD");
        Expect(results.HttpOptions.Status == STATUS_SUCCESS, "main samples include HTTP OPTIONS");
        Expect(results.HttpsTlsOptions.Status == STATUS_SUCCESS, "main samples include HTTPS TLS options");
        Expect(results.HttpsPost.Status == STATUS_SUCCESS, "main samples include HTTPS POST");
        Expect(results.HttpsPut.Status == STATUS_SUCCESS, "main samples include HTTPS PUT");
        Expect(results.HttpsPatch.Status == STATUS_SUCCESS, "main samples include HTTPS PATCH");
        Expect(results.HttpsDelete.Status == STATUS_SUCCESS, "main samples include HTTPS DELETE");
        Expect(results.HttpsHead.Status == STATUS_SUCCESS, "main samples include HTTPS HEAD");
        Expect(results.HttpsOptions.Status == STATUS_SUCCESS, "main samples include HTTPS OPTIONS");
        Expect(results.Http2Alpn.Status == STATUS_SUCCESS, "main samples include HTTP/2 ALPN option");
        Expect(results.WebSocketEcho.Status == STATUS_SUCCESS, "main samples include WebSocket echo");
        Expect(results.WebSocketEchoAsync.Status == STATUS_SUCCESS, "main samples include async WebSocket echo");
        Expect(results.WebSocketEcho.StatusCode == 0, "main websocket sample does not report handshake status as result status");
        Expect(transport.SawGet, "main samples send GET through high-level API");
        Expect(transport.SawPost, "main samples send POST through high-level API");
        Expect(transport.SawPut, "main samples send PUT through high-level API");
        Expect(transport.SawPatch, "main samples send PATCH through high-level API");
        Expect(transport.SawDelete, "main samples send DELETE through high-level API");
        Expect(transport.SawHead, "main samples send HEAD through high-level API");
        Expect(transport.SawOptions, "main samples send OPTIONS through high-level API");
        Expect(transport.H2AlpnCount == 1, "main samples request h2 ALPN exactly once");
        Expect(transport.NoVerifyCount == 0, "main samples do not use no-verify TLS");
        Expect(transport.VerifiedHttpsForceNewCount == 8, "main verified HTTPS samples force fresh TLS connections");
        Expect(transport.VerifiedHttpsReuseCount == 0, "main verified HTTPS samples avoid reusing idle TLS connections");
        Expect(capture.ConnectCount == 2 && capture.SendCount == 2 && capture.ReceiveCount == 4, "main samples skip websocket banners before sync and async text echoes");
        Expect(capture.LastMinTlsVersion == KhTlsVersion::Tls12 && capture.LastMaxTlsVersion == KhTlsVersion::Tls12, "main websocket samples use TLS 1.2 for the live echo endpoint");
        Expect(capture.LastSendType == KernelHttp::api::KhWebSocketMessageType::Text, "main websocket sample sends text echo payload");

        KhSessionClose(session);

        session = CreateValidSession(wskClient);
        transport = {};
        transport.Response = rawResponse;
        transport.ResponseLength = strlen(rawResponse);
        KhTestSetHttpTransport(TestHttpTransport, &transport);
        capture = {};
        capture.MessageCount = 2;
        capture.RepeatMessages = true;
        capture.Messages[0].Type = KernelHttp::api::KhWebSocketMessageType::Text;
        capture.Messages[0].Data = bannerData;
        capture.Messages[0].DataLength = sizeof(bannerData) - 1;
        capture.Messages[0].FinalFragment = true;
        capture.Messages[1].Type = KernelHttp::api::KhWebSocketMessageType::Text;
        capture.Messages[1].Data = echoData;
        capture.Messages[1].DataLength = sizeof(echoData) - 1;
        capture.Messages[1].FinalFragment = true;
        KhTestSetWebSocketTransport(
            TestWebSocketConnectTransport,
            TestWebSocketSendTransport,
            TestWebSocketReceiveTransport,
            TestWebSocketCloseTransport,
            &capture);

        results = {};
        status = KernelHttp::samples::RunHighLevelApiTestDriverSamples(session, &results);
        Expect(status == STATUS_SUCCESS, "test-driver high-level sample matrix succeeds through API test transports");
        Expect(results.HttpPut.Status == STATUS_SUCCESS, "test-driver matrix includes HTTP PUT");
        Expect(results.HttpGetAsync.Status == STATUS_SUCCESS, "test-driver matrix includes async HTTP GET");
        Expect(results.HttpPatch.Status == STATUS_SUCCESS, "test-driver matrix includes HTTP PATCH");
        Expect(results.HttpDelete.Status == STATUS_SUCCESS, "test-driver matrix includes HTTP DELETE");
        Expect(results.HttpHead.Status == STATUS_SUCCESS, "test-driver matrix includes HTTP HEAD");
        Expect(results.HttpOptions.Status == STATUS_SUCCESS, "test-driver matrix includes HTTP OPTIONS");
        Expect(results.HttpsPost.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS POST");
        Expect(results.HttpsPut.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS PUT");
        Expect(results.HttpsPatch.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS PATCH");
        Expect(results.HttpsDelete.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS DELETE");
        Expect(results.HttpsHead.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS HEAD");
        Expect(results.HttpsOptions.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS OPTIONS");
        Expect(results.HttpsNoVerify.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS no-verify");
        Expect(results.HttpsPostNoVerify.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS POST no-verify");
        Expect(results.HttpsPutNoVerify.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS PUT no-verify");
        Expect(results.HttpsPatchNoVerify.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS PATCH no-verify");
        Expect(results.HttpsDeleteNoVerify.Status == STATUS_SUCCESS, "test-driver matrix includes HTTPS DELETE no-verify");
        Expect(results.WebSocketEchoNoVerify.Status == STATUS_SUCCESS, "test-driver matrix includes WebSocket no-verify");
        Expect(results.WebSocketEchoAsync.Status == STATUS_SUCCESS, "test-driver matrix includes async WebSocket echo");
        Expect(results.WebSocketEchoNoVerify.StatusCode == 0, "test-driver websocket no-verify does not report handshake status as result status");
        Expect(results.RemoteHttpsIpv4.Status == STATUS_SUCCESS, "remote nghttp2 address-family samples include IPv4");
        Expect(results.RemoteHttpsIpv6.Status == STATUS_SUCCESS, "remote nghttp2 address-family samples include IPv6");
        Expect(transport.SawGet, "test-driver matrix sends GET");
        Expect(transport.SawPost, "test-driver matrix sends POST");
        Expect(transport.SawPut, "test-driver matrix sends PUT");
        Expect(transport.SawPatch, "test-driver matrix sends PATCH");
        Expect(transport.SawDelete, "test-driver matrix sends DELETE");
        Expect(transport.SawHead, "test-driver matrix sends HEAD");
        Expect(transport.SawOptions, "test-driver matrix sends OPTIONS");
        Expect(transport.NoVerifyCount >= 5, "test-driver matrix exercises explicit no-verify HTTPS scenarios");
        Expect(transport.Ipv4Count == 1, "test-driver matrix sends one forced remote IPv4 HTTPS request");
        Expect(transport.Ipv6Count == 1, "test-driver matrix sends one forced remote IPv6 HTTPS request");
        Expect(transport.H2AlpnCount >= 1, "test-driver matrix exercises HTTP/2 ALPN");
        Expect(transport.VerifiedHttpsForceNewCount == 10, "test-driver verified HTTPS matrix forces fresh TLS connections");
        Expect(transport.VerifiedHttpsReuseCount == 0, "test-driver verified HTTPS matrix avoids idle TLS reuse");
        Expect(capture.ConnectCount == 3 && capture.SendCount == 3 && capture.ReceiveCount == 6, "test-driver matrix skips websocket banners before sync, async, and no-verify text echoes");
        Expect(capture.LastMinTlsVersion == KhTlsVersion::Tls12 && capture.LastMaxTlsVersion == KhTlsVersion::Tls12, "test-driver websocket samples use TLS 1.2 for the live echo endpoint");
        Expect(capture.LastSendType == KernelHttp::api::KhWebSocketMessageType::Text, "test-driver websocket matrix sends text echo payload");

        KhTestSetHttpTransport(nullptr, nullptr);
        KhTestSetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
        KhSessionClose(session);
    }

    void TestAsyncValidation()
    {
        NTSTATUS status = KhAsyncCancel(nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "async cancel rejects null operation");
        status = KhAsyncWait(nullptr, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "async wait rejects null operation");
        KH_RESPONSE response = reinterpret_cast<KH_RESPONSE>(static_cast<size_t>(1));
        status = KhAsyncGetHttpResponse(nullptr, &response);
        Expect(status == STATUS_INVALID_PARAMETER, "async get HTTP response rejects null operation");
        Expect(response == nullptr, "async get HTTP response clears output");
        KH_WEBSOCKET websocket = reinterpret_cast<KH_WEBSOCKET>(static_cast<size_t>(1));
        status = KhAsyncGetWebSocket(nullptr, &websocket);
        Expect(status == STATUS_INVALID_PARAMETER, "async get websocket rejects null operation");
        Expect(websocket == nullptr, "async get websocket clears output");
        KhAsyncRelease(nullptr);
    }

    void TestIrqlGuards()
    {
        WskClient* wskClient = FakeWskClient();
        KH_SESSION session = nullptr;
        KH_REQUEST request = reinterpret_cast<KH_REQUEST>(static_cast<size_t>(1));
        KH_RESPONSE response = reinterpret_cast<KH_RESPONSE>(static_cast<size_t>(1));
        KH_WEBSOCKET websocket = reinterpret_cast<KH_WEBSOCKET>(static_cast<size_t>(1));
        KH_ASYNC_OPERATION operation = reinterpret_cast<KH_ASYNC_OPERATION>(static_cast<size_t>(1));
        KhResponseView responseView = {};
        KhWebSocketMessage message = {};
        const char text[] = "x";
        const UCHAR data[] = { 1 };

        KhTestSetCurrentIrql(2);
        NTSTATUS status = KhSessionCreate(wskClient, nullptr, &session);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "session create fails first at raised IRQL");
        Expect(session == nullptr, "session create does not touch output at raised IRQL");

        status = KhHttpRequestCreate(nullptr, &request);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "request create fails first at raised IRQL");
        Expect(request == reinterpret_cast<KH_REQUEST>(static_cast<size_t>(1)), "request create does not touch output at raised IRQL");

        status = KhHttpSendSync(nullptr, nullptr, nullptr, &response);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "send sync fails first at raised IRQL");
        Expect(response == reinterpret_cast<KH_RESPONSE>(static_cast<size_t>(1)), "send sync does not touch output at raised IRQL");

        status = KhHttpSendAsync(nullptr, nullptr, nullptr, &operation);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "send async fails first at raised IRQL");
        Expect(operation == reinterpret_cast<KH_ASYNC_OPERATION>(static_cast<size_t>(1)), "send async does not touch output at raised IRQL");

        status = KhResponseGetView(nullptr, &responseView);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "response get view fails first at raised IRQL");

        status = KhWebSocketConnectSync(nullptr, nullptr, &websocket);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "websocket connect sync fails first at raised IRQL");
        Expect(websocket == reinterpret_cast<KH_WEBSOCKET>(static_cast<size_t>(1)), "websocket connect sync does not touch output at raised IRQL");

        status = KhWebSocketConnectAsync(nullptr, nullptr, &operation);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "websocket connect async fails first at raised IRQL");

        status = KhWebSocketSendTextSync(nullptr, text, strlen(text), nullptr);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "websocket send text fails first at raised IRQL");
        status = KhWebSocketSendBinarySync(nullptr, data, sizeof(data), nullptr);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "websocket send binary fails first at raised IRQL");
        status = KhWebSocketReceiveSync(nullptr, nullptr, &message);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "websocket receive fails first at raised IRQL");
        status = KhWebSocketCloseSync(nullptr);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "websocket close fails first at raised IRQL");

        status = KhAsyncCancel(nullptr);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "async cancel fails first at raised IRQL");
        status = KhAsyncWait(nullptr, 0);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "async wait fails first at raised IRQL");
        status = KhAsyncGetHttpResponse(nullptr, &response);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "async get HTTP response fails first at raised IRQL");
        status = KhAsyncGetWebSocket(nullptr, &websocket);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "async get websocket fails first at raised IRQL");

        KhSessionClose(nullptr);
        KhHttpRequestRelease(nullptr);
        KhResponseRelease(nullptr);
        KhAsyncRelease(nullptr);

        KhTestResetCurrentIrql();
    }

    bool FileContains(const char* path, const char* needle)
    {
        FILE* file = nullptr;
        if (fopen_s(&file, path, "rb") != 0 || file == nullptr) {
            g_failed = true;
            printf("FAIL: unable to open %s\n", path);
            return false;
        }

        char line[1024] = {};
        bool found = false;
        while (fgets(line, sizeof(line), file) != nullptr) {
            if (strstr(line, needle) != nullptr) {
                found = true;
                break;
            }
        }

        fclose(file);
        return found;
    }

    void TestBlueScreenPathUsesWorkspaceAndProviderCache()
    {
        Expect(
            FileContains("src\\KernelHttp\\tls\\TlsConnection.cpp", "providerCache_ = options.ProviderCache"),
            "TLS connection options carry provider cache");
        Expect(
            FileContains("src\\KernelHttp\\tls\\TlsConnection.cpp", "validation.ProviderCache = options.ProviderCache"),
            "TLS certificate validation receives provider cache");
        Expect(
            FileContains("src\\KernelHttp\\tls\\CertificateValidator.cpp", "PrepareCertificateValidationScratch"),
            "certificate validation uses explicit scratch storage");
        Expect(
            FileContains("src\\KernelHttp\\tls\\CertificateValidator.cpp", "options.Workspace->CertificateScratch"),
            "certificate validation uses workspace certificate scratch");
        Expect(
            FileContains("src\\KernelHttp\\api\\KernelHttpApi.cpp", "tlsOptions.ProviderCache = session->ProviderCache"),
            "high-level API passes session provider cache into TLS");
    }

    void TestMainDriverUsesHighLevelSamples()
    {
        Expect(
            FileContains("src\\KernelHttp\\net\\WskClient.cpp", "NS_ALL"),
            "WSK address resolution queries all available namespace providers");
        Expect(
            FileContains("src\\KernelHttp\\net\\WskClient.cpp", "case WskAddressFamily::Any"),
            "WSK address resolution keeps a default dual-stack mode");
        Expect(
            FileContains("src\\KernelHttp\\net\\WskClient.cpp", "case WskAddressFamily::Ipv4"),
            "WSK address resolution can request IPv4 candidates explicitly");
        Expect(
            FileContains("src\\KernelHttp\\net\\WskClient.cpp", "case WskAddressFamily::Ipv6"),
            "WSK address resolution can request IPv6 candidates explicitly");
        Expect(
            FileContains("src\\KernelHttp\\net\\WskClient.cpp", "hints.ai_flags = AI_NUMERICSERV"),
            "WSK address resolution declares numeric port service names");
        Expect(
            FileContains("src\\KernelHttp\\net\\WskClient.cpp", "RtlInitUnicodeString(&service, serviceName)"),
            "WSK address resolution passes the validated service name into the query");
        Expect(
            !FileContains("src\\KernelHttp\\net\\WskClient.cpp", "NS_DNS"),
            "WSK address resolution does not force the DNS-only namespace provider");
        Expect(
            !FileContains("src\\KernelHttp\\net\\WskClient.cpp", "hints.ai_family = AF_INET;"),
            "WSK address resolution default is not restricted to IPv4-only results");
        Expect(
            FileContains("src\\KernelHttp\\DriverEntry.cpp", "samples/HighLevelApiSamples.h"),
            "DriverEntry includes high-level sample runner");
        Expect(
            !FileContains("src\\KernelHttp\\DriverEntry.cpp", "samples/HttpVerbSamples.h"),
            "DriverEntry does not include legacy HTTP verb samples");
        Expect(
            !FileContains("src\\KernelHttp\\DriverEntry.cpp", "RunHttpVerbSamples"),
            "DriverEntry does not call legacy HTTP verb sample matrix");
        Expect(
            !FileContains("src\\KernelHttp\\DriverEntry.cpp", "RunHttp2VerbSamples"),
            "DriverEntry does not call legacy HTTP/2 sample matrix");
        Expect(
            FileContains("src\\KernelHttp\\DriverEntry.cpp", "KhSessionCreate"),
            "DriverEntry creates a high-level API session");
        Expect(
            FileContains("src\\KernelHttp\\DriverEntry.cpp", "KhSessionClose"),
            "DriverEntry closes the high-level API session");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "client/HttpsClient.h"),
            "high-level samples do not include HttpsClient directly");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "client/WebSocketClient.h"),
            "high-level samples do not include WebSocketClient directly");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "tls/TlsConnection.h"),
            "high-level samples do not include TlsConnection directly");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "samples/ExternalTrustStore.h"),
            "high-level samples use external trust store helper");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "InitializeExternalTrustStore"),
            "high-level verified samples initialize external trust data");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "http://nghttp2.org/httpbin/get"),
            "high-level HTTP samples use the dual-stack nghttp2 httpbin endpoint");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "http://httpbin.org"),
            "high-level HTTP samples do not use the IPv4-only httpbin.org endpoint");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "https://nghttp2.org/httpbin/get"),
            "remote HTTPS address-family samples use the nghttp2 httpbin endpoint");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "https://127.0.0.1:8443/sample_response_body.txt"),
            "remote HTTPS address-family samples do not use a local IPv4 server");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "https://[::1]:8443/sample_response_body.txt"),
            "remote HTTPS address-family samples do not use a local IPv6 server");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.h", "RemoteHttpsIpv4"),
            "remote HTTPS sample results expose the IPv4 run");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.h", "RemoteHttpsIpv6"),
            "remote HTTPS sample results expose the IPv6 run");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "api::KhAddressFamily::Ipv4"),
            "remote HTTPS samples force IPv4 resolution");
        Expect(
            FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "api::KhAddressFamily::Ipv6"),
            "remote HTTPS samples force IPv6 resolution");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "NgHttp2LeafSpkiSha256"),
            "high-level samples do not pin nghttp2 leaf SPKI");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "NgHttp2LetsEncrypt"),
            "high-level samples do not pin nghttp2 authority SPKI");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "WebSocketEchoLeafSpkiSha256"),
            "high-level samples do not pin websocket echo leaf SPKI");
        Expect(
            !FileContains("src\\KernelHttp\\samples\\HighLevelApiSamples.cpp", "WebSocketEchoLetsEncrypt"),
            "high-level samples do not pin websocket echo authority SPKI");
        Expect(
            FileContains("src\\KernelHttp\\DriverEntry.cpp", "KERNEL_HTTP_TEST_DRIVER_SCENARIOS"),
            "DriverEntry has explicit test-driver scenario matrix switch");
        Expect(
            FileContains("src\\KernelHttp\\DriverEntry.cpp", "DriverEntry continuing after load-time sample failure"),
            "DriverEntry logs load-time sample failure without failing driver load");
        Expect(
            FileContains("src\\KernelHttp\\DriverEntry.cpp", "DriverEntry continuing without WSK after initialization failure"),
            "DriverEntry logs WSK initialization failure without failing driver load");
        Expect(
            FileContains("src\\KernelHttp\\DriverEntry.cpp", "status = STATUS_SUCCESS;"),
            "DriverEntry normalizes load-time sample result to successful driver load");
    }
}

int main()
{
    TestDefaultOptions();
    TestExternalTrustStore();
    TestSessionValidation();
    TestWorkspaceLifecycle();
    TestProviderCache();
    TestRequestValidation();
    TestHttpSendValidation();
    TestConnectionPoolKeys();
    TestConnectionPoolAcquireRelease();
    TestHttpSyncSendResponseManagement();
    TestHighLevelRequestBodyTypes();
    TestHttpSyncConnectionPolicies();
    TestHttpAsyncState();
    TestHttpUrlRequestTargetParsing();
    TestResponseValidation();
    TestWebSocketValidation();
    TestWebSocketApiBehavior();
    TestWebSocketAsyncBehavior();
    TestHighLevelSampleRunners();
    TestAsyncValidation();
    TestIrqlGuards();
    TestBlueScreenPathUsesWorkspaceAndProviderCache();
    TestMainDriverUsesHighLevelSamples();

    if (g_failed) {
        return 1;
    }

    printf("high level api tests passed\n");
    return 0;
}
