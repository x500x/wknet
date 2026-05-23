#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/api/KernelHttpApi.h"
#include "../src/KernelHttp/api/KernelHttpConnectionPool.h"
#include "../src/KernelHttp/api/KernelHttpWorkspace.h"
#include "../src/KernelHttp/crypto/CngProviderCache.h"

#include <stdio.h>
#include <string.h>

using KernelHttp::api::KH_ASYNC_OPERATION;
using KernelHttp::api::KH_REQUEST;
using KernelHttp::api::KH_RESPONSE;
using KernelHttp::api::KH_SESSION;
using KernelHttp::api::KH_WEBSOCKET;
using KernelHttp::api::KhAsyncCancel;
using KernelHttp::api::KhAsyncRelease;
using KernelHttp::api::KhAsyncWait;
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
using KernelHttp::api::KhHttpRequestCreate;
using KernelHttp::api::KhHttpRequestRelease;
using KernelHttp::api::KhHttpRequestSetBody;
using KernelHttp::api::KhHttpRequestSetConnectionPolicy;
using KernelHttp::api::KhHttpRequestSetHeader;
using KernelHttp::api::KhHttpRequestSetMethod;
using KernelHttp::api::KhHttpRequestSetTlsOptions;
using KernelHttp::api::KhHttpRequestSetUrl;
using KernelHttp::api::KhResponseGetHeader;
using KernelHttp::api::KhHttpSendAsync;
using KernelHttp::api::KhHttpSendFlagAggregateWithCallbacks;
using KernelHttp::api::KhHttpSendOptions;
using KernelHttp::api::KhTestSessionHasProviderCache;
using KernelHttp::api::KhTestSessionHasWorkspace;
using KernelHttp::api::KhHttpSendSync;
using KernelHttp::api::KhPoolType;
using KernelHttp::api::KhResponseGetView;
using KernelHttp::api::KhResponseRelease;
using KernelHttp::api::KhResponseView;
using KernelHttp::api::KhSessionClose;
using KernelHttp::api::KhSessionCreate;
using KernelHttp::api::KhSessionOptions;
using KernelHttp::api::KhTestResetCurrentIrql;
using KernelHttp::api::KhTestHttpTransportRequest;
using KernelHttp::api::KhTestHttpTransportResponse;
using KernelHttp::api::KhTestSetHttpTransport;
using KernelHttp::api::KhTestSetCurrentIrql;
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

    NTSTATUS TestMessageCallback(
        void* context,
        KernelHttp::api::KhWebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment)
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(type);
        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(dataLength);
        UNREFERENCED_PARAMETER(finalFragment);
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

    struct TransportContext
    {
        SIZE_T CallCount = 0;
        ULONG LastConnectionId = 0;
        bool LastReused = false;
        KhConnectionPolicy LastPolicy = KhConnectionPolicy::ReuseOrCreate;
        bool LastPoolable = false;
        char LastHost[64] = {};
        USHORT LastPort = 0;
        char LastRequest[512] = {};
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
        transport->LastPoolable = request->PoolableConnection;
        transport->LastPort = request->Port;

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

        response->RawResponse = transport->Response;
        response->RawResponseLength = transport->ResponseLength;
        response->ConnectionReusable = transport->ConnectionReusable;
        return STATUS_SUCCESS;
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

        KH_ASYNC_OPERATION operation = reinterpret_cast<KH_ASYNC_OPERATION>(static_cast<size_t>(1));
        status = KhHttpSendAsync(session, request, nullptr, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "send async rejects null operation output");
        status = KhHttpSendAsync(session, request, nullptr, &operation);
        Expect(status == STATUS_NOT_SUPPORTED, "send async validates inputs before async worker chunk");
        Expect(operation == nullptr, "send async clears operation output before not-supported");

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
        KhResponseRelease(response);

        status = KhHttpRequestSetConnectionPolicy(request, KhConnectionPolicy::NoPool);
        Expect(status == STATUS_SUCCESS, "request sets no-pool policy");
        response = nullptr;
        status = KhHttpSendSync(session, request, nullptr, &response);
        Expect(status == STATUS_SUCCESS, "no-pool request succeeds");
        Expect(!transport.LastPoolable, "no-pool request tells transport it is not poolable");
        KhResponseRelease(response);

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
        status = KhWebSocketConnectAsync(session, &connectOptions, &operation);
        Expect(status == STATUS_NOT_SUPPORTED, "websocket connect async validates before worker chunk");
        Expect(operation == nullptr, "websocket connect async clears operation output before not-supported");

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

    void TestAsyncValidation()
    {
        NTSTATUS status = KhAsyncCancel(nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "async cancel rejects null operation");
        status = KhAsyncWait(nullptr, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "async wait rejects null operation");
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

        KhSessionClose(nullptr);
        KhHttpRequestRelease(nullptr);
        KhResponseRelease(nullptr);
        KhAsyncRelease(nullptr);

        KhTestResetCurrentIrql();
    }
}

int main()
{
    TestDefaultOptions();
    TestSessionValidation();
    TestWorkspaceLifecycle();
    TestProviderCache();
    TestRequestValidation();
    TestHttpSendValidation();
    TestConnectionPoolKeys();
    TestConnectionPoolAcquireRelease();
    TestHttpSyncSendResponseManagement();
    TestHttpSyncConnectionPolicies();
    TestHttpUrlRequestTargetParsing();
    TestResponseValidation();
    TestWebSocketValidation();
    TestAsyncValidation();
    TestIrqlGuards();

    if (g_failed) {
        return 1;
    }

    printf("high level api tests passed\n");
    return 0;
}
