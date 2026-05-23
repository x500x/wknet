#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/api/KernelHttpApi.h"

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
using KernelHttp::api::KhHttpSendAsync;
using KernelHttp::api::KhHttpSendFlagAggregateWithCallbacks;
using KernelHttp::api::KhHttpSendOptions;
using KernelHttp::api::KhHttpSendSync;
using KernelHttp::api::KhPoolType;
using KernelHttp::api::KhResponseGetView;
using KernelHttp::api::KhResponseRelease;
using KernelHttp::api::KhResponseView;
using KernelHttp::api::KhSessionClose;
using KernelHttp::api::KhSessionCreate;
using KernelHttp::api::KhSessionOptions;
using KernelHttp::api::KhTestResetCurrentIrql;
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
        KhSessionClose(session);
        KhSessionClose(nullptr);
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
        status = KhHttpRequestSetHeader(request, "Name", 4, "Value", 5);
        Expect(status == STATUS_NOT_SUPPORTED, "set header is explicit not-supported until header store chunk");

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
        Expect(status == STATUS_NOT_SUPPORTED, "send sync validates callback-only mode before transport chunk");

        options = {};
        options.HeaderCallback = TestHeaderCallback;
        status = KhHttpSendSync(session, request, &options, nullptr);
        Expect(status == STATUS_NOT_SUPPORTED, "send sync validates header callback mode before transport chunk");

        KH_ASYNC_OPERATION operation = reinterpret_cast<KH_ASYNC_OPERATION>(static_cast<size_t>(1));
        status = KhHttpSendAsync(session, request, nullptr, nullptr);
        Expect(status == STATUS_INVALID_PARAMETER, "send async rejects null operation output");
        status = KhHttpSendAsync(session, request, nullptr, &operation);
        Expect(status == STATUS_NOT_SUPPORTED, "send async validates inputs before async worker chunk");
        Expect(operation == nullptr, "send async clears operation output before not-supported");

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
    TestRequestValidation();
    TestHttpSendValidation();
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
