#include "KernelHttpApi.h"

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

namespace KernelHttp
{
namespace api
{
namespace
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    constexpr ULONG PassiveLevel = 0;
    ULONG g_testCurrentIrql = PassiveLevel;
#else
    constexpr ULONG PassiveLevel = PASSIVE_LEVEL;
#endif

    enum class KhHandleKind : ULONG
    {
        Session = 0x4B485331,
        Request = 0x4B485231,
        Response = 0x4B485031,
        WebSocket = 0x4B485731,
        AsyncOperation = 0x4B484131
    };

    struct KhHandleHeader
    {
        KhHandleKind Kind;
        bool Closed;
    };

    bool IsPassiveLevel() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return g_testCurrentIrql == PassiveLevel;
#else
        return KeGetCurrentIrql() == PASSIVE_LEVEL;
#endif
    }

    NTSTATUS CheckPassiveLevel() noexcept
    {
        return IsPassiveLevel() ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
    }

    bool IsValidMaxResponseBytes(SIZE_T value) noexcept
    {
        return value > 0;
    }

    SIZE_T EffectiveMaxResponseBytes(SIZE_T requestValue, SIZE_T sessionValue) noexcept
    {
        return requestValue != 0 ? requestValue : sessionValue;
    }

    bool IsValidTlsOptions(const KhTlsOptions& options) noexcept
    {
        if (static_cast<ULONG>(options.MinVersion) > static_cast<ULONG>(options.MaxVersion)) {
            return false;
        }

        if (options.ServerName == nullptr && options.ServerNameLength != 0) {
            return false;
        }

        if (options.ServerName != nullptr && options.ServerNameLength == 0) {
            return false;
        }

        if (options.Alpn == nullptr && options.AlpnLength != 0) {
            return false;
        }

        if (options.Alpn != nullptr && options.AlpnLength == 0) {
            return false;
        }

        return true;
    }

    bool IsValidSessionOptions(const KhSessionOptions& options) noexcept
    {
        if (!IsValidMaxResponseBytes(options.MaxResponseBytes)) {
            return false;
        }

        if (options.ConnectionPoolCapacity == 0 || options.MaxConnectionsPerHost == 0) {
            return false;
        }

        return IsValidTlsOptions(options.Tls);
    }

    bool IsValidSendOptions(const KhHttpSendOptions& options, const KhSession& session) noexcept;

    bool IsValidWebSocketConnectOptions(const KhWebSocketConnectOptions& options) noexcept
    {
        if (options.Url == nullptr || options.UrlLength == 0) {
            return false;
        }

        if (options.Subprotocol == nullptr && options.SubprotocolLength != 0) {
            return false;
        }

        if (options.Subprotocol != nullptr && options.SubprotocolLength == 0) {
            return false;
        }

        if (!IsValidMaxResponseBytes(options.MaxMessageBytes)) {
            return false;
        }

        return IsValidTlsOptions(options.Tls);
    }

    bool IsValidReceiveOptions(const KhWebSocketReceiveOptions& options) noexcept
    {
        if (options.MessageCallback == nullptr && options.CallbackContext != nullptr) {
            return false;
        }

        if (!options.AutoAllocate && options.MessageCallback == nullptr) {
            return false;
        }

        return true;
    }

    template<typename T>
    T* AllocateHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<T*>(calloc(1, sizeof(T)));
#else
        return new T();
#endif
    }

    template<typename T>
    void FreeHandle(T* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    bool IsSessionHandle(KH_SESSION session) noexcept;
    bool IsRequestHandle(KH_REQUEST request) noexcept;
    bool IsResponseHandle(KH_RESPONSE response) noexcept;
    bool IsWebSocketHandle(KH_WEBSOCKET websocket) noexcept;
    bool IsAsyncHandle(KH_ASYNC_OPERATION operation) noexcept;
}

    struct KhSession
    {
        KhHandleHeader Header = { KhHandleKind::Session, false };
        net::WskClient* WskClient = nullptr;
        KhSessionOptions Options = {};
    };

    struct KhRequest
    {
        KhHandleHeader Header = { KhHandleKind::Request, false };
        KH_SESSION Session = nullptr;
        KhHttpMethod Method = KhHttpMethod::Get;
        const char* Url = nullptr;
        SIZE_T UrlLength = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        KhTlsOptions Tls = {};
        bool HasTlsOverride = false;
        KhConnectionPolicy ConnectionPolicy = KhConnectionPolicy::ReuseOrCreate;
    };

    struct KhResponse
    {
        KhHandleHeader Header = { KhHandleKind::Response, false };
        ULONG StatusCode = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
    };

    struct KhWebSocket
    {
        KhHandleHeader Header = { KhHandleKind::WebSocket, false };
        KH_SESSION Session = nullptr;
        bool Connected = false;
    };

    struct KhAsyncOperation
    {
        KhHandleHeader Header = { KhHandleKind::AsyncOperation, false };
        NTSTATUS Status = STATUS_PENDING;
        bool Canceled = false;
    };

namespace
{
    bool IsValidSendOptions(const KhHttpSendOptions& options, const KhSession& session) noexcept
    {
        if (!IsValidMaxResponseBytes(EffectiveMaxResponseBytes(options.MaxResponseBytes, session.Options.MaxResponseBytes))) {
            return false;
        }

        if (options.HeaderCallback == nullptr && options.BodyCallback == nullptr && options.CallbackContext != nullptr) {
            return false;
        }

        if (options.BodyCallback == nullptr && ((options.Flags & KhHttpSendFlagAggregateWithCallbacks) != 0)) {
            return false;
        }

        return true;
    }

    bool IsHandleHeader(const KhHandleHeader* header, KhHandleKind expectedKind) noexcept
    {
        return header != nullptr && header->Kind == expectedKind && !header->Closed;
    }

    bool IsSessionHandle(KH_SESSION session) noexcept
    {
        return IsHandleHeader(session == nullptr ? nullptr : &session->Header, KhHandleKind::Session);
    }

    bool IsRequestHandle(KH_REQUEST request) noexcept
    {
        return IsHandleHeader(request == nullptr ? nullptr : &request->Header, KhHandleKind::Request);
    }

    bool IsResponseHandle(KH_RESPONSE response) noexcept
    {
        return IsHandleHeader(response == nullptr ? nullptr : &response->Header, KhHandleKind::Response);
    }

    bool IsWebSocketHandle(KH_WEBSOCKET websocket) noexcept
    {
        return IsHandleHeader(websocket == nullptr ? nullptr : &websocket->Header, KhHandleKind::WebSocket);
    }

    bool IsAsyncHandle(KH_ASYNC_OPERATION operation) noexcept
    {
        return IsHandleHeader(operation == nullptr ? nullptr : &operation->Header, KhHandleKind::AsyncOperation);
    }
}

    NTSTATUS KhSessionCreate(
        net::WskClient* wskClient,
        const KhSessionOptions* options,
        KH_SESSION* session) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (wskClient == nullptr || session == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *session = nullptr;

        KhSessionOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidSessionOptions(effectiveOptions)) {
            return STATUS_INVALID_PARAMETER;
        }

        KH_SESSION newSession = AllocateHandle<KhSession>();
        if (newSession == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newSession->Header = { KhHandleKind::Session, false };
        newSession->WskClient = wskClient;
        newSession->Options = effectiveOptions;
        *session = newSession;
        return STATUS_SUCCESS;
    }

    void KhSessionClose(KH_SESSION session) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || session == nullptr) {
            return;
        }

        if (!IsSessionHandle(session)) {
            return;
        }

        session->Header.Closed = true;
        FreeHandle(session);
    }

    NTSTATUS KhHttpRequestCreate(KH_SESSION session, KH_REQUEST* request) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsSessionHandle(session) || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *request = nullptr;

        KH_REQUEST newRequest = AllocateHandle<KhRequest>();
        if (newRequest == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newRequest->Header = { KhHandleKind::Request, false };
        newRequest->Session = session;
        newRequest->Method = KhHttpMethod::Get;
        newRequest->Tls = session->Options.Tls;
        *request = newRequest;
        return STATUS_SUCCESS;
    }

    void KhHttpRequestRelease(KH_REQUEST request) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || request == nullptr) {
            return;
        }

        if (!IsRequestHandle(request)) {
            return;
        }

        request->Header.Closed = true;
        FreeHandle(request);
    }

    NTSTATUS KhHttpRequestSetUrl(KH_REQUEST request, const char* url, SIZE_T urlLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || url == nullptr || urlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        request->Url = url;
        request->UrlLength = urlLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS KhHttpRequestSetMethod(KH_REQUEST request, KhHttpMethod method) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        switch (method) {
        case KhHttpMethod::Get:
        case KhHttpMethod::Post:
        case KhHttpMethod::Put:
        case KhHttpMethod::Patch:
        case KhHttpMethod::Delete:
        case KhHttpMethod::Head:
            request->Method = method;
            return STATUS_SUCCESS;
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS KhHttpRequestSetHeader(
        KH_REQUEST request,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || name == nullptr || nameLength == 0 || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        UNREFERENCED_PARAMETER(valueLength);
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhHttpRequestSetBody(KH_REQUEST request, const UCHAR* body, SIZE_T bodyLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (body == nullptr && bodyLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        request->Body = body;
        request->BodyLength = bodyLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS KhHttpRequestSetTlsOptions(KH_REQUEST request, const KhTlsOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || options == nullptr || !IsValidTlsOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        request->Tls = *options;
        request->HasTlsOverride = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS KhHttpRequestSetConnectionPolicy(KH_REQUEST request, KhConnectionPolicy policy) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        switch (policy) {
        case KhConnectionPolicy::ReuseOrCreate:
        case KhConnectionPolicy::ForceNew:
        case KhConnectionPolicy::NoPool:
            request->ConnectionPolicy = policy;
            return STATUS_SUCCESS;
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS KhHttpSendSync(
        KH_SESSION session,
        KH_REQUEST request,
        const KhHttpSendOptions* options,
        KH_RESPONSE* response) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (response != nullptr) {
            *response = nullptr;
        }

        if (!IsSessionHandle(session) || !IsRequestHandle(request) || request->Session != session) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request->Url == nullptr || request->UrlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        KhHttpSendOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidSendOptions(effectiveOptions, *session)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (effectiveOptions.BodyCallback != nullptr &&
            response == nullptr &&
            ((effectiveOptions.Flags & KhHttpSendFlagAggregateWithCallbacks) != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhHttpSendAsync(
        KH_SESSION session,
        KH_REQUEST request,
        const KhHttpSendOptions* options,
        KH_ASYNC_OPERATION* operation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (operation != nullptr) {
            *operation = nullptr;
        }

        if (!IsSessionHandle(session) || !IsRequestHandle(request) || operation == nullptr || request->Session != session) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request->Url == nullptr || request->UrlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        KhHttpSendOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidSendOptions(effectiveOptions, *session)) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhResponseGetView(KH_RESPONSE response, KhResponseView* view) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsResponseHandle(response) || view == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        view->StatusCode = response->StatusCode;
        view->Body = response->Body;
        view->BodyLength = response->BodyLength;
        return STATUS_SUCCESS;
    }

    void KhResponseRelease(KH_RESPONSE response) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || response == nullptr) {
            return;
        }

        if (!IsResponseHandle(response)) {
            return;
        }

        response->Header.Closed = true;
        FreeHandle(response);
    }

    NTSTATUS KhWebSocketConnectSync(
        KH_SESSION session,
        const KhWebSocketConnectOptions* options,
        KH_WEBSOCKET* websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        if (!IsSessionHandle(session) || options == nullptr || websocket == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhWebSocketConnectAsync(
        KH_SESSION session,
        const KhWebSocketConnectOptions* options,
        KH_ASYNC_OPERATION* operation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (operation != nullptr) {
            *operation = nullptr;
        }

        if (!IsSessionHandle(session) || options == nullptr || operation == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhWebSocketSendTextSync(
        KH_WEBSOCKET websocket,
        const char* text,
        SIZE_T textLength,
        const KhWebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UNREFERENCED_PARAMETER(options);
        if (!IsWebSocketHandle(websocket) || text == nullptr || textLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhWebSocketSendBinarySync(
        KH_WEBSOCKET websocket,
        const UCHAR* data,
        SIZE_T dataLength,
        const KhWebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UNREFERENCED_PARAMETER(options);
        if (!IsWebSocketHandle(websocket) || data == nullptr || dataLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhWebSocketReceiveSync(
        KH_WEBSOCKET websocket,
        const KhWebSocketReceiveOptions* options,
        KhWebSocketMessage* message) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (message != nullptr) {
            *message = {};
        }

        if (!IsWebSocketHandle(websocket)) {
            return STATUS_INVALID_PARAMETER;
        }

        KhWebSocketReceiveOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidReceiveOptions(effectiveOptions)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (effectiveOptions.AutoAllocate && message == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS KhWebSocketCloseSync(KH_WEBSOCKET websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsWebSocketHandle(websocket)) {
            return websocket == nullptr ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        }

        websocket->Connected = false;
        websocket->Header.Closed = true;
        FreeHandle(websocket);
        return STATUS_SUCCESS;
    }

    NTSTATUS KhAsyncCancel(KH_ASYNC_OPERATION operation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsAsyncHandle(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        operation->Canceled = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS KhAsyncWait(KH_ASYNC_OPERATION operation, ULONG timeoutMilliseconds) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UNREFERENCED_PARAMETER(timeoutMilliseconds);
        if (!IsAsyncHandle(operation)) {
            return STATUS_INVALID_PARAMETER;
        }

        return operation->Status;
    }

    void KhAsyncRelease(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || operation == nullptr) {
            return;
        }

        if (!IsAsyncHandle(operation)) {
            return;
        }

        operation->Header.Closed = true;
        FreeHandle(operation);
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    void KhTestSetCurrentIrql(ULONG irql) noexcept
    {
        g_testCurrentIrql = irql;
    }

    void KhTestResetCurrentIrql() noexcept
    {
        g_testCurrentIrql = PassiveLevel;
    }
#endif
}
}
