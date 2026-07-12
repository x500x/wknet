#pragma once

#include <wknet/engine/HandleTypes.h>

namespace wknet
{
namespace session
{
#if defined(WKNET_USER_MODE_TEST)
    extern KhTestHttpTransportCallback g_testHttpTransport;
    extern void* g_testHttpTransportContext;
    extern KhTestWebSocketConnectCallback g_testWebSocketConnect;
    extern KhTestWebSocketSendCallback g_testWebSocketSend;
    extern KhTestWebSocketReceiveCallback g_testWebSocketReceive;
    extern KhTestWebSocketCloseCallback g_testWebSocketClose;
    extern void* g_testWebSocketTransportContext;
#endif

    bool IsPassiveLevel() noexcept;
    NTSTATUS CheckPassiveLevel() noexcept;
    SIZE_T EffectiveMaxResponseBytes(const KhHttpSendOptions* options, SIZE_T sessionValue) noexcept;
    bool IsValidSendOptions(const KhHttpSendOptions& options, const KhSession& session) noexcept;
    bool IsValidWebSocketConnectOptions(const KhWebSocketConnectOptions& options) noexcept;
    bool IsValidReceiveOptions(const KhWebSocketReceiveOptions& options) noexcept;

    // Validates and deep-copies caller-supplied opening-handshake headers into the
    // WebSocket handle. Rejects (STATUS_INVALID_PARAMETER) any header whose name
    // collides with a library-controlled handshake header, and validates name/value
    // text to prevent CRLF injection. On failure the handle's header storage is left
    // empty (caller frees the handle via ReleaseWebSocketStorage).
    _Must_inspect_result_
    NTSTATUS CopyWebSocketHeaders(
        const KhWebSocketHeader* headers,
        SIZE_T headerCount,
        _Inout_ KhWebSocket& websocket) noexcept;
    bool IsValidAddressFamily(KhAddressFamily addressFamily) noexcept;
    net::WskAddressFamily ToWskAddressFamily(KhAddressFamily addressFamily) noexcept;

    _Ret_maybenull_
    void* AllocateApiMemory(SIZE_T length) noexcept;

    void FreeApiMemory(_In_opt_ void* data) noexcept;

    _Ret_maybenull_
    char* AllocateTextCopy(const char* text, SIZE_T length) noexcept;

    _Ret_maybenull_
    UCHAR* AllocateBytesCopy(const UCHAR* data, SIZE_T length) noexcept;

    bool TextEqualsIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right,
        SIZE_T rightLength) noexcept;

    bool TextEqualsLiteralIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept;

    bool TextEqualsLiteral(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept;

    bool TextContainsChar(const char* text, SIZE_T textLength, char needle) noexcept;
    bool IsConnectionCloseStatus(NTSTATUS status) noexcept;
    bool IsOrderlyConnectionCloseStatus(NTSTATUS status) noexcept;
    bool IsDefaultPort(const char* scheme, SIZE_T schemeLength, USHORT port) noexcept;

    _Must_inspect_result_
    NTSTATUS CopyExactText(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;

    bool IsSessionHandle(KH_SESSION session) noexcept;
    bool IsRequestHandle(KH_REQUEST request) noexcept;
    bool IsResponseHandle(KH_RESPONSE response) noexcept;
    bool IsWebSocketHandle(KH_WEBSOCKET websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveSessionHandle(_In_ KH_SESSION session) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveRequestHandle(_In_ KH_REQUEST request) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveResponseHandle(_In_ KH_RESPONSE response) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveWebSocketHandle(_In_ KH_WEBSOCKET websocket) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveSessionHandle(_In_opt_ KH_SESSION session) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveRequestHandle(_In_opt_ KH_REQUEST request) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveResponseHandle(_In_opt_ KH_RESPONSE response) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveWebSocketHandle(_In_opt_ KH_WEBSOCKET websocket) noexcept;

    _Must_inspect_result_
    bool KhSessionBeginOperation(_In_opt_ KH_SESSION session) noexcept;

    void KhSessionEndOperation(_In_opt_ KH_SESSION session) noexcept;

    _Must_inspect_result_
    bool KhRequestBeginOperation(_In_opt_ KH_REQUEST request) noexcept;

    void KhRequestEndOperation(_In_opt_ KH_REQUEST request) noexcept;

    _Must_inspect_result_
    bool KhResponseBeginOperation(_In_opt_ KH_RESPONSE response) noexcept;

    void KhResponseEndOperation(_In_opt_ KH_RESPONSE response) noexcept;

    _Must_inspect_result_
    bool KhWebSocketBeginOperation(_In_opt_ KH_WEBSOCKET websocket) noexcept;

    void KhWebSocketEndOperation(_In_opt_ KH_WEBSOCKET websocket) noexcept;

    class KhSessionOperationScope final
    {
    public:
        explicit KhSessionOperationScope(_In_opt_ KH_SESSION session) noexcept :
            session_(session),
            active_(KhSessionBeginOperation(session))
        {
        }

        ~KhSessionOperationScope() noexcept
        {
            if (active_) {
                KhSessionEndOperation(session_);
            }
        }

        KhSessionOperationScope(const KhSessionOperationScope&) = delete;
        KhSessionOperationScope& operator=(const KhSessionOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        KH_SESSION session_ = nullptr;
        bool active_ = false;
    };

    class KhRequestOperationScope final
    {
    public:
        explicit KhRequestOperationScope(_In_opt_ KH_REQUEST request) noexcept :
            request_(request),
            active_(KhRequestBeginOperation(request))
        {
        }

        ~KhRequestOperationScope() noexcept
        {
            if (active_) {
                KhRequestEndOperation(request_);
            }
        }

        KhRequestOperationScope(const KhRequestOperationScope&) = delete;
        KhRequestOperationScope& operator=(const KhRequestOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        KH_REQUEST request_ = nullptr;
        bool active_ = false;
    };

    class KhResponseOperationScope final
    {
    public:
        explicit KhResponseOperationScope(_In_opt_ KH_RESPONSE response) noexcept :
            response_(response),
            active_(KhResponseBeginOperation(response))
        {
        }

        ~KhResponseOperationScope() noexcept
        {
            if (active_) {
                KhResponseEndOperation(response_);
            }
        }

        KhResponseOperationScope(const KhResponseOperationScope&) = delete;
        KhResponseOperationScope& operator=(const KhResponseOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        KH_RESPONSE response_ = nullptr;
        bool active_ = false;
    };

    void ReleaseRequestStorage(_Inout_ KhRequest& request) noexcept;

    _Must_inspect_result_
    NTSTATUS CloneRequestForAsync(_In_ const KhRequest& source, _Out_ KH_REQUEST* clonedRequest) noexcept;

    void ReleaseResponseStorage(_Inout_ KhResponse& response) noexcept;
    void ReleaseWebSocketStorage(_Inout_ KhWebSocket& websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS BuildHostHeaderValue(
        const KhRequest& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept;

#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS CopyAsciiToWide(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept;

    _Must_inspect_result_
    NTSTATUS FormatServiceName(
        USHORT port,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept;

    tls::TlsProtocol ToTlsProtocol(KhTlsVersion version) noexcept;
#endif
}
}
