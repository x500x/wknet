#pragma once

#include "session/HandleTypes.h"

namespace wknet
{
namespace session
{
#if defined(WKNET_USER_MODE_TEST)
    extern TestHttpTransportCallback g_testHttpTransport;
    extern void* g_testHttpTransportContext;
    extern TestWebSocketConnectCallback g_testWebSocketConnect;
    extern TestWebSocketSendCallback g_testWebSocketSend;
    extern TestWebSocketReceiveCallback g_testWebSocketReceive;
    extern TestWebSocketCloseCallback g_testWebSocketClose;
    extern void* g_testWebSocketTransportContext;
#endif

    bool IsPassiveLevel() noexcept;
    NTSTATUS CheckPassiveLevel() noexcept;
    SIZE_T EffectiveMaxResponseBytes(const HttpSendOptions* options, SIZE_T sessionValue) noexcept;
    bool IsValidSendOptions(const HttpSendOptions& options, const Session& session) noexcept;
    bool IsValidWebSocketConnectOptions(const WebSocketConnectOptions& options) noexcept;
    bool IsValidReceiveOptions(const WebSocketReceiveOptions& options) noexcept;

    // Validates and deep-copies caller-supplied opening-handshake headers into the
    // WebSocket handle. Rejects (STATUS_INVALID_PARAMETER) any header whose name
    // collides with a library-controlled handshake header, and validates name/value
    // text to prevent CRLF injection. On failure the handle's header storage is left
    // empty (caller frees the handle via ReleaseWebSocketStorage).
    _Must_inspect_result_
    NTSTATUS CopyWebSocketHeaders(
        const WebSocketHeader* headers,
        SIZE_T headerCount,
        _Inout_ WebSocket& websocket) noexcept;
    bool IsValidAddressFamily(AddressFamily addressFamily) noexcept;
    net::WskAddressFamily ToWskAddressFamily(AddressFamily addressFamily) noexcept;

    _Ret_maybenull_
    void* AllocateApiMemory(SIZE_T length) noexcept;

    void FreeApiMemory(_In_opt_ void* data) noexcept;

    _Ret_maybenull_
    char* AllocateTextCopy(const char* text, SIZE_T length) noexcept;

    _Ret_maybenull_
    UCHAR* AllocateBytesCopy(const UCHAR* data, SIZE_T length) noexcept;

    void ReleaseStoredHeader(_Inout_ StoredHeader& header) noexcept;
    void ReleaseStoredHeaderList(_Inout_ StoredHeaderList& list) noexcept;
    _Must_inspect_result_
    NTSTATUS EnsureStoredHeaderListCapacity(
        _Inout_ StoredHeaderList& list,
        SIZE_T requiredCount) noexcept;

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

    bool IsSessionHandle(SessionHandle session) noexcept;
    bool IsRequestHandle(RequestHandle request) noexcept;
    bool IsResponseHandle(ResponseHandle response) noexcept;
    bool IsWebSocketHandle(WebSocketHandle websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveSessionHandle(_In_ SessionHandle session) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveRequestHandle(_In_ RequestHandle request) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveResponseHandle(_In_ ResponseHandle response) noexcept;

    _Must_inspect_result_
    NTSTATUS RegisterActiveWebSocketHandle(_In_ WebSocketHandle websocket) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveSessionHandle(_In_opt_ SessionHandle session) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveRequestHandle(_In_opt_ RequestHandle request) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveResponseHandle(_In_opt_ ResponseHandle response) noexcept;

    _Must_inspect_result_
    bool TryCloseActiveWebSocketHandle(_In_opt_ WebSocketHandle websocket) noexcept;

    _Must_inspect_result_
    bool SessionBeginOperation(_In_opt_ SessionHandle session) noexcept;

    void SessionEndOperation(_In_opt_ SessionHandle session) noexcept;

    _Must_inspect_result_
    bool RequestBeginOperation(_In_opt_ RequestHandle request) noexcept;

    void RequestEndOperation(_In_opt_ RequestHandle request) noexcept;

    _Must_inspect_result_
    bool ResponseBeginOperation(_In_opt_ ResponseHandle response) noexcept;

    void ResponseEndOperation(_In_opt_ ResponseHandle response) noexcept;

    _Must_inspect_result_
    bool WebSocketBeginOperation(_In_opt_ WebSocketHandle websocket) noexcept;

    void WebSocketEndOperation(_In_opt_ WebSocketHandle websocket) noexcept;

    class SessionOperationScope final
    {
    public:
        explicit SessionOperationScope(_In_opt_ SessionHandle session) noexcept :
            session_(session),
            active_(SessionBeginOperation(session))
        {
        }

        ~SessionOperationScope() noexcept
        {
            if (active_) {
                SessionEndOperation(session_);
            }
        }

        SessionOperationScope(const SessionOperationScope&) = delete;
        SessionOperationScope& operator=(const SessionOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        SessionHandle session_ = nullptr;
        bool active_ = false;
    };

    class RequestOperationScope final
    {
    public:
        explicit RequestOperationScope(_In_opt_ RequestHandle request) noexcept :
            request_(request),
            active_(RequestBeginOperation(request))
        {
        }

        ~RequestOperationScope() noexcept
        {
            if (active_) {
                RequestEndOperation(request_);
            }
        }

        RequestOperationScope(const RequestOperationScope&) = delete;
        RequestOperationScope& operator=(const RequestOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        RequestHandle request_ = nullptr;
        bool active_ = false;
    };

    class ResponseOperationScope final
    {
    public:
        explicit ResponseOperationScope(_In_opt_ ResponseHandle response) noexcept :
            response_(response),
            active_(ResponseBeginOperation(response))
        {
        }

        ~ResponseOperationScope() noexcept
        {
            if (active_) {
                ResponseEndOperation(response_);
            }
        }

        ResponseOperationScope(const ResponseOperationScope&) = delete;
        ResponseOperationScope& operator=(const ResponseOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        ResponseHandle response_ = nullptr;
        bool active_ = false;
    };

    void ReleaseRequestStorage(_Inout_ Request& request) noexcept;

    _Must_inspect_result_
    NTSTATUS CloneRequestForAsync(_In_ const Request& source, _Out_ RequestHandle* clonedRequest) noexcept;

    void ReleaseResponseStorage(_Inout_ Response& response) noexcept;
    void ReleaseWebSocketStorage(_Inout_ WebSocket& websocket) noexcept;

    _Must_inspect_result_
    NTSTATUS BuildHostHeaderValue(
        const Request& request,
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

    tls::TlsProtocol ToTlsProtocol(TlsVersion version) noexcept;
#endif
}
}
