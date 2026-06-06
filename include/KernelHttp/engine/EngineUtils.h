#pragma once

#include <KernelHttp/engine/HandleTypes.h>

namespace KernelHttp
{
namespace engine
{
#if defined(KERNEL_HTTP_USER_MODE_TEST)
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
    bool KhSessionBeginOperation(_In_opt_ KH_SESSION session) noexcept;

    void KhSessionEndOperation(_In_opt_ KH_SESSION session) noexcept;

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

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
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
