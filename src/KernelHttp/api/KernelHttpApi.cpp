#include "KernelHttpApi.h"
#include "api/KernelHttpAsync.h"
#include "api/KernelHttpConnectionPool.h"
#include "api/KernelHttpWorkspace.h"
#include "crypto/CngProviderCache.h"
#include "client/WebSocketClient.h"
#include "http/HttpParser.h"
#include "http/HttpRequest.h"
#include "net/WskSocket.h"
#include "tls/TlsConnection.h"
#include "websocket/WebSocketFrame.h"

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#else
#include <ws2ipdef.h>
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
    KhTestHttpTransportCallback g_testHttpTransport = nullptr;
    void* g_testHttpTransportContext = nullptr;
    KhTestWebSocketConnectCallback g_testWebSocketConnect = nullptr;
    KhTestWebSocketSendCallback g_testWebSocketSend = nullptr;
    KhTestWebSocketReceiveCallback g_testWebSocketReceive = nullptr;
    KhTestWebSocketCloseCallback g_testWebSocketClose = nullptr;
    void* g_testWebSocketTransportContext = nullptr;
#else
    constexpr ULONG PassiveLevel = PASSIVE_LEVEL;
#endif

    constexpr SIZE_T KhMaxHeadersPerRequest = 16;
    constexpr SIZE_T KhMaxHeadersPerResponse = 32;
    constexpr SIZE_T KhMaxHeaderNameLength = 128;
    constexpr SIZE_T KhMaxHeaderValueLength = 512;
    constexpr SIZE_T KhMaxSchemeLength = 5;
    constexpr SIZE_T KhMaxHostLength = KhPoolMaxHostLength;
    constexpr SIZE_T KhMaxPathLength = 2048;
    constexpr SIZE_T KhMaxServiceNameLength = 5;

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

        if (options.AlpnLength > KhPoolMaxAlpnLength) {
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
    void ReleaseResponseStorage(_Inout_ KhResponse& response) noexcept;

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

    _Ret_maybenull_
    void* AllocateApiMemory(SIZE_T length) noexcept
    {
        if (length == 0) {
            return nullptr;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return calloc(1, length);
#else
        return ExAllocatePool2(POOL_FLAG_NON_PAGED, length, PoolTag);
#endif
    }

    void FreeApiMemory(_In_opt_ void* data) noexcept
    {
        if (data == nullptr) {
            return;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(data);
#else
        ExFreePoolWithTag(data, PoolTag);
#endif
    }

    _Ret_maybenull_
    char* AllocateTextCopy(const char* text, SIZE_T length) noexcept
    {
        if (text == nullptr || length == 0) {
            return nullptr;
        }

        char* copy = static_cast<char*>(AllocateApiMemory(length + 1));
        if (copy == nullptr) {
            return nullptr;
        }

        RtlCopyMemory(copy, text, length);
        copy[length] = '\0';
        return copy;
    }

    _Ret_maybenull_
    UCHAR* AllocateBytesCopy(const UCHAR* data, SIZE_T length) noexcept
    {
        if (length == 0) {
            return nullptr;
        }

        if (data == nullptr) {
            return nullptr;
        }

        UCHAR* copy = static_cast<UCHAR*>(AllocateApiMemory(length));
        if (copy == nullptr) {
            return nullptr;
        }

        RtlCopyMemory(copy, data, length);
        return copy;
    }

    char ToLowerAscii(char value) noexcept
    {
        return (value >= 'A' && value <= 'Z') ? static_cast<char>(value + ('a' - 'A')) : value;
    }

    bool TextEqualsIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right,
        SIZE_T rightLength) noexcept
    {
        if (leftLength != rightLength) {
            return false;
        }

        if (leftLength == 0) {
            return true;
        }

        if (left == nullptr || right == nullptr) {
            return false;
        }

        for (SIZE_T index = 0; index < leftLength; ++index) {
            if (ToLowerAscii(left[index]) != ToLowerAscii(right[index])) {
                return false;
            }
        }

        return true;
    }

    bool TextEqualsLiteralIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept
    {
        return TextEqualsIgnoreCase(left, leftLength, right, http::MakeText(right).Length);
    }

    bool IsDigit(char value) noexcept
    {
        return value >= '0' && value <= '9';
    }

    bool IsDefaultPort(const char* scheme, SIZE_T schemeLength, USHORT port) noexcept
    {
        return ((TextEqualsLiteralIgnoreCase(scheme, schemeLength, "http") ||
            TextEqualsLiteralIgnoreCase(scheme, schemeLength, "ws")) && port == 80) ||
            ((TextEqualsLiteralIgnoreCase(scheme, schemeLength, "https") ||
                TextEqualsLiteralIgnoreCase(scheme, schemeLength, "wss")) && port == 443);
    }

    _Must_inspect_result_
    NTSTATUS CopyLowerText(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (source == nullptr ||
            sourceLength == 0 ||
            destination == nullptr ||
            destinationLength == nullptr ||
            sourceLength >= destinationCapacity) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < sourceLength; ++index) {
            destination[index] = ToLowerAscii(source[index]);
        }
        destination[sourceLength] = '\0';
        *destinationLength = sourceLength;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS CopyExactText(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (source == nullptr ||
            sourceLength == 0 ||
            destination == nullptr ||
            destinationLength == nullptr ||
            sourceLength >= destinationCapacity) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(destination, source, sourceLength);
        destination[sourceLength] = '\0';
        *destinationLength = sourceLength;
        return STATUS_SUCCESS;
    }

    bool IsSessionHandle(KH_SESSION session) noexcept;
    bool IsRequestHandle(KH_REQUEST request) noexcept;
    bool IsResponseHandle(KH_RESPONSE response) noexcept;
    bool IsWebSocketHandle(KH_WEBSOCKET websocket) noexcept;
}

    struct KhSession
    {
        KhHandleHeader Header = { KhHandleKind::Session, false };
        net::WskClient* WskClient = nullptr;
        KhSessionOptions Options = {};
        KhWorkspace* Workspace = nullptr;
        crypto::CngProviderCache* ProviderCache = nullptr;
        KhConnectionPool ConnectionPool = {};
    };

    struct KhStoredHeader
    {
        char* Name = nullptr;
        SIZE_T NameLength = 0;
        char* Value = nullptr;
        SIZE_T ValueLength = 0;
    };

    struct KhRequest
    {
        KhHandleHeader Header = { KhHandleKind::Request, false };
        KH_SESSION Session = nullptr;
        KhHttpMethod Method = KhHttpMethod::Get;
        char* Url = nullptr;
        SIZE_T UrlLength = 0;
        char Scheme[KhMaxSchemeLength + 1] = {};
        SIZE_T SchemeLength = 0;
        char Host[KhMaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        char Path[KhMaxPathLength + 1] = {};
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        KhStoredHeader Headers[KhMaxHeadersPerRequest] = {};
        SIZE_T HeaderCount = 0;
        KhTlsOptions Tls = {};
        bool HasTlsOverride = false;
        KhConnectionPolicy ConnectionPolicy = KhConnectionPolicy::ReuseOrCreate;
    };

    struct KhResponse
    {
        KhHandleHeader Header = { KhHandleKind::Response, false };
        ULONG StatusCode = 0;
        UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        char* HeaderNameStorage = nullptr;
        SIZE_T HeaderNameStorageLength = 0;
        char* HeaderValueStorage = nullptr;
        SIZE_T HeaderValueStorageLength = 0;
    };

    struct KhWebSocket
    {
        KhHandleHeader Header = { KhHandleKind::WebSocket, false };
        KH_SESSION Session = nullptr;
        char* Url = nullptr;
        SIZE_T UrlLength = 0;
        char Scheme[KhMaxSchemeLength + 1] = {};
        SIZE_T SchemeLength = 0;
        char Host[KhMaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        char Path[KhMaxPathLength + 1] = {};
        SIZE_T PathLength = 0;
        USHORT Port = 0;
        char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        UCHAR* LastMessage = nullptr;
        SIZE_T LastMessageLength = 0;
        KhWebSocketMessageType LastMessageType = KhWebSocketMessageType::Binary;
        SIZE_T MaxMessageBytes = KhDefaultMaxResponseBytes;
        bool AutoReplyPing = true;
        bool Connected = false;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        client::WebSocketClient* Client = nullptr;
#endif
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

    void ReleaseStoredHeader(_Inout_ KhStoredHeader& header) noexcept
    {
        FreeApiMemory(header.Name);
        FreeApiMemory(header.Value);
        header = {};
    }

    void ReleaseRequestStorage(_Inout_ KhRequest& request) noexcept
    {
        FreeApiMemory(request.Url);
        request.Url = nullptr;
        request.UrlLength = 0;
        request.SchemeLength = 0;
        request.HostLength = 0;
        request.PathLength = 0;
        request.Port = 0;

        for (SIZE_T index = 0; index < request.HeaderCount && index < KhMaxHeadersPerRequest; ++index) {
            ReleaseStoredHeader(request.Headers[index]);
        }
        request.HeaderCount = 0;
    }

    void ReleaseResponseStorage(KhResponse& response) noexcept
    {
        FreeApiMemory(response.RawResponse);
        FreeApiMemory(response.Body);
        FreeApiMemory(response.Headers);
        FreeApiMemory(response.HeaderNameStorage);
        FreeApiMemory(response.HeaderValueStorage);
        response.RawResponse = nullptr;
        response.RawResponseLength = 0;
        response.Body = nullptr;
        response.BodyLength = 0;
        response.Headers = nullptr;
        response.HeaderCount = 0;
        response.HeaderNameStorage = nullptr;
        response.HeaderNameStorageLength = 0;
        response.HeaderValueStorage = nullptr;
        response.HeaderValueStorageLength = 0;
        response.StatusCode = 0;
    }

    void ReleaseWebSocketStorage(_Inout_ KhWebSocket& websocket) noexcept
    {
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        if (websocket.Client != nullptr) {
            delete websocket.Client;
            websocket.Client = nullptr;
        }
#endif
        FreeApiMemory(websocket.Url);
        FreeApiMemory(websocket.Subprotocol);
        FreeApiMemory(websocket.LastMessage);
        websocket.Url = nullptr;
        websocket.UrlLength = 0;
        websocket.Subprotocol = nullptr;
        websocket.SubprotocolLength = 0;
        websocket.LastMessage = nullptr;
        websocket.LastMessageLength = 0;
        websocket.SchemeLength = 0;
        websocket.HostLength = 0;
        websocket.PathLength = 0;
        websocket.Port = 0;
        websocket.Connected = false;
    }

    _Must_inspect_result_
    NTSTATUS ParsePort(
        const char* text,
        SIZE_T textLength,
        _Out_ USHORT* port) noexcept
    {
        if (port != nullptr) {
            *port = 0;
        }

        if (text == nullptr || textLength == 0 || port == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG value = 0;
        for (SIZE_T index = 0; index < textLength; ++index) {
            if (!IsDigit(text[index])) {
                return STATUS_INVALID_PARAMETER;
            }

            value = (value * 10) + static_cast<ULONG>(text[index] - '0');
            if (value > 0xffff) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        if (value == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        *port = static_cast<USHORT>(value);
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseUrlIntoRequest(
        _Inout_ KhRequest& request,
        const char* url,
        SIZE_T urlLength) noexcept
    {
        if (url == nullptr || urlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T schemeEnd = 0;
        while (schemeEnd < urlLength && url[schemeEnd] != ':') {
            ++schemeEnd;
        }

        if (schemeEnd == 0 ||
            schemeEnd + 3 > urlLength ||
            url[schemeEnd + 1] != '/' ||
            url[schemeEnd + 2] != '/') {
            return STATUS_INVALID_PARAMETER;
        }

        if (!TextEqualsLiteralIgnoreCase(url, schemeEnd, "http") &&
            !TextEqualsLiteralIgnoreCase(url, schemeEnd, "https")) {
            return STATUS_NOT_SUPPORTED;
        }

        const SIZE_T authorityStart = schemeEnd + 3;
        SIZE_T authorityEnd = authorityStart;
        while (authorityEnd < urlLength && url[authorityEnd] != '/' && url[authorityEnd] != '?' && url[authorityEnd] != '#') {
            ++authorityEnd;
        }

        if (authorityEnd == authorityStart) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T hostStart = authorityStart;
        SIZE_T hostLength = authorityEnd - authorityStart;
        SIZE_T portStart = 0;
        SIZE_T portLength = 0;

        for (SIZE_T index = authorityStart; index < authorityEnd; ++index) {
            if (url[index] == ':') {
                if (portStart != 0) {
                    return STATUS_NOT_SUPPORTED;
                }

                portStart = index + 1;
                hostLength = index - authorityStart;
            }
        }

        if (hostLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        USHORT port = TextEqualsLiteralIgnoreCase(url, schemeEnd, "https") ? 443 : 80;
        if (portStart != 0) {
            portLength = authorityEnd - portStart;
            NTSTATUS status = ParsePort(url + portStart, portLength, &port);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        SIZE_T fragmentStart = authorityEnd;
        while (fragmentStart < urlLength && url[fragmentStart] != '#') {
            ++fragmentStart;
        }

        SIZE_T pathStart = authorityEnd;
        SIZE_T pathLength = fragmentStart - authorityEnd;
        if (pathLength == 0) {
            pathStart = 0;
            pathLength = 1;
        }

        if (pathStart == 0) {
            request.Path[0] = '/';
            request.Path[1] = '\0';
            request.PathLength = 1;
        }
        else {
            const bool queryOnly = url[pathStart] == '?';
            const SIZE_T requestTargetLength = pathLength + (queryOnly ? 1 : 0);
            if (requestTargetLength > KhMaxPathLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T outputOffset = 0;
            if (queryOnly) {
                request.Path[outputOffset++] = '/';
            }

            RtlCopyMemory(request.Path + outputOffset, url + pathStart, pathLength);
            request.Path[requestTargetLength] = '\0';
            request.PathLength = requestTargetLength;
        }

        NTSTATUS status = CopyLowerText(
            url,
            schemeEnd,
            request.Scheme,
            sizeof(request.Scheme),
            &request.SchemeLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        hostStart = authorityStart;
        status = CopyLowerText(
            url + hostStart,
            hostLength,
            request.Host,
            sizeof(request.Host),
            &request.HostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        request.Port = port;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseUrlParts(
        const char* url,
        SIZE_T urlLength,
        bool websocketUrl,
        _Out_writes_bytes_(schemeCapacity) char* scheme,
        SIZE_T schemeCapacity,
        _Out_ SIZE_T* schemeLength,
        _Out_writes_bytes_(hostCapacity) char* host,
        SIZE_T hostCapacity,
        _Out_ SIZE_T* hostLength,
        _Out_writes_bytes_(pathCapacity) char* path,
        SIZE_T pathCapacity,
        _Out_ SIZE_T* pathLength,
        _Out_ USHORT* port) noexcept
    {
        if (schemeLength != nullptr) {
            *schemeLength = 0;
        }
        if (hostLength != nullptr) {
            *hostLength = 0;
        }
        if (pathLength != nullptr) {
            *pathLength = 0;
        }
        if (port != nullptr) {
            *port = 0;
        }

        if (url == nullptr ||
            urlLength == 0 ||
            scheme == nullptr ||
            schemeLength == nullptr ||
            host == nullptr ||
            hostLength == nullptr ||
            path == nullptr ||
            pathLength == nullptr ||
            port == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T schemeEnd = 0;
        while (schemeEnd < urlLength && url[schemeEnd] != ':') {
            ++schemeEnd;
        }

        if (schemeEnd == 0 ||
            schemeEnd + 3 > urlLength ||
            url[schemeEnd + 1] != '/' ||
            url[schemeEnd + 2] != '/') {
            return STATUS_INVALID_PARAMETER;
        }

        const bool supported =
            websocketUrl ?
            (TextEqualsLiteralIgnoreCase(url, schemeEnd, "ws") ||
                TextEqualsLiteralIgnoreCase(url, schemeEnd, "wss")) :
            (TextEqualsLiteralIgnoreCase(url, schemeEnd, "http") ||
                TextEqualsLiteralIgnoreCase(url, schemeEnd, "https"));
        if (!supported) {
            return STATUS_NOT_SUPPORTED;
        }

        const SIZE_T authorityStart = schemeEnd + 3;
        SIZE_T authorityEnd = authorityStart;
        while (authorityEnd < urlLength && url[authorityEnd] != '/' && url[authorityEnd] != '?' && url[authorityEnd] != '#') {
            ++authorityEnd;
        }

        if (authorityEnd == authorityStart) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T parsedHostLength = authorityEnd - authorityStart;
        SIZE_T portStart = 0;
        for (SIZE_T index = authorityStart; index < authorityEnd; ++index) {
            if (url[index] == ':') {
                if (portStart != 0) {
                    return STATUS_NOT_SUPPORTED;
                }

                portStart = index + 1;
                parsedHostLength = index - authorityStart;
            }
        }

        if (parsedHostLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        USHORT parsedPort =
            (TextEqualsLiteralIgnoreCase(url, schemeEnd, "https") ||
                TextEqualsLiteralIgnoreCase(url, schemeEnd, "wss")) ? 443 : 80;
        if (portStart != 0) {
            NTSTATUS status = ParsePort(url + portStart, authorityEnd - portStart, &parsedPort);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        SIZE_T fragmentStart = authorityEnd;
        while (fragmentStart < urlLength && url[fragmentStart] != '#') {
            ++fragmentStart;
        }

        SIZE_T targetStart = authorityEnd;
        SIZE_T targetLength = fragmentStart - authorityEnd;
        if (targetLength == 0) {
            if (pathCapacity < 2) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            path[0] = '/';
            path[1] = '\0';
            *pathLength = 1;
        }
        else {
            const bool queryOnly = url[targetStart] == '?';
            const SIZE_T requestTargetLength = targetLength + (queryOnly ? 1 : 0);
            if (requestTargetLength >= pathCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T outputOffset = 0;
            if (queryOnly) {
                path[outputOffset++] = '/';
            }

            RtlCopyMemory(path + outputOffset, url + targetStart, targetLength);
            path[requestTargetLength] = '\0';
            *pathLength = requestTargetLength;
        }

        NTSTATUS status = CopyLowerText(url, schemeEnd, scheme, schemeCapacity, schemeLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = CopyLowerText(
            url + authorityStart,
            parsedHostLength,
            host,
            hostCapacity,
            hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *port = parsedPort;
        return STATUS_SUCCESS;
    }

    http::HttpMethod ToHttpMethod(KhHttpMethod method) noexcept
    {
        switch (method) {
        case KhHttpMethod::Post:
            return http::HttpMethod::Post;
        case KhHttpMethod::Put:
            return http::HttpMethod::Put;
        case KhHttpMethod::Patch:
            return http::HttpMethod::Patch;
        case KhHttpMethod::Delete:
            return http::HttpMethod::DeleteMethod;
        case KhHttpMethod::Head:
            return http::HttpMethod::Head;
        case KhHttpMethod::Get:
        default:
            return http::HttpMethod::Get;
        }
    }

    _Must_inspect_result_
    NTSTATUS BuildHostHeaderValue(
        const KhRequest& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (destination == nullptr ||
            destinationCapacity == 0 ||
            destinationLength == nullptr ||
            request.HostLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request.HostLength >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(destination, request.Host, request.HostLength);
        SIZE_T length = request.HostLength;

        if (!IsDefaultPort(request.Scheme, request.SchemeLength, request.Port)) {
            if (length + 1 >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[length++] = ':';

            char digits[6] = {};
            SIZE_T digitCount = 0;
            USHORT port = request.Port;
            do {
                digits[digitCount++] = static_cast<char>('0' + (port % 10));
                port = static_cast<USHORT>(port / 10);
            } while (port != 0);

            if (length + digitCount >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            for (SIZE_T index = 0; index < digitCount; ++index) {
                destination[length + index] = digits[digitCount - 1 - index];
            }
            length += digitCount;
        }

        destination[length] = '\0';
        *destinationLength = length;
        return STATUS_SUCCESS;
    }

    bool HeaderNameEquals(const KhStoredHeader& header, const char* name) noexcept
    {
        return TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, name);
    }

    _Must_inspect_result_
    NTSTATUS BuildHttpRequestOptions(
        const KhRequest& request,
        _Out_writes_bytes_(hostCapacity) char* host,
        SIZE_T hostCapacity,
        _Out_ http::HttpHeader* headers,
        SIZE_T headerCapacity,
        _Out_ http::HttpRequestBuildOptions* options) noexcept
    {
        if (host == nullptr || headers == nullptr || options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(headers, sizeof(http::HttpHeader) * headerCapacity);
        RtlZeroMemory(options, sizeof(*options));

        SIZE_T hostLength = 0;
        NTSTATUS status = BuildHostHeaderValue(request, host, hostCapacity, &hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T extraHeaderCount = 0;
        for (SIZE_T index = 0; index < request.HeaderCount; ++index) {
            const KhStoredHeader& header = request.Headers[index];
            if (HeaderNameEquals(header, "Host") ||
                HeaderNameEquals(header, "Content-Length") ||
                HeaderNameEquals(header, "Connection")) {
                continue;
            }

            if (extraHeaderCount >= headerCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            headers[extraHeaderCount].Name = { header.Name, header.NameLength };
            headers[extraHeaderCount].Value = { header.Value, header.ValueLength };
            ++extraHeaderCount;
        }

        options->Method = ToHttpMethod(request.Method);
        options->Path = { request.Path, request.PathLength };
        options->Host = { host, hostLength };
        options->Connection = request.ConnectionPolicy == KhConnectionPolicy::NoPool ?
            http::HttpConnectionDirective::Close :
            http::HttpConnectionDirective::KeepAlive;
        options->ExtraHeaders = headers;
        options->ExtraHeaderCount = extraHeaderCount;
        options->Body = reinterpret_cast<const char*>(request.Body);
        options->BodyLength = request.BodyLength;
        options->IncludeContentLength = request.BodyLength > 0;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BuildPoolKey(const KhRequest& request, _Out_ KhConnectionPoolKey* key) noexcept
    {
        if (key == nullptr || request.SchemeLength == 0 || request.HostLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(key, sizeof(*key));
        NTSTATUS status = CopyExactText(
            request.Scheme,
            request.SchemeLength,
            key->Scheme,
            sizeof(key->Scheme),
            &key->SchemeLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = CopyExactText(
            request.Host,
            request.HostLength,
            key->Host,
            sizeof(key->Host),
            &key->HostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        key->Port = request.Port;
        key->MinTlsVersion = request.Tls.MinVersion;
        key->MaxTlsVersion = request.Tls.MaxVersion;
        key->CertificatePolicy = request.Tls.CertificatePolicy;
        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            status = CopyExactText(
                request.Tls.Alpn,
                request.Tls.AlpnLength,
                key->Alpn,
                sizeof(key->Alpn),
                &key->AlpnLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS CreateOwnedResponse(
        const http::HttpResponse& parsed,
        const char* rawResponse,
        SIZE_T rawResponseLength,
        _Out_ KH_RESPONSE* response) noexcept
    {
        if (response != nullptr) {
            *response = nullptr;
        }

        if (response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        KH_RESPONSE newResponse = AllocateHandle<KhResponse>();
        if (newResponse == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newResponse->Header = { KhHandleKind::Response, false };
        newResponse->StatusCode = parsed.StatusCode;

        if (rawResponse != nullptr && rawResponseLength != 0) {
            newResponse->RawResponse = AllocateTextCopy(rawResponse, rawResponseLength);
            if (newResponse->RawResponse == nullptr) {
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newResponse->RawResponseLength = rawResponseLength;
        }

        if (parsed.Body != nullptr && parsed.BodyLength != 0) {
            newResponse->Body = AllocateBytesCopy(
                reinterpret_cast<const UCHAR*>(parsed.Body),
                parsed.BodyLength);
            if (newResponse->Body == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newResponse->BodyLength = parsed.BodyLength;
        }

        if (parsed.HeaderCount != 0) {
            newResponse->Headers = static_cast<http::HttpHeader*>(
                AllocateApiMemory(sizeof(http::HttpHeader) * parsed.HeaderCount));
            if (newResponse->Headers == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T nameStorageLength = 0;
            SIZE_T valueStorageLength = 0;
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                nameStorageLength += parsed.Headers[index].Name.Length;
                valueStorageLength += parsed.Headers[index].Value.Length;
            }

            if (nameStorageLength != 0) {
                newResponse->HeaderNameStorage = static_cast<char*>(AllocateApiMemory(nameStorageLength));
                if (newResponse->HeaderNameStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->HeaderNameStorageLength = nameStorageLength;
            }

            if (valueStorageLength != 0) {
                newResponse->HeaderValueStorage = static_cast<char*>(AllocateApiMemory(valueStorageLength));
                if (newResponse->HeaderValueStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->HeaderValueStorageLength = valueStorageLength;
            }

            SIZE_T nameOffset = 0;
            SIZE_T valueOffset = 0;
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                const http::HttpHeader& source = parsed.Headers[index];
                if (source.Name.Length != 0) {
                    RtlCopyMemory(
                        newResponse->HeaderNameStorage + nameOffset,
                        source.Name.Data,
                        source.Name.Length);
                    newResponse->Headers[index].Name.Data = newResponse->HeaderNameStorage + nameOffset;
                    newResponse->Headers[index].Name.Length = source.Name.Length;
                    nameOffset += source.Name.Length;
                }

                if (source.Value.Length != 0) {
                    RtlCopyMemory(
                        newResponse->HeaderValueStorage + valueOffset,
                        source.Value.Data,
                        source.Value.Length);
                    newResponse->Headers[index].Value.Data = newResponse->HeaderValueStorage + valueOffset;
                    newResponse->Headers[index].Value.Length = source.Value.Length;
                    valueOffset += source.Value.Length;
                }
            }
            newResponse->HeaderCount = parsed.HeaderCount;
        }

        *response = newResponse;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS InvokeResponseCallbacks(
        const KhHttpSendOptions& options,
        const http::HttpResponse& parsed) noexcept
    {
        if (options.HeaderCallback != nullptr) {
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                const http::HttpHeader& header = parsed.Headers[index];
                NTSTATUS status = options.HeaderCallback(
                    options.CallbackContext,
                    header.Name.Data,
                    header.Name.Length,
                    header.Value.Data,
                    header.Value.Length);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }

        if (options.BodyCallback != nullptr) {
            return options.BodyCallback(
                options.CallbackContext,
                reinterpret_cast<const UCHAR*>(parsed.Body),
                parsed.BodyLength,
                true);
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseResponseBytes(
        KhWorkspace& workspace,
        SIZE_T responseLength,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* headers,
        SIZE_T headerCapacity) noexcept
    {
        if (parsed == nullptr || headers == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        http::HttpParseOptions parseOptions = {};
        parseOptions.Headers = headers;
        parseOptions.HeaderCapacity = headerCapacity;
        parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
        parseOptions.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
        parseOptions.ScratchBodyCapacity = workspace.Request.Length;
        parseOptions.MessageCompleteOnConnectionClose = true;

        return http::HttpParser::ParseResponse(
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseLength,
            parseOptions,
            *parsed);
    }

    _Must_inspect_result_
    NTSTATUS BuildRequestBytes(
        const KhRequest& request,
        _Inout_ KhWorkspace& workspace,
        _Out_writes_(headerCapacity) http::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* requestLength) noexcept
    {
        if (requestLength != nullptr) {
            *requestLength = 0;
        }

        if (requestLength == nullptr || requestHeaders == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        char hostHeader[KhMaxHostLength + 8] = {};
        http::HttpRequestBuildOptions buildOptions = {};
        NTSTATUS status = BuildHttpRequestOptions(
            request,
            hostHeader,
            sizeof(hostHeader),
            requestHeaders,
            headerCapacity,
            &buildOptions);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return http::HttpRequestBuilder::Build(
            buildOptions,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            requestLength);
    }

    _Must_inspect_result_
    NTSTATUS BuildWebSocketHandshakeRequest(
        const KhWebSocket& websocket,
        _Inout_ KhWorkspace& workspace,
        _Out_ SIZE_T* requestLength) noexcept
    {
        if (requestLength != nullptr) {
            *requestLength = 0;
        }

        if (requestLength == nullptr || websocket.HostLength == 0 || websocket.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        char hostHeader[KhMaxHostLength + 8] = {};
        SIZE_T hostLength = 0;
        KhRequest hostRequest = {};
        RtlCopyMemory(hostRequest.Scheme, websocket.Scheme, sizeof(hostRequest.Scheme));
        hostRequest.SchemeLength = websocket.SchemeLength;
        RtlCopyMemory(hostRequest.Host, websocket.Host, sizeof(hostRequest.Host));
        hostRequest.HostLength = websocket.HostLength;
        hostRequest.Port = websocket.Port;
        NTSTATUS status = BuildHostHeaderValue(hostRequest, hostHeader, sizeof(hostHeader), &hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        char clientKey[websocket::WebSocketClientKeyBase64Length] = {};
        SIZE_T clientKeyLength = 0;
        status = websocket::WebSocketCodec::GenerateClientKey(
            clientKey,
            sizeof(clientKey),
            &clientKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http::HttpHeader headers[5] = {};
        SIZE_T headerCount = 0;
        headers[headerCount++] = { http::MakeText("Upgrade"), http::MakeText("websocket") };
        headers[headerCount++] = { http::MakeText("Connection"), http::MakeText("Upgrade") };
        headers[headerCount++] = { http::MakeText("Sec-WebSocket-Key"), { clientKey, clientKeyLength } };
        headers[headerCount++] = { http::MakeText("Sec-WebSocket-Version"), http::MakeText("13") };
        if (websocket.Subprotocol != nullptr && websocket.SubprotocolLength != 0) {
            headers[headerCount++] = {
                http::MakeText("Sec-WebSocket-Protocol"),
                { websocket.Subprotocol, websocket.SubprotocolLength }
            };
        }

        http::HttpRequestBuildOptions buildOptions = {};
        buildOptions.Method = http::HttpMethod::Get;
        buildOptions.Path = { websocket.Path, websocket.PathLength };
        buildOptions.Host = { hostHeader, hostLength };
        buildOptions.Connection = http::HttpConnectionDirective::KeepAlive;
        buildOptions.ExtraHeaders = headers;
        buildOptions.ExtraHeaderCount = headerCount;

        return http::HttpRequestBuilder::Build(
            buildOptions,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            requestLength);
    }

    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocket(
        _Inout_ net::WskSocket& socket,
        _Inout_opt_ tls::TlsConnection* tls,
        _Inout_ KhWorkspace& workspace,
        bool responseBodyForbidden,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr || responseHeaders == nullptr || rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *rawResponseLength = 0;
        SIZE_T responseLength = 0;

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = responseHeaders;
            parseOptions.HeaderCapacity = headerCapacity;
            parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
            parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
            parseOptions.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
            parseOptions.ScratchBodyCapacity = workspace.Request.Length;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;

            NTSTATUS status = http::HttpParser::ParseResponse(
                reinterpret_cast<const char*>(workspace.Response.Data),
                responseLength,
                parseOptions,
                *parsed);
            if (status == STATUS_SUCCESS) {
                *rawResponseLength = responseLength;
                return STATUS_SUCCESS;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }

            if (responseLength >= workspace.MaxResponseBytes) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            status = KhWorkspaceEnsureResponseCapacity(&workspace, responseLength + 1);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T received = 0;
            if (tls != nullptr) {
                status = tls->Receive(
                    socket,
                    workspace.Response.Data + responseLength,
                    workspace.Response.Length - responseLength,
                    &received);
            }
            else {
                status = socket.Receive(
                    workspace.Response.Data + responseLength,
                    workspace.Response.Length - responseLength,
                    &received);
            }

            if (!NT_SUCCESS(status)) {
                if (status != STATUS_CONNECTION_DISCONNECTED) {
                    return status;
                }

                parseOptions.MessageCompleteOnConnectionClose = true;
                status = http::HttpParser::ParseResponse(
                    reinterpret_cast<const char*>(workspace.Response.Data),
                    responseLength,
                    parseOptions,
                    *parsed);
                if (NT_SUCCESS(status)) {
                    *rawResponseLength = responseLength;
                }
                return status;
            }

            if (received == 0) {
                parseOptions.MessageCompleteOnConnectionClose = true;
                status = http::HttpParser::ParseResponse(
                    reinterpret_cast<const char*>(workspace.Response.Data),
                    responseLength,
                    parseOptions,
                    *parsed);
                if (NT_SUCCESS(status)) {
                    *rawResponseLength = responseLength;
                }
                return status;
            }

            responseLength += received;
            workspace.ResponseLength = responseLength;
        }
    }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS CopyAsciiToWide(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept
    {
        if (source == nullptr ||
            sourceLength == 0 ||
            destination == nullptr ||
            sourceLength >= destinationCapacity) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < sourceLength; ++index) {
            destination[index] = static_cast<unsigned char>(source[index]);
        }
        destination[sourceLength] = L'\0';
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS FormatServiceName(
        USHORT port,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept
    {
        if (port == 0 || destination == nullptr || destinationCapacity < 2) {
            return STATUS_INVALID_PARAMETER;
        }

        wchar_t digits[KhMaxServiceNameLength + 1] = {};
        SIZE_T digitCount = 0;
        USHORT value = port;
        do {
            digits[digitCount++] = static_cast<wchar_t>(L'0' + (value % 10));
            value = static_cast<USHORT>(value / 10);
        } while (value != 0);

        if (digitCount >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        for (SIZE_T index = 0; index < digitCount; ++index) {
            destination[index] = digits[digitCount - 1 - index];
        }
        destination[digitCount] = L'\0';
        return STATUS_SUCCESS;
    }

    tls::TlsProtocol ToTlsProtocol(KhTlsVersion version) noexcept
    {
        return version == KhTlsVersion::Tls13 ? tls::TlsProtocol::Tls13 : tls::TlsProtocol::Tls12;
    }

    _Must_inspect_result_
    NTSTATUS EnsureSocketConnected(
        _In_ KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhPooledConnection& connection) noexcept
    {
        if (session == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (connection.Socket != nullptr && connection.Socket->IsConnected()) {
            return STATUS_SUCCESS;
        }

        if (connection.Socket != nullptr) {
            delete connection.Socket;
            connection.Socket = nullptr;
        }

        auto* socket = new net::WskSocket();
        if (socket == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        wchar_t serverName[KhMaxHostLength + 1] = {};
        wchar_t serviceName[KhMaxServiceNameLength + 1] = {};
        NTSTATUS status = CopyAsciiToWide(request.Host, request.HostLength, serverName, RTL_NUMBER_OF(serverName));
        if (NT_SUCCESS(status)) {
            status = FormatServiceName(request.Port, serviceName, RTL_NUMBER_OF(serviceName));
        }

        SOCKADDR_STORAGE remoteAddress = {};
        if (NT_SUCCESS(status)) {
            status = session->WskClient->Resolve(serverName, serviceName, &remoteAddress);
        }

        if (NT_SUCCESS(status)) {
            status = socket->Connect(*session->WskClient, reinterpret_cast<const SOCKADDR*>(&remoteAddress));
        }

        if (!NT_SUCCESS(status)) {
            delete socket;
            return status;
        }

        connection.Socket = socket;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS EnsureTlsConnected(
        _In_ KH_SESSION session,
        const KhRequest& request,
        _Inout_ KhPooledConnection& connection,
        _In_reads_bytes_(earlyDataLength) const UCHAR* earlyData,
        SIZE_T earlyDataLength) noexcept
    {
        if (session == nullptr || connection.Socket == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (connection.Tls != nullptr && connection.Tls->IsEstablished()) {
            return STATUS_SUCCESS;
        }

        if (connection.Tls != nullptr) {
            delete connection.Tls;
            connection.Tls = nullptr;
        }

        auto* tlsConnection = new tls::TlsConnection();
        if (tlsConnection == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tls::TlsAlpnProtocol alpn = {};
        tls::TlsClientConnectionOptions tlsOptions = {};
        tlsOptions.ServerName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        tlsOptions.ServerNameLength = request.Tls.ServerName != nullptr ?
            request.Tls.ServerNameLength :
            request.HostLength;
        tlsOptions.CertificateStore = request.Tls.CertificateStore;
        tlsOptions.VerifyCertificate = request.Tls.CertificatePolicy == KhCertificatePolicy::Verify;
        tlsOptions.MinimumProtocol = ToTlsProtocol(request.Tls.MinVersion);
        tlsOptions.MaximumProtocol = ToTlsProtocol(request.Tls.MaxVersion);
        tlsOptions.Workspace = session->Workspace;
        tlsOptions.ProviderCache = session->ProviderCache;
        tlsOptions.EnableSessionResumption = true;

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            alpn.Name = request.Tls.Alpn;
            alpn.NameLength = request.Tls.AlpnLength;
            tlsOptions.AlpnProtocols = &alpn;
            tlsOptions.AlpnProtocolCount = 1;
        }

        if (earlyData != nullptr && earlyDataLength != 0) {
            tlsOptions.EarlyData = earlyData;
            tlsOptions.EarlyDataLength = earlyDataLength;
            tlsOptions.EnableEarlyData = true;
        }

        NTSTATUS status = tlsConnection->Connect(*connection.Socket, tlsOptions);
        if (!NT_SUCCESS(status)) {
            delete tlsConnection;
            return status;
        }

        connection.Tls = tlsConnection;
        return STATUS_SUCCESS;
    }
#endif

    _Must_inspect_result_
    NTSTATUS SendViaTransport(
        KH_SESSION session,
        const KhRequest& request,
        KhWorkspace& workspace,
        KhPooledConnection* pooledConnection,
        bool reusedConnection,
        SIZE_T builtRequestLength,
        _Out_ http::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength,
        _Out_ bool* connectionReusable) noexcept
    {
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (connectionReusable != nullptr) {
            *connectionReusable = false;
        }

        if (session == nullptr ||
            parsed == nullptr ||
            responseHeaders == nullptr ||
            rawResponseLength == nullptr ||
            connectionReusable == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testHttpTransport == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        KhTestHttpTransportRequest testRequest = {};
        testRequest.Scheme = request.Scheme;
        testRequest.SchemeLength = request.SchemeLength;
        testRequest.Host = request.Host;
        testRequest.HostLength = request.HostLength;
        testRequest.Port = request.Port;
        testRequest.BuiltRequest = reinterpret_cast<const char*>(workspace.Request.Data);
        testRequest.BuiltRequestLength = builtRequestLength;
        testRequest.ConnectionPolicy = request.ConnectionPolicy;
        testRequest.PoolableConnection = request.ConnectionPolicy != KhConnectionPolicy::NoPool;
        testRequest.ReusedConnection = reusedConnection;
        testRequest.ConnectionId = pooledConnection != nullptr ? pooledConnection->Id : 0;

        KhTestHttpTransportResponse testResponse = {};
        NTSTATUS status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (testResponse.RawResponse == nullptr || testResponse.RawResponseLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = KhWorkspaceEnsureResponseCapacity(&workspace, testResponse.RawResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlCopyMemory(workspace.Response.Data, testResponse.RawResponse, testResponse.RawResponseLength);
        workspace.ResponseLength = testResponse.RawResponseLength;

        status = ParseResponseBytes(workspace, workspace.ResponseLength, parsed, responseHeaders, headerCapacity);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *rawResponseLength = workspace.ResponseLength;
        *connectionReusable = testResponse.ConnectionReusable && !parsed->HasConnectionClose();
        return STATUS_SUCCESS;
#else
        UNREFERENCED_PARAMETER(reusedConnection);

        if (pooledConnection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https")) {
            if (request.Tls.CertificatePolicy == KhCertificatePolicy::Verify &&
                request.Tls.CertificateStore == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        else if (!TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "http")) {
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS status = EnsureSocketConnected(session, request, *pooledConnection);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        tls::TlsConnection* tlsConnection = nullptr;
        if (TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https")) {
            status = EnsureTlsConnected(
                session,
                request,
                *pooledConnection,
                reinterpret_cast<const UCHAR*>(workspace.Request.Data),
                builtRequestLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            tlsConnection = pooledConnection->Tls;
        }

        SIZE_T sent = 0;
        if (tlsConnection != nullptr) {
            status = tlsConnection->Send(
                *pooledConnection->Socket,
                workspace.Request.Data,
                builtRequestLength,
                &sent);
        }
        else {
            status = pooledConnection->Socket->Send(workspace.Request.Data, builtRequestLength, &sent);
        }

        if (NT_SUCCESS(status) && sent != builtRequestLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadHttpResponseFromSocket(
            *pooledConnection->Socket,
            tlsConnection,
            workspace,
            request.Method == KhHttpMethod::Head,
            parsed,
            responseHeaders,
            headerCapacity,
            rawResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *connectionReusable = !parsed->HasConnectionClose();
        return STATUS_SUCCESS;
#endif
    }

    struct KhAsyncHttpContext final
    {
        KH_SESSION Session = nullptr;
        KH_REQUEST Request = nullptr;
        KhHttpSendOptions Options = {};
        KH_RESPONSE Response = nullptr;
    };

    struct KhAsyncWebSocketConnectContext final
    {
        KH_SESSION Session = nullptr;
        KhWebSocketConnectOptions Options = {};
        char* Url = nullptr;
        char* Subprotocol = nullptr;
        KH_WEBSOCKET WebSocket = nullptr;
    };

    void CleanupAsyncHttpContext(void* context) noexcept
    {
        auto* httpContext = static_cast<KhAsyncHttpContext*>(context);
        if (httpContext != nullptr && httpContext->Response != nullptr) {
            KhResponseRelease(httpContext->Response);
            httpContext->Response = nullptr;
        }
        FreeHandle(httpContext);
    }

    void CleanupAsyncWebSocketConnectContext(void* context) noexcept
    {
        auto* connectContext = static_cast<KhAsyncWebSocketConnectContext*>(context);
        if (connectContext == nullptr) {
            return;
        }

        FreeApiMemory(connectContext->Url);
        FreeApiMemory(connectContext->Subprotocol);
        if (connectContext->WebSocket != nullptr) {
            const NTSTATUS status = KhWebSocketCloseSync(connectContext->WebSocket);
            UNREFERENCED_PARAMETER(status);
            connectContext->WebSocket = nullptr;
        }
        FreeHandle(connectContext);
    }

    NTSTATUS RunHttpAsyncOperation(KH_ASYNC_OPERATION operation, void* context) noexcept
    {
        auto* httpContext = static_cast<KhAsyncHttpContext*>(context);
        if (httpContext == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (KhAsyncOperationIsCanceled(operation)) {
            return STATUS_CANCELLED;
        }

        KH_RESPONSE response = nullptr;
        KH_RESPONSE* responseOutput = nullptr;
        const bool bodyCallbackOnly =
            httpContext->Options.BodyCallback != nullptr &&
            ((httpContext->Options.Flags & KhHttpSendFlagAggregateWithCallbacks) == 0);
        if (!bodyCallbackOnly) {
            responseOutput = &response;
        }

        NTSTATUS status = KhHttpSendSync(
            httpContext->Session,
            httpContext->Request,
            &httpContext->Options,
            responseOutput);
        if (NT_SUCCESS(status)) {
            httpContext->Response = response;
        }
        else if (response != nullptr) {
            KhResponseRelease(response);
        }

        if (KhAsyncOperationIsCanceled(operation) && status == STATUS_SUCCESS) {
            return STATUS_CANCELLED;
        }

        return status;
    }

    _Must_inspect_result_
    NTSTATUS StoreWebSocketMessage(
        _Inout_ KhWebSocket& websocket,
        KhWebSocketMessageType type,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        if (data == nullptr && dataLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength > websocket.MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        UCHAR* copy = nullptr;
        if (dataLength != 0) {
            copy = AllocateBytesCopy(data, dataLength);
            if (copy == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        FreeApiMemory(websocket.LastMessage);
        websocket.LastMessage = copy;
        websocket.LastMessageLength = dataLength;
        websocket.LastMessageType = type;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS CompleteWebSocketConnect(
        KH_SESSION session,
        const KhWebSocketConnectOptions& options,
        _Out_ KH_WEBSOCKET* websocket) noexcept
    {
        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        if (!IsSessionHandle(session) || websocket == nullptr || !IsValidWebSocketConnectOptions(options)) {
            return STATUS_INVALID_PARAMETER;
        }

        char* urlCopy = AllocateTextCopy(options.Url, options.UrlLength);
        if (urlCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KH_WEBSOCKET newWebSocket = AllocateHandle<KhWebSocket>();
        if (newWebSocket == nullptr) {
            FreeApiMemory(urlCopy);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newWebSocket->Header = { KhHandleKind::WebSocket, false };
        newWebSocket->Session = session;
        newWebSocket->Url = urlCopy;
        newWebSocket->UrlLength = options.UrlLength;
        newWebSocket->MaxMessageBytes = options.MaxMessageBytes;
        newWebSocket->AutoReplyPing = options.AutoReplyPing;
        NTSTATUS status = ParseUrlParts(
            newWebSocket->Url,
            newWebSocket->UrlLength,
            true,
            newWebSocket->Scheme,
            sizeof(newWebSocket->Scheme),
            &newWebSocket->SchemeLength,
            newWebSocket->Host,
            sizeof(newWebSocket->Host),
            &newWebSocket->HostLength,
            newWebSocket->Path,
            sizeof(newWebSocket->Path),
            &newWebSocket->PathLength,
            &newWebSocket->Port);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        if (options.Subprotocol != nullptr && options.SubprotocolLength != 0) {
            newWebSocket->Subprotocol = AllocateTextCopy(options.Subprotocol, options.SubprotocolLength);
            if (newWebSocket->Subprotocol == nullptr) {
                ReleaseWebSocketStorage(*newWebSocket);
                FreeHandle(newWebSocket);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newWebSocket->SubprotocolLength = options.SubprotocolLength;
        }

        session->Workspace->MaxResponseBytes = options.MaxMessageBytes;
        KhWorkspaceReset(session->Workspace);

        SIZE_T handshakeLength = 0;
        status = BuildWebSocketHandshakeRequest(*newWebSocket, *session->Workspace, &handshakeLength);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }
        UNREFERENCED_PARAMETER(handshakeLength);

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketConnect == nullptr) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_NOT_SUPPORTED;
        }

        KhTestWebSocketConnectRequest testRequest = {};
        testRequest.Scheme = newWebSocket->Scheme;
        testRequest.SchemeLength = newWebSocket->SchemeLength;
        testRequest.Host = newWebSocket->Host;
        testRequest.HostLength = newWebSocket->HostLength;
        testRequest.Path = newWebSocket->Path;
        testRequest.PathLength = newWebSocket->PathLength;
        testRequest.Port = newWebSocket->Port;
        testRequest.Subprotocol = newWebSocket->Subprotocol;
        testRequest.SubprotocolLength = newWebSocket->SubprotocolLength;
        testRequest.AutoReplyPing = newWebSocket->AutoReplyPing;
        testRequest.MaxMessageBytes = newWebSocket->MaxMessageBytes;

        status = g_testWebSocketConnect(g_testWebSocketTransportContext, &testRequest);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        newWebSocket->Connected = true;
        *websocket = newWebSocket;
        return STATUS_SUCCESS;
#else
        newWebSocket->Client = new client::WebSocketClient();
        if (newWebSocket->Client == nullptr) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        wchar_t serverName[KhMaxHostLength + 1] = {};
        wchar_t serviceName[KhMaxServiceNameLength + 1] = {};
        status = CopyAsciiToWide(newWebSocket->Host, newWebSocket->HostLength, serverName, RTL_NUMBER_OF(serverName));
        if (NT_SUCCESS(status)) {
            status = FormatServiceName(newWebSocket->Port, serviceName, RTL_NUMBER_OF(serviceName));
        }

        client::WebSocketIoBuffers buffers = {};
        buffers.RequestBuffer = reinterpret_cast<char*>(session->Workspace->Request.Data);
        buffers.RequestBufferLength = session->Workspace->Request.Length;
        buffers.ResponseBuffer = reinterpret_cast<char*>(session->Workspace->Response.Data);
        buffers.ResponseBufferLength = session->Workspace->Response.Length;
        buffers.FrameBuffer = session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = session->Workspace->WebSocketFrameScratch.Length;
        buffers.PayloadBuffer = session->Workspace->DecodedBody.Data;
        buffers.PayloadBufferLength = session->Workspace->DecodedBody.Length;
        http::HttpHeader responseHeaders[KhMaxHeadersPerResponse] = {};
        buffers.Headers = responseHeaders;
        buffers.HeaderCapacity = KhMaxHeadersPerResponse;

        client::WebSocketConnectOptions connectOptions = {};
        connectOptions.ServerName = serverName;
        connectOptions.ServiceName = serviceName;
        connectOptions.TlsServerName = options.Tls.ServerName != nullptr ? options.Tls.ServerName : newWebSocket->Host;
        connectOptions.TlsServerNameLength = options.Tls.ServerName != nullptr ?
            options.Tls.ServerNameLength :
            newWebSocket->HostLength;
        connectOptions.Host = newWebSocket->Host;
        connectOptions.HostLength = newWebSocket->HostLength;
        connectOptions.Path = newWebSocket->Path;
        connectOptions.PathLength = newWebSocket->PathLength;
        connectOptions.CertificateStore = options.Tls.CertificateStore;
        connectOptions.Workspace = session->Workspace;
        connectOptions.ProviderCache = session->ProviderCache;
        connectOptions.UseTls = TextEqualsLiteralIgnoreCase(newWebSocket->Scheme, newWebSocket->SchemeLength, "wss");
        connectOptions.VerifyCertificate = options.Tls.CertificatePolicy == KhCertificatePolicy::Verify;

        if (NT_SUCCESS(status)) {
            status = newWebSocket->Client->Connect(*session->WskClient, connectOptions, buffers);
        }

        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        newWebSocket->Connected = true;
        *websocket = newWebSocket;
        return STATUS_SUCCESS;
#endif
    }

    NTSTATUS RunWebSocketConnectAsyncOperation(KH_ASYNC_OPERATION operation, void* context) noexcept
    {
        auto* connectContext = static_cast<KhAsyncWebSocketConnectContext*>(context);
        if (connectContext == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (KhAsyncOperationIsCanceled(operation)) {
            return STATUS_CANCELLED;
        }

        KH_WEBSOCKET websocket = nullptr;
        NTSTATUS status = CompleteWebSocketConnect(connectContext->Session, connectContext->Options, &websocket);
        if (NT_SUCCESS(status)) {
            connectContext->WebSocket = websocket;
        }
        else if (websocket != nullptr) {
            const NTSTATUS closeStatus = KhWebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        if (KhAsyncOperationIsCanceled(operation) && status == STATUS_SUCCESS) {
            return STATUS_CANCELLED;
        }

        return status;
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

        KhWorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = effectiveOptions.ResponsePoolType;
        workspaceOptions.MaxResponseBytes = effectiveOptions.MaxResponseBytes;
        status = KhWorkspaceCreate(&workspaceOptions, &newSession->Workspace);
        if (!NT_SUCCESS(status)) {
            FreeHandle(newSession);
            return status;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        newSession->ProviderCache = AllocateHandle<crypto::CngProviderCache>();
        if (newSession->ProviderCache == nullptr) {
            KhWorkspaceRelease(newSession->Workspace);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = newSession->ProviderCache->Initialize();
        if (!NT_SUCCESS(status)) {
            FreeHandle(newSession->ProviderCache);
            newSession->ProviderCache = nullptr;
            KhWorkspaceRelease(newSession->Workspace);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return status;
        }
#else
        newSession->ProviderCache = new crypto::CngProviderCache();
        if (newSession->ProviderCache == nullptr) {
            KhWorkspaceRelease(newSession->Workspace);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = newSession->ProviderCache->Initialize();
        if (!NT_SUCCESS(status)) {
            delete newSession->ProviderCache;
            newSession->ProviderCache = nullptr;
            KhWorkspaceRelease(newSession->Workspace);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return status;
        }
#endif

        status = KhConnectionPoolInitialize(
            &newSession->ConnectionPool,
            effectiveOptions.ConnectionPoolCapacity);
        if (!NT_SUCCESS(status)) {
            newSession->ProviderCache->Shutdown();
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            FreeHandle(newSession->ProviderCache);
#else
            delete newSession->ProviderCache;
#endif
            newSession->ProviderCache = nullptr;
            KhWorkspaceRelease(newSession->Workspace);
            newSession->Workspace = nullptr;
            FreeHandle(newSession);
            return status;
        }

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
        KhConnectionPoolShutdown(&session->ConnectionPool);
        if (session->ProviderCache != nullptr) {
            session->ProviderCache->Shutdown();
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            FreeHandle(session->ProviderCache);
#else
            delete session->ProviderCache;
#endif
            session->ProviderCache = nullptr;
        }
        KhWorkspaceRelease(session->Workspace);
        session->Workspace = nullptr;
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
        ReleaseRequestStorage(*request);
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

        char* urlCopy = AllocateTextCopy(url, urlLength);
        if (urlCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KhRequest parsed = {};
        NTSTATUS parseStatus = ParseUrlIntoRequest(parsed, urlCopy, urlLength);
        if (!NT_SUCCESS(parseStatus)) {
            FreeApiMemory(urlCopy);
            return parseStatus;
        }

        FreeApiMemory(request->Url);
        request->Url = urlCopy;
        request->UrlLength = urlLength;
        RtlCopyMemory(request->Scheme, parsed.Scheme, sizeof(request->Scheme));
        request->SchemeLength = parsed.SchemeLength;
        RtlCopyMemory(request->Host, parsed.Host, sizeof(request->Host));
        request->HostLength = parsed.HostLength;
        RtlCopyMemory(request->Path, parsed.Path, sizeof(request->Path));
        request->PathLength = parsed.PathLength;
        request->Port = parsed.Port;

        if (!request->HasTlsOverride && TextEqualsLiteralIgnoreCase(request->Scheme, request->SchemeLength, "https")) {
            request->Tls.ServerName = request->Host;
            request->Tls.ServerNameLength = request->HostLength;
        }

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

        if (!IsRequestHandle(request) || name == nullptr || nameLength == 0 || value == nullptr || valueLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (nameLength > KhMaxHeaderNameLength || valueLength > KhMaxHeaderValueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (request->HeaderCount >= KhMaxHeadersPerRequest) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        char* nameCopy = AllocateTextCopy(name, nameLength);
        if (nameCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        char* valueCopy = AllocateTextCopy(value, valueLength);
        if (valueCopy == nullptr) {
            FreeApiMemory(nameCopy);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KhStoredHeader& header = request->Headers[request->HeaderCount++];
        header.Name = nameCopy;
        header.NameLength = nameLength;
        header.Value = valueCopy;
        header.ValueLength = valueLength;
        return STATUS_SUCCESS;
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

        const bool bodyCallbackOnly =
            effectiveOptions.BodyCallback != nullptr &&
            ((effectiveOptions.Flags & KhHttpSendFlagAggregateWithCallbacks) == 0);
        const bool shouldAggregate = !bodyCallbackOnly;
        if (shouldAggregate && response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T maxResponseBytes =
            EffectiveMaxResponseBytes(effectiveOptions.MaxResponseBytes, session->Options.MaxResponseBytes);
        session->Workspace->MaxResponseBytes = maxResponseBytes;
        KhWorkspaceReset(session->Workspace);

        http::HttpHeader requestHeaders[KhMaxHeadersPerRequest] = {};
        SIZE_T builtRequestLength = 0;
        status = BuildRequestBytes(
            *request,
            *session->Workspace,
            requestHeaders,
            KhMaxHeadersPerRequest,
            &builtRequestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        KhConnectionPoolKey poolKey = {};
        status = BuildPoolKey(*request, &poolKey);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        KhPooledConnection* pooledConnection = nullptr;
        bool reusedConnection = false;
        status = KhConnectionPoolAcquire(
            &session->ConnectionPool,
            poolKey,
            request->ConnectionPolicy,
            &pooledConnection,
            &reusedConnection);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http::HttpHeader responseHeaders[KhMaxHeadersPerResponse] = {};
        http::HttpResponse parsed = {};
        SIZE_T rawResponseLength = 0;
        bool connectionReusable = false;

        status = SendViaTransport(
            session,
            *request,
            *session->Workspace,
            pooledConnection,
            reusedConnection,
            builtRequestLength,
            &parsed,
            responseHeaders,
            KhMaxHeadersPerResponse,
            &rawResponseLength,
            &connectionReusable);

        if (NT_SUCCESS(status)) {
            status = InvokeResponseCallbacks(effectiveOptions, parsed);
        }

        if (NT_SUCCESS(status) && shouldAggregate) {
            status = CreateOwnedResponse(
                parsed,
                reinterpret_cast<const char*>(session->Workspace->Response.Data),
                rawResponseLength,
                response);
        }

        const bool canReturnToPool =
            NT_SUCCESS(status) &&
            connectionReusable &&
            request->ConnectionPolicy == KhConnectionPolicy::ReuseOrCreate;
        KhConnectionPoolRelease(&session->ConnectionPool, pooledConnection, canReturnToPool);
        return status;
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

        if (effectiveOptions.BodyCallback != nullptr &&
            ((effectiveOptions.Flags & KhHttpSendFlagAggregateWithCallbacks) != 0) &&
            operation == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        auto* context = AllocateHandle<KhAsyncHttpContext>();
        if (context == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        context->Session = session;
        context->Request = request;
        context->Options = effectiveOptions;
        context->Response = nullptr;

        KhAsyncCreateOptions createOptions = {};
        createOptions.Kind = KhAsyncOperationKind::HttpSend;
        createOptions.WorkerRoutine = RunHttpAsyncOperation;
        createOptions.CleanupRoutine = CleanupAsyncHttpContext;
        createOptions.Context = context;
        createOptions.CompletionCallback = effectiveOptions.CompletionCallback;
        createOptions.CompletionContext = effectiveOptions.CompletionContext;

        status = KhAsyncOperationCreate(createOptions, operation);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncHttpContext(context);
        }

        return status;
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

    NTSTATUS KhResponseGetHeader(
        KH_RESPONSE response,
        const char* name,
        SIZE_T nameLength,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }

        if (!IsResponseHandle(response) ||
            name == nullptr ||
            nameLength == 0 ||
            value == nullptr ||
            valueLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < response->HeaderCount; ++index) {
            const http::HttpHeader& header = response->Headers[index];
            if (TextEqualsIgnoreCase(header.Name.Data, header.Name.Length, name, nameLength)) {
                *value = header.Value.Data;
                *valueLength = header.Value.Length;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
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
        ReleaseResponseStorage(*response);
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

        return CompleteWebSocketConnect(session, *options, websocket);
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

        auto* context = AllocateHandle<KhAsyncWebSocketConnectContext>();
        if (context == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        context->Session = session;
        context->Options = *options;
        context->Url = AllocateTextCopy(options->Url, options->UrlLength);
        if (context->Url == nullptr) {
            CleanupAsyncWebSocketConnectContext(context);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        context->Options.Url = context->Url;

        if (options->Subprotocol != nullptr && options->SubprotocolLength != 0) {
            context->Subprotocol = AllocateTextCopy(options->Subprotocol, options->SubprotocolLength);
            if (context->Subprotocol == nullptr) {
                CleanupAsyncWebSocketConnectContext(context);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            context->Options.Subprotocol = context->Subprotocol;
        }

        KhAsyncCreateOptions createOptions = {};
        createOptions.Kind = KhAsyncOperationKind::WebSocketConnect;
        createOptions.WorkerRoutine = RunWebSocketConnectAsyncOperation;
        createOptions.CleanupRoutine = CleanupAsyncWebSocketConnectContext;
        createOptions.Context = context;

        status = KhAsyncOperationCreate(createOptions, operation);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncWebSocketConnectContext(context);
        }

        return status;
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

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        if (!IsWebSocketHandle(websocket) || !websocket->Connected || text == nullptr || textLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (textLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        return g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            KhWebSocketMessageType::Text,
            reinterpret_cast<const UCHAR*>(text),
            textLength,
            finalFragment);
#else
        UNREFERENCED_PARAMETER(finalFragment);
        if (websocket->Client == nullptr || websocket->Session == nullptr || websocket->Session->Workspace == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
        return websocket->Client->SendText(text, textLength, buffers);
#endif
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

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        if (!IsWebSocketHandle(websocket) || !websocket->Connected || data == nullptr || dataLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        return g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            KhWebSocketMessageType::Binary,
            data,
            dataLength,
            finalFragment);
#else
        UNREFERENCED_PARAMETER(finalFragment);
        if (websocket->Client == nullptr || websocket->Session == nullptr || websocket->Session->Workspace == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
        return websocket->Client->SendBinary(data, dataLength, buffers);
#endif
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

        if (!IsWebSocketHandle(websocket) || !websocket->Connected) {
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketReceive == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        KhTestWebSocketMessage received = {};
        status = g_testWebSocketReceive(g_testWebSocketTransportContext, websocket, &received);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (received.Data == nullptr && received.DataLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T maxMessageBytes =
            effectiveOptions.MaxMessageBytes != 0 ? effectiveOptions.MaxMessageBytes : websocket->MaxMessageBytes;
        if (received.DataLength > maxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (effectiveOptions.MessageCallback != nullptr) {
            status = effectiveOptions.MessageCallback(
                effectiveOptions.CallbackContext,
                received.Type,
                received.Data,
                received.DataLength,
                received.FinalFragment);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (effectiveOptions.AutoAllocate) {
            status = StoreWebSocketMessage(*websocket, received.Type, received.Data, received.DataLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message->Type = websocket->LastMessageType;
            message->Data = websocket->LastMessage;
            message->DataLength = websocket->LastMessageLength;
            message->FinalFragment = received.FinalFragment;
        }

        if (received.Type == KhWebSocketMessageType::Close) {
            websocket->Connected = false;
        }

        return STATUS_SUCCESS;
#else
        if (websocket->Client == nullptr || websocket->Session == nullptr || websocket->Session->Workspace == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        const SIZE_T maxMessageBytes =
            effectiveOptions.MaxMessageBytes != 0 ? effectiveOptions.MaxMessageBytes : websocket->MaxMessageBytes;
        if (maxMessageBytes > websocket->Session->Workspace->DecodedBody.Length) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
        KernelHttp::websocket::WebSocketOpcode opcode = KernelHttp::websocket::WebSocketOpcode::Continuation;
        SIZE_T bytesReceived = 0;
        status = websocket->Client->ReceiveMessage(
            buffers,
            &opcode,
            websocket->Session->Workspace->DecodedBody.Data,
            maxMessageBytes,
            &bytesReceived);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        KhWebSocketMessageType type = KhWebSocketMessageType::Binary;
        if (opcode == KernelHttp::websocket::WebSocketOpcode::Text) {
            type = KhWebSocketMessageType::Text;
        }
        else if (opcode == KernelHttp::websocket::WebSocketOpcode::Close) {
            type = KhWebSocketMessageType::Close;
            websocket->Connected = false;
        }

        const UCHAR* data = websocket->Session->Workspace->DecodedBody.Data;
        if (effectiveOptions.MessageCallback != nullptr) {
            status = effectiveOptions.MessageCallback(
                effectiveOptions.CallbackContext,
                type,
                data,
                bytesReceived,
                true);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (effectiveOptions.AutoAllocate) {
            status = StoreWebSocketMessage(*websocket, type, data, bytesReceived);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message->Type = websocket->LastMessageType;
            message->Data = websocket->LastMessage;
            message->DataLength = websocket->LastMessageLength;
            message->FinalFragment = true;
        }

        return STATUS_SUCCESS;
#endif
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

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketClose != nullptr) {
            g_testWebSocketClose(g_testWebSocketTransportContext, websocket);
        }
#endif
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        if (websocket->Client != nullptr && websocket->Session != nullptr && websocket->Session->Workspace != nullptr) {
            client::WebSocketIoBuffers buffers = {};
            buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
            buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
            const NTSTATUS closeStatus = websocket->Client->Close(buffers);
            UNREFERENCED_PARAMETER(closeStatus);
        }
#endif
        websocket->Connected = false;
        ReleaseWebSocketStorage(*websocket);
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

        return KhAsyncOperationCancel(operation);
    }

    NTSTATUS KhAsyncWait(KH_ASYNC_OPERATION operation, ULONG timeoutMilliseconds) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return KhAsyncOperationWait(operation, timeoutMilliseconds);
    }

    NTSTATUS KhAsyncGetHttpResponse(KH_ASYNC_OPERATION operation, KH_RESPONSE* response) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (response != nullptr) {
            *response = nullptr;
        }

        if (!KhAsyncOperationIsValid(operation) ||
            response == nullptr ||
            KhAsyncOperationGetKind(operation) != KhAsyncOperationKind::HttpSend) {
            return STATUS_INVALID_PARAMETER;
        }

        status = KhAsyncOperationStatus(operation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* context = static_cast<KhAsyncHttpContext*>(KhAsyncOperationContext(operation));
        if (context == nullptr || context->Response == nullptr) {
            return STATUS_NOT_FOUND;
        }

        *response = context->Response;
        context->Response = nullptr;
        return STATUS_SUCCESS;
    }

    NTSTATUS KhAsyncGetWebSocket(KH_ASYNC_OPERATION operation, KH_WEBSOCKET* websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        if (!KhAsyncOperationIsValid(operation) ||
            websocket == nullptr ||
            KhAsyncOperationGetKind(operation) != KhAsyncOperationKind::WebSocketConnect) {
            return STATUS_INVALID_PARAMETER;
        }

        status = KhAsyncOperationStatus(operation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* context = static_cast<KhAsyncWebSocketConnectContext*>(KhAsyncOperationContext(operation));
        if (context == nullptr || context->WebSocket == nullptr) {
            return STATUS_NOT_FOUND;
        }

        *websocket = context->WebSocket;
        context->WebSocket = nullptr;
        return STATUS_SUCCESS;
    }

    void KhAsyncRelease(KH_ASYNC_OPERATION operation) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || operation == nullptr) {
            return;
        }

        KhAsyncOperationRelease(operation);
    }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    void KhTestSetHttpTransport(KhTestHttpTransportCallback callback, void* context) noexcept
    {
        g_testHttpTransport = callback;
        g_testHttpTransportContext = context;
    }

    void KhTestSetWebSocketTransport(
        KhTestWebSocketConnectCallback connectCallback,
        KhTestWebSocketSendCallback sendCallback,
        KhTestWebSocketReceiveCallback receiveCallback,
        KhTestWebSocketCloseCallback closeCallback,
        void* context) noexcept
    {
        g_testWebSocketConnect = connectCallback;
        g_testWebSocketSend = sendCallback;
        g_testWebSocketReceive = receiveCallback;
        g_testWebSocketClose = closeCallback;
        g_testWebSocketTransportContext = context;
    }

    NTSTATUS KhTestAsyncStatus(KH_ASYNC_OPERATION operation) noexcept
    {
        return KhAsyncOperationStatus(operation);
    }

    bool KhTestAsyncIsCompleted(KH_ASYNC_OPERATION operation) noexcept
    {
        return KhAsyncOperationIsCompleted(operation);
    }

    bool KhTestAsyncIsCanceled(KH_ASYNC_OPERATION operation) noexcept
    {
        return KhAsyncOperationIsCanceled(operation);
    }

    void KhTestSetCurrentIrql(ULONG irql) noexcept
    {
        g_testCurrentIrql = irql;
    }

    void KhTestResetCurrentIrql() noexcept
    {
        g_testCurrentIrql = PassiveLevel;
    }

    bool KhTestSessionHasWorkspace(KH_SESSION session) noexcept
    {
        return IsSessionHandle(session) &&
            session->Workspace != nullptr &&
            session->Workspace->Request.Data != nullptr &&
            session->Workspace->Response.Data != nullptr &&
            session->Workspace->DecodedBody.Data != nullptr &&
            session->Workspace->Http2HeaderScratch.Data != nullptr &&
            session->Workspace->TlsHandshakeScratch.Data != nullptr &&
            session->Workspace->CertificateScratch.Data != nullptr &&
            session->Workspace->WebSocketFrameScratch.Data != nullptr;
    }

    bool KhTestSessionHasProviderCache(KH_SESSION session) noexcept
    {
        return IsSessionHandle(session) &&
            session->ProviderCache != nullptr &&
            session->ProviderCache->IsInitialized();
    }
#endif
}
}
