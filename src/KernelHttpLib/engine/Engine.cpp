#include <KernelHttp/engine/Async.h>
#include <KernelHttp/engine/ConnectionPool.h>
#include <KernelHttp/engine/EngineImpl.h>
#include <KernelHttp/engine/HandleAlloc.h>
#include <KernelHttp/engine/UrlParser.h>
#include <KernelHttp/engine/Workspace.h>
#include <KernelHttp/crypto/CngProviderCache.h>
#include <KernelHttp/client/Http2Client.h>
#include <KernelHttp/client/WebSocketClient.h>
#include <KernelHttp/http/HttpContentEncoding.h>
#include <KernelHttp/http/HttpParser.h>
#include <KernelHttp/http/HttpRequest.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/TlsConnection.h>
#include <KernelHttp/websocket/WebSocketFrame.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#include <stdio.h>
#else
#include <ws2ipdef.h>
#endif

namespace KernelHttp
{
namespace engine
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
        UNREFERENCED_PARAMETER(value);
        return true;
    }

    bool IsValidMaxMessageBytes(SIZE_T value) noexcept
    {
        return value > 0;
    }

    SIZE_T EffectiveMaxResponseBytes(const KhHttpSendOptions* options, SIZE_T sessionValue) noexcept
    {
        UNREFERENCED_PARAMETER(sessionValue);
        return options != nullptr ? options->MaxResponseBytes : 0;
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

        if (options.HandshakeReceiveTimeoutMilliseconds == 0) {
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

    bool IsValidAddressFamily(KhAddressFamily addressFamily) noexcept
    {
        return addressFamily == KhAddressFamily::Any ||
            addressFamily == KhAddressFamily::Ipv4 ||
            addressFamily == KhAddressFamily::Ipv6;
    }

    net::WskAddressFamily ToWskAddressFamily(KhAddressFamily addressFamily) noexcept
    {
        switch (addressFamily) {
        case KhAddressFamily::Ipv4:
            return net::WskAddressFamily::Ipv4;
        case KhAddressFamily::Ipv6:
            return net::WskAddressFamily::Ipv6;
        case KhAddressFamily::Any:
        default:
            return net::WskAddressFamily::Any;
        }
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

        if (!IsValidMaxMessageBytes(options.MaxMessageBytes)) {
            return false;
        }

        return IsValidTlsOptions(options.Tls) && IsValidAddressFamily(options.AddressFamily);
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

    bool TextEqualsLiteral(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept
    {
        const SIZE_T rightLength = http::MakeText(right).Length;
        if (leftLength != rightLength) {
            return false;
        }
        if (leftLength == 0) {
            return true;
        }
        if (left == nullptr || right == nullptr) {
            return false;
        }
        return RtlCompareMemory(left, right, leftLength) == leftLength;
    }

    bool TextContainsChar(const char* text, SIZE_T textLength, char needle) noexcept
    {
        if (text == nullptr) {
            return false;
        }

        for (SIZE_T index = 0; index < textLength; ++index) {
            if (text[index] == needle) {
                return true;
            }
        }

        return false;
    }

    bool IsConnectionCloseStatus(NTSTATUS status) noexcept
    {
        return status == STATUS_CONNECTION_DISCONNECTED ||
            status == STATUS_CONNECTION_RESET ||
            status == STATUS_CONNECTION_ABORTED ||
            status == STATUS_DEVICE_NOT_CONNECTED;
    }

    bool IsDefaultPort(const char* scheme, SIZE_T schemeLength, USHORT port) noexcept
    {
        return ((TextEqualsLiteralIgnoreCase(scheme, schemeLength, "http") ||
            TextEqualsLiteralIgnoreCase(scheme, schemeLength, "ws")) && port == 80) ||
            ((TextEqualsLiteralIgnoreCase(scheme, schemeLength, "https") ||
                TextEqualsLiteralIgnoreCase(scheme, schemeLength, "wss")) && port == 443);
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

    bool IsValidSendOptions(const KhHttpSendOptions& options, const KhSession& session) noexcept
    {
        UNREFERENCED_PARAMETER(session);

        if (options.HeaderCallback == nullptr && options.BodyCallback == nullptr && options.CallbackContext != nullptr) {
            return false;
        }

        if (options.BodyCallback == nullptr && ((options.Flags & KhHttpSendFlagAggregateWithCallbacks) != 0)) {
            return false;
        }

        return true;
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

    void ReleaseOwnedBody(_Inout_ KhRequest& request) noexcept
    {
        if (request.OwnedBody != nullptr && request.OwnedBodyCapacity != 0) {
            RtlSecureZeroMemory(request.OwnedBody, request.OwnedBodyCapacity);
        }
        FreeApiMemory(request.OwnedBody);
        request.OwnedBody = nullptr;
        request.OwnedBodyLength = 0;
        request.OwnedBodyCapacity = 0;
        request.Body = nullptr;
        request.BodyLength = 0;
        request.HasBody = false;
    }

    void ResetOwnedBodyContent(_Inout_ KhRequest& request) noexcept
    {
        if (request.OwnedBody != nullptr && request.OwnedBodyCapacity != 0) {
            RtlSecureZeroMemory(request.OwnedBody, request.OwnedBodyCapacity);
        }
        request.OwnedBodyLength = 0;
        request.HasBody = false;
    }

    void AbortOwnedBodyBuild(_Inout_ KhRequest& request) noexcept
    {
        ResetOwnedBodyContent(request);
        request.Body = nullptr;
        request.BodyLength = 0;
    }

    _Must_inspect_result_
    bool AddSize(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
    {
        if (result == nullptr) {
            return false;
        }
        if (left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right) {
            *result = 0;
            return false;
        }
        *result = left + right;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS EnsureOwnedBodyCapacity(_Inout_ KhRequest& request, SIZE_T requiredCapacity) noexcept
    {
        if (requiredCapacity == 0 || requiredCapacity <= request.OwnedBodyCapacity) {
            return STATUS_SUCCESS;
        }

        SIZE_T newCapacity = request.OwnedBodyCapacity;
        if (newCapacity == 0) {
            newCapacity = KhInitialOwnedBodyCapacity;
        }

        while (newCapacity < requiredCapacity) {
            SIZE_T doubled = 0;
            if (!AddSize(newCapacity, newCapacity, &doubled)) {
                newCapacity = requiredCapacity;
                break;
            }
            newCapacity = doubled < requiredCapacity ? requiredCapacity : doubled;
        }

        UCHAR* replacement = static_cast<UCHAR*>(AllocateApiMemory(newCapacity));
        if (replacement == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (request.OwnedBody != nullptr && request.OwnedBodyLength != 0) {
            RtlCopyMemory(replacement, request.OwnedBody, request.OwnedBodyLength);
        }
        if (request.OwnedBody != nullptr && request.OwnedBodyCapacity != 0) {
            RtlSecureZeroMemory(request.OwnedBody, request.OwnedBodyCapacity);
        }
        FreeApiMemory(request.OwnedBody);
        request.OwnedBody = replacement;
        request.OwnedBodyCapacity = newCapacity;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BeginOwnedBodyBuild(_Inout_ KhRequest& request) noexcept
    {
        ResetOwnedBodyContent(request);
        request.Body = request.OwnedBody;
        request.BodyLength = 0;
        request.HasBody = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS AppendOwnedBody(
        _Inout_ KhRequest& request,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        if (data == nullptr && dataLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength == 0) {
            request.Body = request.OwnedBody;
            request.BodyLength = request.OwnedBodyLength;
            request.HasBody = true;
            return STATUS_SUCCESS;
        }

        SIZE_T required = 0;
        if (!AddSize(request.OwnedBodyLength, dataLength, &required)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        NTSTATUS status = EnsureOwnedBodyCapacity(request, required);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlCopyMemory(request.OwnedBody + request.OwnedBodyLength, data, dataLength);
        request.OwnedBodyLength = required;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS AppendOwnedText(_Inout_ KhRequest& request, _In_opt_ const char* text, SIZE_T textLength) noexcept
    {
        return AppendOwnedBody(request, reinterpret_cast<const UCHAR*>(text), textLength);
    }

    _Must_inspect_result_
    NTSTATUS AppendOwnedLiteral(_Inout_ KhRequest& request, _In_z_ const char* text) noexcept
    {
        const http::HttpText value = http::MakeText(text);
        return AppendOwnedText(request, value.Data, value.Length);
    }

    _Must_inspect_result_
    NTSTATUS AddStoredHeader(
        _Inout_ KhRequest& request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
    {
        if (name == nullptr || nameLength == 0 || value == nullptr || valueLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (nameLength > KhMaxHeaderNameLength || valueLength > KhMaxHeaderValueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (request.HeaderCount >= KhMaxHeadersPerRequest) {
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

        KhStoredHeader& header = request.Headers[request.HeaderCount++];
        header.Name = nameCopy;
        header.NameLength = nameLength;
        header.Value = valueCopy;
        header.ValueLength = valueLength;
        return STATUS_SUCCESS;
    }

    void RemoveStoredHeadersByName(_Inout_ KhRequest& request, _In_z_ const char* name) noexcept
    {
        SIZE_T index = 0;
        while (index < request.HeaderCount) {
            if (TextEqualsLiteralIgnoreCase(request.Headers[index].Name, request.Headers[index].NameLength, name)) {
                ReleaseStoredHeader(request.Headers[index]);
                for (SIZE_T moveIndex = index + 1; moveIndex < request.HeaderCount; ++moveIndex) {
                    request.Headers[moveIndex - 1] = request.Headers[moveIndex];
                }
                --request.HeaderCount;
                request.Headers[request.HeaderCount] = {};
            }
            else {
                ++index;
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS ReplaceContentType(
        _Inout_ KhRequest& request,
        _In_reads_bytes_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        if (contentType == nullptr || contentTypeLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        RemoveStoredHeadersByName(request, "Content-Type");
        return AddStoredHeader(
            request,
            "Content-Type",
            http::MakeText("Content-Type").Length,
            contentType,
            contentTypeLength);
    }

    _Must_inspect_result_
    bool IsOptionalTextValid(const char* text, SIZE_T textLength) noexcept
    {
        return (text == nullptr && textLength == 0) || (text != nullptr && textLength != 0);
    }

    _Must_inspect_result_
    bool IsUnreservedFormChar(char value) noexcept
    {
        return (value >= 'A' && value <= 'Z') ||
            (value >= 'a' && value <= 'z') ||
            (value >= '0' && value <= '9') ||
            value == '-' ||
            value == '_' ||
            value == '.' ||
            value == '~';
    }

    _Must_inspect_result_
    NTSTATUS AppendUrlEncodedText(
        _Inout_ KhRequest& request,
        _In_reads_bytes_opt_(textLength) const char* text,
        SIZE_T textLength) noexcept
    {
        if (text == nullptr && textLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        static constexpr char hex[] = "0123456789ABCDEF";
        for (SIZE_T index = 0; index < textLength; ++index) {
            const unsigned char value = static_cast<unsigned char>(text[index]);
            if (IsUnreservedFormChar(static_cast<char>(value))) {
                NTSTATUS status = AppendOwnedText(request, text + index, 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else if (value == ' ') {
                NTSTATUS status = AppendOwnedLiteral(request, "+");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else {
                NTSTATUS status = AppendOwnedLiteral(request, "%");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AppendOwnedText(request, hex + ((value >> 4) & 0x0F), 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AppendOwnedText(request, hex + (value & 0x0F), 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool IsValidHeaderQuotedByte(char value) noexcept
    {
        return value != '\r' && value != '\n';
    }

    _Must_inspect_result_
    NTSTATUS AppendMultipartQuotedValue(
        _Inout_ KhRequest& request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
    {
        if (value == nullptr || valueLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < valueLength; ++index) {
            const char ch = value[index];
            if (!IsValidHeaderQuotedByte(ch)) {
                return STATUS_INVALID_PARAMETER;
            }
            if (ch == '"' || ch == '\\') {
                NTSTATUS status = AppendOwnedLiteral(request, "\\");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            NTSTATUS status = AppendOwnedText(request, &ch, 1);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS GenerateMultipartBoundary(_Inout_ KhRequest& request, _Out_ SIZE_T* boundaryLength) noexcept
    {
        if (boundaryLength != nullptr) {
            *boundaryLength = 0;
        }
        if (boundaryLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const http::HttpText prefix = http::MakeText("----KernelHttpBoundary");
        if (prefix.Length + 8 >= KhMultipartBoundaryStorageLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(request.MultipartBoundary, sizeof(request.MultipartBoundary));
        RtlCopyMemory(request.MultipartBoundary, prefix.Data, prefix.Length);

        ++request.BodyBuildCounter;
        static constexpr char hex[] = "0123456789ABCDEF";
        ULONG value = request.BodyBuildCounter;
        for (SIZE_T index = 0; index < 8; ++index) {
            const ULONG shift = static_cast<ULONG>((7 - index) * 4);
            request.MultipartBoundary[prefix.Length + index] = hex[(value >> shift) & 0x0F];
        }

        *boundaryLength = prefix.Length + 8;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SetMultipartContentType(
        _Inout_ KhRequest& request,
        _In_reads_bytes_(boundaryLength) const char* boundary,
        SIZE_T boundaryLength) noexcept
    {
        const http::HttpText prefix = http::MakeText("multipart/form-data; boundary=");
        SIZE_T contentTypeLength = 0;
        if (!AddSize(prefix.Length, boundaryLength, &contentTypeLength)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        char* contentType = static_cast<char*>(AllocateApiMemory(contentTypeLength + 1));
        if (contentType == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(contentType, prefix.Data, prefix.Length);
        RtlCopyMemory(contentType + prefix.Length, boundary, boundaryLength);
        contentType[contentTypeLength] = '\0';

        const NTSTATUS status = ReplaceContentType(request, contentType, contentTypeLength);
        FreeApiMemory(contentType);
        return status;
    }

    _Must_inspect_result_
    NTSTATUS AppendMultipartPartHeader(
        _Inout_ KhRequest& request,
        _In_reads_bytes_(boundaryLength) const char* boundary,
        SIZE_T boundaryLength,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_opt_(fileNameLength) const char* fileName,
        SIZE_T fileNameLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        if (boundary == nullptr ||
            boundaryLength == 0 ||
            name == nullptr ||
            nameLength == 0 ||
            !IsOptionalTextValid(fileName, fileNameLength) ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = AppendOwnedLiteral(request, "--");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendOwnedText(request, boundary, boundaryLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendOwnedLiteral(request, "\r\nContent-Disposition: form-data; name=\"");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendMultipartQuotedValue(request, name, nameLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendOwnedLiteral(request, "\"");
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (fileName != nullptr && fileNameLength != 0) {
            status = AppendOwnedLiteral(request, "; filename=\"");
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendMultipartQuotedValue(request, fileName, fileNameLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendOwnedLiteral(request, "\"");
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = AppendOwnedLiteral(request, "\r\n");
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (contentType != nullptr && contentTypeLength != 0) {
            status = AppendOwnedLiteral(request, "Content-Type: ");
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendOwnedText(request, contentType, contentTypeLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendOwnedLiteral(request, "\r\n");
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return AppendOwnedLiteral(request, "\r\n");
    }

    void DeriveFileNameFromPath(
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength,
        _Outptr_result_bytebuffer_(*fileNameLength) const char** fileName,
        _Out_ SIZE_T* fileNameLength) noexcept
    {
        if (fileName != nullptr) {
            *fileName = nullptr;
        }
        if (fileNameLength != nullptr) {
            *fileNameLength = 0;
        }
        if (filePath == nullptr || filePathLength == 0 || fileName == nullptr || fileNameLength == nullptr) {
            return;
        }

        SIZE_T start = 0;
        for (SIZE_T index = 0; index < filePathLength; ++index) {
            if (filePath[index] == '\\' || filePath[index] == '/') {
                start = index + 1;
            }
        }

        *fileName = filePath + start;
        *fileNameLength = filePathLength - start;
    }

    _Must_inspect_result_
    NTSTATUS AppendFileToOwnedBody(
        _Inout_ KhRequest& request,
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength) noexcept
    {
        if (filePath == nullptr || filePathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        char* path = AllocateTextCopy(filePath, filePathLength);
        if (path == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        FILE* file = nullptr;
        if (fopen_s(&file, path, "rb") != 0 || file == nullptr) {
            FreeApiMemory(path);
            return STATUS_NOT_FOUND;
        }

        if (_fseeki64(file, 0, SEEK_END) != 0) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_UNSUCCESSFUL;
        }
        const __int64 fileSize = _ftelli64(file);
        if (fileSize < 0) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_UNSUCCESSFUL;
        }
        if (_fseeki64(file, 0, SEEK_SET) != 0) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_UNSUCCESSFUL;
        }

        const unsigned __int64 unsignedSize = static_cast<unsigned __int64>(fileSize);
        if (unsignedSize > static_cast<unsigned __int64>(~static_cast<SIZE_T>(0))) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_BUFFER_TOO_SMALL;
        }

        const SIZE_T bytesToRead = static_cast<SIZE_T>(unsignedSize);
        SIZE_T required = 0;
        if (!AddSize(request.OwnedBodyLength, bytesToRead, &required)) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_INTEGER_OVERFLOW;
        }

        NTSTATUS status = EnsureOwnedBodyCapacity(request, required);
        if (!NT_SUCCESS(status)) {
            fclose(file);
            FreeApiMemory(path);
            return status;
        }

        if (bytesToRead != 0) {
            const size_t read = fread(request.OwnedBody + request.OwnedBodyLength, 1, bytesToRead, file);
            if (read != bytesToRead) {
                fclose(file);
                FreeApiMemory(path);
                return STATUS_UNSUCCESSFUL;
            }
        }

        request.OwnedBodyLength = required;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        fclose(file);
        FreeApiMemory(path);
        return STATUS_SUCCESS;
#else
        if (filePathLength > 0xFFFE) {
            return STATUS_INVALID_PARAMETER;
        }

        char* path = AllocateTextCopy(filePath, filePathLength);
        if (path == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ANSI_STRING ansiPath = {};
        RtlInitAnsiString(&ansiPath, path);
        UNICODE_STRING unicodePath = {};
        NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
        if (!NT_SUCCESS(status)) {
            FreeApiMemory(path);
            return status;
        }

        OBJECT_ATTRIBUTES objectAttributes = {};
        InitializeObjectAttributes(
            &objectAttributes,
            &unicodePath,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            nullptr,
            nullptr);

        IO_STATUS_BLOCK ioStatus = {};
        HANDLE fileHandle = nullptr;
        status = ZwCreateFile(
            &fileHandle,
            GENERIC_READ,
            &objectAttributes,
            &ioStatus,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            nullptr,
            0);
        if (!NT_SUCCESS(status)) {
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return status;
        }

        FILE_STANDARD_INFORMATION fileInfo = {};
        status = ZwQueryInformationFile(
            fileHandle,
            &ioStatus,
            &fileInfo,
            sizeof(fileInfo),
            FileStandardInformation);
        if (!NT_SUCCESS(status) || fileInfo.EndOfFile.QuadPart < 0) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
        }

        const ULONGLONG fileSize = static_cast<ULONGLONG>(fileInfo.EndOfFile.QuadPart);
        if (fileSize > static_cast<ULONGLONG>(~static_cast<SIZE_T>(0))) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return STATUS_BUFFER_TOO_SMALL;
        }

        const SIZE_T bytesToRead = static_cast<SIZE_T>(fileSize);
        SIZE_T required = 0;
        if (!AddSize(request.OwnedBodyLength, bytesToRead, &required)) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return STATUS_INTEGER_OVERFLOW;
        }

        status = EnsureOwnedBodyCapacity(request, required);
        if (!NT_SUCCESS(status)) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return status;
        }

        SIZE_T totalRead = 0;
        while (totalRead < bytesToRead) {
            SIZE_T remaining = bytesToRead - totalRead;
            ULONG chunk = remaining > static_cast<SIZE_T>(0x100000) ?
                0x100000UL :
                static_cast<ULONG>(remaining);
            LARGE_INTEGER offset = {};
            offset.QuadPart = static_cast<LONGLONG>(totalRead);
            status = ZwReadFile(
                fileHandle,
                nullptr,
                nullptr,
                nullptr,
                &ioStatus,
                request.OwnedBody + request.OwnedBodyLength + totalRead,
                chunk,
                &offset,
                nullptr);
            if (!NT_SUCCESS(status)) {
                ZwClose(fileHandle);
                RtlFreeUnicodeString(&unicodePath);
                FreeApiMemory(path);
                return status;
            }
            if (ioStatus.Information == 0) {
                ZwClose(fileHandle);
                RtlFreeUnicodeString(&unicodePath);
                FreeApiMemory(path);
                return STATUS_UNSUCCESSFUL;
            }
            totalRead += static_cast<SIZE_T>(ioStatus.Information);
        }

        request.OwnedBodyLength = required;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        ZwClose(fileHandle);
        RtlFreeUnicodeString(&unicodePath);
        FreeApiMemory(path);
        return STATUS_SUCCESS;
#endif
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
        ReleaseOwnedBody(request);
        FreeApiMemory(request.OwnedTlsServerName);
        FreeApiMemory(request.OwnedTlsAlpn);
        request.OwnedTlsServerName = nullptr;
        request.OwnedTlsAlpn = nullptr;

        for (SIZE_T index = 0; index < request.HeaderCount && index < KhMaxHeadersPerRequest; ++index) {
            ReleaseStoredHeader(request.Headers[index]);
        }
        request.HeaderCount = 0;
    }

    _Must_inspect_result_
    NTSTATUS CloneRequestForAsync(_In_ const KhRequest& source, _Out_ KH_REQUEST* clonedRequest) noexcept
    {
        if (clonedRequest != nullptr) {
            *clonedRequest = nullptr;
        }

        if (clonedRequest == nullptr || !IsRequestHandle(const_cast<KH_REQUEST>(&source))) {
            return STATUS_INVALID_PARAMETER;
        }

        KH_REQUEST clone = AllocateRequestHandle();
        if (clone == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        clone->Header = { KhHandleKind::Request, false };
        clone->Session = source.Session;
        clone->Method = source.Method;
        clone->UrlLength = source.UrlLength;
        clone->SchemeLength = source.SchemeLength;
        clone->HostLength = source.HostLength;
        clone->PathLength = source.PathLength;
        clone->Port = source.Port;
        clone->Tls = source.Tls;
        clone->HasTlsOverride = source.HasTlsOverride;
        clone->ConnectionPolicy = source.ConnectionPolicy;
        clone->AddressFamily = source.AddressFamily;
        RtlCopyMemory(clone->Scheme, source.Scheme, sizeof(clone->Scheme));
        RtlCopyMemory(clone->Host, source.Host, sizeof(clone->Host));
        RtlCopyMemory(clone->Path, source.Path, sizeof(clone->Path));
        RtlCopyMemory(clone->MultipartBoundary, source.MultipartBoundary, sizeof(clone->MultipartBoundary));

        if (source.Url != nullptr && source.UrlLength != 0) {
            clone->Url = AllocateTextCopy(source.Url, source.UrlLength);
            if (clone->Url == nullptr) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        if (source.Tls.ServerName == source.Host) {
            clone->Tls.ServerName = clone->Host;
            clone->Tls.ServerNameLength = clone->HostLength;
        }
        else if (source.Tls.ServerName != nullptr && source.Tls.ServerNameLength != 0) {
            clone->OwnedTlsServerName = AllocateTextCopy(source.Tls.ServerName, source.Tls.ServerNameLength);
            if (clone->OwnedTlsServerName == nullptr) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            clone->Tls.ServerName = clone->OwnedTlsServerName;
        }

        if (source.Tls.Alpn != nullptr && source.Tls.AlpnLength != 0) {
            clone->OwnedTlsAlpn = AllocateTextCopy(source.Tls.Alpn, source.Tls.AlpnLength);
            if (clone->OwnedTlsAlpn == nullptr) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            clone->Tls.Alpn = clone->OwnedTlsAlpn;
        }

        if (source.HasBody && source.BodyLength != 0) {
            NTSTATUS status = BeginOwnedBodyBuild(*clone);
            if (NT_SUCCESS(status)) {
                status = AppendOwnedBody(*clone, source.Body, source.BodyLength);
            }
            if (!NT_SUCCESS(status)) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return status;
            }
        }
        else {
            clone->HasBody = source.HasBody;
            clone->Body = nullptr;
            clone->BodyLength = 0;
        }

        for (SIZE_T index = 0; index < source.HeaderCount && index < KhMaxHeadersPerRequest; ++index) {
            NTSTATUS status = AddStoredHeader(
                *clone,
                source.Headers[index].Name,
                source.Headers[index].NameLength,
                source.Headers[index].Value,
                source.Headers[index].ValueLength);
            if (!NT_SUCCESS(status)) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return status;
            }
        }

        *clonedRequest = clone;
        return STATUS_SUCCESS;
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

        KH_SESSION newSession = AllocateSessionHandle();
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

        newSession->ProviderCache = AllocateProviderCacheHandle();
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

        status = KhConnectionPoolInitialize(
            &newSession->ConnectionPool,
            effectiveOptions.ConnectionPoolCapacity);
        if (!NT_SUCCESS(status)) {
            newSession->ProviderCache->Shutdown();
            FreeHandle(newSession->ProviderCache);
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
            FreeHandle(session->ProviderCache);
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

        KH_REQUEST newRequest = AllocateRequestHandle();
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

        HeapObject<KhRequest> parsed;
        if (!parsed.IsValid()) {
            FreeApiMemory(urlCopy);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS parseStatus = ParseUrlIntoRequest(*parsed.Get(), urlCopy, urlLength);
        if (!NT_SUCCESS(parseStatus)) {
            FreeApiMemory(urlCopy);
            return parseStatus;
        }

        FreeApiMemory(request->Url);
        request->Url = urlCopy;
        request->UrlLength = urlLength;
        RtlCopyMemory(request->Scheme, parsed->Scheme, sizeof(request->Scheme));
        request->SchemeLength = parsed->SchemeLength;
        RtlCopyMemory(request->Host, parsed->Host, sizeof(request->Host));
        request->HostLength = parsed->HostLength;
        RtlCopyMemory(request->Path, parsed->Path, sizeof(request->Path));
        request->PathLength = parsed->PathLength;
        request->Port = parsed->Port;

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
        case KhHttpMethod::Options:
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

        return AddStoredHeader(*request, name, nameLength, value, valueLength);
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

        ReleaseOwnedBody(*request);
        request->Body = body;
        request->BodyLength = bodyLength;
        request->HasBody = body != nullptr || bodyLength != 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS KhHttpRequestClearBody(KH_REQUEST request) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        ReleaseOwnedBody(*request);
        RemoveStoredHeadersByName(*request, "Content-Type");
        return STATUS_SUCCESS;
    }

    NTSTATUS KhHttpRequestSetTextBody(
        KH_REQUEST request,
        const char* text,
        SIZE_T textLength,
        const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            (text == nullptr && textLength != 0) ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendOwnedText(*request, text, textLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        if (contentType == nullptr) {
            const http::HttpText defaultType = http::MakeText("text/plain; charset=utf-8");
            contentType = defaultType.Data;
            contentTypeLength = defaultType.Length;
        }

        return ReplaceContentType(*request, contentType, contentTypeLength);
    }

    NTSTATUS KhHttpRequestSetRawBody(
        KH_REQUEST request,
        const UCHAR* data,
        SIZE_T dataLength,
        const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            (data == nullptr && dataLength != 0) ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendOwnedBody(*request, data, dataLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        if (contentType != nullptr) {
            status = ReplaceContentType(*request, contentType, contentTypeLength);
        }

        return status;
    }

    NTSTATUS KhHttpRequestSetUrlEncodedBody(
        KH_REQUEST request,
        const KhNameValuePair* pairs,
        SIZE_T pairCount) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            pairs == nullptr ||
            pairCount == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < pairCount; ++index) {
            const KhNameValuePair& pair = pairs[index];
            if (pair.Name == nullptr ||
                pair.NameLength == 0 ||
                (pair.Value == nullptr && pair.ValueLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < pairCount; ++index) {
            if (index != 0) {
                status = AppendOwnedLiteral(*request, "&");
                if (!NT_SUCCESS(status)) {
                    AbortOwnedBodyBuild(*request);
                    return status;
                }
            }

            status = AppendUrlEncodedText(*request, pairs[index].Name, pairs[index].NameLength);
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
            status = AppendOwnedLiteral(*request, "=");
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
            status = AppendUrlEncodedText(*request, pairs[index].Value, pairs[index].ValueLength);
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
        }

        const http::HttpText contentType = http::MakeText("application/x-www-form-urlencoded");
        return ReplaceContentType(*request, contentType.Data, contentType.Length);
    }

    NTSTATUS KhHttpRequestSetMultipartFormDataBody(
        KH_REQUEST request,
        const KhMultipartFormDataPart* parts,
        SIZE_T partCount) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            parts == nullptr ||
            partCount == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < partCount; ++index) {
            const KhMultipartFormDataPart& part = parts[index];
            if (part.Name == nullptr ||
                part.NameLength == 0 ||
                !IsOptionalTextValid(part.FileName, part.FileNameLength) ||
                !IsOptionalTextValid(part.ContentType, part.ContentTypeLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            switch (part.Kind) {
            case KhRequestBodyPartKind::Field:
                if (part.Value == nullptr && part.ValueLength != 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                break;
            case KhRequestBodyPartKind::FileBytes:
                if ((part.Data == nullptr && part.DataLength != 0) ||
                    part.FileName == nullptr ||
                    part.FileNameLength == 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                break;
            case KhRequestBodyPartKind::FilePath:
                if (part.FilePath == nullptr || part.FilePathLength == 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                break;
            default:
                return STATUS_INVALID_PARAMETER;
            }
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T boundaryLength = 0;
        status = GenerateMultipartBoundary(*request, &boundaryLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        for (SIZE_T index = 0; index < partCount; ++index) {
            const KhMultipartFormDataPart& part = parts[index];
            const char* fileName = part.FileName;
            SIZE_T fileNameLength = part.FileNameLength;
            if (part.Kind == KhRequestBodyPartKind::FilePath && fileName == nullptr) {
                DeriveFileNameFromPath(part.FilePath, part.FilePathLength, &fileName, &fileNameLength);
                if (fileName == nullptr || fileNameLength == 0) {
                    AbortOwnedBodyBuild(*request);
                    return STATUS_INVALID_PARAMETER;
                }
            }

            status = AppendMultipartPartHeader(
                *request,
                request->MultipartBoundary,
                boundaryLength,
                part.Name,
                part.NameLength,
                fileName,
                fileNameLength,
                part.ContentType,
                part.ContentTypeLength);
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }

            if (part.Kind == KhRequestBodyPartKind::Field) {
                status = AppendOwnedText(*request, part.Value, part.ValueLength);
            }
            else if (part.Kind == KhRequestBodyPartKind::FileBytes) {
                status = AppendOwnedBody(*request, part.Data, part.DataLength);
            }
            else {
                status = AppendFileToOwnedBody(*request, part.FilePath, part.FilePathLength);
            }
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }

            status = AppendOwnedLiteral(*request, "\r\n");
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
        }

        status = AppendOwnedLiteral(*request, "--");
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }
        status = AppendOwnedText(*request, request->MultipartBoundary, boundaryLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }
        status = AppendOwnedLiteral(*request, "--\r\n");
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        return SetMultipartContentType(*request, request->MultipartBoundary, boundaryLength);
    }

    NTSTATUS KhHttpRequestSetFileBody(
        KH_REQUEST request,
        const char* filePath,
        SIZE_T filePathLength,
        const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            filePath == nullptr ||
            filePathLength == 0 ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendFileToOwnedBody(*request, filePath, filePathLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        if (contentType == nullptr) {
            const http::HttpText defaultType = http::MakeText("application/octet-stream");
            contentType = defaultType.Data;
            contentTypeLength = defaultType.Length;
        }

        return ReplaceContentType(*request, contentType, contentTypeLength);
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

    NTSTATUS KhHttpRequestSetAddressFamily(KH_REQUEST request, KhAddressFamily addressFamily) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || !IsValidAddressFamily(addressFamily)) {
            return STATUS_INVALID_PARAMETER;
        }

        request->AddressFamily = addressFamily;
        return STATUS_SUCCESS;
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

    SIZE_T KhResponseHeaderCount(KH_RESPONSE response) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || !IsResponseHandle(response)) {
            return 0;
        }

        return response->HeaderCount;
    }

    NTSTATUS KhResponseGetHeaderAt(
        KH_RESPONSE response,
        SIZE_T index,
        const char** name,
        SIZE_T* nameLength,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (name != nullptr) {
            *name = nullptr;
        }
        if (nameLength != nullptr) {
            *nameLength = 0;
        }
        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }

        if (!IsResponseHandle(response) ||
            name == nullptr ||
            nameLength == nullptr ||
            value == nullptr ||
            valueLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (index >= response->HeaderCount) {
            return STATUS_NOT_FOUND;
        }

        const http::HttpHeader& header = response->Headers[index];
        *name = header.Name.Data;
        *nameLength = header.Name.Length;
        *value = header.Value.Data;
        *valueLength = header.Value.Length;
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
        ReleaseResponseStorage(*response);
        FreeHandle(response);
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
