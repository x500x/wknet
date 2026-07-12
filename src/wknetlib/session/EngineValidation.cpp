#include "session/EnginePrivate.hpp"

namespace wknet
{
namespace session
{
    bool IsPassiveLevel() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return g_testCurrentIrql == PassiveLevel;
#else
        return KeGetCurrentIrql() == PASSIVE_LEVEL;
#endif
    }

    NTSTATUS CheckPassiveLevel() noexcept
    {
        return IsPassiveLevel() ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
    }

    SIZE_T NormalizeMaxResponseBytes(SIZE_T value) noexcept
    {
        return value;
    }

    bool IsValidMaxResponseBytes(SIZE_T value) noexcept
    {
        UNREFERENCED_PARAMETER(value);
        return true;
    }

    bool IsValidMaxResponseHeaders(SIZE_T value) noexcept
    {
        return value != 0 && value <= WKNET_HARD_MAX_HEADERS;
    }

    bool IsValidHttp2MaxHeaderBlockBytes(SIZE_T value) noexcept
    {
        return value != 0 && value <= MaxHttp2HeaderBlockBytes;
    }

    bool IsValidMaxMessageBytes(SIZE_T value) noexcept
    {
        return value > 0;
    }

    bool IsWebSocketSubprotocolSeparator(char value) noexcept
    {
        switch (value) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        case '\t':
            return true;
        default:
            return false;
        }
    }

    bool IsValidWebSocketSubprotocolToken(const char* token, SIZE_T length) noexcept
    {
        if (token == nullptr || length == 0) {
            return false;
        }

        for (SIZE_T index = 0; index < length; ++index) {
            const unsigned char value = static_cast<unsigned char>(token[index]);
            if (value <= 0x20 || value >= 0x7f || IsWebSocketSubprotocolSeparator(token[index])) {
                return false;
            }
        }
        return true;
    }

    bool IsValidWebSocketSubprotocolList(const char* value, SIZE_T length) noexcept
    {
        if (value == nullptr && length == 0) {
            return true;
        }
        if (value == nullptr || length == 0) {
            return false;
        }

        SIZE_T index = 0;
        for (;;) {
            while (index < length && (value[index] == ' ' || value[index] == '\t')) {
                ++index;
            }

            const SIZE_T tokenStart = index;
            while (index < length && value[index] != ',') {
                ++index;
            }

            SIZE_T tokenEnd = index;
            while (tokenEnd > tokenStart &&
                (value[tokenEnd - 1] == ' ' || value[tokenEnd - 1] == '\t')) {
                --tokenEnd;
            }

            if (!IsValidWebSocketSubprotocolToken(value + tokenStart, tokenEnd - tokenStart)) {
                return false;
            }

            if (index == length) {
                break;
            }
            ++index;
            if (index == length) {
                return false;
            }
        }

        return true;
    }

    SIZE_T EffectiveMaxResponseBytes(const HttpSendOptions* options, SIZE_T sessionValue) noexcept
    {
        if (options != nullptr && options->MaxResponseBytes != 0) {
            return NormalizeMaxResponseBytes(options->MaxResponseBytes);
        }

        return NormalizeMaxResponseBytes(sessionValue);
    }

    bool IsValidTlsOptions(const TlsOptions& options) noexcept
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

        if (options.AlpnLength > PoolMaxAlpnLength) {
            return false;
        }

        if (options.HandshakeReceiveTimeoutMilliseconds == 0) {
            return false;
        }

        if (options.MaxTls12Renegotiations > HardMaxTls12Renegotiations) {
            return false;
        }

        return NT_SUCCESS(tls::TlsValidatePolicy(options.Policy));
    }

    bool IsValidProxyAuthorityText(const char* text, SIZE_T textLength) noexcept
    {
        if (text == nullptr || textLength == 0 || textLength > PoolMaxProxyAuthorityLength) {
            return false;
        }

        for (SIZE_T index = 0; index < textLength; ++index) {
            const unsigned char value = static_cast<unsigned char>(text[index]);
            if (value <= 0x20 || value == 0x7f) {
                return false;
            }
        }

        return true;
    }

    bool IsValidProxyHeaderValueText(const char* text, SIZE_T textLength) noexcept
    {
        if (text == nullptr || textLength == 0 || textLength > MaxHeaderValueLength) {
            return false;
        }

        for (SIZE_T index = 0; index < textLength; ++index) {
            const unsigned char value = static_cast<unsigned char>(text[index]);
            if (text[index] != '\t' && (value < 0x20 || value == 0x7f)) {
                return false;
            }
        }

        return true;
    }

    bool IsValidProxyOptions(const ProxyOptions& options) noexcept
    {
        if (!options.Enabled) {
            return options.Host == nullptr &&
                options.HostLength == 0 &&
                options.Port == 0 &&
                options.Family == AddressFamily::Any &&
                options.Authority == nullptr &&
                options.AuthorityLength == 0 &&
                options.AuthHeader == nullptr &&
                options.AuthHeaderLength == 0;
        }

        if (options.Host == nullptr ||
            options.HostLength == 0 ||
            options.HostLength > MaxHostLength ||
            options.Port == 0 ||
            (options.Family != AddressFamily::Any &&
                options.Family != AddressFamily::Ipv4 &&
                options.Family != AddressFamily::Ipv6)) {
            return false;
        }

        if (!IsValidProxyAuthorityText(options.Authority, options.AuthorityLength)) {
            return false;
        }

        if (options.AuthHeader == nullptr) {
            return options.AuthHeaderLength == 0;
        }

        return IsValidProxyHeaderValueText(options.AuthHeader, options.AuthHeaderLength);
    }

    bool IsValidHttp11PipelineOptions(const SessionOptions& options) noexcept
    {
        if (options.Http11PipelineMaxDepth == 0 ||
            options.Http11PipelineMaxDepth > MaxHttp11PipelineDepth ||
            options.Http11PipelineMethodMask == 0 ||
            (options.Http11PipelineMethodMask & ~Http11PipelineKnownMethodMask) != 0) {
            return false;
        }

        return true;
    }

    Http2KeepAliveOptions NormalizeHttp2KeepAliveOptions(
        const Http2KeepAliveOptions& options) noexcept
    {
        Http2KeepAliveOptions normalized = options;
        if (normalized.IdleMilliseconds == 0) {
            normalized.IdleMilliseconds = DefaultHttp2KeepAliveIdleMilliseconds;
        }
        if (normalized.IntervalMilliseconds == 0) {
            normalized.IntervalMilliseconds = DefaultHttp2KeepAliveIntervalMilliseconds;
        }
        if (normalized.AckTimeoutMilliseconds == 0) {
            normalized.AckTimeoutMilliseconds = DefaultHttp2KeepAliveAckTimeoutMilliseconds;
        }
        return normalized;
    }

    bool IsValidHttp2KeepAliveOptions(const Http2KeepAliveOptions& options) noexcept
    {
        if (!options.Enabled) {
            return true;
        }

        return options.IdleMilliseconds != 0 &&
            options.IntervalMilliseconds != 0 &&
            options.AckTimeoutMilliseconds != 0 &&
            options.AckTimeoutMilliseconds <= WskOperationTimeoutMilliseconds;
    }

    bool IsValidSessionOptions(const SessionOptions& options) noexcept
    {
        if (options.RequestBufferBytes == 0) {
            return false;
        }

        if (!IsValidMaxResponseBytes(options.MaxResponseBytes)) {
            return false;
        }

        if (!IsValidMaxResponseHeaders(options.MaxResponseHeaders)) {
            return false;
        }

        if (!IsValidHttp2MaxHeaderBlockBytes(options.Http2MaxHeaderBlockBytes)) {
            return false;
        }

        if (options.ResponsePoolType != PoolType::NonPaged) {
            return false;
        }

        if (options.ConnectionPoolCapacity == 0 ||
            options.ConnectionPoolCapacity > MaxConnectionPoolCapacity ||
            options.MaxConnectionsPerHost == 0 ||
            options.MaxConnectionsPerHost > MaxConnectionPoolCapacity ||
            options.MaxConnectionsPerHost > options.ConnectionPoolCapacity) {
            return false;
        }

        return IsValidHttp11PipelineOptions(options) &&
            IsValidHttp2KeepAliveOptions(options.Http2KeepAlive) &&
            IsValidTlsOptions(options.Tls) &&
            IsValidProxyOptions(options.Proxy);
    }

    bool IsValidAddressFamily(AddressFamily addressFamily) noexcept
    {
        return addressFamily == AddressFamily::Any ||
            addressFamily == AddressFamily::Ipv4 ||
            addressFamily == AddressFamily::Ipv6;
    }

    bool IsValidHttp2CleartextMode(Http2CleartextMode mode) noexcept
    {
        return mode == Http2CleartextMode::Disabled ||
            mode == Http2CleartextMode::PriorKnowledge ||
            mode == Http2CleartextMode::Upgrade;
    }

    bool IsValidWebSocketTransportMode(WebSocketTransportMode mode) noexcept
    {
        return mode == WebSocketTransportMode::LegacyBoolean ||
            mode == WebSocketTransportMode::Http11Only ||
            mode == WebSocketTransportMode::Auto ||
            mode == WebSocketTransportMode::Http2Required;
    }

    net::WskAddressFamily ToWskAddressFamily(AddressFamily addressFamily) noexcept
    {
        switch (addressFamily) {
        case AddressFamily::Ipv4:
            return net::WskAddressFamily::Ipv4;
        case AddressFamily::Ipv6:
            return net::WskAddressFamily::Ipv6;
        case AddressFamily::Any:
        default:
            return net::WskAddressFamily::Any;
        }
    }

    bool IsValidSendOptions(const HttpSendOptions& options, const Session& session) noexcept;
    void ReleaseResponseStorage(_Inout_ Response& response) noexcept;

    bool IsValidWebSocketConnectOptions(const WebSocketConnectOptions& options) noexcept
    {
        constexpr ULONG MaxWebSocketHandshakeRetries = 10;

        if (options.Url == nullptr || options.UrlLength == 0) {
            return false;
        }

        if (options.Subprotocol == nullptr && options.SubprotocolLength != 0) {
            return false;
        }

        if (options.Subprotocol != nullptr && options.SubprotocolLength == 0) {
            return false;
        }

        if (!IsValidMaxMessageBytes(options.MaxMessageBytes) ||
            !IsValidWebSocketSubprotocolList(options.Subprotocol, options.SubprotocolLength)) {
            return false;
        }

        return IsValidTlsOptions(options.Tls) &&
            IsValidAddressFamily(options.AddressFamily) &&
            IsValidWebSocketTransportMode(options.TransportMode) &&
            ws::IsValidPerMessageDeflateOptions(options.PerMessageDeflate) &&
            !(options.ChallengeCallback == nullptr && options.ChallengeContext != nullptr) &&
            options.MaxHandshakeRetries <= MaxWebSocketHandshakeRetries;
    }

    bool IsValidReceiveOptions(const WebSocketReceiveOptions& options) noexcept
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

#if defined(WKNET_USER_MODE_TEST)
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

#if defined(WKNET_USER_MODE_TEST)
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
        return TextEqualsIgnoreCase(left, leftLength, right, http1::MakeText(right).Length);
    }

    bool TextEqualsLiteral(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept
    {
        const SIZE_T rightLength = http1::MakeText(right).Length;
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

    bool IsOrderlyConnectionCloseStatus(NTSTATUS status) noexcept
    {
        return status == STATUS_CONNECTION_DISCONNECTED;
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

    bool IsSessionHandle(SessionHandle session) noexcept;
    bool IsRequestHandle(RequestHandle request) noexcept;
    bool IsResponseHandle(ResponseHandle response) noexcept;
    bool IsWebSocketHandle(WebSocketHandle websocket) noexcept;

    bool IsValidSendOptions(const HttpSendOptions& options, const Session& session) noexcept
    {
        UNREFERENCED_PARAMETER(session);

        constexpr ULONG knownFlags =
            HttpSendFlagAggregateWithCallbacks |
            HttpSendFlagDisableAutoRedirect |
            HttpSendFlagExpectContinue |
            HttpSendFlagAllowTrace |
            HttpSendFlagBypassCache |
            HttpSendFlagNoCacheStore |
            HttpSendFlagOnlyIfCached;

        if (!IsValidMaxResponseBytes(options.MaxResponseBytes)) {
            return false;
        }

        if ((options.Flags & ~knownFlags) != 0) {
            return false;
        }

        if (options.ExpectContinueTimeoutMilliseconds > MaxExpectContinueTimeoutMilliseconds) {
            return false;
        }

        if (!IsValidHttp2CleartextMode(options.Http2CleartextMode)) {
            return false;
        }

        if (!NT_SUCCESS(http1::HttpContentEncoding::ValidateAcceptEncodingPreferences(
            options.AcceptEncodingPreferences,
            options.AcceptEncodingPreferenceCount))) {
            return false;
        }

        if (options.ContentCodingMaterials != nullptr &&
            options.ContentCodingMaterials->Items == nullptr &&
            options.ContentCodingMaterials->ItemCount != 0) {
            return false;
        }

        if (options.HeaderCallback == nullptr && options.BodyCallback == nullptr && options.CallbackContext != nullptr) {
            return false;
        }

        if (options.BodyCallback == nullptr && ((options.Flags & HttpSendFlagAggregateWithCallbacks) != 0)) {
            return false;
        }

        return true;
    }


}
}
