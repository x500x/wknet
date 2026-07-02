#pragma once

#include <KernelHttp/engine/Engine.h>

namespace KernelHttp
{
namespace net
{
    class WskSocket;
}

namespace core
{
    class ITransport;
    class WskTransport;
}

namespace tls
{
    class TlsConnection;
}

namespace http2
{
    class Http2Connection;
}

namespace engine
{
    constexpr SIZE_T KhPoolMaxHostLength = 255;
    constexpr SIZE_T KhPoolMaxTlsServerNameLength = 255;
    constexpr SIZE_T KhPoolMaxAlpnLength = 16;
    constexpr SIZE_T KhPoolMaxProxyAuthorityLength = 255;

    struct KhConnectionPoolKey final
    {
        char Scheme[6] = {};
        SIZE_T SchemeLength = 0;
        char Host[KhPoolMaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        net::WskAddressFamily AddressFamily = net::WskAddressFamily::Any;
        KhTlsVersion MinTlsVersion = KhTlsVersion::Tls12;
        KhTlsVersion MaxTlsVersion = KhTlsVersion::Tls13;
        KhCertificatePolicy CertificatePolicy = KhCertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        const tls::TlsClientCredential* ClientCredential = nullptr;
        tls::TlsPolicy Policy = {};
        char TlsServerName[KhPoolMaxTlsServerNameLength + 1] = {};
        SIZE_T TlsServerNameLength = 0;
        char Alpn[KhPoolMaxAlpnLength + 1] = {};
        SIZE_T AlpnLength = 0;
        bool AutomaticAlpn = false;
        KhHttp2CleartextMode Http2CleartextMode = KhHttp2CleartextMode::Disabled;
        bool ProxyEnabled = false;
        SOCKADDR_STORAGE ProxyAddress = {};
        char ProxyAuthority[KhPoolMaxProxyAuthorityLength + 1] = {};
        SIZE_T ProxyAuthorityLength = 0;
    };

    struct KhPooledConnection final
    {
        bool InUse = false;
        bool Connected = false;
        ULONG Id = 0;
        ULONGLONG LastUsedTime = 0;
        ULONG Http2StreamLeases = 0;
        ULONG Http2MaxStreamLeases = 0;
        bool CloseWhenIdle = false;
        bool ProxyTunnelEstablished = false;
        KhConnectionPoolKey Key = {};
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        net::WskSocket* Socket = nullptr;
        core::WskTransport* RawTransport = nullptr;
        core::ITransport* Transport = nullptr;
        tls::TlsConnection* Tls = nullptr;
        http2::Http2Connection* Http2 = nullptr;
#endif
    };

    struct KhConnectionPool final
    {
        KhPooledConnection* Entries = nullptr;
        ULONG Capacity = 0;
        ULONG ActiveCount = 0;
        ULONG MaxConnectionsPerHost = 0;
        ULONG NextConnectionId = 1;
        ULONG IdleTimeoutMilliseconds = 0;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        FAST_MUTEX Lock = {};
#endif
    };

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolInitialize(
        _Inout_ KhConnectionPool* pool,
        ULONG capacity,
        ULONG maxConnectionsPerHost,
        ULONG idleTimeoutMilliseconds) noexcept;

    void KhConnectionPoolShutdown(_Inout_ KhConnectionPool* pool) noexcept;

    _Must_inspect_result_
    bool KhConnectionPoolKeysEqual(
        _In_ const KhConnectionPoolKey& left,
        _In_ const KhConnectionPoolKey& right) noexcept;

    _Must_inspect_result_
    bool KhConnectionPoolKeysEqualForAutoAlpnAcquire(
        _In_ const KhConnectionPoolKey& left,
        _In_ const KhConnectionPoolKey& right) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolAcquire(
        _Inout_ KhConnectionPool* pool,
        _In_ const KhConnectionPoolKey& key,
        KhConnectionPolicy policy,
        _Outptr_ KhPooledConnection** connection,
        _Out_ bool* reused) noexcept;

    void KhConnectionPoolRelease(
        _Inout_ KhConnectionPool* pool,
        _Inout_opt_ KhPooledConnection* connection,
        bool reusable) noexcept;

    _Must_inspect_result_
    bool KhConnectionPoolHasHttp2StreamLease(
        _In_opt_ const KhPooledConnection* connection) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolPromoteHttp2StreamLease(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        ULONG maxConcurrentStreams) noexcept;

    void KhConnectionPoolClose(
        _Inout_ KhConnectionPool* pool,
        _Inout_opt_ KhPooledConnection* connection) noexcept;
}
}
