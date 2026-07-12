#pragma once

#include <wknet/engine/Engine.h>

namespace wknet
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

namespace session
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
        ULONG MaxTls12Renegotiations = KhDefaultMaxTls12Renegotiations;
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
        ULONG Http1PipelineLeases = 0;
        ULONG Http1MaxPipelineLeases = 0;
        ULONG Http1PipelineNextSequence = 1;
        ULONG Http1PipelineNextReceiveSequence = 1;
        NTSTATUS Http1PipelineFailureStatus = STATUS_SUCCESS;
        UCHAR* Http1PipelineBufferedBytes = nullptr;
        SIZE_T Http1PipelineBufferedLength = 0;
        SIZE_T Http1PipelineBufferedCapacity = 0;
        bool CloseWhenIdle = false;
        bool ProxyTunnelEstablished = false;
        bool Http2KeepAliveInProgress = false;
        ULONGLONG Http2LastKeepAliveTime = 0;
        ULONGLONG Http2KeepAliveSequence = 0;
        UCHAR Http2KeepAliveOpaqueData[8] = {};
        KhConnectionPoolKey Key = {};
#if !defined(WKNET_USER_MODE_TEST)
        KMUTEX Http1PipelineSendLock = {};
        KEVENT Http1PipelineReceiveEvent = {};
#endif
#if !defined(WKNET_USER_MODE_TEST)
        net::WskSocket* Socket = nullptr;
        core::WskTransport* RawTransport = nullptr;
        tls::TlsConnection* Tls = nullptr;
#endif
        core::ITransport* Transport = nullptr;
        http2::Http2Connection* Http2 = nullptr;
    };

    struct KhConnectionPool final
    {
        KhPooledConnection* Entries = nullptr;
        ULONG Capacity = 0;
        ULONG ActiveCount = 0;
        ULONG MaxConnectionsPerHost = 0;
        ULONG NextConnectionId = 1;
        ULONG IdleTimeoutMilliseconds = 0;
        KhHttp2KeepAliveOptions Http2KeepAlive = {};
#if !defined(WKNET_USER_MODE_TEST)
        FAST_MUTEX Lock = {};
        KEVENT Http2KeepAliveStopEvent = {};
        PETHREAD Http2KeepAliveThread = nullptr;
        volatile LONG Http2KeepAliveWorkerStarted = 0;
        volatile LONG Http2KeepAliveStopping = 0;
#endif
    };

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolInitialize(
        _Inout_ KhConnectionPool* pool,
        ULONG capacity,
        ULONG maxConnectionsPerHost,
        ULONG idleTimeoutMilliseconds,
        _In_opt_ const KhHttp2KeepAliveOptions* http2KeepAlive = nullptr) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolStartHttp2KeepAlive(_Inout_ KhConnectionPool* pool) noexcept;

    void KhConnectionPoolStopHttp2KeepAlive(_Inout_opt_ KhConnectionPool* pool) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolRunHttp2KeepAliveSweep(
        _Inout_ KhConnectionPool* pool,
        _Out_opt_ bool* attempted) noexcept;

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

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolAcquireHttp1Pipeline(
        _Inout_ KhConnectionPool* pool,
        _In_ const KhConnectionPoolKey& key,
        KhConnectionPolicy policy,
        ULONG maxPipelineLeases,
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

    _Must_inspect_result_
    bool KhConnectionPoolHasHttp1PipelineLease(
        _In_opt_ const KhPooledConnection* connection) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolPromoteHttp1PipelineLease(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        ULONG maxPipelineLeases) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolBeginHttp1PipelineSend(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        _Out_ ULONG* sequence) noexcept;

    void KhConnectionPoolEndHttp1PipelineSend(
        _Inout_opt_ KhPooledConnection* connection) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolWaitHttp1PipelineReceiveTurn(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        ULONG sequence) noexcept;

    void KhConnectionPoolCompleteHttp1PipelineReceive(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        ULONG sequence) noexcept;

    void KhConnectionPoolFailHttp1Pipeline(
        _Inout_ KhConnectionPool* pool,
        _Inout_opt_ KhPooledConnection* connection,
        NTSTATUS status) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolHttp1PipelineBufferedLength(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        _Out_ SIZE_T* length) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolTakeHttp1PipelineBufferedBytes(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* bytesCopied) noexcept;

    _Must_inspect_result_
    NTSTATUS KhConnectionPoolStoreHttp1PipelineBufferedBytes(
        _Inout_ KhConnectionPool* pool,
        _Inout_ KhPooledConnection* connection,
        _In_reads_bytes_(length) const UCHAR* bytes,
        SIZE_T length) noexcept;

    void KhConnectionPoolClose(
        _Inout_ KhConnectionPool* pool,
        _Inout_opt_ KhPooledConnection* connection) noexcept;
}
}
