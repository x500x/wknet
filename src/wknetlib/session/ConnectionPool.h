#pragma once

#include "session/Engine.h"

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
    constexpr SIZE_T PoolMaxHostLength = 255;
    constexpr SIZE_T PoolMaxTlsServerNameLength = 255;
    constexpr SIZE_T PoolMaxAlpnLength = 16;
    constexpr SIZE_T PoolMaxProxyAuthorityLength = 255;

    struct ConnectionPoolKey final
    {
        char Scheme[6] = {};
        SIZE_T SchemeLength = 0;
        char Host[PoolMaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        net::WskAddressFamily AddressFamily = net::WskAddressFamily::Any;
        TlsVersion MinTlsVersion = TlsVersion::Tls12;
        TlsVersion MaxTlsVersion = TlsVersion::Tls13;
        CertificatePolicy CertificatePolicy = CertificatePolicy::Verify;
        const tls::CertificateStore* CertificateStore = nullptr;
        const tls::TlsClientCredential* ClientCredential = nullptr;
        tls::TlsPolicy Policy = {};
        ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations;
        char TlsServerName[PoolMaxTlsServerNameLength + 1] = {};
        SIZE_T TlsServerNameLength = 0;
        char Alpn[PoolMaxAlpnLength + 1] = {};
        SIZE_T AlpnLength = 0;
        bool AutomaticAlpn = false;
        Http2CleartextMode Http2CleartextMode = Http2CleartextMode::Disabled;
        bool ProxyEnabled = false;
        SOCKADDR_STORAGE ProxyAddress = {};
        char ProxyAuthority[PoolMaxProxyAuthorityLength + 1] = {};
        SIZE_T ProxyAuthorityLength = 0;
    };

    struct PooledConnection final
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
        ConnectionPoolKey Key = {};
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

    struct ConnectionPool final
    {
        PooledConnection* Entries = nullptr;
        ULONG Capacity = 0;
        ULONG ActiveCount = 0;
        ULONG MaxConnectionsPerHost = 0;
        ULONG NextConnectionId = 1;
        ULONG IdleTimeoutMilliseconds = 0;
        Http2KeepAliveOptions Http2KeepAlive = {};
#if !defined(WKNET_USER_MODE_TEST)
        FAST_MUTEX Lock = {};
        KEVENT Http2KeepAliveStopEvent = {};
        PETHREAD Http2KeepAliveThread = nullptr;
        volatile LONG Http2KeepAliveWorkerStarted = 0;
        volatile LONG Http2KeepAliveStopping = 0;
#endif
    };

    _Must_inspect_result_
    NTSTATUS ConnectionPoolInitialize(
        _Inout_ ConnectionPool* pool,
        ULONG capacity,
        ULONG maxConnectionsPerHost,
        ULONG idleTimeoutMilliseconds,
        _In_opt_ const Http2KeepAliveOptions* http2KeepAlive = nullptr) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolStartHttp2KeepAlive(_Inout_ ConnectionPool* pool) noexcept;

    void ConnectionPoolStopHttp2KeepAlive(_Inout_opt_ ConnectionPool* pool) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolRunHttp2KeepAliveSweep(
        _Inout_ ConnectionPool* pool,
        _Out_opt_ bool* attempted) noexcept;

    void ConnectionPoolShutdown(_Inout_ ConnectionPool* pool) noexcept;

    _Must_inspect_result_
    bool ConnectionPoolKeysEqual(
        _In_ const ConnectionPoolKey& left,
        _In_ const ConnectionPoolKey& right) noexcept;

    _Must_inspect_result_
    bool ConnectionPoolKeysEqualForAutoAlpnAcquire(
        _In_ const ConnectionPoolKey& left,
        _In_ const ConnectionPoolKey& right) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolAcquire(
        _Inout_ ConnectionPool* pool,
        _In_ const ConnectionPoolKey& key,
        ConnectionPolicy policy,
        _Outptr_ PooledConnection** connection,
        _Out_ bool* reused) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolAcquireHttp1Pipeline(
        _Inout_ ConnectionPool* pool,
        _In_ const ConnectionPoolKey& key,
        ConnectionPolicy policy,
        ULONG maxPipelineLeases,
        _Outptr_ PooledConnection** connection,
        _Out_ bool* reused) noexcept;

    void ConnectionPoolRelease(
        _Inout_ ConnectionPool* pool,
        _Inout_opt_ PooledConnection* connection,
        bool reusable) noexcept;

    _Must_inspect_result_
    bool ConnectionPoolHasHttp2StreamLease(
        _In_opt_ const PooledConnection* connection) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolPromoteHttp2StreamLease(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        ULONG maxConcurrentStreams) noexcept;

    _Must_inspect_result_
    bool ConnectionPoolHasHttp1PipelineLease(
        _In_opt_ const PooledConnection* connection) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolPromoteHttp1PipelineLease(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        ULONG maxPipelineLeases) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolBeginHttp1PipelineSend(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        _Out_ ULONG* sequence) noexcept;

    void ConnectionPoolEndHttp1PipelineSend(
        _Inout_opt_ PooledConnection* connection) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolWaitHttp1PipelineReceiveTurn(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        ULONG sequence) noexcept;

    void ConnectionPoolCompleteHttp1PipelineReceive(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        ULONG sequence) noexcept;

    void ConnectionPoolFailHttp1Pipeline(
        _Inout_ ConnectionPool* pool,
        _Inout_opt_ PooledConnection* connection,
        NTSTATUS status) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolHttp1PipelineBufferedLength(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        _Out_ SIZE_T* length) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolTakeHttp1PipelineBufferedBytes(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* bytesCopied) noexcept;

    _Must_inspect_result_
    NTSTATUS ConnectionPoolStoreHttp1PipelineBufferedBytes(
        _Inout_ ConnectionPool* pool,
        _Inout_ PooledConnection* connection,
        _In_reads_bytes_(length) const UCHAR* bytes,
        SIZE_T length) noexcept;

    void ConnectionPoolClose(
        _Inout_ ConnectionPool* pool,
        _Inout_opt_ PooledConnection* connection) noexcept;
}
}
