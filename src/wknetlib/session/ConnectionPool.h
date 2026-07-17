#pragma once

#include "session/Engine.h"

namespace wknet
{
namespace net
{
    class WskSocket;
}

namespace transport
{
    struct Transport;
}

namespace tls
{
    class TlsConnection;
}

namespace http2
{
    class Http2Connection;
}

namespace quic
{
class QuicConnection;
}

namespace http3
{
class Http3Connection;
}

namespace session
{
    constexpr SIZE_T PoolMaxHostLength = 255;
    constexpr SIZE_T PoolMaxTlsServerNameLength = 255;
    constexpr SIZE_T PoolMaxAlpnLength = 16;
    constexpr SIZE_T PoolMaxProxyAuthorityLength = 255;
    constexpr SIZE_T PoolMaxProxyHostLength = 255;

    enum class ConnectionKind : ULONG
    {
        None = 0,
        Tcp = 1,
        Quic = 2,
    };

    struct ConnectionPoolKey final
    {
        ConnectionKind Kind = ConnectionKind::Tcp;
        char Scheme[6] = {};
        SIZE_T SchemeLength = 0;
        char Host[PoolMaxHostLength + 1] = {};
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        net::WskAddressFamily AddressFamily = net::WskAddressFamily::Any;
        TlsVersion MinTlsVersion = TlsVersion::Tls12;
        TlsVersion MaxTlsVersion = TlsVersion::Tls13;
        CertificatePolicy CertificatePolicy = CertificatePolicy::Verify;
        // Opaque identity tokens for pool matching only. Do not dereference.
        // Equal pointers share identity; distinct non-null stores/credentials never mix
        // even if content is equivalent (caller lifetime is outside the pool).
        SIZE_T CertificateStoreIdentity = 0;
        SIZE_T ClientCredentialIdentity = 0;
        tls::TlsPolicy Policy = {};
        ULONG MaxTls12Renegotiations = DefaultMaxTls12Renegotiations;
        char TlsServerName[PoolMaxTlsServerNameLength + 1] = {};
        SIZE_T TlsServerNameLength = 0;
        char Alpn[PoolMaxAlpnLength + 1] = {};
        SIZE_T AlpnLength = 0;
        bool AutomaticAlpn = false;
        Http2CleartextMode Http2CleartextMode = Http2CleartextMode::Disabled;
        bool ProxyEnabled = false;
        char ProxyHost[PoolMaxProxyHostLength + 1] = {};
        SIZE_T ProxyHostLength = 0;
        USHORT ProxyPort = 0;
        ::wknet::session::AddressFamily ProxyFamily = ::wknet::session::AddressFamily::Any;
        char ProxyAuthority[PoolMaxProxyAuthorityLength + 1] = {};
        SIZE_T ProxyAuthorityLength = 0;
        char AlternativeHost[PoolMaxHostLength + 1] = {};
        SIZE_T AlternativeHostLength = 0;
        USHORT AlternativePort = 0;
        ULONG QuicVersion = 0;
    };

    struct ConnectionPool;
    struct PooledConnection;

    using PooledQuicCloseRoutine = void (*)(_In_opt_ void *context, _Inout_ ConnectionPool *pool,
                                            _Inout_ PooledConnection *connection,
                                            _Inout_ quic::QuicConnection *quicConnection,
                                            _Inout_ http3::Http3Connection *http3Connection) noexcept;

    struct ConnectionPool final
    {
        PooledConnection* Entries = nullptr;
        ULONG Capacity = 0;
        ULONG ActiveCount = 0;
        ULONG MaxConnectionsPerHost = 0;
        ULONG IdleTimeoutMilliseconds = 0;
        Http2KeepAliveOptions Http2KeepAlive = {};
        volatile LONG QuicCloseOutstanding = 0;
#if defined(WKNET_USER_MODE_TEST)
        // User-mode tests previously left the pool unlocked; concurrent Get races.
        volatile LONG Lock = 0;
#else
        FAST_MUTEX Lock = {};
        KEVENT Http2KeepAliveStopEvent = {};
        KEVENT QuicCloseCompleteEvent = {};
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

    _Must_inspect_result_ NTSTATUS PooledConnectionAdoptQuic(_Inout_ PooledConnection *connection,
                                                             _In_ quic::QuicConnection *quicConnection,
                                                             _In_ http3::Http3Connection *http3Connection,
                                                             PooledQuicCloseRoutine closeRoutine,
                                                             _In_opt_ void *closeContext) noexcept;

    void ConnectionPoolAbandonQuicAcquire(_Inout_ ConnectionPool *pool,
                                          _Inout_opt_ PooledConnection *connection) noexcept;

    _Ret_maybenull_ quic::QuicConnection *PooledConnectionQuic(_In_opt_ PooledConnection *connection) noexcept;

    _Ret_maybenull_ http3::Http3Connection *PooledConnectionHttp3(_In_opt_ PooledConnection *connection) noexcept;

    _Ret_maybenull_ void *PooledConnectionQuicCloseContext(_In_opt_ PooledConnection *connection) noexcept;

    _Must_inspect_result_ NTSTATUS ConnectionPoolPromoteHttp3StreamLease(_Inout_ ConnectionPool *pool,
                                                                         _Inout_ PooledConnection *connection,
                                                                         ULONGLONG streamId, ULONG peerMaxStreams,
                                                                         ULONG localMaxStreams) noexcept;

    _Must_inspect_result_ NTSTATUS ConnectionPoolBindHttp3StreamLease(_Inout_ ConnectionPool *pool,
                                                                      _Inout_ PooledConnection *connection,
                                                                      ULONGLONG streamId, ULONG peerMaxStreams,
                                                                      ULONG localMaxStreams) noexcept;

    void ConnectionPoolReleaseHttp3StreamLease(_Inout_ ConnectionPool *pool, _Inout_opt_ PooledConnection *connection,
                                               bool reusable) noexcept;

    void ConnectionPoolSetHttp3GoAway(_Inout_ ConnectionPool *pool, _Inout_ PooledConnection *connection,
                                      ULONGLONG goAwayStreamId) noexcept;

    void ConnectionPoolSetQuicActiveRequest(_Inout_ ConnectionPool *pool, _Inout_ PooledConnection *connection,
                                            bool active) noexcept;

    void ConnectionPoolSetQuicDraining(_Inout_ ConnectionPool *pool, _Inout_ PooledConnection *connection) noexcept;

    void ConnectionPoolSetQuicWorkerExited(_Inout_ ConnectionPool *pool, _Inout_ PooledConnection *connection) noexcept;

    void ConnectionPoolCompleteQuicClose(_Inout_ ConnectionPool *pool, _Inout_ PooledConnection *connection) noexcept;

#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS PooledConnectionAdoptSocket(
        _Inout_ PooledConnection* connection,
        _In_ net::WskSocket* socket,
        _In_ transport::Transport* transport) noexcept;

    _Must_inspect_result_
    NTSTATUS PooledConnectionAdoptTls(
        _Inout_ PooledConnection* connection,
        _In_ tls::TlsConnection* tlsConnection,
        _In_ transport::Transport* transport) noexcept;

    void PooledConnectionReleaseTls(_Inout_ PooledConnection* connection) noexcept;

    void PooledConnectionCloseTransportResources(_Inout_ PooledConnection* connection) noexcept;
#endif

    _Must_inspect_result_
    NTSTATUS PooledConnectionAdoptHttp2(
        _Inout_ PooledConnection* connection,
        _In_ http2::Http2Connection* http2Connection) noexcept;

    void PooledConnectionReleaseHttp2(_Inout_ PooledConnection* connection) noexcept;

    void PooledConnectionSetProxyTunnelEstablished(
        _Inout_ PooledConnection* connection,
        bool established) noexcept;

    ULONGLONG PooledConnectionId(_In_opt_ const PooledConnection* connection) noexcept;
    bool PooledConnectionProxyTunnelEstablished(_In_opt_ const PooledConnection* connection) noexcept;
    _Ret_maybenull_ transport::Transport* PooledConnectionTransport(
        _In_opt_ PooledConnection* connection) noexcept;
    _Ret_maybenull_ http2::Http2Connection* PooledConnectionHttp2(
        _In_opt_ PooledConnection* connection) noexcept;
#if !defined(WKNET_USER_MODE_TEST)
    _Ret_maybenull_ net::WskSocket* PooledConnectionSocket(
        _In_opt_ PooledConnection* connection) noexcept;
    _Ret_maybenull_ transport::Transport* PooledConnectionRawTransport(
        _In_opt_ PooledConnection* connection) noexcept;
    _Ret_maybenull_ tls::TlsConnection* PooledConnectionTls(
        _In_opt_ PooledConnection* connection) noexcept;
#endif
    _Must_inspect_result_
    NTSTATUS PooledConnectionSetAlpn(
        _Inout_ PooledConnection* connection,
        _In_reads_bytes_(alpnLength) const char* alpn,
        SIZE_T alpnLength) noexcept;
#if defined(WKNET_USER_MODE_TEST)
    void PooledConnectionAttachTestState(
        _Inout_ PooledConnection* connection,
        _In_opt_ transport::Transport* transport,
        _In_opt_ http2::Http2Connection* http2Connection) noexcept;
    ULONGLONG PooledConnectionHttp2LastKeepAliveTime(
        _In_opt_ const PooledConnection* connection) noexcept;
    ULONG PooledConnectionQuicStreamLeaseCount(_In_opt_ const PooledConnection *connection) noexcept;
    bool PooledConnectionQuicActiveRequest(_In_opt_ const PooledConnection *connection) noexcept;
#endif

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
