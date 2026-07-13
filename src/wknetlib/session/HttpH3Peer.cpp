#include "session/HttpEngineInternal.hpp"

#include "http3/Http3Connection.h"
#include "quic/QuicTokenCache.h"
#include "rtl/WorkspaceScratchAllocator.h"
#include "tls/TlsPolicy.h"
#include <wknet/crypto/CngProvider.h>

#if defined(WKNET_USER_MODE_TEST)
#include <mutex>
#endif

namespace wknet::session
{
namespace
{
constexpr SIZE_T HttpH3ConnectionIdLength = 8;

struct HttpH3PeerRouter final
{
#if defined(WKNET_USER_MODE_TEST)
    std::mutex Lock;
#else
    FAST_MUTEX Lock = {};
#endif
    HttpH3DispatchContext *ActiveDispatch = nullptr;
    ULONGLONG ActiveStreamId = HttpH3UnsetStreamId;
    ConnectionPool *Pool = nullptr;
    PooledConnection *PooledConnectionObject = nullptr;
    http3::Http3Connection *Http3 = nullptr;
    Workspace *ScratchWorkspace = nullptr;
    rtl::WorkspaceScratchAllocator *CertificateScratch = nullptr;
    tls::Tls13SessionCache SessionCache = {};
    quic::QuicTokenCache TokenCache;
};

struct HttpH3PeerLease final
{
    HttpH3PeerRouter *Router = nullptr;
    ConnectionPool *Pool = nullptr;
    PooledConnection *PooledConnectionObject = nullptr;
    HttpH3DispatchContext *Dispatch = nullptr;
    bool Reused = false;
    bool StreamBound = false;
    bool Standalone = false;
};

class HttpH3RouterLock final
{
  public:
    explicit HttpH3RouterLock(HttpH3PeerRouter *router) noexcept : router_(router)
    {
        if (router_ == nullptr)
        {
            return;
        }
#if defined(WKNET_USER_MODE_TEST)
        router_->Lock.lock();
#else
        ExAcquireFastMutex(&router_->Lock);
#endif
    }

    ~HttpH3RouterLock() noexcept
    {
        if (router_ == nullptr)
        {
            return;
        }
#if defined(WKNET_USER_MODE_TEST)
        router_->Lock.unlock();
#else
        ExReleaseFastMutex(&router_->Lock);
#endif
    }

    HttpH3RouterLock(const HttpH3RouterLock &) = delete;
    HttpH3RouterLock &operator=(const HttpH3RouterLock &) = delete;

  private:
    HttpH3PeerRouter *router_ = nullptr;
};

ULONG SocketAddressLength(USHORT family) noexcept
{
    if (family == AF_INET)
    {
        return sizeof(SOCKADDR_IN);
    }
    if (family == AF_INET6)
    {
        return sizeof(SOCKADDR_IN6);
    }
    return 0;
}

NTSTATUS CopyAsciiToWide(const char *source, SIZE_T sourceLength, wchar_t *destination,
                         SIZE_T destinationCapacity) noexcept
{
    if (source == nullptr || sourceLength == 0 || destination == nullptr || destinationCapacity <= sourceLength)
    {
        return STATUS_INVALID_PARAMETER;
    }
    for (SIZE_T index = 0; index < sourceLength; ++index)
    {
        const UCHAR value = static_cast<UCHAR>(source[index]);
        if (value == 0 || value > 0x7f)
        {
            return STATUS_NOT_SUPPORTED;
        }
        destination[index] = static_cast<wchar_t>(value);
    }
    destination[sourceLength] = L'\0';
    return STATUS_SUCCESS;
}

NTSTATUS FormatServiceName(USHORT port, wchar_t *destination, SIZE_T destinationCapacity) noexcept
{
    if (port == 0 || destination == nullptr || destinationCapacity < 6)
    {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T digits = 1;
    USHORT remaining = port;
    while (remaining >= 10)
    {
        remaining = static_cast<USHORT>(remaining / 10);
        ++digits;
    }

    remaining = port;
    for (SIZE_T index = 0; index < digits; ++index)
    {
        destination[digits - index - 1] = static_cast<wchar_t>(L'0' + (remaining % 10));
        remaining = static_cast<USHORT>(remaining / 10);
    }
    destination[digits] = L'\0';
    return STATUS_SUCCESS;
}

HttpH3DispatchContext *GetActiveDispatch(HttpH3PeerRouter *router, ULONGLONG streamId) noexcept
{
    if (router == nullptr)
    {
        return nullptr;
    }
    HttpH3RouterLock lock(router);
    if (router->ActiveDispatch == nullptr ||
        (router->ActiveStreamId != HttpH3UnsetStreamId && router->ActiveStreamId != streamId))
    {
        return nullptr;
    }
    return router->ActiveDispatch;
}

ULONG ParseStatusCode(const qpack::QpackFieldView *fields, SIZE_T fieldCount) noexcept
{
    if (fields == nullptr && fieldCount != 0)
    {
        return 0;
    }
    for (SIZE_T index = 0; index < fieldCount; ++index)
    {
        const qpack::QpackFieldView &field = fields[index];
        if (field.Name.Data == nullptr || field.Value.Data == nullptr || field.Name.Length != 7 ||
            field.Value.Length != 3 || RtlCompareMemory(field.Name.Data, ":status", 7) != 7)
        {
            continue;
        }
        ULONG statusCode = 0;
        for (SIZE_T digit = 0; digit < 3; ++digit)
        {
            const UCHAR value = field.Value.Data[digit];
            if (value < '0' || value > '9')
            {
                return 0;
            }
            statusCode = (statusCode * 10) + static_cast<ULONG>(value - '0');
        }
        return statusCode;
    }
    return 0;
}

void FailDispatch(HttpH3PeerRouter *router, HttpH3DispatchContext *dispatch, NTSTATUS status) noexcept
{
    if (dispatch == nullptr || NT_SUCCESS(status))
    {
        return;
    }
    HttpH3DispatchNotifyComplete(dispatch, status, http3::H3_REQUEST_CANCELLED);
    if (router != nullptr && router->Http3 != nullptr && dispatch->StreamId != HttpH3UnsetStreamId)
    {
        (void)http3::Http3ConnectionWorkerCancelRequest(router->Http3, dispatch->StreamId, http3::H3_REQUEST_CANCELLED);
    }
}

void OnHttp3Headers(void *callbackContext, ULONGLONG streamId, const qpack::QpackFieldView *fields, SIZE_T fieldCount,
                    bool trailers) noexcept
{
    HttpH3PeerRouter *router = static_cast<HttpH3PeerRouter *>(callbackContext);
    HttpH3DispatchContext *dispatch = GetActiveDispatch(router, streamId);
    if (dispatch == nullptr)
    {
        return;
    }

    if (!trailers)
    {
        const ULONG statusCode = ParseStatusCode(fields, fieldCount);
        if (statusCode == 0)
        {
            FailDispatch(router, dispatch, STATUS_INVALID_NETWORK_RESPONSE);
            return;
        }
        if (statusCode < 200)
        {
            return;
        }
        HttpH3DispatchNotifyResponseStarted(dispatch, statusCode);
    }

    for (SIZE_T index = 0; index < fieldCount; ++index)
    {
        if (fields[index].Name.Length != 0 && fields[index].Name.Data[0] == ':')
        {
            continue;
        }
        const NTSTATUS status = HttpH3DispatchNotifyHeader(
            dispatch, reinterpret_cast<const char *>(fields[index].Name.Data), fields[index].Name.Length,
            reinterpret_cast<const char *>(fields[index].Value.Data), fields[index].Value.Length, trailers);
        if (!NT_SUCCESS(status))
        {
            FailDispatch(router, dispatch, status);
            return;
        }
    }
}

void OnHttp3Data(void *callbackContext, ULONGLONG streamId, const UCHAR *data, SIZE_T length) noexcept
{
    HttpH3PeerRouter *router = static_cast<HttpH3PeerRouter *>(callbackContext);
    HttpH3DispatchContext *dispatch = GetActiveDispatch(router, streamId);
    if (dispatch == nullptr)
    {
        return;
    }
    const NTSTATUS status = HttpH3DispatchNotifyBody(dispatch, data, length, false);
    if (!NT_SUCCESS(status))
    {
        FailDispatch(router, dispatch, status);
    }
}

void OnHttp3StreamComplete(void *callbackContext, ULONGLONG streamId, NTSTATUS status,
                           ULONGLONG applicationError) noexcept
{
    HttpH3PeerRouter *router = static_cast<HttpH3PeerRouter *>(callbackContext);
    HttpH3DispatchContext *dispatch = GetActiveDispatch(router, streamId);
    if (dispatch == nullptr)
    {
        return;
    }
    NTSTATUS completionStatus = status;
    if (NT_SUCCESS(completionStatus) && !dispatch->BodyFinalDelivered)
    {
        completionStatus = HttpH3DispatchNotifyBody(dispatch, nullptr, 0, true);
    }
    HttpH3DispatchNotifyComplete(dispatch, completionStatus,
                                 NT_SUCCESS(completionStatus) ? applicationError : http3::H3_REQUEST_CANCELLED);
}

void OnHttp3Goaway(void *callbackContext, ULONGLONG streamId) noexcept
{
    HttpH3PeerRouter *router = static_cast<HttpH3PeerRouter *>(callbackContext);
    if (router == nullptr)
    {
        return;
    }
    if (router->Pool != nullptr && router->PooledConnectionObject != nullptr)
    {
        ConnectionPoolSetHttp3GoAway(router->Pool, router->PooledConnectionObject, streamId);
    }

    HttpH3DispatchContext *dispatch = nullptr;
    {
        HttpH3RouterLock lock(router);
        dispatch = router->ActiveDispatch;
    }
    if (dispatch == nullptr)
    {
        return;
    }

    HttpH3GoawayResult result = HttpH3GoawayResult::NoActiveStream;
    const NTSTATUS status = HttpH3DispatchProcessGoaway(dispatch, streamId, &result);
    if (!NT_SUCCESS(status))
    {
        FailDispatch(router, dispatch, status);
        return;
    }
    if (result == HttpH3GoawayResult::StreamRejected)
    {
        if (router->Http3 != nullptr && dispatch->StreamId != HttpH3UnsetStreamId)
        {
            (void)http3::Http3ConnectionWorkerCancelRequest(router->Http3, dispatch->StreamId,
                                                            http3::H3_REQUEST_CANCELLED);
        }
        HttpH3DispatchNotifyComplete(dispatch, STATUS_RETRY, http3::H3_REQUEST_REJECTED);
    }
}

void OnHttp3ConnectionError(void *callbackContext, NTSTATUS status, ULONGLONG applicationError) noexcept
{
    HttpH3PeerRouter *router = static_cast<HttpH3PeerRouter *>(callbackContext);
    if (router == nullptr)
    {
        return;
    }
    if (router->Pool != nullptr && router->PooledConnectionObject != nullptr)
    {
        ConnectionPoolSetQuicDraining(router->Pool, router->PooledConnectionObject);
    }
    HttpH3DispatchContext *dispatch = nullptr;
    {
        HttpH3RouterLock lock(router);
        dispatch = router->ActiveDispatch;
    }
    HttpH3DispatchNotifyComplete(dispatch, status, applicationError);
}

void DestroyRouter(HttpH3PeerRouter *router) noexcept
{
    if (router == nullptr)
    {
        return;
    }
    router->TokenCache.Clear();
    FreeNonPagedObject(router->CertificateScratch);
    router->CertificateScratch = nullptr;
    WorkspaceRelease(router->ScratchWorkspace);
    router->ScratchWorkspace = nullptr;
    FreeNonPagedObject(router);
}

NTSTATUS CreateRouter(HttpH3PeerRouter **router) noexcept
{
    if (router == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *router = nullptr;
    HttpH3PeerRouter *created = AllocateNonPagedObject<HttpH3PeerRouter>();
    if (created == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
#if !defined(WKNET_USER_MODE_TEST)
    ExInitializeFastMutex(&created->Lock);
#endif

    WorkspaceOptions workspaceOptions = {};
    NTSTATUS status = WorkspaceCreate(&workspaceOptions, &created->ScratchWorkspace);
    if (NT_SUCCESS(status))
    {
        created->CertificateScratch = AllocateNonPagedObject<rtl::WorkspaceScratchAllocator>(
            *created->ScratchWorkspace, rtl::WorkspaceScratchAllocator::BufferKind::Certificate);
        status = created->CertificateScratch != nullptr ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    }
    if (NT_SUCCESS(status))
    {
        status = created->TokenCache.Initialize();
    }
    if (!NT_SUCCESS(status))
    {
        DestroyRouter(created);
        return status;
    }

    http3::Http3ConnectionCreateOptions h3Options = {};
    h3Options.Callbacks.Context = created;
    h3Options.Callbacks.Headers = OnHttp3Headers;
    h3Options.Callbacks.Data = OnHttp3Data;
    h3Options.Callbacks.StreamComplete = OnHttp3StreamComplete;
    h3Options.Callbacks.Goaway = OnHttp3Goaway;
    h3Options.Callbacks.ConnectionError = OnHttp3ConnectionError;
    status = http3::Http3ConnectionCreate(h3Options, &created->Http3);
    if (!NT_SUCCESS(status))
    {
        DestroyRouter(created);
        return status;
    }

    *router = created;
    return STATUS_SUCCESS;
}

void CloseQuic(HttpH3PeerRouter *router, quic::QuicConnection *connection) noexcept
{
    UNREFERENCED_PARAMETER(router);
    if (connection == nullptr)
    {
        return;
    }
    quic::QuicOperation closeOperation = {};
    quic::QuicOperationInitialize(&closeOperation);
    const NTSTATUS closeStatus =
        quic::QuicConnectionCloseApplicationAsync(connection, http3::H3_NO_ERROR, &closeOperation);
    if (NT_SUCCESS(closeStatus))
    {
        (void)quic::QuicOperationWait(&closeOperation, WskOperationTimeoutMilliseconds);
    }
    quic::QuicConnectionDestroy(connection);
}

void PooledCloseRoutine(void *context, ConnectionPool *pool, PooledConnection *pooledConnection,
                        quic::QuicConnection *quicConnection, http3::Http3Connection *http3Connection) noexcept
{
    HttpH3PeerRouter *router = static_cast<HttpH3PeerRouter *>(context);
    if (http3Connection != nullptr)
    {
        http3::Http3ConnectionBeginShutdown(http3Connection);
    }
    CloseQuic(router, quicConnection);
    if (http3Connection != nullptr)
    {
        http3::Http3ConnectionDestroy(http3Connection);
    }
    if (router != nullptr)
    {
        router->Http3 = nullptr;
    }
    DestroyRouter(router);
    ConnectionPoolCompleteQuicClose(pool, pooledConnection);
}

NTSTATUS BuildQuicPoolKey(const Request &request, ConnectionPoolKey *key) noexcept
{
    ProxyOptions noProxy = {};
    NTSTATUS status = BuildPoolKey(request, noProxy, Http2CleartextMode::Disabled, key);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    key->Kind = ConnectionKind::Quic;
    key->AutomaticAlpn = false;
    key->Alpn[0] = 'h';
    key->Alpn[1] = '3';
    key->Alpn[2] = '\0';
    key->AlpnLength = 2;
    key->AlternativePort = request.Port;
    key->QuicVersion = quic::QuicVersion1;
    if (request.HostLength > sizeof(key->AlternativeHost) - 1)
    {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(key->AlternativeHost, request.Host, request.HostLength);
    key->AlternativeHost[request.HostLength] = '\0';
    key->AlternativeHostLength = request.HostLength;
    return STATUS_SUCCESS;
}

NTSTATUS ConnectQuic(SessionHandle session, const Request &request, HttpH3PeerRouter *router,
                     quic::QuicConnection **connection) noexcept
{
    if (connection == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *connection = nullptr;
    if (session == nullptr || session->WskClient == nullptr || router == nullptr || router->Http3 == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(tls::TlsValidatePolicy(request.Tls.Policy)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (request.Tls.Policy.EnablePostHandshakeClientAuth)
    {
        return STATUS_NOT_SUPPORTED;
    }

    HeapArray<wchar_t> host(request.HostLength + 1);
    HeapArray<wchar_t> service(6);
    HeapArray<SOCKADDR_STORAGE> addresses(net::WskMaxResolvedAddresses);
    HeapArray<UCHAR> destinationConnectionId(HttpH3ConnectionIdLength);
    HeapArray<UCHAR> sourceConnectionId(HttpH3ConnectionIdLength);
    if (!host.IsValid() || !service.IsValid() || !addresses.IsValid() || !destinationConnectionId.IsValid() ||
        !sourceConnectionId.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = CopyAsciiToWide(request.Host, request.HostLength, host.Get(), host.Count());
    if (NT_SUCCESS(status))
    {
        status = FormatServiceName(request.Port, service.Get(), service.Count());
    }
    SIZE_T addressCount = 0;
    if (NT_SUCCESS(status))
    {
        status = net::WskClientResolveAll(session->WskClient, host.Get(), service.Get(), addresses.Get(),
                                          addresses.Count(), &addressCount, ToWskAddressFamily(request.AddressFamily));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    const char *serverName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
    const SIZE_T serverNameLength =
        request.Tls.ServerName != nullptr ? request.Tls.ServerNameLength : request.HostLength;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;
    for (SIZE_T index = 0; index < addressCount; ++index)
    {
        status = crypto::CngProvider::GenerateRandom(destinationConnectionId.Get(), destinationConnectionId.Count());
        if (NT_SUCCESS(status))
        {
            status = crypto::CngProvider::GenerateRandom(sourceConnectionId.Get(), sourceConnectionId.Count());
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        quic::QuicConnectionCreateOptions createOptions = {};
        createOptions.DatagramClient = session->WskClient;
        createOptions.RemoteAddress = reinterpret_cast<const SOCKADDR *>(&addresses[index]);
        createOptions.RemoteAddressLength = SocketAddressLength(addresses[index].ss_family);
        createOptions.ServerName = serverName;
        createOptions.ServerNameLength = serverNameLength;
        createOptions.InitialDestinationConnectionId = {destinationConnectionId.Get(), destinationConnectionId.Count()};
        createOptions.InitialSourceConnectionId = {sourceConnectionId.Get(), sourceConnectionId.Count()};
        createOptions.CertificateStore = request.Tls.CertificateStore;
        createOptions.CertificateScratchAllocator = router->CertificateScratch;
        createOptions.ProviderCache = session->ProviderCache;
        createOptions.SessionCache = &router->SessionCache;
        createOptions.TokenCache = &router->TokenCache;
        createOptions.ClientCredential = request.Tls.ClientCredential;
        createOptions.ApplicationEventSink = http3::Http3ConnectionApplicationSink(router->Http3);
        createOptions.VerifyCertificate = request.Tls.CertificatePolicy == CertificatePolicy::Verify;
        createOptions.RequireRevocationCheck = request.Tls.Policy.RequireRevocationCheck;

        quic::QuicConnection *candidate = nullptr;
        status = quic::QuicConnectionCreate(createOptions, &candidate);
        if (NT_SUCCESS(status))
        {
            quic::QuicOperation connectOperation = {};
            quic::QuicOperationInitialize(&connectOperation);
            status = quic::QuicConnectionConnect(candidate, &connectOperation);
            if (NT_SUCCESS(status))
            {
                status =
                    quic::QuicOperationWait(&connectOperation, session->Options.Http3.QuicProbeTimeoutMilliseconds);
            }
        }
        if (NT_SUCCESS(status))
        {
            quic::QuicOperation establishedOperation = {};
            quic::QuicOperationInitialize(&establishedOperation);
            status = quic::QuicConnectionWaitEstablishedAsync(candidate, &establishedOperation);
            if (NT_SUCCESS(status))
            {
                status =
                    quic::QuicOperationWait(&establishedOperation, session->Options.Http3.QuicProbeTimeoutMilliseconds);
            }
        }
        if (NT_SUCCESS(status))
        {
            status = http3::Http3ConnectionBindQuic(router->Http3, candidate);
        }
        if (NT_SUCCESS(status))
        {
            *connection = candidate;
            return STATUS_SUCCESS;
        }

        lastStatus = status;
        CloseQuic(router, candidate);
        if (status == STATUS_INSUFFICIENT_RESOURCES)
        {
            return status;
        }
    }
    return lastStatus;
}

NTSTATUS AttachRequest(void *context, HttpH3DispatchContext *dispatch) noexcept
{
    HttpH3PeerLease *lease = static_cast<HttpH3PeerLease *>(context);
    if (lease == nullptr || lease->Router == nullptr || dispatch == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    HttpH3RouterLock lock(lease->Router);
    if (lease->Router->ActiveDispatch != nullptr)
    {
        return STATUS_DEVICE_BUSY;
    }
    lease->Router->ActiveDispatch = dispatch;
    lease->Router->ActiveStreamId = HttpH3UnsetStreamId;
    lease->Dispatch = dispatch;
    return STATUS_SUCCESS;
}

NTSTATUS BindStream(void *context, HttpH3DispatchContext *dispatch, ULONGLONG streamId) noexcept
{
    HttpH3PeerLease *lease = static_cast<HttpH3PeerLease *>(context);
    if (lease == nullptr || lease->Router == nullptr || dispatch == nullptr || streamId > HttpH3MaximumStreamId)
    {
        return STATUS_INVALID_PARAMETER;
    }
    {
        HttpH3RouterLock lock(lease->Router);
        if (lease->Router->ActiveDispatch != dispatch)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        lease->Router->ActiveStreamId = streamId;
    }

    const ULONG peerMaximum = WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS;
    const ULONG localMaximum = WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS;
    if (lease->Standalone)
    {
        WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Verbose, "http3.peer.standalone_close.start");
        lease->StreamBound = true;
        return STATUS_SUCCESS;
    }
    NTSTATUS status = lease->Reused ? ConnectionPoolBindHttp3StreamLease(lease->Pool, lease->PooledConnectionObject,
                                                                         streamId, peerMaximum, localMaximum)
                                    : ConnectionPoolPromoteHttp3StreamLease(lease->Pool, lease->PooledConnectionObject,
                                                                            streamId, peerMaximum, localMaximum);
    if (NT_SUCCESS(status))
    {
        lease->StreamBound = true;
    }
    return status;
}

void ReleasePeer(void *context) noexcept
{
    HttpH3PeerLease *lease = static_cast<HttpH3PeerLease *>(context);
    if (lease == nullptr)
    {
        return;
    }
    if (lease->Router != nullptr)
    {
        HttpH3RouterLock lock(lease->Router);
        if (lease->Router->ActiveDispatch == lease->Dispatch)
        {
            lease->Router->ActiveDispatch = nullptr;
            lease->Router->ActiveStreamId = HttpH3UnsetStreamId;
        }
    }

    bool reusable = false;
    if (lease->Dispatch != nullptr && lease->Dispatch->Peer.Quic != nullptr)
    {
        const quic::QuicConnectionState state = quic::QuicConnectionStateGet(lease->Dispatch->Peer.Quic);
        reusable = state == quic::QuicConnectionState::Established && !lease->Dispatch->GoawayReceived &&
                   (NT_SUCCESS(lease->Dispatch->TerminalStatus) || lease->Dispatch->TerminalStatus == STATUS_CANCELLED);
    }
    if (lease->Standalone)
    {
        if (lease->Router != nullptr && lease->Router->Http3 != nullptr)
        {
            http3::Http3ConnectionBeginShutdown(lease->Router->Http3);
        }
        CloseQuic(lease->Router, lease->Dispatch != nullptr ? lease->Dispatch->Peer.Quic : nullptr);
        if (lease->Router != nullptr && lease->Router->Http3 != nullptr)
        {
            http3::Http3ConnectionDestroy(lease->Router->Http3);
            lease->Router->Http3 = nullptr;
        }
        DestroyRouter(lease->Router);
        WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Verbose, "http3.peer.standalone_close.complete");
    }
    else
    {
        ConnectionPoolReleaseHttp3StreamLease(lease->Pool, lease->PooledConnectionObject, reusable);
    }
    FreeNonPagedObject(lease);
}

NTSTATUS CreateProductionPeer(void *context, const HttpH3PeerCreateOptions *options, HttpH3Peer *peer) noexcept
{
    if (peer != nullptr)
    {
        *peer = {};
    }
    SessionHandle session = static_cast<SessionHandle>(context);
    if (session == nullptr || options == nullptr || options->RequestObject == nullptr || options->Dispatch == nullptr ||
        peer == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    HeapObject<ConnectionPoolKey> key;
    if (!key.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NTSTATUS status = BuildQuicPoolKey(*options->RequestObject, key.Get());
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PooledConnection *pooledConnection = nullptr;
    bool reused = false;
    status = ConnectionPoolAcquire(&session->ConnectionPool, *key.Get(), options->RequestObject->ConnectionPolicy,
                                   &pooledConnection, &reused);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    HttpH3PeerRouter *router = nullptr;
    quic::QuicConnection *quicConnection = nullptr;
    http3::Http3Connection *http3Connection = nullptr;
    if (reused)
    {
        router = static_cast<HttpH3PeerRouter *>(PooledConnectionQuicCloseContext(pooledConnection));
        quicConnection = PooledConnectionQuic(pooledConnection);
        http3Connection = PooledConnectionHttp3(pooledConnection);
        if (router == nullptr || quicConnection == nullptr || http3Connection == nullptr)
        {
            ConnectionPoolReleaseHttp3StreamLease(&session->ConnectionPool, pooledConnection, false);
            return STATUS_INVALID_DEVICE_STATE;
        }
    }
    else
    {
        status = CreateRouter(&router);
        if (NT_SUCCESS(status))
        {
            router->Pool = &session->ConnectionPool;
            router->PooledConnectionObject = pooledConnection;
            status = ConnectQuic(session, *options->RequestObject, router, &quicConnection);
        }
        if (NT_SUCCESS(status))
        {
            http3Connection = router->Http3;
            status = PooledConnectionAdoptQuic(pooledConnection, quicConnection, http3Connection, PooledCloseRoutine,
                                               router);
        }
        if (!NT_SUCCESS(status))
        {
            if (router != nullptr && router->Http3 != nullptr)
            {
                http3::Http3ConnectionBeginShutdown(router->Http3);
            }
            CloseQuic(router, quicConnection);
            if (router != nullptr && router->Http3 != nullptr)
            {
                http3::Http3ConnectionDestroy(router->Http3);
                router->Http3 = nullptr;
            }
            DestroyRouter(router);
            ConnectionPoolAbandonQuicAcquire(&session->ConnectionPool, pooledConnection);
            return status;
        }
    }

    HttpH3PeerLease *lease = AllocateNonPagedObject<HttpH3PeerLease>();
    if (lease == nullptr)
    {
        ConnectionPoolReleaseHttp3StreamLease(&session->ConnectionPool, pooledConnection, false);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    lease->Router = router;
    lease->Pool = &session->ConnectionPool;
    lease->PooledConnectionObject = pooledConnection;
    lease->Reused = reused;

    peer->Context = lease;
    peer->Quic = quicConnection;
    peer->Http3 = http3Connection;
    peer->AttachRequest = AttachRequest;
    peer->BindStream = BindStream;
    peer->Destroy = ReleasePeer;
    return STATUS_SUCCESS;
}
} // namespace

void HttpH3GetProductionPeerFactory(SessionHandle session, HttpH3PeerFactory *factory) noexcept
{
    if (factory == nullptr)
    {
        return;
    }
    factory->Context = session;
    factory->Create = CreateProductionPeer;
}

#if defined(WKNET_USER_MODE_TEST)
NTSTATUS HttpH3TestCreateInMemoryPeer(const HttpH3PeerCreateOptions *options, HttpH3Peer *peer) noexcept
{
    if (peer != nullptr)
    {
        *peer = {};
    }
    if (options == nullptr || options->Dispatch == nullptr || peer == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    HttpH3PeerRouter *router = nullptr;
    NTSTATUS status = CreateRouter(&router);
    quic::QuicConnection *connection = nullptr;
    if (NT_SUCCESS(status))
    {
        quic::QuicConnectionCreateOptions createOptions = {};
        createOptions.ApplicationEventSink = http3::Http3ConnectionApplicationSink(router->Http3);
        status = quic::QuicConnectionCreate(createOptions, &connection);
    }
    if (NT_SUCCESS(status))
    {
        quic::QuicOperation connectOperation = {};
        quic::QuicOperationInitialize(&connectOperation);
        status = quic::QuicConnectionConnect(connection, &connectOperation);
        if (NT_SUCCESS(status))
        {
            status = quic::QuicOperationWait(&connectOperation, 1000);
        }
    }
    if (NT_SUCCESS(status))
    {
        status = quic::QuicConnectionTestConfirmHandshake(connection);
    }
    if (NT_SUCCESS(status))
    {
        status = http3::Http3ConnectionBindQuic(router->Http3, connection);
    }
    if (NT_SUCCESS(status))
    {
        status = http3::Http3ConnectionTestApplyPeerSettings(router->Http3, 128, 2);
    }
    if (!NT_SUCCESS(status))
    {
        if (router != nullptr && router->Http3 != nullptr)
        {
            http3::Http3ConnectionBeginShutdown(router->Http3);
        }
        CloseQuic(router, connection);
        if (router != nullptr && router->Http3 != nullptr)
        {
            http3::Http3ConnectionDestroy(router->Http3);
            router->Http3 = nullptr;
        }
        DestroyRouter(router);
        return status;
    }

    HttpH3PeerLease *lease = AllocateNonPagedObject<HttpH3PeerLease>();
    if (lease == nullptr)
    {
        http3::Http3ConnectionBeginShutdown(router->Http3);
        CloseQuic(router, connection);
        http3::Http3ConnectionDestroy(router->Http3);
        router->Http3 = nullptr;
        DestroyRouter(router);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    lease->Router = router;
    lease->Standalone = true;

    peer->Context = lease;
    peer->Quic = connection;
    peer->Http3 = router->Http3;
    peer->AttachRequest = AttachRequest;
    peer->BindStream = BindStream;
    peer->Destroy = ReleasePeer;
    return STATUS_SUCCESS;
}
#endif
} // namespace wknet::session
