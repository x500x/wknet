#include "session/HttpEngineInternal.hpp"

#include "http3/Http3Connection.h"
#include "quic/QuicClock.h"
#include "quic/QuicTokenCache.h"
#include "rtl/ProtocolAllocator.h"
#include "rtl/WorkspaceScratchAllocator.h"
#include "session/AltSvcCache.h"
#include "tls/TlsPolicy.h"
#include <wknet/crypto/CngProvider.h>

#if defined(WKNET_USER_MODE_TEST)
#include <chrono>
#include <mutex>
#include <thread>
#endif

namespace wknet::session
{
namespace
{
constexpr SIZE_T HttpH3ConnectionIdLength = 8;
constexpr SIZE_T HttpH3RouteCapacity = WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS;
constexpr SIZE_T HttpH3InvalidRouteIndex = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));

struct HttpH3RouteEntry final
{
    HttpH3DispatchContext *Dispatch = nullptr;
    ULONGLONG StreamId = HttpH3UnsetStreamId;
};

struct HttpH3PeerRouter final
{
#if defined(WKNET_USER_MODE_TEST)
    std::mutex Lock;
#else
    FAST_MUTEX Lock = {};
#endif
    HttpH3RouteEntry Routes[HttpH3RouteCapacity] = {};
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
    bool OwnsStandaloneRouter = false;
    SIZE_T RouteIndex = HttpH3InvalidRouteIndex;
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
    for (SIZE_T index = 0; index < HttpH3RouteCapacity; ++index)
    {
        if (router->Routes[index].Dispatch != nullptr && router->Routes[index].StreamId == streamId)
        {
            return router->Routes[index].Dispatch;
        }
    }
    return nullptr;
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

    for (SIZE_T index = 0; index < HttpH3RouteCapacity; ++index)
    {
        HttpH3DispatchContext *dispatch = nullptr;
        {
            HttpH3RouterLock lock(router);
            dispatch = router->Routes[index].Dispatch;
        }
        if (dispatch == nullptr)
        {
            continue;
        }
        HttpH3GoawayResult result = HttpH3GoawayResult::NoActiveStream;
        const NTSTATUS status = HttpH3DispatchProcessGoaway(dispatch, streamId, &result);
        if (!NT_SUCCESS(status))
        {
            FailDispatch(router, dispatch, status);
            continue;
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
    for (SIZE_T index = 0; index < HttpH3RouteCapacity; ++index)
    {
        HttpH3DispatchContext *dispatch = nullptr;
        {
            HttpH3RouterLock lock(router);
            dispatch = router->Routes[index].Dispatch;
        }
        HttpH3DispatchNotifyComplete(dispatch, status, applicationError);
    }
}

void DestroyRouter(HttpH3PeerRouter *router) noexcept
{
    if (router == nullptr)
    {
        return;
    }
    router->TokenCache.Clear();
    FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::SessionHttp3CertificateScratch, router->CertificateScratch);
    router->CertificateScratch = nullptr;
    WorkspaceRelease(router->ScratchWorkspace);
    router->ScratchWorkspace = nullptr;
    FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::SessionHttp3PeerRouter, router);
}

NTSTATUS CreateRouter(HttpH3PeerRouter **router) noexcept
{
    if (router == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *router = nullptr;
    HttpH3PeerRouter *created =
        AllocateProtocolNonPagedObject<HttpH3PeerRouter>(rtl::ProtocolAllocationSite::SessionHttp3PeerRouter);
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
        created->CertificateScratch = AllocateProtocolNonPagedObject<rtl::WorkspaceScratchAllocator>(
            rtl::ProtocolAllocationSite::SessionHttp3CertificateScratch, *created->ScratchWorkspace,
            rtl::WorkspaceScratchAllocator::BufferKind::Certificate);
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

NTSTATUS CheckPeerSettings(void *context, quic::QuicConnection *connection) noexcept
{
    UNREFERENCED_PARAMETER(connection);
    const http3::Http3Connection *http3Connection = static_cast<const http3::Http3Connection *>(context);
    return http3::Http3ConnectionPeerSettingsReceived(http3Connection) ? STATUS_SUCCESS : STATUS_RETRY;
}

NTSTATUS WaitForPeerSettings(quic::QuicConnection *connection, http3::Http3Connection *http3Connection,
                             ULONG timeoutMilliseconds) noexcept
{
    if (connection == nullptr || http3Connection == nullptr || timeoutMilliseconds == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONGLONG now = quic::QuicClockNow100ns();
    const ULONGLONG duration = static_cast<ULONGLONG>(timeoutMilliseconds) * 10000ULL;
    const ULONGLONG deadline = now > ~0ULL - duration ? ~0ULL : now + duration;

    for (;;)
    {
        HeapObject<quic::QuicOperation> operation;
        if (!operation.IsValid())
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        quic::QuicOperationInitialize(operation.Get());
        NTSTATUS status = quic::QuicConnectionExecuteApplication(connection, CheckPeerSettings, http3Connection,
                                                                  operation.Get());
        if (NT_SUCCESS(status))
        {
            status = quic::QuicOperationWait(operation.Get(), timeoutMilliseconds);
        }
        if (NT_SUCCESS(status))
        {
            return STATUS_SUCCESS;
        }
        if (status != STATUS_RETRY)
        {
            return status;
        }
        if (quic::QuicClockNow100ns() >= deadline)
        {
            return STATUS_IO_TIMEOUT;
        }
#if defined(WKNET_USER_MODE_TEST)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
#else
        LARGE_INTEGER delay = {};
        delay.QuadPart = -10000LL;
        const NTSTATUS delayStatus = KeDelayExecutionThread(KernelMode, FALSE, &delay);
        if (!NT_SUCCESS(delayStatus))
        {
            return delayStatus;
        }
#endif
    }
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

NTSTATUS BuildQuicPoolKey(const Request &request, const AltSvcCandidateSnapshot *alternative,
                          ConnectionPoolKey *key) noexcept
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
    const char *alternativeHost = alternative != nullptr ? alternative->Host : request.Host;
    const SIZE_T alternativeHostLength = alternative != nullptr ? alternative->HostLength : request.HostLength;
    key->AlternativePort = alternative != nullptr ? alternative->Port : request.Port;
    key->QuicVersion = quic::QuicVersion1;
    if (alternativeHost == nullptr || alternativeHostLength == 0 ||
        alternativeHostLength > sizeof(key->AlternativeHost) - 1)
    {
        return STATUS_INVALID_PARAMETER;
    }
    RtlCopyMemory(key->AlternativeHost, alternativeHost, alternativeHostLength);
    key->AlternativeHost[alternativeHostLength] = '\0';
    key->AlternativeHostLength = alternativeHostLength;
    return STATUS_SUCCESS;
}

NTSTATUS ConnectQuic(SessionHandle session, const Request &request, const AltSvcCandidateSnapshot *alternative,
                     ULONG probeTimeoutMilliseconds, HttpH3PeerRouter *router,
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

    const char *endpointHost = alternative != nullptr ? alternative->Host : request.Host;
    const SIZE_T endpointHostLength = alternative != nullptr ? alternative->HostLength : request.HostLength;
    const USHORT endpointPort = alternative != nullptr ? alternative->Port : request.Port;
    if (endpointHost == nullptr || endpointHostLength == 0 || endpointPort == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (probeTimeoutMilliseconds == 0)
    {
        probeTimeoutMilliseconds = session->Options.Http3.QuicProbeTimeoutMilliseconds;
    }

    HeapArray<wchar_t> host(endpointHostLength + 1);
    HeapArray<wchar_t> service(6);
    HeapArray<SOCKADDR_STORAGE> addresses(net::WskMaxResolvedAddresses);
    HeapArray<UCHAR> destinationConnectionId(HttpH3ConnectionIdLength);
    HeapArray<UCHAR> sourceConnectionId(HttpH3ConnectionIdLength);
    if (!host.IsValid() || !service.IsValid() || !addresses.IsValid() || !destinationConnectionId.IsValid() ||
        !sourceConnectionId.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = CopyAsciiToWide(endpointHost, endpointHostLength, host.Get(), host.Count());
    if (NT_SUCCESS(status))
    {
        status = FormatServiceName(endpointPort, service.Get(), service.Count());
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
                    quic::QuicOperationWait(&connectOperation, probeTimeoutMilliseconds);
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
                    quic::QuicOperationWait(&establishedOperation, probeTimeoutMilliseconds);
            }
        }
        if (NT_SUCCESS(status))
        {
            status = http3::Http3ConnectionBindQuic(router->Http3, candidate);
        }
        if (NT_SUCCESS(status))
        {
            quic::QuicOperation startOperation = {};
            quic::QuicOperationInitialize(&startOperation);
            status = quic::QuicConnectionExecuteApplication(
                candidate,
                [](void *context, quic::QuicConnection *workerConnection) noexcept -> NTSTATUS {
                    UNREFERENCED_PARAMETER(workerConnection);
                    return http3::Http3ConnectionWorkerStart(static_cast<http3::Http3Connection *>(context));
                },
                router->Http3, &startOperation);
            if (NT_SUCCESS(status))
            {
                status = quic::QuicOperationWait(&startOperation, probeTimeoutMilliseconds);
            }
        }
        if (NT_SUCCESS(status))
        {
            status = WaitForPeerSettings(candidate, router->Http3, probeTimeoutMilliseconds);
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
    for (SIZE_T index = 0; index < HttpH3RouteCapacity; ++index)
    {
        if (lease->Router->Routes[index].Dispatch == nullptr)
        {
            lease->Router->Routes[index].Dispatch = dispatch;
            lease->Router->Routes[index].StreamId = HttpH3UnsetStreamId;
            lease->RouteIndex = index;
            lease->Dispatch = dispatch;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES;
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
        if (lease->RouteIndex >= HttpH3RouteCapacity ||
            lease->Router->Routes[lease->RouteIndex].Dispatch != dispatch)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        lease->Router->Routes[lease->RouteIndex].StreamId = streamId;
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
    if (lease->Router != nullptr && lease->RouteIndex < HttpH3RouteCapacity)
    {
        HttpH3RouterLock lock(lease->Router);
        HttpH3RouteEntry &route = lease->Router->Routes[lease->RouteIndex];
        if (route.Dispatch == lease->Dispatch)
        {
            route = {};
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
        if (lease->OwnsStandaloneRouter && lease->Router != nullptr && lease->Router->Http3 != nullptr)
        {
            http3::Http3ConnectionBeginShutdown(lease->Router->Http3);
        }
        if (lease->OwnsStandaloneRouter)
        {
            CloseQuic(lease->Router, lease->Dispatch != nullptr ? lease->Dispatch->Peer.Quic : nullptr);
            if (lease->Router != nullptr && lease->Router->Http3 != nullptr)
            {
                http3::Http3ConnectionDestroy(lease->Router->Http3);
                lease->Router->Http3 = nullptr;
            }
            DestroyRouter(lease->Router);
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Verbose,
                        "http3.peer.standalone_close.complete");
        }
    }
    else
    {
        ConnectionPoolReleaseHttp3StreamLease(lease->Pool, lease->PooledConnectionObject, reusable);
    }
    FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::SessionHttp3PeerLease, lease);
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
    NTSTATUS status = BuildQuicPoolKey(*options->RequestObject, options->Alternative, key.Get());
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
            status = ConnectQuic(session, *options->RequestObject, options->Alternative,
                                 options->ProbeTimeoutMilliseconds, router, &quicConnection);
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

    HttpH3PeerLease *lease =
        AllocateProtocolNonPagedObject<HttpH3PeerLease>(rtl::ProtocolAllocationSite::SessionHttp3PeerLease);
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

    HttpH3PeerLease *lease =
        AllocateProtocolNonPagedObject<HttpH3PeerLease>(rtl::ProtocolAllocationSite::SessionHttp3PeerLease);
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
    lease->OwnsStandaloneRouter = true;

    peer->Context = lease;
    peer->Quic = connection;
    peer->Http3 = router->Http3;
    peer->AttachRequest = AttachRequest;
    peer->BindStream = BindStream;
    peer->Destroy = ReleasePeer;
    return STATUS_SUCCESS;
}

NTSTATUS HttpH3TestCreateSiblingPeer(const HttpH3Peer *existingPeer, HttpH3Peer *peer) noexcept
{
    if (peer != nullptr)
    {
        *peer = {};
    }
    if (existingPeer == nullptr || existingPeer->Context == nullptr || existingPeer->Quic == nullptr ||
        existingPeer->Http3 == nullptr || peer == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const HttpH3PeerLease *existingLease = static_cast<const HttpH3PeerLease *>(existingPeer->Context);
    if (existingLease->Router == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    HttpH3PeerLease *lease =
        AllocateProtocolNonPagedObject<HttpH3PeerLease>(rtl::ProtocolAllocationSite::SessionHttp3PeerLease);
    if (lease == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    lease->Router = existingLease->Router;
    lease->Standalone = true;

    peer->Context = lease;
    peer->Quic = existingPeer->Quic;
    peer->Http3 = existingPeer->Http3;
    peer->AttachRequest = AttachRequest;
    peer->BindStream = BindStream;
    peer->Destroy = ReleasePeer;
    return STATUS_SUCCESS;
}

void HttpH3TestPeerInjectData(const HttpH3Peer *peer, ULONGLONG streamId, const UCHAR *data,
                              SIZE_T dataLength) noexcept
{
    if (peer == nullptr || peer->Context == nullptr)
    {
        return;
    }
    const HttpH3PeerLease *lease = static_cast<const HttpH3PeerLease *>(peer->Context);
    OnHttp3Data(lease->Router, streamId, data, dataLength);
}

void HttpH3TestPeerInjectGoaway(const HttpH3Peer *peer, ULONGLONG streamId) noexcept
{
    if (peer == nullptr || peer->Context == nullptr)
    {
        return;
    }
    const HttpH3PeerLease *lease = static_cast<const HttpH3PeerLease *>(peer->Context);
    OnHttp3Goaway(lease->Router, streamId);
}

void HttpH3TestPeerInjectConnectionError(const HttpH3Peer *peer, NTSTATUS status,
                                          ULONGLONG applicationError) noexcept
{
    if (peer == nullptr || peer->Context == nullptr)
    {
        return;
    }
    const HttpH3PeerLease *lease = static_cast<const HttpH3PeerLease *>(peer->Context);
    OnHttp3ConnectionError(lease->Router, status, applicationError);
}
#endif
} // namespace wknet::session
