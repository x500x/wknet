#include "http2/Http2Connection.h"
#include "net/WskSocket.h"
#include "rtl/ProtocolFailureInjection.h"
#include "rtl/TraceInternal.h"
#include "session/ConnectionPoolPrivate.hpp"
#include "tls/TlsConnection.h"
#include "transport/Transport.h"

#if defined(WKNET_USER_MODE_TEST)
#include <stdlib.h>
#endif

#if !defined(WKNET_USER_MODE_TEST)
extern "C" NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);
#endif

namespace wknet
{
namespace session
{
namespace
{
    struct DetachedConnectionResources final
    {
#if !defined(WKNET_USER_MODE_TEST)
        net::WskSocket* Socket = nullptr;
        transport::Transport* RawTransport = nullptr;
        tls::TlsConnection* Tls = nullptr;
#endif
        transport::Transport* Transport = nullptr;
        http2::Http2Connection* Http2 = nullptr;
    };

    struct PendingQuicClose final
    {
        PooledQuicCloseRoutine Routine = nullptr;
        void *Context = nullptr;
        ConnectionPool *Pool = nullptr;
        PooledConnection *Connection = nullptr;
        quic::QuicConnection *Quic = nullptr;
        http3::Http3Connection *Http3 = nullptr;
    };

    void DetachConnectionResources(
        _Inout_ PooledConnection& connection,
        _Out_ DetachedConnectionResources* detached) noexcept;

    void StartPendingQuicClose(_Inout_ PendingQuicClose *pending) noexcept
    {
        if (pending != nullptr && pending->Routine != nullptr)
        {
            pending->Routine(pending->Context, pending->Pool, pending->Connection, pending->Quic, pending->Http3);
        }
    }

    void InitializePoolLock(_Inout_ ConnectionPool* pool) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        if (pool != nullptr) {
            InterlockedExchange(&pool->Lock, 0);
        }
#else
        ExInitializeFastMutex(&pool->Lock);
        KeInitializeEvent(&pool->QuicCloseCompleteEvent, NotificationEvent, TRUE);
#endif
    }

    void LockPool(_Inout_ ConnectionPool* pool) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        if (pool == nullptr) {
            return;
        }
        while (InterlockedCompareExchange(&pool->Lock, 1, 0) != 0) {
            YieldProcessor();
        }
#else
        ExAcquireFastMutex(&pool->Lock);
#endif
    }

    void UnlockPool(_Inout_ ConnectionPool* pool) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        if (pool != nullptr) {
            InterlockedExchange(&pool->Lock, 0);
        }
#else
        ExReleaseFastMutex(&pool->Lock);
#endif
    }

    _Ret_maybenull_
    void* AllocatePoolMemory(SIZE_T length) noexcept
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

    void FreePoolMemory(_In_opt_ void* data) noexcept
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

    void InitializePooledConnectionSlot(_Inout_ PooledConnection& connection) noexcept
    {
        connection.Http1PipelineNextSequence = 1;
        connection.Http1PipelineNextReceiveSequence = 1;
        connection.Http1PipelineFailureStatus = STATUS_SUCCESS;
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeMutex(&connection.Http1PipelineSendLock, 0);
        KeInitializeEvent(&connection.Http1PipelineReceiveEvent, NotificationEvent, TRUE);
#endif
    }

    void SignalHttp1PipelineReceiveEvent(_Inout_ PooledConnection& connection) noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        KeSetEvent(&connection.Http1PipelineReceiveEvent, IO_NO_INCREMENT, FALSE);
#else
        UNREFERENCED_PARAMETER(connection);
#endif
    }

    void ClearHttp1PipelineReceiveEvent(_Inout_ PooledConnection& connection) noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        KeClearEvent(&connection.Http1PipelineReceiveEvent);
#else
        UNREFERENCED_PARAMETER(connection);
#endif
    }

    void FreeHttp1PipelineBuffer(_Inout_ PooledConnection& connection) noexcept
    {
        FreePoolMemory(connection.Http1PipelineBufferedBytes);
        connection.Http1PipelineBufferedBytes = nullptr;
        connection.Http1PipelineBufferedLength = 0;
        connection.Http1PipelineBufferedCapacity = 0;
    }

    void ResetHttp1PipelineLeaseState(_Inout_ PooledConnection& connection) noexcept
    {
        connection.Http1PipelineLeases = 0;
        connection.Http1MaxPipelineLeases = 0;
        connection.Http1PipelineNextSequence = 1;
        connection.Http1PipelineNextReceiveSequence = 1;
        connection.Http1PipelineFailureStatus = STATUS_SUCCESS;
        FreeHttp1PipelineBuffer(connection);
        SignalHttp1PipelineReceiveEvent(connection);
    }

    NTSTATUS ActiveHttp1PipelineFailureStatus(_In_ const PooledConnection& connection) noexcept
    {
        if (!NT_SUCCESS(connection.Http1PipelineFailureStatus)) {
            return connection.Http1PipelineFailureStatus;
        }

        return STATUS_CONNECTION_DISCONNECTED;
    }

    _Must_inspect_result_
    ULONGLONG QueryPoolTime() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        static volatile LONGLONG time100ns = 0;
        return static_cast<ULONGLONG>(InterlockedAdd64(&time100ns, 10000));
#else
        return KeQueryInterruptTime();
#endif
    }

    _Must_inspect_result_
    bool IsIdleExpired(
        _In_ const ConnectionPool& pool,
        _In_ const PooledConnection& connection,
        ULONGLONG now) noexcept
    {
        if (pool.IdleTimeoutMilliseconds == 0 || connection.LastUsedTime == 0 || now < connection.LastUsedTime) {
            return false;
        }

        const ULONGLONG timeout100ns = static_cast<ULONGLONG>(pool.IdleTimeoutMilliseconds) * 10000ULL;
        return now - connection.LastUsedTime >= timeout100ns;
    }

    bool TextEquals(
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

        return RtlCompareMemory(left, right, leftLength) == leftLength;
    }

    ConnectionKind EffectiveConnectionKind(ConnectionKind kind) noexcept
    {
        return kind == ConnectionKind::None ? ConnectionKind::Tcp : kind;
    }

    bool ProxyIdentityEquals(
        const ConnectionPoolKey& left,
        const ConnectionPoolKey& right) noexcept
    {
        if (left.ProxyEnabled != right.ProxyEnabled) {
            return false;
        }

        if (!left.ProxyEnabled) {
            return true;
        }

        return left.ProxyPort == right.ProxyPort &&
            left.ProxyFamily == right.ProxyFamily &&
            TextEquals(
                left.ProxyHost,
                left.ProxyHostLength,
                right.ProxyHost,
                right.ProxyHostLength) &&
            TextEquals(
                left.ProxyAuthority,
                left.ProxyAuthorityLength,
                right.ProxyAuthority,
                right.ProxyAuthorityLength);
    }

    _Must_inspect_result_
    bool HasConnectionState(_In_ const PooledConnection& connection) noexcept
    {
        if (connection.InUse ||
            connection.Connected ||
            connection.Http2StreamLeases != 0 ||
            connection.Http1PipelineLeases != 0 ||
            connection.Http1MaxPipelineLeases != 0 ||
            connection.Http1PipelineBufferedBytes != nullptr ||
            connection.Http1PipelineBufferedLength != 0 ||
            connection.CloseWhenIdle) {
            return true;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (connection.Kind == ConnectionKind::Tcp)
        {
            return connection.Holder.Tcp.Socket != nullptr || connection.Holder.Tcp.RawTransport != nullptr ||
                   connection.Holder.Tcp.Transport != nullptr || connection.Holder.Tcp.Tls != nullptr ||
                   connection.Holder.Tcp.Http2 != nullptr;
        }
#else
        if (connection.Kind == ConnectionKind::Tcp)
        {
            return connection.Holder.Tcp.Transport != nullptr || connection.Holder.Tcp.Http2 != nullptr;
        }
#endif
        return connection.Kind == ConnectionKind::Quic &&
               (connection.Holder.Quic.Quic != nullptr || connection.Holder.Quic.Http3 != nullptr ||
                connection.Holder.Quic.Evicting);
    }

    _Must_inspect_result_
    bool HasDetachedConnectionResources(_In_ const DetachedConnectionResources& detached) noexcept
    {
        bool hasResources = false;
#if !defined(WKNET_USER_MODE_TEST)
        hasResources = detached.Socket != nullptr ||
            detached.RawTransport != nullptr ||
            detached.Tls != nullptr;
#endif
        return hasResources ||
            detached.Transport != nullptr ||
            detached.Http2 != nullptr;
    }

    _Must_inspect_result_
    bool CanShareHttp2Connection(
        _In_ const PooledConnection& connection,
        _In_ const ConnectionPoolKey& key) noexcept
    {
        if (connection.Kind != ConnectionKind::Tcp || !connection.Connected || connection.CloseWhenIdle ||
            connection.Http2StreamLeases == 0 || connection.Http2MaxStreamLeases == 0 ||
            connection.Http2StreamLeases >= connection.Http2MaxStreamLeases ||
            !ConnectionPoolKeysEqualForAutoAlpnAcquire(key, connection.Key))
        {
            return false;
        }

        if (connection.Holder.Tcp.Http2 == nullptr || connection.Holder.Tcp.Transport == nullptr)
        {
            return false;
        }

        return true;
    }

    _Must_inspect_result_
    bool CanShareHttp1PipelineConnection(
        _In_ const PooledConnection& connection,
        _In_ const ConnectionPoolKey& key,
        ULONG maxPipelineLeases) noexcept
    {
        if (connection.Kind != ConnectionKind::Tcp || !connection.Connected || !connection.InUse ||
            connection.CloseWhenIdle || connection.Http1PipelineLeases == 0 || connection.Http1MaxPipelineLeases == 0 ||
            connection.Http1PipelineLeases >= connection.Http1MaxPipelineLeases || maxPipelineLeases == 0 ||
            connection.Http2StreamLeases != 0 || !ConnectionPoolKeysEqualForAutoAlpnAcquire(key, connection.Key))
        {
            return false;
        }

        return true;
    }

    _Must_inspect_result_ bool CanShareQuicConnection(_In_ const PooledConnection &connection,
                                                      _In_ const ConnectionPoolKey &key) noexcept
    {
        return connection.Kind == ConnectionKind::Quic && connection.Connected && !connection.CloseWhenIdle &&
               !connection.Holder.Quic.GoAwayReceived &&
               !connection.Holder.Quic.Draining && !connection.Holder.Quic.Evicting &&
               !connection.Holder.Quic.WorkerExited && connection.Holder.Quic.Quic != nullptr &&
               connection.Holder.Quic.Http3 != nullptr &&
               connection.Holder.Quic.StreamLeases < connection.Holder.Quic.MaxStreamLeases &&
               ConnectionPoolKeysEqual(connection.Key, key);
    }

    _Must_inspect_result_ bool BeginQuicCloseLocked(_Inout_ ConnectionPool &pool, _Inout_ PooledConnection &connection,
                                                    _Out_ PendingQuicClose *pending) noexcept
    {
        if (pending == nullptr || connection.Kind != ConnectionKind::Quic || connection.Holder.Quic.CloseStarted ||
            connection.Holder.Quic.CloseRoutine == nullptr)
        {
            return false;
        }

        connection.CloseWhenIdle = true;
        connection.InUse = true;
        connection.Holder.Quic.Evicting = true;
        connection.Holder.Quic.CloseStarted = true;
        pending->Routine = connection.Holder.Quic.CloseRoutine;
        pending->Context = connection.Holder.Quic.CloseContext;
        pending->Pool = &pool;
        pending->Connection = &connection;
        pending->Quic = connection.Holder.Quic.Quic;
        pending->Http3 = connection.Holder.Quic.Http3;
        ++pool.QuicCloseOutstanding;
#if !defined(WKNET_USER_MODE_TEST)
        KeClearEvent(&pool.QuicCloseCompleteEvent);
#endif
        return true;
    }

    _Must_inspect_result_
    bool ConnectionPoolHostQuotaKeysEqual(
        _In_ const ConnectionPoolKey& left,
        _In_ const ConnectionPoolKey& right) noexcept
    {
        return EffectiveConnectionKind(left.Kind) == EffectiveConnectionKind(right.Kind) && left.Port == right.Port &&
               left.AddressFamily == right.AddressFamily &&
               TextEquals(left.Scheme, left.SchemeLength, right.Scheme, right.SchemeLength) &&
               TextEquals(left.Host, left.HostLength, right.Host, right.HostLength);
    }

    _Must_inspect_result_
    ULONG CountConnectionsForHostQuota(
        _In_ const ConnectionPool& pool,
        _In_ const ConnectionPoolKey& key) noexcept
    {
        ULONG count = 0;
        if (pool.Entries == nullptr) {
            return 0;
        }

        for (ULONG index = 0; index < pool.Capacity; ++index) {
            const PooledConnection& candidate = pool.Entries[index];
            if ((candidate.Connected || candidate.InUse) &&
                ConnectionPoolHostQuotaKeysEqual(candidate.Key, key)) {
                ++count;
            }
        }
        return count;
    }

    _Must_inspect_result_
    bool DetachIdleConnectionForHostQuotaLocked(
        _Inout_ ConnectionPool& pool,
        _In_ const ConnectionPoolKey& key,
        _Out_ DetachedConnectionResources* detached) noexcept
    {
        if (pool.Entries == nullptr || detached == nullptr) {
            return false;
        }

        for (ULONG index = 0; index < pool.Capacity; ++index) {
            PooledConnection& candidate = pool.Entries[index];
            if (candidate.Kind == ConnectionKind::Tcp && candidate.Connected && !candidate.InUse &&
                candidate.Http2StreamLeases == 0 && candidate.Http1PipelineLeases == 0 &&
                ConnectionPoolHostQuotaKeysEqual(candidate.Key, key))
            {
                DetachConnectionResources(candidate, detached);
                if (pool.ActiveCount != 0) {
                    --pool.ActiveCount;
                }
                return true;
            }
        }

        return false;
    }

    void DetachConnectionResources(
        _Inout_ PooledConnection& connection,
        _Out_ DetachedConnectionResources* detached) noexcept
    {
        if (detached == nullptr || connection.Kind != ConnectionKind::Tcp)
        {
            return;
        }

#if !defined(WKNET_USER_MODE_TEST)
        detached->Socket = connection.Holder.Tcp.Socket;
        detached->RawTransport = connection.Holder.Tcp.RawTransport;
        detached->Tls = connection.Holder.Tcp.Tls;
#endif
        detached->Transport = connection.Holder.Tcp.Transport;
        detached->Http2 = connection.Holder.Tcp.Http2;
        FreeHttp1PipelineBuffer(connection);
        RtlZeroMemory(&connection, sizeof(connection));
        InitializePooledConnectionSlot(connection);
    }

    void CloseDetachedConnectionResources(_Inout_ DetachedConnectionResources* detached) noexcept
    {
        if (detached == nullptr) {
            return;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (detached->Http2 != nullptr) {
            if (detached->Transport != nullptr) {
                const NTSTATUS shutdownStatus = http2::Http2ConnectionShutdown(detached->Http2, detached->Transport);
                UNREFERENCED_PARAMETER(shutdownStatus);
            }
            http2::Http2ConnectionClose(detached->Http2);
            detached->Http2 = nullptr;
        }
        if (detached->Transport != nullptr &&
            detached->Transport != detached->RawTransport) {
            transport::TransportClose(detached->Transport);
            detached->Transport = nullptr;
        }
        if (detached->Tls != nullptr) {
            tls::TlsConnectionClose(detached->Tls);
            detached->Tls = nullptr;
        }
        if (detached->RawTransport != nullptr) {
            transport::TransportClose(detached->RawTransport);
            detached->RawTransport = nullptr;
        }
        if (detached->Socket != nullptr) {
            net::WskSocketDestroy(detached->Socket);
            detached->Socket = nullptr;
        }
#endif
    }

    Http2KeepAliveOptions NormalizeHttp2KeepAliveOptions(
        const Http2KeepAliveOptions* options) noexcept
    {
        Http2KeepAliveOptions normalized = {};
        if (options != nullptr) {
            normalized = *options;
        }

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

    void StoreHttp2KeepAliveOpaqueData(_Inout_ PooledConnection& connection) noexcept
    {
        const ULONGLONG first =
            connection.Id ^
            (static_cast<ULONGLONG>(connection.Http2KeepAliveSequence) << 32);
        const ULONGLONG second =
            0x4B48503250494E47ULL ^
            (static_cast<ULONGLONG>(connection.Http2KeepAliveSequence) << 1) ^
            connection.Id;

        for (ULONG index = 0; index < 4; ++index) {
            connection.Http2KeepAliveOpaqueData[index] =
                static_cast<UCHAR>((first >> (24 - index * 8)) & 0xff);
            connection.Http2KeepAliveOpaqueData[index + 4] =
                static_cast<UCHAR>((second >> (24 - index * 8)) & 0xff);
        }
    }

    bool IsHttp2KeepAliveDue(
        _In_ const ConnectionPool& pool,
        _In_ const PooledConnection& connection,
        ULONGLONG now) noexcept
    {
        if (!pool.Http2KeepAlive.Enabled || !connection.Connected || connection.InUse || connection.CloseWhenIdle ||
            connection.Http2KeepAliveInProgress || connection.Http2StreamLeases != 0 ||
            connection.Http1PipelineLeases != 0 || connection.Kind != ConnectionKind::Tcp ||
            connection.Holder.Tcp.Transport == nullptr || connection.Holder.Tcp.Http2 == nullptr ||
            !http2::Http2ConnectionIsReusable(connection.Holder.Tcp.Http2) || connection.LastUsedTime == 0 ||
            now < connection.LastUsedTime)
        {
            return false;
        }

        const ULONGLONG idle100ns =
            static_cast<ULONGLONG>(pool.Http2KeepAlive.IdleMilliseconds) * 10000ULL;
        if (now - connection.LastUsedTime < idle100ns) {
            return false;
        }

        if (connection.Http2LastKeepAliveTime == 0) {
            return true;
        }

        if (now < connection.Http2LastKeepAliveTime) {
            return true;
        }

        const ULONGLONG interval100ns =
            static_cast<ULONGLONG>(pool.Http2KeepAlive.IntervalMilliseconds) * 10000ULL;
        return now - connection.Http2LastKeepAliveTime >= interval100ns;
    }

#if !defined(WKNET_USER_MODE_TEST)
    void Http2KeepAliveWorkerRoutine(_In_ void* context)
    {
        auto* pool = static_cast<ConnectionPool*>(context);
        if (pool == nullptr) {
            PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        }

        for (;;) {
            LARGE_INTEGER timeout = {};
            timeout.QuadPart =
                -static_cast<LONGLONG>(pool->Http2KeepAlive.IntervalMilliseconds) * 10000LL;
            const NTSTATUS waitStatus = KeWaitForSingleObject(
                &pool->Http2KeepAliveStopEvent,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            if (waitStatus == STATUS_SUCCESS ||
                InterlockedCompareExchange(&pool->Http2KeepAliveStopping, 0, 0) != 0) {
                break;
            }

            bool attempted = false;
            const NTSTATUS sweepStatus = ConnectionPoolRunHttp2KeepAliveSweep(pool, &attempted);
            UNREFERENCED_PARAMETER(sweepStatus);
            UNREFERENCED_PARAMETER(attempted);
        }

        InterlockedExchange(&pool->Http2KeepAliveWorkerStarted, 0);
        PsTerminateSystemThread(STATUS_SUCCESS);
    }
#endif
}

    NTSTATUS ConnectionPoolInitialize(
        ConnectionPool* pool,
        ULONG capacity,
        ULONG maxConnectionsPerHost,
        ULONG idleTimeoutMilliseconds,
        const Http2KeepAliveOptions* http2KeepAlive) noexcept
    {
        if (pool == nullptr ||
            capacity == 0 ||
            maxConnectionsPerHost == 0 ||
            maxConnectionsPerHost > capacity) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(pool, sizeof(*pool));
        InitializePoolLock(pool);
        pool->Http2KeepAlive = NormalizeHttp2KeepAliveOptions(http2KeepAlive);
        if (!IsValidHttp2KeepAliveOptions(pool->Http2KeepAlive)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (static_cast<SIZE_T>(capacity) > static_cast<SIZE_T>(-1) / sizeof(PooledConnection))
        {
            return STATUS_INTEGER_OVERFLOW;
        }
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeEvent(&pool->Http2KeepAliveStopEvent, NotificationEvent, FALSE);
#endif
        if (rtl::ProtocolFailureInjectionShouldFail(rtl::ProtocolAllocationSite::SessionPoolEntries))
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pool->Entries = static_cast<PooledConnection*>(
            AllocatePoolMemory(sizeof(PooledConnection) * capacity));
        if (pool->Entries == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        rtl::ProtocolFailureInjectionRecordAcquire(rtl::ProtocolAllocationSite::SessionPoolEntries);

        pool->Capacity = capacity;
        pool->MaxConnectionsPerHost = maxConnectionsPerHost;
        pool->IdleTimeoutMilliseconds = idleTimeoutMilliseconds;
        for (ULONG index = 0; index < capacity; ++index) {
            InitializePooledConnectionSlot(pool->Entries[index]);
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS ConnectionPoolStartHttp2KeepAlive(ConnectionPool* pool) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!pool->Http2KeepAlive.Enabled) {
            return STATUS_SUCCESS;
        }

#if defined(WKNET_USER_MODE_TEST)
        return STATUS_SUCCESS;
#else
        if (InterlockedCompareExchange(&pool->Http2KeepAliveWorkerStarted, 1, 0) != 0) {
            return STATUS_SUCCESS;
        }

        InterlockedExchange(&pool->Http2KeepAliveStopping, 0);
        KeClearEvent(&pool->Http2KeepAliveStopEvent);

        HANDLE threadHandle = nullptr;
        NTSTATUS status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            nullptr,
            nullptr,
            nullptr,
            Http2KeepAliveWorkerRoutine,
            pool);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&pool->Http2KeepAliveWorkerStarted, 0);
            InterlockedExchange(&pool->Http2KeepAliveStopping, 1);
            KeSetEvent(&pool->Http2KeepAliveStopEvent, IO_NO_INCREMENT, FALSE);
            return status;
        }

        PETHREAD threadObject = nullptr;
        status = ObReferenceObjectByHandle(
            threadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            reinterpret_cast<PVOID*>(&threadObject),
            nullptr);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&pool->Http2KeepAliveStopping, 1);
            KeSetEvent(&pool->Http2KeepAliveStopEvent, IO_NO_INCREMENT, FALSE);
            LARGE_INTEGER timeout = {};
            timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
            const NTSTATUS waitStatus = ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
            UNREFERENCED_PARAMETER(waitStatus);
            ZwClose(threadHandle);
            InterlockedExchange(&pool->Http2KeepAliveWorkerStarted, 0);
            return status;
        }

        ZwClose(threadHandle);
        pool->Http2KeepAliveThread = threadObject;
        return STATUS_SUCCESS;
#endif
    }

    void ConnectionPoolStopHttp2KeepAlive(ConnectionPool* pool) noexcept
    {
        if (pool == nullptr) {
            return;
        }

#if !defined(WKNET_USER_MODE_TEST)
        PETHREAD thread = nullptr;
        if (pool->Http2KeepAliveThread != nullptr ||
            InterlockedCompareExchange(&pool->Http2KeepAliveWorkerStarted, 0, 0) != 0) {
            InterlockedExchange(&pool->Http2KeepAliveStopping, 1);
            KeSetEvent(&pool->Http2KeepAliveStopEvent, IO_NO_INCREMENT, FALSE);
            thread = pool->Http2KeepAliveThread;
        }

        if (thread != nullptr) {
            LARGE_INTEGER timeout = {};
            timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
            const NTSTATUS waitStatus = KeWaitForSingleObject(
                thread,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            UNREFERENCED_PARAMETER(waitStatus);
            ObDereferenceObject(thread);
            pool->Http2KeepAliveThread = nullptr;
        }

        InterlockedExchange(&pool->Http2KeepAliveStopping, 0);
#endif
    }

    NTSTATUS ConnectionPoolRunHttp2KeepAliveSweep(
        ConnectionPool* pool,
        bool* attempted) noexcept
    {
        if (attempted != nullptr) {
            *attempted = false;
        }
        if (pool == nullptr || pool->Entries == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!pool->Http2KeepAlive.Enabled) {
            return STATUS_SUCCESS;
        }

        PooledConnection* selected = nullptr;
        transport::Transport* transport = nullptr;
        http2::Http2Connection* http2Connection = nullptr;
        const UCHAR* opaqueData = nullptr;
        const ULONGLONG now = QueryPoolTime();

        LockPool(pool);
        for (ULONG index = 0; index < pool->Capacity; ++index) {
            PooledConnection& candidate = pool->Entries[index];
            if (!IsHttp2KeepAliveDue(*pool, candidate, now)) {
                continue;
            }

            candidate.InUse = true;
            candidate.Http2KeepAliveInProgress = true;
            ++candidate.Http2KeepAliveSequence;
            StoreHttp2KeepAliveOpaqueData(candidate);
            selected = &candidate;
            transport = candidate.Holder.Tcp.Transport;
            http2Connection = candidate.Holder.Tcp.Http2;
            opaqueData = candidate.Http2KeepAliveOpaqueData;
            if (attempted != nullptr) {
                *attempted = true;
            }
            break;
        }
        UnlockPool(pool);

        if (selected == nullptr) {
            return STATUS_SUCCESS;
        }

        NTSTATUS status = http2::Http2ConnectionSendPingAndWaitForAck(http2Connection,
            transport,
            opaqueData,
            pool->Http2KeepAlive.AckTimeoutMilliseconds);

        DetachedConnectionResources detached = {};
        LockPool(pool);
        selected->Http2KeepAliveInProgress = false;
        if (NT_SUCCESS(status) && selected->Holder.Tcp.Http2 != nullptr &&
            http2::Http2ConnectionIsReusable(selected->Holder.Tcp.Http2))
        {
            selected->Http2LastKeepAliveTime = QueryPoolTime();
            selected->LastUsedTime = selected->Http2LastKeepAliveTime;
            selected->InUse = false;
        }
        else {
            if (NT_SUCCESS(status)) {
                status = STATUS_CONNECTION_DISCONNECTED;
            }
            const bool wasConnected = selected->Connected;
            DetachConnectionResources(*selected, &detached);
            if (wasConnected && pool->ActiveCount != 0) {
                --pool->ActiveCount;
            }
        }
        UnlockPool(pool);

        CloseDetachedConnectionResources(&detached);
        return status;
    }

    void ConnectionPoolShutdown(ConnectionPool* pool) noexcept
    {
        if (pool == nullptr) {
            return;
        }

        ConnectionPoolStopHttp2KeepAlive(pool);

        if (pool->Entries == nullptr) {
            RtlZeroMemory(pool, sizeof(*pool));
            return;
        }

        for (;;) {
            DetachedConnectionResources detached = {};
            PendingQuicClose pending = {};
            bool found = false;

            LockPool(pool);
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                PooledConnection& entry = pool->Entries[index];
                if (!HasConnectionState(entry)) {
                    continue;
                }

                if (entry.Kind == ConnectionKind::Quic)
                {
                    if (entry.Holder.Quic.CloseStarted)
                    {
                        continue;
                    }
                    found = BeginQuicCloseLocked(*pool, entry, &pending);
                    if (found)
                    {
                        break;
                    }
                    continue;
                }

                const bool wasConnected = entry.Connected;
                DetachConnectionResources(entry, &detached);
                if (wasConnected && pool->ActiveCount != 0) {
                    --pool->ActiveCount;
                }
                found = true;
                break;
            }
            UnlockPool(pool);

            CloseDetachedConnectionResources(&detached);
            StartPendingQuicClose(&pending);
            if (!found) {
                break;
            }
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (pool->QuicCloseOutstanding != 0)
        {
            const NTSTATUS waitStatus =
                KeWaitForSingleObject(&pool->QuicCloseCompleteEvent, Executive, KernelMode, FALSE, nullptr);
            UNREFERENCED_PARAMETER(waitStatus);
        }
#else
        if (pool->QuicCloseOutstanding != 0)
        {
            return;
        }
#endif

        RtlSecureZeroMemory(pool->Entries, sizeof(PooledConnection) * pool->Capacity);
        const bool entriesReleased =
            rtl::ProtocolFailureInjectionRecordRelease(rtl::ProtocolAllocationSite::SessionPoolEntries);
        UNREFERENCED_PARAMETER(entriesReleased);
        FreePoolMemory(pool->Entries);
        RtlZeroMemory(pool, sizeof(*pool));
    }

    _Must_inspect_result_
    bool ConnectionPoolKeysEqualExceptAlpn(
        const ConnectionPoolKey& left,
        const ConnectionPoolKey& right) noexcept
    {
        return EffectiveConnectionKind(left.Kind) == EffectiveConnectionKind(right.Kind) && left.Port == right.Port &&
               left.AddressFamily == right.AddressFamily && left.MinTlsVersion == right.MinTlsVersion &&
               left.MaxTlsVersion == right.MaxTlsVersion && left.CertificatePolicy == right.CertificatePolicy &&
               left.CertificateStoreIdentity == right.CertificateStoreIdentity &&
               left.ClientCredentialIdentity == right.ClientCredentialIdentity &&
               left.MaxTls12Renegotiations == right.MaxTls12Renegotiations &&
               left.Policy.Profile == right.Policy.Profile &&
               left.Policy.EnableTls12RsaKeyExchange == right.Policy.EnableTls12RsaKeyExchange &&
               left.Policy.EnableTls12Cbc == right.Policy.EnableTls12Cbc &&
               left.Policy.EnableTls12Renegotiation == right.Policy.EnableTls12Renegotiation &&
               left.Policy.EnableTls12Sha1Signatures == right.Policy.EnableTls12Sha1Signatures &&
               left.Policy.EnablePostHandshakeClientAuth == right.Policy.EnablePostHandshakeClientAuth &&
               left.Policy.RequireRevocationCheck == right.Policy.RequireRevocationCheck &&
               left.AutomaticAlpn == right.AutomaticAlpn && left.Http2CleartextMode == right.Http2CleartextMode &&
               ProxyIdentityEquals(left, right) && left.AlternativePort == right.AlternativePort &&
               left.QuicVersion == right.QuicVersion &&
               TextEquals(left.Scheme, left.SchemeLength, right.Scheme, right.SchemeLength) &&
               TextEquals(left.Host, left.HostLength, right.Host, right.HostLength) &&
               TextEquals(left.AlternativeHost, left.AlternativeHostLength, right.AlternativeHost,
                          right.AlternativeHostLength) &&
               TextEquals(left.TlsServerName, left.TlsServerNameLength, right.TlsServerName, right.TlsServerNameLength);
    }

    bool ConnectionPoolKeysEqual(
        const ConnectionPoolKey& left,
        const ConnectionPoolKey& right) noexcept
    {
        return ConnectionPoolKeysEqualExceptAlpn(left, right) &&
            TextEquals(left.Alpn, left.AlpnLength, right.Alpn, right.AlpnLength);
    }

    bool ConnectionPoolKeysEqualForAutoAlpnAcquire(
        const ConnectionPoolKey& left,
        const ConnectionPoolKey& right) noexcept
    {
        if (EffectiveConnectionKind(left.Kind) != ConnectionKind::Tcp ||
            EffectiveConnectionKind(right.Kind) != ConnectionKind::Tcp)
        {
            return ConnectionPoolKeysEqual(left, right);
        }
        if (left.AlpnLength != 0 || right.AlpnLength == 0) {
            return ConnectionPoolKeysEqual(left, right);
        }

        if (!left.AutomaticAlpn || !right.AutomaticAlpn) {
            return ConnectionPoolKeysEqual(left, right);
        }

        return ConnectionPoolKeysEqualExceptAlpn(left, right);
    }

    NTSTATUS ConnectionPoolAcquire(
        ConnectionPool* pool,
        const ConnectionPoolKey& key,
        ConnectionPolicy policy,
        PooledConnection** connection,
        bool* reused) noexcept
    {
        if (connection != nullptr) {
            *connection = nullptr;
        }
        if (reused != nullptr) {
            *reused = false;
        }

        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr || reused == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        const ConnectionKind requestedKind = EffectiveConnectionKind(key.Kind);
        if (requestedKind == ConnectionKind::Quic &&
            (key.ProxyEnabled || key.QuicVersion == 0 || !TextEquals(key.Alpn, key.AlpnLength, "h3", 2)))
        {
            return STATUS_INVALID_PARAMETER;
        }

        DetachedConnectionResources detached = {};
        PendingQuicClose pending = {};
        PooledConnection* selected = nullptr;
        const ULONGLONG now = QueryPoolTime();

        LockPool(pool);
        if (policy != ConnectionPolicy::ForceNew && policy != ConnectionPolicy::NoPool) {
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                PooledConnection& candidate = pool->Entries[index];
                if (candidate.Kind == ConnectionKind::Quic && !candidate.InUse &&
                    candidate.Holder.Quic.StreamLeases == 0 && !candidate.Holder.Quic.ActiveRequest &&
                    IsIdleExpired(*pool, candidate, now))
                {
                    BeginQuicCloseLocked(*pool, candidate, &pending);
                    continue;
                }
                if (CanShareQuicConnection(candidate, key))
                {
                    ++candidate.Holder.Quic.StreamLeases;
                    candidate.Holder.Quic.ActiveRequest = true;
                    candidate.InUse = true;
                    selected = &candidate;
                    *reused = true;
                    break;
                }
                if (candidate.InUse && CanShareHttp2Connection(candidate, key)) {
                    ++candidate.Http2StreamLeases;
                    selected = &candidate;
                    *reused = true;
                    break;
                }

                if (candidate.Kind == ConnectionKind::Tcp && candidate.Connected && !candidate.InUse &&
                    candidate.Http2StreamLeases == 0 && candidate.Http1PipelineLeases == 0 &&
                    ConnectionPoolKeysEqualForAutoAlpnAcquire(key, candidate.Key))
                {
                    if (IsIdleExpired(*pool, candidate, now)) {
                        DetachConnectionResources(candidate, &detached);
                        if (pool->ActiveCount != 0) {
                            --pool->ActiveCount;
                        }
                        break;
                    }

                    candidate.InUse = true;
                    selected = &candidate;
                    *reused = true;
                    break;
                }
            }
        }

        if (selected == nullptr) {
            if (policy == ConnectionPolicy::ForceNew || policy == ConnectionPolicy::NoPool)
            {
                for (ULONG index = 0; index < pool->Capacity; ++index)
                {
                    PooledConnection &candidate = pool->Entries[index];
                    if (candidate.Kind == ConnectionKind::Quic && !candidate.InUse &&
                        candidate.Holder.Quic.StreamLeases == 0 && !candidate.Holder.Quic.ActiveRequest &&
                        ConnectionPoolHostQuotaKeysEqual(candidate.Key, key))
                    {
                        BeginQuicCloseLocked(*pool, candidate, &pending);
                        break;
                    }
                }
            }
            if (CountConnectionsForHostQuota(*pool, key) >= pool->MaxConnectionsPerHost) {
                bool idleDetached = HasDetachedConnectionResources(detached);
                if (!idleDetached) {
                    idleDetached = DetachIdleConnectionForHostQuotaLocked(*pool, key, &detached);
                }
                if (!idleDetached ||
                    CountConnectionsForHostQuota(*pool, key) >= pool->MaxConnectionsPerHost) {
                    UnlockPool(pool);
                    CloseDetachedConnectionResources(&detached);
                    StartPendingQuicClose(&pending);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }

            for (ULONG index = 0; index < pool->Capacity; ++index) {
                PooledConnection& candidate = pool->Entries[index];
                if (candidate.Kind == ConnectionKind::None && !candidate.Connected && !candidate.InUse &&
                    candidate.Http2StreamLeases == 0 && candidate.Http1PipelineLeases == 0)
                {
                    if (HasConnectionState(candidate)) {
                        if (HasDetachedConnectionResources(detached)) {
                            continue;
                        }
                        DetachConnectionResources(candidate, &detached);
                    }
                    candidate.InUse = true;
                    candidate.Connected = true;
                    candidate.Key = key;
                    candidate.Kind = requestedKind;
                    if (requestedKind == ConnectionKind::Quic)
                    {
                        candidate.Holder.Quic.ActiveRequest = true;
                    }
                    candidate.Id = rtl::TraceAllocateCorrelationId();
                    candidate.LastUsedTime = 0;
                    ++pool->ActiveCount;
                    selected = &candidate;
                    break;
                }
            }
        }

        if (selected == nullptr && policy != ConnectionPolicy::NoPool) {
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                PooledConnection& candidate = pool->Entries[index];
                if (candidate.Kind == ConnectionKind::Tcp && !candidate.InUse && candidate.Http2StreamLeases == 0 &&
                    candidate.Http1PipelineLeases == 0)
                {
                    const bool wasConnected = candidate.Connected;
                    if (HasConnectionState(candidate)) {
                        if (HasDetachedConnectionResources(detached)) {
                            continue;
                        }
                        DetachConnectionResources(candidate, &detached);
                    }
                    candidate.InUse = true;
                    candidate.Connected = true;
                    candidate.Key = key;
                    candidate.Kind = requestedKind;
                    if (requestedKind == ConnectionKind::Quic)
                    {
                        candidate.Holder.Quic.ActiveRequest = true;
                    }
                    candidate.Id = rtl::TraceAllocateCorrelationId();
                    candidate.LastUsedTime = 0;
                    if (!wasConnected) {
                        ++pool->ActiveCount;
                    }
                    selected = &candidate;
                    break;
                }
            }
        }
        UnlockPool(pool);

        CloseDetachedConnectionResources(&detached);
        StartPendingQuicClose(&pending);

        if (selected == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        *connection = selected;
        return STATUS_SUCCESS;
    }

    NTSTATUS ConnectionPoolAcquireHttp1Pipeline(
        ConnectionPool* pool,
        const ConnectionPoolKey& key,
        ConnectionPolicy policy,
        ULONG maxPipelineLeases,
        PooledConnection** connection,
        bool* reused) noexcept
    {
        if (connection != nullptr) {
            *connection = nullptr;
        }
        if (reused != nullptr) {
            *reused = false;
        }

        if (maxPipelineLeases == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr || reused == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (policy == ConnectionPolicy::ReuseOrCreate) {
            LockPool(pool);
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                PooledConnection& candidate = pool->Entries[index];
                if (CanShareHttp1PipelineConnection(candidate, key, maxPipelineLeases)) {
                    ++candidate.Http1PipelineLeases;
                    *connection = &candidate;
                    *reused = true;
                    UnlockPool(pool);
                    return STATUS_SUCCESS;
                }
            }
            UnlockPool(pool);
        }

        return ConnectionPoolAcquire(pool, key, policy, connection, reused);
    }

    void ConnectionPoolRelease(
        ConnectionPool* pool,
        PooledConnection* connection,
        bool reusable) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr) {
            return;
        }

        if (connection->Kind == ConnectionKind::Quic)
        {
            ConnectionPoolReleaseHttp3StreamLease(pool, connection, reusable);
            return;
        }

        if (!reusable) {
            DetachedConnectionResources detached = {};
            LockPool(pool);
            if (connection->Http2StreamLeases != 0) {
                --connection->Http2StreamLeases;
                connection->CloseWhenIdle = true;
                if (connection->Http2StreamLeases == 0) {
                    const bool wasConnected = connection->Connected;
                    DetachConnectionResources(*connection, &detached);
                    if (wasConnected && pool->ActiveCount != 0) {
                        --pool->ActiveCount;
                    }
                }
            }
            else if (connection->Http1PipelineLeases != 0) {
                --connection->Http1PipelineLeases;
                connection->CloseWhenIdle = true;
                if (NT_SUCCESS(connection->Http1PipelineFailureStatus)) {
                    connection->Http1PipelineFailureStatus = STATUS_CONNECTION_DISCONNECTED;
                }
                SignalHttp1PipelineReceiveEvent(*connection);
                if (connection->Http1PipelineLeases == 0) {
                    const bool wasConnected = connection->Connected;
                    DetachConnectionResources(*connection, &detached);
                    if (wasConnected && pool->ActiveCount != 0) {
                        --pool->ActiveCount;
                    }
                }
            }
            else {
                const bool wasConnected = connection->Connected;
                DetachConnectionResources(*connection, &detached);
                if (wasConnected && pool->ActiveCount != 0) {
                    --pool->ActiveCount;
                }
            }
            UnlockPool(pool);
            CloseDetachedConnectionResources(&detached);
            return;
        }

        DetachedConnectionResources detached = {};
        LockPool(pool);
        if (connection->Http2StreamLeases != 0) {
            --connection->Http2StreamLeases;
            if (connection->Http2StreamLeases == 0) {
                if (connection->CloseWhenIdle) {
                    const bool wasConnected = connection->Connected;
                    DetachConnectionResources(*connection, &detached);
                    if (wasConnected && pool->ActiveCount != 0) {
                        --pool->ActiveCount;
                    }
                }
                else {
                    connection->LastUsedTime = QueryPoolTime();
                    connection->InUse = false;
                }
            }
        }
        else if (connection->Http1PipelineLeases != 0) {
            --connection->Http1PipelineLeases;
            if (connection->Http1PipelineLeases == 0) {
                if (connection->CloseWhenIdle || connection->Http1PipelineBufferedLength != 0) {
                    const bool wasConnected = connection->Connected;
                    DetachConnectionResources(*connection, &detached);
                    if (wasConnected && pool->ActiveCount != 0) {
                        --pool->ActiveCount;
                    }
                }
                else {
                    ResetHttp1PipelineLeaseState(*connection);
                    connection->LastUsedTime = QueryPoolTime();
                    connection->InUse = false;
                }
            }
        }
        else {
            connection->LastUsedTime = QueryPoolTime();
            connection->InUse = false;
        }
        UnlockPool(pool);
        CloseDetachedConnectionResources(&detached);
    }

    NTSTATUS PooledConnectionAdoptQuic(PooledConnection *connection, quic::QuicConnection *quicConnection,
                                       http3::Http3Connection *http3Connection, PooledQuicCloseRoutine closeRoutine,
                                       void *closeContext) noexcept
    {
        if (connection == nullptr || quicConnection == nullptr || http3Connection == nullptr || closeRoutine == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (connection->Kind != ConnectionKind::Quic || connection->Holder.Quic.Quic != nullptr ||
            connection->Holder.Quic.Http3 != nullptr)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        connection->Holder.Quic.Quic = quicConnection;
        connection->Holder.Quic.Http3 = http3Connection;
        connection->Holder.Quic.CloseRoutine = closeRoutine;
        connection->Holder.Quic.CloseContext = closeContext;
        return STATUS_SUCCESS;
    }

    void ConnectionPoolAbandonQuicAcquire(ConnectionPool *pool, PooledConnection *connection) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr)
        {
            return;
        }

        LockPool(pool);
        if (connection->Kind == ConnectionKind::Quic && connection->Holder.Quic.Quic == nullptr &&
            connection->Holder.Quic.Http3 == nullptr)
        {
            const bool wasConnected = connection->Connected;
            RtlSecureZeroMemory(&connection->Holder, sizeof(connection->Holder));
            RtlZeroMemory(&connection->Key, sizeof(connection->Key));
            connection->Kind = ConnectionKind::None;
            connection->InUse = false;
            connection->Connected = false;
            connection->CloseWhenIdle = false;
            connection->LastUsedTime = 0;
            if (wasConnected && pool->ActiveCount != 0)
            {
                --pool->ActiveCount;
            }
        }
        UnlockPool(pool);
    }

    quic::QuicConnection *PooledConnectionQuic(PooledConnection *connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Quic ? connection->Holder.Quic.Quic
                                                                                 : nullptr;
    }

    http3::Http3Connection *PooledConnectionHttp3(PooledConnection *connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Quic ? connection->Holder.Quic.Http3
                                                                                 : nullptr;
    }

    void *PooledConnectionQuicCloseContext(PooledConnection *connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Quic ? connection->Holder.Quic.CloseContext
                                                                                 : nullptr;
    }

    NTSTATUS ConnectionPoolPromoteHttp3StreamLease(ConnectionPool *pool, PooledConnection *connection,
                                                   ULONGLONG streamId, ULONG peerMaxStreams,
                                                   ULONG localMaxStreams) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr || peerMaxStreams == 0 ||
            localMaxStreams == 0 || (streamId & 3ULL) != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        LockPool(pool);
        if (connection->Kind != ConnectionKind::Quic || !connection->Connected || connection->CloseWhenIdle ||
            connection->Holder.Quic.GoAwayReceived || connection->Holder.Quic.Draining ||
            connection->Holder.Quic.Evicting || connection->Holder.Quic.WorkerExited ||
            connection->Holder.Quic.Quic == nullptr || connection->Holder.Quic.Http3 == nullptr)
        {
            UnlockPool(pool);
            return STATUS_INVALID_DEVICE_STATE;
        }

        const ULONG maxStreams = peerMaxStreams < localMaxStreams ? peerMaxStreams : localMaxStreams;
        if (connection->Holder.Quic.StreamLeases >= maxStreams)
        {
            UnlockPool(pool);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        connection->Holder.Quic.MaxStreamLeases = maxStreams;
        ++connection->Holder.Quic.StreamLeases;
        connection->Holder.Quic.LastStreamId = streamId;
        connection->InUse = true;
        UnlockPool(pool);
        return STATUS_SUCCESS;
    }

    NTSTATUS ConnectionPoolBindHttp3StreamLease(ConnectionPool *pool, PooledConnection *connection, ULONGLONG streamId,
                                                ULONG peerMaxStreams, ULONG localMaxStreams) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr || peerMaxStreams == 0 ||
            localMaxStreams == 0 || (streamId & 3ULL) != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        LockPool(pool);
        if (connection->Kind != ConnectionKind::Quic || !connection->Connected || connection->CloseWhenIdle ||
            connection->Holder.Quic.GoAwayReceived || connection->Holder.Quic.Draining ||
            connection->Holder.Quic.Evicting || connection->Holder.Quic.WorkerExited ||
            connection->Holder.Quic.Quic == nullptr || connection->Holder.Quic.Http3 == nullptr ||
            connection->Holder.Quic.StreamLeases == 0 || !connection->Holder.Quic.ActiveRequest)
        {
            UnlockPool(pool);
            return STATUS_INVALID_DEVICE_STATE;
        }

        const ULONG maxStreams = peerMaxStreams < localMaxStreams ? peerMaxStreams : localMaxStreams;
        if (connection->Holder.Quic.StreamLeases > maxStreams)
        {
            UnlockPool(pool);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        connection->Holder.Quic.MaxStreamLeases = maxStreams;
        connection->Holder.Quic.LastStreamId = streamId;
        UnlockPool(pool);
        return STATUS_SUCCESS;
    }

    void ConnectionPoolReleaseHttp3StreamLease(ConnectionPool *pool, PooledConnection *connection,
                                               bool reusable) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr)
        {
            return;
        }

        PendingQuicClose pending = {};
        LockPool(pool);
        if (connection->Kind != ConnectionKind::Quic)
        {
            UnlockPool(pool);
            return;
        }
        if (connection->Holder.Quic.StreamLeases != 0)
        {
            --connection->Holder.Quic.StreamLeases;
        }
        connection->Holder.Quic.ActiveRequest = connection->Holder.Quic.StreamLeases != 0;
        if (!reusable)
        {
            connection->CloseWhenIdle = true;
        }
        if (connection->Holder.Quic.StreamLeases == 0 && !connection->Holder.Quic.ActiveRequest)
        {
            if (connection->CloseWhenIdle || connection->Holder.Quic.GoAwayReceived ||
                connection->Holder.Quic.Draining || connection->Holder.Quic.WorkerExited)
            {
                BeginQuicCloseLocked(*pool, *connection, &pending);
            }
            else
            {
                connection->InUse = false;
                connection->LastUsedTime = QueryPoolTime();
            }
        }
        UnlockPool(pool);
        StartPendingQuicClose(&pending);
    }

    void ConnectionPoolSetHttp3GoAway(ConnectionPool *pool, PooledConnection *connection,
                                      ULONGLONG goAwayStreamId) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr)
        {
            return;
        }
        PendingQuicClose pending = {};
        LockPool(pool);
        if (connection->Kind == ConnectionKind::Quic && (goAwayStreamId & 3ULL) == 0)
        {
            if (!connection->Holder.Quic.GoAwayReceived || goAwayStreamId <= connection->Holder.Quic.GoAwayStreamId)
            {
                connection->Holder.Quic.GoAwayReceived = true;
                connection->Holder.Quic.GoAwayStreamId = goAwayStreamId;
                connection->CloseWhenIdle = true;
                if (connection->Holder.Quic.StreamLeases == 0 && !connection->Holder.Quic.ActiveRequest)
                {
                    BeginQuicCloseLocked(*pool, *connection, &pending);
                }
            }
        }
        UnlockPool(pool);
        StartPendingQuicClose(&pending);
    }

    void ConnectionPoolSetQuicActiveRequest(ConnectionPool *pool, PooledConnection *connection, bool active) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr)
        {
            return;
        }
        PendingQuicClose pending = {};
        LockPool(pool);
        if (connection->Kind == ConnectionKind::Quic)
        {
            connection->Holder.Quic.ActiveRequest = active;
            if (!active && connection->Holder.Quic.StreamLeases == 0 && connection->CloseWhenIdle)
            {
                BeginQuicCloseLocked(*pool, *connection, &pending);
            }
        }
        UnlockPool(pool);
        StartPendingQuicClose(&pending);
    }

    void ConnectionPoolSetQuicDraining(ConnectionPool *pool, PooledConnection *connection) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr)
        {
            return;
        }
        PendingQuicClose pending = {};
        LockPool(pool);
        if (connection->Kind == ConnectionKind::Quic)
        {
            connection->Holder.Quic.Draining = true;
            connection->CloseWhenIdle = true;
            if (connection->Holder.Quic.StreamLeases == 0 && !connection->Holder.Quic.ActiveRequest)
            {
                BeginQuicCloseLocked(*pool, *connection, &pending);
            }
        }
        UnlockPool(pool);
        StartPendingQuicClose(&pending);
    }

    void ConnectionPoolSetQuicWorkerExited(ConnectionPool *pool, PooledConnection *connection) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr)
        {
            return;
        }
        PendingQuicClose pending = {};
        LockPool(pool);
        if (connection->Kind == ConnectionKind::Quic)
        {
            connection->Holder.Quic.WorkerExited = true;
            connection->CloseWhenIdle = true;
            if (connection->Holder.Quic.StreamLeases == 0 && !connection->Holder.Quic.ActiveRequest)
            {
                BeginQuicCloseLocked(*pool, *connection, &pending);
            }
        }
        UnlockPool(pool);
        StartPendingQuicClose(&pending);
    }

    void ConnectionPoolCompleteQuicClose(ConnectionPool *pool, PooledConnection *connection) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr)
        {
            return;
        }

        LockPool(pool);
        if (connection->Kind == ConnectionKind::Quic && connection->Holder.Quic.CloseStarted)
        {
            const bool wasConnected = connection->Connected;
            RtlSecureZeroMemory(&connection->Holder, sizeof(connection->Holder));
            RtlZeroMemory(&connection->Key, sizeof(connection->Key));
            connection->Kind = ConnectionKind::None;
            connection->InUse = false;
            connection->Connected = false;
            connection->CloseWhenIdle = false;
            connection->LastUsedTime = 0;
            if (wasConnected && pool->ActiveCount != 0)
            {
                --pool->ActiveCount;
            }
            if (pool->QuicCloseOutstanding != 0)
            {
                --pool->QuicCloseOutstanding;
            }
#if !defined(WKNET_USER_MODE_TEST)
            if (pool->QuicCloseOutstanding == 0)
            {
                KeSetEvent(&pool->QuicCloseCompleteEvent, IO_NO_INCREMENT, FALSE);
            }
#endif
        }
        UnlockPool(pool);
    }

#if !defined(WKNET_USER_MODE_TEST)
    NTSTATUS PooledConnectionAdoptSocket(
        PooledConnection* connection,
        net::WskSocket* socket,
        transport::Transport* transport) noexcept
    {
        if (connection == nullptr || socket == nullptr || transport == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (connection->Kind != ConnectionKind::Tcp || connection->Holder.Tcp.Socket != nullptr ||
            connection->Holder.Tcp.RawTransport != nullptr || connection->Holder.Tcp.Transport != nullptr ||
            connection->Holder.Tcp.Tls != nullptr || connection->Holder.Tcp.Http2 != nullptr)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        connection->Holder.Tcp.Socket = socket;
        connection->Holder.Tcp.RawTransport = transport;
        connection->Holder.Tcp.Transport = transport;
        net::WskSocketSetConnectionId(socket, connection->Id);
        transport::TransportSetConnectionId(transport, connection->Id);
        connection->ProxyTunnelEstablished = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS PooledConnectionAdoptTls(
        PooledConnection* connection,
        tls::TlsConnection* tlsConnection,
        transport::Transport* transport) noexcept
    {
        if (connection == nullptr || tlsConnection == nullptr || transport == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (connection->Kind != ConnectionKind::Tcp || connection->Holder.Tcp.RawTransport == nullptr ||
            connection->Holder.Tcp.Transport != connection->Holder.Tcp.RawTransport ||
            connection->Holder.Tcp.Tls != nullptr || connection->Holder.Tcp.Http2 != nullptr)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        connection->Holder.Tcp.Tls = tlsConnection;
        connection->Holder.Tcp.Transport = transport;
        tls::TlsConnectionSetConnectionId(tlsConnection, connection->Id);
        transport::TransportSetConnectionId(transport, connection->Id);
        return STATUS_SUCCESS;
    }
#endif

    NTSTATUS PooledConnectionAdoptHttp2(
        PooledConnection* connection,
        http2::Http2Connection* http2Connection) noexcept
    {
        if (connection == nullptr || http2Connection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (connection->Kind != ConnectionKind::Tcp || connection->Holder.Tcp.Transport == nullptr ||
            connection->Holder.Tcp.Http2 != nullptr)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }

        connection->Holder.Tcp.Http2 = http2Connection;
        return STATUS_SUCCESS;
    }

    void PooledConnectionReleaseHttp2(PooledConnection* connection) noexcept
    {
        if (connection == nullptr || connection->Kind != ConnectionKind::Tcp || connection->Holder.Tcp.Http2 == nullptr)
        {
            return;
        }

        if (connection->Holder.Tcp.Transport != nullptr)
        {
            const NTSTATUS shutdownStatus =
                http2::Http2ConnectionShutdown(connection->Holder.Tcp.Http2, connection->Holder.Tcp.Transport);
            UNREFERENCED_PARAMETER(shutdownStatus);
        }
        http2::Http2ConnectionClose(connection->Holder.Tcp.Http2);
        connection->Holder.Tcp.Http2 = nullptr;
    }

#if !defined(WKNET_USER_MODE_TEST)
    void PooledConnectionReleaseTls(PooledConnection* connection) noexcept
    {
        if (connection == nullptr) {
            return;
        }

        PooledConnectionReleaseHttp2(connection);
        if (connection->Holder.Tcp.Transport != nullptr &&
            connection->Holder.Tcp.Transport != connection->Holder.Tcp.RawTransport)
        {
            transport::TransportClose(connection->Holder.Tcp.Transport);
            connection->Holder.Tcp.Transport = connection->Holder.Tcp.RawTransport;
        }
        if (connection->Holder.Tcp.Tls != nullptr)
        {
            tls::TlsConnectionClose(connection->Holder.Tcp.Tls);
            connection->Holder.Tcp.Tls = nullptr;
        }
    }

    void PooledConnectionCloseTransportResources(PooledConnection* connection) noexcept
    {
        if (connection == nullptr) {
            return;
        }

        PooledConnectionReleaseTls(connection);
        if (connection->Holder.Tcp.RawTransport != nullptr)
        {
            transport::TransportClose(connection->Holder.Tcp.RawTransport);
            connection->Holder.Tcp.RawTransport = nullptr;
            connection->Holder.Tcp.Transport = nullptr;
        }
        if (connection->Holder.Tcp.Socket != nullptr)
        {
            net::WskSocketDestroy(connection->Holder.Tcp.Socket);
            connection->Holder.Tcp.Socket = nullptr;
        }

        connection->LastUsedTime = 0;
        connection->ProxyTunnelEstablished = false;
    }
#endif

    void PooledConnectionSetProxyTunnelEstablished(
        PooledConnection* connection,
        bool established) noexcept
    {
        if (connection != nullptr) {
            connection->ProxyTunnelEstablished = established;
        }
    }

    ULONGLONG PooledConnectionId(const PooledConnection* connection) noexcept
    {
        return connection != nullptr ? connection->Id : 0;
    }

    bool PooledConnectionProxyTunnelEstablished(const PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->ProxyTunnelEstablished;
    }

    transport::Transport* PooledConnectionTransport(PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Tcp ? connection->Holder.Tcp.Transport
                                                                                : nullptr;
    }

    http2::Http2Connection* PooledConnectionHttp2(PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Tcp ? connection->Holder.Tcp.Http2
                                                                                : nullptr;
    }

#if !defined(WKNET_USER_MODE_TEST)
    net::WskSocket* PooledConnectionSocket(PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Tcp ? connection->Holder.Tcp.Socket
                                                                                : nullptr;
    }

    transport::Transport* PooledConnectionRawTransport(PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Tcp ? connection->Holder.Tcp.RawTransport
                                                                                : nullptr;
    }

    tls::TlsConnection* PooledConnectionTls(PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Tcp ? connection->Holder.Tcp.Tls : nullptr;
    }
#endif

    NTSTATUS PooledConnectionSetAlpn(
        PooledConnection* connection,
        const char* alpn,
        SIZE_T alpnLength) noexcept
    {
        if (connection == nullptr ||
            (alpnLength != 0 && alpn == nullptr) ||
            alpnLength > PoolMaxAlpnLength) {
            return STATUS_INVALID_PARAMETER;
        }
        RtlZeroMemory(connection->Key.Alpn, sizeof(connection->Key.Alpn));
        if (alpnLength != 0) {
            RtlCopyMemory(connection->Key.Alpn, alpn, alpnLength);
        }
        connection->Key.AlpnLength = alpnLength;
        return STATUS_SUCCESS;
    }

#if defined(WKNET_USER_MODE_TEST)
    void PooledConnectionAttachTestState(
        PooledConnection* connection,
        transport::Transport* transport,
        http2::Http2Connection* http2Connection) noexcept
    {
        if (connection != nullptr) {
            connection->Holder.Tcp.Transport = transport;
            connection->Holder.Tcp.Http2 = http2Connection;
            transport::TransportSetConnectionId(transport, connection->Id);
        }
    }

    ULONGLONG PooledConnectionHttp2LastKeepAliveTime(
        const PooledConnection* connection) noexcept
    {
        return connection != nullptr ? connection->Http2LastKeepAliveTime : 0;
    }

    ULONG PooledConnectionQuicStreamLeaseCount(const PooledConnection *connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Quic
                   ? connection->Holder.Quic.StreamLeases
                   : 0;
    }

    bool PooledConnectionQuicActiveRequest(const PooledConnection *connection) noexcept
    {
        return connection != nullptr && connection->Kind == ConnectionKind::Quic &&
               connection->Holder.Quic.ActiveRequest;
    }
#endif
    bool ConnectionPoolHasHttp2StreamLease(const PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->Http2StreamLeases != 0;
    }

    NTSTATUS ConnectionPoolPromoteHttp2StreamLease(
        ConnectionPool* pool,
        PooledConnection* connection,
        ULONG maxConcurrentStreams) noexcept
    {
        if (pool == nullptr ||
            pool->Entries == nullptr ||
            connection == nullptr ||
            maxConcurrentStreams == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        LockPool(pool);
        if (!connection->Connected ||
            !connection->InUse ||
            connection->CloseWhenIdle ||
            connection->Http2StreamLeases != 0 ||
            connection->Http1PipelineLeases != 0) {
            UnlockPool(pool);
            return STATUS_INVALID_DEVICE_STATE;
        }

#if !defined(WKNET_USER_MODE_TEST)
        if (connection->Kind != ConnectionKind::Tcp || connection->Holder.Tcp.Http2 == nullptr ||
            connection->Holder.Tcp.Transport == nullptr)
        {
            UnlockPool(pool);
            return STATUS_INVALID_DEVICE_STATE;
        }
#endif

        connection->Http2MaxStreamLeases = maxConcurrentStreams;
        connection->Http2StreamLeases = 1;
        UnlockPool(pool);
        return STATUS_SUCCESS;
    }

    bool ConnectionPoolHasHttp1PipelineLease(const PooledConnection* connection) noexcept
    {
        return connection != nullptr && connection->Http1PipelineLeases != 0;
    }

    NTSTATUS ConnectionPoolPromoteHttp1PipelineLease(
        ConnectionPool* pool,
        PooledConnection* connection,
        ULONG maxPipelineLeases) noexcept
    {
        if (pool == nullptr ||
            pool->Entries == nullptr ||
            connection == nullptr ||
            maxPipelineLeases == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        LockPool(pool);
        if (!connection->Connected ||
            !connection->InUse ||
            connection->CloseWhenIdle ||
            connection->Http2StreamLeases != 0 ||
            connection->Http1PipelineLeases != 0) {
            UnlockPool(pool);
            return STATUS_INVALID_DEVICE_STATE;
        }

        connection->Http1MaxPipelineLeases = maxPipelineLeases;
        connection->Http1PipelineLeases = 1;
        connection->Http1PipelineNextSequence = 1;
        connection->Http1PipelineNextReceiveSequence = 1;
        connection->Http1PipelineFailureStatus = STATUS_SUCCESS;
        connection->Http1PipelineBufferedLength = 0;
        SignalHttp1PipelineReceiveEvent(*connection);
        UnlockPool(pool);
        return STATUS_SUCCESS;
    }

    NTSTATUS ConnectionPoolBeginHttp1PipelineSend(
        ConnectionPool* pool,
        PooledConnection* connection,
        ULONG* sequence) noexcept
    {
        if (sequence != nullptr) {
            *sequence = 0;
        }
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr || sequence == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

#if !defined(WKNET_USER_MODE_TEST)
        NTSTATUS waitStatus = KeWaitForSingleObject(
            &connection->Http1PipelineSendLock,
            Executive,
            KernelMode,
            FALSE,
            nullptr);
        if (!NT_SUCCESS(waitStatus)) {
            return waitStatus;
        }
#endif

        NTSTATUS status = STATUS_SUCCESS;
        LockPool(pool);
        if (connection->Http1PipelineLeases == 0 ||
            connection->CloseWhenIdle ||
            !NT_SUCCESS(connection->Http1PipelineFailureStatus) ||
            connection->Http1PipelineNextSequence == 0 ||
            connection->Http1PipelineNextSequence == 0xffffffffUL) {
            status = !NT_SUCCESS(connection->Http1PipelineFailureStatus) ?
                connection->Http1PipelineFailureStatus :
                STATUS_INVALID_DEVICE_STATE;
        }
        else {
            *sequence = connection->Http1PipelineNextSequence;
            ++connection->Http1PipelineNextSequence;
        }
        UnlockPool(pool);

        if (!NT_SUCCESS(status)) {
            ConnectionPoolEndHttp1PipelineSend(connection);
        }
        return status;
    }

    void ConnectionPoolEndHttp1PipelineSend(PooledConnection* connection) noexcept
    {
        if (connection == nullptr) {
            return;
        }

#if !defined(WKNET_USER_MODE_TEST)
        KeReleaseMutex(&connection->Http1PipelineSendLock, FALSE);
#endif
    }

    NTSTATUS ConnectionPoolWaitHttp1PipelineReceiveTurn(
        ConnectionPool* pool,
        PooledConnection* connection,
        ULONG sequence) noexcept
    {
        if (pool == nullptr ||
            pool->Entries == nullptr ||
            connection == nullptr ||
            sequence == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (;;) {
            NTSTATUS status = STATUS_SUCCESS;
            bool ready = false;

            LockPool(pool);
            if (connection->Http1PipelineLeases == 0) {
                status = STATUS_INVALID_DEVICE_STATE;
            }
            else if (connection->CloseWhenIdle || !NT_SUCCESS(connection->Http1PipelineFailureStatus)) {
                status = ActiveHttp1PipelineFailureStatus(*connection);
            }
            else if (connection->Http1PipelineNextReceiveSequence == sequence) {
                ready = true;
            }
            else {
                ClearHttp1PipelineReceiveEvent(*connection);
            }
            UnlockPool(pool);

            if (!NT_SUCCESS(status) || ready) {
                return status;
            }

#if defined(WKNET_USER_MODE_TEST)
            return STATUS_INVALID_DEVICE_STATE;
#else
            LARGE_INTEGER timeout = {};
            timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
            status = KeWaitForSingleObject(
                &connection->Http1PipelineReceiveEvent,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            if (!NT_SUCCESS(status)) {
                return status == STATUS_TIMEOUT ? STATUS_IO_TIMEOUT : status;
            }
#endif
        }
    }

    void ConnectionPoolCompleteHttp1PipelineReceive(
        ConnectionPool* pool,
        PooledConnection* connection,
        ULONG sequence) noexcept
    {
        if (pool == nullptr ||
            pool->Entries == nullptr ||
            connection == nullptr ||
            sequence == 0) {
            return;
        }

        LockPool(pool);
        if (connection->Http1PipelineLeases != 0 &&
            connection->Http1PipelineNextReceiveSequence == sequence) {
            ++connection->Http1PipelineNextReceiveSequence;
            SignalHttp1PipelineReceiveEvent(*connection);
        }
        UnlockPool(pool);
    }

    void ConnectionPoolFailHttp1Pipeline(
        ConnectionPool* pool,
        PooledConnection* connection,
        NTSTATUS status) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr) {
            return;
        }

        if (NT_SUCCESS(status)) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }

        LockPool(pool);
        if (connection->Http1PipelineLeases != 0) {
            connection->CloseWhenIdle = true;
            if (NT_SUCCESS(connection->Http1PipelineFailureStatus)) {
                connection->Http1PipelineFailureStatus = status;
            }
            SignalHttp1PipelineReceiveEvent(*connection);
        }
        UnlockPool(pool);
    }

    NTSTATUS ConnectionPoolHttp1PipelineBufferedLength(
        ConnectionPool* pool,
        PooledConnection* connection,
        SIZE_T* length) noexcept
    {
        if (length != nullptr) {
            *length = 0;
        }
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr || length == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        LockPool(pool);
        *length = connection->Http1PipelineBufferedLength;
        UnlockPool(pool);
        return STATUS_SUCCESS;
    }

    NTSTATUS ConnectionPoolTakeHttp1PipelineBufferedBytes(
        ConnectionPool* pool,
        PooledConnection* connection,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesCopied) noexcept
    {
        if (bytesCopied != nullptr) {
            *bytesCopied = 0;
        }
        if (pool == nullptr ||
            pool->Entries == nullptr ||
            connection == nullptr ||
            bytesCopied == nullptr ||
            (destination == nullptr && destinationCapacity != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        LockPool(pool);
        if (connection->Http1PipelineBufferedLength > destinationCapacity) {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else {
            if (connection->Http1PipelineBufferedLength != 0) {
                RtlCopyMemory(
                    destination,
                    connection->Http1PipelineBufferedBytes,
                    connection->Http1PipelineBufferedLength);
            }
            *bytesCopied = connection->Http1PipelineBufferedLength;
            connection->Http1PipelineBufferedLength = 0;
        }
        UnlockPool(pool);
        return status;
    }

    NTSTATUS ConnectionPoolStoreHttp1PipelineBufferedBytes(
        ConnectionPool* pool,
        PooledConnection* connection,
        const UCHAR* bytes,
        SIZE_T length) noexcept
    {
        if (length == 0) {
            return STATUS_SUCCESS;
        }
        if (pool == nullptr ||
            pool->Entries == nullptr ||
            connection == nullptr ||
            bytes == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        UCHAR* copy = static_cast<UCHAR*>(AllocatePoolMemory(length));
        if (copy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(copy, bytes, length);

        NTSTATUS status = STATUS_SUCCESS;
        LockPool(pool);
        if (connection->Http1PipelineLeases <= 1 ||
            connection->CloseWhenIdle ||
            !NT_SUCCESS(connection->Http1PipelineFailureStatus)) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
            if (connection->CloseWhenIdle || !NT_SUCCESS(connection->Http1PipelineFailureStatus)) {
                status = ActiveHttp1PipelineFailureStatus(*connection);
            }
            connection->CloseWhenIdle = true;
            if (NT_SUCCESS(connection->Http1PipelineFailureStatus)) {
                connection->Http1PipelineFailureStatus = status;
            }
            SignalHttp1PipelineReceiveEvent(*connection);
        }
        else {
            FreeHttp1PipelineBuffer(*connection);
            connection->Http1PipelineBufferedBytes = copy;
            connection->Http1PipelineBufferedLength = length;
            connection->Http1PipelineBufferedCapacity = length;
            copy = nullptr;
        }
        UnlockPool(pool);

        FreePoolMemory(copy);
        return status;
    }

    void ConnectionPoolClose(ConnectionPool* pool, PooledConnection* connection) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr) {
            return;
        }

        if (connection->Kind == ConnectionKind::Quic)
        {
            PendingQuicClose pending = {};
            LockPool(pool);
            connection->CloseWhenIdle = true;
            if (connection->Holder.Quic.StreamLeases == 0 && !connection->Holder.Quic.ActiveRequest)
            {
                BeginQuicCloseLocked(*pool, *connection, &pending);
            }
            UnlockPool(pool);
            StartPendingQuicClose(&pending);
            return;
        }

        DetachedConnectionResources detached = {};
        LockPool(pool);
        if (connection->Http1PipelineLeases != 0 || connection->Http2StreamLeases != 0) {
            connection->CloseWhenIdle = true;
            if (connection->Http1PipelineLeases != 0 &&
                NT_SUCCESS(connection->Http1PipelineFailureStatus)) {
                connection->Http1PipelineFailureStatus = STATUS_CONNECTION_DISCONNECTED;
            }
            SignalHttp1PipelineReceiveEvent(*connection);
        }
        else {
            const bool wasConnected = connection->Connected;
            DetachConnectionResources(*connection, &detached);
            if (wasConnected && pool->ActiveCount != 0) {
                --pool->ActiveCount;
            }
        }
        UnlockPool(pool);

        CloseDetachedConnectionResources(&detached);
    }
}
}
