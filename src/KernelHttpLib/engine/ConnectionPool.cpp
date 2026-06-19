#include <KernelHttp/engine/ConnectionPool.h>
#include <KernelHttp/core/TlsTransport.h>
#include <KernelHttp/core/WskTransport.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/TlsConnection.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

namespace KernelHttp
{
namespace engine
{
namespace
{
    struct KhDetachedConnectionResources final
    {
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        net::WskSocket* Socket = nullptr;
        core::WskTransport* RawTransport = nullptr;
        core::ITransport* Transport = nullptr;
        tls::TlsConnection* Tls = nullptr;
        http2::Http2Connection* Http2 = nullptr;
#endif
    };

    void DetachConnectionResources(
        _Inout_ KhPooledConnection& connection,
        _Out_ KhDetachedConnectionResources* detached) noexcept;

    void InitializePoolLock(_Inout_ KhConnectionPool* pool) noexcept
    {
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        ExInitializeFastMutex(&pool->Lock);
#else
        UNREFERENCED_PARAMETER(pool);
#endif
    }

    void LockPool(_Inout_ KhConnectionPool* pool) noexcept
    {
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        ExAcquireFastMutex(&pool->Lock);
#else
        UNREFERENCED_PARAMETER(pool);
#endif
    }

    void UnlockPool(_Inout_ KhConnectionPool* pool) noexcept
    {
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        ExReleaseFastMutex(&pool->Lock);
#else
        UNREFERENCED_PARAMETER(pool);
#endif
    }

    _Ret_maybenull_
    void* AllocatePoolMemory(SIZE_T length) noexcept
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

    void FreePoolMemory(_In_opt_ void* data) noexcept
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

    _Must_inspect_result_
    ULONGLONG QueryPoolTime() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        static ULONGLONG time100ns = 0;
        time100ns += 10000;
        return time100ns;
#else
        return KeQueryInterruptTime();
#endif
    }

    _Must_inspect_result_
    bool IsIdleExpired(
        _In_ const KhConnectionPool& pool,
        _In_ const KhPooledConnection& connection,
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

    SIZE_T SockaddrStorageCompareLength(const SOCKADDR_STORAGE& address) noexcept
    {
        switch (address.ss_family) {
        case AF_INET:
            return sizeof(SOCKADDR_IN);
        case AF_INET6:
            return sizeof(SOCKADDR_IN6);
        default:
            return sizeof(address.ss_family);
        }
    }

    bool SockaddrStorageEquals(const SOCKADDR_STORAGE& left, const SOCKADDR_STORAGE& right) noexcept
    {
        if (left.ss_family != right.ss_family) {
            return false;
        }

        const SIZE_T compareLength = SockaddrStorageCompareLength(left);
        return RtlCompareMemory(&left, &right, compareLength) == compareLength;
    }

    bool ProxyIdentityEquals(
        const KhConnectionPoolKey& left,
        const KhConnectionPoolKey& right) noexcept
    {
        if (left.ProxyEnabled != right.ProxyEnabled) {
            return false;
        }

        if (!left.ProxyEnabled) {
            return true;
        }

        return SockaddrStorageEquals(left.ProxyAddress, right.ProxyAddress) &&
            TextEquals(
                left.ProxyAuthority,
                left.ProxyAuthorityLength,
                right.ProxyAuthority,
                right.ProxyAuthorityLength);
    }

    _Must_inspect_result_
    bool HasConnectionState(_In_ const KhPooledConnection& connection) noexcept
    {
        if (connection.InUse || connection.Connected) {
            return true;
        }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        return connection.Socket != nullptr ||
            connection.RawTransport != nullptr ||
            connection.Transport != nullptr ||
            connection.Tls != nullptr ||
            connection.Http2 != nullptr;
#else
        return false;
#endif
    }

    _Must_inspect_result_
    bool HasDetachedConnectionResources(_In_ const KhDetachedConnectionResources& detached) noexcept
    {
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        return detached.Socket != nullptr ||
            detached.RawTransport != nullptr ||
            detached.Transport != nullptr ||
            detached.Tls != nullptr ||
            detached.Http2 != nullptr;
#else
        UNREFERENCED_PARAMETER(detached);
        return false;
#endif
    }

    _Must_inspect_result_
    bool ConnectionPoolHostQuotaKeysEqual(
        _In_ const KhConnectionPoolKey& left,
        _In_ const KhConnectionPoolKey& right) noexcept
    {
        return left.Port == right.Port &&
            left.AddressFamily == right.AddressFamily &&
            TextEquals(left.Scheme, left.SchemeLength, right.Scheme, right.SchemeLength) &&
            TextEquals(left.Host, left.HostLength, right.Host, right.HostLength);
    }

    _Must_inspect_result_
    ULONG CountConnectionsForHostQuota(
        _In_ const KhConnectionPool& pool,
        _In_ const KhConnectionPoolKey& key) noexcept
    {
        ULONG count = 0;
        if (pool.Entries == nullptr) {
            return 0;
        }

        for (ULONG index = 0; index < pool.Capacity; ++index) {
            const KhPooledConnection& candidate = pool.Entries[index];
            if ((candidate.Connected || candidate.InUse) &&
                ConnectionPoolHostQuotaKeysEqual(candidate.Key, key)) {
                ++count;
            }
        }
        return count;
    }

    _Must_inspect_result_
    bool DetachIdleConnectionForHostQuotaLocked(
        _Inout_ KhConnectionPool& pool,
        _In_ const KhConnectionPoolKey& key,
        _Out_ KhDetachedConnectionResources* detached) noexcept
    {
        if (pool.Entries == nullptr || detached == nullptr) {
            return false;
        }

        for (ULONG index = 0; index < pool.Capacity; ++index) {
            KhPooledConnection& candidate = pool.Entries[index];
            if (candidate.Connected &&
                !candidate.InUse &&
                ConnectionPoolHostQuotaKeysEqual(candidate.Key, key)) {
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
        _Inout_ KhPooledConnection& connection,
        _Out_ KhDetachedConnectionResources* detached) noexcept
    {
        if (detached == nullptr) {
            return;
        }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        detached->Socket = connection.Socket;
        detached->RawTransport = connection.RawTransport;
        detached->Transport = connection.Transport;
        detached->Tls = connection.Tls;
        detached->Http2 = connection.Http2;
#endif
        RtlZeroMemory(&connection, sizeof(connection));
    }

    void CloseDetachedConnectionResources(_Inout_ KhDetachedConnectionResources* detached) noexcept
    {
        if (detached == nullptr) {
            return;
        }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        if (detached->Http2 != nullptr) {
            if (detached->Transport != nullptr) {
                const NTSTATUS shutdownStatus = detached->Http2->Shutdown(*detached->Transport);
                UNREFERENCED_PARAMETER(shutdownStatus);
            }
            FreeNonPagedObject(detached->Http2);
            detached->Http2 = nullptr;
        }
        if (detached->Transport != nullptr &&
            detached->Transport != detached->RawTransport) {
            FreeNonPagedObject(detached->Transport);
            detached->Transport = nullptr;
        }
        if (detached->Tls != nullptr) {
            FreeNonPagedObject(detached->Tls);
            detached->Tls = nullptr;
        }
        if (detached->RawTransport != nullptr) {
            FreeNonPagedObject(detached->RawTransport);
            detached->RawTransport = nullptr;
        }
        if (detached->Socket != nullptr) {
            const NTSTATUS closeStatus = detached->Socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            FreeNonPagedObject(detached->Socket);
            detached->Socket = nullptr;
        }
#endif
    }
}

    NTSTATUS KhConnectionPoolInitialize(
        KhConnectionPool* pool,
        ULONG capacity,
        ULONG maxConnectionsPerHost,
        ULONG idleTimeoutMilliseconds) noexcept
    {
        if (pool == nullptr ||
            capacity == 0 ||
            maxConnectionsPerHost == 0 ||
            maxConnectionsPerHost > capacity) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(pool, sizeof(*pool));
        InitializePoolLock(pool);
        pool->Entries = static_cast<KhPooledConnection*>(
            AllocatePoolMemory(sizeof(KhPooledConnection) * capacity));
        if (pool->Entries == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        pool->Capacity = capacity;
        pool->MaxConnectionsPerHost = maxConnectionsPerHost;
        pool->NextConnectionId = 1;
        pool->IdleTimeoutMilliseconds = idleTimeoutMilliseconds;
        return STATUS_SUCCESS;
    }

    void KhConnectionPoolShutdown(KhConnectionPool* pool) noexcept
    {
        if (pool == nullptr) {
            return;
        }

        if (pool->Entries == nullptr) {
            RtlZeroMemory(pool, sizeof(*pool));
            return;
        }

        for (;;) {
            KhDetachedConnectionResources detached = {};
            bool found = false;

            LockPool(pool);
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                KhPooledConnection& entry = pool->Entries[index];
                if (!HasConnectionState(entry)) {
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
            if (!found) {
                break;
            }
        }

        RtlSecureZeroMemory(pool->Entries, sizeof(KhPooledConnection) * pool->Capacity);
        FreePoolMemory(pool->Entries);
        RtlZeroMemory(pool, sizeof(*pool));
    }

    _Must_inspect_result_
    bool KhConnectionPoolKeysEqualExceptAlpn(
        const KhConnectionPoolKey& left,
        const KhConnectionPoolKey& right) noexcept
    {
        return left.Port == right.Port &&
            left.AddressFamily == right.AddressFamily &&
            left.MinTlsVersion == right.MinTlsVersion &&
            left.MaxTlsVersion == right.MaxTlsVersion &&
            left.CertificatePolicy == right.CertificatePolicy &&
            left.CertificateStore == right.CertificateStore &&
            left.ClientCredential == right.ClientCredential &&
            left.Policy.Profile == right.Policy.Profile &&
            left.Policy.EnableTls12RsaKeyExchange == right.Policy.EnableTls12RsaKeyExchange &&
            left.Policy.EnableTls12Cbc == right.Policy.EnableTls12Cbc &&
            left.Policy.EnableTls12Renegotiation == right.Policy.EnableTls12Renegotiation &&
            left.Policy.EnableTls12Sha1Signatures == right.Policy.EnableTls12Sha1Signatures &&
            left.Policy.EnablePostHandshakeClientAuth == right.Policy.EnablePostHandshakeClientAuth &&
            left.Policy.RequireRevocationCheck == right.Policy.RequireRevocationCheck &&
            left.AutomaticAlpn == right.AutomaticAlpn &&
            ProxyIdentityEquals(left, right) &&
            TextEquals(left.Scheme, left.SchemeLength, right.Scheme, right.SchemeLength) &&
            TextEquals(left.Host, left.HostLength, right.Host, right.HostLength) &&
            TextEquals(left.TlsServerName, left.TlsServerNameLength, right.TlsServerName, right.TlsServerNameLength);
    }

    bool KhConnectionPoolKeysEqual(
        const KhConnectionPoolKey& left,
        const KhConnectionPoolKey& right) noexcept
    {
        return KhConnectionPoolKeysEqualExceptAlpn(left, right) &&
            TextEquals(left.Alpn, left.AlpnLength, right.Alpn, right.AlpnLength);
    }

    bool KhConnectionPoolKeysEqualForAutoAlpnAcquire(
        const KhConnectionPoolKey& left,
        const KhConnectionPoolKey& right) noexcept
    {
        if (left.AlpnLength != 0 || right.AlpnLength == 0) {
            return KhConnectionPoolKeysEqual(left, right);
        }

        if (!left.AutomaticAlpn || !right.AutomaticAlpn) {
            return KhConnectionPoolKeysEqual(left, right);
        }

        return KhConnectionPoolKeysEqualExceptAlpn(left, right);
    }

    NTSTATUS KhConnectionPoolAcquire(
        KhConnectionPool* pool,
        const KhConnectionPoolKey& key,
        KhConnectionPolicy policy,
        KhPooledConnection** connection,
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

        KhDetachedConnectionResources detached = {};
        KhPooledConnection* selected = nullptr;
        const ULONGLONG now = QueryPoolTime();

        LockPool(pool);
        if (policy != KhConnectionPolicy::ForceNew && policy != KhConnectionPolicy::NoPool) {
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                KhPooledConnection& candidate = pool->Entries[index];
                if (candidate.Connected &&
                    !candidate.InUse &&
                    KhConnectionPoolKeysEqualForAutoAlpnAcquire(key, candidate.Key)) {
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
            if (CountConnectionsForHostQuota(*pool, key) >= pool->MaxConnectionsPerHost) {
                bool idleDetached = HasDetachedConnectionResources(detached);
                if (!idleDetached) {
                    idleDetached = DetachIdleConnectionForHostQuotaLocked(*pool, key, &detached);
                }
                if (!idleDetached ||
                    CountConnectionsForHostQuota(*pool, key) >= pool->MaxConnectionsPerHost) {
                    UnlockPool(pool);
                    CloseDetachedConnectionResources(&detached);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }

            for (ULONG index = 0; index < pool->Capacity; ++index) {
                KhPooledConnection& candidate = pool->Entries[index];
                if (!candidate.Connected && !candidate.InUse) {
                    if (HasConnectionState(candidate)) {
                        if (HasDetachedConnectionResources(detached)) {
                            continue;
                        }
                        DetachConnectionResources(candidate, &detached);
                    }
                    candidate.InUse = true;
                    candidate.Connected = true;
                    candidate.Key = key;
                    candidate.Id = pool->NextConnectionId++;
                    candidate.LastUsedTime = 0;
                    if (candidate.Id == 0) {
                        candidate.Id = pool->NextConnectionId++;
                    }
                    ++pool->ActiveCount;
                    selected = &candidate;
                    break;
                }
            }
        }

        if (selected == nullptr && policy != KhConnectionPolicy::NoPool) {
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                KhPooledConnection& candidate = pool->Entries[index];
                if (!candidate.InUse) {
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
                    candidate.Id = pool->NextConnectionId++;
                    candidate.LastUsedTime = 0;
                    if (candidate.Id == 0) {
                        candidate.Id = pool->NextConnectionId++;
                    }
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

        if (selected == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        *connection = selected;
        return STATUS_SUCCESS;
    }

    void KhConnectionPoolRelease(
        KhConnectionPool* pool,
        KhPooledConnection* connection,
        bool reusable) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr) {
            return;
        }

        if (!reusable) {
            KhConnectionPoolClose(pool, connection);
            return;
        }

        LockPool(pool);
        connection->LastUsedTime = QueryPoolTime();
        connection->InUse = false;
        UnlockPool(pool);
    }

    void KhConnectionPoolClose(KhConnectionPool* pool, KhPooledConnection* connection) noexcept
    {
        if (pool == nullptr || pool->Entries == nullptr || connection == nullptr) {
            return;
        }

        KhDetachedConnectionResources detached = {};
        LockPool(pool);
        const bool wasConnected = connection->Connected;
        DetachConnectionResources(*connection, &detached);
        if (wasConnected && pool->ActiveCount != 0) {
            --pool->ActiveCount;
        }
        UnlockPool(pool);

        CloseDetachedConnectionResources(&detached);
    }
}
}
