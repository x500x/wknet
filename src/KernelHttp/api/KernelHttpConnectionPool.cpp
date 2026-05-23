#include "api/KernelHttpConnectionPool.h"
#include "net/WskSocket.h"
#include "tls/TlsConnection.h"

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

namespace KernelHttp
{
namespace api
{
namespace
{
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

    void ResetConnection(_Inout_ KhPooledConnection& connection) noexcept
    {
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        if (connection.Tls != nullptr) {
            delete connection.Tls;
            connection.Tls = nullptr;
        }
        if (connection.Socket != nullptr) {
            const NTSTATUS closeStatus = connection.Socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            delete connection.Socket;
            connection.Socket = nullptr;
        }
#endif
        RtlZeroMemory(&connection, sizeof(connection));
    }
}

    NTSTATUS KhConnectionPoolInitialize(KhConnectionPool* pool, ULONG capacity) noexcept
    {
        if (pool == nullptr || capacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory(pool, sizeof(*pool));
        pool->Entries = static_cast<KhPooledConnection*>(
            AllocatePoolMemory(sizeof(KhPooledConnection) * capacity));
        if (pool->Entries == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        pool->Capacity = capacity;
        pool->NextConnectionId = 1;
        return STATUS_SUCCESS;
    }

    void KhConnectionPoolShutdown(KhConnectionPool* pool) noexcept
    {
        if (pool == nullptr) {
            return;
        }

        if (pool->Entries != nullptr) {
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                ResetConnection(pool->Entries[index]);
            }
            RtlSecureZeroMemory(pool->Entries, sizeof(KhPooledConnection) * pool->Capacity);
        }
        FreePoolMemory(pool->Entries);
        RtlZeroMemory(pool, sizeof(*pool));
    }

    bool KhConnectionPoolKeysEqual(
        const KhConnectionPoolKey& left,
        const KhConnectionPoolKey& right) noexcept
    {
        return left.Port == right.Port &&
            left.MinTlsVersion == right.MinTlsVersion &&
            left.MaxTlsVersion == right.MaxTlsVersion &&
            left.CertificatePolicy == right.CertificatePolicy &&
            TextEquals(left.Scheme, left.SchemeLength, right.Scheme, right.SchemeLength) &&
            TextEquals(left.Host, left.HostLength, right.Host, right.HostLength) &&
            TextEquals(left.Alpn, left.AlpnLength, right.Alpn, right.AlpnLength);
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

        if (policy != KhConnectionPolicy::ForceNew && policy != KhConnectionPolicy::NoPool) {
            for (ULONG index = 0; index < pool->Capacity; ++index) {
                KhPooledConnection& candidate = pool->Entries[index];
                if (candidate.Connected &&
                    !candidate.InUse &&
                    KhConnectionPoolKeysEqual(candidate.Key, key)) {
                    candidate.InUse = true;
                    *connection = &candidate;
                    *reused = true;
                    return STATUS_SUCCESS;
                }
            }
        }

        for (ULONG index = 0; index < pool->Capacity; ++index) {
            KhPooledConnection& candidate = pool->Entries[index];
            if (!candidate.Connected && !candidate.InUse) {
                ResetConnection(candidate);
                candidate.InUse = true;
                candidate.Connected = true;
                candidate.Key = key;
                candidate.Id = pool->NextConnectionId++;
                if (candidate.Id == 0) {
                    candidate.Id = pool->NextConnectionId++;
                }
                ++pool->ActiveCount;
                *connection = &candidate;
                return STATUS_SUCCESS;
            }
        }

        if (policy == KhConnectionPolicy::NoPool) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (ULONG index = 0; index < pool->Capacity; ++index) {
            KhPooledConnection& candidate = pool->Entries[index];
            if (!candidate.InUse) {
                ResetConnection(candidate);
                candidate.InUse = true;
                candidate.Connected = true;
                candidate.Key = key;
                candidate.Id = pool->NextConnectionId++;
                if (candidate.Id == 0) {
                    candidate.Id = pool->NextConnectionId++;
                }
                *connection = &candidate;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    void KhConnectionPoolRelease(
        KhConnectionPool* pool,
        KhPooledConnection* connection,
        bool reusable) noexcept
    {
        UNREFERENCED_PARAMETER(pool);
        if (connection == nullptr) {
            return;
        }

        if (!reusable) {
            KhConnectionPoolClose(connection);
            return;
        }

        connection->InUse = false;
    }

    void KhConnectionPoolClose(KhPooledConnection* connection) noexcept
    {
        if (connection == nullptr) {
            return;
        }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        if (connection->Tls != nullptr) {
            delete connection->Tls;
            connection->Tls = nullptr;
        }
        if (connection->Socket != nullptr) {
            const NTSTATUS closeStatus = connection->Socket->Close();
            UNREFERENCED_PARAMETER(closeStatus);
            delete connection->Socket;
            connection->Socket = nullptr;
        }
#endif
        connection->InUse = false;
        connection->Connected = false;
    }
}
}
