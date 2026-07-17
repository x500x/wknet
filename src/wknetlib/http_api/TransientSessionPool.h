#pragma once

#include <wknet/http/Session.h>
#include <wknet/http/Headers.h>
#include "session/detail/HttpHandles.h"
#include "session/CookieJar.h"

namespace wknet::http::detail
{
    constexpr ULONG TransientSessionPoolCapacityDefault = 4;
    constexpr ULONG TransientSessionPoolCapacityMax = 16;

    struct TransientSessionPoolState final
    {
#if defined(WKNET_USER_MODE_TEST)
        volatile LONG Lock = 0;
#else
        FAST_MUTEX Lock = {};
        volatile LONG LockInitialized = 0;
#endif
        Session* Slots[TransientSessionPoolCapacityMax] = {};
        ULONG Capacity = TransientSessionPoolCapacityDefault;
        bool Enabled = true;
    };

    inline TransientSessionPoolState& TransientSessionPool() noexcept
    {
        static TransientSessionPoolState state = {};
        return state;
    }

    inline void LockTransientSessionPool() noexcept
    {
        TransientSessionPoolState& pool = TransientSessionPool();
#if defined(WKNET_USER_MODE_TEST)
        while (InterlockedCompareExchange(&pool.Lock, 1, 0) != 0) {
            YieldProcessor();
        }
#else
        if (InterlockedCompareExchange(&pool.LockInitialized, 1, 0) == 0) {
            ExInitializeFastMutex(&pool.Lock);
            InterlockedExchange(&pool.LockInitialized, 2);
        } else {
            while (InterlockedCompareExchange(&pool.LockInitialized, 0, 0) != 2) {
                YieldProcessor();
            }
        }
        ExAcquireFastMutex(&pool.Lock);
#endif
    }

    inline void UnlockTransientSessionPool() noexcept
    {
        TransientSessionPoolState& pool = TransientSessionPool();
#if defined(WKNET_USER_MODE_TEST)
        InterlockedExchange(&pool.Lock, 0);
#else
        ExReleaseFastMutex(&pool.Lock);
#endif
    }

    inline void ResetTransientSession(Session* session) noexcept
    {
        if (session == nullptr) {
            return;
        }
        HeadersRelease(session->DefaultHeaders);
        session->DefaultHeaders = nullptr;
        ::wknet::session::CookieJarClear(&session->CookieJar);
        if (session->AuthHeaderValue != nullptr) {
            RtlSecureZeroMemory(session->AuthHeaderValue, session->AuthHeaderValueLength);
            ::wknet::FreeNonPagedArray(session->AuthHeaderValue);
            session->AuthHeaderValue = nullptr;
            session->AuthHeaderValueLength = 0;
        }
    }

    _Must_inspect_result_
    inline NTSTATUS AcquireTransientSession(_Out_ Session** session) noexcept
    {
        if (session != nullptr) {
            *session = nullptr;
        }
        if (session == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        TransientSessionPoolState& pool = TransientSessionPool();
        if (pool.Enabled && pool.Capacity != 0) {
            LockTransientSessionPool();
            for (ULONG i = 0; i < pool.Capacity && i < TransientSessionPoolCapacityMax; ++i) {
                if (pool.Slots[i] != nullptr) {
                    Session* s = pool.Slots[i];
                    pool.Slots[i] = nullptr;
                    UnlockTransientSessionPool();
                    ResetTransientSession(s);
                    *session = s;
                    return STATUS_SUCCESS;
                }
            }
            UnlockTransientSessionPool();
        }

        return SessionCreate(session);
    }

    inline void ReleaseTransientSession(_In_opt_ Session* session) noexcept
    {
        if (session == nullptr) {
            return;
        }
        ResetTransientSession(session);

        TransientSessionPoolState& pool = TransientSessionPool();
        if (pool.Enabled && pool.Capacity != 0) {
            LockTransientSessionPool();
            for (ULONG i = 0; i < pool.Capacity && i < TransientSessionPoolCapacityMax; ++i) {
                if (pool.Slots[i] == nullptr) {
                    pool.Slots[i] = session;
                    UnlockTransientSessionPool();
                    return;
                }
            }
            UnlockTransientSessionPool();
        }
        SessionClose(session);
    }

    inline void TransientSessionPoolShutdown() noexcept
    {
        TransientSessionPoolState& pool = TransientSessionPool();
        Session* toClose[TransientSessionPoolCapacityMax] = {};
        ULONG count = 0;
        LockTransientSessionPool();
        for (ULONG i = 0; i < TransientSessionPoolCapacityMax; ++i) {
            if (pool.Slots[i] != nullptr) {
                toClose[count++] = pool.Slots[i];
                pool.Slots[i] = nullptr;
            }
        }
        UnlockTransientSessionPool();
        for (ULONG i = 0; i < count; ++i) {
            SessionClose(toClose[i]);
        }
    }
}
