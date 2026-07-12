#pragma once

#include <wknet/engine/HandleTypes.h>

namespace wknet
{
namespace session
{
    inline KhSession* AllocateSessionHandle() noexcept
    {
        return AllocateNonPagedObject<KhSession>();
    }

    inline KhRequest* AllocateRequestHandle() noexcept
    {
        return AllocateNonPagedObject<KhRequest>();
    }

    inline KhResponse* AllocateResponseHandle() noexcept
    {
        return AllocateNonPagedObject<KhResponse>();
    }

    inline KhWebSocket* AllocateWebSocketHandle() noexcept
    {
        return AllocateNonPagedObject<KhWebSocket>();
    }

    inline crypto::CngProviderCache* AllocateProviderCacheHandle() noexcept
    {
        return AllocateNonPagedObject<crypto::CngProviderCache>();
    }

    inline void FreeHandle(_In_opt_ KhSession* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline void FreeHandle(_In_opt_ KhRequest* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline void FreeHandle(_In_opt_ KhResponse* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline void FreeHandle(_In_opt_ KhWebSocket* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline void FreeHandle(_In_opt_ crypto::CngProviderCache* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline bool IsHandleHeader(const KhHandleHeader* header, KhHandleKind expectedKind) noexcept
    {
        return header != nullptr && header->Kind == expectedKind && header->Closed == 0;
    }

    inline bool TryCloseHandleHeader(KhHandleHeader* header, KhHandleKind expectedKind) noexcept
    {
        if (header == nullptr || header->Kind != expectedKind) {
            return false;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (header->Closed != 0) {
            return false;
        }
        header->Closed = 1;
        return true;
#else
        return InterlockedCompareExchange(&header->Closed, 1, 0) == 0;
#endif
    }
}
}
