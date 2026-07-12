#pragma once

#include "session/HandleTypes.h"

namespace wknet
{
namespace session
{
    inline Session* AllocateSessionHandle() noexcept
    {
        return AllocateNonPagedObject<Session>();
    }

    inline Request* AllocateRequestHandle() noexcept
    {
        return AllocateNonPagedObject<Request>();
    }

    inline Response* AllocateResponseHandle() noexcept
    {
        return AllocateNonPagedObject<Response>();
    }

    inline WebSocket* AllocateWebSocketHandle() noexcept
    {
        return AllocateNonPagedObject<WebSocket>();
    }

    inline crypto::CngProviderCache* AllocateProviderCacheHandle() noexcept
    {
        return AllocateNonPagedObject<crypto::CngProviderCache>();
    }

    inline void FreeHandle(_In_opt_ Session* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline void FreeHandle(_In_opt_ Request* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline void FreeHandle(_In_opt_ Response* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
        FreeNonPagedObject(handle);
    }

    inline void FreeHandle(_In_opt_ WebSocket* handle) noexcept
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

    inline bool IsHandleHeader(const HandleHeader* header, HandleKind expectedKind) noexcept
    {
        return header != nullptr && header->Kind == expectedKind && header->Closed == 0;
    }

    inline bool TryCloseHandleHeader(HandleHeader* header, HandleKind expectedKind) noexcept
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
