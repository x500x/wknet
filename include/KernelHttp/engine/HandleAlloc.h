#pragma once

#include <KernelHttp/engine/HandleTypes.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdlib.h>
#endif

namespace KernelHttp
{
namespace engine
{
    inline KhSession* AllocateSessionHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhSession*>(calloc(1, sizeof(KhSession)));
#else
        return new KhSession();
#endif
    }

    inline KhRequest* AllocateRequestHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhRequest*>(calloc(1, sizeof(KhRequest)));
#else
        return new KhRequest();
#endif
    }

    inline KhResponse* AllocateResponseHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhResponse*>(calloc(1, sizeof(KhResponse)));
#else
        return new KhResponse();
#endif
    }

    inline KhWebSocket* AllocateWebSocketHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhWebSocket*>(calloc(1, sizeof(KhWebSocket)));
#else
        return new KhWebSocket();
#endif
    }

    inline crypto::CngProviderCache* AllocateProviderCacheHandle() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<crypto::CngProviderCache*>(calloc(1, sizeof(crypto::CngProviderCache)));
#else
        return new crypto::CngProviderCache();
#endif
    }

    inline void FreeHandle(_In_opt_ KhSession* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ KhRequest* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ KhResponse* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ KhWebSocket* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline void FreeHandle(_In_opt_ crypto::CngProviderCache* handle) noexcept
    {
        if (handle == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(handle);
#else
        delete handle;
#endif
    }

    inline bool IsHandleHeader(const KhHandleHeader* header, KhHandleKind expectedKind) noexcept
    {
        return header != nullptr && header->Kind == expectedKind && !header->Closed;
    }
}
}
