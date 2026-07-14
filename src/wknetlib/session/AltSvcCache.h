#pragma once

#include "http1/HttpTypes.h"
#include "session/Engine.h"
#include <wknet/WknetLimits.h>

namespace wknet::session
{
    struct Request;
    struct AltSvcCache;

    struct AltSvcCacheKey final
    {
        char Scheme[6] = {};
        SIZE_T SchemeLength = 0;
        char OriginHost[WKNET_HARD_MAX_ALT_SVC_HOST_BYTES + 1] = {};
        SIZE_T OriginHostLength = 0;
        USHORT OriginPort = 0;
        char TlsServerName[WKNET_HARD_MAX_ALT_SVC_HOST_BYTES + 1] = {};
        SIZE_T TlsServerNameLength = 0;
        CertificatePolicy CertificatePolicy = CertificatePolicy::Verify;
        const tls::CertificateStore *CertificateStore = nullptr;
        const tls::TlsClientCredential *ClientCredential = nullptr;
        tls::TlsPolicy Policy = {};
        AddressFamily AddressFamily = AddressFamily::Any;
    };

    struct AltSvcCandidateSnapshot final
    {
        char Host[WKNET_HARD_MAX_ALT_SVC_HOST_BYTES + 1] = {};
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        AddressFamily AddressFamily = AddressFamily::Any;
        ULONGLONG EntryGeneration = 0;
        ULONG CandidateIndex = 0;
        bool Persist = false;
    };

    _Must_inspect_result_ NTSTATUS AltSvcCacheCreate(ULONG capacity, ULONG maximumAgeSeconds,
                                                     _Out_ AltSvcCache **cache) noexcept;

    void AltSvcCacheDestroy(_In_opt_ AltSvcCache *cache) noexcept;

    _Must_inspect_result_ NTSTATUS AltSvcBuildKey(_In_ const Request &request,
                                                  _Out_ AltSvcCacheKey *key) noexcept;

    _Must_inspect_result_ NTSTATUS AltSvcCacheStoreResponse(
        _Inout_ AltSvcCache *cache,
        _In_ const AltSvcCacheKey &key,
        _In_reads_(headerCount) const http1::HttpHeader *headers,
        SIZE_T headerCount,
        _Out_opt_ bool *updated) noexcept;

    _Must_inspect_result_ NTSTATUS AltSvcCacheLookup(_Inout_ AltSvcCache *cache,
                                                     _In_ const AltSvcCacheKey &key,
                                                     _Out_ AltSvcCandidateSnapshot *snapshot) noexcept;

    void AltSvcCacheMarkFailure(_Inout_ AltSvcCache *cache,
                                _In_ const AltSvcCacheKey &key,
                                _In_ const AltSvcCandidateSnapshot &snapshot,
                                NTSTATUS status) noexcept;

    void AltSvcCacheMarkSuccess(_Inout_ AltSvcCache *cache,
                                _In_ const AltSvcCacheKey &key,
                                _In_ const AltSvcCandidateSnapshot &snapshot) noexcept;

    void AltSvcCacheNetworkChanged(_Inout_ AltSvcCache *cache) noexcept;

#if defined(WKNET_USER_MODE_TEST)
    ULONG AltSvcCacheEntryCount(_In_opt_ AltSvcCache *cache) noexcept;
#endif
}
