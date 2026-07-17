#include "session/AltSvcCache.h"

#include "session/AltSvcClock.h"
#include "session/EngineUtils.h"
#include "session/HandleTypes.h"
#include "rtl/ProtocolAllocator.h"
#include "rtl/TraceInternal.h"

#ifndef STATUS_NETWORK_UNREACHABLE
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xC000023CL)
#endif

#ifndef STATUS_HOST_UNREACHABLE
#define STATUS_HOST_UNREACHABLE ((NTSTATUS)0xC000023DL)
#endif

namespace wknet::session
{
namespace
{
    constexpr ULONG AltSvcDefaultMaximumAgeSeconds = 86400;
    constexpr ULONGLONG AltSvcInitialBackoffMilliseconds = 1000;
    constexpr ULONGLONG AltSvcMaximumBackoffMilliseconds = 60000;

    struct AltSvcBrokenState final
    {
        ULONGLONG BlockedUntilMilliseconds = 0;
        ULONG ConsecutiveNetworkFailures = 0;
        bool DisabledForLifetime = false;
    };

    struct AltSvcCandidate final
    {
        char Host[WKNET_HARD_MAX_ALT_SVC_HOST_BYTES + 1] = {};
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        ULONGLONG ExpiresAtMilliseconds = 0;
        bool Persist = false;
        AltSvcBrokenState Broken[3] = {};
    };

    struct AltSvcEntry final
    {
        bool InUse = false;
        AltSvcCacheKey Key = {};
        AltSvcCandidate Candidates[WKNET_HARD_MAX_ALT_SVC_CANDIDATES_PER_ORIGIN] = {};
        ULONG CandidateCount = 0;
        ULONGLONG Generation = 0;
        ULONGLONG LastUpdatedMilliseconds = 0;
    };

    struct ParsedCandidateSet final
    {
        AltSvcCandidate Candidates[WKNET_HARD_MAX_ALT_SVC_CANDIDATES_PER_ORIGIN] = {};
        ULONG Count = 0;
        bool Clear = false;
        bool SawHeader = false;
    };

    struct AltSvcParseScratch final
    {
        char Authority[WKNET_HARD_MAX_ALT_SVC_AUTHORITY_BYTES + 1] = {};
        char Ignored[WKNET_HARD_MAX_ALT_SVC_AUTHORITY_BYTES + 1] = {};
        AltSvcCandidate Candidate = {};
    };

}

    struct AltSvcCache final
    {
        AltSvcEntry *Entries = nullptr;
        ULONG Capacity = 0;
        ULONG Count = 0;
        ULONG MaximumAgeSeconds = 0;
        ULONGLONG NextGeneration = 1;
#if defined(WKNET_USER_MODE_TEST)
        volatile LONG Lock = 0;
#else
        FAST_MUTEX Lock = {};
#endif
    };

namespace
{

    class CacheLock final
    {
    public:
        explicit CacheLock(AltSvcCache *cache) noexcept : cache_(cache)
        {
            if (cache_ == nullptr)
            {
                return;
            }
#if defined(WKNET_USER_MODE_TEST)
            while (InterlockedCompareExchange(&cache_->Lock, 1, 0) != 0)
            {
                YieldProcessor();
            }
#else
            ExAcquireFastMutex(&cache_->Lock);
#endif
        }

        ~CacheLock() noexcept
        {
            if (cache_ == nullptr)
            {
                return;
            }
#if defined(WKNET_USER_MODE_TEST)
            InterlockedExchange(&cache_->Lock, 0);
#else
            ExReleaseFastMutex(&cache_->Lock);
#endif
        }

        CacheLock(const CacheLock &) = delete;
        CacheLock &operator=(const CacheLock &) = delete;

    private:
        AltSvcCache *cache_ = nullptr;
    };

    bool IsOptionalWhitespace(char value) noexcept
    {
        return value == ' ' || value == '\t';
    }

    void SkipOptionalWhitespace(const char *value, SIZE_T length, SIZE_T *offset) noexcept
    {
        while (*offset < length && IsOptionalWhitespace(value[*offset]))
        {
            ++(*offset);
        }
    }

    bool IsTokenCharacter(char value) noexcept
    {
        const UCHAR c = static_cast<UCHAR>(value);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        {
            return true;
        }
        switch (value)
        {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
        }
    }

    bool ParseToken(const char *value, SIZE_T length, SIZE_T *offset, const char **token,
                    SIZE_T *tokenLength) noexcept
    {
        const SIZE_T start = *offset;
        while (*offset < length && IsTokenCharacter(value[*offset]))
        {
            ++(*offset);
        }
        if (*offset == start)
        {
            return false;
        }
        *token = value + start;
        *tokenLength = *offset - start;
        return true;
    }

    bool ParseQuotedString(const char *value, SIZE_T length, SIZE_T *offset, char *destination,
                           SIZE_T destinationCapacity, SIZE_T *destinationLength) noexcept
    {
        if (*offset >= length || value[*offset] != '"' || destination == nullptr || destinationCapacity == 0)
        {
            return false;
        }
        ++(*offset);
        SIZE_T written = 0;
        while (*offset < length)
        {
            char current = value[(*offset)++];
            if (current == '"')
            {
                destination[written] = '\0';
                *destinationLength = written;
                return true;
            }
            if (current == '\\')
            {
                if (*offset >= length)
                {
                    return false;
                }
                current = value[(*offset)++];
            }
            const UCHAR byte = static_cast<UCHAR>(current);
            if (byte < 0x20 || byte == 0x7f || written + 1 >= destinationCapacity)
            {
                return false;
            }
            destination[written++] = current;
        }
        return false;
    }

    bool ParseUnsigned(const char *value, SIZE_T length, SIZE_T *offset, ULONGLONG *number) noexcept
    {
        if (*offset >= length || value[*offset] < '0' || value[*offset] > '9')
        {
            return false;
        }
        ULONGLONG parsed = 0;
        while (*offset < length && value[*offset] >= '0' && value[*offset] <= '9')
        {
            const ULONG digit = static_cast<ULONG>(value[*offset] - '0');
            if (parsed > (~0ULL - digit) / 10ULL)
            {
                return false;
            }
            parsed = parsed * 10ULL + digit;
            ++(*offset);
        }
        *number = parsed;
        return true;
    }

    bool ParseAuthority(const char *authority, SIZE_T authorityLength, AltSvcCandidate *candidate) noexcept
    {
        if (authority == nullptr || candidate == nullptr || authorityLength == 0 ||
            authorityLength > WKNET_HARD_MAX_ALT_SVC_AUTHORITY_BYTES)
        {
            return false;
        }

        SIZE_T hostStart = 0;
        SIZE_T hostLength = 0;
        SIZE_T portStart = 0;
        if (authority[0] == '[')
        {
            SIZE_T close = 1;
            while (close < authorityLength && authority[close] != ']')
            {
                ++close;
            }
            if (close >= authorityLength || close + 1 >= authorityLength || authority[close + 1] != ':')
            {
                return false;
            }
            hostStart = 1;
            hostLength = close - 1;
            portStart = close + 2;
        }
        else
        {
            SIZE_T colon = authorityLength;
            while (colon != 0)
            {
                --colon;
                if (authority[colon] == ':')
                {
                    break;
                }
            }
            if (authority[colon] != ':')
            {
                return false;
            }
            hostLength = colon;
            portStart = colon + 1;
        }

        if (hostLength > WKNET_HARD_MAX_ALT_SVC_HOST_BYTES || portStart >= authorityLength)
        {
            return false;
        }
        ULONGLONG port = 0;
        SIZE_T portOffset = portStart;
        if (!ParseUnsigned(authority, authorityLength, &portOffset, &port) || portOffset != authorityLength ||
            port == 0 || port > 65535)
        {
            return false;
        }

        if (hostLength != 0)
        {
            RtlCopyMemory(candidate->Host, authority + hostStart, hostLength);
        }
        candidate->Host[hostLength] = '\0';
        candidate->HostLength = hostLength;
        candidate->Port = static_cast<USHORT>(port);
        return true;
    }

    ULONG FamilyIndex(AddressFamily family) noexcept
    {
        switch (family)
        {
        case AddressFamily::Ipv4:
            return 1;
        case AddressFamily::Ipv6:
            return 2;
        case AddressFamily::Any:
        default:
            return 0;
        }
    }

    bool KeyEquals(const AltSvcCacheKey &left, const AltSvcCacheKey &right) noexcept
    {
        return left.SchemeLength == right.SchemeLength && left.OriginHostLength == right.OriginHostLength &&
               left.OriginPort == right.OriginPort && left.TlsServerNameLength == right.TlsServerNameLength &&
               left.CertificatePolicy == right.CertificatePolicy &&
               left.CertificateStoreIdentity == right.CertificateStoreIdentity &&
               left.ClientCredentialIdentity == right.ClientCredentialIdentity &&
               left.AddressFamily == right.AddressFamily &&
               left.Policy.Profile == right.Policy.Profile &&
               left.Policy.EnableTls12RsaKeyExchange == right.Policy.EnableTls12RsaKeyExchange &&
               left.Policy.EnableTls12Cbc == right.Policy.EnableTls12Cbc &&
               left.Policy.EnableTls12Renegotiation == right.Policy.EnableTls12Renegotiation &&
               left.Policy.EnableTls12Sha1Signatures == right.Policy.EnableTls12Sha1Signatures &&
               left.Policy.EnablePostHandshakeClientAuth == right.Policy.EnablePostHandshakeClientAuth &&
               RtlCompareMemory(left.Scheme, right.Scheme, left.SchemeLength) == left.SchemeLength &&
               RtlCompareMemory(left.OriginHost, right.OriginHost, left.OriginHostLength) == left.OriginHostLength &&
               RtlCompareMemory(left.TlsServerName, right.TlsServerName, left.TlsServerNameLength) ==
                   left.TlsServerNameLength;
    }

    AltSvcEntry *FindEntry(AltSvcCache *cache, const AltSvcCacheKey &key) noexcept;

    bool IsNetworkFailure(NTSTATUS status) noexcept
    {
        return status == STATUS_IO_TIMEOUT || status == STATUS_CONNECTION_DISCONNECTED ||
               status == STATUS_CONNECTION_RESET || status == STATUS_NETWORK_UNREACHABLE ||
               status == STATUS_HOST_UNREACHABLE;
    }

    bool ShouldIgnoreFailure(NTSTATUS status) noexcept
    {
        return status == STATUS_CANCELLED || status == STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS ParseAltSvcValue(AltSvcCache *cache, const AltSvcCacheKey &key,
                              const char *value, SIZE_T valueLength,
                              ParsedCandidateSet *parsed, AltSvcParseScratch *scratch) noexcept
    {
        SIZE_T offset = 0;
        SkipOptionalWhitespace(value, valueLength, &offset);
        if (valueLength - offset == 5 && TextEqualsLiteralIgnoreCase(value + offset, 5, "clear"))
        {
            parsed->Clear = true;
            parsed->SawHeader = true;
            return STATUS_SUCCESS;
        }

        while (offset < valueLength)
        {
            const char *protocol = nullptr;
            SIZE_T protocolLength = 0;
            if (!ParseToken(value, valueLength, &offset, &protocol, &protocolLength))
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            SkipOptionalWhitespace(value, valueLength, &offset);
            if (offset >= valueLength || value[offset++] != '=')
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            SkipOptionalWhitespace(value, valueLength, &offset);

            RtlZeroMemory(scratch->Authority, sizeof(scratch->Authority));
            SIZE_T authorityLength = 0;
            if (!ParseQuotedString(value, valueLength, &offset, scratch->Authority,
                                   sizeof(scratch->Authority), &authorityLength))
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            scratch->Candidate = {};
            AltSvcCandidate &candidate = scratch->Candidate;
            if (!ParseAuthority(scratch->Authority, authorityLength, &candidate))
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            ULONGLONG maximumAge = AltSvcDefaultMaximumAgeSeconds;
            bool persist = false;
            while (true)
            {
                SkipOptionalWhitespace(value, valueLength, &offset);
                if (offset >= valueLength || value[offset] == ',')
                {
                    break;
                }
                if (value[offset++] != ';')
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                SkipOptionalWhitespace(value, valueLength, &offset);
                const char *name = nullptr;
                SIZE_T nameLength = 0;
                if (!ParseToken(value, valueLength, &offset, &name, &nameLength))
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                SkipOptionalWhitespace(value, valueLength, &offset);
                if (offset >= valueLength || value[offset++] != '=')
                {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                SkipOptionalWhitespace(value, valueLength, &offset);

                if (TextEqualsLiteralIgnoreCase(name, nameLength, "ma"))
                {
                    if (!ParseUnsigned(value, valueLength, &offset, &maximumAge))
                    {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
                else if (TextEqualsLiteralIgnoreCase(name, nameLength, "persist"))
                {
                    ULONGLONG persistValue = 0;
                    if (!ParseUnsigned(value, valueLength, &offset, &persistValue) || persistValue > 1)
                    {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    persist = persistValue == 1;
                }
                else
                {
                    if (offset < valueLength && value[offset] == '"')
                    {
                        RtlZeroMemory(scratch->Ignored, sizeof(scratch->Ignored));
                        SIZE_T ignoredLength = 0;
                        if (!ParseQuotedString(value, valueLength, &offset, scratch->Ignored,
                                               sizeof(scratch->Ignored), &ignoredLength))
                        {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                    }
                    else
                    {
                        const char *ignored = nullptr;
                        SIZE_T ignoredLength = 0;
                        if (!ParseToken(value, valueLength, &offset, &ignored, &ignoredLength))
                        {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                    }
                }
            }

            parsed->SawHeader = true;
            if (TextEqualsLiteral(protocol, protocolLength, "h3") && maximumAge != 0)
            {
                if (parsed->Count >= WKNET_HARD_MAX_ALT_SVC_CANDIDATES_PER_ORIGIN)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if (candidate.HostLength == 0)
                {
                    RtlCopyMemory(candidate.Host, key.OriginHost, key.OriginHostLength);
                    candidate.HostLength = key.OriginHostLength;
                    candidate.Host[candidate.HostLength] = '\0';
                }
                const ULONGLONG boundedAge = maximumAge < cache->MaximumAgeSeconds
                                                ? maximumAge
                                                : cache->MaximumAgeSeconds;
                const ULONGLONG now = AltSvcClockNowMilliseconds();
                if (boundedAge > (~0ULL - now) / 1000ULL)
                {
                    return STATUS_INTEGER_OVERFLOW;
                }
                candidate.ExpiresAtMilliseconds = now + boundedAge * 1000ULL;
                candidate.Persist = persist;
                parsed->Candidates[parsed->Count++] = candidate;
            }

            SkipOptionalWhitespace(value, valueLength, &offset);
            if (offset == valueLength)
            {
                break;
            }
            if (value[offset++] != ',')
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            SkipOptionalWhitespace(value, valueLength, &offset);
            if (offset == valueLength)
            {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        return STATUS_SUCCESS;
    }
}

namespace
{
    AltSvcEntry *FindEntry(AltSvcCache *cache, const AltSvcCacheKey &key) noexcept
    {
        for (ULONG index = 0; index < cache->Capacity; ++index)
        {
            AltSvcEntry &entry = cache->Entries[index];
            if (entry.InUse && KeyEquals(entry.Key, key))
            {
                return &entry;
            }
        }
        return nullptr;
    }

    void RemoveEntry(AltSvcCache *cache, AltSvcEntry *entry) noexcept
    {
        if (entry == nullptr || !entry->InUse)
        {
            return;
        }
        RtlSecureZeroMemory(entry, sizeof(*entry));
        if (cache->Count != 0)
        {
            --cache->Count;
        }
    }

    AltSvcEntry *SelectReplacementEntry(AltSvcCache *cache) noexcept
    {
        AltSvcEntry *oldest = nullptr;
        for (ULONG index = 0; index < cache->Capacity; ++index)
        {
            AltSvcEntry &entry = cache->Entries[index];
            if (!entry.InUse)
            {
                return &entry;
            }
            if (oldest == nullptr || entry.LastUpdatedMilliseconds < oldest->LastUpdatedMilliseconds)
            {
                oldest = &entry;
            }
        }
        return oldest;
    }
}

    NTSTATUS AltSvcCacheCreate(ULONG capacity, ULONG maximumAgeSeconds, AltSvcCache **cache) noexcept
    {
        if (cache != nullptr)
        {
            *cache = nullptr;
        }
        if (cache == nullptr || capacity == 0 || capacity > WKNET_HARD_MAX_ALT_SVC_ENTRIES ||
            maximumAgeSeconds == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        AltSvcCache *created = AllocateProtocolNonPagedObject<AltSvcCache>(
            rtl::ProtocolAllocationSite::AltSvcCacheObject);
        if (created == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (static_cast<SIZE_T>(capacity) > static_cast<SIZE_T>(-1) / sizeof(AltSvcEntry))
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcCacheObject, created);
            return STATUS_INTEGER_OVERFLOW;
        }
        created->Entries = AllocateProtocolNonPagedArray<AltSvcEntry>(
            rtl::ProtocolAllocationSite::AltSvcCacheEntries,
            capacity);
        if (created->Entries == nullptr)
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcCacheObject, created);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(created->Entries, sizeof(AltSvcEntry) * capacity);
        created->Capacity = capacity;
        created->MaximumAgeSeconds = maximumAgeSeconds;
#if !defined(WKNET_USER_MODE_TEST)
        ExInitializeFastMutex(&created->Lock);
#endif
        *cache = created;
        return STATUS_SUCCESS;
    }

    void AltSvcCacheDestroy(AltSvcCache *cache) noexcept
    {
        if (cache == nullptr)
        {
            return;
        }
        if (cache->Entries != nullptr)
        {
            RtlSecureZeroMemory(cache->Entries, sizeof(AltSvcEntry) * cache->Capacity);
            FreeProtocolNonPagedArray(rtl::ProtocolAllocationSite::AltSvcCacheEntries, cache->Entries);
            cache->Entries = nullptr;
        }
        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcCacheObject, cache);
    }

    NTSTATUS AltSvcBuildKey(const Request &request, AltSvcCacheKey *key) noexcept
    {
        if (key == nullptr || request.SchemeLength == 0 || request.HostLength == 0 || request.Port == 0 ||
            request.SchemeLength >= sizeof(key->Scheme) ||
            request.HostLength > WKNET_HARD_MAX_ALT_SVC_HOST_BYTES)
        {
            return STATUS_INVALID_PARAMETER;
        }
        *key = {};
        RtlCopyMemory(key->Scheme, request.Scheme, request.SchemeLength);
        key->SchemeLength = request.SchemeLength;
        RtlCopyMemory(key->OriginHost, request.Host, request.HostLength);
        key->OriginHostLength = request.HostLength;
        key->OriginPort = request.Port;

        const char *serverName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        const SIZE_T serverNameLength = request.Tls.ServerName != nullptr
                                            ? request.Tls.ServerNameLength
                                            : request.HostLength;
        if (serverName == nullptr || serverNameLength == 0 ||
            serverNameLength > WKNET_HARD_MAX_ALT_SVC_HOST_BYTES)
        {
            return STATUS_INVALID_PARAMETER;
        }
        RtlCopyMemory(key->TlsServerName, serverName, serverNameLength);
        key->TlsServerNameLength = serverNameLength;
        key->CertificatePolicy = request.Tls.CertificatePolicy;
        key->CertificateStoreIdentity =
            reinterpret_cast<SIZE_T>(request.Tls.CertificateStore);
        key->ClientCredentialIdentity =
            reinterpret_cast<SIZE_T>(request.Tls.ClientCredential);
        key->Policy = request.Tls.Policy;
        key->AddressFamily = request.AddressFamily;
        return STATUS_SUCCESS;
    }

    NTSTATUS AltSvcCacheStoreResponse(AltSvcCache *cache, const AltSvcCacheKey &key,
                                      const http1::HttpHeader *headers, SIZE_T headerCount,
                                      bool *updated) noexcept
    {
        if (updated != nullptr)
        {
            *updated = false;
        }
        if (cache == nullptr || (headers == nullptr && headerCount != 0))
        {
            return STATUS_INVALID_PARAMETER;
        }

        ParsedCandidateSet *parsed = AllocateProtocolNonPagedObject<ParsedCandidateSet>(
            rtl::ProtocolAllocationSite::AltSvcParsedSet);
        AltSvcParseScratch *scratch = AllocateProtocolNonPagedObject<AltSvcParseScratch>(
            rtl::ProtocolAllocationSite::AltSvcParseScratch);
        if (parsed == nullptr || scratch == nullptr)
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParsedSet, parsed);
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParseScratch, scratch);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NTSTATUS status = STATUS_SUCCESS;
        for (SIZE_T index = 0; index < headerCount; ++index)
        {
            const http1::HttpHeader &header = headers[index];
            if (!TextEqualsLiteralIgnoreCase(header.Name.Data, header.Name.Length, "Alt-Svc"))
            {
                continue;
            }
            if (parsed->Clear || !NT_SUCCESS(status))
            {
                status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }
            status = ParseAltSvcValue(cache, key, header.Value.Data, header.Value.Length, parsed, scratch);
        }
        if (!NT_SUCCESS(status) || !parsed->SawHeader)
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParsedSet, parsed);
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParseScratch, scratch);
            return status;
        }

        {
            CacheLock lock(cache);
            AltSvcEntry *entry = FindEntry(cache, key);
            if (parsed->Clear || parsed->Count == 0)
            {
                RemoveEntry(cache, entry);
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Info,
                            "http.altsvc.cleared candidates=0");
            }
            else
            {
                if (entry == nullptr)
                {
                    entry = SelectReplacementEntry(cache);
                    if (entry == nullptr)
                    {
                        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParsedSet, parsed);
                        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParseScratch, scratch);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    if (!entry->InUse)
                    {
                        ++cache->Count;
                    }
                }
                *entry = {};
                entry->InUse = true;
                entry->Key = key;
                entry->CandidateCount = parsed->Count;
                entry->Generation = cache->NextGeneration++;
                entry->LastUpdatedMilliseconds = AltSvcClockNowMilliseconds();
                RtlCopyMemory(entry->Candidates, parsed->Candidates,
                              sizeof(AltSvcCandidate) * parsed->Count);
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Info,
                            "http.altsvc.stored candidates=%u", parsed->Count);
            }
        }

        if (updated != nullptr)
        {
            *updated = true;
        }
        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParsedSet, parsed);
        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::AltSvcParseScratch, scratch);
        return STATUS_SUCCESS;
    }

    NTSTATUS AltSvcCacheLookup(AltSvcCache *cache, const AltSvcCacheKey &key,
                               AltSvcCandidateSnapshot *snapshot) noexcept
    {
        if (snapshot != nullptr)
        {
            *snapshot = {};
        }
        if (cache == nullptr || snapshot == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        CacheLock lock(cache);
        AltSvcEntry *entry = FindEntry(cache, key);
        if (entry == nullptr)
        {
            return STATUS_NOT_FOUND;
        }

        const ULONGLONG now = AltSvcClockNowMilliseconds();
        ULONG liveCount = 0;
        for (ULONG index = 0; index < entry->CandidateCount; ++index)
        {
            AltSvcCandidate &candidate = entry->Candidates[index];
            if (candidate.ExpiresAtMilliseconds <= now)
            {
                continue;
            }
            ++liveCount;
            AltSvcBrokenState &broken = candidate.Broken[FamilyIndex(key.AddressFamily)];
            if (broken.DisabledForLifetime || broken.BlockedUntilMilliseconds > now)
            {
                continue;
            }
            RtlCopyMemory(snapshot->Host, candidate.Host, candidate.HostLength);
            snapshot->HostLength = candidate.HostLength;
            snapshot->Host[candidate.HostLength] = '\0';
            snapshot->Port = candidate.Port;
            snapshot->AddressFamily = key.AddressFamily;
            snapshot->EntryGeneration = entry->Generation;
            snapshot->CandidateIndex = index;
            snapshot->Persist = candidate.Persist;
            return STATUS_SUCCESS;
        }

        if (liveCount == 0)
        {
            RemoveEntry(cache, entry);
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Info,
                        "http.altsvc.expired candidates=0");
        }
        return STATUS_NOT_FOUND;
    }

    void AltSvcCacheMarkFailure(AltSvcCache *cache, const AltSvcCacheKey &key,
                                const AltSvcCandidateSnapshot &snapshot, NTSTATUS status) noexcept
    {
        if (cache == nullptr || ShouldIgnoreFailure(status))
        {
            return;
        }
        CacheLock lock(cache);
        AltSvcEntry *entry = FindEntry(cache, key);
        if (entry == nullptr || entry->Generation != snapshot.EntryGeneration ||
            snapshot.CandidateIndex >= entry->CandidateCount)
        {
            return;
        }

        AltSvcCandidate &candidate = entry->Candidates[snapshot.CandidateIndex];
        AltSvcBrokenState &broken = candidate.Broken[FamilyIndex(snapshot.AddressFamily)];
        if (IsNetworkFailure(status))
        {
            if (broken.ConsecutiveNetworkFailures != static_cast<ULONG>(-1))
            {
                ++broken.ConsecutiveNetworkFailures;
            }
            ULONGLONG backoff = AltSvcInitialBackoffMilliseconds;
            ULONG shifts = broken.ConsecutiveNetworkFailures > 1 ? broken.ConsecutiveNetworkFailures - 1 : 0;
            while (shifts-- != 0 && backoff < AltSvcMaximumBackoffMilliseconds)
            {
                backoff *= 2;
            }
            if (backoff > AltSvcMaximumBackoffMilliseconds)
            {
                backoff = AltSvcMaximumBackoffMilliseconds;
            }
            const ULONGLONG now = AltSvcClockNowMilliseconds();
            broken.BlockedUntilMilliseconds = now > ~0ULL - backoff
                                                  ? candidate.ExpiresAtMilliseconds
                                                  : now + backoff;
            if (broken.BlockedUntilMilliseconds > candidate.ExpiresAtMilliseconds)
            {
                broken.BlockedUntilMilliseconds = candidate.ExpiresAtMilliseconds;
            }
        }
        else
        {
            broken.DisabledForLifetime = true;
        }
        WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Warning,
                    "http.altsvc.broken candidate=%u family=%u status=0x%08X",
                    snapshot.CandidateIndex, static_cast<ULONG>(snapshot.AddressFamily),
                    static_cast<ULONG>(status));
    }

    void AltSvcCacheMarkSuccess(AltSvcCache *cache, const AltSvcCacheKey &key,
                                const AltSvcCandidateSnapshot &snapshot) noexcept
    {
        if (cache == nullptr)
        {
            return;
        }
        CacheLock lock(cache);
        AltSvcEntry *entry = FindEntry(cache, key);
        if (entry == nullptr || entry->Generation != snapshot.EntryGeneration ||
            snapshot.CandidateIndex >= entry->CandidateCount)
        {
            return;
        }
        entry->Candidates[snapshot.CandidateIndex].Broken[FamilyIndex(snapshot.AddressFamily)] = {};
    }

    void AltSvcCacheNetworkChanged(AltSvcCache *cache) noexcept
    {
        if (cache == nullptr)
        {
            return;
        }
        CacheLock lock(cache);
        for (ULONG entryIndex = 0; entryIndex < cache->Capacity; ++entryIndex)
        {
            AltSvcEntry &entry = cache->Entries[entryIndex];
            if (!entry.InUse)
            {
                continue;
            }
            for (ULONG candidateIndex = 0; candidateIndex < entry.CandidateCount; ++candidateIndex)
            {
                RtlZeroMemory(entry.Candidates[candidateIndex].Broken,
                              sizeof(entry.Candidates[candidateIndex].Broken));
            }
        }
    }

#if defined(WKNET_USER_MODE_TEST)
    ULONG AltSvcCacheEntryCount(AltSvcCache *cache) noexcept
    {
        if (cache == nullptr)
        {
            return 0;
        }
        CacheLock lock(cache);
        return cache->Count;
    }
#endif
}
