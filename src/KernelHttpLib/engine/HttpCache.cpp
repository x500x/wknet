#include <KernelHttp/engine/HttpCache.h>
#include <KernelHttp/engine/EngineUtils.h>

namespace KernelHttp
{
namespace engine
{
struct KhHttpCacheEntry final
{
    KhHttpCacheEntry* Prev = nullptr;
    KhHttpCacheEntry* Next = nullptr;
    ULONG Method = 0;
    char* Key = nullptr;
    SIZE_T KeyLength = 0;
    USHORT StatusCode = 0;
    http::HttpHeader* Headers = nullptr;
    SIZE_T HeaderCount = 0;
    char* HeaderNameStorage = nullptr;
    SIZE_T HeaderNameStorageLength = 0;
    char* HeaderValueStorage = nullptr;
    SIZE_T HeaderValueStorageLength = 0;
    UCHAR* Body = nullptr;
    SIZE_T BodyLength = 0;
    SIZE_T BodyCapacity = 0;
    bool Partial = false;
    ULONGLONG CompleteLength = 0;
    KhHttpCacheRange Ranges[KhHttpCacheMaxPartialRanges] = {};
    SIZE_T RangeCount = 0;
    KhHttpCacheVaryField Vary[KhHttpCacheMaxVaryFields] = {};
    SIZE_T VaryCount = 0;
    LONGLONG StoredAtSeconds = 0;
    SIZE_T ChargeBytes = 0;
};

namespace
{
    void FormatUnsignedDecimal(SIZE_T value, char* buffer, SIZE_T capacity, SIZE_T* length) noexcept;
    void AppendLiteral(char* buffer, SIZE_T capacity, SIZE_T* offset, const char* literal) noexcept;
    void AppendUnsignedDecimal(char* buffer, SIZE_T capacity, SIZE_T* offset, ULONGLONG value) noexcept;

    bool IsCacheHandle(KH_HTTP_CACHE cache) noexcept
    {
        return cache != nullptr &&
            cache->Header.Kind == KhHandleKind::HttpCache &&
            cache->Header.Closed == 0;
    }

    void EnsureLockInitialized(KH_HTTP_CACHE cache) noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(cache);
#else
        if (cache == nullptr ||
            InterlockedCompareExchange(&cache->LockInitialized, 0, 0) == 2) {
            return;
        }
        if (InterlockedCompareExchange(&cache->LockInitialized, 1, 0) == 0) {
            ExInitializeFastMutex(&cache->Lock);
            InterlockedExchange(&cache->LockInitialized, 2);
            return;
        }
        LARGE_INTEGER delay = {};
        delay.QuadPart = -10 * 1000;
        while (InterlockedCompareExchange(&cache->LockInitialized, 0, 0) != 2) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
#endif
    }

    void AcquireCacheLock(KH_HTTP_CACHE cache) noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        while (cache->Lock != 0) {
        }
        cache->Lock = 1;
#else
        EnsureLockInitialized(cache);
        ExAcquireFastMutex(&cache->Lock);
#endif
    }

    void ReleaseCacheLock(KH_HTTP_CACHE cache) noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        cache->Lock = 0;
#else
        ExReleaseFastMutex(&cache->Lock);
#endif
    }

    LONGLONG CurrentSeconds() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return 1700000000;
#else
        LARGE_INTEGER now = {};
        KeQuerySystemTimePrecise(&now);
        return now.QuadPart / 10000000LL - 11644473600LL;
#endif
    }

    SIZE_T StringLength(const char* text) noexcept
    {
        SIZE_T length = 0;
        if (text == nullptr) {
            return 0;
        }
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    bool HeaderNameEquals(const KhStoredHeader& header, const char* name) noexcept
    {
        return TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, name);
    }

    bool FindRequestHeader(
        const KhRequest& request,
        const char* name,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }
        for (SIZE_T index = 0; index < request.HeaderCount; ++index) {
            if (HeaderNameEquals(request.Headers[index], name)) {
                if (value != nullptr) {
                    *value = request.Headers[index].Value;
                }
                if (valueLength != nullptr) {
                    *valueLength = request.Headers[index].ValueLength;
                }
                return true;
            }
        }
        return false;
    }

    bool RequestHasHeader(const KhRequest& request, const char* name) noexcept
    {
        return FindRequestHeader(request, name, nullptr, nullptr);
    }

    bool BuildCacheKey(const KhRequest& request, char** key, SIZE_T* keyLength) noexcept
    {
        if (key != nullptr) {
            *key = nullptr;
        }
        if (keyLength != nullptr) {
            *keyLength = 0;
        }
        if (key == nullptr || keyLength == nullptr || request.Url == nullptr || request.UrlLength == 0) {
            return false;
        }

        const char prefix[] = "m:";
        const SIZE_T prefixLength = sizeof(prefix) - 1;
        const SIZE_T required = prefixLength + 10 + 1 + request.UrlLength;
        char* buffer = static_cast<char*>(AllocateApiMemory(required));
        if (buffer == nullptr) {
            return false;
        }

        SIZE_T offset = 0;
        RtlCopyMemory(buffer + offset, prefix, prefixLength);
        offset += prefixLength;
        ULONG method = static_cast<ULONG>(request.Method);
        char digits[10] = {};
        SIZE_T digitCount = 0;
        do {
            digits[digitCount++] = static_cast<char>('0' + method % 10);
            method /= 10;
        } while (method != 0);
        while (digitCount != 0) {
            buffer[offset++] = digits[--digitCount];
        }
        buffer[offset++] = ' ';
        RtlCopyMemory(buffer + offset, request.Url, request.UrlLength);
        offset += request.UrlLength;
        *key = buffer;
        *keyLength = offset;
        return true;
    }

    bool SameUrlKey(const KhHttpCacheEntry& entry, const KhRequest& request) noexcept
    {
        if (entry.Key == nullptr || request.Url == nullptr) {
            return false;
        }
        const char* separator = nullptr;
        for (SIZE_T index = 0; index < entry.KeyLength; ++index) {
            if (entry.Key[index] == ' ') {
                separator = entry.Key + index + 1;
                break;
            }
        }
        if (separator == nullptr) {
            return false;
        }
        const SIZE_T urlLength = entry.KeyLength - static_cast<SIZE_T>(separator - entry.Key);
        return urlLength == request.UrlLength &&
            RtlCompareMemory(separator, request.Url, request.UrlLength) == request.UrlLength;
    }

    void FreeVary(KhHttpCacheEntry& entry) noexcept
    {
        for (SIZE_T index = 0; index < entry.VaryCount; ++index) {
            FreeApiMemory(entry.Vary[index].Name);
            FreeApiMemory(entry.Vary[index].Value);
            entry.Vary[index] = {};
        }
        entry.VaryCount = 0;
    }

    void FreeEntry(KhHttpCacheEntry* entry) noexcept
    {
        if (entry == nullptr) {
            return;
        }
        FreeApiMemory(entry->Key);
        FreeApiMemory(entry->Headers);
        FreeApiMemory(entry->HeaderNameStorage);
        FreeApiMemory(entry->HeaderValueStorage);
        FreeApiMemory(entry->Body);
        FreeVary(*entry);
        FreeNonPagedObject(entry);
    }

    void UnlinkEntry(KH_HTTP_CACHE cache, KhHttpCacheEntry* entry) noexcept
    {
        if (cache == nullptr || entry == nullptr) {
            return;
        }
        if (entry->Prev != nullptr) {
            entry->Prev->Next = entry->Next;
        }
        else {
            cache->Head = entry->Next;
        }
        if (entry->Next != nullptr) {
            entry->Next->Prev = entry->Prev;
        }
        else {
            cache->Tail = entry->Prev;
        }
        entry->Prev = nullptr;
        entry->Next = nullptr;
        if (cache->EntryCount != 0) {
            --cache->EntryCount;
        }
        if (cache->BytesUsed >= entry->ChargeBytes) {
            cache->BytesUsed -= entry->ChargeBytes;
        }
        else {
            cache->BytesUsed = 0;
        }
    }

    void LinkHead(KH_HTTP_CACHE cache, KhHttpCacheEntry* entry) noexcept
    {
        entry->Prev = nullptr;
        entry->Next = cache->Head;
        if (cache->Head != nullptr) {
            cache->Head->Prev = entry;
        }
        else {
            cache->Tail = entry;
        }
        cache->Head = entry;
        ++cache->EntryCount;
        cache->BytesUsed += entry->ChargeBytes;
    }

    void MoveToHead(KH_HTTP_CACHE cache, KhHttpCacheEntry* entry) noexcept
    {
        if (cache->Head == entry) {
            return;
        }
        const SIZE_T charge = entry->ChargeBytes;
        UnlinkEntry(cache, entry);
        entry->ChargeBytes = charge;
        LinkHead(cache, entry);
    }

    void RemoveAndFree(KH_HTTP_CACHE cache, KhHttpCacheEntry* entry) noexcept
    {
        UnlinkEntry(cache, entry);
        FreeEntry(entry);
    }

    void EvictToLimits(KH_HTTP_CACHE cache) noexcept
    {
        while (cache->Tail != nullptr &&
            (cache->EntryCount > cache->Options.MaxEntries ||
                cache->BytesUsed > cache->Options.MaxBytes)) {
            KhHttpCacheEntry* victim = cache->Tail;
            RemoveAndFree(cache, victim);
            ++cache->Stats.Evictions;
        }
    }

    bool CopyHeaders(
        const http::HttpHeader* headers,
        SIZE_T headerCount,
        http::HttpHeader** copiedHeaders,
        char** nameStorage,
        SIZE_T* nameStorageLength,
        char** valueStorage,
        SIZE_T* valueStorageLength) noexcept
    {
        if (copiedHeaders != nullptr) {
            *copiedHeaders = nullptr;
        }
        if (nameStorage != nullptr) {
            *nameStorage = nullptr;
        }
        if (valueStorage != nullptr) {
            *valueStorage = nullptr;
        }
        if (nameStorageLength != nullptr) {
            *nameStorageLength = 0;
        }
        if (valueStorageLength != nullptr) {
            *valueStorageLength = 0;
        }
        if (copiedHeaders == nullptr || nameStorage == nullptr || valueStorage == nullptr ||
            nameStorageLength == nullptr || valueStorageLength == nullptr) {
            return false;
        }
        if (headerCount == 0) {
            return true;
        }

        SIZE_T totalNames = 0;
        SIZE_T totalValues = 0;
        for (SIZE_T index = 0; index < headerCount; ++index) {
            totalNames += headers[index].Name.Length;
            totalValues += headers[index].Value.Length;
        }

        http::HttpHeader* headerCopy = AllocateNonPagedArray<http::HttpHeader>(headerCount);
        char* names = totalNames != 0 ? static_cast<char*>(AllocateApiMemory(totalNames)) : nullptr;
        char* values = totalValues != 0 ? static_cast<char*>(AllocateApiMemory(totalValues)) : nullptr;
        if (headerCopy == nullptr || (totalNames != 0 && names == nullptr) || (totalValues != 0 && values == nullptr)) {
            FreeNonPagedArray(headerCopy);
            FreeApiMemory(names);
            FreeApiMemory(values);
            return false;
        }

        SIZE_T nameOffset = 0;
        SIZE_T valueOffset = 0;
        for (SIZE_T index = 0; index < headerCount; ++index) {
            if (headers[index].Name.Length != 0) {
                RtlCopyMemory(names + nameOffset, headers[index].Name.Data, headers[index].Name.Length);
                headerCopy[index].Name.Data = names + nameOffset;
                headerCopy[index].Name.Length = headers[index].Name.Length;
                nameOffset += headers[index].Name.Length;
            }
            if (headers[index].Value.Length != 0) {
                RtlCopyMemory(values + valueOffset, headers[index].Value.Data, headers[index].Value.Length);
                headerCopy[index].Value.Data = values + valueOffset;
                headerCopy[index].Value.Length = headers[index].Value.Length;
                valueOffset += headers[index].Value.Length;
            }
        }

        *copiedHeaders = headerCopy;
        *nameStorage = names;
        *nameStorageLength = totalNames;
        *valueStorage = values;
        *valueStorageLength = totalValues;
        return true;
    }

    bool CopySnapshotFromEntry(
        const KhHttpCacheEntry& entry,
        const http::HttpByteRange* range,
        KhHttpCacheSnapshot* snapshot) noexcept
    {
        if (snapshot != nullptr) {
            *snapshot = {};
        }
        if (snapshot == nullptr) {
            return false;
        }

        ULONGLONG first = 0;
        ULONGLONG last = 0;
        bool rangeResponse = false;
        if (range != nullptr && range->Valid) {
            if (entry.BodyLength == 0) {
                return false;
            }
            if (range->Suffix) {
                const ULONGLONG suffix = range->SuffixLength > entry.BodyLength ?
                    entry.BodyLength :
                    range->SuffixLength;
                first = static_cast<ULONGLONG>(entry.BodyLength) - suffix;
                last = static_cast<ULONGLONG>(entry.BodyLength) - 1;
            }
            else {
                first = range->First;
                last = range->Last == ~0UL || range->Last >= entry.BodyLength ?
                    static_cast<ULONGLONG>(entry.BodyLength) - 1 :
                    range->Last;
            }
            if (first > last || last >= entry.BodyLength) {
                return false;
            }
            rangeResponse = true;
        }

        SIZE_T headerCount = entry.HeaderCount;
        if (rangeResponse) {
            for (SIZE_T index = 0; index < entry.HeaderCount; ++index) {
                if (http::TextEqualsIgnoreCase(entry.Headers[index].Name, http::MakeText("Content-Length")) ||
                    http::TextEqualsIgnoreCase(entry.Headers[index].Name, http::MakeText("Content-Range"))) {
                    --headerCount;
                }
            }
            headerCount += 2;
        }

        http::HttpHeader* sourceHeaders = entry.Headers;
        http::HttpHeader smallHeaders[KhMaxHeadersPerResponse + 2] = {};
        char contentLength[32] = {};
        char contentRange[96] = {};
        if (rangeResponse) {
            SIZE_T out = 0;
            for (SIZE_T index = 0; index < entry.HeaderCount; ++index) {
                if (!http::TextEqualsIgnoreCase(entry.Headers[index].Name, http::MakeText("Content-Length")) &&
                    !http::TextEqualsIgnoreCase(entry.Headers[index].Name, http::MakeText("Content-Range"))) {
                    smallHeaders[out++] = entry.Headers[index];
                }
            }
            const SIZE_T rangeLength = static_cast<SIZE_T>(last - first + 1);
            SIZE_T lengthOffset = 0;
            FormatUnsignedDecimal(rangeLength, contentLength, sizeof(contentLength), &lengthOffset);
            SIZE_T rangeOffset = 0;
            AppendLiteral(contentRange, sizeof(contentRange), &rangeOffset, "bytes ");
            AppendUnsignedDecimal(contentRange, sizeof(contentRange), &rangeOffset, first);
            AppendLiteral(contentRange, sizeof(contentRange), &rangeOffset, "-");
            AppendUnsignedDecimal(contentRange, sizeof(contentRange), &rangeOffset, last);
            AppendLiteral(contentRange, sizeof(contentRange), &rangeOffset, "/");
            AppendUnsignedDecimal(contentRange, sizeof(contentRange), &rangeOffset, entry.BodyLength);
            smallHeaders[out++] = { http::MakeText("Content-Length"), { contentLength, lengthOffset } };
            smallHeaders[out++] = { http::MakeText("Content-Range"), { contentRange, rangeOffset } };
            sourceHeaders = smallHeaders;
        }

        if (!CopyHeaders(
            sourceHeaders,
            headerCount,
            &snapshot->Headers,
            &snapshot->HeaderNameStorage,
            &snapshot->HeaderNameStorageLength,
            &snapshot->HeaderValueStorage,
            &snapshot->HeaderValueStorageLength)) {
            KhHttpCacheFreeSnapshot(snapshot);
            return false;
        }

        const SIZE_T bodyLength = rangeResponse ? static_cast<SIZE_T>(last - first + 1) : entry.BodyLength;
        if (bodyLength != 0) {
            snapshot->Body = AllocateBytesCopy(
                entry.Body + (rangeResponse ? static_cast<SIZE_T>(first) : 0),
                bodyLength);
            if (snapshot->Body == nullptr) {
                KhHttpCacheFreeSnapshot(snapshot);
                return false;
            }
        }
        snapshot->BodyLength = bodyLength;
        snapshot->StatusCode = rangeResponse ? 206 : entry.StatusCode;
        snapshot->HeaderCount = headerCount;
        return true;
    }

    void FormatUnsignedDecimal(SIZE_T value, char* buffer, SIZE_T capacity, SIZE_T* length) noexcept
    {
        if (length != nullptr) {
            *length = 0;
        }
        if (buffer == nullptr || capacity == 0 || length == nullptr) {
            return;
        }
        char reversed[32] = {};
        SIZE_T count = 0;
        do {
            reversed[count++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        } while (value != 0 && count < sizeof(reversed));
        while (count != 0 && *length < capacity) {
            buffer[(*length)++] = reversed[--count];
        }
    }

    void AppendLiteral(char* buffer, SIZE_T capacity, SIZE_T* offset, const char* literal) noexcept
    {
        if (buffer == nullptr || offset == nullptr || literal == nullptr) {
            return;
        }
        const SIZE_T length = StringLength(literal);
        if (*offset + length > capacity) {
            return;
        }
        RtlCopyMemory(buffer + *offset, literal, length);
        *offset += length;
    }

    void AppendUnsignedDecimal(char* buffer, SIZE_T capacity, SIZE_T* offset, ULONGLONG value) noexcept
    {
        char reversed[32] = {};
        SIZE_T count = 0;
        do {
            reversed[count++] = static_cast<char>('0' + (value % 10));
            value /= 10;
        } while (value != 0 && count < sizeof(reversed));
        while (count != 0 && offset != nullptr && *offset < capacity) {
            buffer[(*offset)++] = reversed[--count];
        }
    }

    bool VaryMatches(const KhHttpCacheEntry& entry, const KhRequest& request) noexcept
    {
        for (SIZE_T index = 0; index < entry.VaryCount; ++index) {
            const char* value = nullptr;
            SIZE_T valueLength = 0;
            FindRequestHeader(request, entry.Vary[index].Name, &value, &valueLength);
            if (valueLength != entry.Vary[index].ValueLength ||
                (valueLength != 0 &&
                    RtlCompareMemory(value, entry.Vary[index].Value, valueLength) != valueLength)) {
                return false;
            }
        }
        return true;
    }

    bool CopyVaryFromResponse(KhHttpCacheEntry& entry, const KhRequest& request, http::HttpText vary) noexcept
    {
        if (vary.Data == nullptr || vary.Length == 0) {
            return true;
        }

        SIZE_T start = 0;
        while (start <= vary.Length && entry.VaryCount < KhHttpCacheMaxVaryFields) {
            SIZE_T end = start;
            while (end < vary.Length && vary.Data[end] != ',') {
                ++end;
            }
            http::HttpText name = { vary.Data + start, end - start };
            while (name.Length != 0 && (name.Data[0] == ' ' || name.Data[0] == '\t')) {
                ++name.Data;
                --name.Length;
            }
            while (name.Length != 0 && (name.Data[name.Length - 1] == ' ' || name.Data[name.Length - 1] == '\t')) {
                --name.Length;
            }
            if (name.Length != 0 && !http::TextEqualsIgnoreCase(name, http::MakeText("*"))) {
                KhHttpCacheVaryField& field = entry.Vary[entry.VaryCount];
                field.Name = AllocateTextCopy(name.Data, name.Length);
                field.NameLength = name.Length;
                const char* value = nullptr;
                SIZE_T valueLength = 0;
                FindRequestHeader(request, field.Name, &value, &valueLength);
                if (valueLength != 0) {
                    field.Value = AllocateTextCopy(value, valueLength);
                    field.ValueLength = valueLength;
                }
                if (field.Name == nullptr || (valueLength != 0 && field.Value == nullptr)) {
                    return false;
                }
                ++entry.VaryCount;
            }
            if (end == vary.Length) {
                break;
            }
            start = end + 1;
        }
        return true;
    }

    bool RangeCovered(const KhHttpCacheEntry& entry, ULONGLONG first, ULONGLONG last) noexcept
    {
        if (!entry.Partial) {
            return last < entry.BodyLength;
        }
        ULONGLONG cursor = first;
        while (cursor <= last) {
            bool advanced = false;
            for (SIZE_T index = 0; index < entry.RangeCount; ++index) {
                const KhHttpCacheRange& range = entry.Ranges[index];
                if (range.First <= cursor && range.Last >= cursor) {
                    if (range.Last == ~0ULL) {
                        return true;
                    }
                    cursor = range.Last + 1;
                    advanced = true;
                    break;
                }
            }
            if (!advanced) {
                return false;
            }
        }
        return true;
    }

    bool RequestedRangeCovered(
        const KhHttpCacheEntry& entry,
        const http::HttpByteRange& requestRange,
        http::HttpByteRange* concreteRange) noexcept
    {
        if (concreteRange != nullptr) {
            *concreteRange = {};
        }
        if (!requestRange.Valid || concreteRange == nullptr || entry.BodyLength == 0) {
            return false;
        }

        ULONGLONG first = 0;
        ULONGLONG last = 0;
        if (requestRange.Suffix) {
            const ULONGLONG suffix = requestRange.SuffixLength > entry.BodyLength ?
                entry.BodyLength :
                requestRange.SuffixLength;
            first = static_cast<ULONGLONG>(entry.BodyLength) - suffix;
            last = static_cast<ULONGLONG>(entry.BodyLength) - 1;
        }
        else {
            first = requestRange.First;
            last = requestRange.Last == ~0UL || requestRange.Last >= entry.BodyLength ?
                static_cast<ULONGLONG>(entry.BodyLength) - 1 :
                requestRange.Last;
        }
        if (first > last || !RangeCovered(entry, first, last)) {
            return false;
        }
        concreteRange->First = first;
        concreteRange->Last = last;
        concreteRange->Valid = true;
        return true;
    }

    bool SameValidator(const KhHttpCacheEntry& entry, const http::HttpCacheMetadata& metadata) noexcept
    {
        http::HttpCacheMetadata entryMetadata = {};
        if (!http::CollectCacheMetadata(entry.Headers, entry.HeaderCount, &entryMetadata)) {
            return false;
        }
        if (entryMetadata.HasETag && metadata.HasETag) {
            return entryMetadata.ETag.Length == metadata.ETag.Length &&
                RtlCompareMemory(entryMetadata.ETag.Data, metadata.ETag.Data, metadata.ETag.Length) ==
                metadata.ETag.Length;
        }
        if (entryMetadata.HasLastModified && metadata.HasLastModified) {
            return entryMetadata.LastModified.Length == metadata.LastModified.Length &&
                RtlCompareMemory(
                    entryMetadata.LastModified.Data,
                    metadata.LastModified.Data,
                    metadata.LastModified.Length) == metadata.LastModified.Length;
        }
        return false;
    }
}

void KhHttpCacheFreeSnapshot(KhHttpCacheSnapshot* snapshot) noexcept
{
    if (snapshot == nullptr) {
        return;
    }
    FreeNonPagedArray(snapshot->Headers);
    FreeApiMemory(snapshot->HeaderNameStorage);
    FreeApiMemory(snapshot->HeaderValueStorage);
    FreeApiMemory(snapshot->Body);
    *snapshot = {};
}

NTSTATUS KhHttpCacheLookup(
    KH_HTTP_CACHE cache,
    const KhRequest& request,
    const KhHttpSendOptions& options,
    KhHttpCacheLookupResult* result) noexcept
{
    if (result != nullptr) {
        *result = {};
    }
    if (result == nullptr || !IsCacheHandle(cache)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((options.Flags & KhHttpSendFlagNoCacheStore) != 0) {
        return STATUS_SUCCESS;
    }

    const bool onlyIfCached =
        (options.Flags & KhHttpSendFlagOnlyIfCached) != 0;
    if ((options.Flags & KhHttpSendFlagBypassCache) != 0 ||
        !http::IsMethodSafeForCache(static_cast<ULONG>(request.Method))) {
        if (onlyIfCached) {
            result->OnlyIfCachedMiss = true;
        }
        return STATUS_SUCCESS;
    }

    const char* cacheControlValue = nullptr;
    SIZE_T cacheControlLength = 0;
    http::HttpCacheMetadata requestMetadata = {};
    if (FindRequestHeader(request, "Cache-Control", &cacheControlValue, &cacheControlLength)) {
        http::ParseCacheControl({ cacheControlValue, cacheControlLength }, &requestMetadata.CacheControl);
    }
    if (onlyIfCached) {
        requestMetadata.CacheControl.OnlyIfCached = true;
    }

    char* key = nullptr;
    SIZE_T keyLength = 0;
    if (!BuildCacheKey(request, &key, &keyLength)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const char* rangeValue = nullptr;
    SIZE_T rangeValueLength = 0;
    http::HttpByteRange requestedRange = {};
    const bool hasRange = FindRequestHeader(request, "Range", &rangeValue, &rangeValueLength) &&
        http::ParseSingleByteRange({ rangeValue, rangeValueLength }, &requestedRange);

    const LONGLONG now = CurrentSeconds();
    AcquireCacheLock(cache);
    for (KhHttpCacheEntry* entry = cache->Head; entry != nullptr; entry = entry->Next) {
        if (entry->KeyLength != keyLength ||
            RtlCompareMemory(entry->Key, key, keyLength) != keyLength ||
            !VaryMatches(*entry, request)) {
            continue;
        }

        http::HttpCacheMetadata responseMetadata = {};
        http::CollectCacheMetadata(entry->Headers, entry->HeaderCount, &responseMetadata);
        bool requiresValidation = true;
        if (!http::CanUseStoredResponse(
            requestMetadata,
            responseMetadata,
            entry->StatusCode,
            entry->StoredAtSeconds,
            now,
            cache->Options.Mode == KhHttpCacheMode::Shared ? http::HttpCacheScope::Shared : http::HttpCacheScope::Private,
            &requiresValidation)) {
            continue;
        }

        if (hasRange) {
            http::HttpByteRange concreteRange = {};
            if (!RequestedRangeCovered(*entry, requestedRange, &concreteRange)) {
                continue;
            }
            if (!requiresValidation &&
                CopySnapshotFromEntry(*entry, &concreteRange, &result->Snapshot)) {
                MoveToHead(cache, entry);
                result->Found = true;
                result->RangeRequest = true;
                result->SatisfiedRange = true;
                ++cache->Stats.Hits;
            }
            else {
                result->Found = true;
                result->RequiresValidation = true;
            }
        }
        else if (!requiresValidation && !entry->Partial &&
            CopySnapshotFromEntry(*entry, nullptr, &result->Snapshot)) {
            MoveToHead(cache, entry);
            result->Found = true;
            ++cache->Stats.Hits;
        }
        else {
            result->Found = true;
            result->RequiresValidation = true;
        }

        if (result->RequiresValidation) {
            if (responseMetadata.HasETag && responseMetadata.ETag.Length <= KhMaxHeaderValueLength) {
                RtlCopyMemory(result->IfNoneMatch, responseMetadata.ETag.Data, responseMetadata.ETag.Length);
                result->IfNoneMatchLength = responseMetadata.ETag.Length;
            }
            else if (responseMetadata.HasLastModified &&
                responseMetadata.LastModified.Length <= KhMaxHeaderValueLength) {
                RtlCopyMemory(
                    result->IfModifiedSince,
                    responseMetadata.LastModified.Data,
                    responseMetadata.LastModified.Length);
                result->IfModifiedSinceLength = responseMetadata.LastModified.Length;
            }
            ++cache->Stats.Revalidations;
        }
        FreeApiMemory(key);
        ReleaseCacheLock(cache);
        return STATUS_SUCCESS;
    }

    ++cache->Stats.Misses;
    if (onlyIfCached) {
        result->OnlyIfCachedMiss = true;
    }
    ReleaseCacheLock(cache);
    FreeApiMemory(key);
    return STATUS_SUCCESS;
}

NTSTATUS KhHttpCacheStoreResponse(
    KH_HTTP_CACHE cache,
    const KhRequest& request,
    const KhHttpSendOptions& options,
    const http::HttpResponse& response) noexcept
{
    if (!IsCacheHandle(cache) || (options.Flags & KhHttpSendFlagNoCacheStore) != 0) {
        return STATUS_SUCCESS;
    }

    const char* requestCc = nullptr;
    SIZE_T requestCcLength = 0;
    http::HttpCacheControl requestControl = {};
    if (FindRequestHeader(request, "Cache-Control", &requestCc, &requestCcLength)) {
        http::ParseCacheControl({ requestCc, requestCcLength }, &requestControl);
    }
    const bool requestHasAuthorization = RequestHasHeader(request, "Authorization");
    http::HttpCacheMetadata metadata = {};
    if (!http::CollectCacheMetadata(response, &metadata) ||
        !http::ResponseMayBeStored(
            static_cast<ULONG>(request.Method),
            requestHasAuthorization,
            requestControl,
            response,
            metadata,
            cache->Options.Mode == KhHttpCacheMode::Shared ? http::HttpCacheScope::Shared : http::HttpCacheScope::Private)) {
        return STATUS_SUCCESS;
    }

    char* key = nullptr;
    SIZE_T keyLength = 0;
    if (!BuildCacheKey(request, &key, &keyLength)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    auto* entry = AllocateNonPagedObject<KhHttpCacheEntry>();
    if (entry == nullptr) {
        FreeApiMemory(key);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    entry->Key = key;
    entry->KeyLength = keyLength;
    entry->Method = static_cast<ULONG>(request.Method);
    entry->StatusCode = response.StatusCode;
    entry->StoredAtSeconds = CurrentSeconds();

    if (!CopyHeaders(
        response.Headers,
        response.HeaderCount,
        &entry->Headers,
        &entry->HeaderNameStorage,
        &entry->HeaderNameStorageLength,
        &entry->HeaderValueStorage,
        &entry->HeaderValueStorageLength) ||
        !CopyVaryFromResponse(*entry, request, metadata.Vary)) {
        FreeEntry(entry);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    entry->HeaderCount = response.HeaderCount;

    http::HttpContentRange contentRange = {};
    if (response.StatusCode == 206 && response.GetContentRange(&contentRange) &&
        contentRange.HasRange && contentRange.HasCompleteLength) {
        const ULONGLONG expectedLength = contentRange.LastBytePos - contentRange.FirstBytePos + 1;
        if (expectedLength != response.BodyLength ||
            contentRange.CompleteLength > static_cast<ULONGLONG>(cache->Options.MaxBytes)) {
            FreeEntry(entry);
            return STATUS_SUCCESS;
        }
        entry->Partial = true;
        entry->CompleteLength = contentRange.CompleteLength;
        entry->BodyCapacity = static_cast<SIZE_T>(contentRange.CompleteLength);
        entry->BodyLength = static_cast<SIZE_T>(contentRange.CompleteLength);
        entry->Body = static_cast<UCHAR*>(AllocateApiMemory(entry->BodyCapacity));
        if (entry->Body == nullptr) {
            FreeEntry(entry);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(entry->Body + static_cast<SIZE_T>(contentRange.FirstBytePos), response.Body, response.BodyLength);
        entry->Ranges[0] = { contentRange.FirstBytePos, contentRange.LastBytePos };
        entry->RangeCount = 1;
    }
    else {
        if (response.BodyLength > cache->Options.MaxBytes) {
            FreeEntry(entry);
            return STATUS_SUCCESS;
        }
        if (response.BodyLength != 0) {
            entry->Body = AllocateBytesCopy(reinterpret_cast<const UCHAR*>(response.Body), response.BodyLength);
            if (entry->Body == nullptr) {
                FreeEntry(entry);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        entry->BodyLength = response.BodyLength;
        entry->BodyCapacity = response.BodyLength;
    }

    entry->ChargeBytes =
        entry->KeyLength +
        entry->HeaderNameStorageLength +
        entry->HeaderValueStorageLength +
        entry->BodyCapacity +
        sizeof(KhHttpCacheEntry);

    AcquireCacheLock(cache);
    for (KhHttpCacheEntry* existing = cache->Head; existing != nullptr;) {
        KhHttpCacheEntry* next = existing->Next;
        if (existing->KeyLength == keyLength &&
            RtlCompareMemory(existing->Key, key, keyLength) == keyLength &&
            VaryMatches(*existing, request)) {
            if (entry->Partial && existing->Partial && SameValidator(*existing, metadata)) {
                if (existing->BodyCapacity == entry->BodyCapacity &&
                    entry->RangeCount != 0 &&
                    existing->RangeCount < KhHttpCacheMaxPartialRanges) {
                    const KhHttpCacheRange added = entry->Ranges[0];
                    const SIZE_T addedOffset = static_cast<SIZE_T>(added.First);
                    const SIZE_T addedLength = static_cast<SIZE_T>(added.Last - added.First + 1);
                    RtlCopyMemory(existing->Body + addedOffset, entry->Body + addedOffset, addedLength);
                    existing->Ranges[existing->RangeCount++] = added;
                    MoveToHead(cache, existing);
                    FreeEntry(entry);
                    ++cache->Stats.Stores;
                    ReleaseCacheLock(cache);
                    return STATUS_SUCCESS;
                }
            }
            RemoveAndFree(cache, existing);
        }
        existing = next;
    }

    LinkHead(cache, entry);
    ++cache->Stats.Stores;
    EvictToLimits(cache);
    ReleaseCacheLock(cache);
    return STATUS_SUCCESS;
}

NTSTATUS KhHttpCacheUpdateNotModified(
    KH_HTTP_CACHE cache,
    const KhRequest& request,
    const http::HttpResponse& response,
    KhHttpCacheSnapshot* snapshot) noexcept
{
    if (snapshot != nullptr) {
        *snapshot = {};
    }
    if (!IsCacheHandle(cache) || snapshot == nullptr || response.StatusCode != 304) {
        return STATUS_NOT_FOUND;
    }

    char* key = nullptr;
    SIZE_T keyLength = 0;
    if (!BuildCacheKey(request, &key, &keyLength)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    AcquireCacheLock(cache);
    for (KhHttpCacheEntry* entry = cache->Head; entry != nullptr; entry = entry->Next) {
        if (entry->KeyLength == keyLength &&
            RtlCompareMemory(entry->Key, key, keyLength) == keyLength &&
            VaryMatches(*entry, request) &&
            !entry->Partial) {
            entry->StoredAtSeconds = CurrentSeconds();
            const bool copied = CopySnapshotFromEntry(*entry, nullptr, snapshot);
            if (copied) {
                MoveToHead(cache, entry);
            }
            ReleaseCacheLock(cache);
            FreeApiMemory(key);
            return copied ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    ReleaseCacheLock(cache);
    FreeApiMemory(key);
    return STATUS_NOT_FOUND;
}

void KhHttpCacheInvalidateForRequest(KH_HTTP_CACHE cache, const KhRequest& request) noexcept
{
    if (!IsCacheHandle(cache)) {
        return;
    }
    AcquireCacheLock(cache);
    for (KhHttpCacheEntry* entry = cache->Head; entry != nullptr;) {
        KhHttpCacheEntry* next = entry->Next;
        if (SameUrlKey(*entry, request)) {
            RemoveAndFree(cache, entry);
            ++cache->Stats.Invalidations;
        }
        entry = next;
    }
    ReleaseCacheLock(cache);
}

NTSTATUS KhHttpCacheCreate(const KhHttpCacheOptions* options, KH_HTTP_CACHE* cache) noexcept
{
    NTSTATUS status = CheckPassiveLevel();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (cache != nullptr) {
        *cache = nullptr;
    }
    if (cache == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    KhHttpCacheOptions effective = {};
    if (options != nullptr) {
        effective = *options;
    }
    if (effective.MaxBytes == 0 || effective.MaxEntries == 0 ||
        (effective.Mode != KhHttpCacheMode::Private && effective.Mode != KhHttpCacheMode::Shared)) {
        return STATUS_INVALID_PARAMETER;
    }

    KH_HTTP_CACHE created = AllocateNonPagedObject<KhHttpCache>();
    if (created == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    created->Header = { KhHandleKind::HttpCache, 0, nullptr };
    created->Options = effective;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    EnsureLockInitialized(created);
#endif
    *cache = created;
    return STATUS_SUCCESS;
}

NTSTATUS KhHttpCacheClear(KH_HTTP_CACHE cache) noexcept
{
    NTSTATUS status = CheckPassiveLevel();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!IsCacheHandle(cache)) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireCacheLock(cache);
    KhHttpCacheEntry* entry = cache->Head;
    cache->Head = nullptr;
    cache->Tail = nullptr;
    cache->EntryCount = 0;
    cache->BytesUsed = 0;
    while (entry != nullptr) {
        KhHttpCacheEntry* next = entry->Next;
        FreeEntry(entry);
        entry = next;
    }
    ReleaseCacheLock(cache);
    return STATUS_SUCCESS;
}

NTSTATUS KhHttpCacheGetStats(KH_HTTP_CACHE cache, KhHttpCacheStats* stats) noexcept
{
    if (stats != nullptr) {
        *stats = {};
    }
    NTSTATUS status = CheckPassiveLevel();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!IsCacheHandle(cache) || stats == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    AcquireCacheLock(cache);
    *stats = cache->Stats;
    stats->EntryCount = cache->EntryCount;
    stats->BytesUsed = cache->BytesUsed;
    ReleaseCacheLock(cache);
    return STATUS_SUCCESS;
}

void KhHttpCacheClose(KH_HTTP_CACHE cache) noexcept
{
    if (!NT_SUCCESS(CheckPassiveLevel()) || cache == nullptr) {
        return;
    }
    if (cache->Header.Kind != KhHandleKind::HttpCache) {
        return;
    }
    KhHttpCacheClear(cache);
#if defined(KERNEL_HTTP_USER_MODE_TEST)
    if (cache->Header.Closed != 0) {
        return;
    }
    cache->Header.Closed = 1;
#else
    if (InterlockedCompareExchange(&cache->Header.Closed, 1, 0) != 0) {
        return;
    }
#endif
    FreeNonPagedObject(cache);
}
}
}
