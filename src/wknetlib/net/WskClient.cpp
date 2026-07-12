#include "net/WskClient.h"

#if !defined(WKNET_USER_MODE_TEST)
#include "WskSync.h"
#endif

#ifndef STATUS_NO_MATCH
#define STATUS_NO_MATCH ((NTSTATUS)0xC0000272L)
#endif

namespace wknet
{
namespace net
{
#if !defined(WKNET_USER_MODE_TEST)
    volatile LONG g_wskAbandonedIrpCount = 0;
#endif

    namespace
    {
#if !defined(WKNET_USER_MODE_TEST)
        const WSK_CLIENT_DISPATCH WskClientDispatch = {
            MAKE_WSK_VERSION(1, 0),
            0,
            nullptr
        };

        struct ResolveRequestContext final
        {
            wchar_t* NodeName = nullptr;
            wchar_t* ServiceName = nullptr;
            UNICODE_STRING Node = {};
            UNICODE_STRING Service = {};
            ADDRINFOEXW Hints = {};
            PADDRINFOEXW Result = nullptr;
        };

        void DeleteResolveRequestContext(_In_opt_ void* context) noexcept
        {
            auto* request = static_cast<ResolveRequestContext*>(context);
            if (request == nullptr) {
                return;
            }

            FreeNonPagedArray(request->NodeName);
            FreeNonPagedArray(request->ServiceName);
            FreeNonPagedObject(request);
        }
#endif

        constexpr SIZE_T ResolveCacheCapacity = 16;
        constexpr SIZE_T ResolveCacheNodeNameChars = 256;
        constexpr SIZE_T ResolveCacheServiceNameChars = 16;
        constexpr ULONGLONG ResolveCacheTtl100ns = 5ULL * 60ULL * 1000ULL * 10000ULL;

        struct ResolveCacheEntry final
        {
            bool Valid = false;
            WskAddressFamily AddressFamily = WskAddressFamily::Any;
            SIZE_T NodeNameLength = 0;
            SIZE_T ServiceNameLength = 0;
            wchar_t NodeName[ResolveCacheNodeNameChars] = {};
            wchar_t ServiceName[ResolveCacheServiceNameChars] = {};
            SOCKADDR_STORAGE Addresses[WskMaxResolvedAddresses] = {};
            SIZE_T AddressCount = 0;
            ULONGLONG CachedAt100ns = 0;
        };

#if defined(WKNET_USER_MODE_TEST)
        WskTestResolveAllCallback g_testResolveAll = nullptr;
        void* g_testResolveAllContext = nullptr;
        ULONGLONG g_testResolveCacheNow100ns = 10000;

        void EnsureResolveCacheLockInitialized() noexcept
        {
        }

        void AcquireResolveCacheLock() noexcept
        {
        }

        void ReleaseResolveCacheLock() noexcept
        {
        }
#else
        FAST_MUTEX g_resolveCacheLock = {};
        volatile LONG g_resolveCacheLockState = 0;
        KEVENT g_wskOutstandingContextEvent = {};
        volatile LONG g_wskOutstandingContextEventState = 0;
        volatile LONG g_wskOutstandingContextCount = 0;
        volatile LONG g_wskOpenSocketCount = 0;
        volatile LONG g_wskClosePendingSocketCount = 0;
        PWSK_SOCKET g_wskLastOpenedSocket = nullptr;
        PWSK_SOCKET g_wskLastCloseStartedSocket = nullptr;
        PWSK_SOCKET g_wskLastClosedSocket = nullptr;
        NTSTATUS g_wskLastSocketCloseStatus = STATUS_SUCCESS;

        void EnsureResolveCacheLockInitialized() noexcept
        {
            const LONG previous = InterlockedCompareExchange(&g_resolveCacheLockState, 1, 0);
            if (previous == 0) {
                ExInitializeFastMutex(&g_resolveCacheLock);
                InterlockedExchange(&g_resolveCacheLockState, 2);
                return;
            }

            while (InterlockedCompareExchange(&g_resolveCacheLockState, 2, 2) != 2) {
                LARGE_INTEGER delay = {};
                delay.QuadPart = -10000LL;
                const NTSTATUS status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
                UNREFERENCED_PARAMETER(status);
            }
        }

        void AcquireResolveCacheLock() noexcept
        {
            ExAcquireFastMutex(&g_resolveCacheLock);
        }

        void ReleaseResolveCacheLock() noexcept
        {
            ExReleaseFastMutex(&g_resolveCacheLock);
        }

        void EnsureWskOutstandingContextEventInitialized() noexcept
        {
            if (InterlockedCompareExchange(&g_wskOutstandingContextEventState, 0, 0) == 2) {
                return;
            }

            if (InterlockedCompareExchange(&g_wskOutstandingContextEventState, 1, 0) == 0) {
                KeInitializeEvent(&g_wskOutstandingContextEvent, NotificationEvent, TRUE);
                InterlockedExchange(&g_wskOutstandingContextEventState, 2);
                return;
            }

            while (InterlockedCompareExchange(&g_wskOutstandingContextEventState, 2, 2) != 2) {
                LARGE_INTEGER delay = {};
                delay.QuadPart = -10000LL;
                const NTSTATUS status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
                UNREFERENCED_PARAMETER(status);
            }
        }
#endif

        ResolveCacheEntry g_resolveCache[ResolveCacheCapacity] = {};
        SIZE_T g_resolveCacheNextSlot = 0;

        _Must_inspect_result_
        ULONGLONG QueryResolveCacheTime() noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            if (g_testResolveCacheNow100ns == 0) {
                g_testResolveCacheNow100ns = 10000;
            }
            return g_testResolveCacheNow100ns;
#else
            return KeQueryInterruptTime();
#endif
        }

        _Must_inspect_result_
        USHORT ByteSwapUshort(USHORT value) noexcept
        {
            return static_cast<USHORT>((value >> 8) | (value << 8));
        }

        _Must_inspect_result_
        SIZE_T WideStringLength(_In_z_ const wchar_t* text) noexcept
        {
            if (text == nullptr) {
                return 0;
            }

            SIZE_T length = 0;
            while (text[length] != L'\0') {
                ++length;
            }
            return length;
        }

        wchar_t LowerAsciiWide(wchar_t ch) noexcept
        {
            if (ch >= L'A' && ch <= L'Z') {
                return static_cast<wchar_t>(ch - L'A' + L'a');
            }
            return ch;
        }

        _Must_inspect_result_
        bool WideEqualsIgnoreCase(
            _In_reads_(leftLength) const wchar_t* left,
            SIZE_T leftLength,
            _In_reads_(rightLength) const wchar_t* right,
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

            for (SIZE_T index = 0; index < leftLength; ++index) {
                if (LowerAsciiWide(left[index]) != LowerAsciiWide(right[index])) {
                    return false;
                }
            }
            return true;
        }

        _Must_inspect_result_
        bool ResolveCacheKeyFits(SIZE_T nodeNameLength, SIZE_T serviceNameLength) noexcept
        {
            return nodeNameLength != 0 &&
                serviceNameLength != 0 &&
                nodeNameLength < ResolveCacheNodeNameChars &&
                serviceNameLength < ResolveCacheServiceNameChars;
        }

        void StoreResolveCache(
            _In_z_ const wchar_t* nodeName,
            _In_z_ const wchar_t* serviceName,
            _In_reads_(addressCount) const SOCKADDR_STORAGE* remoteAddresses,
            SIZE_T addressCount,
            WskAddressFamily addressFamily) noexcept;

        _Must_inspect_result_
        bool IsNoAddressResolveStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_NO_MATCH || status == STATUS_NOT_FOUND;
        }

        _Must_inspect_result_
        NTSTATUS SelectResolveFailureStatus(NTSTATUS ipv4Status, NTSTATUS ipv6Status) noexcept
        {
            if (!IsNoAddressResolveStatus(ipv4Status)) {
                return ipv4Status;
            }
            if (!IsNoAddressResolveStatus(ipv6Status)) {
                return ipv6Status;
            }
            return ipv4Status;
        }

        _Must_inspect_result_
        NTSTATUS ResolveAllExplicitAddressFamilies(
            _Inout_ WskClient& client,
            _In_z_ const wchar_t* nodeName,
            _In_z_ const wchar_t* serviceName,
            _Out_writes_(addressCapacity) SOCKADDR_STORAGE* remoteAddresses,
            SIZE_T addressCapacity,
            _Out_ SIZE_T* addressCount) noexcept
        {
            *addressCount = 0;

            SIZE_T ipv4Count = 0;
            NTSTATUS ipv4Status = client.ResolveAll(
                nodeName,
                serviceName,
                remoteAddresses,
                addressCapacity,
                &ipv4Count,
                WskAddressFamily::Ipv4);
            if (NT_SUCCESS(ipv4Status)) {
                *addressCount = ipv4Count;
            }

            SIZE_T ipv6Count = 0;
            NTSTATUS ipv6Status = STATUS_NO_MATCH;
            if (*addressCount < addressCapacity) {
                ipv6Status = client.ResolveAll(
                    nodeName,
                    serviceName,
                    remoteAddresses + *addressCount,
                    addressCapacity - *addressCount,
                    &ipv6Count,
                    WskAddressFamily::Ipv6);
                if (NT_SUCCESS(ipv6Status)) {
                    *addressCount += ipv6Count;
                }
            }

            if (*addressCount != 0) {
                StoreResolveCache(
                    nodeName,
                    serviceName,
                    remoteAddresses,
                    *addressCount,
                    WskAddressFamily::Any);
                return STATUS_SUCCESS;
            }

            return SelectResolveFailureStatus(ipv4Status, ipv6Status);
        }

        _Must_inspect_result_
        bool ResolveCacheEntryMatches(
            _In_ const ResolveCacheEntry& entry,
            _In_reads_(nodeNameLength) const wchar_t* nodeName,
            SIZE_T nodeNameLength,
            _In_reads_(serviceNameLength) const wchar_t* serviceName,
            SIZE_T serviceNameLength,
            WskAddressFamily addressFamily,
            ULONGLONG now100ns) noexcept
        {
            if (!entry.Valid ||
                entry.AddressFamily != addressFamily ||
                entry.AddressCount == 0 ||
                entry.CachedAt100ns == 0) {
                return false;
            }

            if (now100ns >= entry.CachedAt100ns &&
                now100ns - entry.CachedAt100ns > ResolveCacheTtl100ns) {
                return false;
            }

            return WideEqualsIgnoreCase(entry.NodeName, entry.NodeNameLength, nodeName, nodeNameLength) &&
                WideEqualsIgnoreCase(entry.ServiceName, entry.ServiceNameLength, serviceName, serviceNameLength);
        }

        _Must_inspect_result_
        bool TryCopyResolveCache(
            _In_z_ const wchar_t* nodeName,
            _In_z_ const wchar_t* serviceName,
            _Out_writes_(addressCapacity) SOCKADDR_STORAGE* remoteAddresses,
            SIZE_T addressCapacity,
            _Out_ SIZE_T* addressCount,
            WskAddressFamily addressFamily) noexcept
        {
            if (addressCount != nullptr) {
                *addressCount = 0;
            }
            if (nodeName == nullptr ||
                serviceName == nullptr ||
                remoteAddresses == nullptr ||
                addressCapacity == 0 ||
                addressCount == nullptr) {
                return false;
            }

            const SIZE_T nodeNameLength = WideStringLength(nodeName);
            const SIZE_T serviceNameLength = WideStringLength(serviceName);
            if (!ResolveCacheKeyFits(nodeNameLength, serviceNameLength)) {
                return false;
            }

            EnsureResolveCacheLockInitialized();
            const ULONGLONG now100ns = QueryResolveCacheTime();
            bool copied = false;

            AcquireResolveCacheLock();
            for (SIZE_T index = 0; index < ResolveCacheCapacity; ++index) {
                const ResolveCacheEntry& entry = g_resolveCache[index];
                if (!ResolveCacheEntryMatches(
                    entry,
                    nodeName,
                    nodeNameLength,
                    serviceName,
                    serviceNameLength,
                    addressFamily,
                    now100ns)) {
                    continue;
                }

                const SIZE_T copyCount = entry.AddressCount < addressCapacity ?
                    entry.AddressCount :
                    addressCapacity;
                RtlCopyMemory(remoteAddresses, entry.Addresses, copyCount * sizeof(SOCKADDR_STORAGE));
                *addressCount = copyCount;
                copied = copyCount != 0;
                break;
            }
            ReleaseResolveCacheLock();

            return copied;
        }

        void StoreResolveCache(
            _In_z_ const wchar_t* nodeName,
            _In_z_ const wchar_t* serviceName,
            _In_reads_(addressCount) const SOCKADDR_STORAGE* remoteAddresses,
            SIZE_T addressCount,
            WskAddressFamily addressFamily) noexcept
        {
            if (nodeName == nullptr ||
                serviceName == nullptr ||
                remoteAddresses == nullptr ||
                addressCount == 0) {
                return;
            }

            const SIZE_T nodeNameLength = WideStringLength(nodeName);
            const SIZE_T serviceNameLength = WideStringLength(serviceName);
            if (!ResolveCacheKeyFits(nodeNameLength, serviceNameLength)) {
                return;
            }

            EnsureResolveCacheLockInitialized();
            const ULONGLONG now100ns = QueryResolveCacheTime();
            const SIZE_T storedAddressCount = addressCount < WskMaxResolvedAddresses ?
                addressCount :
                WskMaxResolvedAddresses;
            SIZE_T slot = ResolveCacheCapacity;

            AcquireResolveCacheLock();
            for (SIZE_T index = 0; index < ResolveCacheCapacity; ++index) {
                const ResolveCacheEntry& entry = g_resolveCache[index];
                if (ResolveCacheEntryMatches(
                    entry,
                    nodeName,
                    nodeNameLength,
                    serviceName,
                    serviceNameLength,
                    addressFamily,
                    now100ns)) {
                    slot = index;
                    break;
                }
                if (!entry.Valid && slot == ResolveCacheCapacity) {
                    slot = index;
                }
            }

            if (slot == ResolveCacheCapacity) {
                slot = g_resolveCacheNextSlot;
                g_resolveCacheNextSlot = (g_resolveCacheNextSlot + 1) % ResolveCacheCapacity;
            }

            ResolveCacheEntry& entry = g_resolveCache[slot];
            entry.Valid = false;
            entry.AddressFamily = addressFamily;
            entry.NodeNameLength = nodeNameLength;
            entry.ServiceNameLength = serviceNameLength;
            RtlZeroMemory(entry.NodeName, sizeof(entry.NodeName));
            RtlZeroMemory(entry.ServiceName, sizeof(entry.ServiceName));
            RtlCopyMemory(entry.NodeName, nodeName, nodeNameLength * sizeof(wchar_t));
            RtlCopyMemory(entry.ServiceName, serviceName, serviceNameLength * sizeof(wchar_t));
            RtlCopyMemory(entry.Addresses, remoteAddresses, storedAddressCount * sizeof(SOCKADDR_STORAGE));
            entry.AddressCount = storedAddressCount;
            entry.CachedAt100ns = now100ns;
            entry.Valid = true;
            ReleaseResolveCacheLock();
        }

        void ClearResolveCache() noexcept
        {
            EnsureResolveCacheLockInitialized();

            AcquireResolveCacheLock();
            RtlZeroMemory(g_resolveCache, sizeof(g_resolveCache));
            g_resolveCacheNextSlot = 0;
            ReleaseResolveCacheLock();
        }

#if !defined(WKNET_USER_MODE_TEST)
        _Ret_maybenull_
        wchar_t* AllocateWideStringCopy(_In_z_ const wchar_t* text) noexcept
        {
            const SIZE_T length = WideStringLength(text);
            if (length == 0 || length >= (static_cast<SIZE_T>(MAXUSHORT) / sizeof(wchar_t))) {
                return nullptr;
            }

            wchar_t* copy = AllocateNonPagedArray<wchar_t>(length + 1);
            if (copy == nullptr) {
                return nullptr;
            }

            RtlCopyMemory(copy, text, length * sizeof(wchar_t));
            copy[length] = L'\0';
            return copy;
        }
#endif

        _Must_inspect_result_
        bool ParseTcpPort(
            _In_z_ const wchar_t* serviceName,
            _Out_ USHORT* port) noexcept
        {
            if (serviceName == nullptr || port == nullptr) {
                return false;
            }

            ULONG value = 0;
            for (const wchar_t* current = serviceName; *current != L'\0'; ++current) {
                if (*current < L'0' || *current > L'9') {
                    return false;
                }

                value = (value * 10) + static_cast<ULONG>(*current - L'0');
                if (value > 0xffff) {
                    return false;
                }
            }

            if (value == 0) {
                return false;
            }

            *port = ByteSwapUshort(static_cast<USHORT>(value));
            return true;
        }

        _Must_inspect_result_
        int ToSocketAddressFamily(WskAddressFamily addressFamily) noexcept
        {
            switch (addressFamily) {
            case WskAddressFamily::Any:
                return AF_UNSPEC;
            case WskAddressFamily::Ipv4:
                return AF_INET;
            case WskAddressFamily::Ipv6:
                return AF_INET6;
            default:
                return -1;
            }
        }

#if !defined(WKNET_USER_MODE_TEST)
        _Must_inspect_result_
        bool CopySocketAddress(
            _In_ const ADDRINFOEXW* addressInfo,
            USHORT port,
            _Out_ SOCKADDR_STORAGE* remoteAddress) noexcept
        {
            if (addressInfo == nullptr ||
                addressInfo->ai_addr == nullptr ||
                remoteAddress == nullptr ||
                addressInfo->ai_addrlen > sizeof(*remoteAddress)) {
                return false;
            }

            if (addressInfo->ai_family != AF_INET && addressInfo->ai_family != AF_INET6) {
                return false;
            }

            RtlZeroMemory(remoteAddress, sizeof(*remoteAddress));
            RtlCopyMemory(remoteAddress, addressInfo->ai_addr, addressInfo->ai_addrlen);

            if (remoteAddress->ss_family == AF_INET) {
                reinterpret_cast<SOCKADDR_IN*>(remoteAddress)->sin_port = port;
            }
            else if (remoteAddress->ss_family == AF_INET6) {
                reinterpret_cast<SOCKADDR_IN6*>(remoteAddress)->sin6_port = port;
            }

            return true;
        }
#endif
    }

#if !defined(WKNET_USER_MODE_TEST)
    WskSyncIrpContext* WskSyncAllocateIrpContext() noexcept
    {
        return AllocateNonPagedObject<WskSyncIrpContext>();
    }

    void WskSyncFreeIrpContext(_In_opt_ WskSyncIrpContext* context) noexcept
    {
        if (context == nullptr) {
            return;
        }

        FreeNonPagedObject(context);
    }

    WskBuffer* WskSyncAllocateBufferObject() noexcept
    {
        return AllocateNonPagedObject<WskBuffer>();
    }

    void WskSyncFreeBufferObject(_In_opt_ WskBuffer* buffer) noexcept
    {
        if (buffer == nullptr) {
            return;
        }

        FreeNonPagedObject(buffer);
    }

    void WskSyncTrackContextAllocated() noexcept
    {
        EnsureWskOutstandingContextEventInitialized();
        const LONG count = InterlockedIncrement(&g_wskOutstandingContextCount);
        if (count == 1) {
            KeClearEvent(&g_wskOutstandingContextEvent);
        }
    }

    void WskSyncTrackContextReleased() noexcept
    {
        const LONG count = InterlockedDecrement(&g_wskOutstandingContextCount);
        if (count == 0) {
            EnsureWskOutstandingContextEventInitialized();
            KeSetEvent(&g_wskOutstandingContextEvent, IO_NO_INCREMENT, FALSE);
        }
        else if (count < 0) {
            NT_ASSERT(false);
            InterlockedExchange(&g_wskOutstandingContextCount, 0);
            EnsureWskOutstandingContextEventInitialized();
            KeSetEvent(&g_wskOutstandingContextEvent, IO_NO_INCREMENT, FALSE);
        }
    }

    NTSTATUS WskSyncWaitForOutstandingContexts(ULONG timeoutMilliseconds) noexcept
    {
        EnsureWskOutstandingContextEventInitialized();

        const LONG count = InterlockedCompareExchange(&g_wskOutstandingContextCount, 0, 0);
        if (count == 0) {
            return STATUS_SUCCESS;
        }

        WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Error, "等待 WSK IRP context 完成: outstanding=%ld\r\n", static_cast<long>(count));

        LARGE_INTEGER timeout = {};
        LARGE_INTEGER* timeoutPointer = nullptr;
        if (timeoutMilliseconds != 0xffffffffUL) {
            timeout.QuadPart = -static_cast<LONGLONG>(timeoutMilliseconds) * 10000LL;
            timeoutPointer = &timeout;
        }

        const NTSTATUS status = KeWaitForSingleObject(
            &g_wskOutstandingContextEvent,
            Executive,
            KernelMode,
            FALSE,
            timeoutPointer);
        if (NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Info, "WSK IRP context 已完成\r\n");
        }
        else {
            const LONG remaining = InterlockedCompareExchange(&g_wskOutstandingContextCount, 0, 0);
            UNREFERENCED_PARAMETER(remaining);
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Error, "等待 WSK IRP context 失败: 0x%08X outstanding=%ld\r\n",
                static_cast<ULONG>(status),
                static_cast<long>(remaining));
        }
        return status;
    }

    void WskSyncTrackSocketOpened(_In_opt_ PWSK_SOCKET socket) noexcept
    {
        if (socket == nullptr) {
            return;
        }

        g_wskLastOpenedSocket = socket;
        const LONG count = InterlockedIncrement(&g_wskOpenSocketCount);
        UNREFERENCED_PARAMETER(count);
        WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Info, "WSK socket opened: socket=%p open=%ld\r\n", socket, static_cast<long>(count));
    }

    void WskSyncTrackSocketCloseStarted(_In_opt_ PWSK_SOCKET socket) noexcept
    {
        if (socket == nullptr) {
            return;
        }

        g_wskLastCloseStartedSocket = socket;
        const LONG pending = InterlockedIncrement(&g_wskClosePendingSocketCount);
        UNREFERENCED_PARAMETER(pending);
        WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Info, "WSK socket close started: socket=%p pending=%ld\r\n", socket, static_cast<long>(pending));
    }

    void WskSyncTrackSocketClosed(_In_opt_ PWSK_SOCKET socket, NTSTATUS closeStatus) noexcept
    {
        if (socket == nullptr) {
            return;
        }

        g_wskLastClosedSocket = socket;
        g_wskLastSocketCloseStatus = closeStatus;
        const LONG pending = InterlockedDecrement(&g_wskClosePendingSocketCount);
        LONG open = InterlockedCompareExchange(&g_wskOpenSocketCount, 0, 0);
        UNREFERENCED_PARAMETER(pending);
        if (NT_SUCCESS(closeStatus) && open > 0) {
            open = InterlockedDecrement(&g_wskOpenSocketCount);
        }
        UNREFERENCED_PARAMETER(open);

        WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Verbose,
            "WSK socket close completed: socket=%p status=0x%08X open=%ld pending=%ld\r\n",
            socket,
            static_cast<ULONG>(closeStatus),
            static_cast<long>(open),
            static_cast<long>(pending));
    }

    void WskSyncLogOutstandingSockets() noexcept
    {
        const LONG open = InterlockedCompareExchange(&g_wskOpenSocketCount, 0, 0);
        const LONG pending = InterlockedCompareExchange(&g_wskClosePendingSocketCount, 0, 0);
        const LONG contexts = InterlockedCompareExchange(&g_wskOutstandingContextCount, 0, 0);
        UNREFERENCED_PARAMETER(open);
        UNREFERENCED_PARAMETER(pending);
        UNREFERENCED_PARAMETER(contexts);
        WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Verbose,
            "WSK shutdown state: openSockets=%ld closePending=%ld irpContexts=%ld lastOpen=%p lastCloseStart=%p lastClosed=%p lastCloseStatus=0x%08X\r\n",
            static_cast<long>(open),
            static_cast<long>(pending),
            static_cast<long>(contexts),
            g_wskLastOpenedSocket,
            g_wskLastCloseStartedSocket,
            g_wskLastClosedSocket,
            static_cast<ULONG>(g_wskLastSocketCloseStatus));
    }
#endif

    WskClient::WskClient() noexcept
    {
        clientNpi_.ClientContext = this;
#if !defined(WKNET_USER_MODE_TEST)
        clientNpi_.Dispatch = &WskClientDispatch;
#endif
    }

    WskClient::~WskClient() noexcept
    {
        Shutdown();
    }

    NTSTATUS WskClient::Initialize(ULONG waitTimeoutMilliseconds) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(waitTimeoutMilliseconds);
        registered_ = true;
        providerCaptured_ = true;
        providerNpi_.Client = reinterpret_cast<PWSK_CLIENT>(this);
        providerNpi_.Dispatch = reinterpret_cast<const WSK_PROVIDER_DISPATCH*>(this);
        return STATUS_SUCCESS;
#else
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (providerCaptured_) {
            return STATUS_SUCCESS;
        }

        NTSTATUS status = STATUS_SUCCESS;

        if (!registered_) {
            RtlZeroMemory(&registration_, sizeof(registration_));

            status = WskRegister(&clientNpi_, &registration_);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            registered_ = true;
        }

        RtlZeroMemory(&providerNpi_, sizeof(providerNpi_));

        status = WskCaptureProviderNPI(
            &registration_,
            waitTimeoutMilliseconds,
            &providerNpi_);

        if (!NT_SUCCESS(status)) {
            Shutdown();
            return status;
        }

        providerCaptured_ = true;
        return STATUS_SUCCESS;
#endif
    }

    void WskClient::Shutdown() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        providerCaptured_ = false;
        registered_ = false;
        RtlZeroMemory(&providerNpi_, sizeof(providerNpi_));
        ClearResolveCache();
#else
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            NT_ASSERT(false);
            return;
        }

        if (providerCaptured_ || registered_) {
            const NTSTATUS drainStatus = WskSyncWaitForOutstandingContexts(WskOperationTimeoutMilliseconds);
            if (!NT_SUCCESS(drainStatus)) {
                WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Error, "WSK IRP context 收敛失败: 0x%08X\r\n", static_cast<ULONG>(drainStatus));
            }
            WskSyncLogOutstandingSockets();
        }

        if (providerCaptured_) {
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Info, "开始释放 WSK provider NPI\r\n");
            WskReleaseProviderNPI(&registration_);
            providerCaptured_ = false;
            RtlZeroMemory(&providerNpi_, sizeof(providerNpi_));
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Info, "WSK provider NPI 已释放\r\n");
        }

        if (registered_) {
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Info, "开始注销 WSK client\r\n");
            WskDeregister(&registration_);
            registered_ = false;
            RtlZeroMemory(&registration_, sizeof(registration_));
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Info, "WSK client 已注销\r\n");
        }

        ClearResolveCache();
#endif
    }

    bool WskClient::IsInitialized() const noexcept
    {
        return providerCaptured_ &&
            providerNpi_.Client != nullptr &&
            providerNpi_.Dispatch != nullptr;
    }

    PWSK_CLIENT WskClient::ProviderClient() const noexcept
    {
        return IsInitialized() ? providerNpi_.Client : nullptr;
    }

    const WSK_PROVIDER_DISPATCH* WskClient::ProviderDispatch() const noexcept
    {
        return IsInitialized() ? providerNpi_.Dispatch : nullptr;
    }

#if defined(WKNET_USER_MODE_TEST)
    void WskTestSetResolveAll(WskTestResolveAllCallback callback, void* context) noexcept
    {
        g_testResolveAll = callback;
        g_testResolveAllContext = context;
    }

    void WskTestClearResolveCache() noexcept
    {
        ClearResolveCache();
        g_testResolveCacheNow100ns = 10000;
    }

    void WskTestAdvanceResolveCacheTime(ULONGLONG delta100ns) noexcept
    {
        g_testResolveCacheNow100ns += delta100ns;
        if (g_testResolveCacheNow100ns == 0) {
            g_testResolveCacheNow100ns = 10000;
        }
    }
#endif

    NTSTATUS WskClient::Resolve(
        const wchar_t* nodeName,
        const wchar_t* serviceName,
        SOCKADDR_STORAGE* remoteAddress,
        WskAddressFamily addressFamily) noexcept
    {
        SIZE_T addressCount = 0;
        return ResolveAll(
            nodeName,
            serviceName,
            remoteAddress,
            1,
            &addressCount,
            addressFamily);
    }

    NTSTATUS WskClient::ResolveAll(
        const wchar_t* nodeName,
        const wchar_t* serviceName,
        SOCKADDR_STORAGE* remoteAddresses,
        SIZE_T addressCapacity,
        SIZE_T* addressCount,
        WskAddressFamily addressFamily) noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return STATUS_INVALID_DEVICE_STATE;
        }
#endif

        if (addressCount != nullptr) {
            *addressCount = 0;
        }

        if (nodeName == nullptr || nodeName[0] == L'\0' ||
            serviceName == nullptr || serviceName[0] == L'\0' ||
            remoteAddresses == nullptr ||
            addressCapacity == 0 ||
            addressCount == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

#if !defined(WKNET_USER_MODE_TEST)
        auto* providerClient = ProviderClient();
        const auto* providerDispatch = ProviderDispatch();
        if (providerClient == nullptr ||
            providerDispatch == nullptr ||
            providerDispatch->WskGetAddressInfo == nullptr ||
            providerDispatch->WskFreeAddressInfo == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }
#endif

        USHORT port = 0;
        if (!ParseTcpPort(serviceName, &port)) {
            return STATUS_INVALID_PARAMETER;
        }

        const int socketAddressFamily = ToSocketAddressFamily(addressFamily);
        if (socketAddressFamily < 0) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(port);
        UNREFERENCED_PARAMETER(socketAddressFamily);
#endif

        if (TryCopyResolveCache(
            nodeName,
            serviceName,
            remoteAddresses,
            addressCapacity,
            addressCount,
            addressFamily)) {
            return STATUS_SUCCESS;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (g_testResolveAll == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }

        NTSTATUS status = g_testResolveAll(
            g_testResolveAllContext,
            nodeName,
            serviceName,
            remoteAddresses,
            addressCapacity,
            addressCount,
            addressFamily);
        if (!NT_SUCCESS(status) &&
            addressFamily == WskAddressFamily::Any &&
            IsNoAddressResolveStatus(status)) {
            return ResolveAllExplicitAddressFamilies(
                *this,
                nodeName,
                serviceName,
                remoteAddresses,
                addressCapacity,
                addressCount);
        }
        if (NT_SUCCESS(status) && *addressCount != 0) {
            StoreResolveCache(
                nodeName,
                serviceName,
                remoteAddresses,
                *addressCount,
                addressFamily);
        }
        return status;
#else
        WskSyncIrpContext* context = nullptr;
        NTSTATUS status = WskSyncAllocateIrp(&context);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* request = AllocateNonPagedObject<ResolveRequestContext>();
        if (request == nullptr) {
            WskSyncReleaseUnsubmittedContext(context);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        context->CleanupRoutine = DeleteResolveRequestContext;
        context->CleanupContext = request;

        request->NodeName = AllocateWideStringCopy(nodeName);
        request->ServiceName = AllocateWideStringCopy(serviceName);
        if (request->NodeName == nullptr || request->ServiceName == nullptr) {
            WskSyncReleaseUnsubmittedContext(context);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlInitUnicodeString(&request->Node, request->NodeName);
        RtlInitUnicodeString(&request->Service, request->ServiceName);

        // Microsoft name-resolution providers do not support AI_NUMERICSERV;
        // the library validates the numeric service and patches the port below.
        request->Hints.ai_flags = 0;
        request->Hints.ai_family = socketAddressFamily;
        request->Hints.ai_socktype = SOCK_STREAM;
        request->Hints.ai_protocol = IPPROTO_TCP;

        status = providerDispatch->WskGetAddressInfo(
            providerClient,
            &request->Node,
            &request->Service,
            NS_ALL,
            nullptr,
            &request->Hints,
            &request->Result,
            nullptr,
            nullptr,
            context->Irp);

        status = WskSyncCompleteIrp(status, context, WskOperationTimeoutMilliseconds, nullptr);

        if (!NT_SUCCESS(status)) {
            if (addressFamily == WskAddressFamily::Any && IsNoAddressResolveStatus(status)) {
                WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Warning, "WskGetAddressInfo AF_UNSPEC no match, querying explicit address families\r\n");
                WskSyncReleaseContext(context);
                return ResolveAllExplicitAddressFamilies(
                    *this,
                    nodeName,
                    serviceName,
                    remoteAddresses,
                    addressCapacity,
                    addressCount);
            }
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Error, "WskGetAddressInfo failed: 0x%08X\r\n", static_cast<ULONG>(status));
            WskSyncReleaseContext(context);
            return status;
        }

        if (request->Result == nullptr) {
            if (addressFamily == WskAddressFamily::Any) {
                WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Warning, "WskGetAddressInfo AF_UNSPEC returned no results, querying explicit address families\r\n");
                WskSyncReleaseContext(context);
                return ResolveAllExplicitAddressFamilies(
                    *this,
                    nodeName,
                    serviceName,
                    remoteAddresses,
                    addressCapacity,
                    addressCount);
            }
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Error, "WskGetAddressInfo returned no results\r\n");
            WskSyncReleaseContext(context);
            return STATUS_NO_MATCH;
        }

        status = STATUS_NOT_FOUND;
        for (const ADDRINFOEXW* current = request->Result; current != nullptr; current = current->ai_next) {
            if (CopySocketAddress(current, port, &remoteAddresses[*addressCount])) {
                status = STATUS_SUCCESS;
                ++(*addressCount);
                if (*addressCount >= addressCapacity) {
                    break;
                }
            }
        }

        providerDispatch->WskFreeAddressInfo(providerClient, request->Result);
        request->Result = nullptr;
        if (!NT_SUCCESS(status)) {
            if (addressFamily == WskAddressFamily::Any && IsNoAddressResolveStatus(status)) {
                WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Warning, "WskGetAddressInfo AF_UNSPEC returned no usable address, querying explicit address families\r\n");
                WskSyncReleaseContext(context);
                return ResolveAllExplicitAddressFamilies(
                    *this,
                    nodeName,
                    serviceName,
                    remoteAddresses,
                    addressCapacity,
                    addressCount);
            }
            WKNET_TRACE(::wknet::ComponentNet, ::wknet::TraceLevel::Error, "WskGetAddressInfo returned no AF_INET/AF_INET6 address: 0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        else {
            StoreResolveCache(
                nodeName,
                serviceName,
                remoteAddresses,
                *addressCount,
                addressFamily);
        }
        WskSyncReleaseContext(context);
        return status;
#endif
    }
}
}
