#include "net/WskDatagramSocketPrivate.hpp"

#include <wknet/WknetLimits.h>
#include "rtl/TraceInternal.h"

#if defined(WKNET_USER_MODE_TEST)
#include "net/WskDatagramSocketTest.h"

#include <chrono>
#include <functional>
#include <thread>
#else
#include "net/WskSync.h"

#include <ws2ipdef.h>
#endif

namespace wknet::net
{
namespace
{
_Must_inspect_result_ ULONG AddressLengthForFamily(USHORT family) noexcept
{
    if (family == AF_INET)
    {
        return sizeof(SOCKADDR_IN);
    }
    if (family == AF_INET6)
    {
        return sizeof(SOCKADDR_IN6);
    }
    return 0;
}

void CopyAddress(_Out_ SOCKADDR_STORAGE *destination, _In_ const SOCKADDR *source, ULONG length) noexcept
{
    RtlZeroMemory(destination, sizeof(*destination));
    RtlCopyMemory(destination, source, length);
}

#if defined(WKNET_USER_MODE_TEST)
constexpr SIZE_T TestCompletionQueueCapacity = 16;

struct TestProviderState final
{
    std::mutex Lock;
    test::WskDatagramTestReceiveCompletion Queue[TestCompletionQueueCapacity] = {};
    SIZE_T QueueHead = 0;
    SIZE_T QueueCount = 0;
    WskDatagramSocket *PendingSocket = nullptr;
    test::WskDatagramTestReceiveCompletion PendingCompletion = {};
    bool PendingCancelled = false;
    bool CancelCompletesImmediately = false;
    bool FailAllocation = false;
    NTSTATUS NextOpenStatus = STATUS_SUCCESS;
    NTSTATUS NextBindStatus = STATUS_SUCCESS;
    NTSTATUS NextReceiveStartStatus = STATUS_SUCCESS;
    NTSTATUS NextSendStatus = STATUS_SUCCESS;
    SIZE_T NextSendBytes = static_cast<SIZE_T>(-1);
    test::WskDatagramProviderStatistics Statistics = {};
};

TestProviderState g_testProvider = {};

ULONGLONG CurrentTestThreadToken() noexcept
{
    return static_cast<ULONGLONG>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
}

bool TakeQueuedCompletion(test::WskDatagramTestReceiveCompletion *completion) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    if (g_testProvider.QueueCount == 0)
    {
        *completion = {};
        return false;
    }

    *completion = g_testProvider.Queue[g_testProvider.QueueHead];
    g_testProvider.Queue[g_testProvider.QueueHead] = {};
    g_testProvider.QueueHead = (g_testProvider.QueueHead + 1) % TestCompletionQueueCapacity;
    --g_testProvider.QueueCount;
    return true;
}

NTSTATUS TestOpen(WskDatagramSocket *socket) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    ++g_testProvider.Statistics.OpenCalls;
    const NTSTATUS status = g_testProvider.NextOpenStatus;
    g_testProvider.NextOpenStatus = STATUS_SUCCESS;
    if (NT_SUCCESS(status))
    {
        ++g_testProvider.Statistics.OpenSockets;
        UNREFERENCED_PARAMETER(socket);
    }
    return status;
}

NTSTATUS TestBind() noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    ++g_testProvider.Statistics.BindCalls;
    const NTSTATUS status = g_testProvider.NextBindStatus;
    g_testProvider.NextBindStatus = STATUS_SUCCESS;
    return status;
}

NTSTATUS TestSubmitReceive(WskDatagramSocket *socket) noexcept
{
    test::WskDatagramTestReceiveCompletion completion = {};
    const bool hasCompletion = TakeQueuedCompletion(&completion);

    {
        std::lock_guard<std::mutex> guard(g_testProvider.Lock);
        ++g_testProvider.Statistics.ReceiveCalls;
        ++g_testProvider.Statistics.AllocationAttempts;
        const NTSTATUS status = g_testProvider.NextReceiveStartStatus;
        g_testProvider.NextReceiveStartStatus = STATUS_SUCCESS;
        if (!NT_SUCCESS(status))
        {
            return status;
        }

        ++g_testProvider.Statistics.OutstandingReceives;
        ++g_testProvider.Statistics.BufferReferences;
        if (!hasCompletion)
        {
            completion = {};
        }

        if (!completion.CompleteSynchronously)
        {
            g_testProvider.PendingSocket = socket;
            g_testProvider.PendingCompletion = completion;
            g_testProvider.PendingCancelled = false;
            return STATUS_PENDING;
        }
    }

    socket->TestCompleteReceive(completion.Data, completion.DataLength, completion.RemoteAddress,
                                completion.RemoteAddressLength, completion.Status, false);
    return STATUS_SUCCESS;
}

void TestCancel(WskDatagramSocket *socket) noexcept
{
    test::WskDatagramTestReceiveCompletion completion = {};
    bool complete = false;
    {
        std::lock_guard<std::mutex> guard(g_testProvider.Lock);
        ++g_testProvider.Statistics.CancelCalls;
        if (g_testProvider.PendingSocket != socket)
        {
            return;
        }
        g_testProvider.PendingCancelled = true;
        if (g_testProvider.CancelCompletesImmediately)
        {
            completion = g_testProvider.PendingCompletion;
            g_testProvider.PendingSocket = nullptr;
            g_testProvider.PendingCompletion = {};
            g_testProvider.PendingCancelled = false;
            complete = true;
        }
    }

    if (complete)
    {
        socket->TestCompleteReceive(completion.Data, completion.DataLength, completion.RemoteAddress,
                                    completion.RemoteAddressLength, STATUS_CANCELLED, true);
    }
}

NTSTATUS TestSend(SIZE_T length, SIZE_T *bytesSent) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    ++g_testProvider.Statistics.SendCalls;
    const NTSTATUS status = g_testProvider.NextSendStatus;
    const SIZE_T configuredBytes = g_testProvider.NextSendBytes;
    g_testProvider.NextSendStatus = STATUS_SUCCESS;
    g_testProvider.NextSendBytes = static_cast<SIZE_T>(-1);
    if (bytesSent != nullptr && NT_SUCCESS(status))
    {
        *bytesSent = configuredBytes == static_cast<SIZE_T>(-1) ? length : configuredBytes;
    }
    return status;
}

void TestClose(WskDatagramSocket *socket) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    ++g_testProvider.Statistics.CloseCalls;
    if (g_testProvider.PendingSocket == socket)
    {
        g_testProvider.PendingSocket = nullptr;
        g_testProvider.PendingCompletion = {};
        g_testProvider.PendingCancelled = false;
        --g_testProvider.Statistics.OutstandingReceives;
        --g_testProvider.Statistics.BufferReferences;
    }
    if (g_testProvider.Statistics.OpenSockets > 0)
    {
        --g_testProvider.Statistics.OpenSockets;
    }
}
#else
NTSTATUS CompleteSynchronousWskRequest(NTSTATUS requestStatus, WskSyncIrpContext *context,
                                       SIZE_T *information = nullptr) noexcept
{
    const NTSTATUS status = WskSyncCompleteIrp(requestStatus, context, WskOperationTimeoutMilliseconds, information);
    WskSyncReleaseContext(context);
    return status;
}
#endif
} // namespace

#if defined(WKNET_USER_MODE_TEST)
namespace test
{
void ResetProvider() noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    g_testProvider.QueueHead = 0;
    g_testProvider.QueueCount = 0;
    g_testProvider.PendingSocket = nullptr;
    g_testProvider.PendingCompletion = {};
    g_testProvider.PendingCancelled = false;
    g_testProvider.CancelCompletesImmediately = false;
    g_testProvider.FailAllocation = false;
    g_testProvider.NextOpenStatus = STATUS_SUCCESS;
    g_testProvider.NextBindStatus = STATUS_SUCCESS;
    g_testProvider.NextReceiveStartStatus = STATUS_SUCCESS;
    g_testProvider.NextSendStatus = STATUS_SUCCESS;
    g_testProvider.NextSendBytes = static_cast<SIZE_T>(-1);
    g_testProvider.Statistics = {};
}

void QueueReceiveCompletion(const WskDatagramTestReceiveCompletion &completion) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    if (g_testProvider.QueueCount >= TestCompletionQueueCapacity)
    {
        return;
    }
    const SIZE_T tail = (g_testProvider.QueueHead + g_testProvider.QueueCount) % TestCompletionQueueCapacity;
    g_testProvider.Queue[tail] = completion;
    ++g_testProvider.QueueCount;
}

void SetNextSendResult(NTSTATUS status, SIZE_T bytesSent) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    g_testProvider.NextSendStatus = status;
    g_testProvider.NextSendBytes = bytesSent;
}

void SetNextOpenResult(NTSTATUS status) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    g_testProvider.NextOpenStatus = status;
}

void SetNextBindResult(NTSTATUS status) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    g_testProvider.NextBindStatus = status;
}

void SetNextReceiveStartResult(NTSTATUS status) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    g_testProvider.NextReceiveStartStatus = status;
}

void SetCancelCompletesImmediately(bool enabled) noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    g_testProvider.CancelCompletesImmediately = enabled;
}

void FailNextAllocation() noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    g_testProvider.FailAllocation = true;
}

bool CompletePendingReceive() noexcept
{
    WskDatagramSocket *socket = nullptr;
    WskDatagramTestReceiveCompletion completion = {};
    {
        std::lock_guard<std::mutex> guard(g_testProvider.Lock);
        if (g_testProvider.PendingSocket == nullptr || g_testProvider.PendingCancelled)
        {
            return false;
        }
        socket = g_testProvider.PendingSocket;
        completion = g_testProvider.PendingCompletion;
        g_testProvider.PendingSocket = nullptr;
        g_testProvider.PendingCompletion = {};
    }
    socket->TestCompleteReceive(completion.Data, completion.DataLength, completion.RemoteAddress,
                                completion.RemoteAddressLength, completion.Status, true);
    return true;
}

bool CompleteCancelledReceiveLate() noexcept
{
    WskDatagramSocket *socket = nullptr;
    WskDatagramTestReceiveCompletion completion = {};
    {
        std::lock_guard<std::mutex> guard(g_testProvider.Lock);
        if (g_testProvider.PendingSocket == nullptr || !g_testProvider.PendingCancelled)
        {
            return false;
        }
        socket = g_testProvider.PendingSocket;
        completion = g_testProvider.PendingCompletion;
        g_testProvider.PendingSocket = nullptr;
        g_testProvider.PendingCompletion = {};
        g_testProvider.PendingCancelled = false;
    }
    socket->TestCompleteReceive(completion.Data, completion.DataLength, completion.RemoteAddress,
                                completion.RemoteAddressLength, STATUS_CANCELLED, true);
    return true;
}

WskDatagramProviderStatistics GetProviderStatistics() noexcept
{
    std::lock_guard<std::mutex> guard(g_testProvider.Lock);
    return g_testProvider.Statistics;
}
} // namespace test
#endif

WskDatagramSocket::WskDatagramSocket() noexcept
{
#if !defined(WKNET_USER_MODE_TEST)
    KeInitializeSpinLock(&stateLock_);
    KeInitializeEvent(&receiveEvent_, NotificationEvent, FALSE);
    ExInitializeRundownProtection(&ioRundown_);
#endif
}

WskDatagramSocket::~WskDatagramSocket() noexcept
{
    const NTSTATUS status = Close();
    UNREFERENCED_PARAMETER(status);
#if !defined(WKNET_USER_MODE_TEST)
    if (receiveIrp_ != nullptr)
    {
        IoFreeIrp(receiveIrp_);
        receiveIrp_ = nullptr;
    }
#endif
}

bool WskDatagramSocket::IsPassiveLevel() const noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    return true;
#else
    return KeGetCurrentIrql() == PASSIVE_LEVEL;
#endif
}

ULONG WskDatagramSocket::AddressLength() const noexcept
{
    return AddressLengthForFamily(addressFamily_);
}

bool WskDatagramSocket::AddressMatchesFamily(const SOCKADDR *address) const noexcept
{
    return address != nullptr && AddressLength() != 0 && address->sa_family == addressFamily_;
}

void WskDatagramSocket::MakeWildcardAddress(SOCKADDR_STORAGE *address) const noexcept
{
    RtlZeroMemory(address, sizeof(*address));
    address->ss_family = addressFamily_;
}

NTSTATUS WskDatagramSocket::Open(WskClient &client, USHORT addressFamily) noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (addressFamily != AF_INET && addressFamily != AF_INET6)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!WskClientIsInitialized(&client))
    {
        return STATUS_DEVICE_NOT_READY;
    }

    addressFamily_ = addressFamily;
#if defined(WKNET_USER_MODE_TEST)
    const NTSTATUS status = TestOpen(this);
    if (!NT_SUCCESS(status))
    {
        addressFamily_ = AF_UNSPEC;
        return status;
    }
    socket_ = this;
#else
    const WSK_PROVIDER_DISPATCH *provider = client.ProviderDispatch();
    if (provider == nullptr || provider->WskSocket == nullptr || client.ProviderClient() == nullptr)
    {
        addressFamily_ = AF_UNSPEC;
        return STATUS_DEVICE_NOT_READY;
    }

    WskSyncIrpContext *context = nullptr;
    NTSTATUS status = WskSyncAllocateIrp(&context);
    if (!NT_SUCCESS(status))
    {
        addressFamily_ = AF_UNSPEC;
        return status;
    }

    status = provider->WskSocket(client.ProviderClient(), static_cast<ADDRESS_FAMILY>(addressFamily_), SOCK_DGRAM,
                                 IPPROTO_UDP, WSK_FLAG_DATAGRAM_SOCKET, nullptr, nullptr, nullptr, nullptr, nullptr,
                                 context->Irp);
    SIZE_T information = 0;
    status = CompleteSynchronousWskRequest(status, context, &information);
    if (!NT_SUCCESS(status) || information == 0)
    {
        addressFamily_ = AF_UNSPEC;
        return NT_SUCCESS(status) ? STATUS_INVALID_DEVICE_STATE : status;
    }

    socket_ = reinterpret_cast<PWSK_SOCKET>(information);
    dispatch_ = static_cast<const WSK_PROVIDER_DATAGRAM_DISPATCH *>(socket_->Dispatch);
    WskSyncTrackSocketOpened(socket_);
    if (dispatch_ == nullptr || dispatch_->WskBind == nullptr || dispatch_->WskSendTo == nullptr ||
        dispatch_->WskReceiveFrom == nullptr || dispatch_->Basic.WskCloseSocket == nullptr)
    {
        const NTSTATUS closeStatus = CloseNativeSocket();
        UNREFERENCED_PARAMETER(closeStatus);
        addressFamily_ = AF_UNSPEC;
        return STATUS_INVALID_DEVICE_STATE;
    }
#endif
    endpointState_ = WskDatagramEndpointState::Created;
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocket::Bind(const SOCKADDR *localAddress) noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!AddressMatchesFamily(localAddress))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (endpointState_ != WskDatagramEndpointState::Created)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

#if defined(WKNET_USER_MODE_TEST)
    const NTSTATUS status = TestBind();
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    CopyAddress(&localAddress_, localAddress, AddressLength());
#else
    WskSyncIrpContext *context = nullptr;
    NTSTATUS status = WskSyncAllocateIrp(&context);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = dispatch_->WskBind(socket_, const_cast<SOCKADDR *>(localAddress), 0, context->Irp);
    status = CompleteSynchronousWskRequest(status, context);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    CopyAddress(&localAddress_, localAddress, AddressLength());
    if (dispatch_->WskGetLocalAddress != nullptr)
    {
        context = nullptr;
        status = WskSyncAllocateIrp(&context);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        status = dispatch_->WskGetLocalAddress(socket_, reinterpret_cast<SOCKADDR *>(&localAddress_), context->Irp);
        status = CompleteSynchronousWskRequest(status, context);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
#endif
    hasLocalAddress_ = true;
    endpointState_ = WskDatagramEndpointState::Bound;
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocket::ConnectPeer(const SOCKADDR *remoteAddress) noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!AddressMatchesFamily(remoteAddress))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (endpointState_ != WskDatagramEndpointState::Created && endpointState_ != WskDatagramEndpointState::Bound)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (endpointState_ == WskDatagramEndpointState::Created)
    {
        MakeWildcardAddress(&bindScratchAddress_);
        const NTSTATUS bindStatus = Bind(reinterpret_cast<const SOCKADDR *>(&bindScratchAddress_));
        if (!NT_SUCCESS(bindStatus))
        {
            return bindStatus;
        }
    }

    CopyAddress(&remoteAddress_, remoteAddress, AddressLength());
    hasRemoteAddress_ = true;
    endpointState_ = WskDatagramEndpointState::Connected;
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocket::CompleteReceiveRecord(NTSTATUS status, SIZE_T information, ULONG remoteAddressLength,
                                                  ULONGLONG generation) noexcept
{
    WskDatagramReceiveNotification notification = nullptr;
    void *notificationContext = nullptr;
#if defined(WKNET_USER_MODE_TEST)
    {
        std::lock_guard<std::mutex> guard(stateLock_);
        if ((receiveState_ != WskDatagramReceiveState::Pending &&
             receiveState_ != WskDatagramReceiveState::CancelPending) ||
            generation != receiveGeneration_)
        {
            return STATUS_NOT_FOUND;
        }
        receiveStatus_ = status;
        receiveBytes_ = information;
        receiveRemoteAddressLength_ = remoteAddressLength;
        completedGeneration_ = generation;
        receiveState_ = WskDatagramReceiveState::Completed;
        receiveEventSignaled_ = true;
        notification = receiveNotification_;
        notificationContext = receiveNotificationContext_;
    }
    receiveEvent_.notify_all();
#else
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &oldIrql);
    if ((receiveState_ != WskDatagramReceiveState::Pending &&
         receiveState_ != WskDatagramReceiveState::CancelPending) ||
        generation != receiveGeneration_)
    {
        KeReleaseSpinLock(&stateLock_, oldIrql);
        return STATUS_NOT_FOUND;
    }
    receiveStatus_ = status;
    receiveBytes_ = information;
    receiveRemoteAddressLength_ = remoteAddressLength;
    completedGeneration_ = generation;
    receiveState_ = WskDatagramReceiveState::Completed;
    const bool releaseRundown = completionOwnsIoReference_;
    completionOwnsIoReference_ = false;
    notification = receiveNotification_;
    notificationContext = receiveNotificationContext_;
    KeReleaseSpinLock(&stateLock_, oldIrql);
    KeSetEvent(&receiveEvent_, IO_NO_INCREMENT, FALSE);
    if (releaseRundown)
    {
        ExReleaseRundownProtection(&ioRundown_);
    }
#endif
    if (notification != nullptr)
    {
        notification(notificationContext);
    }
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocket::SetReceiveNotification(WskDatagramReceiveNotification notification, void *context) noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
#if defined(WKNET_USER_MODE_TEST)
    std::lock_guard<std::mutex> guard(stateLock_);
#else
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &oldIrql);
#endif
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
#if !defined(WKNET_USER_MODE_TEST)
        KeReleaseSpinLock(&stateLock_, oldIrql);
#endif
        return STATUS_DEVICE_NOT_READY;
    }
    receiveNotification_ = notification;
    receiveNotificationContext_ = context;
#if !defined(WKNET_USER_MODE_TEST)
    KeReleaseSpinLock(&stateLock_, oldIrql);
#endif
    return STATUS_SUCCESS;
}

#if defined(WKNET_USER_MODE_TEST)
void WskDatagramSocket::TestCompleteReceive(const void *data, SIZE_T dataLength, const SOCKADDR_STORAGE &remoteAddress,
                                            ULONG remoteAddressLength, NTSTATUS status,
                                            bool dispatchCompletion) noexcept
{
    SIZE_T copied = 0;
    ULONGLONG generation = 0;
    {
        std::lock_guard<std::mutex> guard(stateLock_);
        generation = receiveGeneration_;
        if (NT_SUCCESS(status) && dataLength <= receiveCapacity_)
        {
            if (dataLength != 0 && data != nullptr)
            {
                RtlCopyMemory(receiveData_, data, dataLength);
            }
            copied = dataLength;
        }
        else if (NT_SUCCESS(status) && dataLength > receiveCapacity_)
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        receiveRemoteAddress_ = remoteAddress;
    }

    {
        std::lock_guard<std::mutex> guard(g_testProvider.Lock);
        ++g_testProvider.Statistics.CompletionCallbacks;
        g_testProvider.Statistics.CompletionThreadToken = CurrentTestThreadToken();
        if (dispatchCompletion)
        {
            ++g_testProvider.Statistics.DispatchCompletions;
        }
        if (g_testProvider.Statistics.OutstandingReceives > 0)
        {
            --g_testProvider.Statistics.OutstandingReceives;
        }
    }
    (void)CompleteReceiveRecord(status, copied, remoteAddressLength, generation);
}
#else
NTSTATUS WskDatagramSocket::ReceiveCompletionRoutine(PDEVICE_OBJECT deviceObject, PIRP irp, PVOID context) noexcept
{
    UNREFERENCED_PARAMETER(deviceObject);
    auto *socket = static_cast<WskDatagramSocket *>(context);
    if (socket != nullptr)
    {
        (void)socket->CompleteReceiveRecord(irp->IoStatus.Status, static_cast<SIZE_T>(irp->IoStatus.Information),
                                            socket->AddressLength(), socket->receiveGeneration_);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}
#endif

NTSTATUS WskDatagramSocket::StartReceive(void *data, SIZE_T length) noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (data == nullptr || length == 0 || length > WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES || length > MAXULONG)
    {
        return STATUS_INVALID_PARAMETER;
    }

#if defined(WKNET_USER_MODE_TEST)
    {
        std::lock_guard<std::mutex> guard(stateLock_);
        if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
        {
            return STATUS_DEVICE_NOT_READY;
        }
        if (endpointState_ != WskDatagramEndpointState::Bound && endpointState_ != WskDatagramEndpointState::Connected)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (receiveState_ != WskDatagramReceiveState::Idle)
        {
            return STATUS_DEVICE_BUSY;
        }
        receiveData_ = data;
        receiveCapacity_ = length;
        receiveStatus_ = STATUS_PENDING;
        receiveBytes_ = 0;
        receiveRemoteAddress_ = {};
        receiveRemoteAddressLength_ = 0;
        timeoutCancellation_ = false;
        ++receiveGeneration_;
        receiveState_ = WskDatagramReceiveState::Pending;
        receiveEventSignaled_ = false;
    }

    const NTSTATUS submitStatus = TestSubmitReceive(this);
    if (submitStatus == STATUS_PENDING || NT_SUCCESS(submitStatus))
    {
        return STATUS_SUCCESS;
    }

    {
        std::lock_guard<std::mutex> guard(stateLock_);
        receiveState_ = WskDatagramReceiveState::Idle;
        receiveData_ = nullptr;
        receiveCapacity_ = 0;
    }
    return submitStatus;
#else
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &oldIrql);
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        KeReleaseSpinLock(&stateLock_, oldIrql);
        return STATUS_DEVICE_NOT_READY;
    }
    if (endpointState_ != WskDatagramEndpointState::Bound && endpointState_ != WskDatagramEndpointState::Connected)
    {
        KeReleaseSpinLock(&stateLock_, oldIrql);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (receiveState_ != WskDatagramReceiveState::Idle)
    {
        KeReleaseSpinLock(&stateLock_, oldIrql);
        return STATUS_DEVICE_BUSY;
    }
    receiveData_ = data;
    receiveCapacity_ = length;
    receiveStatus_ = STATUS_PENDING;
    receiveBytes_ = 0;
    receiveRemoteAddress_ = {};
    receiveRemoteAddressLength_ = 0;
    timeoutCancellation_ = false;
    ++receiveGeneration_;
    receiveState_ = WskDatagramReceiveState::Pending;
    KeClearEvent(&receiveEvent_);
    KeReleaseSpinLock(&stateLock_, oldIrql);

    receiveMdl_ = IoAllocateMdl(data, static_cast<ULONG>(length), FALSE, FALSE, nullptr);
    if (receiveMdl_ == nullptr)
    {
        ReleaseReceiveResources();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(receiveMdl_);

    if (receiveIrp_ == nullptr)
    {
        receiveIrp_ = IoAllocateIrp(1, FALSE);
        if (receiveIrp_ == nullptr)
        {
            ReleaseReceiveResources();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        IoReuseIrp(receiveIrp_, STATUS_UNSUCCESSFUL);
    }

    if (ExAcquireRundownProtection(&ioRundown_) == FALSE)
    {
        ReleaseReceiveResources();
        return STATUS_DEVICE_NOT_READY;
    }
    completionOwnsIoReference_ = true;
    IoSetCompletionRoutine(receiveIrp_, ReceiveCompletionRoutine, this, TRUE, TRUE, TRUE);

    receiveBuffer_.Mdl = receiveMdl_;
    receiveBuffer_.Offset = 0;
    receiveBuffer_.Length = length;
    receiveControlLength_ = 0;
    receiveControlFlags_ = 0;
    const ULONGLONG generation = receiveGeneration_;
    NTSTATUS status =
        dispatch_->WskReceiveFrom(socket_, &receiveBuffer_, 0, reinterpret_cast<SOCKADDR *>(&receiveRemoteAddress_),
                                  &receiveControlLength_, nullptr, &receiveControlFlags_, receiveIrp_);
    if (status == STATUS_PENDING)
    {
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&stateLock_, &oldIrql);
    const bool alreadyCompleted = receiveState_ == WskDatagramReceiveState::Completed;
    KeReleaseSpinLock(&stateLock_, oldIrql);
    if (!alreadyCompleted && NT_SUCCESS(status))
    {
        status = CompleteReceiveRecord(status, static_cast<SIZE_T>(receiveIrp_->IoStatus.Information), AddressLength(),
                                       generation);
        return NT_SUCCESS(status) ? STATUS_SUCCESS : status;
    }
    if (alreadyCompleted)
    {
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&stateLock_, &oldIrql);
    const bool releaseRundown = completionOwnsIoReference_;
    completionOwnsIoReference_ = false;
    receiveState_ = WskDatagramReceiveState::Idle;
    receiveData_ = nullptr;
    receiveCapacity_ = 0;
    KeReleaseSpinLock(&stateLock_, oldIrql);
    if (releaseRundown)
    {
        ExReleaseRundownProtection(&ioRundown_);
    }
    if (receiveMdl_ != nullptr)
    {
        IoFreeMdl(receiveMdl_);
        receiveMdl_ = nullptr;
    }
    receiveBuffer_ = {};
    return status;
#endif
}

NTSTATUS WskDatagramSocket::CancelReceiveInternal(bool timeoutCancellation) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    {
        std::lock_guard<std::mutex> guard(stateLock_);
        if (receiveState_ == WskDatagramReceiveState::Idle)
        {
            return STATUS_NOT_FOUND;
        }
        if (receiveState_ != WskDatagramReceiveState::Pending)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        receiveState_ = WskDatagramReceiveState::CancelPending;
        timeoutCancellation_ = timeoutCancellation;
    }
    TestCancel(this);
#else
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &oldIrql);
    if (receiveState_ == WskDatagramReceiveState::Idle)
    {
        KeReleaseSpinLock(&stateLock_, oldIrql);
        return STATUS_NOT_FOUND;
    }
    if (receiveState_ != WskDatagramReceiveState::Pending)
    {
        KeReleaseSpinLock(&stateLock_, oldIrql);
        return STATUS_INVALID_DEVICE_STATE;
    }
    receiveState_ = WskDatagramReceiveState::CancelPending;
    timeoutCancellation_ = timeoutCancellation;
    PIRP irp = receiveIrp_;
    KeReleaseSpinLock(&stateLock_, oldIrql);
    if (irp != nullptr)
    {
        IoCancelIrp(irp);
    }
#endif
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocket::CancelReceive() noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    return CancelReceiveInternal(false);
}

void WskDatagramSocket::ReleaseReceiveResources() noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    std::lock_guard<std::mutex> guard(stateLock_);
    if (receiveData_ != nullptr)
    {
        std::lock_guard<std::mutex> providerGuard(g_testProvider.Lock);
        if (g_testProvider.Statistics.BufferReferences > 0)
        {
            --g_testProvider.Statistics.BufferReferences;
        }
    }
    receiveData_ = nullptr;
    receiveCapacity_ = 0;
    receiveState_ = WskDatagramReceiveState::Idle;
    receiveEventSignaled_ = false;
#else
    if (receiveMdl_ != nullptr)
    {
        IoFreeMdl(receiveMdl_);
        receiveMdl_ = nullptr;
    }
    receiveBuffer_ = {};
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &oldIrql);
    receiveData_ = nullptr;
    receiveCapacity_ = 0;
    receiveState_ = WskDatagramReceiveState::Idle;
    KeReleaseSpinLock(&stateLock_, oldIrql);
    KeClearEvent(&receiveEvent_);
#endif
}

NTSTATUS WskDatagramSocket::CompleteReceive(ULONG timeoutMilliseconds, WskDatagramReceiveResult *result) noexcept
{
    if (result != nullptr)
    {
        *result = {};
    }
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (result == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    bool timedOut = false;
#if defined(WKNET_USER_MODE_TEST)
    {
        std::unique_lock<std::mutex> lock(stateLock_);
        if (receiveState_ == WskDatagramReceiveState::Idle)
        {
            return STATUS_NOT_FOUND;
        }
        if (receiveState_ != WskDatagramReceiveState::Completed)
        {
            bool signaled = false;
            if (timeoutMilliseconds == MAXULONG)
            {
                receiveEvent_.wait(lock, [this]() noexcept { return receiveEventSignaled_; });
                signaled = true;
            }
            else
            {
                signaled = receiveEvent_.wait_for(lock, std::chrono::milliseconds(timeoutMilliseconds),
                                                  [this]() noexcept { return receiveEventSignaled_; });
            }
            if (!signaled)
            {
                timedOut = true;
            }
        }
    }
#else
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &oldIrql);
    if (receiveState_ == WskDatagramReceiveState::Idle)
    {
        KeReleaseSpinLock(&stateLock_, oldIrql);
        return STATUS_NOT_FOUND;
    }
    const bool completed = receiveState_ == WskDatagramReceiveState::Completed;
    KeReleaseSpinLock(&stateLock_, oldIrql);
    if (!completed)
    {
        LARGE_INTEGER timeout = {};
        timeout.QuadPart = -static_cast<LONGLONG>(timeoutMilliseconds) * 10000LL;
        const NTSTATUS waitStatus = KeWaitForSingleObject(&receiveEvent_, Executive, KernelMode, FALSE,
                                                          timeoutMilliseconds == MAXULONG ? nullptr : &timeout);
        timedOut = waitStatus == STATUS_TIMEOUT;
        if (!timedOut && waitStatus != STATUS_SUCCESS)
        {
            return waitStatus;
        }
    }
#endif

    if (timedOut)
    {
        const NTSTATUS cancelStatus = CancelReceiveInternal(true);
        if (!NT_SUCCESS(cancelStatus) && cancelStatus != STATUS_INVALID_DEVICE_STATE)
        {
            return cancelStatus;
        }
#if defined(WKNET_USER_MODE_TEST)
        std::unique_lock<std::mutex> lock(stateLock_);
        receiveEvent_.wait(lock, [this]() noexcept { return receiveEventSignaled_; });
#else
        const NTSTATUS drainStatus = KeWaitForSingleObject(&receiveEvent_, Executive, KernelMode, FALSE, nullptr);
        if (drainStatus != STATUS_SUCCESS)
        {
            return drainStatus;
        }
#endif
    }

#if defined(WKNET_USER_MODE_TEST)
    {
        std::lock_guard<std::mutex> guard(stateLock_);
        result->Status = timeoutCancellation_ ? STATUS_IO_TIMEOUT : receiveStatus_;
        result->BytesReceived = receiveBytes_;
        result->RemoteAddress = receiveRemoteAddress_;
        result->RemoteAddressLength = receiveRemoteAddressLength_;
        result->Generation = completedGeneration_;
    }
    {
        std::lock_guard<std::mutex> guard(g_testProvider.Lock);
        ++g_testProvider.Statistics.PassiveConsumers;
        g_testProvider.Statistics.PassiveConsumerThreadToken = CurrentTestThreadToken();
    }
#else
    KIRQL resultIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &resultIrql);
    result->Status = timeoutCancellation_ ? STATUS_IO_TIMEOUT : receiveStatus_;
    result->BytesReceived = receiveBytes_;
    result->RemoteAddress = receiveRemoteAddress_;
    result->RemoteAddressLength = receiveRemoteAddressLength_;
    result->Generation = completedGeneration_;
    KeReleaseSpinLock(&stateLock_, resultIrql);
#endif

    if (NT_SUCCESS(result->Status))
    {
        if (result->BytesReceived > receiveCapacity_ || result->RemoteAddressLength > sizeof(SOCKADDR_STORAGE) ||
            result->RemoteAddressLength != AddressLengthForFamily(result->RemoteAddress.ss_family))
        {
            result->Status = STATUS_INVALID_NETWORK_RESPONSE;
        }
    }

    const NTSTATUS status = result->Status;
    ReleaseReceiveResources();
    if (status == STATUS_CANCELLED)
    {
        const TraceCorrelation correlation = {0, ConnectionId(), 0};
        WKNET_TRACE_CORRELATED(::wknet::ComponentNet, ::wknet::TraceLevel::Verbose, &correlation,
                               "net.datagram.receive.cancelled");
    }
    else if (!NT_SUCCESS(status))
    {
        const TraceCorrelation correlation = {0, ConnectionId(), 0};
        WKNET_TRACE_CORRELATED(::wknet::ComponentNet, ::wknet::TraceLevel::Error, &correlation,
                               "net.datagram.receive.failed status=0x%08X", static_cast<ULONG>(status));
    }
    return status;
}

NTSTATUS WskDatagramSocket::Send(const void *data, SIZE_T length, SIZE_T *bytesSent) noexcept
{
    if (bytesSent != nullptr)
    {
        *bytesSent = 0;
    }
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (endpointState_ != WskDatagramEndpointState::Connected || !hasRemoteAddress_)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    return SendTo(data, length, reinterpret_cast<const SOCKADDR *>(&remoteAddress_), bytesSent);
}

NTSTATUS WskDatagramSocket::SendTo(const void *data, SIZE_T length, const SOCKADDR *remoteAddress,
                                   SIZE_T *bytesSent) noexcept
{
    if (bytesSent != nullptr)
    {
        *bytesSent = 0;
    }
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (data == nullptr || length == 0 || length > WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES ||
        !AddressMatchesFamily(remoteAddress))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (endpointState_ != WskDatagramEndpointState::Bound && endpointState_ != WskDatagramEndpointState::Connected)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS status = STATUS_SUCCESS;
#if defined(WKNET_USER_MODE_TEST)
    status = TestSend(length, bytesSent);
#else
    if (ExAcquireRundownProtection(&ioRundown_) == FALSE)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    status = sendScratch_.EnsureCapacity(WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES);
    if (NT_SUCCESS(status))
    {
        status = sendScratch_.SetData(data, length);
    }
    if (NT_SUCCESS(status))
    {
        WskSyncIrpContext *context = nullptr;
        status = WskSyncAllocateIrp(&context);
        if (NT_SUCCESS(status))
        {
            const NTSTATUS requestStatus = dispatch_->WskSendTo(
                socket_, sendScratch_.WskBuf(), 0, const_cast<SOCKADDR *>(remoteAddress), 0, nullptr, context->Irp);
            SIZE_T information = 0;
            status = CompleteSynchronousWskRequest(requestStatus, context, &information);
            if (NT_SUCCESS(status) && bytesSent != nullptr)
            {
                *bytesSent = information;
            }
        }
    }
    ExReleaseRundownProtection(&ioRundown_);
#endif
    if (!NT_SUCCESS(status))
    {
        const TraceCorrelation correlation = {0, ConnectionId(), 0};
        WKNET_TRACE_CORRELATED(::wknet::ComponentNet, ::wknet::TraceLevel::Error, &correlation,
                               "net.datagram.send.failed status=0x%08X bytes=%Iu", static_cast<ULONG>(status), length);
    }
    return status;
}

NTSTATUS WskDatagramSocket::GetLocalAddress(SOCKADDR_STORAGE *localAddress) const noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (localAddress == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!hasLocalAddress_)
    {
        return STATUS_NOT_FOUND;
    }
    *localAddress = localAddress_;
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocket::GetRemoteAddress(SOCKADDR_STORAGE *remoteAddress) const noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (remoteAddress == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing || endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!hasRemoteAddress_)
    {
        return STATUS_NOT_FOUND;
    }
    *remoteAddress = remoteAddress_;
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocket::CloseNativeSocket() noexcept
{
    PWSK_SOCKET socket = socket_;
    if (socket == nullptr)
    {
        return STATUS_SUCCESS;
    }
#if defined(WKNET_USER_MODE_TEST)
    socket_ = nullptr;
    TestClose(this);
    return STATUS_SUCCESS;
#else
    const WSK_PROVIDER_DATAGRAM_DISPATCH *dispatch = dispatch_;
    if (dispatch == nullptr || dispatch->Basic.WskCloseSocket == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    WskSyncIrpContext *context = nullptr;
    NTSTATUS status = WskSyncAllocateIrp(&context);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    socket_ = nullptr;
    dispatch_ = nullptr;
    WskSyncTrackSocketCloseStarted(socket);
    status = dispatch->Basic.WskCloseSocket(socket, context->Irp);
    status = CompleteSynchronousWskRequest(status, context);
    WskSyncTrackSocketClosed(socket, status);
    return status;
#endif
}

NTSTATUS WskDatagramSocket::Close() noexcept
{
    if (!IsPassiveLevel())
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (endpointState_ == WskDatagramEndpointState::Closed)
    {
        return STATUS_SUCCESS;
    }
    if (endpointState_ == WskDatagramEndpointState::Closing)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    const TraceCorrelation correlation = {0, ConnectionId(), 0};
    WKNET_TRACE_CORRELATED(::wknet::ComponentNet, ::wknet::TraceLevel::Info, &correlation,
                           "net.datagram.close_started");
    endpointState_ = WskDatagramEndpointState::Closing;

    bool waitForReceive = false;
#if defined(WKNET_USER_MODE_TEST)
    {
        std::lock_guard<std::mutex> guard(stateLock_);
        waitForReceive = receiveState_ == WskDatagramReceiveState::Pending ||
                         receiveState_ == WskDatagramReceiveState::CancelPending;
    }
#else
    KIRQL oldIrql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&stateLock_, &oldIrql);
    waitForReceive =
        receiveState_ == WskDatagramReceiveState::Pending || receiveState_ == WskDatagramReceiveState::CancelPending;
    KeReleaseSpinLock(&stateLock_, oldIrql);
#endif
    if (waitForReceive)
    {
        const NTSTATUS cancelStatus = CancelReceiveInternal(false);
        if (!NT_SUCCESS(cancelStatus) && cancelStatus != STATUS_INVALID_DEVICE_STATE)
        {
            return cancelStatus;
        }
#if defined(WKNET_USER_MODE_TEST)
        std::unique_lock<std::mutex> lock(stateLock_);
        receiveEvent_.wait(lock, [this]() noexcept { return receiveEventSignaled_; });
#else
        const NTSTATUS waitStatus = KeWaitForSingleObject(&receiveEvent_, Executive, KernelMode, FALSE, nullptr);
        if (waitStatus != STATUS_SUCCESS)
        {
            return waitStatus;
        }
#endif
    }
#if !defined(WKNET_USER_MODE_TEST)
    ExWaitForRundownProtectionRelease(&ioRundown_);
#endif
    ReleaseReceiveResources();

    const NTSTATUS closeStatus = CloseNativeSocket();
    RtlSecureZeroMemory(&localAddress_, sizeof(localAddress_));
    RtlSecureZeroMemory(&remoteAddress_, sizeof(remoteAddress_));
    RtlSecureZeroMemory(&bindScratchAddress_, sizeof(bindScratchAddress_));
    RtlSecureZeroMemory(&receiveRemoteAddress_, sizeof(receiveRemoteAddress_));
    hasLocalAddress_ = false;
    hasRemoteAddress_ = false;
    endpointState_ = WskDatagramEndpointState::Closed;
    WKNET_TRACE_CORRELATED(::wknet::ComponentNet, ::wknet::TraceLevel::Info, &correlation,
                           "net.datagram.close_completed status=0x%08X", static_cast<ULONG>(closeStatus));
    return closeStatus;
}

void WskDatagramSocket::SetConnectionId(ULONGLONG connectionId) noexcept
{
    connectionId_ = connectionId;
}

ULONGLONG WskDatagramSocket::ConnectionId() const noexcept
{
    return connectionId_;
}

NTSTATUS WskDatagramSocketCreate(WskClient *client, USHORT addressFamily, WskDatagramSocket **socket) noexcept
{
    if (socket != nullptr)
    {
        *socket = nullptr;
    }
    if (client == nullptr || socket == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
#if defined(WKNET_USER_MODE_TEST)
    {
        std::lock_guard<std::mutex> guard(g_testProvider.Lock);
        ++g_testProvider.Statistics.AllocationAttempts;
        if (g_testProvider.FailAllocation)
        {
            g_testProvider.FailAllocation = false;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
#endif
    auto *created = AllocateNonPagedObject<WskDatagramSocket>();
    if (created == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    const NTSTATUS status = created->Open(*client, addressFamily);
    if (!NT_SUCCESS(status))
    {
        FreeNonPagedObject(created);
        return status;
    }
    created->SetConnectionId(::wknet::rtl::TraceAllocateCorrelationId());
    *socket = created;
    const TraceCorrelation correlation = {0, created->ConnectionId(), 0};
    WKNET_TRACE_CORRELATED(::wknet::ComponentNet, ::wknet::TraceLevel::Info, &correlation,
                           "net.datagram.opened family=%u", static_cast<ULONG>(addressFamily));
    return STATUS_SUCCESS;
}

NTSTATUS WskDatagramSocketBind(WskDatagramSocket *socket, const SOCKADDR *localAddress) noexcept
{
    return socket != nullptr ? socket->Bind(localAddress) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketConnectPeer(WskDatagramSocket *socket, const SOCKADDR *remoteAddress) noexcept
{
    return socket != nullptr ? socket->ConnectPeer(remoteAddress) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketStartReceive(WskDatagramSocket *socket, void *data, SIZE_T length) noexcept
{
    return socket != nullptr ? socket->StartReceive(data, length) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketSetReceiveNotification(WskDatagramSocket *socket, WskDatagramReceiveNotification notification,
                                                 void *context) noexcept
{
    return socket != nullptr ? socket->SetReceiveNotification(notification, context) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketCancelReceive(WskDatagramSocket *socket) noexcept
{
    return socket != nullptr ? socket->CancelReceive() : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketCompleteReceive(WskDatagramSocket *socket, ULONG timeoutMilliseconds,
                                          WskDatagramReceiveResult *result) noexcept
{
    return socket != nullptr ? socket->CompleteReceive(timeoutMilliseconds, result) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketSend(WskDatagramSocket *socket, const void *data, SIZE_T length, SIZE_T *bytesSent) noexcept
{
    return socket != nullptr ? socket->Send(data, length, bytesSent) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketSendTo(WskDatagramSocket *socket, const void *data, SIZE_T length,
                                 const SOCKADDR *remoteAddress, SIZE_T *bytesSent) noexcept
{
    return socket != nullptr ? socket->SendTo(data, length, remoteAddress, bytesSent) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketGetLocalAddress(const WskDatagramSocket *socket, SOCKADDR_STORAGE *localAddress) noexcept
{
    return socket != nullptr ? socket->GetLocalAddress(localAddress) : STATUS_INVALID_PARAMETER;
}

NTSTATUS WskDatagramSocketGetRemoteAddress(const WskDatagramSocket *socket, SOCKADDR_STORAGE *remoteAddress) noexcept
{
    return socket != nullptr ? socket->GetRemoteAddress(remoteAddress) : STATUS_INVALID_PARAMETER;
}

void WskDatagramSocketSetConnectionId(WskDatagramSocket *socket, ULONGLONG connectionId) noexcept
{
    if (socket != nullptr)
    {
        socket->SetConnectionId(connectionId);
    }
}

ULONGLONG WskDatagramSocketConnectionId(const WskDatagramSocket *socket) noexcept
{
    return socket != nullptr ? socket->ConnectionId() : 0;
}

NTSTATUS WskDatagramSocketClose(WskDatagramSocket *socket) noexcept
{
    return socket != nullptr ? socket->Close() : STATUS_SUCCESS;
}

void WskDatagramSocketDestroy(WskDatagramSocket *socket) noexcept
{
    if (socket != nullptr)
    {
        const NTSTATUS status = socket->Close();
        UNREFERENCED_PARAMETER(status);
        FreeNonPagedObject(socket);
    }
}
} // namespace wknet::net
