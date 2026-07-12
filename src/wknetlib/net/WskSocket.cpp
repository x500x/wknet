#include "net/WskSocket.h"

#if !defined(WKNET_USER_MODE_TEST)
#include "WskSync.h"

#include <ws2ipdef.h>
#endif

namespace wknet
{
namespace net
{
#if defined(WKNET_USER_MODE_TEST)
    namespace
    {
        WskTestSocketProvider g_testSocketProvider = {};
        void* g_testSocketProviderContext = nullptr;

        bool IsCancellationRequested(_In_opt_ const WskCancellationToken* cancellation) noexcept
        {
            return cancellation != nullptr &&
                cancellation->IsCancellationRequested != nullptr &&
                cancellation->IsCancellationRequested(cancellation->Context);
        }

        bool IsCancellationStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_CANCELLED || status == STATUS_IO_TIMEOUT || status == STATUS_TIMEOUT;
        }
    }

    void WskTestSetSocketProvider(const WskTestSocketProvider* provider, void* context) noexcept
    {
        if (provider == nullptr) {
            g_testSocketProvider = {};
            g_testSocketProviderContext = nullptr;
            return;
        }

        g_testSocketProvider = *provider;
        g_testSocketProviderContext = context;
    }

    WskSocket::~WskSocket() noexcept
    {
        if (socket_ != nullptr || ownershipState_ != OwnershipState::Closed) {
            const NTSTATUS status = Close();
            UNREFERENCED_PARAMETER(status);
        }
    }

    NTSTATUS WskSocket::CloseOwnedSocket(ULONG timeoutMilliseconds) noexcept
    {
        UNREFERENCED_PARAMETER(timeoutMilliseconds);

        PWSK_SOCKET socketToClose = socket_;
        socket_ = nullptr;
        dispatch_ = nullptr;
        ownershipState_ = OwnershipState::Closed;

        if (socketToClose == nullptr) {
            closeIssued_ = 0;
            return STATUS_SUCCESS;
        }

        ioRundownReady_ = false;

        if (closeIssued_ == 0) {
            closeIssued_ = 1;
            if (g_testSocketProvider.Close != nullptr) {
                g_testSocketProvider.Close(g_testSocketProviderContext, socketToClose);
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS WskSocket::CloseAfterCancelledOperation(bool completionOwnedCleanup) noexcept
    {
        UNREFERENCED_PARAMETER(completionOwnedCleanup);
        return CloseOwnedSocket(WskCloseTimeoutMilliseconds);
    }

    void WskSocket::ReinitializeIoRundown() noexcept
    {
        ioRundownReady_ = true;
    }

    NTSTATUS WskSocket::Connect(
        WskClient& client,
        const SOCKADDR* remoteAddress,
        const SOCKADDR* localAddress,
        const WskCancellationToken* cancellation) noexcept
    {
        UNREFERENCED_PARAMETER(client);

        if (socket_ != nullptr || remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsCancellationRequested(cancellation)) {
            return STATUS_CANCELLED;
        }

        if (g_testSocketProvider.Connect == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }

        PWSK_SOCKET connectedSocket = nullptr;
        NTSTATUS status = g_testSocketProvider.Connect(
            g_testSocketProviderContext,
            remoteAddress,
            localAddress,
            cancellation,
            &connectedSocket);

        if (NT_SUCCESS(status)) {
            if (connectedSocket == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            socket_ = connectedSocket;
            ReinitializeIoRundown();
            ownershipState_ = OwnershipState::Active;
            closeIssued_ = 0;
            return STATUS_SUCCESS;
        }

        if (connectedSocket != nullptr && g_testSocketProvider.Close != nullptr) {
            g_testSocketProvider.Close(g_testSocketProviderContext, connectedSocket);
        }

        ownershipState_ = OwnershipState::Closed;
        return status;
    }

    NTSTATUS WskSocket::Send(
        WskBuffer& buffer,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags,
        const WskCancellationToken* cancellation) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }

        if (socket_ == nullptr || ownershipState_ != OwnershipState::Active) {
            return STATUS_INVALID_CONNECTION;
        }
        if (!ioRundownReady_) {
            return STATUS_DEVICE_NOT_READY;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        if (buffer.Data() == nullptr || length > buffer.Capacity()) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsCancellationRequested(cancellation)) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(false);
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_CANCELLED;
        }

        if (g_testSocketProvider.Send == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }

        NTSTATUS status = g_testSocketProvider.Send(
            g_testSocketProviderContext,
            socket_,
            buffer.Data(),
            length,
            bytesSent,
            flags,
            cancellation);
        if (IsCancellationStatus(status)) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(false);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        return status;
    }

    NTSTATUS WskSocket::Send(
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags,
        const WskCancellationToken* cancellation) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = sendScratch_.EnsureCapacity(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = sendScratch_.SetData(data, length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return Send(sendScratch_, length, bytesSent, flags, cancellation);
    }

    NTSTATUS WskSocket::Receive(
        WskBuffer& buffer,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        const WskCancellationToken* cancellation) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (socket_ == nullptr || ownershipState_ != OwnershipState::Active) {
            return STATUS_INVALID_CONNECTION;
        }
        if (!ioRundownReady_) {
            return STATUS_DEVICE_NOT_READY;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        NTSTATUS status = buffer.EnsureCapacity(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (IsCancellationRequested(cancellation)) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(false);
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_CANCELLED;
        }

        if (g_testSocketProvider.Receive == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }

        status = g_testSocketProvider.Receive(
            g_testSocketProviderContext,
            socket_,
            buffer.Data(),
            length,
            bytesReceived,
            flags,
            timeoutMilliseconds,
            cancellation);
        if (IsCancellationStatus(status)) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(false);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        return status;
    }

    NTSTATUS WskSocket::Receive(
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        const WskCancellationToken* cancellation) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        WskBuffer buffer = {};
        NTSTATUS status = buffer.Allocate(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T received = 0;
        status = Receive(buffer, length, &received, flags, timeoutMilliseconds, cancellation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (received > length) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (received != 0) {
            status = buffer.CopyTo(data, received);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (bytesReceived != nullptr) {
            *bytesReceived = received;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS WskSocket::Disconnect(ULONG flags) noexcept
    {
        if (socket_ == nullptr || ownershipState_ != OwnershipState::Active) {
            return STATUS_INVALID_CONNECTION;
        }

        if (g_testSocketProvider.Disconnect == nullptr) {
            return STATUS_SUCCESS;
        }

        return g_testSocketProvider.Disconnect(g_testSocketProviderContext, socket_, flags);
    }

    NTSTATUS WskSocket::Close() noexcept
    {
        return CloseOwnedSocket(WskCloseTimeoutMilliseconds);
    }

    bool WskSocket::IsConnected() const noexcept
    {
        return socket_ != nullptr && ownershipState_ == OwnershipState::Active;
    }

    PWSK_SOCKET WskSocket::NativeSocket() const noexcept
    {
        return socket_;
    }
#else
    namespace
    {
        void DeleteWskBuffer(_In_opt_ void* context) noexcept
        {
            auto* buffer = static_cast<WskBuffer*>(context);
            WskSyncFreeBufferObject(buffer);
        }

        struct WskSocketConnectStorage final
        {
            SOCKADDR_STORAGE LocalAddress = {};
            SOCKADDR_STORAGE RemoteAddress = {};
        };

        void DeleteConnectStorage(_In_opt_ void* context) noexcept
        {
            auto* storage = static_cast<WskSocketConnectStorage*>(context);
            FreeNonPagedObject(storage);
        }

        _Must_inspect_result_
        SIZE_T SocketAddressLength(_In_ const SOCKADDR* address) noexcept
        {
            if (address == nullptr) {
                return 0;
            }

            switch (address->sa_family) {
            case AF_INET:
                return sizeof(SOCKADDR_IN);
            case AF_INET6:
                return sizeof(SOCKADDR_IN6);
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        NTSTATUS CopySocketAddress(
            _In_ const SOCKADDR* source,
            _Out_ SOCKADDR_STORAGE* destination) noexcept
        {
            const SIZE_T addressLength = SocketAddressLength(source);
            if (addressLength == 0 || destination == nullptr || addressLength > sizeof(*destination)) {
                return STATUS_INVALID_PARAMETER;
            }

            RtlZeroMemory(destination, sizeof(*destination));
            RtlCopyMemory(destination, source, addressLength);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AllocateOwnedBuffer(
            SIZE_T length,
            _Inout_ WskSyncIrpContext* context,
            _Outptr_ WskBuffer** buffer) noexcept
        {
            if (context == nullptr || buffer == nullptr || length == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            *buffer = nullptr;

            auto* owned = WskSyncAllocateBufferObject();
            if (owned == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = owned->Allocate(length);
            if (!NT_SUCCESS(status)) {
                WskSyncFreeBufferObject(owned);
                return status;
            }

            context->CleanupRoutine = DeleteWskBuffer;
            context->CleanupContext = owned;
            *buffer = owned;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS BuildWildcardLocalAddress(
            _In_ const SOCKADDR* remoteAddress,
            _Out_ SOCKADDR_STORAGE* storage,
            _Outptr_ SOCKADDR** localAddress) noexcept
        {
            if (remoteAddress == nullptr || storage == nullptr || localAddress == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            RtlZeroMemory(storage, sizeof(*storage));

            switch (remoteAddress->sa_family) {
            case AF_INET:
            {
                auto* ipv4 = reinterpret_cast<SOCKADDR_IN*>(storage);
                ipv4->sin_family = AF_INET;
                *localAddress = reinterpret_cast<SOCKADDR*>(ipv4);
                return STATUS_SUCCESS;
            }
            case AF_INET6:
            {
                auto* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(storage);
                ipv6->sin6_family = AF_INET6;
                *localAddress = reinterpret_cast<SOCKADDR*>(ipv6);
                return STATUS_SUCCESS;
            }
            default:
                *localAddress = nullptr;
                return STATUS_NOT_SUPPORTED;
            }
        }

        bool CanBlockNow() noexcept
        {
            return KeGetCurrentIrql() == PASSIVE_LEVEL;
        }

        bool IsConnectionTerminalStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_CONNECTION_DISCONNECTED ||
                status == STATUS_CONNECTION_RESET ||
                status == STATUS_CONNECTION_ABORTED ||
                status == STATUS_DEVICE_NOT_CONNECTED;
        }

        void CloseNativeSocketIfPresent(_In_opt_ PWSK_SOCKET socket) noexcept
        {
            if (socket == nullptr || socket->Dispatch == nullptr) {
                return;
            }

            const auto* dispatch = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket->Dispatch);
            if (dispatch->Basic.WskCloseSocket == nullptr) {
                return;
            }

            WskSyncIrpContext* context = nullptr;
            NTSTATUS status = WskSyncAllocateIrp(&context);
            if (!NT_SUCCESS(status)) {
                return;
            }

        status = dispatch->Basic.WskCloseSocket(socket, context->Irp);
        WskSyncTrackSocketCloseStarted(socket);
        status = WskSyncCompleteIrp(status, context, 0xffffffffUL, nullptr);
        WskSyncTrackSocketClosed(socket, status);
        UNREFERENCED_PARAMETER(status);
        WskSyncReleaseContext(context);
        }

        void CloseNativeSocketDetachedIfPresent(_In_opt_ PWSK_SOCKET socket) noexcept
        {
            if (socket == nullptr || socket->Dispatch == nullptr) {
                return;
            }

            const auto* dispatch = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket->Dispatch);
            if (dispatch->Basic.WskCloseSocket == nullptr) {
                return;
            }

            WskSyncIrpContext* context = nullptr;
            NTSTATUS status = WskSyncAllocateIrp(&context);
            if (!NT_SUCCESS(status)) {
                WKNET_DBG_PRINT("Unable to allocate detached WSK close IRP: 0x%08X\r\n",
                    static_cast<ULONG>(status));
                return;
            }

            status = dispatch->Basic.WskCloseSocket(socket, context->Irp);
            WskSyncDetachSubmittedIrp(status, context);
        }

        void CloseLateConnectedSocket(
            _In_opt_ void* context,
            NTSTATUS status,
            SIZE_T information) noexcept
        {
            UNREFERENCED_PARAMETER(context);
            UNREFERENCED_PARAMETER(status);

            if (information == 0) {
                return;
            }

            CloseNativeSocketDetachedIfPresent(reinterpret_cast<PWSK_SOCKET>(information));
        }
    }

    WskSocket::WskSocket() noexcept
    {
        ExInitializeRundownProtection(&ioRundown_);
    }

    WskSocket::~WskSocket() noexcept
    {
        if (socket_ != nullptr || ownershipState_ != OwnershipState::Closed) {
            const NTSTATUS status = Close();
            UNREFERENCED_PARAMETER(status);
        }
        ReleaseReusableIrps();
    }

    bool WskSocket::AcquireIoRundown() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return closeIssued_ == 0;
#else
        return ExAcquireRundownProtection(&ioRundown_) != FALSE;
#endif
    }

    void WskSocket::ReleaseIoRundown() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        ExReleaseRundownProtection(&ioRundown_);
#endif
    }

    void WskSocket::WaitForIoRundown() noexcept
    {
#if !defined(WKNET_USER_MODE_TEST)
        ExWaitForRundownProtectionRelease(&ioRundown_);
#endif
        ioRundownReady_ = false;
    }

    void WskSocket::ReinitializeIoRundown() noexcept
    {
        if (ioRundownReady_) {
            return;
        }

#if !defined(WKNET_USER_MODE_TEST)
        ExReInitializeRundownProtection(&ioRundown_);
#endif
        ioRundownReady_ = true;
    }

    NTSTATUS WskSocket::PrepareReusableIrp(
        PIRP* reusableIrp,
        WskSyncIrpContext** context) noexcept
    {
        if (reusableIrp == nullptr || context == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *context = nullptr;
        if (*reusableIrp == nullptr) {
            *reusableIrp = IoAllocateIrp(1, FALSE);
            if (*reusableIrp == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        else {
            IoReuseIrp(*reusableIrp, STATUS_UNSUCCESSFUL);
        }

        return WskSyncInitializeIrpContext(*reusableIrp, true, context);
    }

    void WskSocket::AbandonReusableIrp(PIRP* reusableIrp) noexcept
    {
        if (reusableIrp != nullptr) {
            *reusableIrp = nullptr;
        }
    }

    void WskSocket::ReleaseReusableIrps() noexcept
    {
        if (sendIrp_ != nullptr) {
            IoFreeIrp(sendIrp_);
            sendIrp_ = nullptr;
        }
        if (receiveIrp_ != nullptr) {
            IoFreeIrp(receiveIrp_);
            receiveIrp_ = nullptr;
        }
    }

    NTSTATUS WskSocket::CloseOwnedSocket(ULONG timeoutMilliseconds) noexcept
    {
        UNREFERENCED_PARAMETER(timeoutMilliseconds);

        if (socket_ == nullptr) {
            dispatch_ = nullptr;
            ReleaseReusableIrps();
            if (ownershipState_ != OwnershipState::CompletionOwnedCleanup) {
                ownershipState_ = OwnershipState::Closed;
                InterlockedExchange(&closeIssued_, 0);
            }
            return STATUS_SUCCESS;
        }

        if (dispatch_ == nullptr || dispatch_->Basic.WskCloseSocket == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        WskSyncIrpContext* context = nullptr;
        NTSTATUS status = WskSyncAllocateIrp(&context);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (InterlockedCompareExchange(&closeIssued_, 1, 0) != 0) {
            WskSyncReleaseUnsubmittedContext(context);
            return STATUS_SUCCESS;
        }

        WaitForIoRundown();

        PWSK_SOCKET socketToClose = socket_;
        const auto* dispatch = dispatch_;
        ownershipState_ = OwnershipState::ClosePending;

        status = dispatch->Basic.WskCloseSocket(socketToClose, context->Irp);
        socket_ = nullptr;
        dispatch_ = nullptr;
        WskSyncTrackSocketCloseStarted(socketToClose);

        WskSyncCompletionResult completion = {};
        status = WskSyncCompleteIrp(
            status,
            context,
            0xffffffffUL,
            nullptr,
            nullptr,
            &completion);

        ownershipState_ = completion.CompletionOwnedCleanup
            ? OwnershipState::CompletionOwnedCleanup
            : OwnershipState::Closed;

        WskSyncTrackSocketClosed(socketToClose, status);
        ReleaseReusableIrps();
        WskSyncReleaseContext(context);
        return status;
    }

    NTSTATUS WskSocket::CloseAfterCancelledOperation(bool completionOwnedCleanup) noexcept
    {
        if (socket_ == nullptr) {
            dispatch_ = nullptr;
            ownershipState_ = completionOwnedCleanup
                ? OwnershipState::CompletionOwnedCleanup
                : OwnershipState::Closed;
            return STATUS_SUCCESS;
        }

        ownershipState_ = completionOwnedCleanup
            ? OwnershipState::CompletionOwnedCleanup
            : OwnershipState::CancelPending;

        return CloseOwnedSocket(WskCloseTimeoutMilliseconds);
    }

    NTSTATUS WskSocket::Connect(
        WskClient& client,
        const SOCKADDR* remoteAddress,
        const SOCKADDR* localAddress,
        const WskCancellationToken* cancellation) noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (socket_ != nullptr || remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        auto* providerClient = client.ProviderClient();
        const auto* providerDispatch = client.ProviderDispatch();

        if (providerClient == nullptr ||
            providerDispatch == nullptr ||
            providerDispatch->WskSocketConnect == nullptr) {
            return STATUS_DEVICE_NOT_READY;
        }

        WskSyncIrpContext* context = nullptr;
        NTSTATUS status = WskSyncAllocateIrp(&context);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* addressStorage = AllocateNonPagedObject<WskSocketConnectStorage>();
        if (addressStorage == nullptr) {
            WskSyncReleaseUnsubmittedContext(context);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        context->CleanupRoutine = DeleteConnectStorage;
        context->CleanupContext = addressStorage;
        context->CompletionCleanupRoutine = CloseLateConnectedSocket;

        status = CopySocketAddress(remoteAddress, &addressStorage->RemoteAddress);
        if (!NT_SUCCESS(status)) {
            WskSyncReleaseUnsubmittedContext(context);
            return status;
        }

        SOCKADDR* localAddressForConnect = nullptr;
        if (localAddress != nullptr) {
            status = CopySocketAddress(localAddress, &addressStorage->LocalAddress);
            if (!NT_SUCCESS(status)) {
                WskSyncReleaseUnsubmittedContext(context);
                return status;
            }
            localAddressForConnect = reinterpret_cast<SOCKADDR*>(&addressStorage->LocalAddress);
        }
        else {
            status = BuildWildcardLocalAddress(
                reinterpret_cast<const SOCKADDR*>(&addressStorage->RemoteAddress),
                &addressStorage->LocalAddress,
                &localAddressForConnect);

            if (!NT_SUCCESS(status)) {
                WskSyncReleaseUnsubmittedContext(context);
                return status;
            }
        }

        SIZE_T information = 0;
        WskSyncCompletionResult completion = {};
        status = providerDispatch->WskSocketConnect(
            providerClient,
            SOCK_STREAM,
            IPPROTO_TCP,
            localAddressForConnect,
            reinterpret_cast<SOCKADDR*>(&addressStorage->RemoteAddress),
            0,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            context->Irp);

        status = WskSyncCompleteIrp(
            status,
            context,
            WskOperationTimeoutMilliseconds,
            &information,
            cancellation,
            &completion);

        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("WskSocketConnect failed: 0x%08X family=%u information=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(remoteAddress->sa_family),
                information);
        }

        if (!NT_SUCCESS(status) && information != 0) {
            CloseNativeSocketIfPresent(reinterpret_cast<PWSK_SOCKET>(information));
        }

        if (NT_SUCCESS(status)) {
            socket_ = reinterpret_cast<PWSK_SOCKET>(information);
            if (socket_ == nullptr || socket_->Dispatch == nullptr) {
                CloseNativeSocketIfPresent(socket_);
                socket_ = nullptr;
                status = STATUS_INVALID_DEVICE_STATE;
            }
            else {
                dispatch_ = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket_->Dispatch);
                ReinitializeIoRundown();
                ownershipState_ = OwnershipState::Active;
                InterlockedExchange(&closeIssued_, 0);
                WskSyncTrackSocketOpened(socket_);
            }
        }

        WskSyncReleaseContext(context);
        return status;
    }

    NTSTATUS WskSocket::Send(
        WskBuffer& buffer,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags,
        const WskCancellationToken* cancellation) noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (socket_ == nullptr ||
            dispatch_ == nullptr ||
            ownershipState_ != OwnershipState::Active ||
            dispatch_->WskSend == nullptr) {
            return STATUS_INVALID_CONNECTION;
        }

        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        NTSTATUS status = buffer.Prepare(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        WskSyncIrpContext* context = nullptr;
        status = PrepareReusableIrp(&sendIrp_, &context);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        WskBuffer* operationBuffer = nullptr;
        status = AllocateOwnedBuffer(length, context, &operationBuffer);
        if (NT_SUCCESS(status)) {
            status = operationBuffer->SetData(buffer.Data(), length);
        }
        if (!NT_SUCCESS(status)) {
            WskSyncReleaseUnsubmittedContext(context);
            return status;
        }

        SIZE_T information = 0;
        WskSyncCompletionResult completion = {};
        if (!AcquireIoRundown()) {
            WskSyncReleaseUnsubmittedContext(context);
            return STATUS_DEVICE_NOT_READY;
        }
        status = dispatch_->WskSend(socket_, operationBuffer->WskBuf(), flags, context->Irp);
        status = WskSyncCompleteIrp(
            status,
            context,
            WskOperationTimeoutMilliseconds,
            &information,
            cancellation,
            &completion);
        ReleaseIoRundown();
        if (status == STATUS_IO_TIMEOUT || status == STATUS_CANCELLED) {
            if (completion.CompletionOwnedCleanup) {
                AbandonReusableIrp(&sendIrp_);
            }
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(completion.CompletionOwnedCleanup);
            if (!NT_SUCCESS(closeStatus)) {
                WKNET_DBG_PRINT("WskSend cancellation close failed: 0x%08X\r\n",
                    static_cast<ULONG>(closeStatus));
            }
        }

        if (NT_SUCCESS(status) && bytesSent != nullptr) {
            *bytesSent = information;
        }

        WskSyncReleaseContext(context);
        return status;
    }

    NTSTATUS WskSocket::Send(
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags,
        const WskCancellationToken* cancellation) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        WskBuffer buffer = {};
        NTSTATUS status = buffer.Allocate(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = buffer.SetData(data, length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return Send(buffer, length, bytesSent, flags, cancellation);
    }

    NTSTATUS WskSocket::Receive(
        WskBuffer& buffer,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        const WskCancellationToken* cancellation) noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (socket_ == nullptr ||
            dispatch_ == nullptr ||
            ownershipState_ != OwnershipState::Active ||
            dispatch_->WskReceive == nullptr) {
            return STATUS_INVALID_CONNECTION;
        }

        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        NTSTATUS status = buffer.Prepare(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        WskSyncIrpContext* context = nullptr;
        status = PrepareReusableIrp(&receiveIrp_, &context);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        WskBuffer* operationBuffer = nullptr;
        status = AllocateOwnedBuffer(length, context, &operationBuffer);
        if (!NT_SUCCESS(status)) {
            WskSyncReleaseUnsubmittedContext(context);
            return status;
        }

        SIZE_T information = 0;
        WskSyncCompletionResult completion = {};
        if (!AcquireIoRundown()) {
            WskSyncReleaseUnsubmittedContext(context);
            return STATUS_DEVICE_NOT_READY;
        }
        status = dispatch_->WskReceive(socket_, operationBuffer->WskBuf(), flags, context->Irp);
        status = WskSyncCompleteIrp(
            status,
            context,
            timeoutMilliseconds,
            &information,
            cancellation,
            &completion);
        ReleaseIoRundown();
        if (status == STATUS_IO_TIMEOUT || status == STATUS_CANCELLED) {
            if (completion.CompletionOwnedCleanup) {
                AbandonReusableIrp(&receiveIrp_);
            }
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(completion.CompletionOwnedCleanup);
            if (!NT_SUCCESS(closeStatus)) {
                WKNET_DBG_PRINT("WskReceive cancellation close failed: 0x%08X\r\n",
                    static_cast<ULONG>(closeStatus));
            }
        }

        if (bytesReceived != nullptr) {
            *bytesReceived = information;
        }

        if ((NT_SUCCESS(status) || (information != 0 && IsConnectionTerminalStatus(status))) &&
            information != 0) {
            if (information > length) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            else {
                status = operationBuffer->CopyTo(buffer.Data(), information);
            }
        }

        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("WskReceive failed: 0x%08X information=%Iu requested=%Iu\r\n",
                static_cast<ULONG>(status),
                information,
                length);
        }

        WskSyncReleaseContext(context);
        return status;
    }

    NTSTATUS WskSocket::Receive(
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        const WskCancellationToken* cancellation) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (length == 0) {
            return STATUS_SUCCESS;
        }

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = receiveScratch_.EnsureCapacity(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T received = 0;
        status = Receive(receiveScratch_, length, &received, flags, timeoutMilliseconds, cancellation);
        if (!NT_SUCCESS(status)) {
            if (received != 0 && IsConnectionTerminalStatus(status)) {
                status = receiveScratch_.CopyTo(data, received);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (bytesReceived != nullptr) {
                    *bytesReceived = received;
                }

                return STATUS_SUCCESS;
            }

            return status;
        }

        if (received > 0) {
            status = receiveScratch_.CopyTo(data, received);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (bytesReceived != nullptr) {
            *bytesReceived = received;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS WskSocket::Disconnect(ULONG flags) noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (socket_ == nullptr ||
            dispatch_ == nullptr ||
            ownershipState_ != OwnershipState::Active ||
            dispatch_->WskDisconnect == nullptr) {
            return STATUS_INVALID_CONNECTION;
        }

        WskSyncIrpContext* context = nullptr;
        NTSTATUS status = WskSyncAllocateIrp(&context);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!AcquireIoRundown()) {
            WskSyncReleaseUnsubmittedContext(context);
            return STATUS_DEVICE_NOT_READY;
        }
        status = dispatch_->WskDisconnect(socket_, nullptr, flags, context->Irp);
        WskSyncCompletionResult completion = {};
        status = WskSyncCompleteIrp(
            status,
            context,
            WskCloseTimeoutMilliseconds,
            nullptr,
            nullptr,
            &completion);
        ReleaseIoRundown();
        if (status == STATUS_IO_TIMEOUT) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(completion.CompletionOwnedCleanup);
            if (!NT_SUCCESS(closeStatus)) {
                WKNET_DBG_PRINT("WskDisconnect timeout close failed: 0x%08X\r\n",
                    static_cast<ULONG>(closeStatus));
            }
        }

        WskSyncReleaseContext(context);
        return status;
    }

    NTSTATUS WskSocket::Close() noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        return CloseOwnedSocket(WskCloseTimeoutMilliseconds);
    }

    bool WskSocket::IsConnected() const noexcept
    {
        return socket_ != nullptr && ownershipState_ == OwnershipState::Active;
    }

    PWSK_SOCKET WskSocket::NativeSocket() const noexcept
    {
        return socket_;
    }
#endif
}
}
