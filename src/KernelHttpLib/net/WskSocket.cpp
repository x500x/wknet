#include <KernelHttp/net/WskSocket.h>
#include "WskSync.h"

#include <ws2ipdef.h>

namespace KernelHttp
{
namespace net
{
    namespace
    {
        void DeleteWskBuffer(_In_opt_ void* context) noexcept
        {
            auto* buffer = static_cast<WskBuffer*>(context);
            delete buffer;
        }

        struct WskSocketConnectStorage final
        {
            SOCKADDR_STORAGE LocalAddress = {};
            SOCKADDR_STORAGE RemoteAddress = {};
        };

        void DeleteConnectStorage(_In_opt_ void* context) noexcept
        {
            auto* storage = static_cast<WskSocketConnectStorage*>(context);
            delete storage;
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

            auto* owned = new WskBuffer();
            if (owned == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = owned->Allocate(length);
            if (!NT_SUCCESS(status)) {
                delete owned;
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
            status = WskSyncCompleteIrp(status, context, WskCloseTimeoutMilliseconds, nullptr);
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
                kprintf("Unable to allocate detached WSK close IRP: 0x%08X\r\n",
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

    WskSocket::~WskSocket() noexcept
    {
        if (socket_ != nullptr || ownershipState_ != OwnershipState::Closed) {
            const NTSTATUS status = Close();
            UNREFERENCED_PARAMETER(status);
        }
    }

    NTSTATUS WskSocket::CloseOwnedSocket(ULONG timeoutMilliseconds) noexcept
    {
        if (socket_ == nullptr) {
            dispatch_ = nullptr;
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

        PWSK_SOCKET socketToClose = socket_;
        const auto* dispatch = dispatch_;
        ownershipState_ = OwnershipState::ClosePending;

        status = dispatch->Basic.WskCloseSocket(socketToClose, context->Irp);
        socket_ = nullptr;
        dispatch_ = nullptr;

        WskSyncCompletionResult completion = {};
        status = WskSyncCompleteIrp(
            status,
            context,
            timeoutMilliseconds,
            nullptr,
            nullptr,
            &completion);

        ownershipState_ = completion.CompletionOwnedCleanup
            ? OwnershipState::CompletionOwnedCleanup
            : OwnershipState::Closed;

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

        auto* addressStorage = new WskSocketConnectStorage();
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
            kprintf("WskSocketConnect failed: 0x%08X family=%u information=%Iu\r\n",
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
                ownershipState_ = OwnershipState::Active;
                InterlockedExchange(&closeIssued_, 0);
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
        status = WskSyncAllocateIrp(&context);
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
        status = dispatch_->WskSend(socket_, operationBuffer->WskBuf(), flags, context->Irp);
        status = WskSyncCompleteIrp(
            status,
            context,
            WskOperationTimeoutMilliseconds,
            &information,
            cancellation,
            &completion);
        if (status == STATUS_IO_TIMEOUT || status == STATUS_CANCELLED) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(completion.CompletionOwnedCleanup);
            if (!NT_SUCCESS(closeStatus)) {
                kprintf("WskSend cancellation close failed: 0x%08X\r\n",
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
        status = WskSyncAllocateIrp(&context);
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
        status = dispatch_->WskReceive(socket_, operationBuffer->WskBuf(), flags, context->Irp);
        status = WskSyncCompleteIrp(
            status,
            context,
            timeoutMilliseconds,
            &information,
            cancellation,
            &completion);
        if (status == STATUS_IO_TIMEOUT || status == STATUS_CANCELLED) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(completion.CompletionOwnedCleanup);
            if (!NT_SUCCESS(closeStatus)) {
                kprintf("WskReceive cancellation close failed: 0x%08X\r\n",
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
            kprintf("WskReceive failed: 0x%08X information=%Iu requested=%Iu\r\n",
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

        WskBuffer buffer = {};
        NTSTATUS status = buffer.Allocate(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T received = 0;
        status = Receive(buffer, length, &received, flags, timeoutMilliseconds, cancellation);
        if (!NT_SUCCESS(status)) {
            if (received != 0 && IsConnectionTerminalStatus(status)) {
                status = buffer.CopyTo(data, received);
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

        status = dispatch_->WskDisconnect(socket_, nullptr, flags, context->Irp);
        WskSyncCompletionResult completion = {};
        status = WskSyncCompleteIrp(
            status,
            context,
            WskCloseTimeoutMilliseconds,
            nullptr,
            nullptr,
            &completion);
        if (status == STATUS_IO_TIMEOUT) {
            const NTSTATUS closeStatus = CloseAfterCancelledOperation(completion.CompletionOwnedCleanup);
            if (!NT_SUCCESS(closeStatus)) {
                kprintf("WskDisconnect timeout close failed: 0x%08X\r\n",
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
}
}
