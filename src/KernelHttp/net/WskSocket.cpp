#include "net/WskSocket.h"

#include <ws2ipdef.h>

namespace KernelHttp
{
namespace net
{
    namespace
    {
        _Function_class_(IO_COMPLETION_ROUTINE)
        NTSTATUS WskCompletionRoutine(
            _In_ PDEVICE_OBJECT deviceObject,
            _In_ PIRP irp,
            _In_opt_ PVOID context)
        {
            UNREFERENCED_PARAMETER(deviceObject);
            UNREFERENCED_PARAMETER(irp);

            auto* event = static_cast<PKEVENT>(context);
            KeSetEvent(event, IO_NO_INCREMENT, FALSE);
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        _Must_inspect_result_
        NTSTATUS AllocateSyncIrp(_Outptr_ PIRP* irp, _Out_ PKEVENT event) noexcept
        {
            if (irp == nullptr || event == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *irp = IoAllocateIrp(1, FALSE);
            if (*irp == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            KeInitializeEvent(event, NotificationEvent, FALSE);
            IoSetCompletionRoutine(
                *irp,
                WskCompletionRoutine,
                event,
                TRUE,
                TRUE,
                TRUE);

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS CompleteSyncIrp(
            NTSTATUS requestStatus,
            _In_ PIRP irp,
            _In_ PKEVENT event,
            _Out_opt_ SIZE_T* information,
            ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds) noexcept
        {
            if (requestStatus == STATUS_PENDING) {
                LARGE_INTEGER timeout = {};
                timeout.QuadPart = -static_cast<LONGLONG>(timeoutMilliseconds) * 10 * 1000;

                const NTSTATUS waitStatus = KeWaitForSingleObject(
                    event,
                    Executive,
                    KernelMode,
                    FALSE,
                    &timeout);

                if (waitStatus == STATUS_TIMEOUT) {
                    IoCancelIrp(irp);
                    KeWaitForSingleObject(event, Executive, KernelMode, FALSE, nullptr);

                    if (information != nullptr) {
                        *information = 0;
                    }

                    return STATUS_IO_TIMEOUT;
                }

                requestStatus = irp->IoStatus.Status;
            }

            if (information != nullptr) {
                *information = static_cast<SIZE_T>(irp->IoStatus.Information);
            }

            return requestStatus;
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
    }

    WskSocket::~WskSocket() noexcept
    {
        if (socket_ != nullptr) {
            const NTSTATUS status = Close();
            UNREFERENCED_PARAMETER(status);
        }
    }

    NTSTATUS WskSocket::Connect(
        WskClient& client,
        const SOCKADDR* remoteAddress,
        const SOCKADDR* localAddress) noexcept
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

        SOCKADDR_STORAGE localStorage = {};
        SOCKADDR* localAddressForConnect = const_cast<SOCKADDR*>(localAddress);

        if (localAddressForConnect == nullptr) {
            NTSTATUS status = BuildWildcardLocalAddress(
                remoteAddress,
                &localStorage,
                &localAddressForConnect);

            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        PIRP irp = nullptr;
        KEVENT event = {};

        NTSTATUS status = AllocateSyncIrp(&irp, &event);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T information = 0;
        status = providerDispatch->WskSocketConnect(
            providerClient,
            SOCK_STREAM,
            IPPROTO_TCP,
            localAddressForConnect,
            const_cast<SOCKADDR*>(remoteAddress),
            0,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            irp);

        status = CompleteSyncIrp(status, irp, &event, &information);

        if (!NT_SUCCESS(status)) {
            kprintf("WskSocketConnect failed: 0x%08X family=%u information=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(remoteAddress->sa_family),
                information);
        }

        if (NT_SUCCESS(status)) {
            socket_ = reinterpret_cast<PWSK_SOCKET>(information);
            if (socket_ == nullptr || socket_->Dispatch == nullptr) {
                socket_ = nullptr;
                status = STATUS_INVALID_DEVICE_STATE;
            }
            else {
                dispatch_ = static_cast<const WSK_PROVIDER_CONNECTION_DISPATCH*>(socket_->Dispatch);
            }
        }

        IoFreeIrp(irp);
        return status;
    }

    NTSTATUS WskSocket::Send(
        WskBuffer& buffer,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags) noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (socket_ == nullptr || dispatch_ == nullptr || dispatch_->WskSend == nullptr) {
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

        PIRP irp = nullptr;
        KEVENT event = {};

        status = AllocateSyncIrp(&irp, &event);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T information = 0;
        status = dispatch_->WskSend(socket_, buffer.WskBuf(), flags, irp);
        status = CompleteSyncIrp(status, irp, &event, &information);

        if (NT_SUCCESS(status) && bytesSent != nullptr) {
            *bytesSent = information;
        }

        IoFreeIrp(irp);
        return status;
    }

    NTSTATUS WskSocket::Send(
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags) noexcept
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

        NTSTATUS status = sendBuffer_.EnsureCapacity(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = sendBuffer_.SetData(data, length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return Send(sendBuffer_, length, bytesSent, flags);
    }

    NTSTATUS WskSocket::Receive(
        WskBuffer& buffer,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds) noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (socket_ == nullptr || dispatch_ == nullptr || dispatch_->WskReceive == nullptr) {
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

        PIRP irp = nullptr;
        KEVENT event = {};

        status = AllocateSyncIrp(&irp, &event);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T information = 0;
        status = dispatch_->WskReceive(socket_, buffer.WskBuf(), flags, irp);
        status = CompleteSyncIrp(status, irp, &event, &information, timeoutMilliseconds);

        if (bytesReceived != nullptr) {
            *bytesReceived = information;
        }

        if (!NT_SUCCESS(status)) {
            kprintf("WskReceive failed: 0x%08X information=%Iu requested=%Iu\r\n",
                static_cast<ULONG>(status),
                information,
                length);
        }

        IoFreeIrp(irp);
        return status;
    }

    NTSTATUS WskSocket::Receive(
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds) noexcept
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

        NTSTATUS status = receiveBuffer_.EnsureCapacity(length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T received = 0;
        status = Receive(receiveBuffer_, length, &received, flags, timeoutMilliseconds);
        if (!NT_SUCCESS(status)) {
            if (received != 0 && IsConnectionTerminalStatus(status)) {
                status = receiveBuffer_.CopyTo(data, received);
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
            status = receiveBuffer_.CopyTo(data, received);
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

        if (socket_ == nullptr || dispatch_ == nullptr || dispatch_->WskDisconnect == nullptr) {
            return STATUS_INVALID_CONNECTION;
        }

        PIRP irp = nullptr;
        KEVENT event = {};

        NTSTATUS status = AllocateSyncIrp(&irp, &event);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = dispatch_->WskDisconnect(socket_, nullptr, flags, irp);
        status = CompleteSyncIrp(status, irp, &event, nullptr, WskCloseTimeoutMilliseconds);

        IoFreeIrp(irp);
        return status;
    }

    NTSTATUS WskSocket::Close() noexcept
    {
        if (!CanBlockNow()) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (socket_ == nullptr) {
            return STATUS_SUCCESS;
        }

        if (dispatch_ == nullptr || dispatch_->Basic.WskCloseSocket == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        PIRP irp = nullptr;
        KEVENT event = {};

        NTSTATUS status = AllocateSyncIrp(&irp, &event);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        PWSK_SOCKET socketToClose = socket_;
        const auto* dispatch = dispatch_;

        status = dispatch->Basic.WskCloseSocket(socketToClose, irp);
        socket_ = nullptr;
        dispatch_ = nullptr;

        status = CompleteSyncIrp(status, irp, &event, nullptr, WskCloseTimeoutMilliseconds);

        IoFreeIrp(irp);
        return status;
    }

    bool WskSocket::IsConnected() const noexcept
    {
        return socket_ != nullptr;
    }

    PWSK_SOCKET WskSocket::NativeSocket() const noexcept
    {
        return socket_;
    }
}
}
