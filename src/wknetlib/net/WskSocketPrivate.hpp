#pragma once

#include "net/WskSocket.h"
#include "net/WskClientPrivate.hpp"

namespace wknet::net {
    struct WskSyncIrpContext;

    class WskSocket final
    {
    public:
#if defined(WKNET_USER_MODE_TEST)
        WskSocket() noexcept = default;
#else
        WskSocket() noexcept;
#endif
        WskSocket(const WskSocket&) = delete;
        WskSocket& operator=(const WskSocket&) = delete;
        ~WskSocket() noexcept;
        NTSTATUS Connect(
            WskClient& client,
            const SOCKADDR* remoteAddress,
            const SOCKADDR* localAddress = nullptr,
            const WskCancellationToken* cancellation = nullptr) noexcept;
        NTSTATUS Send(
            WskBuffer& buffer,
            SIZE_T length,
            SIZE_T* bytesSent,
            ULONG flags = WSK_FLAG_NODELAY,
            const WskCancellationToken* cancellation = nullptr) noexcept;
        NTSTATUS Send(
            const void* data,
            SIZE_T length,
            SIZE_T* bytesSent,
            ULONG flags = WSK_FLAG_NODELAY,
            const WskCancellationToken* cancellation = nullptr) noexcept;
        NTSTATUS Receive(
            WskBuffer& buffer,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG flags = 0,
            ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds,
            const WskCancellationToken* cancellation = nullptr) noexcept;
        NTSTATUS Receive(
            void* data,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG flags = 0,
            ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds,
            const WskCancellationToken* cancellation = nullptr) noexcept;
        NTSTATUS Disconnect(ULONG flags = 0) noexcept;
        NTSTATUS Close() noexcept;
        bool IsConnected() const noexcept;
        PWSK_SOCKET NativeSocket() const noexcept;

    private:
        enum class OwnershipState : UCHAR
        {
            Closed,
            Active,
            CancelPending,
            ClosePending,
            CompletionOwnedCleanup
        };
        NTSTATUS CloseOwnedSocket(ULONG timeoutMilliseconds) noexcept;
        NTSTATUS CloseAfterCancelledOperation(bool completionOwnedCleanup) noexcept;
        bool AcquireIoRundown() noexcept;
        void ReleaseIoRundown() noexcept;
        void WaitForIoRundown() noexcept;
        void ReinitializeIoRundown() noexcept;
        NTSTATUS PrepareReusableIrp(PIRP* reusableIrp, WskSyncIrpContext** context) noexcept;
        void AbandonReusableIrp(PIRP* reusableIrp) noexcept;
        void ReleaseReusableIrps() noexcept;

        PWSK_SOCKET socket_ = nullptr;
        const WSK_PROVIDER_CONNECTION_DISPATCH* dispatch_ = nullptr;
        OwnershipState ownershipState_ = OwnershipState::Closed;
        volatile LONG closeIssued_ = 0;
        bool ioRundownReady_ = true;
        WskBuffer sendScratch_ = {};
        WskBuffer receiveScratch_ = {};
        PIRP sendIrp_ = nullptr;
        PIRP receiveIrp_ = nullptr;
#if !defined(WKNET_USER_MODE_TEST)
        EX_RUNDOWN_REF ioRundown_ = {};
#endif
    };
}
