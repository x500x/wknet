#pragma once

#include "net/WskBuffer.h"
#include "net/WskClient.h"

namespace wknet
{
namespace net
{
    struct WskSyncIrpContext;

    typedef bool (*WskCancellationCheck)(_In_opt_ void* context);

    struct WskCancellationToken final
    {
        WskCancellationCheck IsCancellationRequested = nullptr;
        void* Context = nullptr;
    };

#if defined(WKNET_USER_MODE_TEST)
    using PWSK_SOCKET = void*;
    using PIRP = void*;

    struct WSK_PROVIDER_CONNECTION_DISPATCH
    {
        int Dummy = 0;
    };

    typedef NTSTATUS (*WskTestSocketConnectCallback)(
        _In_opt_ void* context,
        _In_ const SOCKADDR* remoteAddress,
        _In_opt_ const SOCKADDR* localAddress,
        _In_opt_ const WskCancellationToken* cancellation,
        _Out_ PWSK_SOCKET* socket);

    typedef NTSTATUS (*WskTestSocketSendCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket,
        _In_reads_bytes_(length) const void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesSent,
        ULONG flags,
        _In_opt_ const WskCancellationToken* cancellation);

    typedef NTSTATUS (*WskTestSocketReceiveCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket,
        _Out_writes_bytes_(length) void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        _In_opt_ const WskCancellationToken* cancellation);

    typedef NTSTATUS (*WskTestSocketDisconnectCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket,
        ULONG flags);

    typedef void (*WskTestSocketCloseCallback)(
        _In_opt_ void* context,
        _In_ PWSK_SOCKET socket);

    struct WskTestSocketProvider final
    {
        WskTestSocketConnectCallback Connect = nullptr;
        WskTestSocketSendCallback Send = nullptr;
        WskTestSocketReceiveCallback Receive = nullptr;
        WskTestSocketDisconnectCallback Disconnect = nullptr;
        WskTestSocketCloseCallback Close = nullptr;
    };

    void WskTestSetSocketProvider(
        _In_opt_ const WskTestSocketProvider* provider,
        _In_opt_ void* context) noexcept;
#endif

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

        _Must_inspect_result_
        NTSTATUS Connect(
            WskClient& client,
            _In_ const SOCKADDR* remoteAddress,
            _In_opt_ const SOCKADDR* localAddress = nullptr,
            _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Send(
            WskBuffer& buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent,
            ULONG flags = WSK_FLAG_NODELAY,
            _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Send(
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent,
            ULONG flags = WSK_FLAG_NODELAY,
            _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Receive(
            WskBuffer& buffer,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG flags = 0,
            ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds,
            _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Receive(
            _Out_writes_bytes_(length) void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived,
            ULONG flags = 0,
            ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds,
            _In_opt_ const WskCancellationToken* cancellation = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Disconnect(ULONG flags = 0) noexcept;

        _Must_inspect_result_
        NTSTATUS Close() noexcept;

        bool IsConnected() const noexcept;

        _Ret_maybenull_
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

        _Must_inspect_result_
        NTSTATUS CloseOwnedSocket(ULONG timeoutMilliseconds) noexcept;

        _Must_inspect_result_
        NTSTATUS CloseAfterCancelledOperation(
            bool completionOwnedCleanup) noexcept;

        _Must_inspect_result_
        bool AcquireIoRundown() noexcept;

        void ReleaseIoRundown() noexcept;

        void WaitForIoRundown() noexcept;

        void ReinitializeIoRundown() noexcept;

        _Must_inspect_result_
        NTSTATUS PrepareReusableIrp(
            _Inout_ PIRP* reusableIrp,
            _Outptr_ WskSyncIrpContext** context) noexcept;

        void AbandonReusableIrp(_Inout_ PIRP* reusableIrp) noexcept;

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
}
