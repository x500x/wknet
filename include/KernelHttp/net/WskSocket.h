#pragma once

#include <KernelHttp/net/WskBuffer.h>
#include <KernelHttp/net/WskClient.h>

namespace KernelHttp
{
namespace net
{
    typedef bool (*WskCancellationCheck)(_In_opt_ void* context);

    struct WskCancellationToken final
    {
        WskCancellationCheck IsCancellationRequested = nullptr;
        void* Context = nullptr;
    };

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    using PWSK_SOCKET = void*;

    struct WSK_PROVIDER_CONNECTION_DISPATCH
    {
        int Dummy = 0;
    };
#endif

    class WskSocket final
    {
    public:
        WskSocket() noexcept = default;

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

        PWSK_SOCKET socket_ = nullptr;
        const WSK_PROVIDER_CONNECTION_DISPATCH* dispatch_ = nullptr;
        OwnershipState ownershipState_ = OwnershipState::Closed;
        volatile LONG closeIssued_ = 0;
    };
}
}
