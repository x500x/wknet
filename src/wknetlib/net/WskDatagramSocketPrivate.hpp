#pragma once

#include "net/WskBuffer.h"
#include "net/WskClientPrivate.hpp"
#include "net/WskDatagramSocket.h"

#if defined(WKNET_USER_MODE_TEST)
#include <condition_variable>
#include <mutex>
using PWSK_SOCKET = void*;
#endif

namespace wknet::net {
    enum class WskDatagramEndpointState : UCHAR
    {
        Created,
        Bound,
        Connected,
        Closing,
        Closed
    };

    enum class WskDatagramReceiveState : UCHAR
    {
        Idle,
        Pending,
        CancelPending,
        Completed
    };

    class WskDatagramSocket final
    {
    public:
        WskDatagramSocket() noexcept;
        WskDatagramSocket(const WskDatagramSocket&) = delete;
        WskDatagramSocket& operator=(const WskDatagramSocket&) = delete;
        ~WskDatagramSocket() noexcept;

        NTSTATUS Open(WskClient& client, USHORT addressFamily) noexcept;
        NTSTATUS Bind(const SOCKADDR* localAddress) noexcept;
        NTSTATUS ConnectPeer(const SOCKADDR* remoteAddress) noexcept;
        NTSTATUS StartReceive(void* data, SIZE_T length) noexcept;
        NTSTATUS CancelReceive() noexcept;
        NTSTATUS CompleteReceive(ULONG timeoutMilliseconds, WskDatagramReceiveResult* result) noexcept;
        NTSTATUS Send(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept;
        NTSTATUS SendTo(
            const void* data,
            SIZE_T length,
            const SOCKADDR* remoteAddress,
            SIZE_T* bytesSent) noexcept;
        NTSTATUS GetLocalAddress(SOCKADDR_STORAGE* localAddress) const noexcept;
        NTSTATUS GetRemoteAddress(SOCKADDR_STORAGE* remoteAddress) const noexcept;
        NTSTATUS Close() noexcept;
        void SetConnectionId(ULONGLONG connectionId) noexcept;
        ULONGLONG ConnectionId() const noexcept;

#if defined(WKNET_USER_MODE_TEST)
        void TestCompleteReceive(
            const void* data,
            SIZE_T dataLength,
            const SOCKADDR_STORAGE& remoteAddress,
            ULONG remoteAddressLength,
            NTSTATUS status,
            bool dispatchCompletion) noexcept;
#endif

    private:
        bool IsPassiveLevel() const noexcept;
        bool AddressMatchesFamily(const SOCKADDR* address) const noexcept;
        ULONG AddressLength() const noexcept;
        void MakeWildcardAddress(SOCKADDR_STORAGE* address) const noexcept;
        NTSTATUS CompleteReceiveRecord(
            NTSTATUS status,
            SIZE_T information,
            ULONG remoteAddressLength,
            ULONGLONG generation) noexcept;
        NTSTATUS CancelReceiveInternal(bool timeoutCancellation) noexcept;
        void ReleaseReceiveResources() noexcept;
        NTSTATUS CloseNativeSocket() noexcept;
#if !defined(WKNET_USER_MODE_TEST)
        _Function_class_(IO_COMPLETION_ROUTINE)
        static NTSTATUS ReceiveCompletionRoutine(
            _In_ PDEVICE_OBJECT deviceObject,
            _In_ PIRP irp,
            _In_opt_ PVOID context) noexcept;
#endif

        USHORT addressFamily_ = AF_UNSPEC;
        WskDatagramEndpointState endpointState_ = WskDatagramEndpointState::Closed;
        WskDatagramReceiveState receiveState_ = WskDatagramReceiveState::Idle;
        PWSK_SOCKET socket_ = nullptr;
#if !defined(WKNET_USER_MODE_TEST)
        const WSK_PROVIDER_DATAGRAM_DISPATCH* dispatch_ = nullptr;
#endif
        ULONGLONG connectionId_ = 0;
        SOCKADDR_STORAGE localAddress_ = {};
        SOCKADDR_STORAGE remoteAddress_ = {};
        SOCKADDR_STORAGE bindScratchAddress_ = {};
        bool hasLocalAddress_ = false;
        bool hasRemoteAddress_ = false;
        void* receiveData_ = nullptr;
        SIZE_T receiveCapacity_ = 0;
        NTSTATUS receiveStatus_ = STATUS_PENDING;
        SIZE_T receiveBytes_ = 0;
        SOCKADDR_STORAGE receiveRemoteAddress_ = {};
        ULONG receiveRemoteAddressLength_ = 0;
        ULONG receiveControlLength_ = 0;
        ULONG receiveControlFlags_ = 0;
        ULONGLONG receiveGeneration_ = 0;
        ULONGLONG completedGeneration_ = 0;
        bool timeoutCancellation_ = false;
        bool completionOwnsIoReference_ = false;
        WSK_BUF receiveBuffer_ = {};
        WskBuffer sendScratch_ = {};

#if defined(WKNET_USER_MODE_TEST)
        mutable std::mutex stateLock_;
        std::condition_variable receiveEvent_;
        bool receiveEventSignaled_ = false;
#else
        mutable KSPIN_LOCK stateLock_ = {};
        KEVENT receiveEvent_ = {};
        EX_RUNDOWN_REF ioRundown_ = {};
        PIRP receiveIrp_ = nullptr;
        PMDL receiveMdl_ = nullptr;
#endif
    };
}
