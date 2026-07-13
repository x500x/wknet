#pragma once

#if !defined(WKNET_USER_MODE_TEST)
#error "WskDatagramSocketTest.h is only available to user-mode tests"
#endif

#include "net/WskDatagramSocket.h"

namespace wknet::net::test {
    struct WskDatagramTestReceiveCompletion final
    {
        NTSTATUS Status = STATUS_SUCCESS;
        const void* Data = nullptr;
        SIZE_T DataLength = 0;
        SOCKADDR_STORAGE RemoteAddress = {};
        ULONG RemoteAddressLength = 0;
        bool CompleteSynchronously = false;
    };

    struct WskDatagramProviderStatistics final
    {
        ULONG OpenCalls = 0;
        ULONG BindCalls = 0;
        ULONG SendCalls = 0;
        ULONG ReceiveCalls = 0;
        ULONG CancelCalls = 0;
        ULONG CloseCalls = 0;
        ULONG CompletionCallbacks = 0;
        ULONG DispatchCompletions = 0;
        ULONG PassiveConsumers = 0;
        ULONG PayloadParseCalls = 0;
        ULONG UpperCallbackCalls = 0;
        ULONGLONG CompletionThreadToken = 0;
        ULONGLONG PassiveConsumerThreadToken = 0;
        ULONG AllocationAttempts = 0;
        LONG OpenSockets = 0;
        LONG OutstandingReceives = 0;
        LONG BufferReferences = 0;
    };

    void ResetProvider() noexcept;
    void QueueReceiveCompletion(const WskDatagramTestReceiveCompletion& completion) noexcept;
    void SetNextSendResult(NTSTATUS status, SIZE_T bytesSent) noexcept;
    void SetNextOpenResult(NTSTATUS status) noexcept;
    void SetNextBindResult(NTSTATUS status) noexcept;
    void SetNextReceiveStartResult(NTSTATUS status) noexcept;
    void SetCancelCompletesImmediately(bool enabled) noexcept;
    void FailNextAllocation() noexcept;
    bool CompletePendingReceive() noexcept;
    bool CompleteCancelledReceiveLate() noexcept;
    WskDatagramProviderStatistics GetProviderStatistics() noexcept;
}
