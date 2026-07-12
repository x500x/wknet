#pragma once

#include "http1/HttpTypes.h"

namespace wknet
{
namespace ws
{
    constexpr UCHAR WebSocketDeflateMinWindowBits = 8;
    constexpr UCHAR WebSocketDeflateMaxWindowBits = 15;

    struct PerMessageDeflateOptions final
    {
        bool Enable = false;
        bool ClientNoContextTakeover = false;
        bool ServerNoContextTakeover = false;
        UCHAR ClientMaxWindowBits = WebSocketDeflateMaxWindowBits;
        UCHAR ServerMaxWindowBits = WebSocketDeflateMaxWindowBits;
    };

    struct PerMessageDeflateNegotiation final
    {
        bool Enabled = false;
        bool ClientNoContextTakeover = false;
        bool ServerNoContextTakeover = false;
        UCHAR ClientMaxWindowBits = WebSocketDeflateMaxWindowBits;
        UCHAR ServerMaxWindowBits = WebSocketDeflateMaxWindowBits;
    };

    _Must_inspect_result_
    bool IsValidPerMessageDeflateOptions(
        _In_ const PerMessageDeflateOptions& options) noexcept;

    class WebSocketDeflateContext final
    {
    public:
        WebSocketDeflateContext() noexcept = default;
        ~WebSocketDeflateContext() noexcept = default;

        WebSocketDeflateContext(const WebSocketDeflateContext&) = delete;
        WebSocketDeflateContext& operator=(const WebSocketDeflateContext&) = delete;

        _Must_inspect_result_
        NTSTATUS Initialize(UCHAR windowBits) noexcept;

        void ResetHistory() noexcept;
        void Release() noexcept;

        _Must_inspect_result_
        bool IsInitialized() const noexcept;

        _Must_inspect_result_
        NTSTATUS InflateMessage(
            _In_reads_bytes_(sourceLength) const UCHAR* source,
            SIZE_T sourceLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS DeflateMessage(
            _In_reads_bytes_opt_(sourceLength) const UCHAR* source,
            SIZE_T sourceLength,
            bool finalFragment,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static SIZE_T MaxStoredDeflateBytes(SIZE_T sourceLength, bool finalFragment) noexcept;

        _Must_inspect_result_
        NTSTATUS EmitByte(
            UCHAR byte,
            SIZE_T encodedLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Inout_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        NTSTATUS CopyFromHistory(
            SIZE_T distance,
            SIZE_T length,
            SIZE_T encodedLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Inout_ SIZE_T* bytesWritten) noexcept;

    private:
        HeapArray<UCHAR> window_ = {};
        SIZE_T windowMask_ = 0;
        SIZE_T windowPosition_ = 0;
        SIZE_T historyBytes_ = 0;
    };
}
}
