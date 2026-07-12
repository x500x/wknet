#pragma once

#include "http2/Http2Frame.h"

namespace wknet
{
namespace http2
{
    enum class Http2StreamState : UCHAR
    {
        Idle,
        Open,
        HalfClosedLocal,
        HalfClosedRemote,
        Closed
    };

    class Http2Stream final
    {
    public:
        Http2Stream() noexcept = default;

        void Initialize(ULONG streamId, ULONG localWindow, ULONG remoteWindow) noexcept;

        ULONG StreamId() const noexcept;
        Http2StreamState State() const noexcept;
        LONG LocalWindow() const noexcept;
        LONG RemoteWindow() const noexcept;

        _Must_inspect_result_
        NTSTATUS SendHeaders(bool endStream) noexcept;

        _Must_inspect_result_
        NTSTATUS SendData(SIZE_T length, bool endStream) noexcept;

        _Must_inspect_result_
        NTSTATUS ReceiveHeaders(bool endStream) noexcept;

        _Must_inspect_result_
        NTSTATUS ReceiveData(SIZE_T length, bool endStream) noexcept;

        _Must_inspect_result_
        NTSTATUS IncreaseRemoteWindow(ULONG increment) noexcept;

        _Must_inspect_result_
        NTSTATUS AdjustRemoteWindow(long long delta) noexcept;

        _Must_inspect_result_
        NTSTATUS IncreaseLocalWindow(ULONG increment) noexcept;

        void Reset() noexcept;
        void Close() noexcept;

    private:
        ULONG streamId_ = 0;
        Http2StreamState state_ = Http2StreamState::Idle;
        LONG localWindow_ = Http2InitialWindowSize;
        LONG remoteWindow_ = Http2InitialWindowSize;
    };
}
}
