#include <KernelHttp/http2/Http2Stream.h>

namespace KernelHttp
{
namespace http2
{
    void Http2Stream::Initialize(ULONG streamId, ULONG localWindow, ULONG remoteWindow) noexcept
    {
        streamId_ = streamId;
        state_ = Http2StreamState::Idle;
        localWindow_ = static_cast<LONG>(localWindow);
        remoteWindow_ = static_cast<LONG>(remoteWindow);
    }

    ULONG Http2Stream::StreamId() const noexcept
    {
        return streamId_;
    }

    Http2StreamState Http2Stream::State() const noexcept
    {
        return state_;
    }

    LONG Http2Stream::LocalWindow() const noexcept
    {
        return localWindow_;
    }

    LONG Http2Stream::RemoteWindow() const noexcept
    {
        return remoteWindow_;
    }

    NTSTATUS Http2Stream::SendHeaders(bool endStream) noexcept
    {
        switch (state_) {
        case Http2StreamState::Idle:
            state_ = endStream ? Http2StreamState::HalfClosedLocal : Http2StreamState::Open;
            return STATUS_SUCCESS;

        case Http2StreamState::Open:
            if (endStream) {
                state_ = Http2StreamState::HalfClosedLocal;
            }
            return STATUS_SUCCESS;

        case Http2StreamState::HalfClosedRemote:
            if (endStream) {
                state_ = Http2StreamState::Closed;
            }
            return STATUS_SUCCESS;

        default:
            return STATUS_INVALID_DEVICE_STATE;
        }
    }

    NTSTATUS Http2Stream::SendData(SIZE_T length, bool endStream) noexcept
    {
        if (state_ != Http2StreamState::Open &&
            state_ != Http2StreamState::HalfClosedRemote) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (length > static_cast<SIZE_T>(remoteWindow_)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        remoteWindow_ -= static_cast<LONG>(length);

        if (endStream) {
            state_ = state_ == Http2StreamState::HalfClosedRemote ?
                Http2StreamState::Closed :
                Http2StreamState::HalfClosedLocal;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Stream::ReceiveHeaders(bool endStream) noexcept
    {
        switch (state_) {
        case Http2StreamState::Idle:
            state_ = endStream ? Http2StreamState::HalfClosedRemote : Http2StreamState::Open;
            return STATUS_SUCCESS;

        case Http2StreamState::Open:
            if (endStream) {
                state_ = Http2StreamState::HalfClosedRemote;
            }
            return STATUS_SUCCESS;

        case Http2StreamState::HalfClosedLocal:
            if (endStream) {
                state_ = Http2StreamState::Closed;
            }
            return STATUS_SUCCESS;

        default:
            return STATUS_INVALID_DEVICE_STATE;
        }
    }

    NTSTATUS Http2Stream::ReceiveData(SIZE_T length, bool endStream) noexcept
    {
        if (state_ != Http2StreamState::Open &&
            state_ != Http2StreamState::HalfClosedLocal) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (length > static_cast<SIZE_T>(localWindow_)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        localWindow_ -= static_cast<LONG>(length);

        if (endStream) {
            state_ = state_ == Http2StreamState::HalfClosedLocal ?
                Http2StreamState::Closed :
                Http2StreamState::HalfClosedRemote;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Stream::IncreaseRemoteWindow(ULONG increment) noexcept
    {
        if (increment == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (remoteWindow_ > static_cast<LONG>(Http2MaxWindowSize - increment)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        remoteWindow_ += static_cast<LONG>(increment);
        return STATUS_SUCCESS;
    }

    NTSTATUS Http2Stream::IncreaseLocalWindow(ULONG increment) noexcept
    {
        if (increment == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (localWindow_ > static_cast<LONG>(Http2MaxWindowSize - increment)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        localWindow_ += static_cast<LONG>(increment);
        return STATUS_SUCCESS;
    }

    void Http2Stream::Reset() noexcept
    {
        streamId_ = 0;
        state_ = Http2StreamState::Idle;
        localWindow_ = Http2InitialWindowSize;
        remoteWindow_ = Http2InitialWindowSize;
    }

    void Http2Stream::Close() noexcept
    {
        state_ = Http2StreamState::Closed;
    }
}
}