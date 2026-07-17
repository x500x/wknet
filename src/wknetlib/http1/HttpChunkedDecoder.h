#pragma once

#include "http1/HttpResponse.h"

namespace wknet
{
namespace http1
{
    // Incremental HTTP/1.1 chunked body decoder (RFC 9112).
    // Feed wire bytes after the response header block; emits application
    // payload via OnData. Trailers are captured when the terminal chunk ends.
    //
    // Multi-KiB trailer line/arena buffers are heap-owned. Construct only via
    // heap (new / AllocateNonPagedObject); do not place this type on the stack.
    class HttpChunkedDecoder final
    {
    public:
        typedef NTSTATUS (*DataCallback)(
            _In_opt_ void* context,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength);

        HttpChunkedDecoder() noexcept;
        ~HttpChunkedDecoder() noexcept;

        HttpChunkedDecoder(const HttpChunkedDecoder&) = delete;
        HttpChunkedDecoder& operator=(const HttpChunkedDecoder&) = delete;

        // Allocate trailer line + arena buffers. Required before Feed.
        _Must_inspect_result_
        NTSTATUS Initialize() noexcept;

        void Reset() noexcept;

        void SetTrailerStorage(
            _Out_writes_opt_(trailerCapacity) HttpHeader* trailers,
            SIZE_T trailerCapacity) noexcept;

        // Feed more wire bytes. On success, *bytesConsumed is advanced for
        // fully processed input. STATUS_MORE_PROCESSING_REQUIRED means more
        // wire data is needed (partial progress may still have been consumed).
        // STATUS_SUCCESS means the chunked body (including trailers) completed.
        _Must_inspect_result_
        NTSTATUS Feed(
            _In_reads_bytes_(dataLength) const char* data,
            SIZE_T dataLength,
            _Out_ SIZE_T* bytesConsumed,
            _In_opt_ DataCallback onData,
            _In_opt_ void* context) noexcept;

        _Must_inspect_result_
        bool IsComplete() const noexcept
        {
            return state_ == State::Complete;
        }

        _Must_inspect_result_
        SIZE_T TrailerCount() const noexcept
        {
            return trailerCount_;
        }

    private:
        enum class State : UCHAR
        {
            SizeLine = 0,
            ChunkData = 1,
            ChunkDataCr = 2,
            ChunkDataLf = 3,
            TrailerLine = 4,
            Complete = 5,
            Failed = 6
        };

        _Must_inspect_result_
        NTSTATUS ProcessSizeLineChar(char ch) noexcept;

        _Must_inspect_result_
        NTSTATUS FinishSizeLine() noexcept;

        _Must_inspect_result_
        NTSTATUS ProcessTrailerLineChar(char ch) noexcept;

        _Must_inspect_result_
        NTSTATUS FinishTrailerLine() noexcept;

        State state_ = State::SizeLine;
        SIZE_T chunkRemaining_ = 0;
        bool sawChunkExtension_ = false;
        bool sizeLineHasDigit_ = false;
        // Small fixed buffer (32 B) — safe on object, object itself is heap-only.
        char sizeLine_[HttpMaxChunkSizeLineBytes] = {};
        SIZE_T sizeLineLength_ = 0;

        // Heap: HttpMaxHeaderLineBytes (8 KiB).
        char* trailerLine_ = nullptr;
        SIZE_T trailerLineLength_ = 0;
        bool trailerLineEmptyPending_ = false;

        HttpHeader* trailers_ = nullptr;
        SIZE_T trailerCapacity_ = 0;
        SIZE_T trailerCount_ = 0;

        // Heap arena for durable trailer name/value storage (4 KiB).
        char* trailerArena_ = nullptr;
        SIZE_T trailerArenaCapacity_ = 0;
        SIZE_T trailerArenaUsed_ = 0;
        bool initialized_ = false;
    };
}
}
