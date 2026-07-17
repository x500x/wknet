#include "http1/HttpChunkedDecoder.h"

namespace wknet
{
namespace http1
{
    namespace
    {
        bool IsHexDigit(char value) noexcept
        {
            return (value >= '0' && value <= '9') ||
                (value >= 'a' && value <= 'f') ||
                (value >= 'A' && value <= 'F');
        }

        UCHAR HexValue(char value) noexcept
        {
            if (value >= '0' && value <= '9') {
                return static_cast<UCHAR>(value - '0');
            }
            if (value >= 'a' && value <= 'f') {
                return static_cast<UCHAR>(10 + value - 'a');
            }
            return static_cast<UCHAR>(10 + value - 'A');
        }

        bool IsTchar(char value) noexcept
        {
            const unsigned char ch = static_cast<unsigned char>(value);
            return (ch >= '0' && ch <= '9') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= 'a' && ch <= 'z') ||
                value == '!' || value == '#' || value == '$' || value == '%' ||
                value == '&' || value == '\'' || value == '*' || value == '+' ||
                value == '-' || value == '.' || value == '^' || value == '_' ||
                value == '`' || value == '|' || value == '~';
        }
    }

    HttpChunkedDecoder::HttpChunkedDecoder() noexcept = default;

    HttpChunkedDecoder::~HttpChunkedDecoder() noexcept
    {
        ::wknet::FreeNonPagedArray(trailerLine_);
        trailerLine_ = nullptr;
        ::wknet::FreeNonPagedArray(trailerArena_);
        trailerArena_ = nullptr;
        trailerArenaCapacity_ = 0;
        initialized_ = false;
    }

    NTSTATUS HttpChunkedDecoder::Initialize() noexcept
    {
        if (initialized_) {
            return STATUS_SUCCESS;
        }
        trailerLine_ = ::wknet::AllocateNonPagedArray<char>(HttpMaxHeaderLineBytes);
        trailerArena_ = ::wknet::AllocateNonPagedArray<char>(4096);
        if (trailerLine_ == nullptr || trailerArena_ == nullptr) {
            ::wknet::FreeNonPagedArray(trailerLine_);
            trailerLine_ = nullptr;
            ::wknet::FreeNonPagedArray(trailerArena_);
            trailerArena_ = nullptr;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        trailerArenaCapacity_ = 4096;
        initialized_ = true;
        return STATUS_SUCCESS;
    }

    void HttpChunkedDecoder::Reset() noexcept
    {
        state_ = State::SizeLine;
        chunkRemaining_ = 0;
        sawChunkExtension_ = false;
        sizeLineHasDigit_ = false;
        sizeLineLength_ = 0;
        trailerLineLength_ = 0;
        trailerLineEmptyPending_ = false;
        trailerCount_ = 0;
        trailerArenaUsed_ = 0;
        // Keep trailer storage pointers and heap buffers; caller owns trailers_.
    }

    void HttpChunkedDecoder::SetTrailerStorage(
        HttpHeader* trailers,
        SIZE_T trailerCapacity) noexcept
    {
        trailers_ = trailers;
        trailerCapacity_ = trailerCapacity;
        trailerCount_ = 0;
        trailerArenaUsed_ = 0;
    }

    NTSTATUS HttpChunkedDecoder::FinishSizeLine() noexcept
    {
        if (!sizeLineHasDigit_) {
            state_ = State::Failed;
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T size = 0;
        for (SIZE_T index = 0; index < sizeLineLength_; ++index) {
            const char ch = sizeLine_[index];
            if (!IsHexDigit(ch)) {
                state_ = State::Failed;
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const SIZE_T digit = HexValue(ch);
            if (size > ((static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - digit) / 16)) {
                state_ = State::Failed;
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            size = (size * 16) + digit;
        }

        chunkRemaining_ = size;
        sizeLineLength_ = 0;
        sizeLineHasDigit_ = false;
        sawChunkExtension_ = false;

        if (chunkRemaining_ == 0) {
            state_ = State::TrailerLine;
            trailerLineLength_ = 0;
            return STATUS_SUCCESS;
        }

        state_ = State::ChunkData;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpChunkedDecoder::ProcessSizeLineChar(char ch) noexcept
    {
        if (ch == '\r') {
            // Wait for LF via size line terminator handled in Feed.
            return STATUS_SUCCESS;
        }
        if (ch == '\n') {
            return FinishSizeLine();
        }

        if (sawChunkExtension_) {
            // Extensions ignored; still bounded.
            if (sizeLineLength_ >= HttpMaxChunkSizeLineBytes) {
                // Extension part can be long; we only stored size digits already.
                return STATUS_SUCCESS;
            }
            return STATUS_SUCCESS;
        }

        if (ch == ';') {
            if (!sizeLineHasDigit_) {
                state_ = State::Failed;
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            sawChunkExtension_ = true;
            return STATUS_SUCCESS;
        }

        if (!IsHexDigit(ch)) {
            state_ = State::Failed;
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (sizeLineLength_ >= HttpMaxChunkSizeLineBytes) {
            state_ = State::Failed;
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        sizeLine_[sizeLineLength_++] = ch;
        sizeLineHasDigit_ = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpChunkedDecoder::FinishTrailerLine() noexcept
    {
        if (trailerLineLength_ == 0) {
            state_ = State::Complete;
            return STATUS_SUCCESS;
        }

        // Parse "name: value"
        SIZE_T colon = trailerLineLength_;
        for (SIZE_T index = 0; index < trailerLineLength_; ++index) {
            if (trailerLine_[index] == ':') {
                colon = index;
                break;
            }
        }
        if (colon == 0 || colon == trailerLineLength_) {
            state_ = State::Failed;
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        for (SIZE_T index = 0; index < colon; ++index) {
            if (!IsTchar(trailerLine_[index])) {
                state_ = State::Failed;
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        SIZE_T valueStart = colon + 1;
        while (valueStart < trailerLineLength_ &&
            (trailerLine_[valueStart] == ' ' || trailerLine_[valueStart] == '\t')) {
            ++valueStart;
        }
        SIZE_T valueEnd = trailerLineLength_;
        while (valueEnd > valueStart &&
            (trailerLine_[valueEnd - 1] == ' ' || trailerLine_[valueEnd - 1] == '\t')) {
            --valueEnd;
        }

        const SIZE_T nameLength = colon;
        const SIZE_T valueLength = valueEnd - valueStart;
        const SIZE_T needed = nameLength + valueLength;
        if (trailerLine_ == nullptr || trailerArena_ == nullptr ||
            needed > trailerArenaCapacity_ - trailerArenaUsed_) {
            state_ = State::Failed;
            return STATUS_BUFFER_OVERFLOW;
        }
        if (trailers_ == nullptr || trailerCount_ >= trailerCapacity_) {
            state_ = State::Failed;
            return STATUS_BUFFER_TOO_SMALL;
        }

        char* nameDst = trailerArena_ + trailerArenaUsed_;
        RtlCopyMemory(nameDst, trailerLine_, nameLength);
        trailerArenaUsed_ += nameLength;
        char* valueDst = trailerArena_ + trailerArenaUsed_;
        if (valueLength != 0) {
            RtlCopyMemory(valueDst, trailerLine_ + valueStart, valueLength);
            trailerArenaUsed_ += valueLength;
        }

        trailers_[trailerCount_].Name.Data = nameDst;
        trailers_[trailerCount_].Name.Length = nameLength;
        trailers_[trailerCount_].Value.Data = valueLength == 0 ? nullptr : valueDst;
        trailers_[trailerCount_].Value.Length = valueLength;
        ++trailerCount_;

        trailerLineLength_ = 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpChunkedDecoder::ProcessTrailerLineChar(char ch) noexcept
    {
        if (ch == '\n') {
            return FinishTrailerLine();
        }
        if (ch == '\r') {
            return STATUS_SUCCESS;
        }
        if (trailerLine_ == nullptr || trailerLineLength_ >= HttpMaxHeaderLineBytes) {
            state_ = State::Failed;
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        trailerLine_[trailerLineLength_++] = ch;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpChunkedDecoder::Feed(
        const char* data,
        SIZE_T dataLength,
        SIZE_T* bytesConsumed,
        DataCallback onData,
        void* context) noexcept
    {
        if (bytesConsumed == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *bytesConsumed = 0;
        if (!initialized_ || trailerLine_ == nullptr || trailerArena_ == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (state_ == State::Complete) {
            return STATUS_SUCCESS;
        }
        if (state_ == State::Failed) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (dataLength == 0) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }
        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T offset = 0;
        while (offset < dataLength) {
            switch (state_) {
            case State::SizeLine: {
                const char ch = data[offset++];
                NTSTATUS status = ProcessSizeLineChar(ch);
                if (!NT_SUCCESS(status)) {
                    *bytesConsumed = offset;
                    return status;
                }
                // ProcessSizeLineChar on '\n' transitions state.
                break;
            }
            case State::ChunkData: {
                const SIZE_T available = dataLength - offset;
                const SIZE_T take = available < chunkRemaining_ ? available : chunkRemaining_;
                if (take != 0) {
                    if (onData != nullptr) {
                        NTSTATUS status = onData(
                            context,
                            reinterpret_cast<const UCHAR*>(data + offset),
                            take);
                        if (!NT_SUCCESS(status)) {
                            state_ = State::Failed;
                            *bytesConsumed = offset;
                            return status;
                        }
                    }
                    offset += take;
                    chunkRemaining_ -= take;
                }
                if (chunkRemaining_ == 0) {
                    state_ = State::ChunkDataCr;
                }
                break;
            }
            case State::ChunkDataCr: {
                const char ch = data[offset++];
                if (ch != '\r') {
                    state_ = State::Failed;
                    *bytesConsumed = offset;
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                state_ = State::ChunkDataLf;
                break;
            }
            case State::ChunkDataLf: {
                const char ch = data[offset++];
                if (ch != '\n') {
                    state_ = State::Failed;
                    *bytesConsumed = offset;
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                state_ = State::SizeLine;
                sizeLineLength_ = 0;
                sizeLineHasDigit_ = false;
                sawChunkExtension_ = false;
                break;
            }
            case State::TrailerLine: {
                const char ch = data[offset++];
                NTSTATUS status = ProcessTrailerLineChar(ch);
                if (!NT_SUCCESS(status)) {
                    *bytesConsumed = offset;
                    return status;
                }
                if (state_ == State::Complete) {
                    *bytesConsumed = offset;
                    return STATUS_SUCCESS;
                }
                break;
            }
            case State::Complete:
                *bytesConsumed = offset;
                return STATUS_SUCCESS;
            case State::Failed:
            default:
                *bytesConsumed = offset;
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        *bytesConsumed = offset;
        return state_ == State::Complete ? STATUS_SUCCESS : STATUS_MORE_PROCESSING_REQUIRED;
    }
}
}
