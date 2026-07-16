#include "sse/EventStreamParser.h"

namespace wknet
{
namespace sse
{
    namespace
    {
        constexpr SIZE_T kDefaultMaxParserBufferBytes = 256 * 1024;
        constexpr SIZE_T kDefaultMaxEventBytes = 1024 * 1024;
        constexpr SIZE_T kMinBufferBytes = 8;
        constexpr SIZE_T kUtf8BomLength = 3;

        bool StartsWithUtf8Bom(_In_reads_bytes_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length >= kUtf8BomLength &&
                data[0] == 0xEF &&
                data[1] == 0xBB &&
                data[2] == 0xBF;
        }
    }

    EventStreamParser::~EventStreamParser() noexcept
    {
        DestroyBuffers();
    }

    NTSTATUS EventStreamParser::Initialize(SIZE_T maxParserBufferBytes, SIZE_T maxEventBytes) noexcept
    {
        DestroyBuffers();
        initialized_ = false;
        sawBom_ = false;
        pendingCr_ = false;
        hasRecommendedRetry_ = false;
        recommendedRetryMilliseconds_ = 0;
        ClearCurrentEvent();

        if (maxParserBufferBytes == 0) {
            maxParserBufferBytes = kDefaultMaxParserBufferBytes;
        }
        if (maxEventBytes == 0) {
            maxEventBytes = kDefaultMaxEventBytes;
        }
        if (maxParserBufferBytes < kMinBufferBytes || maxEventBytes < kMinBufferBytes) {
            return STATUS_INVALID_PARAMETER;
        }

        maxParserBufferBytes_ = maxParserBufferBytes;
        maxEventBytes_ = maxEventBytes;

        // Start small; grow on demand. Cap initials by configured hard maxima.
        const SIZE_T initialLine = maxParserBufferBytes_ < 256 ? maxParserBufferBytes_ : 256;
        const SIZE_T initialData = maxEventBytes_ < 256 ? maxEventBytes_ : 256;
        const SIZE_T initialField = maxEventBytes_ < 64 ? maxEventBytes_ : 64;

        NTSTATUS status = EnsureCapacity(lineBuffer_, lineCapacity_, initialLine, maxParserBufferBytes_);
        if (!NT_SUCCESS(status)) {
            DestroyBuffers();
            return status;
        }
        status = EnsureCapacity(dataBuffer_, dataCapacity_, initialData, maxEventBytes_);
        if (!NT_SUCCESS(status)) {
            DestroyBuffers();
            return status;
        }
        status = EnsureCapacity(eventTypeBuffer_, eventTypeCapacity_, initialField, maxEventBytes_);
        if (!NT_SUCCESS(status)) {
            DestroyBuffers();
            return status;
        }
        status = EnsureCapacity(eventIdBuffer_, eventIdCapacity_, initialField, maxEventBytes_);
        if (!NT_SUCCESS(status)) {
            DestroyBuffers();
            return status;
        }
        status = EnsureCapacity(lastEventIdBuffer_, lastEventIdCapacity_, initialField, maxEventBytes_);
        if (!NT_SUCCESS(status)) {
            DestroyBuffers();
            return status;
        }

        lineLength_ = 0;
        dataLength_ = 0;
        eventTypeLength_ = 0;
        eventIdLength_ = 0;
        eventHasId_ = false;
        lastEventIdLength_ = 0;
        initialized_ = true;
        return STATUS_SUCCESS;
    }

    void EventStreamParser::Reset() noexcept
    {
        if (!initialized_) {
            return;
        }

        sawBom_ = false;
        pendingCr_ = false;
        lineLength_ = 0;
        hasRecommendedRetry_ = false;
        recommendedRetryMilliseconds_ = 0;
        lastEventIdLength_ = 0;
        ClearCurrentEvent();
    }

    void EventStreamParser::DestroyBuffers() noexcept
    {
        FreeNonPagedArray(lineBuffer_);
        lineBuffer_ = nullptr;
        lineLength_ = 0;
        lineCapacity_ = 0;

        FreeNonPagedArray(dataBuffer_);
        dataBuffer_ = nullptr;
        dataLength_ = 0;
        dataCapacity_ = 0;

        FreeNonPagedArray(eventTypeBuffer_);
        eventTypeBuffer_ = nullptr;
        eventTypeLength_ = 0;
        eventTypeCapacity_ = 0;

        FreeNonPagedArray(eventIdBuffer_);
        eventIdBuffer_ = nullptr;
        eventIdLength_ = 0;
        eventIdCapacity_ = 0;
        eventHasId_ = false;

        FreeNonPagedArray(lastEventIdBuffer_);
        lastEventIdBuffer_ = nullptr;
        lastEventIdLength_ = 0;
        lastEventIdCapacity_ = 0;

        initialized_ = false;
        sawBom_ = false;
        pendingCr_ = false;
        hasRecommendedRetry_ = false;
        recommendedRetryMilliseconds_ = 0;
    }

    void EventStreamParser::ClearCurrentEvent() noexcept
    {
        dataLength_ = 0;
        eventTypeLength_ = 0;
        eventIdLength_ = 0;
        eventHasId_ = false;
    }

    NTSTATUS EventStreamParser::EnsureCapacity(
        char*& buffer,
        SIZE_T& capacity,
        SIZE_T needed,
        SIZE_T hardMax) noexcept
    {
        if (needed == 0) {
            return STATUS_SUCCESS;
        }
        if (needed > hardMax) {
            return STATUS_BUFFER_OVERFLOW;
        }
        if (buffer != nullptr && capacity >= needed) {
            return STATUS_SUCCESS;
        }

        SIZE_T newCapacity = capacity == 0 ? kMinBufferBytes : capacity;
        while (newCapacity < needed) {
            if (newCapacity > hardMax / 2) {
                newCapacity = hardMax;
                break;
            }
            newCapacity *= 2;
        }
        if (newCapacity < needed) {
            newCapacity = needed;
        }
        if (newCapacity > hardMax) {
            return STATUS_BUFFER_OVERFLOW;
        }

        char* grown = AllocateNonPagedArray<char>(newCapacity);
        if (grown == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (buffer != nullptr && capacity != 0) {
            RtlCopyMemory(grown, buffer, capacity);
            FreeNonPagedArray(buffer);
        }
        buffer = grown;
        capacity = newCapacity;
        return STATUS_SUCCESS;
    }

    NTSTATUS EventStreamParser::AppendBytes(
        char*& buffer,
        SIZE_T& length,
        SIZE_T& capacity,
        const char* append,
        SIZE_T appendLength,
        SIZE_T hardMax) noexcept
    {
        if (appendLength == 0) {
            return STATUS_SUCCESS;
        }
        if (append == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (length > hardMax || appendLength > hardMax - length) {
            return STATUS_BUFFER_OVERFLOW;
        }

        const SIZE_T needed = length + appendLength;
        NTSTATUS status = EnsureCapacity(buffer, capacity, needed, hardMax);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlCopyMemory(buffer + length, append, appendLength);
        length = needed;
        return STATUS_SUCCESS;
    }

    bool EventStreamParser::IsAllAsciiDigits(const char* text, SIZE_T length) noexcept
    {
        if (text == nullptr || length == 0) {
            return false;
        }
        for (SIZE_T index = 0; index < length; ++index) {
            const char ch = text[index];
            if (ch < '0' || ch > '9') {
                return false;
            }
        }
        return true;
    }

    bool EventStreamParser::ContainsNull(const char* text, SIZE_T length) noexcept
    {
        if (text == nullptr) {
            return false;
        }
        for (SIZE_T index = 0; index < length; ++index) {
            if (text[index] == '\0') {
                return true;
            }
        }
        return false;
    }

    bool EventStreamParser::FieldNameEquals(
        const char* name,
        SIZE_T nameLength,
        const char* literal) noexcept
    {
        if (name == nullptr || literal == nullptr) {
            return false;
        }
        SIZE_T literalLength = 0;
        while (literal[literalLength] != '\0') {
            ++literalLength;
        }
        if (nameLength != literalLength) {
            return false;
        }
        for (SIZE_T index = 0; index < nameLength; ++index) {
            if (name[index] != literal[index]) {
                return false;
            }
        }
        return true;
    }

    NTSTATUS EventStreamParser::DispatchEvent(
        EventStreamEventCallback onEvent,
        void* context) noexcept
    {
        // Empty event (no data fields) is discarded without dispatch.
        if (dataLength_ == 0 && !eventHasId_ && eventTypeLength_ == 0) {
            ClearCurrentEvent();
            return STATUS_SUCCESS;
        }

        // If the event has only type/id and no data, still dispatch (data empty).
        // WHATWG: if data buffer is empty, fire no event — except we still update
        // lastEventId when id was set. Handle id update first.
        if (eventHasId_) {
            // id containing U+0000 is ignored for Last-Event-ID update.
            if (!ContainsNull(eventIdBuffer_, eventIdLength_)) {
                NTSTATUS status = EnsureCapacity(
                    lastEventIdBuffer_,
                    lastEventIdCapacity_,
                    eventIdLength_ == 0 ? 1 : eventIdLength_,
                    maxEventBytes_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (eventIdLength_ != 0) {
                    RtlCopyMemory(lastEventIdBuffer_, eventIdBuffer_, eventIdLength_);
                }
                lastEventIdLength_ = eventIdLength_;
            }
        }

        if (dataLength_ == 0) {
            ClearCurrentEvent();
            return STATUS_SUCCESS;
        }

        // Strip one trailing U+000A that was introduced by data field joining.
        // Spec: "If the data buffer's last character is a U+000A LINE FEED, then
        // remove the last character from the data buffer." — joining always adds
        // LF after each data line, so a final LF is always present when data
        // is non-empty.
        SIZE_T dispatchDataLength = dataLength_;
        if (dispatchDataLength != 0 && dataBuffer_[dispatchDataLength - 1] == '\n') {
            --dispatchDataLength;
        }

        EventStreamEventView view = {};
        if (eventTypeLength_ == 0) {
            view.Type = messageTypeLiteral_;
            view.TypeLength = 7;
        }
        else {
            view.Type = eventTypeBuffer_;
            view.TypeLength = eventTypeLength_;
        }
        view.Data = dataBuffer_;
        view.DataLength = dispatchDataLength;
        view.HasId = eventHasId_ && !ContainsNull(eventIdBuffer_, eventIdLength_);
        if (view.HasId) {
            view.Id = lastEventIdBuffer_;
            view.IdLength = lastEventIdLength_;
        }
        view.HasRetry = false;
        view.RetryMilliseconds = 0;

        NTSTATUS status = STATUS_SUCCESS;
        if (onEvent != nullptr) {
            status = onEvent(context, &view);
        }

        ClearCurrentEvent();
        return status;
    }

    NTSTATUS EventStreamParser::ProcessLine(
        const char* line,
        SIZE_T lineLength,
        EventStreamEventCallback onEvent,
        void* context) noexcept
    {
        if (line == nullptr && lineLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        // Blank line → dispatch.
        if (lineLength == 0) {
            return DispatchEvent(onEvent, context);
        }

        // Comment: lines starting with ':' are ignored.
        if (line[0] == ':') {
            return STATUS_SUCCESS;
        }

        SIZE_T colon = lineLength;
        for (SIZE_T index = 0; index < lineLength; ++index) {
            if (line[index] == ':') {
                colon = index;
                break;
            }
        }

        const char* fieldName = line;
        SIZE_T fieldNameLength = colon == lineLength ? lineLength : colon;
        const char* fieldValue = nullptr;
        SIZE_T fieldValueLength = 0;
        if (colon < lineLength) {
            fieldValue = line + colon + 1;
            fieldValueLength = lineLength - colon - 1;
            // Optional single leading U+0020 SPACE after colon is stripped.
            if (fieldValueLength != 0 && fieldValue[0] == ' ') {
                ++fieldValue;
                --fieldValueLength;
            }
        }
        else {
            fieldValue = line + lineLength;
            fieldValueLength = 0;
        }

        if (FieldNameEquals(fieldName, fieldNameLength, "data")) {
            // Append value + LF.
            NTSTATUS status = AppendBytes(
                dataBuffer_,
                dataLength_,
                dataCapacity_,
                fieldValue,
                fieldValueLength,
                maxEventBytes_);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            const char lf = '\n';
            return AppendBytes(
                dataBuffer_,
                dataLength_,
                dataCapacity_,
                &lf,
                1,
                maxEventBytes_);
        }

        if (FieldNameEquals(fieldName, fieldNameLength, "event")) {
            NTSTATUS status = EnsureCapacity(
                eventTypeBuffer_,
                eventTypeCapacity_,
                fieldValueLength == 0 ? 1 : fieldValueLength,
                maxEventBytes_);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (fieldValueLength != 0) {
                RtlCopyMemory(eventTypeBuffer_, fieldValue, fieldValueLength);
            }
            eventTypeLength_ = fieldValueLength;
            return STATUS_SUCCESS;
        }

        if (FieldNameEquals(fieldName, fieldNameLength, "id")) {
            // Spec: if value contains U+0000, ignore the field for lastEventId,
            // but the field was still "seen". We store and mark HasId; Dispatch
            // skips Last-Event-ID update when null is present.
            NTSTATUS status = EnsureCapacity(
                eventIdBuffer_,
                eventIdCapacity_,
                fieldValueLength == 0 ? 1 : fieldValueLength,
                maxEventBytes_);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (fieldValueLength != 0) {
                RtlCopyMemory(eventIdBuffer_, fieldValue, fieldValueLength);
            }
            eventIdLength_ = fieldValueLength;
            eventHasId_ = true;
            return STATUS_SUCCESS;
        }

        if (FieldNameEquals(fieldName, fieldNameLength, "retry")) {
            if (!IsAllAsciiDigits(fieldValue, fieldValueLength)) {
                // Ignore invalid retry fields.
                return STATUS_SUCCESS;
            }

            ULONGLONG value = 0;
            for (SIZE_T index = 0; index < fieldValueLength; ++index) {
                const ULONGLONG digit = static_cast<ULONGLONG>(fieldValue[index] - '0');
                if (value > (static_cast<ULONGLONG>(MAXULONG) - digit) / 10ULL) {
                    // Overflow → ignore.
                    return STATUS_SUCCESS;
                }
                value = value * 10ULL + digit;
            }

            hasRecommendedRetry_ = true;
            recommendedRetryMilliseconds_ = static_cast<ULONG>(value);
            return STATUS_SUCCESS;
        }

        // Unknown field names are ignored.
        return STATUS_SUCCESS;
    }

    NTSTATUS EventStreamParser::ProcessBufferedLines(
        EventStreamEventCallback onEvent,
        void* context) noexcept
    {
        SIZE_T offset = 0;
        while (offset < lineLength_) {
            SIZE_T lineStart = offset;
            SIZE_T lineEnd = lineLength_;
            LineEnd endKind = LineEnd::None;

            for (SIZE_T index = offset; index < lineLength_; ++index) {
                const char ch = lineBuffer_[index];
                if (ch == '\n') {
                    lineEnd = index;
                    endKind = LineEnd::Lf;
                    break;
                }
                if (ch == '\r') {
                    if (index + 1 < lineLength_ && lineBuffer_[index + 1] == '\n') {
                        lineEnd = index;
                        endKind = LineEnd::CrLf;
                    }
                    else if (index + 1 < lineLength_) {
                        // Bare CR followed by non-LF is a line end.
                        lineEnd = index;
                        endKind = LineEnd::Cr;
                    }
                    else {
                        // CR at end of buffer: wait for more data (may be CRLF).
                        // Keep pending in buffer.
                        if (lineStart != 0) {
                            const SIZE_T remaining = lineLength_ - lineStart;
                            RtlMoveMemory(lineBuffer_, lineBuffer_ + lineStart, remaining);
                            lineLength_ = remaining;
                        }
                        return STATUS_SUCCESS;
                    }
                    break;
                }
            }

            if (endKind == LineEnd::None) {
                // Incomplete line — compact buffer.
                if (lineStart != 0) {
                    const SIZE_T remaining = lineLength_ - lineStart;
                    RtlMoveMemory(lineBuffer_, lineBuffer_ + lineStart, remaining);
                    lineLength_ = remaining;
                }
                return STATUS_SUCCESS;
            }

            const SIZE_T thisLineLength = lineEnd - lineStart;
            NTSTATUS status = ProcessLine(
                lineBuffer_ + lineStart,
                thisLineLength,
                onEvent,
                context);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            offset = lineEnd + (endKind == LineEnd::CrLf ? 2 : 1);
        }

        lineLength_ = 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS EventStreamParser::Feed(
        const UCHAR* data,
        SIZE_T dataLength,
        EventStreamEventCallback onEvent,
        void* context) noexcept
    {
        if (!initialized_) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (dataLength == 0) {
            return STATUS_SUCCESS;
        }
        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T offset = 0;
        if (!sawBom_ && StartsWithUtf8Bom(data, dataLength)) {
            sawBom_ = true;
            offset = kUtf8BomLength;
            if (offset == dataLength) {
                return STATUS_SUCCESS;
            }
        }
        else {
            sawBom_ = true; // only check at stream start
        }

        // Handle pending CR from previous feed that may complete CRLF.
        if (pendingCr_) {
            pendingCr_ = false;
            if (data[offset] == '\n') {
                // Complete CRLF: process empty separator relative to prior line end.
                // The prior CR already ended a line when we deferred — actually we
                // deferred because CR was last byte. Treat as line ending now.
                // The line content is already in lineBuffer_ without the CR.
                NTSTATUS status = ProcessLine(
                    lineBuffer_,
                    lineLength_,
                    onEvent,
                    context);
                lineLength_ = 0;
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                ++offset;
                if (offset == dataLength) {
                    return STATUS_SUCCESS;
                }
            }
            else {
                // Bare CR was a line ending.
                NTSTATUS status = ProcessLine(
                    lineBuffer_,
                    lineLength_,
                    onEvent,
                    context);
                lineLength_ = 0;
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                // fall through to process current byte
            }
        }

        // Append remaining bytes to line buffer and process complete lines.
        const SIZE_T remaining = dataLength - offset;
        if (remaining != 0) {
            // Fast path: if last byte is CR, defer it for CRLF handling.
            SIZE_T appendLength = remaining;
            bool endsWithCr = false;
            if (data[dataLength - 1] == '\r') {
                endsWithCr = true;
                --appendLength;
            }

            if (appendLength != 0) {
                NTSTATUS status = AppendBytes(
                    lineBuffer_,
                    lineLength_,
                    lineCapacity_,
                    reinterpret_cast<const char*>(data + offset),
                    appendLength,
                    maxParserBufferBytes_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            NTSTATUS status = ProcessBufferedLines(onEvent, context);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (endsWithCr) {
                // Defer CR: if lineBuffer has content, CR ends it; wait to see if LF follows.
                pendingCr_ = true;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS EventStreamParser::Finish(
        EventStreamEventCallback onEvent,
        void* context) noexcept
    {
        if (!initialized_) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (pendingCr_) {
            pendingCr_ = false;
            NTSTATUS status = ProcessLine(lineBuffer_, lineLength_, onEvent, context);
            lineLength_ = 0;
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        // Spec: incomplete trailing event is discarded — do not dispatch.
        // Remaining partial line without a terminator is also discarded.
        UNREFERENCED_PARAMETER(onEvent);
        UNREFERENCED_PARAMETER(context);
        lineLength_ = 0;
        ClearCurrentEvent();
        return STATUS_SUCCESS;
    }

    const char* EventStreamParser::LastEventId() const noexcept
    {
        if (!initialized_ || lastEventIdLength_ == 0) {
            return nullptr;
        }
        return lastEventIdBuffer_;
    }

    SIZE_T EventStreamParser::LastEventIdLength() const noexcept
    {
        return initialized_ ? lastEventIdLength_ : 0;
    }

    bool EventStreamParser::HasRecommendedRetry() const noexcept
    {
        return initialized_ && hasRecommendedRetry_;
    }

    ULONG EventStreamParser::RecommendedRetryMilliseconds() const noexcept
    {
        return (initialized_ && hasRecommendedRetry_) ? recommendedRetryMilliseconds_ : 0;
    }
}
}
