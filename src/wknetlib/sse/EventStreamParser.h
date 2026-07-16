#pragma once

#include <wknet/WknetConfig.h>

namespace wknet
{
namespace sse
{
    // View of one dispatched Server-Sent Event (WHATWG HTML event-stream).
    // Pointers remain valid until the next successful Feed/Finish that produces
    // another event, or until Reset/destruction.
    struct EventStreamEventView final
    {
        const char* Type = nullptr;
        SIZE_T TypeLength = 0;
        const char* Data = nullptr;
        SIZE_T DataLength = 0;
        // Present when this event carried an id: field (value may be empty).
        bool HasId = false;
        const char* Id = nullptr;
        SIZE_T IdLength = 0;
        bool HasRetry = false;
        ULONG RetryMilliseconds = 0;
    };

    typedef NTSTATUS (*EventStreamEventCallback)(
        _In_opt_ void* context,
        _In_ const EventStreamEventView* event);

    // Incremental WHATWG event-stream parser. Network-agnostic; caller feeds
    // application-body bytes (post transfer-coding). Incomplete trailing events
    // are discarded on Finish (per spec).
    class EventStreamParser final
    {
    public:
        EventStreamParser() noexcept = default;
        ~EventStreamParser() noexcept;

        EventStreamParser(const EventStreamParser&) = delete;
        EventStreamParser& operator=(const EventStreamParser&) = delete;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxParserBufferBytes, SIZE_T maxEventBytes) noexcept;

        void Reset() noexcept;

        // Feed stream bytes. Invokes onEvent for each complete event (blank-line
        // terminated). onEvent may be null to only update Last-Event-ID / retry
        // side state (events are still fully parsed and discarded).
        _Must_inspect_result_
        NTSTATUS Feed(
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _In_opt_ EventStreamEventCallback onEvent,
            _In_opt_ void* context) noexcept;

        // End of body. Does not dispatch a partial event.
        _Must_inspect_result_
        NTSTATUS Finish(
            _In_opt_ EventStreamEventCallback onEvent,
            _In_opt_ void* context) noexcept;

        _Must_inspect_result_
        const char* LastEventId() const noexcept;

        _Must_inspect_result_
        SIZE_T LastEventIdLength() const noexcept;

        _Must_inspect_result_
        bool HasRecommendedRetry() const noexcept;

        _Must_inspect_result_
        ULONG RecommendedRetryMilliseconds() const noexcept;

        _Must_inspect_result_
        bool IsInitialized() const noexcept
        {
            return initialized_;
        }

    private:
        enum class LineEnd : UCHAR
        {
            None = 0,
            Lf = 1,
            Cr = 2,
            CrLf = 3
        };

        void ClearCurrentEvent() noexcept;
        void DestroyBuffers() noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureCapacity(
            _Inout_ char*& buffer,
            _Inout_ SIZE_T& capacity,
            SIZE_T needed,
            SIZE_T hardMax) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendBytes(
            _Inout_ char*& buffer,
            _Inout_ SIZE_T& length,
            _Inout_ SIZE_T& capacity,
            _In_reads_bytes_(appendLength) const char* append,
            SIZE_T appendLength,
            SIZE_T hardMax) noexcept;

        _Must_inspect_result_
        NTSTATUS ProcessLine(
            _In_reads_bytes_(lineLength) const char* line,
            SIZE_T lineLength,
            _In_opt_ EventStreamEventCallback onEvent,
            _In_opt_ void* context) noexcept;

        _Must_inspect_result_
        NTSTATUS DispatchEvent(
            _In_opt_ EventStreamEventCallback onEvent,
            _In_opt_ void* context) noexcept;

        _Must_inspect_result_
        NTSTATUS ProcessBufferedLines(
            _In_opt_ EventStreamEventCallback onEvent,
            _In_opt_ void* context) noexcept;

        static bool IsAllAsciiDigits(
            _In_reads_bytes_(length) const char* text,
            SIZE_T length) noexcept;

        static bool ContainsNull(
            _In_reads_bytes_(length) const char* text,
            SIZE_T length) noexcept;

        static bool FieldNameEquals(
            _In_reads_bytes_(nameLength) const char* name,
            SIZE_T nameLength,
            _In_z_ const char* literal) noexcept;

        bool initialized_ = false;
        bool sawBom_ = false;
        bool pendingCr_ = false;

        SIZE_T maxParserBufferBytes_ = 0;
        SIZE_T maxEventBytes_ = 0;

        char* lineBuffer_ = nullptr;
        SIZE_T lineLength_ = 0;
        SIZE_T lineCapacity_ = 0;

        char* dataBuffer_ = nullptr;
        SIZE_T dataLength_ = 0;
        SIZE_T dataCapacity_ = 0;

        char* eventTypeBuffer_ = nullptr;
        SIZE_T eventTypeLength_ = 0;
        SIZE_T eventTypeCapacity_ = 0;

        char* eventIdBuffer_ = nullptr;
        SIZE_T eventIdLength_ = 0;
        SIZE_T eventIdCapacity_ = 0;
        bool eventHasId_ = false;

        char* lastEventIdBuffer_ = nullptr;
        SIZE_T lastEventIdLength_ = 0;
        SIZE_T lastEventIdCapacity_ = 0;

        bool hasRecommendedRetry_ = false;
        ULONG recommendedRetryMilliseconds_ = 0;

        // Last dispatched event view storage (type defaults to "message").
        char messageTypeLiteral_[8] = { 'm', 'e', 's', 's', 'a', 'g', 'e', 0 };
    };
}
}
