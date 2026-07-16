#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "sse/EventStreamParser.h"

#include <stdio.h>
#include <string.h>

using wknet::sse::EventStreamEventView;
using wknet::sse::EventStreamParser;

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message)
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    struct CapturedEvent
    {
        char Type[64];
        SIZE_T TypeLength;
        char Data[1024];
        SIZE_T DataLength;
        bool HasId;
        char Id[256];
        SIZE_T IdLength;
    };

    struct CaptureState
    {
        CapturedEvent Events[16];
        SIZE_T Count;
        NTSTATUS ForceStatus;
    };

    void ClearCapture(CaptureState* state)
    {
        state->Count = 0;
        state->ForceStatus = STATUS_SUCCESS;
        RtlZeroMemory(state->Events, sizeof(state->Events));
    }

    NTSTATUS CaptureEvent(void* context, const EventStreamEventView* event)
    {
        auto* state = static_cast<CaptureState*>(context);
        if (state == nullptr || event == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(state->ForceStatus)) {
            return state->ForceStatus;
        }
        if (state->Count >= 16) {
            return STATUS_BUFFER_OVERFLOW;
        }

        CapturedEvent& slot = state->Events[state->Count++];
        slot.TypeLength = event->TypeLength < sizeof(slot.Type) ? event->TypeLength : sizeof(slot.Type) - 1;
        if (event->Type != nullptr && slot.TypeLength != 0) {
            RtlCopyMemory(slot.Type, event->Type, slot.TypeLength);
        }
        slot.Type[slot.TypeLength] = 0;

        slot.DataLength = event->DataLength < sizeof(slot.Data) ? event->DataLength : sizeof(slot.Data) - 1;
        if (event->Data != nullptr && slot.DataLength != 0) {
            RtlCopyMemory(slot.Data, event->Data, slot.DataLength);
        }
        slot.Data[slot.DataLength] = 0;

        slot.HasId = event->HasId;
        slot.IdLength = 0;
        slot.Id[0] = 0;
        if (event->HasId) {
            slot.IdLength = event->IdLength < sizeof(slot.Id) ? event->IdLength : sizeof(slot.Id) - 1;
            if (event->Id != nullptr && slot.IdLength != 0) {
                RtlCopyMemory(slot.Id, event->Id, slot.IdLength);
            }
            slot.Id[slot.IdLength] = 0;
        }
        return STATUS_SUCCESS;
    }

    void FeedAll(EventStreamParser& parser, const char* text, CaptureState* capture)
    {
        const NTSTATUS status = parser.Feed(
            reinterpret_cast<const UCHAR*>(text),
            strlen(text),
            CaptureEvent,
            capture);
        Expect(NT_SUCCESS(status), "Feed succeeds");
    }

    void TestSimpleMessage()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser, "data: hello\n\n", &capture);
        Expect(capture.Count == 1, "one event");
        Expect(strcmp(capture.Events[0].Type, "message") == 0, "default type message");
        Expect(strcmp(capture.Events[0].Data, "hello") == 0, "data hello");
        Expect(!capture.Events[0].HasId, "no id");
    }

    void TestMultilineDataAndEventType()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser,
            "event: update\n"
            "data: line1\n"
            "data: line2\n"
            "\n",
            &capture);
        Expect(capture.Count == 1, "one event");
        Expect(strcmp(capture.Events[0].Type, "update") == 0, "event type");
        Expect(strcmp(capture.Events[0].Data, "line1\nline2") == 0, "joined data");
    }

    void TestIdAndRetry()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser,
            "id: 42\n"
            "retry: 1500\n"
            "data: x\n"
            "\n",
            &capture);
        Expect(capture.Count == 1, "one event");
        Expect(capture.Events[0].HasId, "has id");
        Expect(strcmp(capture.Events[0].Id, "42") == 0, "id 42");
        Expect(parser.LastEventIdLength() == 2, "last id len");
        Expect(parser.LastEventId() != nullptr && memcmp(parser.LastEventId(), "42", 2) == 0, "last id");
        Expect(parser.HasRecommendedRetry(), "has retry");
        Expect(parser.RecommendedRetryMilliseconds() == 1500, "retry 1500");
    }

    void TestIdOnlyDoesNotDispatch()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser, "id: only\n\n", &capture);
        Expect(capture.Count == 0, "no event without data");
        Expect(parser.LastEventIdLength() == 4, "last id updated");
        Expect(parser.LastEventId() != nullptr && memcmp(parser.LastEventId(), "only", 4) == 0, "last id only");
    }

    void TestCommentsAndUnknownFields()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser,
            ": keep-alive\n"
            "foo: bar\n"
            "data: ok\n"
            "\n",
            &capture);
        Expect(capture.Count == 1, "one event");
        Expect(strcmp(capture.Events[0].Data, "ok") == 0, "data ok");
    }

    void TestCrlfAndSplitFeeds()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        const char* parts[] = {
            "da",
            "ta: he",
            "llo\r",
            "\n\r\n"
        };
        for (SIZE_T index = 0; index < 4; ++index) {
            const NTSTATUS status = parser.Feed(
                reinterpret_cast<const UCHAR*>(parts[index]),
                strlen(parts[index]),
                CaptureEvent,
                &capture);
            Expect(NT_SUCCESS(status), "split feed ok");
        }
        Expect(capture.Count == 1, "one event from splits");
        Expect(strcmp(capture.Events[0].Data, "hello") == 0, "split data");
    }

    void TestBomStrippedOnce()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        const UCHAR payload[] = {
            0xEF, 0xBB, 0xBF,
            'd', 'a', 't', 'a', ':', ' ', 'b', 'o', 'm', '\n', '\n'
        };
        const NTSTATUS status = parser.Feed(payload, sizeof(payload), CaptureEvent, &capture);
        Expect(NT_SUCCESS(status), "bom feed");
        Expect(capture.Count == 1, "one event after bom");
        Expect(strcmp(capture.Events[0].Data, "bom") == 0, "bom data");
    }

    void TestInvalidRetryIgnored()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser,
            "retry: 12x\n"
            "data: a\n"
            "\n"
            "retry: 9\n"
            "data: b\n"
            "\n",
            &capture);
        Expect(capture.Count == 2, "two events");
        Expect(parser.HasRecommendedRetry(), "retry set");
        Expect(parser.RecommendedRetryMilliseconds() == 9, "valid retry wins");
    }

    void TestEmptyIdClearsLastEventId()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser, "id: abc\ndata: 1\n\n", &capture);
        Expect(parser.LastEventIdLength() == 3, "id abc");

        FeedAll(parser, "id:\ndata: 2\n\n", &capture);
        Expect(parser.LastEventIdLength() == 0, "empty id clears");
        Expect(capture.Count == 2, "two events");
    }

    void TestSpaceAfterColon()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        // One space after colon stripped; two spaces leave one.
        FeedAll(parser, "data:  x\n\n", &capture);
        Expect(capture.Count == 1, "one event");
        Expect(strcmp(capture.Events[0].Data, " x") == 0, "one leading space kept");
    }

    void TestMaxEventOverflow()
    {
        EventStreamParser parser;
        // maxEventBytes=16: "0123456789abcdef" (16) + joining LF overflows.
        Expect(NT_SUCCESS(parser.Initialize(256, 16)), "Initialize small");
        CaptureState capture = {};
        ClearCapture(&capture);

        const NTSTATUS status = parser.Feed(
            reinterpret_cast<const UCHAR*>("data: 0123456789abcdef\n\n"),
            strlen("data: 0123456789abcdef\n\n"),
            CaptureEvent,
            &capture);
        Expect(status == STATUS_BUFFER_OVERFLOW, "event overflow");
    }

    void TestFinishDiscardsPartial()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser, "data: partial", &capture);
        Expect(capture.Count == 0, "no event yet");
        Expect(NT_SUCCESS(parser.Finish(CaptureEvent, &capture)), "finish");
        Expect(capture.Count == 0, "partial discarded");
    }

    void TestMultipleEvents()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);

        FeedAll(parser,
            "data: one\n\n"
            "data: two\n\n"
            "event: ping\ndata: three\n\n",
            &capture);
        Expect(capture.Count == 3, "three events");
        Expect(strcmp(capture.Events[0].Data, "one") == 0, "e1");
        Expect(strcmp(capture.Events[1].Data, "two") == 0, "e2");
        Expect(strcmp(capture.Events[2].Type, "ping") == 0, "e3 type");
        Expect(strcmp(capture.Events[2].Data, "three") == 0, "e3 data");
    }

    void TestCallbackFailureAborts()
    {
        EventStreamParser parser;
        Expect(NT_SUCCESS(parser.Initialize(4096, 4096)), "Initialize");
        CaptureState capture = {};
        ClearCapture(&capture);
        capture.ForceStatus = STATUS_CANCELLED;

        const NTSTATUS status = parser.Feed(
            reinterpret_cast<const UCHAR*>("data: x\n\n"),
            9,
            CaptureEvent,
            &capture);
        Expect(status == STATUS_CANCELLED, "callback status propagates");
    }
}

int main()
{
    TestSimpleMessage();
    TestMultilineDataAndEventType();
    TestIdAndRetry();
    TestIdOnlyDoesNotDispatch();
    TestCommentsAndUnknownFields();
    TestCrlfAndSplitFeeds();
    TestBomStrippedOnce();
    TestInvalidRetryIgnored();
    TestEmptyIdClearsLastEventId();
    TestSpaceAfterColon();
    TestMaxEventOverflow();
    TestFinishDiscardsPartial();
    TestMultipleEvents();
    TestCallbackFailureAborts();

    if (g_failed) {
        printf("sse_parser_tests: FAILED\n");
        return 1;
    }
    printf("sse_parser_tests: OK\n");
    return 0;
}
