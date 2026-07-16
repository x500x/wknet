#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "http1/HttpChunkedDecoder.h"

#include <stdio.h>
#include <string.h>

using wknet::http1::HttpChunkedDecoder;
using wknet::http1::HttpHeader;

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

    struct BodyCapture
    {
        char Data[1024];
        SIZE_T Length;
        ULONG Calls;
    };

    NTSTATUS OnChunkData(void* context, const UCHAR* data, SIZE_T dataLength)
    {
        auto* capture = static_cast<BodyCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ++capture->Calls;
        if (dataLength == 0) {
            return STATUS_SUCCESS;
        }
        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (capture->Length + dataLength > sizeof(capture->Data)) {
            return STATUS_BUFFER_OVERFLOW;
        }
        RtlCopyMemory(capture->Data + capture->Length, data, dataLength);
        capture->Length += dataLength;
        return STATUS_SUCCESS;
    }

    void TestSingleChunk()
    {
        HttpChunkedDecoder decoder;
        HttpHeader trailers[8] = {};
        decoder.SetTrailerStorage(trailers, 8);
        BodyCapture capture = {};

        const char* wire = "5\r\nhello\r\n0\r\n\r\n";
        SIZE_T consumed = 0;
        NTSTATUS status = decoder.Feed(wire, strlen(wire), &consumed, OnChunkData, &capture);
        Expect(status == STATUS_SUCCESS, "single chunk complete");
        Expect(decoder.IsComplete(), "complete");
        Expect(consumed == strlen(wire), "all consumed");
        Expect(capture.Length == 5, "5 bytes");
        Expect(memcmp(capture.Data, "hello", 5) == 0, "hello");
        Expect(capture.Calls >= 1, "callback called");
    }

    void TestMultiChunkSplitFeeds()
    {
        HttpChunkedDecoder decoder;
        HttpHeader trailers[8] = {};
        decoder.SetTrailerStorage(trailers, 8);
        BodyCapture capture = {};

        // "hello" + " world" = 5 + 6 = 11
        const char* parts[] = {
            "5\r\nhe",
            "llo\r\n6\r\n worl",
            "d\r\n0\r\n\r\n"
        };
        NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;
        for (SIZE_T i = 0; i < 3; ++i) {
            SIZE_T consumed = 0;
            status = decoder.Feed(parts[i], strlen(parts[i]), &consumed, OnChunkData, &capture);
            Expect(consumed == strlen(parts[i]), "part fully consumed");
        }
        Expect(status == STATUS_SUCCESS, "multi complete");
        Expect(capture.Length == 11, "11 bytes");
        Expect(memcmp(capture.Data, "hello world", 11) == 0, "payload");
    }

    void TestTrailers()
    {
        HttpChunkedDecoder decoder;
        HttpHeader trailers[8] = {};
        decoder.SetTrailerStorage(trailers, 8);
        BodyCapture capture = {};

        const char* wire = "3\r\nfoo\r\n0\r\nX-Trail: yes\r\n\r\n";
        SIZE_T consumed = 0;
        NTSTATUS status = decoder.Feed(wire, strlen(wire), &consumed, OnChunkData, &capture);
        Expect(status == STATUS_SUCCESS, "trailers complete");
        Expect(decoder.TrailerCount() == 1, "one trailer");
        Expect(trailers[0].Name.Length == 7, "trailer name len");
        Expect(memcmp(trailers[0].Name.Data, "X-Trail", 7) == 0, "trailer name");
        Expect(trailers[0].Value.Length == 3, "trailer value len");
        Expect(memcmp(trailers[0].Value.Data, "yes", 3) == 0, "trailer value");
        Expect(capture.Length == 3, "body foo");
    }

    void TestEmptyBody()
    {
        HttpChunkedDecoder decoder;
        BodyCapture capture = {};
        const char* wire = "0\r\n\r\n";
        SIZE_T consumed = 0;
        NTSTATUS status = decoder.Feed(wire, strlen(wire), &consumed, OnChunkData, &capture);
        Expect(status == STATUS_SUCCESS, "empty complete");
        Expect(capture.Length == 0, "no body");
        Expect(capture.Calls == 0, "no data callbacks");
    }

    void TestChunkExtensionIgnored()
    {
        HttpChunkedDecoder decoder;
        BodyCapture capture = {};
        const char* wire = "5;ext=1\r\nhello\r\n0\r\n\r\n";
        SIZE_T consumed = 0;
        NTSTATUS status = decoder.Feed(wire, strlen(wire), &consumed, OnChunkData, &capture);
        Expect(status == STATUS_SUCCESS, "ext complete");
        Expect(capture.Length == 5 && memcmp(capture.Data, "hello", 5) == 0, "ext payload");
    }

    void TestBadCrLf()
    {
        HttpChunkedDecoder decoder;
        BodyCapture capture = {};
        const char* wire = "5\r\nhelloXX0\r\n\r\n";
        SIZE_T consumed = 0;
        NTSTATUS status = decoder.Feed(wire, strlen(wire), &consumed, OnChunkData, &capture);
        Expect(!NT_SUCCESS(status), "bad trailer crlf fails");
    }
}

int main()
{
    TestSingleChunk();
    TestMultiChunkSplitFeeds();
    TestTrailers();
    TestEmptyBody();
    TestChunkExtensionIgnored();
    TestBadCrLf();

    if (g_failed) {
        printf("http_chunked_decoder_tests: FAILED\n");
        return 1;
    }
    printf("http_chunked_decoder_tests: OK\n");
    return 0;
}
