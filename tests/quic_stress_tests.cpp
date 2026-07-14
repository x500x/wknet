#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/WknetConfig.h>
#include <wknet/http/Session.h>

#include "http3/Http3Types.h"
#include "quic/QuicConnection.h"
#include "quic/QuicFrame.h"
#include "quic/QuicStream.h"
#include "rtl/ProtocolFailureInjection.h"

#include <chrono>
#include <stdio.h>

namespace
{
    constexpr SIZE_T StressConnectionCount = 8;
    constexpr SIZE_T StressStreamsPerConnection = 64;
    constexpr SIZE_T StressBytesPerStream = 128 * 1024;
    constexpr SIZE_T StressChunkBytes = 1024;
    constexpr SIZE_T StressChunksPerStream = StressBytesPerStream / StressChunkBytes;
    constexpr SIZE_T StressSessionIterations = 100;
    constexpr SIZE_T StressCancelIterations = 1000;
    constexpr ULONGLONG StressTimeoutMilliseconds = 10ULL * 60ULL * 1000ULL;

    bool g_failed = false;

    struct StressEvents final
    {
        SIZE_T Opened = 0;
        SIZE_T Readable = 0;
        SIZE_T Reset = 0;
        SIZE_T Closed = 0;
    };

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition)
        {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void OnOpened(void* context, wknet::quic::QuicStream*) noexcept { ++static_cast<StressEvents*>(context)->Opened; }

    void OnReadable(void* context, wknet::quic::QuicStream*) noexcept
    {
        ++static_cast<StressEvents*>(context)->Readable;
    }

    void OnReset(void* context, wknet::quic::QuicStream*, ULONGLONG, bool) noexcept
    {
        ++static_cast<StressEvents*>(context)->Reset;
    }

    void OnClosed(void* context, wknet::quic::QuicStream*) noexcept { ++static_cast<StressEvents*>(context)->Closed; }

    UCHAR PatternByte(SIZE_T connectionIndex, SIZE_T streamIndex, SIZE_T byteOffset) noexcept
    {
        return static_cast<UCHAR>((connectionIndex * 17 + streamIndex * 13 + byteOffset) & 0xffU);
    }

    void FillChunk(UCHAR* chunk, SIZE_T connectionIndex, SIZE_T streamIndex, SIZE_T chunkIndex) noexcept
    {
        const SIZE_T baseOffset = chunkIndex * StressChunkBytes;
        for (SIZE_T index = 0; index < StressChunkBytes; ++index)
        {
            chunk[index] = PatternByte(connectionIndex, streamIndex, baseOffset + index);
        }
    }

    NTSTATUS DeliverChunk(wknet::quic::QuicConnection* connection, ULONGLONG streamId, SIZE_T connectionIndex,
                          SIZE_T streamIndex, SIZE_T chunkIndex, UCHAR* chunk, bool duplicate) noexcept
    {
        FillChunk(chunk, connectionIndex, streamIndex, chunkIndex);
        wknet::quic::QuicFrame frame = {};
        frame.Kind = wknet::quic::QuicFrameKind::Stream;
        frame.StreamId = streamId;
        frame.Offset = chunkIndex * StressChunkBytes;
        frame.Data = {chunk, StressChunkBytes};
        frame.Fin = chunkIndex + 1 == StressChunksPerStream;
        NTSTATUS status =
            wknet::quic::QuicConnectionTestInjectFrame(connection, wknet::quic::QuicEncryptionLevel::Application,
                                                       wknet::quic::QuicPacketNumberSpace::Application, frame);
        if (NT_SUCCESS(status) && duplicate)
        {
            status =
                wknet::quic::QuicConnectionTestInjectFrame(connection, wknet::quic::QuicEncryptionLevel::Application,
                                                           wknet::quic::QuicPacketNumberSpace::Application, frame);
        }
        return status;
    }

    bool ShouldDrop(SIZE_T connectionIndex, SIZE_T streamIndex, SIZE_T chunkIndex) noexcept
    {
        const SIZE_T ordinal =
            (connectionIndex * StressStreamsPerConnection + streamIndex) * StressChunksPerStream + chunkIndex;
        return ordinal % 100 == 0;
    }

    bool ShouldDuplicate(SIZE_T connectionIndex, SIZE_T streamIndex, SIZE_T chunkIndex) noexcept
    {
        const SIZE_T ordinal =
            (connectionIndex * StressStreamsPerConnection + streamIndex) * StressChunksPerStream + chunkIndex;
        return ordinal % 37 == 0;
    }

    bool ShouldReorder(SIZE_T connectionIndex, SIZE_T streamIndex, SIZE_T chunkIndex) noexcept
    {
        const SIZE_T ordinal =
            (connectionIndex * StressStreamsPerConnection + streamIndex) * StressChunksPerStream + chunkIndex;
        return ordinal % 20 == 0;
    }

    bool CreateConnection(const wknet::quic::QuicStreamApplicationEventSink* sink,
                          wknet::quic::QuicConnection** connection) noexcept
    {
        wknet::quic::QuicConnectionCreateOptions options = {};
        options.ApplicationEventSink = sink;
        if (!NT_SUCCESS(wknet::quic::QuicConnectionCreate(options, connection)))
        {
            return false;
        }
        wknet::quic::QuicOperation connect = {};
        wknet::quic::QuicOperationInitialize(&connect);
        if (!NT_SUCCESS(wknet::quic::QuicConnectionConnect(*connection, &connect)) ||
            !NT_SUCCESS(wknet::quic::QuicOperationWait(&connect, 1000)) ||
            !NT_SUCCESS(wknet::quic::QuicConnectionTestConfirmHandshake(*connection)))
        {
            return false;
        }
        return true;
    }

    void CloseConnection(wknet::quic::QuicConnection* connection) noexcept
    {
        if (connection == nullptr)
        {
            return;
        }
        wknet::quic::QuicOperation close = {};
        wknet::quic::QuicOperationInitialize(&close);
        const NTSTATUS status = wknet::quic::QuicConnectionCloseAsync(connection, &close);
        if (NT_SUCCESS(status))
        {
            Expect(NT_SUCCESS(wknet::quic::QuicOperationWait(&close, 5000)), "stress connection closes");
        }
        wknet::quic::QuicConnectionDestroy(connection);
    }

    void RunConnectionAndStreamStress(StressEvents* events) noexcept
    {
        wknet::HeapArray<wknet::quic::QuicConnection*> connections(StressConnectionCount);
        wknet::HeapArray<ULONGLONG> streamIds(StressConnectionCount * StressStreamsPerConnection);
        wknet::HeapArray<UCHAR> chunk(StressChunkBytes);
        wknet::HeapArray<UCHAR> output(StressBytesPerStream);
        Expect(connections.IsValid() && streamIds.IsValid() && chunk.IsValid() && output.IsValid(),
               "stress buffers allocate");
        if (!connections.IsValid() || !streamIds.IsValid() || !chunk.IsValid() || !output.IsValid())
        {
            return;
        }
        RtlZeroMemory(connections.Get(), connections.Count() * sizeof(connections[0]));

        wknet::quic::QuicStreamApplicationEventSink sink = {};
        sink.Context = events;
        sink.Opened = OnOpened;
        sink.Readable = OnReadable;
        sink.Reset = OnReset;
        sink.Closed = OnClosed;

        for (SIZE_T connectionIndex = 0; connectionIndex < StressConnectionCount; ++connectionIndex)
        {
            Expect(CreateConnection(&sink, &connections[connectionIndex]), "stress QUIC connection establishes");
            if (connections[connectionIndex] == nullptr)
            {
                continue;
            }
            for (SIZE_T streamIndex = 0; streamIndex < StressStreamsPerConnection; ++streamIndex)
            {
                wknet::quic::QuicOperation open = {};
                wknet::quic::QuicOperationInitialize(&open);
                const NTSTATUS openStatus = wknet::quic::QuicConnectionOpenStream(connections[connectionIndex], &open);
                const NTSTATUS waitStatus =
                    NT_SUCCESS(openStatus) ? wknet::quic::QuicOperationWait(&open, 1000) : openStatus;
                Expect(NT_SUCCESS(waitStatus), "stress stream opens");
                streamIds[connectionIndex * StressStreamsPerConnection + streamIndex] = open.StreamId;
            }
        }

        for (SIZE_T connectionIndex = 0; connectionIndex < StressConnectionCount; ++connectionIndex)
        {
            if (connections[connectionIndex] == nullptr)
            {
                continue;
            }
            for (SIZE_T streamIndex = 0; streamIndex < StressStreamsPerConnection; ++streamIndex)
            {
                const ULONGLONG streamId = streamIds[connectionIndex * StressStreamsPerConnection + streamIndex];
                SIZE_T lostChunks[4] = {};
                SIZE_T lostCount = 0;
                for (SIZE_T chunkIndex = 0; chunkIndex < StressChunksPerStream;)
                {
                    if (ShouldReorder(connectionIndex, streamIndex, chunkIndex) &&
                        chunkIndex + 1 < StressChunksPerStream)
                    {
                        const SIZE_T reordered = chunkIndex + 1;
                        if (ShouldDrop(connectionIndex, streamIndex, reordered))
                        {
                            lostChunks[lostCount++] = reordered;
                        }
                        else
                        {
                            Expect(NT_SUCCESS(DeliverChunk(connections[connectionIndex], streamId, connectionIndex,
                                                           streamIndex, reordered, chunk.Get(),
                                                           ShouldDuplicate(connectionIndex, streamIndex, reordered))),
                                   "reordered stress frame is accepted");
                        }
                        if (ShouldDrop(connectionIndex, streamIndex, chunkIndex))
                        {
                            lostChunks[lostCount++] = chunkIndex;
                        }
                        else
                        {
                            Expect(NT_SUCCESS(DeliverChunk(connections[connectionIndex], streamId, connectionIndex,
                                                           streamIndex, chunkIndex, chunk.Get(),
                                                           ShouldDuplicate(connectionIndex, streamIndex, chunkIndex))),
                                   "reordered predecessor frame is accepted");
                        }
                        chunkIndex += 2;
                        continue;
                    }
                    if (ShouldDrop(connectionIndex, streamIndex, chunkIndex))
                    {
                        lostChunks[lostCount++] = chunkIndex;
                    }
                    else
                    {
                        Expect(NT_SUCCESS(DeliverChunk(connections[connectionIndex], streamId, connectionIndex,
                                                       streamIndex, chunkIndex, chunk.Get(),
                                                       ShouldDuplicate(connectionIndex, streamIndex, chunkIndex))),
                               "stress frame is accepted");
                    }
                    ++chunkIndex;
                }
                for (SIZE_T lostIndex = 0; lostIndex < lostCount; ++lostIndex)
                {
                    Expect(NT_SUCCESS(DeliverChunk(connections[connectionIndex], streamId, connectionIndex, streamIndex,
                                                   lostChunks[lostIndex], chunk.Get(), false)),
                           "lost stress frame retransmission is accepted");
                }

                wknet::quic::QuicOperation consume = {};
                wknet::quic::QuicOperationInitialize(&consume);
                NTSTATUS status = wknet::quic::QuicConnectionConsumeStream(connections[connectionIndex], streamId,
                                                                           output.Get(), output.Count(), &consume);
                if (NT_SUCCESS(status))
                {
                    status = wknet::quic::QuicOperationWait(&consume, 1000);
                }
                Expect(NT_SUCCESS(status) && consume.BytesTransferred == StressBytesPerStream && consume.Fin,
                       "stress stream consumes the complete reassembled body");
                bool contentMatches = NT_SUCCESS(status) && consume.BytesTransferred == StressBytesPerStream;
                for (SIZE_T byteIndex = 0; contentMatches && byteIndex < StressBytesPerStream; ++byteIndex)
                {
                    contentMatches = output[byteIndex] == PatternByte(connectionIndex, streamIndex, byteIndex);
                }
                Expect(contentMatches, "stress stream bytes survive loss, reordering and duplication");

                wknet::quic::QuicOperation finish = {};
                wknet::quic::QuicOperationInitialize(&finish);
                status = wknet::quic::QuicConnectionWriteStream(connections[connectionIndex], streamId, nullptr, 0,
                                                                true, &finish);
                if (NT_SUCCESS(status))
                {
                    status = wknet::quic::QuicOperationWait(&finish, 1000);
                }
                Expect(NT_SUCCESS(status), "stress stream send side finishes");
            }
        }

        const SIZE_T expectedStreams = StressConnectionCount * StressStreamsPerConnection;
        Expect(events->Opened == expectedStreams, "stress opened callback count is exact");
        Expect(events->Closed == expectedStreams, "stress completion callback is emitted exactly once per stream");

        for (SIZE_T connectionIndex = 0; connectionIndex < StressConnectionCount; ++connectionIndex)
        {
            CloseConnection(connections[connectionIndex]);
            connections[connectionIndex] = nullptr;
        }
        Expect(events->Closed == expectedStreams, "connection shutdown does not double-complete streams");
    }

    void RunSessionLifecycleStress() noexcept
    {
        for (SIZE_T iteration = 0; iteration < StressSessionIterations; ++iteration)
        {
            wknet::http::Session* session = nullptr;
            Expect(NT_SUCCESS(wknet::http::SessionCreate(&session)) && session != nullptr,
                   "stress SessionCreate succeeds");
            wknet::http::SessionClose(session);
        }
    }

    void RunCancelStorm(StressEvents* events) noexcept
    {
        wknet::quic::QuicStreamApplicationEventSink sink = {};
        sink.Context = events;
        sink.Opened = OnOpened;
        sink.Readable = OnReadable;
        sink.Reset = OnReset;
        sink.Closed = OnClosed;
        const SIZE_T closedBefore = events->Closed;
        for (SIZE_T iteration = 0; iteration < StressCancelIterations; ++iteration)
        {
            wknet::quic::QuicStream* stream = wknet::AllocateNonPagedObject<wknet::quic::QuicStream>();
            Expect(stream != nullptr, "cancel storm stream allocates");
            if (stream == nullptr)
            {
                continue;
            }
            const ULONGLONG streamId = static_cast<ULONGLONG>(iteration) * 4ULL;
            Expect(NT_SUCCESS(stream->Initialize(streamId, StressChunkBytes, 4)), "cancel storm stream initializes");
            stream->SetApplicationEventSink(&sink);
            Expect(NT_SUCCESS(stream->Reset(wknet::http3::H3_REQUEST_CANCELLED, 0)),
                   "cancel storm local reset succeeds");
            Expect(NT_SUCCESS(stream->OnResetReceived(wknet::http3::H3_REQUEST_CANCELLED, 0)),
                   "cancel storm peer reset succeeds");
            wknet::FreeNonPagedObject(stream);
        }
        Expect(events->Closed - closedBefore == StressCancelIterations,
               "cancel storm completes each stream exactly once");
    }
} // namespace

int main()
{
    const auto started = std::chrono::steady_clock::now();
    wknet::rtl::ProtocolFailureInjectionReset();

    StressEvents events = {};
    RunConnectionAndStreamStress(&events);
    RunSessionLifecycleStress();
    RunCancelStorm(&events);

    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    Expect(static_cast<ULONGLONG>(elapsed.count()) <= StressTimeoutMilliseconds,
           "bounded QUIC stress finishes within ten minutes");
    Expect(wknet::rtl::ProtocolFailureInjectionTotalLiveCount() == 0,
           "stress leaves no tracked protocol allocation, command, IRP, timer or worker owner");

    if (g_failed)
    {
        printf("QUIC STRESS TESTS FAILED elapsed_ms=%lld\n", static_cast<long long>(elapsed.count()));
        return 1;
    }
    printf("QUIC STRESS TESTS PASSED elapsed_ms=%lld\n", static_cast<long long>(elapsed.count()));
    return 0;
}
