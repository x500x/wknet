#include "http3/Http3ConnectionPrivate.hpp"

#include "quic/QuicVarInt.h"

namespace wknet::http3
{
namespace
{
constexpr ULONGLONG Http3UnidirectionalControl = 0x00;
constexpr ULONGLONG Http3UnidirectionalPush = 0x01;
constexpr ULONGLONG Http3UnidirectionalQpackEncoder = 0x02;
constexpr ULONGLONG Http3UnidirectionalQpackDecoder = 0x03;

NTSTATUS ConsumeVarIntByte(Http3VarIntParser *parser, UCHAR byte) noexcept
{
    if (parser == nullptr || parser->Complete || parser->Count >= sizeof(parser->Bytes))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (parser->Count == 0)
    {
        parser->Expected = static_cast<UCHAR>(1U << (byte >> 6));
    }
    parser->Bytes[parser->Count] = byte;
    ++parser->Count;
    if (parser->Count != parser->Expected)
    {
        return STATUS_SUCCESS;
    }
    SIZE_T consumed = 0;
    NTSTATUS status = quic::QuicDecodeVarInt(parser->Bytes, parser->Count, &parser->Value, &consumed);
    if (NT_SUCCESS(status) && consumed == parser->Count)
    {
        parser->Complete = true;
        return STATUS_SUCCESS;
    }
    return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
}

NTSTATUS AppendVarInt(ULONGLONG value, UCHAR *output, SIZE_T capacity, SIZE_T *offset) noexcept
{
    if (output == nullptr || offset == nullptr || *offset > capacity)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const SIZE_T encodedLength = quic::QuicVarIntEncodedLength(value);
    if (encodedLength == 0)
    {
        return STATUS_INTEGER_OVERFLOW;
    }
    SIZE_T written = 0;
    NTSTATUS status = quic::QuicEncodeVarInt(value, encodedLength, output + *offset, capacity - *offset, &written);
    if (NT_SUCCESS(status))
    {
        *offset += written;
    }
    return status;
}

bool IsCriticalRole(Http3ConnectionStreamRole role) noexcept
{
    return role == Http3ConnectionStreamRole::PeerControl || role == Http3ConnectionStreamRole::PeerQpackEncoder ||
           role == Http3ConnectionStreamRole::PeerQpackDecoder || role == Http3ConnectionStreamRole::LocalControl ||
           role == Http3ConnectionStreamRole::LocalQpackEncoder || role == Http3ConnectionStreamRole::LocalQpackDecoder;
}

bool IsRequestStreamId(ULONGLONG streamId) noexcept
{
    return quic::QuicStreamIsClientInitiated(streamId) && quic::QuicStreamIsBidirectional(streamId);
}
} // namespace

Http3OwnedBuffer::~Http3OwnedBuffer() noexcept
{
    Clear();
}

NTSTATUS Http3OwnedBuffer::Reserve(SIZE_T capacity) noexcept
{
    if (capacity <= Capacity)
    {
        return STATUS_SUCCESS;
    }
    UCHAR *replacement = AllocateNonPagedArray<UCHAR>(capacity);
    if (replacement == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (Length != 0)
    {
        RtlCopyMemory(replacement, Data, Length);
    }
    FreeNonPagedArray(Data);
    Data = replacement;
    Capacity = capacity;
    return STATUS_SUCCESS;
}

NTSTATUS Http3OwnedBuffer::Append(const UCHAR *data, SIZE_T length, SIZE_T maximum) noexcept
{
    if ((data == nullptr && length != 0) || Length > maximum || length > maximum - Length)
    {
        return length > maximum || Length > maximum - length ? STATUS_BUFFER_TOO_SMALL : STATUS_INVALID_PARAMETER;
    }
    if (length == 0)
    {
        return STATUS_SUCCESS;
    }
    SIZE_T required = Length + length;
    SIZE_T capacity = Capacity == 0 ? 64 : Capacity;
    while (capacity < required)
    {
        if (capacity > maximum / 2)
        {
            capacity = maximum;
            break;
        }
        capacity *= 2;
    }
    NTSTATUS status = Reserve(capacity);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    RtlCopyMemory(Data + Length, data, length);
    Length = required;
    return STATUS_SUCCESS;
}

void Http3OwnedBuffer::ConsumePrefix(SIZE_T length) noexcept
{
    if (length >= Length)
    {
        Length = 0;
        return;
    }
    RtlMoveMemory(Data, Data + length, Length - length);
    Length -= length;
}

void Http3OwnedBuffer::Clear() noexcept
{
    FreeNonPagedArray(Data);
    Data = nullptr;
    Length = 0;
    Capacity = 0;
}

Http3Connection::Http3Connection() noexcept
{
    applicationSink_.Context = this;
    applicationSink_.Opened = OnStreamOpened;
    applicationSink_.Readable = OnStreamReadable;
    applicationSink_.Writable = OnStreamWritable;
    applicationSink_.Reset = OnStreamReset;
    applicationSink_.Closed = OnStreamClosed;
}

Http3Connection::~Http3Connection() noexcept
{
    Clear();
}

NTSTATUS Http3Connection::Initialize(const Http3ConnectionCreateOptions &options) noexcept
{
    if (options.LocalQpackMaximumCapacity > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES ||
        options.LocalQpackBlockedStreams > WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS ||
        options.LocalMaximumFieldSectionBytes == 0 ||
        options.LocalMaximumFieldSectionBytes > WKNET_HARD_MAX_HTTP3_FIELD_SECTION_BYTES)
    {
        return STATUS_INVALID_PARAMETER;
    }
    callbacks_ = options.Callbacks;
    localQpackMaximumCapacity_ = options.LocalQpackMaximumCapacity;
    localQpackBlockedStreams_ = options.LocalQpackBlockedStreams;
    localMaximumFieldSectionBytes_ = options.LocalMaximumFieldSectionBytes;

    NTSTATUS status = streams_.Allocate(Http3MaximumTrackedStreams);
    if (NT_SUCCESS(status))
    {
        status = readScratch_.Allocate(Http3ReadScratchBytes);
    }
    if (NT_SUCCESS(status))
    {
        status = writeScratch_.Allocate(Http3ReadScratchBytes);
    }
    if (NT_SUCCESS(status))
    {
        status = settingIdentifiers_.Allocate(WKNET_HARD_MAX_CONNECTION_CONTROL_SIGNALS);
    }
    if (NT_SUCCESS(status))
    {
        status = decoder_.Initialize(localQpackMaximumCapacity_, localQpackBlockedStreams_,
                                     localMaximumFieldSectionBytes_, WKNET_HARD_MAX_HTTP3_FIELDS);
    }
    if (!NT_SUCCESS(status))
    {
        Clear();
    }
    return status;
}

NTSTATUS Http3Connection::BindQuic(quic::QuicConnection *connection) noexcept
{
    if (connection == nullptr || quicConnection_ != nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    quicConnection_ = connection;
    return STATUS_SUCCESS;
}

const quic::QuicStreamApplicationEventSink *Http3Connection::ApplicationSink() const noexcept
{
    return &applicationSink_;
}

void Http3Connection::BeginShutdown() noexcept
{
    shuttingDown_ = true;
}

bool Http3Connection::PeerSettingsReceived() const noexcept
{
    return peerSettingsReceived_;
}

SIZE_T Http3Connection::PeerQpackMaximumCapacity() const noexcept
{
    return peerQpackMaximumCapacity_;
}

ULONG Http3Connection::PeerQpackBlockedStreams() const noexcept
{
    return peerQpackBlockedStreams_;
}

ULONGLONG Http3Connection::GoawayId() const noexcept
{
    return goawayId_;
}

SIZE_T Http3Connection::BlockedStreamCount() const noexcept
{
    return decoder_.BlockedStreamCount();
}

ULONGLONG Http3Connection::LocalDecoderBytesSent() const noexcept
{
    return localDecoderBytesSent_;
}

#if defined(WKNET_USER_MODE_TEST)
NTSTATUS Http3Connection::TestApplyPeerSettings(SIZE_T qpackMaximumCapacity, ULONG qpackBlockedStreams) noexcept
{
    if (peerSettingsReceived_ || qpackMaximumCapacity > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES ||
        qpackBlockedStreams > WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS)
    {
        return STATUS_INVALID_PARAMETER;
    }
    peerQpackMaximumCapacity_ = qpackMaximumCapacity;
    peerQpackBlockedStreams_ = qpackBlockedStreams;
    peerSettingsReceived_ = true;
    const NTSTATUS status = encoder_.Initialize(peerQpackMaximumCapacity_, peerQpackBlockedStreams_);
    encoderInitialized_ = NT_SUCCESS(status);
    return status;
}
#endif

NTSTATUS Http3Connection::OpenRequest(const Http3RequestOpenOptions &options, ULONGLONG *streamId) noexcept
{
    if (streamId != nullptr)
    {
        *streamId = 0;
    }
    if (streamId == nullptr || !peerSettingsReceived_ || !encoderInitialized_ || failed_)
    {
        return streamId == nullptr ? STATUS_INVALID_PARAMETER : STATUS_DEVICE_NOT_READY;
    }

    quic::QuicStream *stream = nullptr;
    NTSTATUS status = quic::QuicConnectionWorkerOpenBidirectionalStream(quicConnection_, &stream);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    Http3ConnectionStreamState *state = FindStream(stream);
    if (state == nullptr)
    {
        status = AddStream(stream, Http3ConnectionStreamRole::Request, &state);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (state->StreamId >= goawayId_)
    {
        quic::QuicConnectionWorkerResetStream(quicConnection_, state->Stream, H3_REQUEST_REJECTED);
        quic::QuicConnectionWorkerStopSending(quicConnection_, state->Stream, H3_REQUEST_REJECTED);
        return STATUS_DEVICE_NOT_READY;
    }
    Http3ResponseStateInitialize(&state->Response, options.RequestWasHead, options.Fields.Connect);

    const SIZE_T pseudoCount = options.Fields.Connect ? 2 : 4;
    if (options.Fields.HeaderCount > WKNET_HARD_MAX_HTTP3_FIELDS ||
        pseudoCount > WKNET_HARD_MAX_HTTP3_FIELDS - options.Fields.HeaderCount)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    HeapArray<qpack::QpackFieldView> requestFields;
    status = requestFields.Allocate(pseudoCount + options.Fields.HeaderCount);
    SIZE_T requestFieldCount = 0;
    ULONGLONG applicationError = 0;
    if (NT_SUCCESS(status))
    {
        status = Http3BuildRequestFields(options.Fields, requestFields.Get(), requestFields.Count(), &requestFieldCount,
                                         &applicationError);
    }
    if (NT_SUCCESS(status))
    {
        status = EncodeFieldSection(*state, requestFields.Get(), requestFieldCount);
    }
    if (NT_SUCCESS(status))
    {
        status = WriteFrameHeader(*state, Http3FrameTypeHeaders, state->Payload.Length);
    }
    if (NT_SUCCESS(status))
    {
        status = QueueWrite(*state, state->Payload.Data, state->Payload.Length, false);
    }
    if (NT_SUCCESS(status))
    {
        state->RequestHeadersSent = true;
        *streamId = state->StreamId;
    }
    return status;
}

NTSTATUS Http3Connection::WriteRequestData(ULONGLONG streamId, const UCHAR *data, SIZE_T length, bool fin) noexcept
{
    Http3ConnectionStreamState *state = FindStreamById(streamId);
    if (state == nullptr || state->Role != Http3ConnectionStreamRole::Request || !state->RequestHeadersSent ||
        state->RequestFinSent || (data == nullptr && length != 0))
    {
        return state == nullptr ? STATUS_NOT_FOUND : STATUS_INVALID_DEVICE_STATE;
    }
    NTSTATUS status = WriteFrameHeader(*state, Http3FrameTypeData, length);
    if (NT_SUCCESS(status))
    {
        status = QueueWrite(*state, data, length, fin);
    }
    if (NT_SUCCESS(status) && fin)
    {
        state->RequestFinSent = true;
    }
    return status;
}

NTSTATUS Http3Connection::WriteRequestTrailers(ULONGLONG streamId, const qpack::QpackFieldView *fields,
                                               SIZE_T fieldCount) noexcept
{
    Http3ConnectionStreamState *state = FindStreamById(streamId);
    if (state == nullptr || state->Role != Http3ConnectionStreamRole::Request || !state->RequestHeadersSent ||
        state->RequestFinSent || (fields == nullptr && fieldCount != 0))
    {
        return state == nullptr ? STATUS_NOT_FOUND : STATUS_INVALID_DEVICE_STATE;
    }
    ULONGLONG applicationError = 0;
    NTSTATUS status = Http3ValidateTrailers(fields, fieldCount, &applicationError);
    if (NT_SUCCESS(status))
    {
        status = EncodeFieldSection(*state, fields, fieldCount);
    }
    if (NT_SUCCESS(status))
    {
        status = WriteFrameHeader(*state, Http3FrameTypeHeaders, state->Payload.Length);
    }
    if (NT_SUCCESS(status))
    {
        status = QueueWrite(*state, state->Payload.Data, state->Payload.Length, true);
    }
    if (NT_SUCCESS(status))
    {
        state->RequestFinSent = true;
    }
    return status;
}

NTSTATUS Http3Connection::CancelRequest(ULONGLONG streamId, ULONGLONG applicationError) noexcept
{
    Http3ConnectionStreamState *state = FindStreamById(streamId);
    if (state == nullptr || state->Role != Http3ConnectionStreamRole::Request)
    {
        return state == nullptr ? STATUS_NOT_FOUND : STATUS_INVALID_DEVICE_STATE;
    }
    NTSTATUS resetStatus = quic::QuicConnectionWorkerResetStream(quicConnection_, state->Stream, applicationError);
    NTSTATUS stopStatus = quic::QuicConnectionWorkerStopSending(quicConnection_, state->Stream, applicationError);
    NTSTATUS cancelStatus = CancelBlockedSection(*state);
    NotifyStreamComplete(*state, STATUS_CANCELLED, applicationError);
    if (!NT_SUCCESS(resetStatus))
    {
        return resetStatus;
    }
    if (!NT_SUCCESS(stopStatus))
    {
        return stopStatus;
    }
    return cancelStatus;
}

void Http3Connection::OnStreamOpened(void *context, quic::QuicStream *stream) noexcept
{
    Http3Connection *connection = static_cast<Http3Connection *>(context);
    if (connection == nullptr || stream == nullptr || connection->failed_ || connection->shuttingDown_)
    {
        return;
    }
    if (connection->starting_ && quic::QuicStreamIsClientInitiated(stream->Id()) &&
        !quic::QuicStreamIsBidirectional(stream->Id()))
    {
        return;
    }
    NTSTATUS status = connection->EnsureStarted();
    if (!NT_SUCCESS(status))
    {
        connection->CloseConnection(status, H3_INTERNAL_ERROR);
        return;
    }
    if (connection->FindStream(stream) != nullptr)
    {
        return;
    }

    Http3ConnectionStreamRole role = Http3ConnectionStreamRole::PendingUnidirectional;
    if (quic::QuicStreamIsBidirectional(stream->Id()))
    {
        if (!quic::QuicStreamIsClientInitiated(stream->Id()))
        {
            connection->CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_STREAM_CREATION_ERROR);
            return;
        }
        role = Http3ConnectionStreamRole::Request;
    }
    Http3ConnectionStreamState *state = nullptr;
    status = connection->AddStream(stream, role, &state);
    if (!NT_SUCCESS(status))
    {
        connection->CloseConnection(status, H3_EXCESSIVE_LOAD);
    }
}

void Http3Connection::OnStreamReadable(void *context, quic::QuicStream *stream) noexcept
{
    Http3Connection *connection = static_cast<Http3Connection *>(context);
    if (connection == nullptr || stream == nullptr || connection->failed_ || connection->shuttingDown_)
    {
        return;
    }
    Http3ConnectionStreamState *state = connection->FindStream(stream);
    if (state == nullptr)
    {
        OnStreamOpened(context, stream);
        state = connection->FindStream(stream);
    }
    if (state == nullptr)
    {
        return;
    }
    NTSTATUS status = connection->DrainStream(*state);
    if (!NT_SUCCESS(status) && status != STATUS_PENDING)
    {
        connection->CloseConnection(status, H3_GENERAL_PROTOCOL_ERROR);
    }
}

void Http3Connection::OnStreamWritable(void *context, quic::QuicStream *stream) noexcept
{
    Http3Connection *connection = static_cast<Http3Connection *>(context);
    if (connection == nullptr || stream == nullptr || connection->failed_ || connection->shuttingDown_)
    {
        return;
    }
    Http3ConnectionStreamState *state = connection->FindStream(stream);
    if (state != nullptr)
    {
        NTSTATUS status = connection->FlushWrite(*state);
        if (!NT_SUCCESS(status) && status != STATUS_RETRY)
        {
            connection->CloseConnection(status, H3_INTERNAL_ERROR);
        }
    }
}

void Http3Connection::OnStreamReset(void *context, quic::QuicStream *stream, ULONGLONG errorCode,
                                    bool peerInitiated) noexcept
{
    UNREFERENCED_PARAMETER(peerInitiated);
    Http3Connection *connection = static_cast<Http3Connection *>(context);
    if (connection == nullptr || stream == nullptr || connection->failed_ || connection->shuttingDown_)
    {
        return;
    }
    Http3ConnectionStreamState *state = connection->FindStream(stream);
    if (state == nullptr)
    {
        return;
    }
    if (IsCriticalRole(state->Role))
    {
        connection->CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_CLOSED_CRITICAL_STREAM);
        return;
    }
    connection->HandleReset(*state, errorCode);
}

void Http3Connection::OnStreamClosed(void *context, quic::QuicStream *stream) noexcept
{
    Http3Connection *connection = static_cast<Http3Connection *>(context);
    if (connection == nullptr || stream == nullptr || connection->failed_ || connection->shuttingDown_)
    {
        return;
    }
    Http3ConnectionStreamState *state = connection->FindStream(stream);
    if (state == nullptr)
    {
        return;
    }
    if (IsCriticalRole(state->Role))
    {
        connection->CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_CLOSED_CRITICAL_STREAM);
        return;
    }
    if (state->Role == Http3ConnectionStreamRole::Request && !state->CompleteNotified && !state->Blocked)
    {
        NTSTATUS status = connection->HandleStreamFin(*state);
        if (!NT_SUCCESS(status))
        {
            connection->CloseConnection(status, H3_MESSAGE_ERROR);
        }
    }
}

NTSTATUS Http3Connection::EnsureStarted() noexcept
{
    if (started_)
    {
        return STATUS_SUCCESS;
    }
    if (starting_ || quicConnection_ == nullptr)
    {
        return starting_ ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
    }
    starting_ = true;
    NTSTATUS status =
        OpenLocalCriticalStream(Http3ConnectionStreamRole::LocalControl, Http3UnidirectionalControl, &localControl_);
    if (NT_SUCCESS(status))
    {
        status = OpenLocalCriticalStream(Http3ConnectionStreamRole::LocalQpackEncoder, Http3UnidirectionalQpackEncoder,
                                         &localEncoder_);
    }
    if (NT_SUCCESS(status))
    {
        status = OpenLocalCriticalStream(Http3ConnectionStreamRole::LocalQpackDecoder, Http3UnidirectionalQpackDecoder,
                                         &localDecoder_);
    }
    if (NT_SUCCESS(status))
    {
        status = SendLocalSettings();
    }
    starting_ = false;
    started_ = NT_SUCCESS(status);
    if (started_)
    {
        WKNET_TRACE(ComponentHttp3, TraceLevel::Info, "http3.connection.established stream_count=%Iu", streamCount_);
    }
    return status;
}

NTSTATUS Http3Connection::OpenLocalCriticalStream(Http3ConnectionStreamRole role, ULONGLONG streamType,
                                                  quic::QuicStream **stream) noexcept
{
    NTSTATUS status = quic::QuicConnectionWorkerOpenUnidirectionalStream(quicConnection_, stream);
    Http3ConnectionStreamState *state = nullptr;
    if (NT_SUCCESS(status))
    {
        status = AddStream(*stream, role, &state);
    }
    if (NT_SUCCESS(status))
    {
        SIZE_T length = 0;
        status = AppendVarInt(streamType, writeScratch_.Get(), writeScratch_.Count(), &length);
        if (NT_SUCCESS(status))
        {
            status = QueueWrite(*state, writeScratch_.Get(), length);
        }
    }
    return status;
}

NTSTATUS Http3Connection::SendLocalSettings() noexcept
{
    Http3ConnectionStreamState *state = FindStream(localControl_);
    if (state == nullptr)
    {
        return STATUS_NOT_FOUND;
    }
    SIZE_T payloadLength = 0;
    NTSTATUS status =
        AppendVarInt(Http3SettingQpackMaxTableCapacity, writeScratch_.Get(), writeScratch_.Count(), &payloadLength);
    if (NT_SUCCESS(status))
    {
        status = AppendVarInt(localQpackMaximumCapacity_, writeScratch_.Get(), writeScratch_.Count(), &payloadLength);
    }
    if (NT_SUCCESS(status))
    {
        status =
            AppendVarInt(Http3SettingQpackBlockedStreams, writeScratch_.Get(), writeScratch_.Count(), &payloadLength);
    }
    if (NT_SUCCESS(status))
    {
        status = AppendVarInt(localQpackBlockedStreams_, writeScratch_.Get(), writeScratch_.Count(), &payloadLength);
    }
    if (NT_SUCCESS(status))
    {
        status =
            AppendVarInt(Http3SettingMaxFieldSectionSize, writeScratch_.Get(), writeScratch_.Count(), &payloadLength);
    }
    if (NT_SUCCESS(status))
    {
        status =
            AppendVarInt(localMaximumFieldSectionBytes_, writeScratch_.Get(), writeScratch_.Count(), &payloadLength);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SIZE_T headerEnd = payloadLength;
    status = AppendVarInt(Http3FrameTypeSettings, writeScratch_.Get(), writeScratch_.Count(), &headerEnd);
    if (NT_SUCCESS(status))
    {
        status = AppendVarInt(payloadLength, writeScratch_.Get(), writeScratch_.Count(), &headerEnd);
    }
    if (NT_SUCCESS(status))
    {
        status = QueueWrite(*state, writeScratch_.Get() + payloadLength, headerEnd - payloadLength);
    }
    if (NT_SUCCESS(status))
    {
        status = QueueWrite(*state, writeScratch_.Get(), payloadLength);
    }
    return status;
}

NTSTATUS Http3Connection::QueueWrite(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                     bool fin) noexcept
{
    if (state.PendingWriteFin)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (state.PendingWrite.Length != 0)
    {
        NTSTATUS status = state.PendingWrite.Append(data, length, WKNET_HARD_MAX_QPACK_TOTAL_BLOCKED_BYTES);
        if (NT_SUCCESS(status) && fin)
        {
            state.PendingWriteFin = true;
        }
        return status;
    }
    SIZE_T written = 0;
    NTSTATUS status = quic::QuicConnectionWorkerWriteStream(quicConnection_, state.Stream, data, length, fin, &written);
    if (NT_SUCCESS(status) && written == length)
    {
        return STATUS_SUCCESS;
    }
    if (status != STATUS_RETRY && !NT_SUCCESS(status))
    {
        return status;
    }
    const SIZE_T remaining = length - written;
    status = remaining == 0
                 ? STATUS_SUCCESS
                 : state.PendingWrite.Append(data + written, remaining, WKNET_HARD_MAX_QPACK_TOTAL_BLOCKED_BYTES);
    if (NT_SUCCESS(status))
    {
        state.PendingWriteFin = fin;
    }
    return status;
}

NTSTATUS Http3Connection::FlushWrite(Http3ConnectionStreamState &state) noexcept
{
    if (state.PendingWrite.Length == 0 && !state.PendingWriteFin)
    {
        return STATUS_SUCCESS;
    }
    SIZE_T written = 0;
    NTSTATUS status = quic::QuicConnectionWorkerWriteStream(quicConnection_, state.Stream, state.PendingWrite.Data,
                                                            state.PendingWrite.Length, state.PendingWriteFin, &written);
    state.PendingWrite.ConsumePrefix(written);
    if (state.PendingWrite.Length == 0 && NT_SUCCESS(status))
    {
        state.PendingWriteFin = false;
    }
    return status == STATUS_RETRY ? STATUS_RETRY : status;
}

NTSTATUS Http3Connection::WriteFrameHeader(Http3ConnectionStreamState &state, ULONGLONG type,
                                           SIZE_T payloadLength) noexcept
{
    SIZE_T length = 0;
    NTSTATUS status = AppendVarInt(type, writeScratch_.Get(), writeScratch_.Count(), &length);
    if (NT_SUCCESS(status))
    {
        status = AppendVarInt(payloadLength, writeScratch_.Get(), writeScratch_.Count(), &length);
    }
    return NT_SUCCESS(status) ? QueueWrite(state, writeScratch_.Get(), length, false) : status;
}

NTSTATUS Http3Connection::EncodeFieldSection(Http3ConnectionStreamState &state, const qpack::QpackFieldView *fields,
                                             SIZE_T fieldCount) noexcept
{
    state.Payload.Length = 0;
    NTSTATUS status = state.Payload.Reserve(localMaximumFieldSectionBytes_);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    SIZE_T written = 0;
    ULONGLONG applicationError = 0;
    status = encoder_.EncodeFieldSection(state.StreamId, fields, fieldCount, state.Payload.Data, state.Payload.Capacity,
                                         &written, &applicationError);
    if (NT_SUCCESS(status))
    {
        state.Payload.Length = written;
    }
    return status;
}

Http3ConnectionStreamState *Http3Connection::FindStream(quic::QuicStream *stream) noexcept
{
    for (SIZE_T index = 0; index < streamCount_; ++index)
    {
        if (streams_[index].Stream == stream)
        {
            return &streams_[index];
        }
    }
    return nullptr;
}

Http3ConnectionStreamState *Http3Connection::FindStreamById(ULONGLONG streamId) noexcept
{
    for (SIZE_T index = 0; index < streamCount_; ++index)
    {
        if (streams_[index].StreamId == streamId)
        {
            return &streams_[index];
        }
    }
    return nullptr;
}

NTSTATUS Http3Connection::AddStream(quic::QuicStream *stream, Http3ConnectionStreamRole role,
                                    Http3ConnectionStreamState **state) noexcept
{
    if (state != nullptr)
    {
        *state = nullptr;
    }
    if (stream == nullptr || state == nullptr || streamCount_ >= streams_.Count())
    {
        return streamCount_ >= streams_.Count() ? STATUS_INSUFFICIENT_RESOURCES : STATUS_INVALID_PARAMETER;
    }
    Http3ConnectionStreamState &created = streams_[streamCount_];
    created.Stream = stream;
    created.StreamId = stream->Id();
    created.Role = role;
    Http3FrameHeaderParserInitialize(&created.HeaderParser);
    Http3ResponseStateInitialize(&created.Response, false, false);
    ++streamCount_;
    *state = &created;
    WKNET_TRACE(ComponentHttp3, TraceLevel::Info, "http3.stream.open stream_id=%I64u role=%u", created.StreamId,
                static_cast<ULONG>(created.Role));
    return STATUS_SUCCESS;
}

NTSTATUS Http3Connection::DrainStream(Http3ConnectionStreamState &state) noexcept
{
    if (state.Blocked)
    {
        return STATUS_PENDING;
    }
    if (state.Deferred.Length != 0)
    {
        SIZE_T consumed = 0;
        NTSTATUS status = ProcessBytes(state, state.Deferred.Data, state.Deferred.Length, &consumed);
        state.Deferred.ConsumePrefix(consumed);
        if (status == STATUS_PENDING || !NT_SUCCESS(status))
        {
            return status;
        }
    }

    while (!state.Blocked)
    {
        SIZE_T consumed = 0;
        bool fin = false;
        NTSTATUS status = quic::QuicConnectionWorkerConsumeStream(quicConnection_, state.Stream, readScratch_.Get(),
                                                                  readScratch_.Count(), &consumed, &fin);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (consumed != 0)
        {
            SIZE_T processed = 0;
            status = ProcessBytes(state, readScratch_.Get(), consumed, &processed);
            if (processed < consumed)
            {
                NTSTATUS storeStatus = state.Deferred.Append(readScratch_.Get() + processed, consumed - processed,
                                                             WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES);
                if (!NT_SUCCESS(storeStatus))
                {
                    return storeStatus;
                }
            }
            if (status == STATUS_PENDING)
            {
                state.DeferredFin = fin;
                return status;
            }
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
        if (fin)
        {
            state.FinSeen = true;
            return HandleStreamFin(state);
        }
        if (consumed == 0)
        {
            break;
        }
    }
    return state.Blocked ? STATUS_PENDING : STATUS_SUCCESS;
}

NTSTATUS Http3Connection::ProcessBytes(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                       SIZE_T *bytesConsumed) noexcept
{
    if (bytesConsumed == nullptr || (data == nullptr && length != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (state.Role == Http3ConnectionStreamRole::PendingUnidirectional)
    {
        return ProcessUnidirectionalType(state, data, length, bytesConsumed);
    }
    if (state.Role == Http3ConnectionStreamRole::PeerQpackEncoder ||
        state.Role == Http3ConnectionStreamRole::PeerQpackDecoder)
    {
        return ProcessInstructionBytes(state, data, length, bytesConsumed);
    }
    if (state.Role == Http3ConnectionStreamRole::UnknownUnidirectional)
    {
        *bytesConsumed = length;
        return STATUS_SUCCESS;
    }
    return ProcessFramedBytes(state, data, length, bytesConsumed);
}

NTSTATUS Http3Connection::ProcessUnidirectionalType(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                                    SIZE_T *bytesConsumed) noexcept
{
    SIZE_T offset = 0;
    while (offset < length && !state.StreamTypeParser.Complete)
    {
        NTSTATUS status = ConsumeVarIntByte(&state.StreamTypeParser, data[offset]);
        ++offset;
        if (!NT_SUCCESS(status))
        {
            *bytesConsumed = offset;
            return status;
        }
    }
    if (!state.StreamTypeParser.Complete)
    {
        *bytesConsumed = offset;
        return STATUS_SUCCESS;
    }

    const ULONGLONG type = state.StreamTypeParser.Value;
    if (type == Http3UnidirectionalControl)
    {
        if (peerControl_ != nullptr)
        {
            *bytesConsumed = offset;
            return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_STREAM_CREATION_ERROR);
        }
        peerControl_ = state.Stream;
        state.Role = Http3ConnectionStreamRole::PeerControl;
    }
    else if (type == Http3UnidirectionalQpackEncoder)
    {
        if (peerEncoder_ != nullptr)
        {
            *bytesConsumed = offset;
            return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_STREAM_CREATION_ERROR);
        }
        peerEncoder_ = state.Stream;
        state.Role = Http3ConnectionStreamRole::PeerQpackEncoder;
    }
    else if (type == Http3UnidirectionalQpackDecoder)
    {
        if (peerDecoder_ != nullptr)
        {
            *bytesConsumed = offset;
            return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_STREAM_CREATION_ERROR);
        }
        peerDecoder_ = state.Stream;
        state.Role = Http3ConnectionStreamRole::PeerQpackDecoder;
    }
    else if (type == Http3UnidirectionalPush)
    {
        *bytesConsumed = offset;
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_ID_ERROR);
    }
    else
    {
        state.Role = Http3ConnectionStreamRole::UnknownUnidirectional;
    }

    if (offset < length)
    {
        SIZE_T nested = 0;
        NTSTATUS status = ProcessBytes(state, data + offset, length - offset, &nested);
        offset += nested;
        *bytesConsumed = offset;
        return status;
    }
    *bytesConsumed = offset;
    return STATUS_SUCCESS;
}

NTSTATUS Http3Connection::ProcessInstructionBytes(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                                  SIZE_T *bytesConsumed) noexcept
{
    NTSTATUS status = state.Payload.Append(data, length, WKNET_HARD_MAX_QPACK_TOTAL_BLOCKED_BYTES);
    if (!NT_SUCCESS(status))
    {
        *bytesConsumed = 0;
        return status;
    }
    *bytesConsumed = length;
    while (state.Payload.Length != 0)
    {
        SIZE_T consumed = 0;
        ULONGLONG applicationError = 0;
        if (state.Role == Http3ConnectionStreamRole::PeerQpackEncoder)
        {
            status = decoder_.ProcessEncoderInstructions(state.Payload.Data, state.Payload.Length, &consumed,
                                                         &applicationError);
        }
        else
        {
            if (!encoderInitialized_)
            {
                return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_MISSING_SETTINGS);
            }
            status = encoder_.ProcessDecoderInstructions(state.Payload.Data, state.Payload.Length, &consumed,
                                                         &applicationError);
        }
        state.Payload.ConsumePrefix(consumed);
        if (status == STATUS_BUFFER_TOO_SMALL)
        {
            return STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(status))
        {
            return CloseConnection(status, applicationError);
        }
        if (consumed == 0)
        {
            break;
        }
    }
    return state.Role == Http3ConnectionStreamRole::PeerQpackEncoder ? ResumeBlockedStreams() : STATUS_SUCCESS;
}

NTSTATUS Http3Connection::ProcessFramedBytes(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                             SIZE_T *bytesConsumed) noexcept
{
    SIZE_T offset = 0;
    while (offset < length)
    {
        if (!state.FrameActive)
        {
            SIZE_T consumed = 0;
            bool complete = false;
            NTSTATUS status =
                Http3ConsumeFrameHeader(&state.HeaderParser, data + offset, length - offset, &consumed, &complete);
            offset += consumed;
            if (!NT_SUCCESS(status))
            {
                *bytesConsumed = offset;
                return status;
            }
            if (!complete)
            {
                break;
            }
            status = BeginFrame(state);
            if (!NT_SUCCESS(status))
            {
                *bytesConsumed = offset;
                return status;
            }
            if (!state.FrameActive)
            {
                continue;
            }
        }

        SIZE_T consumed = 0;
        NTSTATUS status = ProcessFramePayload(state, data + offset, length - offset, &consumed);
        offset += consumed;
        if (status == STATUS_PENDING || !NT_SUCCESS(status))
        {
            *bytesConsumed = offset;
            return status;
        }
        if (consumed == 0 && state.FrameActive)
        {
            break;
        }
    }
    *bytesConsumed = offset;
    return STATUS_SUCCESS;
}

NTSTATUS Http3Connection::BeginFrame(Http3ConnectionStreamState &state) noexcept
{
    Http3StreamKind streamKind =
        state.Role == Http3ConnectionStreamRole::Request ? Http3StreamKind::Request : Http3StreamKind::Control;
    ULONGLONG applicationError = 0;
    NTSTATUS status = Http3ValidateFramePlacement(state.HeaderParser.Header.Kind, streamKind, Http3EndpointRole::Server,
                                                  &applicationError);
    if (!NT_SUCCESS(status))
    {
        return CloseConnection(status, applicationError);
    }
    if (state.Role == Http3ConnectionStreamRole::PeerControl && !peerSettingsReceived_ &&
        state.HeaderParser.Header.Kind != Http3FrameKind::Settings)
    {
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_MISSING_SETTINGS);
    }
    if (state.HeaderParser.Header.Kind == Http3FrameKind::Settings && peerSettingsReceived_)
    {
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_FRAME_UNEXPECTED);
    }
    if (state.HeaderParser.Header.Kind == Http3FrameKind::PushPromise)
    {
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_ID_ERROR);
    }

    state.FrameActive = true;
    state.PayloadUsed = 0;
    const ULONGLONG length = state.HeaderParser.Header.Length;
    switch (state.HeaderParser.Header.Kind)
    {
    case Http3FrameKind::Data:
        state.PayloadMode = Http3PayloadMode::Stream;
        Http3FramePayloadCursorInitialize(&state.PayloadCursor, length);
        break;
    case Http3FrameKind::Headers:
        if (length > localMaximumFieldSectionBytes_)
        {
            return CloseConnection(STATUS_BUFFER_TOO_SMALL, H3_EXCESSIVE_LOAD);
        }
        state.PayloadMode = Http3PayloadMode::Headers;
        state.Payload.Length = 0;
        if (length != 0)
        {
            status = state.Payload.Reserve(static_cast<SIZE_T>(length));
        }
        break;
    case Http3FrameKind::Settings:
        state.PayloadMode = Http3PayloadMode::Settings;
        status = Http3SettingsParserInitialize(&state.SettingsParser, length, settingIdentifiers_.Get(),
                                               settingIdentifiers_.Count());
        break;
    case Http3FrameKind::Goaway:
    case Http3FrameKind::CancelPush:
    case Http3FrameKind::MaxPushId:
        state.PayloadMode = Http3PayloadMode::SingleValue;
        Http3SingleValueParserInitialize(&state.SingleValueParser, length);
        break;
    case Http3FrameKind::Unknown:
        state.PayloadMode = Http3PayloadMode::Unknown;
        Http3FramePayloadCursorInitialize(&state.PayloadCursor, length);
        break;
    default:
        status = CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_FRAME_UNEXPECTED);
        break;
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (length == 0)
    {
        if (state.PayloadMode == Http3PayloadMode::Settings || state.PayloadMode == Http3PayloadMode::Stream ||
            state.PayloadMode == Http3PayloadMode::Unknown || state.PayloadMode == Http3PayloadMode::Headers)
        {
            return FinishFrame(state);
        }
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_FRAME_ERROR);
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3Connection::ProcessFramePayload(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                              SIZE_T *bytesConsumed) noexcept
{
    *bytesConsumed = 0;
    if (state.PayloadMode == Http3PayloadMode::Stream || state.PayloadMode == Http3PayloadMode::Unknown)
    {
        Http3BufferView view = {};
        bool complete = false;
        NTSTATUS status = Http3ConsumeFramePayload(&state.PayloadCursor, data, length, &view, bytesConsumed, &complete);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (state.PayloadMode == Http3PayloadMode::Stream && view.Length != 0)
        {
            ULONGLONG applicationError = 0;
            status = Http3ProcessResponseData(&state.Response, view.Length, &applicationError);
            if (!NT_SUCCESS(status))
            {
                return CloseConnection(status, applicationError);
            }
            if (callbacks_.Data != nullptr)
            {
                callbacks_.Data(callbacks_.Context, state.StreamId, view.Data, view.Length);
            }
        }
        return complete ? FinishFrame(state) : STATUS_SUCCESS;
    }
    if (state.PayloadMode == Http3PayloadMode::Headers)
    {
        const ULONGLONG remaining = state.HeaderParser.Header.Length - state.PayloadUsed;
        const SIZE_T take = remaining < static_cast<ULONGLONG>(length) ? static_cast<SIZE_T>(remaining) : length;
        if (take != 0)
        {
            RtlCopyMemory(state.Payload.Data + state.PayloadUsed, data, take);
            state.PayloadUsed += take;
            state.Payload.Length = state.PayloadUsed;
        }
        *bytesConsumed = take;
        return state.PayloadUsed == state.HeaderParser.Header.Length ? FinishFrame(state) : STATUS_SUCCESS;
    }
    if (state.PayloadMode == Http3PayloadMode::Settings)
    {
        SIZE_T offset = 0;
        while (offset < length)
        {
            Http3Setting setting = {};
            SIZE_T consumed = 0;
            bool ready = false;
            bool complete = false;
            ULONGLONG applicationError = 0;
            NTSTATUS status = Http3ConsumeSettings(&state.SettingsParser, data + offset, length - offset, &consumed,
                                                   &ready, &setting, &complete, &applicationError);
            offset += consumed;
            if (!NT_SUCCESS(status))
            {
                *bytesConsumed = offset;
                return CloseConnection(status, applicationError);
            }
            if (ready)
            {
                status = ApplySetting(setting);
                if (!NT_SUCCESS(status))
                {
                    *bytesConsumed = offset;
                    return status;
                }
            }
            if (complete)
            {
                *bytesConsumed = offset;
                return FinishFrame(state);
            }
            if (consumed == 0)
            {
                break;
            }
        }
        *bytesConsumed = offset;
        return STATUS_SUCCESS;
    }
    if (state.PayloadMode == Http3PayloadMode::SingleValue)
    {
        bool complete = false;
        ULONGLONG value = 0;
        ULONGLONG applicationError = 0;
        NTSTATUS status = Http3ConsumeSingleValuePayload(&state.SingleValueParser, data, length, bytesConsumed,
                                                         &complete, &value, &applicationError);
        if (!NT_SUCCESS(status))
        {
            return CloseConnection(status, applicationError);
        }
        if (complete)
        {
            status = HandleSingleValue(state, value);
            return NT_SUCCESS(status) ? FinishFrame(state) : status;
        }
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_DEVICE_STATE;
}

NTSTATUS Http3Connection::FinishFrame(Http3ConnectionStreamState &state) noexcept
{
    NTSTATUS status = STATUS_SUCCESS;
    if (state.PayloadMode == Http3PayloadMode::Headers)
    {
        status = DecodeHeaders(state, false);
    }
    else if (state.PayloadMode == Http3PayloadMode::Settings)
    {
        peerSettingsReceived_ = true;
        status = encoder_.Initialize(peerQpackMaximumCapacity_, peerQpackBlockedStreams_);
        encoderInitialized_ = NT_SUCCESS(status);
    }
    state.FrameActive = false;
    state.PayloadMode = Http3PayloadMode::None;
    state.PayloadUsed = 0;
    Http3FrameHeaderParserInitialize(&state.HeaderParser);
    state.SingleValueParser = {};
    state.SettingsParser = {};
    return status;
}

NTSTATUS Http3Connection::DecodeHeaders(Http3ConnectionStreamState &state, bool resume) noexcept
{
    if (!state.Fields.IsValid())
    {
        NTSTATUS status = state.Fields.Allocate(WKNET_HARD_MAX_HTTP3_FIELDS);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    NTSTATUS status = state.FieldBytes.Reserve(localMaximumFieldSectionBytes_);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SIZE_T fieldCount = 0;
    SIZE_T fieldBytes = 0;
    SIZE_T instructionLength = 0;
    ULONGLONG applicationError = 0;
    if (resume)
    {
        status = decoder_.ResumeBlockedFieldSection(state.StreamId, state.Fields.Get(), state.Fields.Count(),
                                                    &fieldCount, state.FieldBytes.Data, state.FieldBytes.Capacity,
                                                    &fieldBytes, writeScratch_.Get(), writeScratch_.Count(),
                                                    &instructionLength, &applicationError);
    }
    else
    {
        status = decoder_.DecodeFieldSection(
            state.StreamId, state.Payload.Data, state.Payload.Length, state.Fields.Get(), state.Fields.Count(),
            &fieldCount, state.FieldBytes.Data, state.FieldBytes.Capacity, &fieldBytes, writeScratch_.Get(),
            writeScratch_.Count(), &instructionLength, &applicationError);
    }
    if (status == STATUS_PENDING)
    {
        state.Blocked = true;
        state.Payload.Length = 0;
        return STATUS_PENDING;
    }
    if (!NT_SUCCESS(status))
    {
        return CloseConnection(status, applicationError);
    }
    state.Blocked = false;
    state.FieldBytes.Length = fieldBytes;
    status = ProcessDecodedFields(state, fieldCount, state.Response.FinalHeadersReceived);
    if (NT_SUCCESS(status) && instructionLength != 0)
    {
        Http3ConnectionStreamState *decoderState = FindStream(localDecoder_);
        status = decoderState != nullptr ? QueueWrite(*decoderState, writeScratch_.Get(), instructionLength)
                                         : STATUS_NOT_FOUND;
        if (NT_SUCCESS(status))
        {
            localDecoderBytesSent_ += instructionLength;
        }
    }
    state.Payload.Length = 0;
    return status;
}

NTSTATUS Http3Connection::ProcessDecodedFields(Http3ConnectionStreamState &state, SIZE_T fieldCount,
                                               bool trailers) noexcept
{
    ULONGLONG applicationError = 0;
    NTSTATUS status =
        Http3ProcessResponseFields(&state.Response, state.Fields.Get(), fieldCount, trailers, &applicationError);
    if (!NT_SUCCESS(status))
    {
        return CloseConnection(status, applicationError);
    }
    if (callbacks_.Headers != nullptr)
    {
        callbacks_.Headers(callbacks_.Context, state.StreamId, state.Fields.Get(), fieldCount, trailers);
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3Connection::ResumeBlockedStreams() noexcept
{
    for (SIZE_T index = 0; index < streamCount_; ++index)
    {
        Http3ConnectionStreamState &state = streams_[index];
        if (!state.Blocked)
        {
            continue;
        }
        NTSTATUS status = DecodeHeaders(state, true);
        if (status == STATUS_PENDING)
        {
            continue;
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (state.Deferred.Length != 0)
        {
            SIZE_T consumed = 0;
            status = ProcessBytes(state, state.Deferred.Data, state.Deferred.Length, &consumed);
            state.Deferred.ConsumePrefix(consumed);
            if (!NT_SUCCESS(status) && status != STATUS_PENDING)
            {
                return status;
            }
        }
        if (!state.Blocked && state.DeferredFin)
        {
            state.DeferredFin = false;
            status = HandleStreamFin(state);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
        if (!state.Blocked)
        {
            status = DrainStream(state);
            if (!NT_SUCCESS(status) && status != STATUS_PENDING)
            {
                return status;
            }
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3Connection::ApplySetting(const Http3Setting &setting) noexcept
{
    if (setting.Kind == Http3SettingKind::QpackMaxTableCapacity)
    {
        peerQpackMaximumCapacity_ = setting.Value > WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES
                                        ? WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES
                                        : static_cast<SIZE_T>(setting.Value);
    }
    else if (setting.Kind == Http3SettingKind::QpackBlockedStreams)
    {
        peerQpackBlockedStreams_ = setting.Value > WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS
                                       ? WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS
                                       : static_cast<ULONG>(setting.Value);
    }
    else if (setting.Kind == Http3SettingKind::MaxFieldSectionSize)
    {
        peerMaximumFieldSectionBytes_ = setting.Value;
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3Connection::HandleSingleValue(Http3ConnectionStreamState &state, ULONGLONG value) noexcept
{
    if (state.HeaderParser.Header.Kind == Http3FrameKind::Goaway)
    {
        if (!IsRequestStreamId(value) || value > goawayId_)
        {
            return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_ID_ERROR);
        }
        goawayId_ = value;
        WKNET_TRACE(ComponentHttp3, TraceLevel::Warning, "http3.connection.goaway stream_id=%I64u", value);
        if (callbacks_.Goaway != nullptr)
        {
            callbacks_.Goaway(callbacks_.Context, value);
        }
        return STATUS_SUCCESS;
    }
    return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_FRAME_UNEXPECTED);
}

NTSTATUS Http3Connection::HandleStreamFin(Http3ConnectionStreamState &state) noexcept
{
    if (state.FrameActive || state.HeaderParser.Phase != Http3FrameHeaderPhase::Type)
    {
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_FRAME_ERROR);
    }
    if (IsCriticalRole(state.Role))
    {
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_CLOSED_CRITICAL_STREAM);
    }
    if (state.Role == Http3ConnectionStreamRole::PendingUnidirectional)
    {
        return CloseConnection(STATUS_INVALID_NETWORK_RESPONSE, H3_STREAM_CREATION_ERROR);
    }
    if (state.Role != Http3ConnectionStreamRole::Request)
    {
        return STATUS_SUCCESS;
    }
    if (state.Blocked)
    {
        state.DeferredFin = true;
        return STATUS_PENDING;
    }
    ULONGLONG applicationError = 0;
    NTSTATUS status = Http3CompleteResponse(&state.Response, &applicationError);
    if (!NT_SUCCESS(status))
    {
        return CloseConnection(status, applicationError);
    }
    NotifyStreamComplete(state, STATUS_SUCCESS, H3_NO_ERROR);
    return STATUS_SUCCESS;
}

void Http3Connection::HandleReset(Http3ConnectionStreamState &state, ULONGLONG errorCode) noexcept
{
    NTSTATUS status = CancelBlockedSection(state);
    WKNET_TRACE(ComponentHttp3, TraceLevel::Info, "http3.stream.reset stream_id=%I64u error=0x%I64X", state.StreamId,
                errorCode);
    NotifyStreamComplete(state, NT_SUCCESS(status) ? STATUS_CANCELLED : status, errorCode);
}

NTSTATUS Http3Connection::CancelBlockedSection(Http3ConnectionStreamState &state) noexcept
{
    SIZE_T instructionLength = 0;
    NTSTATUS status =
        decoder_.CancelStream(state.StreamId, writeScratch_.Get(), writeScratch_.Count(), &instructionLength);
    state.Blocked = false;
    if (status == STATUS_NOT_FOUND)
    {
        return STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status) && instructionLength != 0)
    {
        Http3ConnectionStreamState *decoderState = FindStream(localDecoder_);
        status = decoderState != nullptr ? QueueWrite(*decoderState, writeScratch_.Get(), instructionLength)
                                         : STATUS_NOT_FOUND;
        if (NT_SUCCESS(status))
        {
            localDecoderBytesSent_ += instructionLength;
        }
    }
    return status;
}

NTSTATUS Http3Connection::CloseConnection(NTSTATUS status, ULONGLONG applicationError) noexcept
{
    if (failed_)
    {
        return status;
    }
    failed_ = true;
    WKNET_TRACE(ComponentHttp3, TraceLevel::Error,
                "http3.connection.failed status=0x%08X application_error=0x%I64X stream_count=%Iu",
                static_cast<ULONG>(status), applicationError, streamCount_);
    if (callbacks_.ConnectionError != nullptr)
    {
        callbacks_.ConnectionError(callbacks_.Context, status, applicationError);
    }
    NTSTATUS closeStatus = quicConnection_ != nullptr
                               ? quic::QuicConnectionWorkerCloseApplication(quicConnection_, applicationError)
                               : STATUS_INVALID_DEVICE_STATE;
    return NT_SUCCESS(closeStatus) ? status : closeStatus;
}

void Http3Connection::NotifyStreamComplete(Http3ConnectionStreamState &state, NTSTATUS status,
                                           ULONGLONG applicationError) noexcept
{
    if (state.CompleteNotified)
    {
        return;
    }
    state.CompleteNotified = true;
    WKNET_TRACE(ComponentHttp3, TraceLevel::Info,
                "http3.stream.complete stream_id=%I64u status=0x%08X application_error=0x%I64X", state.StreamId,
                static_cast<ULONG>(status), applicationError);
    if (callbacks_.StreamComplete != nullptr)
    {
        callbacks_.StreamComplete(callbacks_.Context, state.StreamId, status, applicationError);
    }
}

void Http3Connection::Clear() noexcept
{
    encoder_.Reset();
    decoder_.Reset();
    streams_.Reset();
    readScratch_.Reset();
    writeScratch_.Reset();
    settingIdentifiers_.Reset();
    streamCount_ = 0;
    quicConnection_ = nullptr;
}

NTSTATUS Http3ConnectionCreate(const Http3ConnectionCreateOptions &options, Http3Connection **connection) noexcept
{
    if (connection != nullptr)
    {
        *connection = nullptr;
    }
    if (connection == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    Http3Connection *created = AllocateNonPagedObject<Http3Connection>();
    if (created == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NTSTATUS status = created->Initialize(options);
    if (!NT_SUCCESS(status))
    {
        FreeNonPagedObject(created);
        return status;
    }
    *connection = created;
    return STATUS_SUCCESS;
}

NTSTATUS Http3ConnectionBindQuic(Http3Connection *connection, quic::QuicConnection *quicConnection) noexcept
{
    return connection != nullptr ? connection->BindQuic(quicConnection) : STATUS_INVALID_PARAMETER;
}

const quic::QuicStreamApplicationEventSink *Http3ConnectionApplicationSink(const Http3Connection *connection) noexcept
{
    return connection != nullptr ? connection->ApplicationSink() : nullptr;
}

void Http3ConnectionBeginShutdown(Http3Connection *connection) noexcept
{
    if (connection != nullptr)
    {
        connection->BeginShutdown();
    }
}

void Http3ConnectionDestroy(Http3Connection *connection) noexcept
{
    FreeNonPagedObject(connection);
}

NTSTATUS Http3ConnectionWorkerOpenRequest(Http3Connection *connection, const Http3RequestOpenOptions &options,
                                          ULONGLONG *streamId) noexcept
{
    return connection != nullptr ? connection->OpenRequest(options, streamId) : STATUS_INVALID_PARAMETER;
}

NTSTATUS Http3ConnectionWorkerWriteRequestData(Http3Connection *connection, ULONGLONG streamId, const UCHAR *data,
                                               SIZE_T length, bool fin) noexcept
{
    return connection != nullptr ? connection->WriteRequestData(streamId, data, length, fin) : STATUS_INVALID_PARAMETER;
}

NTSTATUS Http3ConnectionWorkerWriteRequestTrailers(Http3Connection *connection, ULONGLONG streamId,
                                                   const qpack::QpackFieldView *fields, SIZE_T fieldCount) noexcept
{
    return connection != nullptr ? connection->WriteRequestTrailers(streamId, fields, fieldCount)
                                 : STATUS_INVALID_PARAMETER;
}

NTSTATUS Http3ConnectionWorkerCancelRequest(Http3Connection *connection, ULONGLONG streamId,
                                            ULONGLONG applicationError) noexcept
{
    return connection != nullptr ? connection->CancelRequest(streamId, applicationError) : STATUS_INVALID_PARAMETER;
}

bool Http3ConnectionPeerSettingsReceived(const Http3Connection *connection) noexcept
{
    return connection != nullptr && connection->PeerSettingsReceived();
}

SIZE_T Http3ConnectionPeerQpackMaximumCapacity(const Http3Connection *connection) noexcept
{
    return connection != nullptr ? connection->PeerQpackMaximumCapacity() : 0;
}

ULONG Http3ConnectionPeerQpackBlockedStreams(const Http3Connection *connection) noexcept
{
    return connection != nullptr ? connection->PeerQpackBlockedStreams() : 0;
}

ULONGLONG Http3ConnectionGoawayId(const Http3Connection *connection) noexcept
{
    return connection != nullptr ? connection->GoawayId() : quic::QuicVarIntMaximum;
}

SIZE_T Http3ConnectionBlockedStreamCount(const Http3Connection *connection) noexcept
{
    return connection != nullptr ? connection->BlockedStreamCount() : 0;
}

ULONGLONG Http3ConnectionLocalDecoderBytesSent(const Http3Connection *connection) noexcept
{
    return connection != nullptr ? connection->LocalDecoderBytesSent() : 0;
}
#if defined(WKNET_USER_MODE_TEST)
NTSTATUS Http3ConnectionTestApplyPeerSettings(Http3Connection *connection, SIZE_T qpackMaximumCapacity,
                                              ULONG qpackBlockedStreams) noexcept
{
    return connection != nullptr ? connection->TestApplyPeerSettings(qpackMaximumCapacity, qpackBlockedStreams)
                                 : STATUS_INVALID_PARAMETER;
}
#endif
} // namespace wknet::http3
