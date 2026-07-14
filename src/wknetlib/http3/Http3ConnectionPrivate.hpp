#pragma once

#include "http3/Http3Connection.h"
#include "http3/Http3Frame.h"
#include "qpack/QpackDecoder.h"
#include "rtl/ProtocolAllocator.h"

namespace wknet::http3
{
constexpr SIZE_T Http3MaximumTrackedStreams =
    WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS + WKNET_HARD_MAX_QUIC_PEER_BIDI_STREAMS +
    WKNET_HARD_MAX_QUIC_LOCAL_UNI_STREAMS + WKNET_HARD_MAX_QUIC_PEER_UNI_STREAMS;
constexpr SIZE_T Http3ReadScratchBytes = 4096;

enum class Http3ConnectionStreamRole : UCHAR
{
    PendingUnidirectional,
    Request,
    PeerControl,
    PeerQpackEncoder,
    PeerQpackDecoder,
    UnknownUnidirectional,
    LocalControl,
    LocalQpackEncoder,
    LocalQpackDecoder
};

enum class Http3PayloadMode : UCHAR
{
    None,
    Stream,
    Headers,
    Settings,
    SingleValue,
    Unknown
};

struct Http3OwnedBuffer final
{
    UCHAR *Data = nullptr;
    SIZE_T Length = 0;
    SIZE_T Capacity = 0;
    rtl::ProtocolAllocationSite AllocationSite = rtl::ProtocolAllocationSite::Invalid;

    ~Http3OwnedBuffer() noexcept;
    NTSTATUS Reserve(SIZE_T capacity) noexcept;
    NTSTATUS Append(_In_reads_bytes_(length) const UCHAR *data, SIZE_T length, SIZE_T maximum) noexcept;
    void ConsumePrefix(SIZE_T length) noexcept;
    void Clear() noexcept;
};

struct Http3ConnectionStreamState final
{
    quic::QuicStream *Stream = nullptr;
    ULONGLONG StreamId = 0;
    Http3ConnectionStreamRole Role = Http3ConnectionStreamRole::PendingUnidirectional;
    Http3FrameHeaderParser HeaderParser = {};
    Http3FramePayloadCursor PayloadCursor = {};
    Http3SingleValueParser SingleValueParser = {};
    Http3SettingsParser SettingsParser = {};
    Http3VarIntParser StreamTypeParser = {};
    Http3ResponseState Response = {};
    Http3OwnedBuffer Payload = {};
    Http3OwnedBuffer Deferred = {};
    Http3OwnedBuffer PendingWrite = {};
    ProtocolHeapArray<qpack::QpackFieldView, rtl::ProtocolAllocationSite::Http3RequestFields> Fields = {};
    Http3OwnedBuffer FieldBytes = {};
    Http3PayloadMode PayloadMode = Http3PayloadMode::None;
    SIZE_T PayloadUsed = 0;
    bool FrameActive = false;
    bool Blocked = false;
    bool DeferredFin = false;
    bool FinSeen = false;
    bool CompleteNotified = false;
    bool PendingWriteFin = false;
    bool RequestHeadersSent = false;
    bool RequestFinSent = false;
};

class Http3Connection final
{
  public:
    Http3Connection() noexcept;
    ~Http3Connection() noexcept;
    Http3Connection(const Http3Connection &) = delete;
    Http3Connection &operator=(const Http3Connection &) = delete;

    NTSTATUS Initialize(const Http3ConnectionCreateOptions &options) noexcept;
    NTSTATUS BindQuic(quic::QuicConnection *connection) noexcept;
    NTSTATUS Start() noexcept;
    const quic::QuicStreamApplicationEventSink *ApplicationSink() const noexcept;
    void BeginShutdown() noexcept;
    bool PeerSettingsReceived() const noexcept;
    SIZE_T PeerQpackMaximumCapacity() const noexcept;
    ULONG PeerQpackBlockedStreams() const noexcept;
    ULONGLONG GoawayId() const noexcept;
    SIZE_T BlockedStreamCount() const noexcept;
    ULONGLONG LocalDecoderBytesSent() const noexcept;
    NTSTATUS OpenRequest(const Http3RequestOpenOptions &options, ULONGLONG *streamId) noexcept;
    NTSTATUS WriteRequestData(ULONGLONG streamId, const UCHAR *data, SIZE_T length, bool fin) noexcept;
    NTSTATUS WriteRequestTrailers(ULONGLONG streamId, const qpack::QpackFieldView *fields, SIZE_T fieldCount) noexcept;
    NTSTATUS CancelRequest(ULONGLONG streamId, ULONGLONG applicationError) noexcept;
#if defined(WKNET_USER_MODE_TEST)
    NTSTATUS TestApplyPeerSettings(SIZE_T qpackMaximumCapacity, ULONG qpackBlockedStreams) noexcept;
#endif

  private:
    static void OnStreamOpened(void *context, quic::QuicStream *stream) noexcept;
    static void OnStreamReadable(void *context, quic::QuicStream *stream) noexcept;
    static void OnStreamWritable(void *context, quic::QuicStream *stream) noexcept;
    static void OnStreamReset(void *context, quic::QuicStream *stream, ULONGLONG errorCode,
                              bool peerInitiated) noexcept;
    static void OnStreamClosed(void *context, quic::QuicStream *stream) noexcept;

    NTSTATUS EnsureStarted() noexcept;
    NTSTATUS OpenLocalCriticalStream(Http3ConnectionStreamRole role, ULONGLONG streamType,
                                     quic::QuicStream **stream) noexcept;
    NTSTATUS SendLocalSettings() noexcept;
    NTSTATUS QueueWrite(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length, bool fin = false) noexcept;
    NTSTATUS FlushWrite(Http3ConnectionStreamState &state) noexcept;
    NTSTATUS WriteFrameHeader(Http3ConnectionStreamState &state, ULONGLONG type, SIZE_T payloadLength) noexcept;
    NTSTATUS EncodeFieldSection(Http3ConnectionStreamState &state, const qpack::QpackFieldView *fields,
                                SIZE_T fieldCount) noexcept;
    Http3ConnectionStreamState *FindStream(quic::QuicStream *stream) noexcept;
    Http3ConnectionStreamState *FindStreamById(ULONGLONG streamId) noexcept;
    NTSTATUS AddStream(quic::QuicStream *stream, Http3ConnectionStreamRole role,
                       Http3ConnectionStreamState **state) noexcept;
    NTSTATUS DrainStream(Http3ConnectionStreamState &state) noexcept;
    NTSTATUS ProcessBytes(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                          SIZE_T *bytesConsumed) noexcept;
    NTSTATUS ProcessUnidirectionalType(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                       SIZE_T *bytesConsumed) noexcept;
    NTSTATUS ProcessInstructionBytes(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                     SIZE_T *bytesConsumed) noexcept;
    NTSTATUS ProcessFramedBytes(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                SIZE_T *bytesConsumed) noexcept;
    NTSTATUS BeginFrame(Http3ConnectionStreamState &state) noexcept;
    NTSTATUS ProcessFramePayload(Http3ConnectionStreamState &state, const UCHAR *data, SIZE_T length,
                                 SIZE_T *bytesConsumed) noexcept;
    NTSTATUS FinishFrame(Http3ConnectionStreamState &state) noexcept;
    NTSTATUS DecodeHeaders(Http3ConnectionStreamState &state, bool resume) noexcept;
    NTSTATUS ProcessDecodedFields(Http3ConnectionStreamState &state, SIZE_T fieldCount, bool trailers) noexcept;
    NTSTATUS ResumeBlockedStreams() noexcept;
    NTSTATUS ApplySetting(const Http3Setting &setting) noexcept;
    NTSTATUS HandleSingleValue(Http3ConnectionStreamState &state, ULONGLONG value) noexcept;
    NTSTATUS HandleStreamFin(Http3ConnectionStreamState &state) noexcept;
    void HandleReset(Http3ConnectionStreamState &state, ULONGLONG errorCode) noexcept;
    NTSTATUS CancelBlockedSection(Http3ConnectionStreamState &state) noexcept;
    NTSTATUS CloseConnection(NTSTATUS status, ULONGLONG applicationError) noexcept;
    void NotifyStreamComplete(Http3ConnectionStreamState &state, NTSTATUS status, ULONGLONG applicationError) noexcept;
    void Clear() noexcept;

    quic::QuicConnection *quicConnection_ = nullptr;
    quic::QuicStreamApplicationEventSink applicationSink_ = {};
    Http3ConnectionCallbacks callbacks_ = {};
    ProtocolHeapArray<Http3ConnectionStreamState, rtl::ProtocolAllocationSite::Http3TrackedStreams> streams_ = {};
    ProtocolHeapArray<UCHAR, rtl::ProtocolAllocationSite::Http3ReadScratch> readScratch_ = {};
    ProtocolHeapArray<UCHAR, rtl::ProtocolAllocationSite::Http3WriteScratch> writeScratch_ = {};
    ProtocolHeapArray<ULONGLONG, rtl::ProtocolAllocationSite::Http3Settings> settingIdentifiers_ = {};
    qpack::QpackEncoder encoder_ = {};
    qpack::QpackDecoder decoder_ = {};
    quic::QuicStream *localControl_ = nullptr;
    quic::QuicStream *localEncoder_ = nullptr;
    quic::QuicStream *localDecoder_ = nullptr;
    quic::QuicStream *peerControl_ = nullptr;
    quic::QuicStream *peerEncoder_ = nullptr;
    quic::QuicStream *peerDecoder_ = nullptr;
    SIZE_T streamCount_ = 0;
    SIZE_T localQpackMaximumCapacity_ = 0;
    ULONG localQpackBlockedStreams_ = 0;
    SIZE_T localMaximumFieldSectionBytes_ = 0;
    SIZE_T peerQpackMaximumCapacity_ = 0;
    ULONG peerQpackBlockedStreams_ = 0;
    ULONGLONG peerMaximumFieldSectionBytes_ = 0;
    ULONGLONG goawayId_ = quic::QuicVarIntMaximum;
    ULONGLONG localDecoderBytesSent_ = 0;
    bool peerSettingsReceived_ = false;
    bool encoderInitialized_ = false;
    bool started_ = false;
    bool starting_ = false;
    bool failed_ = false;
    bool shuttingDown_ = false;
};
} // namespace wknet::http3
