#pragma once

#include "http3/Http3Request.h"
#include "quic/QuicConnection.h"

namespace wknet::http3
{
using Http3HeadersEvent = void (*)(void *context, ULONGLONG streamId,
                                   _In_reads_(fieldCount) const qpack::QpackFieldView *fields, SIZE_T fieldCount,
                                   bool trailers) noexcept;
using Http3DataEvent = void (*)(void *context, ULONGLONG streamId, _In_reads_bytes_(length) const UCHAR *data,
                                SIZE_T length) noexcept;
using Http3StreamCompleteEvent = void (*)(void *context, ULONGLONG streamId, NTSTATUS status,
                                          ULONGLONG applicationError) noexcept;
using Http3GoawayEvent = void (*)(void *context, ULONGLONG streamId) noexcept;
using Http3ConnectionErrorEvent = void (*)(void *context, NTSTATUS status, ULONGLONG applicationError) noexcept;

struct Http3ConnectionCallbacks final
{
    void *Context = nullptr;
    Http3HeadersEvent Headers = nullptr;
    Http3DataEvent Data = nullptr;
    Http3StreamCompleteEvent StreamComplete = nullptr;
    Http3GoawayEvent Goaway = nullptr;
    Http3ConnectionErrorEvent ConnectionError = nullptr;
};

struct Http3ConnectionCreateOptions final
{
    Http3ConnectionCallbacks Callbacks = {};
    SIZE_T LocalQpackMaximumCapacity = WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES;
    ULONG LocalQpackBlockedStreams = WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS;
    SIZE_T LocalMaximumFieldSectionBytes = WKNET_HARD_MAX_HTTP3_FIELD_SECTION_BYTES;
};

struct Http3RequestOpenOptions final
{
    Http3RequestFieldOptions Fields = {};
    bool RequestWasHead = false;
};

class Http3Connection;

NTSTATUS Http3ConnectionCreate(_In_ const Http3ConnectionCreateOptions &options,
                               _Out_ Http3Connection **connection) noexcept;
NTSTATUS Http3ConnectionBindQuic(_Inout_ Http3Connection *connection,
                                 _Inout_ quic::QuicConnection *quicConnection) noexcept;
NTSTATUS Http3ConnectionWorkerStart(_Inout_ Http3Connection *connection) noexcept;
const quic::QuicStreamApplicationEventSink *Http3ConnectionApplicationSink(
    _In_ const Http3Connection *connection) noexcept;
void Http3ConnectionBeginShutdown(_Inout_ Http3Connection *connection) noexcept;
// Call BeginShutdown, close and destroy QuicConnection so callbacks drain, then destroy Http3Connection.
// Http3Connection does not own QuicConnection or QuicStream objects.
void Http3ConnectionDestroy(_Inout_opt_ Http3Connection *connection) noexcept;

NTSTATUS Http3ConnectionWorkerOpenRequest(_Inout_ Http3Connection *connection,
                                          _In_ const Http3RequestOpenOptions &options,
                                          _Out_ ULONGLONG *streamId) noexcept;
NTSTATUS Http3ConnectionWorkerWriteRequestData(_Inout_ Http3Connection *connection, ULONGLONG streamId,
                                               _In_reads_bytes_opt_(length) const UCHAR *data, SIZE_T length,
                                               bool fin) noexcept;
NTSTATUS Http3ConnectionWorkerWriteRequestTrailers(_Inout_ Http3Connection *connection, ULONGLONG streamId,
                                                   _In_reads_(fieldCount) const qpack::QpackFieldView *fields,
                                                   SIZE_T fieldCount) noexcept;
NTSTATUS Http3ConnectionWorkerCancelRequest(_Inout_ Http3Connection *connection, ULONGLONG streamId,
                                            ULONGLONG applicationError) noexcept;

bool Http3ConnectionPeerSettingsReceived(_In_ const Http3Connection *connection) noexcept;
SIZE_T Http3ConnectionPeerQpackMaximumCapacity(_In_ const Http3Connection *connection) noexcept;
ULONG Http3ConnectionPeerQpackBlockedStreams(_In_ const Http3Connection *connection) noexcept;
ULONGLONG Http3ConnectionGoawayId(_In_ const Http3Connection *connection) noexcept;
SIZE_T Http3ConnectionBlockedStreamCount(_In_ const Http3Connection *connection) noexcept;
ULONGLONG Http3ConnectionLocalDecoderBytesSent(_In_ const Http3Connection *connection) noexcept;
#if defined(WKNET_USER_MODE_TEST)
NTSTATUS Http3ConnectionTestApplyPeerSettings(_Inout_ Http3Connection *connection, SIZE_T qpackMaximumCapacity,
                                              ULONG qpackBlockedStreams) noexcept;
#endif
} // namespace wknet::http3
