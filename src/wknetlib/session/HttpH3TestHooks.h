#pragma once

#include "session/HttpEngineInternal.hpp"

#if defined(WKNET_USER_MODE_TEST)
namespace wknet::session
{
enum class HttpH3TestDispatchKind : ULONG
{
    Http1 = 0,
    Http2 = 1,
    Http3 = 2
};

enum class HttpH3TestPoolKind : ULONG
{
    None = 0,
    Tcp = 1,
    Quic = 2
};

struct HttpH3TestSnapshot final
{
    ULONGLONG AttemptGeneration = 0;
    ULONGLONG StreamId = HttpH3UnsetStreamId;
    ULONG H1DispatchCount = 0;
    ULONG H2DispatchCount = 0;
    ULONG H3DispatchCount = 0;
    ULONG BodyReadCount = 0;
    ULONG CompletionCount = 0;
    ULONG PoolLeaseCount = 0;
    HttpH3RequestState RequestState = HttpH3RequestState::NoStream;
    HttpH3TestPoolKind PoolKind = HttpH3TestPoolKind::None;
    NTSTATUS TerminalStatus = STATUS_PENDING;
    ULONGLONG ApplicationError = 0;
};

void HttpH3TestReset() noexcept;
void HttpH3TestSetPeerFactory(_In_opt_ const HttpH3PeerFactory *factory) noexcept;
bool HttpH3TestGetPeerFactory(_Out_ HttpH3PeerFactory *factory) noexcept;
void HttpH3TestRecordDispatch(HttpH3TestDispatchKind kind) noexcept;
void HttpH3TestRecordPoolSnapshot(HttpH3TestPoolKind kind, ULONG leaseCount) noexcept;
void HttpH3TestObserveDispatch(_In_ const HttpH3DispatchContext *context) noexcept;
void HttpH3TestGetSnapshot(_Out_ HttpH3TestSnapshot *snapshot) noexcept;

_Must_inspect_result_ NTSTATUS HttpH3TestCreateInMemoryPeer(_In_ const HttpH3PeerCreateOptions *options,
                                                            _Out_ HttpH3Peer *peer) noexcept;

_Must_inspect_result_ NTSTATUS HttpH3TestDispatchRequired(_In_ const Request *request,
                                                          _In_ const HttpSendOptions *sendOptions,
                                                          ULONGLONG attemptGeneration,
                                                          _Out_ HttpH3DispatchContext *context) noexcept;

void HttpH3TestInjectResponseStarted(_Inout_ HttpH3DispatchContext *context, ULONG statusCode) noexcept;

_Must_inspect_result_ NTSTATUS HttpH3TestInjectHeader(_Inout_ HttpH3DispatchContext *context,
                                                      _In_reads_bytes_(nameLength) const char *name, SIZE_T nameLength,
                                                      _In_reads_bytes_(valueLength) const char *value,
                                                      SIZE_T valueLength, bool trailers) noexcept;

_Must_inspect_result_ NTSTATUS HttpH3TestInjectBody(_Inout_ HttpH3DispatchContext *context,
                                                    _In_reads_bytes_opt_(dataLength) const UCHAR *data,
                                                    SIZE_T dataLength, bool finalChunk) noexcept;

void HttpH3TestInjectCompletion(_Inout_ HttpH3DispatchContext *context, NTSTATUS status,
                                ULONGLONG applicationError) noexcept;

_Must_inspect_result_ NTSTATUS HttpH3TestInjectGoaway(_Inout_ HttpH3DispatchContext *context, ULONGLONG goawayId,
                                                      _Out_ HttpH3GoawayResult *result) noexcept;
} // namespace wknet::session
#endif
