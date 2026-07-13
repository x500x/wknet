#include "session/HttpH3TestHooks.h"

#if defined(WKNET_USER_MODE_TEST)
#include <mutex>

namespace wknet::session
{
namespace
{
std::mutex g_httpH3TestLock;
HttpH3PeerFactory g_httpH3PeerFactory = {};
HttpH3TestSnapshot g_httpH3Snapshot = {};
bool g_httpH3PeerFactorySet = false;
} // namespace

void HttpH3TestReset() noexcept
{
    std::lock_guard<std::mutex> lock(g_httpH3TestLock);
    g_httpH3PeerFactory = {};
    g_httpH3Snapshot = {};
    g_httpH3Snapshot.StreamId = HttpH3UnsetStreamId;
    g_httpH3Snapshot.TerminalStatus = STATUS_PENDING;
    g_httpH3PeerFactorySet = false;
}

void HttpH3TestSetPeerFactory(const HttpH3PeerFactory *factory) noexcept
{
    std::lock_guard<std::mutex> lock(g_httpH3TestLock);
    g_httpH3PeerFactory = factory != nullptr ? *factory : HttpH3PeerFactory{};
    g_httpH3PeerFactorySet = factory != nullptr && factory->Create != nullptr;
}

bool HttpH3TestGetPeerFactory(HttpH3PeerFactory *factory) noexcept
{
    if (factory == nullptr)
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_httpH3TestLock);
    *factory = g_httpH3PeerFactory;
    return g_httpH3PeerFactorySet;
}

void HttpH3TestRecordDispatch(HttpH3TestDispatchKind kind) noexcept
{
    std::lock_guard<std::mutex> lock(g_httpH3TestLock);
    switch (kind)
    {
    case HttpH3TestDispatchKind::Http1:
        ++g_httpH3Snapshot.H1DispatchCount;
        break;
    case HttpH3TestDispatchKind::Http2:
        ++g_httpH3Snapshot.H2DispatchCount;
        break;
    case HttpH3TestDispatchKind::Http3:
        ++g_httpH3Snapshot.H3DispatchCount;
        break;
    }
}

void HttpH3TestRecordPoolSnapshot(HttpH3TestPoolKind kind, ULONG leaseCount) noexcept
{
    std::lock_guard<std::mutex> lock(g_httpH3TestLock);
    g_httpH3Snapshot.PoolKind = kind;
    g_httpH3Snapshot.PoolLeaseCount = leaseCount;
}

void HttpH3TestObserveDispatch(const HttpH3DispatchContext *context) noexcept
{
    if (context == nullptr)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_httpH3TestLock);
    g_httpH3Snapshot.AttemptGeneration = context->AttemptGeneration;
    g_httpH3Snapshot.StreamId = context->StreamId;
    g_httpH3Snapshot.BodyReadCount = context->BodyReadCount;
    g_httpH3Snapshot.RequestState = context->State;
    g_httpH3Snapshot.TerminalStatus = context->TerminalStatus;
    g_httpH3Snapshot.ApplicationError = context->ApplicationError;
    g_httpH3Snapshot.CompletionCount = context->CompletionDelivered ? 1 : 0;
}

void HttpH3TestGetSnapshot(HttpH3TestSnapshot *snapshot) noexcept
{
    if (snapshot == nullptr)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(g_httpH3TestLock);
    *snapshot = g_httpH3Snapshot;
}

NTSTATUS HttpH3TestDispatchRequired(const Request *request, const HttpSendOptions *sendOptions,
                                    ULONGLONG attemptGeneration, HttpH3DispatchContext *context) noexcept
{
    HttpH3PeerFactory factory = {};
    if (!HttpH3TestGetPeerFactory(&factory))
    {
        return STATUS_NOT_FOUND;
    }
    HttpH3DispatchStartOptions options = {};
    options.RequestObject = request;
    options.SendOptions = sendOptions;
    options.PeerFactory = &factory;
    options.AttemptGeneration = attemptGeneration;
    options.DirectCallbacks = true;
    return HttpH3DispatchRequired(context, &options);
}

void HttpH3TestInjectResponseStarted(HttpH3DispatchContext *context, ULONG statusCode) noexcept
{
    HttpH3DispatchNotifyResponseStarted(context, statusCode);
}

NTSTATUS HttpH3TestInjectHeader(HttpH3DispatchContext *context, const char *name, SIZE_T nameLength, const char *value,
                                SIZE_T valueLength, bool trailers) noexcept
{
    return HttpH3DispatchNotifyHeader(context, name, nameLength, value, valueLength, trailers);
}

NTSTATUS HttpH3TestInjectBody(HttpH3DispatchContext *context, const UCHAR *data, SIZE_T dataLength,
                              bool finalChunk) noexcept
{
    return HttpH3DispatchNotifyBody(context, data, dataLength, finalChunk);
}

void HttpH3TestInjectCompletion(HttpH3DispatchContext *context, NTSTATUS status, ULONGLONG applicationError) noexcept
{
    HttpH3DispatchNotifyComplete(context, status, applicationError);
}

NTSTATUS HttpH3TestInjectGoaway(HttpH3DispatchContext *context, ULONGLONG goawayId, HttpH3GoawayResult *result) noexcept
{
    return HttpH3DispatchProcessGoaway(context, goawayId, result);
}
} // namespace wknet::session
#endif
