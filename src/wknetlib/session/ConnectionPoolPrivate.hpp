#pragma once

#include "session/ConnectionPool.h"

namespace wknet::session {
struct TcpConnectionHolder final
{
#if !defined(WKNET_USER_MODE_TEST)
    net::WskSocket *Socket;
    transport::Transport *RawTransport;
    tls::TlsConnection *Tls;
#endif
    transport::Transport *Transport;
    http2::Http2Connection *Http2;
};

struct QuicConnectionHolder final
{
    quic::QuicConnection *Quic;
    http3::Http3Connection *Http3;
    PooledQuicCloseRoutine CloseRoutine;
    void *CloseContext;
    ULONGLONG LastStreamId;
    ULONGLONG GoAwayStreamId;
    ULONG StreamLeases;
    ULONG MaxStreamLeases;
    bool GoAwayReceived;
    bool ActiveRequest;
    bool Draining;
    bool Evicting;
    bool WorkerExited;
    bool CloseStarted;
};

union ConnectionHolder final
{
    TcpConnectionHolder Tcp;
    QuicConnectionHolder Quic;
};

    struct PooledConnection final
    {
        ConnectionKind Kind = ConnectionKind::None;
        bool InUse = false;
        bool Connected = false;
        ULONGLONG Id = 0;
        ULONGLONG LastUsedTime = 0;
        ULONG Http2StreamLeases = 0;
        ULONG Http2MaxStreamLeases = 0;
        ULONG Http1PipelineLeases = 0;
        ULONG Http1MaxPipelineLeases = 0;
        ULONG Http1PipelineNextSequence = 1;
        ULONG Http1PipelineNextReceiveSequence = 1;
        NTSTATUS Http1PipelineFailureStatus = STATUS_SUCCESS;
        UCHAR* Http1PipelineBufferedBytes = nullptr;
        SIZE_T Http1PipelineBufferedLength = 0;
        SIZE_T Http1PipelineBufferedCapacity = 0;
        bool CloseWhenIdle = false;
        bool ProxyTunnelEstablished = false;
        bool Http2KeepAliveInProgress = false;
        ULONGLONG Http2LastKeepAliveTime = 0;
        ULONGLONG Http2KeepAliveSequence = 0;
        UCHAR Http2KeepAliveOpaqueData[8] = {};
        ConnectionPoolKey Key = {};
        ConnectionHolder Holder = {};
#if !defined(WKNET_USER_MODE_TEST)
        KMUTEX Http1PipelineSendLock = {};
        KEVENT Http1PipelineReceiveEvent = {};
#endif
    };
}
