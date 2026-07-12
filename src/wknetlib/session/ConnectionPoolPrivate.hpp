#pragma once

#include "session/ConnectionPool.h"

namespace wknet::session {
    struct PooledConnection final
    {
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
#if !defined(WKNET_USER_MODE_TEST)
        KMUTEX Http1PipelineSendLock = {};
        KEVENT Http1PipelineReceiveEvent = {};
        net::WskSocket* Socket = nullptr;
        transport::Transport* RawTransport = nullptr;
        tls::TlsConnection* Tls = nullptr;
#endif
        transport::Transport* Transport = nullptr;
        http2::Http2Connection* Http2 = nullptr;
    };
}
