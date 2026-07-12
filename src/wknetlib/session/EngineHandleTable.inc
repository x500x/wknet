    constexpr ULONG MaxConnectionPoolCapacity = 1024;
    static_assert(
        DefaultMaxTls12Renegotiations == tls::Tls12DefaultMaxRenegotiations,
        "engine TLS 1.2 renegotiation default must match tls");
    static_assert(
        HardMaxTls12Renegotiations == tls::Tls12HardMaxRenegotiations,
        "engine TLS 1.2 renegotiation hard limit must match tls");
#if defined(WKNET_USER_MODE_TEST)
    volatile LONG g_activeHandleTableLock = 0;
#else
    FAST_MUTEX g_activeHandleTableLock = {};
    volatile LONG g_activeHandleTableLockState = 0;
#endif
    HandleHeader* g_activeSessions = nullptr;
    HandleHeader* g_activeRequests = nullptr;
    HandleHeader* g_activeResponses = nullptr;
    HandleHeader* g_activeWebSockets = nullptr;

#if defined(WKNET_USER_MODE_TEST)
    constexpr ULONG PassiveLevel = 0;
    ULONG g_testCurrentIrql = PassiveLevel;
    TestHttpTransportCallback g_testHttpTransport = nullptr;
    void* g_testHttpTransportContext = nullptr;
    TestWebSocketConnectCallback g_testWebSocketConnect = nullptr;
    TestWebSocketSendCallback g_testWebSocketSend = nullptr;
    TestWebSocketReceiveCallback g_testWebSocketReceive = nullptr;
    TestWebSocketCloseCallback g_testWebSocketClose = nullptr;
    void* g_testWebSocketTransportContext = nullptr;
#endif

namespace
{
    HandleHeader* ToHandleHeader(SessionHandle session) noexcept
    {
        return reinterpret_cast<HandleHeader*>(session);
    }

    HandleHeader* ToHandleHeader(RequestHandle request) noexcept
    {
        return reinterpret_cast<HandleHeader*>(request);
    }

    HandleHeader* ToHandleHeader(ResponseHandle response) noexcept
    {
        return reinterpret_cast<HandleHeader*>(response);
    }

    HandleHeader* ToHandleHeader(WebSocketHandle websocket) noexcept
    {
        return reinterpret_cast<HandleHeader*>(websocket);
    }

#if !defined(WKNET_USER_MODE_TEST)
    void EnsureActiveHandleTableLockInitialized() noexcept
    {
        if (InterlockedCompareExchange(&g_activeHandleTableLockState, 0, 0) == 2) {
            return;
        }

        if (InterlockedCompareExchange(&g_activeHandleTableLockState, 1, 0) == 0) {
            ExInitializeFastMutex(&g_activeHandleTableLock);
            InterlockedExchange(&g_activeHandleTableLockState, 2);
            return;
        }

        LARGE_INTEGER delay = {};
        delay.QuadPart = -10 * 1000;
        while (InterlockedCompareExchange(&g_activeHandleTableLockState, 0, 0) != 2) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }
#endif

    void AcquireActiveHandleTableLock() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        while (g_activeHandleTableLock != 0) {
        }
        g_activeHandleTableLock = 1;
#else
        EnsureActiveHandleTableLockInitialized();
        ExAcquireFastMutex(&g_activeHandleTableLock);
#endif
    }

    void ReleaseActiveHandleTableLock() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        g_activeHandleTableLock = 0;
#else
        ExReleaseFastMutex(&g_activeHandleTableLock);
#endif
    }

    _Ret_maybenull_
    HandleHeader** ActiveHandleList(HandleKind kind) noexcept
    {
        switch (kind) {
        case HandleKind::Session:
            return &g_activeSessions;
        case HandleKind::Request:
            return &g_activeRequests;
        case HandleKind::Response:
            return &g_activeResponses;
        case HandleKind::WebSocket:
            return &g_activeWebSockets;
        default:
            return nullptr;
        }
    }

    _Ret_maybenull_
    HandleHeader* FindActiveHandleLocked(HandleHeader* target, HandleKind kind) noexcept
    {
        HandleHeader** list = ActiveHandleList(kind);
        if (target == nullptr || list == nullptr) {
            return nullptr;
        }

        for (HandleHeader* current = *list; current != nullptr; current = current->TableNext) {
            if (current == target) {
                return current;
            }
        }

        return nullptr;
    }

    _Ret_maybenull_
    HandleHeader** FindActiveHandleLinkLocked(HandleHeader* target, HandleKind kind) noexcept
    {
        HandleHeader** link = ActiveHandleList(kind);
        if (target == nullptr || link == nullptr) {
            return nullptr;
        }

        while (*link != nullptr) {
            if (*link == target) {
                return link;
            }
            link = &((*link)->TableNext);
        }

        return nullptr;
    }

    _Must_inspect_result_
    bool IsActiveHandle(HandleHeader* target, HandleKind kind) noexcept
    {
        bool active = false;
        AcquireActiveHandleTableLock();
        active = FindActiveHandleLocked(target, kind) != nullptr;
        ReleaseActiveHandleTableLock();
        return active;
    }

    _Must_inspect_result_
    NTSTATUS RegisterActiveHandle(HandleHeader* header, HandleKind kind) noexcept
    {
        if (header == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_INVALID_PARAMETER;
        AcquireActiveHandleTableLock();
        HandleHeader** list = ActiveHandleList(kind);
        if (list != nullptr &&
            header->Kind == kind &&
            header->Closed == 0 &&
            header->TableNext == nullptr &&
            FindActiveHandleLocked(header, kind) == nullptr) {
            header->TableNext = *list;
            *list = header;
            status = STATUS_SUCCESS;
        }
        ReleaseActiveHandleTableLock();
        return status;
    }

    _Must_inspect_result_
    bool TryCloseActiveHandle(HandleHeader* target, HandleKind kind) noexcept
    {
        if (target == nullptr) {
            return false;
        }

        bool closed = false;
        AcquireActiveHandleTableLock();
        HandleHeader** link = FindActiveHandleLinkLocked(target, kind);
        if (link != nullptr) {
            HandleHeader* active = *link;
            if (TryCloseHandleHeader(active, kind)) {
                *link = active->TableNext;
                active->TableNext = nullptr;
                closed = true;
            }
        }
        ReleaseActiveHandleTableLock();
        return closed;
    }

    _Ret_maybenull_
    WebSocketHandle FirstActiveWebSocketHandle() noexcept
    {
        WebSocketHandle websocket = nullptr;
        AcquireActiveHandleTableLock();
        if (g_activeWebSockets != nullptr) {
            websocket = reinterpret_cast<WebSocketHandle>(g_activeWebSockets);
        }
        ReleaseActiveHandleTableLock();
        return websocket;
    }

    _Ret_maybenull_
    SessionHandle FirstActiveSessionHandle() noexcept
    {
        SessionHandle session = nullptr;
        AcquireActiveHandleTableLock();
        if (g_activeSessions != nullptr) {
            session = reinterpret_cast<SessionHandle>(g_activeSessions);
        }
        ReleaseActiveHandleTableLock();
        return session;
    }

    _Must_inspect_result_
    bool BeginHandleOperation(HandleHeader* target, HandleKind kind) noexcept
    {
        if (target == nullptr) {
            return false;
        }

        bool active = false;
        AcquireActiveHandleTableLock();
        HandleHeader* tracked = FindActiveHandleLocked(target, kind);
        if (tracked != nullptr && tracked->Closed == 0) {
            volatile LONG* inFlight = nullptr;
#if !defined(WKNET_USER_MODE_TEST)
            KEVENT* drainEvent = nullptr;
#endif
            switch (kind) {
            case HandleKind::Session:
                inFlight = &reinterpret_cast<SessionHandle>(tracked)->InFlight;
#if !defined(WKNET_USER_MODE_TEST)
                drainEvent = &reinterpret_cast<SessionHandle>(tracked)->DrainEvent;
#endif
                break;
            case HandleKind::Request:
                inFlight = &reinterpret_cast<RequestHandle>(tracked)->InFlight;
#if !defined(WKNET_USER_MODE_TEST)
                drainEvent = &reinterpret_cast<RequestHandle>(tracked)->DrainEvent;
#endif
                break;
            case HandleKind::Response:
                inFlight = &reinterpret_cast<ResponseHandle>(tracked)->InFlight;
#if !defined(WKNET_USER_MODE_TEST)
                drainEvent = &reinterpret_cast<ResponseHandle>(tracked)->DrainEvent;
#endif
                break;
            case HandleKind::WebSocket:
                inFlight = &reinterpret_cast<WebSocketHandle>(tracked)->InFlight;
#if !defined(WKNET_USER_MODE_TEST)
                drainEvent = &reinterpret_cast<WebSocketHandle>(tracked)->DrainEvent;
#endif
                break;
            default:
                break;
            }

            if (inFlight != nullptr) {
#if defined(WKNET_USER_MODE_TEST)
                ++(*inFlight);
#else
                InterlockedIncrement(inFlight);
                KeClearEvent(drainEvent);
#endif
                active = true;
            }
        }
        ReleaseActiveHandleTableLock();
        return active;
    }

    void EndHandleOperation(
        HandleHeader* target,
        HandleKind kind,
        _Inout_ volatile LONG* inFlight
#if !defined(WKNET_USER_MODE_TEST)
        ,
        _Inout_ KEVENT* drainEvent
#endif
        ) noexcept
    {
        if (target == nullptr || target->Kind != kind || inFlight == nullptr) {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (*inFlight > 0) {
            --(*inFlight);
        }
#else
        const LONG remaining = InterlockedDecrement(inFlight);
        if (remaining == 0 && drainEvent != nullptr) {
            KeSetEvent(drainEvent, IO_NO_INCREMENT, FALSE);
        }
#endif
    }

    void WaitForHandleDrain(
        _Inout_ volatile LONG* inFlight
#if !defined(WKNET_USER_MODE_TEST)
        ,
        _Inout_ KEVENT* drainEvent
#endif
        ) noexcept
    {
        if (inFlight == nullptr) {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(inFlight);
#else
        LARGE_INTEGER timeout = {};
        timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
        while (InterlockedCompareExchange(inFlight, 0, 0) != 0) {
            const NTSTATUS waitStatus = KeWaitForSingleObject(
                drainEvent,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            UNREFERENCED_PARAMETER(waitStatus);
        }
#endif
    }
}

