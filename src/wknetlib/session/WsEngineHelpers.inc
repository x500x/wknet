

    struct AsyncWebSocketConnectContext final
    {
        SessionHandle Session = nullptr;
        WebSocketConnectOptions Options = {};
        char* Url = nullptr;
        char* Subprotocol = nullptr;
        StoredHeader HeaderStorage[MaxHeadersPerRequest] = {};
        WebSocketHeader HeaderViews[MaxHeadersPerRequest] = {};
        SIZE_T HeaderCount = 0;
        WebSocketHandle WebSocket = nullptr;
        volatile LONG SessionOperationEnded = 0;
    };

    void WebSocketEndOperation(_In_opt_ WebSocketHandle websocket) noexcept
    {
        if (websocket == nullptr || websocket->Header.Kind != HandleKind::WebSocket) {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (websocket->InFlight > 0) {
            --websocket->InFlight;
        }
#else
        const LONG remaining = InterlockedDecrement(&websocket->InFlight);
        if (remaining == 0) {
            KeSetEvent(&websocket->DrainEvent, IO_NO_INCREMENT, FALSE);
        }
#endif
    }

    void WaitForWebSocketDrain(_In_opt_ WebSocketHandle websocket) noexcept
    {
        if (websocket == nullptr) {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(websocket);
#else
        LARGE_INTEGER timeout = {};
        timeout.QuadPart = -static_cast<LONGLONG>(WskOperationTimeoutMilliseconds) * 10000LL;
        while (InterlockedCompareExchange(&websocket->InFlight, 0, 0) != 0) {
            const NTSTATUS waitStatus = KeWaitForSingleObject(
                &websocket->DrainEvent,
                Executive,
                KernelMode,
                FALSE,
                &timeout);
            UNREFERENCED_PARAMETER(waitStatus);
        }
#endif
    }

    class WebSocketOperationScope final
    {
    public:
        explicit WebSocketOperationScope(_In_opt_ WebSocketHandle websocket) noexcept :
            websocket_(websocket),
            active_(WebSocketBeginOperation(websocket))
        {
        }

        ~WebSocketOperationScope() noexcept
        {
            if (active_) {
                WebSocketEndOperation(websocket_);
            }
        }

        WebSocketOperationScope(const WebSocketOperationScope&) = delete;
        WebSocketOperationScope& operator=(const WebSocketOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        WebSocketHandle websocket_ = nullptr;
        bool active_ = false;
    };

#if !defined(WKNET_USER_MODE_TEST)
    class MutexScope final
    {
    public:
        explicit MutexScope(_Inout_ KMUTEX* mutex) noexcept :
            mutex_(mutex)
        {
            if (mutex_ != nullptr) {
                acquired_ = NT_SUCCESS(KeWaitForSingleObject(mutex_, Executive, KernelMode, FALSE, nullptr));
            }
        }

        ~MutexScope() noexcept
        {
            if (mutex_ != nullptr && acquired_) {
                KeReleaseMutex(mutex_, FALSE);
            }
        }

        MutexScope(const MutexScope&) = delete;
        MutexScope& operator=(const MutexScope&) = delete;

    private:
        KMUTEX* mutex_ = nullptr;
        bool acquired_ = false;
    };

    _Must_inspect_result_
    bool TryUseWebSocketSendFrameScratch(
        _In_ const WebSocket& websocket,
        _Inout_ session::WsIoBuffers& buffers) noexcept
    {
        if (websocket.Workspace == nullptr ||
            websocket.Workspace->WebSocketSendFrameScratch.Data == nullptr ||
            websocket.Workspace->WebSocketSendFrameScratch.Length < WorkspaceWebSocketFrameScratchBytes) {
            return false;
        }

        buffers.FrameBuffer = websocket.Workspace->WebSocketSendFrameScratch.Data;
        buffers.FrameBufferLength = websocket.Workspace->WebSocketSendFrameScratch.Length;
        return true;
    }
#endif

    _Ret_maybenull_
    WebSocketHandle TakeAsyncWebSocketConnectResult(
        _Inout_ AsyncWebSocketConnectContext* context) noexcept
    {
        if (context == nullptr) {
            return nullptr;
        }

#if defined(WKNET_USER_MODE_TEST)
        WebSocketHandle websocket = context->WebSocket;
        context->WebSocket = nullptr;
        return websocket;
#else
        return static_cast<WebSocketHandle>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&context->WebSocket),
            nullptr));
#endif
    }

    void EndAsyncWebSocketSessionOperation(
        _Inout_ AsyncWebSocketConnectContext* context) noexcept
    {
        if (context == nullptr || context->Session == nullptr) {
            return;
        }

#if defined(WKNET_USER_MODE_TEST)
        if (context->SessionOperationEnded != 0) {
            return;
        }
        context->SessionOperationEnded = 1;
#else
        if (InterlockedCompareExchange(&context->SessionOperationEnded, 1, 0) != 0) {
            return;
        }
#endif
        SessionEndOperation(context->Session);
    }


    _Ret_maybenull_
    AsyncWebSocketConnectContext* AllocateAsyncWebSocketConnectContext() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return static_cast<AsyncWebSocketConnectContext*>(calloc(1, sizeof(AsyncWebSocketConnectContext)));
#else
        return AllocateNonPagedObject<AsyncWebSocketConnectContext>();
#endif
    }

    void FreeAsyncWebSocketConnectContext(_In_opt_ AsyncWebSocketConnectContext* context) noexcept
    {
        if (context == nullptr) {
            return;
        }
#if defined(WKNET_USER_MODE_TEST)
        free(context);
#else
        FreeNonPagedObject(context);
#endif
    }


    void CleanupAsyncWebSocketConnectContext(void* context) noexcept
    {
        auto* connectContext = static_cast<AsyncWebSocketConnectContext*>(context);
        if (connectContext == nullptr) {
            return;
        }

        EndAsyncWebSocketSessionOperation(connectContext);

        FreeApiMemory(connectContext->Url);
        FreeApiMemory(connectContext->Subprotocol);
        for (SIZE_T index = 0; index < connectContext->HeaderCount && index < MaxHeadersPerRequest; ++index) {
            FreeApiMemory(connectContext->HeaderStorage[index].Name);
            FreeApiMemory(connectContext->HeaderStorage[index].Value);
        }
        connectContext->HeaderCount = 0;
        WebSocketHandle websocket = TakeAsyncWebSocketConnectResult(connectContext);
        if (websocket != nullptr) {
            const NTSTATUS status = WebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(status);
        }
        FreeAsyncWebSocketConnectContext(connectContext);
    }


    _Must_inspect_result_
    NTSTATUS StoreWebSocketMessage(
        _Inout_ WebSocket& websocket,
        WebSocketMessageType type,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        if (data == nullptr && dataLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength > websocket.MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        UCHAR* copy = nullptr;
        if (dataLength != 0) {
            copy = AllocateBytesCopy(data, dataLength);
            if (copy == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        FreeApiMemory(websocket.LastMessage);
        websocket.LastMessage = copy;
        websocket.LastMessageLength = dataLength;
        websocket.LastMessageType = type;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool IsValidWebSocketCloseStatus(USHORT statusCode) noexcept
    {
        if (statusCode >= 3000 && statusCode <= 4999) {
            return true;
        }

        if (statusCode < 1000 || statusCode > 1014) {
            return false;
        }

        return statusCode != 1004 &&
            statusCode != 1005 &&
            statusCode != 1006;
    }

    bool FinishWebSocketUtf8CodePoint(ULONG codePoint, UCHAR expected) noexcept
    {
        return !((expected == 2 && codePoint < 0x800) ||
            (expected == 3 && codePoint < 0x10000) ||
            codePoint > 0x10ffff ||
            (codePoint >= 0xd800 && codePoint <= 0xdfff));
    }

    NTSTATUS AdvanceWebSocketUtf8State(
        const UCHAR* data,
        SIZE_T length,
        bool finalFragment,
        ULONG* codePoint,
        UCHAR* remaining,
        UCHAR* expected) noexcept
    {
        if ((data == nullptr && length != 0) ||
            codePoint == nullptr ||
            remaining == nullptr ||
            expected == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < length; ++index) {
            const UCHAR ch = data[index];
            if (*remaining != 0) {
                if ((ch & 0xc0) != 0x80) {
                    return STATUS_INVALID_PARAMETER;
                }
                *codePoint = (*codePoint << 6) | (ch & 0x3f);
                --(*remaining);
                if (*remaining == 0) {
                    if (!FinishWebSocketUtf8CodePoint(*codePoint, *expected)) {
                        return STATUS_INVALID_PARAMETER;
                    }
                    *codePoint = 0;
                    *expected = 0;
                }
                continue;
            }

            if (ch <= 0x7f) {
                continue;
            }

            if (ch >= 0xc2 && ch <= 0xdf) {
                *codePoint = ch & 0x1f;
                *remaining = 1;
                *expected = 1;
            }
            else if (ch >= 0xe0 && ch <= 0xef) {
                *codePoint = ch & 0x0f;
                *remaining = 2;
                *expected = 2;
            }
            else if (ch >= 0xf0 && ch <= 0xf4) {
                *codePoint = ch & 0x07;
                *remaining = 3;
                *expected = 3;
            }
            else {
                return STATUS_INVALID_PARAMETER;
            }
        }

        if (finalFragment && *remaining != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return STATUS_SUCCESS;
    }

    bool IsValidWebSocketUtf8(const UCHAR* data, SIZE_T length) noexcept
    {
        ULONG codePoint = 0;
        UCHAR remaining = 0;
        UCHAR expected = 0;
        return NT_SUCCESS(AdvanceWebSocketUtf8State(
            data,
            length,
            true,
            &codePoint,
            &remaining,
            &expected));
    }

    void ResetWebSocketSendFragmentState(_Inout_ WebSocket& websocket) noexcept
    {
        websocket.SendFragmentOpen = false;
        websocket.SendFragmentType = WebSocketMessageType::Binary;
        websocket.SendFragmentLength = 0;
        websocket.SendTextUtf8CodePoint = 0;
        websocket.SendTextUtf8Remaining = 0;
        websocket.SendTextUtf8Expected = 0;
    }

    bool IsWebSocketTransportTerminalStatus(NTSTATUS status) noexcept
    {
        return status == STATUS_CONNECTION_DISCONNECTED ||
            status == STATUS_CONNECTION_RESET ||
            status == STATUS_CONNECTION_ABORTED ||
            status == STATUS_DEVICE_NOT_CONNECTED ||
            status == STATUS_IO_TIMEOUT ||
            status == STATUS_CANCELLED ||
            status == STATUS_TIMEOUT ||
            status == STATUS_INVALID_NETWORK_RESPONSE;
    }

    NTSTATUS CloseWebSocketTransport(_Inout_ WebSocket& websocket) noexcept
    {
        websocket.Connected = false;
        ResetWebSocketSendFragmentState(websocket);
        if (websocket.TransportClosed) {
            return STATUS_SUCCESS;
        }

        websocket.TransportClosed = true;
#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketClose != nullptr) {
            g_testWebSocketClose(g_testWebSocketTransportContext, &websocket);
        }
        return STATUS_SUCCESS;
#else
        if (websocket.Client == nullptr) {
            return STATUS_SUCCESS;
        }

        HeapArray<UCHAR> frameBuffer(WorkspaceWebSocketFrameScratchBytes);
        session::WsIoBuffers buffers = {};
        if (frameBuffer.IsValid()) {
            buffers.FrameBuffer = frameBuffer.Get();
            buffers.FrameBufferLength = frameBuffer.Count();
        }
        return websocket.Client->Close(buffers);
#endif
    }

    void DisconnectWebSocketOnTerminalStatus(_Inout_ WebSocket& websocket, NTSTATUS status) noexcept
    {
        if (IsWebSocketTransportTerminalStatus(status)) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }
    }

    NTSTATUS ValidateWebSocketOutgoingText(
        const WebSocket& websocket,
        WebSocketMessageType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment,
        ULONG* codePoint,
        UCHAR* remaining,
        UCHAR* expected) noexcept
    {
        if (codePoint == nullptr || remaining == nullptr || expected == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool continuation = type == WebSocketMessageType::Continuation;
        const bool textFragment =
            type == WebSocketMessageType::Text ||
            (continuation && websocket.SendFragmentType == WebSocketMessageType::Text);
        if (!textFragment) {
            *codePoint = 0;
            *remaining = 0;
            *expected = 0;
            return STATUS_SUCCESS;
        }

        *codePoint = continuation ? websocket.SendTextUtf8CodePoint : 0;
        *remaining = continuation ? websocket.SendTextUtf8Remaining : 0;
        *expected = continuation ? websocket.SendTextUtf8Expected : 0;
        return AdvanceWebSocketUtf8State(
            data,
            dataLength,
            finalFragment,
            codePoint,
            remaining,
            expected);
    }

    void CompleteWebSocketSendFragment(
        _Inout_ WebSocket& websocket,
        WebSocketMessageType type,
        SIZE_T dataLength,
        bool finalFragment,
        ULONG codePoint,
        UCHAR remaining,
        UCHAR expected) noexcept
    {
        if (finalFragment) {
            ResetWebSocketSendFragmentState(websocket);
            return;
        }

        if (!websocket.SendFragmentOpen) {
            websocket.SendFragmentType = type;
            websocket.SendFragmentLength = dataLength;
        }
        else {
            websocket.SendFragmentLength += dataLength;
        }
        websocket.SendFragmentOpen = true;
        if (websocket.SendFragmentType == WebSocketMessageType::Text) {
            websocket.SendTextUtf8CodePoint = codePoint;
            websocket.SendTextUtf8Remaining = remaining;
            websocket.SendTextUtf8Expected = expected;
        }
        else {
            websocket.SendTextUtf8CodePoint = 0;
            websocket.SendTextUtf8Remaining = 0;
            websocket.SendTextUtf8Expected = 0;
        }
    }

