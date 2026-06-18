#include <KernelHttp/engine/WsEngine.h>
#include <KernelHttp/engine/EngineImpl.h>
#include <KernelHttp/engine/HandleAlloc.h>
#include <KernelHttp/engine/UrlParser.h>
#include <KernelHttp/http/HttpRequest.h>
#include <KernelHttp/websocket/WebSocketFrame.h>

namespace KernelHttp
{
namespace engine
{
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
    static bool IsWebSocketAsyncCancellationRequested(_In_opt_ void* context) noexcept
    {
        return context != nullptr &&
            KhAsyncOperationIsCanceled(static_cast<KH_ASYNC_OPERATION>(context));
    }
#endif

    _Must_inspect_result_
    NTSTATUS BuildWebSocketHandshakeRequest(
        const KhWebSocket& websocket,
        _Inout_ KhWorkspace& workspace,
        _Out_ SIZE_T* requestLength) noexcept
    {
        if (requestLength != nullptr) {
            *requestLength = 0;
        }

        if (requestLength == nullptr || websocket.HostLength == 0 || websocket.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> hostHeader(KhMaxHostHeaderLength);
        if (!hostHeader.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T hostLength = 0;
        HeapArray<KhRequest> hostRequestStorage(1);
        if (!hostRequestStorage.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        KhRequest& hostRequest = hostRequestStorage[0];
        RtlCopyMemory(hostRequest.Scheme, websocket.Scheme, sizeof(hostRequest.Scheme));
        hostRequest.SchemeLength = websocket.SchemeLength;
        RtlCopyMemory(hostRequest.Host, websocket.Host, sizeof(hostRequest.Host));
        hostRequest.HostLength = websocket.HostLength;
        hostRequest.Port = websocket.Port;
        NTSTATUS status = BuildHostHeaderValue(hostRequest, hostHeader.Get(), hostHeader.Count(), &hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<char> clientKey(websocket::WebSocketClientKeyBase64Length);
        if (!clientKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T clientKeyLength = 0;
        status = websocket::WebSocketCodec::GenerateClientKey(
            clientKey.Get(),
            clientKey.Count(),
            &clientKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<http::HttpHeader> headers(4 + KhMaxHeadersPerRequest);
        if (!headers.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T headerCount = 0;
        headers[headerCount++] = { http::MakeText("Upgrade"), http::MakeText("websocket") };
        headers[headerCount++] = { http::MakeText("Sec-WebSocket-Key"), { clientKey.Get(), clientKeyLength } };
        headers[headerCount++] = { http::MakeText("Sec-WebSocket-Version"), http::MakeText("13") };
        if (websocket.Subprotocol != nullptr && websocket.SubprotocolLength != 0) {
            headers[headerCount++] = {
                http::MakeText("Sec-WebSocket-Protocol"),
                { websocket.Subprotocol, websocket.SubprotocolLength }
            };
        }

        for (SIZE_T index = 0; index < websocket.ExtraHeaderCount && index < KhMaxHeadersPerRequest; ++index) {
            const KhStoredHeader& stored = websocket.ExtraHeaders[index];
            headers[headerCount++] = {
                { stored.Name, stored.NameLength },
                { stored.Value, stored.ValueLength }
            };
        }

        http::HttpRequestBuildOptions buildOptions = {};
        buildOptions.Method = http::HttpMethod::Get;
        buildOptions.Path = { websocket.Path, websocket.PathLength };
        buildOptions.Host = { hostHeader.Get(), hostLength };
        buildOptions.Connection = http::HttpConnectionDirective::Upgrade;
        buildOptions.ExtraHeaders = headers.Get();
        buildOptions.ExtraHeaderCount = headerCount;

        return http::HttpRequestBuilder::Build(
            buildOptions,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            requestLength);
    }


    struct KhAsyncWebSocketConnectContext final
    {
        KH_SESSION Session = nullptr;
        KhWebSocketConnectOptions Options = {};
        char* Url = nullptr;
        char* Subprotocol = nullptr;
        KhStoredHeader HeaderStorage[KhMaxHeadersPerRequest] = {};
        KhWebSocketHeader HeaderViews[KhMaxHeadersPerRequest] = {};
        SIZE_T HeaderCount = 0;
        KH_WEBSOCKET WebSocket = nullptr;
        volatile LONG SessionOperationEnded = 0;
    };

    void KhWebSocketEndOperation(_In_opt_ KH_WEBSOCKET websocket) noexcept
    {
        if (websocket == nullptr || websocket->Header.Kind != KhHandleKind::WebSocket) {
            return;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

    void WaitForWebSocketDrain(_In_opt_ KH_WEBSOCKET websocket) noexcept
    {
        if (websocket == nullptr) {
            return;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
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

    class KhWebSocketOperationScope final
    {
    public:
        explicit KhWebSocketOperationScope(_In_opt_ KH_WEBSOCKET websocket) noexcept :
            websocket_(websocket),
            active_(KhWebSocketBeginOperation(websocket))
        {
        }

        ~KhWebSocketOperationScope() noexcept
        {
            if (active_) {
                KhWebSocketEndOperation(websocket_);
            }
        }

        KhWebSocketOperationScope(const KhWebSocketOperationScope&) = delete;
        KhWebSocketOperationScope& operator=(const KhWebSocketOperationScope&) = delete;

        _Must_inspect_result_
        bool IsActive() const noexcept
        {
            return active_;
        }

    private:
        KH_WEBSOCKET websocket_ = nullptr;
        bool active_ = false;
    };

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
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
#endif

    _Ret_maybenull_
    KH_WEBSOCKET TakeAsyncWebSocketConnectResult(
        _Inout_ KhAsyncWebSocketConnectContext* context) noexcept
    {
        if (context == nullptr) {
            return nullptr;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        KH_WEBSOCKET websocket = context->WebSocket;
        context->WebSocket = nullptr;
        return websocket;
#else
        return static_cast<KH_WEBSOCKET>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&context->WebSocket),
            nullptr));
#endif
    }

    void EndAsyncWebSocketSessionOperation(
        _Inout_ KhAsyncWebSocketConnectContext* context) noexcept
    {
        if (context == nullptr || context->Session == nullptr) {
            return;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (context->SessionOperationEnded != 0) {
            return;
        }
        context->SessionOperationEnded = 1;
#else
        if (InterlockedCompareExchange(&context->SessionOperationEnded, 1, 0) != 0) {
            return;
        }
#endif
        KhSessionEndOperation(context->Session);
    }


    _Ret_maybenull_
    KhAsyncWebSocketConnectContext* AllocateAsyncWebSocketConnectContext() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhAsyncWebSocketConnectContext*>(calloc(1, sizeof(KhAsyncWebSocketConnectContext)));
#else
        return AllocateNonPagedObject<KhAsyncWebSocketConnectContext>();
#endif
    }

    void FreeAsyncWebSocketConnectContext(_In_opt_ KhAsyncWebSocketConnectContext* context) noexcept
    {
        if (context == nullptr) {
            return;
        }
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        free(context);
#else
        FreeNonPagedObject(context);
#endif
    }


    void CleanupAsyncWebSocketConnectContext(void* context) noexcept
    {
        auto* connectContext = static_cast<KhAsyncWebSocketConnectContext*>(context);
        if (connectContext == nullptr) {
            return;
        }

        EndAsyncWebSocketSessionOperation(connectContext);

        FreeApiMemory(connectContext->Url);
        FreeApiMemory(connectContext->Subprotocol);
        for (SIZE_T index = 0; index < connectContext->HeaderCount && index < KhMaxHeadersPerRequest; ++index) {
            FreeApiMemory(connectContext->HeaderStorage[index].Name);
            FreeApiMemory(connectContext->HeaderStorage[index].Value);
        }
        connectContext->HeaderCount = 0;
        KH_WEBSOCKET websocket = TakeAsyncWebSocketConnectResult(connectContext);
        if (websocket != nullptr) {
            const NTSTATUS status = KhWebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(status);
        }
        FreeAsyncWebSocketConnectContext(connectContext);
    }


    _Must_inspect_result_
    NTSTATUS StoreWebSocketMessage(
        _Inout_ KhWebSocket& websocket,
        KhWebSocketMessageType type,
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

    void ResetWebSocketSendFragmentState(_Inout_ KhWebSocket& websocket) noexcept
    {
        websocket.SendFragmentOpen = false;
        websocket.SendFragmentType = KhWebSocketMessageType::Binary;
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

    NTSTATUS CloseWebSocketTransport(_Inout_ KhWebSocket& websocket) noexcept
    {
        websocket.Connected = false;
        ResetWebSocketSendFragmentState(websocket);
        if (websocket.TransportClosed) {
            return STATUS_SUCCESS;
        }

        websocket.TransportClosed = true;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketClose != nullptr) {
            g_testWebSocketClose(g_testWebSocketTransportContext, &websocket);
        }
        return STATUS_SUCCESS;
#else
        if (websocket.Client == nullptr) {
            return STATUS_SUCCESS;
        }

        HeapArray<UCHAR> frameBuffer(KhWorkspaceWebSocketFrameScratchBytes);
        client::WebSocketIoBuffers buffers = {};
        if (frameBuffer.IsValid()) {
            buffers.FrameBuffer = frameBuffer.Get();
            buffers.FrameBufferLength = frameBuffer.Count();
        }
        return websocket.Client->Close(buffers);
#endif
    }

    void DisconnectWebSocketOnTerminalStatus(_Inout_ KhWebSocket& websocket, NTSTATUS status) noexcept
    {
        if (IsWebSocketTransportTerminalStatus(status)) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }
    }

    NTSTATUS ValidateWebSocketOutgoingText(
        const KhWebSocket& websocket,
        KhWebSocketMessageType type,
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

        const bool continuation = type == KhWebSocketMessageType::Continuation;
        const bool textFragment =
            type == KhWebSocketMessageType::Text ||
            (continuation && websocket.SendFragmentType == KhWebSocketMessageType::Text);
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
        _Inout_ KhWebSocket& websocket,
        KhWebSocketMessageType type,
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
        if (websocket.SendFragmentType == KhWebSocketMessageType::Text) {
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

    _Must_inspect_result_
    NTSTATUS StoreWebSocketSubprotocol(
        _Inout_ KhWebSocket& websocket,
        _In_reads_bytes_opt_(subprotocolLength) const char* subprotocol,
        SIZE_T subprotocolLength) noexcept
    {
        if (subprotocol == nullptr && subprotocolLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        char* copy = nullptr;
        if (subprotocolLength != 0) {
            copy = AllocateTextCopy(subprotocol, subprotocolLength);
            if (copy == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        FreeApiMemory(websocket.Subprotocol);
        websocket.Subprotocol = copy;
        websocket.SubprotocolLength = subprotocolLength;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS CompleteWebSocketConnect(
        KH_SESSION session,
        const KhWebSocketConnectOptions& options,
        _Out_ KH_WEBSOCKET* websocket,
        _In_opt_ KH_ASYNC_OPERATION cancellationOperation) noexcept
    {
        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        if (websocket == nullptr || !IsValidWebSocketConnectOptions(options)) {
            return STATUS_INVALID_PARAMETER;
        }

        char* urlCopy = AllocateTextCopy(options.Url, options.UrlLength);
        if (urlCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KH_WEBSOCKET newWebSocket = AllocateWebSocketHandle();
        if (newWebSocket == nullptr) {
            FreeApiMemory(urlCopy);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newWebSocket->Header = { KhHandleKind::WebSocket, 0, nullptr };
        newWebSocket->Session = session;
        newWebSocket->Url = urlCopy;
        newWebSocket->UrlLength = options.UrlLength;
        newWebSocket->MaxMessageBytes = options.MaxMessageBytes;
        newWebSocket->AutoReplyPing = options.AutoReplyPing;
        newWebSocket->InFlight = 0;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        KeInitializeMutex(&newWebSocket->SendLock, 0);
        KeInitializeMutex(&newWebSocket->ReceiveLock, 0);
        KeInitializeEvent(&newWebSocket->DrainEvent, NotificationEvent, TRUE);
#endif

        KhWorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = KhPoolType::NonPaged;
        workspaceOptions.MaxResponseBytes = options.MaxMessageBytes;
        NTSTATUS status = KhWorkspaceCreate(&workspaceOptions, &newWebSocket->Workspace);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }
        status = KhWorkspaceEnsureWebSocketPayloadCapacity(
            newWebSocket->Workspace,
            newWebSocket->MaxMessageBytes);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        status = ParseUrlParts(
            newWebSocket->Url,
            newWebSocket->UrlLength,
            true,
            newWebSocket->Scheme,
            sizeof(newWebSocket->Scheme),
            &newWebSocket->SchemeLength,
            newWebSocket->Host,
            sizeof(newWebSocket->Host),
            &newWebSocket->HostLength,
            newWebSocket->Path,
            sizeof(newWebSocket->Path),
            &newWebSocket->PathLength,
            &newWebSocket->Port);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        if (options.Subprotocol != nullptr && options.SubprotocolLength != 0) {
            newWebSocket->Subprotocol = AllocateTextCopy(options.Subprotocol, options.SubprotocolLength);
            if (newWebSocket->Subprotocol == nullptr) {
                ReleaseWebSocketStorage(*newWebSocket);
                FreeHandle(newWebSocket);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newWebSocket->SubprotocolLength = options.SubprotocolLength;
        }

        status = CopyWebSocketHeaders(options.Headers, options.HeaderCount, *newWebSocket);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        KhTlsOptions effectiveTls = options.Tls;
        if (options.Tls.CertificatePolicy == KhCertificatePolicy::Verify &&
            options.Tls.CertificateStore == nullptr &&
            options.Tls.ServerName == nullptr &&
            options.Tls.ServerNameLength == 0 &&
            options.Tls.Alpn == nullptr &&
            options.Tls.AlpnLength == 0 &&
            options.Tls.MinVersion == KhTlsVersion::Tls12 &&
            options.Tls.MaxVersion == KhTlsVersion::Tls13 &&
            options.Tls.Policy.Profile == tls::TlsSecurityProfile::ModernDefault &&
            !options.Tls.Policy.EnableTls12RsaKeyExchange &&
            !options.Tls.Policy.EnableTls12Cbc &&
            !options.Tls.Policy.EnableTls12Renegotiation &&
            !options.Tls.Policy.EnableTls12Sha1Signatures &&
            !options.Tls.Policy.EnablePostHandshakeClientAuth &&
            !options.Tls.Policy.RequireRevocationCheck &&
            options.Tls.HandshakeReceiveTimeoutMilliseconds == KhDefaultTlsHandshakeReceiveTimeoutMilliseconds) {
            effectiveTls = session->Options.Tls;
        }
        if (effectiveTls.ServerName == nullptr &&
            TextEqualsLiteralIgnoreCase(newWebSocket->Scheme, newWebSocket->SchemeLength, "wss")) {
            effectiveTls.ServerName = newWebSocket->Host;
            effectiveTls.ServerNameLength = newWebSocket->HostLength;
        }

        newWebSocket->Workspace->MaxResponseBytes = options.MaxMessageBytes;
        KhWorkspaceReset(newWebSocket->Workspace);

        SIZE_T handshakeLength = 0;
        status = BuildWebSocketHandshakeRequest(*newWebSocket, *newWebSocket->Workspace, &handshakeLength);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }
        UNREFERENCED_PARAMETER(handshakeLength);

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketConnect == nullptr) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_NOT_SUPPORTED;
        }

        KhTestWebSocketConnectRequest testRequest = {};
        testRequest.Scheme = newWebSocket->Scheme;
        testRequest.SchemeLength = newWebSocket->SchemeLength;
        testRequest.Host = newWebSocket->Host;
        testRequest.HostLength = newWebSocket->HostLength;
        testRequest.Path = newWebSocket->Path;
        testRequest.PathLength = newWebSocket->PathLength;
        testRequest.Port = newWebSocket->Port;
        testRequest.Subprotocol = newWebSocket->Subprotocol;
        testRequest.SubprotocolLength = newWebSocket->SubprotocolLength;
        testRequest.CertificatePolicy = effectiveTls.CertificatePolicy;
        testRequest.CertificateStore = effectiveTls.CertificateStore;
        testRequest.ClientCredential = effectiveTls.ClientCredential;
        testRequest.MinTlsVersion = effectiveTls.MinVersion;
        testRequest.MaxTlsVersion = effectiveTls.MaxVersion;
        testRequest.Policy = effectiveTls.Policy;
        testRequest.HandshakeReceiveTimeoutMilliseconds = effectiveTls.HandshakeReceiveTimeoutMilliseconds;
        testRequest.AddressFamily = options.AddressFamily;
        testRequest.AutoReplyPing = newWebSocket->AutoReplyPing;
        testRequest.MaxMessageBytes = newWebSocket->MaxMessageBytes;

        status = g_testWebSocketConnect(g_testWebSocketTransportContext, &testRequest);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        newWebSocket->Connected = true;
        newWebSocket->TransportClosed = false;
        status = RegisterActiveWebSocketHandle(newWebSocket);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }
        *websocket = newWebSocket;
        return STATUS_SUCCESS;
#else
        newWebSocket->Client = AllocateNonPagedObject<client::WebSocketClient>();
        if (newWebSocket->Client == nullptr) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        HeapArray<wchar_t> serverName(KhMaxHostLength + 1);
        HeapArray<wchar_t> serviceName(KhMaxServiceNameLength + 1);
        if (!serverName.IsValid() || !serviceName.IsValid()) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = CopyAsciiToWide(newWebSocket->Host, newWebSocket->HostLength, serverName.Get(), serverName.Count());
        if (NT_SUCCESS(status)) {
            status = FormatServiceName(newWebSocket->Port, serviceName.Get(), serviceName.Count());
        }

        client::WebSocketIoBuffers buffers = {};
        buffers.RequestBuffer = reinterpret_cast<char*>(newWebSocket->Workspace->Request.Data);
        buffers.RequestBufferLength = newWebSocket->Workspace->Request.Length;
        buffers.ResponseBuffer = reinterpret_cast<char*>(newWebSocket->Workspace->Response.Data);
        buffers.ResponseBufferLength = newWebSocket->Workspace->Response.Length;
        buffers.FrameBuffer = newWebSocket->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = newWebSocket->Workspace->WebSocketFrameScratch.Length;
        buffers.PayloadBuffer = newWebSocket->Workspace->WebSocketPayloadScratch.Data;
        buffers.PayloadBufferLength = newWebSocket->Workspace->WebSocketPayloadScratch.Length;
        HeapArray<http::HttpHeader> responseHeaders(KhMaxHeadersPerResponse);
        if (!responseHeaders.IsValid()) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        buffers.Headers = responseHeaders.Get();
        buffers.HeaderCapacity = KhMaxHeadersPerResponse;

        client::WebSocketConnectOptions connectOptions = {};
        HeapArray<http::HttpHeader> extraHeaderViews(KhMaxHeadersPerRequest);
        if (!extraHeaderViews.IsValid()) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T extraHeaderViewCount = 0;
        for (SIZE_T index = 0; index < newWebSocket->ExtraHeaderCount && index < KhMaxHeadersPerRequest; ++index) {
            const KhStoredHeader& stored = newWebSocket->ExtraHeaders[index];
            extraHeaderViews[extraHeaderViewCount++] = {
                { stored.Name, stored.NameLength },
                { stored.Value, stored.ValueLength }
            };
        }
        connectOptions.ServerName = serverName.Get();
        connectOptions.ServiceName = serviceName.Get();
        connectOptions.TlsServerName = effectiveTls.ServerName != nullptr ? effectiveTls.ServerName : newWebSocket->Host;
        connectOptions.TlsServerNameLength = effectiveTls.ServerName != nullptr ?
            effectiveTls.ServerNameLength :
            newWebSocket->HostLength;
        connectOptions.Host = newWebSocket->Host;
        connectOptions.HostLength = newWebSocket->HostLength;
        connectOptions.Port = newWebSocket->Port;
        connectOptions.Path = newWebSocket->Path;
        connectOptions.PathLength = newWebSocket->PathLength;
        connectOptions.Subprotocol = newWebSocket->Subprotocol;
        connectOptions.SubprotocolLength = newWebSocket->SubprotocolLength;
        connectOptions.ExtraHeaders = extraHeaderViewCount != 0 ? extraHeaderViews.Get() : nullptr;
        connectOptions.ExtraHeaderCount = extraHeaderViewCount;
        connectOptions.CertificateStore = effectiveTls.CertificateStore;
        connectOptions.ClientCredential = effectiveTls.ClientCredential;
        connectOptions.Workspace = newWebSocket->Workspace;
        connectOptions.ProviderCache = session->ProviderCache;
        connectOptions.AddressFamily = ToWskAddressFamily(options.AddressFamily);
        connectOptions.MinimumTlsProtocol = ToTlsProtocol(effectiveTls.MinVersion);
        connectOptions.MaximumTlsProtocol = ToTlsProtocol(effectiveTls.MaxVersion);
        connectOptions.Policy = effectiveTls.Policy;
        connectOptions.HandshakeReceiveTimeoutMilliseconds = effectiveTls.HandshakeReceiveTimeoutMilliseconds;
        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsWebSocketAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
            connectOptions.Cancellation = &cancellation;
        }
        connectOptions.UseTls = TextEqualsLiteralIgnoreCase(newWebSocket->Scheme, newWebSocket->SchemeLength, "wss");
        connectOptions.VerifyCertificate = effectiveTls.CertificatePolicy == KhCertificatePolicy::Verify;

        if (NT_SUCCESS(status)) {
            status = newWebSocket->Client->Connect(*session->WskClient, connectOptions, buffers);
        }

        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        SIZE_T selectedSubprotocolLength = 0;
        const char* selectedSubprotocol =
            newWebSocket->Client->SelectedSubprotocol(&selectedSubprotocolLength);
        status = StoreWebSocketSubprotocol(
            *newWebSocket,
            selectedSubprotocol,
            selectedSubprotocolLength);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }

        newWebSocket->Connected = true;
        newWebSocket->TransportClosed = false;
        status = RegisterActiveWebSocketHandle(newWebSocket);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }
        *websocket = newWebSocket;
        return STATUS_SUCCESS;
#endif
    }

    NTSTATUS RunWebSocketConnectAsyncOperation(KH_ASYNC_OPERATION operation, void* context) noexcept
    {
        auto* connectContext = static_cast<KhAsyncWebSocketConnectContext*>(context);
        if (connectContext == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        if (KhAsyncOperationIsCanceled(operation)) {
            status = STATUS_CANCELLED;
            EndAsyncWebSocketSessionOperation(connectContext);
            return status;
        }

        KH_WEBSOCKET websocket = nullptr;
        status = CompleteWebSocketConnect(connectContext->Session, connectContext->Options, &websocket, operation);
        if (NT_SUCCESS(status)) {
            connectContext->WebSocket = websocket;
        }
        else if (websocket != nullptr) {
            const NTSTATUS closeStatus = KhWebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        if (KhAsyncOperationIsCanceled(operation) && status == STATUS_SUCCESS) {
            status = STATUS_CANCELLED;
        }

        EndAsyncWebSocketSessionOperation(connectContext);
        return status;
    }

    NTSTATUS KhWebSocketConnectSyncImpl(
        KH_SESSION session,
        const KhWebSocketConnectOptions* options,
        KH_WEBSOCKET* websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        KhSessionOperationScope sessionScope(session);
        if (!sessionScope.IsActive()) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options == nullptr || websocket == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        return CompleteWebSocketConnect(session, *options, websocket, nullptr);
    }

    NTSTATUS KhWebSocketConnectAsyncImpl(
        KH_SESSION session,
        const KhWebSocketConnectOptions* options,
        KH_ASYNC_OPERATION* operation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (operation != nullptr) {
            *operation = nullptr;
        }

        if (!KhSessionBeginOperation(session)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options == nullptr || operation == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            KhSessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }

        auto* context = AllocateAsyncWebSocketConnectContext();
        if (context == nullptr) {
            KhSessionEndOperation(session);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        context->Session = session;
        context->Options = *options;
        context->SessionOperationEnded = 0;
        context->Url = AllocateTextCopy(options->Url, options->UrlLength);
        if (context->Url == nullptr) {
            CleanupAsyncWebSocketConnectContext(context);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        context->Options.Url = context->Url;

        if (options->Subprotocol != nullptr && options->SubprotocolLength != 0) {
            context->Subprotocol = AllocateTextCopy(options->Subprotocol, options->SubprotocolLength);
            if (context->Subprotocol == nullptr) {
                CleanupAsyncWebSocketConnectContext(context);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            context->Options.Subprotocol = context->Subprotocol;
        }

        if (options->Headers != nullptr && options->HeaderCount != 0) {
            if (options->HeaderCount > KhMaxHeadersPerRequest) {
                CleanupAsyncWebSocketConnectContext(context);
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < options->HeaderCount; ++index) {
                const KhWebSocketHeader& src = options->Headers[index];
                KhStoredHeader& dst = context->HeaderStorage[index];

                dst.Name = AllocateTextCopy(src.Name, src.NameLength);
                if (dst.Name == nullptr) {
                    CleanupAsyncWebSocketConnectContext(context);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                dst.NameLength = src.NameLength;

                if (src.ValueLength != 0) {
                    dst.Value = AllocateTextCopy(src.Value, src.ValueLength);
                    if (dst.Value == nullptr) {
                        CleanupAsyncWebSocketConnectContext(context);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
                dst.ValueLength = src.ValueLength;

                context->HeaderCount = index + 1;

                context->HeaderViews[index].Name = dst.Name;
                context->HeaderViews[index].NameLength = dst.NameLength;
                context->HeaderViews[index].Value = dst.Value;
                context->HeaderViews[index].ValueLength = dst.ValueLength;
            }

            context->Options.Headers = context->HeaderViews;
        }

        KhAsyncCreateOptions createOptions = {};
        createOptions.Kind = KhAsyncOperationKind::WebSocketConnect;
        createOptions.WorkerRoutine = RunWebSocketConnectAsyncOperation;
        createOptions.CleanupRoutine = CleanupAsyncWebSocketConnectContext;
        createOptions.Context = context;
        createOptions.StartSuspended = true;

        status = KhAsyncOperationCreate(createOptions, operation);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncWebSocketConnectContext(context);
            return status;
        }

        status = KhAsyncOperationQueue(*operation);
        if (!NT_SUCCESS(status)) {
            KhAsyncOperationRelease(*operation);
            *operation = nullptr;
        }

        return status;
    }

    NTSTATUS KhWebSocketSendTextSyncImpl(
        KH_WEBSOCKET websocket,
        const char* text,
        SIZE_T textLength,
        const KhWebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        KhWebSocketOperationScope operation(websocket);
        if (!operation.IsActive() || (text == nullptr && textLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        if (websocket->SendFragmentOpen) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (textLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG nextCodePoint = 0;
        UCHAR nextRemaining = 0;
        UCHAR nextExpected = 0;
        status = ValidateWebSocketOutgoingText(
            *websocket,
            KhWebSocketMessageType::Text,
            reinterpret_cast<const UCHAR*>(text),
            textLength,
            finalFragment,
            &nextCodePoint,
            &nextRemaining,
            &nextExpected);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            KhWebSocketMessageType::Text,
            reinterpret_cast<const UCHAR*>(text),
            textLength,
            finalFragment);
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                KhWebSocketMessageType::Text,
                textLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        HeapArray<UCHAR> frameBuffer(KhWorkspaceWebSocketFrameScratchBytes);
        if (!frameBuffer.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        MutexScope sendLock(&websocket->SendLock);
        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = frameBuffer.Get();
        buffers.FrameBufferLength = frameBuffer.Count();
        status = websocket->Client->SendText(text, textLength, buffers, finalFragment);
        if (!NT_SUCCESS(status)) {
            kprintf("KhWebSocketSendTextSync Client->SendText failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                KhWebSocketMessageType::Text,
                textLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

    NTSTATUS KhWebSocketSendBinarySyncImpl(
        KH_WEBSOCKET websocket,
        const UCHAR* data,
        SIZE_T dataLength,
        const KhWebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        KhWebSocketOperationScope operation(websocket);
        if (!operation.IsActive() || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        if (websocket->SendFragmentOpen) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (dataLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG nextCodePoint = 0;
        UCHAR nextRemaining = 0;
        UCHAR nextExpected = 0;
        status = ValidateWebSocketOutgoingText(
            *websocket,
            KhWebSocketMessageType::Binary,
            data,
            dataLength,
            finalFragment,
            &nextCodePoint,
            &nextRemaining,
            &nextExpected);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            KhWebSocketMessageType::Binary,
            data,
            dataLength,
            finalFragment);
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                KhWebSocketMessageType::Binary,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        HeapArray<UCHAR> frameBuffer(KhWorkspaceWebSocketFrameScratchBytes);
        if (!frameBuffer.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        MutexScope sendLock(&websocket->SendLock);
        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = frameBuffer.Get();
        buffers.FrameBufferLength = frameBuffer.Count();
        status = websocket->Client->SendBinary(data, dataLength, buffers, finalFragment);
        if (!NT_SUCCESS(status)) {
            kprintf("KhWebSocketSendBinarySync Client->SendBinary failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                KhWebSocketMessageType::Binary,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

    NTSTATUS KhWebSocketSendContinuationSyncImpl(
        KH_WEBSOCKET websocket,
        const UCHAR* data,
        SIZE_T dataLength,
        const KhWebSocketSendOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool finalFragment = options == nullptr ? true : options->FinalFragment;
        KhWebSocketOperationScope operation(websocket);
        if (!operation.IsActive() || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        if (!websocket->SendFragmentOpen) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (websocket->SendFragmentLength > websocket->MaxMessageBytes ||
            dataLength > websocket->MaxMessageBytes - websocket->SendFragmentLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        ULONG nextCodePoint = 0;
        UCHAR nextRemaining = 0;
        UCHAR nextExpected = 0;
        status = ValidateWebSocketOutgoingText(
            *websocket,
            KhWebSocketMessageType::Continuation,
            data,
            dataLength,
            finalFragment,
            &nextCodePoint,
            &nextRemaining,
            &nextExpected);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            KhWebSocketMessageType::Continuation,
            data,
            dataLength,
            finalFragment);
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                KhWebSocketMessageType::Continuation,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        HeapArray<UCHAR> frameBuffer(KhWorkspaceWebSocketFrameScratchBytes);
        if (!frameBuffer.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        MutexScope sendLock(&websocket->SendLock);
        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = frameBuffer.Get();
        buffers.FrameBufferLength = frameBuffer.Count();
        status = websocket->Client->SendContinuation(data, dataLength, buffers, finalFragment);
        if (!NT_SUCCESS(status)) {
            kprintf("KhWebSocketSendContinuationSync Client->SendContinuation failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        if (NT_SUCCESS(status)) {
            CompleteWebSocketSendFragment(
                *websocket,
                KhWebSocketMessageType::Continuation,
                dataLength,
                finalFragment,
                nextCodePoint,
                nextRemaining,
                nextExpected);
        }
        else {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

    NTSTATUS KhWebSocketSendControlSyncImpl(
        KH_WEBSOCKET websocket,
        KhWebSocketMessageType type,
        const UCHAR* payload,
        SIZE_T payloadLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (type != KhWebSocketMessageType::Ping &&
            type != KhWebSocketMessageType::Pong) {
            return STATUS_INVALID_PARAMETER;
        }

        KhWebSocketOperationScope operation(websocket);
        if (!operation.IsActive() ||
            (payload == nullptr && payloadLength != 0) ||
            payloadLength > websocket::WebSocketMaxControlPayloadLength) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        status = g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            type,
            payload,
            payloadLength,
            true);
        if (!NT_SUCCESS(status)) {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        HeapArray<UCHAR> frameBuffer(KhWorkspaceWebSocketFrameScratchBytes);
        if (!frameBuffer.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        MutexScope sendLock(&websocket->SendLock);
        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = frameBuffer.Get();
        buffers.FrameBufferLength = frameBuffer.Count();
        if (type == KhWebSocketMessageType::Ping) {
            status = websocket->Client->SendPing(payload, payloadLength, buffers);
        }
        else {
            status = websocket->Client->SendPong(payload, payloadLength, buffers);
        }
        if (!NT_SUCCESS(status)) {
            kprintf("KhWebSocketSendControlSync Client->SendControl failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
        }
        return status;
#endif
    }

    NTSTATUS KhWebSocketSendPingSyncImpl(
        KH_WEBSOCKET websocket,
        const UCHAR* payload,
        SIZE_T payloadLength) noexcept
    {
        return KhWebSocketSendControlSyncImpl(
            websocket,
            KhWebSocketMessageType::Ping,
            payload,
            payloadLength);
    }

    NTSTATUS KhWebSocketSendPongSyncImpl(
        KH_WEBSOCKET websocket,
        const UCHAR* payload,
        SIZE_T payloadLength) noexcept
    {
        return KhWebSocketSendControlSyncImpl(
            websocket,
            KhWebSocketMessageType::Pong,
            payload,
            payloadLength);
    }

    NTSTATUS KhWebSocketReceiveSyncImpl(
        KH_WEBSOCKET websocket,
        const KhWebSocketReceiveOptions* options,
        KhWebSocketMessage* message) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (message != nullptr) {
            *message = {};
        }

        KhWebSocketOperationScope operation(websocket);
        if (!operation.IsActive()) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!websocket->Connected) {
            return websocket->TransportClosed ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_PARAMETER;
        }

        KhWebSocketReceiveOptions effectiveOptions = {};
        effectiveOptions.AutoAllocate = true;
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidReceiveOptions(effectiveOptions)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (effectiveOptions.AutoAllocate && message == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketReceive == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        KhTestWebSocketMessage received = {};
        status = g_testWebSocketReceive(g_testWebSocketTransportContext, websocket, &received);
        if (!NT_SUCCESS(status)) {
            DisconnectWebSocketOnTerminalStatus(*websocket, status);
            return status;
        }

        if (received.Data == nullptr && received.DataLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T maxMessageBytes = websocket->MaxMessageBytes;
        if (effectiveOptions.MaxMessageBytes != 0 &&
            effectiveOptions.MaxMessageBytes < maxMessageBytes) {
            maxMessageBytes = effectiveOptions.MaxMessageBytes;
        }
        if (received.DataLength > maxMessageBytes) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
            UNREFERENCED_PARAMETER(closeStatus);
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (effectiveOptions.MessageCallback != nullptr) {
            status = effectiveOptions.MessageCallback(
                effectiveOptions.CallbackContext,
                received.Type,
                received.Data,
                received.DataLength,
                received.FinalFragment);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (effectiveOptions.AutoAllocate) {
            status = StoreWebSocketMessage(*websocket, received.Type, received.Data, received.DataLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message->Type = websocket->LastMessageType;
            message->Data = websocket->LastMessage;
            message->DataLength = websocket->LastMessageLength;
            message->FinalFragment = received.FinalFragment;
        }

        if (received.Type == KhWebSocketMessageType::Close) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        return STATUS_SUCCESS;
#else
        if (websocket->Client == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        SIZE_T maxMessageBytes = websocket->MaxMessageBytes;
        if (effectiveOptions.MaxMessageBytes != 0 &&
            effectiveOptions.MaxMessageBytes < maxMessageBytes) {
            maxMessageBytes = effectiveOptions.MaxMessageBytes;
        }
        if (websocket->Workspace == nullptr ||
            websocket->Workspace->WebSocketFrameScratch.Data == nullptr ||
            websocket->Workspace->WebSocketFrameScratch.Length < KhWorkspaceWebSocketFrameScratchBytes ||
            websocket->Workspace->WebSocketPayloadScratch.Data == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (websocket->Workspace->WebSocketPayloadScratch.Length < maxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        MutexScope receiveLock(&websocket->ReceiveLock);
        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Workspace->WebSocketFrameScratch.Length;
        KernelHttp::websocket::WebSocketOpcode opcode = KernelHttp::websocket::WebSocketOpcode::Continuation;
        SIZE_T bytesReceived = 0;
        status = websocket->Client->ReceiveMessage(
            buffers,
            &opcode,
            websocket->Workspace->WebSocketPayloadScratch.Data,
            maxMessageBytes,
            &bytesReceived,
            websocket->AutoReplyPing);
        if (!NT_SUCCESS(status)) {
            kprintf("KhWebSocketReceiveSync Client->ReceiveMessage failed: 0x%08X\r\n",
                static_cast<ULONG>(status));
            if (status == STATUS_BUFFER_TOO_SMALL || IsWebSocketTransportTerminalStatus(status)) {
                const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
                UNREFERENCED_PARAMETER(closeStatus);
            }
            return status;
        }

        KhWebSocketMessageType type = KhWebSocketMessageType::Binary;
        if (opcode == KernelHttp::websocket::WebSocketOpcode::Text) {
            type = KhWebSocketMessageType::Text;
        }
        else if (opcode == KernelHttp::websocket::WebSocketOpcode::Close) {
            type = KhWebSocketMessageType::Close;
        }
        else if (opcode == KernelHttp::websocket::WebSocketOpcode::Ping) {
            type = KhWebSocketMessageType::Ping;
        }
        else if (opcode == KernelHttp::websocket::WebSocketOpcode::Pong) {
            type = KhWebSocketMessageType::Pong;
        }

        const UCHAR* data = websocket->Workspace->WebSocketPayloadScratch.Data;
        if (effectiveOptions.MessageCallback != nullptr) {
            status = effectiveOptions.MessageCallback(
                effectiveOptions.CallbackContext,
                type,
                data,
                bytesReceived,
                true);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (effectiveOptions.AutoAllocate) {
            status = StoreWebSocketMessage(*websocket, type, data, bytesReceived);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message->Type = websocket->LastMessageType;
            message->Data = websocket->LastMessage;
            message->DataLength = websocket->LastMessageLength;
            message->FinalFragment = true;
        }

        if (type == KhWebSocketMessageType::Close) {
            const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        return STATUS_SUCCESS;
#endif
    }

    NTSTATUS KhWebSocketCloseSyncImpl(KH_WEBSOCKET websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket == nullptr) {
            return STATUS_SUCCESS;
        }

        if (!TryCloseActiveWebSocketHandle(websocket)) {
            return STATUS_INVALID_PARAMETER;
        }

        WaitForWebSocketDrain(websocket);

        const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
        UNREFERENCED_PARAMETER(closeStatus);
        ReleaseWebSocketStorage(*websocket);
        FreeHandle(websocket);
        return STATUS_SUCCESS;
    }

    NTSTATUS KhWebSocketCloseExSyncImpl(
        KH_WEBSOCKET websocket,
        USHORT statusCode,
        const UCHAR* reason,
        SIZE_T reasonLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsValidWebSocketCloseStatus(statusCode) ||
            (reason == nullptr && reasonLength != 0) ||
            reasonLength > websocket::WebSocketMaxControlPayloadLength - 2 ||
            !IsValidWebSocketUtf8(reason, reasonLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (websocket == nullptr) {
            return STATUS_SUCCESS;
        }

        if (!TryCloseActiveWebSocketHandle(websocket)) {
            return STATUS_INVALID_PARAMETER;
        }

        WaitForWebSocketDrain(websocket);

        HeapArray<UCHAR> closePayload(2 + reasonLength);
        if (!closePayload.IsValid()) {
            ReleaseWebSocketStorage(*websocket);
            FreeHandle(websocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        closePayload[0] = static_cast<UCHAR>((statusCode >> 8) & 0xff);
        closePayload[1] = static_cast<UCHAR>(statusCode & 0xff);
        if (reasonLength != 0) {
            RtlCopyMemory(closePayload.Get() + 2, reason, reasonLength);
        }

        status = STATUS_SUCCESS;
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend != nullptr && websocket->Connected) {
            status = g_testWebSocketSend(
                g_testWebSocketTransportContext,
                websocket,
                KhWebSocketMessageType::Close,
                closePayload.Get(),
                closePayload.Count(),
                true);
        }
        const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
        UNREFERENCED_PARAMETER(closeStatus);
#endif
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        if (websocket->Client != nullptr) {
            HeapArray<UCHAR> frameBuffer(KhWorkspaceWebSocketFrameScratchBytes);
            if (!frameBuffer.IsValid()) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else {
                client::WebSocketIoBuffers buffers = {};
                buffers.FrameBuffer = frameBuffer.Get();
                buffers.FrameBufferLength = frameBuffer.Count();
                status = websocket->Client->Close(statusCode, reason, reasonLength, buffers);
            }
        }
        const NTSTATUS closeStatus = CloseWebSocketTransport(*websocket);
        if (NT_SUCCESS(status)) {
            status = closeStatus;
        }
#endif
        ReleaseWebSocketStorage(*websocket);
        FreeHandle(websocket);
        return status;
    }

    NTSTATUS KhWebSocketSelectedSubprotocol(
        KH_WEBSOCKET websocket,
        const char** subprotocol,
        SIZE_T* subprotocolLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (subprotocol != nullptr) {
            *subprotocol = nullptr;
        }
        if (subprotocolLength != nullptr) {
            *subprotocolLength = 0;
        }

        KhWebSocketOperationScope operation(websocket);
        if (!operation.IsActive() ||
            subprotocol == nullptr ||
            subprotocolLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (websocket->Subprotocol == nullptr || websocket->SubprotocolLength == 0) {
            return STATUS_NOT_FOUND;
        }

        *subprotocol = websocket->Subprotocol;
        *subprotocolLength = websocket->SubprotocolLength;
        return STATUS_SUCCESS;
    }


    NTSTATUS KhAsyncGetWebSocket(KH_ASYNC_OPERATION operation, KH_WEBSOCKET* websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        if (!KhAsyncOperationIsValid(operation) ||
            websocket == nullptr ||
            KhAsyncOperationGetKind(operation) != KhAsyncOperationKind::WebSocketConnect) {
            return STATUS_INVALID_PARAMETER;
        }

        status = KhAsyncOperationStatus(operation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* context = static_cast<KhAsyncWebSocketConnectContext*>(KhAsyncOperationContext(operation));
        KH_WEBSOCKET asyncWebSocket = TakeAsyncWebSocketConnectResult(context);
        if (asyncWebSocket == nullptr) {
            return STATUS_NOT_FOUND;
        }

        *websocket = asyncWebSocket;
        return STATUS_SUCCESS;
    }



NTSTATUS KhWebSocketConnectSync(
    KH_SESSION session,
    const KhWebSocketConnectOptions* options,
    KH_WEBSOCKET* websocket) noexcept
{
    return KhWebSocketConnectSyncImpl(session, options, websocket);
}

NTSTATUS KhWebSocketConnectAsync(
    KH_SESSION session,
    const KhWebSocketConnectOptions* options,
    KH_ASYNC_OPERATION* operation) noexcept
{
    return KhWebSocketConnectAsyncImpl(session, options, operation);
}

NTSTATUS KhWebSocketSendTextSync(
    KH_WEBSOCKET websocket,
    const char* text,
    SIZE_T textLength,
    const KhWebSocketSendOptions* options) noexcept
{
    return KhWebSocketSendTextSyncImpl(websocket, text, textLength, options);
}

NTSTATUS KhWebSocketSendBinarySync(
    KH_WEBSOCKET websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const KhWebSocketSendOptions* options) noexcept
{
    return KhWebSocketSendBinarySyncImpl(websocket, data, dataLength, options);
}

NTSTATUS KhWebSocketSendContinuationSync(
    KH_WEBSOCKET websocket,
    const UCHAR* data,
    SIZE_T dataLength,
    const KhWebSocketSendOptions* options) noexcept
{
    return KhWebSocketSendContinuationSyncImpl(websocket, data, dataLength, options);
}

NTSTATUS KhWebSocketSendPingSync(
    KH_WEBSOCKET websocket,
    const UCHAR* payload,
    SIZE_T payloadLength) noexcept
{
    return KhWebSocketSendPingSyncImpl(websocket, payload, payloadLength);
}

NTSTATUS KhWebSocketSendPongSync(
    KH_WEBSOCKET websocket,
    const UCHAR* payload,
    SIZE_T payloadLength) noexcept
{
    return KhWebSocketSendPongSyncImpl(websocket, payload, payloadLength);
}

NTSTATUS KhWebSocketReceiveSync(
    KH_WEBSOCKET websocket,
    const KhWebSocketReceiveOptions* options,
    KhWebSocketMessage* message) noexcept
{
    return KhWebSocketReceiveSyncImpl(websocket, options, message);
}

NTSTATUS KhWebSocketCloseSync(KH_WEBSOCKET websocket) noexcept
{
    return KhWebSocketCloseSyncImpl(websocket);
}

NTSTATUS KhWebSocketCloseExSync(
    KH_WEBSOCKET websocket,
    USHORT statusCode,
    const UCHAR* reason,
    SIZE_T reasonLength) noexcept
{
    return KhWebSocketCloseExSyncImpl(websocket, statusCode, reason, reasonLength);
}
}
}
