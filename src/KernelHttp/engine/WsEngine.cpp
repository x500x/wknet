#include <KernelHttp/engine/WsEngine.h>
#include <KernelHttp/engine/EngineInternal.h>
#include <KernelHttp/engine/UrlParser.h>
#include <KernelHttp/http/HttpRequest.h>
#include <KernelHttp/websocket/WebSocketFrame.h>

namespace KernelHttp
{
namespace engine
{
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

        HeapArray<http::HttpHeader> headers(5);
        if (!headers.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T headerCount = 0;
        headers[headerCount++] = { http::MakeText("Upgrade"), http::MakeText("websocket") };
        headers[headerCount++] = { http::MakeText("Connection"), http::MakeText("Upgrade") };
        headers[headerCount++] = { http::MakeText("Sec-WebSocket-Key"), { clientKey.Get(), clientKeyLength } };
        headers[headerCount++] = { http::MakeText("Sec-WebSocket-Version"), http::MakeText("13") };
        if (websocket.Subprotocol != nullptr && websocket.SubprotocolLength != 0) {
            headers[headerCount++] = {
                http::MakeText("Sec-WebSocket-Protocol"),
                { websocket.Subprotocol, websocket.SubprotocolLength }
            };
        }

        http::HttpRequestBuildOptions buildOptions = {};
        buildOptions.Method = http::HttpMethod::Get;
        buildOptions.Path = { websocket.Path, websocket.PathLength };
        buildOptions.Host = { hostHeader.Get(), hostLength };
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
        KH_WEBSOCKET WebSocket = nullptr;
    };


    _Ret_maybenull_
    KhAsyncWebSocketConnectContext* AllocateAsyncWebSocketConnectContext() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return static_cast<KhAsyncWebSocketConnectContext*>(calloc(1, sizeof(KhAsyncWebSocketConnectContext)));
#else
        return new KhAsyncWebSocketConnectContext();
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
        delete context;
#endif
    }


    void CleanupAsyncWebSocketConnectContext(void* context) noexcept
    {
        auto* connectContext = static_cast<KhAsyncWebSocketConnectContext*>(context);
        if (connectContext == nullptr) {
            return;
        }

        FreeApiMemory(connectContext->Url);
        FreeApiMemory(connectContext->Subprotocol);
        if (connectContext->WebSocket != nullptr) {
            const NTSTATUS status = KhWebSocketCloseSync(connectContext->WebSocket);
            UNREFERENCED_PARAMETER(status);
            connectContext->WebSocket = nullptr;
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
    NTSTATUS CompleteWebSocketConnect(
        KH_SESSION session,
        const KhWebSocketConnectOptions& options,
        _Out_ KH_WEBSOCKET* websocket) noexcept
    {
        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        if (!IsSessionHandle(session) || websocket == nullptr || !IsValidWebSocketConnectOptions(options)) {
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

        newWebSocket->Header = { KhHandleKind::WebSocket, false };
        newWebSocket->Session = session;
        newWebSocket->Url = urlCopy;
        newWebSocket->UrlLength = options.UrlLength;
        newWebSocket->MaxMessageBytes = options.MaxMessageBytes;
        newWebSocket->AutoReplyPing = options.AutoReplyPing;
        NTSTATUS status = ParseUrlParts(
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

        KhTlsOptions effectiveTls = options.Tls;
        if (options.Tls.CertificatePolicy == KhCertificatePolicy::Verify &&
            options.Tls.CertificateStore == nullptr &&
            options.Tls.ServerName == nullptr &&
            options.Tls.ServerNameLength == 0 &&
            options.Tls.Alpn == nullptr &&
            options.Tls.AlpnLength == 0 &&
            options.Tls.MinVersion == KhTlsVersion::Tls12 &&
            options.Tls.MaxVersion == KhTlsVersion::Tls13 &&
            options.Tls.HandshakeReceiveTimeoutMilliseconds == KhDefaultTlsHandshakeReceiveTimeoutMilliseconds) {
            effectiveTls = session->Options.Tls;
        }
        if (effectiveTls.ServerName == nullptr &&
            TextEqualsLiteralIgnoreCase(newWebSocket->Scheme, newWebSocket->SchemeLength, "wss")) {
            effectiveTls.ServerName = newWebSocket->Host;
            effectiveTls.ServerNameLength = newWebSocket->HostLength;
        }

        session->Workspace->MaxResponseBytes = options.MaxMessageBytes;
        KhWorkspaceReset(session->Workspace);

        SIZE_T handshakeLength = 0;
        status = BuildWebSocketHandshakeRequest(*newWebSocket, *session->Workspace, &handshakeLength);
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
        testRequest.MinTlsVersion = effectiveTls.MinVersion;
        testRequest.MaxTlsVersion = effectiveTls.MaxVersion;
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
        *websocket = newWebSocket;
        return STATUS_SUCCESS;
#else
        newWebSocket->Client = new client::WebSocketClient();
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
        buffers.RequestBuffer = reinterpret_cast<char*>(session->Workspace->Request.Data);
        buffers.RequestBufferLength = session->Workspace->Request.Length;
        buffers.ResponseBuffer = reinterpret_cast<char*>(session->Workspace->Response.Data);
        buffers.ResponseBufferLength = session->Workspace->Response.Length;
        buffers.FrameBuffer = session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = session->Workspace->WebSocketFrameScratch.Length;
        buffers.PayloadBuffer = session->Workspace->DecodedBody.Data;
        buffers.PayloadBufferLength = session->Workspace->DecodedBody.Length;
        HeapArray<http::HttpHeader> responseHeaders(KhMaxHeadersPerResponse);
        if (!responseHeaders.IsValid()) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        buffers.Headers = responseHeaders.Get();
        buffers.HeaderCapacity = KhMaxHeadersPerResponse;

        client::WebSocketConnectOptions connectOptions = {};
        connectOptions.ServerName = serverName.Get();
        connectOptions.ServiceName = serviceName.Get();
        connectOptions.TlsServerName = effectiveTls.ServerName != nullptr ? effectiveTls.ServerName : newWebSocket->Host;
        connectOptions.TlsServerNameLength = effectiveTls.ServerName != nullptr ?
            effectiveTls.ServerNameLength :
            newWebSocket->HostLength;
        connectOptions.Host = newWebSocket->Host;
        connectOptions.HostLength = newWebSocket->HostLength;
        connectOptions.Path = newWebSocket->Path;
        connectOptions.PathLength = newWebSocket->PathLength;
        connectOptions.Subprotocol = newWebSocket->Subprotocol;
        connectOptions.SubprotocolLength = newWebSocket->SubprotocolLength;
        connectOptions.CertificateStore = effectiveTls.CertificateStore;
        connectOptions.Workspace = session->Workspace;
        connectOptions.ProviderCache = session->ProviderCache;
        connectOptions.AddressFamily = ToWskAddressFamily(options.AddressFamily);
        connectOptions.MinimumTlsProtocol = ToTlsProtocol(effectiveTls.MinVersion);
        connectOptions.MaximumTlsProtocol = ToTlsProtocol(effectiveTls.MaxVersion);
        connectOptions.HandshakeReceiveTimeoutMilliseconds = effectiveTls.HandshakeReceiveTimeoutMilliseconds;
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

        newWebSocket->Connected = true;
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

        if (KhAsyncOperationIsCanceled(operation)) {
            return STATUS_CANCELLED;
        }

        KH_WEBSOCKET websocket = nullptr;
        NTSTATUS status = CompleteWebSocketConnect(connectContext->Session, connectContext->Options, &websocket);
        if (NT_SUCCESS(status)) {
            connectContext->WebSocket = websocket;
        }
        else if (websocket != nullptr) {
            const NTSTATUS closeStatus = KhWebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        if (KhAsyncOperationIsCanceled(operation) && status == STATUS_SUCCESS) {
            return STATUS_CANCELLED;
        }

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

        if (!IsSessionHandle(session) || options == nullptr || websocket == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        return CompleteWebSocketConnect(session, *options, websocket);
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

        if (!IsSessionHandle(session) || options == nullptr || operation == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        auto* context = AllocateAsyncWebSocketConnectContext();
        if (context == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        context->Session = session;
        context->Options = *options;
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

        KhAsyncCreateOptions createOptions = {};
        createOptions.Kind = KhAsyncOperationKind::WebSocketConnect;
        createOptions.WorkerRoutine = RunWebSocketConnectAsyncOperation;
        createOptions.CleanupRoutine = CleanupAsyncWebSocketConnectContext;
        createOptions.Context = context;

        status = KhAsyncOperationCreate(createOptions, operation);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncWebSocketConnectContext(context);
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
        if (!IsWebSocketHandle(websocket) || !websocket->Connected || text == nullptr || textLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (textLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        return g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            KhWebSocketMessageType::Text,
            reinterpret_cast<const UCHAR*>(text),
            textLength,
            finalFragment);
#else
        UNREFERENCED_PARAMETER(finalFragment);
        if (websocket->Client == nullptr || websocket->Session == nullptr || websocket->Session->Workspace == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
        return websocket->Client->SendText(text, textLength, buffers);
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
        if (!IsWebSocketHandle(websocket) || !websocket->Connected || data == nullptr || dataLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength > websocket->MaxMessageBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketSend == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        return g_testWebSocketSend(
            g_testWebSocketTransportContext,
            websocket,
            KhWebSocketMessageType::Binary,
            data,
            dataLength,
            finalFragment);
#else
        UNREFERENCED_PARAMETER(finalFragment);
        if (websocket->Client == nullptr || websocket->Session == nullptr || websocket->Session->Workspace == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
        return websocket->Client->SendBinary(data, dataLength, buffers);
#endif
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

        if (!IsWebSocketHandle(websocket) || !websocket->Connected) {
            return STATUS_INVALID_PARAMETER;
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
            return status;
        }

        if (received.Data == nullptr && received.DataLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T maxMessageBytes =
            effectiveOptions.MaxMessageBytes != 0 ? effectiveOptions.MaxMessageBytes : websocket->MaxMessageBytes;
        if (received.DataLength > maxMessageBytes) {
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
            websocket->Connected = false;
        }

        return STATUS_SUCCESS;
#else
        if (websocket->Client == nullptr || websocket->Session == nullptr || websocket->Session->Workspace == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        const SIZE_T maxMessageBytes =
            effectiveOptions.MaxMessageBytes != 0 ? effectiveOptions.MaxMessageBytes : websocket->MaxMessageBytes;
        const SIZE_T outputCapacity =
            maxMessageBytes < websocket->Session->Workspace->DecodedBody.Length ?
            maxMessageBytes :
            websocket->Session->Workspace->DecodedBody.Length;

        client::WebSocketIoBuffers buffers = {};
        buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
        buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
        KernelHttp::websocket::WebSocketOpcode opcode = KernelHttp::websocket::WebSocketOpcode::Continuation;
        SIZE_T bytesReceived = 0;
        status = websocket->Client->ReceiveMessage(
            buffers,
            &opcode,
            websocket->Session->Workspace->DecodedBody.Data,
            outputCapacity,
            &bytesReceived);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        KhWebSocketMessageType type = KhWebSocketMessageType::Binary;
        if (opcode == KernelHttp::websocket::WebSocketOpcode::Text) {
            type = KhWebSocketMessageType::Text;
        }
        else if (opcode == KernelHttp::websocket::WebSocketOpcode::Close) {
            type = KhWebSocketMessageType::Close;
            websocket->Connected = false;
        }

        const UCHAR* data = websocket->Session->Workspace->DecodedBody.Data;
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

        return STATUS_SUCCESS;
#endif
    }

    NTSTATUS KhWebSocketCloseSyncImpl(KH_WEBSOCKET websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsWebSocketHandle(websocket)) {
            return websocket == nullptr ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
        if (g_testWebSocketClose != nullptr) {
            g_testWebSocketClose(g_testWebSocketTransportContext, websocket);
        }
#endif
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        if (websocket->Client != nullptr && websocket->Session != nullptr && websocket->Session->Workspace != nullptr) {
            client::WebSocketIoBuffers buffers = {};
            buffers.FrameBuffer = websocket->Session->Workspace->WebSocketFrameScratch.Data;
            buffers.FrameBufferLength = websocket->Session->Workspace->WebSocketFrameScratch.Length;
            const NTSTATUS closeStatus = websocket->Client->Close(buffers);
            UNREFERENCED_PARAMETER(closeStatus);
        }
#endif
        websocket->Connected = false;
        ReleaseWebSocketStorage(*websocket);
        websocket->Header.Closed = true;
        FreeHandle(websocket);
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
        if (context == nullptr || context->WebSocket == nullptr) {
            return STATUS_NOT_FOUND;
        }

        *websocket = context->WebSocket;
        context->WebSocket = nullptr;
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
}
}
