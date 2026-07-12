    _Must_inspect_result_
    NTSTATUS StoreWebSocketSubprotocol(
        _Inout_ WebSocket& websocket,
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
        SessionHandle session,
        const WebSocketConnectOptions& options,
        _Out_ WebSocketHandle* websocket,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
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

        WebSocketHandle newWebSocket = AllocateWebSocketHandle();
        if (newWebSocket == nullptr) {
            FreeApiMemory(urlCopy);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newWebSocket->Header = { HandleKind::WebSocket, 0, nullptr };
        newWebSocket->Session = session;
        newWebSocket->Url = urlCopy;
        newWebSocket->UrlLength = options.UrlLength;
        newWebSocket->MaxMessageBytes = options.MaxMessageBytes;
        newWebSocket->AutoReplyPing = options.AutoReplyPing;
        newWebSocket->PerMessageDeflate = options.PerMessageDeflate;
        newWebSocket->InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeMutex(&newWebSocket->SendLock, 0);
        KeInitializeMutex(&newWebSocket->ReceiveLock, 0);
        KeInitializeEvent(&newWebSocket->DrainEvent, NotificationEvent, TRUE);
#endif

        WorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = PoolType::NonPaged;
        workspaceOptions.MaxResponseBytes = options.MaxMessageBytes;
        NTSTATUS status = WorkspaceCreateFromLookaside(
            &workspaceOptions,
            &session->WorkspaceLookaside,
            &newWebSocket->Workspace);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }
        status = WorkspaceEnsureWebSocketPayloadCapacity(
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
        if (WebSocketModeRequiresWss(options) &&
            !TextEqualsLiteralIgnoreCase(newWebSocket->Scheme, newWebSocket->SchemeLength, "wss")) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_NOT_SUPPORTED;
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

        TlsOptions effectiveTls = options.Tls;
        if (options.Tls.CertificatePolicy == CertificatePolicy::Verify &&
            options.Tls.CertificateStore == nullptr &&
            options.Tls.ServerName == nullptr &&
            options.Tls.ServerNameLength == 0 &&
            options.Tls.Alpn == nullptr &&
            options.Tls.AlpnLength == 0 &&
            options.Tls.MinVersion == TlsVersion::Tls12 &&
            options.Tls.MaxVersion == TlsVersion::Tls13 &&
            options.Tls.Policy.Profile == tls::TlsSecurityProfile::ModernDefault &&
            !options.Tls.Policy.EnableTls12RsaKeyExchange &&
            !options.Tls.Policy.EnableTls12Cbc &&
            !options.Tls.Policy.EnableTls12Renegotiation &&
            !options.Tls.Policy.EnableTls12Sha1Signatures &&
            !options.Tls.Policy.EnablePostHandshakeClientAuth &&
            !options.Tls.Policy.RequireRevocationCheck &&
            options.Tls.HandshakeReceiveTimeoutMilliseconds == DefaultTlsHandshakeReceiveTimeoutMilliseconds &&
            options.Tls.MaxTls12Renegotiations == DefaultMaxTls12Renegotiations) {
            effectiveTls = session->Options.Tls;
        }
        if (effectiveTls.ServerName == nullptr &&
            TextEqualsLiteralIgnoreCase(newWebSocket->Scheme, newWebSocket->SchemeLength, "wss")) {
            effectiveTls.ServerName = newWebSocket->Host;
            effectiveTls.ServerNameLength = newWebSocket->HostLength;
        }

        newWebSocket->Workspace->MaxResponseBytes = options.MaxMessageBytes;
        WorkspaceReset(newWebSocket->Workspace);

        SIZE_T handshakeLength = 0;
        status = BuildWebSocketHandshakeRequest(*newWebSocket, *newWebSocket->Workspace, &handshakeLength);
        WKNET_DBG_PRINT("DEBUG BuildWebSocketHandshakeRequest status=0x%08X scheme=%.*s port=%u\r\n",
            static_cast<ULONG>(status),
            static_cast<int>(newWebSocket->SchemeLength),
            newWebSocket->Scheme,
            newWebSocket->Port);
        if (!NT_SUCCESS(status)) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return status;
        }
        UNREFERENCED_PARAMETER(handshakeLength);

#if defined(WKNET_USER_MODE_TEST)
        if (g_testWebSocketConnect == nullptr) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_NOT_SUPPORTED;
        }

        TestWebSocketConnectRequest testRequest = {};
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
        testRequest.MaxTls12Renegotiations = effectiveTls.MaxTls12Renegotiations;
        testRequest.AddressFamily = options.AddressFamily;
        testRequest.AutoReplyPing = newWebSocket->AutoReplyPing;
        testRequest.MaxMessageBytes = newWebSocket->MaxMessageBytes;
        testRequest.AllowWebSocketOverHttp2 = options.AllowWebSocketOverHttp2;
        testRequest.TransportMode = options.TransportMode;
        testRequest.PerMessageDeflate = options.PerMessageDeflate;

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

        HeapArray<wchar_t> serverName(MaxHostLength + 1);
        HeapArray<wchar_t> serviceName(MaxServiceNameLength + 1);
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
        HeapArray<http1::HttpHeader> responseHeaders(MaxHeadersPerResponse);
        if (!responseHeaders.IsValid()) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        buffers.Headers = responseHeaders.Get();
        buffers.HeaderCapacity = MaxHeadersPerResponse;

        client::WebSocketConnectOptions connectOptions = {};
        HeapArray<http1::HttpHeader> extraHeaderViews(MaxHeadersPerRequest);
        if (!extraHeaderViews.IsValid()) {
            ReleaseWebSocketStorage(*newWebSocket);
            FreeHandle(newWebSocket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T extraHeaderViewCount = 0;
        for (SIZE_T index = 0; index < newWebSocket->ExtraHeaderCount && index < MaxHeadersPerRequest; ++index) {
            const StoredHeader& stored = newWebSocket->ExtraHeaders[index];
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
        connectOptions.MaxTls12Renegotiations = effectiveTls.MaxTls12Renegotiations;
        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsWebSocketAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
            connectOptions.Cancellation = &cancellation;
        }
        connectOptions.UseTls = TextEqualsLiteralIgnoreCase(newWebSocket->Scheme, newWebSocket->SchemeLength, "wss");
        connectOptions.VerifyCertificate = effectiveTls.CertificatePolicy == CertificatePolicy::Verify;
        connectOptions.AllowWebSocketOverHttp2 = options.AllowWebSocketOverHttp2;
        connectOptions.TransportMode = ToClientWebSocketTransportMode(options.TransportMode);
        connectOptions.PerMessageDeflate = options.PerMessageDeflate;
        WebSocketChallengeBridgeContext challengeBridge = {};
        if (options.ChallengeCallback != nullptr) {
            challengeBridge.Callback = options.ChallengeCallback;
            challengeBridge.Context = options.ChallengeContext;
            connectOptions.ChallengeCallback = WebSocketChallengeBridge;
            connectOptions.ChallengeContext = &challengeBridge;
            connectOptions.MaxHandshakeRetries = options.MaxHandshakeRetries;
        }

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

    NTSTATUS RunWebSocketConnectAsyncOperation(AsyncOperationHandle operation, void* context) noexcept
    {
        auto* connectContext = static_cast<AsyncWebSocketConnectContext*>(context);
        if (connectContext == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        if (AsyncOperationIsCanceled(operation)) {
            status = STATUS_CANCELLED;
            EndAsyncWebSocketSessionOperation(connectContext);
            return status;
        }

        WebSocketHandle websocket = nullptr;
        status = CompleteWebSocketConnect(connectContext->Session, connectContext->Options, &websocket, operation);
        if (NT_SUCCESS(status)) {
            connectContext->WebSocket = websocket;
        }
        else if (websocket != nullptr) {
            const NTSTATUS closeStatus = WebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(closeStatus);
        }

        if (AsyncOperationIsCanceled(operation) && status == STATUS_SUCCESS) {
            status = STATUS_CANCELLED;
        }

        EndAsyncWebSocketSessionOperation(connectContext);
        return status;
    }

    NTSTATUS WebSocketConnectSyncImpl(
        SessionHandle session,
        const WebSocketConnectOptions* options,
        WebSocketHandle* websocket) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (websocket != nullptr) {
            *websocket = nullptr;
        }

        SessionOperationScope sessionScope(session);
        if (!sessionScope.IsActive()) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options == nullptr || websocket == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        return CompleteWebSocketConnect(session, *options, websocket, nullptr);
    }

    NTSTATUS WebSocketConnectAsyncImpl(
        SessionHandle session,
        const WebSocketConnectOptions* options,
        AsyncOperationHandle* operation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (operation != nullptr) {
            *operation = nullptr;
        }

        if (!SessionBeginOperation(session)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options == nullptr || operation == nullptr || !IsValidWebSocketConnectOptions(*options)) {
            SessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }

        auto* context = AllocateAsyncWebSocketConnectContext();
        if (context == nullptr) {
            SessionEndOperation(session);
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
            if (options->HeaderCount > MaxHeadersPerRequest) {
                CleanupAsyncWebSocketConnectContext(context);
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < options->HeaderCount; ++index) {
                const WebSocketHeader& src = options->Headers[index];
                StoredHeader& dst = context->HeaderStorage[index];

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

        AsyncCreateOptions createOptions = {};
        createOptions.Kind = AsyncOperationKind::WebSocketConnect;
        createOptions.WorkerRoutine = RunWebSocketConnectAsyncOperation;
        createOptions.CleanupRoutine = CleanupAsyncWebSocketConnectContext;
        createOptions.Context = context;
        createOptions.StartSuspended = true;

        status = AsyncOperationCreate(createOptions, operation);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncWebSocketConnectContext(context);
            return status;
        }

        status = AsyncOperationQueue(*operation);
        if (!NT_SUCCESS(status)) {
            AsyncOperationRelease(*operation);
            *operation = nullptr;
        }

        return status;
    }

