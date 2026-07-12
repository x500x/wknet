#if !defined(WKNET_USER_MODE_TEST)
    static bool IsWebSocketAsyncCancellationRequested(_In_opt_ void* context) noexcept
    {
        return context != nullptr &&
            AsyncOperationIsCanceled(static_cast<AsyncOperationHandle>(context));
    }
#endif

    bool WebSocketModeAllowsHttp2(const WebSocketConnectOptions& options) noexcept
    {
        switch (options.TransportMode) {
        case WebSocketTransportMode::Http11Only:
            return false;
        case WebSocketTransportMode::Auto:
        case WebSocketTransportMode::Http2Required:
            return true;
        case WebSocketTransportMode::LegacyBoolean:
        default:
            return options.AllowWebSocketOverHttp2;
        }
    }

    bool WebSocketModeRequiresWss(const WebSocketConnectOptions& options) noexcept
    {
        return options.TransportMode == WebSocketTransportMode::Http2Required ||
            (options.TransportMode == WebSocketTransportMode::LegacyBoolean &&
                options.AllowWebSocketOverHttp2);
    }

    client::WebSocketTransportMode ToClientWebSocketTransportMode(WebSocketTransportMode mode) noexcept
    {
        switch (mode) {
        case WebSocketTransportMode::Http11Only:
            return client::WebSocketTransportMode::Http11Only;
        case WebSocketTransportMode::Auto:
            return client::WebSocketTransportMode::Auto;
        case WebSocketTransportMode::Http2Required:
            return client::WebSocketTransportMode::Http2Required;
        case WebSocketTransportMode::LegacyBoolean:
        default:
            return client::WebSocketTransportMode::LegacyBoolean;
        }
    }

    struct WebSocketChallengeBridgeContext final
    {
        WebSocketHandshakeChallengeCallback Callback = nullptr;
        void* Context = nullptr;
    };

    NTSTATUS WebSocketChallengeBridge(
        void* context,
        const client::WebSocketHandshakeChallenge* challenge,
        client::WebSocketHandshakeRetryAction* action) noexcept
    {
        auto* bridge = static_cast<WebSocketChallengeBridgeContext*>(context);
        if (bridge == nullptr ||
            bridge->Callback == nullptr ||
            challenge == nullptr ||
            action == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        WebSocketHandshakeChallenge apiChallenge = {};
        apiChallenge.StatusCode = challenge->StatusCode;
        apiChallenge.Headers = challenge->Headers;
        apiChallenge.HeaderCount = challenge->HeaderCount;
        apiChallenge.Redirect = challenge->Redirect;
        apiChallenge.AuthenticationChallenge = challenge->AuthenticationChallenge;

        WebSocketHandshakeRetryAction apiAction = {};
        NTSTATUS status = bridge->Callback(bridge->Context, &apiChallenge, &apiAction);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        action->RedirectPath = apiAction.RedirectPath;
        action->RedirectPathLength = apiAction.RedirectPathLength;
        action->Headers = apiAction.Headers;
        action->HeaderCount = apiAction.HeaderCount;
        return STATUS_SUCCESS;
    }

    NTSTATUS AppendWebSocketLiteral(
        const char* literal,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* length) noexcept
    {
        if (literal == nullptr || destination == nullptr || length == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        const http1::HttpText text = http1::MakeText(literal);
        if (text.Length > destinationCapacity - *length) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(destination + *length, text.Data, text.Length);
        *length += text.Length;
        return STATUS_SUCCESS;
    }

    NTSTATUS AppendWebSocketWindowBits(
        UCHAR value,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* length) noexcept
    {
        if (value < ws::WebSocketDeflateMinWindowBits ||
            value > ws::WebSocketDeflateMaxWindowBits ||
            destination == nullptr ||
            length == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (destinationCapacity - *length < 2) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (value >= 10) {
            destination[(*length)++] = static_cast<char>('0' + (value / 10));
        }
        destination[(*length)++] = static_cast<char>('0' + (value % 10));
        return STATUS_SUCCESS;
    }

    NTSTATUS BuildWebSocketDeflateOffer(
        const ws::PerMessageDeflateOptions& options,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* length) noexcept
    {
        if (length != nullptr) {
            *length = 0;
        }
        if (destination == nullptr || length == nullptr || !options.Enable) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = AppendWebSocketLiteral("permessage-deflate; client_max_window_bits=", destination, destinationCapacity, length);
        if (NT_SUCCESS(status)) {
            status = AppendWebSocketWindowBits(options.ClientMaxWindowBits, destination, destinationCapacity, length);
        }
        if (NT_SUCCESS(status)) {
            status = AppendWebSocketLiteral("; server_max_window_bits=", destination, destinationCapacity, length);
        }
        if (NT_SUCCESS(status)) {
            status = AppendWebSocketWindowBits(options.ServerMaxWindowBits, destination, destinationCapacity, length);
        }
        if (NT_SUCCESS(status) && options.ClientNoContextTakeover) {
            status = AppendWebSocketLiteral("; client_no_context_takeover", destination, destinationCapacity, length);
        }
        if (NT_SUCCESS(status) && options.ServerNoContextTakeover) {
            status = AppendWebSocketLiteral("; server_no_context_takeover", destination, destinationCapacity, length);
        }
        return status;
    }

    _Must_inspect_result_
    NTSTATUS BuildWebSocketHandshakeRequest(
        const WebSocket& websocket,
        _Inout_ Workspace& workspace,
        _Out_ SIZE_T* requestLength) noexcept
    {
        if (requestLength != nullptr) {
            *requestLength = 0;
        }

        if (requestLength == nullptr || websocket.HostLength == 0 || websocket.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> hostHeader(MaxHostHeaderLength);
        if (!hostHeader.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T hostLength = 0;
        HeapArray<Request> hostRequestStorage(1);
        if (!hostRequestStorage.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Request& hostRequest = hostRequestStorage[0];
        RtlCopyMemory(hostRequest.Scheme, websocket.Scheme, sizeof(hostRequest.Scheme));
        hostRequest.SchemeLength = websocket.SchemeLength;
        RtlCopyMemory(hostRequest.Host, websocket.Host, sizeof(hostRequest.Host));
        hostRequest.HostLength = websocket.HostLength;
        hostRequest.Port = websocket.Port;
        NTSTATUS status = BuildHostHeaderValue(hostRequest, hostHeader.Get(), hostHeader.Count(), &hostLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<char> clientKey(ws::WebSocketClientKeyBase64Length);
        if (!clientKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T clientKeyLength = 0;
        status = ws::WebSocketCodec::GenerateClientKey(
            clientKey.Get(),
            clientKey.Count(),
            &clientKeyLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<char> extensionOffer;
        SIZE_T extensionOfferLength = 0;
        if (websocket.PerMessageDeflate.Enable) {
            status = extensionOffer.Allocate(160);
            if (NT_SUCCESS(status)) {
                status = BuildWebSocketDeflateOffer(
                    websocket.PerMessageDeflate,
                    extensionOffer.Get(),
                    extensionOffer.Count(),
                    &extensionOfferLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        HeapArray<http1::HttpHeader> headers(5 + MaxHeadersPerRequest);
        if (!headers.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T headerCount = 0;
        headers[headerCount++] = { http1::MakeText("Upgrade"), http1::MakeText("websocket") };
        headers[headerCount++] = { http1::MakeText("Sec-WebSocket-Key"), { clientKey.Get(), clientKeyLength } };
        headers[headerCount++] = { http1::MakeText("Sec-WebSocket-Version"), http1::MakeText("13") };
        if (websocket.Subprotocol != nullptr && websocket.SubprotocolLength != 0) {
            headers[headerCount++] = {
                http1::MakeText("Sec-WebSocket-Protocol"),
                { websocket.Subprotocol, websocket.SubprotocolLength }
            };
        }
        if (websocket.PerMessageDeflate.Enable) {
            headers[headerCount++] = {
                http1::MakeText("Sec-WebSocket-Extensions"),
                { extensionOffer.Get(), extensionOfferLength }
            };
        }

        for (SIZE_T index = 0; index < websocket.ExtraHeaderCount && index < MaxHeadersPerRequest; ++index) {
            const StoredHeader& stored = websocket.ExtraHeaders[index];
            headers[headerCount++] = {
                { stored.Name, stored.NameLength },
                { stored.Value, stored.ValueLength }
            };
        }

        http1::HttpRequestBuildOptions buildOptions = {};
        buildOptions.Method = http1::HttpMethod::Get;
        buildOptions.Path = { websocket.Path, websocket.PathLength };
        buildOptions.Host = { hostHeader.Get(), hostLength };
        buildOptions.Connection = http1::HttpConnectionDirective::Upgrade;
        buildOptions.ExtraHeaders = headers.Get();
        buildOptions.ExtraHeaderCount = headerCount;

        return http1::HttpRequestBuilder::Build(
            buildOptions,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            requestLength);
    }
