#if defined(WKNET_USER_MODE_TEST)
    void PopulateTestHttpTransportRequest(
        const Request& request,
        const Session& session,
        PooledConnection* pooledConnection,
        bool reusedConnection,
        _In_reads_bytes_opt_(builtRequestLength) const char* builtRequest,
        SIZE_T builtRequestLength,
        SIZE_T headerBytesLength,
        SIZE_T bodyBytesLength,
        bool expectContinueEnabled,
        bool expectContinueBodySent,
        _Out_ TestHttpTransportRequest* testRequest,
        Http2CleartextMode http2CleartextMode = Http2CleartextMode::Disabled,
        bool usedHttp2 = false,
        bool http11PipelineEnabled = false,
        bool http11PipelineLease = false,
        ULONG http11PipelineSequence = 0) noexcept
    {
        if (testRequest == nullptr) {
            return;
        }

        RtlZeroMemory(testRequest, sizeof(*testRequest));
        testRequest->Scheme = request.Scheme;
        testRequest->SchemeLength = request.SchemeLength;
        testRequest->Host = request.Host;
        testRequest->HostLength = request.HostLength;
        testRequest->Port = request.Port;
        testRequest->AddressFamily = request.AddressFamily;
        testRequest->BuiltRequest = builtRequest;
        testRequest->BuiltRequestLength = builtRequestLength;
        testRequest->HeaderBytesLength = headerBytesLength;
        testRequest->BodyBytesLength = bodyBytesLength;
        testRequest->ExpectContinueEnabled = expectContinueEnabled;
        testRequest->ExpectContinueBodySent = expectContinueBodySent;
        testRequest->ConnectionPolicy = request.ConnectionPolicy;
        testRequest->CertificatePolicy = request.Tls.CertificatePolicy;
        testRequest->CertificateStore = request.Tls.CertificateStore;
        testRequest->ClientCredential = request.Tls.ClientCredential;
        testRequest->Alpn = request.Tls.Alpn;
        testRequest->AlpnLength = request.Tls.AlpnLength;
        if (IsAutomaticHttpAlpnMode(request)) {
            testRequest->OfferedAlpn = "h2,http/1.1";
            testRequest->OfferedAlpnLength = 11;
        }
        else if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            testRequest->OfferedAlpn = request.Tls.Alpn;
            testRequest->OfferedAlpnLength = request.Tls.AlpnLength;
        }
        testRequest->Policy = request.Tls.Policy;
        testRequest->MaxTls12Renegotiations = request.Tls.MaxTls12Renegotiations;
        testRequest->ProxyEnabled = session.Options.Proxy.Enabled;
        testRequest->ProxyAddress = session.Options.Proxy.Address;
        testRequest->ProxyAuthority = session.Options.Proxy.Authority;
        testRequest->ProxyAuthorityLength = session.Options.Proxy.AuthorityLength;
        testRequest->ProxyAuthHeader = session.Options.Proxy.AuthHeader;
        testRequest->ProxyAuthHeaderLength = session.Options.Proxy.AuthHeaderLength;
        testRequest->PoolableConnection = request.ConnectionPolicy != ConnectionPolicy::NoPool;
        testRequest->ReusedConnection = reusedConnection;
        testRequest->ConnectionId = pooledConnection != nullptr ? pooledConnection->Id : 0;
        testRequest->Http11PipelineEnabled = http11PipelineEnabled;
        testRequest->Http11PipelineLease = http11PipelineLease;
        testRequest->Http11PipelineSequence = http11PipelineSequence;
        testRequest->Http2CleartextMode = http2CleartextMode;
        testRequest->UsedHttp2 = usedHttp2;
    }
#endif

    _Must_inspect_result_
    NTSTATUS SendViaTransport(
        SessionHandle session,
        const Request& request,
        const HttpSendOptions& sendOptions,
        Workspace& workspace,
        PooledConnection* pooledConnection,
        bool reusedConnection,
        bool allowHttp11Pipeline,
        ULONG http11PipelineMaxDepth,
        SIZE_T builtRequestLength,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength,
        _Out_ bool* connectionReusable,
        _Out_opt_ bool* usedHttp11Pipeline,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
    {
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (connectionReusable != nullptr) {
            *connectionReusable = false;
        }
        if (usedHttp11Pipeline != nullptr) {
            *usedHttp11Pipeline = false;
        }

        if (session == nullptr ||
            parsed == nullptr ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr ||
            rawResponseLength == nullptr ||
            connectionReusable == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsHttpsRequest(request) &&
            request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            !IsSupportedHttpAlpn(request.Tls.Alpn, request.Tls.AlpnLength)) {
            return STATUS_NOT_SUPPORTED;
        }

        HeapArray<http1::HttpAcceptEncodingEntry> acceptEncodingEntries(http1::HttpMaxAcceptEncodingEntries);
        if (!acceptEncodingEntries.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        http1::HttpAcceptEncodingRules acceptEncodingRules = {};
        acceptEncodingRules.Entries = acceptEncodingEntries.Get();
        acceptEncodingRules.EntryCapacity = acceptEncodingEntries.Count();
        http1::HttpAcceptEncodingPolicy acceptPolicy = {};
        NTSTATUS status = BuildAcceptEncodingPolicyFromRequestHeaders(
            requestHeaders,
            requestHeaderCount,
            &acceptEncodingRules,
            &acceptPolicy);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if defined(WKNET_USER_MODE_TEST)
        UNREFERENCED_PARAMETER(cancellationOperation);

        if (g_testHttpTransport == nullptr) {
            return STATUS_NOT_SUPPORTED;
        }

        SIZE_T headerBytesLength = 0;
        if (!FindHttpRequestBodyOffset(workspace.Request.Data, builtRequestLength, &headerBytesLength)) {
            return STATUS_INVALID_PARAMETER;
        }
        SIZE_T bodyBytesLength = builtRequestLength - headerBytesLength;
        const bool useExpectContinue = RequestUsesExpectContinue(sendOptions, request);
        Http2CleartextMode http2CleartextMode = Http2CleartextMode::Disabled;
        status = EffectiveHttp2CleartextMode(
            sendOptions,
            request,
            &http2CleartextMode);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const bool useHttp2Cleartext =
            http2CleartextMode != Http2CleartextMode::Disabled;
        if (useHttp2Cleartext && useExpectContinue) {
            return STATUS_NOT_SUPPORTED;
        }
        if (http2CleartextMode == Http2CleartextMode::Upgrade &&
            (request.HasBody || request.BodySourceCallback != nullptr || request.TrailerCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool h2ExplicitlyRequestedForTest =
            request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "h2");
        bool testHttp11PipelineLease = false;
        ULONG testHttp11PipelineSequence = 0;

        TestHttpTransportResponse testResponse = {};
        status = STATUS_SUCCESS;
        TestHttpTransportRequest testRequest = {};
        if (useExpectContinue) {
            PopulateTestHttpTransportRequest(
                request,
                *session,
                pooledConnection,
                reusedConnection,
                reinterpret_cast<const char*>(workspace.Request.Data),
                headerBytesLength,
                headerBytesLength,
                bodyBytesLength,
                true,
                false,
                &testRequest,
                http2CleartextMode,
                useHttp2Cleartext);
            status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);

            USHORT firstStatusCode = 0;
            const bool receivedContinue =
                NT_SUCCESS(status) &&
                TryReadRawResponseStatusCode(
                    testResponse.RawResponse,
                    testResponse.RawResponseLength,
                    &firstStatusCode) &&
                firstStatusCode == 100;

            if (status == STATUS_IO_TIMEOUT || receivedContinue) {
                if (request.BodySourceCallback != nullptr) {
                    status = SimulateHttp1RequestBodySourceForTest(request, workspace, &bodyBytesLength);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                testResponse = {};
                PopulateTestHttpTransportRequest(
                    request,
                    *session,
                    pooledConnection,
                    reusedConnection,
                    reinterpret_cast<const char*>(workspace.Request.Data + headerBytesLength),
                    bodyBytesLength,
                    headerBytesLength,
                    bodyBytesLength,
                    true,
                    true,
                    &testRequest,
                    http2CleartextMode,
                    useHttp2Cleartext);
                status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);
            }
        }
        else {
            if (request.BodySourceCallback != nullptr) {
                status = SimulateHttp1RequestBodySourceForTest(request, workspace, &bodyBytesLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            const bool canUseTestHttp11Pipeline =
                allowHttp11Pipeline &&
                pooledConnection != nullptr &&
                !useHttp2Cleartext &&
                !h2ExplicitlyRequestedForTest;
            if (canUseTestHttp11Pipeline) {
                if (!ConnectionPoolHasHttp1PipelineLease(pooledConnection)) {
                    status = ConnectionPoolPromoteHttp1PipelineLease(
                        &session->ConnectionPool,
                        pooledConnection,
                        http11PipelineMaxDepth);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }

                status = ConnectionPoolBeginHttp1PipelineSend(
                    &session->ConnectionPool,
                    pooledConnection,
                    &testHttp11PipelineSequence);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                testHttp11PipelineLease = true;
                if (usedHttp11Pipeline != nullptr) {
                    *usedHttp11Pipeline = true;
                }
            }
            PopulateTestHttpTransportRequest(
                request,
                *session,
                pooledConnection,
                reusedConnection,
                reinterpret_cast<const char*>(workspace.Request.Data),
                builtRequestLength,
                headerBytesLength,
                bodyBytesLength,
                false,
                false,
                &testRequest,
                http2CleartextMode,
                useHttp2Cleartext,
                allowHttp11Pipeline,
                testHttp11PipelineLease,
                testHttp11PipelineSequence);
            status = g_testHttpTransport(g_testHttpTransportContext, &testRequest, &testResponse);
            if (testHttp11PipelineLease) {
                ConnectionPoolEndHttp1PipelineSend(pooledConnection);
            }
        }
        if (!NT_SUCCESS(status)) {
            if (testHttp11PipelineLease) {
                ConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
            }
            return status;
        }

        if (useHttp2Cleartext) {
            if (testHttp11PipelineLease) {
                ConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_NOT_SUPPORTED);
                return STATUS_NOT_SUPPORTED;
            }
            parsed->MajorVersion = 2;
            parsed->MinorVersion = 0;
            parsed->StatusCode = 200;
            workspace.ResponseLength = 0;
            *rawResponseLength = 0;
            *connectionReusable = false;
            return STATUS_SUCCESS;
        }

        if (TextEqualsLiteral(testResponse.NegotiatedAlpn, testResponse.NegotiatedAlpnLength, "h2")) {
            if (testHttp11PipelineLease) {
                ConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_NOT_SUPPORTED);
                return STATUS_NOT_SUPPORTED;
            }
            if (useExpectContinue) {
                return STATUS_NOT_SUPPORTED;
            }
            parsed->MajorVersion = 2;
            parsed->MinorVersion = 0;
            parsed->StatusCode = 200;
            workspace.ResponseLength = 0;
            *rawResponseLength = 0;
            *connectionReusable = false;
            return STATUS_SUCCESS;
        }

        if (request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "h2") &&
            !TextEqualsLiteral(testResponse.NegotiatedAlpn, testResponse.NegotiatedAlpnLength, "h2")) {
            return STATUS_NOT_SUPPORTED;
        }

        if (testResponse.RawResponse == nullptr || testResponse.RawResponseLength == 0) {
            if (testHttp11PipelineLease) {
                ConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_INVALID_NETWORK_RESPONSE);
            }
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (testHttp11PipelineLease) {
            status = ConnectionPoolWaitHttp1PipelineReceiveTurn(
                &session->ConnectionPool,
                pooledConnection,
                testHttp11PipelineSequence);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = WorkspaceEnsureResponseCapacity(&workspace, testResponse.RawResponseLength);
        if (!NT_SUCCESS(status)) {
            if (testHttp11PipelineLease) {
                ConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
            }
            return status;
        }

        RtlCopyMemory(workspace.Response.Data, testResponse.RawResponse, testResponse.RawResponseLength);
        workspace.ResponseLength = testResponse.RawResponseLength;

        status = ParseResponseBytes(
            workspace,
            workspace.ResponseLength,
            !testResponse.ConnectionReusable,
            &acceptPolicy,
            sendOptions.ContentCodingMaterials,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity);
        if (!NT_SUCCESS(status)) {
            if (testHttp11PipelineLease) {
                ConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
            }
            return status;
        }

        if (testHttp11PipelineLease) {
            status = PreserveHttp1PipelineTrailingBytes(
                &session->ConnectionPool,
                pooledConnection,
                workspace,
                *parsed,
                rawResponseLength);
            if (!NT_SUCCESS(status)) {
                ConnectionPoolFailHttp1Pipeline(&session->ConnectionPool, pooledConnection, status);
                return status;
            }

            *connectionReusable =
                testResponse.ConnectionReusable &&
                IsHttpConnectionReusable(*parsed, *rawResponseLength) &&
                parsed->MajorVersion == 1 &&
                parsed->MinorVersion == 1;
            if (*connectionReusable) {
                ConnectionPoolCompleteHttp1PipelineReceive(
                    &session->ConnectionPool,
                    pooledConnection,
                    testHttp11PipelineSequence);
            }
            else {
                ConnectionPoolFailHttp1Pipeline(
                    &session->ConnectionPool,
                    pooledConnection,
                    STATUS_CONNECTION_DISCONNECTED);
            }
        }
        else {
            *rawResponseLength = workspace.ResponseLength;
            *connectionReusable =
                testResponse.ConnectionReusable &&
                IsHttpConnectionReusable(*parsed, *rawResponseLength);
        }
        return STATUS_SUCCESS;
#else
        UNREFERENCED_PARAMETER(reusedConnection);

        if (pooledConnection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsHttpsRequest(request)) {
            if (request.Tls.CertificatePolicy == CertificatePolicy::Verify &&
                request.Tls.CertificateStore == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        else if (!TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "http")) {
            return STATUS_NOT_SUPPORTED;
        }

        const bool useExpectContinue = RequestUsesExpectContinue(sendOptions, request);
        Http2CleartextMode http2CleartextMode = Http2CleartextMode::Disabled;
        status = EffectiveHttp2CleartextMode(
            sendOptions,
            request,
            &http2CleartextMode);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool useHttp2Cleartext =
            http2CleartextMode != Http2CleartextMode::Disabled;
        if (useHttp2Cleartext && session->Options.Proxy.Enabled) {
            return STATUS_NOT_SUPPORTED;
        }
        if (useHttp2Cleartext && useExpectContinue) {
            return STATUS_NOT_SUPPORTED;
        }
        if (http2CleartextMode == Http2CleartextMode::Upgrade &&
            (request.HasBody || request.BodySourceCallback != nullptr || request.TrailerCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = EnsureSocketConnected(session, request, *pooledConnection, cancellationOperation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        tls::TlsConnection* tlsConnection = nullptr;
        if (IsHttpsRequest(request)) {
            status = EnsureTlsConnected(
                session,
                request,
                workspace,
                *pooledConnection,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                cancellationOperation);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            tlsConnection = pooledConnection->Tls;
        }

        if (tlsConnection != nullptr && IsAutomaticHttpAlpnMode(request)) {
            const char* negotiatedAlpn = tlsConnection->NegotiatedAlpn();
            const SIZE_T negotiatedAlpnLength = tlsConnection->NegotiatedAlpnLength();
            if (negotiatedAlpnLength != 0) {
                NTSTATUS keyStatus = CopyExactText(
                    negotiatedAlpn,
                    negotiatedAlpnLength,
                    pooledConnection->Key.Alpn,
                    sizeof(pooledConnection->Key.Alpn),
                    &pooledConnection->Key.AlpnLength);
                if (!NT_SUCCESS(keyStatus)) {
                    return keyStatus;
                }
            }
        }

#if !defined(WKNET_USER_MODE_TEST)
        WskCancellationScope cancellationScope(pooledConnection->RawTransport, cancellationOperation);
#else
        UNREFERENCED_PARAMETER(cancellationOperation);
#endif

        if (useHttp2Cleartext) {
            if (pooledConnection->Transport == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            if (http2CleartextMode == Http2CleartextMode::Upgrade &&
                pooledConnection->Http2 == nullptr) {
                status = SendH2cUpgradeViaTransport(
                    request,
                    workspace,
                    *pooledConnection,
                    sendOptions,
                    session->Options.Http2MaxHeaderBlockBytes,
                    requestHeaders,
                    requestHeaderCount,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    rawResponseLength);
            }
            else {
                status = SendHttp2ViaTransport(
                    request,
                    workspace,
                    sendOptions,
                    &session->ConnectionPool,
                    *pooledConnection,
                    session->Options.Http2MaxHeaderBlockBytes,
                    requestHeaders,
                    requestHeaderCount,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    rawResponseLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *connectionReusable =
                pooledConnection->Http2 != nullptr &&
                pooledConnection->Http2->IsReusable();
            return STATUS_SUCCESS;
        }

        const bool h2ExplicitlyRequested =
            request.Tls.Alpn != nullptr &&
            request.Tls.AlpnLength != 0 &&
            TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "h2");
        const bool h2Negotiated =
            tlsConnection != nullptr &&
            TextEqualsLiteral(
                tlsConnection->NegotiatedAlpn(),
                tlsConnection->NegotiatedAlpnLength(),
                "h2");

        if (h2Negotiated || h2ExplicitlyRequested) {
            if (useExpectContinue) {
                return STATUS_NOT_SUPPORTED;
            }

            if (pooledConnection->Transport == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            const char* negotiatedAlpn = tlsConnection->NegotiatedAlpn();
            const SIZE_T negotiatedAlpnLength = tlsConnection->NegotiatedAlpnLength();
            if (!TextEqualsLiteral(negotiatedAlpn, negotiatedAlpnLength, "h2")) {
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error, "High-level HTTP/2 ALPN not negotiated: %.*s\r\n",
                    static_cast<int>(negotiatedAlpnLength),
                    negotiatedAlpn != nullptr ? negotiatedAlpn : "");
                return STATUS_NOT_SUPPORTED;
            }

            status = SendHttp2ViaTransport(
                request,
                workspace,
                sendOptions,
                &session->ConnectionPool,
                *pooledConnection,
                session->Options.Http2MaxHeaderBlockBytes,
                requestHeaders,
                requestHeaderCount,
                parsed,
                responseHeaders,
                headerCapacity,
                rawResponseLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *connectionReusable =
                pooledConnection->Http2 != nullptr &&
                pooledConnection->Http2->IsReusable();
            return STATUS_SUCCESS;
        }

        if (pooledConnection->Transport == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (allowHttp11Pipeline) {
            if (!ConnectionPoolHasHttp1PipelineLease(pooledConnection)) {
                status = ConnectionPoolPromoteHttp1PipelineLease(
                    &session->ConnectionPool,
                    pooledConnection,
                    http11PipelineMaxDepth);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (usedHttp11Pipeline != nullptr) {
                *usedHttp11Pipeline = true;
            }

            return SendHttp1PipelineRequestBuffer(
                &session->ConnectionPool,
                pooledConnection,
                *pooledConnection->Transport,
                workspace,
                workspace.Request.Data,
                builtRequestLength,
                request.Method == HttpMethod::Head,
                &acceptPolicy,
                sendOptions.ContentCodingMaterials,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength,
                connectionReusable);
        }

        if (useExpectContinue) {
            if (request.BodySourceCallback != nullptr) {
                status = SendHttp1RequestSourceWithExpect(
                    *pooledConnection->Transport,
                    workspace,
                    request,
                    workspace.Request.Data,
                    builtRequestLength,
                    EffectiveExpectContinueTimeoutMilliseconds(sendOptions),
                    request.Method == HttpMethod::Head,
                    &acceptPolicy,
                    sendOptions.ContentCodingMaterials,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }
            else {
                status = SendHttp1RequestBufferWithExpect(
                    *pooledConnection->Transport,
                    workspace,
                    workspace.Request.Data,
                    builtRequestLength,
                    EffectiveExpectContinueTimeoutMilliseconds(sendOptions),
                    request.Method == HttpMethod::Head,
                    &acceptPolicy,
                    sendOptions.ContentCodingMaterials,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }
        }
        else {
            status = SendHttp1RequestBuffer(
                *pooledConnection->Transport,
                workspace.Request.Data,
                builtRequestLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (request.BodySourceCallback != nullptr) {
                status = SendHttp1RequestBodySource(
                    *pooledConnection->Transport,
                    request,
                    workspace);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            status = ReadHttpResponseFromSocket(
                *pooledConnection->Transport,
                workspace,
                request.Method == HttpMethod::Head,
                &acceptPolicy,
                sendOptions.ContentCodingMaterials,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *connectionReusable = IsHttpConnectionReusable(*parsed, *rawResponseLength);
        return STATUS_SUCCESS;
#endif
    }

