#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS BuildHttp2OptionsFromRequest(
        const Request& request,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        http1::HttpText authority,
        _Out_writes_(extraHeaderCapacity) http1::HttpHeader* extraHeaders,
        SIZE_T extraHeaderCapacity,
        _In_opt_ const http2::Http2RequestBodySource* bodySource,
        _Out_writes_(trailerCapacity) http1::HttpHeader* trailers,
        SIZE_T trailerCapacity,
        char lowerTrailerNames[client::Http2MaxRequestTrailers][client::Http2MaxHeaderNameLength],
        _Out_ client::Http2RequestOptions* options) noexcept
    {
        if (requestHeaders == nullptr || extraHeaders == nullptr || options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (authority.Data == nullptr || authority.Length == 0 || request.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request.BodySourceCallback != nullptr && bodySource == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *options = {};
        options->TransportMode = client::Http2TransportMode::TlsAlpn;
        options->ServerName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        options->ServerNameLength = request.Tls.ServerName != nullptr ?
            request.Tls.ServerNameLength :
            request.HostLength;
        options->Method = ToHttpMethod(request.Method);
        options->Path = { request.Path, request.PathLength };
        options->Authority = authority;
        options->Body = request.BodySourceCallback == nullptr ? request.Body : nullptr;
        options->BodyLength = request.BodySourceCallback == nullptr ? request.BodyLength : 0;
        options->BodySource = bodySource;
        options->IncludeContentLength =
            request.HasBody &&
            request.BodyMode == RequestBodyMode::ContentLength;
        options->CertificateStore = request.Tls.CertificateStore;
        options->VerifyCertificate = request.Tls.CertificatePolicy == CertificatePolicy::Verify;
        options->Policy = request.Tls.Policy;
        options->ClientCredential = request.Tls.ClientCredential;
        options->MaxTls12Renegotiations = request.Tls.MaxTls12Renegotiations;

        SIZE_T extraHeaderCount = 0;
        for (SIZE_T index = 0; index < requestHeaderCount; ++index) {
            const http1::HttpHeader& header = requestHeaders[index];
            if (http1::TextEqualsIgnoreCase(header.Name, http1::MakeText("Host"))) {
                continue;
            }
            if (http1::TextEqualsIgnoreCase(header.Name, http1::MakeText("User-Agent"))) {
                options->UserAgent = header.Value;
                continue;
            }
            if (http1::TextEqualsIgnoreCase(header.Name, http1::MakeText("Content-Type"))) {
                options->ContentType = header.Value;
                continue;
            }
            if (http1::TextEqualsIgnoreCase(header.Name, http1::MakeText("Accept-Encoding"))) {
                options->AcceptEncoding = header.Value;
                continue;
            }
            if (extraHeaderCount >= extraHeaderCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            extraHeaders[extraHeaderCount++] = header;
        }

        options->ExtraHeaders = extraHeaders;
        options->ExtraHeaderCount = extraHeaderCount;
        SIZE_T trailerCount = 0;
        NTSTATUS status = BuildHttp2TrailersFromRequest(
            request,
            trailers,
            trailerCapacity,
            lowerTrailerNames,
            &trailerCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        options->Trailers = trailerCount != 0 ? trailers : nullptr;
        options->TrailerCount = trailerCount;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS AppendHttp2ResponseBodyToWorkspace(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        auto* workspace = static_cast<Workspace*>(context);
        if (workspace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        return WorkspaceAppendResponse(workspace, data, dataLength);
    }

    _Must_inspect_result_
    NTSTATUS DecodeContentWithWorkspace(
        _In_reads_(responseHeaderCount) const http1::HttpHeader* responseHeaders,
        SIZE_T responseHeaderCount,
        _In_reads_bytes_(responseBodyLength) const char* responseBody,
        SIZE_T responseBodyLength,
        _Inout_ Workspace& workspace,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpContentDecodeResult* decoded) noexcept
    {
        if (decoded == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *decoded = {};

        for (;;) {
            http1::HttpContentDecodeBuffers decodeBuffers = {};
            decodeBuffers.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
            decodeBuffers.DecodedBodyCapacity = workspace.DecodedBody.Length;
            decodeBuffers.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
            decodeBuffers.ScratchBodyCapacity = workspace.Request.Length;
            decodeBuffers.Materials = materials;

            NTSTATUS status = http1::HttpContentEncoding::Decode(
                responseHeaders,
                responseHeaderCount,
                responseBody,
                responseBodyLength,
                decodeBuffers,
                *decoded,
                acceptPolicy);
            if (status != STATUS_BUFFER_TOO_SMALL) {
                if (NT_SUCCESS(status) &&
                    workspace.MaxResponseBytes != 0 &&
                    decoded->BodyLength > workspace.MaxResponseBytes) {
                    *decoded = {};
                    return STATUS_BUFFER_TOO_SMALL;
                }
                return status;
            }

            status = GrowDecodedBodyAfterBufferTooSmall(workspace);
            if (!NT_SUCCESS(status)) {
                *decoded = {};
                return status;
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS SendHttp2ViaTransport(
        const Request& request,
        Workspace& workspace,
        _In_ const HttpSendOptions& sendOptions,
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection& pooledConnection,
        SIZE_T maxHeaderBlockBytes,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr ||
            connectionPool == nullptr ||
            responseHeaders == nullptr ||
            rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *parsed = {};
        *rawResponseLength = 0;
        workspace.ResponseLength = 0;

        ApiHttp2Scratch h2Scratch = {};
        NTSTATUS status = PrepareApiHttp2Scratch(workspace, &h2Scratch);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T authorityLength = 0;
        status = BuildHostHeaderValue(
            request,
            h2Scratch.AuthorityBuffer,
            h2Scratch.AuthorityCapacity,
            &authorityLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http2::Http2RequestBodySource h2BodySource = {};
        const http2::Http2RequestBodySource* h2BodySourcePtr = nullptr;
        if (request.BodySourceCallback != nullptr) {
            h2BodySource.Read = request.BodySourceCallback;
            h2BodySource.Context = request.BodySourceContext;
            h2BodySource.ContentLength = request.BodySourceContentLength;
            h2BodySource.ContentLengthKnown = request.BodySourceContentLengthKnown;
            h2BodySourcePtr = &h2BodySource;
        }

        client::Http2RequestOptions h2Options = {};
        status = BuildHttp2OptionsFromRequest(
            request,
            requestHeaders,
            requestHeaderCount,
            { h2Scratch.AuthorityBuffer, authorityLength },
            h2Scratch.ExtraHeaders,
            client::Http2MaxRequestHeaders,
            h2BodySourcePtr,
            h2Scratch.Trailers,
            client::Http2MaxRequestTrailers,
            h2Scratch.LowerTrailerNames,
            &h2Options);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        h2Options.Priority = sendOptions.Http2Priority;

        SIZE_T h2HeaderCount = 0;
        status = client::BuildHttp2RequestHeaders(
            h2Options,
            h2Scratch.Headers,
            client::Http2MaxRequestHeaders,
            h2Scratch.LowerHeaderNames,
            h2Scratch.ContentLengthBuffer,
            &h2HeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (pooledConnection.Transport == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (pooledConnection.Http2 == nullptr) {
            auto* h2Connection = AllocateNonPagedObject<http2::Http2Connection>();
            if (h2Connection == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = h2Connection->Initialize(*pooledConnection.Transport, maxHeaderBlockBytes);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "High-level HTTP/2 init failed: 0x%08X\r\n", static_cast<ULONG>(status));
                FreeNonPagedObject(h2Connection);
                return status;
            }
            status = PooledConnectionAdoptHttp2(&pooledConnection, h2Connection);
            if (!NT_SUCCESS(status)) {
                FreeNonPagedObject(h2Connection);
                return status;
            }
        }

        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        http2::Http2ResponseBodySink responseBodySink = {};
        responseBodySink.Append = AppendHttp2ResponseBodyToWorkspace;
        responseBodySink.Context = &workspace;

        const bool h2LeaseAlreadyHeld =
            ConnectionPoolHasHttp2StreamLease(&pooledConnection);
        ULONG streamId = 0;
        http2::Http2RequestBody requestBody = {};
        requestBody.Data = h2Options.Body;
        requestBody.DataLength = h2Options.BodyLength;
        requestBody.Source = h2Options.BodySource;
        requestBody.Trailers = h2Options.Trailers;
        requestBody.TrailerCount = h2Options.TrailerCount;
        requestBody.Priority = h2Options.Priority;
        requestBody.HasBody =
            request.HasBody ||
            h2Options.BodySource != nullptr ||
            h2Options.TrailerCount != 0 ||
            (h2Options.Body != nullptr && h2Options.BodyLength != 0);
        status = pooledConnection.Http2->BeginRequest(
            *pooledConnection.Transport,
            h2Scratch.Headers,
            h2HeaderCount,
            requestBody,
            responseHeaders,
            headerCapacity,
            &responseHeaderCount,
            responseBodySink,
            &responseBodyLength,
            &statusCode,
            reinterpret_cast<char*>(workspace.Http2HeaderScratch.Data),
            workspace.Http2HeaderScratch.Length,
            &streamId);

        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "High-level HTTP/2 request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (!h2LeaseAlreadyHeld) {
            status = ConnectionPoolPromoteHttp2StreamLease(
                connectionPool,
                &pooledConnection,
                pooledConnection.Http2->MaxConcurrentStreams());
            if (!NT_SUCCESS(status)) {
                pooledConnection.Http2->ReleaseStream(streamId);
                return status;
            }
        }

        status = pooledConnection.Http2->ReceiveResponse(
            *pooledConnection.Transport,
            streamId);
        if (!NT_SUCCESS(status)) {
            pooledConnection.Http2->ReleaseStream(streamId);
            if (status == STATUS_BUFFER_TOO_SMALL && workspace.MaxResponseBytes != 0) {
                WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Verbose,
                    "High-level HTTP/2 response reached MaxResponseBytes limit: status=0x%08X MaxResponseBytes=%Iu\r\n",
                    static_cast<ULONG>(status),
                    workspace.MaxResponseBytes);
            }
            else {
                WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "High-level HTTP/2 response failed: 0x%08X\r\n", static_cast<ULONG>(status));
            }
            return status;
        }

        HeapArray<http1::HttpAcceptEncodingEntry> acceptEncodingEntries(http1::HttpMaxAcceptEncodingEntries);
        if (!acceptEncodingEntries.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        http1::HttpAcceptEncodingRules acceptEncodingRules = {};
        acceptEncodingRules.Entries = acceptEncodingEntries.Get();
        acceptEncodingRules.EntryCapacity = acceptEncodingEntries.Count();
        http1::HttpAcceptEncodingPolicy acceptPolicy = {};
        status = BuildAcceptEncodingPolicyFromRequestHeaders(
            requestHeaders,
            requestHeaderCount,
            &acceptEncodingRules,
            &acceptPolicy);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http1::HttpContentDecodeResult decoded = {};
        status = DecodeContentWithWorkspace(
            responseHeaders,
            responseHeaderCount,
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseBodyLength,
            workspace,
            &acceptPolicy,
            sendOptions.ContentCodingMaterials,
            &decoded);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "High-level HTTP/2 content decode failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        parsed->MajorVersion = 2;
        parsed->MinorVersion = 0;
        parsed->StatusCode = statusCode;
        parsed->Headers = responseHeaders;
        parsed->HeaderCount = responseHeaderCount;
        parsed->Body = decoded.Body;
        parsed->BodyLength = decoded.BodyLength;
        parsed->BytesConsumed = responseBodyLength;
        parsed->BodyKind = http1::HttpBodyKind::ContentLength;
        workspace.ResponseLength = responseBodyLength;
        *rawResponseLength = responseBodyLength;
        return STATUS_SUCCESS;
    }

    class H2cReplayTransport final : public core::ITransport
    {
    public:
        H2cReplayTransport() noexcept = default;

        NTSTATUS Initialize(
            _Inout_ core::ITransport* inner,
            _In_reads_bytes_opt_(replayLength) const UCHAR* replayBytes,
            SIZE_T replayLength) noexcept
        {
            if (inner == nullptr || (replayBytes == nullptr && replayLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            inner_ = inner;
            replayBytes_ = replayBytes;
            replayLength_ = replayLength;
            replayOffset_ = 0;
            return STATUS_SUCCESS;
        }

        NTSTATUS Send(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept override
        {
            if (inner_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return inner_->Send(data, length, bytesSent);
        }

        NTSTATUS Receive(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept override
        {
            NTSTATUS status = ReceiveReplay(buffer, length, bytesReceived);
            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }
            if (inner_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return inner_->Receive(buffer, length, bytesReceived);
        }

        NTSTATUS ReceiveWithTimeout(
            void* buffer,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept override
        {
            NTSTATUS status = ReceiveReplay(buffer, length, bytesReceived);
            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }
            if (inner_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
            return inner_->ReceiveWithTimeout(buffer, length, bytesReceived, timeoutMilliseconds);
        }

    private:
        NTSTATUS ReceiveReplay(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
        {
            if (bytesReceived != nullptr) {
                *bytesReceived = 0;
            }
            if (replayOffset_ >= replayLength_) {
                return STATUS_MORE_PROCESSING_REQUIRED;
            }
            if (buffer == nullptr || length == 0 || replayBytes_ == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T available = replayLength_ - replayOffset_;
            SIZE_T toCopy = length < available ? length : available;
            RtlCopyMemory(buffer, replayBytes_ + replayOffset_, toCopy);
            replayOffset_ += toCopy;
            if (bytesReceived != nullptr) {
                *bytesReceived = toCopy;
            }
            return STATUS_SUCCESS;
        }

        core::ITransport* inner_ = nullptr;
        const UCHAR* replayBytes_ = nullptr;
        SIZE_T replayLength_ = 0;
        SIZE_T replayOffset_ = 0;
    };

    SIZE_T H2cLiteralLength(_In_z_ const char* text) noexcept
    {
        SIZE_T length = 0;
        if (text == nullptr) {
            return 0;
        }
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    http1::HttpText HttpMethodText(HttpMethod method) noexcept
    {
        switch (method) {
        case HttpMethod::Post:
            return http1::MakeText("POST");
        case HttpMethod::Put:
            return http1::MakeText("PUT");
        case HttpMethod::Patch:
            return http1::MakeText("PATCH");
        case HttpMethod::Delete:
            return http1::MakeText("DELETE");
        case HttpMethod::Head:
            return http1::MakeText("HEAD");
        case HttpMethod::Options:
            return http1::MakeText("OPTIONS");
        case HttpMethod::Connect:
            return http1::MakeText("CONNECT");
        case HttpMethod::Trace:
            return http1::MakeText("TRACE");
        case HttpMethod::Get:
        default:
            return http1::MakeText("GET");
        }
    }

    NTSTATUS AppendH2cText(
        _Out_writes_bytes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset,
        http1::HttpText text) noexcept
    {
        if (output == nullptr ||
            offset == nullptr ||
            *offset > capacity ||
            (text.Data == nullptr && text.Length != 0) ||
            text.Length > capacity - *offset) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (text.Length != 0) {
            RtlCopyMemory(output + *offset, text.Data, text.Length);
            *offset += text.Length;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS AppendH2cLiteral(
        _Out_writes_bytes_(capacity) char* output,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset,
        _In_z_ const char* literal) noexcept
    {
        return AppendH2cText(output, capacity, offset, { literal, H2cLiteralLength(literal) });
    }

    bool IsH2cUpgradeControlledHeader(http1::HttpText name) noexcept
    {
        return http1::TextEqualsIgnoreCase(name, http1::MakeText("Connection")) ||
            http1::TextEqualsIgnoreCase(name, http1::MakeText("Upgrade")) ||
            http1::TextEqualsIgnoreCase(name, http1::MakeText("HTTP2-Settings")) ||
            http1::TextEqualsIgnoreCase(name, http1::MakeText("Host")) ||
            http1::TextEqualsIgnoreCase(name, http1::MakeText("Content-Length")) ||
            http1::TextEqualsIgnoreCase(name, http1::MakeText("Transfer-Encoding"));
    }

    _Must_inspect_result_
    NTSTATUS BuildH2cUpgradeRequest(
        const Request& request,
        http1::HttpText authority,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_writes_bytes_(outputCapacity) char* output,
        SIZE_T outputCapacity,
        _Out_ SIZE_T* outputLength) noexcept
    {
        if (outputLength != nullptr) {
            *outputLength = 0;
        }
        if (authority.Data == nullptr ||
            authority.Length == 0 ||
            request.Path == nullptr ||
            request.PathLength == 0 ||
            (requestHeaders == nullptr && requestHeaderCount != 0) ||
            output == nullptr ||
            outputLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> settingsValue(128);
        if (!settingsValue.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        http2::Http2Settings settings = {};
        http1::HttpText settingsText = {};
        NTSTATUS status = http2::Http2FrameCodec::EncodeSettingsPayloadBase64Url(
            settings,
            settingsValue.Get(),
            settingsValue.Count(),
            &settingsText.Length);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        settingsText.Data = settingsValue.Get();

        SIZE_T offset = 0;
        status = AppendH2cText(output, outputCapacity, &offset, HttpMethodText(request.Method));
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, " ");
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cText(output, outputCapacity, &offset, { request.Path, request.PathLength });
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, " HTTP/1.1\r\nHost: ");
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cText(output, outputCapacity, &offset, authority);
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, "\r\n");
        if (!NT_SUCCESS(status)) return status;

        for (SIZE_T index = 0; index < requestHeaderCount; ++index) {
            const http1::HttpHeader& header = requestHeaders[index];
            if (header.Name.Data == nullptr ||
                header.Name.Length == 0 ||
                (header.Value.Data == nullptr && header.Value.Length != 0) ||
                IsH2cUpgradeControlledHeader(header.Name)) {
                return STATUS_INVALID_PARAMETER;
            }

            status = AppendH2cText(output, outputCapacity, &offset, header.Name);
            if (!NT_SUCCESS(status)) return status;
            status = AppendH2cLiteral(output, outputCapacity, &offset, ": ");
            if (!NT_SUCCESS(status)) return status;
            status = AppendH2cText(output, outputCapacity, &offset, header.Value);
            if (!NT_SUCCESS(status)) return status;
            status = AppendH2cLiteral(output, outputCapacity, &offset, "\r\n");
            if (!NT_SUCCESS(status)) return status;
        }

        status = AppendH2cLiteral(
            output,
            outputCapacity,
            &offset,
            "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: ");
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cText(output, outputCapacity, &offset, settingsText);
        if (!NT_SUCCESS(status)) return status;
        status = AppendH2cLiteral(output, outputCapacity, &offset, "\r\n\r\n");
        if (!NT_SUCCESS(status)) return status;

        *outputLength = offset;
        return STATUS_SUCCESS;
    }

    SIZE_T FindH2cHeaderEnd(_In_reads_bytes_(length) const UCHAR* data, SIZE_T length) noexcept
    {
        if (data == nullptr || length < 4) {
            return static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        }
        for (SIZE_T index = 0; index <= length - 4; ++index) {
            if (data[index] == '\r' &&
                data[index + 1] == '\n' &&
                data[index + 2] == '\r' &&
                data[index + 3] == '\n') {
                return index + 4;
            }
        }
        return static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
    }

    bool H2cHeaderBlockHasToken(
        _In_reads_bytes_(length) const char* data,
        SIZE_T length,
        http1::HttpText headerName,
        http1::HttpText token) noexcept
    {
        if (data == nullptr) {
            return false;
        }

        SIZE_T lineStart = 0;
        while (lineStart + 1 < length) {
            SIZE_T lineEnd = lineStart;
            while (lineEnd + 1 < length &&
                !(data[lineEnd] == '\r' && data[lineEnd + 1] == '\n')) {
                ++lineEnd;
            }

            SIZE_T colon = lineStart;
            while (colon < lineEnd && data[colon] != ':') {
                ++colon;
            }
            if (colon < lineEnd) {
                http1::HttpText name = { data + lineStart, colon - lineStart };
                http1::HttpText value = { data + colon + 1, lineEnd - colon - 1 };
                if (http1::TextEqualsIgnoreCase(name, headerName) &&
                    http1::HeaderValueHasToken(value, token)) {
                    return true;
                }
            }

            if (lineEnd + 1 >= length) {
                break;
            }
            lineStart = lineEnd + 2;
        }

        return false;
    }

    _Must_inspect_result_
    NTSTATUS ValidateH2cUpgradeResponse(
        _In_reads_bytes_(headerLength) const char* data,
        SIZE_T headerLength) noexcept
    {
        if (data == nullptr || headerLength < 12) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (data[0] != 'H' || data[1] != 'T' || data[2] != 'T' || data[3] != 'P' || data[4] != '/') {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T cursor = 5;
        while (cursor < headerLength && data[cursor] != ' ') {
            ++cursor;
        }
        if (cursor + 4 >= headerLength || data[cursor] != ' ') {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (data[cursor + 1] != '1' || data[cursor + 2] != '0' || data[cursor + 3] != '1') {
            return STATUS_NOT_SUPPORTED;
        }

        if (!H2cHeaderBlockHasToken(
                data,
                headerLength,
                http1::MakeText("Upgrade"),
                http1::MakeText("h2c")) ||
            !H2cHeaderBlockHasToken(
                data,
                headerLength,
                http1::MakeText("Connection"),
                http1::MakeText("Upgrade"))) {
            return STATUS_NOT_SUPPORTED;
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadH2cUpgradeResponse(
        _Inout_ core::ITransport& transport,
        _Inout_ Workspace& workspace,
        _Inout_ HeapArray<UCHAR>& replayBytes,
        _Out_ SIZE_T* replayLength) noexcept
    {
        if (replayLength != nullptr) {
            *replayLength = 0;
        }
        if (workspace.Response.Data == nullptr ||
            workspace.Response.Length == 0 ||
            replayLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        workspace.ResponseLength = 0;
        for (;;) {
            const SIZE_T headerEnd = FindH2cHeaderEnd(workspace.Response.Data, workspace.ResponseLength);
            if (headerEnd != static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                NTSTATUS status = ValidateH2cUpgradeResponse(
                    reinterpret_cast<const char*>(workspace.Response.Data),
                    headerEnd);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                const SIZE_T extraLength = workspace.ResponseLength - headerEnd;
                if (extraLength != 0) {
                    status = replayBytes.Allocate(extraLength);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    RtlCopyMemory(replayBytes.Get(), workspace.Response.Data + headerEnd, extraLength);
                }

                *replayLength = extraLength;
                workspace.ResponseLength = 0;
                return STATUS_SUCCESS;
            }

            if (workspace.ResponseLength == workspace.Response.Length) {
                NTSTATUS status = WorkspaceEnsureResponseCapacity(&workspace, workspace.ResponseLength + 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            SIZE_T received = 0;
            NTSTATUS status = transport.Receive(
                workspace.Response.Data + workspace.ResponseLength,
                workspace.Response.Length - workspace.ResponseLength,
                &received);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (received == 0) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
            workspace.ResponseLength += received;
        }
    }

    _Must_inspect_result_
    NTSTATUS SendH2cUpgradeViaTransport(
        const Request& request,
        Workspace& workspace,
        _Inout_ PooledConnection& pooledConnection,
        _In_ const HttpSendOptions& sendOptions,
        SIZE_T maxHeaderBlockBytes,
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr || responseHeaders == nullptr || rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (request.HasBody ||
            request.BodyLength != 0 ||
            request.BodySourceCallback != nullptr ||
            request.TrailerCount != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (pooledConnection.Transport == nullptr || pooledConnection.Http2 != nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        *parsed = {};
        *rawResponseLength = 0;
        workspace.ResponseLength = 0;

        ApiHttp2Scratch h2Scratch = {};
        NTSTATUS status = PrepareApiHttp2Scratch(workspace, &h2Scratch);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T authorityLength = 0;
        status = BuildHostHeaderValue(
            request,
            h2Scratch.AuthorityBuffer,
            h2Scratch.AuthorityCapacity,
            &authorityLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T upgradeRequestLength = 0;
        status = BuildH2cUpgradeRequest(
            request,
            { h2Scratch.AuthorityBuffer, authorityLength },
            requestHeaders,
            requestHeaderCount,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            &upgradeRequestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T sent = 0;
        status = pooledConnection.Transport->Send(
            workspace.Request.Data,
            upgradeRequestLength,
            &sent);
        if (NT_SUCCESS(status) && sent != upgradeRequestLength) {
            return STATUS_CONNECTION_DISCONNECTED;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> replayBytes;
        SIZE_T replayLength = 0;
        status = ReadH2cUpgradeResponse(
            *pooledConnection.Transport,
            workspace,
            replayBytes,
            &replayLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* h2Connection = AllocateNonPagedObject<http2::Http2Connection>();
        if (h2Connection == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        HeapObject<H2cReplayTransport> replayTransport;
        if (!replayTransport.IsValid()) {
            FreeNonPagedObject(h2Connection);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        core::ITransport* activeTransport = pooledConnection.Transport;
        if (replayLength != 0) {
            status = replayTransport->Initialize(
                pooledConnection.Transport,
                replayBytes.Get(),
                replayLength);
            if (!NT_SUCCESS(status)) {
                FreeNonPagedObject(h2Connection);
                return status;
            }
            activeTransport = replayTransport.Get();
        }

        status = h2Connection->InitializeAfterUpgrade(*activeTransport, maxHeaderBlockBytes);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "High-level h2c Upgrade init failed: 0x%08X\r\n", static_cast<ULONG>(status));
            FreeNonPagedObject(h2Connection);
            return status;
        }
        status = PooledConnectionAdoptHttp2(&pooledConnection, h2Connection);
        if (!NT_SUCCESS(status)) {
            FreeNonPagedObject(h2Connection);
            return status;
        }

        SIZE_T responseHeaderCount = 0;
        SIZE_T responseBodyLength = 0;
        USHORT statusCode = 0;
        http2::Http2ResponseBodySink responseBodySink = {};
        responseBodySink.Append = AppendHttp2ResponseBodyToWorkspace;
        responseBodySink.Context = &workspace;

        status = pooledConnection.Http2->ReceiveResponse(
            *activeTransport,
            1,
            responseHeaders,
            headerCapacity,
            &responseHeaderCount,
            responseBodySink,
            &responseBodyLength,
            &statusCode,
            reinterpret_cast<char*>(workspace.Http2HeaderScratch.Data),
            workspace.Http2HeaderScratch.Length);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "High-level h2c Upgrade stream 1 failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapArray<http1::HttpAcceptEncodingEntry> acceptEncodingEntries(http1::HttpMaxAcceptEncodingEntries);
        if (!acceptEncodingEntries.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        http1::HttpAcceptEncodingRules acceptEncodingRules = {};
        acceptEncodingRules.Entries = acceptEncodingEntries.Get();
        acceptEncodingRules.EntryCapacity = acceptEncodingEntries.Count();
        http1::HttpAcceptEncodingPolicy acceptPolicy = {};
        status = BuildAcceptEncodingPolicyFromRequestHeaders(
            requestHeaders,
            requestHeaderCount,
            &acceptEncodingRules,
            &acceptPolicy);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http1::HttpContentDecodeResult decoded = {};
        status = DecodeContentWithWorkspace(
            responseHeaders,
            responseHeaderCount,
            reinterpret_cast<const char*>(workspace.Response.Data),
            responseBodyLength,
            workspace,
            &acceptPolicy,
            sendOptions.ContentCodingMaterials,
            &decoded);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentHttp2, ::wknet::TraceLevel::Error, "High-level h2c Upgrade content decode failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        parsed->MajorVersion = 2;
        parsed->MinorVersion = 0;
        parsed->StatusCode = statusCode;
        parsed->Headers = responseHeaders;
        parsed->HeaderCount = responseHeaderCount;
        parsed->Body = decoded.Body;
        parsed->BodyLength = decoded.BodyLength;
        parsed->BytesConsumed = responseBodyLength;
        parsed->BodyKind = http1::HttpBodyKind::ContentLength;
        workspace.ResponseLength = responseBodyLength;
        *rawResponseLength = responseBodyLength;
        return STATUS_SUCCESS;
    }
#endif

