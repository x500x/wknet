    constexpr SIZE_T HttpRequestHeaderScratchBytes =
        sizeof(http1::HttpHeader) * MaxHeadersPerRequest;
    constexpr SIZE_T HttpRequestTrailerScratchBytes =
        sizeof(http1::HttpHeader) * MaxHeadersPerRequest;
    constexpr SIZE_T HttpResponseHeaderScratchBytes =
        sizeof(http1::HttpHeader) * MaxHeadersPerResponse;
    constexpr SIZE_T HttpResponseTrailerScratchBytes =
        sizeof(http1::HttpHeader) * MaxTrailersPerResponse;
    constexpr SIZE_T HttpHostHeaderScratchBytes =
        MaxHostHeaderLength;
    constexpr SIZE_T HttpRequestTargetScratchBytes =
        MaxSchemeLength + 3 + MaxHostHeaderLength + MaxPathLength;
    constexpr SIZE_T HttpHeaderScratchRequiredBytes =
        HttpRequestHeaderScratchBytes +
        HttpRequestTrailerScratchBytes +
        HttpResponseHeaderScratchBytes +
        HttpResponseTrailerScratchBytes +
        HttpHostHeaderScratchBytes +
        HttpRequestTargetScratchBytes;
    constexpr char DefaultAcceptEncodingValue[] = "gzip, deflate, br, zstd, identity";
    constexpr char DeflateUnavailableAcceptEncoding[] = "br, identity";
    constexpr SIZE_T WorkspaceCacheMaxRetainedBytes = 256 * 1024;

    constexpr SIZE_T Http2HeaderScratchBytes =
        sizeof(http1::HttpHeader) * client::Http2MaxRequestHeaders;
    constexpr SIZE_T Http2ExtraHeaderScratchBytes =
        sizeof(http1::HttpHeader) * client::Http2MaxRequestHeaders;
    constexpr SIZE_T Http2TrailerScratchBytes =
        sizeof(http1::HttpHeader) * client::Http2MaxRequestTrailers;
    constexpr SIZE_T Http2LowerHeaderScratchBytes =
        client::Http2MaxRequestHeaders * client::Http2MaxHeaderNameLength;
    constexpr SIZE_T Http2LowerTrailerScratchBytes =
        client::Http2MaxRequestTrailers * client::Http2MaxHeaderNameLength;
    constexpr SIZE_T Http2RequestScratchBytes =
        Http2HeaderScratchBytes +
        Http2ExtraHeaderScratchBytes +
        Http2TrailerScratchBytes +
        Http2LowerHeaderScratchBytes +
        Http2LowerTrailerScratchBytes +
        client::Http2ContentLengthBufferLength;

    struct ApiHttp2Scratch final
    {
        http1::HttpHeader* Headers = nullptr;
        http1::HttpHeader* ExtraHeaders = nullptr;
        http1::HttpHeader* Trailers = nullptr;
        char (*LowerHeaderNames)[client::Http2MaxHeaderNameLength] = nullptr;
        char (*LowerTrailerNames)[client::Http2MaxHeaderNameLength] = nullptr;
        char* ContentLengthBuffer = nullptr;
        char* AuthorityBuffer = nullptr;
        SIZE_T AuthorityCapacity = 0;
    };

    struct ApiHttpHeaderScratch final
    {
        http1::HttpHeader* RequestHeaders = nullptr;
        http1::HttpHeader* RequestTrailers = nullptr;
        http1::HttpHeader* ResponseHeaders = nullptr;
        http1::HttpHeader* ResponseTrailers = nullptr;
        char* HostHeader = nullptr;
        SIZE_T HostHeaderCapacity = 0;
        char* RequestTarget = nullptr;
        SIZE_T RequestTargetCapacity = 0;
    };

    struct RedirectOriginSnapshot final
    {
        char Scheme[MaxSchemeLength + 1] = {};
        char Host[MaxHostLength + 1] = {};
    };

    _Must_inspect_result_
    NTSTATUS GrowDecodedBodyAfterBufferTooSmall(_Inout_ Workspace& workspace) noexcept;

    http1::HttpText DefaultAcceptEncoding() noexcept
    {
        return http1::MakeText(
            codec::DeflateRuntimeAvailable() ?
                DefaultAcceptEncodingValue :
                DeflateUnavailableAcceptEncoding);
    }

    _Must_inspect_result_
    NTSTATUS BuildEffectiveAcceptEncoding(
        _In_ const HttpSendOptions& sendOptions,
        _Inout_ Workspace& workspace,
        _Out_ http1::HttpText* value) noexcept
    {
        if (value != nullptr) {
            *value = {};
        }
        if (value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (sendOptions.AcceptEncodingPreferenceCount == 0) {
            *value = DefaultAcceptEncoding();
            return STATUS_SUCCESS;
        }
        if (workspace.DecodedBody.Data == nullptr || workspace.DecodedBody.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return http1::HttpContentEncoding::BuildAcceptEncodingHeader(
            sendOptions.AcceptEncodingPreferences,
            sendOptions.AcceptEncodingPreferenceCount,
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            workspace.DecodedBody.Length,
            value);
    }

    _Must_inspect_result_
    NTSTATUS BuildAcceptEncodingPolicyFromRequestHeaders(
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Inout_ http1::HttpAcceptEncodingRules* rules,
        _Out_ http1::HttpAcceptEncodingPolicy* policy) noexcept
    {
        if (policy != nullptr) {
            *policy = {};
        }
        if (policy == nullptr ||
            rules == nullptr ||
            rules->Entries == nullptr ||
            (requestHeaders == nullptr && requestHeaderCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        rules->EntryCount = 0;
        rules->EmptyHeader = false;
        bool foundAcceptEncoding = false;
        for (SIZE_T index = 0; index < requestHeaderCount; ++index) {
            const http1::HttpHeader& header = requestHeaders[index];
            if (!http1::TextEqualsIgnoreCase(header.Name, http1::MakeText("Accept-Encoding"))) {
                continue;
            }

            foundAcceptEncoding = true;
            NTSTATUS status = http1::HttpContentEncoding::ParseAcceptEncoding(header.Value, rules);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (!foundAcceptEncoding) {
            return STATUS_INVALID_PARAMETER;
        }

        policy->Rules = rules;
        return STATUS_SUCCESS;
    }

    bool RequestHasHeader(_In_ const Request& request, _In_z_ const char* name) noexcept
    {
        if (name == nullptr) {
            return false;
        }
        for (SIZE_T index = 0; index < request.HeaderCount; ++index) {
            if (TextEqualsLiteralIgnoreCase(
                request.Headers[index].Name,
                request.Headers[index].NameLength,
                name)) {
                return true;
            }
        }
        return false;
    }

    void FillParsedFromCacheSnapshot(
        const HttpCacheSnapshot& snapshot,
        _Out_ http1::HttpResponse* parsed) noexcept
    {
        if (parsed == nullptr) {
            return;
        }
        *parsed = {};
        parsed->MajorVersion = 1;
        parsed->MinorVersion = 1;
        parsed->StatusCode = snapshot.StatusCode;
        parsed->Headers = snapshot.Headers;
        parsed->HeaderCount = snapshot.HeaderCount;
        parsed->Body = reinterpret_cast<const char*>(snapshot.Body);
        parsed->BodyLength = snapshot.BodyLength;
        parsed->BodyKind = http1::HttpBodyKind::ContentLength;
        parsed->BytesConsumed = snapshot.BodyLength;
    }

    _Ret_maybenull_
    Workspace* ExchangeSessionWorkspace(_In_ SessionHandle session, _In_opt_ Workspace* workspace) noexcept
    {
        if (session == nullptr) {
            return nullptr;
        }

#if defined(WKNET_USER_MODE_TEST)
        Workspace* previous = session->Workspace;
        session->Workspace = workspace;
        return previous;
#else
        return static_cast<Workspace*>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&session->Workspace),
            workspace));
#endif
    }

    _Ret_maybenull_
    Workspace* CompareExchangeSessionWorkspace(
        _In_ SessionHandle session,
        _In_opt_ Workspace* workspace,
        _In_opt_ Workspace* expected) noexcept
    {
        if (session == nullptr) {
            return nullptr;
        }

#if defined(WKNET_USER_MODE_TEST)
        Workspace* previous = session->Workspace;
        if (previous == expected) {
            session->Workspace = workspace;
        }
        return previous;
#else
        return static_cast<Workspace*>(InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&session->Workspace),
            workspace,
            expected));
#endif
    }

    SIZE_T WorkspaceRetainedBytes(_In_ const Workspace& workspace) noexcept
    {
        return workspace.Request.Length +
            workspace.Response.Length +
            workspace.DecodedBody.Length +
            workspace.HttpHeaderScratch.Length +
            workspace.Http2HeaderScratch.Length +
            workspace.TlsHandshakeScratch.Length +
            workspace.CertificateScratch.Length +
            workspace.WebSocketFrameScratch.Length +
            workspace.WebSocketSendFrameScratch.Length +
            workspace.WebSocketPayloadScratch.Length;
    }

    bool CanCacheRequestWorkspace(
        _In_ const Workspace& workspace,
        SIZE_T requestBufferBytes) noexcept
    {
        return workspace.PoolType == PoolType::NonPaged &&
            workspace.Request.Length >= requestBufferBytes &&
            WorkspaceRetainedBytes(workspace) <= WorkspaceCacheMaxRetainedBytes;
    }

    NTSTATUS AcquireRequestWorkspace(
        _In_ SessionHandle session,
        SIZE_T maxResponseBytes,
        _Outptr_ Workspace** workspace) noexcept
    {
        if (session == nullptr || workspace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *workspace = nullptr;

        Workspace* cached = ExchangeSessionWorkspace(session, nullptr);
        if (cached != nullptr) {
            if (cached->Request.Length >= session->Options.RequestBufferBytes) {
                cached->MaxResponseBytes = maxResponseBytes;
                WorkspaceReset(cached);
                *workspace = cached;
                return STATUS_SUCCESS;
            }

            WorkspaceReleaseToLookaside(cached, &session->WorkspaceLookaside);
        }

        WorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = PoolType::NonPaged;
        workspaceOptions.RequestBufferBytes = session->Options.RequestBufferBytes;
        workspaceOptions.MaxResponseBytes = maxResponseBytes;
        return WorkspaceCreateFromLookaside(
            &workspaceOptions,
            &session->WorkspaceLookaside,
            workspace);
    }

    void ReleaseRequestWorkspace(_In_ SessionHandle session, _In_opt_ Workspace* workspace) noexcept
    {
        if (workspace == nullptr) {
            return;
        }

        if (session == nullptr ||
            !CanCacheRequestWorkspace(*workspace, session->Options.RequestBufferBytes)) {
            WorkspaceReleaseToLookaside(workspace, session != nullptr ? &session->WorkspaceLookaside : nullptr);
            return;
        }

        workspace->MaxResponseBytes = session->Options.MaxResponseBytes;
        WorkspaceReset(workspace);

        if (CompareExchangeSessionWorkspace(session, workspace, nullptr) != nullptr) {
            WorkspaceReleaseToLookaside(workspace, &session->WorkspaceLookaside);
        }
    }

    class WorkspaceGuard final
    {
    public:
        WorkspaceGuard() noexcept = default;

        ~WorkspaceGuard() noexcept
        {
            Reset();
        }

        WorkspaceGuard(const WorkspaceGuard&) = delete;
        WorkspaceGuard& operator=(const WorkspaceGuard&) = delete;

        _Must_inspect_result_
        NTSTATUS Create(SIZE_T maxResponseBytes, SIZE_T requestBufferBytes) noexcept
        {
            Reset();

            WorkspaceOptions workspaceOptions = {};
            workspaceOptions.PoolType = PoolType::NonPaged;
            workspaceOptions.RequestBufferBytes = requestBufferBytes;
            workspaceOptions.MaxResponseBytes = maxResponseBytes;
            return WorkspaceCreate(&workspaceOptions, &workspace_);
        }

        _Must_inspect_result_
        NTSTATUS CreateForSession(_In_ SessionHandle session, SIZE_T maxResponseBytes) noexcept
        {
            Reset();
            session_ = session;
            return AcquireRequestWorkspace(session, maxResponseBytes, &workspace_);
        }

        void Reset() noexcept
        {
            if (session_ != nullptr) {
                ReleaseRequestWorkspace(session_, workspace_);
            }
            else {
                WorkspaceRelease(workspace_);
            }
            workspace_ = nullptr;
            session_ = nullptr;
        }

        _Ret_maybenull_
        Workspace* Get() noexcept
        {
            return workspace_;
        }

        _Must_inspect_result_
        bool IsValid() const noexcept
        {
            return workspace_ != nullptr;
        }

    private:
        SessionHandle session_ = nullptr;
        Workspace* workspace_ = nullptr;
    };

    _Must_inspect_result_
    NTSTATUS PrepareApiHttpHeaderScratch(
        _Inout_ Workspace& workspace,
        _Out_ ApiHttpHeaderScratch* scratch) noexcept
    {
        if (scratch == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *scratch = {};
        if (workspace.HttpHeaderScratch.Data == nullptr ||
            workspace.HttpHeaderScratch.Length < HttpHeaderScratchRequiredBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(workspace.HttpHeaderScratch.Data, workspace.HttpHeaderScratch.Length);
        scratch->RequestHeaders = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data);
        scratch->RequestTrailers = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data + HttpRequestHeaderScratchBytes);
        scratch->ResponseHeaders = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes);
        scratch->ResponseTrailers = reinterpret_cast<http1::HttpHeader*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes +
            HttpResponseHeaderScratchBytes);
        scratch->HostHeader = reinterpret_cast<char*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes +
            HttpResponseHeaderScratchBytes +
            HttpResponseTrailerScratchBytes);
        scratch->HostHeaderCapacity = HttpHostHeaderScratchBytes;
        scratch->RequestTarget = reinterpret_cast<char*>(
            workspace.HttpHeaderScratch.Data +
            HttpRequestHeaderScratchBytes +
            HttpRequestTrailerScratchBytes +
            HttpResponseHeaderScratchBytes +
            HttpResponseTrailerScratchBytes +
            HttpHostHeaderScratchBytes);
        scratch->RequestTargetCapacity = HttpRequestTargetScratchBytes;
        return STATUS_SUCCESS;
    }

#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS PrepareApiHttp2Scratch(
        _Inout_ Workspace& workspace,
        _Out_ ApiHttp2Scratch* scratch) noexcept
    {
        if (scratch == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *scratch = {};
        if (workspace.Http2HeaderScratch.Data == nullptr ||
            workspace.Http2HeaderScratch.Length < Http2RequestScratchBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(workspace.Http2HeaderScratch.Data, workspace.Http2HeaderScratch.Length);
        scratch->Headers = reinterpret_cast<http1::HttpHeader*>(workspace.Http2HeaderScratch.Data);
        scratch->ExtraHeaders = reinterpret_cast<http1::HttpHeader*>(
            workspace.Http2HeaderScratch.Data + Http2HeaderScratchBytes);
        scratch->Trailers = reinterpret_cast<http1::HttpHeader*>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes);
        scratch->LowerHeaderNames = reinterpret_cast<char (*)[client::Http2MaxHeaderNameLength]>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes +
            Http2TrailerScratchBytes);
        scratch->LowerTrailerNames = reinterpret_cast<char (*)[client::Http2MaxHeaderNameLength]>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes +
            Http2TrailerScratchBytes +
            Http2LowerHeaderScratchBytes);
        scratch->ContentLengthBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data +
            Http2HeaderScratchBytes +
            Http2ExtraHeaderScratchBytes +
            Http2TrailerScratchBytes +
            Http2LowerHeaderScratchBytes +
            Http2LowerTrailerScratchBytes);
        scratch->AuthorityBuffer = reinterpret_cast<char*>(
            workspace.Http2HeaderScratch.Data + Http2RequestScratchBytes);
        scratch->AuthorityCapacity = workspace.Http2HeaderScratch.Length - Http2RequestScratchBytes;
        return STATUS_SUCCESS;
    }

    bool LowercaseHttp2HeaderName(
        http1::HttpText name,
        _Out_writes_(capacity) char* output,
        SIZE_T capacity,
        _Out_ http1::HttpText* lowered) noexcept
    {
        if (lowered != nullptr) {
            *lowered = {};
        }
        if (name.Data == nullptr ||
            name.Length == 0 ||
            name.Length > client::Http2MaxHeaderNameLength ||
            output == nullptr ||
            lowered == nullptr ||
            name.Length > capacity ||
            name.Data[0] == ':') {
            return false;
        }

        for (SIZE_T index = 0; index < name.Length; ++index) {
            const UCHAR value = static_cast<UCHAR>(name.Data[index]);
            if (value <= 0x20 || value >= 0x7f || value == ':') {
                return false;
            }

            char loweredValue = name.Data[index];
            if (loweredValue >= 'A' && loweredValue <= 'Z') {
                loweredValue = static_cast<char>(loweredValue + 32);
            }
            output[index] = loweredValue;
        }

        lowered->Data = output;
        lowered->Length = name.Length;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS BuildHttp2TrailersFromRequest(
        const Request& request,
        _Out_writes_(trailerCapacity) http1::HttpHeader* trailers,
        SIZE_T trailerCapacity,
        char lowerTrailerNames[client::Http2MaxRequestTrailers][client::Http2MaxHeaderNameLength],
        _Out_ SIZE_T* trailerCount) noexcept
    {
        if (trailerCount != nullptr) {
            *trailerCount = 0;
        }
        if (trailerCount == nullptr ||
            (request.TrailerCount != 0 && (trailers == nullptr || lowerTrailerNames == nullptr)) ||
            request.TrailerCount > trailerCapacity ||
            request.TrailerCount > client::Http2MaxRequestTrailers) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
            const StoredHeader& trailer = request.Trailers[index];
            http1::HttpText loweredName = {};
            if (!LowercaseHttp2HeaderName(
                { trailer.Name, trailer.NameLength },
                lowerTrailerNames[index],
                client::Http2MaxHeaderNameLength,
                &loweredName) ||
                (trailer.Value == nullptr && trailer.ValueLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            trailers[index].Name = loweredName;
            trailers[index].Value = { trailer.Value, trailer.ValueLength };
        }

        *trailerCount = request.TrailerCount;
        return STATUS_SUCCESS;
    }
#endif

    http1::HttpMethod ToHttpMethod(HttpMethod method) noexcept
    {
        switch (method) {
        case HttpMethod::Post:
            return http1::HttpMethod::Post;
        case HttpMethod::Put:
            return http1::HttpMethod::Put;
        case HttpMethod::Patch:
            return http1::HttpMethod::Patch;
        case HttpMethod::Delete:
            return http1::HttpMethod::DeleteMethod;
        case HttpMethod::Head:
            return http1::HttpMethod::Head;
        case HttpMethod::Options:
            return http1::HttpMethod::Options;
        case HttpMethod::Connect:
            return http1::HttpMethod::Connect;
        case HttpMethod::Trace:
            return http1::HttpMethod::Trace;
        case HttpMethod::Get:
        default:
            return http1::HttpMethod::Get;
        }
    }

    _Must_inspect_result_
    NTSTATUS BuildHostHeaderValue(
        const Request& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (destination == nullptr ||
            destinationCapacity == 0 ||
            destinationLength == nullptr ||
            request.HostLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool ipv6Literal = TextContainsChar(request.Host, request.HostLength, ':');
        const SIZE_T bracketBytes = ipv6Literal ? 2 : 0;
        if (request.HostLength + bracketBytes >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T length = 0;
        if (ipv6Literal) {
            destination[length++] = '[';
        }
        RtlCopyMemory(destination + length, request.Host, request.HostLength);
        length += request.HostLength;
        if (ipv6Literal) {
            destination[length++] = ']';
        }

        if (!IsDefaultPort(request.Scheme, request.SchemeLength, request.Port)) {
            if (length + 1 >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[length++] = ':';

            SIZE_T divisor = 1;
            while ((request.Port / divisor) >= 10) {
                divisor *= 10;
            }

            SIZE_T digitCount = 0;
            for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
                ++digitCount;
            }

            if (length + digitCount >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
                destination[length++] = static_cast<char>('0' + ((request.Port / currentDivisor) % 10));
            }
        }

        destination[length] = '\0';
        *destinationLength = length;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BuildProxyAbsoluteFormTarget(
        const Request& request,
        http1::HttpText hostHeader,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (destination == nullptr ||
            destinationCapacity == 0 ||
            destinationLength == nullptr ||
            request.SchemeLength == 0 ||
            hostHeader.Data == nullptr ||
            hostHeader.Length == 0 ||
            request.Path == nullptr ||
            request.PathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        constexpr SIZE_T schemeSeparatorLength = 3;
        const SIZE_T required =
            request.SchemeLength +
            schemeSeparatorLength +
            hostHeader.Length +
            request.PathLength;
        if (required >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T length = 0;
        RtlCopyMemory(destination + length, request.Scheme, request.SchemeLength);
        length += request.SchemeLength;
        RtlCopyMemory(destination + length, "://", schemeSeparatorLength);
        length += schemeSeparatorLength;
        RtlCopyMemory(destination + length, hostHeader.Data, hostHeader.Length);
        length += hostHeader.Length;
        RtlCopyMemory(destination + length, request.Path, request.PathLength);
        length += request.PathLength;
        destination[length] = '\0';
        *destinationLength = length;
        return STATUS_SUCCESS;
    }

    bool HeaderNameEquals(const StoredHeader& header, const char* name) noexcept
    {
        return TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, name);
    }

    bool IsSupportedHttpAlpn(const char* alpn, SIZE_T alpnLength) noexcept
    {
        return TextEqualsLiteral(alpn, alpnLength, "h2") ||
            TextEqualsLiteral(alpn, alpnLength, "http/1.1");
    }

    bool IsHttpsRequest(const Request& request) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https");
    }

    bool IsPlainHttpRequest(const Request& request) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "http");
    }

    bool IsAutomaticHttpAlpnMode(const Request& request) noexcept
    {
        return IsHttpsRequest(request) &&
            request.Tls.PreferHttp2 &&
            request.Tls.Alpn == nullptr &&
            request.Tls.AlpnLength == 0;
    }

    NTSTATUS EffectiveHttp2CleartextMode(
        _In_ const HttpSendOptions& options,
        _In_ const Request& request,
        _Out_ Http2CleartextMode* mode) noexcept
    {
        if (mode == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *mode = Http2CleartextMode::Disabled;
        if (options.Http2CleartextMode == Http2CleartextMode::Disabled) {
            return STATUS_SUCCESS;
        }

        if (!IsPlainHttpRequest(request)) {
            return STATUS_NOT_SUPPORTED;
        }

        *mode = options.Http2CleartextMode;
        return STATUS_SUCCESS;
    }

    void RefreshResponseParseDecodedBuffers(
        _In_ const Workspace& workspace,
        _Inout_ http1::HttpParseOptions& parseOptions) noexcept
    {
        parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
    }

    bool IsTlsVersionAllowed(
        TlsVersion minimum,
        TlsVersion maximum,
        TlsVersion protocol) noexcept
    {
        return static_cast<USHORT>(minimum) <= static_cast<USHORT>(protocol) &&
            static_cast<USHORT>(protocol) <= static_cast<USHORT>(maximum);
    }

    bool IsHttpTls12ConfirmationCandidate(
        const Request& request,
        const tls::TlsHandshakeFailure& failure) noexcept
    {
        const bool failureCanConfirmTls12 =
            failure.Category == tls::TlsHandshakeFailureCategory::VersionNegotiation ||
            (failure.Category == tls::TlsHandshakeFailureCategory::NetworkIo &&
                failure.BeforeTls13FirstServerHello &&
                failure.Status != STATUS_IO_TIMEOUT);
        return IsTlsVersionAllowed(request.Tls.MinVersion, request.Tls.MaxVersion, TlsVersion::Tls12) &&
            IsTlsVersionAllowed(request.Tls.MinVersion, request.Tls.MaxVersion, TlsVersion::Tls13) &&
            failureCanConfirmTls12;
    }

    bool IsSafeFreshConnectionRetryMethod(HttpMethod method) noexcept
    {
        return method == HttpMethod::Get ||
            method == HttpMethod::Head ||
            method == HttpMethod::Options;
    }

    bool IsTraceSensitiveHeader(const StoredHeader& header) noexcept
    {
        return HeaderNameEquals(header, "Authorization") ||
            HeaderNameEquals(header, "Proxy-Authorization") ||
            HeaderNameEquals(header, "Cookie");
    }

    bool IsFreshConnectionRetryStatus(NTSTATUS status) noexcept
    {
        return IsConnectionCloseStatus(status) ||
            status == STATUS_RETRY ||
            status == STATUS_IO_TIMEOUT;
    }

    bool ShouldRetryWithFreshConnection(
        _In_ const Request& request,
        NTSTATUS status,
        bool reusedConnection) noexcept
    {
        return !NT_SUCCESS(status) &&
            request.ConnectionPolicy == ConnectionPolicy::ReuseOrCreate &&
            IsSafeFreshConnectionRetryMethod(request.Method) &&
            (status == STATUS_RETRY ||
                (reusedConnection && IsFreshConnectionRetryStatus(status)));
    }

    bool RequestUsesExpectContinue(
        _In_ const HttpSendOptions& options,
        _In_ const Request& request) noexcept;

    ULONG Http11PipelineMethodBit(HttpMethod method) noexcept
    {
        switch (method) {
        case HttpMethod::Get:
            return Http11PipelineMethodGet;
        case HttpMethod::Post:
            return Http11PipelineMethodPost;
        case HttpMethod::Put:
            return Http11PipelineMethodPut;
        case HttpMethod::Patch:
            return Http11PipelineMethodPatch;
        case HttpMethod::Delete:
            return Http11PipelineMethodDelete;
        case HttpMethod::Head:
            return Http11PipelineMethodHead;
        case HttpMethod::Options:
            return Http11PipelineMethodOptions;
        case HttpMethod::Connect:
            return Http11PipelineMethodConnect;
        case HttpMethod::Trace:
            return Http11PipelineMethodTrace;
        default:
            return 0;
        }
    }

    bool IsHttp11PipelineTlsModeEligible(_In_ const Request& request) noexcept
    {
        if (!IsHttpsRequest(request)) {
            return true;
        }

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            return TextEqualsLiteral(request.Tls.Alpn, request.Tls.AlpnLength, "http/1.1");
        }

        return !request.Tls.PreferHttp2;
    }

    bool IsHttp11PipelineCandidate(
        _In_ const Session& session,
        _In_ const Request& request,
        _In_ const HttpSendOptions& options,
        Http2CleartextMode http2CleartextMode) noexcept
    {
        if (!session.Options.EnableHttp11Pipeline ||
            request.ConnectionPolicy != ConnectionPolicy::ReuseOrCreate ||
            http2CleartextMode != Http2CleartextMode::Disabled ||
            RequestUsesExpectContinue(options, request) ||
            !IsHttp11PipelineTlsModeEligible(request) ||
            request.HasBody ||
            request.BodyLength != 0 ||
            request.BodySourceCallback != nullptr ||
            request.TrailerCount != 0) {
            return false;
        }

        const ULONG methodBit = Http11PipelineMethodBit(request.Method);
        return methodBit != 0 && (session.Options.Http11PipelineMethodMask & methodBit) != 0;
    }

    bool RequestUsesExpectContinue(
        _In_ const HttpSendOptions& options,
        _In_ const Request& request) noexcept
    {
        return ((options.Flags & HttpSendFlagExpectContinue) != 0) && request.HasBody;
    }

    ULONG EffectiveExpectContinueTimeoutMilliseconds(
        _In_ const HttpSendOptions& options) noexcept
    {
        return options.ExpectContinueTimeoutMilliseconds != 0 ?
            options.ExpectContinueTimeoutMilliseconds :
            DefaultExpectContinueTimeoutMilliseconds;
    }

    bool TryReadRawResponseStatusCode(
        _In_reads_bytes_(rawResponseLength) const char* rawResponse,
        SIZE_T rawResponseLength,
        _Out_ USHORT* statusCode) noexcept
    {
        if (statusCode != nullptr) {
            *statusCode = 0;
        }
        if (rawResponse == nullptr || statusCode == nullptr || rawResponseLength < 12) {
            return false;
        }

        SIZE_T cursor = 0;
        while (cursor < rawResponseLength &&
            rawResponse[cursor] != ' ' &&
            rawResponse[cursor] != '\r' &&
            rawResponse[cursor] != '\n') {
            ++cursor;
        }

        if (cursor >= rawResponseLength || rawResponse[cursor] != ' ') {
            return false;
        }
        ++cursor;

        if (cursor + 3 > rawResponseLength) {
            return false;
        }

        USHORT parsed = 0;
        for (SIZE_T index = 0; index < 3; ++index) {
            const char value = rawResponse[cursor + index];
            if (value < '0' || value > '9') {
                return false;
            }
            parsed = static_cast<USHORT>((parsed * 10) + static_cast<USHORT>(value - '0'));
        }

        *statusCode = parsed;
        return true;
    }

    _Must_inspect_result_
