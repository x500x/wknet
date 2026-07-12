    SIZE_T LiteralLength(_In_z_ const char* text) noexcept
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

    char HttpRedirectToLowerAscii(char value) noexcept
    {
        return value >= 'A' && value <= 'Z' ?
            static_cast<char>(value - 'A' + 'a') :
            value;
    }

    bool StartsWithLiteralIgnoreCase(
        const char* value,
        SIZE_T valueLength,
        _In_z_ const char* literal) noexcept
    {
        const SIZE_T literalLength = LiteralLength(literal);
        if (value == nullptr || literal == nullptr || literalLength > valueLength) {
            return false;
        }

        for (SIZE_T index = 0; index < literalLength; ++index) {
            if (HttpRedirectToLowerAscii(value[index]) != HttpRedirectToLowerAscii(literal[index])) {
                return false;
            }
        }
        return true;
    }

    bool IsRedirectStatus(USHORT statusCode) noexcept
    {
        return statusCode == 301 ||
            statusCode == 302 ||
            statusCode == 303 ||
            statusCode == 307 ||
            statusCode == 308;
    }

    bool ShouldRewriteRedirectToGet(USHORT statusCode, HttpMethod method) noexcept
    {
        if (statusCode == 303) {
            return method != HttpMethod::Head;
        }

        if (statusCode != 301 && statusCode != 302) {
            return false;
        }

        return method == HttpMethod::Post;
    }

#if !defined(WKNET_USER_MODE_TEST)
    static bool IsHttpAsyncCancellationRequested(_In_opt_ void* context) noexcept
    {
        return context != nullptr &&
            AsyncOperationIsCanceled(static_cast<AsyncOperationHandle>(context));
    }
#endif

    bool RedirectsEnabled(const HttpSendOptions& options) noexcept
    {
        return (options.Flags & HttpSendFlagDisableAutoRedirect) == 0;
    }

    ULONG EffectiveMaxRedirects(const HttpSendOptions& options) noexcept
    {
        return options.MaxRedirects != 0 ? options.MaxRedirects : DefaultMaxRedirects;
    }

    http1::HttpText FindLocationHeader(const http1::HttpResponse& response) noexcept
    {
        const http1::HttpHeader* header = nullptr;
        if (response.FindHeader(http1::MakeText("Location"), &header) && header != nullptr) {
            return header->Value;
        }

        return {};
    }

    bool IsAbsoluteHttpLocation(http1::HttpText location) noexcept
    {
        return StartsWithLiteralIgnoreCase(location.Data, location.Length, "http://") ||
            StartsWithLiteralIgnoreCase(location.Data, location.Length, "https://");
    }

    http1::HttpText TrimRedirectLocation(http1::HttpText location) noexcept
    {
        while (location.Length != 0 &&
            (location.Data[0] == ' ' || location.Data[0] == '\t')) {
            ++location.Data;
            --location.Length;
        }

        while (location.Length != 0 &&
            (location.Data[location.Length - 1] == ' ' ||
                location.Data[location.Length - 1] == '\t')) {
            --location.Length;
        }
        return location;
    }

    bool IsUriSchemeChar(char value, bool first) noexcept
    {
        if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')) {
            return true;
        }
        if (first) {
            return false;
        }
        return (value >= '0' && value <= '9') ||
            value == '+' ||
            value == '-' ||
            value == '.';
    }

    bool HasUriScheme(http1::HttpText location) noexcept
    {
        if (location.Data == nullptr || location.Length == 0) {
            return false;
        }

        for (SIZE_T index = 0; index < location.Length; ++index) {
            const char value = location.Data[index];
            if (value == ':' && index != 0) {
                for (SIZE_T schemeIndex = 0; schemeIndex < index; ++schemeIndex) {
                    if (!IsUriSchemeChar(location.Data[schemeIndex], schemeIndex == 0)) {
                        return false;
                    }
                }
                return true;
            }
            if (value == '/' || value == '?' || value == '#') {
                return false;
            }
        }
        return false;
    }

    bool IsSchemeRelativeLocation(http1::HttpText location) noexcept
    {
        return location.Data != nullptr &&
            location.Length >= 2 &&
            location.Data[0] == '/' &&
            location.Data[1] == '/';
    }

    bool IsPathAbsoluteLocation(http1::HttpText location) noexcept
    {
        return location.Data != nullptr &&
            location.Length >= 1 &&
            location.Data[0] == '/';
    }

    _Must_inspect_result_
    NTSTATUS AppendRedirectText(
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* offset,
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength) noexcept
    {
        if (destination == nullptr ||
            offset == nullptr ||
            (text == nullptr && textLength != 0) ||
            *offset > destinationCapacity ||
            textLength > destinationCapacity - *offset) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (textLength != 0) {
            RtlCopyMemory(destination + *offset, text, textLength);
            *offset += textLength;
        }
        return STATUS_SUCCESS;
    }

    void RemovePreviousRedirectPathSegment(
        _Inout_updates_(*pathLength) char* path,
        _Inout_ SIZE_T* pathLength) noexcept
    {
        if (path == nullptr || pathLength == nullptr || *pathLength == 0) {
            return;
        }

        SIZE_T end = *pathLength;
        if (end > 1 && path[end - 1] == '/') {
            --end;
        }

        while (end > 0 && path[end - 1] != '/') {
            --end;
        }

        *pathLength = end == 0 ? 0 : end;
        if (*pathLength == 0) {
            path[(*pathLength)++] = '/';
        }
    }

    void RemoveRedirectDotSegments(
        _Inout_updates_(*pathLength) char* path,
        _Inout_ SIZE_T* pathLength) noexcept
    {
        if (path == nullptr || pathLength == nullptr || *pathLength == 0) {
            return;
        }

        const SIZE_T inputLength = *pathLength;
        SIZE_T read = 0;
        SIZE_T write = 0;
        while (read < inputLength) {
            if (path[read] == '/') {
                path[write++] = path[read++];
                continue;
            }

            const SIZE_T segmentStart = read;
            while (read < inputLength && path[read] != '/') {
                ++read;
            }
            const SIZE_T segmentLength = read - segmentStart;

            if (segmentLength == 1 && path[segmentStart] == '.') {
                if (read < inputLength && path[read] == '/') {
                    ++read;
                }
                continue;
            }

            if (segmentLength == 2 &&
                path[segmentStart] == '.' &&
                path[segmentStart + 1] == '.') {
                RemovePreviousRedirectPathSegment(path, &write);
                if (read < inputLength && path[read] == '/') {
                    ++read;
                }
                continue;
            }

            if (write != segmentStart) {
                RtlMoveMemory(path + write, path + segmentStart, segmentLength);
            }
            write += segmentLength;
        }

        if (write == 0) {
            path[write++] = '/';
        }
        *pathLength = write;
    }

    SIZE_T FindRedirectChar(
        _In_reads_bytes_opt_(textLength) const char* text,
        SIZE_T textLength,
        char needle) noexcept
    {
        if (text == nullptr) {
            return textLength;
        }
        for (SIZE_T index = 0; index < textLength; ++index) {
            if (text[index] == needle) {
                return index;
            }
        }
        return textLength;
    }

    http1::HttpText BaseRequestFragment(const Request& request) noexcept
    {
        if (request.Url == nullptr || request.UrlLength == 0) {
            return {};
        }

        const SIZE_T fragment = FindRedirectChar(request.Url, request.UrlLength, '#');
        if (fragment == request.UrlLength) {
            return {};
        }
        return { request.Url + fragment, request.UrlLength - fragment };
    }

    _Must_inspect_result_
    NTSTATUS AppendRedirectOrigin(
        const Request& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* offset) noexcept
    {
        NTSTATUS status = AppendRedirectText(
            destination,
            destinationCapacity,
            offset,
            request.Scheme,
            request.SchemeLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendRedirectText(destination, destinationCapacity, offset, "://", 3);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T authorityLength = 0;
        status = BuildHostHeaderValue(
            request,
            destination + *offset,
            destinationCapacity - *offset,
            &authorityLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        *offset += authorityLength;
        return STATUS_SUCCESS;
    }

    void SplitRedirectReference(
        http1::HttpText location,
        _Out_ http1::HttpText* path,
        _Out_ http1::HttpText* query,
        _Out_ http1::HttpText* fragment,
        _Out_ bool* hasQuery,
        _Out_ bool* hasFragment) noexcept
    {
        if (path != nullptr) {
            *path = {};
        }
        if (query != nullptr) {
            *query = {};
        }
        if (fragment != nullptr) {
            *fragment = {};
        }
        if (hasQuery != nullptr) {
            *hasQuery = false;
        }
        if (hasFragment != nullptr) {
            *hasFragment = false;
        }

        if (location.Data == nullptr) {
            return;
        }

        const SIZE_T fragmentIndex = FindRedirectChar(location.Data, location.Length, '#');
        const SIZE_T queryIndex = FindRedirectChar(location.Data, fragmentIndex, '?');
        if (path != nullptr) {
            *path = { location.Data, queryIndex };
        }
        if (queryIndex < fragmentIndex) {
            if (hasQuery != nullptr) {
                *hasQuery = true;
            }
            if (query != nullptr) {
                *query = { location.Data + queryIndex, fragmentIndex - queryIndex };
            }
        }
        if (fragmentIndex < location.Length) {
            if (hasFragment != nullptr) {
                *hasFragment = true;
            }
            if (fragment != nullptr) {
                *fragment = { location.Data + fragmentIndex, location.Length - fragmentIndex };
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS AppendRedirectPathAndSuffix(
        const Request& request,
        http1::HttpText location,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* offset) noexcept
    {
        http1::HttpText referencePath = {};
        http1::HttpText referenceQuery = {};
        http1::HttpText referenceFragment = {};
        bool hasReferenceQuery = false;
        bool hasReferenceFragment = false;
        SplitRedirectReference(
            location,
            &referencePath,
            &referenceQuery,
            &referenceFragment,
            &hasReferenceQuery,
            &hasReferenceFragment);

        const SIZE_T baseQueryIndex = FindRedirectChar(request.Path, request.PathLength, '?');
        const http1::HttpText basePath = { request.Path, baseQueryIndex };
        const http1::HttpText baseQuery =
            baseQueryIndex < request.PathLength ?
            http1::HttpText{ request.Path + baseQueryIndex, request.PathLength - baseQueryIndex } :
            http1::HttpText{};

        const SIZE_T pathStartOffset = *offset;
        NTSTATUS status = STATUS_SUCCESS;
        if (referencePath.Length == 0) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                basePath.Data,
                basePath.Length);
        }
        else if (referencePath.Data[0] == '/') {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                referencePath.Data,
                referencePath.Length);
        }
        else {
            SIZE_T baseDirectoryLength = basePath.Length;
            while (baseDirectoryLength != 0 && basePath.Data[baseDirectoryLength - 1] != '/') {
                --baseDirectoryLength;
            }
            if (baseDirectoryLength == 0) {
                status = AppendRedirectText(destination, destinationCapacity, offset, "/", 1);
            }
            else {
                status = AppendRedirectText(
                    destination,
                    destinationCapacity,
                    offset,
                    basePath.Data,
                    baseDirectoryLength);
            }
            if (NT_SUCCESS(status)) {
                status = AppendRedirectText(
                    destination,
                    destinationCapacity,
                    offset,
                    referencePath.Data,
                    referencePath.Length);
            }
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T normalizedPathLength = *offset - pathStartOffset;
        RemoveRedirectDotSegments(destination + pathStartOffset, &normalizedPathLength);
        *offset = pathStartOffset + normalizedPathLength;

        if (hasReferenceQuery) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                referenceQuery.Data,
                referenceQuery.Length);
        }
        else if (referencePath.Length == 0 && baseQuery.Data != nullptr) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                baseQuery.Data,
                baseQuery.Length);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const http1::HttpText fragmentToAppend =
            hasReferenceFragment ? referenceFragment : BaseRequestFragment(request);
        if (fragmentToAppend.Data != nullptr && fragmentToAppend.Length != 0) {
            status = AppendRedirectText(
                destination,
                destinationCapacity,
                offset,
                fragmentToAppend.Data,
                fragmentToAppend.Length);
        }
        return status;
    }

    void ReleaseStoredRedirectHeader(_Inout_ StoredHeader& header) noexcept
    {
        FreeApiMemory(header.Name);
        FreeApiMemory(header.Value);
        header = {};
    }

    void RemoveRedirectSensitiveHeaders(_Inout_ Request& request) noexcept
    {
        SIZE_T index = 0;
        while (index < request.HeaderCount) {
            const StoredHeader& header = request.Headers[index];
            const bool sensitive =
                TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, "Authorization") ||
                TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, "Cookie") ||
                TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, "Proxy-Authorization");
            if (!sensitive) {
                ++index;
                continue;
            }

            ReleaseStoredRedirectHeader(request.Headers[index]);
            for (SIZE_T moveIndex = index + 1; moveIndex < request.HeaderCount; ++moveIndex) {
                request.Headers[moveIndex - 1] = request.Headers[moveIndex];
            }
            --request.HeaderCount;
            request.Headers[request.HeaderCount] = {};
        }
    }

    bool IsCrossOriginRedirect(
        const char* oldScheme,
        SIZE_T oldSchemeLength,
        const char* oldHost,
        SIZE_T oldHostLength,
        USHORT oldPort,
        const Request& redirected) noexcept
    {
        return oldPort != redirected.Port ||
            !TextEqualsIgnoreCase(oldScheme, oldSchemeLength, redirected.Scheme, redirected.SchemeLength) ||
            !TextEqualsIgnoreCase(oldHost, oldHostLength, redirected.Host, redirected.HostLength);
    }

    bool IsHttpsDowngradeRedirect(
        const Request& request,
        http1::HttpText redirectUrl) noexcept
    {
        return TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https") &&
            StartsWithLiteralIgnoreCase(redirectUrl.Data, redirectUrl.Length, "http://");
    }

    _Must_inspect_result_
    NTSTATUS BuildRedirectUrl(
        const Request& request,
        http1::HttpText location,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        location = TrimRedirectLocation(location);
        if (location.Data == nullptr ||
            location.Length == 0 ||
            destination == nullptr ||
            destinationLength == nullptr ||
            request.SchemeLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (IsAbsoluteHttpLocation(location)) {
            SIZE_T offset = 0;
            NTSTATUS status = AppendRedirectText(
                destination,
                destinationCapacity,
                &offset,
                location.Data,
                location.Length);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (FindRedirectChar(location.Data, location.Length, '#') == location.Length) {
                const http1::HttpText baseFragment = BaseRequestFragment(request);
                if (baseFragment.Data != nullptr && baseFragment.Length != 0) {
                    status = AppendRedirectText(
                        destination,
                        destinationCapacity,
                        &offset,
                        baseFragment.Data,
                        baseFragment.Length);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }

            *destinationLength = offset;
            return STATUS_SUCCESS;
        }

        if (HasUriScheme(location)) {
            return STATUS_NOT_SUPPORTED;
        }

        SIZE_T offset = 0;
        if (IsSchemeRelativeLocation(location)) {
            NTSTATUS status = AppendRedirectText(
                destination,
                destinationCapacity,
                &offset,
                request.Scheme,
                request.SchemeLength);
            if (NT_SUCCESS(status)) {
                status = AppendRedirectText(destination, destinationCapacity, &offset, ":", 1);
            }
            if (NT_SUCCESS(status)) {
                status = AppendRedirectText(
                    destination,
                    destinationCapacity,
                    &offset,
                    location.Data,
                    location.Length);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            *destinationLength = offset;
            return STATUS_SUCCESS;
        }

        NTSTATUS status = AppendRedirectOrigin(request, destination, destinationCapacity, &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendRedirectPathAndSuffix(
            request,
            location,
            destination,
            destinationCapacity,
            &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        *destinationLength = offset;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ApplyRedirectToRequest(
        _Inout_ Request& request,
        USHORT statusCode,
        http1::HttpText location,
        _Inout_ Workspace& workspace) noexcept
    {
        HeapObject<RedirectOriginSnapshot> oldOrigin;
        if (!oldOrigin.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        const SIZE_T oldSchemeLength = request.SchemeLength;
        const SIZE_T oldHostLength = request.HostLength;
        const USHORT oldPort = request.Port;
        const bool hadTlsOverride = request.HasTlsOverride;
        const bool tlsServerNameMatchedOldHost =
            request.Tls.ServerName == nullptr ||
            TextEqualsIgnoreCase(
                request.Tls.ServerName,
                request.Tls.ServerNameLength,
                request.Host,
                request.HostLength);
        RtlCopyMemory(oldOrigin->Scheme, request.Scheme, sizeof(oldOrigin->Scheme));
        RtlCopyMemory(oldOrigin->Host, request.Host, sizeof(oldOrigin->Host));

        SIZE_T redirectUrlLength = 0;
        NTSTATUS status = BuildRedirectUrl(
            request,
            location,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            &redirectUrlLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const char* redirectUrl = reinterpret_cast<const char*>(workspace.Request.Data);

        if (IsHttpsDowngradeRedirect(request, { redirectUrl, redirectUrlLength })) {
            return STATUS_NOT_SUPPORTED;
        }

        status = HttpRequestSetUrl(&request, redirectUrl, redirectUrlLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (IsCrossOriginRedirect(
            oldOrigin->Scheme,
            oldSchemeLength,
            oldOrigin->Host,
            oldHostLength,
            oldPort,
            request)) {
            if (hadTlsOverride && !tlsServerNameMatchedOldHost) {
                return STATUS_NOT_SUPPORTED;
            }
            if (TextEqualsLiteralIgnoreCase(request.Scheme, request.SchemeLength, "https")) {
                FreeApiMemory(request.OwnedTlsServerName);
                request.OwnedTlsServerName = nullptr;
                request.Tls.ServerName = request.Host;
                request.Tls.ServerNameLength = request.HostLength;
            }
            RemoveRedirectSensitiveHeaders(request);
        }

        if (ShouldRewriteRedirectToGet(statusCode, request.Method)) {
            status = HttpRequestSetMethod(&request, HttpMethod::Get);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = HttpRequestClearBody(&request);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
