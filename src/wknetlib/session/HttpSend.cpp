#include "session/HttpEngineInternal.hpp"
#include "rtl/TraceInternal.h"

namespace wknet
{
namespace session
{
    _Must_inspect_result_
    NTSTATUS SendSingleHttpRequest(
        SessionHandle session,
        const Request& request,
        const HttpSendOptions& sendOptions,
        _Inout_ Workspace& workspace,
        _Inout_ ApiHttpHeaderScratch& headerScratch,
        _Out_ http1::HttpResponse* parsed,
        _Out_ SIZE_T* rawResponseLength,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
    {
        if (parsed != nullptr) {
            *parsed = {};
        }
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (session == nullptr || parsed == nullptr || rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        WorkspaceReset(&workspace);

        NTSTATUS status = PrepareApiHttpHeaderScratch(workspace, &headerScratch);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T builtRequestLength = 0;
        SIZE_T requestHeaderCount = 0;
        const bool useExpectContinue = RequestUsesExpectContinue(sendOptions, request);
        const bool allowTrace = (sendOptions.Flags & HttpSendFlagAllowTrace) != 0;
        const bool useProxyAbsoluteForm = session->Options.Proxy.Enabled && !IsHttpsRequest(request);
        status = BuildRequestBytes(
            request,
            useExpectContinue,
            allowTrace,
            useProxyAbsoluteForm,
            session->Options.Proxy,
            workspace,
            sendOptions,
            headerScratch.HostHeader,
            headerScratch.HostHeaderCapacity,
            headerScratch.RequestTarget,
            headerScratch.RequestTargetCapacity,
            headerScratch.RequestHeaders,
            MaxHeadersPerRequest,
            headerScratch.RequestTrailers,
            MaxHeadersPerRequest,
            &builtRequestLength,
            &requestHeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapObject<ConnectionPoolKey> poolKey;
        if (!poolKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Http2CleartextMode http2CleartextMode = Http2CleartextMode::Disabled;
        status = EffectiveHttp2CleartextMode(sendOptions, request, &http2CleartextMode);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildPoolKey(request, session->Options.Proxy, http2CleartextMode, poolKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool allowHttp11Pipeline =
            IsHttp11PipelineCandidate(*session, request, sendOptions, http2CleartextMode);
        PooledConnection* pooledConnection = nullptr;
        bool reusedConnection = false;
        if (allowHttp11Pipeline) {
            status = ConnectionPoolAcquireHttp1Pipeline(
                &session->ConnectionPool,
                *poolKey.Get(),
                request.ConnectionPolicy,
                session->Options.Http11PipelineMaxDepth,
                &pooledConnection,
                &reusedConnection);
        }
        else {
            status = ConnectionPoolAcquire(
                &session->ConnectionPool,
                *poolKey.Get(),
                request.ConnectionPolicy,
                &pooledConnection,
                &reusedConnection);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const TraceCorrelation connectionCorrelation = {
            sendOptions.TraceOperationId,
            PooledConnectionId(pooledConnection),
            0
        };
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentSession,
            ::wknet::TraceLevel::Verbose,
            &connectionCorrelation,
            "pool.connection.acquire reused=%u pipeline=%u",
            reusedConnection ? 1u : 0u,
            allowHttp11Pipeline ? 1u : 0u);

        bool connectionReusable = false;
        bool usedHttp11Pipeline = false;
        const SIZE_T responseHeaderCapacity = session->Options.MaxResponseHeaders;
        status = SendViaTransport(
            session,
            request,
            sendOptions,
            workspace,
            pooledConnection,
            reusedConnection,
            allowHttp11Pipeline,
            session->Options.Http11PipelineMaxDepth,
            builtRequestLength,
            headerScratch.RequestHeaders,
            requestHeaderCount,
            parsed,
            headerScratch.ResponseHeaders,
            responseHeaderCapacity,
            headerScratch.ResponseTrailers,
            MaxTrailersPerResponse,
            rawResponseLength,
            &connectionReusable,
            &usedHttp11Pipeline,
            cancellationOperation);

        const bool shouldRetryWithFreshConnection =
            !usedHttp11Pipeline &&
            ShouldRetryWithFreshConnection(request, status, reusedConnection);

        if (shouldRetryWithFreshConnection) {
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Warning,
                &connectionCorrelation,
                "http.connection.retry status=0x%08X",
                static_cast<ULONG>(status));
            ConnectionPoolClose(&session->ConnectionPool, pooledConnection);
            pooledConnection = nullptr;

            PooledConnection* retryConnection = nullptr;
            bool retryReused = false;
            NTSTATUS retryStatus = ConnectionPoolAcquire(
                &session->ConnectionPool,
                *poolKey.Get(),
                ConnectionPolicy::ForceNew,
                &retryConnection,
                &retryReused);
            if (NT_SUCCESS(retryStatus) && !retryReused) {
                WorkspaceReset(&workspace);
                retryStatus = PrepareApiHttpHeaderScratch(workspace, &headerScratch);
                if (NT_SUCCESS(retryStatus)) {
                    retryStatus = BuildRequestBytes(
                        request,
                        useExpectContinue,
                        allowTrace,
                        useProxyAbsoluteForm,
                        session->Options.Proxy,
                        workspace,
                        sendOptions,
                        headerScratch.HostHeader,
                        headerScratch.HostHeaderCapacity,
                        headerScratch.RequestTarget,
                        headerScratch.RequestTargetCapacity,
                        headerScratch.RequestHeaders,
                        MaxHeadersPerRequest,
                        headerScratch.RequestTrailers,
                        MaxHeadersPerRequest,
                        &builtRequestLength,
                        &requestHeaderCount);
                }
                if (!NT_SUCCESS(retryStatus)) {
                    ConnectionPoolRelease(&session->ConnectionPool, retryConnection, false);
                    return retryStatus;
                }

                *parsed = {};
                *rawResponseLength = 0;
                connectionReusable = false;
                status = SendViaTransport(
                    session,
                    request,
                    sendOptions,
                    workspace,
                    retryConnection,
                    retryReused,
                    false,
                    session->Options.Http11PipelineMaxDepth,
                    builtRequestLength,
                    headerScratch.RequestHeaders,
                    requestHeaderCount,
                    parsed,
                    headerScratch.ResponseHeaders,
                    responseHeaderCapacity,
                    headerScratch.ResponseTrailers,
                    MaxTrailersPerResponse,
                    rawResponseLength,
                    &connectionReusable,
                    &usedHttp11Pipeline,
                    cancellationOperation);

                if (!NT_SUCCESS(status)) {
                    ConnectionPoolRelease(&session->ConnectionPool, retryConnection, false);
                    retryConnection = nullptr;
                }
                else {
                    pooledConnection = retryConnection;
                }
            }
        }

        const bool canReturnToPool =
            NT_SUCCESS(status) &&
            connectionReusable &&
            request.ConnectionPolicy == ConnectionPolicy::ReuseOrCreate;
        ConnectionPoolRelease(&session->ConnectionPool, pooledConnection, canReturnToPool);
        return status;
    }


    struct AsyncHttpContext final
    {
        SessionHandle Session = nullptr;
        RequestHandle Request = nullptr;
        HttpSendOptions Options = {};
        http1::HttpAcceptEncodingPreference AcceptEncodingPreferences[http1::HttpMaxAcceptEncodingPreferences] = {};
        ResponseHandle Response = nullptr;
        volatile LONG SessionOperationEnded = 0;
    };

    _Ret_maybenull_
    ResponseHandle TakeAsyncHttpResponse(_Inout_ AsyncHttpContext* context) noexcept
    {
        if (context == nullptr) {
            return nullptr;
        }

#if defined(WKNET_USER_MODE_TEST)
        ResponseHandle response = context->Response;
        context->Response = nullptr;
        return response;
#else
        return static_cast<ResponseHandle>(InterlockedExchangePointer(
            reinterpret_cast<PVOID volatile*>(&context->Response),
            nullptr));
#endif
    }

    void EndAsyncHttpSessionOperation(_Inout_ AsyncHttpContext* context) noexcept
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
    AsyncHttpContext* AllocateAsyncHttpContext() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return static_cast<AsyncHttpContext*>(calloc(1, sizeof(AsyncHttpContext)));
#else
        return AllocateNonPagedObject<AsyncHttpContext>();
#endif
    }

    void FreeAsyncHttpContext(_In_opt_ AsyncHttpContext* context) noexcept
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


    void CleanupAsyncHttpContext(void* context) noexcept
    {
        auto* httpContext = static_cast<AsyncHttpContext*>(context);
        if (httpContext == nullptr) {
            return;
        }

        EndAsyncHttpSessionOperation(httpContext);

        ResponseHandle response = TakeAsyncHttpResponse(httpContext);
        if (response != nullptr) {
            ResponseRelease(response);
        }

        if (httpContext->Request != nullptr) {
            HttpRequestRelease(httpContext->Request);
            httpContext->Request = nullptr;
        }
        FreeAsyncHttpContext(httpContext);
    }

    _Must_inspect_result_
    NTSTATUS HttpSendSyncImpl(
        _In_ SessionHandle session,
        _In_ RequestHandle request,
        _In_opt_ const HttpSendOptions* options,
        ResponseHandle* response,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept;

    NTSTATUS RunHttpAsyncOperation(AsyncOperationHandle operation, void* context) noexcept
    {
        auto* httpContext = static_cast<AsyncHttpContext*>(context);
        if (httpContext == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;
        if (AsyncOperationIsCanceled(operation)) {
            status = STATUS_CANCELLED;
            EndAsyncHttpSessionOperation(httpContext);
            return status;
        }

        ResponseHandle response = nullptr;
        ResponseHandle* responseOutput = nullptr;
        const bool bodyCallbackOnly =
            httpContext->Options.BodyCallback != nullptr &&
            ((httpContext->Options.Flags & HttpSendFlagAggregateWithCallbacks) == 0);
        if (!bodyCallbackOnly) {
            responseOutput = &response;
        }

        status = HttpSendSyncImpl(
            httpContext->Session,
            httpContext->Request,
            &httpContext->Options,
            responseOutput,
            operation);
        if (NT_SUCCESS(status)) {
            httpContext->Response = response;
        }
        else if (response != nullptr) {
            ResponseRelease(response);
        }

        if (AsyncOperationIsCanceled(operation) && status == STATUS_SUCCESS) {
            status = STATUS_CANCELLED;
        }

        EndAsyncHttpSessionOperation(httpContext);
        return status;
    }


    NTSTATUS HttpSendSyncImpl(
        SessionHandle session,
        RequestHandle request,
        const HttpSendOptions* options,
        ResponseHandle* response,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (response != nullptr) {
            *response = nullptr;
        }

        SessionOperationScope sessionScope(session);
        if (!sessionScope.IsActive()) {
            return STATUS_INVALID_PARAMETER;
        }

        RequestOperationScope requestScope(request);
        if (!requestScope.IsActive() || request->Session != session) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request->Url == nullptr || request->UrlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (TextEqualsLiteralIgnoreCase(request->Scheme, request->SchemeLength, "https") &&
            request->Tls.Alpn != nullptr &&
            request->Tls.AlpnLength != 0 &&
            !IsSupportedHttpAlpn(request->Tls.Alpn, request->Tls.AlpnLength)) {
            return STATUS_NOT_SUPPORTED;
        }

        HttpSendOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidSendOptions(effectiveOptions, *session)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (effectiveOptions.TraceOperationId == 0) {
            effectiveOptions.TraceOperationId = rtl::TraceAllocateCorrelationId();
        }
        const TraceCorrelation operationCorrelation = {
            effectiveOptions.TraceOperationId,
            0,
            0
        };
        WKNET_TRACE_CORRELATED(
            ::wknet::ComponentSession,
            ::wknet::TraceLevel::Info,
            &operationCorrelation,
            "http.request.start method=%u body_bytes=%Iu async=%u",
            static_cast<ULONG>(request->Method),
            request->HasBody ? request->BodyLength : static_cast<SIZE_T>(0),
            cancellationOperation != nullptr ? 1u : 0u);

        if (effectiveOptions.BodyCallback != nullptr &&
            response == nullptr &&
            ((effectiveOptions.Flags & HttpSendFlagAggregateWithCallbacks) != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool bodyCallbackOnly =
            effectiveOptions.BodyCallback != nullptr &&
            ((effectiveOptions.Flags & HttpSendFlagAggregateWithCallbacks) == 0);
        const bool shouldAggregate = !bodyCallbackOnly;
        if (shouldAggregate && response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HttpCacheHandle effectiveCache = effectiveOptions.Cache != nullptr ? effectiveOptions.Cache : session->Cache;
        HttpCacheLookupResult cacheLookup = {};
        HttpCacheSnapshot activeCacheSnapshot = {};
        bool activeCacheSnapshotValid = false;
        RequestHandle redirectRequest = nullptr;
        Request* currentRequest = request;

        if (effectiveCache != nullptr) {
            status = HttpCacheLookup(effectiveCache, *currentRequest, effectiveOptions, &cacheLookup);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE_CORRELATED(
                    ::wknet::ComponentSession,
                    ::wknet::TraceLevel::Error,
                    &operationCorrelation,
                    "http.cache.lookup.failed status=0x%08X",
                    static_cast<ULONG>(status));
                return status;
            }
            if (cacheLookup.OnlyIfCachedMiss) {
                WKNET_TRACE_CORRELATED(
                    ::wknet::ComponentSession,
                    ::wknet::TraceLevel::Info,
                    &operationCorrelation,
                    "http.cache.only_if_cached_miss");
                return STATUS_NOT_FOUND;
            }
            if (cacheLookup.Found && !cacheLookup.RequiresValidation) {
                http1::HttpResponse cachedParsed = {};
                FillParsedFromCacheSnapshot(cacheLookup.Snapshot, &cachedParsed);
                status = InvokeResponseCallbacks(effectiveOptions, cachedParsed);
                if (NT_SUCCESS(status) && shouldAggregate) {
                    status = CreateOwnedResponse(cachedParsed, nullptr, 0, response);
                }
                HttpCacheFreeSnapshot(&cacheLookup.Snapshot);
                WKNET_TRACE_CORRELATED(
                    ::wknet::ComponentSession,
                    NT_SUCCESS(status) ? ::wknet::TraceLevel::Info : ::wknet::TraceLevel::Error,
                    &operationCorrelation,
                    NT_SUCCESS(status) ?
                        "http.request.complete source=cache status_code=%u body_bytes=%Iu" :
                        "http.request.failed source=cache status=0x%08X",
                    NT_SUCCESS(status) ? cachedParsed.StatusCode : static_cast<ULONG>(status),
                    NT_SUCCESS(status) ? cachedParsed.BodyLength : static_cast<SIZE_T>(0));
                return status;
            }
            if (cacheLookup.Found && cacheLookup.RequiresValidation) {
                if ((effectiveOptions.Flags & HttpSendFlagOnlyIfCached) != 0) {
                    return STATUS_NOT_FOUND;
                }
                status = CloneRequestForAsync(*currentRequest, &redirectRequest);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                currentRequest = redirectRequest;
                if (cacheLookup.IfNoneMatchLength != 0 &&
                    !RequestHasHeader(*currentRequest, "If-None-Match")) {
                    status = HttpRequestSetHeader(
                        currentRequest,
                        "If-None-Match",
                        sizeof("If-None-Match") - 1,
                        cacheLookup.IfNoneMatch,
                        cacheLookup.IfNoneMatchLength);
                }
                else if (cacheLookup.IfModifiedSinceLength != 0 &&
                    !RequestHasHeader(*currentRequest, "If-Modified-Since")) {
                    status = HttpRequestSetHeader(
                        currentRequest,
                        "If-Modified-Since",
                        sizeof("If-Modified-Since") - 1,
                        cacheLookup.IfModifiedSince,
                        cacheLookup.IfModifiedSinceLength);
                }
                if (!NT_SUCCESS(status)) {
                    HttpRequestRelease(redirectRequest);
                    return status;
                }
            }
        }

        const SIZE_T maxResponseBytes = bodyCallbackOnly ?
            0 :
            EffectiveMaxResponseBytes(options, session->Options.MaxResponseBytes);
        WorkspaceGuard requestWorkspace;
        status = requestWorkspace.CreateForSession(session, maxResponseBytes);
        if (!NT_SUCCESS(status) || !requestWorkspace.IsValid()) {
            return !NT_SUCCESS(status) ? status : STATUS_INSUFFICIENT_RESOURCES;
        }
        Workspace& workspace = *requestWorkspace.Get();

        HeapObject<ApiHttpHeaderScratch> headerScratch;
        if (!headerScratch.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        http1::HttpResponse parsed = {};
        SIZE_T rawResponseLength = 0;
        const bool followRedirects = RedirectsEnabled(effectiveOptions);
        const ULONG maxRedirects = EffectiveMaxRedirects(effectiveOptions);
        ULONG redirectCount = 0;

        for (;;) {
            if (cancellationOperation != nullptr && AsyncOperationIsCanceled(cancellationOperation)) {
                status = STATUS_CANCELLED;
                break;
            }

            status = SendSingleHttpRequest(
                session,
                *currentRequest,
                effectiveOptions,
                workspace,
                *headerScratch.Get(),
                &parsed,
                &rawResponseLength,
                cancellationOperation);
            if (!NT_SUCCESS(status)) {
                break;
            }

            if (!followRedirects ||
                !IsRedirectStatus(parsed.StatusCode) ||
                redirectCount >= maxRedirects) {
                break;
            }

            const http1::HttpText location = FindLocationHeader(parsed);
            if (location.Data == nullptr || location.Length == 0) {
                break;
            }

            if (redirectRequest == nullptr) {
                status = CloneRequestForAsync(*currentRequest, &redirectRequest);
                if (!NT_SUCCESS(status)) {
                    break;
                }
                currentRequest = redirectRequest;
            }

            status = ApplyRedirectToRequest(*currentRequest, parsed.StatusCode, location, workspace);
            if (status == STATUS_NOT_FOUND || status == STATUS_INVALID_PARAMETER) {
                status = STATUS_SUCCESS;
                break;
            }
            if (!NT_SUCCESS(status)) {
                break;
            }

            ++redirectCount;
        }

        if (NT_SUCCESS(status) &&
            effectiveCache != nullptr &&
            parsed.StatusCode == 304) {
            status = HttpCacheUpdateNotModified(
                effectiveCache,
                *currentRequest,
                parsed,
                &activeCacheSnapshot);
            if (NT_SUCCESS(status)) {
                FillParsedFromCacheSnapshot(activeCacheSnapshot, &parsed);
                rawResponseLength = 0;
                activeCacheSnapshotValid = true;
            }
            else if (status == STATUS_NOT_FOUND) {
                status = STATUS_SUCCESS;
            }
        }

        if (NT_SUCCESS(status)) {
            status = InvokeResponseCallbacks(effectiveOptions, parsed);
        }

        if (NT_SUCCESS(status) &&
            effectiveCache != nullptr &&
            parsed.StatusCode != 304 &&
            !activeCacheSnapshotValid) {
            if (http1::IsUnsafeMethodForInvalidation(static_cast<ULONG>(currentRequest->Method)) &&
                parsed.StatusCode >= 200 &&
                parsed.StatusCode < 400) {
                HttpCacheInvalidateForRequest(effectiveCache, *currentRequest);
            }
            else {
                NTSTATUS cacheStatus = HttpCacheStoreResponse(
                    effectiveCache,
                    *currentRequest,
                    effectiveOptions,
                    parsed);
                if (!NT_SUCCESS(cacheStatus)) {
                    status = cacheStatus;
                }
            }
        }

        if (NT_SUCCESS(status) && shouldAggregate) {
            status = CreateOwnedResponse(
                parsed,
                activeCacheSnapshotValid ? nullptr : reinterpret_cast<const char*>(workspace.Response.Data),
                activeCacheSnapshotValid ? 0 : rawResponseLength,
                response);
        }

        if (activeCacheSnapshotValid) {
            HttpCacheFreeSnapshot(&activeCacheSnapshot);
        }
        if (redirectRequest != nullptr) {
            HttpRequestRelease(redirectRequest);
        }
        if (NT_SUCCESS(status)) {
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Info,
                &operationCorrelation,
                "http.request.complete status_code=%u body_bytes=%Iu redirects=%u",
                parsed.StatusCode,
                parsed.BodyLength,
                redirectCount);
        }
        else {
            WKNET_TRACE_CORRELATED(
                ::wknet::ComponentSession,
                ::wknet::TraceLevel::Error,
                &operationCorrelation,
                "http.request.failed status=0x%08X redirects=%u",
                static_cast<ULONG>(status),
                redirectCount);
        }
        return status;
    }

    NTSTATUS HttpSendAsyncImpl(
        SessionHandle session,
        RequestHandle request,
        const HttpSendOptions* options,
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

        RequestOperationScope requestScope(request);
        if (!requestScope.IsActive() || operation == nullptr || request->Session != session) {
            SessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }

        if (request->Url == nullptr || request->UrlLength == 0) {
            SessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }

        HttpSendOptions effectiveOptions = {};
        if (options != nullptr) {
            effectiveOptions = *options;
        }

        if (!IsValidSendOptions(effectiveOptions, *session)) {
            SessionEndOperation(session);
            return STATUS_INVALID_PARAMETER;
        }
        if (effectiveOptions.TraceOperationId == 0) {
            effectiveOptions.TraceOperationId = rtl::TraceAllocateCorrelationId();
        }

        auto* context = AllocateAsyncHttpContext();
        if (context == nullptr) {
            SessionEndOperation(session);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        context->Session = session;
        context->Options = effectiveOptions;
        if (effectiveOptions.AcceptEncodingPreferenceCount != 0) {
            RtlCopyMemory(
                context->AcceptEncodingPreferences,
                effectiveOptions.AcceptEncodingPreferences,
                sizeof(context->AcceptEncodingPreferences[0]) * effectiveOptions.AcceptEncodingPreferenceCount);
            context->Options.AcceptEncodingPreferences = context->AcceptEncodingPreferences;
        }
        context->Response = nullptr;
        context->SessionOperationEnded = 0;

        status = CloneRequestForAsync(*request, &context->Request);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncHttpContext(context);
            return status;
        }

        AsyncCreateOptions createOptions = {};
        createOptions.Kind = AsyncOperationKind::HttpSend;
        createOptions.WorkerRoutine = RunHttpAsyncOperation;
        createOptions.CleanupRoutine = CleanupAsyncHttpContext;
        createOptions.Context = context;
        createOptions.CompletionCallback = effectiveOptions.CompletionCallback;
        createOptions.CompletionContext = effectiveOptions.CompletionContext;
        createOptions.StartSuspended = true;
        createOptions.TraceOperationId = effectiveOptions.TraceOperationId;

        status = AsyncOperationCreate(createOptions, operation);
        if (!NT_SUCCESS(status)) {
            CleanupAsyncHttpContext(context);
            return status;
        }

        status = AsyncOperationQueue(*operation);
        if (!NT_SUCCESS(status)) {
            AsyncOperationRelease(*operation);
            *operation = nullptr;
        }

        return status;
    }


    NTSTATUS AsyncGetHttpResponse(AsyncOperationHandle operation, ResponseHandle* response) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (response != nullptr) {
            *response = nullptr;
        }

        if (!AsyncOperationIsValid(operation) ||
            response == nullptr ||
            AsyncOperationGetKind(operation) != AsyncOperationKind::HttpSend) {
            return STATUS_INVALID_PARAMETER;
        }

        status = AsyncOperationStatus(operation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        auto* context = static_cast<AsyncHttpContext*>(AsyncOperationContext(operation));
        ResponseHandle asyncResponse = TakeAsyncHttpResponse(context);
        if (asyncResponse == nullptr) {
            return STATUS_NOT_FOUND;
        }

        *response = asyncResponse;
        return STATUS_SUCCESS;
    }

#if defined(WKNET_USER_MODE_TEST)
    bool TestIsHttpTls12ConfirmationCandidate(
        TlsVersion minVersion,
        TlsVersion maxVersion,
        ULONG category,
        NTSTATUS status,
        bool beforeTls13FirstServerHello) noexcept
    {
        Request request = {};
        request.Tls.MinVersion = minVersion;
        request.Tls.MaxVersion = maxVersion;
        tls::TlsHandshakeFailure failure = {};
        failure.Category = static_cast<tls::TlsHandshakeFailureCategory>(category);
        failure.Status = status;
        failure.BeforeTls13FirstServerHello = beforeTls13FirstServerHello;
        return IsHttpTls12ConfirmationCandidate(request, failure);
    }
#endif

NTSTATUS HttpSendSync(
    SessionHandle session,
    RequestHandle request,
    const HttpSendOptions* options,
    ResponseHandle* response) noexcept
{
    return HttpSendSyncImpl(session, request, options, response, nullptr);
}

NTSTATUS HttpSendAsync(
    SessionHandle session,
    RequestHandle request,
    const HttpSendOptions* options,
    AsyncOperationHandle* operation) noexcept
{
    return HttpSendAsyncImpl(session, request, options, operation);
}

}
}
