#include "session/HttpEngineInternal.hpp"
#include "http1/HttpChunkedDecoder.h"

namespace wknet
{
namespace session
{

    _Must_inspect_result_
    NTSTATUS GrowDecodedBodyAfterBufferTooSmall(_Inout_ Workspace& workspace) noexcept
    {
        const SIZE_T currentLength = workspace.DecodedBody.Length;
        if (workspace.MaxResponseBytes != 0 && currentLength >= workspace.MaxResponseBytes) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T requiredCapacity = currentLength == 0 ?
            WorkspaceDecodedBodyBytes :
            currentLength * 2;
        if (currentLength != 0 &&
            requiredCapacity < currentLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (workspace.MaxResponseBytes != 0 &&
            requiredCapacity > workspace.MaxResponseBytes) {
            requiredCapacity = workspace.MaxResponseBytes;
        }

        if (requiredCapacity <= currentLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return WorkspaceEnsureDecodedBodyCapacity(&workspace, requiredCapacity);
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
    NTSTATUS BuildRequestBytes(
        const Request& request,
        bool addExpectContinue,
        bool allowTrace,
        bool useProxyAbsoluteForm,
        const ProxyOptions& proxy,
        _Inout_ Workspace& workspace,
        _In_ const HttpSendOptions& sendOptions,
        _Out_writes_bytes_(hostHeaderCapacity) char* hostHeader,
        SIZE_T hostHeaderCapacity,
        _Out_writes_bytes_(requestTargetCapacity) char* requestTarget,
        SIZE_T requestTargetCapacity,
        _Out_writes_(headerCapacity) http1::HttpHeader* requestHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* requestTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* requestLength,
        _Out_opt_ SIZE_T* requestHeaderCount = nullptr) noexcept
    {
        if (requestLength != nullptr) {
            *requestLength = 0;
        }
        if (requestHeaderCount != nullptr) {
            *requestHeaderCount = 0;
        }

        if (requestLength == nullptr ||
            requestHeaders == nullptr ||
            hostHeader == nullptr ||
            hostHeaderCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        http1::HttpText acceptEncoding = {};
        NTSTATUS status = STATUS_SUCCESS;
        if (!RequestHasHeader(request, "Accept-Encoding")) {
            status = BuildEffectiveAcceptEncoding(sendOptions, workspace, &acceptEncoding);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        http1::HttpRequestBuildOptions buildOptions = {};
        status = BuildHttpRequestOptions(
            request,
            addExpectContinue,
            allowTrace,
            useProxyAbsoluteForm,
            proxy,
            acceptEncoding,
            hostHeader,
            hostHeaderCapacity,
            requestTarget,
            requestTargetCapacity,
            requestHeaders,
            headerCapacity,
            requestTrailers,
            trailerCapacity,
            &buildOptions,
            requestHeaderCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (request.BodySourceCallback != nullptr) {
            // Headers-only build for streaming body sources.
            SIZE_T headerOnlyEstimate =
                request.PathLength + request.HostLength + 512 + (request.HeaderCount * 128);
            if (headerOnlyEstimate < 4096) {
                headerOnlyEstimate = 4096;
            }
            status = WorkspaceEnsureRequestCapacity(&workspace, headerOnlyEstimate);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return http1::HttpRequestBuilder::BuildHeaders(
                buildOptions,
                reinterpret_cast<char*>(workspace.Request.Data),
                workspace.Request.Length,
                requestLength);
        }

        // Grow request wire buffer for long targets / many headers / large bodies.
        SIZE_T estimate =
            request.PathLength +
            request.HostLength +
            request.BodyLength +
            1024 +
            (request.HeaderCount * 192) +
            (request.TrailerCount * 192);
        if (estimate < workspace.Request.Length) {
            estimate = workspace.Request.Length;
        }
        status = WorkspaceEnsureRequestCapacity(&workspace, estimate);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = http1::HttpRequestBuilder::Build(
            buildOptions,
            reinterpret_cast<char*>(workspace.Request.Data),
            workspace.Request.Length,
            requestLength);
        if (status == STATUS_BUFFER_TOO_SMALL && requestLength != nullptr && *requestLength != 0) {
            // Builder may report exact needed size; grow once and retry.
            status = WorkspaceEnsureRequestCapacity(&workspace, *requestLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = http1::HttpRequestBuilder::Build(
                buildOptions,
                reinterpret_cast<char*>(workspace.Request.Data),
                workspace.Request.Length,
                requestLength);
        }
        return status;
    }

    _Must_inspect_result_
    bool FindHttpRequestBodyOffset(
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        _Out_ SIZE_T* bodyOffset) noexcept
    {
        if (bodyOffset != nullptr) {
            *bodyOffset = 0;
        }
        if (requestBytes == nullptr || bodyOffset == nullptr || requestLength < 4) {
            return false;
        }

        for (SIZE_T index = 0; index <= requestLength - 4; ++index) {
            if (requestBytes[index] == '\r' &&
                requestBytes[index + 1] == '\n' &&
                requestBytes[index + 2] == '\r' &&
                requestBytes[index + 3] == '\n') {
                *bodyOffset = index + 4;
                return true;
            }
        }

        return false;
    }

    _Must_inspect_result_
    NTSTATUS SendTransportSegment(
        _Inout_ transport::Transport* transport,
        _In_reads_bytes_opt_(length) const UCHAR* data,
        SIZE_T length) noexcept
    {
        if (length == 0) {
            return STATUS_SUCCESS;
        }
        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T totalSent = 0;
        while (totalSent < length) {
            SIZE_T sent = 0;
            NTSTATUS status = transport::TransportSend(transport, data + totalSent, length - totalSent, &sent);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (sent == 0) {
                return STATUS_CONNECTION_DISCONNECTED;
            }
            totalSent += sent;
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBuffer(
        _Inout_ transport::Transport* transport,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength) noexcept
    {
        SIZE_T bodyOffset = 0;
        if (!FindHttpRequestBodyOffset(requestBytes, requestLength, &bodyOffset)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = SendTransportSegment(transport, requestBytes, bodyOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return SendTransportSegment(
            transport,
            requestBytes + bodyOffset,
            requestLength - bodyOffset);
    }

#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocket(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SendHttp1PipelineRequestBuffer(
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection* pooledConnection,
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength,
        _Out_ bool* connectionReusable) noexcept
    {
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (connectionReusable != nullptr) {
            *connectionReusable = false;
        }
        if (connectionPool == nullptr ||
            pooledConnection == nullptr ||
            parsed == nullptr ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr ||
            rawResponseLength == nullptr ||
            connectionReusable == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG sequence = 0;
        NTSTATUS status = ConnectionPoolBeginHttp1PipelineSend(
            connectionPool,
            pooledConnection,
            &sequence);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendHttp1RequestBuffer(transport, requestBytes, requestLength);
        ConnectionPoolEndHttp1PipelineSend(pooledConnection);
        if (!NT_SUCCESS(status)) {
            ConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        status = ConnectionPoolWaitHttp1PipelineReceiveTurn(
            connectionPool,
            pooledConnection,
            sequence);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = LoadHttp1PipelineBufferedBytes(connectionPool, pooledConnection, workspace);
        if (!NT_SUCCESS(status)) {
            ConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        status = ReadHttpResponseFromSocket(
            transport,
            workspace,
            responseBodyForbidden,
            acceptPolicy,
            materials,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
        if (!NT_SUCCESS(status)) {
            ConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        status = PreserveHttp1PipelineTrailingBytes(
            connectionPool,
            pooledConnection,
            workspace,
            *parsed,
            rawResponseLength);
        if (!NT_SUCCESS(status)) {
            ConnectionPoolFailHttp1Pipeline(connectionPool, pooledConnection, status);
            return status;
        }

        const bool reusable =
            IsHttpConnectionReusable(*parsed, *rawResponseLength) &&
            parsed->MajorVersion == 1 &&
            parsed->MinorVersion == 1;
        if (reusable) {
            ConnectionPoolCompleteHttp1PipelineReceive(
                connectionPool,
                pooledConnection,
                sequence);
        }
        else {
            ConnectionPoolFailHttp1Pipeline(
                connectionPool,
                pooledConnection,
                STATUS_CONNECTION_DISCONNECTED);
        }

        *connectionReusable = reusable;
        return STATUS_SUCCESS;
    }
#endif

    _Must_inspect_result_
    bool FormatChunkPrefix(
        _Out_writes_bytes_(capacity) UCHAR* destination,
        SIZE_T capacity,
        SIZE_T value,
        _Out_ SIZE_T* length) noexcept
    {
        if (length != nullptr) {
            *length = 0;
        }
        if (destination == nullptr || length == nullptr || capacity < 3) {
            return false;
        }

        SIZE_T shift = (sizeof(SIZE_T) * 8) - 4;
        bool wroteDigit = false;
        SIZE_T cursor = 0;
        for (;;) {
            const SIZE_T digit = (value >> shift) & 0x0f;
            if (digit != 0 || wroteDigit || shift == 0) {
                if (cursor >= capacity) {
                    return false;
                }
                static constexpr char hex[] = "0123456789abcdef";
                destination[cursor++] = static_cast<UCHAR>(hex[digit]);
                wroteDigit = true;
            }

            if (shift == 0) {
                break;
            }
            shift -= 4;
        }

        if (cursor + 2 > capacity) {
            return false;
        }
        destination[cursor++] = '\r';
        destination[cursor++] = '\n';
        *length = cursor;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestTrailers(
        _Inout_ transport::Transport* transport,
        _In_ const Request& request) noexcept
    {
        NTSTATUS status = SendTransportSegment(
            transport,
            reinterpret_cast<const UCHAR*>("0\r\n"),
            sizeof("0\r\n") - 1);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
            const StoredHeader& trailer = request.Trailers[index];
            status = SendTransportSegment(
                transport,
                reinterpret_cast<const UCHAR*>(trailer.Name),
                trailer.NameLength);
            if (NT_SUCCESS(status)) {
                status = SendTransportSegment(
                    transport,
                    reinterpret_cast<const UCHAR*>(": "),
                    sizeof(": ") - 1);
            }
            if (NT_SUCCESS(status)) {
                status = SendTransportSegment(
                    transport,
                    reinterpret_cast<const UCHAR*>(trailer.Value),
                    trailer.ValueLength);
            }
            if (NT_SUCCESS(status)) {
                status = SendTransportSegment(
                    transport,
                    reinterpret_cast<const UCHAR*>("\r\n"),
                    sizeof("\r\n") - 1);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return SendTransportSegment(
            transport,
            reinterpret_cast<const UCHAR*>("\r\n"),
            sizeof("\r\n") - 1);
    }

    _Must_inspect_result_
    NTSTATUS ReadRequestBodySource(
        _In_ const Request& request,
        _Out_writes_bytes_(bufferCapacity) UCHAR* buffer,
        SIZE_T bufferCapacity,
        _Out_ SIZE_T* bytesRead,
        _Out_ bool* endOfBody) noexcept
    {
        if (request.BodySourceCallback == nullptr ||
            buffer == nullptr ||
            bufferCapacity == 0 ||
            bytesRead == nullptr ||
            endOfBody == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *bytesRead = 0;
        *endOfBody = false;
        NTSTATUS status = request.BodySourceCallback(
            request.BodySourceContext,
            buffer,
            bufferCapacity,
            bytesRead,
            endOfBody);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (*bytesRead > bufferCapacity) {
            return STATUS_INVALID_PARAMETER;
        }
        if (*bytesRead == 0 && !*endOfBody) {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBodySource(
        _Inout_ transport::Transport* transport,
        _In_ const Request& request,
        _Inout_ Workspace& workspace) noexcept
    {
        if (request.BodySourceCallback == nullptr ||
            workspace.Request.Data == nullptr ||
            workspace.Request.Length <= 32) {
            return STATUS_INVALID_PARAMETER;
        }

        constexpr SIZE_T prefixCapacity = 32;
        UCHAR* chunkPrefix = workspace.Request.Data;
        UCHAR* bodyBuffer = workspace.Request.Data + prefixCapacity;
        const SIZE_T bodyBufferCapacity = workspace.Request.Length - prefixCapacity;
        SIZE_T totalSent = 0;

        for (;;) {
            SIZE_T bytesRead = 0;
            bool endOfBody = false;
            NTSTATUS status = ReadRequestBodySource(
                request,
                bodyBuffer,
                bodyBufferCapacity,
                &bytesRead,
                &endOfBody);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (request.BodyMode == RequestBodyMode::ContentLength) {
                if (!request.BodySourceContentLengthKnown) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (bytesRead > request.BodySourceContentLength - totalSent) {
                    return STATUS_INVALID_PARAMETER;
                }
                status = SendTransportSegment(transport, bodyBuffer, bytesRead);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                totalSent += bytesRead;
                if (totalSent == request.BodySourceContentLength) {
                    return STATUS_SUCCESS;
                }
                if (endOfBody) {
                    return STATUS_INVALID_PARAMETER;
                }
                continue;
            }

            if (bytesRead != 0) {
                SIZE_T prefixLength = 0;
                if (!FormatChunkPrefix(chunkPrefix, prefixCapacity, bytesRead, &prefixLength)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                status = SendTransportSegment(transport, chunkPrefix, prefixLength);
                if (NT_SUCCESS(status)) {
                    status = SendTransportSegment(transport, bodyBuffer, bytesRead);
                }
                if (NT_SUCCESS(status)) {
                    status = SendTransportSegment(
                        transport,
                        reinterpret_cast<const UCHAR*>("\r\n"),
                        sizeof("\r\n") - 1);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (endOfBody) {
                return SendHttp1RequestTrailers(transport, request);
            }
        }
    }

    _Must_inspect_result_
    bool AddSizeChecked(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
    {
        if (result == nullptr) {
            return false;
        }
        if (left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right) {
            return false;
        }
        *result = left + right;
        return true;
    }

#if defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS SimulateHttp1RequestBodySourceForTest(
        _In_ const Request& request,
        _Inout_ Workspace& workspace,
        _Out_ SIZE_T* bodyBytesLength) noexcept
    {
        if (bodyBytesLength != nullptr) {
            *bodyBytesLength = 0;
        }
        if (request.BodySourceCallback == nullptr || bodyBytesLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (workspace.DecodedBody.Data == nullptr || workspace.DecodedBody.Length <= 32) {
            return STATUS_INVALID_PARAMETER;
        }

        constexpr SIZE_T prefixCapacity = 32;
        UCHAR* chunkPrefix = workspace.DecodedBody.Data;
        UCHAR* bodyBuffer = workspace.DecodedBody.Data + prefixCapacity;
        const SIZE_T bodyBufferCapacity = workspace.DecodedBody.Length - prefixCapacity;
        SIZE_T totalBodyBytes = 0;
        SIZE_T totalPayloadBytes = 0;

        for (;;) {
            SIZE_T bytesRead = 0;
            bool endOfBody = false;
            NTSTATUS status = ReadRequestBodySource(
                request,
                bodyBuffer,
                bodyBufferCapacity,
                &bytesRead,
                &endOfBody);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (request.BodyMode == RequestBodyMode::ContentLength) {
                if (!request.BodySourceContentLengthKnown) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (bytesRead > request.BodySourceContentLength - totalPayloadBytes) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (!AddSizeChecked(totalPayloadBytes, bytesRead, &totalPayloadBytes)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                if (totalPayloadBytes == request.BodySourceContentLength) {
                    *bodyBytesLength = totalPayloadBytes;
                    return STATUS_SUCCESS;
                }
                if (endOfBody) {
                    return STATUS_INVALID_PARAMETER;
                }
                continue;
            }

            if (bytesRead != 0) {
                SIZE_T prefixLength = 0;
                if (!FormatChunkPrefix(chunkPrefix, prefixCapacity, bytesRead, &prefixLength)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                SIZE_T next = 0;
                if (!AddSizeChecked(totalBodyBytes, prefixLength, &next) ||
                    !AddSizeChecked(next, bytesRead, &next) ||
                    !AddSizeChecked(next, sizeof("\r\n") - 1, &next)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                totalBodyBytes = next;
            }

            if (endOfBody) {
                SIZE_T next = 0;
                if (!AddSizeChecked(totalBodyBytes, sizeof("0\r\n") - 1, &next)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                for (SIZE_T index = 0; index < request.TrailerCount; ++index) {
                    const StoredHeader& trailer = request.Trailers[index];
                    if (!AddSizeChecked(next, trailer.NameLength, &next) ||
                        !AddSizeChecked(next, sizeof(": ") - 1, &next) ||
                        !AddSizeChecked(next, trailer.ValueLength, &next) ||
                        !AddSizeChecked(next, sizeof("\r\n") - 1, &next)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                }
                if (!AddSizeChecked(next, sizeof("\r\n") - 1, &next)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                *bodyBytesLength = next;
                return STATUS_SUCCESS;
            }
        }
    }
#endif

#if !defined(WKNET_USER_MODE_TEST)

    namespace
    {
        bool ResponseHasNonIdentityContentEncoding(const http1::HttpResponse& response) noexcept
        {
            const http1::HttpHeader* header = nullptr;
            if (!response.FindHeader(http1::MakeText("Content-Encoding"), &header) ||
                header == nullptr) {
                return false;
            }
            if (header->Value.Length == 0) {
                return false;
            }
            // identity is a no-op; anything else needs full-buffer decode today.
            return !http1::TextEqualsIgnoreCase(header->Value, http1::MakeText("identity"));
        }

        struct StreamAggregateContext final
        {
            BodyCallback UserCallback = nullptr;
            void* UserContext = nullptr;
            UCHAR* Aggregate = nullptr;
            SIZE_T AggregateCapacity = 0;
            SIZE_T AggregateLength = 0;
            SIZE_T MaxAggregateBytes = 0; // 0 = unlimited
            bool DoAggregate = false;
        };

        NTSTATUS StreamBodyOnData(
            void* context,
            const UCHAR* data,
            SIZE_T dataLength) noexcept
        {
            auto* state = static_cast<StreamAggregateContext*>(context);
            if (state == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (state->DoAggregate && dataLength != 0) {
                if (state->MaxAggregateBytes != 0 &&
                    (state->AggregateLength > state->MaxAggregateBytes ||
                        dataLength > state->MaxAggregateBytes - state->AggregateLength)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                const SIZE_T needed = state->AggregateLength + dataLength;
                if (needed > state->AggregateCapacity) {
                    SIZE_T newCap = state->AggregateCapacity == 0 ? 4096 : state->AggregateCapacity;
                    while (newCap < needed) {
                        if (newCap > (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / 2)) {
                            return STATUS_BUFFER_TOO_SMALL;
                        }
                        newCap *= 2;
                    }
                    if (state->MaxAggregateBytes != 0 && newCap > state->MaxAggregateBytes) {
                        newCap = state->MaxAggregateBytes;
                    }
                    if (newCap < needed) {
                        return STATUS_BUFFER_TOO_SMALL;
                    }
                    UCHAR* grown = static_cast<UCHAR*>(AllocateNonPagedPoolBytes(newCap));
                    if (grown == nullptr) {
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    if (state->Aggregate != nullptr && state->AggregateLength != 0) {
                        RtlCopyMemory(grown, state->Aggregate, state->AggregateLength);
                    }
                    FreeNonPagedPoolBytes(state->Aggregate);
                    state->Aggregate = grown;
                    state->AggregateCapacity = newCap;
                }
                RtlCopyMemory(state->Aggregate + state->AggregateLength, data, dataLength);
                state->AggregateLength += dataLength;
            }

            if (state->UserCallback != nullptr && dataLength != 0) {
                return state->UserCallback(
                    state->UserContext,
                    data,
                    dataLength,
                    false);
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS StreamReceiveMore(
            transport::Transport* transport,
            UCHAR* window,
            SIZE_T windowCapacity,
            SIZE_T* windowLength,
            ULONG timeoutMilliseconds,
            SIZE_T* receivedOut) noexcept
        {
            if (receivedOut != nullptr) {
                *receivedOut = 0;
            }
            if (transport == nullptr || window == nullptr || windowLength == nullptr || receivedOut == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (*windowLength >= windowCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            SIZE_T received = 0;
            NTSTATUS status = transport::TransportReceiveWithTimeout(
                transport,
                window + *windowLength,
                windowCapacity - *windowLength,
                &received,
                timeoutMilliseconds);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            *windowLength += received;
            *receivedOut = received;
            return STATUS_SUCCESS;
        }

        // After transfer-decoded body is fully accumulated (or streamed), either:
        // - identity: keep existing aggregate/callback semantics, or
        // - non-identity CE: full-buffer decode then deliver plaintext to BodyCallback.
        _Must_inspect_result_
        NTSTATUS FinalizeStreamingBody(
            _Inout_ StreamAggregateContext& streamCtx,
            _Inout_ Workspace& workspace,
            _Inout_ http1::HttpResponse* parsed,
            bool aggregateBody,
            bool needsContentDecode,
            _In_reads_(responseHeaderCount) const http1::HttpHeader* responseHeaders,
            SIZE_T responseHeaderCount,
            _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
            _In_opt_ const codec::DecodeMaterials* materials,
            _In_opt_ BodyCallback bodyCallback,
            _In_opt_ void* callbackContext,
            _Out_ bool* bodyDelivered) noexcept
        {
            if (parsed == nullptr || bodyDelivered == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (needsContentDecode) {
                const char* encodedBody = reinterpret_cast<const char*>(streamCtx.Aggregate);
                const SIZE_T encodedLength = streamCtx.AggregateLength;
                http1::HttpContentDecodeResult decoded = {};
                NTSTATUS status = DecodeContentWithWorkspace(
                    responseHeaders,
                    responseHeaderCount,
                    encodedBody,
                    encodedLength,
                    workspace,
                    acceptPolicy,
                    materials,
                    &decoded);
                // Encoded aggregate is no longer needed after decode.
                FreeNonPagedPoolBytes(streamCtx.Aggregate);
                streamCtx.Aggregate = nullptr;
                streamCtx.AggregateLength = 0;
                streamCtx.AggregateCapacity = 0;
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (bodyCallback != nullptr) {
                    if (decoded.BodyLength != 0 && decoded.Body != nullptr) {
                        status = bodyCallback(
                            callbackContext,
                            reinterpret_cast<const UCHAR*>(decoded.Body),
                            decoded.BodyLength,
                            false);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    status = bodyCallback(callbackContext, nullptr, 0, true);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    *bodyDelivered = true;
                }

                if (aggregateBody && decoded.BodyLength != 0 && decoded.Body != nullptr) {
                    parsed->Body = decoded.Body;
                    parsed->BodyLength = decoded.BodyLength;
                }
                else {
                    parsed->Body = nullptr;
                    parsed->BodyLength = 0;
                }
                workspace.ResponseLength = 0;
                return STATUS_SUCCESS;
            }

            if (bodyCallback != nullptr) {
                const NTSTATUS status = bodyCallback(callbackContext, nullptr, 0, true);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                *bodyDelivered = true;
            }
            if (aggregateBody && streamCtx.AggregateLength != 0) {
                FreeNonPagedPoolBytes(workspace.Response.Data);
                workspace.Response.Data = streamCtx.Aggregate;
                workspace.Response.Length = streamCtx.AggregateCapacity;
                workspace.ResponseLength = streamCtx.AggregateLength;
                streamCtx.Aggregate = nullptr;
                parsed->Body = reinterpret_cast<const char*>(workspace.Response.Data);
                parsed->BodyLength = workspace.ResponseLength;
            }
            else {
                parsed->Body = nullptr;
                parsed->BodyLength = 0;
                workspace.ResponseLength = 0;
            }
            return STATUS_SUCCESS;
        }
    }

    _Must_inspect_result_
    ULONGLONG MakeResponseReadDeadline(ULONG timeoutMilliseconds) noexcept
    {
        return KeQueryInterruptTime() +
            (static_cast<ULONGLONG>(timeoutMilliseconds) * 10000ULL);
    }

    _Must_inspect_result_
    bool TryGetRemainingResponseReadTimeout(
        ULONGLONG deadline,
        _Out_ ULONG* timeoutMilliseconds) noexcept
    {
        if (timeoutMilliseconds == nullptr) {
            return false;
        }

        const ULONGLONG now = KeQueryInterruptTime();
        if (now >= deadline) {
            *timeoutMilliseconds = 0;
            return false;
        }

        const ULONGLONG remaining100ns = deadline - now;
        ULONGLONG remainingMilliseconds = (remaining100ns + 9999ULL) / 10000ULL;
        if (remainingMilliseconds == 0) {
            remainingMilliseconds = 1;
        }
        if (remainingMilliseconds > 0xffffffffULL) {
            remainingMilliseconds = 0xffffffffULL;
        }

        *timeoutMilliseconds = static_cast<ULONG>(remainingMilliseconds);
        return true;
    }

    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocketEx(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        bool responseBodyForbidden,
        bool preserveInformationalResponses,
        ULONG readTimeoutMilliseconds,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (parsed == nullptr ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr ||
            rawResponseLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *rawResponseLength = 0;
        SIZE_T responseLength = workspace.ResponseLength;
        const ULONGLONG responseReadDeadline = MakeResponseReadDeadline(readTimeoutMilliseconds);

        for (;;) {
            http1::HttpParseOptions parseOptions = {};
            parseOptions.Headers = responseHeaders;
            parseOptions.HeaderCapacity = headerCapacity;
            parseOptions.Trailers = responseTrailers;
            parseOptions.TrailerCapacity = trailerCapacity;
            parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
            parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
            parseOptions.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
            parseOptions.ScratchBodyCapacity = workspace.Request.Length;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;
            parseOptions.AcceptEncodingPolicy = acceptPolicy;
            parseOptions.ContentCodingMaterials = materials;

            NTSTATUS status = http1::HttpParser::ParseResponse(
                reinterpret_cast<const char*>(workspace.Response.Data),
                responseLength,
                parseOptions,
                *parsed);
            if (status == STATUS_SUCCESS) {
                if (preserveInformationalResponses) {
                    workspace.ResponseLength = responseLength;
                    *rawResponseLength = responseLength;
                    return STATUS_SUCCESS;
                }

                bool skippedInformational = false;
                status = DiscardNonFinalInformationalResponse(
                    workspace.Response.Data,
                    &responseLength,
                    *parsed,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (skippedInformational) {
                    workspace.ResponseLength = responseLength;
                    continue;
                }

                *rawResponseLength = responseLength;
                return STATUS_SUCCESS;
            }

            // Content decoding (gzip/deflate/br) and chunked transfer-decoding write into the
            // workspace DecodedBody buffer, which starts at WorkspaceDecodedBodyBytes. A decoded
            // body larger than the current buffer surfaces as STATUS_BUFFER_TOO_SMALL here. Grow the
            // buffer (bounded only when MaxResponseBytes is nonzero) and re-parse, mirroring the
            // HTTP/2 decode path.
            if (status == STATUS_BUFFER_TOO_SMALL) {
                status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                continue;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }

            if (workspace.MaxResponseBytes != 0 && responseLength >= workspace.MaxResponseBytes) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            if (responseLength == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            status = WorkspaceEnsureResponseCapacity(&workspace, responseLength + 1);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T received = 0;
            ULONG receiveTimeoutMilliseconds = WskOperationTimeoutMilliseconds;
            if (!TryGetRemainingResponseReadTimeout(responseReadDeadline, &receiveTimeoutMilliseconds)) {
                return STATUS_IO_TIMEOUT;
            }

            status = transport::TransportReceiveWithTimeout(transport,
                workspace.Response.Data + responseLength,
                workspace.Response.Length - responseLength,
                &received,
                receiveTimeoutMilliseconds);

            if (!NT_SUCCESS(status)) {
                if (!IsOrderlyConnectionCloseStatus(status)) {
                    return status;
                }
                if (responseLength == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                for (;;) {
                    parseOptions.MessageCompleteOnConnectionClose = true;
                    status = http1::HttpParser::ParseResponse(
                        reinterpret_cast<const char*>(workspace.Response.Data),
                        responseLength,
                        parseOptions,
                        *parsed);
                    if (status == STATUS_BUFFER_TOO_SMALL) {
                        status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                        continue;
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    if (preserveInformationalResponses) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        workspace.Response.Data,
                        &responseLength,
                        *parsed,
                        &skippedInformational);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (!skippedInformational) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
                    }
                }
            }

            if (received == 0) {
                if (responseLength == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                for (;;) {
                    parseOptions.MessageCompleteOnConnectionClose = true;
                    status = http1::HttpParser::ParseResponse(
                        reinterpret_cast<const char*>(workspace.Response.Data),
                        responseLength,
                        parseOptions,
                        *parsed);
                    if (status == STATUS_BUFFER_TOO_SMALL) {
                        status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                        continue;
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    if (preserveInformationalResponses) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        workspace.Response.Data,
                        &responseLength,
                        *parsed,
                        &skippedInformational);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (!skippedInformational) {
                        workspace.ResponseLength = responseLength;
                        *rawResponseLength = responseLength;
                        return STATUS_SUCCESS;
                    }
                }
            }

            responseLength += received;
            workspace.ResponseLength = responseLength;
        }
    }

    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocket(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        return ReadHttpResponseFromSocketEx(
            transport,
            workspace,
            responseBodyForbidden,
            false,
            WskOperationTimeoutMilliseconds,
            acceptPolicy,
            materials,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
    }

    _Must_inspect_result_
    NTSTATUS ReadHttpResponseFromSocketStreaming(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        ULONG bodyReadTimeoutMilliseconds,
        ULONG bodyIdleTimeoutMilliseconds,
        bool aggregateBody,
        _In_opt_ ResponseStartCallback responseStartCallback,
        _In_opt_ HeaderCallback headerCallback,
        _In_opt_ BodyCallback bodyCallback,
        _In_opt_ void* callbackContext,
        _Out_ bool* bodyDelivered,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (bodyDelivered != nullptr) {
            *bodyDelivered = false;
        }
        if (rawResponseLength != nullptr) {
            *rawResponseLength = 0;
        }
        if (transport == nullptr ||
            parsed == nullptr ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr ||
            rawResponseLength == nullptr ||
            bodyDelivered == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const ULONG perReadTimeout = bodyReadTimeoutMilliseconds == 0 ?
            WskOperationTimeoutMilliseconds :
            bodyReadTimeoutMilliseconds;
        const ULONG idleTimeout = bodyIdleTimeoutMilliseconds == 0 ?
            perReadTimeout :
            bodyIdleTimeoutMilliseconds;

        SIZE_T responseLength = workspace.ResponseLength;
        http1::HttpResponse headerParsed = {};
        SIZE_T contentLength = 0;
        for (;;) {
            http1::HttpParseOptions parseOptions = {};
            parseOptions.Headers = responseHeaders;
            parseOptions.HeaderCapacity = headerCapacity;
            parseOptions.Trailers = responseTrailers;
            parseOptions.TrailerCapacity = trailerCapacity;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;

            NTSTATUS status = http1::HttpParser::ParseResponseHeaders(
                reinterpret_cast<const char*>(workspace.Response.Data),
                responseLength,
                parseOptions,
                headerParsed,
                &contentLength);
            if (status == STATUS_SUCCESS) {
                if (IsNonFinalInformationalResponse(headerParsed)) {
                    if (headerParsed.BytesConsumed > responseLength) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T remaining = responseLength - headerParsed.BytesConsumed;
                    if (remaining != 0) {
                        RtlMoveMemory(
                            workspace.Response.Data,
                            workspace.Response.Data + headerParsed.BytesConsumed,
                            remaining);
                    }
                    responseLength = remaining;
                    workspace.ResponseLength = responseLength;
                    headerParsed = {};
                    contentLength = 0;
                    continue;
                }
                break;
            }
            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                return status;
            }
            if (responseLength >= HttpMaxHeaderBytes + 4) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            status = WorkspaceEnsureResponseCapacity(&workspace, responseLength + 4096);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            SIZE_T received = 0;
            status = transport::TransportReceiveWithTimeout(
                transport,
                workspace.Response.Data + responseLength,
                workspace.Response.Length - responseLength,
                &received,
                perReadTimeout);
            if (!NT_SUCCESS(status)) {
                if (IsOrderlyConnectionCloseStatus(status)) {
                    return responseLength == 0 ? STATUS_CONNECTION_DISCONNECTED : status;
                }
                return status;
            }
            if (received == 0) {
                return responseLength == 0 ?
                    STATUS_CONNECTION_DISCONNECTED :
                    STATUS_INVALID_NETWORK_RESPONSE;
            }
            responseLength += received;
            workspace.ResponseLength = responseLength;
        }

        *parsed = headerParsed;
        const SIZE_T headerBytes = headerParsed.BytesConsumed;
        if (headerBytes > responseLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        // Non-identity CE requires full-buffer decode after transfer-coding is complete.
        // Accumulate TE-decoded body without live user callbacks, then decode + deliver.
        const bool needsContentDecode =
            ResponseHasNonIdentityContentEncoding(headerParsed) &&
            headerParsed.BodyKind != http1::HttpBodyKind::None;

        if (responseStartCallback != nullptr) {
            const NTSTATUS startStatus = responseStartCallback(
                callbackContext,
                headerParsed.StatusCode);
            if (!NT_SUCCESS(startStatus)) {
                return startStatus;
            }
        }
        if (headerCallback != nullptr) {
            for (SIZE_T index = 0; index < headerParsed.HeaderCount; ++index) {
                const http1::HttpHeader& header = headerParsed.Headers[index];
                const NTSTATUS headerStatus = headerCallback(
                    callbackContext,
                    header.Name.Data,
                    header.Name.Length,
                    header.Value.Data,
                    header.Value.Length);
                if (!NT_SUCCESS(headerStatus)) {
                    return headerStatus;
                }
            }
            parsed->HeadersDeliveredViaCallback = true;
        }

        // Kernel system-thread stacks are small. Never put the 16 KiB receive window
        // (or HttpChunkedDecoder's multi-KiB trailer buffers) on the stack.
        constexpr SIZE_T kWindowCapacity = 16 * 1024;
        struct StreamingBodyResources final
        {
            UCHAR* Window = nullptr;
            http1::HttpChunkedDecoder* Decoder = nullptr;
            StreamAggregateContext StreamCtx = {};

            ~StreamingBodyResources() noexcept
            {
                FreeNonPagedPoolBytes(StreamCtx.Aggregate);
                StreamCtx.Aggregate = nullptr;
                delete Decoder;
                Decoder = nullptr;
                FreeNonPagedPoolBytes(Window);
                Window = nullptr;
            }
        };

        if (headerParsed.BodyKind == http1::HttpBodyKind::None) {
            if (bodyCallback != nullptr) {
                const NTSTATUS status = bodyCallback(callbackContext, nullptr, 0, true);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                *bodyDelivered = true;
            }
            *rawResponseLength = headerBytes;
            workspace.ResponseLength = 0;
            return STATUS_SUCCESS;
        }

        StreamingBodyResources resources = {};
        resources.Window = static_cast<UCHAR*>(AllocateNonPagedPoolBytes(kWindowCapacity));
        if (resources.Window == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T windowLength = 0;
        SIZE_T workspaceBodyOffset = headerBytes;
        SIZE_T workspaceBodyRemaining = responseLength - headerBytes;
        UCHAR* const window = resources.Window;

        // CE path: force internal aggregation and suppress live user body callbacks so
        // compressed wire bytes never leak to OnBody. Identity path keeps prior semantics.
        resources.StreamCtx.UserCallback = needsContentDecode ? nullptr : bodyCallback;
        resources.StreamCtx.UserContext = callbackContext;
        resources.StreamCtx.DoAggregate = needsContentDecode || aggregateBody;
        resources.StreamCtx.MaxAggregateBytes = workspace.MaxResponseBytes;

        // Content-Length path
        if (headerParsed.BodyKind == http1::HttpBodyKind::ContentLength) {
            SIZE_T remaining = contentLength;
            windowLength = 0;
            workspaceBodyOffset = headerBytes;
            workspaceBodyRemaining = responseLength - headerBytes;

            while (remaining != 0) {
                if (windowLength == 0 && workspaceBodyRemaining != 0) {
                    const SIZE_T take = workspaceBodyRemaining < kWindowCapacity ?
                        workspaceBodyRemaining : kWindowCapacity;
                    RtlCopyMemory(
                        window,
                        workspace.Response.Data + workspaceBodyOffset,
                        take);
                    windowLength = take;
                    workspaceBodyOffset += take;
                    workspaceBodyRemaining -= take;
                }
                if (windowLength == 0) {
                    SIZE_T received = 0;
                    NTSTATUS status = StreamReceiveMore(
                        transport,
                        window,
                        kWindowCapacity,
                        &windowLength,
                        idleTimeout,
                        &received);
                    if (!NT_SUCCESS(status) || received == 0) {
                        return STATUS_CONNECTION_DISCONNECTED;
                    }
                }

                const SIZE_T take = windowLength < remaining ? windowLength : remaining;
                NTSTATUS status = StreamBodyOnData(&resources.StreamCtx, window, take);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (take < windowLength) {
                    RtlMoveMemory(window, window + take, windowLength - take);
                }
                windowLength -= take;
                remaining -= take;
            }

            *rawResponseLength = headerBytes + contentLength;
            return FinalizeStreamingBody(
                resources.StreamCtx,
                workspace,
                parsed,
                aggregateBody,
                needsContentDecode,
                responseHeaders,
                headerParsed.HeaderCount,
                acceptPolicy,
                materials,
                bodyCallback,
                callbackContext,
                bodyDelivered);
        }

        if (headerParsed.BodyKind == http1::HttpBodyKind::Chunked) {
            // HttpChunkedDecoder embeds multi-KiB trailer buffers; keep it off the stack.
            resources.Decoder = new http1::HttpChunkedDecoder();
            if (resources.Decoder == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            resources.Decoder->SetTrailerStorage(responseTrailers, trailerCapacity);
            windowLength = 0;
            workspaceBodyOffset = headerBytes;
            workspaceBodyRemaining = responseLength - headerBytes;

            for (;;) {
                if (windowLength == 0 && workspaceBodyRemaining != 0) {
                    const SIZE_T take = workspaceBodyRemaining < kWindowCapacity ?
                        workspaceBodyRemaining : kWindowCapacity;
                    RtlCopyMemory(
                        window,
                        workspace.Response.Data + workspaceBodyOffset,
                        take);
                    windowLength = take;
                    workspaceBodyOffset += take;
                    workspaceBodyRemaining -= take;
                }
                if (windowLength == 0) {
                    SIZE_T received = 0;
                    NTSTATUS status = StreamReceiveMore(
                        transport,
                        window,
                        kWindowCapacity,
                        &windowLength,
                        idleTimeout,
                        &received);
                    if (!NT_SUCCESS(status) || received == 0) {
                        return STATUS_CONNECTION_DISCONNECTED;
                    }
                }

                SIZE_T consumed = 0;
                NTSTATUS status = resources.Decoder->Feed(
                    reinterpret_cast<const char*>(window),
                    windowLength,
                    &consumed,
                    StreamBodyOnData,
                    &resources.StreamCtx);
                if (consumed != 0) {
                    if (consumed < windowLength) {
                        RtlMoveMemory(window, window + consumed, windowLength - consumed);
                    }
                    windowLength -= consumed;
                }
                if (status == STATUS_SUCCESS) {
                    parsed->Trailers = responseTrailers;
                    parsed->TrailerCount = resources.Decoder->TrailerCount();
                    *rawResponseLength = headerBytes;
                    return FinalizeStreamingBody(
                        resources.StreamCtx,
                        workspace,
                        parsed,
                        aggregateBody,
                        needsContentDecode,
                        responseHeaders,
                        headerParsed.HeaderCount,
                        acceptPolicy,
                        materials,
                        bodyCallback,
                        callbackContext,
                        bodyDelivered);
                }
                if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                    return status;
                }
            }
        }

        // Close-delimited.
        windowLength = 0;
        workspaceBodyOffset = headerBytes;
        workspaceBodyRemaining = responseLength - headerBytes;
        for (;;) {
            if (windowLength == 0 && workspaceBodyRemaining != 0) {
                const SIZE_T take = workspaceBodyRemaining < kWindowCapacity ?
                    workspaceBodyRemaining : kWindowCapacity;
                RtlCopyMemory(
                    window,
                    workspace.Response.Data + workspaceBodyOffset,
                    take);
                windowLength = take;
                workspaceBodyOffset += take;
                workspaceBodyRemaining -= take;
            }
            if (windowLength != 0) {
                NTSTATUS status = StreamBodyOnData(&resources.StreamCtx, window, windowLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                windowLength = 0;
                continue;
            }

            SIZE_T received = 0;
            NTSTATUS status = StreamReceiveMore(
                transport,
                window,
                kWindowCapacity,
                &windowLength,
                idleTimeout,
                &received);
            if (!NT_SUCCESS(status) || received == 0) {
                parsed->BodyEndsOnConnectionClose = true;
                *rawResponseLength = headerBytes;
                return FinalizeStreamingBody(
                    resources.StreamCtx,
                    workspace,
                    parsed,
                    aggregateBody,
                    needsContentDecode,
                    responseHeaders,
                    headerParsed.HeaderCount,
                    acceptPolicy,
                    materials,
                    bodyCallback,
                    callbackContext,
                    bodyDelivered);
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestBufferWithExpect(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        ULONG expectContinueTimeoutMilliseconds,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        SIZE_T bodyOffset = 0;
        if (!FindHttpRequestBodyOffset(requestBytes, requestLength, &bodyOffset)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = SendTransportSegment(transport, requestBytes, bodyOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        workspace.ResponseLength = 0;
        ULONG informationalCount = 0;
        for (;;) {
            status = ReadHttpResponseFromSocketEx(
                transport,
                workspace,
                responseBodyForbidden,
                true,
                expectContinueTimeoutMilliseconds,
                acceptPolicy,
                materials,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength);

            if (!NT_SUCCESS(status) || !IsNonFinalInformationalResponse(*parsed) || parsed->StatusCode == 100) {
                break;
            }

            if (informationalCount >= 16) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++informationalCount;

            bool skippedInformational = false;
            SIZE_T bufferedLength = workspace.ResponseLength;
            status = DiscardNonFinalInformationalResponse(
                workspace.Response.Data,
                &bufferedLength,
                *parsed,
                &skippedInformational);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!skippedInformational) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            workspace.ResponseLength = bufferedLength;
            *parsed = {};
            *rawResponseLength = 0;
        }

        if (NT_SUCCESS(status)) {
            if (parsed->StatusCode == 100) {
                bool skippedInformational = false;
                SIZE_T bufferedLength = workspace.ResponseLength;
                status = DiscardNonFinalInformationalResponse(
                    workspace.Response.Data,
                    &bufferedLength,
                    *parsed,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (!skippedInformational) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                workspace.ResponseLength = bufferedLength;
                *parsed = {};
                *rawResponseLength = 0;

                status = SendTransportSegment(
                    transport,
                    requestBytes + bodyOffset,
                    requestLength - bodyOffset);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return ReadHttpResponseFromSocket(
                    transport,
                    workspace,
                    responseBodyForbidden,
                    acceptPolicy,
                    materials,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }

            return STATUS_SUCCESS;
        }

        if (status != STATUS_IO_TIMEOUT) {
            return status;
        }

        status = SendTransportSegment(
            transport,
            requestBytes + bodyOffset,
            requestLength - bodyOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *parsed = {};
        *rawResponseLength = 0;
        return ReadHttpResponseFromSocket(
            transport,
            workspace,
            responseBodyForbidden,
            acceptPolicy,
            materials,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
    }

    _Must_inspect_result_
    NTSTATUS SendHttp1RequestSourceWithExpect(
        _Inout_ transport::Transport* transport,
        _Inout_ Workspace& workspace,
        _In_ const Request& request,
        _In_reads_bytes_(requestLength) const UCHAR* requestBytes,
        SIZE_T requestLength,
        ULONG expectContinueTimeoutMilliseconds,
        bool responseBodyForbidden,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        NTSTATUS status = SendTransportSegment(transport, requestBytes, requestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        workspace.ResponseLength = 0;
        ULONG informationalCount = 0;
        for (;;) {
            status = ReadHttpResponseFromSocketEx(
                transport,
                workspace,
                responseBodyForbidden,
                true,
                expectContinueTimeoutMilliseconds,
                acceptPolicy,
                materials,
                parsed,
                responseHeaders,
                headerCapacity,
                responseTrailers,
                trailerCapacity,
                rawResponseLength);

            if (!NT_SUCCESS(status) || !IsNonFinalInformationalResponse(*parsed) || parsed->StatusCode == 100) {
                break;
            }

            if (informationalCount >= 16) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ++informationalCount;

            bool skippedInformational = false;
            SIZE_T bufferedLength = workspace.ResponseLength;
            status = DiscardNonFinalInformationalResponse(
                workspace.Response.Data,
                &bufferedLength,
                *parsed,
                &skippedInformational);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!skippedInformational) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            workspace.ResponseLength = bufferedLength;
            *parsed = {};
            *rawResponseLength = 0;
        }

        if (NT_SUCCESS(status)) {
            if (parsed->StatusCode == 100) {
                bool skippedInformational = false;
                SIZE_T bufferedLength = workspace.ResponseLength;
                status = DiscardNonFinalInformationalResponse(
                    workspace.Response.Data,
                    &bufferedLength,
                    *parsed,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (!skippedInformational) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                workspace.ResponseLength = bufferedLength;
                *parsed = {};
                *rawResponseLength = 0;

                status = SendHttp1RequestBodySource(transport, request, workspace);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return ReadHttpResponseFromSocket(
                    transport,
                    workspace,
                    responseBodyForbidden,
                    acceptPolicy,
                    materials,
                    parsed,
                    responseHeaders,
                    headerCapacity,
                    responseTrailers,
                    trailerCapacity,
                    rawResponseLength);
            }

            return STATUS_SUCCESS;
        }

        if (status != STATUS_IO_TIMEOUT) {
            return status;
        }

        status = SendHttp1RequestBodySource(transport, request, workspace);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *parsed = {};
        *rawResponseLength = 0;
        return ReadHttpResponseFromSocket(
            transport,
            workspace,
            responseBodyForbidden,
            acceptPolicy,
            materials,
            parsed,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            rawResponseLength);
    }
#endif

}
}

