#include "session/HttpEngineInternal.hpp"

namespace wknet
{
namespace session
{
    _Must_inspect_result_
    NTSTATUS CreateOwnedResponse(
        const http1::HttpResponse& parsed,
        const char* rawResponse,
        SIZE_T rawResponseLength,
        _Out_ ResponseHandle* response) noexcept
    {
        if (response != nullptr) {
            *response = nullptr;
        }

        if (response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ResponseHandle newResponse = AllocateResponseHandle();
        if (newResponse == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newResponse->Header = { HandleKind::Response, 0, nullptr };
        newResponse->StatusCode = parsed.StatusCode;
        newResponse->InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeEvent(&newResponse->DrainEvent, NotificationEvent, TRUE);
#endif

        if (rawResponse != nullptr && rawResponseLength != 0) {
            newResponse->RawResponse = AllocateTextCopy(rawResponse, rawResponseLength);
            if (newResponse->RawResponse == nullptr) {
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newResponse->RawResponseLength = rawResponseLength;
        }

        if (parsed.Body != nullptr && parsed.BodyLength != 0) {
            newResponse->Body = AllocateBytesCopy(
                reinterpret_cast<const UCHAR*>(parsed.Body),
                parsed.BodyLength);
            if (newResponse->Body == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            newResponse->BodyLength = parsed.BodyLength;
        }

        if (parsed.HeaderCount != 0) {
            newResponse->Headers = static_cast<http1::HttpHeader*>(
                AllocateApiMemory(sizeof(http1::HttpHeader) * parsed.HeaderCount));
            if (newResponse->Headers == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T nameStorageLength = 0;
            SIZE_T valueStorageLength = 0;
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                nameStorageLength += parsed.Headers[index].Name.Length;
                valueStorageLength += parsed.Headers[index].Value.Length;
            }

            if (nameStorageLength != 0) {
                newResponse->HeaderNameStorage = static_cast<char*>(AllocateApiMemory(nameStorageLength));
                if (newResponse->HeaderNameStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->HeaderNameStorageLength = nameStorageLength;
            }

            if (valueStorageLength != 0) {
                newResponse->HeaderValueStorage = static_cast<char*>(AllocateApiMemory(valueStorageLength));
                if (newResponse->HeaderValueStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->HeaderValueStorageLength = valueStorageLength;
            }

            SIZE_T nameOffset = 0;
            SIZE_T valueOffset = 0;
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                const http1::HttpHeader& source = parsed.Headers[index];
                if (source.Name.Length != 0) {
                    RtlCopyMemory(
                        newResponse->HeaderNameStorage + nameOffset,
                        source.Name.Data,
                        source.Name.Length);
                    newResponse->Headers[index].Name.Data = newResponse->HeaderNameStorage + nameOffset;
                    newResponse->Headers[index].Name.Length = source.Name.Length;
                    nameOffset += source.Name.Length;
                }

                if (source.Value.Length != 0) {
                    RtlCopyMemory(
                        newResponse->HeaderValueStorage + valueOffset,
                        source.Value.Data,
                        source.Value.Length);
                    newResponse->Headers[index].Value.Data = newResponse->HeaderValueStorage + valueOffset;
                    newResponse->Headers[index].Value.Length = source.Value.Length;
                    valueOffset += source.Value.Length;
                }
            }
            newResponse->HeaderCount = parsed.HeaderCount;
        }

        if (parsed.TrailerCount != 0) {
            newResponse->Trailers = static_cast<http1::HttpHeader*>(
                AllocateApiMemory(sizeof(http1::HttpHeader) * parsed.TrailerCount));
            if (newResponse->Trailers == nullptr) {
                ReleaseResponseStorage(*newResponse);
                FreeHandle(newResponse);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T nameStorageLength = 0;
            SIZE_T valueStorageLength = 0;
            for (SIZE_T index = 0; index < parsed.TrailerCount; ++index) {
                nameStorageLength += parsed.Trailers[index].Name.Length;
                valueStorageLength += parsed.Trailers[index].Value.Length;
            }

            if (nameStorageLength != 0) {
                newResponse->TrailerNameStorage = static_cast<char*>(AllocateApiMemory(nameStorageLength));
                if (newResponse->TrailerNameStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->TrailerNameStorageLength = nameStorageLength;
            }

            if (valueStorageLength != 0) {
                newResponse->TrailerValueStorage = static_cast<char*>(AllocateApiMemory(valueStorageLength));
                if (newResponse->TrailerValueStorage == nullptr) {
                    ReleaseResponseStorage(*newResponse);
                    FreeHandle(newResponse);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                newResponse->TrailerValueStorageLength = valueStorageLength;
            }

            SIZE_T nameOffset = 0;
            SIZE_T valueOffset = 0;
            for (SIZE_T index = 0; index < parsed.TrailerCount; ++index) {
                const http1::HttpHeader& source = parsed.Trailers[index];
                if (source.Name.Length != 0) {
                    RtlCopyMemory(
                        newResponse->TrailerNameStorage + nameOffset,
                        source.Name.Data,
                        source.Name.Length);
                    newResponse->Trailers[index].Name.Data = newResponse->TrailerNameStorage + nameOffset;
                    newResponse->Trailers[index].Name.Length = source.Name.Length;
                    nameOffset += source.Name.Length;
                }

                if (source.Value.Length != 0) {
                    RtlCopyMemory(
                        newResponse->TrailerValueStorage + valueOffset,
                        source.Value.Data,
                        source.Value.Length);
                    newResponse->Trailers[index].Value.Data = newResponse->TrailerValueStorage + valueOffset;
                    newResponse->Trailers[index].Value.Length = source.Value.Length;
                    valueOffset += source.Value.Length;
                }
            }
            newResponse->TrailerCount = parsed.TrailerCount;
        }

        NTSTATUS status = RegisterActiveResponseHandle(newResponse);
        if (!NT_SUCCESS(status)) {
            ReleaseResponseStorage(*newResponse);
            FreeHandle(newResponse);
            return status;
        }

        *response = newResponse;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS InvokeResponseCallbacks(
        const HttpSendOptions& options,
        const http1::HttpResponse& parsed) noexcept
    {
        if (options.HeaderCallback != nullptr) {
            for (SIZE_T index = 0; index < parsed.HeaderCount; ++index) {
                const http1::HttpHeader& header = parsed.Headers[index];
                NTSTATUS status = options.HeaderCallback(
                    options.CallbackContext,
                    header.Name.Data,
                    header.Name.Length,
                    header.Value.Data,
                    header.Value.Length);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }

        if (options.BodyCallback != nullptr) {
            return options.BodyCallback(
                options.CallbackContext,
                reinterpret_cast<const UCHAR*>(parsed.Body),
                parsed.BodyLength,
                true);
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool IsNonFinalInformationalResponse(const http1::HttpResponse& parsed) noexcept
    {
        return parsed.StatusCode >= 100 &&
            parsed.StatusCode < 200 &&
            parsed.StatusCode != 101;
    }

    _Must_inspect_result_
    NTSTATUS DiscardNonFinalInformationalResponse(
        _Inout_updates_bytes_(*responseLength) UCHAR* responseBuffer,
        _Inout_ SIZE_T* responseLength,
        _Inout_ http1::HttpResponse& parsed,
        _Out_ bool* skipped) noexcept
    {
        if (skipped != nullptr) {
            *skipped = false;
        }
        if (responseBuffer == nullptr || responseLength == nullptr || skipped == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!IsNonFinalInformationalResponse(parsed)) {
            return STATUS_SUCCESS;
        }
        if (parsed.BytesConsumed > *responseLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T remaining = *responseLength - parsed.BytesConsumed;
        if (remaining != 0) {
            RtlMoveMemory(responseBuffer, responseBuffer + parsed.BytesConsumed, remaining);
        }
        *responseLength = remaining;
        parsed = {};
        *skipped = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseResponseBytes(
        Workspace& workspace,
        SIZE_T responseLength,
        bool messageCompleteOnConnectionClose,
        _In_opt_ const http1::HttpAcceptEncodingPolicy* acceptPolicy,
        _In_opt_ const codec::DecodeMaterials* materials,
        _Out_ http1::HttpResponse* parsed,
        _Out_writes_(headerCapacity) http1::HttpHeader* headers,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* trailers,
        SIZE_T trailerCapacity) noexcept
    {
        if (parsed == nullptr || headers == nullptr || trailers == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        http1::HttpParseOptions parseOptions = {};
        parseOptions.Headers = headers;
        parseOptions.HeaderCapacity = headerCapacity;
        parseOptions.Trailers = trailers;
        parseOptions.TrailerCapacity = trailerCapacity;
        parseOptions.DecodedBody = reinterpret_cast<char*>(workspace.DecodedBody.Data);
        parseOptions.DecodedBodyCapacity = workspace.DecodedBody.Length;
        parseOptions.ScratchBody = reinterpret_cast<char*>(workspace.Request.Data);
        parseOptions.ScratchBodyCapacity = workspace.Request.Length;
        parseOptions.MessageCompleteOnConnectionClose = messageCompleteOnConnectionClose;
        parseOptions.AcceptEncodingPolicy = acceptPolicy;
        parseOptions.ContentCodingMaterials = materials;

        SIZE_T parseLength = responseLength;
        for (;;) {
            NTSTATUS status = http1::HttpParser::ParseResponse(
                reinterpret_cast<const char*>(workspace.Response.Data),
                parseLength,
                parseOptions,
                *parsed);
            if (status == STATUS_BUFFER_TOO_SMALL) {
                status = GrowDecodedBodyAfterBufferTooSmall(workspace);
                if (!NT_SUCCESS(status)) {
                    workspace.ResponseLength = parseLength;
                    return status;
                }
                RefreshResponseParseDecodedBuffers(workspace, parseOptions);
                continue;
            }
            if (status != STATUS_SUCCESS) {
                workspace.ResponseLength = parseLength;
                return status;
            }

            bool skipped = false;
            status = DiscardNonFinalInformationalResponse(
                workspace.Response.Data,
                &parseLength,
                *parsed,
                &skipped);
            if (!NT_SUCCESS(status)) {
                workspace.ResponseLength = parseLength;
                return status;
            }
            if (!skipped) {
                workspace.ResponseLength = parseLength;
                return STATUS_SUCCESS;
            }
        }
    }

    bool IsHttpConnectionReusable(
        _In_ const http1::HttpResponse& parsed,
        SIZE_T rawResponseLength) noexcept
    {
        if (parsed.StatusCode == 101 ||
            parsed.BodyEndsOnConnectionClose ||
            parsed.HasConnectionClose() ||
            parsed.BytesConsumed != rawResponseLength ||
            parsed.MajorVersion != 1) {
            return false;
        }

        if (parsed.MinorVersion == 0) {
            return parsed.HasConnectionKeepAlive();
        }

        return parsed.MinorVersion == 1;
    }

    _Must_inspect_result_
    NTSTATUS LoadHttp1PipelineBufferedBytes(
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection* pooledConnection,
        _Inout_ Workspace& workspace) noexcept
    {
        if (connectionPool == nullptr || pooledConnection == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        workspace.ResponseLength = 0;
        SIZE_T bufferedLength = 0;
        NTSTATUS status = ConnectionPoolHttp1PipelineBufferedLength(
            connectionPool,
            pooledConnection,
            &bufferedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (bufferedLength == 0) {
            return STATUS_SUCCESS;
        }

        status = WorkspaceEnsureResponseCapacity(&workspace, bufferedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T copied = 0;
        status = ConnectionPoolTakeHttp1PipelineBufferedBytes(
            connectionPool,
            pooledConnection,
            workspace.Response.Data,
            workspace.Response.Length,
            &copied);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        workspace.ResponseLength = copied;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS PreserveHttp1PipelineTrailingBytes(
        _Inout_ ConnectionPool* connectionPool,
        _Inout_ PooledConnection* pooledConnection,
        _Inout_ Workspace& workspace,
        _In_ const http1::HttpResponse& parsed,
        _Out_ SIZE_T* rawResponseLength) noexcept
    {
        if (connectionPool == nullptr ||
            pooledConnection == nullptr ||
            rawResponseLength == nullptr ||
            parsed.BytesConsumed > workspace.ResponseLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T consumed = parsed.BytesConsumed;
        const SIZE_T trailingLength = workspace.ResponseLength - consumed;
        if (trailingLength != 0) {
            NTSTATUS status = ConnectionPoolStoreHttp1PipelineBufferedBytes(
                connectionPool,
                pooledConnection,
                workspace.Response.Data + consumed,
                trailingLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        workspace.ResponseLength = consumed;
        *rawResponseLength = consumed;
        return STATUS_SUCCESS;
    }

}
}

