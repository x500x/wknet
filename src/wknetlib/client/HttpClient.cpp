#include "client/HttpClient.h"
#include "rtl/Irql.h"

namespace wknet
{
namespace client
{
    namespace
    {
        _Must_inspect_result_
        bool IsNonFinalInformationalResponse(const http1::HttpResponse& response) noexcept
        {
            return response.StatusCode >= 100 &&
                response.StatusCode < 200 &&
                response.StatusCode != 101;
        }

        _Must_inspect_result_
        NTSTATUS DiscardNonFinalInformationalResponse(
            _Inout_updates_bytes_(*responseLength) char* responseBuffer,
            _Inout_ SIZE_T* responseLength,
            _Inout_ http1::HttpResponse& response,
            _Out_ bool* skipped) noexcept
        {
            if (skipped != nullptr) {
                *skipped = false;
            }
            if (responseBuffer == nullptr || responseLength == nullptr || skipped == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            if (!IsNonFinalInformationalResponse(response)) {
                return STATUS_SUCCESS;
            }
            if (response.BytesConsumed > *responseLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T remaining = *responseLength - response.BytesConsumed;
            if (remaining != 0) {
                RtlMoveMemory(responseBuffer, responseBuffer + response.BytesConsumed, remaining);
            }
            *responseLength = remaining;
            response = {};
            *skipped = true;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS HttpClient::SendRequest(
        net::WskClient& wskClient,
        const HttpRequestOptions& options,
        const HttpResponseBuffers& buffers,
        http1::HttpResponse& response) noexcept
    {
        response = {};

        NTSTATUS status = core::CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (options.ServerName == nullptr ||
            options.ServerName[0] == L'\0' ||
            options.ServiceName == nullptr ||
            options.ServiceName[0] == L'\0' ||
            buffers.RequestBuffer == nullptr ||
            buffers.RequestBufferLength == 0 ||
            buffers.ResponseBuffer == nullptr ||
            buffers.ResponseBufferLength == 0 ||
            buffers.Headers == nullptr ||
            buffers.HeaderCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T requestLength = 0;
        status = http1::HttpRequestBuilder::Build(
            options.Request,
            buffers.RequestBuffer,
            buffers.RequestBufferLength,
            &requestLength);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("HttpClient build request failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapObject<SOCKADDR_STORAGE> remoteAddress;
        if (!remoteAddress.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = wskClient.Resolve(options.ServerName, options.ServiceName, remoteAddress.Get());
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("HttpClient resolve failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapObject<net::WskSocket> socket;
        if (!socket.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = socket->Connect(wskClient, reinterpret_cast<const SOCKADDR*>(remoteAddress.Get()));
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("HttpClient connect failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        SIZE_T sent = 0;
        status = socket->Send(buffers.RequestBuffer, requestLength, &sent);
        if (NT_SUCCESS(status) && sent != requestLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("HttpClient send failed: 0x%08X sent=%Iu expected=%Iu\r\n",
                static_cast<ULONG>(status),
                sent,
                requestLength);
        }

        if (NT_SUCCESS(status)) {
            status = ReadHttpResponse(*socket.Get(), options.ResponseBodyForbidden, buffers, response);
            if (!NT_SUCCESS(status)) {
                WKNET_DBG_PRINT("HttpClient read response failed: 0x%08X\r\n", static_cast<ULONG>(status));
            }
        }

        const NTSTATUS closeStatus = socket->Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }

    NTSTATUS HttpClient::ReadHttpResponse(
        net::WskSocket& socket,
        bool responseBodyForbidden,
        const HttpResponseBuffers& buffers,
        http1::HttpResponse& response) noexcept
    {
        SIZE_T responseLength = 0;

        for (;;) {
            http1::HttpParseOptions parseOptions = {};
            parseOptions.Headers = buffers.Headers;
            parseOptions.HeaderCapacity = buffers.HeaderCapacity;
            parseOptions.DecodedBody = buffers.DecodedBodyBuffer;
            parseOptions.DecodedBodyCapacity = buffers.DecodedBodyBufferLength;
            parseOptions.ScratchBody = buffers.ScratchBodyBuffer;
            parseOptions.ScratchBodyCapacity = buffers.ScratchBodyBufferLength;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;

            NTSTATUS status = http1::HttpParser::ParseResponse(
                buffers.ResponseBuffer,
                responseLength,
                parseOptions,
                response);
            if (status == STATUS_SUCCESS) {
                bool skippedInformational = false;
                status = DiscardNonFinalInformationalResponse(
                    buffers.ResponseBuffer,
                    &responseLength,
                    response,
                    &skippedInformational);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (skippedInformational) {
                    continue;
                }
                return STATUS_SUCCESS;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
                WKNET_DBG_PRINT("HttpClient parse response failed: 0x%08X bytes=%Iu\r\n",
                    static_cast<ULONG>(status),
                    responseLength);
                return status;
            }

            if (responseLength >= buffers.ResponseBufferLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T received = 0;
            status = socket.Receive(
                buffers.ResponseBuffer + responseLength,
                buffers.ResponseBufferLength - responseLength,
                &received);
            if (!NT_SUCCESS(status)) {
                if (status != STATUS_CONNECTION_DISCONNECTED) {
                    WKNET_DBG_PRINT("HttpClient receive failed: 0x%08X bytes=%Iu\r\n",
                        static_cast<ULONG>(status),
                        responseLength);
                    return status;
                }

                parseOptions.MessageCompleteOnConnectionClose = true;
                for (;;) {
                    status = http1::HttpParser::ParseResponse(
                        buffers.ResponseBuffer,
                        responseLength,
                        parseOptions,
                        response);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        buffers.ResponseBuffer,
                        &responseLength,
                        response,
                        &skippedInformational);
                    if (!NT_SUCCESS(status) || !skippedInformational) {
                        return status;
                    }
                }
            }

            if (received == 0) {
                parseOptions.MessageCompleteOnConnectionClose = true;
                for (;;) {
                    status = http1::HttpParser::ParseResponse(
                        buffers.ResponseBuffer,
                        responseLength,
                        parseOptions,
                        response);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    bool skippedInformational = false;
                    status = DiscardNonFinalInformationalResponse(
                        buffers.ResponseBuffer,
                        &responseLength,
                        response,
                        &skippedInformational);
                    if (!NT_SUCCESS(status) || !skippedInformational) {
                        return status;
                    }
                }
            }

            responseLength += received;
        }
    }
}
}
