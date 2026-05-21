#include "client/HttpClient.h"

namespace KernelHttp
{
namespace client
{
    NTSTATUS HttpClient::SendRequest(
        net::WskClient& wskClient,
        const HttpRequestOptions& options,
        const HttpResponseBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        response = {};

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
        NTSTATUS status = http::HttpRequestBuilder::Build(
            options.Request,
            buffers.RequestBuffer,
            buffers.RequestBufferLength,
            &requestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SOCKADDR_STORAGE remoteAddress = {};
        status = wskClient.Resolve(options.ServerName, options.ServiceName, &remoteAddress);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        net::WskSocket socket;
        status = socket.Connect(wskClient, reinterpret_cast<const SOCKADDR*>(&remoteAddress));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T sent = 0;
        status = socket.Send(buffers.RequestBuffer, requestLength, &sent);
        if (NT_SUCCESS(status) && sent != requestLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }

        if (NT_SUCCESS(status)) {
            status = ReadHttpResponse(socket, buffers, response);
        }

        const NTSTATUS closeStatus = socket.Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }

    NTSTATUS HttpClient::ReadHttpResponse(
        net::WskSocket& socket,
        const HttpResponseBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        SIZE_T responseLength = 0;

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = buffers.Headers;
            parseOptions.HeaderCapacity = buffers.HeaderCapacity;
            parseOptions.DecodedBody = buffers.DecodedBodyBuffer;
            parseOptions.DecodedBodyCapacity = buffers.DecodedBodyBufferLength;

            NTSTATUS status = http::HttpParser::ParseResponse(
                buffers.ResponseBuffer,
                responseLength,
                parseOptions,
                response);
            if (status == STATUS_SUCCESS) {
                return STATUS_SUCCESS;
            }

            if (status != STATUS_MORE_PROCESSING_REQUIRED) {
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
                    return status;
                }

                parseOptions.MessageCompleteOnConnectionClose = true;
                return http::HttpParser::ParseResponse(
                    buffers.ResponseBuffer,
                    responseLength,
                    parseOptions,
                    response);
            }

            if (received == 0) {
                parseOptions.MessageCompleteOnConnectionClose = true;
                return http::HttpParser::ParseResponse(
                    buffers.ResponseBuffer,
                    responseLength,
                    parseOptions,
                    response);
            }

            responseLength += received;
        }
    }
}
}
