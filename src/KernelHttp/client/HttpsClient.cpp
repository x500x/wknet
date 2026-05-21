#include "client/HttpsClient.h"

namespace KernelHttp
{
namespace client
{
    NTSTATUS HttpsClient::SendRequest(
        net::WskClient& wskClient,
        const HttpsRequestOptions& options,
        const HttpsResponseBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        response = {};

        if (options.RemoteAddress == nullptr ||
            options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            options.CertificateStore == nullptr ||
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

        net::WskSocket socket;
        status = socket.Connect(wskClient, options.RemoteAddress);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        tls::TlsConnection tls;
        tls::TlsClientConnectionOptions tlsOptions = {};
        tlsOptions.ServerName = options.ServerName;
        tlsOptions.ServerNameLength = options.ServerNameLength;
        tlsOptions.CertificateStore = options.CertificateStore;

        status = tls.Connect(socket, tlsOptions);
        if (!NT_SUCCESS(status)) {
            const NTSTATUS closeStatus = socket.Close();
            UNREFERENCED_PARAMETER(closeStatus);
            return status;
        }

        SIZE_T sent = 0;
        status = tls.Send(socket, buffers.RequestBuffer, requestLength, &sent);
        if (NT_SUCCESS(status) && sent != requestLength) {
            status = STATUS_CONNECTION_DISCONNECTED;
        }

        if (NT_SUCCESS(status)) {
            status = ReadHttpResponse(socket, tls, options.ResponseBodyForbidden, buffers, response);
        }

        const NTSTATUS closeStatus = socket.Close();
        UNREFERENCED_PARAMETER(closeStatus);
        return status;
    }

    NTSTATUS HttpsClient::ReadHttpResponse(
        net::WskSocket& socket,
        tls::TlsConnection& tls,
        bool responseBodyForbidden,
        const HttpsResponseBuffers& buffers,
        http::HttpResponse& response) noexcept
    {
        SIZE_T responseLength = 0;

        for (;;) {
            http::HttpParseOptions parseOptions = {};
            parseOptions.Headers = buffers.Headers;
            parseOptions.HeaderCapacity = buffers.HeaderCapacity;
            parseOptions.DecodedBody = buffers.DecodedBodyBuffer;
            parseOptions.DecodedBodyCapacity = buffers.DecodedBodyBufferLength;
            parseOptions.ResponseBodyForbidden = responseBodyForbidden;

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
            status = tls.Receive(
                socket,
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
