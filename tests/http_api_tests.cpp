#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "http2/Http2Connection.h"
#include "http3/Http3Types.h"
#include "net/WskSocket.h"
#include "quic/QuicTypes.h"
#include "rtl/Lookaside.h"
#include "rtl/ProtocolFailureInjection.h"
#include "session/Async.h"
#include "session/ConnectionPool.h"
#include "session/HandleTypes.h"
#include "session/HttpH3TestHooks.h"
#include "session/Workspace.h"
#include "session/detail/HttpHandles.h"
#include "transport/Transport.h"
#include <wknet/Wknet.h>
#include <wknet/test/Test.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef STATUS_NO_MATCH
#define STATUS_NO_MATCH ((NTSTATUS)0xC0000272L)
#endif

namespace
{
    class TestWskClient final
    {
    public:
        TestWskClient() noexcept { createStatus_ = wknet::net::WskClientCreate(&client_); }
        ~TestWskClient() noexcept { wknet::net::WskClientClose(client_); }
        NTSTATUS Initialize() noexcept
        {
            return NT_SUCCESS(createStatus_)
                ? wknet::net::WskClientInitialize(client_)
                : createStatus_;
        }
        NTSTATUS ResolveAll(
            const wchar_t* nodeName,
            const wchar_t* serviceName,
            SOCKADDR_STORAGE* addresses,
            SIZE_T capacity,
            SIZE_T* count,
            wknet::net::WskAddressFamily family = wknet::net::WskAddressFamily::Any) noexcept
        {
            return wknet::net::WskClientResolveAll(
                client_, nodeName, serviceName, addresses, capacity, count, family);
        }
        wknet::net::WskClient* Get() noexcept { return client_; }

    private:
        wknet::net::WskClient* client_ = nullptr;
        NTSTATUS createStatus_ = STATUS_UNSUCCESSFUL;
    };

    class TestWskSocket final
    {
    public:
        TestWskSocket() noexcept { createStatus_ = wknet::net::WskSocketCreate(&socket_); }
        ~TestWskSocket() noexcept { wknet::net::WskSocketDestroy(socket_); }
        NTSTATUS Connect(
            TestWskClient& client,
            const SOCKADDR* remoteAddress,
            const SOCKADDR* localAddress = nullptr,
            const wknet::net::WskCancellationToken* cancellation = nullptr) noexcept
        {
            return NT_SUCCESS(createStatus_)
                ? wknet::net::WskSocketConnect(socket_, client.Get(), remoteAddress, localAddress, cancellation)
                : createStatus_;
        }
        NTSTATUS Send(
            const void* data,
            SIZE_T length,
            SIZE_T* bytesSent,
            ULONG flags = WSK_FLAG_NODELAY,
            const wknet::net::WskCancellationToken* cancellation = nullptr) noexcept
        {
            return wknet::net::WskSocketSend(socket_, data, length, bytesSent, flags, cancellation);
        }
        NTSTATUS Receive(
            void* data,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG flags = 0,
            ULONG timeoutMilliseconds = wknet::WskOperationTimeoutMilliseconds,
            const wknet::net::WskCancellationToken* cancellation = nullptr) noexcept
        {
            return wknet::net::WskSocketReceive(
                socket_, data, length, bytesReceived, flags, timeoutMilliseconds, cancellation);
        }
        NTSTATUS Close() noexcept { return wknet::net::WskSocketClose(socket_); }
        bool IsConnected() const noexcept { return wknet::net::WskSocketIsConnected(socket_); }

    private:
        wknet::net::WskSocket* socket_ = nullptr;
        NTSTATUS createStatus_ = STATUS_UNSUCCESSFUL;
    };

    class TestHttp2Connection final
    {
    public:
        TestHttp2Connection() noexcept { createStatus_ = wknet::http2::Http2ConnectionCreate(&connection_); }
        ~TestHttp2Connection() noexcept { wknet::http2::Http2ConnectionClose(connection_); }
        wknet::http2::Http2Connection* Get() noexcept { return connection_; }
        NTSTATUS CreateStatus() const noexcept { return createStatus_; }

    private:
        wknet::http2::Http2Connection* connection_ = nullptr;
        NTSTATUS createStatus_ = STATUS_UNSUCCESSFUL;
    };

    bool g_failed = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    SIZE_T Length(const char* literal) noexcept
    {
        SIZE_T length = 0;
        while (literal[length] != '\0') {
            ++length;
        }
        return length;
    }

    bool LoadTestFile(const char* path, UCHAR** data, SIZE_T* dataLength) noexcept
    {
        if (path == nullptr || data == nullptr || dataLength == nullptr) {
            return false;
        }
        *data = nullptr;
        *dataLength = 0;

        FILE* file = nullptr;
        if (fopen_s(&file, path, "rb") != 0 || file == nullptr) {
            return false;
        }
        if (fseek(file, 0, SEEK_END) != 0) {
            fclose(file);
            return false;
        }
        const long fileLength = ftell(file);
        if (fileLength <= 0 || fseek(file, 0, SEEK_SET) != 0) {
            fclose(file);
            return false;
        }

        const SIZE_T length = static_cast<SIZE_T>(fileLength);
        auto* buffer = static_cast<UCHAR*>(malloc(length));
        if (buffer == nullptr) {
            fclose(file);
            return false;
        }
        const SIZE_T bytesRead = fread(buffer, 1, length, file);
        fclose(file);
        if (bytesRead != length) {
            free(buffer);
            return false;
        }

        *data = buffer;
        *dataLength = length;
        return true;
    }

    bool BufferContainsLiteral(const char* value, SIZE_T valueLength, const char* literal) noexcept
    {
        if (value == nullptr || literal == nullptr) {
            return false;
        }

        const SIZE_T literalLength = Length(literal);
        if (literalLength == 0 || literalLength > valueLength) {
            return false;
        }

        for (SIZE_T offset = 0; offset + literalLength <= valueLength; ++offset) {
            if (memcmp(value + offset, literal, literalLength) == 0) {
                return true;
            }
        }
        return false;
    }

    constexpr const char* EncodedBodyLiteral = "encoded response body";

    const unsigned char GzipBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xff, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49,
        0x4d, 0x51, 0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf,
        0x2b, 0x4e, 0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04,
        0x00, 0xec, 0xa9, 0xb0, 0x05, 0x15, 0x00, 0x00,
        0x00
    };

    const unsigned char ZstdDictionary[] = {
        0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x64, 0x20,
        0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
        0x20
    };

    const unsigned char DczBody[] = {
        0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x15, 0x55, 0x00,
        0x00, 0x20, 0x62, 0x6f, 0x64, 0x79, 0x01, 0x00,
        0x34, 0x4f, 0x20
    };

    SIZE_T BuildTransferGzipChunkedResponse(char* buffer, SIZE_T capacity) noexcept
    {
        if (buffer == nullptr) {
            return 0;
        }

        const int headerLength = snprintf(
            buffer,
            capacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: gzip, chunked\r\n"
            "\r\n"
            "%zx\r\n",
            sizeof(GzipBody));
        if (headerLength <= 0 || static_cast<SIZE_T>(headerLength) > capacity) {
            return 0;
        }

        SIZE_T cursor = static_cast<SIZE_T>(headerLength);
        if (sizeof(GzipBody) > capacity - cursor) {
            return 0;
        }

        memcpy(buffer + cursor, GzipBody, sizeof(GzipBody));
        cursor += sizeof(GzipBody);

        const char trailer[] = "\r\n0\r\n\r\n";
        if (sizeof(trailer) - 1 > capacity - cursor) {
            return 0;
        }

        memcpy(buffer + cursor, trailer, sizeof(trailer) - 1);
        cursor += sizeof(trailer) - 1;
        return cursor;
    }

    SIZE_T BuildTransferGzipCloseDelimitedResponse(char* buffer, SIZE_T capacity) noexcept
    {
        if (buffer == nullptr) {
            return 0;
        }

        const int headerLength = snprintf(
            buffer,
            capacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: gzip\r\n"
            "\r\n");
        if (headerLength <= 0 || static_cast<SIZE_T>(headerLength) > capacity) {
            return 0;
        }

        SIZE_T cursor = static_cast<SIZE_T>(headerLength);
        if (sizeof(GzipBody) > capacity - cursor) {
            return 0;
        }

        memcpy(buffer + cursor, GzipBody, sizeof(GzipBody));
        cursor += sizeof(GzipBody);
        return cursor;
    }

    struct Http2KeepAliveTestTransport final
    {
        Http2KeepAliveTestTransport() noexcept
        {
            const wknet::transport::TransportCallbacks callbacks = {
                SendCallback,
                ReceiveCallback,
                ReceiveWithTimeoutCallback,
                nullptr
            };
            CreateStatus = wknet::transport::TransportCreateCallbacks(&callbacks, this, &Handle);
        }

        ~Http2KeepAliveTestTransport() noexcept
        {
            wknet::transport::TransportClose(Handle);
        }

        wknet::transport::Transport* Handle = nullptr;
        NTSTATUS CreateStatus = STATUS_UNSUCCESSFUL;
        bool TimeoutAck = false;
        ULONG SendCalls = 0;
        ULONG ReceiveCalls = 0;
        ULONG LastTimeoutMs = 0;
        SIZE_T AckOffset = 0;
        UCHAR AckFrame[17] = {};
        UCHAR LastPingOpaque[8] = {};

        NTSTATUS Send(const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
        {
            if (bytesSent != nullptr) {
                *bytesSent = 0;
            }
            if (data == nullptr || length != sizeof(AckFrame)) {
                return STATUS_INVALID_PARAMETER;
            }

            const UCHAR* bytes = static_cast<const UCHAR*>(data);
            if (bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 8 ||
                bytes[3] != 0x06 || bytes[4] != 0 || bytes[5] != 0 ||
                bytes[6] != 0 || bytes[7] != 0 || bytes[8] != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            ++SendCalls;
            memcpy(LastPingOpaque, bytes + 9, sizeof(LastPingOpaque));
            AckFrame[0] = 0;
            AckFrame[1] = 0;
            AckFrame[2] = 8;
            AckFrame[3] = 0x06;
            AckFrame[4] = 0x01;
            AckFrame[5] = 0;
            AckFrame[6] = 0;
            AckFrame[7] = 0;
            AckFrame[8] = 0;
            memcpy(AckFrame + 9, LastPingOpaque, sizeof(LastPingOpaque));
            AckOffset = 0;

            if (bytesSent != nullptr) {
                *bytesSent = length;
            }
            return STATUS_SUCCESS;
        }

        NTSTATUS Receive(void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
        {
            return ReceiveWithTimeout(buffer, length, bytesReceived, 0);
        }

        NTSTATUS ReceiveWithTimeout(
            void* buffer,
            SIZE_T length,
            SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept
        {
            if (bytesReceived != nullptr) {
                *bytesReceived = 0;
            }
            LastTimeoutMs = timeoutMilliseconds;
            if (TimeoutAck) {
                return STATUS_IO_TIMEOUT;
            }
            if (buffer == nullptr || length == 0 || AckOffset >= sizeof(AckFrame)) {
                return STATUS_CONNECTION_DISCONNECTED;
            }

            ++ReceiveCalls;
            const SIZE_T remaining = sizeof(AckFrame) - AckOffset;
            const SIZE_T copyLength = remaining < length ? remaining : length;
            memcpy(buffer, AckFrame + AckOffset, copyLength);
            AckOffset += copyLength;
            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }
            return STATUS_SUCCESS;
        }

        static NTSTATUS SendCallback(
            void* context, const void* data, SIZE_T length, SIZE_T* bytesSent) noexcept
        {
            auto* self = static_cast<Http2KeepAliveTestTransport*>(context);
            return self != nullptr ? self->Send(data, length, bytesSent) : STATUS_INVALID_PARAMETER;
        }

        static NTSTATUS ReceiveCallback(
            void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived) noexcept
        {
            auto* self = static_cast<Http2KeepAliveTestTransport*>(context);
            return self != nullptr ? self->Receive(buffer, length, bytesReceived) : STATUS_INVALID_PARAMETER;
        }

        static NTSTATUS ReceiveWithTimeoutCallback(
            void* context, void* buffer, SIZE_T length, SIZE_T* bytesReceived,
            ULONG timeoutMilliseconds) noexcept
        {
            auto* self = static_cast<Http2KeepAliveTestTransport*>(context);
            return self != nullptr
                ? self->ReceiveWithTimeout(buffer, length, bytesReceived, timeoutMilliseconds)
                : STATUS_INVALID_PARAMETER;
        }
    };

    SIZE_T BuildLargeHttpResponse(char* buffer, SIZE_T capacity) noexcept
    {
        const char* header =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5000\r\n"
            "\r\n";
        const SIZE_T headerLength = Length(header);
        const SIZE_T bodyLength = 5000;
        if (buffer == nullptr || capacity < headerLength + bodyLength) {
            return 0;
        }

        memcpy(buffer, header, headerLength);
        for (SIZE_T index = 0; index < bodyLength; ++index) {
            buffer[headerLength + index] = 'a';
        }
        return headerLength + bodyLength;
    }

    struct CapturedRequest
    {
        char Scheme[8] = {};
        SIZE_T SchemeLength = 0;
        char Host[64] = {};
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        char Body[256] = {};
        SIZE_T BodyLength = 0;
        SIZE_T ObservedBodyLength = 0;
        // Sized large enough for dynamic multi-header / long Cookie request wires.
        char BuiltRequest[8 * 1024] = {};
        SIZE_T BuiltRequestLength = 0;
        SIZE_T CallCount = 0;
        const char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        bool ProxyEnabled = false;
        char ProxyHost[128] = {};
        SIZE_T ProxyHostLength = 0;
        USHORT ProxyPort = 0;
        wknet::http::AddressFamily ProxyFamily = wknet::http::AddressFamily::Any;
        char ProxyAuthority[128] = {};
        SIZE_T ProxyAuthorityLength = 0;
        char ProxyAuthHeader[128] = {};
        SIZE_T ProxyAuthHeaderLength = 0;
        wknet::http::Http2CleartextMode Http2CleartextMode =
            wknet::http::Http2CleartextMode::Disabled;
        bool UsedHttp2 = false;
        bool Http11PipelineEnabled = false;
        bool Http11PipelineLease = false;
        ULONG Http11PipelineSequence = 0;
        ULONG MaxTls12Renegotiations = 0;
    };

    struct StreamingBodyContext
    {
        const char* const* Chunks = nullptr;
        const SIZE_T* ChunkLengths = nullptr;
        SIZE_T ChunkCount = 0;
        SIZE_T Index = 0;
        SIZE_T Offset = 0;
        SIZE_T CallCount = 0;
    };

    struct BodyCallbackCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T TotalBytes = 0;
        bool FinalChunk = false;
        char Buffer[512] = {};
        SIZE_T BufferLength = 0;
    };

    struct RedirectCapture
    {
        SIZE_T CallCount = 0;
        char Requests[8][512] = {};
        SIZE_T RequestLengths[8] = {};
    };

    struct RedirectMethodCapture
    {
        USHORT RedirectStatus = 302;
        SIZE_T CallCount = 0;
        char Requests[2][512] = {};
        SIZE_T RequestLengths[2] = {};
    };

    struct ReusedFailureCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
        SIZE_T NewConnectionCallCount = 0;
        ULONGLONG FirstConnectionId = 0;
        ULONGLONG RetryConnectionId = 0;
        NTSTATUS FailureStatus = STATUS_CONNECTION_RESET;
    };

    struct FreshTimeoutCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
        SIZE_T NewConnectionCallCount = 0;
        ULONGLONG FirstConnectionId = 0;
        ULONGLONG RetryConnectionId = 0;
    };

    struct FreshRetrySignalCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T NewConnectionCallCount = 0;
        ULONGLONG FirstConnectionId = 0;
        ULONGLONG RetryConnectionId = 0;
        NTSTATUS FailureStatus = STATUS_RETRY;
    };

    struct ReuseDecisionCapture
    {
        const char* FirstResponse = nullptr;
        SIZE_T FirstResponseLength = 0;
        bool FirstConnectionReusable = true;
        const char* SecondResponse = nullptr;
        SIZE_T SecondResponseLength = 0;
        bool SecondConnectionReusable = true;
        SIZE_T CallCount = 0;
        SIZE_T ReusedCallCount = 0;
    };

    struct Http11PipelineCapture
    {
        SIZE_T CallCount = 0;
        bool LastPipelineEnabled = false;
        bool LastPipelineLease = false;
        bool LastReusedConnection = false;
        ULONG LastPipelineSequence = 0;
        const char* RawResponse = nullptr;
        SIZE_T RawResponseLength = 0;
        bool ConnectionReusable = true;
    };

    struct CompletionCapture
    {
        SIZE_T CallCount = 0;
        NTSTATUS LastStatus = STATUS_PENDING;
    };

    struct CacheCapture
    {
        const char* Responses[8] = {};
        SIZE_T ResponseLengths[8] = {};
        SIZE_T ResponseCount = 0;
        SIZE_T CallCount = 0;
        char Requests[8][1024] = {};
        SIZE_T RequestLengths[8] = {};
    };

    struct LongUrlCapture
    {
        SIZE_T CallCount = 0;
        bool SawLongOriginForm = false;
    };

    struct ExpectContinueCapture
    {
        SIZE_T CallCount = 0;
        SIZE_T HeaderCallCount = 0;
        SIZE_T BodyCallCount = 0;
        NTSTATUS FirstStatus = STATUS_SUCCESS;
        const char* FirstResponse = nullptr;
        SIZE_T FirstResponseLength = 0;
        const char* FinalResponse = nullptr;
        SIZE_T FinalResponseLength = 0;
        char HeaderSegment[768] = {};
        SIZE_T HeaderSegmentLength = 0;
        char BodySegment[256] = {};
        SIZE_T BodySegmentLength = 0;
        bool FirstExpectContinueEnabled = false;
        bool FirstExpectContinueBodySent = false;
        bool SecondExpectContinueBodySent = false;
    };

    void CopySegment(
        const char* source,
        SIZE_T sourceLength,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* copiedLength) noexcept
    {
        if (copiedLength != nullptr) {
            *copiedLength = 0;
        }
        if (source == nullptr || destination == nullptr || destinationCapacity == 0) {
            return;
        }

        SIZE_T copyLength = sourceLength < destinationCapacity - 1
            ? sourceLength
            : destinationCapacity - 1;
        if (copyLength != 0) {
            memcpy(destination, source, copyLength);
        }
        destination[copyLength] = '\0';
        if (copiedLength != nullptr) {
            *copiedLength = copyLength;
        }
    }

    void RecordCompletion(void* context, NTSTATUS status) noexcept
    {
        auto* capture = static_cast<CompletionCapture*>(context);
        if (capture == nullptr) {
            return;
        }

        ++capture->CallCount;
        capture->LastStatus = status;
    }

    NTSTATUS TestTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* captured = static_cast<CapturedRequest*>(context);
        if (captured == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++captured->CallCount;
        captured->Port = request->Port;
        captured->SchemeLength = request->SchemeLength < sizeof(captured->Scheme) - 1
            ? request->SchemeLength
            : sizeof(captured->Scheme) - 1;
        memcpy(captured->Scheme, request->Scheme, captured->SchemeLength);
        captured->Scheme[captured->SchemeLength] = '\0';
        captured->HostLength = request->HostLength < sizeof(captured->Host) - 1
            ? request->HostLength
            : sizeof(captured->Host) - 1;
        memcpy(captured->Host, request->Host, captured->HostLength);
        captured->Host[captured->HostLength] = '\0';

        const char* requestBytes = request->BuiltRequest;
        SIZE_T requestLength = request->BuiltRequestLength;
        captured->BuiltRequestLength = requestLength < sizeof(captured->BuiltRequest) - 1
            ? requestLength
            : sizeof(captured->BuiltRequest) - 1;
        memcpy(captured->BuiltRequest, requestBytes, captured->BuiltRequestLength);
        captured->BuiltRequest[captured->BuiltRequestLength] = '\0';
        captured->ProxyEnabled = request->ProxyEnabled;
        captured->ProxyHostLength = request->ProxyHostLength < sizeof(captured->ProxyHost) - 1
            ? request->ProxyHostLength
            : sizeof(captured->ProxyHost) - 1;
        if (request->ProxyHost != nullptr && captured->ProxyHostLength != 0) {
            memcpy(captured->ProxyHost, request->ProxyHost, captured->ProxyHostLength);
        }
        captured->ProxyHost[captured->ProxyHostLength] = '\0';
        captured->ProxyPort = request->ProxyPort;
        captured->ProxyFamily = request->ProxyFamily;
        captured->ProxyAuthorityLength = request->ProxyAuthorityLength < sizeof(captured->ProxyAuthority) - 1
            ? request->ProxyAuthorityLength
            : sizeof(captured->ProxyAuthority) - 1;
        if (request->ProxyAuthority != nullptr && captured->ProxyAuthorityLength != 0) {
            memcpy(captured->ProxyAuthority, request->ProxyAuthority, captured->ProxyAuthorityLength);
        }
        captured->ProxyAuthority[captured->ProxyAuthorityLength] = '\0';
        captured->ProxyAuthHeaderLength = request->ProxyAuthHeaderLength < sizeof(captured->ProxyAuthHeader) - 1
            ? request->ProxyAuthHeaderLength
            : sizeof(captured->ProxyAuthHeader) - 1;
        if (request->ProxyAuthHeader != nullptr && captured->ProxyAuthHeaderLength != 0) {
            memcpy(captured->ProxyAuthHeader, request->ProxyAuthHeader, captured->ProxyAuthHeaderLength);
        }
        captured->ProxyAuthHeader[captured->ProxyAuthHeaderLength] = '\0';
        captured->Http2CleartextMode = request->Http2CleartextMode;
        captured->UsedHttp2 = request->UsedHttp2;
        captured->Http11PipelineEnabled = request->Http11PipelineEnabled;
        captured->Http11PipelineLease = request->Http11PipelineLease;
        captured->Http11PipelineSequence = request->Http11PipelineSequence;
        captured->MaxTls12Renegotiations = request->MaxTls12Renegotiations;

        const char* bodyMarker = "\r\n\r\n";
        const SIZE_T markerLength = 4;
        for (SIZE_T index = 0; index + markerLength <= requestLength; ++index) {
            if (memcmp(requestBytes + index, bodyMarker, markerLength) == 0) {
                const char* bodyStart = requestBytes + index + markerLength;
                SIZE_T bodyLength = requestLength - (index + markerLength);
                captured->ObservedBodyLength = bodyLength;
                if (bodyLength >= sizeof(captured->Body)) {
                    bodyLength = sizeof(captured->Body) - 1;
                }
                memcpy(captured->Body, bodyStart, bodyLength);
                captured->Body[bodyLength] = '\0';
                captured->BodyLength = bodyLength;
                break;
            }
        }
        if (captured->ObservedBodyLength == 0 && request->BodyBytesLength != 0) {
            captured->ObservedBodyLength = request->BodyBytesLength;
        }

        response->RawResponse = captured->RawResponse;
        response->RawResponseLength = captured->RawResponseLength;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS CacheTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<CacheCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        const SIZE_T index = capture->CallCount < 8 ? capture->CallCount : 7;
        const SIZE_T copyLength = request->BuiltRequestLength < sizeof(capture->Requests[index]) - 1
            ? request->BuiltRequestLength
            : sizeof(capture->Requests[index]) - 1;
        if (copyLength != 0) {
            memcpy(capture->Requests[index], request->BuiltRequest, copyLength);
        }
        capture->Requests[index][copyLength] = '\0';
        capture->RequestLengths[index] = copyLength;
        ++capture->CallCount;

        SIZE_T responseIndex = capture->CallCount - 1;
        if (responseIndex >= capture->ResponseCount && capture->ResponseCount != 0) {
            responseIndex = capture->ResponseCount - 1;
        }
        response->RawResponse = capture->Responses[responseIndex];
        response->RawResponseLength = capture->ResponseLengths[responseIndex];
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS StreamingBodyRead(
        void* context,
        UCHAR* buffer,
        SIZE_T bufferCapacity,
        SIZE_T* bytesRead,
        bool* endOfBody) noexcept
    {
        auto* stream = static_cast<StreamingBodyContext*>(context);
        if (stream == nullptr || buffer == nullptr || bytesRead == nullptr || endOfBody == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++stream->CallCount;
        *bytesRead = 0;
        *endOfBody = false;
        if (stream->Index >= stream->ChunkCount) {
            *endOfBody = true;
            return STATUS_SUCCESS;
        }

        const char* source = stream->Chunks[stream->Index];
        const SIZE_T sourceLength = stream->ChunkLengths[stream->Index];
        const SIZE_T remaining = sourceLength - stream->Offset;
        const SIZE_T copy = remaining < bufferCapacity ? remaining : bufferCapacity;
        if (copy != 0) {
            memcpy(buffer, source + stream->Offset, copy);
        }
        stream->Offset += copy;
        *bytesRead = copy;

        if (stream->Offset == sourceLength) {
            ++stream->Index;
            stream->Offset = 0;
        }
        if (stream->Index >= stream->ChunkCount) {
            *endOfBody = true;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS CountingBodyCallback(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalChunk) noexcept
    {
        auto* capture = static_cast<BodyCallbackCapture*>(context);
        if (capture == nullptr || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        ++capture->CallCount;
        capture->TotalBytes += dataLength;
        capture->FinalChunk = finalChunk;
        if (data != nullptr && dataLength != 0) {
            const SIZE_T room = sizeof(capture->Buffer) - capture->BufferLength;
            const SIZE_T take = dataLength < room ? dataLength : room;
            if (take != 0) {
                memcpy(capture->Buffer + capture->BufferLength, data, take);
                capture->BufferLength += take;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS CreateHttp3RouterTestPeer(
        void*,
        const wknet::session::HttpH3PeerCreateOptions* options,
        wknet::session::HttpH3Peer* peer) noexcept
    {
        return wknet::session::HttpH3TestCreateInMemoryPeer(options, peer);
    }

    bool InitializeHttp3RouterDispatch(
        wknet::session::HttpH3DispatchContext* dispatch,
        wknet::session::Request* request,
        wknet::session::HttpSendOptions* sendOptions,
        ULONGLONG attemptGeneration) noexcept
    {
        wknet::session::HttpH3PeerFactory factory = {};
        factory.Create = CreateHttp3RouterTestPeer;

        wknet::session::HttpH3DispatchStartOptions options = {};
        options.RequestObject = request;
        options.SendOptions = sendOptions;
        options.PeerFactory = &factory;
        options.AttemptGeneration = attemptGeneration;
        options.DirectCallbacks = true;
        return NT_SUCCESS(wknet::session::HttpH3DispatchInitialize(dispatch, &options));
    }

    bool AttachHttp3RouterDispatchPair(
        wknet::session::HttpH3DispatchContext* first,
        wknet::session::HttpH3DispatchContext* second) noexcept
    {
        wknet::session::HttpH3PeerCreateOptions createOptions = {};
        createOptions.Dispatch = first;
        NTSTATUS status = wknet::session::HttpH3TestCreateInMemoryPeer(&createOptions, &first->Peer);
        if (!NT_SUCCESS(status))
        {
            return false;
        }
        first->PeerCreated = true;

        status = wknet::session::HttpH3TestCreateSiblingPeer(&first->Peer, &second->Peer);
        if (!NT_SUCCESS(status))
        {
            return false;
        }
        second->PeerCreated = true;

        status = first->Peer.AttachRequest(first->Peer.Context, first);
        if (NT_SUCCESS(status))
        {
            status = second->Peer.AttachRequest(second->Peer.Context, second);
        }
        if (NT_SUCCESS(status))
        {
            status = first->Peer.BindStream(first->Peer.Context, first, 0);
        }
        if (NT_SUCCESS(status))
        {
            status = second->Peer.BindStream(second->Peer.Context, second, 4);
        }
        if (NT_SUCCESS(status))
        {
            status = wknet::session::HttpH3DispatchAdvanceState(
                first,
                wknet::session::HttpH3RequestState::StreamCreated,
                0,
                STATUS_PENDING);
        }
        if (NT_SUCCESS(status))
        {
            status = wknet::session::HttpH3DispatchAdvanceState(
                second,
                wknet::session::HttpH3RequestState::StreamCreated,
                4,
                STATUS_PENDING);
        }
        return NT_SUCCESS(status);
    }

    NTSTATUS LongUrlTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<LongUrlCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        static const char marker[] = " HTTP/1.1\r\n";
        constexpr SIZE_T requestTargetLength = 16384;
        if (request->BuiltRequest != nullptr &&
            request->BuiltRequestLength > 4 + requestTargetLength + sizeof(marker) - 1 &&
            memcmp(request->BuiltRequest, "GET /", 5) == 0 &&
            request->BuiltRequest[4 + requestTargetLength - 1] == 'a' &&
            memcmp(
                request->BuiltRequest + 4 + requestTargetLength,
                marker,
                sizeof(marker) - 1) == 0) {
            capture->SawLongOriginForm = true;
        }

        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";
        response->RawResponse = responseBytes;
        response->RawResponseLength = sizeof(responseBytes) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS ExpectContinueTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<ExpectContinueCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (capture->CallCount == 1) {
            capture->FirstExpectContinueEnabled = request->ExpectContinueEnabled;
            capture->FirstExpectContinueBodySent = request->ExpectContinueBodySent;
            CopySegment(
                request->BuiltRequest,
                request->BuiltRequestLength,
                capture->HeaderSegment,
                sizeof(capture->HeaderSegment),
                &capture->HeaderSegmentLength);

            if (!request->ExpectContinueEnabled) {
                response->RawResponse = capture->FinalResponse;
                response->RawResponseLength = capture->FinalResponseLength;
                response->ConnectionReusable = false;
                return STATUS_SUCCESS;
            }

            ++capture->HeaderCallCount;
            if (!NT_SUCCESS(capture->FirstStatus)) {
                return capture->FirstStatus;
            }

            response->RawResponse = capture->FirstResponse;
            response->RawResponseLength = capture->FirstResponseLength;
            response->ConnectionReusable = false;
            return STATUS_SUCCESS;
        }

        if (!request->ExpectContinueEnabled || !request->ExpectContinueBodySent) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ++capture->BodyCallCount;
        capture->SecondExpectContinueBodySent = request->ExpectContinueBodySent;
        CopySegment(
            request->BuiltRequest,
            request->BuiltRequestLength,
            capture->BodySegment,
            sizeof(capture->BodySegment),
            &capture->BodySegmentLength);

        response->RawResponse = capture->FinalResponse;
        response->RawResponseLength = capture->FinalResponseLength;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    void ExpectRejectedRequestHeader(
        const char* headerName,
        const char* headerValue,
        bool includeBody,
        NTSTATUS expectedStatus,
        const char* message) noexcept
    {
        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        CapturedRequest captured = {};
        captured.RawResponse = responseBytes;
        captured.RawResponseLength = sizeof(responseBytes) - 1;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reserved header rejection");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for reserved header rejection");

        const char* url = "http://example.com/rejected-header";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for reserved header rejection");

        if (includeBody) {
            const char* body = "payload";
            status = wknet::http::RequestSetBody(
                request,
                reinterpret_cast<const UCHAR*>(body),
                Length(body));
            Expect(NT_SUCCESS(status), "RequestSetBody succeeds for reserved header rejection");
        }

        status = wknet::http::RequestSetHeader(
            request,
            headerName,
            Length(headerName),
            headerValue,
            Length(headerValue));
        Expect(NT_SUCCESS(status), "RequestSetHeader stores reserved header until send validation");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Send(session, request, nullptr, &response);
        Expect(status == expectedStatus, message);
        Expect(response == nullptr, "reserved header rejection does not allocate response");
        Expect(captured.CallCount == 0, "reserved header rejection does not reach transport");

        wknet::http::ResponseRelease(response);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void CaptureRedirectRequest(
        RedirectCapture& capture,
        const wknet::http::test::HttpTransportRequest& request) noexcept
    {
        if (capture.CallCount >= sizeof(capture.Requests) / sizeof(capture.Requests[0])) {
            return;
        }

        const SIZE_T index = capture.CallCount;
        const SIZE_T copy = request.BuiltRequestLength < sizeof(capture.Requests[index]) - 1
            ? request.BuiltRequestLength
            : sizeof(capture.Requests[index]) - 1;
        memcpy(capture.Requests[index], request.BuiltRequest, copy);
        capture.Requests[index][copy] = '\0';
        capture.RequestLengths[index] = copy;
    }

    NTSTATUS RedirectTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        CaptureRedirectRequest(*capture, *request);
        ++capture->CallCount;

        static const char redirectToSecond[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: /redirect/2\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectToFinal[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: /final\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "done";

        if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, " /redirect/1 ")) {
            response->RawResponse = redirectToSecond;
            response->RawResponseLength = sizeof(redirectToSecond) - 1;
        }
        else if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, " /redirect/2 ")) {
            response->RawResponse = redirectToFinal;
            response->RawResponseLength = sizeof(redirectToFinal) - 1;
        }
        else if (BufferContainsLiteral(request->BuiltRequest, request->BuiltRequestLength, " /final ")) {
            response->RawResponse = finalResponse;
            response->RawResponseLength = sizeof(finalResponse) - 1;
        }
        else {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS RelativeRedirectTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        CaptureRedirectRequest(*capture, *request);
        ++capture->CallCount;

        static const char redirectToSibling[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: next\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectToParent[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: ../other?x=1\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectQueryOnly[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: ?page=2\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char redirectToOtherOrigin[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: //other.example/final\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "done";

        switch (capture->CallCount) {
        case 1:
            response->RawResponse = redirectToSibling;
            response->RawResponseLength = sizeof(redirectToSibling) - 1;
            break;
        case 2:
            response->RawResponse = redirectToParent;
            response->RawResponseLength = sizeof(redirectToParent) - 1;
            break;
        case 3:
            response->RawResponse = redirectQueryOnly;
            response->RawResponseLength = sizeof(redirectQueryOnly) - 1;
            break;
        case 4:
            response->RawResponse = redirectToOtherOrigin;
            response->RawResponseLength = sizeof(redirectToOtherOrigin) - 1;
            break;
        case 5:
            response->RawResponse = finalResponse;
            response->RawResponseLength = sizeof(finalResponse) - 1;
            break;
        default:
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpsDowngradeRedirectTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        CaptureRedirectRequest(*capture, *request);
        ++capture->CallCount;

        static const char downgradeRedirect[] =
            "HTTP/1.1 302 Found\r\n"
            "Location: http://secure.example/final\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        response->RawResponse = downgradeRedirect;
        response->RawResponseLength = sizeof(downgradeRedirect) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS RedirectMethodTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<RedirectMethodCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (capture->CallCount < sizeof(capture->Requests) / sizeof(capture->Requests[0])) {
            const SIZE_T index = capture->CallCount;
            const SIZE_T copy = request->BuiltRequestLength < sizeof(capture->Requests[index]) - 1
                ? request->BuiltRequestLength
                : sizeof(capture->Requests[index]) - 1;
            memcpy(capture->Requests[index], request->BuiltRequest, copy);
            capture->Requests[index][copy] = '\0';
            capture->RequestLengths[index] = copy;
        }
        ++capture->CallCount;

        static char redirectResponse[160] = {};
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        if (capture->CallCount == 1) {
            const int written = snprintf(
                redirectResponse,
                sizeof(redirectResponse),
                "HTTP/1.1 %u Redirect\r\n"
                "Location: /target\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n",
                static_cast<unsigned>(capture->RedirectStatus));
            if (written <= 0 || static_cast<SIZE_T>(written) >= sizeof(redirectResponse)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            response->RawResponse = redirectResponse;
            response->RawResponseLength = static_cast<SIZE_T>(written);
        }
        else if (capture->CallCount == 2) {
            response->RawResponse = finalResponse;
            response->RawResponseLength = sizeof(finalResponse) - 1;
        }
        else {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS ReusedFailureTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<ReusedFailureCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (request->ReusedConnection) {
            ++capture->ReusedCallCount;
            return capture->FailureStatus;
        }

        ++capture->NewConnectionCallCount;
        if (capture->FirstConnectionId == 0) {
            capture->FirstConnectionId = request->ConnectionId;
        }
        else {
            capture->RetryConnectionId = request->ConnectionId;
        }

        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        response->RawResponse = responseBytes;
        response->RawResponseLength = sizeof(responseBytes) - 1;
        response->ConnectionReusable = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS FreshTimeoutTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<FreshTimeoutCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (request->ReusedConnection) {
            ++capture->ReusedCallCount;
            return STATUS_INVALID_DEVICE_STATE;
        }

        ++capture->NewConnectionCallCount;
        if (capture->FirstConnectionId == 0) {
            capture->FirstConnectionId = request->ConnectionId;
            return STATUS_IO_TIMEOUT;
        }

        capture->RetryConnectionId = request->ConnectionId;

        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";
        response->RawResponse = responseBytes;
        response->RawResponseLength = sizeof(responseBytes) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS FreshRetrySignalTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<FreshRetrySignalCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (request->ReusedConnection) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        ++capture->NewConnectionCallCount;
        if (capture->FirstConnectionId == 0) {
            capture->FirstConnectionId = request->ConnectionId;
            return capture->FailureStatus;
        }

        capture->RetryConnectionId = request->ConnectionId;

        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";
        response->RawResponse = responseBytes;
        response->RawResponseLength = sizeof(responseBytes) - 1;
        response->ConnectionReusable = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS ReuseDecisionTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<ReuseDecisionCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        if (request->ReusedConnection) {
            ++capture->ReusedCallCount;
        }

        if (capture->CallCount == 1) {
            response->RawResponse = capture->FirstResponse;
            response->RawResponseLength = capture->FirstResponseLength;
            response->ConnectionReusable = capture->FirstConnectionReusable;
        }
        else {
            response->RawResponse = capture->SecondResponse;
            response->RawResponseLength = capture->SecondResponseLength;
            response->ConnectionReusable = capture->SecondConnectionReusable;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS Http11PipelineTransport(
        void* context,
        const wknet::http::test::HttpTransportRequest* request,
        wknet::http::test::HttpTransportResponse* response) noexcept
    {
        auto* capture = static_cast<Http11PipelineCapture*>(context);
        if (capture == nullptr || request == nullptr || response == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        capture->LastPipelineEnabled = request->Http11PipelineEnabled;
        capture->LastPipelineLease = request->Http11PipelineLease;
        capture->LastPipelineSequence = request->Http11PipelineSequence;
        capture->LastReusedConnection = request->ReusedConnection;

        response->RawResponse = capture->RawResponse;
        response->RawResponseLength = capture->RawResponseLength;
        response->ConnectionReusable = capture->ConnectionReusable;
        return STATUS_SUCCESS;
    }

    struct WsCapture
    {
        SIZE_T ConnectCount = 0;
        SIZE_T SendCount = 0;
        SIZE_T ReceiveCount = 0;
        SIZE_T CloseCount = 0;
        char LastScheme[8] = {};
        SIZE_T LastSchemeLength = 0;
        char LastHost[64] = {};
        SIZE_T LastHostLength = 0;
        char LastSubprotocol[64] = {};
        SIZE_T LastSubprotocolLength = 0;
        char LastSendBuffer[64] = {};
        UCHAR LastSendData[128] = {};
        SIZE_T LastSendLength = 0;
        wknet::websocket::MsgType LastSendType = wknet::websocket::MsgType::Text;
        bool LastSendFinalFragment = false;
        wknet::websocket::MsgType NextType = wknet::websocket::MsgType::Text;
        UCHAR NextData[64] = {};
        SIZE_T NextLength = 0;
        bool LastAllowWebSocketOverHttp2 = false;
        wknet::http::WebSocketTransportMode LastTransportMode =
            wknet::http::WebSocketTransportMode::Auto;
        wknet::websocket::PerMessageDeflateOptions LastPerMessageDeflate = {};
        ULONG LastMaxTls12Renegotiations = 0;
        NTSTATUS SendStatus = STATUS_SUCCESS;
        NTSTATUS ReceiveStatus = STATUS_SUCCESS;
    };

    NTSTATUS WsConnectCallback(
        void* context,
        const wknet::http::test::WebSocketConnectRequest* request) noexcept
    {
        auto* capture = static_cast<WsCapture*>(context);
        if (capture == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        ++capture->ConnectCount;
        capture->LastSchemeLength = request->SchemeLength < sizeof(capture->LastScheme) - 1
            ? request->SchemeLength
            : sizeof(capture->LastScheme) - 1;
        memcpy(capture->LastScheme, request->Scheme, capture->LastSchemeLength);
        capture->LastScheme[capture->LastSchemeLength] = '\0';
        capture->LastHostLength = request->HostLength < sizeof(capture->LastHost) - 1
            ? request->HostLength
            : sizeof(capture->LastHost) - 1;
        memcpy(capture->LastHost, request->Host, capture->LastHostLength);
        capture->LastHost[capture->LastHostLength] = '\0';
        if (request->Subprotocol != nullptr && request->SubprotocolLength != 0) {
            capture->LastSubprotocolLength = request->SubprotocolLength < sizeof(capture->LastSubprotocol) - 1
                ? request->SubprotocolLength
                : sizeof(capture->LastSubprotocol) - 1;
            memcpy(capture->LastSubprotocol, request->Subprotocol, capture->LastSubprotocolLength);
            capture->LastSubprotocol[capture->LastSubprotocolLength] = '\0';
        }
        capture->LastAllowWebSocketOverHttp2 = request->AllowWebSocketOverHttp2;
        capture->LastTransportMode = request->TransportMode;
        capture->LastPerMessageDeflate = request->PerMessageDeflate;
        capture->LastMaxTls12Renegotiations = request->MaxTls12Renegotiations;
        return STATUS_SUCCESS;
    }

    NTSTATUS WsSendCallback(
        void* context,
        wknet::websocket::WebSocket* websocket,
        wknet::websocket::MsgType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WsCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(capture->SendStatus)) {
            return capture->SendStatus;
        }
        ++capture->SendCount;
        capture->LastSendType = type;
        capture->LastSendFinalFragment = finalFragment;
        const SIZE_T dataCopy = dataLength < sizeof(capture->LastSendData)
            ? dataLength
            : sizeof(capture->LastSendData);
        if (dataCopy != 0 && data != nullptr) {
            memcpy(capture->LastSendData, data, dataCopy);
        }
        const SIZE_T copy = dataLength < sizeof(capture->LastSendBuffer) - 1
            ? dataLength
            : sizeof(capture->LastSendBuffer) - 1;
        if (copy != 0 && data != nullptr) {
            memcpy(capture->LastSendBuffer, data, copy);
        }
        capture->LastSendBuffer[copy] = '\0';
        capture->LastSendLength = dataLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS WsReceiveCallback(
        void* context,
        wknet::websocket::WebSocket* websocket,
        wknet::http::test::WebSocketMessage* message) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WsCapture*>(context);
        if (capture == nullptr || message == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(capture->ReceiveStatus)) {
            return capture->ReceiveStatus;
        }
        ++capture->ReceiveCount;
        message->Type = capture->NextType;
        message->Data = capture->NextData;
        message->DataLength = capture->NextLength;
        message->FinalFragment = true;
        return STATUS_SUCCESS;
    }

    void WsCloseCallback(void* context, wknet::websocket::WebSocket* websocket) noexcept
    {
        UNREFERENCED_PARAMETER(websocket);
        auto* capture = static_cast<WsCapture*>(context);
        if (capture != nullptr) {
            ++capture->CloseCount;
        }
    }

    void TestSessionCreateAndClose() noexcept
    {
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        wknet::http::TlsConfig tls = wknet::http::DefaultTlsConfig();
        UNREFERENCED_PARAMETER(config);
        UNREFERENCED_PARAMETER(tls);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");
        Expect(session != nullptr, "Session pointer non-null");
        wknet::http::SessionClose(session);

        wknet::session::SessionHandle apiSession = nullptr;
        status = wknet::session::SessionCreate(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            nullptr,
            &apiSession);
        Expect(NT_SUCCESS(status), "engine SessionCreate succeeds");
        Expect(apiSession != nullptr, "engine session pointer non-null");
        if (apiSession != nullptr) {
            Expect(apiSession->WorkspaceLookaside.IsInitialized(), "session workspace lookaside initializes");
            Expect(
                apiSession->WorkspaceLookaside.BlockSize() == sizeof(wknet::session::Workspace),
                "session workspace lookaside uses Workspace block size");
        }
        wknet::session::SessionClose(apiSession);
    }

    void TestDestroyIsUnconditionalHighLevelDrain() noexcept
    {
        wknet::http::Destroy();
        Expect(true, "Destroy accepts no in-flight async operations");
    }

    void TestSimpleGet() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/test";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds");
        Expect(captured.CallCount == 1, "transport called once");
        Expect(strcmp(captured.Host, "example.com") == 0, "host captured");
        Expect(captured.Port == 80, "port is 80");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Accept-Encoding: gzip, deflate, br, zstd, identity\r\n"),
            "default Accept-Encoding is added");

        Expect(wknet::http::ResponseStatusCode(resp) == 200, "status code is 200");
        Expect(wknet::http::ResponseBodyLength(resp) == 5, "body length is 5");
        const UCHAR* body = wknet::http::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, "hello", 5) == 0, "body content is hello");
        Expect(wknet::http::ResponseHeaderCount(resp) == 2, "response header count is 2");

        const char* headerName = nullptr;
        SIZE_T headerNameLength = 0;
        const char* headerValue = nullptr;
        SIZE_T headerValueLength = 0;
        status = wknet::http::ResponseGetHeaderAt(
            resp,
            0,
            &headerName,
            &headerNameLength,
            &headerValue,
            &headerValueLength);
        Expect(NT_SUCCESS(status), "first response header is readable");
        Expect(headerNameLength == Length("Content-Type") &&
            memcmp(headerName, "Content-Type", headerNameLength) == 0,
            "first response header name matches");
        Expect(headerValueLength == Length("text/plain") &&
            memcmp(headerValue, "text/plain", headerValueLength) == 0,
            "first response header value matches");

        status = wknet::http::ResponseGetHeaderAt(
            resp,
            1,
            &headerName,
            &headerNameLength,
            &headerValue,
            &headerValueLength);
        Expect(NT_SUCCESS(status), "second response header is readable");
        Expect(headerNameLength == Length("Content-Length") &&
            memcmp(headerName, "Content-Length", headerNameLength) == 0,
            "second response header name matches");
        Expect(headerValueLength == Length("5") &&
            memcmp(headerValue, "5", headerValueLength) == 0,
            "second response header value matches");

        status = wknet::http::ResponseGetHeaderAt(
            resp,
            2,
            &headerName,
            &headerNameLength,
            &headerValue,
            &headerValueLength);
        Expect(!NT_SUCCESS(status), "out-of-range response header is rejected");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestTls12RenegotiationLimitConfigPropagates() noexcept
    {
        wknet::http::SessionConfig invalidConfig = wknet::http::DefaultSessionConfig();
        invalidConfig.Tls.MaxTls12Renegotiations = wknet::http::HardMaxTls12Renegotiations + 1;
        wknet::http::Session* invalidSession = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&invalidConfig, &invalidSession);
        Expect(status == STATUS_INVALID_PARAMETER, "SessionCreate rejects TLS 1.2 renegotiation limit above hard maximum");
        Expect(invalidSession == nullptr, "invalid TLS renegotiation limit leaves session null");

        const char* response =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for TLS renegotiation config propagation");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for TLS renegotiation config propagation");

        const char* url = "https://example.com/renegotiation-limit";
        if (NT_SUCCESS(status)) {
            status = wknet::http::RequestSetUrl(request, url, Length(url));
        }

        wknet::http::TlsConfig tls = wknet::http::DefaultTlsConfig();
        tls.Policy.Profile = wknet::http::TlsSecurityProfile::CompatibilityExplicit;
        tls.Policy.EnableTls12Renegotiation = true;
        tls.MaxTls12Renegotiations = 2;
        if (NT_SUCCESS(status)) {
            status = wknet::http::RequestSetTls(request, &tls);
        }

        wknet::http::Response* resp = nullptr;
        if (NT_SUCCESS(status)) {
            status = wknet::http::Send(session, request, &resp);
        }

        Expect(NT_SUCCESS(status), "HTTPS request with TLS renegotiation limit succeeds through test transport");
        Expect(captured.MaxTls12Renegotiations == 2, "TLS 1.2 renegotiation limit propagates to HTTP transport");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSessionTlsServerNameSurvivesUrlAssignment() noexcept
    {
        static const char ExplicitServerName[] = "localhost";
        wknet::session::SessionOptions explicitOptions = {};
        explicitOptions.Tls.ServerName = ExplicitServerName;
        explicitOptions.Tls.ServerNameLength = sizeof(ExplicitServerName) - 1;

        wknet::session::SessionHandle explicitSession = nullptr;
        NTSTATUS status = wknet::session::SessionCreate(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &explicitOptions,
            &explicitSession);
        Expect(NT_SUCCESS(status), "engine SessionCreate accepts an explicit TLS server name");

        wknet::session::RequestHandle explicitRequest = nullptr;
        if (NT_SUCCESS(status))
        {
            status = wknet::session::HttpRequestCreate(explicitSession, &explicitRequest);
        }
        Expect(NT_SUCCESS(status), "engine RequestCreate inherits an explicit TLS server name");

        static const char NumericUrl[] = "https://127.0.0.1/server-name";
        if (NT_SUCCESS(status))
        {
            status = wknet::session::HttpRequestSetUrl(
                explicitRequest,
                NumericUrl,
                sizeof(NumericUrl) - 1);
        }
        Expect(NT_SUCCESS(status), "HTTPS numeric URL is accepted with an explicit TLS server name");
        if (explicitRequest != nullptr)
        {
            Expect(
                explicitRequest->Tls.ServerNameLength == sizeof(ExplicitServerName) - 1 &&
                    memcmp(
                        explicitRequest->Tls.ServerName,
                        ExplicitServerName,
                        sizeof(ExplicitServerName) - 1) == 0,
                "URL assignment preserves the session-level explicit TLS server name");
            Expect(
                explicitRequest->Tls.ServerName != explicitRequest->Host,
                "explicit TLS identity remains distinct from the numeric URL host");
        }
        wknet::session::HttpRequestRelease(explicitRequest);
        wknet::session::SessionClose(explicitSession);

        wknet::session::SessionHandle derivedSession = nullptr;
        status = wknet::session::SessionCreate(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            nullptr,
            &derivedSession);
        Expect(NT_SUCCESS(status), "engine SessionCreate accepts default TLS identity derivation");

        wknet::session::RequestHandle derivedRequest = nullptr;
        if (NT_SUCCESS(status))
        {
            status = wknet::session::HttpRequestCreate(derivedSession, &derivedRequest);
        }
        if (NT_SUCCESS(status))
        {
            status = wknet::session::HttpRequestSetUrl(
                derivedRequest,
                NumericUrl,
                sizeof(NumericUrl) - 1);
        }
        Expect(NT_SUCCESS(status), "HTTPS numeric URL derives the default TLS identity");
        if (derivedRequest != nullptr)
        {
            Expect(
                derivedRequest->Tls.ServerName == derivedRequest->Host &&
                    derivedRequest->Tls.ServerNameLength == Length("127.0.0.1"),
                "default TLS identity continues to derive from the HTTPS URL host");
        }
        wknet::session::HttpRequestRelease(derivedRequest);
        wknet::session::SessionClose(derivedSession);
    }

    void TestAcceptEncodingQValueOptions() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for Accept-Encoding qvalue options");

        wknet::http::AcceptEncodingPreference preferences[] = {
            { wknet::http::AcceptCoding::Brotli, 800 },
            { wknet::http::AcceptCoding::Identity, 0 },
            { wknet::http::AcceptCoding::Any, 0 }
        };
        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.AcceptEncodingPreferences = preferences;
        options.AcceptEncodingPreferenceCount = sizeof(preferences) / sizeof(preferences[0]);

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/qvalue";
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(NT_SUCCESS(status), "GetEx succeeds with custom Accept-Encoding qvalues");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Accept-Encoding: br;q=0.8, identity;q=0, *;q=0\r\n"),
            "custom Accept-Encoding qvalues are emitted");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAcceptEncodingRejectsInvalidPreferences() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for invalid Accept-Encoding options");

        wknet::http::AcceptEncodingPreference preferences[] = {
            { wknet::http::AcceptCoding::Gzip, 1000 },
            { wknet::http::AcceptCoding::Gzip, 500 }
        };
        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.AcceptEncodingPreferences = preferences;
        options.AcceptEncodingPreferenceCount = sizeof(preferences) / sizeof(preferences[0]);

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/qvalue";
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(status == STATUS_INVALID_PARAMETER, "duplicate Accept-Encoding preference is rejected");
        Expect(captured.CallCount == 0, "invalid Accept-Encoding options do not reach transport");
        Expect(resp == nullptr, "invalid Accept-Encoding options do not allocate response");

        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAcceptEncodingQZeroResponseFailsClosed() noexcept
    {
        char response[256] = {};
        const int headerLength = snprintf(
            response,
            sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: gzip\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            sizeof(GzipBody));
        Expect(headerLength > 0, "gzip content-encoding fixture header builds");
        SIZE_T responseLength = static_cast<SIZE_T>(headerLength);
        Expect(responseLength + sizeof(GzipBody) <= sizeof(response), "gzip content-encoding fixture fits");
        if (responseLength + sizeof(GzipBody) <= sizeof(response)) {
            memcpy(response + responseLength, GzipBody, sizeof(GzipBody));
            responseLength += sizeof(GzipBody);
        }

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for Accept-Encoding fail-closed");

        wknet::http::AcceptEncodingPreference preferences[] = {
            { wknet::http::AcceptCoding::Gzip, 0 },
            { wknet::http::AcceptCoding::Identity, 1000 }
        };
        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.AcceptEncodingPreferences = preferences;
        options.AcceptEncodingPreferenceCount = sizeof(preferences) / sizeof(preferences[0]);

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/qzero";
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "q=0 content coding response fails closed");
        Expect(captured.CallCount == 1, "q=0 response is rejected after transport response");
        Expect(resp == nullptr, "q=0 response does not allocate response");

        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestCustomAcceptEncodingHeaderDrivesResponseValidation() noexcept
    {
        char response[256] = {};
        const int headerLength = snprintf(
            response,
            sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: gzip\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            sizeof(GzipBody));
        Expect(headerLength > 0, "custom Accept-Encoding gzip fixture header builds");
        SIZE_T responseLength = static_cast<SIZE_T>(headerLength);
        Expect(responseLength + sizeof(GzipBody) <= sizeof(response), "custom Accept-Encoding gzip fixture fits");
        if (responseLength + sizeof(GzipBody) <= sizeof(response)) {
            memcpy(response + responseLength, GzipBody, sizeof(GzipBody));
            responseLength += sizeof(GzipBody);
        }

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for custom Accept-Encoding validation");

        wknet::http::Headers* headers = nullptr;
        status = wknet::http::HeadersCreate(&headers);
        Expect(NT_SUCCESS(status), "HeadersCreate succeeds for custom Accept-Encoding validation");
        status = wknet::http::HeadersAdd(headers, "Accept-Encoding", "identity");
        Expect(NT_SUCCESS(status), "identity Accept-Encoding header is added");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/custom-accept-encoding";
        status = wknet::http::GetEx(session, url, Length(url), headers, nullptr, &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "custom identity Accept-Encoding rejects gzip response");
        Expect(captured.CallCount == 1, "custom Accept-Encoding validation reaches transport once");
        Expect(resp == nullptr, "custom Accept-Encoding rejected response is not allocated");

        wknet::http::HeadersRelease(headers);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestContentCodingMaterialsDecodeDcz() noexcept
    {
        char response[256] = {};
        const int headerLength = snprintf(
            response,
            sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: dcz\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            sizeof(DczBody));
        Expect(headerLength > 0, "dcz content-encoding fixture header builds");
        SIZE_T responseLength = static_cast<SIZE_T>(headerLength);
        Expect(responseLength + sizeof(DczBody) <= sizeof(response), "dcz content-encoding fixture fits");
        if (responseLength + sizeof(DczBody) <= sizeof(response)) {
            memcpy(response + responseLength, DczBody, sizeof(DczBody));
            responseLength += sizeof(DczBody);
        }

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for dcz material decode");

        wknet::http::AcceptEncodingPreference preferences[] = {
            { wknet::http::AcceptCoding::DictionaryCompressedZstd, 1000 },
            { wknet::http::AcceptCoding::Identity, 1000 }
        };
        wknet::http::CodingExternalMaterial material = {};
        material.Coding = wknet::http::ContentCoding::DictionaryCompressedZstd;
        material.Dictionary = ZstdDictionary;
        material.DictionaryLength = sizeof(ZstdDictionary);
        wknet::http::CodingDecodeMaterials materials = {};
        materials.Items = &material;
        materials.ItemCount = 1;

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.AcceptEncodingPreferences = preferences;
        options.AcceptEncodingPreferenceCount = sizeof(preferences) / sizeof(preferences[0]);
        options.ContentCodingMaterials = &materials;

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/dcz";
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(NT_SUCCESS(status), "GetEx decodes dcz with content coding materials");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Accept-Encoding: dcz, identity\r\n"),
            "dcz Accept-Encoding preference is emitted");
        Expect(wknet::http::ResponseBodyLength(resp) == Length(EncodedBodyLiteral), "dcz decoded body length matches");
        const UCHAR* body = wknet::http::ResponseBody(resp);
        Expect(
            body != nullptr &&
                memcmp(body, EncodedBodyLiteral, Length(EncodedBodyLiteral)) == 0,
            "dcz decoded body matches");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestTraceRequiresExplicitOptIn() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for TRACE test");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/debug";
        status = wknet::http::Trace(session, url, Length(url), &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "TRACE without opt-in is rejected");
        Expect(captured.CallCount == 0, "TRACE without opt-in does not reach transport");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagAllowTrace;
        status = wknet::http::TraceEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(NT_SUCCESS(status), "TRACE with opt-in succeeds");
        Expect(captured.CallCount == 1, "TRACE with opt-in reaches transport once");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "TRACE /debug HTTP/1.1\r\n"),
            "TRACE request line is emitted");
        Expect(
            !BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Content-Length:"),
            "TRACE request has no body framing");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestTypedRangeAndConditionHeaders() noexcept
    {
        const char* response =
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for Range helpers");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for Range helpers");

        const char* url = "http://example.com/file";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for Range helpers");

        status = wknet::http::RequestSetRangeBytes(request, 100, 50, true);
        Expect(status == STATUS_INVALID_PARAMETER, "Range helper rejects inverted byte range");

        status = wknet::http::RequestSetRangeBytes(request, 5, 9, true);
        Expect(NT_SUCCESS(status), "Range helper accepts byte range");

        const char* etag = "\"abc\"";
        status = wknet::http::RequestSetIfNoneMatch(request, etag, Length(etag));
        Expect(NT_SUCCESS(status), "If-None-Match helper accepts ETag");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, &resp);
        Expect(NT_SUCCESS(status), "Range helper request sends");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Range: bytes=5-9\r\n"),
            "Range helper emits byte range header");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "If-None-Match: \"abc\"\r\n"),
            "condition helper emits If-None-Match header");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestTypedSuffixRangeHeader() noexcept
    {
        const char* response =
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for suffix Range helper");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for suffix Range helper");

        const char* url = "http://example.com/file";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for suffix Range helper");

        status = wknet::http::RequestSetRangeSuffix(request, 0);
        Expect(status == STATUS_INVALID_PARAMETER, "suffix Range helper rejects zero length");

        status = wknet::http::RequestSetRangeSuffix(request, 128);
        Expect(NT_SUCCESS(status), "suffix Range helper accepts length");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, &resp);
        Expect(NT_SUCCESS(status), "suffix Range helper request sends");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Range: bytes=-128\r\n"),
            "suffix Range helper emits header");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestEngineTypedRangeAndConditionHeaders() noexcept
    {
        const char* response =
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::session::SessionHandle session = nullptr;
        NTSTATUS status = wknet::session::SessionCreate(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            nullptr,
            &session);
        Expect(NT_SUCCESS(status), "engine SessionCreate succeeds for typed Range helpers");

        wknet::session::RequestHandle request = nullptr;
        status = wknet::session::HttpRequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "engine RequestCreate succeeds for typed Range helpers");

        const char* url = "http://example.com/file";
        status = wknet::session::HttpRequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "engine RequestSetUrl succeeds for typed Range helpers");

        status = wknet::session::HttpRequestSetRangeSuffix(request, 256);
        Expect(NT_SUCCESS(status), "engine suffix Range helper accepts length");

        const char* etag = "\"engine\"";
        status = wknet::session::HttpRequestSetIfMatch(request, etag, Length(etag));
        Expect(NT_SUCCESS(status), "engine If-Match helper accepts ETag");

        wknet::session::ResponseHandle resp = nullptr;
        status = wknet::session::HttpSendSync(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "engine typed Range helper request sends");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Range: bytes=-256\r\n"),
            "engine Range helper emits suffix header");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "If-Match: \"engine\"\r\n"),
            "engine condition helper emits If-Match header");

        wknet::session::ResponseRelease(resp);
        wknet::session::HttpRequestRelease(request);
        wknet::session::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestResponseDuplicateHeaderSemantics() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "X-Repeat: one\r\n"
            "Set-Cookie: a=1\r\n"
            "X-Repeat: two\r\n"
            "Set-Cookie: b=2\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for duplicate header semantics");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/headers";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds for duplicate header semantics");
        Expect(wknet::http::ResponseHeaderCount(resp) == 5, "duplicate headers remain enumerable");

        const char* value = nullptr;
        SIZE_T valueLength = 0;
        status = wknet::http::ResponseGetHeader(
            resp,
            "X-Repeat",
            Length("X-Repeat"),
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "duplicate header is found by name");
        Expect(valueLength == Length("one") && memcmp(value, "one", valueLength) == 0, "header lookup returns first duplicate");

        status = wknet::http::ResponseGetHeader(
            resp,
            "Set-Cookie",
            Length("Set-Cookie"),
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "Set-Cookie is found by name");
        Expect(valueLength == Length("a=1") && memcmp(value, "a=1", valueLength) == 0, "Set-Cookie lookup returns first field");

        const char* name = nullptr;
        SIZE_T nameLength = 0;
        status = wknet::http::ResponseGetHeaderAt(
            resp,
            2,
            &name,
            &nameLength,
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "second X-Repeat is readable by index");
        Expect(nameLength == Length("X-Repeat") && memcmp(name, "X-Repeat", nameLength) == 0, "indexed duplicate header name matches");
        Expect(valueLength == Length("two") && memcmp(value, "two", valueLength) == 0, "indexed duplicate header value matches");

        status = wknet::http::ResponseGetHeaderAt(
            resp,
            3,
            &name,
            &nameLength,
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "second Set-Cookie is readable by index");
        Expect(nameLength == Length("Set-Cookie") && memcmp(name, "Set-Cookie", nameLength) == 0, "indexed Set-Cookie header name matches");
        Expect(valueLength == Length("b=2") && memcmp(value, "b=2", valueLength) == 0, "indexed Set-Cookie value is not merged");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestResponseTransferEncodingDecoded() noexcept
    {
        char response[256] = {};
        const SIZE_T responseLength = BuildTransferGzipChunkedResponse(response, sizeof(response));
        Expect(responseLength != 0, "transfer-coded wknet response fixture builds");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for transfer-coded response");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/transfer";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds for transfer-coded response");
        Expect(captured.CallCount == 1, "transfer-coded response reaches transport once");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "transfer-coded response status code is 200");
        Expect(
            wknet::http::ResponseBodyLength(resp) == Length(EncodedBodyLiteral),
            "transfer-coded response body length is decoded");
        const UCHAR* body = wknet::http::ResponseBody(resp);
        Expect(
            body != nullptr &&
                memcmp(body, EncodedBodyLiteral, Length(EncodedBodyLiteral)) == 0,
            "transfer-coded response body is decoded");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestTransferCodingCloseDelimitedHonorsTestTransportEof() noexcept
    {
        char response[256] = {};
        const SIZE_T responseLength = BuildTransferGzipCloseDelimitedResponse(response, sizeof(response));
        Expect(responseLength != 0, "close-delimited gzip transfer fixture builds");

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = response;
        capture.FirstResponseLength = responseLength;
        capture.FirstConnectionReusable = true;
        wknet::http::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reusable close-delimited test");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/te-gzip";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "test transport does not complete close-delimited transfer while reusable");
        Expect(resp == nullptr, "incomplete close-delimited transfer returns no response");
        Expect(capture.CallCount == 1, "reusable close-delimited attempt reaches transport once");
        wknet::http::SessionClose(session);

        capture = {};
        capture.FirstResponse = response;
        capture.FirstResponseLength = responseLength;
        capture.FirstConnectionReusable = false;
        wknet::http::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        session = nullptr;
        status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for EOF close-delimited test");

        resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "EOF close-delimited transfer succeeds");
        Expect(wknet::http::ResponseBodyLength(resp) == Length(EncodedBodyLiteral), "EOF close-delimited transfer body length is decoded");
        const UCHAR* body = wknet::http::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, EncodedBodyLiteral, Length(EncodedBodyLiteral)) == 0, "EOF close-delimited transfer body is decoded");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestResponseTrailersAreExposed() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "hello\r\n"
            "0\r\n"
            "Digest: sha-256=abc\r\n"
            "\r\n";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for trailer response");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/trailer";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds for trailer response");
        Expect(wknet::http::ResponseBodyLength(resp) == Length("hello"), "trailer response body length matches");
        Expect(wknet::http::ResponseTrailerCount(resp) == 1, "response trailer count is exposed");

        const char* value = nullptr;
        SIZE_T valueLength = 0;
        status = wknet::http::ResponseGetTrailer(
            resp,
            "Digest",
            Length("Digest"),
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "response trailer is found by name");
        Expect(valueLength == Length("sha-256=abc") &&
            memcmp(value, "sha-256=abc", valueLength) == 0,
            "response trailer value matches");

        const char* name = nullptr;
        SIZE_T nameLength = 0;
        status = wknet::http::ResponseGetTrailerAt(
            resp,
            0,
            &name,
            &nameLength,
            &value,
            &valueLength);
        Expect(NT_SUCCESS(status), "response trailer is readable by index");
        Expect(nameLength == Length("Digest") &&
            memcmp(name, "Digest", nameLength) == 0,
            "response trailer name matches");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestInformationalResponsesAreSkipped() noexcept
    {
        const char* response =
            "HTTP/1.1 103 Early Hints\r\n"
            "Link: </style.css>; rel=preload\r\n"
            "\r\n"
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "final";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for informational response test");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/informational";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "Get succeeds after informational responses");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "informational responses are skipped before final status");
        Expect(wknet::http::ResponseBodyLength(resp) == Length("final"), "final response body length is returned");
        const UCHAR* body = wknet::http::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, "final", Length("final")) == 0, "final response body is returned");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSessionMaxResponseBytesLimitsSimpleApi() noexcept
    {
        char response[5100] = {};
        const SIZE_T responseLength = BuildLargeHttpResponse(response, sizeof(response));
        Expect(responseLength != 0, "large response fixture is built");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = 64;

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate accepts unsigned max response limit");

        wknet::http::SessionConfig legacyOversizedConfig = wknet::http::DefaultSessionConfig();
        legacyOversizedConfig.MaxResponseBytes = (64 * 1024 * 1024) + 1;
        wknet::http::Session* legacyOversizedSession = nullptr;
        status = wknet::http::SessionCreate(&legacyOversizedConfig, &legacyOversizedSession);
        Expect(NT_SUCCESS(status), "SessionCreate accepts response limits above the old hard cap");
        wknet::http::SessionClose(legacyOversizedSession);

        const char* url = "http://example.com/large";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "simple Get honors session MaxResponseBytes");
        Expect(resp == nullptr, "session-limited simple Get does not allocate response");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for max response test");
        if (NT_SUCCESS(status)) {
            status = wknet::http::RequestSetUrl(request, url, Length(url));
            Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for max response test");
        }

        wknet::http::SendOptions limitedOptions = wknet::http::DefaultSendOptions();
        limitedOptions.MaxResponseBytes = 64;
        status = wknet::http::Send(session, request, &limitedOptions, &resp);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "explicit nonzero MaxResponseBytes limits response");
        Expect(resp == nullptr, "limited response is not allocated");

        wknet::http::SendOptions legacyOversizedOptions = wknet::http::DefaultSendOptions();
        legacyOversizedOptions.MaxResponseBytes = (64 * 1024 * 1024) + 1;
        status = wknet::http::Send(session, request, &legacyOversizedOptions, &resp);
        Expect(NT_SUCCESS(status), "Send accepts response limits above the old hard cap");
        Expect(wknet::http::ResponseBodyLength(resp) == 5000, "legacy oversized limit returns large body");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        wknet::http::SendOptions largeOptions = wknet::http::DefaultSendOptions();
        largeOptions.MaxResponseBytes = 8192;
        status = wknet::http::Send(session, request, &largeOptions, &resp);
        Expect(NT_SUCCESS(status), "explicit larger MaxResponseBytes overrides session limit");
        Expect(wknet::http::ResponseBodyLength(resp) == 5000, "explicit larger limit returns large body");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);

        wknet::http::SessionConfig unlimitedConfig = wknet::http::DefaultSessionConfig();
        Expect(unlimitedConfig.MaxResponseBytes == 0, "DefaultSessionConfig leaves response aggregation unlimited");
        wknet::http::Session* unlimitedSession = nullptr;
        status = wknet::http::SessionCreate(&unlimitedConfig, &unlimitedSession);
        Expect(NT_SUCCESS(status), "SessionCreate accepts unlimited response aggregation");
        status = wknet::http::Get(unlimitedSession, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "simple Get with default unlimited aggregation succeeds");
        Expect(wknet::http::ResponseBodyLength(resp) == 5000, "default unlimited aggregation returns large body");
        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(unlimitedSession);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestResponseBodyCallbackIgnoresAggregationLimit() noexcept
    {
        char response[5100] = {};
        const SIZE_T responseLength = BuildLargeHttpResponse(response, sizeof(response));
        Expect(responseLength != 0, "large callback response fixture is built");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = 64;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for callback response limit test");

        BodyCallbackCapture callback = {};
        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.OnBody = CountingBodyCallback;
        options.CallbackContext = &callback;

        const char* url = "http://example.com/large-callback";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(NT_SUCCESS(status), "OnBody-only response ignores session aggregation limit");
        Expect(resp == nullptr, "OnBody-only response does not allocate aggregate response");
        Expect(callback.CallCount >= 1, "OnBody-only response callback runs at least once");
        Expect(callback.TotalBytes == 5000, "OnBody-only response callback receives full body");
        Expect(callback.FinalChunk, "OnBody-only response callback marks final chunk");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    SIZE_T BuildGzipContentEncodingResponse(char* buffer, SIZE_T capacity) noexcept
    {
        if (buffer == nullptr) {
            return 0;
        }
        const int headerLength = snprintf(
            buffer,
            capacity,
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: gzip\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            sizeof(GzipBody));
        if (headerLength <= 0 || static_cast<SIZE_T>(headerLength) > capacity) {
            return 0;
        }
        SIZE_T responseLength = static_cast<SIZE_T>(headerLength);
        if (responseLength + sizeof(GzipBody) > capacity) {
            return 0;
        }
        memcpy(buffer + responseLength, GzipBody, sizeof(GzipBody));
        return responseLength + sizeof(GzipBody);
    }

    void TestResponseBodyCallbackDecodesGzipContentEncoding() noexcept
    {
        char response[256] = {};
        const SIZE_T responseLength = BuildGzipContentEncodingResponse(response, sizeof(response));
        Expect(responseLength != 0, "gzip OnBody fixture builds");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for OnBody gzip decode");

        BodyCallbackCapture callback = {};
        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.OnBody = CountingBodyCallback;
        options.CallbackContext = &callback;

        const char* url = "http://example.com/gzip-onbody";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(NT_SUCCESS(status), "OnBody gzip Content-Encoding request succeeds");
        Expect(resp == nullptr, "OnBody-only gzip response does not allocate aggregate response");
        Expect(callback.FinalChunk, "OnBody gzip callback marks final chunk");
        Expect(
            callback.TotalBytes == Length(EncodedBodyLiteral),
            "OnBody gzip callback receives decoded byte count");
        Expect(
            callback.BufferLength == Length(EncodedBodyLiteral) &&
                memcmp(callback.Buffer, EncodedBodyLiteral, Length(EncodedBodyLiteral)) == 0,
            "OnBody gzip callback receives decoded plaintext");
        Expect(
            callback.BufferLength < 2 ||
                !(static_cast<unsigned char>(callback.Buffer[0]) == 0x1f &&
                    static_cast<unsigned char>(callback.Buffer[1]) == 0x8b),
            "OnBody gzip callback does not receive raw gzip magic");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestResponseBodyCallbackAggregateDecodesGzip() noexcept
    {
        char response[256] = {};
        const SIZE_T responseLength = BuildGzipContentEncodingResponse(response, sizeof(response));
        Expect(responseLength != 0, "gzip AggregateWithCallbacks fixture builds");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for AggregateWithCallbacks gzip decode");

        BodyCallbackCapture callback = {};
        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagAggregateWithCallbacks;
        options.OnBody = CountingBodyCallback;
        options.CallbackContext = &callback;

        const char* url = "http://example.com/gzip-aggregate-onbody";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(NT_SUCCESS(status), "AggregateWithCallbacks gzip Content-Encoding request succeeds");
        Expect(resp != nullptr, "AggregateWithCallbacks gzip allocates response");
        Expect(
            resp != nullptr &&
                wknet::http::ResponseBodyLength(resp) == Length(EncodedBodyLiteral) &&
                memcmp(
                    wknet::http::ResponseBody(resp),
                    EncodedBodyLiteral,
                    Length(EncodedBodyLiteral)) == 0,
            "AggregateWithCallbacks gzip response body is decoded plaintext");
        Expect(
            callback.TotalBytes == Length(EncodedBodyLiteral) &&
                callback.BufferLength == Length(EncodedBodyLiteral) &&
                memcmp(callback.Buffer, EncodedBodyLiteral, Length(EncodedBodyLiteral)) == 0,
            "AggregateWithCallbacks gzip OnBody also receives decoded plaintext");
        Expect(callback.FinalChunk, "AggregateWithCallbacks gzip OnBody marks final chunk");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestResponseBodyCallbackGzipHonorsAcceptEncodingPolicy() noexcept
    {
        char response[256] = {};
        const SIZE_T responseLength = BuildGzipContentEncodingResponse(response, sizeof(response));
        Expect(responseLength != 0, "gzip policy OnBody fixture builds");

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = responseLength;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for OnBody Accept-Encoding policy");

        wknet::http::AcceptEncodingPreference preferences[] = {
            { wknet::http::AcceptCoding::Identity, 1000 }
        };
        BodyCallbackCapture callback = {};
        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.OnBody = CountingBodyCallback;
        options.CallbackContext = &callback;
        options.AcceptEncodingPreferences = preferences;
        options.AcceptEncodingPreferenceCount = sizeof(preferences) / sizeof(preferences[0]);

        const char* url = "http://example.com/gzip-onbody-policy";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "OnBody gzip fails closed under identity Accept-Encoding");
        Expect(resp == nullptr, "policy-rejected OnBody gzip does not allocate response");
        Expect(callback.TotalBytes == 0, "policy-rejected OnBody gzip delivers no body bytes");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRequestRejectsHeaderAndUrlInjection() noexcept
    {
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for injection test");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for injection test");

        const char* badHeaderName = "Bad\rName";
        status = wknet::http::RequestSetHeader(
            request,
            badHeaderName,
            Length(badHeaderName),
            "value",
            Length("value"));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetHeader rejects CR in header name");

        const char* badHeaderValue = "ok\r\nInjected: yes";
        status = wknet::http::RequestSetHeader(
            request,
            "X-Test",
            Length("X-Test"),
            badHeaderValue,
            Length(badHeaderValue));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetHeader rejects CRLF in header value");

        const char* badUrl = "http://example.com/path\r\nInjected: yes";
        status = wknet::http::RequestSetUrl(request, badUrl, Length(badUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects CRLF in request target");

        const char* spacedUrl = "http://example.com/a b";
        status = wknet::http::RequestSetUrl(request, spacedUrl, Length(spacedUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects spaces in request target");

        const char* userInfoUrl = "http://user@example.com/path";
        status = wknet::http::RequestSetUrl(request, userInfoUrl, Length(userInfoUrl));
        Expect(status == STATUS_NOT_SUPPORTED, "RequestSetUrl rejects userinfo authority");

        const char* unsupportedAuthorityUrl = "http://example.com:80:90/path";
        status = wknet::http::RequestSetUrl(
            request,
            unsupportedAuthorityUrl,
            Length(unsupportedAuthorityUrl));
        Expect(status == STATUS_NOT_SUPPORTED, "RequestSetUrl rejects unsupported authority form");

        const char* badContentType = "text/plain\r\nX-Test: yes";
        status = wknet::http::RequestSetTextBody(
            request,
            "hello",
            Length("hello"),
            badContentType,
            Length(badContentType));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetTextBody rejects CRLF in Content-Type");

        wknet::http::MultipartPart part = {};
        part.Kind = wknet::http::BodyPartKind::Field;
        part.Name = "field";
        part.NameLength = Length(part.Name);
        part.Value = "value";
        part.ValueLength = Length(part.Value);
        part.ContentType = badContentType;
        part.ContentTypeLength = Length(badContentType);
        status = wknet::http::RequestSetMultipartBody(request, &part, 1);
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetMultipartBody rejects CRLF in part Content-Type");

        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
    }

    void TestUrlRequestTargetAndHostSemantics() noexcept
    {
        static const char response[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = sizeof(response) - 1;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for URL semantics");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://[2001:db8::1]?q=1#fragment";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "IPv6 query-only URL succeeds");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "GET /?q=1 HTTP/1.1\r\n"),
            "query-only URL is sent as origin-form with leading slash and no fragment");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Host: [2001:db8::1]\r\n"),
            "IPv6 Host header is bracketed");
        wknet::http::ResponseRelease(resp);

        captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = sizeof(response) - 1;
        resp = nullptr;
        const char* percentUrl = "http://example.com/a%2Fb?q=x%2Fy#drop";
        status = wknet::http::Get(session, percentUrl, Length(percentUrl), &resp);
        Expect(NT_SUCCESS(status), "percent-encoded URL succeeds");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "GET /a%2Fb?q=x%2Fy HTTP/1.1\r\n"),
            "percent-encoded path and query are passed through without normalization");
        wknet::http::ResponseRelease(resp);

        captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = sizeof(response) - 1;
        resp = nullptr;
        const char idnaUrl[] = {
            'h', 't', 't', 'p', ':', '/', '/', 'b',
            static_cast<char>(0xc3), static_cast<char>(0xbc),
            'c', 'h', 'e', 'r', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            '/', 'p', 'a', 't', 'h', '\0'
        };
        status = wknet::http::Get(session, idnaUrl, Length(idnaUrl), &resp);
        Expect(NT_SUCCESS(status), "IDNA U-label URL succeeds");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Host: xn--bcher-kva.example\r\n"),
            "IDNA U-label host is normalized to A-label for Host/SNI identity");
        wknet::http::ResponseRelease(resp);

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for URL rejection cases");

        const char* badPercentUrl = "http://example.com/a%2G";
        status = wknet::http::RequestSetUrl(request, badPercentUrl, Length(badPercentUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects invalid percent triplet");

        const char invalidUtf8HostUrl[] = {
            'h', 't', 't', 'p', ':', '/', '/', 'b',
            static_cast<char>(0xc3),
            'c', 'h', 'e', 'r', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '/', '\0'
        };
        status = wknet::http::RequestSetUrl(request, invalidUtf8HostUrl, Length(invalidUtf8HostUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects malformed UTF-8 host");

        const char* zoneIdUrl = "http://[fe80::1%25eth0]/";
        status = wknet::http::RequestSetUrl(request, zoneIdUrl, Length(zoneIdUrl));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetUrl rejects IPv6 zone id");

        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);

        static char longUrl[sizeof("http://example.com/") + 16383] = {};
        static char tooLongUrl[sizeof("http://example.com/") + 16384] = {};
        const char prefix[] = "http://example.com/";
        memcpy(longUrl, prefix, sizeof(prefix) - 1);
        for (SIZE_T index = sizeof(prefix) - 1; index < sizeof(longUrl) - 1; ++index) {
            longUrl[index] = 'a';
        }
        longUrl[sizeof(longUrl) - 1] = '\0';

        memcpy(tooLongUrl, prefix, sizeof(prefix) - 1);
        for (SIZE_T index = sizeof(prefix) - 1; index < sizeof(tooLongUrl) - 1; ++index) {
            tooLongUrl[index] = 'a';
        }
        tooLongUrl[sizeof(tooLongUrl) - 1] = '\0';

        LongUrlCapture longCapture = {};
        wknet::http::test::SetHttpTransport(LongUrlTransport, &longCapture);
        session = nullptr;
        status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for long URL");

        resp = nullptr;
        status = wknet::http::Get(session, longUrl, Length(longUrl), &resp);
        Expect(NT_SUCCESS(status), "16384-octet request-target succeeds");
        Expect(longCapture.CallCount == 1, "long URL reaches transport");
        Expect(longCapture.SawLongOriginForm, "long URL is sent as 16384-octet origin-form target");
        wknet::http::ResponseRelease(resp);

        request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for too-long URL");
        status = wknet::http::RequestSetUrl(request, tooLongUrl, Length(tooLongUrl));
        Expect(status == STATUS_BUFFER_TOO_SMALL, "RequestSetUrl rejects request-target above 16384 octets");

        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestReusedConnectionFailureRetriesWithFreshConnection() noexcept
    {
        ReusedFailureCapture capture = {};
        wknet::http::test::SetHttpTransport(ReusedFailureTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reused connection retry");

        const char* url = "http://example.com/retry";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first pooled Get succeeds");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "stale pooled Get retries with fresh connection");
        Expect(capture.CallCount == 3, "transport sees initial, failed reuse, and retry calls");
        Expect(capture.ReusedCallCount == 1, "one reused connection attempt fails");
        Expect(capture.NewConnectionCallCount == 2, "retry uses a fresh connection");
        Expect(capture.FirstConnectionId != 0, "first connection id captured");
        Expect(capture.RetryConnectionId != 0, "retry connection id captured");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "retry uses a different pool connection id");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "retry status code is 200");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSilentClosedPooledConnectionReconnectsWhenCalled() noexcept
    {
        ReusedFailureCapture capture = {};
        capture.FailureStatus = STATUS_CONNECTION_DISCONNECTED;
        wknet::http::test::SetHttpTransport(ReusedFailureTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for silent-close retry");

        const char* url = "http://example.com/silent-close";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first silent-close seed Get succeeds");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "silent-closed pooled Get reconnects when called");
        Expect(capture.CallCount == 3, "silent-close transport sees seed, failed reuse, and reconnect");
        Expect(capture.ReusedCallCount == 1, "silent-close test observes one stale pooled attempt");
        Expect(capture.NewConnectionCallCount == 2, "silent-close reconnect uses a fresh connection");
        Expect(capture.FirstConnectionId != 0, "silent-close first connection id captured");
        Expect(capture.RetryConnectionId != 0, "silent-close retry connection id captured");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "silent-close retry uses a different pool entry");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "silent-close retry status code is 200");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestReusedHeadTimeoutRetriesWithFreshConnection() noexcept
    {
        ReusedFailureCapture capture = {};
        capture.FailureStatus = STATUS_IO_TIMEOUT;
        wknet::http::test::SetHttpTransport(ReusedFailureTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reused HEAD timeout retry");

        const char* url = "http://example.com/retry-head-timeout";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first pooled Get succeeds before HEAD timeout");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Head(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "stale pooled HEAD timeout retries with fresh connection");
        Expect(capture.CallCount == 3, "HEAD timeout sees seed, failed reuse, and fresh retry");
        Expect(capture.ReusedCallCount == 1, "HEAD timeout attempts one stale pooled connection");
        Expect(capture.NewConnectionCallCount == 2, "HEAD timeout retry opens a fresh connection");
        Expect(capture.FirstConnectionId != 0, "HEAD timeout first connection id captured");
        Expect(capture.RetryConnectionId != 0, "HEAD timeout retry connection id captured");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "HEAD timeout retry uses a different pool entry");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "HEAD timeout retry status code is 200");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestReusedConnectionPostFailureDoesNotRetry() noexcept
    {
        ReusedFailureCapture capture = {};
        wknet::http::test::SetHttpTransport(ReusedFailureTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for reused POST retry test");

        const char* url = "http://example.com/retry-post";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first pooled Get succeeds before reused POST");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for reused POST");
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for reused POST");
        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for reused POST");
        const char* payload = "payload";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(payload),
            Length(payload));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for reused POST");

        status = wknet::http::Send(session, request, nullptr, &resp);
        Expect(status == STATUS_CONNECTION_RESET, "reused POST failure is not retried");
        Expect(capture.CallCount == 2, "reused POST sees initial and failed reuse only");
        Expect(capture.ReusedCallCount == 1, "reused POST attempts one stale connection");
        Expect(capture.NewConnectionCallCount == 1, "reused POST does not create retry connection");
        Expect(capture.RetryConnectionId == 0, "reused POST records no retry connection id");
        Expect(resp == nullptr, "reused POST failure returns no response");

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "GET after reused POST failure creates a clean connection");
        Expect(capture.CallCount == 3, "GET after reused POST failure does not reuse the failed pool entry");
        Expect(capture.ReusedCallCount == 1, "failed POST pool entry was removed before next request");
        Expect(capture.NewConnectionCallCount == 2, "GET after reused POST failure opens a fresh connection");
        Expect(capture.RetryConnectionId != 0, "GET after reused POST failure captures fresh connection id");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "GET after reused POST failure uses a new pool entry");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestReusedConnectionPostRetrySignalDoesNotReplay() noexcept
    {
        ReusedFailureCapture capture = {};
        capture.FailureStatus = STATUS_RETRY;
        wknet::http::test::SetHttpTransport(ReusedFailureTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for POST retry-signal test");

        const char* url = "http://example.com/retry-post-signal";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first pooled Get succeeds before POST retry signal");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        const char* body = "payload";
        status = wknet::http::Post(
            session,
            url,
            Length(url),
            reinterpret_cast<const UCHAR*>(body),
            Length(body),
            &resp);
        Expect(status == STATUS_RETRY, "reused POST retry signal is not replayed");
        Expect(capture.CallCount == 2, "POST retry signal sees initial and failed reuse only");
        Expect(capture.ReusedCallCount == 1, "POST retry signal attempts one pooled connection");
        Expect(capture.NewConnectionCallCount == 1, "POST retry signal does not create replay connection");
        Expect(capture.RetryConnectionId == 0, "POST retry signal records no retry connection id");
        Expect(resp == nullptr, "POST retry signal returns no response");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttp11PipelineDefaultDisabled() noexcept
    {
        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        Http11PipelineCapture capture = {};
        capture.RawResponse = responseBytes;
        capture.RawResponseLength = sizeof(responseBytes) - 1;
        wknet::http::test::SetHttpTransport(Http11PipelineTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for default HTTP/1.1 pipeline test");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/pipeline-default";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "default HTTP/1.1 GET succeeds");
        Expect(capture.CallCount == 1, "default pipeline test reaches transport once");
        Expect(!capture.LastPipelineEnabled, "HTTP/1.1 pipeline is disabled by default");
        Expect(!capture.LastPipelineLease, "default GET does not take a pipeline lease");
        Expect(capture.LastPipelineSequence == 0, "default GET has no pipeline sequence");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttp11PipelineGetOptIn() noexcept
    {
        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        Http11PipelineCapture capture = {};
        capture.RawResponse = responseBytes;
        capture.RawResponseLength = sizeof(responseBytes) - 1;
        wknet::http::test::SetHttpTransport(Http11PipelineTransport, &capture);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.EnableHttp11Pipeline = true;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for opt-in HTTP/1.1 pipeline test");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/pipeline-get";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "opt-in HTTP/1.1 GET succeeds");
        Expect(capture.CallCount == 1, "opt-in pipeline GET reaches transport once");
        Expect(capture.LastPipelineEnabled, "opt-in GET marks HTTP/1.1 pipeline enabled");
        Expect(capture.LastPipelineLease, "opt-in GET takes a pipeline lease");
        Expect(capture.LastPipelineSequence == 1, "first opt-in pipeline GET uses sequence 1");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttp11PipelinePostDefaultRejected() noexcept
    {
        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        Http11PipelineCapture capture = {};
        capture.RawResponse = responseBytes;
        capture.RawResponseLength = sizeof(responseBytes) - 1;
        wknet::http::test::SetHttpTransport(Http11PipelineTransport, &capture);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.EnableHttp11Pipeline = true;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for POST pipeline rejection test");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/pipeline-post";
        const char* body = "payload";
        status = wknet::http::Post(
            session,
            url,
            Length(url),
            reinterpret_cast<const UCHAR*>(body),
            Length(body),
            &resp);
        Expect(NT_SUCCESS(status), "opt-in POST succeeds outside HTTP/1.1 pipeline");
        Expect(capture.CallCount == 1, "POST pipeline rejection test reaches transport once");
        Expect(!capture.LastPipelineEnabled, "POST is not pipeline-eligible by default");
        Expect(!capture.LastPipelineLease, "POST does not take a pipeline lease by default");
        Expect(capture.LastPipelineSequence == 0, "POST has no pipeline sequence by default");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestConnectionPoolHonorsMaxConnectionsPerHost() noexcept
    {
        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 4, 1, 30000);
        Expect(NT_SUCCESS(status), "connection pool initializes with per-host limit");

        wknet::session::ConnectionPoolKey firstKey = {};
        memcpy(firstKey.Scheme, "http", Length("http"));
        firstKey.SchemeLength = Length("http");
        memcpy(firstKey.Host, "example.com", Length("example.com"));
        firstKey.HostLength = Length("example.com");
        firstKey.Port = 80;

        wknet::session::ConnectionPoolKey secondKey = firstKey;
        memcpy(secondKey.Host, "other.example", Length("other.example"));
        secondKey.HostLength = Length("other.example");

        wknet::session::PooledConnection* first = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            firstKey,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &first,
            &reused);
        Expect(NT_SUCCESS(status), "first per-host connection acquires");
        Expect(first != nullptr && !reused, "first per-host acquire is fresh");

        wknet::session::PooledConnection* blocked = nullptr;
        reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            firstKey,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &blocked,
            &reused);
        Expect(status == STATUS_INSUFFICIENT_RESOURCES, "same host is limited while first is active");
        Expect(blocked == nullptr, "blocked same-host acquire returns no connection");

        wknet::session::PooledConnection* other = nullptr;
        reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            secondKey,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &other,
            &reused);
        Expect(NT_SUCCESS(status), "different host can acquire under same pool capacity");
        Expect(other != nullptr && !reused, "different host acquire is fresh");

        wknet::session::ConnectionPoolRelease(&pool, other, false);
        wknet::session::ConnectionPoolRelease(&pool, first, false);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestConnectionPoolSharesActiveHttp1PipelineLeases() noexcept
    {
        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000);
        Expect(NT_SUCCESS(status), "connection pool initializes for HTTP/1.1 pipeline sharing");

        wknet::session::ConnectionPoolKey key = {};
        memcpy(key.Scheme, "http", Length("http"));
        key.SchemeLength = Length("http");
        memcpy(key.Host, "example.com", Length("example.com"));
        key.HostLength = Length("example.com");
        key.Port = 80;

        wknet::session::PooledConnection* first = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquireHttp1Pipeline(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            2,
            &first,
            &reused);
        Expect(NT_SUCCESS(status), "first HTTP/1.1 pipeline acquire succeeds");
        Expect(first != nullptr && !reused, "first HTTP/1.1 pipeline acquire is fresh");

        status = wknet::session::ConnectionPoolPromoteHttp1PipelineLease(&pool, first, 2);
        Expect(NT_SUCCESS(status), "first HTTP/1.1 lease promotes connection to pipeline mode");
        Expect(
            wknet::session::ConnectionPoolHasHttp1PipelineLease(first),
            "promoted connection reports HTTP/1.1 pipeline lease");

        ULONG firstSequence = 0;
        status = wknet::session::ConnectionPoolBeginHttp1PipelineSend(&pool, first, &firstSequence);
        Expect(NT_SUCCESS(status), "first HTTP/1.1 pipeline send begins");
        Expect(firstSequence == 1, "first HTTP/1.1 pipeline sequence is 1");
        wknet::session::ConnectionPoolEndHttp1PipelineSend(first);

        wknet::session::PooledConnection* second = nullptr;
        reused = false;
        status = wknet::session::ConnectionPoolAcquireHttp1Pipeline(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            2,
            &second,
            &reused);
        Expect(NT_SUCCESS(status), "second HTTP/1.1 pipeline acquire succeeds");
        Expect(second == first && reused, "second HTTP/1.1 pipeline acquire shares active connection");

        ULONG secondSequence = 0;
        status = wknet::session::ConnectionPoolBeginHttp1PipelineSend(&pool, second, &secondSequence);
        Expect(NT_SUCCESS(status), "second HTTP/1.1 pipeline send begins");
        Expect(secondSequence == 2, "second HTTP/1.1 pipeline sequence is 2");
        wknet::session::ConnectionPoolEndHttp1PipelineSend(second);

        status = wknet::session::ConnectionPoolWaitHttp1PipelineReceiveTurn(&pool, first, firstSequence);
        Expect(NT_SUCCESS(status), "first HTTP/1.1 pipeline response turn is ready");

        const UCHAR extra[] = { 'H', 'T', 'T', 'P' };
        status = wknet::session::ConnectionPoolStoreHttp1PipelineBufferedBytes(
            &pool,
            first,
            extra,
            sizeof(extra));
        Expect(NT_SUCCESS(status), "HTTP/1.1 pipeline stores bytes for next response");

        SIZE_T bufferedLength = 0;
        status = wknet::session::ConnectionPoolHttp1PipelineBufferedLength(
            &pool,
            second,
            &bufferedLength);
        Expect(NT_SUCCESS(status), "HTTP/1.1 pipeline reports buffered bytes");
        Expect(bufferedLength == sizeof(extra), "HTTP/1.1 pipeline buffered byte count matches");

        UCHAR copied[sizeof(extra)] = {};
        SIZE_T copiedLength = 0;
        status = wknet::session::ConnectionPoolTakeHttp1PipelineBufferedBytes(
            &pool,
            second,
            copied,
            sizeof(copied),
            &copiedLength);
        Expect(NT_SUCCESS(status), "HTTP/1.1 pipeline takes buffered bytes");
        Expect(copiedLength == sizeof(extra), "HTTP/1.1 pipeline copied byte count matches");
        Expect(memcmp(copied, extra, sizeof(extra)) == 0, "HTTP/1.1 pipeline copied bytes match");

        wknet::session::ConnectionPoolCompleteHttp1PipelineReceive(&pool, first, firstSequence);
        status = wknet::session::ConnectionPoolWaitHttp1PipelineReceiveTurn(&pool, second, secondSequence);
        Expect(NT_SUCCESS(status), "second HTTP/1.1 pipeline response waits for FIFO turn");
        wknet::session::ConnectionPoolCompleteHttp1PipelineReceive(&pool, second, secondSequence);

        wknet::session::ConnectionPoolRelease(&pool, second, true);
        wknet::session::ConnectionPoolRelease(&pool, first, true);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestConnectionPoolHttp1PipelineFailureClosesLeases() noexcept
    {
        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000);
        Expect(NT_SUCCESS(status), "connection pool initializes for HTTP/1.1 pipeline failure");

        wknet::session::ConnectionPoolKey key = {};
        memcpy(key.Scheme, "http", Length("http"));
        key.SchemeLength = Length("http");
        memcpy(key.Host, "example.com", Length("example.com"));
        key.HostLength = Length("example.com");
        key.Port = 80;

        wknet::session::PooledConnection* first = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquireHttp1Pipeline(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            2,
            &first,
            &reused);
        Expect(NT_SUCCESS(status), "first failure pipeline acquire succeeds");
        status = wknet::session::ConnectionPoolPromoteHttp1PipelineLease(&pool, first, 2);
        Expect(NT_SUCCESS(status), "failure pipeline promote succeeds");

        ULONG firstSequence = 0;
        status = wknet::session::ConnectionPoolBeginHttp1PipelineSend(&pool, first, &firstSequence);
        Expect(NT_SUCCESS(status), "first failure pipeline send begins");
        wknet::session::ConnectionPoolEndHttp1PipelineSend(first);

        wknet::session::PooledConnection* second = nullptr;
        reused = false;
        status = wknet::session::ConnectionPoolAcquireHttp1Pipeline(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            2,
            &second,
            &reused);
        Expect(NT_SUCCESS(status), "second failure pipeline acquire succeeds");
        Expect(second == first && reused, "second failure pipeline acquire shares active connection");

        ULONG secondSequence = 0;
        status = wknet::session::ConnectionPoolBeginHttp1PipelineSend(&pool, second, &secondSequence);
        Expect(NT_SUCCESS(status), "second failure pipeline send begins before failure");
        wknet::session::ConnectionPoolEndHttp1PipelineSend(second);

        wknet::session::ConnectionPoolFailHttp1Pipeline(
            &pool,
            first,
            STATUS_INVALID_NETWORK_RESPONSE);
        status = wknet::session::ConnectionPoolWaitHttp1PipelineReceiveTurn(
            &pool,
            second,
            secondSequence);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "pipeline failure propagates to pending response");

        wknet::session::ConnectionPoolRelease(&pool, second, false);
        wknet::session::ConnectionPoolRelease(&pool, first, false);

        wknet::session::PooledConnection* fresh = nullptr;
        reused = true;
        status = wknet::session::ConnectionPoolAcquireHttp1Pipeline(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            2,
            &fresh,
            &reused);
        Expect(NT_SUCCESS(status), "pipeline acquire after failure creates usable connection");
        Expect(fresh != nullptr && !reused, "failed pipeline connection is not reused");
        wknet::session::ConnectionPoolRelease(&pool, fresh, false);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestConnectionPoolSharesActiveHttp2StreamLeases() noexcept
    {
        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000);
        Expect(NT_SUCCESS(status), "connection pool initializes for HTTP/2 stream sharing");

        wknet::session::ConnectionPoolKey key = {};
        memcpy(key.Scheme, "https", Length("https"));
        key.SchemeLength = Length("https");
        memcpy(key.Host, "example.com", Length("example.com"));
        key.HostLength = Length("example.com");
        key.Port = 443;
        memcpy(key.Alpn, "h2", Length("h2"));
        key.AlpnLength = Length("h2");

        wknet::session::PooledConnection* first = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &first,
            &reused);
        Expect(NT_SUCCESS(status), "first HTTP/2 pool acquire succeeds");
        Expect(first != nullptr && !reused, "first HTTP/2 acquire is fresh");
        Http2KeepAliveTestTransport transport = {};
        TestHttp2Connection connection;
        wknet::session::PooledConnectionAttachTestState(first, transport.Handle, connection.Get());

        status = wknet::session::ConnectionPoolPromoteHttp2StreamLease(&pool, first, 2);
        Expect(NT_SUCCESS(status), "first HTTP/2 stream lease promotes connection");

        wknet::session::PooledConnection* second = nullptr;
        reused = false;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &second,
            &reused);
        Expect(NT_SUCCESS(status), "second HTTP/2 stream lease shares active connection");
        Expect(second == first && reused, "second HTTP/2 stream lease reuses same connection");

        wknet::session::PooledConnection* blocked = nullptr;
        reused = false;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &blocked,
            &reused);
        Expect(status == STATUS_INSUFFICIENT_RESOURCES, "HTTP/2 stream lease cap blocks third active lease");
        Expect(blocked == nullptr, "blocked HTTP/2 stream lease returns no connection");

        wknet::session::ConnectionPoolRelease(&pool, second, true);

        wknet::session::PooledConnection* third = nullptr;
        reused = false;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &third,
            &reused);
        Expect(NT_SUCCESS(status), "released HTTP/2 stream lease frees capacity");
        Expect(third == first && reused, "third HTTP/2 stream lease reuses same active connection");

        wknet::session::ConnectionPoolRelease(&pool, third, true);
        wknet::session::ConnectionPoolRelease(&pool, first, true);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestHttp2KeepAliveDefaultDisabled() noexcept
    {
        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive default-disabled pool initializes");

        wknet::session::ConnectionPoolKey key = {};
        memcpy(key.Scheme, "https", Length("https"));
        key.SchemeLength = Length("https");
        memcpy(key.Host, "example.com", Length("example.com"));
        key.HostLength = Length("example.com");
        key.Port = 443;
        memcpy(key.Alpn, "h2", Length("h2"));
        key.AlpnLength = Length("h2");

        Http2KeepAliveTestTransport transport = {};
        TestHttp2Connection connection;
        wknet::session::PooledConnection* pooled = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &pooled,
            &reused);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive default-disabled acquire succeeds");
        wknet::session::PooledConnectionAttachTestState(pooled, transport.Handle, connection.Get());
        wknet::session::ConnectionPoolRelease(&pool, pooled, true);

        bool attempted = true;
        status = wknet::session::ConnectionPoolRunHttp2KeepAliveSweep(&pool, &attempted);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive default-disabled sweep succeeds");
        Expect(!attempted, "HTTP/2 keepalive default-disabled sweep does not attempt PING");
        Expect(transport.SendCalls == 0, "HTTP/2 keepalive default-disabled sweep sends no PING");
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestHttp2KeepAliveSendsPingForIdleConnection() noexcept
    {
        wknet::session::Http2KeepAliveOptions keepAlive = {};
        keepAlive.Enabled = true;
        keepAlive.IdleMilliseconds = 1;
        keepAlive.IntervalMilliseconds = 1;
        keepAlive.AckTimeoutMilliseconds = 7;

        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000, &keepAlive);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive enabled pool initializes");

        wknet::session::ConnectionPoolKey key = {};
        memcpy(key.Scheme, "https", Length("https"));
        key.SchemeLength = Length("https");
        memcpy(key.Host, "example.com", Length("example.com"));
        key.HostLength = Length("example.com");
        key.Port = 443;
        memcpy(key.Alpn, "h2", Length("h2"));
        key.AlpnLength = Length("h2");

        Http2KeepAliveTestTransport transport = {};
        TestHttp2Connection connection;
        wknet::session::PooledConnection* pooled = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &pooled,
            &reused);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive idle acquire succeeds");
        wknet::session::PooledConnectionAttachTestState(pooled, transport.Handle, connection.Get());
        wknet::session::ConnectionPoolRelease(&pool, pooled, true);

        bool attempted = false;
        status = wknet::session::ConnectionPoolRunHttp2KeepAliveSweep(&pool, &attempted);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive idle sweep succeeds");
        Expect(attempted, "HTTP/2 keepalive idle sweep attempts PING");
        Expect(transport.SendCalls == 1, "HTTP/2 keepalive idle sweep sends one PING");
        Expect(transport.LastTimeoutMs == keepAlive.AckTimeoutMilliseconds,
            "HTTP/2 keepalive idle sweep uses ACK timeout");
        Expect(wknet::session::PooledConnectionHttp2LastKeepAliveTime(pooled) != 0,
            "HTTP/2 keepalive records successful PING time");
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestHttp2KeepAliveSkipsNotDueAndActiveConnections() noexcept
    {
        wknet::session::Http2KeepAliveOptions keepAlive = {};
        keepAlive.Enabled = true;
        keepAlive.IdleMilliseconds = 1000;
        keepAlive.IntervalMilliseconds = 1000;
        keepAlive.AckTimeoutMilliseconds = 5;

        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000, &keepAlive);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive skip pool initializes");

        wknet::session::ConnectionPoolKey key = {};
        memcpy(key.Scheme, "https", Length("https"));
        key.SchemeLength = Length("https");
        memcpy(key.Host, "example.com", Length("example.com"));
        key.HostLength = Length("example.com");
        key.Port = 443;
        memcpy(key.Alpn, "h2", Length("h2"));
        key.AlpnLength = Length("h2");

        Http2KeepAliveTestTransport transport = {};
        TestHttp2Connection connection;
        wknet::session::PooledConnection* pooled = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &pooled,
            &reused);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive not-due acquire succeeds");
        wknet::session::PooledConnectionAttachTestState(pooled, transport.Handle, connection.Get());
        wknet::session::ConnectionPoolRelease(&pool, pooled, true);

        bool attempted = true;
        status = wknet::session::ConnectionPoolRunHttp2KeepAliveSweep(&pool, &attempted);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive not-due sweep succeeds");
        Expect(!attempted, "HTTP/2 keepalive not-due sweep skips PING");
        Expect(transport.SendCalls == 0, "HTTP/2 keepalive not-due sweep sends no PING");

        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &pooled,
            &reused);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive active acquire succeeds");
        wknet::session::PooledConnectionAttachTestState(pooled, transport.Handle, connection.Get());
        status = wknet::session::ConnectionPoolPromoteHttp2StreamLease(&pool, pooled, 2);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive active stream lease promotes");

        attempted = true;
        status = wknet::session::ConnectionPoolRunHttp2KeepAliveSweep(&pool, &attempted);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive active sweep succeeds");
        Expect(!attempted, "HTTP/2 keepalive active stream sweep skips PING");
        Expect(transport.SendCalls == 0, "HTTP/2 keepalive active stream sends no PING");
        wknet::session::ConnectionPoolRelease(&pool, pooled, false);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestHttp2KeepAliveAckTimeoutClosesIdleConnection() noexcept
    {
        wknet::session::Http2KeepAliveOptions keepAlive = {};
        keepAlive.Enabled = true;
        keepAlive.IdleMilliseconds = 1;
        keepAlive.IntervalMilliseconds = 1;
        keepAlive.AckTimeoutMilliseconds = 5;

        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000, &keepAlive);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive timeout pool initializes");

        wknet::session::ConnectionPoolKey key = {};
        memcpy(key.Scheme, "https", Length("https"));
        key.SchemeLength = Length("https");
        memcpy(key.Host, "example.com", Length("example.com"));
        key.HostLength = Length("example.com");
        key.Port = 443;
        memcpy(key.Alpn, "h2", Length("h2"));
        key.AlpnLength = Length("h2");

        Http2KeepAliveTestTransport transport = {};
        transport.TimeoutAck = true;
        TestHttp2Connection connection;
        wknet::session::PooledConnection* pooled = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &pooled,
            &reused);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive timeout acquire succeeds");
        wknet::session::PooledConnectionAttachTestState(pooled, transport.Handle, connection.Get());
        wknet::session::ConnectionPoolRelease(&pool, pooled, true);

        bool attempted = false;
        status = wknet::session::ConnectionPoolRunHttp2KeepAliveSweep(&pool, &attempted);
        Expect(status == STATUS_IO_TIMEOUT, "HTTP/2 keepalive ACK timeout is reported");
        Expect(attempted, "HTTP/2 keepalive timeout sweep attempts PING");
        Expect(transport.SendCalls == 1, "HTTP/2 keepalive timeout sends one PING");
        Expect(pool.ActiveCount == 0, "HTTP/2 keepalive timeout closes idle pooled connection");

        wknet::session::PooledConnection* fresh = nullptr;
        reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &fresh,
            &reused);
        Expect(NT_SUCCESS(status), "HTTP/2 keepalive timeout allows fresh acquire");
        Expect(fresh != nullptr && !reused, "HTTP/2 keepalive timeout does not reuse closed connection");
        wknet::session::ConnectionPoolRelease(&pool, fresh, false);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestConnectionPoolHostQuotaSeparatesTlsReuseIdentity() noexcept
    {
        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000);
        Expect(NT_SUCCESS(status), "connection pool initializes for TLS identity quota");

        wknet::session::ConnectionPoolKey firstKey = {};
        memcpy(firstKey.Scheme, "https", Length("https"));
        firstKey.SchemeLength = Length("https");
        memcpy(firstKey.Host, "example.com", Length("example.com"));
        firstKey.HostLength = Length("example.com");
        firstKey.Port = 443;
        memcpy(firstKey.TlsServerName, "api.example.com", Length("api.example.com"));
        firstKey.TlsServerNameLength = Length("api.example.com");
        memcpy(firstKey.Alpn, "h2", Length("h2"));
        firstKey.AlpnLength = Length("h2");

        wknet::session::ConnectionPoolKey secondIdentity = firstKey;
        memcpy(secondIdentity.TlsServerName, "other.example.com", Length("other.example.com"));
        secondIdentity.TlsServerNameLength = Length("other.example.com");

        wknet::session::PooledConnection* first = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            firstKey,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &first,
            &reused);
        Expect(NT_SUCCESS(status), "first TLS identity connection acquires");
        Expect(first != nullptr && !reused, "first TLS identity acquire is fresh");

        wknet::session::PooledConnection* blocked = nullptr;
        reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            secondIdentity,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &blocked,
            &reused);
        Expect(status == STATUS_INSUFFICIENT_RESOURCES, "active same-host different TLS identity counts toward host quota");
        Expect(blocked == nullptr, "blocked TLS identity acquire returns no connection");

        const ULONGLONG firstId = wknet::session::PooledConnectionId(first);
        wknet::session::ConnectionPoolRelease(&pool, first, true);

        wknet::session::PooledConnection* second = nullptr;
        reused = true;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            secondIdentity,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &second,
            &reused);
        Expect(NT_SUCCESS(status), "idle same-host different TLS identity can replace old idle slot");
        Expect(second != nullptr && !reused, "different TLS identity is not reused across identity key");
        Expect(second != nullptr && wknet::session::PooledConnectionId(second) != firstId,
            "different TLS identity receives a fresh connection id");

        wknet::session::ConnectionPoolRelease(&pool, second, false);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestConnectionPoolKeyIncludesTlsIdentity() noexcept
    {
        wknet::session::ConnectionPoolKey base = {};
        memcpy(base.Scheme, "https", Length("https"));
        base.SchemeLength = Length("https");
        memcpy(base.Host, "example.com", Length("example.com"));
        base.HostLength = Length("example.com");
        base.Port = 443;
        base.MinTlsVersion = wknet::session::TlsVersion::Tls12;
        base.MaxTlsVersion = wknet::session::TlsVersion::Tls13;
        base.CertificatePolicy = wknet::session::CertificatePolicy::Verify;
        base.CertificateStore = reinterpret_cast<const wknet::tls::CertificateStore*>(static_cast<uintptr_t>(0x1000));
        memcpy(base.TlsServerName, "api.example.com", Length("api.example.com"));
        base.TlsServerNameLength = Length("api.example.com");
        memcpy(base.Alpn, "h2", Length("h2"));
        base.AlpnLength = Length("h2");

        wknet::session::ConnectionPoolKey same = base;
        Expect(
            wknet::session::ConnectionPoolKeysEqual(base, same),
            "connection pool keys match when TLS identity is identical");

        wknet::session::ConnectionPoolKey differentSni = base;
        memcpy(differentSni.TlsServerName, "other.example", Length("other.example"));
        differentSni.TlsServerNameLength = Length("other.example");
        Expect(
            !wknet::session::ConnectionPoolKeysEqual(base, differentSni),
            "connection pool key includes TLS server name");

        wknet::session::ConnectionPoolKey differentStore = base;
        differentStore.CertificateStore =
            reinterpret_cast<const wknet::tls::CertificateStore*>(static_cast<uintptr_t>(0x2000));
        Expect(
            !wknet::session::ConnectionPoolKeysEqual(base, differentStore),
            "connection pool key includes certificate store identity");

        wknet::session::ConnectionPoolKey differentRenegotiationLimit = base;
        differentRenegotiationLimit.MaxTls12Renegotiations = 2;
        Expect(
            !wknet::session::ConnectionPoolKeysEqual(base, differentRenegotiationLimit),
            "connection pool key includes TLS 1.2 renegotiation limit");

        wknet::session::ConnectionPoolKey proxyKey = base;
        proxyKey.ProxyEnabled = true;
        memcpy(proxyKey.ProxyHost, "proxy.example", Length("proxy.example"));
        proxyKey.ProxyHostLength = Length("proxy.example");
        proxyKey.ProxyPort = 8080;
        proxyKey.ProxyFamily = wknet::session::AddressFamily::Ipv4;
        memcpy(proxyKey.ProxyAuthority, "proxy.example:8080", Length("proxy.example:8080"));
        proxyKey.ProxyAuthorityLength = Length("proxy.example:8080");

        Expect(
            !wknet::session::ConnectionPoolKeysEqual(base, proxyKey),
            "connection pool key includes proxy enablement");

        wknet::session::ConnectionPoolKey sameProxy = proxyKey;
        Expect(
            wknet::session::ConnectionPoolKeysEqual(proxyKey, sameProxy),
            "connection pool keys match when proxy identity is identical");

        wknet::session::ConnectionPoolKey differentProxyAddress = proxyKey;
        memcpy(differentProxyAddress.ProxyHost, "other.example", Length("other.example"));
        differentProxyAddress.ProxyHostLength = Length("other.example");
        Expect(
            !wknet::session::ConnectionPoolKeysEqual(proxyKey, differentProxyAddress),
            "connection pool key includes proxy address");

        wknet::session::ConnectionPoolKey differentProxyAuthority = proxyKey;
        memcpy(differentProxyAuthority.ProxyAuthority, "other-proxy:8080", Length("other-proxy:8080"));
        differentProxyAuthority.ProxyAuthorityLength = Length("other-proxy:8080");
        Expect(
            !wknet::session::ConnectionPoolKeysEqual(proxyKey, differentProxyAuthority),
            "connection pool key includes proxy authority");
    }

    struct FakeResolveCapture
    {
        SIZE_T CallCount = 0;
        wknet::net::WskAddressFamily LastFamily = wknet::net::WskAddressFamily::Any;
        USHORT LastServicePort = 0;
        bool NoMatchForAny = false;
    };

    USHORT HostToNetworkPort(const wchar_t* serviceName) noexcept
    {
        USHORT port = 0;
        if (serviceName == nullptr) {
            return 0;
        }

        for (const wchar_t* current = serviceName; *current != L'\0'; ++current) {
            if (*current < L'0' || *current > L'9') {
                return 0;
            }

            port = static_cast<USHORT>((port * 10) + static_cast<USHORT>(*current - L'0'));
        }

        return static_cast<USHORT>((port >> 8) | (port << 8));
    }

    void FillProxyConfig(wknet::http::ProxyConfig& proxy) noexcept
    {
        proxy.Enabled = true;
        proxy.Host = "proxy.example";
        proxy.HostLength = Length(proxy.Host);
        proxy.Port = 8080;
        proxy.Family = wknet::http::AddressFamily::Ipv4;
        proxy.Authority = "proxy.example:8080";
        proxy.AuthorityLength = Length(proxy.Authority);
    }

    void TestSessionProxyConfigReachesTransport() noexcept
    {
        CapturedRequest captured = {};
        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";
        captured.RawResponse = responseBytes;
        captured.RawResponseLength = sizeof(responseBytes) - 1;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        FillProxyConfig(config.Proxy);
        config.Proxy.AuthHeader = "Basic c2VjcmV0";
        config.Proxy.AuthHeaderLength = Length(config.Proxy.AuthHeader);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate accepts complete proxy config");

        const char* url = "https://example.com/proxy";
        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, url, Length(url), &response);
        Expect(NT_SUCCESS(status), "HTTPS request with session proxy reaches transport");
        Expect(captured.CallCount == 1, "proxy HTTPS request issues one transport call");
        Expect(captured.ProxyEnabled, "transport observes proxy enabled");
        Expect(captured.ProxyFamily == wknet::http::AddressFamily::Ipv4, "transport observes proxy address family");
        Expect(
            captured.ProxyPort == 8080,
            "transport observes proxy address port");
        Expect(
            captured.ProxyHostLength == Length("proxy.example") &&
                memcmp(captured.ProxyHost, "proxy.example", Length("proxy.example")) == 0,
            "transport observes proxy host");
        Expect(
            captured.ProxyAuthorityLength == Length("proxy.example:8080") &&
                memcmp(captured.ProxyAuthority, "proxy.example:8080", Length("proxy.example:8080")) == 0,
            "transport observes proxy authority");
        Expect(
            captured.ProxyAuthHeaderLength == Length("Basic c2VjcmV0") &&
                memcmp(captured.ProxyAuthHeader, "Basic c2VjcmV0", Length("Basic c2VjcmV0")) == 0,
            "transport observes opaque proxy auth header");
        Expect(
            !BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Proxy-Authorization"),
            "target request does not receive proxy credentials");

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestFreshRetrySignalRetriesSafeMethodsOnly() noexcept
    {
        {
            FreshRetrySignalCapture capture = {};
            wknet::http::test::SetHttpTransport(FreshRetrySignalTransport, &capture);

            wknet::http::Session* session = nullptr;
            NTSTATUS status = wknet::http::SessionCreate(&session);
            Expect(NT_SUCCESS(status), "SessionCreate succeeds for fresh retry signal GET");

            const char* url = "http://example.com/fresh-retry";
            wknet::http::Response* resp = nullptr;
            status = wknet::http::Get(session, url, Length(url), &resp);
            Expect(NT_SUCCESS(status), "fresh STATUS_RETRY GET retries once on a new connection");
            Expect(capture.CallCount == 2, "fresh STATUS_RETRY GET sees initial and retry calls");
            Expect(capture.NewConnectionCallCount == 2, "fresh STATUS_RETRY GET opens two fresh connections");
            Expect(capture.FirstConnectionId != 0, "fresh STATUS_RETRY first connection id captured");
            Expect(capture.RetryConnectionId != 0, "fresh STATUS_RETRY retry connection id captured");
            Expect(capture.RetryConnectionId != capture.FirstConnectionId,
                "fresh STATUS_RETRY retry uses a different pool entry");
            Expect(wknet::http::ResponseStatusCode(resp) == 200, "fresh STATUS_RETRY retry status is 200");

            wknet::http::ResponseRelease(resp);
            wknet::http::SessionClose(session);
            wknet::http::test::SetHttpTransport(nullptr, nullptr);
        }

        {
            FreshRetrySignalCapture capture = {};
            wknet::http::test::SetHttpTransport(FreshRetrySignalTransport, &capture);

            wknet::http::Session* session = nullptr;
            NTSTATUS status = wknet::http::SessionCreate(&session);
            Expect(NT_SUCCESS(status), "SessionCreate succeeds for fresh retry signal POST");

            const char* url = "http://example.com/fresh-retry-post";
            const char* body = "payload";
            wknet::http::Response* resp = nullptr;
            status = wknet::http::Post(
                session,
                url,
                Length(url),
                reinterpret_cast<const UCHAR*>(body),
                Length(body),
                &resp);
            Expect(status == STATUS_RETRY, "fresh STATUS_RETRY POST is not replayed");
            Expect(capture.CallCount == 1, "fresh STATUS_RETRY POST sees only the first call");
            Expect(capture.NewConnectionCallCount == 1, "fresh STATUS_RETRY POST opens no retry connection");
            Expect(capture.RetryConnectionId == 0, "fresh STATUS_RETRY POST records no retry connection id");
            Expect(resp == nullptr, "fresh STATUS_RETRY POST returns no response");

            wknet::http::ResponseRelease(resp);
            wknet::http::SessionClose(session);
            wknet::http::test::SetHttpTransport(nullptr, nullptr);
        }
    }

    void TestHttp2CleartextExplicitEntry() noexcept
    {
        static const char http1Response[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        {
            CapturedRequest captured = {};
            captured.RawResponse = http1Response;
            captured.RawResponseLength = sizeof(http1Response) - 1;
            wknet::http::test::SetHttpTransport(TestTransport, &captured);

            wknet::http::Session* session = nullptr;
            NTSTATUS status = wknet::http::SessionCreate(&session);
            Expect(NT_SUCCESS(status), "SessionCreate succeeds for default h2c disabled test");

            const char* url = "http://example.com/default-h1";
            wknet::http::Response* resp = nullptr;
            status = wknet::http::Get(session, url, Length(url), &resp);
            Expect(NT_SUCCESS(status), "default http request succeeds over HTTP/1.1");
            Expect(!captured.UsedHttp2, "default http request does not use h2c");
            Expect(captured.Http2CleartextMode == wknet::http::Http2CleartextMode::Disabled,
                "default http request records h2c disabled");

            wknet::http::ResponseRelease(resp);
            wknet::http::SessionClose(session);
            wknet::http::test::SetHttpTransport(nullptr, nullptr);
        }

        {
            CapturedRequest captured = {};
            wknet::http::test::SetHttpTransport(TestTransport, &captured);

            wknet::http::Session* session = nullptr;
            NTSTATUS status = wknet::http::SessionCreate(&session);
            Expect(NT_SUCCESS(status), "SessionCreate succeeds for h2c prior knowledge");

            wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
            options.Http2CleartextMode = wknet::http::Http2CleartextMode::PriorKnowledge;
            const char* url = "http://example.com/h2c-prior";
            wknet::http::Response* resp = nullptr;
            status = wknet::http::GetEx(session, url, Length(url), nullptr, &options, &resp);
            Expect(NT_SUCCESS(status), "explicit h2c prior knowledge succeeds through test transport");
            Expect(captured.UsedHttp2, "explicit h2c prior knowledge uses HTTP/2");
            Expect(captured.Http2CleartextMode == wknet::http::Http2CleartextMode::PriorKnowledge,
                "explicit h2c prior knowledge mode propagates to transport");
            Expect(wknet::http::ResponseStatusCode(resp) == 200, "explicit h2c prior response status is 200");

            wknet::http::ResponseRelease(resp);
            wknet::http::SessionClose(session);
            wknet::http::test::SetHttpTransport(nullptr, nullptr);
        }

        {
            CapturedRequest captured = {};
            wknet::http::test::SetHttpTransport(TestTransport, &captured);

            wknet::http::Session* session = nullptr;
            NTSTATUS status = wknet::http::SessionCreate(&session);
            Expect(NT_SUCCESS(status), "SessionCreate succeeds for h2c upgrade body rejection");

            wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
            options.Http2CleartextMode = wknet::http::Http2CleartextMode::Upgrade;
            const char* url = "http://example.com/h2c-upgrade-body";
            const char* body = "payload";
            wknet::http::Request* request = nullptr;
            status = wknet::http::RequestCreate(session, &request);
            Expect(NT_SUCCESS(status), "RequestCreate succeeds for h2c Upgrade body rejection");
            status = wknet::http::RequestSetUrl(request, url, Length(url));
            Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for h2c Upgrade body rejection");
            status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
            Expect(NT_SUCCESS(status), "RequestSetMethod succeeds for h2c Upgrade body rejection");
            status = wknet::http::RequestSetBody(
                request,
                reinterpret_cast<const UCHAR*>(body),
                Length(body));
            Expect(NT_SUCCESS(status), "RequestSetBody succeeds for h2c Upgrade body rejection");

            wknet::http::Response* resp = nullptr;
            status = wknet::http::Send(
                session,
                request,
                &options,
                &resp);
            Expect(status == STATUS_INVALID_PARAMETER, "h2c Upgrade rejects requests with a body");
            Expect(resp == nullptr, "h2c Upgrade body rejection returns no response");
            Expect(captured.CallCount == 0, "h2c Upgrade body rejection does not reach transport");

            wknet::http::ResponseRelease(resp);
            wknet::http::RequestRelease(request);
            wknet::http::SessionClose(session);
            wknet::http::test::SetHttpTransport(nullptr, nullptr);
        }
    }

    void TestSessionProxyRejectsInvalidConfig() noexcept
    {
        wknet::http::Session* session = nullptr;
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Proxy.Enabled = true;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "SessionCreate rejects proxy without address and authority");
        Expect(session == nullptr, "invalid proxy session is not returned");

        config = wknet::http::DefaultSessionConfig();
        FillProxyConfig(config.Proxy);
        config.Proxy.Authority = "proxy.example:8080\r\nInjected: x";
        config.Proxy.AuthorityLength = Length(config.Proxy.Authority);
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "SessionCreate rejects proxy authority CRLF injection");
        Expect(session == nullptr, "CRLF proxy authority session is not returned");

        config = wknet::http::DefaultSessionConfig();
        FillProxyConfig(config.Proxy);
        config.Proxy.AuthHeader = "Basic ok\r\nInjected: x";
        config.Proxy.AuthHeaderLength = Length(config.Proxy.AuthHeader);
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "SessionCreate rejects proxy auth CRLF injection");
        Expect(session == nullptr, "CRLF proxy auth session is not returned");

        config = wknet::http::DefaultSessionConfig();
        config.Proxy.Authority = "proxy.example:8080";
        config.Proxy.AuthorityLength = Length(config.Proxy.Authority);
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "SessionCreate rejects disabled proxy with stray fields");
        Expect(session == nullptr, "disabled stray proxy session is not returned");
    }

    void TestPlainHttpProxyUsesAbsoluteForm() noexcept
    {
        CapturedRequest captured = {};
        static const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";
        captured.RawResponse = responseBytes;
        captured.RawResponseLength = sizeof(responseBytes) - 1;
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        FillProxyConfig(config.Proxy);
        config.Proxy.AuthHeader = "Basic cHJveHk=";
        config.Proxy.AuthHeaderLength = Length(config.Proxy.AuthHeader);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate accepts proxy config before plaintext proxy request");

        const char* url = "http://example.com:8081/proxy?q=1";
        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, url, Length(url), &response);
        Expect(NT_SUCCESS(status), "plain HTTP over proxy succeeds");
        Expect(wknet::http::ResponseStatusCode(response) == 200, "plain HTTP proxy response status");
        Expect(captured.CallCount == 1, "plain HTTP proxy reaches transport");
        Expect(captured.ProxyEnabled, "plain HTTP proxy transport observes proxy enabled");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "GET http://example.com:8081/proxy?q=1 HTTP/1.1\r\n"),
            "plain HTTP proxy request uses absolute-form target");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Host: example.com:8081\r\n"),
            "plain HTTP proxy keeps origin Host header");
        Expect(
            BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Proxy-Authorization: Basic cHJveHk=\r\n"),
            "plain HTTP proxy includes configured proxy credentials");
        Expect(
            !BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "CONNECT "),
            "plain HTTP proxy does not build CONNECT tunnel request");

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    ULONG WideChecksum(const wchar_t* text) noexcept
    {
        ULONG checksum = 0;
        if (text == nullptr) {
            return checksum;
        }

        for (const wchar_t* current = text; *current != L'\0'; ++current) {
            checksum = (checksum * 131U) + static_cast<ULONG>(*current);
        }
        return checksum;
    }

    NTSTATUS FakeResolveAll(
        void* context,
        const wchar_t* nodeName,
        const wchar_t* serviceName,
        SOCKADDR_STORAGE* remoteAddresses,
        SIZE_T addressCapacity,
        SIZE_T* addressCount,
        wknet::net::WskAddressFamily addressFamily) noexcept
    {
        auto* capture = static_cast<FakeResolveCapture*>(context);
        if (capture == nullptr ||
            remoteAddresses == nullptr ||
            addressCapacity == 0 ||
            addressCount == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->CallCount;
        capture->LastFamily = addressFamily;
        capture->LastServicePort = HostToNetworkPort(serviceName);
        *addressCount = 0;
        if (capture->NoMatchForAny &&
            addressFamily == wknet::net::WskAddressFamily::Any) {
            return STATUS_NO_MATCH;
        }

        const ULONG checksum = WideChecksum(nodeName);
        if (addressFamily == wknet::net::WskAddressFamily::Any ||
            addressFamily == wknet::net::WskAddressFamily::Ipv4) {
            auto* ipv4 = reinterpret_cast<SOCKADDR_IN*>(&remoteAddresses[*addressCount]);
            RtlZeroMemory(ipv4, sizeof(*ipv4));
            ipv4->sin_family = AF_INET;
            ipv4->sin_port = capture->LastServicePort;
            ipv4->sin_addr = 0x0a000001UL + checksum + static_cast<ULONG>(capture->CallCount);
            ++(*addressCount);
        }

        if (*addressCount < addressCapacity &&
            (addressFamily == wknet::net::WskAddressFamily::Any ||
                addressFamily == wknet::net::WskAddressFamily::Ipv6)) {
            auto* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(&remoteAddresses[*addressCount]);
            RtlZeroMemory(ipv6, sizeof(*ipv6));
            ipv6->sin6_family = AF_INET6;
            ipv6->sin6_port = capture->LastServicePort;
            ipv6->sin6_addr[15] = static_cast<UCHAR>(checksum + capture->CallCount);
            ++(*addressCount);
        }

        return *addressCount != 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }

    void TestResolveAllCacheBoundaries() noexcept
    {
        wknet::net::WskTestClearResolveCache();
        FakeResolveCapture capture = {};
        wknet::net::WskTestSetResolveAll(FakeResolveAll, &capture);

        TestWskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "test WskClient initializes");

        SOCKADDR_STORAGE addresses[wknet::net::WskMaxResolvedAddresses] = {};
        SIZE_T addressCount = 0;
        status = client.ResolveAll(
            L"Example.COM",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "first ResolveAll succeeds");
        Expect(addressCount == 2, "Any resolve returns IPv4 and IPv6 fixtures");
        Expect(capture.CallCount == 1, "first ResolveAll reaches resolver");

        RtlZeroMemory(addresses, sizeof(addresses));
        addressCount = 0;
        status = client.ResolveAll(
            L"example.com",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "cached ResolveAll succeeds case-insensitively");
        Expect(addressCount == 2, "cached ResolveAll preserves address count");
        Expect(capture.CallCount == 1, "cached ResolveAll does not call resolver");

        status = client.ResolveAll(
            L"example.com",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Ipv4);
        Expect(NT_SUCCESS(status), "family-isolated ResolveAll succeeds");
        Expect(addressCount == 1, "IPv4-only ResolveAll returns one address");
        Expect(capture.CallCount == 2, "address family is part of DNS cache key");
        Expect(capture.LastFamily == wknet::net::WskAddressFamily::Ipv4, "resolver observes IPv4 family");

        constexpr ULONGLONG ResolveCacheTtl100ns = 5ULL * 60ULL * 1000ULL * 10000ULL;
        wknet::net::WskTestAdvanceResolveCacheTime(ResolveCacheTtl100ns + 10000ULL);
        status = client.ResolveAll(
            L"example.com",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "expired ResolveAll succeeds");
        Expect(capture.CallCount == 3, "expired DNS cache entry is refreshed");

        wknet::net::WskTestClearResolveCache();
        capture.CallCount = 0;
        status = client.ResolveAll(
            L"host00.example",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "initial capacity ResolveAll succeeds");

        // ResolveCacheCapacity is 256. Fill 256 additional hosts after host00 so host00 is evicted.
        for (SIZE_T index = 1; index <= 256; ++index) {
            wchar_t host[] = L"host000.example";
            host[4] = static_cast<wchar_t>(L'0' + ((index / 100) % 10));
            host[5] = static_cast<wchar_t>(L'0' + ((index / 10) % 10));
            host[6] = static_cast<wchar_t>(L'0' + (index % 10));
            status = client.ResolveAll(
                host,
                L"443",
                addresses,
                wknet::net::WskMaxResolvedAddresses,
                &addressCount,
                wknet::net::WskAddressFamily::Any);
            Expect(NT_SUCCESS(status), "capacity fill ResolveAll succeeds");
        }

        status = client.ResolveAll(
            L"host00.example",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "evicted ResolveAll succeeds");
        // 1 initial host00 + 256 fillers + 1 re-resolve after eviction = 258.
        Expect(capture.CallCount == 258, "DNS cache capacity replacement evicts the oldest slot");

        wknet::net::WskTestSetResolveAll(nullptr, nullptr);
        wknet::net::WskTestClearResolveCache();
    }

    void TestResolveAllAnyNoMatchQueriesExplicitFamilies() noexcept
    {
        wknet::net::WskTestClearResolveCache();
        FakeResolveCapture capture = {};
        capture.NoMatchForAny = true;
        wknet::net::WskTestSetResolveAll(FakeResolveAll, &capture);

        TestWskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "test WskClient initializes for explicit family query test");

        SOCKADDR_STORAGE addresses[wknet::net::WskMaxResolvedAddresses] = {};
        SIZE_T addressCount = 0;
        status = client.ResolveAll(
            L"ipv4-only.example",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "Any resolve recovers from AF_UNSPEC no-match with explicit families");
        Expect(addressCount == 2, "explicit family query returns merged IPv4 and IPv6 fixtures");
        Expect(capture.CallCount == 3, "Any no-match is followed by IPv4 and IPv6 resolver calls");
        Expect(capture.LastFamily == wknet::net::WskAddressFamily::Ipv6, "last explicit query checks IPv6");
        Expect(reinterpret_cast<SOCKADDR_IN*>(&addresses[0])->sin_family == AF_INET, "merged addresses keep IPv4 first");
        Expect(reinterpret_cast<SOCKADDR_IN6*>(&addresses[1])->sin6_family == AF_INET6, "merged addresses keep IPv6 second");

        RtlZeroMemory(addresses, sizeof(addresses));
        addressCount = 0;
        status = client.ResolveAll(
            L"IPV4-ONLY.EXAMPLE",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "merged Any result is cached case-insensitively");
        Expect(addressCount == 2, "cached merged Any result preserves address count");
        Expect(capture.CallCount == 3, "cached merged Any result does not query resolver again");

        wknet::net::WskTestSetResolveAll(nullptr, nullptr);
        wknet::net::WskTestClearResolveCache();
    }

    struct FakeWskSocketCapture
    {
        SIZE_T ConnectCount = 0;
        SIZE_T SendCount = 0;
        SIZE_T ReceiveCount = 0;
        SIZE_T CloseCount = 0;
        NTSTATUS NextConnectStatus = STATUS_SUCCESS;
        NTSTATUS ConnectStatuses[4] = {};
        SIZE_T ConnectStatusCount = 0;
        NTSTATUS NextSendStatus = STATUS_SUCCESS;
        NTSTATUS NextReceiveStatus = STATUS_SUCCESS;
        bool ReturnSocketOnFailedConnect = false;
        wknet::net::PWSK_SOCKET LastClosedSocket = nullptr;
        USHORT ConnectFamilies[4] = {};
        USHORT ConnectPorts[4] = {};
        char LastSend[32] = {};
        SIZE_T LastSendLength = 0;
    };

    bool AlwaysCancel(void* context) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        return true;
    }

    NTSTATUS FakeWskConnect(
        void* context,
        const SOCKADDR* remoteAddress,
        const SOCKADDR* localAddress,
        const wknet::net::WskCancellationToken* cancellation,
        wknet::net::PWSK_SOCKET* socket) noexcept
    {
        UNREFERENCED_PARAMETER(localAddress);
        UNREFERENCED_PARAMETER(cancellation);

        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr || remoteAddress == nullptr || socket == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T connectIndex = capture->ConnectCount;
        ++capture->ConnectCount;
        if (connectIndex < 4) {
            capture->ConnectFamilies[connectIndex] = remoteAddress->sa_family;
            if (remoteAddress->sa_family == AF_INET) {
                capture->ConnectPorts[connectIndex] =
                    reinterpret_cast<const SOCKADDR_IN*>(remoteAddress)->sin_port;
            }
            else if (remoteAddress->sa_family == AF_INET6) {
                capture->ConnectPorts[connectIndex] =
                    reinterpret_cast<const SOCKADDR_IN6*>(remoteAddress)->sin6_port;
            }
        }

        NTSTATUS status = capture->NextConnectStatus;
        if (connectIndex < capture->ConnectStatusCount) {
            status = capture->ConnectStatuses[connectIndex];
        }

        *socket = nullptr;
        if (NT_SUCCESS(status) || capture->ReturnSocketOnFailedConnect) {
            *socket = reinterpret_cast<wknet::net::PWSK_SOCKET>(
                static_cast<uintptr_t>(0x1000U + static_cast<ULONG>(capture->ConnectCount)));
        }

        return status;
    }

    NTSTATUS FakeWskSend(
        void* context,
        wknet::net::PWSK_SOCKET socket,
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent,
        ULONG flags,
        const wknet::net::WskCancellationToken* cancellation) noexcept
    {
        UNREFERENCED_PARAMETER(socket);
        UNREFERENCED_PARAMETER(flags);
        UNREFERENCED_PARAMETER(cancellation);

        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr || data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->SendCount;
        capture->LastSendLength = length < sizeof(capture->LastSend) ? length : sizeof(capture->LastSend);
        memcpy(capture->LastSend, data, capture->LastSendLength);
        if (bytesSent != nullptr) {
            *bytesSent = NT_SUCCESS(capture->NextSendStatus) ? length : 0;
        }
        return capture->NextSendStatus;
    }

    NTSTATUS FakeWskReceive(
        void* context,
        wknet::net::PWSK_SOCKET socket,
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG flags,
        ULONG timeoutMilliseconds,
        const wknet::net::WskCancellationToken* cancellation) noexcept
    {
        UNREFERENCED_PARAMETER(socket);
        UNREFERENCED_PARAMETER(flags);
        UNREFERENCED_PARAMETER(timeoutMilliseconds);
        UNREFERENCED_PARAMETER(cancellation);

        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr || data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++capture->ReceiveCount;
        if (NT_SUCCESS(capture->NextReceiveStatus) && length != 0) {
            static const char payload[] = "rx";
            const SIZE_T copy = sizeof(payload) - 1 < length ? sizeof(payload) - 1 : length;
            memcpy(data, payload, copy);
            if (bytesReceived != nullptr) {
                *bytesReceived = copy;
            }
        }
        else if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }
        return capture->NextReceiveStatus;
    }

    void FakeWskClose(void* context, wknet::net::PWSK_SOCKET socket) noexcept
    {
        auto* capture = static_cast<FakeWskSocketCapture*>(context);
        if (capture == nullptr) {
            return;
        }

        ++capture->CloseCount;
        capture->LastClosedSocket = socket;
    }

    void TestWskFakeProviderCancellationAndCleanup() noexcept
    {
        FakeWskSocketCapture capture = {};
        wknet::net::WskTestSocketProvider provider = {};
        provider.Connect = FakeWskConnect;
        provider.Send = FakeWskSend;
        provider.Receive = FakeWskReceive;
        provider.Close = FakeWskClose;
        wknet::net::WskTestSetSocketProvider(&provider, &capture);

        TestWskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "fake WSK client initializes");

        SOCKADDR_IN remote = {};
        remote.sin_family = AF_INET;
        remote.sin_port = HostToNetworkPort(L"443");

        capture.NextConnectStatus = STATUS_IO_TIMEOUT;
        capture.ReturnSocketOnFailedConnect = true;
        TestWskSocket timeoutSocket;
        status = timeoutSocket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(status == STATUS_IO_TIMEOUT, "fake connect timeout is returned");
        Expect(capture.CloseCount == 1, "late connected socket is closed after failed connect");
        Expect(!timeoutSocket.IsConnected(), "timeout socket is not connected");

        capture.NextConnectStatus = STATUS_SUCCESS;
        capture.ReturnSocketOnFailedConnect = false;
        TestWskSocket sendSocket;
        status = sendSocket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(NT_SUCCESS(status), "fake connect succeeds before send cancel");
        Expect(sendSocket.IsConnected(), "send socket is connected");

        wknet::net::WskCancellationToken cancellation = {};
        cancellation.IsCancellationRequested = AlwaysCancel;
        SIZE_T sent = 99;
        status = sendSocket.Send("abc", Length("abc"), &sent, 0, &cancellation);
        Expect(status == STATUS_CANCELLED, "send observes caller cancellation");
        Expect(sent == 0, "canceled send reports zero bytes");
        Expect(capture.CloseCount == 2, "canceled send closes socket");
        Expect(!sendSocket.IsConnected(), "canceled send detaches socket");
        status = sendSocket.Close();
        Expect(NT_SUCCESS(status), "closing an already canceled send socket succeeds");
        Expect(capture.CloseCount == 2, "close after canceled send is idempotent");

        TestWskSocket receiveSocket;
        status = receiveSocket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(NT_SUCCESS(status), "fake connect succeeds before receive timeout");
        capture.NextReceiveStatus = STATUS_IO_TIMEOUT;
        char receiveBuffer[8] = {};
        SIZE_T received = 99;
        status = receiveSocket.Receive(receiveBuffer, sizeof(receiveBuffer), &received);
        Expect(status == STATUS_IO_TIMEOUT, "receive timeout is returned");
        Expect(received == 0, "timed-out receive reports zero bytes");
        Expect(capture.CloseCount == 3, "timed-out receive closes socket");
        Expect(!receiveSocket.IsConnected(), "timed-out receive detaches socket");

        wknet::net::WskTestSetSocketProvider(nullptr, nullptr);
    }

    void TestWskSocketCanReconnectAfterClose() noexcept
    {
        FakeWskSocketCapture capture = {};
        wknet::net::WskTestSocketProvider provider = {};
        provider.Connect = FakeWskConnect;
        provider.Send = FakeWskSend;
        provider.Close = FakeWskClose;
        wknet::net::WskTestSetSocketProvider(&provider, &capture);

        TestWskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "fake WSK client initializes for socket reuse");

        SOCKADDR_IN remote = {};
        remote.sin_family = AF_INET;
        remote.sin_port = HostToNetworkPort(L"443");

        TestWskSocket socket;
        status = socket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(NT_SUCCESS(status), "first reusable socket connect succeeds");

        SIZE_T sent = 0;
        status = socket.Send("first", Length("first"), &sent);
        Expect(NT_SUCCESS(status), "first reusable socket send succeeds");
        Expect(sent == Length("first"), "first reusable socket send length matches");

        status = socket.Close();
        Expect(NT_SUCCESS(status), "reusable socket first close succeeds");

        status = socket.Connect(client, reinterpret_cast<SOCKADDR*>(&remote));
        Expect(NT_SUCCESS(status), "reusable socket reconnect succeeds");

        sent = 0;
        status = socket.Send("second", Length("second"), &sent);
        Expect(NT_SUCCESS(status), "reconnected socket send succeeds");
        Expect(sent == Length("second"), "reconnected socket send length matches");

        status = socket.Close();
        Expect(NT_SUCCESS(status), "reusable socket final close succeeds");
        Expect(capture.ConnectCount == 2, "reusable socket connects twice");
        Expect(capture.SendCount == 2, "reusable socket sends twice");
        Expect(capture.CloseCount == 2, "reusable socket closes twice");

        wknet::net::WskTestSetSocketProvider(nullptr, nullptr);
    }

    void TestResolveAllSequentialConnectFallback() noexcept
    {
        wknet::net::WskTestClearResolveCache();

        FakeResolveCapture resolveCapture = {};
        wknet::net::WskTestSetResolveAll(FakeResolveAll, &resolveCapture);

        FakeWskSocketCapture socketCapture = {};
        socketCapture.ConnectStatusCount = 2;
        socketCapture.ConnectStatuses[0] = STATUS_IO_TIMEOUT;
        socketCapture.ConnectStatuses[1] = STATUS_SUCCESS;

        wknet::net::WskTestSocketProvider provider = {};
        provider.Connect = FakeWskConnect;
        provider.Close = FakeWskClose;
        wknet::net::WskTestSetSocketProvider(&provider, &socketCapture);

        TestWskClient client;
        NTSTATUS status = client.Initialize();
        Expect(NT_SUCCESS(status), "fake WSK client initializes for sequential connect");

        SOCKADDR_STORAGE addresses[wknet::net::WskMaxResolvedAddresses] = {};
        SIZE_T addressCount = 0;
        status = client.ResolveAll(
            L"fallback.example",
            L"443",
            addresses,
            wknet::net::WskMaxResolvedAddresses,
            &addressCount,
            wknet::net::WskAddressFamily::Any);
        Expect(NT_SUCCESS(status), "ResolveAll returns sequential connect candidates");
        Expect(addressCount == 2, "ResolveAll returns two ordered candidates");

        TestWskSocket firstSocket;
        status = firstSocket.Connect(client, reinterpret_cast<const SOCKADDR*>(&addresses[0]));
        Expect(status == STATUS_IO_TIMEOUT, "first resolved address connect failure is surfaced");
        Expect(!firstSocket.IsConnected(), "failed first resolved address does not leave a connected socket");

        TestWskSocket secondSocket;
        status = secondSocket.Connect(client, reinterpret_cast<const SOCKADDR*>(&addresses[1]));
        Expect(NT_SUCCESS(status), "second resolved address connect succeeds after first failure");
        Expect(secondSocket.IsConnected(), "second resolved address leaves socket connected");
        Expect(socketCapture.ConnectCount == 2, "two resolved addresses were tried in order");
        Expect(socketCapture.ConnectFamilies[0] == AF_INET, "first sequential candidate is IPv4");
        Expect(socketCapture.ConnectFamilies[1] == AF_INET6, "second sequential candidate is IPv6");
        Expect(socketCapture.ConnectPorts[0] == HostToNetworkPort(L"443"), "first sequential candidate keeps service port");
        Expect(socketCapture.ConnectPorts[1] == HostToNetworkPort(L"443"), "second sequential candidate keeps service port");

        status = secondSocket.Close();
        Expect(NT_SUCCESS(status), "closing sequential connect socket succeeds");
        Expect(socketCapture.CloseCount == 1, "only the successful sequential socket is closed");

        wknet::net::WskTestSetSocketProvider(nullptr, nullptr);
        wknet::net::WskTestSetResolveAll(nullptr, nullptr);
        wknet::net::WskTestClearResolveCache();
    }

    void TestIdleTimeoutSkipsExpiredConnection() noexcept
    {
        ReusedFailureCapture capture = {};
        wknet::http::test::SetHttpTransport(ReusedFailureTransport, &capture);

        wknet::http::SessionConfig config = {};
        config.IdleTimeoutMs = 1;

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for idle timeout");

        const char* url = "http://example.com/idle";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "first idle-timeout Get succeeds");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "expired pooled Get creates a new connection");
        Expect(capture.CallCount == 2, "idle timeout avoids stale reuse attempt");
        Expect(capture.ReusedCallCount == 0, "expired connection is not reported as reused");
        Expect(capture.NewConnectionCallCount == 2, "idle timeout uses two new connections");
        Expect(capture.FirstConnectionId != 0, "first idle connection id captured");
        Expect(capture.RetryConnectionId != 0, "second idle connection id captured");
        Expect(capture.RetryConnectionId != capture.FirstConnectionId, "idle timeout uses a different connection id");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestCloseDelimitedResponseDoesNotEnterPool() noexcept
    {
        static const char closeDelimitedResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "close-body";
        static const char secondResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = closeDelimitedResponse;
        capture.FirstResponseLength = Length(closeDelimitedResponse);
        capture.FirstConnectionReusable = false;
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        wknet::http::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for close-delimited reuse test");

        const char* url = "http://example.com/close-delimited";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "close-delimited Get succeeds");
        Expect(wknet::http::ResponseBodyLength(resp) == Length("close-body"), "close-delimited body is returned");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after close-delimited response succeeds");
        Expect(capture.CallCount == 2, "close-delimited test sends two requests");
        Expect(capture.ReusedCallCount == 0, "close-delimited response is not returned to the pool");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttp10ConnectionReuseRules() noexcept
    {
        static const char http10NoDirective[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        static const char http10KeepAlive[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "ok";
        static const char secondResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = http10NoDirective;
        capture.FirstResponseLength = Length(http10NoDirective);
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        wknet::http::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTP/1.0 reuse test");

        const char* url = "http://example.com/http10";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "HTTP/1.0 default-close Get succeeds");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after HTTP/1.0 default-close succeeds");
        Expect(capture.ReusedCallCount == 0, "HTTP/1.0 without keep-alive is not reused");
        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);

        capture = {};
        capture.FirstResponse = http10KeepAlive;
        capture.FirstResponseLength = Length(http10KeepAlive);
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        wknet::http::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        session = nullptr;
        status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for HTTP/1.0 keep-alive reuse test");

        resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "HTTP/1.0 keep-alive Get succeeds");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after HTTP/1.0 keep-alive succeeds");
        Expect(capture.ReusedCallCount == 1, "HTTP/1.0 keep-alive response is reusable");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSwitchingProtocolsDoesNotEnterHttpPool() noexcept
    {
        static const char switchingResponse[] =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "\r\n";
        static const char secondResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";

        ReuseDecisionCapture capture = {};
        capture.FirstResponse = switchingResponse;
        capture.FirstResponseLength = Length(switchingResponse);
        capture.SecondResponse = secondResponse;
        capture.SecondResponseLength = Length(secondResponse);
        wknet::http::test::SetHttpTransport(ReuseDecisionTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for 101 reuse test");

        const char* url = "http://example.com/upgrade";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "101 response Get succeeds");
        Expect(wknet::http::ResponseStatusCode(resp) == 101, "101 status reaches caller");
        wknet::http::ResponseRelease(resp);
        resp = nullptr;

        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "second Get after 101 response succeeds");
        Expect(capture.CallCount == 2, "101 test sends two requests");
        Expect(capture.ReusedCallCount == 0, "101 response is not returned to the HTTP pool");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestFreshSafeConnectionTimeoutDoesNotRetry() noexcept
    {
        FreshTimeoutCapture capture = {};
        wknet::http::test::SetHttpTransport(FreshTimeoutTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for fresh timeout retry");

        const char* url = "http://example.com/fresh-timeout";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(status == STATUS_IO_TIMEOUT, "fresh GET timeout is returned without stale-pool retry");
        Expect(capture.CallCount == 1, "fresh timeout makes one transport call");
        Expect(capture.ReusedCallCount == 0, "fresh timeout does not reuse a stale connection");
        Expect(capture.NewConnectionCallCount == 1, "fresh timeout opens one connection");
        Expect(capture.FirstConnectionId != 0, "fresh timeout first connection id captured");
        Expect(capture.RetryConnectionId == 0, "fresh timeout has no retry connection id");
        Expect(resp == nullptr, "fresh timeout does not allocate a response");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestFreshPostTimeoutDoesNotRetry() noexcept
    {
        FreshTimeoutCapture capture = {};
        wknet::http::test::SetHttpTransport(FreshTimeoutTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for fresh POST timeout");

        const char* url = "http://example.com/fresh-post-timeout";
        const char* body = "payload";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Post(
            session,
            url,
            Length(url),
            reinterpret_cast<const UCHAR*>(body),
            Length(body),
            &resp);
        Expect(status == STATUS_IO_TIMEOUT, "fresh POST timeout is not retried");
        Expect(resp == nullptr, "fresh POST timeout does not allocate a response");
        Expect(capture.CallCount == 1, "fresh POST timeout makes one transport call");
        Expect(capture.NewConnectionCallCount == 1, "fresh POST timeout opens one connection");
        Expect(capture.RetryConnectionId == 0, "fresh POST timeout has no retry connection id");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestPostWithBody() noexcept
    {
        const char* response =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        const char* url = "http://example.com/api";
        const char* body = "payload-bytes";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Post(
            session,
            url,
            Length(url),
            reinterpret_cast<const UCHAR*>(body),
            Length(body),
            &resp);
        Expect(NT_SUCCESS(status), "Post succeeds");
        Expect(wknet::http::ResponseStatusCode(resp) == 201, "status code is 201");
        Expect(captured.BodyLength == Length(body), "body length passed through");
        Expect(memcmp(captured.Body, body, Length(body)) == 0, "body content passed through");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestChunkedRequestBody() noexcept
    {
        const char* response =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for chunked request body");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for chunked request body");

        const char* url = "http://example.com/upload";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for chunked request body");

        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds for chunked request body");

        const char* body = "payload-bytes";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for chunked request body");

        status = wknet::http::RequestSetBodyMode(
            request,
            wknet::http::RequestBodyMode::Chunked);
        Expect(NT_SUCCESS(status), "RequestSetBodyMode enables chunked request body");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "chunked request body send succeeds");
        Expect(wknet::http::ResponseStatusCode(resp) == 201, "chunked request response status is 201");
        Expect(BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Transfer-Encoding: chunked"), "chunked request emits Transfer-Encoding");
        Expect(!BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Content-Length:"), "chunked request omits Content-Length");
        Expect(BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "\r\nd\r\npayload-bytes\r\n0\r\n\r\n"), "chunked request body is framed");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestChunkedRequestTrailers() noexcept
    {
        const char* response =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for chunked trailers");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for chunked trailers");

        const char* url = "http://example.com/upload";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for chunked trailers");

        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds for chunked trailers");

        const char* body = "payload-bytes";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for chunked trailers");

        status = wknet::http::RequestSetBodyMode(request, wknet::http::RequestBodyMode::Chunked);
        Expect(NT_SUCCESS(status), "RequestSetBodyMode enables chunked for trailers");

        // Forbidden trailer fields are rejected at add time.
        status = wknet::http::RequestAddTrailer(request, "Content-Length", Length("Content-Length"), "5", 1);
        Expect(status == STATUS_NOT_SUPPORTED, "RequestAddTrailer rejects forbidden trailer field");

        // CRLF injection in the trailer value is rejected.
        const char* injected = "ok\r\nX-Injected: 1";
        status = wknet::http::RequestAddTrailer(request, "X-Checksum", Length("X-Checksum"), injected, Length(injected));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestAddTrailer rejects CRLF injection");

        // Valid trailers are accepted and emitted, order preserved.
        const char* checksum = "abc123";
        status = wknet::http::RequestAddTrailer(request, "X-Checksum", Length("X-Checksum"), checksum, Length(checksum));
        Expect(NT_SUCCESS(status), "RequestAddTrailer accepts a valid trailer");

        const char* expires = "Wed, 21 Oct 2015 07:28:00 GMT";
        status = wknet::http::RequestAddTrailer(request, "Expires", Length("Expires"), expires, Length(expires));
        Expect(NT_SUCCESS(status), "RequestAddTrailer accepts a second valid trailer");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "chunked trailers send succeeds");
        Expect(wknet::http::ResponseStatusCode(resp) == 201, "chunked trailers response status is 201");
        Expect(BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "\r\nd\r\npayload-bytes\r\n0\r\n"
            "X-Checksum: abc123\r\n"
            "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
            "\r\n"), "chunked request emits trailers after the final chunk");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestStreamingRequestBodyContentLength() noexcept
    {
        const char* response =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for streaming content-length body");

        static const char first[] = "hello";
        static const char second[] = "-world";
        const char* chunks[] = { first, second };
        const SIZE_T chunkLengths[] = { sizeof(first) - 1, sizeof(second) - 1 };
        StreamingBodyContext stream = {};
        stream.Chunks = chunks;
        stream.ChunkLengths = chunkLengths;
        stream.ChunkCount = sizeof(chunks) / sizeof(chunks[0]);

        wknet::http::Body* body = nullptr;
        status = wknet::http::BodyCreateStream(
            StreamingBodyRead,
            &stream,
            (sizeof(first) - 1) + (sizeof(second) - 1),
            true,
            "text/plain",
            sizeof("text/plain") - 1,
            &body);
        Expect(NT_SUCCESS(status), "BodyCreateStream succeeds for known-length body");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/upload";
        status = wknet::http::PostEx(session, url, Length(url), nullptr, body, nullptr, &resp);
        Expect(NT_SUCCESS(status), "known-length streaming body send succeeds");
        Expect(captured.CallCount == 1, "known-length streaming body reaches transport once");
        Expect(stream.CallCount == 2, "known-length streaming body is read in source chunks");
        Expect(captured.ObservedBodyLength == (sizeof(first) - 1) + (sizeof(second) - 1),
            "known-length streaming body wire length matches payload");
        Expect(BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Content-Length: 11\r\n"), "known-length streaming body emits Content-Length");
        Expect(!BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Transfer-Encoding: chunked"), "known-length streaming body does not emit chunked");

        wknet::http::ResponseRelease(resp);
        wknet::http::BodyRelease(body);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestStreamingRequestBodyChunkedTrailers() noexcept
    {
        const char* response =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for streaming chunked body");

        static const char first[] = "hello";
        static const char second[] = "-world";
        const char* chunks[] = { first, second };
        const SIZE_T chunkLengths[] = { sizeof(first) - 1, sizeof(second) - 1 };
        StreamingBodyContext stream = {};
        stream.Chunks = chunks;
        stream.ChunkLengths = chunkLengths;
        stream.ChunkCount = sizeof(chunks) / sizeof(chunks[0]);

        wknet::http::Body* body = nullptr;
        status = wknet::http::BodyCreateStream(
            StreamingBodyRead,
            &stream,
            0,
            false,
            nullptr,
            0,
            &body);
        Expect(NT_SUCCESS(status), "BodyCreateStream succeeds for unknown-length body");
        status = wknet::http::BodyAddTrailerEx(
            body,
            "X-Checksum",
            sizeof("X-Checksum") - 1,
            "abc",
            sizeof("abc") - 1);
        Expect(NT_SUCCESS(status), "BodyAddTrailerEx succeeds for streaming chunked body");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/upload";
        status = wknet::http::PostEx(session, url, Length(url), nullptr, body, nullptr, &resp);
        Expect(NT_SUCCESS(status), "chunked streaming body send succeeds");
        Expect(captured.CallCount == 1, "chunked streaming body reaches transport once");
        Expect(stream.CallCount == 2, "chunked streaming body is read in source chunks");
        Expect(captured.ObservedBodyLength == 43, "chunked streaming body wire length includes framing and trailer");
        Expect(BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Transfer-Encoding: chunked\r\n"), "unknown-length streaming body emits chunked");
        Expect(!BufferContainsLiteral(
            captured.BuiltRequest,
            captured.BuiltRequestLength,
            "Content-Length:"), "unknown-length streaming body omits Content-Length");

        wknet::http::ResponseRelease(resp);
        wknet::http::BodyRelease(body);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestTrailersRejectedWithoutChunked() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for non-chunked trailer rejection");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for non-chunked trailer rejection");

        const char* url = "http://example.com/upload";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for non-chunked trailer rejection");

        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds for non-chunked trailer rejection");

        const char* body = "payload-bytes";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for non-chunked trailer rejection");

        // A trailer can be staged regardless of body mode...
        const char* checksum = "abc123";
        status = wknet::http::RequestAddTrailer(request, "X-Checksum", Length("X-Checksum"), checksum, Length(checksum));
        Expect(NT_SUCCESS(status), "RequestAddTrailer stages trailer before send-time mode check");

        // ...but the default Content-Length mode has nowhere to emit it, so send fails.
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, nullptr, &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "trailers without chunked transfer fail at send");
        Expect(resp == nullptr, "no response produced when trailers are rejected");

        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestSessionRequestBufferBytesLimitsRequestBody() noexcept
    {
        // Request wire buffer now grows on demand. RequestBufferBytes is an initial
        // size hint, not a hard rejection threshold for ordinary request bodies.
        static UCHAR body[20 * 1024] = {};
        for (SIZE_T index = 0; index < sizeof(body); ++index) {
            body[index] = static_cast<UCHAR>('a' + (index % 26));
        }

        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for default request buffer test");

        const char* url = "http://example.com/large-post";
        wknet::http::Response* resp = nullptr;
        status = wknet::http::Post(
            session,
            url,
            Length(url),
            body,
            sizeof(body),
            &resp);
        Expect(NT_SUCCESS(status), "default request buffer grows for oversized request body");
        Expect(captured.CallCount == 1, "grown request body reaches transport");
        Expect(captured.ObservedBodyLength == sizeof(body), "grown request body length reaches transport");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "grown request body response parses");
        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.RequestBufferBytes = 32 * 1024;
        captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);

        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate accepts custom request buffer");

        resp = nullptr;
        status = wknet::http::Post(
            session,
            url,
            Length(url),
            body,
            sizeof(body),
            &resp);
        Expect(NT_SUCCESS(status), "custom request buffer allows larger request body");
        Expect(captured.CallCount == 1, "larger request body reaches transport");
        Expect(captured.ObservedBodyLength == sizeof(body), "larger request body length reaches transport");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "larger request body response parses");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRequestBuilder() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds");

        const char* url = "http://example.com/v1/data";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds");

        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Put);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds");

        const char* json = "{\"key\":\"value\"}";
        status = wknet::http::RequestSetJsonBody(request, json, Length(json));
        Expect(NT_SUCCESS(status), "RequestSetJsonBody succeeds");

        const char* hdrName = "X-Custom";
        const char* hdrValue = "abc";
        status = wknet::http::RequestSetHeader(
            request,
            hdrName, Length(hdrName),
            hdrValue, Length(hdrValue));
        Expect(NT_SUCCESS(status), "RequestSetHeader succeeds");

        const char* encodingName = "Accept-Encoding";
        const char* encodingValue = "identity";
        status = wknet::http::RequestSetHeader(
            request,
            encodingName, Length(encodingName),
            encodingValue, Length(encodingValue));
        Expect(NT_SUCCESS(status), "custom Accept-Encoding header succeeds");

        const char* rangeName = "Range";
        const char* rangeValue = "bytes=0-3";
        status = wknet::http::RequestSetHeader(
            request,
            rangeName, Length(rangeName),
            rangeValue, Length(rangeValue));
        Expect(NT_SUCCESS(status), "Range header succeeds as pass-through");

        const char* conditionName = "If-None-Match";
        const char* conditionValue = "\"etag\"";
        status = wknet::http::RequestSetHeader(
            request,
            conditionName, Length(conditionName),
            conditionValue, Length(conditionValue));
        Expect(NT_SUCCESS(status), "conditional request header succeeds as pass-through");

        wknet::http::Response* resp = nullptr;
        wknet::http::SendOptions sendOptions = wknet::http::DefaultSendOptions();
        status = wknet::http::Send(session, request, &sendOptions, &resp);
        Expect(NT_SUCCESS(status), "Send succeeds");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "status code is 200");
        Expect(captured.BodyLength == Length(json), "json body length");
        Expect(memcmp(captured.Body, json, Length(json)) == 0, "json body content");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Accept-Encoding: identity\r\n"),
            "custom Accept-Encoding is preserved");
        Expect(
            !BufferContainsLiteral(
                captured.BuiltRequest,
                captured.BuiltRequestLength,
                "Accept-Encoding: gzip, deflate, br, zstd, identity\r\n"),
            "default Accept-Encoding is not duplicated over custom value");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Range: bytes=0-3\r\n"),
            "Range header is passed through");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "If-None-Match: \"etag\"\r\n"),
            "conditional request header is passed through");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }


    void TestDynamicRequestHeadersAndLongValues() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for dynamic headers");

        wknet::http::Headers* headers = nullptr;
        status = wknet::http::HeadersCreate(&headers);
        Expect(NT_SUCCESS(status), "HeadersCreate succeeds");

        // More than the old fixed 16-slot table.
        for (ULONG index = 0; index < 40; ++index) {
            char name[32] = {};
            char value[16] = {};
            const int nameLength = sprintf_s(name, "X-Dyn-%u", index);
            const int valueLength = sprintf_s(value, "%u", index);
            Expect(nameLength > 0 && valueLength > 0, "dynamic header names format");
            status = wknet::http::HeadersAddEx(
                headers,
                name,
                static_cast<SIZE_T>(nameLength),
                value,
                static_cast<SIZE_T>(valueLength));
            Expect(NT_SUCCESS(status), "HeadersAddEx grows past old 16-slot cap");
        }

        // Cookie/JWT-sized value that exceeds the old 512-byte hard cap.
        char longCookie[700] = {};
        memset(longCookie, 'a', sizeof(longCookie) - 1);
        status = wknet::http::HeadersAdd(headers, "Cookie", longCookie);
        Expect(NT_SUCCESS(status), "HeadersAdd accepts >512-byte Cookie");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/dynamic-headers";
        status = wknet::http::GetEx(session, url, Length(url), headers, nullptr, &resp);
        Expect(NT_SUCCESS(status), "GetEx with many/long headers succeeds");
        Expect(captured.CallCount == 1, "dynamic header request reaches transport");
        Expect(captured.BuiltRequestLength != 0, "transport captured request bytes");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "Cookie:"),
            "long Cookie is serialized");
        Expect(
            BufferContainsLiteral(captured.BuiltRequest, captured.BuiltRequestLength, "X-Dyn-39:"),
            "40th custom header is serialized");
        Expect(captured.BuiltRequestLength > 512, "request wire size exceeds old value cap");

        wknet::http::ResponseRelease(resp);
        wknet::http::HeadersRelease(headers);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRequestTransferEncodingRejected() noexcept
    {
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for Transfer-Encoding rejection");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for Transfer-Encoding rejection");

        const char* url = "http://example.com/upload";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for Transfer-Encoding rejection");

        const char* body = "hello";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for Transfer-Encoding rejection");

        const char* headerName = "Transfer-Encoding";
        const char* headerValue = "chunked";
        status = wknet::http::RequestSetHeader(
            request,
            headerName,
            Length(headerName),
            headerValue,
            Length(headerValue));
        Expect(NT_SUCCESS(status), "RequestSetHeader stores Transfer-Encoding until send validation");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, nullptr, &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "wknet send rejects request Transfer-Encoding");
        Expect(resp == nullptr, "rejected Transfer-Encoding does not allocate a response");
        Expect(captured.CallCount == 0, "rejected Transfer-Encoding does not reach transport");

        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRequestReservedHeadersRejected() noexcept
    {
        ExpectRejectedRequestHeader(
            "Host",
            "other.example",
            false,
            STATUS_INVALID_PARAMETER,
            "wknet send rejects caller-supplied Host header");

        ExpectRejectedRequestHeader(
            "Content-Length",
            "12",
            false,
            STATUS_INVALID_PARAMETER,
            "wknet send rejects caller-supplied Content-Length header");

        ExpectRejectedRequestHeader(
            "Connection",
            "close",
            false,
            STATUS_INVALID_PARAMETER,
            "wknet send rejects caller-supplied Connection header");

        ExpectRejectedRequestHeader(
            "TE",
            "trailers",
            false,
            STATUS_NOT_SUPPORTED,
            "wknet send rejects request TE header");

        ExpectRejectedRequestHeader(
            "Trailer",
            "Digest",
            false,
            STATUS_NOT_SUPPORTED,
            "wknet send rejects request Trailer header");

        ExpectRejectedRequestHeader(
            "Expect",
            "100-continue",
            true,
            STATUS_NOT_SUPPORTED,
            "wknet send rejects body with Expect: 100-continue");
    }

    void TestExpectContinueSendsBodyAfter100() noexcept
    {
        static const char continueResponse[] =
            "HTTP/1.1 100 Continue\r\n"
            "\r\n";
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        ExpectContinueCapture capture = {};
        capture.FirstResponse = continueResponse;
        capture.FirstResponseLength = sizeof(continueResponse) - 1;
        capture.FinalResponse = finalResponse;
        capture.FinalResponseLength = sizeof(finalResponse) - 1;
        wknet::http::test::SetHttpTransport(ExpectContinueTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for expect continue");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for expect continue");

        const char* url = "http://example.com/expect";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for expect continue");
        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for expect continue");

        const char* body = "payload";
        status = wknet::http::RequestSetBody(request, reinterpret_cast<const UCHAR*>(body), Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for expect continue");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagExpectContinue;

        wknet::http::Response* response = nullptr;
        status = wknet::http::Send(session, request, &options, &response);
        Expect(NT_SUCCESS(status), "expect continue send succeeds after 100");
        Expect(wknet::http::ResponseStatusCode(response) == 200, "expect continue final status is returned");
        Expect(capture.CallCount == 2, "expect continue uses header and body phases");
        Expect(capture.HeaderCallCount == 1, "expect continue header phase observed");
        Expect(capture.BodyCallCount == 1, "expect continue body phase observed");
        Expect(capture.FirstExpectContinueEnabled, "expect continue flag reaches transport");
        Expect(!capture.FirstExpectContinueBodySent, "first expect continue phase does not send body");
        Expect(capture.SecondExpectContinueBodySent, "second expect continue phase sends body");
        Expect(
            BufferContainsLiteral(capture.HeaderSegment, capture.HeaderSegmentLength, "Expect: 100-continue\r\n"),
            "expect continue header is injected");
        Expect(
            !BufferContainsLiteral(capture.HeaderSegment, capture.HeaderSegmentLength, body),
            "expect continue header phase excludes request body");
        Expect(capture.BodySegmentLength == Length(body), "expect continue body segment length");
        Expect(memcmp(capture.BodySegment, body, Length(body)) == 0, "expect continue body segment bytes");

        wknet::http::ResponseRelease(response);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestExpectContinueFinalResponseSkipsBody() noexcept
    {
        static const char finalResponse[] =
            "HTTP/1.1 417 Expectation Failed\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";

        ExpectContinueCapture capture = {};
        capture.FirstResponse = finalResponse;
        capture.FirstResponseLength = sizeof(finalResponse) - 1;
        capture.FinalResponse = finalResponse;
        capture.FinalResponseLength = sizeof(finalResponse) - 1;
        wknet::http::test::SetHttpTransport(ExpectContinueTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for expect final response");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for expect final response");

        const char* url = "http://example.com/expect-final";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for expect final response");
        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for expect final response");

        const char* body = "payload";
        status = wknet::http::RequestSetBody(request, reinterpret_cast<const UCHAR*>(body), Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for expect final response");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagExpectContinue;

        wknet::http::Response* response = nullptr;
        status = wknet::http::Send(session, request, &options, &response);
        Expect(NT_SUCCESS(status), "expect continue returns final response");
        Expect(wknet::http::ResponseStatusCode(response) == 417, "expect continue returns 417 to caller");
        Expect(capture.CallCount == 1, "expect continue final response uses one phase");
        Expect(capture.BodyCallCount == 0, "expect continue final response skips body");
        Expect(
            BufferContainsLiteral(capture.HeaderSegment, capture.HeaderSegmentLength, "Expect: 100-continue\r\n"),
            "expect continue final response still injects header");
        Expect(
            !BufferContainsLiteral(capture.HeaderSegment, capture.HeaderSegmentLength, body),
            "expect continue final response header phase excludes body");

        wknet::http::ResponseRelease(response);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestExpectContinueTimeoutSendsBody() noexcept
    {
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        ExpectContinueCapture capture = {};
        capture.FirstStatus = STATUS_IO_TIMEOUT;
        capture.FinalResponse = finalResponse;
        capture.FinalResponseLength = sizeof(finalResponse) - 1;
        wknet::http::test::SetHttpTransport(ExpectContinueTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for expect timeout");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for expect timeout");

        const char* url = "http://example.com/expect-timeout";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for expect timeout");
        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for expect timeout");

        const char* body = "payload";
        status = wknet::http::RequestSetBody(request, reinterpret_cast<const UCHAR*>(body), Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for expect timeout");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagExpectContinue;
        options.ExpectContinueTimeoutMs = 1;

        wknet::http::Response* response = nullptr;
        status = wknet::http::Send(session, request, &options, &response);
        Expect(NT_SUCCESS(status), "expect continue timeout sends body");
        Expect(wknet::http::ResponseStatusCode(response) == 200, "expect continue timeout final status");
        Expect(capture.CallCount == 2, "expect continue timeout uses second phase");
        Expect(capture.BodyCallCount == 1, "expect continue timeout sends body phase");
        Expect(capture.BodySegmentLength == Length(body), "expect continue timeout body length");
        Expect(memcmp(capture.BodySegment, body, Length(body)) == 0, "expect continue timeout body bytes");

        wknet::http::ResponseRelease(response);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestExpectContinueDisconnectReturnsError() noexcept
    {
        ExpectContinueCapture capture = {};
        capture.FirstStatus = STATUS_CONNECTION_RESET;
        wknet::http::test::SetHttpTransport(ExpectContinueTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for expect disconnect");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for expect disconnect");

        const char* url = "http://example.com/expect-disconnect";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for expect disconnect");
        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for expect disconnect");

        const char* body = "payload";
        status = wknet::http::RequestSetBody(request, reinterpret_cast<const UCHAR*>(body), Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for expect disconnect");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagExpectContinue;

        wknet::http::Response* response = nullptr;
        status = wknet::http::Send(session, request, &options, &response);
        Expect(status == STATUS_CONNECTION_RESET, "expect continue disconnect returns transport error");
        Expect(response == nullptr, "expect continue disconnect does not allocate response");
        Expect(capture.CallCount == 1, "expect continue disconnect uses one phase");
        Expect(capture.BodyCallCount == 0, "expect continue disconnect skips body");

        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestExpectContinueWithoutBodyDoesNotInjectHeader() noexcept
    {
        static const char finalResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        ExpectContinueCapture capture = {};
        capture.FinalResponse = finalResponse;
        capture.FinalResponseLength = sizeof(finalResponse) - 1;
        wknet::http::test::SetHttpTransport(ExpectContinueTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for expect without body");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for expect without body");

        const char* url = "http://example.com/expect-without-body";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for expect without body");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagExpectContinue;

        wknet::http::Response* response = nullptr;
        status = wknet::http::Send(session, request, &options, &response);
        Expect(NT_SUCCESS(status), "expect continue flag without body sends normally");
        Expect(wknet::http::ResponseStatusCode(response) == 200, "expect without body status");
        Expect(capture.CallCount == 1, "expect without body uses one phase");
        Expect(!capture.FirstExpectContinueEnabled, "expect without body does not enable transport phase");
        Expect(
            !BufferContainsLiteral(capture.HeaderSegment, capture.HeaderSegmentLength, "Expect: 100-continue\r\n"),
            "expect without body does not inject header");

        wknet::http::ResponseRelease(response);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRequestMethodRejectsUnsupportedValues() noexcept
    {
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for method boundary test");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for method boundary test");

        status = wknet::http::RequestSetMethod(
            request,
            wknet::http::Method::Connect);
        Expect(NT_SUCCESS(status), "RequestSetMethod accepts CONNECT method enum");

        status = wknet::http::RequestSetMethod(
            request,
            static_cast<wknet::http::Method>(0xFFFFFFFFUL));
        Expect(status == STATUS_INVALID_PARAMETER, "RequestSetMethod rejects unsupported method enum");

        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
    }

    void TestAutoRedirectFollowsToFinalResponse() noexcept
    {
        RedirectCapture capture = {};
        wknet::http::test::SetHttpTransport(RedirectTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for redirect");

        wknet::http::Response* resp = nullptr;
        const char* url = "http://example.com/redirect/1";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(NT_SUCCESS(status), "default redirect succeeds");
        Expect(capture.CallCount == 3, "default redirect follows two hops");
        Expect(
            BufferContainsLiteral(capture.Requests[0], capture.RequestLengths[0], "GET /redirect/1 "),
            "first redirect request path is captured");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /redirect/2 "),
            "second redirect request path is captured");
        Expect(
            BufferContainsLiteral(capture.Requests[2], capture.RequestLengths[2], "GET /final "),
            "final redirect request path is captured");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "redirect final status is 200");
        Expect(wknet::http::ResponseBodyLength(resp) == 4, "redirect final body length");
        const UCHAR* body = wknet::http::ResponseBody(resp);
        Expect(body != nullptr && memcmp(body, "done", 4) == 0, "redirect final body");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAutoRedirectCanBeDisabled() noexcept
    {
        RedirectCapture capture = {};
        wknet::http::test::SetHttpTransport(RedirectTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for disabled redirect");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for disabled redirect");

        const char* url = "http://example.com/redirect/1";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for disabled redirect");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagDisableAutoRedirect;

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, &options, &resp);
        Expect(NT_SUCCESS(status), "disabled redirect send succeeds");
        Expect(capture.CallCount == 1, "disabled redirect does not follow Location");
        Expect(wknet::http::ResponseStatusCode(resp) == 302, "disabled redirect returns 302");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAutoRedirectHonorsCustomMaximum() noexcept
    {
        RedirectCapture capture = {};
        wknet::http::test::SetHttpTransport(RedirectTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for redirect limit");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for redirect limit");

        const char* url = "http://example.com/redirect/1";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for redirect limit");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.MaxRedirects = 1;

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, &options, &resp);
        Expect(NT_SUCCESS(status), "limited redirect send succeeds");
        Expect(capture.CallCount == 2, "custom redirect limit follows once");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /redirect/2 "),
            "custom redirect limit stops after first follow");
        Expect(wknet::http::ResponseStatusCode(resp) == 302, "custom redirect limit returns last 302");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestPostRedirectRewritesToGet() noexcept
    {
        RedirectCapture capture = {};
        wknet::http::test::SetHttpTransport(RedirectTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for POST redirect");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for POST redirect");

        const char* url = "http://example.com/redirect/1";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for POST redirect");
        status = wknet::http::RequestSetMethod(request, wknet::http::Method::Post);
        Expect(NT_SUCCESS(status), "RequestSetMethod POST succeeds for redirect");

        const char* payload = "payload";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(payload),
            Length(payload));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for POST redirect");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.MaxRedirects = 1;

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, &options, &resp);
        Expect(NT_SUCCESS(status), "POST redirect send succeeds");
        Expect(capture.CallCount == 2, "POST redirect follows once");
        Expect(
            BufferContainsLiteral(capture.Requests[0], capture.RequestLengths[0], "POST /redirect/1 "),
            "first POST redirect request uses POST");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /redirect/2 "),
            "302 POST redirect rewrites to GET");
        Expect(
            !BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], payload),
            "302 POST redirect clears body");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAutoRedirectResolvesRelativeReferencesAndSanitizesCrossOriginHeaders() noexcept
    {
        RedirectCapture capture = {};
        wknet::http::test::SetHttpTransport(RelativeRedirectTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for relative redirect");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for relative redirect");

        const char* url = "https://example.com/dir/page?keep=1#frag";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for relative redirect");

        status = wknet::http::RequestSetHeader(
            request,
            "Authorization",
            Length("Authorization"),
            "Bearer secret",
            Length("Bearer secret"));
        Expect(NT_SUCCESS(status), "Authorization header is accepted before redirect");
        status = wknet::http::RequestSetHeader(
            request,
            "Cookie",
            Length("Cookie"),
            "sid=secret",
            Length("sid=secret"));
        Expect(NT_SUCCESS(status), "Cookie header is accepted before redirect");
        status = wknet::http::RequestSetHeader(
            request,
            "Proxy-Authorization",
            Length("Proxy-Authorization"),
            "Basic secret",
            Length("Basic secret"));
        Expect(NT_SUCCESS(status), "Proxy-Authorization header is accepted before redirect");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "relative redirect chain succeeds");
        Expect(capture.CallCount == 5, "relative redirect follows all hops");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "GET /dir/next "),
            "relative redirect resolves sibling path");
        Expect(
            BufferContainsLiteral(capture.Requests[2], capture.RequestLengths[2], "GET /other?x=1 "),
            "relative redirect resolves parent path");
        Expect(
            BufferContainsLiteral(capture.Requests[3], capture.RequestLengths[3], "GET /other?page=2 "),
            "query-only redirect inherits current path");
        Expect(
            BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Host: other.example\r\n"),
            "scheme-relative redirect switches authority");
        Expect(
            !BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Authorization:"),
            "cross-origin redirect strips Authorization");
        Expect(
            !BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Cookie:"),
            "cross-origin redirect strips Cookie");
        Expect(
            !BufferContainsLiteral(capture.Requests[4], capture.RequestLengths[4], "Proxy-Authorization:"),
            "cross-origin redirect strips Proxy-Authorization");
        Expect(wknet::http::ResponseStatusCode(resp) == 200, "relative redirect final status is 200");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpsDowngradeRedirectIsRejected() noexcept
    {
        RedirectCapture capture = {};
        wknet::http::test::SetHttpTransport(HttpsDowngradeRedirectTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for downgrade redirect");

        wknet::http::Response* resp = nullptr;
        const char* url = "https://secure.example/redirect";
        status = wknet::http::Get(session, url, Length(url), &resp);
        Expect(status == STATUS_NOT_SUPPORTED, "HTTPS to HTTP redirect is rejected by default");
        Expect(capture.CallCount == 1, "downgrade redirect does not send target request");
        Expect(resp == nullptr, "downgrade redirect does not allocate final response");

        wknet::http::ResponseRelease(resp);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void RunRedirectMethodCase(
        const char* label,
        wknet::http::Method method,
        USHORT statusCode,
        const char* expectedFirstMethod,
        const char* expectedSecondMethod,
        bool expectBodyOnSecond) noexcept
    {
        RedirectMethodCapture capture = {};
        capture.RedirectStatus = statusCode;
        wknet::http::test::SetHttpTransport(RedirectMethodTransport, &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), label);

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for redirect method case");
        status = wknet::http::RequestSetUrl(request, "http://example.com/source", Length("http://example.com/source"));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for redirect method case");
        status = wknet::http::RequestSetMethod(request, method);
        Expect(NT_SUCCESS(status), "RequestSetMethod succeeds for redirect method case");

        const char* payload = "payload";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(payload),
            Length(payload));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for redirect method case");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::Send(session, request, nullptr, &resp);
        Expect(NT_SUCCESS(status), "redirect method case send succeeds");
        Expect(capture.CallCount == 2, "redirect method case follows one hop");
        Expect(
            BufferContainsLiteral(capture.Requests[0], capture.RequestLengths[0], expectedFirstMethod),
            "redirect method first request method matches");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], expectedSecondMethod),
            "redirect method second request method matches");
        Expect(
            BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], payload) == expectBodyOnSecond,
            "redirect method body rewrite matches");

        wknet::http::ResponseRelease(resp);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestRedirectMethodRewriteRules() noexcept
    {
        RunRedirectMethodCase(
            "SessionCreate succeeds for PUT 302 redirect method case",
            wknet::http::Method::Put,
            302,
            "PUT /source ",
            "PUT /target ",
            true);
        RunRedirectMethodCase(
            "SessionCreate succeeds for POST 303 redirect method case",
            wknet::http::Method::Post,
            303,
            "POST /source ",
            "GET /target ",
            false);
        RunRedirectMethodCase(
            "SessionCreate succeeds for POST 307 redirect method case",
            wknet::http::Method::Post,
            307,
            "POST /source ",
            "POST /target ",
            true);
        RunRedirectMethodCase(
            "SessionCreate succeeds for POST 308 redirect method case",
            wknet::http::Method::Post,
            308,
            "POST /source ",
            "POST /target ",
            true);
    }

    void TestAsyncGet() noexcept
    {
        const char* response =
            "HTTP/1.1 202 Accepted\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "done";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);
        wknet::http::test::SetAsyncAutoRun(true);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds");

        const char* url = "http://example.com/async";
        wknet::http::AsyncOp* op = nullptr;
        status = wknet::http::GetAsync(session, url, Length(url), &op);
        Expect(NT_SUCCESS(status), "GetAsync succeeds");
        Expect(op != nullptr, "async op non-null");

        Expect(wknet::http::AsyncIsCompleted(op), "async op completed under auto-run");
        Expect(NT_SUCCESS(wknet::http::AsyncWait(op, 0)), "async wait returns success");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::AsyncGetResponse(op, &resp);
        Expect(NT_SUCCESS(status), "AsyncGetResponse succeeds");
        Expect(resp != nullptr, "async response non-null");
        Expect(wknet::http::ResponseStatusCode(resp) == 202, "async status code");

        wknet::http::Response* secondResp = nullptr;
        status = wknet::http::AsyncGetResponse(op, &secondResp);
        Expect(!NT_SUCCESS(status), "AsyncGetResponse only returns the response once");
        Expect(secondResp == nullptr, "second async response output stays null");

        wknet::http::ResponseRelease(resp);
        wknet::http::AsyncRelease(op);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestAsyncRequestIsCopied() noexcept
    {
        const char* response =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        CapturedRequest captured = {};
        captured.RawResponse = response;
        captured.RawResponseLength = Length(response);
        wknet::http::test::SetHttpTransport(TestTransport, &captured);
        wknet::http::test::SetAsyncAutoRun(false);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for copied async request");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for copied async request");

        const char* url = "http://example.com/copied";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for copied async request");

        const char* body = "async-body";
        status = wknet::http::RequestSetBody(
            request,
            reinterpret_cast<const UCHAR*>(body),
            Length(body));
        Expect(NT_SUCCESS(status), "RequestSetBody succeeds for copied async request");

        wknet::http::AsyncOp* op = nullptr;
        status = wknet::http::SendAsync(session, request, nullptr, &op);
        Expect(NT_SUCCESS(status), "SendAsync with options overload succeeds");
        wknet::http::RequestRelease(request);

        status = wknet::http::test::RunAsyncOperation(op);
        Expect(NT_SUCCESS(status), "manual async run succeeds after releasing request");
        Expect(captured.CallCount == 1, "copied async request transport called once");
        Expect(captured.BodyLength == Length(body), "copied async request body length");
        Expect(memcmp(captured.Body, body, Length(body)) == 0, "copied async request body content");

        wknet::http::Response* resp = nullptr;
        status = wknet::http::AsyncGetResponse(op, &resp);
        Expect(NT_SUCCESS(status), "AsyncGetResponse succeeds for copied async request");
        Expect(wknet::http::ResponseStatusCode(resp) == 204, "copied async status code");

        wknet::http::ResponseRelease(resp);
        wknet::http::AsyncRelease(op);
        wknet::http::SessionClose(session);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
        wknet::http::test::SetAsyncAutoRun(true);
    }

    void TestAsyncCancelCompletionOnce() noexcept
    {
        wknet::http::test::SetAsyncAutoRun(false);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for async cancel");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds for async cancel");

        const char* url = "http://example.com/cancel";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(NT_SUCCESS(status), "RequestSetUrl succeeds for async cancel");

        CompletionCapture completion = {};
        wknet::http::AsyncOptions* options = nullptr;
        status = wknet::http::AsyncOptionsCreate(&options);
        Expect(NT_SUCCESS(status), "AsyncOptionsCreate succeeds for async cancel");
        options->OnComplete = RecordCompletion;
        options->CompletionContext = &completion;

        wknet::http::AsyncOp* op = nullptr;
        status = wknet::http::AsyncSendEx(
            request,
            wknet::http::Method::Get,
            url,
            Length(url),
            nullptr,
            nullptr,
            options,
            &op);
        Expect(NT_SUCCESS(status), "AsyncSendEx succeeds for async cancel");

        status = wknet::http::AsyncCancel(op);
        Expect(NT_SUCCESS(status), "AsyncCancel succeeds");
        status = wknet::http::test::RunAsyncOperation(op);
        Expect(status == STATUS_CANCELLED, "manual run preserves canceled status");
        Expect(completion.CallCount == 1, "completion callback fires once");
        Expect(completion.LastStatus == STATUS_CANCELLED, "completion status is canceled");

        wknet::http::AsyncRelease(op);
        wknet::http::AsyncOptionsRelease(options);
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
        wknet::http::test::SetAsyncAutoRun(true);
    }

    struct AsyncReleaseDuringWorkerCapture
    {
        bool ObservedCanceledAfterRelease = false;
        NTSTATUS CancelStatus = STATUS_UNSUCCESSFUL;
        SIZE_T CleanupCount = 0;
        SIZE_T CompletionCount = 0;
        NTSTATUS CompletionStatus = STATUS_UNSUCCESSFUL;
    };

    void RecordAsyncReleaseDuringWorkerCompletion(void* context, NTSTATUS status) noexcept
    {
        auto* capture = static_cast<AsyncReleaseDuringWorkerCapture*>(context);
        if (capture == nullptr) {
            return;
        }

        ++capture->CompletionCount;
        capture->CompletionStatus = status;
    }

    void CleanupAsyncReleaseDuringWorker(void* context) noexcept
    {
        auto* capture = static_cast<AsyncReleaseDuringWorkerCapture*>(context);
        if (capture != nullptr) {
            ++capture->CleanupCount;
        }
    }

    NTSTATUS ReleaseDuringAsyncWorker(
        wknet::session::AsyncOperationHandle operation,
        void* context) noexcept
    {
        auto* capture = static_cast<AsyncReleaseDuringWorkerCapture*>(context);
        if (capture == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        capture->CancelStatus = wknet::session::AsyncOperationCancel(operation);
        wknet::session::AsyncOperationRelease(operation);
        capture->ObservedCanceledAfterRelease =
            wknet::session::AsyncOperationIsCanceled(operation);
        return capture->ObservedCanceledAfterRelease ? STATUS_CANCELLED : STATUS_UNSUCCESSFUL;
    }

    void TestAsyncWorkerObservesCancelAfterRelease() noexcept
    {
        wknet::http::test::SetAsyncAutoRun(false);

        AsyncReleaseDuringWorkerCapture capture = {};
        wknet::session::AsyncCreateOptions options = {};
        options.Kind = wknet::session::AsyncOperationKind::HttpSend;
        options.WorkerRoutine = ReleaseDuringAsyncWorker;
        options.CleanupRoutine = CleanupAsyncReleaseDuringWorker;
        options.Context = &capture;
        options.CompletionCallback = RecordAsyncReleaseDuringWorkerCompletion;
        options.CompletionContext = &capture;

        wknet::session::AsyncOperationHandle operation = nullptr;
        NTSTATUS status = wknet::session::AsyncOperationCreate(options, &operation);
        Expect(NT_SUCCESS(status), "direct async operation create succeeds");
        Expect(operation != nullptr, "direct async operation is returned");

        status = wknet::session::TestRunAsyncOperation(operation);
        Expect(status == STATUS_CANCELLED, "manual run returns canceled after release");
        Expect(NT_SUCCESS(capture.CancelStatus), "worker cancel succeeds before release");
        Expect(capture.ObservedCanceledAfterRelease, "worker observes cancel after release");
        Expect(capture.CompletionCount == 1, "completion fires once when worker releases handle");
        Expect(capture.CompletionStatus == STATUS_CANCELLED, "completion status remains canceled");
        Expect(capture.CleanupCount == 1, "cleanup fires once after worker reference is released");
        Expect(NT_SUCCESS(wknet::session::EngineDrainAsync()), "async drain succeeds after manual worker release");

        wknet::http::test::SetAsyncAutoRun(true);
    }

    struct AllocatorProbe
    {
        ULONG Magic = 0x504C4C41;
    };

    void TestNonPagedAllocatorBaseline() noexcept
    {
        void* empty = wknet::AllocateNonPagedPoolBytes(0);
        Expect(empty == nullptr, "zero-byte nonpaged allocation is rejected");

        auto* bytes = static_cast<UCHAR*>(wknet::AllocateNonPagedPoolBytes(16));
        Expect(bytes != nullptr, "nonpaged byte allocation succeeds");
        bool bytesAreZero = true;
        for (SIZE_T index = 0; bytes != nullptr && index < 16; ++index) {
            if (bytes[index] != 0) {
                bytesAreZero = false;
            }
        }
        Expect(bytesAreZero, "nonpaged byte allocation is zero initialized");
        wknet::FreeNonPagedPoolBytes(bytes);

        wknet::HeapArray<UCHAR> array(8);
        Expect(array.IsValid(), "HeapArray uses nonpaged allocator wrapper");
        bool arrayIsZero = true;
        for (SIZE_T index = 0; array.IsValid() && index < array.Count(); ++index) {
            if (array[index] != 0) {
                arrayIsZero = false;
            }
        }
        Expect(arrayIsZero, "HeapArray remains zero initialized");

        wknet::HeapObject<AllocatorProbe> object;
        Expect(object.IsValid(), "HeapObject uses nonpaged allocator wrapper");
        Expect(object->Magic == 0x504C4C41, "HeapObject preserves constructor initialization");
    }

    void TestLookasideListBaseline() noexcept
    {
        wknet::rtl::LookasideList lookaside;
        Expect(!lookaside.IsInitialized(), "lookaside starts uninitialized");
        Expect(lookaside.BlockSize() == 0, "uninitialized lookaside has zero block size");
        Expect(lookaside.Allocate() == nullptr, "uninitialized lookaside does not allocate");

        NTSTATUS status = lookaside.Initialize(0);
        Expect(status == STATUS_INVALID_PARAMETER, "lookaside rejects zero-sized blocks");
        Expect(!lookaside.IsInitialized(), "zero-sized lookaside remains uninitialized");

        status = lookaside.Initialize(32);
        Expect(NT_SUCCESS(status), "lookaside initializes fixed block size");
        Expect(lookaside.IsInitialized(), "lookaside reports initialized state");
        Expect(lookaside.BlockSize() == 32, "lookaside stores block size");

        void* block = lookaside.Allocate();
        Expect(block != nullptr, "lookaside allocates a fixed block");
        if (block != nullptr) {
            memset(block, 0x5a, lookaside.BlockSize());
        }
        lookaside.Free(block);

        status = lookaside.Initialize(64);
        Expect(NT_SUCCESS(status), "lookaside reinitializes after shutdown");
        Expect(lookaside.BlockSize() == 64, "lookaside updates block size on reinitialize");
        lookaside.Shutdown();
        Expect(!lookaside.IsInitialized(), "lookaside shuts down");
        Expect(lookaside.BlockSize() == 0, "shutdown resets block size");
        Expect(lookaside.Allocate() == nullptr, "shutdown lookaside does not allocate");
    }

    void TestWknetHardLimitsAreStable() noexcept
    {
        static_assert(
            wknet::WKNET_HARD_MAX_RESPONSE_BYTES == 0,
            "response hard cap uses 0 to mean no low library-wide byte cap");
        static_assert(
            wknet::http::DefaultMaxResponseBytes == 0,
            "public default response aggregation is unlimited");
        static_assert(
            wknet::http::DefaultMaxWebSocketMessageBytes > 0,
            "websocket message default remains independently bounded");
        static_assert(
            wknet::WKNET_HARD_MAX_HEADER_SECTION >= wknet::HttpMaxHeaderBytes,
            "hard header cap must cover the parser header limit");
        static_assert(
            wknet::WKNET_HARD_MAX_HEADERS >= wknet::HttpMaxHeaders,
            "hard header count must cover the parser header count limit");
        static_assert(
            wknet::WKNET_HARD_MAX_DECODED_BYTES == 0,
            "decoded aggregate cap follows response/caller capacity");
        static_assert(
            wknet::WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL > 0,
            "local H2 stream cap must reject zero-stream configurations");
        static_assert(
            wknet::WKNET_HARD_MAX_CONNECTION_FRAMES >=
                wknet::WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL,
            "connection frame budget must cover at least one frame per allowed stream");
        static_assert(
            wknet::WKNET_HARD_MAX_CONNECTION_CONTROL_SIGNALS > 0,
            "connection control signal cap must be explicit");

        static_assert(
            wknet::WKNET_HARD_MAX_CONNECTION_BYTES == 0,
            "long-lived connections do not use a low lifetime byte cap");
    }

    void TestPagedPoolRejected() noexcept
    {
        wknet::session::WorkspaceOptions workspaceOptions = {};
        workspaceOptions.PoolType = wknet::session::PoolType::Paged;
        wknet::session::Workspace* workspace = nullptr;
        NTSTATUS status = wknet::session::WorkspaceCreate(&workspaceOptions, &workspace);
        Expect(status == STATUS_INVALID_PARAMETER, "workspace rejects paged pool");
        Expect(workspace == nullptr, "workspace output remains null when paged pool is rejected");

        workspaceOptions = {};
        workspaceOptions.MaxResponseBytes = (64 * 1024 * 1024) + 1;
        status = wknet::session::WorkspaceCreate(&workspaceOptions, &workspace);
        Expect(NT_SUCCESS(status), "workspace accepts response limits above the old hard cap");
        wknet::session::WorkspaceRelease(workspace);
        workspace = nullptr;

        wknet::session::SessionOptions sessionOptions = {};
        sessionOptions.ResponsePoolType = wknet::session::PoolType::Paged;
        wknet::session::SessionHandle apiSession = nullptr;
        status = wknet::session::SessionCreate(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &sessionOptions,
            &apiSession);
        Expect(status == STATUS_INVALID_PARAMETER, "engine SessionCreate rejects paged response pool");
        Expect(apiSession == nullptr, "engine SessionCreate does not allocate a paged session");

        sessionOptions = {};
        sessionOptions.MaxResponseHeaders = wknet::WKNET_HARD_MAX_HEADERS + 1;
        status = wknet::session::SessionCreate(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &sessionOptions,
            &apiSession);
        Expect(status == STATUS_INVALID_PARAMETER, "engine SessionCreate rejects response header count above hard cap");
        Expect(apiSession == nullptr, "engine SessionCreate does not allocate a header-overlimit session");

        sessionOptions = {};
        sessionOptions.Http2MaxHeaderBlockBytes = wknet::WKNET_HARD_MAX_HEADER_SECTION + 1;
        status = wknet::session::SessionCreate(
            reinterpret_cast<wknet::net::WskClient*>(0x1),
            &sessionOptions,
            &apiSession);
        Expect(status == STATUS_INVALID_PARAMETER, "engine SessionCreate rejects H2 header block above hard cap");
        Expect(apiSession == nullptr, "engine SessionCreate does not allocate an H2-header-overlimit session");

        wknet::http::SessionConfig config = {};
        config.ResponsePool = wknet::http::PoolType::Paged;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "wknet SessionCreate rejects paged response pool");
        Expect(session == nullptr, "wknet SessionCreate does not allocate a paged session");
    }

    void TestHttp2KeepAliveSessionConfigDefaultsAndValidation() noexcept
    {
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        Expect(!config.Http2KeepAlive.Enabled, "HTTP/2 keepalive is disabled by default");
        Expect(
            config.Http2KeepAlive.IdleMs == wknet::http::DefaultHttp2KeepAliveIdleMs,
            "HTTP/2 keepalive default idle matches constant");
        Expect(
            config.Http2KeepAlive.IntervalMs == wknet::http::DefaultHttp2KeepAliveIntervalMs,
            "HTTP/2 keepalive default interval matches constant");
        Expect(
            config.Http2KeepAlive.AckTimeoutMs == wknet::http::DefaultHttp2KeepAliveAckTimeoutMs,
            "HTTP/2 keepalive default ACK timeout matches constant");

        config.Http2KeepAlive.Enabled = true;
        config.Http2KeepAlive.IdleMs = 0;
        config.Http2KeepAlive.IntervalMs = 0;
        config.Http2KeepAlive.AckTimeoutMs = 0;
        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "wknet SessionCreate normalizes zero HTTP/2 keepalive timings");
        wknet::http::SessionClose(session);

        config = wknet::http::DefaultSessionConfig();
        config.Http2KeepAlive.Enabled = true;
        config.Http2KeepAlive.AckTimeoutMs = wknet::WskOperationTimeoutMilliseconds + 1;
        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "wknet SessionCreate rejects oversized HTTP/2 keepalive ACK timeout");
        Expect(session == nullptr, "wknet SessionCreate does not allocate invalid HTTP/2 keepalive session");
    }

    void TestHttp3SessionConfigDefaultsMappingAndValidation() noexcept
    {
        Expect(static_cast<ULONG>(wknet::http::Http3ConnectMode::Auto) == 0 &&
                   static_cast<ULONG>(wknet::http::Http3ConnectMode::Disabled) == 1 &&
                   static_cast<ULONG>(wknet::http::Http3ConnectMode::Required) == 2,
               "public HTTP/3 connect modes preserve the frozen ABI values");
        Expect(static_cast<ULONG>(wknet::http::Http3RaceMode::DelayedTcpFallback) == 0 &&
                   static_cast<ULONG>(wknet::http::Http3RaceMode::SequentialPreferHttp3) == 1,
               "public HTTP/3 race modes preserve the frozen ABI values");

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        Expect(config.Http3.Mode == wknet::http::Http3ConnectMode::Auto, "public HTTP/3 connect mode defaults to Auto");
        Expect(config.Http3.Race == wknet::http::Http3RaceMode::DelayedTcpFallback,
               "public HTTP/3 race mode defaults to delayed TCP fallback");
        Expect(config.Http3.RaceWindowMs == 250 && config.Http3.QuicProbeTimeoutMs == 1500 &&
                   config.Http3.AltSvcMaxEntries == 64 && config.Http3.AltSvcMaxAgeSec == 604800,
               "public HTTP/3 timing and Alt-Svc defaults match the total design");

        wknet::session::SessionOptions engineDefaults = {};
        Expect(engineDefaults.Http3.Mode == wknet::session::Http3ConnectMode::Disabled,
               "internal HTTP/3 default remains explicit Disabled");
        wknet::session::Http3Options internalAuto = engineDefaults.Http3;
        internalAuto.Mode = wknet::session::Http3ConnectMode::Auto;
        const wknet::session::Http3Options normalized = wknet::session::NormalizeHttp3Options(internalAuto);
        Expect(normalized.Mode == wknet::session::Http3ConnectMode::Auto,
               "M9 normalization preserves enabled Auto mode");

        config.Http3.Race = wknet::http::Http3RaceMode::SequentialPreferHttp3;
        config.Http3.RaceWindowMs = 333;
        config.Http3.QuicProbeTimeoutMs = 1777;
        config.Http3.AltSvcMaxEntries = 7;
        config.Http3.AltSvcMaxAgeSec = 86400;
        wknet::http::Session *session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "public Auto HTTP/3 session config is accepted");
        Expect(session != nullptr && session->Engine != nullptr &&
                   session->Engine->Options.Http3.Mode == wknet::session::Http3ConnectMode::Auto &&
                   session->Engine->Options.Http3.Race == wknet::session::Http3RaceMode::SequentialPreferHttp3 &&
                   session->Engine->Options.Http3.RaceWindowMilliseconds == 333 &&
                   session->Engine->Options.Http3.QuicProbeTimeoutMilliseconds == 1777 &&
                   session->Engine->Options.Http3.AltSvcMaxEntries == 7 &&
                   session->Engine->Options.Http3.AltSvcMaxAgeSeconds == 86400,
               "public HTTP/3 config maps to enabled internal Auto options");
        wknet::http::SessionClose(session);

        config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status) && session != nullptr &&
                   session->Engine->Options.Http3.Mode == wknet::session::Http3ConnectMode::Required,
               "Required survives public-to-internal mapping");
        wknet::http::SessionClose(session);

        config = wknet::http::DefaultSessionConfig();
        config.Http3.RaceWindowMs = 0;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/3 race window rejects zero");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.RaceWindowMs = wknet::http::MaxHttp3RaceWindowMs + 1;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/3 race window rejects values above the policy maximum");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.QuicProbeTimeoutMs = 0;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/3 QUIC probe timeout rejects zero");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.QuicProbeTimeoutMs = wknet::http::MaxHttp3QuicProbeTimeoutMs + 1;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/3 QUIC probe timeout rejects oversized values");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.AltSvcMaxEntries = wknet::WKNET_HARD_MAX_ALT_SVC_ENTRIES + 1;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/3 Alt-Svc entry count obeys the local hard limit");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.AltSvcMaxAgeSec = wknet::http::MaxHttp3AltSvcMaxAgeSec + 1;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER,
               "HTTP/3 Alt-Svc age rejects values whose millisecond conversion overflows ULONG");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = static_cast<wknet::http::Http3ConnectMode>(99);
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/3 connect mode rejects unknown enum values");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.Race = static_cast<wknet::http::Http3RaceMode>(99);
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER, "HTTP/3 race mode rejects unknown enum values");
    }

    void TestHttp3RequiredConflictContract() noexcept
    {
        wknet::session::Http3Options http3 = {};
        http3.Mode = wknet::session::Http3ConnectMode::Required;
        wknet::session::TlsOptions tls = {};
        wknet::session::HttpSendOptions send = {};
        wknet::session::Http3ConnectMode effective = wknet::session::Http3ConnectMode::Disabled;

        NTSTATUS status = wknet::session::ResolveHttp3ConnectMode(http3, tls, false, &send, true, false, &effective);
        Expect(NT_SUCCESS(status) && effective == wknet::session::Http3ConnectMode::Required,
               "Required HTTPS without conflicts remains Required");

        status = wknet::session::ResolveHttp3ConnectMode(http3, tls, false, &send, false, false, &effective);
        Expect(status == STATUS_NOT_SUPPORTED, "Required with plaintext HTTP returns STATUS_NOT_SUPPORTED");
        send.Http2CleartextMode = wknet::session::Http2CleartextMode::PriorKnowledge;
        status = wknet::session::ResolveHttp3ConnectMode(http3, tls, false, &send, true, false, &effective);
        Expect(status == STATUS_NOT_SUPPORTED, "Required with h2c prior knowledge returns STATUS_NOT_SUPPORTED");
        send.Http2CleartextMode = wknet::session::Http2CleartextMode::Disabled;
        status = wknet::session::ResolveHttp3ConnectMode(http3, tls, true, &send, true, false, &effective);
        Expect(status == STATUS_NOT_SUPPORTED, "Required with an HTTP proxy returns STATUS_NOT_SUPPORTED");

        tls.Alpn = "smtp";
        tls.AlpnLength = Length("smtp");
        status = wknet::session::ResolveHttp3ConnectMode(http3, tls, false, &send, true, false, &effective);
        Expect(status == STATUS_INVALID_PARAMETER,
               "Required with explicit non-HTTP ALPN returns STATUS_INVALID_PARAMETER");
        tls.Alpn = "h2";
        tls.AlpnLength = Length("h2");
        wknet::http2::Http2Priority priority = {};
        send.Http2Priority = &priority;
        status = wknet::session::ResolveHttp3ConnectMode(http3, tls, false, &send, true, false, &effective);
        Expect(status == STATUS_INVALID_PARAMETER, "Required with HTTP/2 priority returns STATUS_INVALID_PARAMETER");

        send.Http2Priority = nullptr;
        status = wknet::session::ResolveHttp3ConnectMode(http3, tls, true, &send, false, true, &effective);
        Expect(NT_SUCCESS(status) && effective == wknet::session::Http3ConnectMode::Disabled,
               "WebSocket explicitly normalizes away from H3 and keeps its existing H1/H2 selection");

        wknet::session::Http3Options autoMode = http3;
        autoMode.Mode = wknet::session::Http3ConnectMode::Auto;
        send.Http2Priority = &priority;
        status = wknet::session::ResolveHttp3ConnectMode(autoMode, tls, true, &send, false, false, &effective);
        Expect(NT_SUCCESS(status) && effective == wknet::session::Http3ConnectMode::Disabled,
               "Auto remains TCP-compatible when H3 conflicts are present");

        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        FillProxyConfig(config.Proxy);
        wknet::http::Session *session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_NOT_SUPPORTED && session == nullptr,
               "public Required session rejects proxy configuration with STATUS_NOT_SUPPORTED");
        config = wknet::http::DefaultSessionConfig();
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        config.Tls.Alpn = "acme-tls/1";
        config.Tls.AlpnLength = Length("acme-tls/1");
        status = wknet::http::SessionCreate(&config, &session);
        Expect(status == STATUS_INVALID_PARAMETER && session == nullptr,
               "public Required session rejects explicit non-HTTP ALPN with STATUS_INVALID_PARAMETER");
    }

    void TestHttp3PoolFailureInjection() noexcept
    {
        wknet::rtl::ProtocolFailureInjectionReset();
        wknet::rtl::ProtocolFailureInjectionSetFailOnNth(wknet::rtl::ProtocolAllocationSite::SessionPoolEntries, 1);
        wknet::session::ConnectionPool pool = {};
        Expect(wknet::session::ConnectionPoolInitialize(&pool, 2, 1, 30000) == STATUS_INSUFFICIENT_RESOURCES,
               "HTTP/3 pool entry failpoint is propagated");
        Expect(pool.Entries == nullptr && wknet::rtl::ProtocolFailureInjectionLiveCount(
                                              wknet::rtl::ProtocolAllocationSite::SessionPoolEntries) == 0,
               "failed pool initialization has no live entry table");
        wknet::rtl::ProtocolFailureInjectionSetFailOnNth(wknet::rtl::ProtocolAllocationSite::SessionPoolEntries, 0);
    }

    struct Http3PoolCloseCapture final
    {
        ULONG CloseCount = 0;
    };

    void CloseHttp3PoolEntry(void *context, wknet::session::ConnectionPool *pool,
                             wknet::session::PooledConnection *connection, wknet::quic::QuicConnection *quicConnection,
                             wknet::http3::Http3Connection *http3Connection) noexcept
    {
        Http3PoolCloseCapture *capture = static_cast<Http3PoolCloseCapture *>(context);
        Expect(capture != nullptr && quicConnection != nullptr && http3Connection != nullptr,
               "HTTP/3 pool close receives the strict QUIC holder resources");
        if (capture != nullptr)
        {
            ++capture->CloseCount;
        }
        wknet::session::ConnectionPoolCompleteQuicClose(pool, connection);
    }

    void TestConnectionPoolHttp3LeaseAndGoawayLifecycle() noexcept
    {
        wknet::session::ConnectionPool pool = {};
        NTSTATUS status = wknet::session::ConnectionPoolInitialize(&pool, 2, 2, 30000);
        Expect(NT_SUCCESS(status), "HTTP/3 pool initializes");

        wknet::session::ConnectionPoolKey key = {};
        key.Kind = wknet::session::ConnectionKind::Quic;
        memcpy(key.Scheme, "https", 5);
        key.SchemeLength = 5;
        memcpy(key.Host, "example.com", 11);
        key.HostLength = 11;
        key.Port = 443;
        memcpy(key.TlsServerName, "example.com", 11);
        key.TlsServerNameLength = 11;
        memcpy(key.Alpn, "h3", 2);
        key.AlpnLength = 2;
        memcpy(key.AlternativeHost, "example.com", 11);
        key.AlternativeHostLength = 11;
        key.AlternativePort = 443;
        key.QuicVersion = wknet::quic::QuicVersion1;

        wknet::session::PooledConnection *connection = nullptr;
        bool reused = true;
        status = wknet::session::ConnectionPoolAcquire(&pool, key, wknet::session::ConnectionPolicy::ReuseOrCreate,
                                                       &connection, &reused);
        Expect(NT_SUCCESS(status) && connection != nullptr && !reused,
               "first HTTP/3 pool acquire reserves a QUIC entry");

        Http3PoolCloseCapture closeCapture = {};
        auto *quicConnection = reinterpret_cast<wknet::quic::QuicConnection *>(static_cast<uintptr_t>(1));
        auto *http3Connection = reinterpret_cast<wknet::http3::Http3Connection *>(static_cast<uintptr_t>(2));
        status = wknet::session::PooledConnectionAdoptQuic(connection, quicConnection, http3Connection,
                                                           CloseHttp3PoolEntry, &closeCapture);
        Expect(NT_SUCCESS(status), "HTTP/3 pool adopts one strict QUIC/H3 holder");
        status = wknet::session::ConnectionPoolPromoteHttp3StreamLease(&pool, connection, 0, 8, 8);
        Expect(NT_SUCCESS(status), "new HTTP/3 request promotes its reserved stream lease");
        Expect(
            wknet::session::PooledConnectionQuicStreamLeaseCount(connection) == 1 &&
                wknet::session::PooledConnectionQuicActiveRequest(connection),
            "first HTTP/3 stream lease marks the pooled connection active");

        wknet::session::PooledConnection *concurrent = nullptr;
        reused = false;
        status = wknet::session::ConnectionPoolAcquire(
            &pool,
            key,
            wknet::session::ConnectionPolicy::ReuseOrCreate,
            &concurrent,
            &reused);
        Expect(
            NT_SUCCESS(status) && concurrent == connection && reused,
            "active HTTP/3 pooled connection accepts a concurrent stream lease");
        status = wknet::session::ConnectionPoolBindHttp3StreamLease(&pool, concurrent, 4, 8, 8);
        Expect(NT_SUCCESS(status), "concurrent HTTP/3 stream lease binds independently");
        Expect(
            wknet::session::PooledConnectionQuicStreamLeaseCount(connection) == 2 &&
                wknet::session::PooledConnectionQuicActiveRequest(connection),
            "two HTTP/3 stream leases keep the pooled connection active");

        wknet::session::ConnectionPoolReleaseHttp3StreamLease(&pool, connection, true);
        Expect(
            wknet::session::PooledConnectionQuicStreamLeaseCount(concurrent) == 1 &&
                wknet::session::PooledConnectionQuicActiveRequest(concurrent),
            "releasing one HTTP/3 stream keeps the remaining request active");
        wknet::session::ConnectionPoolReleaseHttp3StreamLease(&pool, concurrent, true);
        Expect(
            wknet::session::PooledConnectionQuicStreamLeaseCount(connection) == 0 &&
                !wknet::session::PooledConnectionQuicActiveRequest(connection),
            "releasing the final HTTP/3 stream returns the connection to idle");

        connection = nullptr;
        reused = false;
        status = wknet::session::ConnectionPoolAcquire(&pool, key, wknet::session::ConnectionPolicy::ReuseOrCreate,
                                                       &connection, &reused);
        Expect(NT_SUCCESS(status) && reused, "idle HTTP/3 entry is reused with a reserved stream lease");
        status = wknet::session::ConnectionPoolBindHttp3StreamLease(&pool, connection, 4, 8, 8);
        Expect(NT_SUCCESS(status), "reused HTTP/3 stream lease binds its new stream ID");
        wknet::session::ConnectionPoolSetHttp3GoAway(&pool, connection, 4);
        Expect(closeCapture.CloseCount == 0, "GOAWAY waits for the active HTTP/3 request lease to drain");
        wknet::session::ConnectionPoolReleaseHttp3StreamLease(&pool, connection, true);
        Expect(closeCapture.CloseCount == 1, "GOAWAY closes the HTTP/3 entry after the last active lease drains");

        connection = nullptr;
        reused = true;
        status = wknet::session::ConnectionPoolAcquire(&pool, key, wknet::session::ConnectionPolicy::ReuseOrCreate,
                                                       &connection, &reused);
        Expect(NT_SUCCESS(status) && !reused, "GOAWAY-drained HTTP/3 entry cannot be reused");
        wknet::session::ConnectionPoolAbandonQuicAcquire(&pool, connection);
        wknet::session::ConnectionPoolShutdown(&pool);
    }

    void TestHttp3RouterRoutesConcurrentDispatches() noexcept
    {
        wknet::session::Request firstRequest = {};
        wknet::session::Request secondRequest = {};
        BodyCallbackCapture firstBody = {};
        BodyCallbackCapture secondBody = {};
        wknet::session::HttpSendOptions firstSend = {};
        firstSend.BodyCallback = CountingBodyCallback;
        firstSend.CallbackContext = &firstBody;
        wknet::session::HttpSendOptions secondSend = {};
        secondSend.BodyCallback = CountingBodyCallback;
        secondSend.CallbackContext = &secondBody;

        wknet::session::HttpH3DispatchContext first = {};
        wknet::session::HttpH3DispatchContext second = {};
        const bool firstInitialized = InitializeHttp3RouterDispatch(&first, &firstRequest, &firstSend, 1);
        const bool secondInitialized = InitializeHttp3RouterDispatch(&second, &secondRequest, &secondSend, 2);
        Expect(firstInitialized && secondInitialized, "HTTP/3 router dispatch contexts initialize");

        bool attached = false;
        if (firstInitialized && secondInitialized)
        {
            attached = AttachHttp3RouterDispatchPair(&first, &second);
        }
        Expect(attached, "HTTP/3 router attaches two dispatches to one connection");
        if (attached)
        {
            static const UCHAR FirstData[] = {1, 2};
            static const UCHAR SecondData[] = {3, 4, 5};
            wknet::session::HttpH3TestPeerInjectData(&first.Peer, 0, FirstData, sizeof(FirstData));
            wknet::session::HttpH3TestPeerInjectData(&first.Peer, 4, SecondData, sizeof(SecondData));
            Expect(
                firstBody.CallCount == 1 && firstBody.TotalBytes == sizeof(FirstData),
                "HTTP/3 router sends stream 0 data only to its dispatch");
            Expect(
                secondBody.CallCount == 1 && secondBody.TotalBytes == sizeof(SecondData),
                "HTTP/3 router sends stream 4 data only to its dispatch");

            wknet::session::HttpH3TestPeerInjectGoaway(&first.Peer, 4);
            Expect(
                first.GoawayReceived &&
                    first.GoawayResult == wknet::session::HttpH3GoawayResult::StreamMayHaveBeenProcessed,
                "HTTP/3 GOAWAY notifies the lower active stream without rejecting it");
            Expect(
                second.GoawayReceived &&
                    second.GoawayResult == wknet::session::HttpH3GoawayResult::StreamRejected &&
                    second.CompletionDelivered && second.TerminalStatus == STATUS_RETRY,
                "HTTP/3 GOAWAY notifies and rejects the boundary stream");
        }
        if (secondInitialized)
        {
            wknet::session::HttpH3DispatchRelease(&second);
        }
        if (firstInitialized)
        {
            wknet::session::HttpH3DispatchRelease(&first);
        }

        firstBody = {};
        secondBody = {};
        first = {};
        second = {};
        const bool errorFirstInitialized = InitializeHttp3RouterDispatch(&first, &firstRequest, &firstSend, 3);
        const bool errorSecondInitialized = InitializeHttp3RouterDispatch(&second, &secondRequest, &secondSend, 4);
        Expect(
            errorFirstInitialized && errorSecondInitialized,
            "HTTP/3 connection-error dispatch contexts initialize");

        attached = false;
        if (errorFirstInitialized && errorSecondInitialized)
        {
            attached = AttachHttp3RouterDispatchPair(&first, &second);
        }
        Expect(attached, "HTTP/3 router attaches two dispatches for connection-error fanout");
        if (attached)
        {
            wknet::session::HttpH3TestPeerInjectConnectionError(
                &first.Peer,
                STATUS_CONNECTION_DISCONNECTED,
                wknet::http3::H3_INTERNAL_ERROR);
            Expect(
                first.CompletionDelivered && first.TerminalStatus == STATUS_CONNECTION_DISCONNECTED,
                "HTTP/3 connection error completes the first active dispatch");
            Expect(
                second.CompletionDelivered && second.TerminalStatus == STATUS_CONNECTION_DISCONNECTED,
                "HTTP/3 connection error completes the second active dispatch");
        }
        if (errorSecondInitialized)
        {
            wknet::session::HttpH3DispatchRelease(&second);
        }
        if (errorFirstInitialized)
        {
            wknet::session::HttpH3DispatchRelease(&first);
        }
    }

    void TestIrqlCheck() noexcept
    {
        wknet::http::test::SetCurrentIrql(2);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "SessionCreate fails at non-PASSIVE");
        Expect(session == nullptr, "session not allocated at non-PASSIVE");

        wknet::http::test::ResetCurrentIrql();

        status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds before raised IRQL checks");

        wknet::http::Request* request = nullptr;
        status = wknet::http::RequestCreate(session, &request);
        Expect(NT_SUCCESS(status), "RequestCreate succeeds before raised IRQL checks");

        wknet::http::test::SetCurrentIrql(2);

        wknet::http::Request* raisedRequest = nullptr;
        status = wknet::http::RequestCreate(session, &raisedRequest);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "RequestCreate fails at non-PASSIVE");
        Expect(raisedRequest == nullptr, "request not allocated at non-PASSIVE");

        const char* url = "http://example.com/raised";
        status = wknet::http::RequestSetUrl(request, url, Length(url));
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "RequestSetUrl fails at non-PASSIVE");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Send(session, request, &response);
        Expect(status == STATUS_INVALID_DEVICE_REQUEST, "Send fails at non-PASSIVE");
        Expect(response == nullptr, "response not allocated at non-PASSIVE");

        wknet::http::test::ResetCurrentIrql();
        wknet::http::RequestRelease(request);
        wknet::http::SessionClose(session);
    }

    void TestWebSocketTransportModeDefaults() noexcept
    {
        Expect(
            static_cast<ULONG>(wknet::http::WebSocketTransportMode::Auto) == 0,
            "public websocket Auto transport mode remains ABI zero");
        Expect(
            static_cast<ULONG>(wknet::session::WebSocketTransportMode::Auto) == 0,
            "engine websocket Auto transport mode remains ABI zero");

        wknet::websocket::ConnectConfig aggregateConfig = {};
        Expect(
            aggregateConfig.TransportMode == wknet::http::WebSocketTransportMode::Auto,
            "aggregate websocket connect config defaults to Auto");

        wknet::websocket::ConnectConfig defaultConfig = wknet::websocket::DefaultConnectConfig();
        Expect(
            defaultConfig.TransportMode == wknet::http::WebSocketTransportMode::Auto,
            "DefaultConnectConfig defaults to Auto");

        wknet::session::WebSocketConnectOptions engineOptions = {};
        Expect(
            engineOptions.TransportMode == wknet::session::WebSocketTransportMode::Auto,
            "engine websocket connect options default to Auto");

        WsCapture capture = {};
        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for websocket transport defaults");

        const char* url = "wss://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        status = wknet::websocket::Connect(session, url, Length(url), &ws);
        Expect(NT_SUCCESS(status), "URL websocket connect succeeds with default Auto transport");
        Expect(
            capture.LastTransportMode == wknet::http::WebSocketTransportMode::Auto,
            "URL websocket connect propagates Auto transport mode");
        status = wknet::websocket::Close(ws);
        Expect(NT_SUCCESS(status), "URL websocket default transport close succeeds");

        capture = {};
        wknet::websocket::ConnectConfig http11Config = wknet::websocket::DefaultConnectConfig();
        http11Config.Url = url;
        http11Config.UrlLength = Length(url);
        http11Config.TransportMode = wknet::http::WebSocketTransportMode::Http11Only;
        ws = nullptr;
        status = wknet::websocket::Connect(session, &http11Config, &ws);
        Expect(NT_SUCCESS(status), "explicit HTTP/1.1 websocket connect succeeds");
        Expect(
            capture.LastTransportMode == wknet::http::WebSocketTransportMode::Http11Only,
            "explicit HTTP/1.1 websocket transport mode propagates");
        Expect(!capture.LastAllowWebSocketOverHttp2, "explicit HTTP/1.1 websocket connect does not set legacy h2 flag");
        status = wknet::websocket::Close(ws);
        Expect(NT_SUCCESS(status), "explicit HTTP/1.1 websocket close succeeds");

        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketRoundTrip() noexcept
    {
        WsCapture capture = {};
        const char* echo = "world";
        capture.NextType = wknet::websocket::MsgType::Text;
        capture.NextLength = Length(echo);
        memcpy(capture.NextData, echo, capture.NextLength);

        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws");

        const char* url = "ws://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds");
        Expect(capture.ConnectCount == 1, "connect called once");
        Expect(strcmp(capture.LastScheme, "ws") == 0, "scheme captured");
        Expect(strcmp(capture.LastHost, "example.com") == 0, "host captured");
        Expect(
            capture.LastTransportMode == wknet::http::WebSocketTransportMode::Auto,
            "default websocket connect config uses Auto transport mode");
        Expect(!capture.LastPerMessageDeflate.Enable, "default websocket connect config leaves permessage-deflate disabled");

        const char* hello = "hello";
        status = wknet::websocket::SendText(ws, hello, Length(hello));
        Expect(NT_SUCCESS(status), "WsSendText succeeds");
        Expect(capture.SendCount == 1, "send called once");
        Expect(strcmp(capture.LastSendBuffer, hello) == 0, "send payload captured");

        wknet::websocket::Message message = {};
        status = wknet::websocket::Receive(ws, &message);
        Expect(NT_SUCCESS(status), "WsReceive succeeds");
        Expect(message.Type == wknet::websocket::MsgType::Text, "received type Text");
        Expect(message.DataLength == Length(echo), "received length matches");
        Expect(message.Final, "received final flag matches");
        Expect(message.Data != nullptr && memcmp(message.Data, echo, message.DataLength) == 0,
            "received payload matches");

        status = wknet::websocket::Close(ws);
        Expect(NT_SUCCESS(status), "WsClose succeeds");
        Expect(capture.CloseCount == 1, "close called once");

        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketPerMessageDeflateOptInPropagates() noexcept
    {
        WsCapture capture = {};
        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for websocket permessage-deflate opt-in");

        const char* url = "ws://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.PerMessageDeflate.Enable = true;
        wsConfig.PerMessageDeflate.ClientNoContextTakeover = true;
        wsConfig.PerMessageDeflate.ServerNoContextTakeover = true;
        wsConfig.PerMessageDeflate.ClientMaxWindowBits = 12;
        wsConfig.PerMessageDeflate.ServerMaxWindowBits = 13;

        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "websocket permessage-deflate opt-in connect succeeds through test transport");
        Expect(capture.LastPerMessageDeflate.Enable, "permessage-deflate enable propagates to engine");
        Expect(capture.LastPerMessageDeflate.ClientNoContextTakeover,
            "permessage-deflate client_no_context_takeover propagates");
        Expect(capture.LastPerMessageDeflate.ServerNoContextTakeover,
            "permessage-deflate server_no_context_takeover propagates");
        Expect(capture.LastPerMessageDeflate.ClientMaxWindowBits == 12,
            "permessage-deflate client window bits propagates");
        Expect(capture.LastPerMessageDeflate.ServerMaxWindowBits == 13,
            "permessage-deflate server window bits propagates");

        status = wknet::websocket::Close(ws);
        Expect(NT_SUCCESS(status), "websocket permessage-deflate opt-in close succeeds");
        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketHttp2OptInPropagates() noexcept
    {
        WsCapture capture = {};
        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for wss h2 opt-in");

        const char* url = "wss://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.AllowWebSocketOverHttp2 = true;
        wsConfig.TransportMode = wknet::http::WebSocketTransportMode::LegacyBoolean;
        wsConfig.Tls.MaxTls12Renegotiations = 2;
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "wss websocket h2 opt-in connect succeeds through test transport");
        Expect(capture.LastAllowWebSocketOverHttp2, "wss websocket h2 opt-in propagates to engine");
        Expect(
            capture.LastTransportMode == wknet::http::WebSocketTransportMode::LegacyBoolean,
            "legacy websocket h2 opt-in keeps legacy transport mode");
        Expect(
            capture.LastMaxTls12Renegotiations == 2,
            "wss websocket TLS 1.2 renegotiation limit propagates to engine");

        status = wknet::websocket::Close(ws);
        Expect(NT_SUCCESS(status), "wss websocket h2 opt-in close succeeds");
        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketHttp2OptInRejectsCleartextWs() noexcept
    {
        WsCapture capture = {};
        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws h2 rejection");

        const char* url = "ws://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.TransportMode = wknet::http::WebSocketTransportMode::Http2Required;
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(status == STATUS_NOT_SUPPORTED, "ws h2-required rejects unsupported h2c path");
        Expect(ws == nullptr, "ws h2-required rejection leaves websocket null");
        Expect(capture.ConnectCount == 0, "ws h2-required rejection does not reach transport");

        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketControlFramesAndCloseEx() noexcept
    {
        WsCapture capture = {};
        const UCHAR pingPayload[] = { 'h', 'b' };
        capture.NextType = wknet::websocket::MsgType::Ping;
        capture.NextLength = sizeof(pingPayload);
        memcpy(capture.NextData, pingPayload, capture.NextLength);

        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws controls");

        const char* url = "ws://example.com/socket";
        const char* subprotocol = "chat";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.Subprotocol = subprotocol;
        wsConfig.SubprotocolLength = Length(subprotocol);
        wsConfig.AutoReplyPing = false;
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for control frame API");
        Expect(strcmp(capture.LastSubprotocol, subprotocol) == 0, "subprotocol is sent in websocket connect");

        const char* selectedSubprotocol = nullptr;
        SIZE_T selectedSubprotocolLength = 0;
        status = wknet::websocket::SelectedSubprotocol(
            ws,
            &selectedSubprotocol,
            &selectedSubprotocolLength);
        Expect(NT_SUCCESS(status), "selected subprotocol query succeeds");
        Expect(
            selectedSubprotocol != nullptr &&
            selectedSubprotocolLength == Length(subprotocol) &&
            memcmp(selectedSubprotocol, subprotocol, selectedSubprotocolLength) == 0,
            "selected subprotocol matches negotiated token");

        wknet::websocket::Message message = {};
        status = wknet::websocket::Receive(ws, &message);
        Expect(NT_SUCCESS(status), "WsReceive returns manual ping event");
        Expect(message.Type == wknet::websocket::MsgType::Ping, "received ping type");
        Expect(message.DataLength == sizeof(pingPayload), "received ping payload length");

        status = wknet::websocket::SendPong(ws, message.Data, message.DataLength);
        Expect(NT_SUCCESS(status), "WsSendPong succeeds");
        Expect(capture.LastSendType == wknet::websocket::MsgType::Pong, "pong type captured");
        Expect(capture.LastSendLength == sizeof(pingPayload), "pong payload length captured");
        Expect(memcmp(capture.LastSendData, pingPayload, sizeof(pingPayload)) == 0, "pong payload captured");
        Expect(capture.LastSendFinalFragment, "pong is final");

        const UCHAR activePing[] = { 'p', 'i', 'n', 'g' };
        status = wknet::websocket::SendPing(ws, activePing, sizeof(activePing));
        Expect(NT_SUCCESS(status), "WsSendPing succeeds");
        Expect(capture.LastSendType == wknet::websocket::MsgType::Ping, "ping type captured");
        Expect(capture.LastSendLength == sizeof(activePing), "ping payload length captured");
        Expect(memcmp(capture.LastSendData, activePing, sizeof(activePing)) == 0, "ping payload captured");

        UCHAR tooLargePing[126] = {};
        status = wknet::websocket::SendPing(ws, tooLargePing, sizeof(tooLargePing));
        Expect(status == STATUS_INVALID_PARAMETER, "WsSendPing rejects oversized control payload");

        const UCHAR reason[] = { 'b', 'y', 'e' };
        status = wknet::websocket::CloseEx(ws, 1000, reason, sizeof(reason));
        Expect(NT_SUCCESS(status), "WsCloseEx succeeds");
        Expect(capture.LastSendType == wknet::websocket::MsgType::Close, "close type captured");
        Expect(capture.LastSendLength == 2 + sizeof(reason), "close payload length captured");
        Expect(capture.LastSendData[0] == 0x03 && capture.LastSendData[1] == 0xe8, "close code captured");
        Expect(memcmp(capture.LastSendData + 2, reason, sizeof(reason)) == 0, "close reason captured");
        Expect(capture.CloseCount == 1, "CloseEx closes websocket once");

        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketFragmentedSendEnforcesTotalLimit() noexcept
    {
        WsCapture capture = {};
        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws fragmented limit");

        const char* url = "ws://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.MaxMessageBytes = 5;
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for fragmented limit");

        wknet::websocket::SendOptions nonFinal = {};
        nonFinal.FinalFragment = false;
        const UCHAR first[] = { 'a', 'b', 'c' };
        status = wknet::websocket::SendBinaryEx(ws, first, sizeof(first), &nonFinal);
        Expect(NT_SUCCESS(status), "first non-final binary fragment succeeds");
        Expect(capture.SendCount == 1, "first fragment reaches test transport");

        const UCHAR tooLarge[] = { 'd', 'e', 'f' };
        status = wknet::websocket::SendContinuation(ws, tooLarge, sizeof(tooLarge));
        Expect(status == STATUS_BUFFER_TOO_SMALL, "continuation exceeding MaxMessageBytes is rejected");
        Expect(capture.SendCount == 1, "oversized continuation is not sent");

        const UCHAR final[] = { 'd', 'e' };
        status = wknet::websocket::SendContinuation(ws, final, sizeof(final));
        Expect(NT_SUCCESS(status), "smaller final continuation still succeeds");
        Expect(capture.SendCount == 2, "final continuation reaches test transport");
        Expect(capture.LastSendType == wknet::websocket::MsgType::Continuation,
            "final continuation type captured");
        Expect(capture.LastSendFinalFragment, "final continuation closes fragmented send");

        wknet::websocket::Close(ws);
        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketReceiveCannotRaiseConnectionLimit() noexcept
    {
        WsCapture capture = {};
        const UCHAR payload[] = { 'a', 'b', 'c', 'd', 'e', 'f' };
        capture.NextType = wknet::websocket::MsgType::Binary;
        capture.NextLength = sizeof(payload);
        memcpy(capture.NextData, payload, capture.NextLength);

        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws receive connection limit");

        const char* url = "ws://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        wsConfig.MaxMessageBytes = 5;
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for receive connection limit");

        wknet::websocket::ReceiveOptions receiveOptions = {};
        receiveOptions.MaxMessageBytes = 10;
        wknet::websocket::Message message = {};
        status = wknet::websocket::ReceiveEx(ws, &receiveOptions, &message);
        Expect(status == STATUS_BUFFER_TOO_SMALL, "WsReceiveEx cannot raise connection MaxMessageBytes");
        Expect(capture.ReceiveCount == 1, "oversized receive reaches test transport once");
        Expect(capture.CloseCount == 1, "oversized receive closes websocket transport");

        wknet::websocket::Close(ws);
        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketPublicValidationMatchesRealPath() noexcept
    {
        WsCapture capture = {};
        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws public validation");

        const char* url = "ws://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig invalidConfig = wknet::websocket::DefaultConnectConfig();
        invalidConfig.Url = url;
        invalidConfig.UrlLength = Length(url);
        invalidConfig.Subprotocol = "bad token";
        invalidConfig.SubprotocolLength = Length(invalidConfig.Subprotocol);
        status = wknet::websocket::Connect(session, &invalidConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "WsConnect rejects invalid subprotocol token");
        Expect(ws == nullptr, "invalid subprotocol does not allocate websocket");
        Expect(capture.ConnectCount == 0, "invalid subprotocol does not reach test transport");

        wknet::websocket::ConnectConfig invalidDeflateConfig = wknet::websocket::DefaultConnectConfig();
        invalidDeflateConfig.Url = url;
        invalidDeflateConfig.UrlLength = Length(url);
        invalidDeflateConfig.PerMessageDeflate.Enable = true;
        invalidDeflateConfig.PerMessageDeflate.ClientMaxWindowBits = 7;
        status = wknet::websocket::Connect(session, &invalidDeflateConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "WsConnect rejects invalid permessage-deflate window bits");
        Expect(ws == nullptr, "invalid permessage-deflate options do not allocate websocket");
        Expect(capture.ConnectCount == 0, "invalid permessage-deflate options do not reach test transport");

        wknet::websocket::Header controlledHeader = {};
        controlledHeader.Name = "Sec-WebSocket-Key";
        controlledHeader.NameLength = Length(controlledHeader.Name);
        controlledHeader.Value = "injected";
        controlledHeader.ValueLength = Length(controlledHeader.Value);
        wknet::websocket::ConnectConfig controlledConfig = wknet::websocket::DefaultConnectConfig();
        controlledConfig.Url = url;
        controlledConfig.UrlLength = Length(url);
        controlledConfig.Headers = &controlledHeader;
        controlledConfig.HeaderCount = 1;
        status = wknet::websocket::Connect(session, &controlledConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "WsConnect rejects override of controlled header");
        Expect(ws == nullptr, "controlled header override does not allocate websocket");
        Expect(capture.ConnectCount == 0, "controlled header override does not reach test transport");

        wknet::websocket::Header injectionHeader = {};
        injectionHeader.Name = "Origin";
        injectionHeader.NameLength = Length(injectionHeader.Name);
        injectionHeader.Value = "evil\r\nX-Injected: 1";
        injectionHeader.ValueLength = Length(injectionHeader.Value);
        wknet::websocket::ConnectConfig injectionConfig = wknet::websocket::DefaultConnectConfig();
        injectionConfig.Url = url;
        injectionConfig.UrlLength = Length(url);
        injectionConfig.Headers = &injectionHeader;
        injectionConfig.HeaderCount = 1;
        status = wknet::websocket::Connect(session, &injectionConfig, &ws);
        Expect(status == STATUS_INVALID_PARAMETER, "WsConnect rejects CRLF injection in header value");
        Expect(capture.ConnectCount == 0, "CRLF injection does not reach test transport");

        wknet::websocket::Header okHeader = {};
        okHeader.Name = "Origin";
        okHeader.NameLength = Length(okHeader.Name);
        okHeader.Value = "https://example.com";
        okHeader.ValueLength = Length(okHeader.Value);
        wknet::websocket::ConnectConfig customConfig = wknet::websocket::DefaultConnectConfig();
        customConfig.Url = url;
        customConfig.UrlLength = Length(url);
        customConfig.Headers = &okHeader;
        customConfig.HeaderCount = 1;
        status = wknet::websocket::Connect(session, &customConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect accepts valid custom header");
        Expect(capture.ConnectCount == 1, "valid custom header reaches test transport");
        if (NT_SUCCESS(status)) {
            status = wknet::websocket::Close(ws);
            Expect(NT_SUCCESS(status), "WsClose succeeds after custom header connect");
            ws = nullptr;
        }
        // Reset counters so the remaining assertions observe a clean sequence.
        capture.ConnectCount = 0;
        capture.CloseCount = 0;
        capture.SendCount = 0;

        wknet::websocket::ConnectConfig validConfig = wknet::websocket::DefaultConnectConfig();
        validConfig.Url = url;
        validConfig.UrlLength = Length(url);
        status = wknet::websocket::Connect(session, &validConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for public validation");

        const unsigned char invalidText[] = { 0xc3, 0x28 };
        status = wknet::websocket::SendText(
            ws,
            reinterpret_cast<const char*>(invalidText),
            sizeof(invalidText));
        Expect(status == STATUS_INVALID_PARAMETER, "WsSendText rejects invalid UTF-8 before test transport");
        Expect(capture.SendCount == 0, "invalid text send does not reach test transport");

        const UCHAR invalidReason[] = { 0xc3, 0x28 };
        status = wknet::websocket::CloseEx(ws, 1000, invalidReason, sizeof(invalidReason));
        Expect(status == STATUS_INVALID_PARAMETER, "WsCloseEx rejects invalid UTF-8 reason");
        Expect(capture.CloseCount == 0, "invalid close reason does not close websocket");

        wknet::websocket::Close(ws);
        Expect(capture.CloseCount == 1, "valid cleanup close reaches test transport once");
        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestWebSocketTerminalTransportStatusDisconnectsHandle() noexcept
    {
        WsCapture capture = {};
        wknet::http::test::SetWebSocketTransport(
            WsConnectCallback,
            WsSendCallback,
            WsReceiveCallback,
            WsCloseCallback,
            &capture);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for ws terminal status");

        const char* url = "ws://example.com/socket";
        wknet::websocket::WebSocket* ws = nullptr;
        wknet::websocket::ConnectConfig wsConfig = wknet::websocket::DefaultConnectConfig();
        wsConfig.Url = url;
        wsConfig.UrlLength = Length(url);
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for send terminal status");

        capture.SendStatus = STATUS_IO_TIMEOUT;
        const char* text = "timeout";
        status = wknet::websocket::SendText(ws, text, Length(text));
        Expect(status == STATUS_IO_TIMEOUT, "terminal send status is returned");
        Expect(capture.CloseCount == 1, "terminal send status closes test transport");
        capture.SendStatus = STATUS_SUCCESS;

        status = wknet::websocket::SendText(ws, text, Length(text));
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "send after terminal send status is disconnected");
        Expect(capture.SendCount == 0, "send after terminal status does not reach test transport again");

        wknet::websocket::Close(ws);
        Expect(capture.CloseCount == 1, "WsClose after terminal send status is idempotent");

        ws = nullptr;
        status = wknet::websocket::Connect(session, &wsConfig, &ws);
        Expect(NT_SUCCESS(status), "WsConnect succeeds for receive terminal status");
        capture.ReceiveStatus = STATUS_CANCELLED;
        wknet::websocket::Message message = {};
        status = wknet::websocket::Receive(ws, &message);
        Expect(status == STATUS_CANCELLED, "terminal receive status is returned");
        Expect(capture.CloseCount == 2, "terminal receive status closes test transport");
        capture.ReceiveStatus = STATUS_SUCCESS;

        status = wknet::websocket::Receive(ws, &message);
        Expect(status == STATUS_CONNECTION_DISCONNECTED, "receive after terminal status is disconnected");

        wknet::websocket::Close(ws);
        Expect(capture.CloseCount == 2, "WsClose after terminal receive status is idempotent");

        wknet::http::SessionClose(session);
        wknet::http::test::SetWebSocketTransport(nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    void TestHttpCacheFreshHit() noexcept
    {
        const char response[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=60\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "fresh";
        CacheCapture capture = {};
        capture.Responses[0] = response;
        capture.ResponseLengths[0] = sizeof(response) - 1;
        capture.ResponseCount = 1;
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);

        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for fresh hit");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds with cache");

        wknet::http::Response* first = nullptr;
        status = wknet::http::Get(session, "http://example.com/cache", &first);
        Expect(NT_SUCCESS(status), "first cached GET succeeds");
        Expect(capture.CallCount == 1, "first cached GET reaches transport");
        wknet::http::ResponseRelease(first);

        wknet::http::Response* second = nullptr;
        status = wknet::http::Get(session, "http://example.com/cache", &second);
        Expect(NT_SUCCESS(status), "fresh cached GET succeeds");
        Expect(capture.CallCount == 1, "fresh cached GET does not reach transport");
        Expect(wknet::http::ResponseStatusCode(second) == 200, "fresh cached response status is preserved");
        Expect(wknet::http::ResponseBodyLength(second) == 5 &&
            memcmp(wknet::http::ResponseBody(second), "fresh", 5) == 0,
            "fresh cached body is returned");

        wknet::http::CacheStats stats = {};
        status = wknet::http::CacheGetStats(cache, &stats);
        Expect(NT_SUCCESS(status), "CacheGetStats succeeds");
        Expect(stats.Hits == 1 && stats.Stores == 1, "cache stats record hit and store");

        wknet::http::ResponseRelease(second);
        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpCacheStaleRevalidatesWith304() noexcept
    {
        const char firstResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=0\r\n"
            "ETag: \"abc\"\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "cached";
        const char notModified[] =
            "HTTP/1.1 304 Not Modified\r\n"
            "ETag: \"abc\"\r\n"
            "\r\n";
        CacheCapture capture = {};
        capture.Responses[0] = firstResponse;
        capture.ResponseLengths[0] = sizeof(firstResponse) - 1;
        capture.Responses[1] = notModified;
        capture.ResponseLengths[1] = sizeof(notModified) - 1;
        capture.ResponseCount = 2;
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);

        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for revalidation");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for revalidation");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, "http://example.com/revalidate", &response);
        Expect(NT_SUCCESS(status), "initial stale-cache GET succeeds");
        wknet::http::ResponseRelease(response);

        response = nullptr;
        status = wknet::http::Get(session, "http://example.com/revalidate", &response);
        Expect(NT_SUCCESS(status), "304 revalidation GET succeeds");
        Expect(capture.CallCount == 2, "stale cache reaches transport for validation");
        Expect(BufferContainsLiteral(capture.Requests[1], capture.RequestLengths[1], "If-None-Match: \"abc\"\r\n"),
            "stale cache emits If-None-Match");
        Expect(wknet::http::ResponseStatusCode(response) == 200, "304 merge returns cached status");
        Expect(wknet::http::ResponseBodyLength(response) == 6 &&
            memcmp(wknet::http::ResponseBody(response), "cached", 6) == 0,
            "304 merge returns cached body");

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpCacheOnlyIfCachedMiss() noexcept
    {
        CacheCapture capture = {};
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);
        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for only-if-cached");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for only-if-cached");

        wknet::http::SendOptions options = wknet::http::DefaultSendOptions();
        options.Flags = wknet::http::SendFlagOnlyIfCached;
        wknet::http::Response* response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/miss", Length("http://example.com/miss"), nullptr, &options, &response);
        Expect(status == STATUS_NOT_FOUND, "only-if-cached miss returns not found");
        Expect(response == nullptr, "only-if-cached miss does not allocate response");
        Expect(capture.CallCount == 0, "only-if-cached miss does not reach transport");

        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpCacheVarySeparatesRequests() noexcept
    {
        const char gzipResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=60\r\n"
            "Vary: Accept-Encoding\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "gzip";
        const char brResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=60\r\n"
            "Vary: Accept-Encoding\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "br";
        CacheCapture capture = {};
        capture.Responses[0] = gzipResponse;
        capture.ResponseLengths[0] = sizeof(gzipResponse) - 1;
        capture.Responses[1] = brResponse;
        capture.ResponseLengths[1] = sizeof(brResponse) - 1;
        capture.ResponseCount = 2;
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);

        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for Vary");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for Vary");

        wknet::http::Headers* gzipHeaders = nullptr;
        wknet::http::Headers* brHeaders = nullptr;
        status = wknet::http::HeadersCreate(&gzipHeaders);
        Expect(NT_SUCCESS(status), "gzip headers create");
        status = wknet::http::HeadersAdd(gzipHeaders, "Accept-Encoding", "gzip");
        Expect(NT_SUCCESS(status), "gzip header add");
        status = wknet::http::HeadersCreate(&brHeaders);
        Expect(NT_SUCCESS(status), "br headers create");
        status = wknet::http::HeadersAdd(brHeaders, "Accept-Encoding", "br");
        Expect(NT_SUCCESS(status), "br header add");

        wknet::http::Response* response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/vary", Length("http://example.com/vary"), gzipHeaders, nullptr, &response);
        Expect(NT_SUCCESS(status), "gzip Vary request succeeds");
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/vary", Length("http://example.com/vary"), brHeaders, nullptr, &response);
        Expect(NT_SUCCESS(status), "br Vary request succeeds");
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/vary", Length("http://example.com/vary"), gzipHeaders, nullptr, &response);
        Expect(NT_SUCCESS(status), "gzip Vary cache hit succeeds");
        Expect(capture.CallCount == 2, "Vary hit does not reach transport");
        Expect(wknet::http::ResponseBodyLength(response) == 4 &&
            memcmp(wknet::http::ResponseBody(response), "gzip", 4) == 0,
            "Vary returns matching representation");

        wknet::http::ResponseRelease(response);
        wknet::http::HeadersRelease(gzipHeaders);
        wknet::http::HeadersRelease(brHeaders);
        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpCacheServesRangeFromFullResponse() noexcept
    {
        const char fullResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=60\r\n"
            "Content-Length: 10\r\n"
            "\r\n"
            "abcdefghij";
        CacheCapture capture = {};
        capture.Responses[0] = fullResponse;
        capture.ResponseLengths[0] = sizeof(fullResponse) - 1;
        capture.ResponseCount = 1;
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);

        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for range");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for range");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, "http://example.com/range", &response);
        Expect(NT_SUCCESS(status), "initial range source GET succeeds");
        wknet::http::ResponseRelease(response);

        wknet::http::Headers* headers = nullptr;
        status = wknet::http::HeadersCreate(&headers);
        Expect(NT_SUCCESS(status), "range headers create");
        status = wknet::http::HeadersAdd(headers, "Range", "bytes=2-5");
        Expect(NT_SUCCESS(status), "range header add");
        response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/range", Length("http://example.com/range"), headers, nullptr, &response);
        Expect(NT_SUCCESS(status), "range cache hit succeeds");
        Expect(capture.CallCount == 1, "range cache hit avoids transport");
        Expect(wknet::http::ResponseStatusCode(response) == 206, "range cache hit returns 206");
        Expect(wknet::http::ResponseBodyLength(response) == 4 &&
            memcmp(wknet::http::ResponseBody(response), "cdef", 4) == 0,
            "range cache hit returns sliced body");

        wknet::http::ResponseRelease(response);
        wknet::http::HeadersRelease(headers);
        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpCacheCombinesPartialContent() noexcept
    {
        const char firstPartial[] =
            "HTTP/1.1 206 Partial Content\r\n"
            "Cache-Control: max-age=60\r\n"
            "ETag: \"range-a\"\r\n"
            "Content-Range: bytes 0-3/8\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "abcd";
        const char secondPartial[] =
            "HTTP/1.1 206 Partial Content\r\n"
            "Cache-Control: max-age=60\r\n"
            "ETag: \"range-a\"\r\n"
            "Content-Range: bytes 4-7/8\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "efgh";
        CacheCapture capture = {};
        capture.Responses[0] = firstPartial;
        capture.ResponseLengths[0] = sizeof(firstPartial) - 1;
        capture.Responses[1] = secondPartial;
        capture.ResponseLengths[1] = sizeof(secondPartial) - 1;
        capture.ResponseCount = 2;
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);

        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for partial combine");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for partial combine");

        wknet::http::Headers* firstRange = nullptr;
        wknet::http::Headers* secondRange = nullptr;
        wknet::http::Headers* fullRange = nullptr;
        status = wknet::http::HeadersCreate(&firstRange);
        Expect(NT_SUCCESS(status), "first partial range headers create");
        status = wknet::http::HeadersAdd(firstRange, "Range", "bytes=0-3");
        Expect(NT_SUCCESS(status), "first partial range header add");
        status = wknet::http::HeadersCreate(&secondRange);
        Expect(NT_SUCCESS(status), "second partial range headers create");
        status = wknet::http::HeadersAdd(secondRange, "Range", "bytes=4-7");
        Expect(NT_SUCCESS(status), "second partial range header add");
        status = wknet::http::HeadersCreate(&fullRange);
        Expect(NT_SUCCESS(status), "combined partial range headers create");
        status = wknet::http::HeadersAdd(fullRange, "Range", "bytes=0-7");
        Expect(NT_SUCCESS(status), "combined partial range header add");

        wknet::http::Response* response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/partial", Length("http://example.com/partial"), firstRange, nullptr, &response);
        Expect(NT_SUCCESS(status), "first partial GET succeeds");
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/partial", Length("http://example.com/partial"), secondRange, nullptr, &response);
        Expect(NT_SUCCESS(status), "second partial GET succeeds");
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = wknet::http::GetEx(session, "http://example.com/partial", Length("http://example.com/partial"), fullRange, nullptr, &response);
        Expect(NT_SUCCESS(status), "combined partial cache hit succeeds");
        Expect(capture.CallCount == 2, "combined partial range avoids transport");
        Expect(wknet::http::ResponseStatusCode(response) == 206, "combined partial response is 206");
        Expect(wknet::http::ResponseBodyLength(response) == 8 &&
            memcmp(wknet::http::ResponseBody(response), "abcdefgh", 8) == 0,
            "combined partial response returns merged body");

        wknet::http::ResponseRelease(response);
        wknet::http::HeadersRelease(firstRange);
        wknet::http::HeadersRelease(secondRange);
        wknet::http::HeadersRelease(fullRange);
        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpCacheUnsafeMethodInvalidates() noexcept
    {
        const char firstResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=60\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "one";
        const char postResponse[] =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        const char secondResponse[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=60\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "two";
        CacheCapture capture = {};
        capture.Responses[0] = firstResponse;
        capture.ResponseLengths[0] = sizeof(firstResponse) - 1;
        capture.Responses[1] = postResponse;
        capture.ResponseLengths[1] = sizeof(postResponse) - 1;
        capture.Responses[2] = secondResponse;
        capture.ResponseLengths[2] = sizeof(secondResponse) - 1;
        capture.ResponseCount = 3;
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);

        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for invalidation");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for invalidation");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, "http://example.com/item", &response);
        Expect(NT_SUCCESS(status), "initial invalidation GET succeeds");
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = wknet::http::SendEx(session, wknet::http::Method::Post, "http://example.com/item", Length("http://example.com/item"), nullptr, nullptr, nullptr, &response);
        Expect(NT_SUCCESS(status), "unsafe method succeeds");
        wknet::http::ResponseRelease(response);
        response = nullptr;
        status = wknet::http::Get(session, "http://example.com/item", &response);
        Expect(NT_SUCCESS(status), "GET after invalidation succeeds");
        Expect(capture.CallCount == 3, "GET after unsafe method reaches transport");
        Expect(wknet::http::ResponseBodyLength(response) == 3 &&
            memcmp(wknet::http::ResponseBody(response), "two", 3) == 0,
            "GET after invalidation returns new representation");

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestHttpCacheAsyncHit() noexcept
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Cache-Control: max-age=60\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "async";
        CacheCapture capture = {};
        capture.Responses[0] = responseBytes;
        capture.ResponseLengths[0] = sizeof(responseBytes) - 1;
        capture.ResponseCount = 1;
        wknet::http::test::SetHttpTransport(CacheTransport, &capture);

        wknet::http::Cache* cache = nullptr;
        NTSTATUS status = wknet::http::CacheCreate(&cache);
        Expect(NT_SUCCESS(status), "CacheCreate succeeds for async hit");
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.Cache = cache;
        wknet::http::Session* session = nullptr;
        status = wknet::http::SessionCreate(&config, &session);
        Expect(NT_SUCCESS(status), "SessionCreate succeeds for async hit");

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, "http://example.com/async-cache", &response);
        Expect(NT_SUCCESS(status), "initial async cache seed succeeds");
        wknet::http::ResponseRelease(response);

        wknet::http::AsyncOp* operation = nullptr;
        status = wknet::http::AsyncGet(session, "http://example.com/async-cache", &operation);
        Expect(NT_SUCCESS(status), "AsyncGet cache hit starts");
        status = wknet::http::AsyncGetResponse(operation, &response);
        Expect(NT_SUCCESS(status), "AsyncGetResponse returns cached response");
        Expect(capture.CallCount == 1, "async cache hit avoids transport");
        Expect(wknet::http::ResponseBodyLength(response) == 5 &&
            memcmp(wknet::http::ResponseBody(response), "async", 5) == 0,
            "async cache hit returns cached body");

        wknet::http::ResponseRelease(response);
        wknet::http::AsyncRelease(operation);
        wknet::http::SessionClose(session);
        wknet::http::CacheRelease(cache);
        wknet::http::test::SetHttpTransport(nullptr, nullptr);
    }

    void TestCertificateStoreStrictLoadSemantics() noexcept
    {
        UCHAR* rootPem = nullptr;
        SIZE_T rootPemLength = 0;
        const bool loaded = LoadTestFile(
            "tests/testdata/pki/root.cert.pem",
            &rootPem,
            &rootPemLength);
        Expect(loaded, "certificate API test loads repository root PEM");
        if (!loaded) {
            return;
        }

        wknet::http::CertificateStore* store = nullptr;
        NTSTATUS status = wknet::http::CertificateStoreCreate(nullptr, &store);
        Expect(NT_SUCCESS(status) && store != nullptr, "CertificateStoreCreate accepts empty options");
        if (!NT_SUCCESS(status) || store == nullptr) {
            free(rootPem);
            return;
        }

        status = wknet::http::CertificateStoreLoadPemBundle(store, rootPem, rootPemLength);
        Expect(NT_SUCCESS(status), "CertificateStoreLoadPemBundle accepts a valid PEM certificate");

        static const UCHAR InvalidCompletePem[] =
            "-----BEGIN CERTIFICATE-----\n"
            "%%%%\n"
            "-----END CERTIFICATE-----\n";
        status = wknet::http::CertificateStoreLoadPemBundle(
            store,
            InvalidCompletePem,
            sizeof(InvalidCompletePem) - 1);
        Expect(NT_SUCCESS(status), "complete unusable PEM member is isolated");

        static const UCHAR UnterminatedPem[] =
            "-----BEGIN CERTIFICATE-----\n"
            "AAAA\n";
        status = wknet::http::CertificateStoreLoadPemBundle(
            store,
            UnterminatedPem,
            sizeof(UnterminatedPem) - 1);
        Expect(!NT_SUCCESS(status), "unterminated PEM member fails closed");

        static const UCHAR InvalidDer[] = { 0x30, 0x00 };
        status = wknet::http::CertificateStoreLoadDer(store, InvalidDer, sizeof(InvalidDer));
        Expect(!NT_SUCCESS(status), "invalid single DER certificate fails strictly");

        status = wknet::http::CertificateStoreLoadPemBundle(store, InvalidDer, sizeof(InvalidDer));
        Expect(!NT_SUCCESS(status), "PEM loader rejects non-PEM input");

        status = wknet::http::CertificateStoreLoadDer(store, rootPem, rootPemLength);
        Expect(!NT_SUCCESS(status), "DER loader rejects PEM input");

        wknet::http::CertificateAuthorityBundle invalidBundle = {};
        invalidBundle.Data = InvalidDer;
        invalidBundle.DataLength = sizeof(InvalidDer);
        wknet::http::CertificateStoreOptions options = {};
        options.AuthorityBundles = &invalidBundle;
        options.AuthorityBundleCount = 1;
        wknet::http::CertificateStore* invalidStore = nullptr;
        status = wknet::http::CertificateStoreCreate(&options, &invalidStore);
        Expect(!NT_SUCCESS(status) && invalidStore == nullptr,
            "CertificateStoreCreate validates initial authority bundle data");

        wknet::http::CertificateStoreClose(store);
        free(rootPem);
    }
}

int main() noexcept
{
    wknet::http::test::ResetCurrentIrql();
    wknet::http::test::SetAsyncAutoRun(true);

    TestSessionCreateAndClose();
    TestDestroyIsUnconditionalHighLevelDrain();
    TestSimpleGet();
    TestTls12RenegotiationLimitConfigPropagates();
    TestSessionTlsServerNameSurvivesUrlAssignment();
    TestAcceptEncodingQValueOptions();
    TestAcceptEncodingRejectsInvalidPreferences();
    TestAcceptEncodingQZeroResponseFailsClosed();
    TestCustomAcceptEncodingHeaderDrivesResponseValidation();
    TestContentCodingMaterialsDecodeDcz();
    TestTraceRequiresExplicitOptIn();
    TestTypedRangeAndConditionHeaders();
    TestTypedSuffixRangeHeader();
    TestEngineTypedRangeAndConditionHeaders();
    TestResponseDuplicateHeaderSemantics();
    TestResponseTransferEncodingDecoded();
    TestTransferCodingCloseDelimitedHonorsTestTransportEof();
    TestResponseTrailersAreExposed();
    TestInformationalResponsesAreSkipped();
    TestSessionMaxResponseBytesLimitsSimpleApi();
    TestResponseBodyCallbackIgnoresAggregationLimit();
    TestResponseBodyCallbackDecodesGzipContentEncoding();
    TestResponseBodyCallbackAggregateDecodesGzip();
    TestResponseBodyCallbackGzipHonorsAcceptEncodingPolicy();
    TestRequestRejectsHeaderAndUrlInjection();
    TestUrlRequestTargetAndHostSemantics();
    TestReusedConnectionFailureRetriesWithFreshConnection();
    TestSilentClosedPooledConnectionReconnectsWhenCalled();
    TestReusedHeadTimeoutRetriesWithFreshConnection();
    TestReusedConnectionPostFailureDoesNotRetry();
    TestReusedConnectionPostRetrySignalDoesNotReplay();
    TestHttp11PipelineDefaultDisabled();
    TestHttp11PipelineGetOptIn();
    TestHttp11PipelinePostDefaultRejected();
    TestFreshRetrySignalRetriesSafeMethodsOnly();
    TestHttp2CleartextExplicitEntry();
    TestConnectionPoolHonorsMaxConnectionsPerHost();
    TestConnectionPoolSharesActiveHttp1PipelineLeases();
    TestConnectionPoolHttp1PipelineFailureClosesLeases();
    TestConnectionPoolSharesActiveHttp2StreamLeases();
    TestHttp2KeepAliveDefaultDisabled();
    TestHttp2KeepAliveSendsPingForIdleConnection();
    TestHttp2KeepAliveSkipsNotDueAndActiveConnections();
    TestHttp2KeepAliveAckTimeoutClosesIdleConnection();
    TestConnectionPoolHostQuotaSeparatesTlsReuseIdentity();
    TestConnectionPoolKeyIncludesTlsIdentity();
    TestSessionProxyConfigReachesTransport();
    TestSessionProxyRejectsInvalidConfig();
    TestPlainHttpProxyUsesAbsoluteForm();
    TestResolveAllCacheBoundaries();
    TestResolveAllAnyNoMatchQueriesExplicitFamilies();
    TestResolveAllSequentialConnectFallback();
    TestWskFakeProviderCancellationAndCleanup();
    TestWskSocketCanReconnectAfterClose();
    TestIdleTimeoutSkipsExpiredConnection();
    TestCloseDelimitedResponseDoesNotEnterPool();
    TestHttp10ConnectionReuseRules();
    TestSwitchingProtocolsDoesNotEnterHttpPool();
    TestFreshSafeConnectionTimeoutDoesNotRetry();
    TestFreshPostTimeoutDoesNotRetry();
    TestPostWithBody();
    TestChunkedRequestBody();
    TestChunkedRequestTrailers();
    TestStreamingRequestBodyContentLength();
    TestStreamingRequestBodyChunkedTrailers();
    TestTrailersRejectedWithoutChunked();
    TestSessionRequestBufferBytesLimitsRequestBody();
    TestRequestBuilder();
    TestDynamicRequestHeadersAndLongValues();
    TestRequestTransferEncodingRejected();
    TestRequestReservedHeadersRejected();
    TestExpectContinueSendsBodyAfter100();
    TestExpectContinueFinalResponseSkipsBody();
    TestExpectContinueTimeoutSendsBody();
    TestExpectContinueDisconnectReturnsError();
    TestExpectContinueWithoutBodyDoesNotInjectHeader();
    TestRequestMethodRejectsUnsupportedValues();
    TestAutoRedirectFollowsToFinalResponse();
    TestAutoRedirectCanBeDisabled();
    TestAutoRedirectHonorsCustomMaximum();
    TestPostRedirectRewritesToGet();
    TestAutoRedirectResolvesRelativeReferencesAndSanitizesCrossOriginHeaders();
    TestHttpsDowngradeRedirectIsRejected();
    TestRedirectMethodRewriteRules();
    TestAsyncGet();
    TestAsyncRequestIsCopied();
    TestAsyncCancelCompletionOnce();
    TestAsyncWorkerObservesCancelAfterRelease();
    TestNonPagedAllocatorBaseline();
    TestLookasideListBaseline();
    TestWknetHardLimitsAreStable();
    TestPagedPoolRejected();
    TestHttp2KeepAliveSessionConfigDefaultsAndValidation();
    TestHttp3SessionConfigDefaultsMappingAndValidation();
    TestHttp3RequiredConflictContract();
    TestHttp3PoolFailureInjection();
    TestConnectionPoolHttp3LeaseAndGoawayLifecycle();
    TestHttp3RouterRoutesConcurrentDispatches();
    TestIrqlCheck();
    TestWebSocketTransportModeDefaults();
    TestWebSocketRoundTrip();
    TestWebSocketPerMessageDeflateOptInPropagates();
    TestWebSocketHttp2OptInPropagates();
    TestWebSocketHttp2OptInRejectsCleartextWs();
    TestWebSocketControlFramesAndCloseEx();
    TestWebSocketFragmentedSendEnforcesTotalLimit();
    TestWebSocketReceiveCannotRaiseConnectionLimit();
    TestWebSocketPublicValidationMatchesRealPath();
    TestWebSocketTerminalTransportStatusDisconnectsHandle();
    TestHttpCacheFreshHit();
    TestHttpCacheStaleRevalidatesWith304();
    TestHttpCacheOnlyIfCachedMiss();
    TestHttpCacheVarySeparatesRequests();
    TestHttpCacheServesRangeFromFullResponse();
    TestHttpCacheCombinesPartialContent();
    TestHttpCacheUnsafeMethodInvalidates();
    TestHttpCacheAsyncHit();
    TestCertificateStoreStrictLoadSemantics();

    if (g_failed) {
        printf("wknet HTTP API tests FAILED\n");
        return 1;
    }
    printf("wknet HTTP API tests passed\n");
    return 0;
}
