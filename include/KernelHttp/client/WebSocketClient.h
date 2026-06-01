#pragma once

#include <KernelHttp/http/HttpParser.h>
#include <KernelHttp/net/WskClient.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/CertificateStore.h>
#include <KernelHttp/tls/TlsConnection.h>
#include <KernelHttp/websocket/WebSocketFrame.h>

namespace KernelHttp
{
namespace core
{
    class WskTransport;
}

namespace engine
{
    struct KhWorkspace;
}

namespace crypto
{
    class CngProviderCache;
}

namespace client
{
    struct WebSocketConnectOptions final
    {
        const wchar_t* ServerName = nullptr;
        const wchar_t* ServiceName = L"80";
        const char* TlsServerName = nullptr;
        SIZE_T TlsServerNameLength = 0;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        const char* Path = "/";
        SIZE_T PathLength = 1;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        const tls::CertificateStore* CertificateStore = nullptr;
        engine::KhWorkspace* Workspace = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        net::WskAddressFamily AddressFamily = net::WskAddressFamily::Any;
        tls::TlsProtocol MinimumTlsProtocol = tls::TlsProtocol::Tls12;
        tls::TlsProtocol MaximumTlsProtocol = tls::TlsProtocol::Tls13;
        ULONG HandshakeReceiveTimeoutMilliseconds = TlsHandshakeReceiveTimeoutMilliseconds;
        bool UseTls = false;
        bool VerifyCertificate = true;
    };

    struct WebSocketIoBuffers final
    {
        char* RequestBuffer = nullptr;
        SIZE_T RequestBufferLength = 0;
        char* ResponseBuffer = nullptr;
        SIZE_T ResponseBufferLength = 0;
        UCHAR* FrameBuffer = nullptr;
        SIZE_T FrameBufferLength = 0;
        UCHAR* PayloadBuffer = nullptr;
        SIZE_T PayloadBufferLength = 0;
        http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCapacity = 0;
    };

    struct WebSocketEchoResult final
    {
        USHORT HandshakeStatusCode = 0;
        websocket::WebSocketOpcode Opcode = websocket::WebSocketOpcode::Continuation;
        SIZE_T BytesReceived = 0;
    };

    class WebSocketClient final
    {
    public:
        WebSocketClient() noexcept = default;
        ~WebSocketClient() noexcept;

        WebSocketClient(const WebSocketClient&) = delete;
        WebSocketClient& operator=(const WebSocketClient&) = delete;

        _Must_inspect_result_
        NTSTATUS Connect(
            _Inout_ net::WskClient& wskClient,
            _In_ const WebSocketConnectOptions& options,
            _In_ const WebSocketIoBuffers& buffers,
            _Out_opt_ USHORT* statusCode = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS SendText(
            _In_reads_bytes_(messageLength) const char* message,
            SIZE_T messageLength,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendBinary(
            _In_reads_bytes_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS ReceiveMessage(
            _In_ const WebSocketIoBuffers& buffers,
            _Out_ websocket::WebSocketOpcode* opcode,
            _Out_writes_bytes_(outputCapacity) UCHAR* output,
            SIZE_T outputCapacity,
            _Out_ SIZE_T* bytesReceived) noexcept;

        _Must_inspect_result_
        NTSTATUS Close(_In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendTextAndReceiveEcho(
            _In_reads_bytes_(messageLength) const char* message,
            SIZE_T messageLength,
            _In_ const WebSocketIoBuffers& buffers,
            _Out_ WebSocketEchoResult& result) noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS SendRaw(
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS ReceiveRaw(
            _Out_writes_bytes_(length) void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureMaskingKeyScratch() noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureBufferedFrameCapacity(SIZE_T capacity) noexcept;

        _Must_inspect_result_
        NTSTATUS ConnectAddress(
            _Inout_ net::WskClient& wskClient,
            _In_ const SOCKADDR* remoteAddress,
            _In_ const WebSocketConnectOptions& options,
            _In_ const WebSocketIoBuffers& buffers,
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            SIZE_T requestLength,
            _Out_opt_ USHORT* statusCode) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHandshakeResponse(
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            _In_ const WebSocketIoBuffers& buffers,
            _Out_ http::HttpResponse& response) noexcept;

        net::WskSocket socket_ = {};
        core::WskTransport* rawTransport_ = nullptr;
        tls::TlsConnection* tls_ = nullptr;
        UCHAR* maskingKey_ = nullptr;
        UCHAR* bufferedFrame_ = nullptr;
        SIZE_T bufferedFrameCapacity_ = 0;
        SIZE_T bufferedFrameLength_ = 0;
        bool useTls_ = false;
        bool connected_ = false;
    };
}
}
