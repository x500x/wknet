#pragma once

#include <KernelHttp/http/HttpParser.h>
#include <KernelHttp/http2/Http2Connection.h>
#include <KernelHttp/net/WskClient.h>
#include <KernelHttp/net/WskSocket.h>
#include <KernelHttp/tls/CertificateStore.h>
#include <KernelHttp/tls/TlsConnection.h>
#include <KernelHttp/websocket/WebSocketFrame.h>

namespace KernelHttp
{
namespace core
{
    class ITransport;
    class TlsTransport;
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
    enum class WebSocketTransportMode : ULONG
    {
        LegacyBoolean = 0,
        Http11Only = 1,
        Auto = 2,
        Http2Required = 3
    };

    struct WebSocketHandshakeChallenge final
    {
        USHORT StatusCode = 0;
        const http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        bool Redirect = false;
        bool AuthenticationChallenge = false;
    };

    struct WebSocketHandshakeRetryAction final
    {
        const char* RedirectPath = nullptr;
        SIZE_T RedirectPathLength = 0;
        const http::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
    };

    typedef NTSTATUS (*WebSocketHandshakeChallengeCallback)(
        _In_opt_ void* context,
        _In_ const WebSocketHandshakeChallenge* challenge,
        _Out_ WebSocketHandshakeRetryAction* action);

    struct WebSocketConnectOptions final
    {
        const wchar_t* ServerName = nullptr;
        const wchar_t* ServiceName = L"80";
        const char* TlsServerName = nullptr;
        SIZE_T TlsServerNameLength = 0;
        const char* Host = nullptr;
        SIZE_T HostLength = 0;
        USHORT Port = 0;
        const char* Path = "/";
        SIZE_T PathLength = 1;
        const char* Subprotocol = nullptr;
        SIZE_T SubprotocolLength = 0;
        const http::HttpHeader* ExtraHeaders = nullptr;
        SIZE_T ExtraHeaderCount = 0;
        const tls::CertificateStore* CertificateStore = nullptr;
        engine::KhWorkspace* Workspace = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        net::WskAddressFamily AddressFamily = net::WskAddressFamily::Any;
        tls::TlsProtocol MinimumTlsProtocol = tls::TlsProtocol::Tls12;
        tls::TlsProtocol MaximumTlsProtocol = tls::TlsProtocol::Tls13;
        tls::TlsPolicy Policy = {};
        const tls::TlsClientCredential* ClientCredential = nullptr;
        ULONG HandshakeReceiveTimeoutMilliseconds = TlsHandshakeReceiveTimeoutMilliseconds;
        ULONG MaxTls12Renegotiations = tls::Tls12DefaultMaxRenegotiations;
        const net::WskCancellationToken* Cancellation = nullptr;
        bool UseTls = false;
        bool VerifyCertificate = true;
        bool AllowWebSocketOverHttp2 = false;
        WebSocketTransportMode TransportMode = WebSocketTransportMode::LegacyBoolean;
        websocket::PerMessageDeflateOptions PerMessageDeflate = {};
        WebSocketHandshakeChallengeCallback ChallengeCallback = nullptr;
        void* ChallengeContext = nullptr;
        ULONG MaxHandshakeRetries = 0;
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
            _In_ const WebSocketIoBuffers& buffers,
            bool finalFragment = true) noexcept;

        _Must_inspect_result_
        NTSTATUS SendBinary(
            _In_reads_bytes_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _In_ const WebSocketIoBuffers& buffers,
            bool finalFragment = true) noexcept;

        _Must_inspect_result_
        NTSTATUS SendContinuation(
            _In_reads_bytes_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _In_ const WebSocketIoBuffers& buffers,
            bool finalFragment = true) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPing(
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPong(
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS ReceiveMessage(
            _In_ const WebSocketIoBuffers& buffers,
            _Out_ websocket::WebSocketOpcode* opcode,
            _Out_writes_bytes_(outputCapacity) UCHAR* output,
            SIZE_T outputCapacity,
            _Out_ SIZE_T* bytesReceived,
            bool autoReplyPing = true,
            bool deliverFragments = false,
            _Out_opt_ bool* finalFragment = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Close(_In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS Close(
            USHORT statusCode,
            _In_reads_bytes_opt_(reasonLength) const UCHAR* reason,
            SIZE_T reasonLength,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Ret_maybenull_
        const char* SelectedSubprotocol(_Out_opt_ SIZE_T* subprotocolLength = nullptr) const noexcept;

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
            _Out_opt_ SIZE_T* bytesReceived = nullptr,
            ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds) noexcept;

        _Must_inspect_result_
        NTSTATUS WaitForPeerClose(_In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureBufferedFrameCapacity(SIZE_T capacity) noexcept;

        _Must_inspect_result_
        NTSTATUS CloseTransport() noexcept;

        _Must_inspect_result_
        NTSTATUS StoreSelectedSubprotocol(_In_ const http::HttpText& subprotocol) noexcept;

        void ResetReceiveFragment() noexcept;
        void ResetSendFragment() noexcept;

        _Must_inspect_result_
        NTSTATUS SendCloseStatus(
            USHORT statusCode,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendCloseFrame(
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendControlFrame(
            websocket::WebSocketOpcode opcode,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WebSocketIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS EncodeAndSendFrame(
            websocket::WebSocketOpcode opcode,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WebSocketIoBuffers& buffers,
            bool finalFragment,
            bool rsv1 = false) noexcept;

        _Must_inspect_result_
        NTSTATUS EncodeAndSendMessageFrame(
            websocket::WebSocketOpcode opcode,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WebSocketIoBuffers& buffers,
            bool finalFragment) noexcept;

        NTSTATUS FailConnectionWithClose(
            USHORT statusCode,
            _In_ const WebSocketIoBuffers& buffers,
            NTSTATUS returnStatus) noexcept;

        _Must_inspect_result_
        NTSTATUS SendFrame(
            websocket::WebSocketOpcode opcode,
            _In_reads_bytes_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _In_ const WebSocketIoBuffers& buffers,
            bool finalFragment) noexcept;

        _Must_inspect_result_
        NTSTATUS ConnectAddress(
            _Inout_ net::WskClient& wskClient,
            _In_ const SOCKADDR* remoteAddress,
            _In_ const WebSocketConnectOptions& options,
            _In_ const WebSocketIoBuffers& buffers,
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            SIZE_T requestLength,
            _Out_opt_ USHORT* statusCode,
            _Out_opt_ bool* tls12ConfirmationCandidate) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHandshakeResponse(
            _In_reads_bytes_(clientKeyLength) const char* clientKey,
            SIZE_T clientKeyLength,
            _In_reads_bytes_opt_(requestedSubprotocolLength) const char* requestedSubprotocol,
            SIZE_T requestedSubprotocolLength,
            _In_ const websocket::PerMessageDeflateOptions& perMessageDeflate,
            _In_ const WebSocketIoBuffers& buffers,
            _Out_ http::HttpResponse& response) noexcept;

        net::WskSocket socket_ = {};
        core::WskTransport* rawTransport_ = nullptr;
        core::TlsTransport* h2Transport_ = nullptr;
        tls::TlsConnection* tls_ = nullptr;
        http2::Http2Connection* h2Connection_ = nullptr;
        ULONG h2StreamId_ = 0;
        HeapObject<websocket::WebSocketFrameHeader> receiveFrameHeader_;
        UCHAR* bufferedFrame_ = nullptr;
        SIZE_T bufferedFrameCapacity_ = 0;
        SIZE_T bufferedFrameLength_ = 0;
        HeapArray<char> selectedSubprotocol_ = {};
        SIZE_T selectedSubprotocolLength_ = 0;
        bool useTls_ = false;
        bool connected_ = false;
        bool transportClosed_ = true;
        bool sendFragmentOpen_ = false;
        websocket::WebSocketOpcode sendFragmentOpcode_ = websocket::WebSocketOpcode::Continuation;
        ULONG sendTextUtf8CodePoint_ = 0;
        UCHAR sendTextUtf8Remaining_ = 0;
        UCHAR sendTextUtf8Expected_ = 0;
        bool closeSent_ = false;
        bool closeReceived_ = false;
        bool receiveFragmentOpen_ = false;
        bool receiveCompressedMessage_ = false;
        bool sendCompressedMessage_ = false;
        websocket::PerMessageDeflateNegotiation perMessageDeflate_ = {};
        websocket::WebSocketDeflateContext receiveDeflate_ = {};
        websocket::WebSocketOpcode receiveFragmentOpcode_ = websocket::WebSocketOpcode::Continuation;
        SIZE_T receiveFragmentLength_ = 0;
        ULONG receiveTextUtf8CodePoint_ = 0;
        UCHAR receiveTextUtf8Remaining_ = 0;
        UCHAR receiveTextUtf8Expected_ = 0;
    };
}
}
