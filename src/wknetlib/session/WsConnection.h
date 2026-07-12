#pragma once

#include "http1/HttpParser.h"
#include "http2/Http2Connection.h"
#include "net/WskClient.h"
#include "net/WskSocket.h"
#include "tls/CertificateStore.h"
#include "tls/TlsConnection.h"
#include "ws/WebSocketFrame.h"

namespace wknet
{
namespace transport
{
    struct Transport;
}

namespace session
{
    struct Workspace;
}

namespace crypto
{
    class CngProviderCache;
}

namespace session
{
    enum class WsConnectionTransportMode : ULONG
    {
        Auto = 0,
        Http11Only = 1,
        Http2Required = 2,
        LegacyBoolean = 3
    };

    struct WsHandshakeChallenge final
    {
        USHORT StatusCode = 0;
        const http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        bool Redirect = false;
        bool AuthenticationChallenge = false;
    };

    struct WsHandshakeRetryAction final
    {
        const char* RedirectPath = nullptr;
        SIZE_T RedirectPathLength = 0;
        const http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
    };

    typedef NTSTATUS (*WsHandshakeChallengeCallback)(
        _In_opt_ void* context,
        _In_ const WsHandshakeChallenge* challenge,
        _Out_ WsHandshakeRetryAction* action);

    struct WsConnectionOptions final
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
        const http1::HttpHeader* ExtraHeaders = nullptr;
        SIZE_T ExtraHeaderCount = 0;
        const tls::CertificateStore* CertificateStore = nullptr;
        session::Workspace* Workspace = nullptr;
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
        WsConnectionTransportMode TransportMode = WsConnectionTransportMode::Auto;
        ws::PerMessageDeflateOptions PerMessageDeflate = {};
        WsHandshakeChallengeCallback ChallengeCallback = nullptr;
        void* ChallengeContext = nullptr;
        ULONG MaxHandshakeRetries = 0;
        ULONGLONG TraceOperationId = 0;
        ULONGLONG TraceConnectionId = 0;
    };

    struct WsIoBuffers final
    {
        char* RequestBuffer = nullptr;
        SIZE_T RequestBufferLength = 0;
        char* ResponseBuffer = nullptr;
        SIZE_T ResponseBufferLength = 0;
        UCHAR* FrameBuffer = nullptr;
        SIZE_T FrameBufferLength = 0;
        UCHAR* PayloadBuffer = nullptr;
        SIZE_T PayloadBufferLength = 0;
        http1::HttpHeader* Headers = nullptr;
        SIZE_T HeaderCapacity = 0;
    };

    struct WsEchoResult final
    {
        USHORT HandshakeStatusCode = 0;
        ws::WebSocketOpcode Opcode = ws::WebSocketOpcode::Continuation;
        SIZE_T BytesReceived = 0;
    };

    class WsConnection final
    {
    public:
        WsConnection() noexcept = default;
        ~WsConnection() noexcept;

        WsConnection(const WsConnection&) = delete;
        WsConnection& operator=(const WsConnection&) = delete;

        _Must_inspect_result_
        NTSTATUS Connect(
            _Inout_ net::WskClient* wskClient,
            _In_ const WsConnectionOptions& options,
            _In_ const WsIoBuffers& buffers,
            _Out_opt_ USHORT* statusCode = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS SendText(
            _In_reads_bytes_(messageLength) const char* message,
            SIZE_T messageLength,
            _In_ const WsIoBuffers& buffers,
            bool finalFragment = true) noexcept;

        _Must_inspect_result_
        NTSTATUS SendBinary(
            _In_reads_bytes_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _In_ const WsIoBuffers& buffers,
            bool finalFragment = true) noexcept;

        _Must_inspect_result_
        NTSTATUS SendContinuation(
            _In_reads_bytes_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _In_ const WsIoBuffers& buffers,
            bool finalFragment = true) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPing(
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WsIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPong(
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WsIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS ReceiveMessage(
            _In_ const WsIoBuffers& buffers,
            _Out_ ws::WebSocketOpcode* opcode,
            _Out_writes_bytes_(outputCapacity) UCHAR* output,
            SIZE_T outputCapacity,
            _Out_ SIZE_T* bytesReceived,
            bool autoReplyPing = true,
            bool deliverFragments = false,
            _Out_opt_ bool* finalFragment = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Close(_In_ const WsIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS Close(
            USHORT statusCode,
            _In_reads_bytes_opt_(reasonLength) const UCHAR* reason,
            SIZE_T reasonLength,
            _In_ const WsIoBuffers& buffers) noexcept;

        _Ret_maybenull_
        const char* SelectedSubprotocol(_Out_opt_ SIZE_T* subprotocolLength = nullptr) const noexcept;

        _Must_inspect_result_
        NTSTATUS SendTextAndReceiveEcho(
            _In_reads_bytes_(messageLength) const char* message,
            SIZE_T messageLength,
            _In_ const WsIoBuffers& buffers,
            _Out_ WsEchoResult& result) noexcept;

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
        NTSTATUS WaitForPeerClose(_In_ const WsIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureBufferedFrameCapacity(SIZE_T capacity) noexcept;

        _Must_inspect_result_
        NTSTATUS CloseTransport() noexcept;

        _Must_inspect_result_
        NTSTATUS StoreSelectedSubprotocol(_In_ const http1::HttpText& subprotocol) noexcept;

        void ResetReceiveFragment() noexcept;
        void ResetSendFragment() noexcept;

        _Must_inspect_result_
        NTSTATUS SendCloseStatus(
            USHORT statusCode,
            _In_ const WsIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendCloseFrame(
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WsIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS SendControlFrame(
            ws::WebSocketOpcode opcode,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WsIoBuffers& buffers) noexcept;

        _Must_inspect_result_
        NTSTATUS EncodeAndSendFrame(
            ws::WebSocketOpcode opcode,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WsIoBuffers& buffers,
            bool finalFragment,
            bool rsv1 = false) noexcept;

        _Must_inspect_result_
        NTSTATUS EncodeAndSendMessageFrame(
            ws::WebSocketOpcode opcode,
            _In_reads_bytes_opt_(payloadLength) const UCHAR* payload,
            SIZE_T payloadLength,
            _In_ const WsIoBuffers& buffers,
            bool finalFragment) noexcept;

        NTSTATUS FailConnectionWithClose(
            USHORT statusCode,
            _In_ const WsIoBuffers& buffers,
            NTSTATUS returnStatus) noexcept;

        _Must_inspect_result_
        NTSTATUS SendFrame(
            ws::WebSocketOpcode opcode,
            _In_reads_bytes_(messageLength) const UCHAR* message,
            SIZE_T messageLength,
            _In_ const WsIoBuffers& buffers,
            bool finalFragment) noexcept;

        _Must_inspect_result_
        NTSTATUS ConnectAddress(
            _Inout_ net::WskClient* wskClient,
            _In_ const SOCKADDR* remoteAddress,
            _In_ const WsConnectionOptions& options,
            _In_ const WsIoBuffers& buffers,
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
            _In_ const ws::PerMessageDeflateOptions& perMessageDeflate,
            _In_ const WsIoBuffers& buffers,
            _Out_ http1::HttpResponse& response) noexcept;

        net::WskSocket* socket_ = nullptr;
        transport::Transport* rawTransport_ = nullptr;
        transport::Transport* h2Transport_ = nullptr;
        tls::TlsConnection* tls_ = nullptr;
        http2::Http2Connection* h2Connection_ = nullptr;
        ULONG h2StreamId_ = 0;
        HeapObject<ws::WebSocketFrameHeader> receiveFrameHeader_;
        UCHAR* bufferedFrame_ = nullptr;
        SIZE_T bufferedFrameCapacity_ = 0;
        SIZE_T bufferedFrameLength_ = 0;
        HeapArray<char> selectedSubprotocol_ = {};
        SIZE_T selectedSubprotocolLength_ = 0;
        bool useTls_ = false;
        bool connected_ = false;
        bool transportClosed_ = true;
        bool sendFragmentOpen_ = false;
        ws::WebSocketOpcode sendFragmentOpcode_ = ws::WebSocketOpcode::Continuation;
        ULONG sendTextUtf8CodePoint_ = 0;
        UCHAR sendTextUtf8Remaining_ = 0;
        UCHAR sendTextUtf8Expected_ = 0;
        bool closeSent_ = false;
        bool closeReceived_ = false;
        bool receiveFragmentOpen_ = false;
        bool receiveCompressedMessage_ = false;
        bool sendCompressedMessage_ = false;
        ws::PerMessageDeflateNegotiation perMessageDeflate_ = {};
        ws::WebSocketDeflateContext receiveDeflate_ = {};
        ws::WebSocketOpcode receiveFragmentOpcode_ = ws::WebSocketOpcode::Continuation;
        SIZE_T receiveFragmentLength_ = 0;
        ULONGLONG traceOperationId_ = 0;
        ULONGLONG traceConnectionId_ = 0;
        ULONG receiveTextUtf8CodePoint_ = 0;
        UCHAR receiveTextUtf8Remaining_ = 0;
        UCHAR receiveTextUtf8Expected_ = 0;
    };
}
}
