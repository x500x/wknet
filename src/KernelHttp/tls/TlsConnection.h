#pragma once

#include "net/WskSocket.h"
#include "tls/CertificateValidator.h"
#include "tls/TlsHandshake13.h"

namespace KernelHttp
{
namespace api
{
    struct KhWorkspace;
}

namespace crypto
{
    class CngProviderCache;
}

namespace tls
{
    constexpr SIZE_T TlsIoBufferLength = TlsRecordHeaderLength + TlsMaxPlaintextLength + 2048;
    constexpr SIZE_T TlsHandshakeBufferLength = 8192;
    constexpr SIZE_T TlsApplicationBufferLength = TlsMaxPlaintextLength;

    struct TlsClientConnectionOptions final
    {
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const CertificateStore* CertificateStore = nullptr;
        bool VerifyCertificate = true;
        const TlsAlpnProtocol* AlpnProtocols = nullptr;
        SIZE_T AlpnProtocolCount = 0;
        const UCHAR* EarlyData = nullptr;
        SIZE_T EarlyDataLength = 0;
        SIZE_T* EarlyDataBytesSent = nullptr;
        bool* EarlyDataAccepted = nullptr;
        TlsProtocol MinimumProtocol = TlsProtocol::Tls12;
        TlsProtocol MaximumProtocol = TlsProtocol::Tls13;
        Tls13SessionCache* SessionCache = nullptr;
        api::KhWorkspace* Workspace = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        bool EnableSessionResumption = true;
        bool EnableEarlyData = false;
    };

    class TlsConnection final
    {
    public:
        TlsConnection() noexcept = default;
        ~TlsConnection() noexcept;

        TlsConnection(const TlsConnection&) = delete;
        TlsConnection& operator=(const TlsConnection&) = delete;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Connect(
            _Inout_ net::WskSocket& socket,
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS Send(
            _Inout_ net::WskSocket& socket,
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Receive(
            _Inout_ net::WskSocket& socket,
            _Out_writes_bytes_(length) void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived = nullptr) noexcept;

        _Must_inspect_result_
        bool IsEstablished() const noexcept;

        const TlsContext& Context() const noexcept;

        // ALPN negotiation result (valid after Connect succeeds)
        const char* NegotiatedAlpn() const noexcept;
        SIZE_T NegotiatedAlpnLength() const noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS PrepareScratch(
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS EnsureBuffers() noexcept;

        _Must_inspect_result_
        NTSTATUS GetHandshakeScratch(
            SIZE_T offset,
            SIZE_T length,
            _Outptr_result_bytebuffer_(length) UCHAR** buffer) noexcept;

        _Must_inspect_result_
        NTSTATUS ConnectTls12(
            _Inout_ net::WskSocket& socket,
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS ConnectTls13(
            _Inout_ net::WskSocket& socket,
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPlainRecordWithVersion(
            _Inout_ net::WskSocket& socket,
            TlsProtocolVersion version,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPlainRecord(
            _Inout_ net::WskSocket& socket,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendProtectedRecord(
            _Inout_ net::WskSocket& socket,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendProtectedRecord13(
            _Inout_ net::WskSocket& socket,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadRecord(
            _Inout_ net::WskSocket& socket,
            _Out_ TlsMutablePlaintextRecord& record) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHandshakeMessage13(
            _Inout_ net::WskSocket& socket,
            _Out_ TlsHandshakeMessageView& message,
            bool updateTranscript) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadOptionalCompatibilityChangeCipherSpec(
            _Inout_ net::WskSocket& socket) noexcept;

        _Must_inspect_result_
        NTSTATUS ValidateTls13Certificate(
            _In_ const Tls13CertificateView& certificate,
            _In_ const TlsClientConnectionOptions& options,
            _Out_ crypto::CngKey& serverPublicKey) noexcept;

        _Must_inspect_result_
        NTSTATUS VerifyTls13CertificateVerify(
            _In_ const Tls13CertificateVerifyView& certificateVerify,
            _In_ const crypto::CngKey& serverPublicKey,
            _In_reads_bytes_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength) noexcept;

        _Must_inspect_result_
        NTSTATUS StoreTls13Ticket(
            _In_ const Tls13NewSessionTicketView& ticket,
            _Inout_opt_ Tls13SessionCache* externalCache) noexcept;

        _Must_inspect_result_
        NTSTATUS SelectTls13Ticket(
            _In_ const TlsClientConnectionOptions& options,
            _Out_ Tls13PskIdentity& identity,
            _Outptr_result_bytebuffer_(*resumptionSecretLength) const UCHAR** resumptionSecret,
            _Out_ SIZE_T* resumptionSecretLength,
            _Out_ bool* earlyDataAllowed) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadServerChangeCipherSpec(
            _Inout_ net::WskSocket& socket,
            bool allowNewSessionTicket) noexcept;

        _Must_inspect_result_
        NTSTATUS ConsumeOptionalPlainHandshakeRecord(
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ConsumeTls13PostHandshakeRecord(
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHandshakeMessage(
            _Inout_ net::WskSocket& socket,
            _Out_ TlsHandshakeMessageView& message,
            bool updateTranscript) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendTranscript(
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept;

        _Must_inspect_result_
        NTSTATUS FinishTranscript(
            _Out_writes_bytes_(capacity) UCHAR* digest,
            SIZE_T capacity,
            _Out_ SIZE_T* digestLength) const noexcept;

        _Must_inspect_result_
        NTSTATUS VerifyServerKeyExchange(
            _In_ const TlsServerKeyExchangeView& keyExchange,
            _In_ const crypto::CngKey& serverPublicKey) noexcept;

        _Must_inspect_result_
        NTSTATUS GenerateClientKeyExchange(
            TlsNamedGroup namedGroup,
            _In_ const crypto::CngKey& peerKey,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        TlsContext context_ = {};
        TlsAeadCipherState clientWriteState_ = {};
        TlsAeadCipherState serverWriteState_ = {};
        TlsTranscriptHash transcript_ = {};
        api::KhWorkspace* workspace_ = nullptr;
        const crypto::CngProviderCache* providerCache_ = nullptr;
        UCHAR* ownedTlsScratch_ = nullptr;
        SIZE_T ownedTlsScratchLength_ = 0;
        UCHAR* inputBuffer_ = nullptr;
        UCHAR* outputBuffer_ = nullptr;
        UCHAR* tls13InnerPlaintextBuffer_ = nullptr;
        SIZE_T inputLength_ = 0;
        UCHAR* plaintextBuffer_ = nullptr;
        SIZE_T plaintextLength_ = 0;
        UCHAR* handshakeBuffer_ = nullptr;
        SIZE_T handshakeLength_ = 0;
        SIZE_T handshakeConsumed_ = 0;
        SIZE_T lastHandshakeOffset_ = 0;
        SIZE_T lastHandshakeLength_ = 0;
        bool encrypted_ = false;
        bool tls13RecordProtection_ = false;
        char* negotiatedAlpn_ = nullptr;
        SIZE_T negotiatedAlpnLength_ = 0;
    };
}
}
