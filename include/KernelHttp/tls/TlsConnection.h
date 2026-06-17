#pragma once

#include <KernelHttp/core/IScratchAllocator.h>
#include <KernelHttp/core/ITransport.h>
#include <KernelHttp/tls/CertificateValidator.h>
#include <KernelHttp/tls/TlsHandshake13.h>
#include <KernelHttp/tls/TlsPolicy.h>
#include <KernelHttp/tls/TlsRecord.h>

namespace KernelHttp
{
namespace crypto
{
    class CngProviderCache;
}

namespace tls
{
    constexpr SIZE_T TlsIoBufferLength = TlsRecordHeaderLength + TlsMaxPlaintextLength + 2048;
    constexpr SIZE_T TlsHandshakeBufferLength = 8192;
    constexpr SIZE_T TlsApplicationBufferLength = TlsMaxPlaintextLength + 1;
    constexpr ULONG TlsApplicationMaxEmptyRecords = 16;
    constexpr ULONG TlsApplicationMaxPostHandshakeRecords = 16;
    constexpr ULONG TlsHandshakeMaxRecords = 64;

    struct TlsReceiveDeadline final
    {
        bool Enabled = false;
        ULONGLONG DeadlineMilliseconds = 0;
    };

    enum class TlsHandshakeFailureCategory : ULONG
    {
        None = 0,
        VersionNegotiation = 1,
        CertificateValidation = 2,
        AlpnMismatch = 3,
        NetworkIo = 4,
        DecodeError = 5,
        CryptoError = 6,
        PeerAlert = 7,
        LocalPolicy = 8
    };

    struct TlsHandshakeFailure final
    {
        TlsHandshakeFailureCategory Category = TlsHandshakeFailureCategory::None;
        NTSTATUS Status = STATUS_SUCCESS;
        TlsAlert PeerAlert = {};
        bool HasPeerAlert = false;
        bool BeforeTls13FirstServerHello = false;
    };

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
        TlsPolicy Policy = {};
        ULONG HandshakeReceiveTimeoutMilliseconds = TlsHandshakeReceiveTimeoutMilliseconds;
        Tls13SessionCache* SessionCache = nullptr;
        Tls12SessionCache* Tls12SessionCache = nullptr;
        const TlsClientCredential* ClientCredential = nullptr;
        core::IScratchAllocator* HandshakeScratchAllocator = nullptr;
        core::IScratchAllocator* CertificateScratchAllocator = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        bool EnableSessionResumption = true;
        bool EnableEarlyData = false;
        bool EarlyDataReplaySafe = false;
        SIZE_T Tls13RecordPaddingLength = 0;
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
            _Inout_ core::ITransport& transport,
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS Send(
            _Inout_ core::ITransport& transport,
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Receive(
            _Inout_ core::ITransport& transport,
            _Out_writes_bytes_(length) void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived = nullptr,
            ULONG receiveTimeoutMilliseconds = WskOperationTimeoutMilliseconds) noexcept;

        _Must_inspect_result_
        bool IsEstablished() const noexcept;

        const TlsContext& Context() const noexcept;

        // ALPN negotiation result (valid after Connect succeeds)
        const char* NegotiatedAlpn() const noexcept;
        SIZE_T NegotiatedAlpnLength() const noexcept;
        const TlsHandshakeFailure& LastHandshakeFailure() const noexcept;

    private:
        void RecordTls13FirstServerHelloFailure(
            _In_ const TlsClientConnectionOptions& options,
            NTSTATUS status) noexcept;

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

        void ReleaseHandshakeScratch() noexcept;

        _Must_inspect_result_
        NTSTATUS ConnectTls12(
            _Inout_ core::ITransport& transport,
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS ConnectTls13(
            _Inout_ core::ITransport& transport,
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPlainRecordWithVersion(
            _Inout_ core::ITransport& transport,
            TlsProtocolVersion version,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPlainRecord(
            _Inout_ core::ITransport& transport,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendProtectedRecord(
            _Inout_ core::ITransport& transport,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendProtectedRecord13(
            _Inout_ core::ITransport& transport,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendPendingTls13KeyUpdate(
            _Inout_ core::ITransport& transport) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadRecord(
            _Inout_ core::ITransport& transport,
            _Out_ TlsMutablePlaintextRecord& record,
            ULONG receiveTimeoutMilliseconds = WskOperationTimeoutMilliseconds,
            _In_opt_ const TlsReceiveDeadline* receiveDeadline = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHandshakeMessage13(
            _Inout_ core::ITransport& transport,
            _Out_ TlsHandshakeMessageView& message,
            bool updateTranscript) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadOptionalCompatibilityChangeCipherSpec(
            _Inout_ core::ITransport& transport) noexcept;

        _Must_inspect_result_
        NTSTATUS ValidateTls13Certificate(
            _In_ const Tls13CertificateView& certificate,
            _In_ const TlsClientConnectionOptions& options,
            _Out_ crypto::CngKey& serverPublicKey) noexcept;

        _Must_inspect_result_
        NTSTATUS VerifyTls13CertificateVerify(
            _In_ const Tls13CertificateVerifyView& certificateVerify,
            _In_ const crypto::CngKey& serverPublicKey,
            CertificatePublicKeyAlgorithm publicKeyAlgorithm,
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
            _Out_ bool* earlyDataAllowed,
            _Outptr_result_maybenull_ const Tls13SessionTicket** selectedTicket) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadServerChangeCipherSpec(
            _Inout_ core::ITransport& transport,
            bool allowNewSessionTicket) noexcept;

        _Must_inspect_result_
        NTSTATUS ConsumeOptionalPlainHandshakeRecord(
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ConsumeTls13PostHandshakeRecord(
            _Inout_ core::ITransport& transport,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHandshakeMessage(
            _Inout_ core::ITransport& transport,
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
            _In_ const TlsServerKeyExchangeView& keyExchange,
            _In_opt_ const crypto::CngKey* peerKey,
            _In_opt_ const crypto::CngKey* rsaPublicKey,
            SIZE_T rsaCiphertextLength,
            _Out_writes_bytes_(premasterSecretCapacity) UCHAR* premasterSecret,
            SIZE_T premasterSecretCapacity,
            _Out_ SIZE_T* premasterSecretLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        void ClearHandshakeFailure() noexcept;
        void RecordHandshakeFailure(TlsHandshakeFailureCategory category, NTSTATUS status) noexcept;
        void RecordPeerAlertFailure(_In_ const TlsMutablePlaintextRecord& record) noexcept;

        TlsContext context_ = {};
        TlsAeadCipherState clientWriteState_ = {};
        TlsAeadCipherState serverWriteState_ = {};
        TlsTranscriptHash transcript_ = {};
        core::IScratchAllocator* handshakeScratchAllocator_ = nullptr;
        core::IScratchAllocator* certificateScratchAllocator_ = nullptr;
        UCHAR* handshakeScratch_ = nullptr;
        SIZE_T handshakeScratchLength_ = 0;
        const crypto::CngProviderCache* providerCache_ = nullptr;
        UCHAR* ownedTlsScratch_ = nullptr;
        SIZE_T ownedTlsScratchLength_ = 0;
        UCHAR* inputBuffer_ = nullptr;
        UCHAR* outputBuffer_ = nullptr;
        UCHAR* tls13InnerPlaintextBuffer_ = nullptr;
        UCHAR tls13KeyUpdateMessage_[TlsHandshakeHeaderLength + 1] = {};
        SIZE_T inputLength_ = 0;
        UCHAR* plaintextBuffer_ = nullptr;
        SIZE_T plaintextLength_ = 0;
        UCHAR* handshakeBuffer_ = nullptr;
        SIZE_T handshakeLength_ = 0;
        SIZE_T handshakeConsumed_ = 0;
        SIZE_T lastHandshakeOffset_ = 0;
        SIZE_T lastHandshakeLength_ = 0;
        ULONG handshakeReceiveTimeoutMilliseconds_ = TlsHandshakeReceiveTimeoutMilliseconds;
        TlsReceiveDeadline handshakeReceiveDeadline_ = {};
        bool encrypted_ = false;
        bool tls13RecordProtection_ = false;
        SIZE_T tls13RecordPaddingLength_ = 0;
        bool tls13PostHandshakeClientAuthAllowed_ = false;
        volatile LONG tls13PeerRequestedKeyUpdate_ = 0;
        const TlsClientCredential* clientCredential_ = nullptr;
        Tls12SessionCache* tls12SessionCache_ = nullptr;
        Tls13SessionCache* tls13ExternalSessionCache_ = nullptr;
        TlsPolicy tlsPolicy_ = {};
        ULONG tlsPolicyIdentity_ = 0;
        CertificatePublicKeyAlgorithm serverCertificatePublicKeyAlgorithm_ = CertificatePublicKeyAlgorithm::Unknown;
        HeapObject<TlsKeyBlock> tlsKeyBlockScratch_;
        HeapObject<Tls12Session> tls12SessionScratch_;
        HeapObject<Tls13SessionTicket> tls13SessionTicketScratch_;
        UCHAR tls12PendingTicket_[Tls12MaxTicketLength] = {};
        SIZE_T tls12PendingTicketLength_ = 0;
        ULONG tls12PendingTicketLifetimeHintSeconds_ = 0;
        char tls13TicketServerName_[Tls13MaxTicketServerNameLength + 1] = {};
        SIZE_T tls13TicketServerNameLength_ = 0;
        bool tls13TicketServerNameCacheable_ = false;
        char* negotiatedAlpn_ = nullptr;
        SIZE_T negotiatedAlpnLength_ = 0;
        TlsHandshakeFailure lastHandshakeFailure_ = {};
    };
}
}
