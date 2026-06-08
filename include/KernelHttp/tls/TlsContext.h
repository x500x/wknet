#pragma once

#include <KernelHttp/tls/TlsRecord.h>

namespace KernelHttp
{
namespace tls
{
    constexpr SIZE_T TlsRandomLength = 32;
    constexpr SIZE_T TlsMasterSecretLength = 48;
    constexpr SIZE_T TlsVerifyDataLength = 12;
    constexpr SIZE_T TlsMaxKeyBlockLength = 160;
    constexpr SIZE_T Tls13MaxSecretLength = 48;
    constexpr SIZE_T Tls13MaxHashLength = 48;
    constexpr SIZE_T Tls13MaxTicketIdentityLength = 256;
    constexpr SIZE_T Tls13MaxTicketNonceLength = 32;
    constexpr SIZE_T Tls13MaxTicketServerNameLength = 255;
    constexpr SIZE_T Tls13MaxTicketAlpnLength = 15;
    constexpr SIZE_T Tls13MaxTicketCount = 4;
    constexpr ULONG Tls13MaxTicketLifetimeSeconds = 604800;

    enum class TlsProtocol : UCHAR
    {
        Tls12,
        Tls13
    };

    enum class TlsCipherSuite : USHORT
    {
        TlsAes128GcmSha256 = 0x1301,
        TlsAes256GcmSha384 = 0x1302,
        TlsEcdheRsaWithAes128GcmSha256 = 0xC02F,
        TlsEcdheEcdsaWithAes128GcmSha256 = 0xC02B,
        TlsEcdheRsaWithAes256GcmSha384 = 0xC030,
        TlsEcdheEcdsaWithAes256GcmSha384 = 0xC02C
    };

    enum class TlsHandshakeState : UCHAR
    {
        Idle,
        ClientHelloSent,
        ServerHelloReceived,
        ServerCertificateReceived,
        ServerKeyExchangeReceived,
        CertificateRequestReceived,
        ServerHelloDoneReceived,
        ClientFinishedSent,
        Established,
        Failed
    };

    enum class TlsEarlyDataState : UCHAR
    {
        Disabled,
        Offered,
        Accepted,
        Rejected
    };

    struct TlsSessionSecrets final
    {
        UCHAR ClientRandom[TlsRandomLength] = {};
        UCHAR ServerRandom[TlsRandomLength] = {};
        UCHAR MasterSecret[TlsMasterSecretLength] = {};
        SIZE_T MasterSecretLength = 0;
        TlsCipherSuite CipherSuite = TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256;
    };

    struct TlsKeyBlock final
    {
        UCHAR Data[TlsMaxKeyBlockLength] = {};
        SIZE_T Length = 0;
    };

    struct Tls13TrafficSecrets final
    {
        UCHAR EarlySecret[Tls13MaxSecretLength] = {};
        UCHAR HandshakeSecret[Tls13MaxSecretLength] = {};
        UCHAR MasterSecret[Tls13MaxSecretLength] = {};
        UCHAR ClientEarlyTrafficSecret[Tls13MaxSecretLength] = {};
        UCHAR ClientHandshakeTrafficSecret[Tls13MaxSecretLength] = {};
        UCHAR ServerHandshakeTrafficSecret[Tls13MaxSecretLength] = {};
        UCHAR ClientApplicationTrafficSecret[Tls13MaxSecretLength] = {};
        UCHAR ServerApplicationTrafficSecret[Tls13MaxSecretLength] = {};
        UCHAR ExporterMasterSecret[Tls13MaxSecretLength] = {};
        UCHAR ResumptionMasterSecret[Tls13MaxSecretLength] = {};
        SIZE_T SecretLength = 0;
    };

    struct Tls13SessionTicket final
    {
        UCHAR Identity[Tls13MaxTicketIdentityLength] = {};
        SIZE_T IdentityLength = 0;
        UCHAR Nonce[Tls13MaxTicketNonceLength] = {};
        SIZE_T NonceLength = 0;
        ULONG LifetimeSeconds = 0;
        ULONG AgeAdd = 0;
        ULONG MaxEarlyDataSize = 0;
        ULONGLONG IssueTimeMilliseconds = 0;
        TlsProtocolVersion Version = { 3, 4 };
        char ServerName[Tls13MaxTicketServerNameLength + 1] = {};
        SIZE_T ServerNameLength = 0;
        char Alpn[Tls13MaxTicketAlpnLength + 1] = {};
        SIZE_T AlpnLength = 0;
        TlsCipherSuite CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;
        UCHAR ResumptionSecret[Tls13MaxSecretLength] = {};
        SIZE_T ResumptionSecretLength = 0;
    };

    struct Tls13SessionCache final
    {
        Tls13SessionTicket Tickets[Tls13MaxTicketCount] = {};
        SIZE_T TicketCount = 0;
    };

    class TlsContext final
    {
    public:
        TlsContext() noexcept;
        ~TlsContext() noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS InitializeClient(_In_ TlsProtocolVersion version) noexcept;

        _Must_inspect_result_
        NTSTATUS InitializeClient13() noexcept;

        _Must_inspect_result_
        NTSTATUS SetCipherSuite(TlsCipherSuite cipherSuite) noexcept;

        _Must_inspect_result_
        NTSTATUS SetServerRandom(
            _In_reads_bytes_(TlsRandomLength) const UCHAR* random) noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveMasterSecret(
            _In_reads_bytes_(premasterSecretLength) const UCHAR* premasterSecret,
            SIZE_T premasterSecretLength) noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveKeyBlock(
            _Out_ TlsKeyBlock& keyBlock,
            SIZE_T requiredLength) const noexcept;

        _Must_inspect_result_
        NTSTATUS ConfigureAesGcmStates(
            _In_ const TlsKeyBlock& keyBlock,
            _Out_ TlsAeadCipherState& clientWriteState,
            _Out_ TlsAeadCipherState& serverWriteState) const noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveTls13EarlySecret(
            _In_reads_bytes_opt_(pskLength) const UCHAR* psk,
            SIZE_T pskLength) noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveTls13HandshakeSecrets(
            _In_reads_bytes_(sharedSecretLength) const UCHAR* sharedSecret,
            SIZE_T sharedSecretLength,
            _In_reads_bytes_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength) noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveTls13ClientEarlyTrafficSecret(
            _In_reads_bytes_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength) noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveTls13ApplicationSecrets(
            _In_reads_bytes_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ConfigureTls13HandshakeAesGcmStates(
            _Out_ TlsAeadCipherState& clientWriteState,
            _Out_ TlsAeadCipherState& serverWriteState) const noexcept;

        _Must_inspect_result_
        NTSTATUS ConfigureTls13EarlyAesGcmState(
            _Out_ TlsAeadCipherState& clientWriteState) const noexcept;

        _Must_inspect_result_
        NTSTATUS ConfigureTls13ApplicationAesGcmStates(
            _Out_ TlsAeadCipherState& clientWriteState,
            _Out_ TlsAeadCipherState& serverWriteState) const noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveTls13FinishedKey(
            bool clientFinished,
            _Out_writes_bytes_(keyCapacity) UCHAR* key,
            SIZE_T keyCapacity,
            _Out_ SIZE_T* keyLength) const noexcept;

        _Must_inspect_result_
        NTSTATUS DeriveTls13ResumptionSecret(
            _In_reads_bytes_(ticketNonceLength) const UCHAR* ticketNonce,
            SIZE_T ticketNonceLength,
            _Out_writes_bytes_(secretCapacity) UCHAR* secret,
            SIZE_T secretCapacity,
            _Out_ SIZE_T* secretLength) const noexcept;

        _Must_inspect_result_
        NTSTATUS StoreTls13Ticket(_In_ const Tls13SessionTicket& ticket) noexcept;

        TlsProtocolVersion Version() const noexcept;
        TlsProtocol Protocol() const noexcept;
        TlsHandshakeState State() const noexcept;
        TlsCipherSuite CipherSuite() const noexcept;
        const TlsSessionSecrets& Secrets() const noexcept;
        const Tls13TrafficSecrets& Tls13Secrets() const noexcept;
        Tls13SessionCache& SessionCache() noexcept;
        const Tls13SessionCache& SessionCache() const noexcept;

        void SetState(TlsHandshakeState state) noexcept;

    private:
        TlsProtocol protocol_ = TlsProtocol::Tls12;
        TlsProtocolVersion version_ = {};
        TlsHandshakeState state_ = TlsHandshakeState::Idle;
        TlsSessionSecrets secrets_ = {};
        Tls13TrafficSecrets tls13Secrets_ = {};
        Tls13SessionCache tls13SessionCache_ = {};
    };
}
}
