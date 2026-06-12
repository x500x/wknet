#pragma once

#include <KernelHttp/tls/TlsContext.h>

namespace KernelHttp
{
namespace tls
{
    constexpr SIZE_T TlsHandshakeHeaderLength = 4;
    constexpr SIZE_T TlsMaxHandshakeMessageLength = 0x00ffffff;
    constexpr SIZE_T TlsMaxTranscriptHashLength = 64;

    enum class TlsHandshakeType : UCHAR
    {
        ClientHello = 1,
        ServerHello = 2,
        NewSessionTicket = 4,
        EndOfEarlyData = 5,
        EncryptedExtensions = 8,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        ClientKeyExchange = 16,
        CertificateVerify = 15,
        CertificateStatus = 22,
        Finished = 20,
        KeyUpdate = 24
    };

    enum class TlsNamedGroup : USHORT
    {
        Secp256r1 = 23,
        Secp384r1 = 24,
        Secp521r1 = 25,
        X25519 = 29,
        X448 = 30,
        Ffdhe2048 = 256,
        Ffdhe3072 = 257,
        Ffdhe4096 = 258,
        Ffdhe6144 = 259,
        Ffdhe8192 = 260
    };

    enum class TlsSignatureScheme : USHORT
    {
        RsaPkcs1Sha1 = 0x0201,
        EcdsaSha1 = 0x0203,
        RsaPkcs1Sha256 = 0x0401,
        EcdsaSecp256r1Sha256 = 0x0403,
        RsaPkcs1Sha384 = 0x0501,
        EcdsaSecp384r1Sha384 = 0x0503,
        RsaPkcs1Sha512 = 0x0601,
        EcdsaSecp521r1Sha512 = 0x0603,
        Ed25519 = 0x0807,
        Ed448 = 0x0808,
        RsaPssRsaeSha256 = 0x0804,
        RsaPssRsaeSha384 = 0x0805,
        RsaPssRsaeSha512 = 0x0806,
        RsaPssPssSha256 = 0x0809,
        RsaPssPssSha384 = 0x080a,
        RsaPssPssSha512 = 0x080b
    };

    struct TlsHandshakeMessageView final
    {
        TlsHandshakeType Type = TlsHandshakeType::ClientHello;
        const UCHAR* Body = nullptr;
        SIZE_T BodyLength = 0;
        SIZE_T BytesConsumed = 0;
    };

    struct Tls12NewSessionTicketView final
    {
        ULONG LifetimeHintSeconds = 0;
        const UCHAR* Ticket = nullptr;
        SIZE_T TicketLength = 0;
    };

    struct Tls12CertificateStatusView final
    {
        UCHAR StatusType = 0;
        const UCHAR* OcspResponse = nullptr;
        SIZE_T OcspResponseLength = 0;
    };

    struct TlsAlpnProtocol final
    {
        const char* Name = nullptr;
        SIZE_T NameLength = 0;
    };

    struct TlsClientHelloOptions final
    {
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const TlsCipherSuite* CipherSuites = nullptr;
        SIZE_T CipherSuiteCount = 0;
        const TlsNamedGroup* NamedGroups = nullptr;
        SIZE_T NamedGroupCount = 0;
        const TlsSignatureScheme* SignatureSchemes = nullptr;
        SIZE_T SignatureSchemeCount = 0;
        const TlsAlpnProtocol* AlpnProtocols = nullptr;
        SIZE_T AlpnProtocolCount = 0;
        const UCHAR* SessionId = nullptr;
        SIZE_T SessionIdLength = 0;
        const UCHAR* SessionTicket = nullptr;
        SIZE_T SessionTicketLength = 0;
        bool OfferEncryptThenMac = false;
        bool OfferStatusRequest = false;
    };

    struct TlsServerHelloView final
    {
        TlsProtocolVersion Version = {};
        const UCHAR* Random = nullptr;
        SIZE_T RandomLength = 0;
        const UCHAR* SessionId = nullptr;
        SIZE_T SessionIdLength = 0;
        TlsCipherSuite CipherSuite = TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256;
        UCHAR CompressionMethod = 0;
        const UCHAR* Extensions = nullptr;
        SIZE_T ExtensionsLength = 0;
        bool HasExtendedMasterSecret = false;
        bool HasSecureRenegotiation = false;
        bool HasEncryptThenMac = false;
    };

    struct TlsCertificateListView final
    {
        const UCHAR* Certificates = nullptr;
        SIZE_T CertificatesLength = 0;
        SIZE_T CertificateCount = 0;
    };

    struct TlsServerKeyExchangeView final
    {
        const UCHAR* Parameters = nullptr;
        SIZE_T ParametersLength = 0;
        TlsNamedGroup NamedGroup = TlsNamedGroup::Secp256r1;
        const UCHAR* EcPoint = nullptr;
        SIZE_T EcPointLength = 0;
        const UCHAR* DhPrime = nullptr;
        SIZE_T DhPrimeLength = 0;
        const UCHAR* DhGenerator = nullptr;
        SIZE_T DhGeneratorLength = 0;
        const UCHAR* DhPublicKey = nullptr;
        SIZE_T DhPublicKeyLength = 0;
        TlsSignatureScheme SignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;
        const UCHAR* Signature = nullptr;
        SIZE_T SignatureLength = 0;
    };

    struct TlsCertificateRequestView final
    {
        const UCHAR* CertificateTypes = nullptr;
        SIZE_T CertificateTypeCount = 0;
        const UCHAR* SignatureSchemes = nullptr;
        SIZE_T SignatureSchemeCount = 0;
        const UCHAR* DistinguishedNames = nullptr;
        SIZE_T DistinguishedNamesLength = 0;
    };

    class TlsTranscriptHash final
    {
    public:
        TlsTranscriptHash() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(crypto::HashAlgorithm algorithm) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Update(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength) noexcept;

        _Must_inspect_result_
        NTSTATUS Finish(
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) const noexcept;

    private:
        crypto::HashAlgorithm algorithm_ = crypto::HashAlgorithm::Sha256;
        crypto::CngHashContext hash_ = {};
    };

    class TlsHandshake12 final
    {
    public:
        TlsHandshake12() = delete;

        _Must_inspect_result_
        static crypto::HashAlgorithm PrfHashForCipherSuite(TlsCipherSuite cipherSuite) noexcept;

        _Must_inspect_result_
        static NTSTATUS Prf(
            crypto::HashAlgorithm algorithm,
            _In_reads_bytes_(secretLength) const UCHAR* secret,
            SIZE_T secretLength,
            _In_z_ const char* label,
            _In_reads_bytes_(seedLength) const UCHAR* seed,
            SIZE_T seedLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS ParseMessage(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_ TlsHandshakeMessageView& message) noexcept;

        _Must_inspect_result_
        static NTSTATUS ParseNewSessionTicket(
            _In_ const TlsHandshakeMessageView& message,
            _Out_ Tls12NewSessionTicketView& ticket) noexcept;

        _Must_inspect_result_
        static NTSTATUS ParseCertificateStatus(
            _In_ const TlsHandshakeMessageView& message,
            _Out_ Tls12CertificateStatusView& certificateStatus) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeClientHello(
            _Inout_ TlsContext& context,
            _In_ const TlsClientHelloOptions& options,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS ParseServerHello(
            _Inout_ TlsContext& context,
            _In_ const TlsHandshakeMessageView& message,
            _Out_ TlsServerHelloView& serverHello) noexcept;

        _Must_inspect_result_
        static NTSTATUS ValidateServerHelloOffer(
            _In_ const TlsServerHelloView& serverHello,
            _In_ const TlsClientHelloOptions& clientHello) noexcept;

        _Must_inspect_result_
        static NTSTATUS ParseCertificateList(
            _Inout_ TlsContext& context,
            _In_ const TlsHandshakeMessageView& message,
            _Out_ TlsCertificateListView& certificates) noexcept;

        _Must_inspect_result_
        static NTSTATUS ParseServerKeyExchange(
            _Inout_ TlsContext& context,
            _In_ const TlsHandshakeMessageView& message,
            _Out_ TlsServerKeyExchangeView& keyExchange) noexcept;

        _Must_inspect_result_
        static NTSTATUS ValidateServerKeyExchangeOffer(
            _In_ const TlsServerKeyExchangeView& keyExchange,
            _In_ const TlsClientHelloOptions& clientHello) noexcept;

        _Must_inspect_result_
        static NTSTATUS ParseCertificateRequest(
            _Inout_ TlsContext& context,
            _In_ const TlsHandshakeMessageView& message,
            _Out_ TlsCertificateRequestView& certificateRequest) noexcept;

        _Must_inspect_result_
        static NTSTATUS MarkServerHelloDone(
            _Inout_ TlsContext& context,
            _In_ const TlsHandshakeMessageView& message) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeClientKeyExchange(
            _In_reads_bytes_(publicKeyLength) const UCHAR* publicKey,
            SIZE_T publicKeyLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeCertificate(
            _In_reads_bytes_opt_(certificateListLength) const UCHAR* certificateList,
            SIZE_T certificateListLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeCertificateVerify(
            TlsSignatureScheme signatureScheme,
            _In_reads_bytes_(signatureLength) const UCHAR* signature,
            SIZE_T signatureLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeFinished(
            _Inout_ TlsContext& context,
            bool clientFinished,
            _In_reads_bytes_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS VerifyFinished(
            _In_ const TlsContext& context,
            bool clientFinished,
            _In_reads_bytes_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength,
            _In_reads_bytes_(verifyDataLength) const UCHAR* verifyData,
            SIZE_T verifyDataLength) noexcept;
    };
}
}
