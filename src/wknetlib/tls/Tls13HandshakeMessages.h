#pragma once

#include "tls/TlsHandshake12.h"

namespace wknet
{
namespace tls
{
constexpr SIZE_T Tls13KeyShareMaxPublicKeyLength = 1024;
constexpr SIZE_T Tls13MaxExtensionsLength = 4096;
constexpr SIZE_T Tls13MaxBinderLength = 48;
constexpr SIZE_T Tls13CertificateVerifyContextPaddingLength = 64;
constexpr SIZE_T Tls13CertificateVerifyContextLength = sizeof("TLS 1.3, server CertificateVerify") - 1;
constexpr SIZE_T Tls13CertificateVerifyInputMaxLength =
    Tls13CertificateVerifyContextPaddingLength + Tls13CertificateVerifyContextLength + 1 + TlsMaxTranscriptHashLength;

enum class Tls13PskKeyExchangeMode : UCHAR
{
    PskKe = 0,
    PskDheKe = 1
};

struct Tls13KeyShareEntry final
{
    TlsNamedGroup Group = TlsNamedGroup::Secp256r1;
    const UCHAR *KeyExchange = nullptr;
    SIZE_T KeyExchangeLength = 0;
};

struct Tls13PskIdentity final
{
    const UCHAR *Identity = nullptr;
    SIZE_T IdentityLength = 0;
    ULONG ObfuscatedTicketAge = 0;
    const UCHAR *Binder = nullptr;
    SIZE_T BinderLength = 0;
};

struct Tls13ExtensionView final
{
    USHORT Type = 0;
    const UCHAR *Data = nullptr;
    SIZE_T Length = 0;
};

struct Tls13ClientHelloOptions final
{
    const char *ServerName = nullptr;
    SIZE_T ServerNameLength = 0;
    const TlsCipherSuite *CipherSuites = nullptr;
    SIZE_T CipherSuiteCount = 0;
    const TlsNamedGroup *NamedGroups = nullptr;
    SIZE_T NamedGroupCount = 0;
    const TlsSignatureScheme *SignatureSchemes = nullptr;
    SIZE_T SignatureSchemeCount = 0;
    const TlsAlpnProtocol *AlpnProtocols = nullptr;
    SIZE_T AlpnProtocolCount = 0;
    const Tls13KeyShareEntry *KeyShares = nullptr;
    SIZE_T KeyShareCount = 0;
    const Tls13PskIdentity *PskIdentities = nullptr;
    SIZE_T PskIdentityCount = 0;
    const Tls13ExtensionView *CustomExtensions = nullptr;
    SIZE_T CustomExtensionCount = 0;
    bool OfferEarlyData = false;
};

struct Tls13ServerHelloView final
{
    TlsProtocolVersion LegacyVersion = {};
    const UCHAR *Random = nullptr;
    SIZE_T RandomLength = 0;
    const UCHAR *SessionId = nullptr;
    SIZE_T SessionIdLength = 0;
    TlsCipherSuite CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;
    TlsProtocolVersion SelectedVersion = {};
    Tls13KeyShareEntry KeyShare = {};
    USHORT SelectedPskIdentity = 0xffff;
    const UCHAR *Extensions = nullptr;
    SIZE_T ExtensionsLength = 0;
    bool IsHelloRetryRequest = false;
    TlsNamedGroup RetryGroup = TlsNamedGroup::Secp256r1;
};

struct Tls13EncryptedExtensionsView final
{
    const char *Alpn = nullptr;
    SIZE_T AlpnLength = 0;
    bool EarlyDataAccepted = false;
    const UCHAR *Extensions = nullptr;
    SIZE_T ExtensionsLength = 0;
};

struct Tls13CertificateRequestView final
{
    const UCHAR *Context = nullptr;
    SIZE_T ContextLength = 0;
    const UCHAR *Extensions = nullptr;
    SIZE_T ExtensionsLength = 0;
};

struct Tls13CertificateView final
{
    const UCHAR *RequestContext = nullptr;
    SIZE_T RequestContextLength = 0;
    const UCHAR *Certificates = nullptr;
    SIZE_T CertificatesLength = 0;
    SIZE_T CertificateCount = 0;
};

struct Tls13CertificateVerifyView final
{
    TlsSignatureScheme SignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;
    const UCHAR *Signature = nullptr;
    SIZE_T SignatureLength = 0;
};

enum class Tls13KeyUpdateRequest : UCHAR
{
    UpdateNotRequested = 0,
    UpdateRequested = 1
};

struct Tls13KeyUpdateView final
{
    Tls13KeyUpdateRequest Request = Tls13KeyUpdateRequest::UpdateNotRequested;
};

struct Tls13NewSessionTicketView final
{
    ULONG LifetimeSeconds = 0;
    ULONG AgeAdd = 0;
    const UCHAR *Nonce = nullptr;
    SIZE_T NonceLength = 0;
    const UCHAR *Ticket = nullptr;
    SIZE_T TicketLength = 0;
    ULONG MaxEarlyDataSize = 0;
};

class Tls13HandshakeMessages final
{
  public:
    Tls13HandshakeMessages() = delete;

    _Must_inspect_result_ static crypto::HashAlgorithm HashForCipherSuite(TlsCipherSuite cipherSuite) noexcept;

    _Must_inspect_result_ static bool IsSupportedCipherSuite(TlsCipherSuite cipherSuite) noexcept;

    _Must_inspect_result_ static NTSTATUS EncodeClientHello(_Inout_ TlsContext &context,
                                                            _In_ const Tls13ClientHelloOptions &options,
                                                            _Out_writes_bytes_(destinationCapacity) UCHAR *destination,
                                                            SIZE_T destinationCapacity,
                                                            _Out_opt_ SIZE_T *bytesWritten) noexcept;

    _Must_inspect_result_ static NTSTATUS ComputePskBinder(
        _In_ const TlsContext &context, _In_reads_bytes_(resumptionSecretLength) const UCHAR *resumptionSecret,
        SIZE_T resumptionSecretLength,
        _In_reads_bytes_(partialClientHelloHashLength) const UCHAR *partialClientHelloHash,
        SIZE_T partialClientHelloHashLength, _Out_writes_bytes_(binderCapacity) UCHAR *binder, SIZE_T binderCapacity,
        _Out_ SIZE_T *binderLength) noexcept;

    _Must_inspect_result_ static NTSTATUS FindPskBinderTranscriptLength(_In_reads_bytes_(clientHelloLength)
                                                                            const UCHAR *clientHello,
                                                                        SIZE_T clientHelloLength,
                                                                        _Out_ SIZE_T *transcriptLength) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseServerHello(_Inout_ TlsContext &context,
                                                           _In_ const TlsHandshakeMessageView &message,
                                                           _Out_ Tls13ServerHelloView &serverHello) noexcept;

    _Must_inspect_result_ static NTSTATUS ValidateServerHelloOffer(
        _In_ const Tls13ServerHelloView &serverHello, _In_ const Tls13ClientHelloOptions &clientHello) noexcept;

    _Must_inspect_result_ static NTSTATUS ValidateSelectedPskIdentity(_In_ const Tls13ServerHelloView &serverHello,
                                                                      SIZE_T offeredPskIdentityCount) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseEncryptedExtensions(
        _In_ const TlsHandshakeMessageView &message, _Out_ Tls13EncryptedExtensionsView &encryptedExtensions) noexcept;

    _Must_inspect_result_ static NTSTATUS FindExtensionView(_In_reads_bytes_opt_(extensionsLength)
                                                                const UCHAR *extensions,
                                                            SIZE_T extensionsLength, USHORT extensionType,
                                                            _Out_ Tls13ExtensionView &extension,
                                                            _Out_opt_ bool *found = nullptr) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseCertificateRequest(
        _In_ const TlsHandshakeMessageView &message, _Out_ Tls13CertificateRequestView &certificateRequest) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseCertificate(_In_ const TlsHandshakeMessageView &message,
                                                           _Out_ Tls13CertificateView &certificate) noexcept;

    _Must_inspect_result_ static NTSTATUS EncodeEmptyCertificate(
        _In_reads_bytes_(requestContextLength) const UCHAR *requestContext, SIZE_T requestContextLength,
        _Out_writes_bytes_(destinationCapacity) UCHAR *destination, SIZE_T destinationCapacity,
        _Out_opt_ SIZE_T *bytesWritten) noexcept;

    _Must_inspect_result_ static NTSTATUS EncodeCertificate(
        _In_reads_bytes_(requestContextLength) const UCHAR *requestContext, SIZE_T requestContextLength,
        _In_reads_bytes_opt_(certificateListLength) const UCHAR *certificateList, SIZE_T certificateListLength,
        _Out_writes_bytes_(destinationCapacity) UCHAR *destination, SIZE_T destinationCapacity,
        _Out_opt_ SIZE_T *bytesWritten) noexcept;

    _Must_inspect_result_ static NTSTATUS EncodeCertificateVerify(
        TlsSignatureScheme signatureScheme, _In_reads_bytes_(signatureLength) const UCHAR *signature,
        SIZE_T signatureLength, _Out_writes_bytes_(destinationCapacity) UCHAR *destination, SIZE_T destinationCapacity,
        _Out_opt_ SIZE_T *bytesWritten) noexcept;

    _Must_inspect_result_ static NTSTATUS EncodeEndOfEarlyData(_Out_writes_bytes_(destinationCapacity)
                                                                   UCHAR *destination,
                                                               SIZE_T destinationCapacity,
                                                               _Out_opt_ SIZE_T *bytesWritten) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseCertificateVerify(
        _In_ const TlsHandshakeMessageView &message, _Out_ Tls13CertificateVerifyView &certificateVerify) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseKeyUpdate(_In_ const TlsHandshakeMessageView &message,
                                                         _Out_ Tls13KeyUpdateView &keyUpdate) noexcept;

    _Must_inspect_result_ static NTSTATUS EncodeKeyUpdate(Tls13KeyUpdateRequest request,
                                                          _Out_writes_bytes_(destinationCapacity) UCHAR *destination,
                                                          SIZE_T destinationCapacity,
                                                          _Out_opt_ SIZE_T *bytesWritten) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseNewSessionTicket(_In_ const TlsHandshakeMessageView &message,
                                                                _Out_ Tls13NewSessionTicketView &ticket) noexcept;

    _Must_inspect_result_ static NTSTATUS ParseNextNewSessionTicket(_In_reads_bytes_(dataLength) const UCHAR *data,
                                                                    SIZE_T dataLength, _Inout_ SIZE_T *offset,
                                                                    _Out_ Tls13NewSessionTicketView &ticket) noexcept;

    _Must_inspect_result_ static NTSTATUS EncodeFinished(_In_ const TlsContext &context, bool clientFinished,
                                                         _In_reads_bytes_(transcriptHashLength)
                                                             const UCHAR *transcriptHash,
                                                         SIZE_T transcriptHashLength,
                                                         _Out_writes_bytes_(destinationCapacity) UCHAR *destination,
                                                         SIZE_T destinationCapacity,
                                                         _Out_opt_ SIZE_T *bytesWritten) noexcept;

    _Must_inspect_result_ static NTSTATUS VerifyFinished(_In_ const TlsContext &context, bool clientFinished,
                                                         _In_reads_bytes_(transcriptHashLength)
                                                             const UCHAR *transcriptHash,
                                                         SIZE_T transcriptHashLength,
                                                         _In_reads_bytes_(verifyDataLength) const UCHAR *verifyData,
                                                         SIZE_T verifyDataLength) noexcept;

    _Must_inspect_result_ static NTSTATUS BuildCertificateVerifyInput(
        bool server, _In_reads_bytes_(transcriptHashLength) const UCHAR *transcriptHash, SIZE_T transcriptHashLength,
        _Out_writes_bytes_(destinationCapacity) UCHAR *destination, SIZE_T destinationCapacity,
        _Out_ SIZE_T *bytesWritten) noexcept;
};
} // namespace tls
} // namespace wknet
