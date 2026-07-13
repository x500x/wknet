#pragma once

#include "quic/QuicCrypto.h"
#include "quic/QuicStream.h"
#include "quic/QuicTransportParameters.h"
#include "tls/CertificateValidator.h"
#include "tls/Tls13HandshakeMessages.h"
#include "tls/TlsTranscriptHash.h"
#include <wknet/crypto/KeyExchange.h>
#include <wknet/crypto/TlsCredential.h>

namespace wknet::quic
{
enum class QuicEncryptionLevel : UCHAR
{
    Initial,
    Handshake,
    Application
};

enum class QuicTlsState : UCHAR
{
    Idle,
    AwaitServerHello,
    AwaitSharedSecret,
    AwaitEncryptedExtensions,
    AwaitCertificate,
    AwaitCertificateVerify,
    AwaitFinished,
    Established,
    Failed
};

struct QuicTlsClientOptions final
{
    const char *ServerName = nullptr;
    SIZE_T ServerNameLength = 0;
    QuicBufferView LocalTransportParameters = {};
    const tls::Tls13KeyShareEntry *KeyShares = nullptr;
    SIZE_T KeyShareCount = 0;
    const tls::CertificateStore *CertificateStore = nullptr;
    rtl::IScratchAllocator *CertificateScratchAllocator = nullptr;
    const crypto::CngProviderCache *ProviderCache = nullptr;
    tls::Tls13SessionCache *SessionCache = nullptr;
    const crypto::TlsClientCredential *ClientCredential = nullptr;
    bool VerifyCertificate = true;
    bool RequireRevocationCheck = false;
};

class QuicTls final
{
  public:
    QuicTls() noexcept = default;
    QuicTls(const QuicTls &) = delete;
    QuicTls &operator=(const QuicTls &) = delete;
    ~QuicTls() noexcept;

    NTSTATUS Initialize(const QuicTlsClientOptions &options) noexcept;
    NTSTATUS Start(UCHAR *clientHello, SIZE_T capacity, SIZE_T *bytesWritten) noexcept;
    NTSTATUS ReceiveCrypto(QuicEncryptionLevel level, ULONGLONG offset, const UCHAR *data, SIZE_T length) noexcept;
    NTSTATUS InstallSharedSecret(const UCHAR *sharedSecret, SIZE_T sharedSecretLength) noexcept;
    NTSTATUS TakeHandshakeOutput(UCHAR *output, SIZE_T capacity, SIZE_T *bytesWritten) noexcept;
    NTSTATUS TakeInitialOutput(UCHAR *output, SIZE_T capacity, SIZE_T *bytesWritten) noexcept;
    NTSTATUS OnTlsAlert(UCHAR alertDescription) noexcept;
    NTSTATUS DiscardInitialKeys() noexcept;
    NTSTATUS ConfirmHandshake() noexcept;
    void Clear() noexcept;

    QuicTlsState State() const noexcept
    {
        return state_;
    }

    ULONGLONG TransportError() const noexcept
    {
        return transportError_;
    }

    const QuicTransportParameters &PeerTransportParameters() const noexcept
    {
        return peerTransportParameters_;
    }

    const QuicPacketKeySet &HandshakeWriteKey() const noexcept
    {
        return handshakeWriteKey_;
    }

    const QuicPacketKeySet &HandshakeReadKey() const noexcept
    {
        return handshakeReadKey_;
    }

    const QuicPacketKeySet &ApplicationWriteKey() const noexcept
    {
        return applicationWriteKey_;
    }

    const QuicPacketKeySet &ApplicationReadKey() const noexcept
    {
        return applicationReadKey_;
    }

    bool InitialKeysDiscarded() const noexcept
    {
        return initialKeysDiscarded_;
    }

    bool HandshakeKeysDiscarded() const noexcept
    {
        return handshakeKeysDiscarded_;
    }
#if defined(WKNET_USER_MODE_TEST)
    bool ClientCertificateVerifySelectedForTest() const noexcept
    {
        return sendClientCertificateVerify_;
    }
    tls::TlsSignatureScheme ClientCertificateSignatureSchemeForTest() const noexcept
    {
        return clientCertificateSignatureScheme_;
    }
#endif

  private:
    struct CryptoLevelBuffer final
    {
        QuicStream Reassembly;
        HeapArray<UCHAR> ParseBuffer;
        ULONGLONG ParseOffset = 0;
        SIZE_T ParseLength = 0;
    };

    static SIZE_T LevelIndex(QuicEncryptionLevel level) noexcept;
    NTSTATUS DrainCrypto(QuicEncryptionLevel level) noexcept;
    NTSTATUS ProcessBufferedMessages(QuicEncryptionLevel level) noexcept;
    NTSTATUS ProcessMessage(QuicEncryptionLevel level, const tls::TlsHandshakeMessageView &message,
                            const UCHAR *encoded, SIZE_T encodedLength) noexcept;
    NTSTATUS ProcessServerHello(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                SIZE_T encodedLength) noexcept;
    NTSTATUS ProcessEncryptedExtensions(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                        SIZE_T encodedLength) noexcept;
    NTSTATUS ProcessCertificate(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                SIZE_T encodedLength) noexcept;
    NTSTATUS ProcessCertificateVerify(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                      SIZE_T encodedLength) noexcept;
    NTSTATUS ProcessFinished(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                             SIZE_T encodedLength) noexcept;
    NTSTATUS ValidateCertificate(const tls::Tls13CertificateView &certificate) noexcept;
    NTSTATUS VerifyCertificateSignature(const tls::Tls13CertificateVerifyView &certificateVerify,
                                        const UCHAR *transcriptHash, SIZE_T transcriptHashLength) noexcept;
    NTSTATUS InstallHandshakeKeys() noexcept;
    NTSTATUS InstallApplicationKeys() noexcept;
    NTSTATUS ProcessHelloRetryRequest(const tls::Tls13ServerHelloView &serverHello, const UCHAR *encoded,
                                      SIZE_T encodedLength) noexcept;
    NTSTATUS SelectClientCredentialSignature(const tls::Tls13CertificateRequestView &request) noexcept;
    NTSTATUS AppendClientCredentialOutput(UCHAR *output, SIZE_T capacity, SIZE_T *offset) noexcept;
    NTSTATUS Fail(NTSTATUS status, ULONGLONG transportError = 0) noexcept;

    CryptoLevelBuffer levels_[3];
    tls::TlsContext context_;
    tls::TlsTranscriptHash transcript_;
    HeapArray<char> serverName_;
    HeapArray<UCHAR> localTransportParameters_;
    HeapArray<UCHAR> peerTransportParametersBytes_;
    HeapArray<UCHAR> clientHello_;
    HeapArray<UCHAR> pendingHandshakeOutput_;
    SIZE_T pendingHandshakeOutputLength_ = 0;
    HeapArray<UCHAR> pendingInitialOutput_;
    SIZE_T pendingInitialOutputLength_ = 0;
    HeapArray<UCHAR> certificateRequestContext_;
    HeapArray<tls::Tls13KeyShareEntry> keyShares_;
    HeapArray<UCHAR> keyShareBytes_;
    const tls::CertificateStore *certificateStore_ = nullptr;
    rtl::IScratchAllocator *certificateScratchAllocator_ = nullptr;
    const crypto::CngProviderCache *providerCache_ = nullptr;
    tls::Tls13SessionCache *sessionCache_ = nullptr;
    const crypto::TlsClientCredential *clientCredential_ = nullptr;
    crypto::CngKey serverPublicKey_;
    crypto::KeyExchangeKeyPair keyPair_;
    tls::CertificatePublicKeyAlgorithm serverPublicKeyAlgorithm_ = tls::CertificatePublicKeyAlgorithm::Unknown;
    UCHAR serverEd25519PublicKey_[32] = {};
    SIZE_T serverEd25519PublicKeyLength_ = 0;
    UCHAR serverEd448PublicKey_[57] = {};
    SIZE_T serverEd448PublicKeyLength_ = 0;
    QuicTransportParameters peerTransportParameters_ = {};
    QuicPacketKeySet handshakeWriteKey_ = {};
    QuicPacketKeySet handshakeReadKey_ = {};
    QuicPacketKeySet applicationWriteKey_ = {};
    QuicPacketKeySet applicationReadKey_ = {};
    QuicTlsState state_ = QuicTlsState::Idle;
    ULONGLONG transportError_ = 0;
    bool verifyCertificate_ = true;
    bool requireRevocationCheck_ = false;
    bool certificateRequested_ = false;
    bool ownsKeyPair_ = false;
    bool initialKeysDiscarded_ = false;
    bool handshakeKeysDiscarded_ = false;
    tls::TlsSignatureScheme clientCertificateSignatureScheme_ = tls::TlsSignatureScheme::RsaPkcs1Sha256;
    bool sendClientCertificateVerify_ = false;
    bool helloRetryRequestUsed_ = false;
};
} // namespace wknet::quic
