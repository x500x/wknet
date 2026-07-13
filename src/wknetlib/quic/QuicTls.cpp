#include "quic/QuicTls.h"
#include "quic/QuicClock.h"
#include "tls/TlsHandshake12.h"
#include <wknet/crypto/Ed25519.h>
#include <wknet/crypto/Ed448.h>

namespace wknet::quic
{
namespace
{
constexpr USHORT ExtensionQuicTransportParameters = 57;
constexpr USHORT ExtensionCookie = 44;
constexpr USHORT ExtensionSignatureAlgorithms = 13;
constexpr ULONGLONG QuicTransportParameterError = 0x8;
constexpr ULONGLONG QuicProtocolViolation = 0xA;
constexpr ULONGLONG QuicCryptoBufferExceeded = 0xD;
constexpr ULONGLONG QuicCryptoErrorBase = 0x100;
constexpr SIZE_T QuicTlsPendingOutputCapacity = 8192;

NTSTATUS ToKeyExchangeGroup(tls::TlsNamedGroup group, crypto::KeyExchangeGroup *keyExchangeGroup) noexcept
{
    if (keyExchangeGroup == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const crypto::KeyExchangeGroup candidate = static_cast<crypto::KeyExchangeGroup>(group);
    if (!crypto::KeyExchange::IsSupportedGroup(candidate))
    {
        return STATUS_NOT_SUPPORTED;
    }
    *keyExchangeGroup = candidate;
    return STATUS_SUCCESS;
}

bool ClientCredentialAllowsScheme(const crypto::TlsClientCredential &credential,
                                  tls::TlsSignatureScheme scheme) noexcept
{
    if (!credential.AllowsDigitalSignature)
    {
        return false;
    }
    if (credential.SupportedSignatureSchemeCount != 0)
    {
        if (credential.SupportedSignatureSchemes == nullptr)
        {
            return false;
        }
        for (SIZE_T index = 0; index < credential.SupportedSignatureSchemeCount; ++index)
        {
            if (credential.SupportedSignatureSchemes[index] == static_cast<crypto::TlsSignatureScheme>(scheme))
            {
                return true;
            }
        }
        return false;
    }
    switch (credential.KeyAlgorithm)
    {
    case crypto::TlsClientCredentialKeyAlgorithm::Rsa:
        return scheme == tls::TlsSignatureScheme::RsaPssRsaeSha256 ||
               scheme == tls::TlsSignatureScheme::RsaPssRsaeSha384 ||
               scheme == tls::TlsSignatureScheme::RsaPssRsaeSha512;
    case crypto::TlsClientCredentialKeyAlgorithm::RsaPss:
        return scheme == tls::TlsSignatureScheme::RsaPssPssSha256 ||
               scheme == tls::TlsSignatureScheme::RsaPssPssSha384 || scheme == tls::TlsSignatureScheme::RsaPssPssSha512;
    case crypto::TlsClientCredentialKeyAlgorithm::EcdsaP256:
        return scheme == tls::TlsSignatureScheme::EcdsaSecp256r1Sha256;
    case crypto::TlsClientCredentialKeyAlgorithm::EcdsaP384:
        return scheme == tls::TlsSignatureScheme::EcdsaSecp384r1Sha384;
    case crypto::TlsClientCredentialKeyAlgorithm::EcdsaP521:
        return scheme == tls::TlsSignatureScheme::EcdsaSecp521r1Sha512;
    case crypto::TlsClientCredentialKeyAlgorithm::Ed25519:
        return scheme == tls::TlsSignatureScheme::Ed25519;
    case crypto::TlsClientCredentialKeyAlgorithm::Ed448:
        return scheme == tls::TlsSignatureScheme::Ed448;
    default:
        return false;
    }
}

QuicCipherSuite ToQuicCipherSuite(tls::TlsCipherSuite cipherSuite) noexcept
{
    switch (cipherSuite)
    {
    case tls::TlsCipherSuite::TlsAes256GcmSha384:
        return QuicCipherSuite::Aes256GcmSha384;
    case tls::TlsCipherSuite::TlsChaCha20Poly1305Sha256:
        return QuicCipherSuite::ChaCha20Poly1305Sha256;
    case tls::TlsCipherSuite::TlsAes128GcmSha256:
    default:
        return QuicCipherSuite::Aes128GcmSha256;
    }
}

crypto::HashAlgorithm HashForSignature(tls::TlsSignatureScheme scheme) noexcept
{
    switch (scheme)
    {
    case tls::TlsSignatureScheme::RsaPkcs1Sha1:
    case tls::TlsSignatureScheme::EcdsaSha1:
        return crypto::HashAlgorithm::Sha1;
    case tls::TlsSignatureScheme::RsaPkcs1Sha384:
    case tls::TlsSignatureScheme::RsaPssRsaeSha384:
    case tls::TlsSignatureScheme::RsaPssPssSha384:
    case tls::TlsSignatureScheme::EcdsaSecp384r1Sha384:
        return crypto::HashAlgorithm::Sha384;
    case tls::TlsSignatureScheme::RsaPkcs1Sha512:
    case tls::TlsSignatureScheme::RsaPssRsaeSha512:
    case tls::TlsSignatureScheme::RsaPssPssSha512:
    case tls::TlsSignatureScheme::EcdsaSecp521r1Sha512:
    case tls::TlsSignatureScheme::Ed25519:
    case tls::TlsSignatureScheme::Ed448:
        return crypto::HashAlgorithm::Sha512;
    default:
        return crypto::HashAlgorithm::Sha256;
    }
}

NTSTATUS ToSignatureAlgorithm(tls::TlsSignatureScheme scheme, crypto::SignatureAlgorithm *algorithm) noexcept
{
    if (algorithm == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    switch (scheme)
    {
    case tls::TlsSignatureScheme::RsaPkcs1Sha1:
        *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha1;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::RsaPkcs1Sha256:
        *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::RsaPkcs1Sha384:
        *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha384;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::RsaPkcs1Sha512:
        *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha512;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::RsaPssRsaeSha256:
    case tls::TlsSignatureScheme::RsaPssPssSha256:
        *algorithm = crypto::SignatureAlgorithm::RsaPssSha256;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::RsaPssRsaeSha384:
    case tls::TlsSignatureScheme::RsaPssPssSha384:
        *algorithm = crypto::SignatureAlgorithm::RsaPssSha384;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::RsaPssRsaeSha512:
    case tls::TlsSignatureScheme::RsaPssPssSha512:
        *algorithm = crypto::SignatureAlgorithm::RsaPssSha512;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::EcdsaSha1:
        *algorithm = crypto::SignatureAlgorithm::EcdsaSha1;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::EcdsaSecp256r1Sha256:
        *algorithm = crypto::SignatureAlgorithm::EcdsaSha256;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::EcdsaSecp384r1Sha384:
        *algorithm = crypto::SignatureAlgorithm::EcdsaSha384;
        return STATUS_SUCCESS;
    case tls::TlsSignatureScheme::EcdsaSecp521r1Sha512:
        *algorithm = crypto::SignatureAlgorithm::EcdsaSha512;
        return STATUS_SUCCESS;
    default:
        return STATUS_NOT_SUPPORTED;
    }
}

bool SignatureSchemeMatchesPublicKey(tls::CertificatePublicKeyAlgorithm algorithm,
                                     tls::TlsSignatureScheme scheme) noexcept
{
    switch (algorithm)
    {
    case tls::CertificatePublicKeyAlgorithm::Rsa:
        return scheme == tls::TlsSignatureScheme::RsaPkcs1Sha256 || scheme == tls::TlsSignatureScheme::RsaPkcs1Sha384 ||
               scheme == tls::TlsSignatureScheme::RsaPkcs1Sha512 ||
               scheme == tls::TlsSignatureScheme::RsaPssRsaeSha256 ||
               scheme == tls::TlsSignatureScheme::RsaPssRsaeSha384 ||
               scheme == tls::TlsSignatureScheme::RsaPssRsaeSha512;
    case tls::CertificatePublicKeyAlgorithm::EcdsaP256:
        return scheme == tls::TlsSignatureScheme::EcdsaSecp256r1Sha256;
    case tls::CertificatePublicKeyAlgorithm::EcdsaP384:
        return scheme == tls::TlsSignatureScheme::EcdsaSecp384r1Sha384;
    case tls::CertificatePublicKeyAlgorithm::EcdsaP521:
        return scheme == tls::TlsSignatureScheme::EcdsaSecp521r1Sha512;
    case tls::CertificatePublicKeyAlgorithm::Ed25519:
        return scheme == tls::TlsSignatureScheme::Ed25519;
    case tls::CertificatePublicKeyAlgorithm::Ed448:
        return scheme == tls::TlsSignatureScheme::Ed448;
    default:
        return false;
    }
}

NTSTATUS ConvertCertificateList(const tls::Tls13CertificateView &certificate, UCHAR *destination,
                                SIZE_T destinationCapacity, SIZE_T *bytesWritten, SIZE_T *certificateCount) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (certificateCount != nullptr)
    {
        *certificateCount = 0;
    }
    if (certificate.Certificates == nullptr || certificate.CertificatesLength == 0 || destination == nullptr ||
        bytesWritten == nullptr || certificateCount == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T sourceOffset = 0;
    SIZE_T outputOffset = 0;
    SIZE_T count = 0;
    while (sourceOffset < certificate.CertificatesLength)
    {
        if (certificate.CertificatesLength - sourceOffset < 3)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const SIZE_T certificateLength = (static_cast<SIZE_T>(certificate.Certificates[sourceOffset]) << 16) |
                                         (static_cast<SIZE_T>(certificate.Certificates[sourceOffset + 1]) << 8) |
                                         certificate.Certificates[sourceOffset + 2];
        sourceOffset += 3;
        if (certificateLength == 0 || certificateLength > certificate.CertificatesLength - sourceOffset ||
            certificateLength + 3 > destinationCapacity - outputOffset)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        destination[outputOffset++] = static_cast<UCHAR>((certificateLength >> 16) & 0xff);
        destination[outputOffset++] = static_cast<UCHAR>((certificateLength >> 8) & 0xff);
        destination[outputOffset++] = static_cast<UCHAR>(certificateLength & 0xff);
        RtlCopyMemory(destination + outputOffset, certificate.Certificates + sourceOffset, certificateLength);
        outputOffset += certificateLength;
        sourceOffset += certificateLength;
        if (certificate.CertificatesLength - sourceOffset < 2)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const SIZE_T extensionsLength = (static_cast<SIZE_T>(certificate.Certificates[sourceOffset]) << 8) |
                                        certificate.Certificates[sourceOffset + 1];
        sourceOffset += 2;
        if (extensionsLength > certificate.CertificatesLength - sourceOffset)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        sourceOffset += extensionsLength;
        ++count;
    }
    *bytesWritten = outputOffset;
    *certificateCount = count;
    return count == 0 ? STATUS_INVALID_NETWORK_RESPONSE : STATUS_SUCCESS;
}
} // namespace

QuicTls::~QuicTls() noexcept
{
    Clear();
}

SIZE_T QuicTls::LevelIndex(QuicEncryptionLevel level) noexcept
{
    return static_cast<SIZE_T>(level);
}

void QuicTls::Clear() noexcept
{
    for (SIZE_T index = 0; index < 3; ++index)
    {
        levels_[index].Reassembly.Clear();
        if (levels_[index].ParseBuffer.IsValid())
        {
            RtlSecureZeroMemory(levels_[index].ParseBuffer.Get(), levels_[index].ParseBuffer.Count());
        }
        levels_[index].ParseBuffer.Reset();
        levels_[index].ParseOffset = 0;
        levels_[index].ParseLength = 0;
    }
    if (serverName_.IsValid())
    {
        RtlSecureZeroMemory(serverName_.Get(), serverName_.Count());
    }
    if (localTransportParameters_.IsValid())
    {
        RtlSecureZeroMemory(localTransportParameters_.Get(), localTransportParameters_.Count());
    }
    if (peerTransportParametersBytes_.IsValid())
    {
        RtlSecureZeroMemory(peerTransportParametersBytes_.Get(), peerTransportParametersBytes_.Count());
    }
    if (clientHello_.IsValid())
    {
        RtlSecureZeroMemory(clientHello_.Get(), clientHello_.Count());
    }
    if (pendingHandshakeOutput_.IsValid())
    {
        RtlSecureZeroMemory(pendingHandshakeOutput_.Get(), pendingHandshakeOutput_.Count());
    }
    if (keyShareBytes_.IsValid())
    {
        RtlSecureZeroMemory(keyShareBytes_.Get(), keyShareBytes_.Count());
    }
    serverName_.Reset();
    localTransportParameters_.Reset();
    peerTransportParametersBytes_.Reset();
    clientHello_.Reset();
    pendingHandshakeOutput_.Reset();
    pendingHandshakeOutputLength_ = 0;
    if (pendingInitialOutput_.IsValid())
    {
        RtlSecureZeroMemory(pendingInitialOutput_.Get(), pendingInitialOutput_.Count());
    }
    pendingInitialOutput_.Reset();
    pendingInitialOutputLength_ = 0;
    certificateRequestContext_.Reset();
    keyShares_.Reset();
    keyShareBytes_.Reset();
    serverPublicKey_.Close();
    keyPair_.Reset();
    RtlSecureZeroMemory(serverEd25519PublicKey_, sizeof(serverEd25519PublicKey_));
    RtlSecureZeroMemory(serverEd448PublicKey_, sizeof(serverEd448PublicKey_));
    serverEd25519PublicKeyLength_ = 0;
    serverEd448PublicKeyLength_ = 0;
    QuicClearPacketKeySet(&handshakeWriteKey_);
    QuicClearPacketKeySet(&handshakeReadKey_);
    QuicClearPacketKeySet(&applicationWriteKey_);
    QuicClearPacketKeySet(&applicationReadKey_);
    context_.Reset();
    transcript_.Reset();
    peerTransportParameters_ = {};
    certificateStore_ = nullptr;
    certificateScratchAllocator_ = nullptr;
    providerCache_ = nullptr;
    sessionCache_ = nullptr;
    clientCredential_ = nullptr;
    serverPublicKeyAlgorithm_ = tls::CertificatePublicKeyAlgorithm::Unknown;
    state_ = QuicTlsState::Idle;
    transportError_ = 0;
    verifyCertificate_ = true;
    requireRevocationCheck_ = false;
    certificateRequested_ = false;
    ownsKeyPair_ = false;
    initialKeysDiscarded_ = false;
    handshakeKeysDiscarded_ = false;
    clientCertificateSignatureScheme_ = tls::TlsSignatureScheme::RsaPkcs1Sha256;
    sendClientCertificateVerify_ = false;
    helloRetryRequestUsed_ = false;
}

NTSTATUS QuicTls::Initialize(const QuicTlsClientOptions &options) noexcept
{
    Clear();
    if (options.ServerName == nullptr || options.ServerNameLength == 0 || options.ServerNameLength > 253 ||
        options.LocalTransportParameters.Data == nullptr || options.LocalTransportParameters.Length == 0 ||
        options.LocalTransportParameters.Length > tls::Tls13MaxExtensionsLength ||
        ((options.KeyShares == nullptr) != (options.KeyShareCount == 0)) || options.KeyShareCount > 16 ||
        (options.ClientCredential != nullptr &&
         ((options.ClientCredential->CertificateList == nullptr) !=
              (options.ClientCredential->CertificateListLength == 0) ||
          (options.ClientCredential->SupportedSignatureSchemes == nullptr) !=
              (options.ClientCredential->SupportedSignatureSchemeCount == 0) ||
          options.ClientCredential->SupportedSignatureSchemeCount > 64 ||
          options.ClientCredential->CertificateListLength > QuicTlsPendingOutputCapacity - 1024 ||
          (options.ClientCredential->CertificateListLength != 0 && options.ClientCredential->Sign == nullptr))))
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T keyShareBytes = 0;
    for (SIZE_T index = 0; index < options.KeyShareCount; ++index)
    {
        if (options.KeyShares[index].KeyExchange == nullptr || options.KeyShares[index].KeyExchangeLength == 0 ||
            options.KeyShares[index].KeyExchangeLength > tls::Tls13KeyShareMaxPublicKeyLength ||
            options.KeyShares[index].KeyExchangeLength > ~static_cast<SIZE_T>(0) - keyShareBytes)
        {
            return STATUS_INVALID_PARAMETER;
        }
        keyShareBytes += options.KeyShares[index].KeyExchangeLength;
    }

    NTSTATUS status = STATUS_SUCCESS;
    tls::Tls13KeyShareEntry generatedKeyShare = {};
    const tls::Tls13KeyShareEntry *sourceKeyShares = options.KeyShares;
    SIZE_T sourceKeyShareCount = options.KeyShareCount;
    if (sourceKeyShareCount == 0)
    {
        status =
            crypto::KeyExchange::GenerateKeyPair(options.ProviderCache, crypto::KeyExchangeGroup::X25519, keyPair_);
        if (NT_SUCCESS(status))
        {
            generatedKeyShare.Group = tls::TlsNamedGroup::X25519;
            generatedKeyShare.KeyExchange = keyPair_.PublicKey;
            generatedKeyShare.KeyExchangeLength = keyPair_.PublicKeyLength;
            sourceKeyShares = &generatedKeyShare;
            sourceKeyShareCount = 1;
            keyShareBytes = generatedKeyShare.KeyExchangeLength;
            ownsKeyPair_ = true;
        }
    }
    if (NT_SUCCESS(status))
    {
        status = serverName_.Allocate(options.ServerNameLength + 1);
    }
    if (NT_SUCCESS(status))
    {
        status = localTransportParameters_.Allocate(options.LocalTransportParameters.Length);
    }
    if (NT_SUCCESS(status))
    {
        status = keyShares_.Allocate(sourceKeyShareCount);
    }
    if (NT_SUCCESS(status))
    {
        status = keyShareBytes_.Allocate(keyShareBytes);
    }
    if (NT_SUCCESS(status))
    {
    }
    for (SIZE_T index = 0; NT_SUCCESS(status) && index < 3; ++index)
    {
        status = levels_[index].Reassembly.Initialize(1, WKNET_HARD_MAX_QUIC_CRYPTO_REASSEMBLY_BYTES,
                                                      WKNET_HARD_MAX_QUIC_CRYPTO_GAPS);
    }
    if (!NT_SUCCESS(status))
    {
        Clear();
        return status;
    }

    RtlCopyMemory(serverName_.Get(), options.ServerName, options.ServerNameLength);
    serverName_[options.ServerNameLength] = '\0';
    RtlCopyMemory(localTransportParameters_.Get(), options.LocalTransportParameters.Data,
                  options.LocalTransportParameters.Length);
    SIZE_T keyShareOffset = 0;
    for (SIZE_T index = 0; index < sourceKeyShareCount; ++index)
    {
        const tls::Tls13KeyShareEntry &source = sourceKeyShares[index];
        RtlCopyMemory(keyShareBytes_.Get() + keyShareOffset, source.KeyExchange, source.KeyExchangeLength);
        keyShares_[index].Group = source.Group;
        keyShares_[index].KeyExchange = keyShareBytes_.Get() + keyShareOffset;
        keyShares_[index].KeyExchangeLength = source.KeyExchangeLength;
        keyShareOffset += source.KeyExchangeLength;
    }

    certificateStore_ = options.CertificateStore;
    certificateScratchAllocator_ = options.CertificateScratchAllocator;
    providerCache_ = options.ProviderCache;
    sessionCache_ = options.SessionCache;
    clientCredential_ = options.ClientCredential;
    verifyCertificate_ = options.VerifyCertificate;
    requireRevocationCheck_ = options.RequireRevocationCheck;
    return context_.InitializeClient13();
}

NTSTATUS QuicTls::Start(UCHAR *clientHello, SIZE_T capacity, SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (state_ != QuicTlsState::Idle || clientHello == nullptr || bytesWritten == nullptr || !serverName_.IsValid())
    {
        return STATUS_INVALID_PARAMETER;
    }

    const tls::TlsAlpnProtocol alpn = {"h3", 2};
    const tls::Tls13ExtensionView transportParameters = {
        ExtensionQuicTransportParameters, localTransportParameters_.Get(), localTransportParameters_.Count()};
    tls::Tls13ClientHelloOptions options = {};
    options.ServerName = serverName_.Get();
    options.ServerNameLength = serverName_.Count() - 1;
    options.AlpnProtocols = &alpn;
    options.AlpnProtocolCount = 1;
    options.KeyShares = keyShares_.Get();
    options.KeyShareCount = keyShares_.Count();
    options.CustomExtensions = &transportParameters;
    options.CustomExtensionCount = 1;

    NTSTATUS status =
        tls::Tls13HandshakeMessages::EncodeClientHello(context_, options, clientHello, capacity, bytesWritten);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = clientHello_.Allocate(*bytesWritten);
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }
    RtlCopyMemory(clientHello_.Get(), clientHello, *bytesWritten);
    state_ = QuicTlsState::AwaitServerHello;
    WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.handshake.start");
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::ReceiveCrypto(QuicEncryptionLevel level, ULONGLONG offset, const UCHAR *data, SIZE_T length) noexcept
{
    const SIZE_T levelIndex = LevelIndex(level);
    if (state_ == QuicTlsState::Failed || levelIndex >= 3)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (offset > QuicVarIntMaximum || length > QuicVarIntMaximum - offset)
    {
        return Fail(STATUS_INVALID_PARAMETER);
    }
    const CryptoLevelBuffer &levelBuffer = levels_[levelIndex];
    const ULONGLONG end = offset + length;
    const ULONGLONG parseEnd = levelBuffer.ParseOffset + levelBuffer.ParseLength;
    const ULONGLONG overlapStart = offset > levelBuffer.ParseOffset ? offset : levelBuffer.ParseOffset;
    const ULONGLONG overlapEnd = end < parseEnd ? end : parseEnd;
    for (ULONGLONG current = overlapStart; current < overlapEnd; ++current)
    {
        if (data[static_cast<SIZE_T>(current - offset)] !=
            levelBuffer.ParseBuffer[static_cast<SIZE_T>(current - levelBuffer.ParseOffset)])
        {
            return Fail(STATUS_INVALID_NETWORK_RESPONSE, QuicProtocolViolation);
        }
    }
    NTSTATUS status = levels_[levelIndex].Reassembly.Receive(offset, data, length, false);
    if (!NT_SUCCESS(status))
    {
        return Fail(status, status == STATUS_INSUFFICIENT_RESOURCES ? QuicCryptoBufferExceeded : QuicProtocolViolation);
    }

    ULONGLONG bufferedBytes = 0;
    for (SIZE_T index = 0; index < 3; ++index)
    {
        bufferedBytes += levels_[index].Reassembly.BufferedBytes() + levels_[index].ParseLength;
    }
    if (bufferedBytes > WKNET_HARD_MAX_QUIC_CRYPTO_REASSEMBLY_BYTES)
    {
        return Fail(STATUS_INSUFFICIENT_RESOURCES, QuicCryptoBufferExceeded);
    }
    return DrainCrypto(level);
}

NTSTATUS QuicTls::DrainCrypto(QuicEncryptionLevel level) noexcept
{
    const SIZE_T levelIndex = LevelIndex(level);
    CryptoLevelBuffer &levelBuffer = levels_[levelIndex];
    if (!levelBuffer.ParseBuffer.IsValid())
    {
        const NTSTATUS allocationStatus = levelBuffer.ParseBuffer.Allocate(WKNET_HARD_MAX_QUIC_CRYPTO_REASSEMBLY_BYTES);
        if (!NT_SUCCESS(allocationStatus))
        {
            return Fail(allocationStatus, QuicCryptoBufferExceeded);
        }
    }

    for (;;)
    {
        SIZE_T consumed = 0;
        bool fin = false;
        NTSTATUS status =
            levelBuffer.Reassembly.Consume(levelBuffer.ParseBuffer.Get() + levelBuffer.ParseLength,
                                           levelBuffer.ParseBuffer.Count() - levelBuffer.ParseLength, &consumed, &fin);
        UNREFERENCED_PARAMETER(fin);
        if (!NT_SUCCESS(status))
        {
            return Fail(status, QuicCryptoBufferExceeded);
        }
        levelBuffer.ParseLength += consumed;
        status = ProcessBufferedMessages(level);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (consumed == 0)
        {
            return STATUS_SUCCESS;
        }
    }
}

NTSTATUS QuicTls::ProcessBufferedMessages(QuicEncryptionLevel level) noexcept
{
    if (state_ == QuicTlsState::AwaitSharedSecret && level == QuicEncryptionLevel::Handshake)
    {
        return STATUS_SUCCESS;
    }
    CryptoLevelBuffer &levelBuffer = levels_[LevelIndex(level)];
    while (levelBuffer.ParseLength >= tls::TlsHandshakeHeaderLength)
    {
        const UCHAR *encoded = levelBuffer.ParseBuffer.Get();
        const SIZE_T bodyLength =
            (static_cast<SIZE_T>(encoded[1]) << 16) | (static_cast<SIZE_T>(encoded[2]) << 8) | encoded[3];
        const SIZE_T messageLength = tls::TlsHandshakeHeaderLength + bodyLength;
        if (messageLength > WKNET_HARD_MAX_QUIC_CRYPTO_REASSEMBLY_BYTES)
        {
            return Fail(STATUS_INVALID_NETWORK_RESPONSE, QuicCryptoBufferExceeded);
        }
        if (levelBuffer.ParseLength < messageLength)
        {
            return STATUS_SUCCESS;
        }

        tls::TlsHandshakeMessageView message = {};
        NTSTATUS status = tls::TlsHandshake12::ParseMessage(encoded, messageLength, message);
        if (NT_SUCCESS(status))
        {
            status = ProcessMessage(level, message, encoded, messageLength);
        }
        if (!NT_SUCCESS(status))
        {
            return state_ == QuicTlsState::Failed ? status : Fail(status);
        }

        const SIZE_T remaining = levelBuffer.ParseLength - messageLength;
        if (remaining != 0)
        {
            RtlMoveMemory(levelBuffer.ParseBuffer.Get(), levelBuffer.ParseBuffer.Get() + messageLength, remaining);
        }
        RtlSecureZeroMemory(levelBuffer.ParseBuffer.Get() + remaining, messageLength);
        levelBuffer.ParseLength = remaining;
        levelBuffer.ParseOffset += messageLength;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::ProcessMessage(QuicEncryptionLevel level, const tls::TlsHandshakeMessageView &message,
                                 const UCHAR *encoded, SIZE_T encodedLength) noexcept
{
    if (message.Type == tls::TlsHandshakeType::KeyUpdate)
    {
        return Fail(STATUS_INVALID_NETWORK_RESPONSE, QuicProtocolViolation);
    }
    if (state_ == QuicTlsState::AwaitServerHello)
    {
        return level == QuicEncryptionLevel::Initial && message.Type == tls::TlsHandshakeType::ServerHello
                   ? ProcessServerHello(message, encoded, encodedLength)
                   : Fail(STATUS_INVALID_NETWORK_RESPONSE);
    }
    if (state_ == QuicTlsState::AwaitEncryptedExtensions)
    {
        return level == QuicEncryptionLevel::Handshake && message.Type == tls::TlsHandshakeType::EncryptedExtensions
                   ? ProcessEncryptedExtensions(message, encoded, encodedLength)
                   : Fail(STATUS_INVALID_NETWORK_RESPONSE);
    }
    if (state_ == QuicTlsState::AwaitCertificate)
    {
        if (level != QuicEncryptionLevel::Handshake)
        {
            return Fail(STATUS_INVALID_NETWORK_RESPONSE);
        }
        if (message.Type == tls::TlsHandshakeType::CertificateRequest)
        {
            tls::Tls13CertificateRequestView request = {};
            NTSTATUS status = tls::Tls13HandshakeMessages::ParseCertificateRequest(message, request);
            if (NT_SUCCESS(status) && request.ContextLength != 0)
            {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (NT_SUCCESS(status))
            {
                certificateRequestContext_.Reset();
                if (request.ContextLength != 0)
                {
                    status = certificateRequestContext_.Allocate(request.ContextLength);
                    if (NT_SUCCESS(status))
                    {
                        RtlCopyMemory(certificateRequestContext_.Get(), request.Context, request.ContextLength);
                    }
                }
            }
            if (NT_SUCCESS(status))
            {
                status = SelectClientCredentialSignature(request);
            }
            if (NT_SUCCESS(status))
            {
                status = transcript_.Update(encoded, encodedLength);
            }
            certificateRequested_ = NT_SUCCESS(status);
            return status;
        }
        return message.Type == tls::TlsHandshakeType::Certificate ? ProcessCertificate(message, encoded, encodedLength)
                                                                  : Fail(STATUS_INVALID_NETWORK_RESPONSE);
    }
    if (state_ == QuicTlsState::AwaitCertificateVerify)
    {
        return level == QuicEncryptionLevel::Handshake && message.Type == tls::TlsHandshakeType::CertificateVerify
                   ? ProcessCertificateVerify(message, encoded, encodedLength)
                   : Fail(STATUS_INVALID_NETWORK_RESPONSE);
    }
    if (state_ == QuicTlsState::AwaitFinished)
    {
        return level == QuicEncryptionLevel::Handshake && message.Type == tls::TlsHandshakeType::Finished
                   ? ProcessFinished(message, encoded, encodedLength)
                   : Fail(STATUS_INVALID_NETWORK_RESPONSE);
    }
    if (state_ == QuicTlsState::Established && level == QuicEncryptionLevel::Application &&
        message.Type == tls::TlsHandshakeType::NewSessionTicket)
    {
        tls::Tls13NewSessionTicketView ticketView = {};
        NTSTATUS status = tls::Tls13HandshakeMessages::ParseNewSessionTicket(message, ticketView);
        if (!NT_SUCCESS(status) || sessionCache_ == nullptr)
        {
            return status;
        }
        tls::Tls13SessionTicket ticket = {};
        if (ticketView.TicketLength > sizeof(ticket.Identity) || ticketView.NonceLength > sizeof(ticket.Nonce))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        RtlCopyMemory(ticket.Identity, ticketView.Ticket, ticketView.TicketLength);
        ticket.IdentityLength = ticketView.TicketLength;
        RtlCopyMemory(ticket.Nonce, ticketView.Nonce, ticketView.NonceLength);
        ticket.NonceLength = ticketView.NonceLength;
        ticket.LifetimeSeconds = ticketView.LifetimeSeconds;
        ticket.AgeAdd = ticketView.AgeAdd;
        ticket.MaxEarlyDataSize = ticketView.MaxEarlyDataSize;
        ticket.IssueTimeMilliseconds = QuicClockNow100ns() / 10000ULL;
        ticket.Version = {3, 4};
        ticket.CipherSuite = context_.CipherSuite();
        ticket.ServerNameLength = serverName_.Count() - 1;
        RtlCopyMemory(ticket.ServerName, serverName_.Get(), ticket.ServerNameLength);
        ticket.ServerName[ticket.ServerNameLength] = '\0';
        ticket.Alpn[0] = 'h';
        ticket.Alpn[1] = '3';
        ticket.Alpn[2] = '\0';
        ticket.AlpnLength = 2;
        status = context_.DeriveTls13ResumptionSecret(ticket.Nonce, ticket.NonceLength, ticket.ResumptionSecret,
                                                      sizeof(ticket.ResumptionSecret), &ticket.ResumptionSecretLength);
        if (NT_SUCCESS(status))
        {
            status = context_.StoreTls13Ticket(ticket);
        }
        if (NT_SUCCESS(status))
        {
            if (sessionCache_->TicketCount < tls::Tls13MaxTicketCount)
            {
                sessionCache_->Tickets[sessionCache_->TicketCount++] = ticket;
            }
            else
            {
                for (SIZE_T index = 1; index < tls::Tls13MaxTicketCount; ++index)
                {
                    sessionCache_->Tickets[index - 1] = sessionCache_->Tickets[index];
                }
                sessionCache_->Tickets[tls::Tls13MaxTicketCount - 1] = ticket;
            }
        }
        RtlSecureZeroMemory(&ticket, sizeof(ticket));
        return status;
    }
    return Fail(STATUS_INVALID_NETWORK_RESPONSE);
}

NTSTATUS QuicTls::ProcessServerHello(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                     SIZE_T encodedLength) noexcept
{
    tls::Tls13ServerHelloView serverHello = {};
    NTSTATUS status = tls::Tls13HandshakeMessages::ParseServerHello(context_, message, serverHello);
    if (!NT_SUCCESS(status))
    {
        WKNET_TRACE(ComponentQuic, TraceLevel::Error, "quic.handshake.server_hello_failed stage=parse status=0x%08X",
                    status);
    }
    tls::Tls13ClientHelloOptions offer = {};
    offer.KeyShares = keyShares_.Get();
    offer.KeyShareCount = keyShares_.Count();
    if (NT_SUCCESS(status))
    {
        status = tls::Tls13HandshakeMessages::ValidateServerHelloOffer(serverHello, offer);
        if (!NT_SUCCESS(status))
        {
            WKNET_TRACE(ComponentQuic, TraceLevel::Error,
                        "quic.handshake.server_hello_failed stage=offer status=0x%08X", status);
        }
    }
    if (NT_SUCCESS(status) && serverHello.IsHelloRetryRequest)
    {
        return ProcessHelloRetryRequest(serverHello, encoded, encodedLength);
    }
    if (NT_SUCCESS(status) && !helloRetryRequestUsed_)
    {
        status = transcript_.Initialize(tls::Tls13HandshakeMessages::HashForCipherSuite(serverHello.CipherSuite));
        if (!NT_SUCCESS(status))
        {
            WKNET_TRACE(ComponentQuic, TraceLevel::Error,
                        "quic.handshake.server_hello_failed stage=transcript_init status=0x%08X", status);
        }
    }
    if (NT_SUCCESS(status) && !helloRetryRequestUsed_)
    {
        status = transcript_.Update(clientHello_.Get(), clientHello_.Count());
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(encoded, encodedLength);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    state_ = QuicTlsState::AwaitSharedSecret;
    if (!ownsKeyPair_)
    {
        return STATUS_SUCCESS;
    }
    HeapArray<UCHAR> sharedSecret(crypto::KeyExchangeMaxSharedSecretLength);
    if (!sharedSecret.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T sharedSecretLength = 0;
    status = crypto::KeyExchange::DeriveSharedSecret(providerCache_, keyPair_, serverHello.KeyShare.KeyExchange,
                                                     serverHello.KeyShare.KeyExchangeLength, sharedSecret.Get(),
                                                     sharedSecret.Count(), &sharedSecretLength);
    if (NT_SUCCESS(status))
    {
        status = InstallSharedSecret(sharedSecret.Get(), sharedSecretLength);
    }
    RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
    keyPair_.Reset();
    ownsKeyPair_ = false;
    return status;
}

NTSTATUS QuicTls::ProcessHelloRetryRequest(const tls::Tls13ServerHelloView &serverHello, const UCHAR *encoded,
                                           SIZE_T encodedLength) noexcept
{
    if (helloRetryRequestUsed_)
    {
        return Fail(STATUS_INVALID_NETWORK_RESPONSE);
    }

    crypto::KeyExchangeGroup retryGroup = crypto::KeyExchangeGroup::Secp256r1;
    NTSTATUS status = ToKeyExchangeGroup(serverHello.RetryGroup, &retryGroup);
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }

    HeapArray<UCHAR> firstClientHelloHash(tls::TlsMaxTranscriptHashLength);
    if (!firstClientHelloHash.IsValid())
    {
        return Fail(STATUS_INSUFFICIENT_RESOURCES);
    }
    SIZE_T firstClientHelloHashLength = 0;
    status = transcript_.Initialize(tls::Tls13HandshakeMessages::HashForCipherSuite(serverHello.CipherSuite));
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(clientHello_.Get(), clientHello_.Count());
    }
    if (NT_SUCCESS(status))
    {
        status =
            transcript_.Snapshot(firstClientHelloHash.Get(), firstClientHelloHash.Count(), &firstClientHelloHashLength);
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.ReplaceWithMessageHash(firstClientHelloHash.Get(), firstClientHelloHashLength);
    }
    RtlSecureZeroMemory(firstClientHelloHash.Get(), firstClientHelloHash.Count());
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(encoded, encodedLength);
    }
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }

    keyPair_.Reset();
    ownsKeyPair_ = false;
    status = crypto::KeyExchange::GenerateKeyPair(providerCache_, retryGroup, keyPair_);
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }
    ownsKeyPair_ = true;
    keyShares_.Reset();
    keyShareBytes_.Reset();
    status = keyShares_.Allocate(1);
    if (NT_SUCCESS(status))
    {
        status = keyShareBytes_.Allocate(keyPair_.PublicKeyLength);
    }
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }
    RtlCopyMemory(keyShareBytes_.Get(), keyPair_.PublicKey, keyPair_.PublicKeyLength);
    keyShares_[0].Group = serverHello.RetryGroup;
    keyShares_[0].KeyExchange = keyShareBytes_.Get();
    keyShares_[0].KeyExchangeLength = keyShareBytes_.Count();

    tls::Tls13ExtensionView cookie = {};
    bool hasCookie = false;
    status = tls::Tls13HandshakeMessages::FindExtensionView(serverHello.Extensions, serverHello.ExtensionsLength,
                                                            ExtensionCookie, cookie, &hasCookie);
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }
    const tls::TlsAlpnProtocol alpn = {"h3", 2};
    tls::Tls13ExtensionView customExtensions[2] = {};
    customExtensions[0] = {ExtensionQuicTransportParameters, localTransportParameters_.Get(),
                           localTransportParameters_.Count()};
    SIZE_T customExtensionCount = 1;
    if (hasCookie)
    {
        customExtensions[customExtensionCount++] = cookie;
    }
    tls::Tls13ClientHelloOptions options = {};
    options.ServerName = serverName_.Get();
    options.ServerNameLength = serverName_.Count() - 1;
    options.AlpnProtocols = &alpn;
    options.AlpnProtocolCount = 1;
    options.KeyShares = keyShares_.Get();
    options.KeyShareCount = keyShares_.Count();
    options.CustomExtensions = customExtensions;
    options.CustomExtensionCount = customExtensionCount;

    status = pendingInitialOutput_.Allocate(QuicTlsPendingOutputCapacity);
    if (NT_SUCCESS(status))
    {
        status =
            tls::Tls13HandshakeMessages::EncodeClientHello(context_, options, pendingInitialOutput_.Get(),
                                                           pendingInitialOutput_.Count(), &pendingInitialOutputLength_);
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(pendingInitialOutput_.Get(), pendingInitialOutputLength_);
    }
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }
    helloRetryRequestUsed_ = true;
    state_ = QuicTlsState::AwaitServerHello;
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::InstallSharedSecret(const UCHAR *sharedSecret, SIZE_T sharedSecretLength) noexcept
{
    if (state_ != QuicTlsState::AwaitSharedSecret || sharedSecret == nullptr || sharedSecretLength == 0)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    HeapArray<UCHAR> transcriptHash(tls::TlsMaxTranscriptHashLength);
    if (!transcriptHash.IsValid())
    {
        return Fail(STATUS_INSUFFICIENT_RESOURCES);
    }
    SIZE_T transcriptHashLength = 0;
    NTSTATUS status = transcript_.Snapshot(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
    if (NT_SUCCESS(status))
    {
        status = context_.DeriveTls13HandshakeSecrets(sharedSecret, sharedSecretLength, transcriptHash.Get(),
                                                      transcriptHashLength);
    }
    if (NT_SUCCESS(status))
    {
        status = InstallHandshakeKeys();
    }
    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
    if (!NT_SUCCESS(status))
    {
        return Fail(status);
    }
    state_ = QuicTlsState::AwaitEncryptedExtensions;
    return ProcessBufferedMessages(QuicEncryptionLevel::Handshake);
}

NTSTATUS QuicTls::InstallHandshakeKeys() noexcept
{
    const tls::Tls13TrafficSecrets &secrets = context_.Tls13Secrets();
    const QuicCipherSuite suite = ToQuicCipherSuite(context_.CipherSuite());
    NTSTATUS status =
        QuicInstallWriteSecret(suite, secrets.ClientHandshakeTrafficSecret, secrets.SecretLength, &handshakeWriteKey_);
    if (NT_SUCCESS(status))
    {
        status = QuicInstallReadSecret(suite, secrets.ServerHandshakeTrafficSecret, secrets.SecretLength,
                                       &handshakeReadKey_);
    }
    return status;
}

NTSTATUS QuicTls::ProcessEncryptedExtensions(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                             SIZE_T encodedLength) noexcept
{
    tls::Tls13EncryptedExtensionsView encryptedExtensions = {};
    NTSTATUS status = tls::Tls13HandshakeMessages::ParseEncryptedExtensions(message, encryptedExtensions);
    if (!NT_SUCCESS(status) || encryptedExtensions.Alpn == nullptr || encryptedExtensions.AlpnLength != 2 ||
        encryptedExtensions.Alpn[0] != 'h' || encryptedExtensions.Alpn[1] != '3' ||
        encryptedExtensions.EarlyDataAccepted)
    {
        return Fail(NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status);
    }

    tls::Tls13ExtensionView transportParameters = {};
    bool found = false;
    status = tls::Tls13HandshakeMessages::FindExtensionView(
        encryptedExtensions.Extensions, encryptedExtensions.ExtensionsLength, ExtensionQuicTransportParameters,
        transportParameters, &found);
    if (!NT_SUCCESS(status) || !found)
    {
        return Fail(NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status, QuicTransportParameterError);
    }
    if (transportParameters.Length == 0)
    {
        return Fail(STATUS_INVALID_NETWORK_RESPONSE, QuicTransportParameterError);
    }
    status = peerTransportParametersBytes_.Allocate(transportParameters.Length);
    if (NT_SUCCESS(status) && transportParameters.Length != 0)
    {
        RtlCopyMemory(peerTransportParametersBytes_.Get(), transportParameters.Data, transportParameters.Length);
    }
    if (NT_SUCCESS(status))
    {
        status =
            QuicParseTransportParameters(peerTransportParametersBytes_.Get(), peerTransportParametersBytes_.Count(),
                                         QuicTransportParameterPeerRole::Server, &peerTransportParameters_);
    }
    if (!NT_SUCCESS(status))
    {
        return Fail(status, QuicTransportParameterError);
    }
    status = transcript_.Update(encoded, encodedLength);
    if (NT_SUCCESS(status))
    {
        state_ = QuicTlsState::AwaitCertificate;
    }
    return status;
}

NTSTATUS QuicTls::ProcessCertificate(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                     SIZE_T encodedLength) noexcept
{
    tls::Tls13CertificateView certificate = {};
    NTSTATUS status = tls::Tls13HandshakeMessages::ParseCertificate(message, certificate);
    if (NT_SUCCESS(status))
    {
        status = ValidateCertificate(certificate);
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(encoded, encodedLength);
    }
    if (NT_SUCCESS(status))
    {
        state_ = QuicTlsState::AwaitCertificateVerify;
    }
    return status;
}

NTSTATUS QuicTls::ValidateCertificate(const tls::Tls13CertificateView &certificate) noexcept
{
    HeapArray<UCHAR> legacy(certificate.CertificatesLength);
    HeapObject<tls::CertificateValidationResult> result;
    if (!legacy.IsValid() || !result.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T legacyLength = 0;
    SIZE_T certificateCount = 0;
    NTSTATUS status =
        ConvertCertificateList(certificate, legacy.Get(), legacy.Count(), &legacyLength, &certificateCount);
    if (NT_SUCCESS(status))
    {
        tls::CertificateChainView chain = {};
        chain.Certificates = legacy.Get();
        chain.CertificatesLength = legacyLength;
        chain.CertificateCount = certificateCount;
        tls::CertificateValidationOptions validation = {};
        validation.HostName = serverName_.Get();
        validation.HostNameLength = serverName_.Count() - 1;
        validation.Store = certificateStore_;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = providerCache_;
        validation.VerifyCertificate = verifyCertificate_;
        validation.RequireRevocationCheck = requireRevocationCheck_;
        status = tls::CertificateValidator::ValidateChain(chain, validation, result.Get());
    }
    if (NT_SUCCESS(status))
    {
        serverPublicKeyAlgorithm_ = result->Leaf.PublicKeyAlgorithm;
        if (result->Leaf.HasKeyUsage && !result->Leaf.AllowsDigitalSignature)
        {
            status = STATUS_TRUST_FAILURE;
        }
        else if (serverPublicKeyAlgorithm_ == tls::CertificatePublicKeyAlgorithm::Ed25519)
        {
            if (result->Leaf.PublicKeyLength != crypto::Ed25519PublicKeyLength)
            {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            else
            {
                RtlCopyMemory(serverEd25519PublicKey_, result->Leaf.PublicKey, result->Leaf.PublicKeyLength);
                serverEd25519PublicKeyLength_ = result->Leaf.PublicKeyLength;
            }
        }
        else if (serverPublicKeyAlgorithm_ == tls::CertificatePublicKeyAlgorithm::Ed448)
        {
            if (result->Leaf.PublicKeyLength != crypto::Ed448PublicKeyLength)
            {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            else
            {
                RtlCopyMemory(serverEd448PublicKey_, result->Leaf.PublicKey, result->Leaf.PublicKeyLength);
                serverEd448PublicKeyLength_ = result->Leaf.PublicKeyLength;
            }
        }
        else
        {
            status = tls::CertificateValidator::ImportSubjectPublicKey(providerCache_, result->Leaf, serverPublicKey_);
        }
    }
    RtlSecureZeroMemory(legacy.Get(), legacy.Count());
    return status;
}

NTSTATUS QuicTls::ProcessCertificateVerify(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                           SIZE_T encodedLength) noexcept
{
    tls::Tls13CertificateVerifyView certificateVerify = {};
    NTSTATUS status = tls::Tls13HandshakeMessages::ParseCertificateVerify(message, certificateVerify);
    HeapArray<UCHAR> transcriptHash(tls::TlsMaxTranscriptHashLength);
    if (!transcriptHash.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T transcriptHashLength = 0;
    if (NT_SUCCESS(status))
    {
        status = transcript_.Snapshot(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
    }
    if (NT_SUCCESS(status))
    {
        status = VerifyCertificateSignature(certificateVerify, transcriptHash.Get(), transcriptHashLength);
    }
    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(encoded, encodedLength);
    }
    if (NT_SUCCESS(status))
    {
        state_ = QuicTlsState::AwaitFinished;
    }
    return status;
}

NTSTATUS QuicTls::VerifyCertificateSignature(const tls::Tls13CertificateVerifyView &certificateVerify,
                                             const UCHAR *transcriptHash, SIZE_T transcriptHashLength) noexcept
{
    if (!SignatureSchemeMatchesPublicKey(serverPublicKeyAlgorithm_, certificateVerify.SignatureScheme))
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    HeapArray<UCHAR> signedInput(tls::Tls13CertificateVerifyInputMaxLength);
    if (!signedInput.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T signedInputLength = 0;
    NTSTATUS status = tls::Tls13HandshakeMessages::BuildCertificateVerifyInput(
        true, transcriptHash, transcriptHashLength, signedInput.Get(), signedInput.Count(), &signedInputLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (certificateVerify.SignatureScheme == tls::TlsSignatureScheme::Ed25519)
    {
        status = crypto::CngProvider::VerifyEd25519(serverEd25519PublicKey_, serverEd25519PublicKeyLength_,
                                                    signedInput.Get(), signedInputLength, certificateVerify.Signature,
                                                    certificateVerify.SignatureLength);
    }
    else if (certificateVerify.SignatureScheme == tls::TlsSignatureScheme::Ed448)
    {
        status = crypto::CngProvider::VerifyEd448(serverEd448PublicKey_, serverEd448PublicKeyLength_, signedInput.Get(),
                                                  signedInputLength, certificateVerify.Signature,
                                                  certificateVerify.SignatureLength);
    }
    else
    {
        HeapArray<UCHAR> hash(tls::TlsMaxTranscriptHashLength);
        if (!hash.IsValid())
        {
            RtlSecureZeroMemory(signedInput.Get(), signedInput.Count());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T hashLength = 0;
        status = crypto::CngProvider::Hash(providerCache_, HashForSignature(certificateVerify.SignatureScheme),
                                           signedInput.Get(), signedInputLength, hash.Get(), hash.Count(), &hashLength);
        crypto::SignatureAlgorithm signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        if (NT_SUCCESS(status))
        {
            status = ToSignatureAlgorithm(certificateVerify.SignatureScheme, &signatureAlgorithm);
        }
        if (NT_SUCCESS(status))
        {
            status = crypto::CngProvider::VerifySignature(providerCache_, signatureAlgorithm, serverPublicKey_,
                                                          hash.Get(), hashLength, certificateVerify.Signature,
                                                          certificateVerify.SignatureLength);
        }
        RtlSecureZeroMemory(hash.Get(), hash.Count());
    }
    RtlSecureZeroMemory(signedInput.Get(), signedInput.Count());
    return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
}

NTSTATUS QuicTls::SelectClientCredentialSignature(const tls::Tls13CertificateRequestView &request) noexcept
{
    sendClientCertificateVerify_ = false;
    if (clientCredential_ == nullptr || clientCredential_->CertificateList == nullptr ||
        clientCredential_->CertificateListLength == 0 || clientCredential_->Sign == nullptr)
    {
        return STATUS_SUCCESS;
    }

    tls::Tls13ExtensionView signatureAlgorithms = {};
    bool found = false;
    NTSTATUS status = tls::Tls13HandshakeMessages::FindExtensionView(
        request.Extensions, request.ExtensionsLength, ExtensionSignatureAlgorithms, signatureAlgorithms, &found);
    if (!NT_SUCCESS(status) || !found || signatureAlgorithms.Data == nullptr || signatureAlgorithms.Length < 4)
    {
        return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
    }
    const SIZE_T listLength = (static_cast<SIZE_T>(signatureAlgorithms.Data[0]) << 8) | signatureAlgorithms.Data[1];
    if (listLength == 0 || listLength != signatureAlgorithms.Length - 2 || (listLength & 1U) != 0)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    for (SIZE_T offset = 2; offset < signatureAlgorithms.Length; offset += 2)
    {
        const tls::TlsSignatureScheme scheme = static_cast<tls::TlsSignatureScheme>(
            (static_cast<USHORT>(signatureAlgorithms.Data[offset]) << 8) | signatureAlgorithms.Data[offset + 1]);
        if (ClientCredentialAllowsScheme(*clientCredential_, scheme))
        {
            clientCertificateSignatureScheme_ = scheme;
            sendClientCertificateVerify_ = true;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::AppendClientCredentialOutput(UCHAR *output, SIZE_T capacity, SIZE_T *offset) noexcept
{
    if (output == nullptr || offset == nullptr || *offset > capacity)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!certificateRequested_)
    {
        return STATUS_SUCCESS;
    }

    const UCHAR *certificateList = sendClientCertificateVerify_ ? clientCredential_->CertificateList : nullptr;
    const SIZE_T certificateListLength = sendClientCertificateVerify_ ? clientCredential_->CertificateListLength : 0;
    SIZE_T certificateLength = 0;
    NTSTATUS status = tls::Tls13HandshakeMessages::EncodeCertificate(
        certificateRequestContext_.Get(), certificateRequestContext_.Count(), certificateList, certificateListLength,
        output + *offset, capacity - *offset, &certificateLength);
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(output + *offset, certificateLength);
        *offset += certificateLength;
    }
    if (!NT_SUCCESS(status) || !sendClientCertificateVerify_)
    {
        return status;
    }

    HeapArray<UCHAR> transcriptHash(tls::TlsMaxTranscriptHashLength);
    HeapArray<UCHAR> signedInput(tls::Tls13CertificateVerifyInputMaxLength);
    HeapArray<UCHAR> signature(QuicTlsPendingOutputCapacity);
    if (!transcriptHash.IsValid() || !signedInput.IsValid() || !signature.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T transcriptHashLength = 0;
    status = transcript_.Snapshot(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
    SIZE_T signedInputLength = 0;
    if (NT_SUCCESS(status))
    {
        status = tls::Tls13HandshakeMessages::BuildCertificateVerifyInput(false, transcriptHash.Get(),
                                                                          transcriptHashLength, signedInput.Get(),
                                                                          signedInput.Count(), &signedInputLength);
    }
    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
    SIZE_T signatureLength = 0;
    if (NT_SUCCESS(status))
    {
        status = clientCredential_->Sign(
            clientCredential_->SignContext, static_cast<crypto::TlsSignatureScheme>(clientCertificateSignatureScheme_),
            signedInput.Get(), signedInputLength, signature.Get(), signature.Count(), &signatureLength);
    }
    RtlSecureZeroMemory(signedInput.Get(), signedInput.Count());
    SIZE_T certificateVerifyLength = 0;
    if (NT_SUCCESS(status))
    {
        status = tls::Tls13HandshakeMessages::EncodeCertificateVerify(
            clientCertificateSignatureScheme_, signature.Get(), signatureLength, output + *offset, capacity - *offset,
            &certificateVerifyLength);
    }
    RtlSecureZeroMemory(signature.Get(), signature.Count());
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(output + *offset, certificateVerifyLength);
        *offset += certificateVerifyLength;
    }
    return status;
}

NTSTATUS QuicTls::ProcessFinished(const tls::TlsHandshakeMessageView &message, const UCHAR *encoded,
                                  SIZE_T encodedLength) noexcept
{
    HeapArray<UCHAR> transcriptHash(tls::TlsMaxTranscriptHashLength);
    if (!transcriptHash.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SIZE_T transcriptHashLength = 0;
    NTSTATUS status = transcript_.Snapshot(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
    if (NT_SUCCESS(status))
    {
        status = tls::Tls13HandshakeMessages::VerifyFinished(context_, false, transcriptHash.Get(),
                                                             transcriptHashLength, message.Body, message.BodyLength);
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(encoded, encodedLength);
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.Snapshot(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
    }
    if (NT_SUCCESS(status))
    {
        status = context_.DeriveTls13ApplicationSecrets(transcriptHash.Get(), transcriptHashLength);
    }
    if (NT_SUCCESS(status))
    {
        status = InstallApplicationKeys();
    }
    if (NT_SUCCESS(status))
    {
        status = pendingHandshakeOutput_.Allocate(QuicTlsPendingOutputCapacity);
    }

    SIZE_T outputLength = 0;
    if (NT_SUCCESS(status) && certificateRequested_)
    {
        status =
            AppendClientCredentialOutput(pendingHandshakeOutput_.Get(), pendingHandshakeOutput_.Count(), &outputLength);
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.Snapshot(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
    }
    SIZE_T finishedLength = 0;
    if (NT_SUCCESS(status))
    {
        status = tls::Tls13HandshakeMessages::EncodeFinished(
            context_, true, transcriptHash.Get(), transcriptHashLength, pendingHandshakeOutput_.Get() + outputLength,
            pendingHandshakeOutput_.Count() - outputLength, &finishedLength);
    }
    if (NT_SUCCESS(status))
    {
        status = transcript_.Update(pendingHandshakeOutput_.Get() + outputLength, finishedLength);
        outputLength += finishedLength;
    }
    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (outputLength < pendingHandshakeOutput_.Count())
    {
        RtlSecureZeroMemory(pendingHandshakeOutput_.Get() + outputLength,
                            pendingHandshakeOutput_.Count() - outputLength);
    }
    pendingHandshakeOutputLength_ = outputLength;
    context_.SetState(tls::TlsHandshakeState::Established);
    state_ = QuicTlsState::Established;
    WKNET_TRACE(ComponentQuic, TraceLevel::Info, "quic.handshake.complete");
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::InstallApplicationKeys() noexcept
{
    const tls::Tls13TrafficSecrets &secrets = context_.Tls13Secrets();
    const QuicCipherSuite suite = ToQuicCipherSuite(context_.CipherSuite());
    NTSTATUS status = QuicInstallWriteSecret(suite, secrets.ClientApplicationTrafficSecret, secrets.SecretLength,
                                             &applicationWriteKey_);
    if (NT_SUCCESS(status))
    {
        status = QuicInstallReadSecret(suite, secrets.ServerApplicationTrafficSecret, secrets.SecretLength,
                                       &applicationReadKey_);
    }
    return status;
}

NTSTATUS QuicTls::TakeInitialOutput(UCHAR *output, SIZE_T capacity, SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (output == nullptr || bytesWritten == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!pendingInitialOutput_.IsValid() || pendingInitialOutputLength_ == 0)
    {
        return STATUS_NOT_FOUND;
    }
    if (capacity < pendingInitialOutputLength_)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(output, pendingInitialOutput_.Get(), pendingInitialOutputLength_);
    *bytesWritten = pendingInitialOutputLength_;
    RtlSecureZeroMemory(pendingInitialOutput_.Get(), pendingInitialOutput_.Count());
    pendingInitialOutput_.Reset();
    pendingInitialOutputLength_ = 0;
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::TakeHandshakeOutput(UCHAR *output, SIZE_T capacity, SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (output == nullptr || bytesWritten == nullptr || !pendingHandshakeOutput_.IsValid())
    {
        return STATUS_INVALID_PARAMETER;
    }
    const SIZE_T length = pendingHandshakeOutputLength_;
    if (capacity < length)
    {
        *bytesWritten = length;
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlCopyMemory(output, pendingHandshakeOutput_.Get(), length);
    *bytesWritten = length;
    RtlSecureZeroMemory(pendingHandshakeOutput_.Get(), pendingHandshakeOutput_.Count());
    pendingHandshakeOutput_.Reset();
    pendingHandshakeOutputLength_ = 0;
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::OnTlsAlert(UCHAR alertDescription) noexcept
{
    return Fail(STATUS_CONNECTION_ABORTED, QuicCryptoErrorBase + alertDescription);
}

NTSTATUS QuicTls::DiscardInitialKeys() noexcept
{
    if (state_ == QuicTlsState::Idle || state_ == QuicTlsState::AwaitServerHello ||
        state_ == QuicTlsState::AwaitSharedSecret || state_ == QuicTlsState::Failed)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!initialKeysDiscarded_)
    {
        levels_[LevelIndex(QuicEncryptionLevel::Initial)].Reassembly.Clear();
        levels_[LevelIndex(QuicEncryptionLevel::Initial)].ParseBuffer.Reset();
        levels_[LevelIndex(QuicEncryptionLevel::Initial)].ParseOffset = 0;
        levels_[LevelIndex(QuicEncryptionLevel::Initial)].ParseLength = 0;
        initialKeysDiscarded_ = true;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::ConfirmHandshake() noexcept
{
    if (state_ != QuicTlsState::Established)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!handshakeKeysDiscarded_)
    {
        QuicClearPacketKeySet(&handshakeWriteKey_);
        QuicClearPacketKeySet(&handshakeReadKey_);
        levels_[LevelIndex(QuicEncryptionLevel::Handshake)].Reassembly.Clear();
        levels_[LevelIndex(QuicEncryptionLevel::Handshake)].ParseBuffer.Reset();
        levels_[LevelIndex(QuicEncryptionLevel::Handshake)].ParseOffset = 0;
        levels_[LevelIndex(QuicEncryptionLevel::Handshake)].ParseLength = 0;
        handshakeKeysDiscarded_ = true;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicTls::Fail(NTSTATUS status, ULONGLONG transportError) noexcept
{
    if (state_ != QuicTlsState::Failed)
    {
        state_ = QuicTlsState::Failed;
        transportError_ = transportError == 0 ? QuicProtocolViolation : transportError;
        QuicClearPacketKeySet(&handshakeWriteKey_);
        QuicClearPacketKeySet(&handshakeReadKey_);
        QuicClearPacketKeySet(&applicationWriteKey_);
        QuicClearPacketKeySet(&applicationReadKey_);
        if (pendingHandshakeOutput_.IsValid())
        {
            RtlSecureZeroMemory(pendingHandshakeOutput_.Get(), pendingHandshakeOutput_.Count());
            pendingHandshakeOutput_.Reset();
            pendingHandshakeOutputLength_ = 0;
        }
        transcript_.Reset();
        context_.Reset();
        context_.SetState(tls::TlsHandshakeState::Failed);
        WKNET_TRACE(ComponentQuic, TraceLevel::Error, "quic.handshake.failed status=0x%08X transport_error=%I64u",
                    status, transportError_);
    }
    return status;
}
} // namespace wknet::quic
