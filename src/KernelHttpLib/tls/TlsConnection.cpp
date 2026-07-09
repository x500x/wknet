#include <KernelHttp/tls/TlsConnection.h>

#include <KernelHttp/KernelHttpLimits.h>
#include <KernelHttp/crypto/CngProviderCache.h>
#include <KernelHttp/crypto/Ed25519.h>
#include <KernelHttp/crypto/Ed448.h>
#include <KernelHttp/crypto/KeyExchange.h>
#include <KernelHttp/tls/TlsCapabilities.h>
#include <KernelHttp/tls/TlsHandshake13.h>

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <time.h>
#endif

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        constexpr SIZE_T TlsScratchClientHelloOffset = 0;
        constexpr SIZE_T TlsScratchClientHelloLength = 4096;
        constexpr SIZE_T TlsScratchFirstClientHelloOffset =
            TlsScratchClientHelloOffset + TlsScratchClientHelloLength;
        constexpr SIZE_T TlsScratchFirstClientHelloLength = 4096;
        constexpr SIZE_T TlsScratchSecondClientHelloOffset =
            TlsScratchFirstClientHelloOffset + TlsScratchFirstClientHelloLength;
        constexpr SIZE_T TlsScratchSecondClientHelloLength = 4096;
        constexpr SIZE_T TlsScratchHelloRetryOffset =
            TlsScratchSecondClientHelloOffset + TlsScratchSecondClientHelloLength;
        constexpr SIZE_T TlsScratchHelloRetryLength = 512;
        constexpr SIZE_T TlsScratchLegacyCertificateOffset =
            TlsScratchHelloRetryOffset + TlsScratchHelloRetryLength;
        constexpr SIZE_T TlsScratchLegacyCertificateLength = TlsHandshakeBufferLength;
        constexpr SIZE_T TlsScratchSignedInputOffset =
            TlsScratchLegacyCertificateOffset + TlsScratchLegacyCertificateLength;
        constexpr SIZE_T TlsScratchSignedInputLength = Tls13CertificateVerifyInputMaxLength;
        constexpr SIZE_T TlsScratchSignedDataOffset =
            TlsScratchSignedInputOffset + TlsScratchSignedInputLength;
        constexpr SIZE_T TlsScratchSignedDataLength = (TlsRandomLength * 2) + (crypto::KeyExchangeMaxPublicKeyLength * 2) + 16;
        constexpr SIZE_T TlsScratchHandshakeBufferOffset =
            TlsScratchSignedDataOffset + TlsScratchSignedDataLength;
        constexpr SIZE_T TlsScratchHandshakeBufferLength = TlsHandshakeBufferLength;
        constexpr SIZE_T TlsScratchRequiredLength =
            TlsScratchHandshakeBufferOffset + TlsScratchHandshakeBufferLength;

        LONG ExchangeTlsFlag(_Inout_ volatile LONG* target, LONG value) noexcept
        {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            const LONG previous = *target;
            *target = value;
            return previous;
#else
            return InterlockedExchange(target, value);
#endif
        }

        _Must_inspect_result_
        Tls12KeyExchangeKind Tls12KeyExchangeForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
            return capability != nullptr ? capability->Tls12KeyExchange : Tls12KeyExchangeKind::None;
        }

        struct Tls12ServerKeyExchangeDiagnostic final
        {
            UCHAR CurveType = 0;
            USHORT NamedGroup = 0;
            UCHAR EcPointLength = 0;
            USHORT SignatureScheme = 0;
            USHORT SignatureLength = 0;
            SIZE_T Offset = 0;
        };

        bool TryReadDiagnosticUint16(
            _In_reads_bytes_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Inout_ SIZE_T* offset,
            _Out_ USHORT* value) noexcept
        {
            if (body == nullptr || offset == nullptr || value == nullptr ||
                *offset > bodyLength || bodyLength - *offset < sizeof(USHORT)) {
                return false;
            }

            *value = static_cast<USHORT>(
                (static_cast<USHORT>(body[*offset]) << 8) |
                static_cast<USHORT>(body[*offset + 1]));
            *offset += sizeof(USHORT);
            return true;
        }

        bool TrySkipDiagnosticOpaque16(
            _In_reads_bytes_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Inout_ SIZE_T* offset) noexcept
        {
            USHORT length = 0;
            if (!TryReadDiagnosticUint16(body, bodyLength, offset, &length)) {
                return false;
            }
            if (*offset > bodyLength || static_cast<SIZE_T>(length) > bodyLength - *offset) {
                return false;
            }

            *offset += length;
            return true;
        }

        void CaptureServerKeyExchangeDiagnostic(
            Tls12KeyExchangeKind keyExchangeKind,
            _In_ const TlsHandshakeMessageView& handshake,
            _Out_ Tls12ServerKeyExchangeDiagnostic* diagnostic) noexcept
        {
            if (diagnostic == nullptr) {
                return;
            }

            *diagnostic = {};
            const UCHAR* body = handshake.Body;
            const SIZE_T bodyLength = handshake.BodyLength;
            if (body == nullptr || bodyLength == 0) {
                return;
            }

            SIZE_T offset = 0;
            if (keyExchangeKind == Tls12KeyExchangeKind::EcdheRsa ||
                keyExchangeKind == Tls12KeyExchangeKind::EcdheEcdsa) {
                diagnostic->CurveType = body[offset++];
                diagnostic->Offset = offset;

                if (!TryReadDiagnosticUint16(body, bodyLength, &offset, &diagnostic->NamedGroup)) {
                    return;
                }
                diagnostic->Offset = offset;

                if (offset >= bodyLength) {
                    return;
                }
                diagnostic->EcPointLength = body[offset++];
                diagnostic->Offset = offset;

                if (static_cast<SIZE_T>(diagnostic->EcPointLength) > bodyLength - offset) {
                    return;
                }
                offset += diagnostic->EcPointLength;
                diagnostic->Offset = offset;
            }
            else if (keyExchangeKind == Tls12KeyExchangeKind::DheRsa) {
                if (!TrySkipDiagnosticOpaque16(body, bodyLength, &offset)) {
                    diagnostic->Offset = offset;
                    return;
                }
                if (!TrySkipDiagnosticOpaque16(body, bodyLength, &offset)) {
                    diagnostic->Offset = offset;
                    return;
                }
                if (!TrySkipDiagnosticOpaque16(body, bodyLength, &offset)) {
                    diagnostic->Offset = offset;
                    return;
                }
                diagnostic->Offset = offset;
            }
            else {
                return;
            }

            if (!TryReadDiagnosticUint16(body, bodyLength, &offset, &diagnostic->SignatureScheme)) {
                return;
            }
            diagnostic->Offset = offset;

            if (!TryReadDiagnosticUint16(body, bodyLength, &offset, &diagnostic->SignatureLength)) {
                return;
            }
            diagnostic->Offset = offset;

            if (static_cast<SIZE_T>(diagnostic->SignatureLength) > bodyLength - offset) {
                return;
            }
            offset += diagnostic->SignatureLength;
            diagnostic->Offset = offset;
        }

        void LogServerKeyExchangeParseFailure(
            NTSTATUS status,
            TlsCipherSuite cipherSuite,
            Tls12KeyExchangeKind keyExchangeKind,
            _In_ const TlsHandshakeMessageView& handshake) noexcept
        {
            Tls12ServerKeyExchangeDiagnostic diagnostic = {};
            CaptureServerKeyExchangeDiagnostic(keyExchangeKind, handshake, &diagnostic);

            kprintf(
                "TlsConnection parse ServerKeyExchange failed: 0x%08X cipher=0x%04X kx=%u type=%u body=%Iu curve=%u group=%u point=%u sig=0x%04X sigLen=%u offset=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(cipherSuite),
                static_cast<unsigned>(keyExchangeKind),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength,
                static_cast<unsigned>(diagnostic.CurveType),
                static_cast<unsigned>(diagnostic.NamedGroup),
                static_cast<unsigned>(diagnostic.EcPointLength),
                static_cast<unsigned>(diagnostic.SignatureScheme),
                static_cast<unsigned>(diagnostic.SignatureLength),
                diagnostic.Offset);
        }

        _Must_inspect_result_
        SIZE_T Tls12AeadKeyLengthForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            switch (cipherSuite) {
            case TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384:
            case TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384:
            case TlsCipherSuite::TlsDheRsaWithAes256GcmSha384:
            case TlsCipherSuite::TlsRsaWithAes256GcmSha384:
            case TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsDheRsaWithChaCha20Poly1305Sha256:
                return 32;
            default:
                return 16;
            }
        }

        _Must_inspect_result_
        SIZE_T Tls12MacKeyLengthForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
            if (capability == nullptr) {
                return 0;
            }

            switch (capability->RecordMac) {
            case TlsRecordMacKind::HmacSha384:
                return 48;
            case TlsRecordMacKind::HmacSha256:
                return 32;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        SIZE_T Tls12FixedIvLengthForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
            if (capability != nullptr && capability->BulkCipher == TlsBulkCipherKind::AesCbc) {
                return 0;
            }
            return TlsAesGcmFixedIvLength;
        }

        _Must_inspect_result_
        NTSTATUS EncodeClientKeyExchangeOpaque16(
            _In_reads_bytes_(publicKeyLength) const UCHAR* publicKey,
            SIZE_T publicKeyLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }
            if (publicKey == nullptr ||
                publicKeyLength == 0 ||
                publicKeyLength > 0xffff ||
                destination == nullptr ||
                bytesWritten == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            const SIZE_T bodyLength = sizeof(USHORT) + publicKeyLength;
            const SIZE_T required = TlsHandshakeHeaderLength + bodyLength;
            if (destinationCapacity < required) {
                *bytesWritten = required;
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[0] = static_cast<UCHAR>(TlsHandshakeType::ClientKeyExchange);
            destination[1] = static_cast<UCHAR>((bodyLength >> 16) & 0xff);
            destination[2] = static_cast<UCHAR>((bodyLength >> 8) & 0xff);
            destination[3] = static_cast<UCHAR>(bodyLength & 0xff);
            destination[4] = static_cast<UCHAR>((publicKeyLength >> 8) & 0xff);
            destination[5] = static_cast<UCHAR>(publicKeyLength & 0xff);
            RtlCopyMemory(destination + 6, publicKey, publicKeyLength);
            *bytesWritten = required;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        SIZE_T ReadLittleEndianUint32(_In_reads_bytes_(sizeof(ULONG)) const UCHAR* data) noexcept
        {
            return static_cast<SIZE_T>(data[0]) |
                (static_cast<SIZE_T>(data[1]) << 8) |
                (static_cast<SIZE_T>(data[2]) << 16) |
                (static_cast<SIZE_T>(data[3]) << 24);
        }

        _Must_inspect_result_
        NTSTATUS ExportTlsEcPoint(
            _In_ const crypto::CngKey& privateKey,
            _Out_writes_bytes_(publicPointCapacity) UCHAR* publicPoint,
            SIZE_T publicPointCapacity,
            _Out_ SIZE_T* publicPointLength) noexcept
        {
            constexpr SIZE_T EccPublicBlobHeaderLength = sizeof(ULONG) * 2;
            constexpr SIZE_T EccPublicBlobMaxCoordinateLength = 66;

            if (publicPointLength != nullptr) {
                *publicPointLength = 0;
            }
            if (publicPoint == nullptr || publicPointCapacity == 0 || publicPointLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<UCHAR> publicBlob(EccPublicBlobHeaderLength + (EccPublicBlobMaxCoordinateLength * 2));
            if (!publicBlob.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T publicBlobLength = 0;
            NTSTATUS status = privateKey.ExportPublicKey(
                L"ECCPUBLICBLOB",
                publicBlob.Get(),
                publicBlob.Count(),
                &publicBlobLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (publicBlobLength != 0 && publicBlob[0] == 4) {
                if (publicBlobLength != 65 && publicBlobLength != 97 && publicBlobLength != 133) {
                    RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (publicBlobLength > publicPointCapacity) {
                    RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                    *publicPointLength = publicBlobLength;
                    return STATUS_BUFFER_TOO_SMALL;
                }

                RtlCopyMemory(publicPoint, publicBlob.Get(), publicBlobLength);
                *publicPointLength = publicBlobLength;
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                return STATUS_SUCCESS;
            }
            if (publicBlobLength < EccPublicBlobHeaderLength) {
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T keyBytes = ReadLittleEndianUint32(publicBlob.Get() + sizeof(ULONG));
            const SIZE_T coordinatesLength = keyBytes * 2;
            const SIZE_T pointLength = coordinatesLength + 1;
            if (keyBytes == 0 ||
                keyBytes > EccPublicBlobMaxCoordinateLength ||
                coordinatesLength > publicBlobLength - EccPublicBlobHeaderLength) {
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (pointLength > publicPointCapacity) {
                RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
                *publicPointLength = pointLength;
                return STATUS_BUFFER_TOO_SMALL;
            }

            publicPoint[0] = 4;
            RtlCopyMemory(publicPoint + 1, publicBlob.Get() + EccPublicBlobHeaderLength, coordinatesLength);
            *publicPointLength = pointLength;
            RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        crypto::EcCurve ToEcCurve(TlsNamedGroup group) noexcept
        {
            switch (group) {
            case TlsNamedGroup::Secp256r1:
                return crypto::EcCurve::P256;
            case TlsNamedGroup::Secp384r1:
                return crypto::EcCurve::P384;
            case TlsNamedGroup::Secp521r1:
                return crypto::EcCurve::P521;
            default:
                return crypto::EcCurve::P256;
            }
        }

        _Must_inspect_result_
        NTSTATUS ToKeyExchangeGroup(TlsNamedGroup group, _Out_ crypto::KeyExchangeGroup* keyExchangeGroup) noexcept
        {
            if (keyExchangeGroup == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            switch (group) {
            case TlsNamedGroup::Secp256r1:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Secp256r1;
                return STATUS_SUCCESS;
            case TlsNamedGroup::Secp384r1:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Secp384r1;
                return STATUS_SUCCESS;
            case TlsNamedGroup::Secp521r1:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Secp521r1;
                return STATUS_SUCCESS;
            case TlsNamedGroup::X25519:
                *keyExchangeGroup = crypto::KeyExchangeGroup::X25519;
                return STATUS_SUCCESS;
            case TlsNamedGroup::X448:
                *keyExchangeGroup = crypto::KeyExchangeGroup::X448;
                return STATUS_SUCCESS;
            case TlsNamedGroup::Ffdhe2048:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Ffdhe2048;
                return STATUS_SUCCESS;
            case TlsNamedGroup::Ffdhe3072:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Ffdhe3072;
                return STATUS_SUCCESS;
            case TlsNamedGroup::Ffdhe4096:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Ffdhe4096;
                return STATUS_SUCCESS;
            case TlsNamedGroup::Ffdhe6144:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Ffdhe6144;
                return STATUS_SUCCESS;
            case TlsNamedGroup::Ffdhe8192:
                *keyExchangeGroup = crypto::KeyExchangeGroup::Ffdhe8192;
                return STATUS_SUCCESS;
            default:
                return STATUS_NOT_SUPPORTED;
            }
        }

        _Must_inspect_result_
        NTSTATUS ToSignatureAlgorithm(
            TlsSignatureScheme scheme,
            _Out_ crypto::SignatureAlgorithm* algorithm) noexcept
        {
            if (algorithm == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            switch (scheme) {
            case TlsSignatureScheme::RsaPkcs1Sha1:
                *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha1;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPkcs1Sha256:
                *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPkcs1Sha384:
                *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha384;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPkcs1Sha512:
                *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha512;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPssRsaeSha256:
            case TlsSignatureScheme::RsaPssPssSha256:
                *algorithm = crypto::SignatureAlgorithm::RsaPssSha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPssRsaeSha384:
            case TlsSignatureScheme::RsaPssPssSha384:
                *algorithm = crypto::SignatureAlgorithm::RsaPssSha384;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPssRsaeSha512:
            case TlsSignatureScheme::RsaPssPssSha512:
                *algorithm = crypto::SignatureAlgorithm::RsaPssSha512;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSha1:
                *algorithm = crypto::SignatureAlgorithm::EcdsaSha1;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSecp256r1Sha256:
                *algorithm = crypto::SignatureAlgorithm::EcdsaSha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSecp384r1Sha384:
                *algorithm = crypto::SignatureAlgorithm::EcdsaSha384;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSecp521r1Sha512:
                *algorithm = crypto::SignatureAlgorithm::EcdsaSha512;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::Ed25519:
                *algorithm = crypto::SignatureAlgorithm::Ed25519;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::Ed448:
                *algorithm = crypto::SignatureAlgorithm::Ed448;
                return STATUS_SUCCESS;
            default:
                return STATUS_NOT_SUPPORTED;
            }
        }

        _Must_inspect_result_
        crypto::HashAlgorithm HashForSignature(TlsSignatureScheme scheme) noexcept
        {
            switch (scheme) {
            case TlsSignatureScheme::RsaPkcs1Sha1:
            case TlsSignatureScheme::EcdsaSha1:
                return crypto::HashAlgorithm::Sha1;
            case TlsSignatureScheme::RsaPkcs1Sha512:
            case TlsSignatureScheme::RsaPssRsaeSha512:
            case TlsSignatureScheme::RsaPssPssSha512:
            case TlsSignatureScheme::EcdsaSecp521r1Sha512:
            case TlsSignatureScheme::Ed25519:
            case TlsSignatureScheme::Ed448:
                return crypto::HashAlgorithm::Sha512;
            case TlsSignatureScheme::RsaPkcs1Sha384:
            case TlsSignatureScheme::RsaPssRsaeSha384:
            case TlsSignatureScheme::RsaPssPssSha384:
            case TlsSignatureScheme::EcdsaSecp384r1Sha384:
                return crypto::HashAlgorithm::Sha384;
            default:
                return crypto::HashAlgorithm::Sha256;
            }
        }

        _Must_inspect_result_
        bool SignatureSchemeMatchesPublicKey(
            CertificatePublicKeyAlgorithm publicKeyAlgorithm,
            TlsSignatureScheme scheme) noexcept
        {
            switch (publicKeyAlgorithm) {
            case CertificatePublicKeyAlgorithm::Rsa:
                switch (scheme) {
                case TlsSignatureScheme::RsaPkcs1Sha1:
                case TlsSignatureScheme::RsaPkcs1Sha256:
                case TlsSignatureScheme::RsaPkcs1Sha384:
                case TlsSignatureScheme::RsaPkcs1Sha512:
                case TlsSignatureScheme::RsaPssRsaeSha256:
                case TlsSignatureScheme::RsaPssRsaeSha384:
                case TlsSignatureScheme::RsaPssRsaeSha512:
                    return true;
                default:
                    return false;
                }
            case CertificatePublicKeyAlgorithm::EcdsaP256:
                return scheme == TlsSignatureScheme::EcdsaSha1 ||
                    scheme == TlsSignatureScheme::EcdsaSecp256r1Sha256;
            case CertificatePublicKeyAlgorithm::EcdsaP384:
                return scheme == TlsSignatureScheme::EcdsaSha1 ||
                    scheme == TlsSignatureScheme::EcdsaSecp384r1Sha384;
            case CertificatePublicKeyAlgorithm::EcdsaP521:
                return scheme == TlsSignatureScheme::EcdsaSha1 ||
                    scheme == TlsSignatureScheme::EcdsaSecp521r1Sha512;
            case CertificatePublicKeyAlgorithm::Ed25519:
                return scheme == TlsSignatureScheme::Ed25519;
            case CertificatePublicKeyAlgorithm::Ed448:
                return scheme == TlsSignatureScheme::Ed448;
            default:
                return false;
            }
        }

        _Must_inspect_result_
        bool SignatureSchemeMatchesClientCredential(
            const TlsClientCredential& credential,
            TlsSignatureScheme scheme) noexcept
        {
            if (!credential.AllowsDigitalSignature || credential.Sign == nullptr) {
                return false;
            }

            switch (credential.KeyAlgorithm) {
            case TlsClientCredentialKeyAlgorithm::Rsa:
                switch (scheme) {
                case TlsSignatureScheme::RsaPkcs1Sha1:
                case TlsSignatureScheme::RsaPkcs1Sha256:
                case TlsSignatureScheme::RsaPkcs1Sha384:
                case TlsSignatureScheme::RsaPkcs1Sha512:
                case TlsSignatureScheme::RsaPssRsaeSha256:
                case TlsSignatureScheme::RsaPssRsaeSha384:
                case TlsSignatureScheme::RsaPssRsaeSha512:
                    return true;
                default:
                    return false;
                }
            case TlsClientCredentialKeyAlgorithm::RsaPss:
                return scheme == TlsSignatureScheme::RsaPssPssSha256 ||
                    scheme == TlsSignatureScheme::RsaPssPssSha384 ||
                    scheme == TlsSignatureScheme::RsaPssPssSha512;
            case TlsClientCredentialKeyAlgorithm::EcdsaP256:
                return scheme == TlsSignatureScheme::EcdsaSha1 ||
                    scheme == TlsSignatureScheme::EcdsaSecp256r1Sha256;
            case TlsClientCredentialKeyAlgorithm::EcdsaP384:
                return scheme == TlsSignatureScheme::EcdsaSha1 ||
                    scheme == TlsSignatureScheme::EcdsaSecp384r1Sha384;
            case TlsClientCredentialKeyAlgorithm::EcdsaP521:
                return scheme == TlsSignatureScheme::EcdsaSha1 ||
                    scheme == TlsSignatureScheme::EcdsaSecp521r1Sha512;
            case TlsClientCredentialKeyAlgorithm::Ed25519:
                return scheme == TlsSignatureScheme::Ed25519;
            case TlsClientCredentialKeyAlgorithm::Ed448:
                return scheme == TlsSignatureScheme::Ed448;
            default:
                return false;
            }
        }

        const TlsNamedGroup TlsDefaultOfferNamedGroups[] = {
            TlsNamedGroup::X25519,
            TlsNamedGroup::X448,
            TlsNamedGroup::Secp256r1,
            TlsNamedGroup::Secp384r1,
            TlsNamedGroup::Secp521r1,
            TlsNamedGroup::Ffdhe2048,
            TlsNamedGroup::Ffdhe3072,
            TlsNamedGroup::Ffdhe4096,
            TlsNamedGroup::Ffdhe6144,
            TlsNamedGroup::Ffdhe8192
        };

        const TlsSignatureScheme TlsDefaultOfferSignatureSchemes[] = {
            TlsSignatureScheme::RsaPssRsaeSha256,
            TlsSignatureScheme::RsaPssRsaeSha384,
            TlsSignatureScheme::RsaPssRsaeSha512,
            TlsSignatureScheme::EcdsaSecp256r1Sha256,
            TlsSignatureScheme::EcdsaSecp384r1Sha384,
            TlsSignatureScheme::EcdsaSecp521r1Sha512,
            TlsSignatureScheme::Ed25519,
            TlsSignatureScheme::Ed448,
            TlsSignatureScheme::RsaPssPssSha256,
            TlsSignatureScheme::RsaPssPssSha384,
            TlsSignatureScheme::RsaPssPssSha512,
            TlsSignatureScheme::RsaPkcs1Sha256,
            TlsSignatureScheme::RsaPkcs1Sha384,
            TlsSignatureScheme::RsaPkcs1Sha512,
            TlsSignatureScheme::RsaPkcs1Sha1,
            TlsSignatureScheme::EcdsaSha1
        };

        _Must_inspect_result_
        NTSTATUS BuildTls12PolicyOffers(
            _In_ const TlsPolicy& policy,
            _Inout_ HeapArray<TlsCipherSuite>& cipherSuites,
            _Out_ SIZE_T* cipherSuiteCount,
            _Inout_ HeapArray<TlsNamedGroup>& namedGroups,
            _Out_ SIZE_T* namedGroupCount,
            _Inout_ HeapArray<TlsSignatureScheme>& signatureSchemes,
            _Out_ SIZE_T* signatureSchemeCount) noexcept
        {
            if (cipherSuiteCount == nullptr || namedGroupCount == nullptr || signatureSchemeCount == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *cipherSuiteCount = 0;
            *namedGroupCount = 0;
            *signatureSchemeCount = 0;

            NTSTATUS status = cipherSuites.Allocate(TlsCipherSuiteCapabilityCount());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = namedGroups.Allocate(sizeof(TlsDefaultOfferNamedGroups) / sizeof(TlsDefaultOfferNamedGroups[0]));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = signatureSchemes.Allocate(sizeof(TlsDefaultOfferSignatureSchemes) / sizeof(TlsDefaultOfferSignatureSchemes[0]));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            for (SIZE_T index = 0; index < TlsCipherSuiteCapabilityCount(); ++index) {
                const TlsCipherSuiteCapability* capability = TlsCipherSuiteCapabilityAt(index);
                if (capability != nullptr &&
                    capability->Protocol == TlsProtocol::Tls12 &&
                    TlsPolicyAllowsCipherSuite(policy, capability->CipherSuite)) {
                    cipherSuites[*cipherSuiteCount] = capability->CipherSuite;
                    ++(*cipherSuiteCount);
                }
            }

            for (SIZE_T index = 0; index < sizeof(TlsDefaultOfferNamedGroups) / sizeof(TlsDefaultOfferNamedGroups[0]); ++index) {
                if (TlsPolicyAllowsNamedGroup(policy, TlsDefaultOfferNamedGroups[index])) {
                    namedGroups[*namedGroupCount] = TlsDefaultOfferNamedGroups[index];
                    ++(*namedGroupCount);
                }
            }

            for (SIZE_T index = 0; index < sizeof(TlsDefaultOfferSignatureSchemes) / sizeof(TlsDefaultOfferSignatureSchemes[0]); ++index) {
                if (TlsPolicyAllowsSignatureScheme(policy, TlsDefaultOfferSignatureSchemes[index])) {
                    signatureSchemes[*signatureSchemeCount] = TlsDefaultOfferSignatureSchemes[index];
                    ++(*signatureSchemeCount);
                }
            }

            return *cipherSuiteCount == 0 || *namedGroupCount == 0 || *signatureSchemeCount == 0 ?
                STATUS_NOT_SUPPORTED :
                STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsValidBuffer(const void* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        NTSTATUS LogTls13Failure(_In_z_ const char* stage, NTSTATUS status) noexcept
        {
#if defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
            kprintf("TlsConnection TLS1.3 %s failed: 0x%08X\r\n", stage, static_cast<ULONG>(status));
#else
            UNREFERENCED_PARAMETER(stage);
#endif
            return status;
        }

        _Must_inspect_result_
        TlsHandshakeFailureCategory CategoryForPeerAlert(const TlsAlert& alert) noexcept
        {
            switch (alert.Description) {
            case TlsAlertDescription::ProtocolVersion:
                return TlsHandshakeFailureCategory::VersionNegotiation;
            case TlsAlertDescription::BadCertificate:
                return TlsHandshakeFailureCategory::CertificateValidation;
            default:
                return TlsHandshakeFailureCategory::PeerAlert;
            }
        }

        _Must_inspect_result_
        TlsHandshakeFailureCategory CategoryForStatus(NTSTATUS status) noexcept
        {
            switch (status) {
            case STATUS_TRUST_FAILURE:
            case STATUS_INVALID_SIGNATURE:
                return TlsHandshakeFailureCategory::CertificateValidation;
            case STATUS_IO_TIMEOUT:
            case STATUS_CONNECTION_ABORTED:
            case STATUS_CONNECTION_DISCONNECTED:
            case STATUS_CONNECTION_RESET:
                return TlsHandshakeFailureCategory::NetworkIo;
            case STATUS_INVALID_NETWORK_RESPONSE:
                return TlsHandshakeFailureCategory::DecodeError;
            case STATUS_NOT_SUPPORTED:
                return TlsHandshakeFailureCategory::LocalPolicy;
            case STATUS_INVALID_PARAMETER:
                return TlsHandshakeFailureCategory::LocalPolicy;
            default:
                return TlsHandshakeFailureCategory::CryptoError;
            }
        }

        _Must_inspect_result_
        ULONGLONG CurrentMilliseconds() noexcept
        {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
            return static_cast<ULONGLONG>(time(nullptr)) * 1000ULL;
#else
            LARGE_INTEGER now = {};
            KeQuerySystemTimePrecise(&now);
            return static_cast<ULONGLONG>(now.QuadPart / 10000LL);
#endif
        }

        _Must_inspect_result_
        bool AddMilliseconds(ULONGLONG value, ULONG delta, _Out_ ULONGLONG* result) noexcept
        {
            if (result == nullptr) {
                return false;
            }

            const ULONGLONG addend = static_cast<ULONGLONG>(delta);
            if (value > (~0ULL - addend)) {
                return false;
            }

            *result = value + addend;
            return true;
        }

        _Must_inspect_result_
        TlsReceiveDeadline MakeReceiveDeadline(ULONG timeoutMilliseconds) noexcept
        {
            TlsReceiveDeadline deadline = {};
            if (timeoutMilliseconds == 0 || timeoutMilliseconds == 0xffffffffUL) {
                return deadline;
            }

            ULONGLONG expiresAt = 0;
            if (AddMilliseconds(CurrentMilliseconds(), timeoutMilliseconds, &expiresAt)) {
                deadline.Enabled = true;
                deadline.DeadlineMilliseconds = expiresAt;
            }

            return deadline;
        }

        _Must_inspect_result_
        NTSTATUS RemainingReceiveTimeout(
            ULONG defaultTimeoutMilliseconds,
            _In_opt_ const TlsReceiveDeadline* deadline,
            _Out_ ULONG* timeoutMilliseconds) noexcept
        {
            if (timeoutMilliseconds == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *timeoutMilliseconds = defaultTimeoutMilliseconds;
            if (deadline == nullptr || !deadline->Enabled) {
                return STATUS_SUCCESS;
            }

            const ULONGLONG now = CurrentMilliseconds();
            if (now >= deadline->DeadlineMilliseconds) {
                return STATUS_IO_TIMEOUT;
            }

            ULONGLONG remaining = deadline->DeadlineMilliseconds - now;
            if (remaining == 0) {
                return STATUS_IO_TIMEOUT;
            }

            if (remaining > static_cast<ULONGLONG>(0xffffffffUL)) {
                remaining = 0xffffffffUL;
            }

            const ULONG boundedRemaining = static_cast<ULONG>(remaining);
            if (defaultTimeoutMilliseconds == 0xffffffffUL) {
                *timeoutMilliseconds = boundedRemaining;
            }
            else {
                *timeoutMilliseconds =
                    boundedRemaining < defaultTimeoutMilliseconds ? boundedRemaining : defaultTimeoutMilliseconds;
            }

            if (*timeoutMilliseconds == 0) {
                *timeoutMilliseconds = 1;
            }

            return STATUS_SUCCESS;
        }

        constexpr USHORT TlsExtensionSessionTicket = 35;
        constexpr USHORT TlsExtensionAlpn = 16;
        constexpr UCHAR Tls13DowngradeSentinelTls12[8] = {
            'D', 'O', 'W', 'N', 'G', 'R', 'D', 0x01
        };
        constexpr UCHAR Tls13DowngradeSentinelTls11[8] = {
            'D', 'O', 'W', 'N', 'G', 'R', 'D', 0x00
        };

        enum class Tls13ServerHelloVersionSelection : ULONG
        {
            NotTls12 = 0,
            Tls12Selected = 1,
            RejectedDowngrade = 2
        };

        _Must_inspect_result_
        bool ProtocolAllowed(const TlsClientConnectionOptions& options, TlsProtocol protocol) noexcept
        {
            return static_cast<UCHAR>(options.MinimumProtocol) <= static_cast<UCHAR>(protocol) &&
                static_cast<UCHAR>(protocol) <= static_cast<UCHAR>(options.MaximumProtocol);
        }

        _Must_inspect_result_
        bool CanConfirmTls12FromTls13Attempt(const TlsClientConnectionOptions& options) noexcept
        {
            return ProtocolAllowed(options, TlsProtocol::Tls12) &&
                ProtocolAllowed(options, TlsProtocol::Tls13) &&
                (!options.EnableEarlyData ||
                    options.EarlyData == nullptr ||
                    options.EarlyDataLength == 0);
        }

        _Must_inspect_result_
        bool HasTls13DowngradeSentinel(const TlsServerHelloView& serverHello) noexcept
        {
            if (serverHello.Random == nullptr ||
                serverHello.RandomLength < sizeof(Tls13DowngradeSentinelTls12)) {
                return false;
            }

            const UCHAR* sentinel =
                serverHello.Random + serverHello.RandomLength - sizeof(Tls13DowngradeSentinelTls12);
            return RtlCompareMemory(
                    sentinel,
                    Tls13DowngradeSentinelTls12,
                    sizeof(Tls13DowngradeSentinelTls12)) == sizeof(Tls13DowngradeSentinelTls12) ||
                RtlCompareMemory(
                    sentinel,
                    Tls13DowngradeSentinelTls11,
                    sizeof(Tls13DowngradeSentinelTls11)) == sizeof(Tls13DowngradeSentinelTls11);
        }

        _Must_inspect_result_
        Tls13ServerHelloVersionSelection ClassifyTls12ServerHelloFromTls13Attempt(
            const TlsClientConnectionOptions& options,
            const TlsHandshakeMessageView& handshake) noexcept
        {
            if (!CanConfirmTls12FromTls13Attempt(options)) {
                return Tls13ServerHelloVersionSelection::NotTls12;
            }

            TlsContext tls12Context;
            NTSTATUS status = tls12Context.InitializeClient({ 3, 3 });
            if (!NT_SUCCESS(status)) {
                return Tls13ServerHelloVersionSelection::NotTls12;
            }

            TlsServerHelloView tls12ServerHello = {};
            status = TlsHandshake12::ParseServerHello(tls12Context, handshake, tls12ServerHello);
            if (!NT_SUCCESS(status)) {
                return Tls13ServerHelloVersionSelection::NotTls12;
            }

            if (HasTls13DowngradeSentinel(tls12ServerHello)) {
                return Tls13ServerHelloVersionSelection::RejectedDowngrade;
            }

            return Tls13ServerHelloVersionSelection::Tls12Selected;
        }

        _Must_inspect_result_
        NTSTATUS ServerHelloHasEmptyExtension(
            const TlsServerHelloView& serverHello,
            USHORT extensionType,
            bool* found) noexcept
        {
            if (found == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *found = false;
            if (serverHello.ExtensionsLength == 0) {
                return STATUS_SUCCESS;
            }

            if (serverHello.Extensions == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < serverHello.ExtensionsLength) {
                if (serverHello.ExtensionsLength - offset < 4) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const USHORT currentType = static_cast<USHORT>(
                    (static_cast<USHORT>(serverHello.Extensions[offset]) << 8) |
                    serverHello.Extensions[offset + 1]);
                const SIZE_T currentLength =
                    (static_cast<SIZE_T>(serverHello.Extensions[offset + 2]) << 8) |
                    serverHello.Extensions[offset + 3];
                offset += 4;

                if (currentLength > serverHello.ExtensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (currentType == extensionType) {
                    if (*found || currentLength != 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    *found = true;
                }

                offset += currentLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseServerHelloAlpn(
            const TlsServerHelloView& serverHello,
            char* alpnOut,
            SIZE_T alpnCapacity,
            SIZE_T* alpnLength) noexcept
        {
            if (alpnOut == nullptr || alpnLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *alpnLength = 0;

            if (serverHello.ExtensionsLength == 0 || serverHello.Extensions == nullptr) {
                return STATUS_SUCCESS;
            }

            SIZE_T offset = 0;
            while (offset < serverHello.ExtensionsLength) {
                if (serverHello.ExtensionsLength - offset < 4) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const USHORT currentType = static_cast<USHORT>(
                    (static_cast<USHORT>(serverHello.Extensions[offset]) << 8) |
                    serverHello.Extensions[offset + 1]);
                const SIZE_T currentLength =
                    (static_cast<SIZE_T>(serverHello.Extensions[offset + 2]) << 8) |
                    serverHello.Extensions[offset + 3];
                offset += 4;

                if (currentLength > serverHello.ExtensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (currentType == TlsExtensionAlpn) {
                    if (currentLength < 4) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const UCHAR* extData = serverHello.Extensions + offset;
                    const SIZE_T listLength =
                        (static_cast<SIZE_T>(extData[0]) << 8) | extData[1];
                    if (listLength != currentLength - 2 || listLength < 2) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T protoLen = extData[2];
                    if (protoLen == 0 || protoLen + 1 != listLength) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    if (protoLen >= alpnCapacity) {
                        return STATUS_BUFFER_TOO_SMALL;
                    }
                    for (SIZE_T i = 0; i < protoLen; ++i) {
                        alpnOut[i] = static_cast<char>(extData[3 + i]);
                    }
                    alpnOut[protoLen] = '\0';
                    *alpnLength = protoLen;
                    return STATUS_SUCCESS;
                }

                offset += currentLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsOfferedAlpn(
            _In_ const TlsClientConnectionOptions& options,
            _In_reads_bytes_opt_(alpnLength) const char* alpn,
            SIZE_T alpnLength) noexcept
        {
            if (alpn == nullptr || alpnLength == 0) {
                return true;
            }

            if (options.AlpnProtocols == nullptr || options.AlpnProtocolCount == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < options.AlpnProtocolCount; ++index) {
                const TlsAlpnProtocol& offered = options.AlpnProtocols[index];
                if (offered.Name == nullptr ||
                    offered.NameLength == 0 ||
                    offered.NameLength != alpnLength) {
                    continue;
                }

                if (RtlCompareMemory(offered.Name, alpn, alpnLength) == alpnLength) {
                    return true;
                }
            }

            return false;
        }

        _Must_inspect_result_
        bool TextEqualsIgnoreCase(
            _In_reads_(leftLength) const char* left,
            SIZE_T leftLength,
            _In_reads_(rightLength) const char* right,
            SIZE_T rightLength) noexcept
        {
            if (left == nullptr || right == nullptr || leftLength != rightLength) {
                return false;
            }

            for (SIZE_T index = 0; index < leftLength; ++index) {
                char leftChar = left[index];
                char rightChar = right[index];
                if (leftChar >= 'A' && leftChar <= 'Z') {
                    leftChar = static_cast<char>(leftChar - 'A' + 'a');
                }
                if (rightChar >= 'A' && rightChar <= 'Z') {
                    rightChar = static_cast<char>(rightChar - 'A' + 'a');
                }
                if (leftChar != rightChar) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool TicketServerNameMatches(
            _In_ const Tls13SessionTicket& ticket,
            _In_ const TlsClientConnectionOptions& options) noexcept
        {
            return ticket.ServerNameLength != 0 &&
                ticket.ServerNameLength <= Tls13MaxTicketServerNameLength &&
                options.ServerNameLength <= Tls13MaxTicketServerNameLength &&
                TextEqualsIgnoreCase(
                    ticket.ServerName,
                    ticket.ServerNameLength,
                    options.ServerName,
                    options.ServerNameLength);
        }

        _Must_inspect_result_
        bool TicketAlpnMatches(
            _In_ const Tls13SessionTicket& ticket,
            _In_ const TlsClientConnectionOptions& options) noexcept
        {
            if (ticket.AlpnLength == 0) {
                return options.AlpnProtocols == nullptr || options.AlpnProtocolCount == 0;
            }

            if (ticket.AlpnLength > Tls13MaxTicketAlpnLength) {
                return false;
            }

            return IsOfferedAlpn(options, ticket.Alpn, ticket.AlpnLength);
        }

        _Must_inspect_result_
        bool Tls12SessionServerNameMatches(
            _In_ const Tls12Session& session,
            _In_ const TlsClientConnectionOptions& options) noexcept
        {
            return session.ServerNameLength != 0 &&
                session.ServerNameLength <= Tls12MaxSessionServerNameLength &&
                options.ServerNameLength <= Tls12MaxSessionServerNameLength &&
                TextEqualsIgnoreCase(
                    session.ServerName,
                    session.ServerNameLength,
                    options.ServerName,
                    options.ServerNameLength);
        }

        _Must_inspect_result_
        bool Tls12SessionAlpnMatches(
            _In_ const Tls12Session& session,
            _In_ const TlsClientConnectionOptions& options) noexcept
        {
            if (session.AlpnLength == 0) {
                return options.AlpnProtocols == nullptr || options.AlpnProtocolCount == 0;
            }

            if (session.AlpnLength > Tls12MaxSessionAlpnLength) {
                return false;
            }

            return IsOfferedAlpn(options, session.Alpn, session.AlpnLength);
        }

        _Must_inspect_result_
        bool Tls12ServerHelloEchoedSessionId(
            _In_ const TlsServerHelloView& serverHello,
            _In_ const Tls12Session& session) noexcept
        {
            return session.SessionIdLength != 0 &&
                serverHello.SessionId != nullptr &&
                serverHello.SessionIdLength == session.SessionIdLength &&
                RtlCompareMemory(serverHello.SessionId, session.SessionId, session.SessionIdLength) == session.SessionIdLength;
        }

        _Must_inspect_result_
        const Tls12Session* SelectTls12Session(
            _In_ const TlsClientConnectionOptions& options,
            ULONG policyIdentity) noexcept
        {
            if (!options.EnableSessionResumption ||
                options.Tls12SessionCache == nullptr ||
                options.Tls12SessionCache->SessionCount == 0 ||
                options.Tls12SessionCache->SessionCount > Tls12MaxSessionCount) {
                return nullptr;
            }

            const ULONGLONG now = CurrentMilliseconds();
            for (SIZE_T index = options.Tls12SessionCache->SessionCount; index > 0; --index) {
                const Tls12Session& session = options.Tls12SessionCache->Sessions[index - 1];
                if (session.MasterSecretLength != TlsMasterSecretLength ||
                    session.Version.Major != 3 ||
                    session.Version.Minor != 3 ||
                    session.PolicyIdentity != policyIdentity ||
                    !TlsPolicyAllowsCipherSuite(options.Policy, session.CipherSuite) ||
                    !Tls12SessionServerNameMatches(session, options) ||
                    !Tls12SessionAlpnMatches(session, options)) {
                    continue;
                }

                if (session.TicketLifetimeHintSeconds != 0) {
                    if (session.TicketLifetimeHintSeconds > (~0ULL / 1000ULL)) {
                        continue;
                    }
                    const ULONGLONG lifetimeMilliseconds =
                        static_cast<ULONGLONG>(session.TicketLifetimeHintSeconds) * 1000ULL;
                    if (session.IssueTimeMilliseconds > (~0ULL - lifetimeMilliseconds)) {
                        continue;
                    }
                    const ULONGLONG expiresAt = session.IssueTimeMilliseconds + lifetimeMilliseconds;
                    if (now < session.IssueTimeMilliseconds || now >= expiresAt) {
                        continue;
                    }
                }

                if (session.SessionIdLength == 0 && session.TicketLength == 0) {
                    continue;
                }
                if (session.SessionIdLength > Tls12MaxSessionIdLength ||
                    session.TicketLength > Tls12MaxTicketLength) {
                    continue;
                }

                return &session;
            }

            return nullptr;
        }

        void StoreTls12SessionInCache(
            _Inout_opt_ Tls12SessionCache* cache,
            _In_ const Tls12Session& session) noexcept
        {
            if (cache == nullptr ||
                session.MasterSecretLength != TlsMasterSecretLength ||
                (session.SessionIdLength == 0 && session.TicketLength == 0)) {
                return;
            }

            if (cache->SessionCount < Tls12MaxSessionCount) {
                cache->Sessions[cache->SessionCount] = session;
                ++cache->SessionCount;
            }
            else {
                for (SIZE_T index = 1; index < Tls12MaxSessionCount; ++index) {
                    cache->Sessions[index - 1] = cache->Sessions[index];
                }
                cache->Sessions[Tls12MaxSessionCount - 1] = session;
            }
        }

        void StoreTls12SessionFromHandshake(
            _Inout_opt_ Tls12SessionCache* cache,
            _Inout_ Tls12Session& stored,
            _In_ const TlsClientConnectionOptions& options,
            ULONG policyIdentity,
            _In_ const TlsServerHelloView& serverHello,
            _In_ const TlsSessionSecrets& secrets,
            _In_reads_bytes_(pendingTicketLength) const UCHAR* pendingTicket,
            SIZE_T pendingTicketLength,
            ULONG pendingTicketLifetimeHintSeconds,
            _In_reads_bytes_opt_(negotiatedAlpnLength) const char* negotiatedAlpn,
            SIZE_T negotiatedAlpnLength) noexcept
        {
            if (!options.EnableSessionResumption ||
                cache == nullptr ||
                secrets.MasterSecretLength != TlsMasterSecretLength ||
                options.ServerName == nullptr ||
                options.ServerNameLength == 0 ||
                options.ServerNameLength > Tls12MaxSessionServerNameLength ||
                negotiatedAlpnLength > Tls12MaxSessionAlpnLength ||
                serverHello.SessionIdLength > Tls12MaxSessionIdLength ||
                pendingTicketLength > Tls12MaxTicketLength ||
                (serverHello.SessionIdLength == 0 && pendingTicketLength == 0)) {
                return;
            }

            RtlSecureZeroMemory(&stored, sizeof(stored));
            stored.SessionIdLength = serverHello.SessionIdLength;
            if (stored.SessionIdLength != 0) {
                RtlCopyMemory(stored.SessionId, serverHello.SessionId, stored.SessionIdLength);
            }
            stored.TicketLength = pendingTicketLength;
            if (stored.TicketLength != 0) {
                RtlCopyMemory(stored.Ticket, pendingTicket, stored.TicketLength);
            }
            stored.TicketLifetimeHintSeconds = pendingTicketLifetimeHintSeconds;
            stored.IssueTimeMilliseconds = CurrentMilliseconds();
            stored.Version = { 3, 3 };
            stored.ServerNameLength = options.ServerNameLength;
            RtlCopyMemory(stored.ServerName, options.ServerName, options.ServerNameLength);
            stored.ServerName[options.ServerNameLength] = '\0';
            stored.AlpnLength = negotiatedAlpnLength;
            if (negotiatedAlpnLength != 0) {
                RtlCopyMemory(stored.Alpn, negotiatedAlpn, negotiatedAlpnLength);
                stored.Alpn[negotiatedAlpnLength] = '\0';
            }
            stored.CipherSuite = secrets.CipherSuite;
            stored.MasterSecretLength = secrets.MasterSecretLength;
            RtlCopyMemory(stored.MasterSecret, secrets.MasterSecret, secrets.MasterSecretLength);
            stored.PolicyIdentity = policyIdentity;

            StoreTls12SessionInCache(cache, stored);
            RtlSecureZeroMemory(&stored, sizeof(stored));
        }

        _Must_inspect_result_
        bool MultiplySecondsToMilliseconds(ULONG seconds, _Out_ ULONGLONG* milliseconds) noexcept
        {
            if (milliseconds == nullptr) {
                return false;
            }

            if (seconds > (~0ULL / 1000ULL)) {
                return false;
            }

            *milliseconds = static_cast<ULONGLONG>(seconds) * 1000ULL;
            return true;
        }

        _Must_inspect_result_
        bool AddUnsigned64(ULONGLONG left, ULONGLONG right, _Out_ ULONGLONG* result) noexcept
        {
            if (result == nullptr || left > (~0ULL - right)) {
                return false;
            }

            *result = left + right;
            return true;
        }

        _Must_inspect_result_
        NTSTATUS ComputePskBinderForClientHello(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const TlsContext& context,
            _In_reads_bytes_(resumptionSecretLength) const UCHAR* resumptionSecret,
            SIZE_T resumptionSecretLength,
            _In_reads_bytes_opt_(firstClientHelloLength) const UCHAR* firstClientHello,
            SIZE_T firstClientHelloLength,
            _In_reads_bytes_opt_(helloRetryRequestLength) const UCHAR* helloRetryRequest,
            SIZE_T helloRetryRequestLength,
            _In_reads_bytes_(clientHelloLength) const UCHAR* clientHello,
            SIZE_T clientHelloLength,
            _Out_writes_bytes_(binderCapacity) UCHAR* binder,
            SIZE_T binderCapacity,
            _Out_ SIZE_T* binderLength) noexcept
        {
            if (binderLength != nullptr) {
                *binderLength = 0;
            }
            if (resumptionSecret == nullptr ||
                resumptionSecretLength == 0 ||
                clientHello == nullptr ||
                clientHelloLength == 0 ||
                binder == nullptr ||
                binderLength == nullptr ||
                !IsValidBuffer(firstClientHello, firstClientHelloLength) ||
                !IsValidBuffer(helloRetryRequest, helloRetryRequestLength) ||
                ((firstClientHello == nullptr || firstClientHelloLength == 0) &&
                    (helloRetryRequest != nullptr || helloRetryRequestLength != 0)) ||
                ((firstClientHello != nullptr && firstClientHelloLength != 0) &&
                    (helloRetryRequest == nullptr || helloRetryRequestLength == 0))) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T binderTranscriptLength = 0;
            NTSTATUS status = TlsHandshake13::FindPskBinderTranscriptLength(
                clientHello,
                clientHelloLength,
                &binderTranscriptLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const crypto::HashAlgorithm algorithm = TlsHandshake13::HashForCipherSuite(context.CipherSuite());
            HeapArray<UCHAR> partialHash(TlsMaxTranscriptHashLength);
            if (!partialHash.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T partialHashLength = 0;
            if (firstClientHello == nullptr || firstClientHelloLength == 0) {
                status = crypto::CngProvider::Hash(
                    providerCache,
                    algorithm,
                    clientHello,
                    binderTranscriptLength,
                    partialHash.Get(),
                    partialHash.Count(),
                    &partialHashLength);
            }
            else {
                HeapArray<UCHAR> firstHash(TlsMaxTranscriptHashLength);
                HeapArray<UCHAR> synthetic(4 + TlsMaxTranscriptHashLength);
                if (!firstHash.IsValid() || !synthetic.IsValid()) {
                    RtlSecureZeroMemory(partialHash.Get(), partialHash.Count());
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                SIZE_T firstHashLength = 0;
                status = crypto::CngProvider::Hash(
                    providerCache,
                    algorithm,
                    firstClientHello,
                    firstClientHelloLength,
                    firstHash.Get(),
                    firstHash.Count(),
                    &firstHashLength);
                if (NT_SUCCESS(status)) {
                    synthetic[0] = 254;
                    synthetic[1] = static_cast<UCHAR>((firstHashLength >> 16) & 0xff);
                    synthetic[2] = static_cast<UCHAR>((firstHashLength >> 8) & 0xff);
                    synthetic[3] = static_cast<UCHAR>(firstHashLength & 0xff);
                    RtlCopyMemory(synthetic.Get() + 4, firstHash.Get(), firstHashLength);

                    TlsTranscriptHash binderTranscript;
                    status = binderTranscript.Initialize(algorithm);
                    if (NT_SUCCESS(status)) {
                        status = binderTranscript.Update(synthetic.Get(), 4 + firstHashLength);
                    }
                    if (NT_SUCCESS(status)) {
                        status = binderTranscript.Update(helloRetryRequest, helloRetryRequestLength);
                    }
                    if (NT_SUCCESS(status)) {
                        status = binderTranscript.Update(clientHello, binderTranscriptLength);
                    }
                    if (NT_SUCCESS(status)) {
                        status = binderTranscript.Finish(partialHash.Get(), partialHash.Count(), &partialHashLength);
                    }
                    binderTranscript.Reset();
                }

                RtlSecureZeroMemory(firstHash.Get(), firstHash.Count());
                RtlSecureZeroMemory(synthetic.Get(), synthetic.Count());
            }

            if (NT_SUCCESS(status)) {
                status = TlsHandshake13::ComputePskBinder(
                    context,
                    resumptionSecret,
                    resumptionSecretLength,
                    partialHash.Get(),
                    partialHashLength,
                    binder,
                    binderCapacity,
                    binderLength);
            }
            RtlSecureZeroMemory(partialHash.Get(), partialHash.Count());
            return status;
        }

        _Must_inspect_result_
        NTSTATUS ValidateSelectedPskForConnection(
            _In_ const TlsContext& context,
            _In_ const Tls13ServerHelloView& serverHello,
            SIZE_T offeredPskIdentityCount,
            _In_opt_ const Tls13SessionTicket* selectedTicket) noexcept
        {
            NTSTATUS status = TlsHandshake13::ValidateSelectedPskIdentity(serverHello, offeredPskIdentityCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (serverHello.SelectedPskIdentity == 0xffff) {
                return STATUS_SUCCESS;
            }

            if (selectedTicket == nullptr ||
                selectedTicket->ResumptionSecretLength == 0 ||
                selectedTicket->CipherSuite != context.CipherSuite()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS GetTls13SignatureParameters(
            TlsSignatureScheme scheme,
            _Out_ crypto::HashAlgorithm* hashAlgorithm,
            _Out_ crypto::SignatureAlgorithm* signatureAlgorithm) noexcept
        {
            if (hashAlgorithm == nullptr || signatureAlgorithm == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *hashAlgorithm = HashForSignature(scheme);
            return ToSignatureAlgorithm(scheme, signatureAlgorithm);
        }

        _Must_inspect_result_
        bool SignatureListContains(
            _In_reads_bytes_(signatureSchemesLength) const UCHAR* signatureSchemes,
            SIZE_T signatureSchemesLength,
            TlsSignatureScheme scheme) noexcept
        {
            if (signatureSchemes == nullptr || signatureSchemesLength == 0 || (signatureSchemesLength % sizeof(USHORT)) != 0) {
                return false;
            }

            for (SIZE_T offset = 0; offset < signatureSchemesLength; offset += sizeof(USHORT)) {
                const USHORT current = static_cast<USHORT>(
                    (static_cast<USHORT>(signatureSchemes[offset]) << 8) |
                    signatureSchemes[offset + 1]);
                if (current == static_cast<USHORT>(scheme)) {
                    return true;
                }
            }

            return false;
        }

        _Must_inspect_result_
        NTSTATUS FindTls13CertificateRequestSignatureAlgorithms(
            _In_ const Tls13CertificateRequestView& request,
            _Outptr_result_bytebuffer_(*signatureSchemesLength) const UCHAR** signatureSchemes,
            _Out_ SIZE_T* signatureSchemesLength) noexcept
        {
            if (signatureSchemes == nullptr || signatureSchemesLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *signatureSchemes = nullptr;
            *signatureSchemesLength = 0;
            if (request.Extensions == nullptr || request.ExtensionsLength == 0) {
                return STATUS_SUCCESS;
            }

            SIZE_T offset = 0;
            while (offset < request.ExtensionsLength) {
                if (request.ExtensionsLength - offset < 4) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const USHORT extensionType = static_cast<USHORT>(
                    (static_cast<USHORT>(request.Extensions[offset]) << 8) |
                    request.Extensions[offset + 1]);
                const SIZE_T extensionLength =
                    (static_cast<SIZE_T>(request.Extensions[offset + 2]) << 8) |
                    request.Extensions[offset + 3];
                offset += 4;
                if (extensionLength > request.ExtensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (extensionType == 13) {
                    if (*signatureSchemes != nullptr || extensionLength < 2) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T vectorLength =
                        (static_cast<SIZE_T>(request.Extensions[offset]) << 8) |
                        request.Extensions[offset + 1];
                    if (vectorLength + 2 != extensionLength || (vectorLength % sizeof(USHORT)) != 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    *signatureSchemes = request.Extensions + offset + 2;
                    *signatureSchemesLength = vectorLength;
                }

                offset += extensionLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS SelectClientCredentialSignatureScheme(
            _In_ const TlsPolicy& policy,
            _In_ const TlsClientCredential& credential,
            _In_reads_bytes_opt_(peerSignatureSchemesLength) const UCHAR* peerSignatureSchemes,
            SIZE_T peerSignatureSchemesLength,
            _Out_ TlsSignatureScheme* selectedScheme) noexcept
        {
            if (selectedScheme == nullptr ||
                credential.SupportedSignatureSchemes == nullptr ||
                credential.SupportedSignatureSchemeCount == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            *selectedScheme = TlsSignatureScheme::RsaPkcs1Sha256;
            for (SIZE_T index = 0; index < credential.SupportedSignatureSchemeCount; ++index) {
                const TlsSignatureScheme candidate = credential.SupportedSignatureSchemes[index];
                if (!TlsPolicyAllowsSignatureScheme(policy, candidate) ||
                    !SignatureSchemeMatchesClientCredential(credential, candidate)) {
                    continue;
                }
                if (peerSignatureSchemes != nullptr &&
                    peerSignatureSchemesLength != 0 &&
                    !SignatureListContains(peerSignatureSchemes, peerSignatureSchemesLength, candidate)) {
                    continue;
                }

                *selectedScheme = candidate;
                return STATUS_SUCCESS;
            }

            return STATUS_NOT_SUPPORTED;
        }

        _Must_inspect_result_
        NTSTATUS ConvertTls13CertificateListToLegacy(
            const Tls13CertificateView& certificate,
            UCHAR* destination,
            SIZE_T destinationCapacity,
            SIZE_T* bytesWritten,
            SIZE_T* certificateCount) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }
            if (certificateCount != nullptr) {
                *certificateCount = 0;
            }
            if (certificate.Certificates == nullptr ||
                certificate.CertificatesLength == 0 ||
                destination == nullptr ||
                bytesWritten == nullptr ||
                certificateCount == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T sourceOffset = 0;
            SIZE_T outputOffset = 0;
            SIZE_T count = 0;
            while (sourceOffset < certificate.CertificatesLength) {
                if (certificate.CertificatesLength - sourceOffset < 3) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T certLength =
                    (static_cast<SIZE_T>(certificate.Certificates[sourceOffset]) << 16) |
                    (static_cast<SIZE_T>(certificate.Certificates[sourceOffset + 1]) << 8) |
                    certificate.Certificates[sourceOffset + 2];
                sourceOffset += 3;
                if (certLength == 0 || certLength > certificate.CertificatesLength - sourceOffset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (destinationCapacity - outputOffset < certLength + 3) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                destination[outputOffset++] = static_cast<UCHAR>((certLength >> 16) & 0xff);
                destination[outputOffset++] = static_cast<UCHAR>((certLength >> 8) & 0xff);
                destination[outputOffset++] = static_cast<UCHAR>(certLength & 0xff);
                RtlCopyMemory(destination + outputOffset, certificate.Certificates + sourceOffset, certLength);
                outputOffset += certLength;
                sourceOffset += certLength;

                if (certificate.CertificatesLength - sourceOffset < 2) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                const SIZE_T extensionsLength =
                    (static_cast<SIZE_T>(certificate.Certificates[sourceOffset]) << 8) |
                    certificate.Certificates[sourceOffset + 1];
                sourceOffset += 2;
                if (extensionsLength > certificate.CertificatesLength - sourceOffset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                sourceOffset += extensionsLength;
                ++count;
            }

            *bytesWritten = outputOffset;
            *certificateCount = count;
            return count == 0 ? STATUS_INVALID_NETWORK_RESPONSE : STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS SendAll(core::ITransport& transport, const UCHAR* data, SIZE_T length) noexcept
        {
            if (!IsValidBuffer(data, length)) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T sentTotal = 0;
            while (sentTotal < length) {
                SIZE_T sent = 0;
                NTSTATUS status = transport.Send(data + sentTotal, length - sentTotal, &sent);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (sent == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                sentTotal += sent;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadExact(
            core::ITransport& transport,
            UCHAR* data,
            SIZE_T length,
            ULONG receiveTimeoutMilliseconds = WskOperationTimeoutMilliseconds,
            _In_opt_ const TlsReceiveDeadline* receiveDeadline = nullptr) noexcept
        {
            if (!IsValidBuffer(data, length)) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T receivedTotal = 0;
            while (receivedTotal < length) {
                SIZE_T received = 0;
                ULONG attemptTimeoutMilliseconds = receiveTimeoutMilliseconds;
                NTSTATUS status = RemainingReceiveTimeout(
                    receiveTimeoutMilliseconds,
                    receiveDeadline,
                    &attemptTimeoutMilliseconds);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = transport.ReceiveWithTimeout(
                    data + receivedTotal,
                    length - receivedTotal,
                    &received,
                    attemptTimeoutMilliseconds);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (received == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                receivedTotal += received;
            }

            return STATUS_SUCCESS;
        }
    }

    TlsConnection::~TlsConnection() noexcept
    {
        Reset();
        FreeNonPagedArray(inputBuffer_);
        FreeNonPagedArray(outputBuffer_);
        FreeNonPagedArray(tls13InnerPlaintextBuffer_);
        FreeNonPagedArray(plaintextBuffer_);
        FreeNonPagedArray(negotiatedAlpn_);
        inputBuffer_ = nullptr;
        outputBuffer_ = nullptr;
        tls13InnerPlaintextBuffer_ = nullptr;
        plaintextBuffer_ = nullptr;
        handshakeBuffer_ = nullptr;
        negotiatedAlpn_ = nullptr;
    }

    void TlsConnection::Reset() noexcept
    {
        context_.Reset();
        clientWriteState_.Reset();
        serverWriteState_.Reset();
        tls12PendingClientWriteState_.Reset();
        tls12PendingServerWriteState_.Reset();
        transcript_.Reset();
        if (inputBuffer_ != nullptr) {
            RtlSecureZeroMemory(inputBuffer_, TlsIoBufferLength);
        }
        if (outputBuffer_ != nullptr) {
            RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        }
        if (tls13InnerPlaintextBuffer_ != nullptr) {
            RtlSecureZeroMemory(tls13InnerPlaintextBuffer_, TlsMaxPlaintextLength + 1);
        }
        if (plaintextBuffer_ != nullptr) {
            RtlSecureZeroMemory(plaintextBuffer_, TlsApplicationBufferLength);
        }
        if (handshakeBuffer_ != nullptr) {
            RtlSecureZeroMemory(handshakeBuffer_, TlsScratchHandshakeBufferLength);
        }
        ReleaseHandshakeScratch();
        certificateScratchAllocator_ = nullptr;
        providerCache_ = nullptr;
        inputLength_ = 0;
        plaintextLength_ = 0;
        tlsConnectionBytesRead_ = 0;
        tlsConnectionRecordsRead_ = 0;
        handshakeBuffer_ = nullptr;
        handshakeLength_ = 0;
        handshakeConsumed_ = 0;
        lastHandshakeOffset_ = 0;
        lastHandshakeLength_ = 0;
        handshakeReceiveTimeoutMilliseconds_ = TlsHandshakeReceiveTimeoutMilliseconds;
        handshakeReceiveDeadline_ = {};
        encrypted_ = false;
        tls13RecordProtection_ = false;
        tls13RecordPaddingLength_ = 0;
        tls13PostHandshakeClientAuthAllowed_ = false;
        ExchangeTlsFlag(&tls13PeerRequestedKeyUpdate_, 0);
        clientCredential_ = nullptr;
        tls12SessionCache_ = nullptr;
        tls13ExternalSessionCache_ = nullptr;
        tls12RenegotiationOptions_ = {};
        tlsPolicy_ = {};
        tlsPolicyIdentity_ = 0;
        tls12MaxRenegotiations_ = Tls12DefaultMaxRenegotiations;
        tls12RenegotiationCount_ = 0;
        tls12Renegotiating_ = false;
        RtlSecureZeroMemory(tls12LastClientVerifyData_, sizeof(tls12LastClientVerifyData_));
        tls12LastClientVerifyDataLength_ = 0;
        RtlSecureZeroMemory(tls12LastServerVerifyData_, sizeof(tls12LastServerVerifyData_));
        tls12LastServerVerifyDataLength_ = 0;
        serverCertificatePublicKeyAlgorithm_ = CertificatePublicKeyAlgorithm::Unknown;
        RtlSecureZeroMemory(serverEd25519PublicKey_, sizeof(serverEd25519PublicKey_));
        serverEd25519PublicKeyLength_ = 0;
        RtlSecureZeroMemory(serverEd448PublicKey_, sizeof(serverEd448PublicKey_));
        serverEd448PublicKeyLength_ = 0;
        if (tlsKeyBlockScratch_.IsValid()) {
            RtlSecureZeroMemory(tlsKeyBlockScratch_.Get(), sizeof(TlsKeyBlock));
        }
        if (tls12SessionScratch_.IsValid()) {
            RtlSecureZeroMemory(tls12SessionScratch_.Get(), sizeof(Tls12Session));
        }
        if (tls13SessionTicketScratch_.IsValid()) {
            RtlSecureZeroMemory(tls13SessionTicketScratch_.Get(), sizeof(Tls13SessionTicket));
        }
        RtlSecureZeroMemory(tls12PendingTicket_, sizeof(tls12PendingTicket_));
        tls12PendingTicketLength_ = 0;
        tls12PendingTicketLifetimeHintSeconds_ = 0;
        RtlSecureZeroMemory(tls13TicketServerName_, sizeof(tls13TicketServerName_));
        tls13TicketServerNameLength_ = 0;
        tls13TicketServerNameCacheable_ = false;
        if (negotiatedAlpn_ != nullptr) {
            RtlSecureZeroMemory(negotiatedAlpn_, 16);
        }
        negotiatedAlpnLength_ = 0;
        ClearHandshakeFailure();
    }

    NTSTATUS TlsConnection::EnsureBuffers() noexcept
    {
        if (inputBuffer_ == nullptr) {
            inputBuffer_ = AllocateNonPagedArray<UCHAR>(TlsIoBufferLength);
            if (inputBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (outputBuffer_ == nullptr) {
            outputBuffer_ = AllocateNonPagedArray<UCHAR>(TlsIoBufferLength);
            if (outputBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (tls13InnerPlaintextBuffer_ == nullptr) {
            tls13InnerPlaintextBuffer_ = AllocateNonPagedArray<UCHAR>(TlsMaxPlaintextLength + 1);
            if (tls13InnerPlaintextBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (plaintextBuffer_ == nullptr) {
            plaintextBuffer_ = AllocateNonPagedArray<UCHAR>(TlsApplicationBufferLength);
            if (plaintextBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (handshakeBuffer_ == nullptr) {
            NTSTATUS status = GetHandshakeScratch(
                TlsScratchHandshakeBufferOffset,
                TlsScratchHandshakeBufferLength,
                &handshakeBuffer_);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            RtlSecureZeroMemory(handshakeBuffer_, TlsScratchHandshakeBufferLength);
        }
        if (negotiatedAlpn_ == nullptr) {
            negotiatedAlpn_ = AllocateNonPagedArray<char>(16);
            if (negotiatedAlpn_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::PrepareScratch(const TlsClientConnectionOptions& options) noexcept
    {
        ReleaseHandshakeScratch();

        handshakeScratchAllocator_ = options.HandshakeScratchAllocator;
        certificateScratchAllocator_ = options.CertificateScratchAllocator;
        providerCache_ = options.ProviderCache;

        if (handshakeScratchAllocator_ != nullptr) {
            void* buffer = nullptr;
            const NTSTATUS status = handshakeScratchAllocator_->Acquire(
                TlsScratchRequiredLength,
                &buffer);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            handshakeScratch_ = static_cast<UCHAR*>(buffer);
            handshakeScratchLength_ = TlsScratchRequiredLength;
            RtlSecureZeroMemory(handshakeScratch_, handshakeScratchLength_);
            return STATUS_SUCCESS;
        }

        if (ownedTlsScratch_ == nullptr || ownedTlsScratchLength_ < TlsScratchRequiredLength) {
            if (ownedTlsScratch_ != nullptr) {
                RtlSecureZeroMemory(ownedTlsScratch_, ownedTlsScratchLength_);
                FreeNonPagedArray(ownedTlsScratch_);
                ownedTlsScratch_ = nullptr;
                ownedTlsScratchLength_ = 0;
            }

            ownedTlsScratch_ = AllocateNonPagedArray<UCHAR>(TlsScratchRequiredLength);
            if (ownedTlsScratch_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ownedTlsScratchLength_ = TlsScratchRequiredLength;
        }

        RtlSecureZeroMemory(ownedTlsScratch_, ownedTlsScratchLength_);
        handshakeScratch_ = ownedTlsScratch_;
        handshakeScratchLength_ = ownedTlsScratchLength_;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::GetHandshakeScratch(
        SIZE_T offset,
        SIZE_T length,
        UCHAR** buffer) noexcept
    {
        if (buffer != nullptr) {
            *buffer = nullptr;
        }

        if (buffer == nullptr || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        UCHAR* base = handshakeScratch_;
        SIZE_T capacity = handshakeScratchLength_;

        if (base == nullptr || offset > capacity || length > capacity - offset) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        *buffer = base + offset;
        return STATUS_SUCCESS;
    }

    void TlsConnection::ReleaseHandshakeScratch() noexcept
    {
        if (handshakeScratch_ != nullptr && handshakeScratchLength_ != 0) {
            RtlSecureZeroMemory(handshakeScratch_, handshakeScratchLength_);
        }

        if (handshakeScratchAllocator_ != nullptr && handshakeScratch_ != nullptr) {
            handshakeScratchAllocator_->Release(handshakeScratch_);
        }

        if (ownedTlsScratch_ != nullptr) {
            RtlSecureZeroMemory(ownedTlsScratch_, ownedTlsScratchLength_);
            FreeNonPagedArray(ownedTlsScratch_);
            ownedTlsScratch_ = nullptr;
            ownedTlsScratchLength_ = 0;
        }

        handshakeScratchAllocator_ = nullptr;
        handshakeScratch_ = nullptr;
        handshakeScratchLength_ = 0;
        handshakeBuffer_ = nullptr;
    }

    NTSTATUS TlsConnection::Connect(
        core::ITransport& transport,
        const TlsClientConnectionOptions& options) noexcept
    {
        ClearHandshakeFailure();
        if (options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            !IsValidBuffer(options.EarlyData, options.EarlyDataLength) ||
            options.HandshakeReceiveTimeoutMilliseconds == 0 ||
            options.Tls13RecordPaddingLength > Tls13MaxRecordPaddingLength ||
            options.MaxTls12Renegotiations > Tls12HardMaxRenegotiations ||
            (options.VerifyCertificate && options.CertificateStore == nullptr) ||
            !NT_SUCCESS(TlsValidatePolicy(options.Policy)) ||
            static_cast<UCHAR>(options.MinimumProtocol) > static_cast<UCHAR>(options.MaximumProtocol)) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
        }
        if (options.EnableEarlyData &&
            options.EarlyData != nullptr &&
            options.EarlyDataLength != 0 &&
            !options.EarlyDataReplaySafe) {
            if (options.EarlyDataBytesSent != nullptr) {
                *options.EarlyDataBytesSent = 0;
            }
            if (options.EarlyDataAccepted != nullptr) {
                *options.EarlyDataAccepted = false;
            }
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }

        Reset();
        ClearHandshakeFailure();
        handshakeReceiveTimeoutMilliseconds_ = options.HandshakeReceiveTimeoutMilliseconds;
        handshakeReceiveDeadline_ = MakeReceiveDeadline(handshakeReceiveTimeoutMilliseconds_);
        tls13RecordPaddingLength_ = options.Tls13RecordPaddingLength;
        tls13PostHandshakeClientAuthAllowed_ = options.Policy.EnablePostHandshakeClientAuth;
        clientCredential_ = options.ClientCredential;
        tls12SessionCache_ = options.Tls12SessionCache;
        tls13ExternalSessionCache_ = options.SessionCache;
        tls12RenegotiationOptions_ = options;
        tlsPolicy_ = options.Policy;
        tls12MaxRenegotiations_ = options.MaxTls12Renegotiations;
        tlsPolicyIdentity_ =
            (static_cast<ULONG>(options.Policy.Profile) << 24) |
            (options.Policy.EnableTls12RsaKeyExchange ? 0x00000001UL : 0) |
            (options.Policy.EnableTls12Cbc ? 0x00000002UL : 0) |
            (options.Policy.EnableTls12Renegotiation ? 0x00000004UL : 0) |
            (options.Policy.EnablePostHandshakeClientAuth ? 0x00000008UL : 0) |
            (options.Policy.RequireRevocationCheck ? 0x00000010UL : 0);
        serverCertificatePublicKeyAlgorithm_ = CertificatePublicKeyAlgorithm::Unknown;
        RtlSecureZeroMemory(serverEd25519PublicKey_, sizeof(serverEd25519PublicKey_));
        serverEd25519PublicKeyLength_ = 0;
        RtlSecureZeroMemory(serverEd448PublicKey_, sizeof(serverEd448PublicKey_));
        serverEd448PublicKeyLength_ = 0;

        NTSTATUS status = PrepareScratch(options);
        if (NT_SUCCESS(status)) {
            status = EnsureBuffers();
        }
        if (!NT_SUCCESS(status)) {
            ReleaseHandshakeScratch();
            certificateScratchAllocator_ = nullptr;
            return status;
        }

        if (ProtocolAllowed(options, TlsProtocol::Tls13)) {
            status = ConnectTls13(transport, options);
        }
        else if (ProtocolAllowed(options, TlsProtocol::Tls12)) {
            status = ConnectTls12(transport, options);
        }
        else {
            status = STATUS_NOT_SUPPORTED;
        }

        ReleaseHandshakeScratch();
        certificateScratchAllocator_ = nullptr;
        if (!NT_SUCCESS(status) &&
            lastHandshakeFailure_.Category == TlsHandshakeFailureCategory::None) {
            RecordHandshakeFailure(CategoryForStatus(status), status);
        }
        return status;
    }

    NTSTATUS TlsConnection::ConnectTls12(
        core::ITransport& transport,
        const TlsClientConnectionOptions& options) noexcept
    {
        tls13RecordProtection_ = false;

        NTSTATUS status = context_.InitializeClient({ 3, 3 });
        if (NT_SUCCESS(status)) {
            status = transcript_.Initialize(crypto::HashAlgorithm::Sha256);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (options.EarlyDataAccepted != nullptr) {
            *options.EarlyDataAccepted = false;
        }
        if (options.EarlyDataBytesSent != nullptr) {
            *options.EarlyDataBytesSent = 0;
        }
        if (options.EnableEarlyData) {
            return STATUS_NOT_SUPPORTED;
        }

        UCHAR* message = nullptr;
        status = GetHandshakeScratch(
            TlsScratchClientHelloOffset,
            TlsScratchClientHelloLength,
            &message);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(message, TlsScratchClientHelloLength);
        SIZE_T messageLength = 0;

        TlsClientHelloOptions hello = {};
        hello.ServerName = options.ServerName;
        hello.ServerNameLength = options.ServerNameLength;
        hello.AlpnProtocols = options.AlpnProtocols;
        hello.AlpnProtocolCount = options.AlpnProtocolCount;
        hello.OfferEncryptThenMac = options.Policy.EnableTls12Cbc;
        hello.OfferStatusRequest = true;

        HeapArray<TlsCipherSuite> offeredCipherSuites;
        HeapArray<TlsNamedGroup> offeredNamedGroups;
        HeapArray<TlsSignatureScheme> offeredSignatureSchemes;
        SIZE_T offeredCipherSuiteCount = 0;
        SIZE_T offeredNamedGroupCount = 0;
        SIZE_T offeredSignatureSchemeCount = 0;
        status = BuildTls12PolicyOffers(
            options.Policy,
            offeredCipherSuites,
            &offeredCipherSuiteCount,
            offeredNamedGroups,
            &offeredNamedGroupCount,
            offeredSignatureSchemes,
            &offeredSignatureSchemeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        hello.CipherSuites = offeredCipherSuites.Get();
        hello.CipherSuiteCount = offeredCipherSuiteCount;
        hello.NamedGroups = offeredNamedGroups.Get();
        hello.NamedGroupCount = offeredNamedGroupCount;
        hello.SignatureSchemes = offeredSignatureSchemes.Get();
        hello.SignatureSchemeCount = offeredSignatureSchemeCount;

        const Tls12Session* selectedTls12Session = SelectTls12Session(options, tlsPolicyIdentity_);
        if (selectedTls12Session != nullptr) {
            hello.SessionId = selectedTls12Session->SessionId;
            hello.SessionIdLength = selectedTls12Session->SessionIdLength;
            hello.SessionTicket = selectedTls12Session->Ticket;
            hello.SessionTicketLength = selectedTls12Session->TicketLength;
        }

        status = TlsHandshake12::EncodeClientHello(
            context_,
            hello,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection encode ClientHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        UCHAR* clientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchFirstClientHelloOffset,
            TlsScratchFirstClientHelloLength,
            &clientHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (messageLength > TlsScratchFirstClientHelloLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(clientHello, message, messageLength);
        const SIZE_T clientHelloLength = messageLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send ClientHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsHandshakeMessageView handshake = {};
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read ServerHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context_, handshake, serverHello);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerHello failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }
        status = TlsHandshake12::ValidateServerHelloOffer(serverHello, hello);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection ServerHello selected value was not offered: 0x%08X cipher=0x%04X\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(serverHello.CipherSuite));
            return status;
        }
        if (!serverHello.HasExtendedMasterSecret) {
            kprintf("TlsConnection TLS1.2 ServerHello missing extended_master_secret\r\n");
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }
        if (!serverHello.HasSecureRenegotiation ||
            serverHello.SecureRenegotiationDataLength != 0) {
            kprintf("TlsConnection TLS1.2 ServerHello missing secure renegotiation indication\r\n");
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }
        const TlsCipherSuiteCapability* selectedCapability = TlsFindCipherSuiteCapability(context_.CipherSuite());
        if (selectedCapability == nullptr ||
            !TlsPolicyAllowsCipherSuite(options.Policy, context_.CipherSuite())) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }
        if (selectedCapability->BulkCipher == TlsBulkCipherKind::AesCbc && !serverHello.HasEncryptThenMac) {
            kprintf("TlsConnection TLS1.2 CBC ServerHello missing encrypt_then_mac\r\n");
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }

        bool serverMaySendNewSessionTicket = false;
        status = ServerHelloHasEmptyExtension(serverHello, TlsExtensionSessionTicket, &serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerHello extensions failed: 0x%08X len=%Iu\r\n",
                static_cast<ULONG>(status),
                serverHello.ExtensionsLength);
            return status;
        }
        kprintf("TlsConnection ServerHello cipher=0x%04X sessionTicket=%u extensions=%Iu\r\n",
            static_cast<unsigned>(serverHello.CipherSuite),
            serverMaySendNewSessionTicket ? 1u : 0u,
            serverHello.ExtensionsLength);

        // Parse ALPN from ServerHello
        status = ParseServerHelloAlpn(serverHello, negotiatedAlpn_, 16, &negotiatedAlpnLength_);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ALPN failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }
        if (negotiatedAlpnLength_ > 0) {
            kprintf("TlsConnection ALPN negotiated: %.*s\r\n",
                static_cast<int>(negotiatedAlpnLength_), negotiatedAlpn_);
            if (!IsOfferedAlpn(options, negotiatedAlpn_, negotiatedAlpnLength_)) {
                kprintf("TlsConnection ALPN was not offered by client\r\n");
                RecordHandshakeFailure(TlsHandshakeFailureCategory::AlpnMismatch, STATUS_NOT_SUPPORTED);
                return STATUS_NOT_SUPPORTED;
            }
        }

        status = transcript_.Initialize(TlsHandshake12::PrfHashForCipherSuite(context_.CipherSuite()));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection reinitialize transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = transcript_.Update(clientHello, clientHelloLength);
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection update transcript after ServerHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (selectedTls12Session != nullptr && Tls12ServerHelloEchoedSessionId(serverHello, *selectedTls12Session)) {
            if (selectedTls12Session->CipherSuite != context_.CipherSuite() ||
                selectedTls12Session->AlpnLength != negotiatedAlpnLength_ ||
                (selectedTls12Session->AlpnLength != 0 &&
                    RtlCompareMemory(
                        selectedTls12Session->Alpn,
                        negotiatedAlpn_,
                        selectedTls12Session->AlpnLength) != selectedTls12Session->AlpnLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = context_.SetTls12ResumedMasterSecret(
                selectedTls12Session->CipherSuite,
                selectedTls12Session->MasterSecret,
                selectedTls12Session->MasterSecretLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (!tlsKeyBlockScratch_.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            TlsKeyBlock& resumedKeyBlock = *tlsKeyBlockScratch_.Get();
            RtlSecureZeroMemory(&resumedKeyBlock, sizeof(resumedKeyBlock));
            const SIZE_T resumedKeyLength = Tls12AeadKeyLengthForCipherSuite(context_.CipherSuite());
            const SIZE_T resumedMacKeyLength = Tls12MacKeyLengthForCipherSuite(context_.CipherSuite());
            const SIZE_T resumedFixedIvLength = Tls12FixedIvLengthForCipherSuite(context_.CipherSuite());
            status = context_.DeriveKeyBlock(
                resumedKeyBlock,
                (resumedMacKeyLength * 2) + (resumedKeyLength * 2) + (resumedFixedIvLength * 2));
            if (NT_SUCCESS(status)) {
                status = context_.ConfigureAesGcmStates(resumedKeyBlock, clientWriteState_, serverWriteState_);
            }
            RtlSecureZeroMemory(&resumedKeyBlock, sizeof(resumedKeyBlock));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadServerChangeCipherSpec(transport, serverMaySendNewSessionTicket);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            encrypted_ = true;

            status = ReadHandshakeMessage(transport, handshake, false);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (handshake.Type != TlsHandshakeType::Finished) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            HeapArray<UCHAR> resumedTranscriptHash(TlsMaxTranscriptHashLength);
            if (!resumedTranscriptHash.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T resumedTranscriptHashLength = 0;
            status = FinishTranscript(
                resumedTranscriptHash.Get(),
                resumedTranscriptHash.Count(),
                &resumedTranscriptHashLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::VerifyFinished(
                    context_,
                    false,
                    resumedTranscriptHash.Get(),
                    resumedTranscriptHashLength,
                    handshake.Body,
                    handshake.BodyLength);
            }
            RtlSecureZeroMemory(resumedTranscriptHash.Get(), resumedTranscriptHash.Count());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (handshake.BodyLength != TlsVerifyDataLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(tls12LastServerVerifyData_, handshake.Body, TlsVerifyDataLength);
            tls12LastServerVerifyDataLength_ = TlsVerifyDataLength;

            status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            static const UCHAR changeCipherSpec[] = { 1 };
            status = SendPlainRecord(
                transport,
                TlsContentType::ChangeCipherSpec,
                changeCipherSpec,
                sizeof(changeCipherSpec));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = FinishTranscript(
                resumedTranscriptHash.Get(),
                resumedTranscriptHash.Count(),
                &resumedTranscriptHashLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::EncodeFinished(
                    context_,
                    true,
                    resumedTranscriptHash.Get(),
                    resumedTranscriptHashLength,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
            }
            RtlSecureZeroMemory(resumedTranscriptHash.Get(), resumedTranscriptHash.Count());
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (messageLength != TlsHandshakeHeaderLength + TlsVerifyDataLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(tls12LastClientVerifyData_, message + TlsHandshakeHeaderLength, TlsVerifyDataLength);
            tls12LastClientVerifyDataLength_ = TlsVerifyDataLength;

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (!tls12SessionScratch_.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            StoreTls12SessionFromHandshake(
                tls12SessionCache_,
                *tls12SessionScratch_.Get(),
                options,
                tlsPolicyIdentity_,
                serverHello,
                context_.Secrets(),
                tls12PendingTicket_,
                tls12PendingTicketLength_,
                tls12PendingTicketLifetimeHintSeconds_,
                negotiatedAlpn_,
                negotiatedAlpnLength_);
            context_.SetState(TlsHandshakeState::Established);
            return STATUS_SUCCESS;
        }

        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read Certificate failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsCertificateListView certificates = {};
        status = TlsHandshake12::ParseCertificateList(context_, handshake, certificates);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse Certificate failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }
        kprintf("TlsConnection Certificate count=%Iu bytes=%Iu\r\n",
            certificates.CertificateCount,
            certificates.CertificatesLength);

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = options.ProviderCache;
        validation.VerifyCertificate = options.VerifyCertificate;
        validation.RequireRevocationCheck = options.Policy.RequireRevocationCheck;

        HeapObject<CertificateValidationResult> validationResult;
        if (!validationResult.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificates.Certificates;
        chain.CertificatesLength = certificates.CertificatesLength;
        chain.CertificateCount = certificates.CertificateCount;
        status = CertificateValidator::ValidateChain(chain, validation, validationResult.Get());
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection validate Certificate failed: 0x%08X count=%Iu bytes=%Iu\r\n",
                static_cast<ULONG>(status),
                chain.CertificateCount,
                chain.CertificatesLength);
            return status;
        }
        serverCertificatePublicKeyAlgorithm_ = validationResult->Leaf.PublicKeyAlgorithm;
        if ((selectedCapability->Authentication == TlsAuthenticationKind::Rsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) ||
            (selectedCapability->Authentication == TlsAuthenticationKind::Ecdsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP256 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP384 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP521 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed25519 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed448)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
            serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (validationResult->Leaf.HasKeyUsage) {
            if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsKeyEncipherment) {
                return STATUS_TRUST_FAILURE;
            }
            if (selectedCapability->Tls12KeyExchange != Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsDigitalSignature) {
                return STATUS_TRUST_FAILURE;
            }
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed25519) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed25519PublicKeyLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd25519PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed25519PublicKeyLength);
            serverEd25519PublicKeyLength_ = crypto::Ed25519PublicKeyLength;
        }
        else if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed448) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed448PublicKeyLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd448PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed448PublicKeyLength);
            serverEd448PublicKeyLength_ = crypto::Ed448PublicKeyLength;
        }
        else {
            status = CertificateValidator::ImportSubjectPublicKey(providerCache_, validationResult->Leaf, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection import server public key failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }
        }

        const Tls12KeyExchangeKind serverKeyExchangeKind =
            Tls12KeyExchangeForCipherSuite(context_.CipherSuite());
        TlsServerKeyExchangeView keyExchange = {};
        HeapObject<crypto::CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        bool needsCngPeerKey = false;
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read post-Certificate handshake failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (handshake.Type == TlsHandshakeType::CertificateStatus) {
            Tls12CertificateStatusView certificateStatus = {};
            status = TlsHandshake12::ParseCertificateStatus(handshake, certificateStatus);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection parse CertificateStatus failed: 0x%08X body=%Iu\r\n",
                    static_cast<ULONG>(status),
                    handshake.BodyLength);
                return status;
            }

            kprintf("TlsConnection CertificateStatus OCSP bytes=%Iu\r\n",
                certificateStatus.OcspResponseLength);

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection read post-CertificateStatus handshake failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }
        }

        if (serverKeyExchangeKind != Tls12KeyExchangeKind::Rsa) {
            status = TlsHandshake12::ParseServerKeyExchange(context_, handshake, keyExchange);
            if (!NT_SUCCESS(status)) {
                LogServerKeyExchangeParseFailure(
                    status,
                    context_.CipherSuite(),
                    serverKeyExchangeKind,
                    handshake);
                return status;
            }
            status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, hello);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection ServerKeyExchange selected value was not offered: 0x%08X group=%u signature=0x%04X\r\n",
                    static_cast<ULONG>(status),
                    static_cast<unsigned>(keyExchange.NamedGroup),
                    static_cast<unsigned>(keyExchange.SignatureScheme));
                return status;
            }

            status = VerifyServerKeyExchange(keyExchange, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection verify ServerKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }

            crypto::KeyExchangeGroup selectedGroup = crypto::KeyExchangeGroup::Secp256r1;
            status = ToKeyExchangeGroup(keyExchange.NamedGroup, &selectedGroup);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            needsCngPeerKey =
                serverKeyExchangeKind != Tls12KeyExchangeKind::DheRsa &&
                selectedGroup != crypto::KeyExchangeGroup::X25519 &&
                selectedGroup != crypto::KeyExchangeGroup::X448;
            if (needsCngPeerKey) {
                status = crypto::CngProvider::ImportEcdhPublicKey(
                    providerCache_,
                    ToEcCurve(keyExchange.NamedGroup),
                    keyExchange.EcPoint,
                    keyExchange.EcPointLength,
                    *peerKey.Get());
                if (!NT_SUCCESS(status)) {
                    kprintf("TlsConnection import ServerKeyExchange ECDH key failed: 0x%08X group=%u point=%Iu\r\n",
                        static_cast<ULONG>(status),
                        static_cast<unsigned>(keyExchange.NamedGroup),
                        keyExchange.EcPointLength);
                    return status;
                }
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection read ServerHelloDone failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }
        }

        bool clientCertificateRequested = false;
        bool sendClientCertificateVerify = false;
        TlsSignatureScheme clientCertificateSignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            TlsCertificateRequestView request = {};
            status = TlsHandshake12::ParseCertificateRequest(context_, handshake, request);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            clientCertificateRequested = true;
            const UCHAR* credentialCertificateList = nullptr;
            SIZE_T credentialCertificateListLength = 0;
            if (clientCredential_ != nullptr &&
                clientCredential_->CertificateList != nullptr &&
                clientCredential_->CertificateListLength != 0 &&
                clientCredential_->Sign != nullptr) {
                const SIZE_T peerSignatureSchemesLength = request.SignatureSchemeCount * sizeof(USHORT);
                status = SelectClientCredentialSignatureScheme(
                    options.Policy,
                    *clientCredential_,
                    request.SignatureSchemes,
                    peerSignatureSchemesLength,
                    &clientCertificateSignatureScheme);
                if (NT_SUCCESS(status)) {
                    credentialCertificateList = clientCredential_->CertificateList;
                    credentialCertificateListLength = clientCredential_->CertificateListLength;
                    sendClientCertificateVerify = true;
                }
                else if (status != STATUS_NOT_SUPPORTED) {
                    return status;
                }
            }

            status = TlsHandshake12::EncodeCertificate(
                credentialCertificateList,
                credentialCertificateListLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = TlsHandshake12::MarkServerHelloDone(context_, handshake);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerHelloDone failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }

        HeapArray<UCHAR> premasterSecret(crypto::KeyExchangeMaxSharedSecretLength);
        if (!premasterSecret.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T premasterSecretLength = 0;
        status = GenerateClientKeyExchange(
            keyExchange,
            needsCngPeerKey ? peerKey.Get() : nullptr,
            serverKeyExchangeKind == Tls12KeyExchangeKind::Rsa ? serverPublicKey.Get() : nullptr,
            validationResult->Leaf.RsaModulusLength,
            premasterSecret.Get(),
            premasterSecret.Count(),
            &premasterSecretLength,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            kprintf("TlsConnection generate ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            kprintf("TlsConnection send ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!transcriptHash.IsValid()) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T transcriptHashLength = 0;
        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status) && clientCertificateRequested && sendClientCertificateVerify) {
            HeapArray<UCHAR> signature(TlsScratchHandshakeBufferLength);
            if (!signature.IsValid()) {
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T signatureLength = 0;
            status = clientCredential_->Sign(
                clientCredential_->SignContext,
                clientCertificateSignatureScheme,
                transcriptHash.Get(),
                transcriptHashLength,
                signature.Get(),
                signature.Count(),
                &signatureLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::EncodeCertificateVerify(
                    clientCertificateSignatureScheme,
                    signature.Get(),
                    signatureLength,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
            }
            RtlSecureZeroMemory(signature.Get(), signature.Count());
            if (NT_SUCCESS(status)) {
                status = AppendTranscript(message, messageLength);
            }
            if (NT_SUCCESS(status)) {
                status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
        }
        if (NT_SUCCESS(status)) {
            status = context_.DeriveExtendedMasterSecret(
                premasterSecret.Get(),
                premasterSecretLength,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            kprintf("TlsConnection derive TLS1.2 extended master secret failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (!tlsKeyBlockScratch_.IsValid()) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        TlsKeyBlock& keyBlock = *tlsKeyBlockScratch_.Get();
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        const SIZE_T keyLength = Tls12AeadKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T macKeyLength = Tls12MacKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T fixedIvLength = Tls12FixedIvLengthForCipherSuite(context_.CipherSuite());
        status = context_.DeriveKeyBlock(keyBlock, (macKeyLength * 2) + (keyLength * 2) + (fixedIvLength * 2));
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureAesGcmStates(keyBlock, clientWriteState_, serverWriteState_);
        }
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            kprintf("TlsConnection derive TLS1.2 key block failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        static const UCHAR changeCipherSpec[] = { 1 };
        status = SendPlainRecord(transport, TlsContentType::ChangeCipherSpec, changeCipherSpec, sizeof(changeCipherSpec));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send ChangeCipherSpec failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection finish client transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = TlsHandshake12::EncodeFinished(
            context_,
            true,
            transcriptHash.Get(),
            transcriptHashLength,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection encode client Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }
        if (messageLength != TlsHandshakeHeaderLength + TlsVerifyDataLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        RtlCopyMemory(tls12LastClientVerifyData_, message + TlsHandshakeHeaderLength, TlsVerifyDataLength);
        tls12LastClientVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send client Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = ReadServerChangeCipherSpec(transport, serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read server ChangeCipherSpec failed: 0x%08X allowTicket=%u\r\n",
                static_cast<ULONG>(status),
                serverMaySendNewSessionTicket ? 1u : 0u);
            return status;
        }

        encrypted_ = true;

        status = ReadHandshakeMessage(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read server Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (handshake.Type != TlsHandshakeType::Finished) {
            kprintf("TlsConnection unexpected server Finished type=%u body=%Iu\r\n",
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection finish server transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = TlsHandshake12::VerifyFinished(
            context_,
            false,
            transcriptHash.Get(),
            transcriptHashLength,
            handshake.Body,
            handshake.BodyLength);
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection verify server Finished failed: 0x%08X body=%Iu\r\n",
                static_cast<ULONG>(status),
                handshake.BodyLength);
            return status;
        }
        if (handshake.BodyLength != TlsVerifyDataLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        RtlCopyMemory(tls12LastServerVerifyData_, handshake.Body, TlsVerifyDataLength);
        tls12LastServerVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection append server Finished transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (!tls12SessionScratch_.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        StoreTls12SessionFromHandshake(
            tls12SessionCache_,
            *tls12SessionScratch_.Get(),
            options,
            tlsPolicyIdentity_,
            serverHello,
            context_.Secrets(),
            tls12PendingTicket_,
            tls12PendingTicketLength_,
            tls12PendingTicketLifetimeHintSeconds_,
            negotiatedAlpn_,
            negotiatedAlpnLength_);
        context_.SetState(TlsHandshakeState::Established);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::ConnectTls13(
        core::ITransport& transport,
        const TlsClientConnectionOptions& options) noexcept
    {
        tls13RecordProtection_ = false;
        encrypted_ = false;

        NTSTATUS status = context_.InitializeClient13();
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("InitializeClient13", status);
        }
        status = transcript_.Initialize(crypto::HashAlgorithm::Sha256);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("InitializeSha256Transcript", status);
        }
        if (options.EarlyDataAccepted != nullptr) {
            *options.EarlyDataAccepted = false;
        }
        if (options.EarlyDataBytesSent != nullptr) {
            *options.EarlyDataBytesSent = 0;
        }
        RtlSecureZeroMemory(tls13TicketServerName_, sizeof(tls13TicketServerName_));
        tls13TicketServerNameLength_ = 0;
        tls13TicketServerNameCacheable_ = options.ServerNameLength <= Tls13MaxTicketServerNameLength;
        if (tls13TicketServerNameCacheable_) {
            RtlCopyMemory(tls13TicketServerName_, options.ServerName, options.ServerNameLength);
            tls13TicketServerName_[options.ServerNameLength] = '\0';
            tls13TicketServerNameLength_ = options.ServerNameLength;
        }

        HeapObject<crypto::KeyExchangeKeyPair> keyPair;
        if (!keyPair.IsValid()) {
            return LogTls13Failure("AllocateClientKeyExchangePair", STATUS_INSUFFICIENT_RESOURCES);
        }

        status = crypto::KeyExchange::GenerateKeyPair(
            providerCache_,
            crypto::KeyExchangeGroup::X25519,
            *keyPair.Get());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GenerateInitialKeyShare", status);
        }

        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::X25519;
        keyShare.KeyExchange = keyPair->PublicKey;
        keyShare.KeyExchangeLength = keyPair->PublicKeyLength;

        Tls13PskIdentity pskIdentity = {};
        const UCHAR* resumptionSecret = nullptr;
        SIZE_T resumptionSecretLength = 0;
        bool earlyDataAllowed = false;
        const Tls13SessionTicket* selectedTicket = nullptr;
        status = SelectTls13Ticket(
            options,
            pskIdentity,
            &resumptionSecret,
            &resumptionSecretLength,
            &earlyDataAllowed,
            &selectedTicket);
        if (status == STATUS_NOT_FOUND) {
            status = STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("SelectTls13Ticket", status);
        }

        HeapArray<UCHAR> binder(Tls13MaxBinderLength);
        if (!binder.IsValid()) {
            return LogTls13Failure("AllocatePskBinder", STATUS_INSUFFICIENT_RESOURCES);
        }
        if (pskIdentity.IdentityLength != 0) {
            pskIdentity.Binder = binder.Get();
            pskIdentity.BinderLength = context_.CipherSuite() == TlsCipherSuite::TlsAes256GcmSha384 ? 48 : 32;
        }

        Tls13ClientHelloOptions hello = {};
        hello.ServerName = options.ServerName;
        hello.ServerNameLength = options.ServerNameLength;
        hello.AlpnProtocols = options.AlpnProtocols;
        hello.AlpnProtocolCount = options.AlpnProtocolCount;
        hello.KeyShares = &keyShare;
        hello.KeyShareCount = 1;
        hello.PskIdentities = pskIdentity.IdentityLength != 0 ? &pskIdentity : nullptr;
        hello.PskIdentityCount = pskIdentity.IdentityLength != 0 ? 1 : 0;
        hello.OfferEarlyData = options.EnableEarlyData && earlyDataAllowed;

        UCHAR* message = nullptr;
        status = GetHandshakeScratch(
            TlsScratchClientHelloOffset,
            TlsScratchClientHelloLength,
            &message);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetClientHelloScratch", status);
        }
        RtlSecureZeroMemory(message, TlsScratchClientHelloLength);
        SIZE_T messageLength = 0;
        status = TlsHandshake13::EncodeClientHello(
            context_,
            hello,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("EncodeInitialClientHello", status);
        }

        if (pskIdentity.IdentityLength != 0) {
            status = ComputePskBinderForClientHello(
                providerCache_,
                context_,
                resumptionSecret,
                resumptionSecretLength,
                nullptr,
                0,
                nullptr,
                0,
                message,
                messageLength,
                binder.Get(),
                binder.Count(),
                &pskIdentity.BinderLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ComputePskBinder", status);
            }

            status = TlsHandshake13::EncodeClientHello(
                context_,
                hello,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodePskClientHello", status);
            }
        }

        UCHAR* firstClientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchFirstClientHelloOffset,
            TlsScratchFirstClientHelloLength,
            &firstClientHello);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetFirstClientHelloScratch", status);
        }
        RtlSecureZeroMemory(firstClientHello, TlsScratchFirstClientHelloLength);
        SIZE_T firstClientHelloLength = messageLength;
        if (firstClientHelloLength > TlsScratchFirstClientHelloLength) {
            return LogTls13Failure("StoreFirstClientHello", STATUS_BUFFER_TOO_SMALL);
        }
        RtlCopyMemory(firstClientHello, message, firstClientHelloLength);

        UCHAR* secondClientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchSecondClientHelloOffset,
            TlsScratchSecondClientHelloLength,
            &secondClientHello);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetSecondClientHelloScratch", status);
        }
        RtlSecureZeroMemory(secondClientHello, TlsScratchSecondClientHelloLength);
        SIZE_T secondClientHelloLength = 0;
        UCHAR* helloRetryRequest = nullptr;
        status = GetHandshakeScratch(
            TlsScratchHelloRetryOffset,
            TlsScratchHelloRetryLength,
            &helloRetryRequest);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetHelloRetryScratch", status);
        }
        RtlSecureZeroMemory(helloRetryRequest, TlsScratchHelloRetryLength);
        SIZE_T helloRetryRequestLength = 0;
        bool usedHelloRetryRequest = false;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecordWithVersion(transport, { 3, 3 }, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("SendInitialClientHello", status);
        }

        if (hello.OfferEarlyData &&
            options.EarlyDataReplaySafe &&
            options.EarlyData != nullptr &&
            options.EarlyDataLength != 0) {
            HeapArray<UCHAR> clientHelloHash(TlsMaxTranscriptHashLength);
            if (!clientHelloHash.IsValid()) {
                return LogTls13Failure("AllocateEarlyDataClientHelloHash", STATUS_INSUFFICIENT_RESOURCES);
            }

            SIZE_T clientHelloHashLength = 0;
            status = FinishTranscript(clientHelloHash.Get(), clientHelloHash.Count(), &clientHelloHashLength);
            if (NT_SUCCESS(status)) {
                status = context_.DeriveTls13EarlySecret(resumptionSecret, resumptionSecretLength);
            }
            if (NT_SUCCESS(status)) {
                status = context_.DeriveTls13ClientEarlyTrafficSecret(clientHelloHash.Get(), clientHelloHashLength);
            }
            if (NT_SUCCESS(status)) {
                status = context_.ConfigureTls13EarlyAesGcmState(clientWriteState_);
            }
            RtlSecureZeroMemory(clientHelloHash.Get(), clientHelloHash.Count());
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ConfigureEarlyDataKeys", status);
            }

            SIZE_T sent = 0;
            while (sent < options.EarlyDataLength) {
                const SIZE_T fragmentLimit = TlsMaxPlaintextLength - tls13RecordPaddingLength_;
                const SIZE_T chunk = (options.EarlyDataLength - sent) > fragmentLimit ?
                    fragmentLimit :
                    (options.EarlyDataLength - sent);
                status = SendProtectedRecord13(
                    transport,
                    TlsContentType::ApplicationData,
                    options.EarlyData + sent,
                    chunk);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("SendEarlyData", status);
                }
                sent += chunk;
            }
            if (options.EarlyDataBytesSent != nullptr) {
                *options.EarlyDataBytesSent = sent;
            }
        }

        TlsHandshakeMessageView handshake = {};
        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            RecordTls13FirstServerHelloFailure(options, status);
            return LogTls13Failure("ReadFirstServerHello", status);
        }

        Tls13ServerHelloView serverHello = {};
        status = TlsHandshake13::ParseServerHello(context_, handshake, serverHello);
        if (!NT_SUCCESS(status)) {
            const Tls13ServerHelloVersionSelection selection =
                ClassifyTls12ServerHelloFromTls13Attempt(options, handshake);
            if (selection == Tls13ServerHelloVersionSelection::Tls12Selected) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
            }
            else if (selection == Tls13ServerHelloVersionSelection::RejectedDowngrade) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::DecodeError, STATUS_INVALID_NETWORK_RESPONSE);
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            else if (status == STATUS_NOT_SUPPORTED) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
            }
            return LogTls13Failure("ParseFirstServerHello", status);
        }
        status = TlsHandshake13::ValidateServerHelloOffer(serverHello, hello);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ValidateFirstServerHelloOffer", status);
        }
        // TLS 1.3 parsing requires supported_versions == 0x0304. This client
        // does not perform in-handshake fallback; future fallback must validate
        // RFC 8446 downgrade sentinels at the negotiated version boundary.
        status = ValidateSelectedPskForConnection(
            context_,
            serverHello,
            hello.PskIdentityCount,
            selectedTicket);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ValidateFirstSelectedPskIdentity", status);
        }

        if (serverHello.IsHelloRetryRequest) {
            usedHelloRetryRequest = true;
            helloRetryRequestLength = lastHandshakeLength_;
            if (helloRetryRequestLength > TlsScratchHelloRetryLength) {
                return LogTls13Failure("StoreHelloRetryRequest", STATUS_BUFFER_TOO_SMALL);
            }
            RtlCopyMemory(helloRetryRequest, handshakeBuffer_ + lastHandshakeOffset_, helloRetryRequestLength);

            crypto::KeyExchangeGroup retryGroup = crypto::KeyExchangeGroup::Secp256r1;
            status = ToKeyExchangeGroup(serverHello.RetryGroup, &retryGroup);
            if (!NT_SUCCESS(status) || !crypto::KeyExchange::IsSupportedGroup(retryGroup)) {
                return LogTls13Failure("ValidateHelloRetryGroup", STATUS_NOT_SUPPORTED);
            }

            status = crypto::KeyExchange::GenerateKeyPair(
                providerCache_,
                retryGroup,
                *keyPair.Get());
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("GenerateRetryKeyShare", status);
            }

            keyShare.Group = serverHello.RetryGroup;
            keyShare.KeyExchange = keyPair->PublicKey;
            keyShare.KeyExchangeLength = keyPair->PublicKeyLength;
            if (pskIdentity.IdentityLength != 0 &&
                selectedTicket != nullptr &&
                selectedTicket->CipherSuite != context_.CipherSuite()) {
                return LogTls13Failure("ValidateHelloRetryPskCipher", STATUS_INVALID_NETWORK_RESPONSE);
            }
            status = TlsHandshake13::EncodeClientHello(
                context_,
                hello,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodeRetryClientHello", status);
            }
            if (pskIdentity.IdentityLength != 0) {
                status = ComputePskBinderForClientHello(
                    providerCache_,
                    context_,
                    resumptionSecret,
                    resumptionSecretLength,
                    firstClientHello,
                    firstClientHelloLength,
                    helloRetryRequest,
                    helloRetryRequestLength,
                    message,
                    messageLength,
                    binder.Get(),
                    binder.Count(),
                    &pskIdentity.BinderLength);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("ComputeRetryPskBinder", status);
                }

                status = TlsHandshake13::EncodeClientHello(
                    context_,
                    hello,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("EncodeRetryPskClientHello", status);
                }
            }
            secondClientHelloLength = messageLength;
            if (secondClientHelloLength > TlsScratchSecondClientHelloLength) {
                return LogTls13Failure("StoreSecondClientHello", STATUS_BUFFER_TOO_SMALL);
            }
            RtlCopyMemory(secondClientHello, message, secondClientHelloLength);

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendPlainRecordWithVersion(transport, { 3, 3 }, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("SendRetryClientHello", status);
            }

            status = ReadHandshakeMessage13(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ReadRetryServerHello", status);
            }

            status = TlsHandshake13::ParseServerHello(context_, handshake, serverHello);
            if (!NT_SUCCESS(status)) {
                const Tls13ServerHelloVersionSelection selection =
                    ClassifyTls12ServerHelloFromTls13Attempt(options, handshake);
                if (selection == Tls13ServerHelloVersionSelection::Tls12Selected) {
                    RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
                }
                else if (selection == Tls13ServerHelloVersionSelection::RejectedDowngrade) {
                    RecordHandshakeFailure(TlsHandshakeFailureCategory::DecodeError, STATUS_INVALID_NETWORK_RESPONSE);
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                else if (status == STATUS_NOT_SUPPORTED) {
                    RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
                }
                return LogTls13Failure("ParseRetryServerHello", status);
            }
            status = TlsHandshake13::ValidateServerHelloOffer(serverHello, hello);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ValidateRetryServerHelloOffer", status);
            }
            if (serverHello.IsHelloRetryRequest) {
                return LogTls13Failure("RejectRepeatedHelloRetryRequest", STATUS_INVALID_NETWORK_RESPONSE);
            }
            status = ValidateSelectedPskForConnection(
                context_,
                serverHello,
                hello.PskIdentityCount,
                selectedTicket);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ValidateRetrySelectedPskIdentity", status);
            }
        }

        HeapArray<UCHAR> sharedSecret(crypto::KeyExchangeMaxSharedSecretLength);
        if (!sharedSecret.IsValid()) {
            return LogTls13Failure("AllocateEcdhSharedSecret", STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T sharedSecretLength = 0;
        status = crypto::KeyExchange::DeriveSharedSecret(
            providerCache_,
            *keyPair.Get(),
            serverHello.KeyShare.KeyExchange,
            serverHello.KeyShare.KeyExchangeLength,
            sharedSecret.Get(),
            sharedSecret.Count(),
            &sharedSecretLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("DeriveEcdhSharedSecret", status);
        }

        status = transcript_.Initialize(TlsHandshake13::HashForCipherSuite(context_.CipherSuite()));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("InitializeSelectedCipherTranscript", status);
        }

        if (usedHelloRetryRequest) {
            HeapArray<UCHAR> firstHash(TlsMaxTranscriptHashLength);
            if (!firstHash.IsValid()) {
                RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
                return LogTls13Failure("AllocateHelloRetryFirstHash", STATUS_INSUFFICIENT_RESOURCES);
            }

            SIZE_T firstHashLength = 0;
            TlsTranscriptHash firstTranscript;
            status = firstTranscript.Initialize(TlsHandshake13::HashForCipherSuite(context_.CipherSuite()));
            if (NT_SUCCESS(status)) {
                status = firstTranscript.Update(firstClientHello, firstClientHelloLength);
            }
            if (NT_SUCCESS(status)) {
                status = firstTranscript.Finish(firstHash.Get(), firstHash.Count(), &firstHashLength);
            }

            HeapArray<UCHAR> synthetic;
            if (NT_SUCCESS(status)) {
                status = synthetic.Allocate(4 + TlsMaxTranscriptHashLength);
            }
            if (NT_SUCCESS(status)) {
                synthetic[0] = 254;
                synthetic[1] = static_cast<UCHAR>((firstHashLength >> 16) & 0xff);
                synthetic[2] = static_cast<UCHAR>((firstHashLength >> 8) & 0xff);
                synthetic[3] = static_cast<UCHAR>(firstHashLength & 0xff);
                RtlCopyMemory(synthetic.Get() + 4, firstHash.Get(), firstHashLength);
                status = transcript_.Update(synthetic.Get(), 4 + firstHashLength);
                RtlSecureZeroMemory(synthetic.Get(), synthetic.Count());
            }
            RtlSecureZeroMemory(firstHash.Get(), firstHash.Count());
            if (NT_SUCCESS(status)) {
                status = transcript_.Update(helloRetryRequest, helloRetryRequestLength);
            }
            if (NT_SUCCESS(status)) {
                status = transcript_.Update(secondClientHello, secondClientHelloLength);
            }
        }
        else {
            status = transcript_.Update(firstClientHello, firstClientHelloLength);
        }
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        }
        RtlSecureZeroMemory(firstClientHello, TlsScratchFirstClientHelloLength);
        RtlSecureZeroMemory(secondClientHello, TlsScratchSecondClientHelloLength);
        RtlSecureZeroMemory(helloRetryRequest, TlsScratchHelloRetryLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("RebuildTls13Transcript", status);
        }

        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!transcriptHash.IsValid()) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("AllocateTls13TranscriptHash", STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T transcriptHashLength = 0;
        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = context_.DeriveTls13EarlySecret(
                serverHello.SelectedPskIdentity != 0xffff ? resumptionSecret : nullptr,
                serverHello.SelectedPskIdentity != 0xffff ? resumptionSecretLength : 0);
        }
        if (NT_SUCCESS(status)) {
            status = context_.DeriveTls13HandshakeSecrets(
                sharedSecret.Get(),
                sharedSecretLength,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureTls13HandshakeAesGcmStates(clientWriteState_, serverWriteState_);
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("DeriveTls13HandshakeKeys", status);
        }

        encrypted_ = true;
        tls13RecordProtection_ = true;

        status = ReadOptionalCompatibilityChangeCipherSpec(transport);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ReadCompatibilityChangeCipherSpec", status);
        }

        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ReadEncryptedExtensions", status);
        }

        Tls13EncryptedExtensionsView encryptedExtensions = {};
        status = TlsHandshake13::ParseEncryptedExtensions(handshake, encryptedExtensions);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ParseEncryptedExtensions", status);
        }
        if (encryptedExtensions.AlpnLength != 0) {
            if (encryptedExtensions.AlpnLength >= 16) {
                return LogTls13Failure("StoreNegotiatedAlpn", STATUS_BUFFER_TOO_SMALL);
            }
            RtlCopyMemory(negotiatedAlpn_, encryptedExtensions.Alpn, encryptedExtensions.AlpnLength);
            negotiatedAlpn_[encryptedExtensions.AlpnLength] = '\0';
            negotiatedAlpnLength_ = encryptedExtensions.AlpnLength;
            if (!IsOfferedAlpn(options, negotiatedAlpn_, negotiatedAlpnLength_)) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::AlpnMismatch, STATUS_NOT_SUPPORTED);
                return LogTls13Failure("ValidateNegotiatedAlpn", STATUS_NOT_SUPPORTED);
            }
        }
        if (serverHello.SelectedPskIdentity != 0xffff && selectedTicket != nullptr) {
            if (selectedTicket->AlpnLength != encryptedExtensions.AlpnLength ||
                (selectedTicket->AlpnLength != 0 &&
                    RtlCompareMemory(
                        selectedTicket->Alpn,
                        encryptedExtensions.Alpn,
                        selectedTicket->AlpnLength) != selectedTicket->AlpnLength)) {
                return LogTls13Failure("ValidateResumedAlpnBinding", STATUS_INVALID_NETWORK_RESPONSE);
            }
        }
        if (encryptedExtensions.EarlyDataAccepted &&
            (!hello.OfferEarlyData || serverHello.SelectedPskIdentity == 0xffff)) {
            return LogTls13Failure("RejectUnexpectedEarlyDataAcceptance", STATUS_INVALID_NETWORK_RESPONSE);
        }
        if (options.EarlyDataAccepted != nullptr) {
            *options.EarlyDataAccepted = encryptedExtensions.EarlyDataAccepted;
        }

        HeapArray<UCHAR> clientCertificateRequestContext(255);
        if (!clientCertificateRequestContext.IsValid()) {
            return LogTls13Failure("AllocateClientCertificateRequestContext", STATUS_INSUFFICIENT_RESOURCES);
        }
        bool clientCertificateRequested = false;
        SIZE_T clientCertificateRequestContextLength = 0;
        bool sendClientCertificateVerify = false;
        TlsSignatureScheme clientCertificateSignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;

        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ReadCertificateOrRequest", status);
        }

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            Tls13CertificateRequestView certificateRequest = {};
            status = TlsHandshake13::ParseCertificateRequest(handshake, certificateRequest);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ParseCertificateRequest", status);
            }
            if (certificateRequest.ContextLength != 0 ||
                certificateRequest.ContextLength > clientCertificateRequestContext.Count()) {
                return LogTls13Failure("ValidateTls13ClientCertificateRequestContext", STATUS_INVALID_NETWORK_RESPONSE);
            }
            clientCertificateRequested = true;
            clientCertificateRequestContextLength = certificateRequest.ContextLength;
            if (clientCertificateRequestContextLength != 0) {
                RtlCopyMemory(
                    clientCertificateRequestContext.Get(),
                    certificateRequest.Context,
                    clientCertificateRequestContextLength);
            }
            const UCHAR* peerSignatureSchemes = nullptr;
            SIZE_T peerSignatureSchemesLength = 0;
            status = FindTls13CertificateRequestSignatureAlgorithms(
                certificateRequest,
                &peerSignatureSchemes,
                &peerSignatureSchemesLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("FindTls13ClientCertificateRequestSignatureAlgorithms", status);
            }
            if (clientCredential_ != nullptr &&
                clientCredential_->CertificateList != nullptr &&
                clientCredential_->CertificateListLength != 0 &&
                clientCredential_->Sign != nullptr) {
                status = SelectClientCredentialSignatureScheme(
                    options.Policy,
                    *clientCredential_,
                    peerSignatureSchemes,
                    peerSignatureSchemesLength,
                    &clientCertificateSignatureScheme);
                if (NT_SUCCESS(status)) {
                    sendClientCertificateVerify = true;
                }
                else if (status != STATUS_NOT_SUPPORTED) {
                    return LogTls13Failure("SelectTls13ClientCertificateSignature", status);
                }
            }

            status = ReadHandshakeMessage13(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ReadCertificateAfterRequest", status);
            }
        }

        Tls13CertificateView certificate = {};
        status = TlsHandshake13::ParseCertificate(handshake, certificate);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ParseCertificate", status);
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return LogTls13Failure("AllocateServerCertificatePublicKey", STATUS_INSUFFICIENT_RESOURCES);
        }

        status = ValidateTls13Certificate(certificate, options, *serverPublicKey.Get());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ValidateTls13Certificate", status);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("FinishTranscriptBeforeCertificateVerify", status);
        }

        status = ReadHandshakeMessage13(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return LogTls13Failure("ReadCertificateVerify", status);
        }

        Tls13CertificateVerifyView certificateVerify = {};
        status = TlsHandshake13::ParseCertificateVerify(handshake, certificateVerify);
        if (NT_SUCCESS(status)) {
            status = VerifyTls13CertificateVerify(
                certificateVerify,
                *serverPublicKey.Get(),
                serverCertificatePublicKeyAlgorithm_,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("VerifyCertificateVerify", status);
        }

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("AppendCertificateVerifyTranscript", status);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("FinishTranscriptBeforeServerFinished", status);
        }

        status = ReadHandshakeMessage13(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return LogTls13Failure("ReadServerFinished", status);
        }
        status = TlsHandshake13::VerifyFinished(
            context_,
            false,
            transcriptHash.Get(),
            transcriptHashLength,
            handshake.Body,
            handshake.BodyLength);
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("VerifyServerFinished", status);
        }

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("AppendServerFinishedTranscript", status);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = context_.DeriveTls13ApplicationSecrets(transcriptHash.Get(), transcriptHashLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("DeriveTls13ApplicationSecrets", status);
        }

        if (encryptedExtensions.EarlyDataAccepted) {
            status = TlsHandshake13::EncodeEndOfEarlyData(
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodeEndOfEarlyData", status);
            }

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("SendEndOfEarlyData", status);
            }
        }

        if (clientCertificateRequested) {
            const UCHAR* credentialCertificateList = sendClientCertificateVerify ? clientCredential_->CertificateList : nullptr;
            const SIZE_T credentialCertificateListLength = sendClientCertificateVerify ? clientCredential_->CertificateListLength : 0;
            status = TlsHandshake13::EncodeCertificate(
                clientCertificateRequestContext.Get(),
                clientCertificateRequestContextLength,
                credentialCertificateList,
                credentialCertificateListLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodeClientCertificate", status);
            }

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("SendClientCertificate", status);
            }

            if (sendClientCertificateVerify) {
                status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("FinishTranscriptBeforeClientCertificateVerify", status);
                }

                UCHAR* signedInput = nullptr;
                status = GetHandshakeScratch(
                    TlsScratchSignedInputOffset,
                    TlsScratchSignedInputLength,
                    &signedInput);
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                    return LogTls13Failure("GetClientCertificateVerifyInputScratch", status);
                }

                SIZE_T signedInputLength = 0;
                status = TlsHandshake13::BuildCertificateVerifyInput(
                    false,
                    transcriptHash.Get(),
                    transcriptHashLength,
                    signedInput,
                    TlsScratchSignedInputLength,
                    &signedInputLength);
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                    return LogTls13Failure("BuildClientCertificateVerifyInput", status);
                }

                HeapArray<UCHAR> signature(TlsScratchHandshakeBufferLength);
                if (!signature.IsValid()) {
                    RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                    return LogTls13Failure("AllocateClientCertificateVerifySignature", STATUS_INSUFFICIENT_RESOURCES);
                }

                SIZE_T signatureLength = 0;
                status = clientCredential_->Sign(
                    clientCredential_->SignContext,
                    clientCertificateSignatureScheme,
                    signedInput,
                    signedInputLength,
                    signature.Get(),
                    signature.Count(),
                    &signatureLength);
                RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                if (NT_SUCCESS(status)) {
                    status = TlsHandshake13::EncodeCertificateVerify(
                        clientCertificateSignatureScheme,
                        signature.Get(),
                        signatureLength,
                        message,
                        TlsScratchClientHelloLength,
                        &messageLength);
                }
                RtlSecureZeroMemory(signature.Get(), signature.Count());
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("EncodeClientCertificateVerify", status);
                }

                status = AppendTranscript(message, messageLength);
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
                }
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("SendClientCertificateVerify", status);
                }
            }
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake13::EncodeFinished(
                context_,
                true,
                transcriptHash.Get(),
                transcriptHashLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("EncodeClientFinished", status);
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("SendClientFinished", status);
        }

        status = context_.ConfigureTls13ApplicationAesGcmStates(clientWriteState_, serverWriteState_);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ConfigureTls13ApplicationKeys", status);
        }

        context_.SetState(TlsHandshakeState::Established);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::Send(
        core::ITransport& transport,
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }

        if (!IsEstablished() || !IsValidBuffer(data, length)) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T sent = 0;
        const UCHAR* bytes = static_cast<const UCHAR*>(data);
        while (sent < length) {
            const SIZE_T fragmentLimit =
                tls13RecordProtection_ ? TlsMaxPlaintextLength - tls13RecordPaddingLength_ : TlsMaxPlaintextLength;
            const SIZE_T chunk = (length - sent) > fragmentLimit ? fragmentLimit : (length - sent);
            NTSTATUS status = STATUS_SUCCESS;
            if (tls13RecordProtection_) {
                status = SendPendingTls13KeyUpdate(transport);
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::ApplicationData, bytes + sent, chunk);
                }
            }
            else {
                status = SendProtectedRecord(transport, TlsContentType::ApplicationData, bytes + sent, chunk);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            sent += chunk;
        }

        if (bytesSent != nullptr) {
            *bytesSent = sent;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::Receive(
        core::ITransport& transport,
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived,
        ULONG receiveTimeoutMilliseconds) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (!IsEstablished() || data == nullptr || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (plaintextLength_ != 0) {
            const SIZE_T copyLength = plaintextLength_ < length ? plaintextLength_ : length;
            RtlCopyMemory(data, plaintextBuffer_, copyLength);

            if (copyLength < plaintextLength_) {
                RtlMoveMemory(plaintextBuffer_, plaintextBuffer_ + copyLength, plaintextLength_ - copyLength);
            }

            plaintextLength_ -= copyLength;
            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }

            return STATUS_SUCCESS;
        }

        TlsReceiveDeadline receiveDeadline = MakeReceiveDeadline(receiveTimeoutMilliseconds);
        ULONG emptyApplicationRecords = 0;
        ULONG postHandshakeRecords = 0;
        for (;;) {
            TlsMutablePlaintextRecord record = {};
            NTSTATUS status = ReadRecord(transport, record, receiveTimeoutMilliseconds, &receiveDeadline);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection read record failed before HTTP: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }

            if (tls13RecordProtection_ && record.ContentType == TlsContentType::Handshake) {
                if (++postHandshakeRecords > TlsApplicationMaxPostHandshakeRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = ConsumeTls13PostHandshakeRecord(transport, record.Fragment, record.FragmentLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                continue;
            }

            if (!tls13RecordProtection_ &&
                context_.Protocol() == TlsProtocol::Tls12 &&
                record.ContentType == TlsContentType::Handshake) {
                if (++postHandshakeRecords > TlsApplicationMaxPostHandshakeRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = ConsumeTls12PostHandshakeRecord(transport, record.Fragment, record.FragmentLength);
                if (!NT_SUCCESS(status)) {
                    kprintf("TlsConnection consume TLS1.2 post-handshake message during HTTP read failed: 0x%08X length=%Iu\r\n",
                        static_cast<ULONG>(status),
                        record.FragmentLength);
                    return status;
                }
                continue;
            }

            if (record.ContentType == TlsContentType::Alert) {
                TlsAlert alert = {};
                status = TlsRecordLayer::DecodeAlert(record.Fragment, record.FragmentLength, alert);
                if (!NT_SUCCESS(status)) {
                    kprintf("TlsConnection decode alert during HTTP read failed: 0x%08X length=%Iu\r\n",
                        static_cast<ULONG>(status),
                        record.FragmentLength);
                    return status;
                }

                kprintf("TlsConnection receive alert during HTTP read level=%u description=%u\r\n",
                    static_cast<unsigned>(alert.Level),
                    static_cast<unsigned>(alert.Description));
                return alert.CloseNotify ? STATUS_CONNECTION_DISCONNECTED : STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!tls13RecordProtection_ &&
                context_.Protocol() == TlsProtocol::Tls12 &&
                (handshakeLength_ != 0 || handshakeConsumed_ != 0)) {
                kprintf("TlsConnection incomplete TLS1.2 handshake before application data length=%Iu consumed=%Iu\r\n",
                    handshakeLength_,
                    handshakeConsumed_);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (record.ContentType != TlsContentType::ApplicationData) {
                kprintf("TlsConnection unexpected record during HTTP read type=%u length=%Iu\r\n",
                    static_cast<unsigned>(record.ContentType),
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (record.FragmentLength == 0) {
                ++emptyApplicationRecords;
                if (emptyApplicationRecords > TlsApplicationMaxEmptyRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                continue;
            }

            emptyApplicationRecords = 0;
            postHandshakeRecords = 0;
            const SIZE_T copyLength = record.FragmentLength < length ? record.FragmentLength : length;
            RtlCopyMemory(data, record.Fragment, copyLength);

            if (copyLength < record.FragmentLength) {
                plaintextLength_ = record.FragmentLength - copyLength;
                RtlMoveMemory(plaintextBuffer_, record.Fragment + copyLength, plaintextLength_);
            }

            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }

            return STATUS_SUCCESS;
        }
    }

    bool TlsConnection::IsEstablished() const noexcept
    {
        return context_.State() == TlsHandshakeState::Established;
    }

    const TlsContext& TlsConnection::Context() const noexcept
    {
        return context_;
    }

    const char* TlsConnection::NegotiatedAlpn() const noexcept
    {
        return negotiatedAlpnLength_ > 0 ? negotiatedAlpn_ : nullptr;
    }

    SIZE_T TlsConnection::NegotiatedAlpnLength() const noexcept
    {
        return negotiatedAlpnLength_;
    }

    const TlsHandshakeFailure& TlsConnection::LastHandshakeFailure() const noexcept
    {
        return lastHandshakeFailure_;
    }

    void TlsConnection::RecordTls13FirstServerHelloFailure(
        const TlsClientConnectionOptions& options,
        NTSTATUS status) noexcept
    {
        if (!CanConfirmTls12FromTls13Attempt(options)) {
            return;
        }

        lastHandshakeFailure_.BeforeTls13FirstServerHello = true;
        if (status == STATUS_INVALID_NETWORK_RESPONSE &&
            lastHandshakeFailure_.HasPeerAlert &&
            (lastHandshakeFailure_.PeerAlert.Description == TlsAlertDescription::HandshakeFailure ||
                lastHandshakeFailure_.PeerAlert.CloseNotify)) {
            lastHandshakeFailure_.Category = TlsHandshakeFailureCategory::VersionNegotiation;
            lastHandshakeFailure_.Status = status;
        }
    }

    void TlsConnection::ClearHandshakeFailure() noexcept
    {
        lastHandshakeFailure_ = {};
    }

    void TlsConnection::RecordHandshakeFailure(
        TlsHandshakeFailureCategory category,
        NTSTATUS status) noexcept
    {
        if (category == TlsHandshakeFailureCategory::None) {
            return;
        }

        lastHandshakeFailure_.Category = category;
        lastHandshakeFailure_.Status = status;
        lastHandshakeFailure_.PeerAlert = {};
        lastHandshakeFailure_.HasPeerAlert = false;
    }

    void TlsConnection::RecordPeerAlertFailure(const TlsMutablePlaintextRecord& record) noexcept
    {
        TlsAlert alert = {};
        const NTSTATUS status = TlsRecordLayer::DecodeAlert(record.Fragment, record.FragmentLength, alert);
        if (!NT_SUCCESS(status)) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::DecodeError, status);
            return;
        }

        lastHandshakeFailure_.Category = CategoryForPeerAlert(alert);
        lastHandshakeFailure_.Status = STATUS_INVALID_NETWORK_RESPONSE;
        lastHandshakeFailure_.PeerAlert = alert;
        lastHandshakeFailure_.HasPeerAlert = true;
    }

    NTSTATUS TlsConnection::SendPlainRecord(
        core::ITransport& transport,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        return SendPlainRecordWithVersion(transport, context_.Version(), contentType, fragment, fragmentLength);
    }

    NTSTATUS TlsConnection::SendPlainRecordWithVersion(
        core::ITransport& transport,
        TlsProtocolVersion version,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = version;
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;

        NTSTATUS status = TlsRecordLayer::EncodePlaintext(record, outputBuffer_, TlsIoBufferLength, &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(transport, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        return status;
    }

    NTSTATUS TlsConnection::SendProtectedRecord(
        core::ITransport& transport,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = context_.Version();
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;

        NTSTATUS status = clientWriteState_.EncryptThenMac ?
            TlsRecordLayer::ProtectAesCbcEncryptThenMac(
                record,
                clientWriteState_,
                outputBuffer_,
                TlsIoBufferLength,
                &written) :
            TlsRecordLayer::ProtectAesGcm(record, clientWriteState_, outputBuffer_, TlsIoBufferLength, &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(transport, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        return status;
    }

    NTSTATUS TlsConnection::SendPendingTls13KeyUpdate(core::ITransport& transport) noexcept
    {
        if (ExchangeTlsFlag(&tls13PeerRequestedKeyUpdate_, 0) == 0) {
            return STATUS_SUCCESS;
        }

        SIZE_T messageLength = 0;
        NTSTATUS status = TlsHandshake13::EncodeKeyUpdate(
            Tls13KeyUpdateRequest::UpdateNotRequested,
            tls13KeyUpdateMessage_,
            sizeof(tls13KeyUpdateMessage_),
            &messageLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendProtectedRecord13(transport, TlsContentType::Handshake, tls13KeyUpdateMessage_, messageLength);
        RtlSecureZeroMemory(tls13KeyUpdateMessage_, sizeof(tls13KeyUpdateMessage_));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return context_.UpdateTls13ApplicationTrafficSecret(true, clientWriteState_);
    }

    NTSTATUS TlsConnection::SendProtectedRecord13(
        core::ITransport& transport,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = { 3, 3 };
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;
        record.Tls13PaddingLength = tls13RecordPaddingLength_;

        if (tls13InnerPlaintextBuffer_ == nullptr) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm13WithScratch(
            record,
            clientWriteState_,
            tls13InnerPlaintextBuffer_,
            TlsMaxPlaintextLength + 1,
            outputBuffer_,
            TlsIoBufferLength,
            &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(transport, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        return status;
    }

    NTSTATUS TlsConnection::ReadRecord(
        core::ITransport& transport,
        TlsMutablePlaintextRecord& record,
        ULONG receiveTimeoutMilliseconds,
        const TlsReceiveDeadline* receiveDeadline) noexcept
    {
        record = {};

        for (;;) {
            TlsRecordView view = {};
            NTSTATUS status = TlsRecordLayer::Parse(inputBuffer_, inputLength_, view);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (inputLength_ < TlsRecordHeaderLength) {
                    status = ReadExact(
                        transport,
                        inputBuffer_ + inputLength_,
                        TlsRecordHeaderLength - inputLength_,
                        receiveTimeoutMilliseconds,
                        receiveDeadline);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    inputLength_ = TlsRecordHeaderLength;
                    continue;
                }

                const SIZE_T fragmentLength =
                    (static_cast<SIZE_T>(inputBuffer_[3]) << 8) | inputBuffer_[4];
                if (fragmentLength > TlsMaxPlaintextLength + 2048) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T recordLength = TlsRecordHeaderLength + fragmentLength;
                if (recordLength > TlsIoBufferLength) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                status = RecordReceivedTlsRecord(recordLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = ReadExact(
                    transport,
                    inputBuffer_ + inputLength_,
                    recordLength - inputLength_,
                    receiveTimeoutMilliseconds,
                    receiveDeadline);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                inputLength_ = recordLength;
                continue;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (encrypted_ &&
                !(tls13RecordProtection_ && view.ContentType == TlsContentType::ChangeCipherSpec)) {
                if (tls13RecordProtection_) {
                    status = TlsRecordLayer::UnprotectAesGcm13(
                        view,
                        serverWriteState_,
                        plaintextBuffer_,
                        TlsApplicationBufferLength,
                        record);
                }
                else if (serverWriteState_.EncryptThenMac) {
                    status = TlsRecordLayer::UnprotectAesCbcEncryptThenMac(
                        view,
                        serverWriteState_,
                        plaintextBuffer_,
                        TlsApplicationBufferLength,
                        record);
                }
                else {
                    status = TlsRecordLayer::UnprotectAesGcm(
                        view,
                        serverWriteState_,
                        plaintextBuffer_,
                        TlsApplicationBufferLength,
                        record);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                plaintextLength_ = 0;
            }
            else {
                if (view.FragmentLength > TlsMaxPlaintextLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (view.FragmentLength > TlsApplicationBufferLength) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                record.ContentType = view.ContentType;
                record.Version = view.Version;
                record.FragmentLength = view.FragmentLength;

                if (view.FragmentLength != 0) {
                    RtlCopyMemory(plaintextBuffer_, view.Fragment, view.FragmentLength);
                }

                record.Fragment = plaintextBuffer_;
                plaintextLength_ = 0;
            }

            const SIZE_T consumed = view.BytesConsumed;
            if (consumed < inputLength_) {
                RtlMoveMemory(inputBuffer_, inputBuffer_ + consumed, inputLength_ - consumed);
            }

            inputLength_ -= consumed;
            if (record.ContentType == TlsContentType::Alert) {
                RecordPeerAlertFailure(record);
            }
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS TlsConnection::RecordReceivedTlsRecord(SIZE_T recordLength) noexcept
    {
        const ULONGLONG recordBytes = static_cast<ULONGLONG>(recordLength);
        if (tlsConnectionRecordsRead_ >= KH_HARD_MAX_CONNECTION_FRAMES ||
            (KH_HARD_MAX_CONNECTION_BYTES != 0 &&
                (recordBytes > KH_HARD_MAX_CONNECTION_BYTES ||
                    tlsConnectionBytesRead_ > KH_HARD_MAX_CONNECTION_BYTES - recordBytes))) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ++tlsConnectionRecordsRead_;
        tlsConnectionBytesRead_ += recordBytes;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::ReadServerChangeCipherSpec(
        core::ITransport& transport,
        bool allowNewSessionTicket) noexcept
    {
        ULONG recordsRead = 0;
        for (;;) {
            if (++recordsRead > TlsHandshakeMaxRecords) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            TlsMutablePlaintextRecord record = {};
            NTSTATUS status = ReadRecord(
                transport,
                record,
                handshakeReceiveTimeoutMilliseconds_,
                &handshakeReceiveDeadline_);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection ReadServerChangeCipherSpec ReadRecord failed: 0x%08X\r\n",
                    static_cast<ULONG>(status));
                return status;
            }

            if (record.ContentType == TlsContentType::Alert) {
                kprintf("TlsConnection ReadServerChangeCipherSpec alert length=%Iu\r\n", record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (record.ContentType == TlsContentType::ChangeCipherSpec) {
                if (handshakeLength_ != 0 ||
                    handshakeConsumed_ != 0 ||
                    record.FragmentLength != 1 ||
                    record.Fragment == nullptr ||
                    record.Fragment[0] != 1) {
                    kprintf("TlsConnection invalid server ChangeCipherSpec len=%Iu hs=%Iu consumed=%Iu\r\n",
                        record.FragmentLength,
                        handshakeLength_,
                        handshakeConsumed_);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                return STATUS_SUCCESS;
            }

            if (record.ContentType != TlsContentType::Handshake) {
                kprintf("TlsConnection expected ChangeCipherSpec got type=%u length=%Iu\r\n",
                    static_cast<unsigned>(record.ContentType),
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!allowNewSessionTicket) {
                kprintf("TlsConnection got unnegotiated handshake before ChangeCipherSpec length=%Iu\r\n",
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = ConsumeOptionalPlainHandshakeRecord(record.Fragment, record.FragmentLength);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection consume NewSessionTicket failed: 0x%08X length=%Iu\r\n",
                    static_cast<ULONG>(status),
                    record.FragmentLength);
                return status;
            }
        }
    }

    NTSTATUS TlsConnection::ReadOptionalCompatibilityChangeCipherSpec(core::ITransport& transport) noexcept
    {
        TlsRecordView view = {};
        NTSTATUS status = TlsRecordLayer::Parse(inputBuffer_, inputLength_, view);
        if (status == STATUS_MORE_PROCESSING_REQUIRED) {
            if (inputLength_ < TlsRecordHeaderLength) {
                status = ReadExact(
                    transport,
                    inputBuffer_ + inputLength_,
                    TlsRecordHeaderLength - inputLength_,
                    handshakeReceiveTimeoutMilliseconds_,
                    &handshakeReceiveDeadline_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                inputLength_ = TlsRecordHeaderLength;
            }

            const SIZE_T fragmentLength =
                (static_cast<SIZE_T>(inputBuffer_[3]) << 8) | inputBuffer_[4];
            const SIZE_T recordLength = TlsRecordHeaderLength + fragmentLength;
            if (recordLength > TlsIoBufferLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            status = ReadExact(
                transport,
                inputBuffer_ + inputLength_,
                recordLength - inputLength_,
                handshakeReceiveTimeoutMilliseconds_,
                &handshakeReceiveDeadline_);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            inputLength_ = recordLength;
            status = TlsRecordLayer::Parse(inputBuffer_, inputLength_, view);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (view.ContentType != TlsContentType::ChangeCipherSpec) {
            return STATUS_SUCCESS;
        }

        if (view.FragmentLength != 1 || view.Fragment == nullptr || view.Fragment[0] != 1) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T consumed = view.BytesConsumed;
        if (consumed < inputLength_) {
            RtlMoveMemory(inputBuffer_, inputBuffer_ + consumed, inputLength_ - consumed);
        }
        inputLength_ -= consumed;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::ReadHandshakeMessage13(
        core::ITransport& transport,
        TlsHandshakeMessageView& message,
        bool updateTranscript) noexcept
    {
        return ReadHandshakeMessage(transport, message, updateTranscript);
    }

    NTSTATUS TlsConnection::ValidateTls13Certificate(
        const Tls13CertificateView& certificate,
        const TlsClientConnectionOptions& options,
        crypto::CngKey& serverPublicKey) noexcept
    {
        UCHAR* legacyCertificateList = nullptr;
        NTSTATUS status = GetHandshakeScratch(
            TlsScratchLegacyCertificateOffset,
            TlsScratchLegacyCertificateLength,
            &legacyCertificateList);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetTls13LegacyCertificateScratch", status);
        }

        RtlZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
        SIZE_T legacyCertificateListLength = 0;
        SIZE_T certificateCount = 0;
        status = ConvertTls13CertificateListToLegacy(
            certificate,
            legacyCertificateList,
            TlsScratchLegacyCertificateLength,
            &legacyCertificateListLength,
            &certificateCount);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return LogTls13Failure("ConvertTls13CertificateList", status);
        }

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = options.ProviderCache;
        validation.VerifyCertificate = options.VerifyCertificate;
        validation.RequireRevocationCheck = options.Policy.RequireRevocationCheck;

        CertificateChainView chain = {};
        chain.Certificates = legacyCertificateList;
        chain.CertificatesLength = legacyCertificateListLength;
        chain.CertificateCount = certificateCount;

        HeapObject<CertificateValidationResult> result;
        if (!result.IsValid()) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = CertificateValidator::ValidateChain(chain, validation, result.Get());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return LogTls13Failure("ValidateTls13CertificateChain", status);
        }
        serverCertificatePublicKeyAlgorithm_ = result->Leaf.PublicKeyAlgorithm;
        if (result->Leaf.HasKeyUsage && !result->Leaf.AllowsDigitalSignature) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return STATUS_TRUST_FAILURE;
        }

        if (result->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed25519) {
            if (result->Leaf.PublicKey == nullptr ||
                result->Leaf.PublicKeyLength != crypto::Ed25519PublicKeyLength) {
                RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd25519PublicKey_, result->Leaf.PublicKey, crypto::Ed25519PublicKeyLength);
            serverEd25519PublicKeyLength_ = crypto::Ed25519PublicKeyLength;
        }
        else if (result->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed448) {
            if (result->Leaf.PublicKey == nullptr ||
                result->Leaf.PublicKeyLength != crypto::Ed448PublicKeyLength) {
                RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd448PublicKey_, result->Leaf.PublicKey, crypto::Ed448PublicKeyLength);
            serverEd448PublicKeyLength_ = crypto::Ed448PublicKeyLength;
        }
        else {
            status = CertificateValidator::ImportSubjectPublicKey(providerCache_, result->Leaf, serverPublicKey);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
                return LogTls13Failure("ImportTls13CertificatePublicKey", status);
            }
        }
        RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::VerifyTls13CertificateVerify(
        const Tls13CertificateVerifyView& certificateVerify,
        const crypto::CngKey& serverPublicKey,
        CertificatePublicKeyAlgorithm publicKeyAlgorithm,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength) noexcept
    {
        if (!SignatureSchemeMatchesPublicKey(publicKeyAlgorithm, certificateVerify.SignatureScheme)) {
            return LogTls13Failure("ValidateTls13CertificateVerifyKeyAlgorithm", STATUS_INVALID_NETWORK_RESPONSE);
        }

        crypto::HashAlgorithm hashAlgorithm = crypto::HashAlgorithm::Sha256;
        crypto::SignatureAlgorithm signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        NTSTATUS status = GetTls13SignatureParameters(
            certificateVerify.SignatureScheme,
            &hashAlgorithm,
            &signatureAlgorithm);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetTls13CertificateVerifySignatureParameters", STATUS_INVALID_NETWORK_RESPONSE);
        }

        UCHAR* signedInput = nullptr;
        status = GetHandshakeScratch(
            TlsScratchSignedInputOffset,
            TlsScratchSignedInputLength,
            &signedInput);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetTls13CertificateVerifyInputScratch", status);
        }
        RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
        SIZE_T signedInputLength = 0;
        status = TlsHandshake13::BuildCertificateVerifyInput(
            true,
            transcriptHash,
            transcriptHashLength,
            signedInput,
            TlsScratchSignedInputLength,
            &signedInputLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("BuildTls13CertificateVerifyInput", status);
        }

        if (certificateVerify.SignatureScheme == TlsSignatureScheme::Ed25519) {
            if (serverEd25519PublicKeyLength_ != crypto::Ed25519PublicKeyLength) {
                RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                return LogTls13Failure("VerifyTls13CertificateVerifyEd25519Key", STATUS_INVALID_NETWORK_RESPONSE);
            }

            status = crypto::CngProvider::VerifyEd25519(
                serverEd25519PublicKey_,
                serverEd25519PublicKeyLength_,
                signedInput,
                signedInputLength,
                certificateVerify.Signature,
                certificateVerify.SignatureLength);
            RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
            if (!NT_SUCCESS(status)) {
                status = LogTls13Failure("VerifyTls13CertificateVerifyEd25519Signature", status);
            }
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }
        if (certificateVerify.SignatureScheme == TlsSignatureScheme::Ed448) {
            if (serverEd448PublicKeyLength_ != crypto::Ed448PublicKeyLength) {
                RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                return LogTls13Failure("VerifyTls13CertificateVerifyEd448Key", STATUS_INVALID_NETWORK_RESPONSE);
            }

            status = crypto::CngProvider::VerifyEd448(
                serverEd448PublicKey_,
                serverEd448PublicKeyLength_,
                signedInput,
                signedInputLength,
                certificateVerify.Signature,
                certificateVerify.SignatureLength);
            RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
            if (!NT_SUCCESS(status)) {
                status = LogTls13Failure("VerifyTls13CertificateVerifyEd448Signature", status);
            }
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }

        HeapArray<UCHAR> hash(64);
        if (!hash.IsValid()) {
            return LogTls13Failure("AllocateTls13CertificateVerifyHash", STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T hashLength = 0;
        status = crypto::CngProvider::Hash(
            providerCache_,
            hashAlgorithm,
            signedInput,
            signedInputLength,
            hash.Get(),
            hash.Count(),
            &hashLength);
        RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("HashTls13CertificateVerifyInput", status);
        }

        status = crypto::CngProvider::VerifySignature(
            providerCache_,
            signatureAlgorithm,
            serverPublicKey,
            hash.Get(),
            hashLength,
            certificateVerify.Signature,
            certificateVerify.SignatureLength);
        if (!NT_SUCCESS(status)) {
            status = LogTls13Failure("VerifyTls13CertificateVerifySignature", status);
        }
        RtlSecureZeroMemory(hash.Get(), hash.Count());
        return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
    }

    NTSTATUS TlsConnection::StoreTls13Ticket(
        const Tls13NewSessionTicketView& ticket,
        Tls13SessionCache* externalCache) noexcept
    {
        if (ticket.Ticket == nullptr ||
            ticket.TicketLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (ticket.LifetimeSeconds == 0 ||
            ticket.LifetimeSeconds > Tls13MaxTicketLifetimeSeconds ||
            !tls13TicketServerNameCacheable_ ||
            tls13TicketServerNameLength_ == 0 ||
            negotiatedAlpnLength_ > Tls13MaxTicketAlpnLength) {
            return STATUS_SUCCESS;
        }
        if (ticket.TicketLength > Tls13MaxTicketIdentityLength ||
            ticket.NonceLength > Tls13MaxTicketNonceLength) {
#if defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
            kprintf(
                "TlsConnection TLS1.3 skip uncacheable NewSessionTicket ticket=%Iu nonce=%Iu\r\n",
                ticket.TicketLength,
                ticket.NonceLength);
#endif
            return STATUS_SUCCESS;
        }

        if (!tls13SessionTicketScratch_.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Tls13SessionTicket& stored = *tls13SessionTicketScratch_.Get();
        RtlSecureZeroMemory(&stored, sizeof(stored));
        stored.IdentityLength = ticket.TicketLength;
        RtlCopyMemory(stored.Identity, ticket.Ticket, ticket.TicketLength);
        stored.NonceLength = ticket.NonceLength;
        if (ticket.NonceLength != 0) {
            RtlCopyMemory(stored.Nonce, ticket.Nonce, ticket.NonceLength);
        }
        stored.LifetimeSeconds = ticket.LifetimeSeconds;
        stored.AgeAdd = ticket.AgeAdd;
        stored.MaxEarlyDataSize = ticket.MaxEarlyDataSize;
        stored.IssueTimeMilliseconds = CurrentMilliseconds();
        stored.Version = { 3, 4 };
        stored.ServerNameLength = tls13TicketServerNameLength_;
        RtlCopyMemory(stored.ServerName, tls13TicketServerName_, tls13TicketServerNameLength_);
        stored.ServerName[tls13TicketServerNameLength_] = '\0';
        stored.AlpnLength = negotiatedAlpnLength_;
        if (negotiatedAlpnLength_ != 0) {
            RtlCopyMemory(stored.Alpn, negotiatedAlpn_, negotiatedAlpnLength_);
            stored.Alpn[negotiatedAlpnLength_] = '\0';
        }
        stored.CipherSuite = context_.CipherSuite();
        stored.PolicyIdentity = tlsPolicyIdentity_;

        NTSTATUS status = context_.DeriveTls13ResumptionSecret(
            stored.Nonce,
            stored.NonceLength,
            stored.ResumptionSecret,
            sizeof(stored.ResumptionSecret),
            &stored.ResumptionSecretLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = context_.StoreTls13Ticket(stored);
        if (NT_SUCCESS(status) && externalCache != nullptr) {
            if (externalCache->TicketCount < Tls13MaxTicketCount) {
                externalCache->Tickets[externalCache->TicketCount] = stored;
                ++externalCache->TicketCount;
            }
            else {
                for (SIZE_T index = 1; index < Tls13MaxTicketCount; ++index) {
                    externalCache->Tickets[index - 1] = externalCache->Tickets[index];
                }
                externalCache->Tickets[Tls13MaxTicketCount - 1] = stored;
            }
        }
        RtlSecureZeroMemory(&stored, sizeof(stored));
        return status;
    }

    NTSTATUS TlsConnection::SelectTls13Ticket(
        const TlsClientConnectionOptions& options,
        Tls13PskIdentity& identity,
        const UCHAR** resumptionSecret,
        SIZE_T* resumptionSecretLength,
        bool* earlyDataAllowed,
        const Tls13SessionTicket** selectedTicket) noexcept
    {
        identity = {};
        if (resumptionSecret != nullptr) {
            *resumptionSecret = nullptr;
        }
        if (resumptionSecretLength != nullptr) {
            *resumptionSecretLength = 0;
        }
        if (earlyDataAllowed != nullptr) {
            *earlyDataAllowed = false;
        }
        if (selectedTicket != nullptr) {
            *selectedTicket = nullptr;
        }

        if (resumptionSecret == nullptr ||
            resumptionSecretLength == nullptr ||
            earlyDataAllowed == nullptr ||
            selectedTicket == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!options.EnableSessionResumption || options.SessionCache == nullptr || options.SessionCache->TicketCount == 0) {
            return STATUS_NOT_FOUND;
        }
        if (options.SessionCache->TicketCount > Tls13MaxTicketCount) {
            return STATUS_INVALID_PARAMETER;
        }

        const ULONGLONG now = CurrentMilliseconds();
        for (SIZE_T index = options.SessionCache->TicketCount; index > 0; --index) {
            const Tls13SessionTicket& ticket = options.SessionCache->Tickets[index - 1];
            if (ticket.IdentityLength == 0 ||
                ticket.IdentityLength > Tls13MaxTicketIdentityLength ||
                ticket.ResumptionSecretLength == 0 ||
                ticket.ResumptionSecretLength > Tls13MaxSecretLength ||
                ticket.LifetimeSeconds == 0 ||
                ticket.LifetimeSeconds > Tls13MaxTicketLifetimeSeconds ||
                ticket.IssueTimeMilliseconds == 0 ||
                ticket.Version.Major != 3 ||
                ticket.Version.Minor != 4 ||
                ticket.PolicyIdentity != tlsPolicyIdentity_ ||
                !TlsHandshake13::IsSupportedCipherSuite(ticket.CipherSuite) ||
                !TicketServerNameMatches(ticket, options) ||
                !TicketAlpnMatches(ticket, options)) {
                continue;
            }

            ULONGLONG lifetimeMilliseconds = 0;
            ULONGLONG expiresAt = 0;
            if (!MultiplySecondsToMilliseconds(ticket.LifetimeSeconds, &lifetimeMilliseconds) ||
                !AddUnsigned64(ticket.IssueTimeMilliseconds, lifetimeMilliseconds, &expiresAt) ||
                now < ticket.IssueTimeMilliseconds ||
                now >= expiresAt) {
                continue;
            }

            const NTSTATUS status = context_.SetCipherSuite(ticket.CipherSuite);
            if (!NT_SUCCESS(status)) {
                continue;
            }

            identity.Identity = ticket.Identity;
            identity.IdentityLength = ticket.IdentityLength;
            identity.ObfuscatedTicketAge =
                static_cast<ULONG>(now - ticket.IssueTimeMilliseconds) + ticket.AgeAdd;
            *resumptionSecret = ticket.ResumptionSecret;
            *resumptionSecretLength = ticket.ResumptionSecretLength;
            *earlyDataAllowed = options.EnableEarlyData &&
                options.EarlyDataReplaySafe &&
                ticket.MaxEarlyDataSize != 0 &&
                options.EarlyData != nullptr &&
                options.EarlyDataLength <= ticket.MaxEarlyDataSize;
            *selectedTicket = &ticket;
            return STATUS_SUCCESS;
        }

        return STATUS_NOT_FOUND;
    }

    NTSTATUS TlsConnection::ConsumeOptionalPlainHandshakeRecord(const UCHAR* fragment, SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr ||
            fragmentLength == 0 ||
            fragmentLength > TlsHandshakeBufferLength - handshakeLength_) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (fragmentLength != 0) {
            RtlCopyMemory(handshakeBuffer_ + handshakeLength_, fragment, fragmentLength);
            handshakeLength_ += fragmentLength;
        }

        SIZE_T messageCount = 0;
        for (;;) {
            TlsHandshakeMessageView parsed = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                handshakeBuffer_ + handshakeConsumed_,
                handshakeLength_ - handshakeConsumed_,
                parsed);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (handshakeConsumed_ != 0) {
                    if (handshakeConsumed_ < handshakeLength_) {
                        RtlMoveMemory(
                            handshakeBuffer_,
                            handshakeBuffer_ + handshakeConsumed_,
                            handshakeLength_ - handshakeConsumed_);
                    }

                    handshakeLength_ -= handshakeConsumed_;
                    handshakeConsumed_ = 0;
                }

                return STATUS_SUCCESS;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (++messageCount > KhTlsMaxPostHandshakeMessagesPerRecord) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            Tls12NewSessionTicketView ticket = {};
            status = TlsHandshake12::ParseNewSessionTicket(parsed, ticket);
            if (!NT_SUCCESS(status)) {
                if (status == STATUS_NOT_SUPPORTED) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                return status;
            }
            if (ticket.Ticket != nullptr &&
                ticket.TicketLength != 0 &&
                ticket.TicketLength <= Tls12MaxTicketLength) {
                RtlSecureZeroMemory(tls12PendingTicket_, sizeof(tls12PendingTicket_));
                RtlCopyMemory(tls12PendingTicket_, ticket.Ticket, ticket.TicketLength);
                tls12PendingTicketLength_ = ticket.TicketLength;
                tls12PendingTicketLifetimeHintSeconds_ = ticket.LifetimeHintSeconds;
            }

            // TLS 1.2 NewSessionTicket is sent before ChangeCipherSpec and remains
            // part of the handshake transcript used by Finished.
            status = AppendTranscript(handshakeBuffer_ + handshakeConsumed_, parsed.BytesConsumed);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            handshakeConsumed_ += parsed.BytesConsumed;
            if (handshakeConsumed_ == handshakeLength_) {
                handshakeLength_ = 0;
                handshakeConsumed_ = 0;
                return STATUS_SUCCESS;
            }
        }
    }

    NTSTATUS TlsConnection::FinishTls12RenegotiationAttempt(NTSTATUS status) noexcept
    {
        tls12Renegotiating_ = false;
        tls12PendingClientWriteState_.Reset();
        tls12PendingServerWriteState_.Reset();
        ReleaseHandshakeScratch();
        certificateScratchAllocator_ = nullptr;
        if (!NT_SUCCESS(status)) {
            if (lastHandshakeFailure_.Category == TlsHandshakeFailureCategory::None) {
                RecordHandshakeFailure(CategoryForStatus(status), status);
            }
            context_.SetState(TlsHandshakeState::Failed);
        }
        return status;
    }

    NTSTATUS TlsConnection::ConsumeTls12PostHandshakeRecord(
        core::ITransport& transport,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr || fragmentLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        TlsHandshakeMessageView message = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(fragment, fragmentLength, message);
        if (!NT_SUCCESS(status)) {
            return status == STATUS_MORE_PROCESSING_REQUIRED ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        if (message.BytesConsumed != fragmentLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (message.Type == TlsHandshakeType::NewSessionTicket) {
            return ConsumeOptionalPlainHandshakeRecord(fragment, fragmentLength);
        }
        if (message.Type != TlsHandshakeType::HelloRequest) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (message.BodyLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return RenegotiateTls12(transport);
    }

    NTSTATUS TlsConnection::RenegotiateTls12(core::ITransport& transport) noexcept
    {
        if (tls12Renegotiating_ ||
            tls13RecordProtection_ ||
            context_.Protocol() != TlsProtocol::Tls12 ||
            context_.State() != TlsHandshakeState::Established ||
            !encrypted_ ||
            !TlsPolicyAllowsTls12Renegotiation(tlsPolicy_) ||
            tls12MaxRenegotiations_ == 0 ||
            tls12RenegotiationCount_ >= tls12MaxRenegotiations_ ||
            tls12LastClientVerifyDataLength_ != TlsVerifyDataLength ||
            tls12LastServerVerifyDataLength_ != TlsVerifyDataLength) {
            return STATUS_NOT_SUPPORTED;
        }

        tls12Renegotiating_ = true;
        handshakeLength_ = 0;
        handshakeConsumed_ = 0;
        lastHandshakeOffset_ = 0;
        lastHandshakeLength_ = 0;
        RtlSecureZeroMemory(tls12PendingTicket_, sizeof(tls12PendingTicket_));
        tls12PendingTicketLength_ = 0;
        tls12PendingTicketLifetimeHintSeconds_ = 0;

        TlsClientConnectionOptions options = tls12RenegotiationOptions_;
        options.EnableSessionResumption = false;
        options.Tls12SessionCache = nullptr;
        options.SessionCache = nullptr;
        options.EnableEarlyData = false;
        options.EarlyData = nullptr;
        options.EarlyDataLength = 0;
        options.EarlyDataAccepted = nullptr;
        options.EarlyDataBytesSent = nullptr;

        NTSTATUS status = PrepareScratch(options);
        if (NT_SUCCESS(status)) {
            status = EnsureBuffers();
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = context_.InitializeClient({ 3, 3 });
        if (NT_SUCCESS(status)) {
            status = transcript_.Initialize(crypto::HashAlgorithm::Sha256);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        UCHAR* message = nullptr;
        status = GetHandshakeScratch(
            TlsScratchClientHelloOffset,
            TlsScratchClientHelloLength,
            &message);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        RtlSecureZeroMemory(message, TlsScratchClientHelloLength);
        SIZE_T messageLength = 0;

        TlsClientHelloOptions hello = {};
        hello.ServerName = options.ServerName;
        hello.ServerNameLength = options.ServerNameLength;
        hello.AlpnProtocols = options.AlpnProtocols;
        hello.AlpnProtocolCount = options.AlpnProtocolCount;
        hello.OfferEncryptThenMac = options.Policy.EnableTls12Cbc;
        hello.OfferStatusRequest = true;
        hello.RenegotiationInfo = tls12LastClientVerifyData_;
        hello.RenegotiationInfoLength = tls12LastClientVerifyDataLength_;

        HeapArray<TlsCipherSuite> offeredCipherSuites;
        HeapArray<TlsNamedGroup> offeredNamedGroups;
        HeapArray<TlsSignatureScheme> offeredSignatureSchemes;
        SIZE_T offeredCipherSuiteCount = 0;
        SIZE_T offeredNamedGroupCount = 0;
        SIZE_T offeredSignatureSchemeCount = 0;
        status = BuildTls12PolicyOffers(
            options.Policy,
            offeredCipherSuites,
            &offeredCipherSuiteCount,
            offeredNamedGroups,
            &offeredNamedGroupCount,
            offeredSignatureSchemes,
            &offeredSignatureSchemeCount);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        hello.CipherSuites = offeredCipherSuites.Get();
        hello.CipherSuiteCount = offeredCipherSuiteCount;
        hello.NamedGroups = offeredNamedGroups.Get();
        hello.NamedGroupCount = offeredNamedGroupCount;
        hello.SignatureSchemes = offeredSignatureSchemes.Get();
        hello.SignatureSchemeCount = offeredSignatureSchemeCount;

        status = TlsHandshake12::EncodeClientHello(
            context_,
            hello,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        UCHAR* clientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchFirstClientHelloOffset,
            TlsScratchFirstClientHelloLength,
            &clientHello);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (messageLength > TlsScratchFirstClientHelloLength) {
            return FinishTls12RenegotiationAttempt(STATUS_BUFFER_TOO_SMALL);
        }
        RtlCopyMemory(clientHello, message, messageLength);
        const SIZE_T clientHelloLength = messageLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        TlsHandshakeMessageView handshake = {};
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context_, handshake, serverHello);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake12::ValidateServerHelloOffer(serverHello, hello);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (!serverHello.HasExtendedMasterSecret ||
            !serverHello.HasSecureRenegotiation ||
            serverHello.SecureRenegotiationDataLength != (TlsVerifyDataLength * 2) ||
            serverHello.SecureRenegotiationData == nullptr ||
            RtlCompareMemory(
                serverHello.SecureRenegotiationData,
                tls12LastClientVerifyData_,
                TlsVerifyDataLength) != TlsVerifyDataLength ||
            RtlCompareMemory(
                serverHello.SecureRenegotiationData + TlsVerifyDataLength,
                tls12LastServerVerifyData_,
                TlsVerifyDataLength) != TlsVerifyDataLength) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }

        const TlsCipherSuiteCapability* selectedCapability = TlsFindCipherSuiteCapability(context_.CipherSuite());
        if (selectedCapability == nullptr ||
            !TlsPolicyAllowsCipherSuite(options.Policy, context_.CipherSuite())) {
            return FinishTls12RenegotiationAttempt(STATUS_NOT_SUPPORTED);
        }
        if (selectedCapability->BulkCipher == TlsBulkCipherKind::AesCbc && !serverHello.HasEncryptThenMac) {
            return FinishTls12RenegotiationAttempt(STATUS_NOT_SUPPORTED);
        }

        bool serverMaySendNewSessionTicket = false;
        status = ServerHelloHasEmptyExtension(serverHello, TlsExtensionSessionTicket, &serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = ParseServerHelloAlpn(serverHello, negotiatedAlpn_, 16, &negotiatedAlpnLength_);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (negotiatedAlpnLength_ != 0 &&
            !IsOfferedAlpn(options, negotiatedAlpn_, negotiatedAlpnLength_)) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::AlpnMismatch, STATUS_NOT_SUPPORTED);
            return FinishTls12RenegotiationAttempt(STATUS_NOT_SUPPORTED);
        }

        status = transcript_.Initialize(TlsHandshake12::PrfHashForCipherSuite(context_.CipherSuite()));
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(clientHello, clientHelloLength);
        }
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        TlsCertificateListView certificates = {};
        status = TlsHandshake12::ParseCertificateList(context_, handshake, certificates);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = options.ProviderCache;
        validation.VerifyCertificate = options.VerifyCertificate;
        validation.RequireRevocationCheck = options.Policy.RequireRevocationCheck;

        HeapObject<CertificateValidationResult> validationResult;
        if (!validationResult.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        CertificateChainView chain = {};
        chain.Certificates = certificates.Certificates;
        chain.CertificatesLength = certificates.CertificatesLength;
        chain.CertificateCount = certificates.CertificateCount;
        status = CertificateValidator::ValidateChain(chain, validation, validationResult.Get());
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        serverCertificatePublicKeyAlgorithm_ = validationResult->Leaf.PublicKeyAlgorithm;
        if ((selectedCapability->Authentication == TlsAuthenticationKind::Rsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) ||
            (selectedCapability->Authentication == TlsAuthenticationKind::Ecdsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP256 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP384 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP521 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed25519 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed448)) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
            serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        if (validationResult->Leaf.HasKeyUsage) {
            if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsKeyEncipherment) {
                return FinishTls12RenegotiationAttempt(STATUS_TRUST_FAILURE);
            }
            if (selectedCapability->Tls12KeyExchange != Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsDigitalSignature) {
                return FinishTls12RenegotiationAttempt(STATUS_TRUST_FAILURE);
            }
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed25519) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed25519PublicKeyLength) {
                return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
            }
            RtlCopyMemory(serverEd25519PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed25519PublicKeyLength);
            serverEd25519PublicKeyLength_ = crypto::Ed25519PublicKeyLength;
        }
        else if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed448) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed448PublicKeyLength) {
                return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
            }
            RtlCopyMemory(serverEd448PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed448PublicKeyLength);
            serverEd448PublicKeyLength_ = crypto::Ed448PublicKeyLength;
        }
        else {
            status = CertificateValidator::ImportSubjectPublicKey(providerCache_, validationResult->Leaf, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        const Tls12KeyExchangeKind serverKeyExchangeKind =
            Tls12KeyExchangeForCipherSuite(context_.CipherSuite());
        TlsServerKeyExchangeView keyExchange = {};
        HeapObject<crypto::CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        bool needsCngPeerKey = false;
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        if (handshake.Type == TlsHandshakeType::CertificateStatus) {
            Tls12CertificateStatusView certificateStatus = {};
            status = TlsHandshake12::ParseCertificateStatus(handshake, certificateStatus);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        if (serverKeyExchangeKind != Tls12KeyExchangeKind::Rsa) {
            status = TlsHandshake12::ParseServerKeyExchange(context_, handshake, keyExchange);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, hello);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            status = VerifyServerKeyExchange(keyExchange, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            crypto::KeyExchangeGroup selectedGroup = crypto::KeyExchangeGroup::Secp256r1;
            status = ToKeyExchangeGroup(keyExchange.NamedGroup, &selectedGroup);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            needsCngPeerKey =
                serverKeyExchangeKind != Tls12KeyExchangeKind::DheRsa &&
                selectedGroup != crypto::KeyExchangeGroup::X25519 &&
                selectedGroup != crypto::KeyExchangeGroup::X448;
            if (needsCngPeerKey) {
                status = crypto::CngProvider::ImportEcdhPublicKey(
                    providerCache_,
                    ToEcCurve(keyExchange.NamedGroup),
                    keyExchange.EcPoint,
                    keyExchange.EcPointLength,
                    *peerKey.Get());
                if (!NT_SUCCESS(status)) {
                    return FinishTls12RenegotiationAttempt(status);
                }
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        bool clientCertificateRequested = false;
        bool sendClientCertificateVerify = false;
        TlsSignatureScheme clientCertificateSignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            TlsCertificateRequestView request = {};
            status = TlsHandshake12::ParseCertificateRequest(context_, handshake, request);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            clientCertificateRequested = true;
            const UCHAR* credentialCertificateList = nullptr;
            SIZE_T credentialCertificateListLength = 0;
            if (clientCredential_ != nullptr &&
                clientCredential_->CertificateList != nullptr &&
                clientCredential_->CertificateListLength != 0 &&
                clientCredential_->Sign != nullptr) {
                const SIZE_T peerSignatureSchemesLength = request.SignatureSchemeCount * sizeof(USHORT);
                status = SelectClientCredentialSignatureScheme(
                    options.Policy,
                    *clientCredential_,
                    request.SignatureSchemes,
                    peerSignatureSchemesLength,
                    &clientCertificateSignatureScheme);
                if (NT_SUCCESS(status)) {
                    credentialCertificateList = clientCredential_->CertificateList;
                    credentialCertificateListLength = clientCredential_->CertificateListLength;
                    sendClientCertificateVerify = true;
                }
                else if (status != STATUS_NOT_SUPPORTED) {
                    return FinishTls12RenegotiationAttempt(status);
                }
            }

            status = TlsHandshake12::EncodeCertificate(
                credentialCertificateList,
                credentialCertificateListLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        status = TlsHandshake12::MarkServerHelloDone(context_, handshake);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        HeapArray<UCHAR> premasterSecret(crypto::KeyExchangeMaxSharedSecretLength);
        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!premasterSecret.IsValid() || !transcriptHash.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T premasterSecretLength = 0;
        status = GenerateClientKeyExchange(
            keyExchange,
            needsCngPeerKey ? peerKey.Get() : nullptr,
            serverKeyExchangeKind == Tls12KeyExchangeKind::Rsa ? serverPublicKey.Get() : nullptr,
            validationResult->Leaf.RsaModulusLength,
            premasterSecret.Get(),
            premasterSecret.Count(),
            &premasterSecretLength,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        SIZE_T transcriptHashLength = 0;
        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status) && clientCertificateRequested && sendClientCertificateVerify) {
            HeapArray<UCHAR> signature(TlsScratchHandshakeBufferLength);
            if (!signature.IsValid()) {
                RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
            }

            SIZE_T signatureLength = 0;
            status = clientCredential_->Sign(
                clientCredential_->SignContext,
                clientCertificateSignatureScheme,
                transcriptHash.Get(),
                transcriptHashLength,
                signature.Get(),
                signature.Count(),
                &signatureLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::EncodeCertificateVerify(
                    clientCertificateSignatureScheme,
                    signature.Get(),
                    signatureLength,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
            }
            RtlSecureZeroMemory(signature.Get(), signature.Count());
            if (NT_SUCCESS(status)) {
                status = AppendTranscript(message, messageLength);
            }
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
        }
        if (NT_SUCCESS(status)) {
            status = context_.DeriveExtendedMasterSecret(
                premasterSecret.Get(),
                premasterSecretLength,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        if (!tlsKeyBlockScratch_.IsValid()) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }
        TlsKeyBlock& keyBlock = *tlsKeyBlockScratch_.Get();
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        const SIZE_T keyLength = Tls12AeadKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T macKeyLength = Tls12MacKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T fixedIvLength = Tls12FixedIvLengthForCipherSuite(context_.CipherSuite());
        status = context_.DeriveKeyBlock(keyBlock, (macKeyLength * 2) + (keyLength * 2) + (fixedIvLength * 2));
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureAesGcmStates(keyBlock, tls12PendingClientWriteState_, tls12PendingServerWriteState_);
        }
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        static const UCHAR changeCipherSpec[] = { 1 };
        status = SendProtectedRecord(transport, TlsContentType::ChangeCipherSpec, changeCipherSpec, sizeof(changeCipherSpec));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }
        clientWriteState_ = tls12PendingClientWriteState_;
        tls12PendingClientWriteState_.Reset();

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake12::EncodeFinished(
                context_,
                true,
                transcriptHash.Get(),
                transcriptHashLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (messageLength != TlsHandshakeHeaderLength + TlsVerifyDataLength) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        RtlCopyMemory(tls12LastClientVerifyData_, message + TlsHandshakeHeaderLength, TlsVerifyDataLength);
        tls12LastClientVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = ReadServerChangeCipherSpec(transport, serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        serverWriteState_ = tls12PendingServerWriteState_;
        tls12PendingServerWriteState_.Reset();
        encrypted_ = true;

        status = ReadHandshakeMessage(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (handshake.Type != TlsHandshakeType::Finished) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake12::VerifyFinished(
                context_,
                false,
                transcriptHash.Get(),
                transcriptHashLength,
                handshake.Body,
                handshake.BodyLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (handshake.BodyLength != TlsVerifyDataLength) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        RtlCopyMemory(tls12LastServerVerifyData_, handshake.Body, TlsVerifyDataLength);
        tls12LastServerVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        ++tls12RenegotiationCount_;
        context_.SetState(TlsHandshakeState::Established);
        return FinishTls12RenegotiationAttempt(STATUS_SUCCESS);
    }

    NTSTATUS TlsConnection::ConsumeTls13PostHandshakeRecord(
        core::ITransport& transport,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr || fragmentLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T offset = 0;
        SIZE_T messageCount = 0;
        bool keyUpdated = false;
        bool updateRequested = false;
        while (offset < fragmentLength) {
            TlsHandshakeMessageView message = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                fragment + offset,
                fragmentLength - offset,
                message);
            if (!NT_SUCCESS(status)) {
                return status == STATUS_MORE_PROCESSING_REQUIRED ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            if (++messageCount > KhTlsMaxPostHandshakeMessagesPerRecord) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (message.Type == TlsHandshakeType::NewSessionTicket) {
                Tls13NewSessionTicketView ticket = {};
                status = TlsHandshake13::ParseNewSessionTicket(message, ticket);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = StoreTls13Ticket(ticket, tls13ExternalSessionCache_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else if (message.Type == TlsHandshakeType::KeyUpdate) {
                Tls13KeyUpdateView keyUpdate = {};
                status = TlsHandshake13::ParseKeyUpdate(message, keyUpdate);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (!keyUpdated) {
                    status = context_.UpdateTls13ApplicationTrafficSecret(false, serverWriteState_);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    keyUpdated = true;
                }
                if (keyUpdate.Request == Tls13KeyUpdateRequest::UpdateRequested) {
                    updateRequested = true;
                }
            }
            else if (message.Type == TlsHandshakeType::CertificateRequest) {
                if (!tls13PostHandshakeClientAuthAllowed_) {
                    return STATUS_NOT_SUPPORTED;
                }

                Tls13CertificateRequestView request = {};
                status = TlsHandshake13::ParseCertificateRequest(message, request);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (request.ContextLength == 0 || request.ContextLength > 255) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const UCHAR* peerSignatureSchemes = nullptr;
                SIZE_T peerSignatureSchemesLength = 0;
                status = FindTls13CertificateRequestSignatureAlgorithms(
                    request,
                    &peerSignatureSchemes,
                    &peerSignatureSchemesLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                bool sendCertificateVerify = false;
                TlsSignatureScheme signatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;
                if (clientCredential_ != nullptr &&
                    clientCredential_->CertificateList != nullptr &&
                    clientCredential_->CertificateListLength != 0 &&
                    clientCredential_->Sign != nullptr) {
                    status = SelectClientCredentialSignatureScheme(
                        tlsPolicy_,
                        *clientCredential_,
                        peerSignatureSchemes,
                        peerSignatureSchemesLength,
                        &signatureScheme);
                    if (NT_SUCCESS(status)) {
                        sendCertificateVerify = true;
                    }
                    else if (status != STATUS_NOT_SUPPORTED) {
                        return status;
                    }
                }

                status = AppendTranscript(fragment + offset, message.BytesConsumed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                HeapArray<UCHAR> output(TlsHandshakeBufferLength);
                if (!output.IsValid()) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                const UCHAR* certificateList = sendCertificateVerify ? clientCredential_->CertificateList : nullptr;
                const SIZE_T certificateListLength = sendCertificateVerify ? clientCredential_->CertificateListLength : 0;
                SIZE_T outputLength = 0;
                status = TlsHandshake13::EncodeCertificate(
                    request.Context,
                    request.ContextLength,
                    certificateList,
                    certificateListLength,
                    output.Get(),
                    output.Count(),
                    &outputLength);
                if (NT_SUCCESS(status)) {
                    status = AppendTranscript(output.Get(), outputLength);
                }
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::Handshake, output.Get(), outputLength);
                }
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(output.Get(), output.Count());
                    return status;
                }

                HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
                if (!transcriptHash.IsValid()) {
                    RtlSecureZeroMemory(output.Get(), output.Count());
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                SIZE_T transcriptHashLength = 0;
                if (sendCertificateVerify) {
                    status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
                    if (!NT_SUCCESS(status)) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                        return status;
                    }

                    HeapArray<UCHAR> signedInput(Tls13CertificateVerifyInputMaxLength);
                    HeapArray<UCHAR> signature(TlsHandshakeBufferLength);
                    if (!signedInput.IsValid() || !signature.IsValid()) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    SIZE_T signedInputLength = 0;
                    status = TlsHandshake13::BuildCertificateVerifyInput(
                        false,
                        transcriptHash.Get(),
                        transcriptHashLength,
                        signedInput.Get(),
                        signedInput.Count(),
                        &signedInputLength);
                    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                    if (NT_SUCCESS(status)) {
                        SIZE_T signatureLength = 0;
                        status = clientCredential_->Sign(
                            clientCredential_->SignContext,
                            signatureScheme,
                            signedInput.Get(),
                            signedInputLength,
                            signature.Get(),
                            signature.Count(),
                            &signatureLength);
                        if (NT_SUCCESS(status)) {
                            status = TlsHandshake13::EncodeCertificateVerify(
                                signatureScheme,
                                signature.Get(),
                                signatureLength,
                                output.Get(),
                                output.Count(),
                                &outputLength);
                        }
                    }
                    RtlSecureZeroMemory(signedInput.Get(), signedInput.Count());
                    RtlSecureZeroMemory(signature.Get(), signature.Count());
                    if (!NT_SUCCESS(status)) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        return status;
                    }

                    status = AppendTranscript(output.Get(), outputLength);
                    if (NT_SUCCESS(status)) {
                        status = SendProtectedRecord13(transport, TlsContentType::Handshake, output.Get(), outputLength);
                    }
                    if (!NT_SUCCESS(status)) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        return status;
                    }
                }

                status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
                if (NT_SUCCESS(status)) {
                    status = TlsHandshake13::EncodeFinished(
                        context_,
                        true,
                        transcriptHash.Get(),
                        transcriptHashLength,
                        output.Get(),
                        output.Count(),
                        &outputLength);
                }
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                if (NT_SUCCESS(status)) {
                    status = AppendTranscript(output.Get(), outputLength);
                }
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::Handshake, output.Get(), outputLength);
                }
                RtlSecureZeroMemory(output.Get(), output.Count());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else {
                return STATUS_NOT_SUPPORTED;
            }

            offset += message.BytesConsumed;
        }

        if (updateRequested) {
            ExchangeTlsFlag(&tls13PeerRequestedKeyUpdate_, 1);
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::ReadHandshakeMessage(
        core::ITransport& transport,
        TlsHandshakeMessageView& message,
        bool updateTranscript) noexcept
    {
        message = {};
        lastHandshakeLength_ = 0;
        lastHandshakeOffset_ = handshakeConsumed_;
        ULONG recordsRead = 0;

        for (;;) {
            TlsHandshakeMessageView parsed = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                handshakeBuffer_ + handshakeConsumed_,
                handshakeLength_ - handshakeConsumed_,
                parsed);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (handshakeConsumed_ != 0) {
                    if (handshakeConsumed_ < handshakeLength_) {
                        RtlMoveMemory(
                            handshakeBuffer_,
                            handshakeBuffer_ + handshakeConsumed_,
                            handshakeLength_ - handshakeConsumed_);
                    }

                    handshakeLength_ -= handshakeConsumed_;
                    handshakeConsumed_ = 0;
                }

                TlsMutablePlaintextRecord record = {};
                if (++recordsRead > TlsHandshakeMaxRecords) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                status = ReadRecord(
                    transport,
                    record,
                    handshakeReceiveTimeoutMilliseconds_,
                    &handshakeReceiveDeadline_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (record.ContentType == TlsContentType::Alert) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (record.ContentType != TlsContentType::Handshake ||
                    record.FragmentLength > (TlsHandshakeBufferLength - handshakeLength_)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                RtlCopyMemory(handshakeBuffer_ + handshakeLength_, record.Fragment, record.FragmentLength);
                handshakeLength_ += record.FragmentLength;
                continue;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (updateTranscript) {
                status = AppendTranscript(handshakeBuffer_ + handshakeConsumed_, parsed.BytesConsumed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            lastHandshakeOffset_ = handshakeConsumed_;
            lastHandshakeLength_ = parsed.BytesConsumed;
            message = parsed;
            handshakeConsumed_ += parsed.BytesConsumed;
            if (handshakeConsumed_ == handshakeLength_) {
                handshakeLength_ = 0;
                handshakeConsumed_ = 0;
            }

            return STATUS_SUCCESS;
        }
    }

    NTSTATUS TlsConnection::AppendTranscript(const UCHAR* data, SIZE_T length) noexcept
    {
        return transcript_.Update(data, length);
    }

    NTSTATUS TlsConnection::FinishTranscript(UCHAR* digest, SIZE_T capacity, SIZE_T* digestLength) const noexcept
    {
        return transcript_.Finish(digest, capacity, digestLength);
    }

    NTSTATUS TlsConnection::VerifyServerKeyExchange(
        const TlsServerKeyExchangeView& keyExchange,
        const crypto::CngKey& serverPublicKey) noexcept
    {
        if (!SignatureSchemeMatchesPublicKey(serverCertificatePublicKeyAlgorithm_, keyExchange.SignatureScheme)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        UCHAR* signedData = nullptr;
        NTSTATUS status = GetHandshakeScratch(
            TlsScratchSignedDataOffset,
            TlsScratchSignedDataLength,
            &signedData);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);

        if (keyExchange.ParametersLength > TlsScratchSignedDataLength - (TlsRandomLength * 2)) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(signedData, context_.Secrets().ClientRandom, TlsRandomLength);
        RtlCopyMemory(signedData + TlsRandomLength, context_.Secrets().ServerRandom, TlsRandomLength);
        RtlCopyMemory(signedData + (TlsRandomLength * 2), keyExchange.Parameters, keyExchange.ParametersLength);
        const SIZE_T signedDataLength = (TlsRandomLength * 2) + keyExchange.ParametersLength;

        if (keyExchange.SignatureScheme == TlsSignatureScheme::Ed25519) {
            if (serverEd25519PublicKeyLength_ != crypto::Ed25519PublicKeyLength) {
                RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = crypto::CngProvider::VerifyEd25519(
                serverEd25519PublicKey_,
                serverEd25519PublicKeyLength_,
                signedData,
                signedDataLength,
                keyExchange.Signature,
                keyExchange.SignatureLength);
            RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }
        if (keyExchange.SignatureScheme == TlsSignatureScheme::Ed448) {
            if (serverEd448PublicKeyLength_ != crypto::Ed448PublicKeyLength) {
                RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = crypto::CngProvider::VerifyEd448(
                serverEd448PublicKey_,
                serverEd448PublicKeyLength_,
                signedData,
                signedDataLength,
                keyExchange.Signature,
                keyExchange.SignatureLength);
            RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }

        HeapArray<UCHAR> hash(64);
        if (!hash.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T hashLength = 0;
        status = crypto::CngProvider::Hash(
            providerCache_,
            HashForSignature(keyExchange.SignatureScheme),
            signedData,
            signedDataLength,
            hash.Get(),
            hash.Count(),
            &hashLength);
        RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        crypto::SignatureAlgorithm signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        status = ToSignatureAlgorithm(keyExchange.SignatureScheme, &signatureAlgorithm);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(hash.Get(), hash.Count());
            return status;
        }

        status = crypto::CngProvider::VerifySignature(
            providerCache_,
            signatureAlgorithm,
            serverPublicKey,
            hash.Get(),
            hashLength,
            keyExchange.Signature,
            keyExchange.SignatureLength);
        RtlSecureZeroMemory(hash.Get(), hash.Count());
        return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
    }

    NTSTATUS TlsConnection::GenerateClientKeyExchange(
        const TlsServerKeyExchangeView& keyExchange,
        const crypto::CngKey* peerKey,
        const crypto::CngKey* rsaPublicKey,
        SIZE_T rsaCiphertextLength,
        UCHAR* premasterSecret,
        SIZE_T premasterSecretCapacity,
        SIZE_T* premasterSecretLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (premasterSecret == nullptr ||
            premasterSecretCapacity == 0 ||
            premasterSecretLength == nullptr ||
            bytesWritten == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *premasterSecretLength = 0;
        *bytesWritten = 0;

        const Tls12KeyExchangeKind keyExchangeKind = Tls12KeyExchangeForCipherSuite(context_.CipherSuite());
        NTSTATUS status = STATUS_SUCCESS;
        if (keyExchangeKind == Tls12KeyExchangeKind::Rsa) {
            if (rsaPublicKey == nullptr ||
                rsaCiphertextLength == 0 ||
                premasterSecretCapacity < TlsMasterSecretLength) {
                return STATUS_INVALID_PARAMETER;
            }

            premasterSecret[0] = 3;
            premasterSecret[1] = 3;
            status = crypto::CngProvider::GenerateRandom(premasterSecret + 2, TlsMasterSecretLength - 2);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                return status;
            }
            *premasterSecretLength = TlsMasterSecretLength;

            HeapArray<UCHAR> ciphertext(rsaCiphertextLength);
            if (!ciphertext.IsValid()) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T ciphertextLength = 0;
            status = crypto::CngProvider::EncryptRsaPkcs1(
                providerCache_,
                *rsaPublicKey,
                premasterSecret,
                *premasterSecretLength,
                ciphertext.Get(),
                ciphertext.Count(),
                &ciphertextLength);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(ciphertext.Get(), ciphertext.Count());
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
                return status;
            }

            status = EncodeClientKeyExchangeOpaque16(
                ciphertext.Get(),
                ciphertextLength,
                destination,
                destinationCapacity,
                bytesWritten);
            RtlSecureZeroMemory(ciphertext.Get(), ciphertext.Count());
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
            }
            return status;
        }

        crypto::KeyExchangeGroup group = crypto::KeyExchangeGroup::Secp256r1;
        status = ToKeyExchangeGroup(keyExchange.NamedGroup, &group);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (keyExchangeKind == Tls12KeyExchangeKind::DheRsa ||
            group == crypto::KeyExchangeGroup::X25519 ||
            group == crypto::KeyExchangeGroup::X448) {
            const UCHAR* peerPublicKey = keyExchangeKind == Tls12KeyExchangeKind::DheRsa ?
                keyExchange.DhPublicKey :
                keyExchange.EcPoint;
            const SIZE_T peerPublicKeyLength = keyExchangeKind == Tls12KeyExchangeKind::DheRsa ?
                keyExchange.DhPublicKeyLength :
                keyExchange.EcPointLength;
            if (peerPublicKey == nullptr || peerPublicKeyLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapObject<crypto::KeyExchangeKeyPair> keyPair;
            if (!keyPair.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = crypto::KeyExchange::GenerateKeyPair(providerCache_, group, *keyPair.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = crypto::KeyExchange::DeriveSharedSecret(
                providerCache_,
                *keyPair.Get(),
                peerPublicKey,
                peerPublicKeyLength,
                premasterSecret,
                premasterSecretCapacity,
                premasterSecretLength);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                return status;
            }

            status = keyExchangeKind == Tls12KeyExchangeKind::DheRsa ?
                EncodeClientKeyExchangeOpaque16(
                    keyPair->PublicKey,
                    keyPair->PublicKeyLength,
                    destination,
                    destinationCapacity,
                    bytesWritten) :
                TlsHandshake12::EncodeClientKeyExchange(
                    keyPair->PublicKey,
                    keyPair->PublicKeyLength,
                    destination,
                    destinationCapacity,
                    bytesWritten);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
            }
            return status;
        }

        if (peerKey == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapObject<crypto::CngKey> privateKey;
        if (!privateKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = crypto::CngProvider::GenerateEcdhKeyPair(
            providerCache_,
            ToEcCurve(keyExchange.NamedGroup),
            *privateKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> publicPoint(1 + (66 * 2));
        if (!publicPoint.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T pointLength = 0;
        status = ExportTlsEcPoint(*privateKey.Get(), publicPoint.Get(), publicPoint.Count(), &pointLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = crypto::CngProvider::DeriveEcdhSecret(
            providerCache_,
            *privateKey.Get(),
            *peerKey,
            premasterSecret,
            premasterSecretCapacity,
            premasterSecretLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = TlsHandshake12::EncodeClientKeyExchange(
            publicPoint.Get(),
            pointLength,
            destination,
            destinationCapacity,
            bytesWritten);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
            *premasterSecretLength = 0;
        }

        return status;
    }
}
}
