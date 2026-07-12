#pragma once

#include "tls/TlsConnectionPrivate.hpp"

#include <wknet/WknetLimits.h>
#include <wknet/crypto/CngProviderCache.h>
#include <wknet/crypto/Ed25519.h>
#include <wknet/crypto/Ed448.h>
#include <wknet/crypto/KeyExchange.h>
#include "tls/TlsCapabilities.h"
#include "tls/TlsHandshake13.h"

#if defined(WKNET_USER_MODE_TEST)
#include <time.h>
#endif

namespace wknet
{
namespace tls
{
    namespace connection_detail
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

        inline LONG ExchangeTlsFlag(_Inout_ volatile LONG* target, LONG value) noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            const LONG previous = *target;
            *target = value;
            return previous;
#else
            return InterlockedExchange(target, value);
#endif
        }

        _Must_inspect_result_
        inline Tls12KeyExchangeKind Tls12KeyExchangeForCipherSuite(TlsCipherSuite cipherSuite) noexcept
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

        inline bool TryReadDiagnosticUint16(
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

        inline bool TrySkipDiagnosticOpaque16(
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

        inline void CaptureServerKeyExchangeDiagnostic(
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

        inline void LogServerKeyExchangeParseFailure(
            NTSTATUS status,
            TlsCipherSuite cipherSuite,
            Tls12KeyExchangeKind keyExchangeKind,
            _In_ const TlsHandshakeMessageView& handshake) noexcept
        {
            Tls12ServerKeyExchangeDiagnostic diagnostic = {};
            CaptureServerKeyExchangeDiagnostic(keyExchangeKind, handshake, &diagnostic);

            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error,
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
        inline SIZE_T Tls12AeadKeyLengthForCipherSuite(TlsCipherSuite cipherSuite) noexcept
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
        inline SIZE_T Tls12MacKeyLengthForCipherSuite(TlsCipherSuite cipherSuite) noexcept
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
        inline SIZE_T Tls12FixedIvLengthForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
            if (capability != nullptr && capability->BulkCipher == TlsBulkCipherKind::AesCbc) {
                return 0;
            }
            return TlsAesGcmFixedIvLength;
        }

        _Must_inspect_result_
        inline NTSTATUS EncodeClientKeyExchangeOpaque16(
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
        inline SIZE_T ReadLittleEndianUint32(_In_reads_bytes_(sizeof(ULONG)) const UCHAR* data) noexcept
        {
            return static_cast<SIZE_T>(data[0]) |
                (static_cast<SIZE_T>(data[1]) << 8) |
                (static_cast<SIZE_T>(data[2]) << 16) |
                (static_cast<SIZE_T>(data[3]) << 24);
        }

        _Must_inspect_result_
        inline NTSTATUS ExportTlsEcPoint(
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
        inline crypto::EcCurve ToEcCurve(TlsNamedGroup group) noexcept
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
        inline NTSTATUS ToKeyExchangeGroup(TlsNamedGroup group, _Out_ crypto::KeyExchangeGroup* keyExchangeGroup) noexcept
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
        inline NTSTATUS ToSignatureAlgorithm(
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
        inline crypto::HashAlgorithm HashForSignature(TlsSignatureScheme scheme) noexcept
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
        inline bool SignatureSchemeMatchesPublicKey(
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
        inline bool SignatureSchemeMatchesClientCredential(
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
        inline NTSTATUS BuildTls12PolicyOffers(
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
        inline bool IsValidBuffer(const void* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        inline NTSTATUS LogTls13Failure(_In_z_ const char* stage, NTSTATUS status) noexcept
        {
#if defined(DBG) && !defined(WKNET_USER_MODE_TEST)
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection TLS1.3 %s failed: 0x%08X\r\n", stage, static_cast<ULONG>(status));
#else
            UNREFERENCED_PARAMETER(stage);
#endif
            return status;
        }

        _Must_inspect_result_
        inline TlsHandshakeFailureCategory CategoryForPeerAlert(const TlsAlert& alert) noexcept
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
        inline TlsHandshakeFailureCategory CategoryForStatus(NTSTATUS status) noexcept
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
        inline ULONGLONG CurrentMilliseconds() noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            return static_cast<ULONGLONG>(time(nullptr)) * 1000ULL;
#else
            LARGE_INTEGER now = {};
            KeQuerySystemTimePrecise(&now);
            return static_cast<ULONGLONG>(now.QuadPart / 10000LL);
#endif
        }

        _Must_inspect_result_
        inline bool AddMilliseconds(ULONGLONG value, ULONG delta, _Out_ ULONGLONG* result) noexcept
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
        inline TlsReceiveDeadline MakeReceiveDeadline(ULONG timeoutMilliseconds) noexcept
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
        inline NTSTATUS RemainingReceiveTimeout(
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
        inline bool ProtocolAllowed(const TlsClientConnectionOptions& options, TlsProtocol protocol) noexcept
        {
            return static_cast<UCHAR>(options.MinimumProtocol) <= static_cast<UCHAR>(protocol) &&
                static_cast<UCHAR>(protocol) <= static_cast<UCHAR>(options.MaximumProtocol);
        }

        _Must_inspect_result_
        inline bool CanConfirmTls12FromTls13Attempt(const TlsClientConnectionOptions& options) noexcept
        {
            return ProtocolAllowed(options, TlsProtocol::Tls12) &&
                ProtocolAllowed(options, TlsProtocol::Tls13) &&
                (!options.EnableEarlyData ||
                    options.EarlyData == nullptr ||
                    options.EarlyDataLength == 0);
        }

        _Must_inspect_result_
        inline bool HasTls13DowngradeSentinel(const TlsServerHelloView& serverHello) noexcept
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
        inline Tls13ServerHelloVersionSelection ClassifyTls12ServerHelloFromTls13Attempt(
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
        inline NTSTATUS ServerHelloHasEmptyExtension(
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
        inline NTSTATUS ParseServerHelloAlpn(
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
        inline bool IsOfferedAlpn(
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
        inline bool TextEqualsIgnoreCase(
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
        inline bool TicketServerNameMatches(
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
        inline bool TicketAlpnMatches(
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
        inline bool Tls12SessionServerNameMatches(
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
        inline bool Tls12SessionAlpnMatches(
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
        inline bool Tls12ServerHelloEchoedSessionId(
            _In_ const TlsServerHelloView& serverHello,
            _In_ const Tls12Session& session) noexcept
        {
            return session.SessionIdLength != 0 &&
                serverHello.SessionId != nullptr &&
                serverHello.SessionIdLength == session.SessionIdLength &&
                RtlCompareMemory(serverHello.SessionId, session.SessionId, session.SessionIdLength) == session.SessionIdLength;
        }

        _Must_inspect_result_
        inline const Tls12Session* SelectTls12Session(
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

        inline void StoreTls12SessionInCache(
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

        inline void StoreTls12SessionFromHandshake(
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
        inline bool MultiplySecondsToMilliseconds(ULONG seconds, _Out_ ULONGLONG* milliseconds) noexcept
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
        inline bool AddUnsigned64(ULONGLONG left, ULONGLONG right, _Out_ ULONGLONG* result) noexcept
        {
            if (result == nullptr || left > (~0ULL - right)) {
                return false;
            }

            *result = left + right;
            return true;
        }

        _Must_inspect_result_
        inline NTSTATUS ComputePskBinderForClientHello(
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
        inline NTSTATUS ValidateSelectedPskForConnection(
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
        inline NTSTATUS GetTls13SignatureParameters(
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
        inline bool SignatureListContains(
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
        inline NTSTATUS FindTls13CertificateRequestSignatureAlgorithms(
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
        inline NTSTATUS SelectClientCredentialSignatureScheme(
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
        inline NTSTATUS ConvertTls13CertificateListToLegacy(
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
        inline NTSTATUS SendAll(transport::Transport* transport, const UCHAR* data, SIZE_T length) noexcept
        {
            if (!IsValidBuffer(data, length)) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T sentTotal = 0;
            while (sentTotal < length) {
                SIZE_T sent = 0;
                NTSTATUS status = transport::TransportSend(transport, data + sentTotal, length - sentTotal, &sent);
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
        inline NTSTATUS ReadExact(
            transport::Transport* transport,
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

                status = transport::TransportReceiveWithTimeout(transport,
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

    using namespace connection_detail;
}
}
