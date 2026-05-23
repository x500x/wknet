#include "tls/CertificateValidator.h"
#include "api/KernelHttpWorkspace.h"
#include "crypto/CngProviderCache.h"

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <time.h>
#define kprintf(...)
#else
#include "KernelHttpConfig.h"
#endif

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        constexpr UCHAR TagBoolean = 0x01;
        constexpr UCHAR TagInteger = 0x02;
        constexpr UCHAR TagBitString = 0x03;
        constexpr UCHAR TagOctetString = 0x04;
        constexpr UCHAR TagNull = 0x05;
        constexpr UCHAR TagOid = 0x06;
        constexpr UCHAR TagUtf8String = 0x0c;
        constexpr UCHAR TagSequence = 0x30;
        constexpr UCHAR TagSet = 0x31;
        constexpr UCHAR TagPrintableString = 0x13;
        constexpr UCHAR TagUtcTime = 0x17;
        constexpr UCHAR TagGeneralizedTime = 0x18;
        constexpr UCHAR TagIa5String = 0x16;
        constexpr UCHAR TagTbsVersion = 0xa0;
        constexpr UCHAR TagExtensions = 0xa3;
        constexpr UCHAR TagDnsName = 0x82;

        const UCHAR OidCommonName[] = { 0x55, 0x04, 0x03 };
        const UCHAR OidRsaEncryption[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
        const UCHAR OidSha256WithRsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
        const UCHAR OidSha384WithRsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
        const UCHAR OidEcPublicKey[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
        const UCHAR OidSecp256r1[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
        const UCHAR OidSecp384r1[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
        const UCHAR OidSecp521r1[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };
        const UCHAR OidEcdsaWithSha256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
        const UCHAR OidEcdsaWithSha384[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
        const UCHAR OidBasicConstraints[] = { 0x55, 0x1d, 0x13 };
        const UCHAR OidSubjectAltName[] = { 0x55, 0x1d, 0x11 };
        const UCHAR OidExtendedKeyUsage[] = { 0x55, 0x1d, 0x25 };
        const UCHAR OidServerAuth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
        constexpr SIZE_T CertificateMaxAuthorityDerLength = 8192;
        constexpr SIZE_T CertificateScratchParsedBytes = sizeof(ParsedCertificate) * CertificateMaxChainLength;
        constexpr SIZE_T CertificateScratchRequiredBytes =
            CertificateScratchParsedBytes + CertificateMaxAuthorityDerLength;

        const char PemCertificateBegin[] = "-----BEGIN CERTIFICATE-----";
        const char PemCertificateEnd[] = "-----END CERTIFICATE-----";

        struct DerElement final
        {
            UCHAR Tag = 0;
            const UCHAR* Header = nullptr;
            SIZE_T HeaderLength = 0;
            const UCHAR* Value = nullptr;
            SIZE_T ValueLength = 0;
            const UCHAR* Full = nullptr;
            SIZE_T FullLength = 0;
        };

        struct CertificateValidationScratch final
        {
            UCHAR* Data = nullptr;
            SIZE_T Length = 0;
            bool Owned = false;
            ParsedCertificate* Parsed = nullptr;
            UCHAR* Authority = nullptr;
            SIZE_T AuthorityLength = 0;
        };

        _Must_inspect_result_
        NTSTATUS PrepareCertificateValidationScratch(
            _In_ const CertificateValidationOptions& options,
            _Out_ CertificateValidationScratch& scratch) noexcept
        {
            scratch = {};

            if (options.Workspace != nullptr) {
                if (options.Workspace->CertificateScratch.Data == nullptr ||
                    options.Workspace->CertificateScratch.Length < CertificateScratchRequiredBytes) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                scratch.Data = options.Workspace->CertificateScratch.Data;
                scratch.Length = options.Workspace->CertificateScratch.Length;
            }
            else {
                scratch.Data = new UCHAR[CertificateScratchRequiredBytes];
                if (scratch.Data == nullptr) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                scratch.Length = CertificateScratchRequiredBytes;
                scratch.Owned = true;
            }

            RtlZeroMemory(scratch.Data, scratch.Length);
            scratch.Parsed = reinterpret_cast<ParsedCertificate*>(scratch.Data);
            scratch.Authority = scratch.Data + CertificateScratchParsedBytes;
            scratch.AuthorityLength = scratch.Length - CertificateScratchParsedBytes;
            return STATUS_SUCCESS;
        }

        void ReleaseCertificateValidationScratch(_Inout_ CertificateValidationScratch& scratch) noexcept
        {
            if (scratch.Data != nullptr && scratch.Length != 0) {
                RtlSecureZeroMemory(scratch.Data, scratch.Length);
            }

            if (scratch.Owned) {
                delete[] scratch.Data;
            }

            scratch = {};
        }

        _Must_inspect_result_
        bool HasCapacity(SIZE_T capacity, SIZE_T offset, SIZE_T length) noexcept
        {
            return offset <= capacity && length <= (capacity - offset);
        }

        _Must_inspect_result_
        bool MemoryEquals(const UCHAR* left, const UCHAR* right, SIZE_T length) noexcept
        {
            if (left == nullptr || right == nullptr) {
                return false;
            }

            UCHAR diff = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                diff = static_cast<UCHAR>(diff | (left[index] ^ right[index]));
            }

            return diff == 0;
        }

        _Must_inspect_result_
        bool OidEquals(
            _In_ const DerElement& oid,
            _In_reads_bytes_(expectedLength) const UCHAR* expected,
            SIZE_T expectedLength) noexcept
        {
            return oid.Tag == TagOid &&
                oid.ValueLength == expectedLength &&
                MemoryEquals(oid.Value, expected, expectedLength);
        }

        _Must_inspect_result_
        NTSTATUS ReadElement(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Inout_ SIZE_T* offset,
            _Out_ DerElement& element) noexcept
        {
            element = {};

            if (data == nullptr || offset == nullptr || !HasCapacity(dataLength, *offset, 2)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T start = *offset;
            element.Tag = data[*offset];
            ++(*offset);

            UCHAR lengthByte = data[*offset];
            ++(*offset);

            SIZE_T valueLength = 0;
            if ((lengthByte & 0x80) == 0) {
                valueLength = lengthByte;
            }
            else {
                const UCHAR lengthBytes = static_cast<UCHAR>(lengthByte & 0x7f);
                if (lengthBytes == 0 ||
                    lengthBytes > sizeof(SIZE_T) ||
                    !HasCapacity(dataLength, *offset, lengthBytes)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                for (UCHAR index = 0; index < lengthBytes; ++index) {
                    valueLength = (valueLength << 8) | data[*offset + index];
                }

                *offset += lengthBytes;
            }

            if (!HasCapacity(dataLength, *offset, valueLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            element.Header = data + start;
            element.HeaderLength = *offset - start;
            element.Value = data + *offset;
            element.ValueLength = valueLength;
            element.Full = data + start;
            element.FullLength = element.HeaderLength + element.ValueLength;
            *offset += valueLength;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadExpected(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Inout_ SIZE_T* offset,
            UCHAR tag,
            _Out_ DerElement& element) noexcept
        {
            NTSTATUS status = ReadElement(data, dataLength, offset, element);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            return element.Tag == tag ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        bool IsCharacterString(UCHAR tag) noexcept
        {
            return tag == TagUtf8String || tag == TagPrintableString || tag == TagIa5String;
        }

        _Must_inspect_result_
        bool IsDigit(UCHAR value) noexcept
        {
            return value >= '0' && value <= '9';
        }

        _Must_inspect_result_
        NTSTATUS ParseTwoDigits(const UCHAR* data, SIZE_T offset, int* value) noexcept
        {
            if (data == nullptr || value == nullptr ||
                !IsDigit(data[offset]) ||
                !IsDigit(data[offset + 1])) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *value = ((data[offset] - '0') * 10) + (data[offset + 1] - '0');
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        long long PackTime(int year, int month, int day, int hour, int minute, int second) noexcept
        {
            return (static_cast<long long>(year) * 10000000000LL) +
                (static_cast<long long>(month) * 100000000LL) +
                (static_cast<long long>(day) * 1000000LL) +
                (static_cast<long long>(hour) * 10000LL) +
                (static_cast<long long>(minute) * 100LL) +
                second;
        }

        _Must_inspect_result_
        NTSTATUS ParseDerTime(_In_ const DerElement& time, _Out_ long long* packed) noexcept
        {
            if (packed == nullptr || time.Value == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            int year = 0;
            int month = 0;
            int day = 0;
            int hour = 0;
            int minute = 0;
            int second = 0;
            NTSTATUS status = STATUS_SUCCESS;

            if (time.Tag == TagUtcTime) {
                if (time.ValueLength != 13 || time.Value[12] != 'Z') {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                int shortYear = 0;
                status = ParseTwoDigits(time.Value, 0, &shortYear);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
                status = ParseTwoDigits(time.Value, 2, &month);
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 4, &day);
                }
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 6, &hour);
                }
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 8, &minute);
                }
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 10, &second);
                }
            }
            else if (time.Tag == TagGeneralizedTime) {
                if (time.ValueLength != 15 || time.Value[14] != 'Z') {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                for (SIZE_T index = 0; index < 4; ++index) {
                    if (!IsDigit(time.Value[index])) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    year = (year * 10) + (time.Value[index] - '0');
                }

                status = ParseTwoDigits(time.Value, 4, &month);
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 6, &day);
                }
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 8, &hour);
                }
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 10, &minute);
                }
                if (NT_SUCCESS(status)) {
                    status = ParseTwoDigits(time.Value, 12, &second);
                }
            }
            else {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (month < 1 || month > 12 ||
                day < 1 || day > 31 ||
                hour > 23 ||
                minute > 59 ||
                second > 59) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *packed = PackTime(year, month, day, hour, minute, second);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS CurrentPackedTime(_Out_ long long* packed) noexcept
        {
            if (packed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

#if defined(KERNEL_HTTP_USER_MODE_TEST)
            time_t now = time(nullptr);
            if (now == static_cast<time_t>(-1)) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            struct tm utc = {};
#if defined(_WIN32)
            if (gmtime_s(&utc, &now) != 0) {
                return STATUS_INVALID_DEVICE_STATE;
            }
#else
            if (gmtime_r(&now, &utc) == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }
#endif
            *packed = PackTime(
                utc.tm_year + 1900,
                utc.tm_mon + 1,
                utc.tm_mday,
                utc.tm_hour,
                utc.tm_min,
                utc.tm_sec);
#else
            LARGE_INTEGER systemTime = {};
            TIME_FIELDS fields = {};
            KeQuerySystemTimePrecise(&systemTime);
            RtlTimeToTimeFields(&systemTime, &fields);
            *packed = PackTime(
                fields.Year,
                fields.Month,
                fields.Day,
                fields.Hour,
                fields.Minute,
                fields.Second);
#endif
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseAlgorithmIdentifier(
            _In_ const DerElement& algorithm,
            _Out_opt_ CertificateSignatureAlgorithm* signatureAlgorithm,
            _Out_opt_ CertificatePublicKeyAlgorithm* publicKeyAlgorithm) noexcept
        {
            if (signatureAlgorithm != nullptr) {
                *signatureAlgorithm = CertificateSignatureAlgorithm::Unknown;
            }

            if (publicKeyAlgorithm != nullptr) {
                *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::Unknown;
            }

            if (algorithm.Tag != TagSequence) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            DerElement oid = {};
            NTSTATUS status = ReadExpected(algorithm.Value, algorithm.ValueLength, &offset, TagOid, oid);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (signatureAlgorithm != nullptr) {
                if (OidEquals(oid, OidSha256WithRsa, sizeof(OidSha256WithRsa))) {
                    *signatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs1Sha256;
                }
                else if (OidEquals(oid, OidSha384WithRsa, sizeof(OidSha384WithRsa))) {
                    *signatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs1Sha384;
                }
                else if (OidEquals(oid, OidEcdsaWithSha256, sizeof(OidEcdsaWithSha256))) {
                    *signatureAlgorithm = CertificateSignatureAlgorithm::EcdsaSha256;
                }
                else if (OidEquals(oid, OidEcdsaWithSha384, sizeof(OidEcdsaWithSha384))) {
                    *signatureAlgorithm = CertificateSignatureAlgorithm::EcdsaSha384;
                }
            }

            if (publicKeyAlgorithm != nullptr) {
                if (OidEquals(oid, OidRsaEncryption, sizeof(OidRsaEncryption))) {
                    *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::Rsa;
                }
                else if (OidEquals(oid, OidEcPublicKey, sizeof(OidEcPublicKey))) {
                    DerElement curve = {};
                    status = ReadExpected(algorithm.Value, algorithm.ValueLength, &offset, TagOid, curve);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    if (OidEquals(curve, OidSecp256r1, sizeof(OidSecp256r1))) {
                        *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::EcdsaP256;
                    }
                    else if (OidEquals(curve, OidSecp384r1, sizeof(OidSecp384r1))) {
                        *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::EcdsaP384;
                    }
                    else if (OidEquals(curve, OidSecp521r1, sizeof(OidSecp521r1))) {
                        *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::EcdsaP521;
                    }
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseName(_In_ const DerElement& name, _Inout_ ParsedCertificate& certificate) noexcept
        {
            if (name.Tag != TagSequence) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T setOffset = 0;
            while (setOffset < name.ValueLength) {
                DerElement set = {};
                NTSTATUS status = ReadExpected(name.Value, name.ValueLength, &setOffset, TagSet, set);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T attrOffset = 0;
                while (attrOffset < set.ValueLength) {
                    DerElement attribute = {};
                    status = ReadExpected(set.Value, set.ValueLength, &attrOffset, TagSequence, attribute);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    SIZE_T itemOffset = 0;
                    DerElement oid = {};
                    DerElement value = {};
                    status = ReadExpected(attribute.Value, attribute.ValueLength, &itemOffset, TagOid, oid);
                    if (NT_SUCCESS(status)) {
                        status = ReadElement(attribute.Value, attribute.ValueLength, &itemOffset, value);
                    }

                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    if (certificate.CommonName == nullptr &&
                        OidEquals(oid, OidCommonName, sizeof(OidCommonName)) &&
                        IsCharacterString(value.Tag)) {
                        certificate.CommonName = reinterpret_cast<const char*>(value.Value);
                        certificate.CommonNameLength = value.ValueLength;
                    }
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseBasicConstraints(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement sequence = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, sequence);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            certificate.HasBasicConstraints = true;
            certificate.IsCa = false;

            SIZE_T offset = 0;
            if (offset < sequence.ValueLength) {
                DerElement ca = {};
                status = ReadElement(sequence.Value, sequence.ValueLength, &offset, ca);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (ca.Tag == TagBoolean && ca.ValueLength == 1) {
                    certificate.IsCa = ca.Value[0] != 0;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseSubjectAltName(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement names = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, names);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T offset = 0;
            while (offset < names.ValueLength) {
                DerElement name = {};
                status = ReadElement(names.Value, names.ValueLength, &offset, name);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (name.Tag == TagDnsName && certificate.DnsNameCount < (sizeof(certificate.DnsNames) / sizeof(certificate.DnsNames[0]))) {
                    const SIZE_T index = certificate.DnsNameCount;
                    certificate.DnsNames[index] = reinterpret_cast<const char*>(name.Value);
                    certificate.DnsNameLengths[index] = name.ValueLength;
                    ++certificate.DnsNameCount;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseExtendedKeyUsage(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement usages = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, usages);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            certificate.HasExtendedKeyUsage = true;
            certificate.AllowsServerAuth = false;

            SIZE_T offset = 0;
            while (offset < usages.ValueLength) {
                DerElement usage = {};
                status = ReadExpected(usages.Value, usages.ValueLength, &offset, TagOid, usage);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (OidEquals(usage, OidServerAuth, sizeof(OidServerAuth))) {
                    certificate.AllowsServerAuth = true;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseExtensions(_In_ const DerElement& extensions, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T sequenceOffset = 0;
            DerElement sequence = {};
            NTSTATUS status = ReadExpected(extensions.Value, extensions.ValueLength, &sequenceOffset, TagSequence, sequence);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T offset = 0;
            while (offset < sequence.ValueLength) {
                DerElement extension = {};
                status = ReadExpected(sequence.Value, sequence.ValueLength, &offset, TagSequence, extension);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T itemOffset = 0;
                DerElement oid = {};
                status = ReadExpected(extension.Value, extension.ValueLength, &itemOffset, TagOid, oid);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (itemOffset < extension.ValueLength && extension.Value[itemOffset] == TagBoolean) {
                    DerElement critical = {};
                    status = ReadExpected(extension.Value, extension.ValueLength, &itemOffset, TagBoolean, critical);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }

                DerElement value = {};
                status = ReadExpected(extension.Value, extension.ValueLength, &itemOffset, TagOctetString, value);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (OidEquals(oid, OidBasicConstraints, sizeof(OidBasicConstraints))) {
                    status = ParseBasicConstraints(value, certificate);
                }
                else if (OidEquals(oid, OidSubjectAltName, sizeof(OidSubjectAltName))) {
                    status = ParseSubjectAltName(value, certificate);
                }
                else if (OidEquals(oid, OidExtendedKeyUsage, sizeof(OidExtendedKeyUsage))) {
                    status = ParseExtendedKeyUsage(value, certificate);
                }

                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseSubjectPublicKeyInfo(_In_ const DerElement& spki, _Inout_ ParsedCertificate& certificate) noexcept
        {
            if (spki.Tag != TagSequence) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            certificate.SubjectPublicKeyInfo = spki.Full;
            certificate.SubjectPublicKeyInfoLength = spki.FullLength;

            SIZE_T offset = 0;
            DerElement algorithm = {};
            DerElement key = {};
            NTSTATUS status = ReadExpected(spki.Value, spki.ValueLength, &offset, TagSequence, algorithm);
            if (NT_SUCCESS(status)) {
                status = ParseAlgorithmIdentifier(algorithm, nullptr, &certificate.PublicKeyAlgorithm);
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(spki.Value, spki.ValueLength, &offset, TagBitString, key);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (key.ValueLength < 2 || key.Value[0] != 0) {
                return STATUS_NOT_SUPPORTED;
            }

            certificate.PublicKey = key.Value + 1;
            certificate.PublicKeyLength = key.ValueLength - 1;

            if (certificate.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Rsa) {
                SIZE_T rsaOffset = 0;
                DerElement rsaSequence = {};
                status = ReadExpected(certificate.PublicKey, certificate.PublicKeyLength, &rsaOffset, TagSequence, rsaSequence);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T keyOffset = 0;
                DerElement modulus = {};
                DerElement exponent = {};
                status = ReadExpected(rsaSequence.Value, rsaSequence.ValueLength, &keyOffset, TagInteger, modulus);
                if (NT_SUCCESS(status)) {
                    status = ReadExpected(rsaSequence.Value, rsaSequence.ValueLength, &keyOffset, TagInteger, exponent);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                certificate.RsaModulus = modulus.Value;
                certificate.RsaModulusLength = modulus.ValueLength;
                while (certificate.RsaModulusLength > 1 && certificate.RsaModulus[0] == 0) {
                    ++certificate.RsaModulus;
                    --certificate.RsaModulusLength;
                }

                certificate.RsaExponent = exponent.Value;
                certificate.RsaExponentLength = exponent.ValueLength;
            }

            return certificate.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Unknown ?
                STATUS_NOT_SUPPORTED :
                STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool CharEqualsIgnoreCase(char left, char right) noexcept
        {
            if (left >= 'A' && left <= 'Z') {
                left = static_cast<char>(left - 'A' + 'a');
            }

            if (right >= 'A' && right <= 'Z') {
                right = static_cast<char>(right - 'A' + 'a');
            }

            return left == right;
        }

        _Must_inspect_result_
        bool HostNameMatches(
            _In_reads_(patternLength) const char* pattern,
            SIZE_T patternLength,
            _In_reads_(hostLength) const char* host,
            SIZE_T hostLength) noexcept
        {
            if (pattern == nullptr || host == nullptr || patternLength == 0 || hostLength == 0) {
                return false;
            }

            if (patternLength > 2 && pattern[0] == '*' && pattern[1] == '.') {
                const SIZE_T suffixLength = patternLength - 1;
                if (hostLength <= suffixLength) {
                    return false;
                }

                for (SIZE_T index = 0; index < hostLength - suffixLength; ++index) {
                    if (host[index] == '.') {
                        return false;
                    }
                }

                for (SIZE_T index = 0; index < suffixLength; ++index) {
                    if (!CharEqualsIgnoreCase(pattern[index + 1], host[hostLength - suffixLength + index])) {
                        return false;
                    }
                }

                return true;
            }

            if (patternLength != hostLength) {
                return false;
            }

            for (SIZE_T index = 0; index < hostLength; ++index) {
                if (!CharEqualsIgnoreCase(pattern[index], host[index])) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        NTSTATUS ValidateHostName(_In_ const ParsedCertificate& leaf, _In_ const CertificateValidationOptions& options) noexcept
        {
            if (options.HostName == nullptr || options.HostNameLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (leaf.DnsNameCount != 0) {
                for (SIZE_T index = 0; index < leaf.DnsNameCount; ++index) {
                    if (HostNameMatches(leaf.DnsNames[index], leaf.DnsNameLengths[index], options.HostName, options.HostNameLength)) {
                        return STATUS_SUCCESS;
                    }
                }

                return STATUS_TRUST_FAILURE;
            }

            if (HostNameMatches(leaf.CommonName, leaf.CommonNameLength, options.HostName, options.HostNameLength)) {
                return STATUS_SUCCESS;
            }

            return STATUS_TRUST_FAILURE;
        }

        _Must_inspect_result_
        NTSTATUS HashForSignature(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            CertificateSignatureAlgorithm algorithm,
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(hashCapacity) UCHAR* hash,
            SIZE_T hashCapacity,
            _Out_ SIZE_T* hashLength) noexcept
        {
            if (hashLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            crypto::HashAlgorithm hashAlgorithm = crypto::HashAlgorithm::Sha256;
            switch (algorithm) {
            case CertificateSignatureAlgorithm::RsaPkcs1Sha256:
            case CertificateSignatureAlgorithm::EcdsaSha256:
                hashAlgorithm = crypto::HashAlgorithm::Sha256;
                break;
            case CertificateSignatureAlgorithm::RsaPkcs1Sha384:
            case CertificateSignatureAlgorithm::EcdsaSha384:
                hashAlgorithm = crypto::HashAlgorithm::Sha384;
                break;
            default:
                return STATUS_NOT_SUPPORTED;
            }

            return crypto::CngProvider::Hash(providerCache, hashAlgorithm, data, dataLength, hash, hashCapacity, hashLength);
        }

        _Must_inspect_result_
        NTSTATUS VerifyCertificateSignature(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer) noexcept
        {
            crypto::CngKey issuerKey;
            NTSTATUS status = CertificateValidator::ImportSubjectPublicKey(providerCache, issuer, issuerKey);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            UCHAR hash[48] = {};
            SIZE_T hashLength = 0;
            status = HashForSignature(
                providerCache,
                certificate.SignatureAlgorithm,
                certificate.TbsCertificate,
                certificate.TbsCertificateLength,
                hash,
                sizeof(hash),
                &hashLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = crypto::CngProvider::VerifySignature(
                providerCache,
                CertificateValidator::ToSignatureAlgorithm(certificate.SignatureAlgorithm),
                issuerKey,
                hash,
                hashLength,
                certificate.Signature,
                certificate.SignatureLength);

            RtlSecureZeroMemory(hash, sizeof(hash));
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }

        _Must_inspect_result_
        NTSTATUS ReadNextCertificate(
            _In_ const CertificateChainView& chain,
            _Inout_ SIZE_T* offset,
            _Outptr_result_bytebuffer_(*certificateLength) const UCHAR** certificate,
            _Out_ SIZE_T* certificateLength) noexcept
        {
            if (offset == nullptr || certificate == nullptr || certificateLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (chain.Certificates == nullptr ||
                *offset > chain.CertificatesLength ||
                chain.CertificatesLength - *offset < 3) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *certificateLength =
                (static_cast<SIZE_T>(chain.Certificates[*offset]) << 16) |
                (static_cast<SIZE_T>(chain.Certificates[*offset + 1]) << 8) |
                chain.Certificates[*offset + 2];
            *offset += 3;

            if (*certificateLength == 0 || *certificateLength > chain.CertificatesLength - *offset) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *certificate = chain.Certificates + *offset;
            *offset += *certificateLength;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS HashSubjectPublicKey(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _Out_writes_bytes_(CertificateSha256ThumbprintLength) UCHAR* spkiSha256) noexcept
        {
            if (spkiSha256 == nullptr ||
                certificate.SubjectPublicKeyInfo == nullptr ||
                certificate.SubjectPublicKeyInfoLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T hashLength = 0;
            NTSTATUS status = crypto::CngProvider::Hash(
                providerCache,
                crypto::HashAlgorithm::Sha256,
                certificate.SubjectPublicKeyInfo,
                certificate.SubjectPublicKeyInfoLength,
                spkiSha256,
                CertificateSha256ThumbprintLength,
                &hashLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            return hashLength == CertificateSha256ThumbprintLength ?
                STATUS_SUCCESS :
                STATUS_INVALID_NETWORK_RESPONSE;
        }

        void FillLeafResult(
            _In_ const ParsedCertificate& leaf,
            _In_reads_bytes_(CertificateSha256ThumbprintLength) const UCHAR* spkiSha256,
            _Out_opt_ CertificateValidationResult* result) noexcept
        {
            if (result == nullptr) {
                return;
            }

            result->Leaf = leaf;
            RtlCopyMemory(
                result->LeafSubjectPublicKeySha256,
                spkiSha256,
                CertificateSha256ThumbprintLength);
        }

        _Must_inspect_result_
        bool MatchBytes(
            _In_reads_bytes_(leftLength) const UCHAR* left,
            SIZE_T leftLength,
            _In_reads_bytes_(rightLength) const char* right,
            SIZE_T rightLength) noexcept
        {
            if (left == nullptr || right == nullptr || leftLength != rightLength) {
                return false;
            }

            for (SIZE_T index = 0; index < leftLength; ++index) {
                if (left[index] != static_cast<UCHAR>(right[index])) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool FindPattern(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _In_reads_bytes_(patternLength) const char* pattern,
            SIZE_T patternLength,
            SIZE_T start,
            _Out_ SIZE_T* foundAt) noexcept
        {
            if (foundAt == nullptr) {
                return false;
            }

            *foundAt = 0;
            if (data == nullptr ||
                pattern == nullptr ||
                patternLength == 0 ||
                start > dataLength ||
                patternLength > dataLength - start) {
                return false;
            }

            for (SIZE_T index = start; index <= dataLength - patternLength; ++index) {
                if (MatchBytes(data + index, patternLength, pattern, patternLength)) {
                    *foundAt = index;
                    return true;
                }
            }

            return false;
        }

        _Must_inspect_result_
        bool IsPemWhitespace(UCHAR value) noexcept
        {
            return value == ' ' ||
                value == '\r' ||
                value == '\n' ||
                value == '\t';
        }

        _Must_inspect_result_
        bool DecodeBase64Char(UCHAR input, _Out_ UCHAR* value) noexcept
        {
            if (value == nullptr) {
                return false;
            }

            if (input >= 'A' && input <= 'Z') {
                *value = static_cast<UCHAR>(input - 'A');
                return true;
            }

            if (input >= 'a' && input <= 'z') {
                *value = static_cast<UCHAR>(input - 'a' + 26);
                return true;
            }

            if (input >= '0' && input <= '9') {
                *value = static_cast<UCHAR>(input - '0' + 52);
                return true;
            }

            if (input == '+') {
                *value = 62;
                return true;
            }

            if (input == '/') {
                *value = 63;
                return true;
            }

            return false;
        }

        _Must_inspect_result_
        NTSTATUS FlushBase64Quartet(
            _In_reads_(4) const UCHAR* quartet,
            _In_reads_(4) const bool* padding,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Inout_ SIZE_T* destinationLength,
            _Out_ bool* completed) noexcept
        {
            if (quartet == nullptr ||
                padding == nullptr ||
                destination == nullptr ||
                destinationLength == nullptr ||
                completed == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *completed = false;
            if (padding[0] ||
                padding[1] ||
                (padding[2] && !padding[3])) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T bytesToWrite = padding[2] ? 1 : (padding[3] ? 2 : 3);
            if (*destinationLength > destinationCapacity ||
                bytesToWrite > destinationCapacity - *destinationLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            const ULONG value =
                (static_cast<ULONG>(quartet[0]) << 18) |
                (static_cast<ULONG>(quartet[1]) << 12) |
                (static_cast<ULONG>(quartet[2]) << 6) |
                quartet[3];

            destination[(*destinationLength)++] = static_cast<UCHAR>((value >> 16) & 0xff);
            if (bytesToWrite > 1) {
                destination[(*destinationLength)++] = static_cast<UCHAR>((value >> 8) & 0xff);
            }

            if (bytesToWrite > 2) {
                destination[(*destinationLength)++] = static_cast<UCHAR>(value & 0xff);
            }

            *completed = padding[2] || padding[3];
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS DecodePemCertificate(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            SIZE_T start,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* destinationLength,
            _Out_ SIZE_T* nextOffset) noexcept
        {
            if (destinationLength != nullptr) {
                *destinationLength = 0;
            }

            if (nextOffset != nullptr) {
                *nextOffset = start;
            }

            if (data == nullptr ||
                destination == nullptr ||
                destinationLength == nullptr ||
                nextOffset == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T begin = 0;
            if (!FindPattern(
                data,
                dataLength,
                PemCertificateBegin,
                sizeof(PemCertificateBegin) - 1,
                start,
                &begin)) {
                return STATUS_NOT_FOUND;
            }

            SIZE_T bodyStart = begin + (sizeof(PemCertificateBegin) - 1);
            SIZE_T end = 0;
            if (!FindPattern(
                data,
                dataLength,
                PemCertificateEnd,
                sizeof(PemCertificateEnd) - 1,
                bodyStart,
                &end)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            UCHAR quartet[4] = {};
            bool padding[4] = {};
            SIZE_T quartetLength = 0;
            bool completed = false;

            for (SIZE_T index = bodyStart; index < end; ++index) {
                const UCHAR input = data[index];
                if (IsPemWhitespace(input)) {
                    continue;
                }

                if (completed) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                UCHAR value = 0;
                bool isPadding = false;
                if (input == '=') {
                    isPadding = true;
                }
                else if (!DecodeBase64Char(input, &value)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                quartet[quartetLength] = value;
                padding[quartetLength] = isPadding;
                ++quartetLength;

                if (quartetLength == 4) {
                    NTSTATUS status = FlushBase64Quartet(
                        quartet,
                        padding,
                        destination,
                        destinationCapacity,
                        destinationLength,
                        &completed);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    RtlZeroMemory(quartet, sizeof(quartet));
                    RtlZeroMemory(padding, sizeof(padding));
                    quartetLength = 0;
                }
            }

            if (quartetLength != 0 || *destinationLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *nextOffset = end + (sizeof(PemCertificateEnd) - 1);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsExactAnchorMatch(
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& anchor) noexcept
        {
            return certificate.SubjectLength == anchor.SubjectLength &&
                certificate.SubjectPublicKeyInfoLength == anchor.SubjectPublicKeyInfoLength &&
                MemoryEquals(certificate.Subject, anchor.Subject, certificate.SubjectLength) &&
                MemoryEquals(
                    certificate.SubjectPublicKeyInfo,
                    anchor.SubjectPublicKeyInfo,
                    certificate.SubjectPublicKeyInfoLength);
        }

        _Must_inspect_result_
        NTSTATUS AnchorSignsCertificate(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& anchor,
            _Out_ bool* trusted) noexcept
        {
            if (trusted == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *trusted = false;
            if (IsExactAnchorMatch(certificate, anchor)) {
                *trusted = true;
                return STATUS_SUCCESS;
            }

            if (!anchor.HasBasicConstraints ||
                !anchor.IsCa ||
                certificate.IssuerLength != anchor.SubjectLength ||
                !MemoryEquals(certificate.Issuer, anchor.Subject, certificate.IssuerLength)) {
                return STATUS_SUCCESS;
            }

            NTSTATUS status = VerifyCertificateSignature(providerCache, certificate, anchor);
            if (NT_SUCCESS(status)) {
                *trusted = true;
                return STATUS_SUCCESS;
            }

            return status == STATUS_INVALID_SIGNATURE ? STATUS_SUCCESS : status;
        }

        _Must_inspect_result_
        NTSTATUS ParsedCertificateMatchesAuthorityBundle(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _In_ const CertificateAuthorityBundle& bundle,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ bool* trusted) noexcept
        {
            if (trusted != nullptr) {
                *trusted = false;
            }

            if (certificate.Der == nullptr ||
                bundle.Data == nullptr ||
                bundle.DataLength == 0 ||
                scratch == nullptr ||
                trusted == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T firstPem = 0;
            if (!FindPattern(
                bundle.Data,
                bundle.DataLength,
                PemCertificateBegin,
                sizeof(PemCertificateBegin) - 1,
                0,
                &firstPem)) {
                ParsedCertificate anchor = {};
                NTSTATUS status = CertificateValidator::ParseCertificate(
                    bundle.Data,
                    bundle.DataLength,
                    anchor);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return AnchorSignsCertificate(providerCache, certificate, anchor, trusted);
            }

            SIZE_T offset = firstPem;
            while (offset < bundle.DataLength) {
                SIZE_T derLength = 0;
                SIZE_T nextOffset = offset;
                NTSTATUS status = DecodePemCertificate(
                    bundle.Data,
                    bundle.DataLength,
                    offset,
                    scratch,
                    scratchCapacity,
                    &derLength,
                    &nextOffset);
                if (status == STATUS_NOT_FOUND) {
                    return STATUS_SUCCESS;
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                ParsedCertificate anchor = {};
                status = CertificateValidator::ParseCertificate(scratch, derLength, anchor);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = AnchorSignsCertificate(providerCache, certificate, anchor, trusted);
                if (!NT_SUCCESS(status) || *trusted) {
                    return status;
                }

                offset = nextOffset;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS StoreHasTrustedAnchor(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_opt_ const CertificateStore* store,
            _In_ const ParsedCertificate& certificate,
            _In_reads_bytes_(CertificateSha256ThumbprintLength) const UCHAR* certificateSpkiSha256,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ bool* trusted) noexcept
        {
            if (trusted != nullptr) {
                *trusted = false;
            }

            if (certificateSpkiSha256 == nullptr || scratch == nullptr || trusted == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (store != nullptr &&
                store->IsTrustedAnchor(
                    certificate.Subject,
                    certificate.SubjectLength,
                    certificateSpkiSha256,
                    CertificateSha256ThumbprintLength)) {
                *trusted = true;
                return STATUS_SUCCESS;
            }

            if (store != nullptr) {
                for (SIZE_T index = 0; index < store->AuthorityBundleCount(); ++index) {
                    const CertificateAuthorityBundle* bundle = store->AuthorityBundleAt(index);
                    if (bundle == nullptr) {
                        return STATUS_INVALID_DEVICE_STATE;
                    }

                    NTSTATUS status = ParsedCertificateMatchesAuthorityBundle(
                        providerCache,
                        certificate,
                        *bundle,
                        scratch,
                        scratchCapacity,
                        trusted);
                    if (!NT_SUCCESS(status) || *trusted) {
                        return status;
                    }
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS FindTrustedAnchor(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_opt_ const CertificateStore* store,
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ SIZE_T* trustedAnchorIndex) noexcept
        {
            if (trustedAnchorIndex != nullptr) {
                *trustedAnchorIndex = certificateCount;
            }

            if (certificates == nullptr ||
                certificateCount == 0 ||
                scratch == nullptr ||
                scratchCapacity < CertificateMaxAuthorityDerLength ||
                trustedAnchorIndex == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = STATUS_SUCCESS;
            for (SIZE_T index = 0; index < certificateCount; ++index) {
                UCHAR certSpkiSha256[CertificateSha256ThumbprintLength] = {};
                status = HashSubjectPublicKey(providerCache, certificates[index], certSpkiSha256);
                if (!NT_SUCCESS(status)) {
                    kprintf("CertificateValidator: Cert %Iu SPKI hash failed: 0x%08X\r\n", index, static_cast<ULONG>(status));
                    break;
                }

                kprintf("CertificateValidator: Cert %Iu SPKI SHA256: %02X%02X%02X%02X...\r\n",
                    index, certSpkiSha256[0], certSpkiSha256[1], certSpkiSha256[2], certSpkiSha256[3]);

                bool trusted = false;
                status = StoreHasTrustedAnchor(
                    providerCache,
                    store,
                    certificates[index],
                    certSpkiSha256,
                    scratch,
                    scratchCapacity,
                    &trusted);
                if (!NT_SUCCESS(status)) {
                    break;
                }

                if (trusted) {
                    kprintf("CertificateValidator: Found trusted anchor at index %Iu\r\n", index);
                    *trustedAnchorIndex = index;
                    break;
                }
            }

            return status;
        }
    }

    NTSTATUS CertificateValidator::ParseCertificate(
        const UCHAR* der,
        SIZE_T derLength,
        ParsedCertificate& certificate) noexcept
    {
        certificate = {};
        if (der == nullptr || derLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T offset = 0;
        DerElement root = {};
        NTSTATUS status = ReadExpected(der, derLength, &offset, TagSequence, root);
        if (!NT_SUCCESS(status) || offset != derLength) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        certificate.Der = der;
        certificate.DerLength = derLength;

        SIZE_T certOffset = 0;
        DerElement tbs = {};
        DerElement signatureAlgorithm = {};
        DerElement signature = {};
        status = ReadExpected(root.Value, root.ValueLength, &certOffset, TagSequence, tbs);
        if (NT_SUCCESS(status)) {
            status = ReadExpected(root.Value, root.ValueLength, &certOffset, TagSequence, signatureAlgorithm);
        }
        if (NT_SUCCESS(status)) {
            status = ParseAlgorithmIdentifier(signatureAlgorithm, &certificate.SignatureAlgorithm, nullptr);
        }
        if (NT_SUCCESS(status)) {
            status = ReadExpected(root.Value, root.ValueLength, &certOffset, TagBitString, signature);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (signature.ValueLength < 2 || signature.Value[0] != 0) {
            return STATUS_NOT_SUPPORTED;
        }

        certificate.TbsCertificate = tbs.Full;
        certificate.TbsCertificateLength = tbs.FullLength;
        certificate.Signature = signature.Value + 1;
        certificate.SignatureLength = signature.ValueLength - 1;

        SIZE_T tbsOffset = 0;
        if (tbs.ValueLength != 0 && tbs.Value[0] == TagTbsVersion) {
            DerElement version = {};
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagTbsVersion, version);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        DerElement serial = {};
        DerElement innerSignature = {};
        DerElement issuer = {};
        DerElement validity = {};
        DerElement subject = {};
        DerElement spki = {};

        status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagInteger, serial);
        if (NT_SUCCESS(status)) {
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, innerSignature);
        }
        if (NT_SUCCESS(status)) {
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, issuer);
        }
        if (NT_SUCCESS(status)) {
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, validity);
        }
        if (NT_SUCCESS(status)) {
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, subject);
        }
        if (NT_SUCCESS(status)) {
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, spki);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        certificate.Issuer = issuer.Full;
        certificate.IssuerLength = issuer.FullLength;
        certificate.Subject = subject.Full;
        certificate.SubjectLength = subject.FullLength;

        SIZE_T validityOffset = 0;
        DerElement notBefore = {};
        DerElement notAfter = {};
        status = ReadElement(validity.Value, validity.ValueLength, &validityOffset, notBefore);
        if (NT_SUCCESS(status)) {
            status = ReadElement(validity.Value, validity.ValueLength, &validityOffset, notAfter);
        }
        if (NT_SUCCESS(status)) {
            status = ParseDerTime(notBefore, &certificate.NotBefore);
        }
        if (NT_SUCCESS(status)) {
            status = ParseDerTime(notAfter, &certificate.NotAfter);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ParseName(subject, certificate);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ParseSubjectPublicKeyInfo(spki, certificate);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        while (tbsOffset < tbs.ValueLength) {
            DerElement optional = {};
            status = ReadElement(tbs.Value, tbs.ValueLength, &tbsOffset, optional);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (optional.Tag == TagExtensions) {
                status = ParseExtensions(optional, certificate);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS CertificateValidator::ValidateChain(
        const CertificateChainView& chain,
        const CertificateValidationOptions& options,
        CertificateValidationResult* result) noexcept
    {
        if (result != nullptr) {
            *result = {};
        }

        if (chain.Certificates == nullptr ||
            chain.CertificatesLength == 0 ||
            chain.CertificateCount == 0 ||
            chain.CertificateCount > CertificateMaxChainLength) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options.VerifyCertificate &&
            (options.HostName == nullptr || options.HostNameLength == 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        CertificateValidationScratch scratch = {};
        NTSTATUS status = PrepareCertificateValidationScratch(options, scratch);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ParsedCertificate* const parsed = scratch.Parsed;
        SIZE_T offset = 0;
        const SIZE_T certificatesToParse = options.VerifyCertificate ? chain.CertificateCount : 1;

        for (SIZE_T index = 0; index < certificatesToParse; ++index) {
            const UCHAR* der = nullptr;
            SIZE_T derLength = 0;
            status = ReadNextCertificate(chain, &offset, &der, &derLength);
            if (NT_SUCCESS(status)) {
                status = ParseCertificate(der, derLength, parsed[index]);
            }
            if (!NT_SUCCESS(status)) {
                ReleaseCertificateValidationScratch(scratch);
                return status;
            }
        }

        if (options.VerifyCertificate && offset != chain.CertificatesLength) {
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        UCHAR spkiSha256[CertificateSha256ThumbprintLength] = {};
        status = HashSubjectPublicKey(options.ProviderCache, parsed[0], spkiSha256);
        if (!NT_SUCCESS(status)) {
            kprintf("CertificateValidator: Leaf SPKI hash failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        kprintf("CertificateValidator: Leaf SPKI SHA256: %02X%02X%02X%02X...\r\n",
            spkiSha256[0], spkiSha256[1], spkiSha256[2], spkiSha256[3]);

        if (!options.VerifyCertificate) {
            FillLeafResult(parsed[0], spkiSha256, result);
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_SUCCESS;
        }

        long long now = 0;
        status = CurrentPackedTime(&now);
        if (!NT_SUCCESS(status)) {
            kprintf("CertificateValidator: CurrentPackedTime failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        for (SIZE_T index = 0; index < chain.CertificateCount; ++index) {
            if (now < parsed[index].NotBefore || now > parsed[index].NotAfter) {
                kprintf("CertificateValidator: Certificate %Iu time validation failed\r\n", index);
                RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }
        }

        if (options.RequireServerAuthEku &&
            parsed[0].HasExtendedKeyUsage &&
            !parsed[0].AllowsServerAuth) {
            kprintf("CertificateValidator: ServerAuth EKU validation failed\r\n");
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_TRUST_FAILURE;
        }

        status = ValidateHostName(parsed[0], options);
        if (!NT_SUCCESS(status)) {
            kprintf("CertificateValidator: HostName validation failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        for (SIZE_T index = 0; index + 1 < chain.CertificateCount; ++index) {
            if (parsed[index].IssuerLength != parsed[index + 1].SubjectLength ||
                !MemoryEquals(parsed[index].Issuer, parsed[index + 1].Subject, parsed[index].IssuerLength)) {
                kprintf("CertificateValidator: Chain issuer/subject mismatch at %Iu\r\n", index);
                RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }

            if (!parsed[index + 1].HasBasicConstraints || !parsed[index + 1].IsCa) {
                kprintf("CertificateValidator: Certificate %Iu is not a CA\r\n", index + 1);
                RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }

            status = VerifyCertificateSignature(options.ProviderCache, parsed[index], parsed[index + 1]);
            if (!NT_SUCCESS(status)) {
                kprintf("CertificateValidator: Signature verification failed at %Iu: 0x%08X\r\n", index, static_cast<ULONG>(status));
                RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
                ReleaseCertificateValidationScratch(scratch);
                return status;
            }
        }

        if (options.Store != nullptr &&
            !options.Store->MatchesPin(options.HostName, options.HostNameLength, spkiSha256, sizeof(spkiSha256))) {
            kprintf("CertificateValidator: Pin validation failed\r\n");
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_TRUST_FAILURE;
        }

        SIZE_T trustedAnchorIndex = chain.CertificateCount;
        status = FindTrustedAnchor(
            options.ProviderCache,
            options.Store,
            parsed,
            chain.CertificateCount,
            scratch.Authority,
            scratch.AuthorityLength,
            &trustedAnchorIndex);
        if (!NT_SUCCESS(status)) {
            kprintf("CertificateValidator: Trust anchor search failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        if (trustedAnchorIndex == chain.CertificateCount) {
            kprintf("CertificateValidator: No trusted anchor found in chain\r\n");
            RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_TRUST_FAILURE;
        }

        if (trustedAnchorIndex == 0 &&
             chain.CertificateCount == 1 &&
             parsed[0].IssuerLength == parsed[0].SubjectLength &&
             MemoryEquals(parsed[0].Issuer, parsed[0].Subject, parsed[0].IssuerLength)) {
            status = VerifyCertificateSignature(options.ProviderCache, parsed[0], parsed[0]);
            if (!NT_SUCCESS(status)) {
                kprintf("CertificateValidator: Self-signed signature verification failed: 0x%08X\r\n", static_cast<ULONG>(status));
                RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
                ReleaseCertificateValidationScratch(scratch);
                return status;
            }
        }

        FillLeafResult(parsed[0], spkiSha256, result);
        RtlSecureZeroMemory(spkiSha256, sizeof(spkiSha256));
        ReleaseCertificateValidationScratch(scratch);
        return STATUS_SUCCESS;
    }

    NTSTATUS CertificateValidator::ImportSubjectPublicKey(
        const ParsedCertificate& certificate,
        crypto::CngKey& publicKey) noexcept
    {
        return ImportSubjectPublicKey(nullptr, certificate, publicKey);
    }

    NTSTATUS CertificateValidator::ImportSubjectPublicKey(
        const crypto::CngProviderCache* providerCache,
        const ParsedCertificate& certificate,
        crypto::CngKey& publicKey) noexcept
    {
        switch (certificate.PublicKeyAlgorithm) {
        case CertificatePublicKeyAlgorithm::Rsa:
            return crypto::CngProvider::ImportRsaPublicKey(
                providerCache,
                certificate.RsaExponent,
                certificate.RsaExponentLength,
                certificate.RsaModulus,
                certificate.RsaModulusLength,
                publicKey);
        case CertificatePublicKeyAlgorithm::EcdsaP256:
            return crypto::CngProvider::ImportEcdsaPublicKey(
                providerCache,
                crypto::EcCurve::P256,
                certificate.PublicKey,
                certificate.PublicKeyLength,
                publicKey);
        case CertificatePublicKeyAlgorithm::EcdsaP384:
            return crypto::CngProvider::ImportEcdsaPublicKey(
                providerCache,
                crypto::EcCurve::P384,
                certificate.PublicKey,
                certificate.PublicKeyLength,
                publicKey);
        case CertificatePublicKeyAlgorithm::EcdsaP521:
            return crypto::CngProvider::ImportEcdsaPublicKey(
                providerCache,
                crypto::EcCurve::P521,
                certificate.PublicKey,
                certificate.PublicKeyLength,
                publicKey);
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }

    crypto::SignatureAlgorithm CertificateValidator::ToSignatureAlgorithm(
        CertificateSignatureAlgorithm algorithm) noexcept
    {
        switch (algorithm) {
        case CertificateSignatureAlgorithm::RsaPkcs1Sha256:
            return crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        case CertificateSignatureAlgorithm::RsaPkcs1Sha384:
            return crypto::SignatureAlgorithm::RsaPkcs1Sha384;
        case CertificateSignatureAlgorithm::EcdsaSha256:
            return crypto::SignatureAlgorithm::EcdsaSha256;
        case CertificateSignatureAlgorithm::EcdsaSha384:
            return crypto::SignatureAlgorithm::EcdsaSha384;
        default:
            return crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        }
    }
}
}
