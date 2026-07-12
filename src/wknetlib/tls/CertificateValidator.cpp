#include <wknet/tls/CertificateValidator.h>
#include <wknet/crypto/CngProviderCache.h>

#if defined(WKNET_USER_MODE_TEST)
#include <time.h>
// Quiet cert-validator spam in user-mode protocol tests.
#undef WKNET_DBG_PRINT
#define WKNET_DBG_PRINT(...)
#else
#include <wknet/WknetConfig.h>
#endif

namespace wknet
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
        constexpr UCHAR TagEnumerated = 0x0a;
        constexpr UCHAR TagUtf8String = 0x0c;
        constexpr UCHAR TagSequence = 0x30;
        constexpr UCHAR TagSet = 0x31;
        constexpr UCHAR TagPrintableString = 0x13;
        constexpr UCHAR TagUtcTime = 0x17;
        constexpr UCHAR TagGeneralizedTime = 0x18;
        constexpr UCHAR TagIa5String = 0x16;
        constexpr UCHAR TagTbsVersion = 0xa0;
        constexpr UCHAR TagExtensions = 0xa3;
        constexpr UCHAR TagPermittedSubtrees = 0xa0;
        constexpr UCHAR TagExcludedSubtrees = 0xa1;
        constexpr UCHAR TagMinimumBaseDistance = 0x80;
        constexpr UCHAR TagMaximumBaseDistance = 0x81;
        constexpr UCHAR TagDnsName = 0x82;
        constexpr UCHAR TagDirectoryName = 0xa4;
        constexpr UCHAR TagUniformResourceIdentifier = 0x86;
        constexpr UCHAR TagIpAddress = 0x87;

        const UCHAR OidCommonName[] = { 0x55, 0x04, 0x03 };
        const UCHAR OidSha1[] = { 0x2b, 0x0e, 0x03, 0x02, 0x1a };
        const UCHAR OidRsaEncryption[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
        const UCHAR OidSha256WithRsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
        const UCHAR OidSha384WithRsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
        const UCHAR OidEcPublicKey[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
        const UCHAR OidSecp256r1[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
        const UCHAR OidSecp384r1[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
        const UCHAR OidSecp521r1[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };
        const UCHAR OidEcdsaWithSha256[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
        const UCHAR OidEcdsaWithSha384[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
        // id-Ed25519 = 1.3.101.112 (RFC 8410); used for both the SPKI algorithm
        // and the certificate signature algorithm (no parameters).
        const UCHAR OidEd25519[] = { 0x2b, 0x65, 0x70 };
        // id-Ed448 = 1.3.101.113 (RFC 8410); used for both the SPKI algorithm
        // and the certificate signature algorithm (no parameters).
        const UCHAR OidEd448[] = { 0x2b, 0x65, 0x71 };
        const UCHAR OidBasicConstraints[] = { 0x55, 0x1d, 0x13 };
        const UCHAR OidKeyUsage[] = { 0x55, 0x1d, 0x0f };
        const UCHAR OidSubjectKeyIdentifier[] = { 0x55, 0x1d, 0x0e };
        const UCHAR OidAuthorityKeyIdentifier[] = { 0x55, 0x1d, 0x23 };
        const UCHAR OidSubjectAltName[] = { 0x55, 0x1d, 0x11 };
        const UCHAR OidCrlDistributionPoints[] = { 0x55, 0x1d, 0x1f };
        const UCHAR OidNameConstraints[] = { 0x55, 0x1d, 0x1e };
        const UCHAR OidCertificatePolicies[] = { 0x55, 0x1d, 0x20 };
        const UCHAR OidAnyPolicy[] = { 0x55, 0x1d, 0x20, 0x00 };
        const UCHAR OidPolicyConstraints[] = { 0x55, 0x1d, 0x24 };
        const UCHAR OidInhibitAnyPolicy[] = { 0x55, 0x1d, 0x36 };
        const UCHAR OidExtendedKeyUsage[] = { 0x55, 0x1d, 0x25 };
        const UCHAR OidAuthorityInfoAccess[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
        const UCHAR OidOcspAccessMethod[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 };
        const UCHAR OidBasicOcspResponse[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
        const UCHAR OidServerAuth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
        const UCHAR OidOcspSigning[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };
        constexpr SIZE_T CertificateMaxAuthorityDerLength = 32768;
        constexpr SIZE_T CertificateMaxNormalizedDnsNameLength = 255;
        constexpr SIZE_T CertificateScratchParsedBytes = sizeof(ParsedCertificate) * CertificateMaxChainLength;
        constexpr SIZE_T CertificateScratchAnchorBytes = sizeof(ParsedCertificate);
        constexpr SIZE_T CertificateScratchRequiredBytes =
            CertificateScratchParsedBytes + CertificateScratchAnchorBytes + CertificateMaxAuthorityDerLength;

        const char PemCertificateBegin[] = "-----BEGIN CERTIFICATE-----";
        const char PemCertificateEnd[] = "-----END CERTIFICATE-----";
        constexpr const char PunycodePrefix[] = "xn--";

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
            core::IScratchAllocator* Allocator = nullptr;
            ParsedCertificate* Parsed = nullptr;
            ParsedCertificate* Anchor = nullptr;
            UCHAR* Authority = nullptr;
            SIZE_T AuthorityLength = 0;
        };

        _Must_inspect_result_
        NTSTATUS PrepareCertificateValidationScratch(
            _In_ const CertificateValidationOptions& options,
            _Out_ CertificateValidationScratch& scratch) noexcept
        {
            scratch = {};

            if (options.ScratchAllocator != nullptr) {
                void* buffer = nullptr;
                const NTSTATUS status = options.ScratchAllocator->Acquire(
                    CertificateScratchRequiredBytes,
                    &buffer);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                scratch.Data = static_cast<UCHAR*>(buffer);
                scratch.Length = CertificateScratchRequiredBytes;
                scratch.Allocator = options.ScratchAllocator;
            }
            else {
                scratch.Data = AllocateNonPagedArray<UCHAR>(CertificateScratchRequiredBytes);
                if (scratch.Data == nullptr) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                scratch.Length = CertificateScratchRequiredBytes;
                scratch.Owned = true;
            }

            RtlZeroMemory(scratch.Data, scratch.Length);
            scratch.Parsed = reinterpret_cast<ParsedCertificate*>(scratch.Data);
            scratch.Anchor = reinterpret_cast<ParsedCertificate*>(scratch.Data + CertificateScratchParsedBytes);
            scratch.Authority = scratch.Data + CertificateScratchParsedBytes + CertificateScratchAnchorBytes;
            scratch.AuthorityLength = scratch.Length - CertificateScratchParsedBytes;
            scratch.AuthorityLength -= CertificateScratchAnchorBytes;
            return STATUS_SUCCESS;
        }

        void ReleaseCertificateValidationScratch(_Inout_ CertificateValidationScratch& scratch) noexcept
        {
            if (scratch.Data != nullptr && scratch.Length != 0) {
                RtlSecureZeroMemory(scratch.Data, scratch.Length);
            }

            if (scratch.Owned) {
                FreeNonPagedArray(scratch.Data);
            }
            else if (scratch.Allocator != nullptr) {
                scratch.Allocator->Release(scratch.Data);
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
        bool OidElementsEqual(_In_ const DerElement& left, _In_ const DerElement& right) noexcept
        {
            return left.Tag == TagOid &&
                right.Tag == TagOid &&
                left.ValueLength == right.ValueLength &&
                MemoryEquals(left.Value, right.Value, left.ValueLength);
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
                if ((lengthBytes > 1 && data[*offset] == 0) ||
                    valueLength < 0x80) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
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
        NTSTATUS ParseUnsignedDerInteger(_In_ const DerElement& integer, _Out_ ULONG* value) noexcept
        {
            if (value == nullptr || integer.Tag != TagInteger || integer.Value == nullptr || integer.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if ((integer.Value[0] & 0x80) != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            if (integer.ValueLength > 1 && integer.Value[0] == 0) {
                if ((integer.Value[1] & 0x80) == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                offset = 1;
            }

            ULONG parsed = 0;
            while (offset < integer.ValueLength) {
                if (parsed > (0xffffffffUL >> 8)) {
                    return STATUS_INTEGER_OVERFLOW;
                }

                parsed = (parsed << 8) | integer.Value[offset];
                ++offset;
            }

            *value = parsed;
            return STATUS_SUCCESS;
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
        bool IsLeapYear(int year) noexcept
        {
            return (year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0);
        }

        _Must_inspect_result_
        int DaysInMonth(int year, int month) noexcept
        {
            switch (month) {
            case 1:
            case 3:
            case 5:
            case 7:
            case 8:
            case 10:
            case 12:
                return 31;
            case 4:
            case 6:
            case 9:
            case 11:
                return 30;
            case 2:
                return IsLeapYear(year) ? 29 : 28;
            default:
                return 0;
            }
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

            const int monthDays = DaysInMonth(year, month);
            if (monthDays == 0 ||
                day < 1 ||
                day > monthDays ||
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

#if defined(WKNET_USER_MODE_TEST)
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
                else if (OidEquals(oid, OidEd25519, sizeof(OidEd25519))) {
                    *signatureAlgorithm = CertificateSignatureAlgorithm::Ed25519;
                }
                else if (OidEquals(oid, OidEd448, sizeof(OidEd448))) {
                    *signatureAlgorithm = CertificateSignatureAlgorithm::Ed448;
                }
            }

            if (publicKeyAlgorithm != nullptr) {
                if (OidEquals(oid, OidRsaEncryption, sizeof(OidRsaEncryption))) {
                    *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::Rsa;
                }
                else if (OidEquals(oid, OidEd25519, sizeof(OidEd25519))) {
                    *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::Ed25519;
                }
                else if (OidEquals(oid, OidEd448, sizeof(OidEd448))) {
                    *publicKeyAlgorithm = CertificatePublicKeyAlgorithm::Ed448;
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
            certificate.HasPathLenConstraint = false;
            certificate.PathLenConstraint = 0;

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
                else if (ca.Tag == TagInteger) {
                    certificate.HasPathLenConstraint = true;
                    status = ParseUnsignedDerInteger(ca, &certificate.PathLenConstraint);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            if (offset < sequence.ValueLength) {
                DerElement pathLen = {};
                status = ReadExpected(sequence.Value, sequence.ValueLength, &offset, TagInteger, pathLen);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                certificate.HasPathLenConstraint = true;
                status = ParseUnsignedDerInteger(pathLen, &certificate.PathLenConstraint);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (offset != sequence.ValueLength ||
                (certificate.HasPathLenConstraint && !certificate.IsCa)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool BitStringHasBit(_In_ const DerElement& bitString, ULONG bitIndex) noexcept
        {
            if (bitString.Value == nullptr || bitString.ValueLength < 2) {
                return false;
            }

            const SIZE_T byteIndex = 1 + (bitIndex / 8);
            if (byteIndex >= bitString.ValueLength) {
                return false;
            }

            const UCHAR bitMask = static_cast<UCHAR>(0x80 >> (bitIndex % 8));
            return (bitString.Value[byteIndex] & bitMask) != 0;
        }

        _Must_inspect_result_
        NTSTATUS ParseKeyUsage(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement bitString = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagBitString, bitString);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (valueOffset != extensionValue.ValueLength ||
                bitString.Value == nullptr ||
                bitString.ValueLength < 2 ||
                bitString.Value[0] > 7) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const UCHAR unusedBits = bitString.Value[0];
            if (unusedBits != 0) {
                const UCHAR unusedMask = static_cast<UCHAR>((1U << unusedBits) - 1U);
                if ((bitString.Value[bitString.ValueLength - 1] & unusedMask) != 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            certificate.HasKeyUsage = true;
            certificate.AllowsDigitalSignature = BitStringHasBit(bitString, 0);
            certificate.AllowsKeyEncipherment = BitStringHasBit(bitString, 2);
            certificate.AllowsKeyCertSign = BitStringHasBit(bitString, 5);
            certificate.AllowsCrlSign = BitStringHasBit(bitString, 6);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsAsciiBytes(_In_reads_bytes_(length) const UCHAR* value, SIZE_T length) noexcept;

        _Must_inspect_result_
        NTSTATUS ParseSubjectAltName(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement names = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, names);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < names.ValueLength) {
                DerElement name = {};
                status = ReadElement(names.Value, names.ValueLength, &offset, name);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (name.Tag == TagDnsName) {
                    if (!IsAsciiBytes(name.Value, name.ValueLength)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    if (certificate.DnsNameCount >= (sizeof(certificate.DnsNames) / sizeof(certificate.DnsNames[0]))) {
                        return STATUS_NOT_SUPPORTED;
                    }

                    const SIZE_T index = certificate.DnsNameCount;
                    certificate.DnsNames[index] = reinterpret_cast<const char*>(name.Value);
                    certificate.DnsNameLengths[index] = name.ValueLength;
                    ++certificate.DnsNameCount;
                }
                else if (name.Tag == TagIpAddress) {
                    if (name.Value == nullptr ||
                        (name.ValueLength != 4 && name.ValueLength != 16)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    if (certificate.IpAddressCount >= (sizeof(certificate.IpAddresses) / sizeof(certificate.IpAddresses[0]))) {
                        return STATUS_NOT_SUPPORTED;
                    }

                    const SIZE_T index = certificate.IpAddressCount;
                    RtlCopyMemory(certificate.IpAddresses[index], name.Value, name.ValueLength);
                    certificate.IpAddressLengths[index] = name.ValueLength;
                    ++certificate.IpAddressCount;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool BytesStartWithIgnoreCase(
            _In_reads_bytes_(length) const UCHAR* value,
            SIZE_T length,
            _In_z_ const char* prefix) noexcept
        {
            if (value == nullptr || prefix == nullptr) {
                return false;
            }

            SIZE_T prefixLength = 0;
            while (prefix[prefixLength] != '\0') {
                ++prefixLength;
            }
            if (length < prefixLength) {
                return false;
            }

            for (SIZE_T index = 0; index < prefixLength; ++index) {
                char left = static_cast<char>(value[index]);
                char right = prefix[index];
                if (left >= 'A' && left <= 'Z') {
                    left = static_cast<char>(left - 'A' + 'a');
                }
                if (right >= 'A' && right <= 'Z') {
                    right = static_cast<char>(right - 'A' + 'a');
                }
                if (left != right) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool IsValidRevocationUri(_In_reads_bytes_(length) const UCHAR* value, SIZE_T length) noexcept
        {
            if (value == nullptr ||
                length == 0 ||
                length > CertificateMaxRevocationUriLength ||
                !IsAsciiBytes(value, length) ||
                (!BytesStartWithIgnoreCase(value, length, "http://") &&
                    !BytesStartWithIgnoreCase(value, length, "https://"))) {
                return false;
            }

            for (SIZE_T index = 0; index < length; ++index) {
                if (value[index] < 0x20 || value[index] == 0x7f) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        NTSTATUS AddRevocationUri(
            _Inout_ ParsedCertificate& certificate,
            CertificateRevocationSource source,
            _In_ const DerElement& uri) noexcept
        {
            if (uri.Tag != TagUniformResourceIdentifier ||
                !IsValidRevocationUri(uri.Value, uri.ValueLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T* count = source == CertificateRevocationSource::Ocsp ?
                &certificate.OcspUriCount :
                &certificate.CrlDistributionPointUriCount;
            const char** uris = source == CertificateRevocationSource::Ocsp ?
                certificate.OcspUris :
                certificate.CrlDistributionPointUris;
            SIZE_T* lengths = source == CertificateRevocationSource::Ocsp ?
                certificate.OcspUriLengths :
                certificate.CrlDistributionPointUriLengths;

            if (*count >= CertificateMaxRevocationUris) {
                return STATUS_NOT_SUPPORTED;
            }

            uris[*count] = reinterpret_cast<const char*>(uri.Value);
            lengths[*count] = uri.ValueLength;
            ++(*count);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseAuthorityInfoAccess(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement descriptions = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, descriptions);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < descriptions.ValueLength) {
                DerElement description = {};
                status = ReadExpected(descriptions.Value, descriptions.ValueLength, &offset, TagSequence, description);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T itemOffset = 0;
                DerElement method = {};
                DerElement location = {};
                status = ReadExpected(description.Value, description.ValueLength, &itemOffset, TagOid, method);
                if (NT_SUCCESS(status)) {
                    status = ReadElement(description.Value, description.ValueLength, &itemOffset, location);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (itemOffset != description.ValueLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (OidEquals(method, OidOcspAccessMethod, sizeof(OidOcspAccessMethod)) &&
                    location.Tag == TagUniformResourceIdentifier) {
                    status = AddRevocationUri(certificate, CertificateRevocationSource::Ocsp, location);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseCrlDistributionPoints(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement points = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, points);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T pointOffset = 0;
            while (pointOffset < points.ValueLength) {
                DerElement point = {};
                status = ReadExpected(points.Value, points.ValueLength, &pointOffset, TagSequence, point);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T itemOffset = 0;
                while (itemOffset < point.ValueLength) {
                    DerElement item = {};
                    status = ReadElement(point.Value, point.ValueLength, &itemOffset, item);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    if (item.Tag != 0xa0) {
                        continue;
                    }

                    SIZE_T nameOffset = 0;
                    DerElement fullName = {};
                    status = ReadElement(item.Value, item.ValueLength, &nameOffset, fullName);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (nameOffset != item.ValueLength || fullName.Tag != 0xa0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    SIZE_T generalNameOffset = 0;
                    while (generalNameOffset < fullName.ValueLength) {
                        DerElement name = {};
                        status = ReadElement(fullName.Value, fullName.ValueLength, &generalNameOffset, name);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        if (name.Tag == TagUniformResourceIdentifier) {
                            status = AddRevocationUri(certificate, CertificateRevocationSource::Crl, name);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                    }
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool NameConstraintBytesAreAscii(_In_reads_bytes_(length) const UCHAR* value, SIZE_T length) noexcept
        {
            if (value == nullptr) {
                return length == 0;
            }

            for (SIZE_T index = 0; index < length; ++index) {
                if (value[index] > 0x7f) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        NTSTATUS AddDnsNameConstraint(
            _Inout_ ParsedCertificate& certificate,
            bool permitted,
            _In_reads_bytes_(length) const UCHAR* value,
            SIZE_T length) noexcept
        {
            if (value == nullptr || length == 0 || !NameConstraintBytesAreAscii(value, length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T* count = permitted ? &certificate.PermittedDnsSubtreeCount : &certificate.ExcludedDnsSubtreeCount;
            const char** names = permitted ? certificate.PermittedDnsSubtrees : certificate.ExcludedDnsSubtrees;
            SIZE_T* lengths = permitted ? certificate.PermittedDnsSubtreeLengths : certificate.ExcludedDnsSubtreeLengths;
            if (*count >= CertificateMaxNameConstraints) {
                return STATUS_NOT_SUPPORTED;
            }

            names[*count] = reinterpret_cast<const char*>(value);
            lengths[*count] = length;
            ++(*count);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AddIpNameConstraint(
            _Inout_ ParsedCertificate& certificate,
            bool permitted,
            _In_reads_bytes_(length) const UCHAR* value,
            SIZE_T length) noexcept
        {
            if (value == nullptr || (length != 8 && length != 32)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T* count = permitted ? &certificate.PermittedIpSubtreeCount : &certificate.ExcludedIpSubtreeCount;
            UCHAR (*subtrees)[32] = permitted ? certificate.PermittedIpSubtrees : certificate.ExcludedIpSubtrees;
            SIZE_T* lengths = permitted ? certificate.PermittedIpSubtreeLengths : certificate.ExcludedIpSubtreeLengths;
            if (*count >= CertificateMaxNameConstraints) {
                return STATUS_NOT_SUPPORTED;
            }

            RtlCopyMemory(subtrees[*count], value, length);
            lengths[*count] = length;
            ++(*count);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AddDirectoryNameConstraint(
            _Inout_ ParsedCertificate& certificate,
            bool permitted,
            _In_ const DerElement& value) noexcept
        {
            if (value.Tag != TagDirectoryName || value.Value == nullptr || value.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T nameOffset = 0;
            DerElement name = {};
            NTSTATUS status = ReadExpected(value.Value, value.ValueLength, &nameOffset, TagSequence, name);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (nameOffset != value.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T* count = permitted ? &certificate.PermittedDirectoryNameCount : &certificate.ExcludedDirectoryNameCount;
            const UCHAR** names = permitted ? certificate.PermittedDirectoryNames : certificate.ExcludedDirectoryNames;
            SIZE_T* lengths = permitted ? certificate.PermittedDirectoryNameLengths : certificate.ExcludedDirectoryNameLengths;
            if (*count >= CertificateMaxNameConstraints) {
                return STATUS_NOT_SUPPORTED;
            }

            names[*count] = name.Full;
            lengths[*count] = name.FullLength;
            ++(*count);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseGeneralSubtreeRemainder(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            SIZE_T offset) noexcept
        {
            while (offset < dataLength) {
                DerElement field = {};
                NTSTATUS status = ReadElement(data, dataLength, &offset, field);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (field.Tag == TagMinimumBaseDistance) {
                    if (field.Value == nullptr ||
                        field.ValueLength != 1 ||
                        field.Value[0] != 0) {
                        return STATUS_NOT_SUPPORTED;
                    }
                }
                else if (field.Tag == TagMaximumBaseDistance) {
                    return STATUS_NOT_SUPPORTED;
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseNameConstraintSubtree(
            _In_ const DerElement& subtree,
            bool permitted,
            _Inout_ ParsedCertificate& certificate) noexcept
        {
            if (subtree.Tag != TagSequence) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T subtreeOffset = 0;
            DerElement base = {};
            NTSTATUS status = ReadElement(subtree.Value, subtree.ValueLength, &subtreeOffset, base);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (base.Tag == TagDnsName) {
                status = AddDnsNameConstraint(certificate, permitted, base.Value, base.ValueLength);
            }
            else if (base.Tag == TagIpAddress) {
                status = AddIpNameConstraint(certificate, permitted, base.Value, base.ValueLength);
            }
            else if (base.Tag == TagDirectoryName) {
                status = AddDirectoryNameConstraint(certificate, permitted, base);
            }
            else {
                return STATUS_NOT_SUPPORTED;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            return ParseGeneralSubtreeRemainder(subtree.Value, subtree.ValueLength, subtreeOffset);
        }

        _Must_inspect_result_
        NTSTATUS ParseNameConstraintSubtrees(
            _In_ const DerElement& subtrees,
            bool permitted,
            _Inout_ ParsedCertificate& certificate) noexcept
        {
            if (subtrees.Tag != (permitted ? TagPermittedSubtrees : TagExcludedSubtrees) ||
                subtrees.Value == nullptr ||
                subtrees.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < subtrees.ValueLength) {
                DerElement subtree = {};
                NTSTATUS status = ReadExpected(subtrees.Value, subtrees.ValueLength, &offset, TagSequence, subtree);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = ParseNameConstraintSubtree(subtree, permitted, certificate);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseNameConstraints(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement constraints = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, constraints);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < constraints.ValueLength) {
                DerElement subtrees = {};
                status = ReadElement(constraints.Value, constraints.ValueLength, &offset, subtrees);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (subtrees.Tag == TagPermittedSubtrees) {
                    status = ParseNameConstraintSubtrees(subtrees, true, certificate);
                }
                else if (subtrees.Tag == TagExcludedSubtrees) {
                    status = ParseNameConstraintSubtrees(subtrees, false, certificate);
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            certificate.HasNameConstraints = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool IsValidObjectIdentifierValue(_In_ const DerElement& oid) noexcept
        {
            if (oid.Tag != TagOid || oid.Value == nullptr || oid.ValueLength == 0) {
                return false;
            }

            bool continuation = false;
            for (SIZE_T index = 0; index < oid.ValueLength; ++index) {
                continuation = (oid.Value[index] & 0x80) != 0;
            }

            return !continuation;
        }

        _Must_inspect_result_
        NTSTATUS ParsePolicyQualifierInfos(_In_ const DerElement& qualifiers) noexcept
        {
            if (qualifiers.Tag != TagSequence || qualifiers.Value == nullptr || qualifiers.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T qualifierOffset = 0;
            while (qualifierOffset < qualifiers.ValueLength) {
                DerElement qualifierInfo = {};
                NTSTATUS status = ReadExpected(
                    qualifiers.Value,
                    qualifiers.ValueLength,
                    &qualifierOffset,
                    TagSequence,
                    qualifierInfo);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T itemOffset = 0;
                DerElement qualifierId = {};
                status = ReadExpected(
                    qualifierInfo.Value,
                    qualifierInfo.ValueLength,
                    &itemOffset,
                    TagOid,
                    qualifierId);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (!IsValidObjectIdentifierValue(qualifierId)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (itemOffset < qualifierInfo.ValueLength) {
                    DerElement qualifier = {};
                    status = ReadElement(
                        qualifierInfo.Value,
                        qualifierInfo.ValueLength,
                        &itemOffset,
                        qualifier);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                if (itemOffset != qualifierInfo.ValueLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseCertificatePolicies(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement policies = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, policies);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength ||
                policies.Value == nullptr ||
                policies.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T policyOffset = 0;
            while (policyOffset < policies.ValueLength) {
                DerElement policyInfo = {};
                status = ReadExpected(
                    policies.Value,
                    policies.ValueLength,
                    &policyOffset,
                    TagSequence,
                    policyInfo);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T itemOffset = 0;
                DerElement policyOid = {};
                status = ReadExpected(
                    policyInfo.Value,
                    policyInfo.ValueLength,
                    &itemOffset,
                    TagOid,
                    policyOid);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (!IsValidObjectIdentifierValue(policyOid)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (certificate.CertificatePolicyOidCount >= CertificateMaxCertificatePolicies) {
                    return STATUS_NOT_SUPPORTED;
                }

                certificate.CertificatePolicyOids[certificate.CertificatePolicyOidCount] = policyOid.Value;
                certificate.CertificatePolicyOidLengths[certificate.CertificatePolicyOidCount] = policyOid.ValueLength;
                ++certificate.CertificatePolicyOidCount;
                if (OidEquals(policyOid, OidAnyPolicy, sizeof(OidAnyPolicy))) {
                    certificate.HasAnyPolicy = true;
                }

                if (itemOffset < policyInfo.ValueLength) {
                    DerElement qualifiers = {};
                    status = ReadExpected(
                        policyInfo.Value,
                        policyInfo.ValueLength,
                        &itemOffset,
                        TagSequence,
                        qualifiers);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ParsePolicyQualifierInfos(qualifiers);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                if (itemOffset != policyInfo.ValueLength) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            certificate.HasCertificatePolicies = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseImplicitUnsignedInteger(_In_ const DerElement& integer, _Out_ ULONG* value) noexcept
        {
            if (value == nullptr || integer.Value == nullptr || integer.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if ((integer.Value[0] & 0x80) != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            ULONG parsed = 0;
            for (SIZE_T offset = 0; offset < integer.ValueLength; ++offset) {
                if (parsed > (0xffffffffUL >> 8)) {
                    return STATUS_INTEGER_OVERFLOW;
                }

                parsed = (parsed << 8) | integer.Value[offset];
            }

            *value = parsed;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParsePolicyConstraints(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement constraints = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagSequence, constraints);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength || constraints.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < constraints.ValueLength) {
                DerElement constraint = {};
                status = ReadElement(constraints.Value, constraints.ValueLength, &offset, constraint);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                ULONG skipCerts = 0;
                status = ParseImplicitUnsignedInteger(constraint, &skipCerts);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (constraint.Tag == TagMinimumBaseDistance) {
                    certificate.RequireExplicitPolicy = true;
                    certificate.RequireExplicitPolicySkipCerts = skipCerts;
                }
                else if (constraint.Tag == TagMaximumBaseDistance) {
                    certificate.InhibitPolicyMapping = true;
                    certificate.InhibitPolicyMappingSkipCerts = skipCerts;
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            certificate.HasPolicyConstraints = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseInhibitAnyPolicy(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement skipCerts = {};
            NTSTATUS status = ReadExpected(extensionValue.Value, extensionValue.ValueLength, &valueOffset, TagInteger, skipCerts);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            ULONG parsed = 0;
            status = ParseUnsignedDerInteger(skipCerts, &parsed);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            certificate.HasInhibitAnyPolicy = true;
            certificate.InhibitAnyPolicySkipCerts = parsed;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseSubjectKeyIdentifier(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement keyIdentifier = {};
            NTSTATUS status = ReadExpected(
                extensionValue.Value,
                extensionValue.ValueLength,
                &valueOffset,
                TagOctetString,
                keyIdentifier);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (valueOffset != extensionValue.ValueLength ||
                keyIdentifier.Value == nullptr ||
                keyIdentifier.ValueLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            certificate.SubjectKeyIdentifier = keyIdentifier.Value;
            certificate.SubjectKeyIdentifierLength = keyIdentifier.ValueLength;
            certificate.HasSubjectKeyIdentifier = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseAuthorityKeyIdentifier(_In_ const DerElement& extensionValue, _Inout_ ParsedCertificate& certificate) noexcept
        {
            SIZE_T valueOffset = 0;
            DerElement sequence = {};
            NTSTATUS status = ReadExpected(
                extensionValue.Value,
                extensionValue.ValueLength,
                &valueOffset,
                TagSequence,
                sequence);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (valueOffset != extensionValue.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < sequence.ValueLength) {
                DerElement item = {};
                status = ReadElement(sequence.Value, sequence.ValueLength, &offset, item);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (item.Tag == 0x80) {
                    if (certificate.HasAuthorityKeyIdentifier ||
                        item.Value == nullptr ||
                        item.ValueLength == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    certificate.AuthorityKeyIdentifier = item.Value;
                    certificate.AuthorityKeyIdentifierLength = item.ValueLength;
                    certificate.HasAuthorityKeyIdentifier = true;
                }
                else if (item.Tag == 0xa1 || item.Tag == 0x82) {
                    continue;
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
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
            certificate.AllowsOcspSigning = false;

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
                else if (OidEquals(usage, OidOcspSigning, sizeof(OidOcspSigning))) {
                    certificate.AllowsOcspSigning = true;
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
                const SIZE_T currentExtensionOffset = offset;
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

                SIZE_T priorOffset = 0;
                while (priorOffset < currentExtensionOffset) {
                    DerElement priorExtension = {};
                    status = ReadExpected(sequence.Value, currentExtensionOffset, &priorOffset, TagSequence, priorExtension);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    SIZE_T priorItemOffset = 0;
                    DerElement priorOid = {};
                    status = ReadExpected(
                        priorExtension.Value,
                        priorExtension.ValueLength,
                        &priorItemOffset,
                        TagOid,
                        priorOid);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (OidElementsEqual(oid, priorOid)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }

                bool criticalExtension = false;
                if (itemOffset < extension.ValueLength && extension.Value[itemOffset] == TagBoolean) {
                    DerElement critical = {};
                    status = ReadExpected(extension.Value, extension.ValueLength, &itemOffset, TagBoolean, critical);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (critical.ValueLength != 1 || critical.Value == nullptr) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    criticalExtension = critical.Value[0] != 0;
                }

                DerElement value = {};
                status = ReadExpected(extension.Value, extension.ValueLength, &itemOffset, TagOctetString, value);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                bool recognized = true;
                if (OidEquals(oid, OidBasicConstraints, sizeof(OidBasicConstraints))) {
                    status = ParseBasicConstraints(value, certificate);
                }
                else if (OidEquals(oid, OidKeyUsage, sizeof(OidKeyUsage))) {
                    status = ParseKeyUsage(value, certificate);
                }
                else if (OidEquals(oid, OidSubjectKeyIdentifier, sizeof(OidSubjectKeyIdentifier))) {
                    status = ParseSubjectKeyIdentifier(value, certificate);
                }
                else if (OidEquals(oid, OidAuthorityKeyIdentifier, sizeof(OidAuthorityKeyIdentifier))) {
                    status = ParseAuthorityKeyIdentifier(value, certificate);
                }
                else if (OidEquals(oid, OidSubjectAltName, sizeof(OidSubjectAltName))) {
                    status = ParseSubjectAltName(value, certificate);
                }
                else if (OidEquals(oid, OidAuthorityInfoAccess, sizeof(OidAuthorityInfoAccess))) {
                    if (criticalExtension) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = ParseAuthorityInfoAccess(value, certificate);
                }
                else if (OidEquals(oid, OidCrlDistributionPoints, sizeof(OidCrlDistributionPoints))) {
                    if (criticalExtension) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = ParseCrlDistributionPoints(value, certificate);
                }
                else if (OidEquals(oid, OidNameConstraints, sizeof(OidNameConstraints))) {
                    status = ParseNameConstraints(value, certificate);
                }
                else if (OidEquals(oid, OidCertificatePolicies, sizeof(OidCertificatePolicies))) {
                    certificate.CertificatePoliciesCritical = criticalExtension;
                    status = ParseCertificatePolicies(value, certificate);
                }
                else if (OidEquals(oid, OidPolicyConstraints, sizeof(OidPolicyConstraints))) {
                    status = ParsePolicyConstraints(value, certificate);
                }
                else if (OidEquals(oid, OidInhibitAnyPolicy, sizeof(OidInhibitAnyPolicy))) {
                    status = ParseInhibitAnyPolicy(value, certificate);
                }
                else if (OidEquals(oid, OidExtendedKeyUsage, sizeof(OidExtendedKeyUsage))) {
                    status = ParseExtendedKeyUsage(value, certificate);
                }
                else {
                    recognized = false;
                    if (criticalExtension) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }

                if (recognized && !NT_SUCCESS(status)) {
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
                if (certificate.RsaModulusLength * 8 < KhMinRsaModulusBits) {
                    return STATUS_NOT_SUPPORTED;
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
        bool ContainsNonAscii(_In_reads_(length) const char* value, SIZE_T length) noexcept
        {
            if (value == nullptr) {
                return length != 0;
            }

            for (SIZE_T index = 0; index < length; ++index) {
                if (static_cast<UCHAR>(value[index]) > 0x7f) {
                    return true;
                }
            }

            return false;
        }

        _Must_inspect_result_
        bool IsAsciiBytes(_In_reads_bytes_(length) const UCHAR* value, SIZE_T length) noexcept
        {
            if (value == nullptr) {
                return length != 0;
            }

            for (SIZE_T index = 0; index < length; ++index) {
                if (value[index] > 0x7f) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        bool IsAsciiAlpha(char value) noexcept
        {
            return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
        }

        _Must_inspect_result_
        bool IsAsciiAlnum(char value) noexcept
        {
            return IsAsciiAlpha(value) || (value >= '0' && value <= '9');
        }

        _Must_inspect_result_
        bool IsValidDnsLabelByte(char value) noexcept
        {
            return IsAsciiAlnum(value) || value == '-';
        }

        _Must_inspect_result_
        char ToLowerAsciiChar(char value) noexcept
        {
            return (value >= 'A' && value <= 'Z') ? static_cast<char>(value - 'A' + 'a') : value;
        }

        _Must_inspect_result_
        char EncodePunycodeDigit(ULONG digit) noexcept
        {
            return static_cast<char>(digit < 26 ? ('a' + digit) : ('0' + (digit - 26)));
        }

        _Must_inspect_result_
        ULONG AdaptPunycodeBias(ULONG delta, ULONG numPoints, bool firstTime) noexcept
        {
            delta = firstTime ? (delta / 700) : (delta / 2);
            delta += delta / numPoints;

            ULONG k = 0;
            while (delta > (((36 - 1) * 26) / 2)) {
                delta /= 36 - 1;
                k += 36;
            }

            return k + (((36 - 1 + 1) * delta) / (delta + 38));
        }

        _Must_inspect_result_
        NTSTATUS AppendOutputChar(
            char value,
            _Out_writes_bytes_(capacity) char* output,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (output == nullptr || offset == nullptr || *offset >= capacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            output[*offset] = value;
            ++(*offset);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS DecodeUtf8CodePoint(
            _In_reads_bytes_(length) const char* text,
            SIZE_T length,
            _Inout_ SIZE_T* offset,
            _Out_ ULONG* codePoint) noexcept
        {
            if (text == nullptr || offset == nullptr || codePoint == nullptr || *offset >= length) {
                return STATUS_INVALID_PARAMETER;
            }

            const UCHAR first = static_cast<UCHAR>(text[*offset]);
            if (first < 0x80) {
                *codePoint = first;
                ++(*offset);
                return STATUS_SUCCESS;
            }

            UCHAR expectedLength = 0;
            ULONG value = 0;
            if ((first & 0xe0) == 0xc0) {
                expectedLength = 2;
                value = first & 0x1f;
            }
            else if ((first & 0xf0) == 0xe0) {
                expectedLength = 3;
                value = first & 0x0f;
            }
            else if ((first & 0xf8) == 0xf0) {
                expectedLength = 4;
                value = first & 0x07;
            }
            else {
                return STATUS_INVALID_PARAMETER;
            }

            if (expectedLength > length - *offset) {
                return STATUS_INVALID_PARAMETER;
            }

            for (UCHAR index = 1; index < expectedLength; ++index) {
                const UCHAR next = static_cast<UCHAR>(text[*offset + index]);
                if ((next & 0xc0) != 0x80) {
                    return STATUS_INVALID_PARAMETER;
                }

                value = (value << 6) | (next & 0x3f);
            }

            if ((expectedLength == 2 && value < 0x80) ||
                (expectedLength == 3 && value < 0x800) ||
                (expectedLength == 4 && value < 0x10000) ||
                (value >= 0xd800 && value <= 0xdfff) ||
                value > 0x10ffff) {
                return STATUS_INVALID_PARAMETER;
            }

            *offset += expectedLength;
            *codePoint = value;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS PunycodeEncodeLabel(
            _In_reads_(labelLength) const char* label,
            SIZE_T labelLength,
            _Out_writes_bytes_(outputCapacity) char* output,
            SIZE_T outputCapacity,
            _Out_ SIZE_T* outputLength) noexcept
        {
            if (outputLength != nullptr) {
                *outputLength = 0;
            }
            if (label == nullptr ||
                labelLength == 0 ||
                output == nullptr ||
                outputLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<ULONG> codePoints(labelLength);
            if (!codePoints.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T inputOffset = 0;
            SIZE_T codePointCount = 0;
            bool hasNonAscii = false;
            while (inputOffset < labelLength) {
                ULONG codePoint = 0;
                NTSTATUS status = DecodeUtf8CodePoint(label, labelLength, &inputOffset, &codePoint);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (codePoint == '.') {
                    return STATUS_INVALID_PARAMETER;
                }
                if (codePoint < 0x80) {
                    const char ascii = static_cast<char>(codePoint);
                    if (!IsValidDnsLabelByte(ascii)) {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                else {
                    hasNonAscii = true;
                }

                codePoints[codePointCount++] = codePoint;
            }

            SIZE_T out = 0;
            if (!hasNonAscii) {
                for (SIZE_T index = 0; index < codePointCount; ++index) {
                    NTSTATUS status = AppendOutputChar(
                        ToLowerAsciiChar(static_cast<char>(codePoints[index])),
                        output,
                        outputCapacity,
                        &out);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                *outputLength = out;
                return out <= 63 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T index = 0; index < sizeof(PunycodePrefix) - 1; ++index) {
                NTSTATUS status = AppendOutputChar(PunycodePrefix[index], output, outputCapacity, &out);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            SIZE_T basicCount = 0;
            for (SIZE_T index = 0; index < codePointCount; ++index) {
                if (codePoints[index] < 0x80) {
                    NTSTATUS status = AppendOutputChar(
                        ToLowerAsciiChar(static_cast<char>(codePoints[index])),
                        output,
                        outputCapacity,
                        &out);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    ++basicCount;
                }
            }

            SIZE_T handledCount = basicCount;
            if (basicCount != 0) {
                NTSTATUS status = AppendOutputChar('-', output, outputCapacity, &out);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            ULONG n = 128;
            ULONG delta = 0;
            ULONG bias = 72;
            while (handledCount < codePointCount) {
                ULONG m = 0x10ffff;
                for (SIZE_T index = 0; index < codePointCount; ++index) {
                    if (codePoints[index] >= n && codePoints[index] < m) {
                        m = codePoints[index];
                    }
                }

                if (m == 0x10ffff ||
                    m < n ||
                    (m - n) > ((0xffffffffUL - delta) / static_cast<ULONG>(handledCount + 1))) {
                    return STATUS_INTEGER_OVERFLOW;
                }

                delta += (m - n) * static_cast<ULONG>(handledCount + 1);
                n = m;

                for (SIZE_T index = 0; index < codePointCount; ++index) {
                    if (codePoints[index] < n) {
                        if (delta == 0xffffffffUL) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                        ++delta;
                    }
                    else if (codePoints[index] == n) {
                        ULONG q = delta;
                        for (ULONG k = 36;; k += 36) {
                            const ULONG t = k <= bias ? 1 : (k >= bias + 26 ? 26 : k - bias);
                            if (q < t) {
                                break;
                            }

                            const ULONG code = t + ((q - t) % (36 - t));
                            NTSTATUS status = AppendOutputChar(EncodePunycodeDigit(code), output, outputCapacity, &out);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                            q = (q - t) / (36 - t);
                        }

                        NTSTATUS status = AppendOutputChar(EncodePunycodeDigit(q), output, outputCapacity, &out);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        bias = AdaptPunycodeBias(delta, static_cast<ULONG>(handledCount + 1), handledCount == basicCount);
                        delta = 0;
                        ++handledCount;
                    }
                }

                if (delta == 0xffffffffUL || n == 0x10ffff) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                ++delta;
                ++n;
            }

            *outputLength = out;
            return out <= 63 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        }

        _Must_inspect_result_
        NTSTATUS NormalizeDnsName(
            _In_reads_(hostLength) const char* host,
            SIZE_T hostLength,
            bool enableIdna,
            _Out_writes_bytes_(outputCapacity) char* output,
            SIZE_T outputCapacity,
            _Out_ SIZE_T* outputLength) noexcept
        {
            if (outputLength != nullptr) {
                *outputLength = 0;
            }
            if (host == nullptr ||
                hostLength == 0 ||
                output == nullptr ||
                outputLength == nullptr ||
                outputCapacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (ContainsNonAscii(host, hostLength) && !enableIdna) {
                return STATUS_NOT_SUPPORTED;
            }

            SIZE_T inputOffset = 0;
            SIZE_T out = 0;
            while (inputOffset < hostLength) {
                const SIZE_T labelStart = inputOffset;
                while (inputOffset < hostLength && host[inputOffset] != '.') {
                    ++inputOffset;
                }

                const SIZE_T labelLength = inputOffset - labelStart;
                if (labelLength == 0) {
                    return STATUS_INVALID_PARAMETER;
                }

                SIZE_T written = 0;
                NTSTATUS status = PunycodeEncodeLabel(
                    host + labelStart,
                    labelLength,
                    output + out,
                    outputCapacity - out,
                    &written);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                out += written;
                if (inputOffset < hostLength) {
                    status = AppendOutputChar('.', output, outputCapacity, &out);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    ++inputOffset;
                }
            }

            if (out == 0 ||
                out > CertificateMaxNormalizedDnsNameLength ||
                out >= outputCapacity) {
                return STATUS_INVALID_PARAMETER;
            }

            output[out] = '\0';
            *outputLength = out;
            return STATUS_SUCCESS;
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
        bool IsDecimalDigit(char value) noexcept
        {
            return value >= '0' && value <= '9';
        }

        _Must_inspect_result_
        bool ParseIpv4Literal(
            _In_reads_(hostLength) const char* host,
            SIZE_T hostLength,
            _Out_writes_bytes_(4) UCHAR* address) noexcept
        {
            if (host == nullptr || hostLength == 0 || address == nullptr) {
                return false;
            }

            SIZE_T index = 0;
            for (SIZE_T part = 0; part < 4; ++part) {
                if (index >= hostLength || !IsDecimalDigit(host[index])) {
                    return false;
                }

                ULONG value = 0;
                SIZE_T digits = 0;
                while (index < hostLength && IsDecimalDigit(host[index])) {
                    value = (value * 10) + static_cast<ULONG>(host[index] - '0');
                    if (value > 255) {
                        return false;
                    }
                    ++index;
                    ++digits;
                }

                if (digits == 0) {
                    return false;
                }

                address[part] = static_cast<UCHAR>(value);
                if (part == 3) {
                    return index == hostLength;
                }

                if (index >= hostLength || host[index] != '.') {
                    return false;
                }
                ++index;
            }

            return false;
        }

        _Must_inspect_result_
        bool HexValue(char value, _Out_ USHORT* digit) noexcept
        {
            if (digit == nullptr) {
                return false;
            }

            if (value >= '0' && value <= '9') {
                *digit = static_cast<USHORT>(value - '0');
                return true;
            }
            if (value >= 'a' && value <= 'f') {
                *digit = static_cast<USHORT>(10 + value - 'a');
                return true;
            }
            if (value >= 'A' && value <= 'F') {
                *digit = static_cast<USHORT>(10 + value - 'A');
                return true;
            }

            return false;
        }

        _Must_inspect_result_
        bool ParseIpv6Literal(
            _In_reads_(hostLength) const char* host,
            SIZE_T hostLength,
            _Out_writes_bytes_(16) UCHAR* address) noexcept
        {
            if (host == nullptr || hostLength == 0 || address == nullptr) {
                return false;
            }

            SIZE_T start = 0;
            SIZE_T length = hostLength;
            if (hostLength >= 2 && host[0] == '[' && host[hostLength - 1] == ']') {
                start = 1;
                length = hostLength - 2;
            }
            if (length == 0) {
                return false;
            }

            HeapArray<USHORT> groups(8);
            if (!groups.IsValid()) {
                return false;
            }

            SIZE_T groupCount = 0;
            SIZE_T compressIndex = static_cast<SIZE_T>(-1);
            SIZE_T index = start;
            const SIZE_T end = start + length;

            while (index < end) {
                if (host[index] == ':') {
                    if (index + 1 >= end || host[index + 1] != ':' || compressIndex != static_cast<SIZE_T>(-1)) {
                        return false;
                    }
                    compressIndex = groupCount;
                    index += 2;
                    if (index == end) {
                        break;
                    }
                    continue;
                }

                if (groupCount >= 8) {
                    return false;
                }

                USHORT value = 0;
                SIZE_T digits = 0;
                while (index < end) {
                    USHORT digit = 0;
                    if (!HexValue(host[index], &digit)) {
                        break;
                    }
                    if (digits == 4) {
                        return false;
                    }
                    value = static_cast<USHORT>((value << 4) | digit);
                    ++digits;
                    ++index;
                }
                if (digits == 0) {
                    return false;
                }

                groups[groupCount++] = value;
                if (index == end) {
                    break;
                }
                if (host[index] != ':') {
                    return false;
                }
                if (index + 1 < end && host[index + 1] == ':') {
                    if (compressIndex != static_cast<SIZE_T>(-1)) {
                        return false;
                    }
                    compressIndex = groupCount;
                    index += 2;
                    if (index == end) {
                        break;
                    }
                }
                else {
                    ++index;
                    if (index == end) {
                        return false;
                    }
                }
            }

            if (compressIndex == static_cast<SIZE_T>(-1)) {
                if (groupCount != 8) {
                    return false;
                }
            }
            else {
                if (groupCount >= 8) {
                    return false;
                }
                const SIZE_T zeros = 8 - groupCount;
                for (SIZE_T move = groupCount; move > compressIndex; --move) {
                    groups[move + zeros - 1] = groups[move - 1];
                }
                for (SIZE_T fill = 0; fill < zeros; ++fill) {
                    groups[compressIndex + fill] = 0;
                }
                groupCount = 8;
            }

            for (SIZE_T group = 0; group < 8; ++group) {
                address[group * 2] = static_cast<UCHAR>((groups[group] >> 8) & 0xff);
                address[(group * 2) + 1] = static_cast<UCHAR>(groups[group] & 0xff);
            }

            return true;
        }

        _Must_inspect_result_
        bool ParseIpLiteral(
            _In_reads_(hostLength) const char* host,
            SIZE_T hostLength,
            _Out_writes_bytes_(16) UCHAR* address,
            _Out_ SIZE_T* addressLength) noexcept
        {
            if (addressLength != nullptr) {
                *addressLength = 0;
            }
            if (host == nullptr || hostLength == 0 || address == nullptr || addressLength == nullptr) {
                return false;
            }

            if (ParseIpv4Literal(host, hostLength, address)) {
                *addressLength = 4;
                return true;
            }
            if (ParseIpv6Literal(host, hostLength, address)) {
                *addressLength = 16;
                return true;
            }

            return false;
        }

        _Must_inspect_result_
        NTSTATUS ValidateHostName(
            _In_ const ParsedCertificate& leaf,
            _In_reads_(hostNameLength) const char* hostName,
            SIZE_T hostNameLength) noexcept
        {
            if (hostName == nullptr || hostNameLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<UCHAR> hostAddress(16);
            if (!hostAddress.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T hostAddressLength = 0;
            if (ParseIpLiteral(hostName, hostNameLength, hostAddress.Get(), &hostAddressLength)) {
                for (SIZE_T index = 0; index < leaf.IpAddressCount; ++index) {
                    if (leaf.IpAddressLengths[index] == hostAddressLength &&
                        RtlCompareMemory(leaf.IpAddresses[index], hostAddress.Get(), hostAddressLength) == hostAddressLength) {
                        return STATUS_SUCCESS;
                    }
                }

                return STATUS_TRUST_FAILURE;
            }

            if (leaf.DnsNameCount != 0) {
                for (SIZE_T index = 0; index < leaf.DnsNameCount; ++index) {
                    if (HostNameMatches(leaf.DnsNames[index], leaf.DnsNameLengths[index], hostName, hostNameLength)) {
                        return STATUS_SUCCESS;
                    }
                }

                return STATUS_TRUST_FAILURE;
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
            // Ed25519 (RFC 8032/8410): PureEdDSA verifies the full TBSCertificate
            // bytes directly (no external hash) against the issuer's raw 32-byte
            // key, so it bypasses HashForSignature / ImportSubjectPublicKey.
            if (certificate.SignatureAlgorithm == CertificateSignatureAlgorithm::Ed25519) {
                if (issuer.PublicKeyAlgorithm != CertificatePublicKeyAlgorithm::Ed25519) {
                    return STATUS_INVALID_SIGNATURE;
                }

                NTSTATUS status = crypto::CngProvider::VerifyEd25519(
                    issuer.PublicKey,
                    issuer.PublicKeyLength,
                    certificate.TbsCertificate,
                    certificate.TbsCertificateLength,
                    certificate.Signature,
                    certificate.SignatureLength);
                return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
            }
            if (certificate.SignatureAlgorithm == CertificateSignatureAlgorithm::Ed448) {
                if (issuer.PublicKeyAlgorithm != CertificatePublicKeyAlgorithm::Ed448) {
                    return STATUS_INVALID_SIGNATURE;
                }

                NTSTATUS status = crypto::CngProvider::VerifyEd448(
                    issuer.PublicKey,
                    issuer.PublicKeyLength,
                    certificate.TbsCertificate,
                    certificate.TbsCertificateLength,
                    certificate.Signature,
                    certificate.SignatureLength);
                return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
            }

            HeapObject<crypto::CngKey> issuerKey;
            if (!issuerKey.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = CertificateValidator::ImportSubjectPublicKey(providerCache, issuer, *issuerKey.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            HeapArray<UCHAR> hash(64);
            if (!hash.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T hashLength = 0;
            status = HashForSignature(
                providerCache,
                certificate.SignatureAlgorithm,
                certificate.TbsCertificate,
                certificate.TbsCertificateLength,
                hash.Get(),
                hash.Count(),
                &hashLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            crypto::SignatureAlgorithm verifyAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
            status = CertificateValidator::ToSignatureAlgorithm(
                certificate.SignatureAlgorithm,
                &verifyAlgorithm);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(hash.Get(), hash.Count());
                return status;
            }

            status = crypto::CngProvider::VerifySignature(
                providerCache,
                verifyAlgorithm,
                *issuerKey.Get(),
                hash.Get(),
                hashLength,
                certificate.Signature,
                certificate.SignatureLength);

            RtlSecureZeroMemory(hash.Get(), hash.Count());
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
            _Out_ SIZE_T* certificateOffset,
            _Out_ SIZE_T* nextOffset) noexcept
        {
            if (destinationLength != nullptr) {
                *destinationLength = 0;
            }

            if (certificateOffset != nullptr) {
                *certificateOffset = start;
            }

            if (nextOffset != nullptr) {
                *nextOffset = start;
            }

            if (data == nullptr ||
                destination == nullptr ||
                destinationLength == nullptr ||
                certificateOffset == nullptr ||
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

            *certificateOffset = begin;
            *nextOffset = end + (sizeof(PemCertificateEnd) - 1);

            HeapArray<UCHAR> quartet(4);
            HeapArray<bool> padding(4);
            if (!quartet.IsValid() || !padding.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

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
                        quartet.Get(),
                        padding.Get(),
                        destination,
                        destinationCapacity,
                        destinationLength,
                        &completed);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    RtlZeroMemory(quartet.Get(), quartet.Count());
                    RtlZeroMemory(padding.Get(), padding.Count() * sizeof(bool));
                    quartetLength = 0;
                }
            }

            if (quartetLength != 0 || *destinationLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

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
        bool IsSelfIssued(_In_ const ParsedCertificate& certificate) noexcept
        {
            return certificate.SubjectLength == certificate.IssuerLength &&
                MemoryEquals(certificate.Subject, certificate.Issuer, certificate.SubjectLength);
        }

        _Must_inspect_result_
        SIZE_T CountSubordinateCaCertificates(
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount,
            SIZE_T issuerIndex) noexcept
        {
            if (certificates == nullptr || issuerIndex > certificateCount) {
                return 0;
            }

            SIZE_T count = 0;
            for (SIZE_T index = 1; index < issuerIndex; ++index) {
                if (certificates[index].IsCa && !IsSelfIssued(certificates[index])) {
                    ++count;
                }
            }

            return count;
        }

        _Must_inspect_result_
        bool DistinguishedNameEquals(
            _In_reads_bytes_(leftLength) const UCHAR* left,
            SIZE_T leftLength,
            _In_reads_bytes_(rightLength) const UCHAR* right,
            SIZE_T rightLength) noexcept
        {
            return leftLength == rightLength && MemoryEquals(left, right, leftLength);
        }

        _Must_inspect_result_
        bool CertificateIssuerMatches(
            _In_ const ParsedCertificate& child,
            _In_ const ParsedCertificate& issuer) noexcept
        {
            return DistinguishedNameEquals(
                child.Issuer,
                child.IssuerLength,
                issuer.Subject,
                issuer.SubjectLength);
        }

        _Must_inspect_result_
        bool CertificateIssuesAny(
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount,
            SIZE_T issuerIndex) noexcept
        {
            if (certificates == nullptr || issuerIndex >= certificateCount) {
                return false;
            }

            for (SIZE_T index = 0; index < certificateCount; ++index) {
                if (index != issuerIndex && CertificateIssuerMatches(certificates[index], certificates[issuerIndex])) {
                    return true;
                }
            }

            return false;
        }

        _Must_inspect_result_
        bool CertificateNameMatchesHost(
            _In_ const ParsedCertificate& certificate,
            _In_reads_(hostNameLength) const char* hostName,
            SIZE_T hostNameLength) noexcept
        {
            return ValidateHostName(certificate, hostName, hostNameLength) == STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS StoreHasTrustedAnchor(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_opt_ const CertificateStore* store,
            _In_ const ParsedCertificate& certificate,
            _In_reads_bytes_(CertificateSha256ThumbprintLength) const UCHAR* certificateSpkiSha256,
            SIZE_T subordinateCaCount,
            _Inout_ ParsedCertificate* anchor,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ bool* trusted) noexcept;

        struct CertificatePathSearchFrame final
        {
            SIZE_T NextCandidateIndex = 0;
            UCHAR Priority = 2;
        };

        _Must_inspect_result_
        bool CertificateKeyIdentifiersPermitIssuer(
            _In_ const ParsedCertificate& child,
            _In_ const ParsedCertificate& issuer,
            _Out_ bool* strongMatch) noexcept
        {
            if (strongMatch != nullptr) {
                *strongMatch = false;
            }

            if (strongMatch == nullptr) {
                return false;
            }

            if (child.HasAuthorityKeyIdentifier && issuer.HasSubjectKeyIdentifier) {
                if (child.AuthorityKeyIdentifierLength != issuer.SubjectKeyIdentifierLength ||
                    !MemoryEquals(
                        child.AuthorityKeyIdentifier,
                        issuer.SubjectKeyIdentifier,
                        child.AuthorityKeyIdentifierLength)) {
                    return false;
                }

                *strongMatch = true;
            }

            return true;
        }

        _Must_inspect_result_
        NTSTATUS CertificateCanIssueForPath(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& child,
            _In_ const ParsedCertificate& issuer,
            UCHAR requiredPriority,
            _Out_ bool* matches) noexcept
        {
            if (matches != nullptr) {
                *matches = false;
            }
            if (matches == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (!CertificateIssuerMatches(child, issuer) ||
                !issuer.HasBasicConstraints ||
                !issuer.IsCa ||
                !issuer.HasKeyUsage ||
                !issuer.AllowsKeyCertSign) {
                return STATUS_SUCCESS;
            }

            bool strongKeyIdentifierMatch = false;
            if (!CertificateKeyIdentifiersPermitIssuer(child, issuer, &strongKeyIdentifierMatch)) {
                return STATUS_SUCCESS;
            }
            if (requiredPriority == 2 && !strongKeyIdentifierMatch) {
                return STATUS_SUCCESS;
            }

            const NTSTATUS status = VerifyCertificateSignature(providerCache, child, issuer);
            if (status == STATUS_INVALID_SIGNATURE) {
                return STATUS_SUCCESS;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *matches = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        SIZE_T CountSubordinateCaCertificatesInPath(
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount,
            _In_reads_(pathCount) const SIZE_T* pathIndices,
            SIZE_T pathCount) noexcept
        {
            if (certificates == nullptr || pathIndices == nullptr || pathCount < 2) {
                return 0;
            }

            SIZE_T count = 0;
            for (SIZE_T pathIndex = 1; pathIndex < pathCount; ++pathIndex) {
                const SIZE_T certificateIndex = pathIndices[pathIndex];
                if (certificateIndex < certificateCount &&
                    certificates[certificateIndex].IsCa &&
                    !IsSelfIssued(certificates[certificateIndex])) {
                    ++count;
                }
            }

            return count;
        }

        _Must_inspect_result_
        NTSTATUS PathEndsAtTrustedAnchor(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_opt_ const CertificateStore* store,
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount,
            _In_reads_(pathCount) const SIZE_T* pathIndices,
            SIZE_T pathCount,
            _Inout_ ParsedCertificate* anchor,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ bool* trusted) noexcept
        {
            if (trusted != nullptr) {
                *trusted = false;
            }
            if (certificates == nullptr ||
                certificateCount == 0 ||
                pathIndices == nullptr ||
                pathCount == 0 ||
                anchor == nullptr ||
                scratch == nullptr ||
                trusted == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            const SIZE_T currentIndex = pathIndices[pathCount - 1];
            if (currentIndex >= certificateCount) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<UCHAR> certSpkiSha256(CertificateSha256ThumbprintLength);
            if (!certSpkiSha256.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = HashSubjectPublicKey(providerCache, certificates[currentIndex], certSpkiSha256.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const SIZE_T subordinateCaCount = CountSubordinateCaCertificatesInPath(
                certificates,
                certificateCount,
                pathIndices,
                pathCount);
            status = StoreHasTrustedAnchor(
                providerCache,
                store,
                certificates[currentIndex],
                certSpkiSha256.Get(),
                subordinateCaCount,
                anchor,
                scratch,
                scratchCapacity,
                trusted);
            RtlSecureZeroMemory(certSpkiSha256.Get(), certSpkiSha256.Count());
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildCertificatePath(
            _Inout_updates_(certificateCount) ParsedCertificate* certificates,
            SIZE_T certificateCount,
            _In_reads_(hostNameLength) const char* hostName,
            SIZE_T hostNameLength,
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_opt_ const CertificateStore* store,
            _Inout_ ParsedCertificate* anchor,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ SIZE_T* pathCount) noexcept
        {
            if (pathCount != nullptr) {
                *pathCount = 0;
            }
            if (certificates == nullptr ||
                certificateCount == 0 ||
                certificateCount > CertificateMaxChainLength ||
                anchor == nullptr ||
                scratch == nullptr ||
                scratchCapacity < CertificateMaxAuthorityDerLength ||
                pathCount == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<ParsedCertificate> ordered(CertificateMaxChainLength);
            HeapArray<UCHAR> used(CertificateMaxChainLength);
            HeapArray<SIZE_T> pathIndices(CertificateMaxChainLength);
            HeapArray<CertificatePathSearchFrame> frames(CertificateMaxChainLength);
            if (!ordered.IsValid() || !used.IsValid() || !pathIndices.IsValid() || !frames.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            for (UCHAR leafPass = 0; leafPass < 2; ++leafPass) {
                for (SIZE_T leafIndex = 0; leafIndex < certificateCount; ++leafIndex) {
                    if (CertificateIssuesAny(certificates, certificateCount, leafIndex)) {
                        continue;
                    }

                    if (leafPass == 0 &&
                        !CertificateNameMatchesHost(certificates[leafIndex], hostName, hostNameLength)) {
                        continue;
                    }

                    RtlZeroMemory(used.Get(), used.Count());
                    RtlZeroMemory(pathIndices.Get(), pathIndices.Count() * sizeof(SIZE_T));
                    RtlZeroMemory(frames.Get(), frames.Count() * sizeof(CertificatePathSearchFrame));

                    SIZE_T currentPathCount = 1;
                    pathIndices[0] = leafIndex;
                    used[leafIndex] = 1;
                    frames[0].Priority = 2;
                    frames[0].NextCandidateIndex = 0;

                    for (;;) {
                        bool trusted = false;
                        NTSTATUS status = PathEndsAtTrustedAnchor(
                            providerCache,
                            store,
                            certificates,
                            certificateCount,
                            pathIndices.Get(),
                            currentPathCount,
                            anchor,
                            scratch,
                            scratchCapacity,
                            &trusted);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        if (trusted) {
                            for (SIZE_T index = 0; index < currentPathCount; ++index) {
                                ordered[index] = certificates[pathIndices[index]];
                            }
                            for (SIZE_T index = 0; index < currentPathCount; ++index) {
                                certificates[index] = ordered[index];
                            }

                            *pathCount = currentPathCount;
                            return STATUS_SUCCESS;
                        }

                        CertificatePathSearchFrame* const frame = &frames[currentPathCount - 1];
                        SIZE_T issuerIndex = certificateCount;
                        while (issuerIndex == certificateCount && frame->Priority != 0) {
                            while (frame->NextCandidateIndex < certificateCount) {
                                const SIZE_T candidateIndex = frame->NextCandidateIndex;
                                ++frame->NextCandidateIndex;
                                if (used[candidateIndex] != 0) {
                                    continue;
                                }

                                bool matches = false;
                                status = CertificateCanIssueForPath(
                                    providerCache,
                                    certificates[pathIndices[currentPathCount - 1]],
                                    certificates[candidateIndex],
                                    frame->Priority,
                                    &matches);
                                if (!NT_SUCCESS(status)) {
                                    return status;
                                }

                                if (matches) {
                                    issuerIndex = candidateIndex;
                                    break;
                                }
                            }

                            if (issuerIndex == certificateCount) {
                                --frame->Priority;
                                frame->NextCandidateIndex = 0;
                            }
                        }

                        if (issuerIndex != certificateCount &&
                            currentPathCount < CertificateMaxChainLength) {
                            pathIndices[currentPathCount] = issuerIndex;
                            used[issuerIndex] = 1;
                            frames[currentPathCount].Priority = 2;
                            frames[currentPathCount].NextCandidateIndex = 0;
                            ++currentPathCount;
                            continue;
                        }

                        used[pathIndices[currentPathCount - 1]] = 0;
                        if (currentPathCount == 1) {
                            break;
                        }

                        --currentPathCount;
                    }
                }
            }

            return STATUS_TRUST_FAILURE;
        }

        _Must_inspect_result_
        bool DnsNameMatchesSubtree(
            _In_reads_(nameLength) const char* name,
            SIZE_T nameLength,
            _In_reads_(subtreeLength) const char* subtree,
            SIZE_T subtreeLength) noexcept
        {
            if (name == nullptr || subtree == nullptr || nameLength == 0 || subtreeLength == 0) {
                return false;
            }

            if (subtree[0] == '.') {
                if (nameLength <= subtreeLength) {
                    return false;
                }

                const SIZE_T suffixStart = nameLength - subtreeLength;
                for (SIZE_T index = 0; index < subtreeLength; ++index) {
                    if (!CharEqualsIgnoreCase(name[suffixStart + index], subtree[index])) {
                        return false;
                    }
                }

                return true;
            }

            if (nameLength == subtreeLength) {
                bool exact = true;
                for (SIZE_T index = 0; index < nameLength; ++index) {
                    if (!CharEqualsIgnoreCase(name[index], subtree[index])) {
                        exact = false;
                        break;
                    }
                }
                if (exact) {
                    return true;
                }
            }

            if (nameLength <= subtreeLength + 1 ||
                name[nameLength - subtreeLength - 1] != '.') {
                return false;
            }

            const SIZE_T suffixStart = nameLength - subtreeLength;
            for (SIZE_T index = 0; index < subtreeLength; ++index) {
                if (!CharEqualsIgnoreCase(name[suffixStart + index], subtree[index])) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        NTSTATUS ValidateDnsNameAgainstConstraints(
            _In_reads_(nameLength) const char* name,
            SIZE_T nameLength,
            _In_ const ParsedCertificate& issuer) noexcept
        {
            for (SIZE_T index = 0; index < issuer.ExcludedDnsSubtreeCount; ++index) {
                if (DnsNameMatchesSubtree(
                    name,
                    nameLength,
                    issuer.ExcludedDnsSubtrees[index],
                    issuer.ExcludedDnsSubtreeLengths[index])) {
                    return STATUS_TRUST_FAILURE;
                }
            }

            if (issuer.PermittedDnsSubtreeCount == 0) {
                return STATUS_SUCCESS;
            }

            for (SIZE_T index = 0; index < issuer.PermittedDnsSubtreeCount; ++index) {
                if (DnsNameMatchesSubtree(
                    name,
                    nameLength,
                    issuer.PermittedDnsSubtrees[index],
                    issuer.PermittedDnsSubtreeLengths[index])) {
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_TRUST_FAILURE;
        }

        _Must_inspect_result_
        bool IpAddressMatchesSubtree(
            _In_reads_bytes_(addressLength) const UCHAR* address,
            SIZE_T addressLength,
            _In_reads_bytes_(subtreeLength) const UCHAR* subtree,
            SIZE_T subtreeLength) noexcept
        {
            if (address == nullptr ||
                subtree == nullptr ||
                !((addressLength == 4 && subtreeLength == 8) ||
                    (addressLength == 16 && subtreeLength == 32))) {
                return false;
            }

            for (SIZE_T index = 0; index < addressLength; ++index) {
                const UCHAR mask = subtree[addressLength + index];
                if ((address[index] & mask) != (subtree[index] & mask)) {
                    return false;
                }
            }

            return true;
        }

        _Must_inspect_result_
        NTSTATUS ValidateIpAddressAgainstConstraints(
            _In_reads_bytes_(addressLength) const UCHAR* address,
            SIZE_T addressLength,
            _In_ const ParsedCertificate& issuer) noexcept
        {
            for (SIZE_T index = 0; index < issuer.ExcludedIpSubtreeCount; ++index) {
                if (IpAddressMatchesSubtree(
                    address,
                    addressLength,
                    issuer.ExcludedIpSubtrees[index],
                    issuer.ExcludedIpSubtreeLengths[index])) {
                    return STATUS_TRUST_FAILURE;
                }
            }

            if (issuer.PermittedIpSubtreeCount == 0) {
                return STATUS_SUCCESS;
            }

            for (SIZE_T index = 0; index < issuer.PermittedIpSubtreeCount; ++index) {
                if (IpAddressMatchesSubtree(
                    address,
                    addressLength,
                    issuer.PermittedIpSubtrees[index],
                    issuer.PermittedIpSubtreeLengths[index])) {
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_TRUST_FAILURE;
        }

        _Must_inspect_result_
        NTSTATUS ValidateDirectoryNameAgainstConstraints(
            _In_ const ParsedCertificate& subject,
            _In_ const ParsedCertificate& issuer) noexcept
        {
            for (SIZE_T index = 0; index < issuer.ExcludedDirectoryNameCount; ++index) {
                if (DistinguishedNameEquals(
                    subject.Subject,
                    subject.SubjectLength,
                    issuer.ExcludedDirectoryNames[index],
                    issuer.ExcludedDirectoryNameLengths[index])) {
                    return STATUS_TRUST_FAILURE;
                }
            }

            if (issuer.PermittedDirectoryNameCount == 0) {
                return STATUS_SUCCESS;
            }

            for (SIZE_T index = 0; index < issuer.PermittedDirectoryNameCount; ++index) {
                if (DistinguishedNameEquals(
                    subject.Subject,
                    subject.SubjectLength,
                    issuer.PermittedDirectoryNames[index],
                    issuer.PermittedDirectoryNameLengths[index])) {
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_TRUST_FAILURE;
        }

        _Must_inspect_result_
        NTSTATUS ValidateNameConstraintsFromIssuer(
            _In_ const ParsedCertificate& subject,
            _In_ const ParsedCertificate& issuer,
            bool subjectIsLeaf) noexcept
        {
            if (!issuer.HasNameConstraints) {
                return STATUS_SUCCESS;
            }

            if (!subjectIsLeaf && IsSelfIssued(subject)) {
                return STATUS_SUCCESS;
            }

            NTSTATUS status = ValidateDirectoryNameAgainstConstraints(subject, issuer);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            for (SIZE_T index = 0; index < subject.DnsNameCount; ++index) {
                status = ValidateDnsNameAgainstConstraints(
                    subject.DnsNames[index],
                    subject.DnsNameLengths[index],
                    issuer);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (subject.DnsNameCount == 0 && subject.CommonName != nullptr && subject.CommonNameLength != 0) {
                status = ValidateDnsNameAgainstConstraints(subject.CommonName, subject.CommonNameLength, issuer);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            for (SIZE_T index = 0; index < subject.IpAddressCount; ++index) {
                status = ValidateIpAddressAgainstConstraints(
                    subject.IpAddresses[index],
                    subject.IpAddressLengths[index],
                    issuer);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateNameConstraints(
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount) noexcept
        {
            if (certificates == nullptr || certificateCount == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T issuerIndex = 1; issuerIndex < certificateCount; ++issuerIndex) {
                for (SIZE_T subjectIndex = 0; subjectIndex < issuerIndex; ++subjectIndex) {
                    const bool subjectIsLeaf = subjectIndex == 0;
                    NTSTATUS status = ValidateNameConstraintsFromIssuer(
                        certificates[subjectIndex],
                        certificates[issuerIndex],
                        subjectIsLeaf);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool CertificateHasConcretePolicy(_In_ const ParsedCertificate& certificate) noexcept
        {
            for (SIZE_T index = 0; index < certificate.CertificatePolicyOidCount; ++index) {
                if (certificate.CertificatePolicyOidLengths[index] != sizeof(OidAnyPolicy) ||
                    !MemoryEquals(certificate.CertificatePolicyOids[index], OidAnyPolicy, sizeof(OidAnyPolicy))) {
                    return true;
                }
            }

            return false;
        }

        _Must_inspect_result_
        bool CertificatePoliciesIntersect(
            _In_ const ParsedCertificate& left,
            _In_ const ParsedCertificate& right) noexcept
        {
            for (SIZE_T leftIndex = 0; leftIndex < left.CertificatePolicyOidCount; ++leftIndex) {
                if (left.CertificatePolicyOidLengths[leftIndex] == sizeof(OidAnyPolicy) &&
                    MemoryEquals(left.CertificatePolicyOids[leftIndex], OidAnyPolicy, sizeof(OidAnyPolicy))) {
                    continue;
                }

                for (SIZE_T rightIndex = 0; rightIndex < right.CertificatePolicyOidCount; ++rightIndex) {
                    if (right.CertificatePolicyOidLengths[rightIndex] == sizeof(OidAnyPolicy) &&
                        MemoryEquals(right.CertificatePolicyOids[rightIndex], OidAnyPolicy, sizeof(OidAnyPolicy))) {
                        continue;
                    }

                    if (left.CertificatePolicyOidLengths[leftIndex] == right.CertificatePolicyOidLengths[rightIndex] &&
                        MemoryEquals(
                            left.CertificatePolicyOids[leftIndex],
                            right.CertificatePolicyOids[rightIndex],
                            left.CertificatePolicyOidLengths[leftIndex])) {
                        return true;
                    }
                }
            }

            return false;
        }

        _Must_inspect_result_
        NTSTATUS ValidateCertificatePolicyTree(
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount) noexcept
        {
            if (certificates == nullptr || certificateCount == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            const ParsedCertificate& leaf = certificates[0];
            for (SIZE_T index = 1; index < certificateCount; ++index) {
                const ParsedCertificate& issuer = certificates[index];
                if (issuer.RequireExplicitPolicy &&
                    issuer.RequireExplicitPolicySkipCerts == 0 &&
                    !leaf.HasCertificatePolicies) {
                    return STATUS_TRUST_FAILURE;
                }

                if (issuer.HasInhibitAnyPolicy &&
                    issuer.InhibitAnyPolicySkipCerts == 0 &&
                    leaf.HasAnyPolicy &&
                    !CertificateHasConcretePolicy(leaf)) {
                    return STATUS_TRUST_FAILURE;
                }

                if (issuer.CertificatePoliciesCritical &&
                    issuer.HasCertificatePolicies &&
                    leaf.HasCertificatePolicies &&
                    !issuer.HasAnyPolicy &&
                    !leaf.HasAnyPolicy &&
                    !CertificatePoliciesIntersect(issuer, leaf)) {
                    return STATUS_TRUST_FAILURE;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        SIZE_T DerLengthFieldLength(SIZE_T valueLength) noexcept
        {
            if (valueLength < 0x80) {
                return 1;
            }

            SIZE_T lengthBytes = 0;
            SIZE_T remaining = valueLength;
            while (remaining != 0) {
                ++lengthBytes;
                remaining >>= 8;
            }

            return 1 + lengthBytes;
        }

        _Must_inspect_result_
        SIZE_T DerHeaderLength(SIZE_T valueLength) noexcept
        {
            return 1 + DerLengthFieldLength(valueLength);
        }

        _Must_inspect_result_
        NTSTATUS WriteDerLength(
            SIZE_T valueLength,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (destination == nullptr || offset == nullptr || *offset > capacity) {
                return STATUS_INVALID_PARAMETER;
            }

            if (valueLength < 0x80) {
                if (!HasCapacity(capacity, *offset, 1)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                destination[(*offset)++] = static_cast<UCHAR>(valueLength);
                return STATUS_SUCCESS;
            }

            UCHAR encoded[sizeof(SIZE_T)] = {};
            SIZE_T encodedLength = 0;
            SIZE_T remaining = valueLength;
            while (remaining != 0) {
                encoded[sizeof(encoded) - 1 - encodedLength] = static_cast<UCHAR>(remaining & 0xff);
                remaining >>= 8;
                ++encodedLength;
            }

            if (!HasCapacity(capacity, *offset, 1 + encodedLength)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            destination[(*offset)++] = static_cast<UCHAR>(0x80 | encodedLength);
            RtlCopyMemory(destination + *offset, encoded + sizeof(encoded) - encodedLength, encodedLength);
            *offset += encodedLength;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS WriteDerHeader(
            UCHAR tag,
            SIZE_T valueLength,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (destination == nullptr || offset == nullptr || *offset > capacity) {
                return STATUS_INVALID_PARAMETER;
            }
            if (!HasCapacity(capacity, *offset, 1)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[(*offset)++] = tag;
            return WriteDerLength(valueLength, destination, capacity, offset);
        }

        _Must_inspect_result_
        NTSTATUS WriteDerElement(
            UCHAR tag,
            _In_reads_bytes_(valueLength) const UCHAR* value,
            SIZE_T valueLength,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            NTSTATUS status = WriteDerHeader(tag, valueLength, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!HasCapacity(capacity, *offset, valueLength) ||
                (value == nullptr && valueLength != 0)) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (valueLength != 0) {
                RtlCopyMemory(destination + *offset, value, valueLength);
            }
            *offset += valueLength;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseSha1AlgorithmIdentifier(_In_ const DerElement& algorithm) noexcept
        {
            if (algorithm.Tag != TagSequence) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            DerElement oid = {};
            NTSTATUS status = ReadExpected(algorithm.Value, algorithm.ValueLength, &offset, TagOid, oid);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!OidEquals(oid, OidSha1, sizeof(OidSha1))) {
                return STATUS_NOT_SUPPORTED;
            }
            if (offset < algorithm.ValueLength) {
                DerElement parameters = {};
                status = ReadElement(algorithm.Value, algorithm.ValueLength, &offset, parameters);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (parameters.Tag != TagNull || parameters.ValueLength != 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            return offset == algorithm.ValueLength ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        NTSTATUS HashSha1(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_writes_bytes_(CertificateSha1ThumbprintLength) UCHAR* hash) noexcept
        {
            if (data == nullptr || dataLength == 0 || hash == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T hashLength = 0;
            NTSTATUS status = crypto::CngProvider::Hash(
                providerCache,
                crypto::HashAlgorithm::Sha1,
                data,
                dataLength,
                hash,
                CertificateSha1ThumbprintLength,
                &hashLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            return hashLength == CertificateSha1ThumbprintLength ?
                STATUS_SUCCESS :
                STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        NTSTATUS BuildOcspRequestDer(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer,
            _Out_writes_bytes_(requestCapacity) UCHAR* request,
            SIZE_T requestCapacity,
            _Out_ SIZE_T* requestLength,
            _Out_writes_bytes_(CertificateSha1ThumbprintLength) UCHAR* issuerNameSha1,
            _Out_writes_bytes_(CertificateSha1ThumbprintLength) UCHAR* issuerKeySha1) noexcept
        {
            static const UCHAR Sha1AlgorithmIdentifierDer[] = {
                0x30, 0x09,
                0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
                0x05, 0x00
            };

            if (requestLength != nullptr) {
                *requestLength = 0;
            }
            if (request == nullptr ||
                requestLength == nullptr ||
                issuerNameSha1 == nullptr ||
                issuerKeySha1 == nullptr ||
                certificate.SerialNumber == nullptr ||
                certificate.SerialNumberLength == 0 ||
                issuer.Subject == nullptr ||
                issuer.SubjectLength == 0 ||
                issuer.PublicKey == nullptr ||
                issuer.PublicKeyLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = HashSha1(providerCache, issuer.Subject, issuer.SubjectLength, issuerNameSha1);
            if (NT_SUCCESS(status)) {
                status = HashSha1(providerCache, issuer.PublicKey, issuer.PublicKeyLength, issuerKeySha1);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const SIZE_T serialLength = DerHeaderLength(certificate.SerialNumberLength) + certificate.SerialNumberLength;
            const SIZE_T certIdValueLength =
                sizeof(Sha1AlgorithmIdentifierDer) +
                DerHeaderLength(CertificateSha1ThumbprintLength) + CertificateSha1ThumbprintLength +
                DerHeaderLength(CertificateSha1ThumbprintLength) + CertificateSha1ThumbprintLength +
                serialLength;
            const SIZE_T certIdLength = DerHeaderLength(certIdValueLength) + certIdValueLength;
            const SIZE_T singleRequestValueLength = certIdLength;
            const SIZE_T singleRequestLength = DerHeaderLength(singleRequestValueLength) + singleRequestValueLength;
            const SIZE_T requestListValueLength = singleRequestLength;
            const SIZE_T requestListLength = DerHeaderLength(requestListValueLength) + requestListValueLength;
            const SIZE_T tbsValueLength = requestListLength;
            const SIZE_T tbsLength = DerHeaderLength(tbsValueLength) + tbsValueLength;
            const SIZE_T ocspValueLength = tbsLength;
            const SIZE_T ocspLength = DerHeaderLength(ocspValueLength) + ocspValueLength;
            if (ocspLength > requestCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T offset = 0;
            status = WriteDerHeader(TagSequence, ocspValueLength, request, requestCapacity, &offset);
            if (NT_SUCCESS(status)) {
                status = WriteDerHeader(TagSequence, tbsValueLength, request, requestCapacity, &offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteDerHeader(TagSequence, requestListValueLength, request, requestCapacity, &offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteDerHeader(TagSequence, singleRequestValueLength, request, requestCapacity, &offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteDerHeader(TagSequence, certIdValueLength, request, requestCapacity, &offset);
            }
            if (NT_SUCCESS(status) && HasCapacity(requestCapacity, offset, sizeof(Sha1AlgorithmIdentifierDer))) {
                RtlCopyMemory(request + offset, Sha1AlgorithmIdentifierDer, sizeof(Sha1AlgorithmIdentifierDer));
                offset += sizeof(Sha1AlgorithmIdentifierDer);
            }
            else if (NT_SUCCESS(status)) {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            if (NT_SUCCESS(status)) {
                status = WriteDerElement(
                    TagOctetString,
                    issuerNameSha1,
                    CertificateSha1ThumbprintLength,
                    request,
                    requestCapacity,
                    &offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteDerElement(
                    TagOctetString,
                    issuerKeySha1,
                    CertificateSha1ThumbprintLength,
                    request,
                    requestCapacity,
                    &offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteDerElement(
                    TagInteger,
                    certificate.SerialNumber,
                    certificate.SerialNumberLength,
                    request,
                    requestCapacity,
                    &offset);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *requestLength = offset;
            return offset == ocspLength ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        NTSTATUS VerifySignedData(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            CertificateSignatureAlgorithm algorithm,
            _In_reads_bytes_(tbsLength) const UCHAR* tbs,
            SIZE_T tbsLength,
            _In_ const DerElement& signature,
            _In_ const ParsedCertificate& signer) noexcept
        {
            if (signature.Tag != TagBitString ||
                signature.Value == nullptr ||
                signature.ValueLength < 2 ||
                signature.Value[0] != 0 ||
                tbs == nullptr ||
                tbsLength == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            ParsedCertificate signedData = {};
            signedData.SignatureAlgorithm = algorithm;
            signedData.TbsCertificate = tbs;
            signedData.TbsCertificateLength = tbsLength;
            signedData.Signature = signature.Value + 1;
            signedData.SignatureLength = signature.ValueLength - 1;
            return VerifyCertificateSignature(providerCache, signedData, signer);
        }

        _Must_inspect_result_
        bool DistinguishedNamesMatch(_In_ const DerElement& encodedName, _In_ const ParsedCertificate& certificate) noexcept
        {
            return encodedName.Tag == TagSequence &&
                certificate.Subject != nullptr &&
                encodedName.FullLength == certificate.SubjectLength &&
                MemoryEquals(encodedName.Full, certificate.Subject, encodedName.FullLength);
        }

        _Must_inspect_result_
        bool ResponderIdMatchesCertificate(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const DerElement& responderId,
            _In_ const ParsedCertificate& certificate) noexcept
        {
            if (responderId.Tag == 0xa1) {
                SIZE_T offset = 0;
                DerElement name = {};
                if (!NT_SUCCESS(ReadExpected(responderId.Value, responderId.ValueLength, &offset, TagSequence, name)) ||
                    offset != responderId.ValueLength) {
                    return false;
                }

                return DistinguishedNamesMatch(name, certificate);
            }

            if (responderId.Tag == 0x82) {
                if (responderId.Value == nullptr ||
                    responderId.ValueLength != CertificateSha1ThumbprintLength ||
                    certificate.PublicKey == nullptr ||
                    certificate.PublicKeyLength == 0) {
                    return false;
                }

                UCHAR keyHash[CertificateSha1ThumbprintLength] = {};
                if (!NT_SUCCESS(HashSha1(providerCache, certificate.PublicKey, certificate.PublicKeyLength, keyHash))) {
                    RtlSecureZeroMemory(keyHash, sizeof(keyHash));
                    return false;
                }

                const bool matches = MemoryEquals(keyHash, responderId.Value, CertificateSha1ThumbprintLength);
                RtlSecureZeroMemory(keyHash, sizeof(keyHash));
                return matches;
            }

            return false;
        }

        _Must_inspect_result_
        NTSTATUS VerifyOcspResponderSignature(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const DerElement& responderId,
            _In_ const DerElement& tbsResponseData,
            CertificateSignatureAlgorithm signatureAlgorithm,
            _In_ const DerElement& signature,
            _In_opt_ const DerElement* responderCertificates,
            _In_ const ParsedCertificate& issuer,
            long long now) noexcept
        {
            if (ResponderIdMatchesCertificate(providerCache, responderId, issuer)) {
                return VerifySignedData(
                    providerCache,
                    signatureAlgorithm,
                    tbsResponseData.Full,
                    tbsResponseData.FullLength,
                    signature,
                    issuer);
            }

            if (responderCertificates == nullptr || responderCertificates->Tag != 0xa0) {
                return STATUS_TRUST_FAILURE;
            }

            SIZE_T explicitOffset = 0;
            DerElement certSequence = {};
            NTSTATUS status = ReadExpected(
                responderCertificates->Value,
                responderCertificates->ValueLength,
                &explicitOffset,
                TagSequence,
                certSequence);
            if (!NT_SUCCESS(status) || explicitOffset != responderCertificates->ValueLength) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            SIZE_T offset = 0;
            while (offset < certSequence.ValueLength) {
                DerElement certDer = {};
                status = ReadExpected(certSequence.Value, certSequence.ValueLength, &offset, TagSequence, certDer);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                ParsedCertificate responder = {};
                status = CertificateValidator::ParseCertificate(certDer.Full, certDer.FullLength, responder);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (!ResponderIdMatchesCertificate(providerCache, responderId, responder)) {
                    continue;
                }
                if (now < responder.NotBefore ||
                    now > responder.NotAfter ||
                    responder.IssuerLength != issuer.SubjectLength ||
                    !MemoryEquals(responder.Issuer, issuer.Subject, responder.IssuerLength) ||
                    !responder.HasExtendedKeyUsage ||
                    !responder.AllowsOcspSigning ||
                    (responder.HasKeyUsage && !responder.AllowsDigitalSignature)) {
                    return STATUS_TRUST_FAILURE;
                }

                status = VerifyCertificateSignature(providerCache, responder, issuer);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return VerifySignedData(
                    providerCache,
                    signatureAlgorithm,
                    tbsResponseData.Full,
                    tbsResponseData.FullLength,
                    signature,
                    responder);
            }

            return STATUS_TRUST_FAILURE;
        }

        _Must_inspect_result_
        NTSTATUS ParseOcspCertIdMatches(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const DerElement& certId,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer,
            _Out_ bool* matches) noexcept
        {
            if (matches != nullptr) {
                *matches = false;
            }
            if (matches == nullptr || certId.Tag != TagSequence) {
                return STATUS_INVALID_PARAMETER;
            }

            UCHAR issuerNameSha1[CertificateSha1ThumbprintLength] = {};
            UCHAR issuerKeySha1[CertificateSha1ThumbprintLength] = {};
            NTSTATUS status = HashSha1(providerCache, issuer.Subject, issuer.SubjectLength, issuerNameSha1);
            if (NT_SUCCESS(status)) {
                status = HashSha1(providerCache, issuer.PublicKey, issuer.PublicKeyLength, issuerKeySha1);
            }
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(issuerNameSha1, sizeof(issuerNameSha1));
                RtlSecureZeroMemory(issuerKeySha1, sizeof(issuerKeySha1));
                return status;
            }

            SIZE_T offset = 0;
            DerElement hashAlgorithm = {};
            DerElement issuerNameHash = {};
            DerElement issuerKeyHash = {};
            DerElement serial = {};
            status = ReadExpected(certId.Value, certId.ValueLength, &offset, TagSequence, hashAlgorithm);
            if (NT_SUCCESS(status)) {
                status = ParseSha1AlgorithmIdentifier(hashAlgorithm);
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(certId.Value, certId.ValueLength, &offset, TagOctetString, issuerNameHash);
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(certId.Value, certId.ValueLength, &offset, TagOctetString, issuerKeyHash);
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(certId.Value, certId.ValueLength, &offset, TagInteger, serial);
            }
            if (NT_SUCCESS(status) && offset != certId.ValueLength) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (NT_SUCCESS(status)) {
                *matches =
                    issuerNameHash.ValueLength == CertificateSha1ThumbprintLength &&
                    issuerKeyHash.ValueLength == CertificateSha1ThumbprintLength &&
                    MemoryEquals(issuerNameHash.Value, issuerNameSha1, CertificateSha1ThumbprintLength) &&
                    MemoryEquals(issuerKeyHash.Value, issuerKeySha1, CertificateSha1ThumbprintLength) &&
                    serial.ValueLength == certificate.SerialNumberLength &&
                    MemoryEquals(serial.Value, certificate.SerialNumber, certificate.SerialNumberLength);
            }

            RtlSecureZeroMemory(issuerNameSha1, sizeof(issuerNameSha1));
            RtlSecureZeroMemory(issuerKeySha1, sizeof(issuerKeySha1));
            return status;
        }

        _Must_inspect_result_
        NTSTATUS ParseOcspSingleResponse(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const DerElement& singleResponse,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer,
            _Out_ bool* matches,
            _Out_ CertificateRevocationStatus* revocationStatus,
            _Out_ long long* thisUpdate,
            _Out_ long long* nextUpdate) noexcept
        {
            if (matches != nullptr) {
                *matches = false;
            }
            if (revocationStatus != nullptr) {
                *revocationStatus = CertificateRevocationStatus::Unknown;
            }
            if (thisUpdate != nullptr) {
                *thisUpdate = 0;
            }
            if (nextUpdate != nullptr) {
                *nextUpdate = 0;
            }
            if (matches == nullptr ||
                revocationStatus == nullptr ||
                thisUpdate == nullptr ||
                nextUpdate == nullptr ||
                singleResponse.Tag != TagSequence) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T offset = 0;
            DerElement certId = {};
            DerElement statusElement = {};
            DerElement parsedThisUpdate = {};
            NTSTATUS status = ReadExpected(singleResponse.Value, singleResponse.ValueLength, &offset, TagSequence, certId);
            if (NT_SUCCESS(status)) {
                status = ParseOcspCertIdMatches(providerCache, certId, certificate, issuer, matches);
            }
            if (!NT_SUCCESS(status) || !*matches) {
                return status;
            }
            status = ReadElement(singleResponse.Value, singleResponse.ValueLength, &offset, statusElement);
            if (NT_SUCCESS(status)) {
                status = ReadElement(singleResponse.Value, singleResponse.ValueLength, &offset, parsedThisUpdate);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (statusElement.Tag == 0x80 && statusElement.ValueLength == 0) {
                *revocationStatus = CertificateRevocationStatus::Good;
            }
            else if (statusElement.Tag == 0xa1) {
                *revocationStatus = CertificateRevocationStatus::Revoked;
            }
            else if (statusElement.Tag == 0x82 && statusElement.ValueLength == 0) {
                *revocationStatus = CertificateRevocationStatus::Unknown;
            }
            else {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = ParseDerTime(parsedThisUpdate, thisUpdate);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *nextUpdate = 0;
            while (offset < singleResponse.ValueLength) {
                DerElement optional = {};
                status = ReadElement(singleResponse.Value, singleResponse.ValueLength, &offset, optional);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (optional.Tag == 0xa0) {
                    SIZE_T timeOffset = 0;
                    DerElement parsedNextUpdate = {};
                    status = ReadElement(optional.Value, optional.ValueLength, &timeOffset, parsedNextUpdate);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (timeOffset != optional.ValueLength) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = ParseDerTime(parsedNextUpdate, nextUpdate);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                else if (optional.Tag == 0xa1) {
                    continue;
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateOcspEvidence(
            _In_ const CertificateRevocationEntry& entry,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer,
            _In_opt_ const crypto::CngProviderCache* providerCache,
            long long now) noexcept
        {
            if (entry.EvidenceDer == nullptr || entry.EvidenceDerLength == 0) {
                return STATUS_TRUST_FAILURE;
            }

            SIZE_T offset = 0;
            DerElement ocspResponse = {};
            NTSTATUS status = ReadExpected(entry.EvidenceDer, entry.EvidenceDerLength, &offset, TagSequence, ocspResponse);
            if (!NT_SUCCESS(status) || offset != entry.EvidenceDerLength) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            SIZE_T responseOffset = 0;
            DerElement responseStatus = {};
            status = ReadExpected(ocspResponse.Value, ocspResponse.ValueLength, &responseOffset, TagEnumerated, responseStatus);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (responseStatus.ValueLength != 1 || responseStatus.Value[0] != 0) {
                return STATUS_TRUST_FAILURE;
            }

            DerElement responseBytes = {};
            status = ReadExpected(ocspResponse.Value, ocspResponse.ValueLength, &responseOffset, 0xa0, responseBytes);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (responseOffset != ocspResponse.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T bytesOffset = 0;
            DerElement responseBytesSequence = {};
            status = ReadExpected(responseBytes.Value, responseBytes.ValueLength, &bytesOffset, TagSequence, responseBytesSequence);
            if (!NT_SUCCESS(status) || bytesOffset != responseBytes.ValueLength) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            SIZE_T itemOffset = 0;
            DerElement responseType = {};
            DerElement responseOctets = {};
            status = ReadExpected(responseBytesSequence.Value, responseBytesSequence.ValueLength, &itemOffset, TagOid, responseType);
            if (NT_SUCCESS(status)) {
                status = ReadExpected(responseBytesSequence.Value, responseBytesSequence.ValueLength, &itemOffset, TagOctetString, responseOctets);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (itemOffset != responseBytesSequence.ValueLength ||
                !OidEquals(responseType, OidBasicOcspResponse, sizeof(OidBasicOcspResponse))) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T basicOffset = 0;
            DerElement basicResponse = {};
            status = ReadExpected(responseOctets.Value, responseOctets.ValueLength, &basicOffset, TagSequence, basicResponse);
            if (!NT_SUCCESS(status) || basicOffset != responseOctets.ValueLength) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            SIZE_T basicItemOffset = 0;
            DerElement tbsResponseData = {};
            DerElement signatureAlgorithm = {};
            DerElement signature = {};
            status = ReadExpected(basicResponse.Value, basicResponse.ValueLength, &basicItemOffset, TagSequence, tbsResponseData);
            if (NT_SUCCESS(status)) {
                status = ReadExpected(basicResponse.Value, basicResponse.ValueLength, &basicItemOffset, TagSequence, signatureAlgorithm);
            }
            CertificateSignatureAlgorithm parsedSignatureAlgorithm = CertificateSignatureAlgorithm::Unknown;
            if (NT_SUCCESS(status)) {
                status = ParseAlgorithmIdentifier(signatureAlgorithm, &parsedSignatureAlgorithm, nullptr);
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(basicResponse.Value, basicResponse.ValueLength, &basicItemOffset, TagBitString, signature);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            DerElement responderCertificates = {};
            DerElement* responderCertificatesPtr = nullptr;
            if (basicItemOffset < basicResponse.ValueLength) {
                status = ReadElement(basicResponse.Value, basicResponse.ValueLength, &basicItemOffset, responderCertificates);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (responderCertificates.Tag != 0xa0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                responderCertificatesPtr = &responderCertificates;
            }
            if (basicItemOffset != basicResponse.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T responseDataOffset = 0;
            if (tbsResponseData.ValueLength != 0 && tbsResponseData.Value[0] == 0xa0) {
                DerElement version = {};
                status = ReadExpected(tbsResponseData.Value, tbsResponseData.ValueLength, &responseDataOffset, 0xa0, version);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            DerElement responderId = {};
            DerElement producedAt = {};
            DerElement responses = {};
            status = ReadElement(tbsResponseData.Value, tbsResponseData.ValueLength, &responseDataOffset, responderId);
            if (NT_SUCCESS(status)) {
                status = ReadElement(tbsResponseData.Value, tbsResponseData.ValueLength, &responseDataOffset, producedAt);
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(tbsResponseData.Value, tbsResponseData.ValueLength, &responseDataOffset, TagSequence, responses);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            long long producedAtPacked = 0;
            status = ParseDerTime(producedAt, &producedAtPacked);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (producedAtPacked > now) {
                return STATUS_TRUST_FAILURE;
            }

            while (responseDataOffset < tbsResponseData.ValueLength) {
                DerElement optional = {};
                status = ReadElement(tbsResponseData.Value, tbsResponseData.ValueLength, &responseDataOffset, optional);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (optional.Tag != 0xa1) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            status = VerifyOcspResponderSignature(
                providerCache,
                responderId,
                tbsResponseData,
                parsedSignatureAlgorithm,
                signature,
                responderCertificatesPtr,
                issuer,
                now);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T singleOffset = 0;
            bool matched = false;
            CertificateRevocationStatus revocationStatus = CertificateRevocationStatus::Unknown;
            long long thisUpdate = 0;
            long long nextUpdate = 0;
            while (singleOffset < responses.ValueLength) {
                DerElement singleResponse = {};
                status = ReadExpected(responses.Value, responses.ValueLength, &singleOffset, TagSequence, singleResponse);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                bool singleMatches = false;
                status = ParseOcspSingleResponse(
                    providerCache,
                    singleResponse,
                    certificate,
                    issuer,
                    &singleMatches,
                    &revocationStatus,
                    &thisUpdate,
                    &nextUpdate);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (singleMatches) {
                    matched = true;
                    break;
                }
            }

            if (!matched ||
                revocationStatus != CertificateRevocationStatus::Good ||
                nextUpdate == 0 ||
                now < thisUpdate ||
                now > nextUpdate) {
                return STATUS_TRUST_FAILURE;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateCrlEvidence(
            _In_ const CertificateRevocationEntry& entry,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer,
            _In_opt_ const crypto::CngProviderCache* providerCache,
            long long now) noexcept
        {
            if (entry.EvidenceDer == nullptr || entry.EvidenceDerLength == 0) {
                return STATUS_TRUST_FAILURE;
            }
            if (!issuer.HasKeyUsage || !issuer.AllowsCrlSign) {
                return STATUS_TRUST_FAILURE;
            }

            SIZE_T offset = 0;
            DerElement crl = {};
            NTSTATUS status = ReadExpected(entry.EvidenceDer, entry.EvidenceDerLength, &offset, TagSequence, crl);
            if (!NT_SUCCESS(status) || offset != entry.EvidenceDerLength) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            SIZE_T crlOffset = 0;
            DerElement tbs = {};
            DerElement signatureAlgorithm = {};
            DerElement signature = {};
            status = ReadExpected(crl.Value, crl.ValueLength, &crlOffset, TagSequence, tbs);
            if (NT_SUCCESS(status)) {
                status = ReadExpected(crl.Value, crl.ValueLength, &crlOffset, TagSequence, signatureAlgorithm);
            }
            CertificateSignatureAlgorithm parsedSignatureAlgorithm = CertificateSignatureAlgorithm::Unknown;
            if (NT_SUCCESS(status)) {
                status = ParseAlgorithmIdentifier(signatureAlgorithm, &parsedSignatureAlgorithm, nullptr);
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(crl.Value, crl.ValueLength, &crlOffset, TagBitString, signature);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (crlOffset != crl.ValueLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T tbsOffset = 0;
            if (tbs.ValueLength != 0 && tbs.Value[0] == TagInteger) {
                DerElement version = {};
                status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagInteger, version);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            DerElement innerSignatureAlgorithm = {};
            DerElement issuerName = {};
            DerElement thisUpdateElement = {};
            DerElement nextUpdateElement = {};
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, innerSignatureAlgorithm);
            CertificateSignatureAlgorithm innerSignature = CertificateSignatureAlgorithm::Unknown;
            if (NT_SUCCESS(status)) {
                status = ParseAlgorithmIdentifier(innerSignatureAlgorithm, &innerSignature, nullptr);
            }
            if (NT_SUCCESS(status) && innerSignature != parsedSignatureAlgorithm) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (NT_SUCCESS(status)) {
                status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, issuerName);
            }
            if (NT_SUCCESS(status)) {
                status = ReadElement(tbs.Value, tbs.ValueLength, &tbsOffset, thisUpdateElement);
            }
            if (NT_SUCCESS(status)) {
                status = ReadElement(tbs.Value, tbs.ValueLength, &tbsOffset, nextUpdateElement);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (!DistinguishedNamesMatch(issuerName, issuer)) {
                return STATUS_TRUST_FAILURE;
            }

            long long thisUpdate = 0;
            long long nextUpdate = 0;
            status = ParseDerTime(thisUpdateElement, &thisUpdate);
            if (NT_SUCCESS(status)) {
                status = ParseDerTime(nextUpdateElement, &nextUpdate);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (now < thisUpdate || now > nextUpdate) {
                return STATUS_TRUST_FAILURE;
            }

            status = VerifySignedData(
                providerCache,
                parsedSignatureAlgorithm,
                tbs.Full,
                tbs.FullLength,
                signature,
                issuer);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (tbsOffset < tbs.ValueLength && tbs.Value[tbsOffset] == TagSequence) {
                DerElement revokedCertificates = {};
                status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, revokedCertificates);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T revokedOffset = 0;
                while (revokedOffset < revokedCertificates.ValueLength) {
                    DerElement revoked = {};
                    status = ReadExpected(
                        revokedCertificates.Value,
                        revokedCertificates.ValueLength,
                        &revokedOffset,
                        TagSequence,
                        revoked);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    SIZE_T itemOffset = 0;
                    DerElement serial = {};
                    status = ReadExpected(revoked.Value, revoked.ValueLength, &itemOffset, TagInteger, serial);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (serial.ValueLength == certificate.SerialNumberLength &&
                        MemoryEquals(serial.Value, certificate.SerialNumber, certificate.SerialNumberLength)) {
                        return STATUS_TRUST_FAILURE;
                    }
                }
            }

            while (tbsOffset < tbs.ValueLength) {
                DerElement optional = {};
                status = ReadElement(tbs.Value, tbs.ValueLength, &tbsOffset, optional);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (optional.Tag != 0xa0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateRevocationEntryEvidence(
            _In_ const CertificateRevocationEntry& entry,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer,
            _In_opt_ const crypto::CngProviderCache* providerCache,
            long long now) noexcept
        {
            if (entry.IssuerNameLength != certificate.IssuerLength ||
                entry.SerialNumberLength != certificate.SerialNumberLength ||
                !MemoryEquals(entry.IssuerName, certificate.Issuer, certificate.IssuerLength) ||
                !MemoryEquals(entry.SerialNumber, certificate.SerialNumber, certificate.SerialNumberLength) ||
                entry.EvidenceDer == nullptr ||
                entry.EvidenceDerLength == 0) {
                return STATUS_TRUST_FAILURE;
            }

            return entry.Source == CertificateRevocationSource::Ocsp ?
                ValidateOcspEvidence(entry, certificate, issuer, providerCache, now) :
                ValidateCrlEvidence(entry, certificate, issuer, providerCache, now);
        }

        NTSTATUS QueryAndValidateRevocationProvider(
            _In_ const CertificateStore& store,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& issuer,
            _In_opt_ const crypto::CngProviderCache* providerCache,
            CertificateRevocationSource source,
            long long now,
            _Out_ bool* found) noexcept
        {
            if (found != nullptr) {
                *found = false;
            }
            if (found == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            CertificateRevocationProviderQuery query = {};
            query.CertificateDer = certificate.Der;
            query.CertificateDerLength = certificate.DerLength;
            query.IssuerCertificateDer = issuer.Der;
            query.IssuerCertificateDerLength = issuer.DerLength;
            query.IssuerName = certificate.Issuer;
            query.IssuerNameLength = certificate.IssuerLength;
            query.SerialNumber = certificate.SerialNumber;
            query.SerialNumberLength = certificate.SerialNumberLength;
            query.IssuerSubjectPublicKeyInfo = issuer.SubjectPublicKeyInfo;
            query.IssuerSubjectPublicKeyInfoLength = issuer.SubjectPublicKeyInfoLength;
            query.PreferredSource = source;

            query.OcspUriCount = certificate.OcspUriCount;
            for (SIZE_T index = 0; index < certificate.OcspUriCount; ++index) {
                query.OcspUris[index] = certificate.OcspUris[index];
                query.OcspUriLengths[index] = certificate.OcspUriLengths[index];
            }
            query.CrlDistributionPointUriCount = certificate.CrlDistributionPointUriCount;
            for (SIZE_T index = 0; index < certificate.CrlDistributionPointUriCount; ++index) {
                query.CrlDistributionPointUris[index] = certificate.CrlDistributionPointUris[index];
                query.CrlDistributionPointUriLengths[index] = certificate.CrlDistributionPointUriLengths[index];
            }

            HeapArray<UCHAR> ocspRequest;
            if (source == CertificateRevocationSource::Ocsp) {
                NTSTATUS allocateStatus = ocspRequest.Allocate(CertificateMaxAuthorityDerLength);
                if (!NT_SUCCESS(allocateStatus)) {
                    return allocateStatus;
                }

                SIZE_T ocspRequestLength = 0;
                NTSTATUS buildStatus = BuildOcspRequestDer(
                    providerCache,
                    certificate,
                    issuer,
                    ocspRequest.Get(),
                    ocspRequest.Count(),
                    &ocspRequestLength,
                    query.OcspIssuerNameSha1,
                    query.OcspIssuerKeySha1);
                if (!NT_SUCCESS(buildStatus)) {
                    RtlSecureZeroMemory(ocspRequest.Get(), ocspRequest.Count());
                    return buildStatus;
                }
                query.OcspRequestDer = ocspRequest.Get();
                query.OcspRequestDerLength = ocspRequestLength;
            }

            CertificateRevocationEntry providerEntry = {};
            NTSTATUS status = store.QueryRevocationProvider(query, &providerEntry);
            if (ocspRequest.IsValid()) {
                RtlSecureZeroMemory(ocspRequest.Get(), ocspRequest.Count());
            }
            if (status == STATUS_NOT_FOUND) {
                return STATUS_SUCCESS;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            *found = true;
            return ValidateRevocationEntryEvidence(providerEntry, certificate, issuer, providerCache, now);
        }

        _Must_inspect_result_
        const ParsedCertificate* SelectRevocationIssuer(
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount,
            SIZE_T certificateIndex,
            SIZE_T trustedAnchorIndex,
            _In_opt_ const ParsedCertificate* trustedAnchor) noexcept
        {
            if (certificates == nullptr || certificateIndex >= certificateCount) {
                return nullptr;
            }

            if (certificateIndex + 1 < certificateCount) {
                return &certificates[certificateIndex + 1];
            }

            const ParsedCertificate& certificate = certificates[certificateIndex];
            if (trustedAnchor != nullptr &&
                trustedAnchorIndex == certificateIndex &&
                trustedAnchor->Subject != nullptr &&
                trustedAnchor->SubjectLength != 0 &&
                certificate.IssuerLength == trustedAnchor->SubjectLength &&
                MemoryEquals(certificate.Issuer, trustedAnchor->Subject, certificate.IssuerLength)) {
                return trustedAnchor;
            }

            if (certificate.IssuerLength == certificate.SubjectLength &&
                MemoryEquals(certificate.Issuer, certificate.Subject, certificate.IssuerLength)) {
                return &certificate;
            }

            return nullptr;
        }

        _Must_inspect_result_
        NTSTATUS ValidateCertificateRevocation(
            _In_reads_(certificateCount) const ParsedCertificate* certificates,
            SIZE_T certificateCount,
            _In_ const CertificateValidationOptions& options,
            SIZE_T trustedAnchorIndex,
            _In_opt_ const ParsedCertificate* trustedAnchor,
            long long now) noexcept
        {
            CertificateRevocationMode mode = options.RevocationMode;
            if (mode == CertificateRevocationMode::Off && options.RequireRevocationCheck) {
                mode = CertificateRevocationMode::OnlineRequired;
            }
            if (mode == CertificateRevocationMode::Off) {
                return STATUS_SUCCESS;
            }
            if (options.Store == nullptr || certificates == nullptr || certificateCount == 0) {
                return STATUS_TRUST_FAILURE;
            }

            const SIZE_T lastChecked =
                trustedAnchorIndex < certificateCount ? trustedAnchorIndex : certificateCount - 1;
            for (SIZE_T index = 0; index <= lastChecked; ++index) {
                const ParsedCertificate& certificate = certificates[index];
                const ParsedCertificate* issuer = SelectRevocationIssuer(
                    certificates,
                    certificateCount,
                    index,
                    trustedAnchorIndex,
                    trustedAnchor);
                if (issuer == nullptr) {
                    return STATUS_TRUST_FAILURE;
                }

                if (index == 0 && options.StapledOcspResponse != nullptr && options.StapledOcspResponseLength != 0) {
                    CertificateRevocationEntry stapled = {};
                    stapled.IssuerName = certificate.Issuer;
                    stapled.IssuerNameLength = certificate.IssuerLength;
                    stapled.SerialNumber = certificate.SerialNumber;
                    stapled.SerialNumberLength = certificate.SerialNumberLength;
                    stapled.Source = CertificateRevocationSource::Ocsp;
                    stapled.EvidenceDer = options.StapledOcspResponse;
                    stapled.EvidenceDerLength = options.StapledOcspResponseLength;
                    NTSTATUS stapledStatus = ValidateRevocationEntryEvidence(
                        stapled,
                        certificate,
                        *issuer,
                        options.ProviderCache,
                        now);
                    if (!NT_SUCCESS(stapledStatus)) {
                        return stapledStatus;
                    }
                    continue;
                }

                const CertificateRevocationEntry* entry = options.Store->FindRevocationEntry(
                    certificate.Issuer,
                    certificate.IssuerLength,
                    certificate.SerialNumber,
                    certificate.SerialNumberLength,
                    CertificateRevocationSource::Ocsp);

                if (entry != nullptr) {
                    NTSTATUS status = ValidateRevocationEntryEvidence(
                        *entry,
                        certificate,
                        *issuer,
                        options.ProviderCache,
                        now);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    continue;
                }

                bool providerFound = false;
                NTSTATUS providerStatus = QueryAndValidateRevocationProvider(
                    *options.Store,
                    certificate,
                    *issuer,
                    options.ProviderCache,
                    CertificateRevocationSource::Ocsp,
                    now,
                    &providerFound);
                if (!NT_SUCCESS(providerStatus)) {
                    return providerStatus;
                }
                if (providerFound) {
                    continue;
                }

                if (mode == CertificateRevocationMode::OnlineRequired) {
                    entry = options.Store->FindRevocationEntry(
                        certificate.Issuer,
                        certificate.IssuerLength,
                        certificate.SerialNumber,
                        certificate.SerialNumberLength,
                        CertificateRevocationSource::Crl);
                    if (entry != nullptr) {
                        NTSTATUS status = ValidateRevocationEntryEvidence(
                            *entry,
                            certificate,
                            *issuer,
                            options.ProviderCache,
                            now);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        continue;
                    }

                    providerStatus = QueryAndValidateRevocationProvider(
                        *options.Store,
                        certificate,
                        *issuer,
                        options.ProviderCache,
                        CertificateRevocationSource::Crl,
                        now,
                        &providerFound);
                    if (!NT_SUCCESS(providerStatus)) {
                        return providerStatus;
                    }
                    if (providerFound) {
                        continue;
                    }
                }

                return STATUS_TRUST_FAILURE;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AnchorSignsCertificate(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _In_ const ParsedCertificate& anchor,
            SIZE_T subordinateCaCount,
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
                !anchor.HasKeyUsage ||
                !anchor.AllowsKeyCertSign ||
                (anchor.HasPathLenConstraint && subordinateCaCount > anchor.PathLenConstraint) ||
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
        bool IsSkippableAuthorityCertificateStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_INVALID_NETWORK_RESPONSE ||
                status == STATUS_NOT_SUPPORTED ||
                status == STATUS_BUFFER_TOO_SMALL;
        }

        _Must_inspect_result_
        NTSTATUS ParsedCertificateMatchesAuthorityBundle(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_ const ParsedCertificate& certificate,
            _In_ const CertificateAuthorityBundle& bundle,
            SIZE_T subordinateCaCount,
            _Inout_ ParsedCertificate* anchor,
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
                anchor == nullptr ||
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
                *anchor = {};
                NTSTATUS status = CertificateValidator::ParseCertificate(
                    bundle.Data,
                    bundle.DataLength,
                    *anchor);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return AnchorSignsCertificate(providerCache, certificate, *anchor, subordinateCaCount, trusted);
            }

            SIZE_T offset = firstPem;
            SIZE_T certificateIndex = 0;
            while (offset < bundle.DataLength) {
                SIZE_T derLength = 0;
                SIZE_T certificateOffset = offset;
                SIZE_T nextOffset = offset;
                NTSTATUS status = DecodePemCertificate(
                    bundle.Data,
                    bundle.DataLength,
                    offset,
                    scratch,
                    scratchCapacity,
                    &derLength,
                    &certificateOffset,
                    &nextOffset);
                if (status == STATUS_NOT_FOUND) {
                    return STATUS_SUCCESS;
                }
                if (!NT_SUCCESS(status)) {
                    if (nextOffset > offset &&
                        IsSkippableAuthorityCertificateStatus(status)) {
                        WKNET_DBG_PRINT(
                            "CertificateValidator: Authority certificate skipped: index=%Iu offset=%Iu status=0x%08X\r\n",
                            certificateIndex,
                            certificateOffset,
                            static_cast<ULONG>(status));
                        offset = nextOffset;
                        ++certificateIndex;
                        continue;
                    }

                    return status;
                }

                *anchor = {};
                status = CertificateValidator::ParseCertificate(scratch, derLength, *anchor);
                if (!NT_SUCCESS(status)) {
                    if (IsSkippableAuthorityCertificateStatus(status)) {
                        WKNET_DBG_PRINT(
                            "CertificateValidator: Authority certificate skipped: index=%Iu offset=%Iu status=0x%08X\r\n",
                            certificateIndex,
                            certificateOffset,
                            static_cast<ULONG>(status));
                        offset = nextOffset;
                        ++certificateIndex;
                        continue;
                    }

                    return status;
                }

                status = AnchorSignsCertificate(providerCache, certificate, *anchor, subordinateCaCount, trusted);
                if (!NT_SUCCESS(status) || *trusted) {
                    return status;
                }

                offset = nextOffset;
                ++certificateIndex;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS StoreHasTrustedAnchor(
            _In_opt_ const crypto::CngProviderCache* providerCache,
            _In_opt_ const CertificateStore* store,
            _In_ const ParsedCertificate& certificate,
            _In_reads_bytes_(CertificateSha256ThumbprintLength) const UCHAR* certificateSpkiSha256,
            SIZE_T subordinateCaCount,
            _Inout_ ParsedCertificate* anchor,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ bool* trusted) noexcept
        {
            if (trusted != nullptr) {
                *trusted = false;
            }

            if (certificateSpkiSha256 == nullptr || anchor == nullptr || scratch == nullptr || trusted == nullptr) {
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
                        subordinateCaCount,
                        anchor,
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
            _Inout_ ParsedCertificate* anchor,
            _Out_writes_bytes_(scratchCapacity) UCHAR* scratch,
            SIZE_T scratchCapacity,
            _Out_ SIZE_T* trustedAnchorIndex) noexcept
        {
            if (trustedAnchorIndex != nullptr) {
                *trustedAnchorIndex = certificateCount;
            }

            if (certificates == nullptr ||
                certificateCount == 0 ||
                anchor == nullptr ||
                scratch == nullptr ||
                scratchCapacity < CertificateMaxAuthorityDerLength ||
                trustedAnchorIndex == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = STATUS_SUCCESS;
            for (SIZE_T index = 0; index < certificateCount; ++index) {
                HeapArray<UCHAR> certSpkiSha256(CertificateSha256ThumbprintLength);
                if (!certSpkiSha256.IsValid()) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                status = HashSubjectPublicKey(providerCache, certificates[index], certSpkiSha256.Get());
                if (!NT_SUCCESS(status)) {
                    WKNET_DBG_PRINT("CertificateValidator: Cert %Iu SPKI hash failed: 0x%08X\r\n", index, static_cast<ULONG>(status));
                    break;
                }

                WKNET_DBG_PRINT("CertificateValidator: Cert %Iu SPKI SHA256: %02X%02X%02X%02X...\r\n",
                    index, certSpkiSha256[0], certSpkiSha256[1], certSpkiSha256[2], certSpkiSha256[3]);

                bool trusted = false;
                const SIZE_T subordinateCaCount = CountSubordinateCaCertificates(
                    certificates,
                    certificateCount,
                    index + 1);
                status = StoreHasTrustedAnchor(
                    providerCache,
                    store,
                    certificates[index],
                    certSpkiSha256.Get(),
                    subordinateCaCount,
                    anchor,
                    scratch,
                    scratchCapacity,
                    &trusted);
                if (!NT_SUCCESS(status)) {
                    break;
                }

                if (trusted) {
                    WKNET_DBG_PRINT("CertificateValidator: Found trusted anchor at index %Iu\r\n", index);
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
            certificate.SerialNumber = serial.Value;
            certificate.SerialNumberLength = serial.ValueLength;
        }
        if (NT_SUCCESS(status)) {
            status = ReadExpected(tbs.Value, tbs.ValueLength, &tbsOffset, TagSequence, innerSignature);
        }
        if (NT_SUCCESS(status)) {
            CertificateSignatureAlgorithm innerSignatureAlgorithm = CertificateSignatureAlgorithm::Unknown;
            status = ParseAlgorithmIdentifier(innerSignature, &innerSignatureAlgorithm, nullptr);
            if (NT_SUCCESS(status) && innerSignatureAlgorithm != certificate.SignatureAlgorithm) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
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

    _Must_inspect_result_
    static NTSTATUS ValidateChainImpl(
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
                status = CertificateValidator::ParseCertificate(der, derLength, parsed[index]);
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

        SIZE_T pathCount = certificatesToParse;
        const char* validationHost = options.HostName;
        SIZE_T validationHostLength = options.HostNameLength;
        HeapArray<char> normalizedHost;
        if (options.VerifyCertificate) {
            HeapArray<UCHAR> hostAddress(16);
            if (!hostAddress.IsValid()) {
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T hostAddressLength = 0;
            if (!ParseIpLiteral(options.HostName, options.HostNameLength, hostAddress.Get(), &hostAddressLength)) {
                status = normalizedHost.Allocate(CertificateMaxNormalizedDnsNameLength + 1);
                if (!NT_SUCCESS(status)) {
                    ReleaseCertificateValidationScratch(scratch);
                    return status;
                }

                status = NormalizeDnsName(
                    options.HostName,
                    options.HostNameLength,
                    options.EnableIdna,
                    normalizedHost.Get(),
                    normalizedHost.Count(),
                    &validationHostLength);
                if (!NT_SUCCESS(status)) {
                    ReleaseCertificateValidationScratch(scratch);
                    return status;
                }

                validationHost = normalizedHost.Get();
            }

            status = BuildCertificatePath(
                parsed,
                chain.CertificateCount,
                validationHost,
                validationHostLength,
                options.ProviderCache,
                options.Store,
                scratch.Anchor,
                scratch.Authority,
                scratch.AuthorityLength,
                &pathCount);
            if (!NT_SUCCESS(status)) {
                ReleaseCertificateValidationScratch(scratch);
                return status;
            }
        }

        HeapArray<UCHAR> spkiSha256(CertificateSha256ThumbprintLength);
        if (!spkiSha256.IsValid()) {
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = HashSubjectPublicKey(options.ProviderCache, parsed[0], spkiSha256.Get());
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("CertificateValidator: Leaf SPKI hash failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        WKNET_DBG_PRINT("CertificateValidator: Leaf SPKI SHA256: %02X%02X%02X%02X...\r\n",
            spkiSha256[0], spkiSha256[1], spkiSha256[2], spkiSha256[3]);

        if (!options.VerifyCertificate) {
            FillLeafResult(parsed[0], spkiSha256.Get(), result);
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_SUCCESS;
        }

        status = ValidateNameConstraints(parsed, pathCount);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("CertificateValidator: Name Constraints validation failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        status = ValidateCertificatePolicyTree(parsed, pathCount);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("CertificateValidator: Certificate policy validation failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        long long now = 0;
        status = CurrentPackedTime(&now);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("CertificateValidator: CurrentPackedTime failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        for (SIZE_T index = 0; index < pathCount; ++index) {
            if (now < parsed[index].NotBefore || now > parsed[index].NotAfter) {
                WKNET_DBG_PRINT("CertificateValidator: Certificate %Iu time validation failed\r\n", index);
                RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }
        }

        if (options.RequireServerAuthEku &&
            (!parsed[0].HasExtendedKeyUsage || !parsed[0].AllowsServerAuth)) {
            WKNET_DBG_PRINT("CertificateValidator: ServerAuth EKU validation failed\r\n");
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_TRUST_FAILURE;
        }

        if ((parsed[0].HasBasicConstraints && parsed[0].IsCa) ||
            !parsed[0].HasKeyUsage ||
            !parsed[0].AllowsDigitalSignature) {
            WKNET_DBG_PRINT("CertificateValidator: Leaf certificate usage validation failed\r\n");
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_TRUST_FAILURE;
        }

        status = ValidateHostName(parsed[0], validationHost, validationHostLength);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("CertificateValidator: HostName validation failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        for (SIZE_T index = 0; index + 1 < pathCount; ++index) {
            if (parsed[index].IssuerLength != parsed[index + 1].SubjectLength ||
                !MemoryEquals(parsed[index].Issuer, parsed[index + 1].Subject, parsed[index].IssuerLength)) {
                WKNET_DBG_PRINT("CertificateValidator: Chain issuer/subject mismatch at %Iu\r\n", index);
                RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }

            if (!parsed[index + 1].HasBasicConstraints || !parsed[index + 1].IsCa) {
                WKNET_DBG_PRINT("CertificateValidator: Certificate %Iu is not a CA\r\n", index + 1);
                RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }

            if (!parsed[index + 1].HasKeyUsage || !parsed[index + 1].AllowsKeyCertSign) {
                WKNET_DBG_PRINT("CertificateValidator: Certificate %Iu lacks keyCertSign\r\n", index + 1);
                RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }

            const SIZE_T subordinateCaCount = CountSubordinateCaCertificates(
                parsed,
                pathCount,
                index + 1);
            if (parsed[index + 1].HasPathLenConstraint &&
                subordinateCaCount > parsed[index + 1].PathLenConstraint) {
                WKNET_DBG_PRINT("CertificateValidator: pathLenConstraint failed at %Iu\r\n", index + 1);
                RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
                ReleaseCertificateValidationScratch(scratch);
                return STATUS_TRUST_FAILURE;
            }

            status = VerifyCertificateSignature(options.ProviderCache, parsed[index], parsed[index + 1]);
            if (!NT_SUCCESS(status)) {
                WKNET_DBG_PRINT("CertificateValidator: Signature verification failed at %Iu: 0x%08X\r\n", index, static_cast<ULONG>(status));
                RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
                ReleaseCertificateValidationScratch(scratch);
                return status;
            }
        }

        if (options.Store != nullptr &&
            !options.Store->MatchesPin(validationHost, validationHostLength, spkiSha256.Get(), spkiSha256.Count())) {
            WKNET_DBG_PRINT("CertificateValidator: Pin validation failed\r\n");
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_TRUST_FAILURE;
        }

        SIZE_T trustedAnchorIndex = pathCount;
        status = FindTrustedAnchor(
            options.ProviderCache,
            options.Store,
            parsed,
            pathCount,
            scratch.Anchor,
            scratch.Authority,
            scratch.AuthorityLength,
            &trustedAnchorIndex);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("CertificateValidator: Trust anchor search failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        if (trustedAnchorIndex == pathCount) {
            WKNET_DBG_PRINT("CertificateValidator: No trusted anchor found in chain\r\n");
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return STATUS_TRUST_FAILURE;
        }

        if (trustedAnchorIndex == 0 &&
             pathCount == 1 &&
             parsed[0].IssuerLength == parsed[0].SubjectLength &&
             MemoryEquals(parsed[0].Issuer, parsed[0].Subject, parsed[0].IssuerLength)) {
            status = VerifyCertificateSignature(options.ProviderCache, parsed[0], parsed[0]);
            if (!NT_SUCCESS(status)) {
                WKNET_DBG_PRINT("CertificateValidator: Self-signed signature verification failed: 0x%08X\r\n", static_cast<ULONG>(status));
                RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
                ReleaseCertificateValidationScratch(scratch);
                return status;
            }
        }

        status = ValidateCertificateRevocation(parsed, pathCount, options, trustedAnchorIndex, scratch.Anchor, now);
        if (!NT_SUCCESS(status)) {
            WKNET_DBG_PRINT("CertificateValidator: Revocation validation failed: 0x%08X\r\n", static_cast<ULONG>(status));
            RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
            ReleaseCertificateValidationScratch(scratch);
            return status;
        }

        FillLeafResult(parsed[0], spkiSha256.Get(), result);
        RtlSecureZeroMemory(spkiSha256.Get(), spkiSha256.Count());
        ReleaseCertificateValidationScratch(scratch);
        return STATUS_SUCCESS;
    }

#if !defined(WKNET_USER_MODE_TEST)
    namespace
    {
        struct ValidateChainCalloutContext final
        {
            const CertificateChainView* Chain = nullptr;
            const CertificateValidationOptions* Options = nullptr;
            CertificateValidationResult* Result = nullptr;
            NTSTATUS Status = STATUS_UNSUCCESSFUL;
        };

        void NTAPI ValidateChainExpandedStackCallout(_In_opt_ PVOID parameter)
        {
            ValidateChainCalloutContext* const context = static_cast<ValidateChainCalloutContext*>(parameter);
            if (context == nullptr || context->Chain == nullptr || context->Options == nullptr) {
                return;
            }

            context->Status = ValidateChainImpl(*context->Chain, *context->Options, context->Result);
        }
    }
#endif

    NTSTATUS CertificateValidator::ValidateChain(
        const CertificateChainView& chain,
        const CertificateValidationOptions& options,
        CertificateValidationResult* result) noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return ValidateChainImpl(chain, options, result);
#else
        HeapObject<ValidateChainCalloutContext> context;
        if (!context.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        context->Chain = &chain;
        context->Options = &options;
        context->Result = result;
        context->Status = STATUS_UNSUCCESSFUL;

        const NTSTATUS status = KeExpandKernelStackAndCalloutEx(
            ValidateChainExpandedStackCallout,
            context.Get(),
            MAXIMUM_EXPANSION_SIZE,
            TRUE,
            nullptr);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return context->Status;
#endif
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

    NTSTATUS CertificateValidator::ToSignatureAlgorithm(
        CertificateSignatureAlgorithm algorithm,
        crypto::SignatureAlgorithm* signatureAlgorithm) noexcept
    {
        if (signatureAlgorithm == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        switch (algorithm) {
        case CertificateSignatureAlgorithm::RsaPkcs1Sha256:
            *signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
            return STATUS_SUCCESS;
        case CertificateSignatureAlgorithm::RsaPkcs1Sha384:
            *signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha384;
            return STATUS_SUCCESS;
        case CertificateSignatureAlgorithm::EcdsaSha256:
            *signatureAlgorithm = crypto::SignatureAlgorithm::EcdsaSha256;
            return STATUS_SUCCESS;
        case CertificateSignatureAlgorithm::EcdsaSha384:
            *signatureAlgorithm = crypto::SignatureAlgorithm::EcdsaSha384;
            return STATUS_SUCCESS;
        case CertificateSignatureAlgorithm::Ed25519:
            *signatureAlgorithm = crypto::SignatureAlgorithm::Ed25519;
            return STATUS_SUCCESS;
        case CertificateSignatureAlgorithm::Ed448:
            *signatureAlgorithm = crypto::SignatureAlgorithm::Ed448;
            return STATUS_SUCCESS;
        default:
            return STATUS_NOT_SUPPORTED;
        }
    }
}
}
