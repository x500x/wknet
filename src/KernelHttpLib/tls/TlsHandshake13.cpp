#include <KernelHttp/tls/TlsHandshake13.h>

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        constexpr USHORT ExtensionServerName = 0;
        constexpr USHORT ExtensionSupportedGroups = 10;
        constexpr USHORT ExtensionSignatureAlgorithms = 13;
        constexpr USHORT ExtensionAlpn = 16;
        constexpr USHORT ExtensionPreSharedKey = 41;
        constexpr USHORT ExtensionEarlyData = 42;
        constexpr USHORT ExtensionSupportedVersions = 43;
        constexpr USHORT ExtensionPskKeyExchangeModes = 45;
        constexpr USHORT ExtensionSignatureAlgorithmsCert = 50;
        constexpr USHORT ExtensionKeyShare = 51;
        constexpr USHORT Tls13Version = 0x0304;
        constexpr UCHAR NullCompressionMethod = 0;

        const UCHAR HelloRetryRequestRandom[TlsRandomLength] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };

        const TlsCipherSuite DefaultCipherSuites[] = {
            TlsCipherSuite::TlsAes128GcmSha256,
            TlsCipherSuite::TlsAes256GcmSha384,
            TlsCipherSuite::TlsChaCha20Poly1305Sha256
        };

        const TlsNamedGroup DefaultNamedGroups[] = {
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

        const TlsSignatureScheme DefaultSignatureSchemes[] = {
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
            TlsSignatureScheme::RsaPkcs1Sha512
        };

        _Must_inspect_result_
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        _Must_inspect_result_
        bool HasCapacity(SIZE_T capacity, SIZE_T offset, SIZE_T writeLength) noexcept
        {
            return offset <= capacity && writeLength <= (capacity - offset);
        }

        _Must_inspect_result_
        SIZE_T StringLength(_In_z_ const char* value) noexcept
        {
            SIZE_T length = 0;
            if (value == nullptr) {
                return 0;
            }

            while (value[length] != '\0') {
                ++length;
            }

            return length;
        }

        _Must_inspect_result_
        NTSTATUS WriteByte(UCHAR value, _Out_writes_bytes_(capacity) UCHAR* destination, SIZE_T capacity, _Inout_ SIZE_T* offset) noexcept
        {
            if (destination == nullptr || offset == nullptr || !HasCapacity(capacity, *offset, 1)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[*offset] = value;
            ++(*offset);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS WriteUint16(USHORT value, _Out_writes_bytes_(capacity) UCHAR* destination, SIZE_T capacity, _Inout_ SIZE_T* offset) noexcept
        {
            if (destination == nullptr || offset == nullptr || !HasCapacity(capacity, *offset, 2)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[*offset] = static_cast<UCHAR>((value >> 8) & 0xff);
            destination[*offset + 1] = static_cast<UCHAR>(value & 0xff);
            *offset += 2;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS WriteUint24(ULONG value, _Out_writes_bytes_(capacity) UCHAR* destination, SIZE_T capacity, _Inout_ SIZE_T* offset) noexcept
        {
            if (value > TlsMaxHandshakeMessageLength ||
                destination == nullptr ||
                offset == nullptr ||
                !HasCapacity(capacity, *offset, 3)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[*offset] = static_cast<UCHAR>((value >> 16) & 0xff);
            destination[*offset + 1] = static_cast<UCHAR>((value >> 8) & 0xff);
            destination[*offset + 2] = static_cast<UCHAR>(value & 0xff);
            *offset += 3;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS WriteUint32(ULONG value, _Out_writes_bytes_(capacity) UCHAR* destination, SIZE_T capacity, _Inout_ SIZE_T* offset) noexcept
        {
            if (destination == nullptr || offset == nullptr || !HasCapacity(capacity, *offset, 4)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            destination[*offset] = static_cast<UCHAR>((value >> 24) & 0xff);
            destination[*offset + 1] = static_cast<UCHAR>((value >> 16) & 0xff);
            destination[*offset + 2] = static_cast<UCHAR>((value >> 8) & 0xff);
            destination[*offset + 3] = static_cast<UCHAR>(value & 0xff);
            *offset += 4;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS WriteBytes(
            _In_reads_bytes_opt_(length) const UCHAR* source,
            SIZE_T length,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (!IsValidBuffer(source, length) ||
                destination == nullptr ||
                offset == nullptr ||
                !HasCapacity(capacity, *offset, length)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            if (length != 0) {
                RtlCopyMemory(destination + *offset, source, length);
            }

            *offset += length;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadByte(
            _In_reads_bytes_(capacity) const UCHAR* source,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset,
            _Out_ UCHAR* value) noexcept
        {
            if (source == nullptr || offset == nullptr || value == nullptr || !HasCapacity(capacity, *offset, 1)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *value = source[*offset];
            ++(*offset);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadUint16(
            _In_reads_bytes_(capacity) const UCHAR* source,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset,
            _Out_ USHORT* value) noexcept
        {
            if (source == nullptr || offset == nullptr || value == nullptr || !HasCapacity(capacity, *offset, 2)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *value = static_cast<USHORT>((static_cast<USHORT>(source[*offset]) << 8) | source[*offset + 1]);
            *offset += 2;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadUint24(
            _In_reads_bytes_(capacity) const UCHAR* source,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset,
            _Out_ SIZE_T* value) noexcept
        {
            if (source == nullptr || offset == nullptr || value == nullptr || !HasCapacity(capacity, *offset, 3)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *value =
                (static_cast<SIZE_T>(source[*offset]) << 16) |
                (static_cast<SIZE_T>(source[*offset + 1]) << 8) |
                source[*offset + 2];
            *offset += 3;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadUint32(
            _In_reads_bytes_(capacity) const UCHAR* source,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset,
            _Out_ ULONG* value) noexcept
        {
            if (source == nullptr || offset == nullptr || value == nullptr || !HasCapacity(capacity, *offset, 4)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *value =
                (static_cast<ULONG>(source[*offset]) << 24) |
                (static_cast<ULONG>(source[*offset + 1]) << 16) |
                (static_cast<ULONG>(source[*offset + 2]) << 8) |
                source[*offset + 3];
            *offset += 4;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadBytes(
            _In_reads_bytes_(capacity) const UCHAR* source,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset,
            SIZE_T length,
            _Outptr_result_bytebuffer_(length) const UCHAR** value) noexcept
        {
            if (source == nullptr || offset == nullptr || value == nullptr || !HasCapacity(capacity, *offset, length)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *value = source + *offset;
            *offset += length;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateHandshakeType(const TlsHandshakeMessageView& message, TlsHandshakeType expected) noexcept
        {
            if (message.Type != expected || (message.Body == nullptr && message.BodyLength != 0)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool MemoryEquals(const UCHAR* left, const UCHAR* right, SIZE_T length) noexcept
        {
            UCHAR diff = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                diff = static_cast<UCHAR>(diff | (left[index] ^ right[index]));
            }

            return diff == 0;
        }

        _Must_inspect_result_
        bool IsAsciiLetter(UCHAR value) noexcept
        {
            return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
        }

        _Must_inspect_result_
        bool IsAsciiDigit(UCHAR value) noexcept
        {
            return value >= '0' && value <= '9';
        }

        _Must_inspect_result_
        bool IsValidSniDnsName(_In_reads_(length) const char* name, SIZE_T length) noexcept
        {
            if (name == nullptr || length == 0 || length > 253) {
                return false;
            }

            bool hasAlpha = false;
            SIZE_T labelLength = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                const UCHAR ch = static_cast<UCHAR>(name[index]);
                if (ch >= 0x80 || ch == ':') {
                    return false;
                }
                if (ch == '.') {
                    if (labelLength == 0 || labelLength > 63) {
                        return false;
                    }
                    labelLength = 0;
                    continue;
                }
                if (!IsAsciiLetter(ch) && !IsAsciiDigit(ch) && ch != '-') {
                    return false;
                }
                if (IsAsciiLetter(ch)) {
                    hasAlpha = true;
                }
                ++labelLength;
            }

            return hasAlpha && labelLength != 0 && labelLength <= 63;
        }

        _Must_inspect_result_
        NTSTATUS BuildServerNameExtension(
            const Tls13ClientHelloOptions& options,
            UCHAR* destination,
            SIZE_T capacity,
            SIZE_T* offset) noexcept
        {
            if (options.ServerName == nullptr || options.ServerNameLength == 0) {
                return STATUS_SUCCESS;
            }

            if (options.ServerNameLength > 0xffff - 5 ||
                !IsValidSniDnsName(options.ServerName, options.ServerNameLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = WriteUint16(ExtensionServerName, destination, capacity, offset);
            const SIZE_T lengthOffset = *offset;
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteUint16(static_cast<USHORT>(options.ServerNameLength + 3), destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(0, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteUint16(static_cast<USHORT>(options.ServerNameLength), destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteBytes(reinterpret_cast<const UCHAR*>(options.ServerName), options.ServerNameLength, destination, capacity, offset);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const USHORT extensionLength = static_cast<USHORT>(options.ServerNameLength + 5);
            destination[lengthOffset] = static_cast<UCHAR>((extensionLength >> 8) & 0xff);
            destination[lengthOffset + 1] = static_cast<UCHAR>(extensionLength & 0xff);
            return STATUS_SUCCESS;
        }

        template <typename TValue>
        _Must_inspect_result_
        NTSTATUS BuildUint16VectorExtension(
            USHORT extensionType,
            const TValue* values,
            SIZE_T valueCount,
            UCHAR* destination,
            SIZE_T capacity,
            SIZE_T* offset) noexcept
        {
            if (values == nullptr || valueCount == 0) {
                return STATUS_SUCCESS;
            }
            if (valueCount > 0x7fff) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = WriteUint16(extensionType, destination, capacity, offset);
            const USHORT vectorLength = static_cast<USHORT>(valueCount * sizeof(USHORT));
            if (NT_SUCCESS(status)) {
                status = WriteUint16(static_cast<USHORT>(vectorLength + 2), destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteUint16(vectorLength, destination, capacity, offset);
            }
            for (SIZE_T index = 0; NT_SUCCESS(status) && index < valueCount; ++index) {
                status = WriteUint16(static_cast<USHORT>(values[index]), destination, capacity, offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildSupportedVersionsExtension(UCHAR* destination, SIZE_T capacity, SIZE_T* offset) noexcept
        {
            NTSTATUS status = WriteUint16(ExtensionSupportedVersions, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(3, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(2, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteUint16(Tls13Version, destination, capacity, offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildPskModesExtension(UCHAR* destination, SIZE_T capacity, SIZE_T* offset) noexcept
        {
            NTSTATUS status = WriteUint16(ExtensionPskKeyExchangeModes, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(2, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(1, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(static_cast<UCHAR>(Tls13PskKeyExchangeMode::PskDheKe), destination, capacity, offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildKeyShareExtension(
            const Tls13ClientHelloOptions& options,
            UCHAR* destination,
            SIZE_T capacity,
            SIZE_T* offset) noexcept
        {
            if (options.KeyShares == nullptr || options.KeyShareCount == 0) {
                return STATUS_SUCCESS;
            }

            NTSTATUS status = WriteUint16(ExtensionKeyShare, destination, capacity, offset);
            const SIZE_T extensionLengthOffset = *offset;
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            const SIZE_T vectorLengthOffset = *offset;
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            const SIZE_T entriesStart = *offset;

            for (SIZE_T index = 0; NT_SUCCESS(status) && index < options.KeyShareCount; ++index) {
                const Tls13KeyShareEntry& share = options.KeyShares[index];
                if (share.KeyExchange == nullptr ||
                    share.KeyExchangeLength == 0 ||
                    share.KeyExchangeLength > 0xffff) {
                    return STATUS_INVALID_PARAMETER;
                }

                status = WriteUint16(static_cast<USHORT>(share.Group), destination, capacity, offset);
                if (NT_SUCCESS(status)) {
                    status = WriteUint16(static_cast<USHORT>(share.KeyExchangeLength), destination, capacity, offset);
                }
                if (NT_SUCCESS(status)) {
                    status = WriteBytes(share.KeyExchange, share.KeyExchangeLength, destination, capacity, offset);
                }
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            const SIZE_T vectorLength = *offset - entriesStart;
            if (vectorLength > 0xffff) {
                return STATUS_INVALID_PARAMETER;
            }
            const USHORT extLength = static_cast<USHORT>(vectorLength + 2);
            destination[extensionLengthOffset] = static_cast<UCHAR>((extLength >> 8) & 0xff);
            destination[extensionLengthOffset + 1] = static_cast<UCHAR>(extLength & 0xff);
            destination[vectorLengthOffset] = static_cast<UCHAR>((vectorLength >> 8) & 0xff);
            destination[vectorLengthOffset + 1] = static_cast<UCHAR>(vectorLength & 0xff);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS BuildAlpnExtension(
            const Tls13ClientHelloOptions& options,
            UCHAR* destination,
            SIZE_T capacity,
            SIZE_T* offset) noexcept
        {
            if (options.AlpnProtocols == nullptr || options.AlpnProtocolCount == 0) {
                return STATUS_SUCCESS;
            }

            SIZE_T listLength = 0;
            for (SIZE_T index = 0; index < options.AlpnProtocolCount; ++index) {
                const TlsAlpnProtocol& protocol = options.AlpnProtocols[index];
                if (protocol.Name == nullptr || protocol.NameLength == 0 || protocol.NameLength > 255) {
                    return STATUS_INVALID_PARAMETER;
                }
                listLength += 1 + protocol.NameLength;
            }
            if (listLength > 0xfffd) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = WriteUint16(ExtensionAlpn, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(static_cast<USHORT>(listLength + 2), destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteUint16(static_cast<USHORT>(listLength), destination, capacity, offset);
            }
            for (SIZE_T index = 0; NT_SUCCESS(status) && index < options.AlpnProtocolCount; ++index) {
                const TlsAlpnProtocol& protocol = options.AlpnProtocols[index];
                status = WriteByte(static_cast<UCHAR>(protocol.NameLength), destination, capacity, offset);
                if (NT_SUCCESS(status)) {
                    status = WriteBytes(reinterpret_cast<const UCHAR*>(protocol.Name), protocol.NameLength, destination, capacity, offset);
                }
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildEarlyDataExtension(bool enabled, UCHAR* destination, SIZE_T capacity, SIZE_T* offset) noexcept
        {
            if (!enabled) {
                return STATUS_SUCCESS;
            }

            NTSTATUS status = WriteUint16(ExtensionEarlyData, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildPreSharedKeyExtension(
            const Tls13ClientHelloOptions& options,
            UCHAR* destination,
            SIZE_T capacity,
            SIZE_T* offset) noexcept
        {
            if (options.PskIdentities == nullptr || options.PskIdentityCount == 0) {
                return STATUS_SUCCESS;
            }

            NTSTATUS status = WriteUint16(ExtensionPreSharedKey, destination, capacity, offset);
            const SIZE_T extensionLengthOffset = *offset;
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            const SIZE_T identitiesLengthOffset = *offset;
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            const SIZE_T identitiesStart = *offset;

            for (SIZE_T index = 0; NT_SUCCESS(status) && index < options.PskIdentityCount; ++index) {
                const Tls13PskIdentity& identity = options.PskIdentities[index];
                if (identity.Identity == nullptr || identity.IdentityLength == 0 || identity.IdentityLength > 0xffff) {
                    return STATUS_INVALID_PARAMETER;
                }
                status = WriteUint16(static_cast<USHORT>(identity.IdentityLength), destination, capacity, offset);
                if (NT_SUCCESS(status)) {
                    status = WriteBytes(identity.Identity, identity.IdentityLength, destination, capacity, offset);
                }
                if (NT_SUCCESS(status)) {
                    status = WriteUint32(identity.ObfuscatedTicketAge, destination, capacity, offset);
                }
            }

            const SIZE_T identitiesLength = *offset - identitiesStart;
            const SIZE_T bindersLengthOffset = *offset;
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            const SIZE_T bindersStart = *offset;

            for (SIZE_T index = 0; NT_SUCCESS(status) && index < options.PskIdentityCount; ++index) {
                const Tls13PskIdentity& identity = options.PskIdentities[index];
                if (identity.Binder == nullptr || identity.BinderLength == 0 || identity.BinderLength > Tls13MaxBinderLength) {
                    return STATUS_INVALID_PARAMETER;
                }
                status = WriteByte(static_cast<UCHAR>(identity.BinderLength), destination, capacity, offset);
                if (NT_SUCCESS(status)) {
                    status = WriteBytes(identity.Binder, identity.BinderLength, destination, capacity, offset);
                }
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            const SIZE_T bindersLength = *offset - bindersStart;
            const SIZE_T extensionLength = 2 + identitiesLength + 2 + bindersLength;
            if (identitiesLength > 0xffff || bindersLength > 0xffff || extensionLength > 0xffff) {
                return STATUS_INVALID_PARAMETER;
            }

            destination[extensionLengthOffset] = static_cast<UCHAR>((extensionLength >> 8) & 0xff);
            destination[extensionLengthOffset + 1] = static_cast<UCHAR>(extensionLength & 0xff);
            destination[identitiesLengthOffset] = static_cast<UCHAR>((identitiesLength >> 8) & 0xff);
            destination[identitiesLengthOffset + 1] = static_cast<UCHAR>(identitiesLength & 0xff);
            destination[bindersLengthOffset] = static_cast<UCHAR>((bindersLength >> 8) & 0xff);
            destination[bindersLengthOffset + 1] = static_cast<UCHAR>(bindersLength & 0xff);
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        SIZE_T HashLength(crypto::HashAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case crypto::HashAlgorithm::Sha384:
                return 48;
            case crypto::HashAlgorithm::Sha1:
                return 20;
            case crypto::HashAlgorithm::Sha256:
            default:
                return 32;
            }
        }

        _Must_inspect_result_
        NTSTATUS BuildHkdfLabel(
            _In_z_ const char* label,
            _In_reads_bytes_opt_(contextLength) const UCHAR* context,
            SIZE_T contextLength,
            SIZE_T outputLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept
        {
            if (label == nullptr ||
                (context == nullptr && contextLength != 0) ||
                destination == nullptr ||
                bytesWritten == nullptr ||
                outputLength > 0xffff ||
                contextLength > 255) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T labelLength = 0;
            while (label[labelLength] != '\0') {
                ++labelLength;
            }

            constexpr char LabelPrefix[] = "tls13 ";
            constexpr SIZE_T LabelPrefixLength = sizeof(LabelPrefix) - 1;
            if (labelLength + LabelPrefixLength > 255) {
                return STATUS_INVALID_PARAMETER;
            }

            const SIZE_T required = 2 + 1 + LabelPrefixLength + labelLength + 1 + contextLength;
            if (destinationCapacity < required) {
                *bytesWritten = required;
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T offset = 0;
            destination[offset++] = static_cast<UCHAR>((outputLength >> 8) & 0xff);
            destination[offset++] = static_cast<UCHAR>(outputLength & 0xff);
            destination[offset++] = static_cast<UCHAR>(LabelPrefixLength + labelLength);
            RtlCopyMemory(destination + offset, LabelPrefix, LabelPrefixLength);
            offset += LabelPrefixLength;
            RtlCopyMemory(destination + offset, label, labelLength);
            offset += labelLength;
            destination[offset++] = static_cast<UCHAR>(contextLength);
            if (contextLength != 0) {
                RtlCopyMemory(destination + offset, context, contextLength);
                offset += contextLength;
            }

            *bytesWritten = offset;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS HkdfExpandLabel(
            crypto::HashAlgorithm algorithm,
            _In_reads_bytes_(secretLength) const UCHAR* secret,
            SIZE_T secretLength,
            _In_z_ const char* label,
            _In_reads_bytes_opt_(contextLength) const UCHAR* context,
            SIZE_T contextLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept
        {
            HeapArray<UCHAR> info(128);
            if (!info.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T infoLength = 0;
            NTSTATUS status = BuildHkdfLabel(
                label,
                context,
                contextLength,
                outputLength,
                info.Get(),
                info.Count(),
                &infoLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = crypto::CngProvider::HkdfExpand(
                algorithm,
                secret,
                secretLength,
                info.Get(),
                infoLength,
                output,
                outputLength);
            RtlSecureZeroMemory(info.Get(), info.Count());
            return status;
        }

        _Must_inspect_result_
        NTSTATUS DeriveSecret(
            crypto::HashAlgorithm algorithm,
            _In_reads_bytes_(secretLength) const UCHAR* secret,
            SIZE_T secretLength,
            _In_z_ const char* label,
            _In_reads_bytes_opt_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept
        {
            return HkdfExpandLabel(
                algorithm,
                secret,
                secretLength,
                label,
                transcriptHash,
                transcriptHashLength,
                output,
                outputLength);
        }

        _Must_inspect_result_
        NTSTATUS FindExtension(
            const UCHAR* extensions,
            SIZE_T extensionsLength,
            USHORT extensionType,
            _Outptr_result_bytebuffer_(*extensionLength) const UCHAR** extension,
            _Out_ SIZE_T* extensionLength,
            _Out_opt_ bool* found) noexcept
        {
            if (extension != nullptr) {
                *extension = nullptr;
            }
            if (extensionLength != nullptr) {
                *extensionLength = 0;
            }
            if (found != nullptr) {
                *found = false;
            }
            if ((extensions == nullptr && extensionsLength != 0) || extension == nullptr || extensionLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T offset = 0;
            while (offset < extensionsLength) {
                if (extensionsLength - offset < 4) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                const USHORT currentType = static_cast<USHORT>(
                    (static_cast<USHORT>(extensions[offset]) << 8) | extensions[offset + 1]);
                const SIZE_T currentLength =
                    (static_cast<SIZE_T>(extensions[offset + 2]) << 8) | extensions[offset + 3];
                offset += 4;
                if (currentLength > extensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (currentType == extensionType) {
                    if (found != nullptr && *found) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    *extension = extensions + offset;
                    *extensionLength = currentLength;
                    if (found != nullptr) {
                        *found = true;
                    }
                }
                offset += currentLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateNoDuplicateExtensions(
            _In_reads_bytes_(extensionsLength) const UCHAR* extensions,
            SIZE_T extensionsLength) noexcept
        {
            if (extensions == nullptr && extensionsLength != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T offset = 0;
            while (offset < extensionsLength) {
                if (extensionsLength - offset < 4) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T currentExtensionOffset = offset;
                const USHORT currentType = static_cast<USHORT>(
                    (static_cast<USHORT>(extensions[offset]) << 8) | extensions[offset + 1]);
                const SIZE_T currentLength =
                    (static_cast<SIZE_T>(extensions[offset + 2]) << 8) | extensions[offset + 3];
                offset += 4;
                if (currentLength > extensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                SIZE_T priorOffset = 0;
                while (priorOffset < currentExtensionOffset) {
                    if (currentExtensionOffset - priorOffset < 4) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    const USHORT priorType = static_cast<USHORT>(
                        (static_cast<USHORT>(extensions[priorOffset]) << 8) |
                        extensions[priorOffset + 1]);
                    const SIZE_T priorLength =
                        (static_cast<SIZE_T>(extensions[priorOffset + 2]) << 8) |
                        extensions[priorOffset + 3];
                    priorOffset += 4;
                    if (priorLength > currentExtensionOffset - priorOffset) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (priorType == currentType) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    priorOffset += priorLength;
                }

                offset += currentLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseAlpnExtension(const UCHAR* data, SIZE_T length, const char** alpn, SIZE_T* alpnLength) noexcept
        {
            if (alpn == nullptr || alpnLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            *alpn = nullptr;
            *alpnLength = 0;
            if (data == nullptr || length < 3) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            USHORT listLength = 0;
            NTSTATUS status = ReadUint16(data, length, &offset, &listLength);
            if (!NT_SUCCESS(status) || listLength != length - offset || listLength == 0) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            UCHAR protocolLength = 0;
            status = ReadByte(data, length, &offset, &protocolLength);
            if (!NT_SUCCESS(status) || protocolLength == 0 || protocolLength > length - offset || offset + protocolLength != length) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            *alpn = reinterpret_cast<const char*>(data + offset);
            *alpnLength = protocolLength;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ComputeFinishedData(
            const TlsContext& context,
            bool clientFinished,
            const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength,
            UCHAR* output,
            SIZE_T outputLength) noexcept
        {
            HeapArray<UCHAR> finishedKey(Tls13MaxSecretLength);
            if (!finishedKey.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T finishedKeyLength = 0;
            NTSTATUS status = context.DeriveTls13FinishedKey(
                clientFinished,
                finishedKey.Get(),
                finishedKey.Count(),
                &finishedKeyLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T hmacLength = 0;
            status = crypto::CngProvider::Hmac(
                TlsHandshake13::HashForCipherSuite(context.CipherSuite()),
                finishedKey.Get(),
                finishedKeyLength,
                transcriptHash,
                transcriptHashLength,
                output,
                outputLength,
                &hmacLength);
            RtlSecureZeroMemory(finishedKey.Get(), finishedKey.Count());
            if (NT_SUCCESS(status) && hmacLength != outputLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            return status;
        }
    }

    crypto::HashAlgorithm TlsHandshake13::HashForCipherSuite(TlsCipherSuite cipherSuite) noexcept
    {
        return cipherSuite == TlsCipherSuite::TlsAes256GcmSha384 ?
            crypto::HashAlgorithm::Sha384 :
            crypto::HashAlgorithm::Sha256;
    }

        bool TlsHandshake13::IsSupportedCipherSuite(TlsCipherSuite cipherSuite) noexcept
    {
        return cipherSuite == TlsCipherSuite::TlsAes128GcmSha256 ||
            cipherSuite == TlsCipherSuite::TlsAes256GcmSha384 ||
            cipherSuite == TlsCipherSuite::TlsChaCha20Poly1305Sha256 ||
            cipherSuite == TlsCipherSuite::TlsAes128CcmSha256 ||
            cipherSuite == TlsCipherSuite::TlsAes128Ccm8Sha256;
    }

    namespace
    {
        _Must_inspect_result_
        bool ContainsCipherSuite(
            _In_reads_(cipherSuiteCount) const TlsCipherSuite* cipherSuites,
            SIZE_T cipherSuiteCount,
            TlsCipherSuite selected) noexcept
        {
            if (cipherSuites == nullptr || cipherSuiteCount == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < cipherSuiteCount; ++index) {
                if (cipherSuites[index] == selected) {
                    return true;
                }
            }
            return false;
        }

        _Must_inspect_result_
        bool ContainsNamedGroup(
            _In_reads_(namedGroupCount) const TlsNamedGroup* namedGroups,
            SIZE_T namedGroupCount,
            TlsNamedGroup selected) noexcept
        {
            if (namedGroups == nullptr || namedGroupCount == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < namedGroupCount; ++index) {
                if (namedGroups[index] == selected) {
                    return true;
                }
            }
            return false;
        }

        _Must_inspect_result_
        bool ContainsKeyShareGroup(
            _In_reads_(keyShareCount) const Tls13KeyShareEntry* keyShares,
            SIZE_T keyShareCount,
            TlsNamedGroup selected) noexcept
        {
            if (keyShares == nullptr || keyShareCount == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < keyShareCount; ++index) {
                if (keyShares[index].Group == selected) {
                    return true;
                }
            }
            return false;
        }
    }

    NTSTATUS TlsHandshake13::EncodeClientHello(
        TlsContext& context,
        const Tls13ClientHelloOptions& options,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (context.Protocol() != TlsProtocol::Tls13 ||
            (options.ServerName == nullptr && options.ServerNameLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        const TlsCipherSuite* cipherSuites = options.CipherSuites != nullptr ? options.CipherSuites : DefaultCipherSuites;
        const SIZE_T cipherSuiteCount = options.CipherSuites != nullptr ? options.CipherSuiteCount : sizeof(DefaultCipherSuites) / sizeof(DefaultCipherSuites[0]);
        const TlsNamedGroup* namedGroups = options.NamedGroups != nullptr ? options.NamedGroups : DefaultNamedGroups;
        const SIZE_T namedGroupCount = options.NamedGroups != nullptr ? options.NamedGroupCount : sizeof(DefaultNamedGroups) / sizeof(DefaultNamedGroups[0]);
        const TlsSignatureScheme* signatureSchemes = options.SignatureSchemes != nullptr ? options.SignatureSchemes : DefaultSignatureSchemes;
        const SIZE_T signatureSchemeCount = options.SignatureSchemes != nullptr ? options.SignatureSchemeCount : sizeof(DefaultSignatureSchemes) / sizeof(DefaultSignatureSchemes[0]);

        if (cipherSuiteCount == 0 || cipherSuiteCount > 0x7fff) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> body(4096);
        HeapArray<UCHAR> extensions(Tls13MaxExtensionsLength);
        if (!body.IsValid() || !extensions.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T offset = 0;
        NTSTATUS status = WriteUint16(0x0303, body.Get(), body.Count(), &offset);
        if (NT_SUCCESS(status)) {
            status = WriteBytes(context.Secrets().ClientRandom, TlsRandomLength, body.Get(), body.Count(), &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteByte(0, body.Get(), body.Count(), &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteUint16(static_cast<USHORT>(cipherSuiteCount * 2), body.Get(), body.Count(), &offset);
        }
        for (SIZE_T index = 0; NT_SUCCESS(status) && index < cipherSuiteCount; ++index) {
            if (!IsSupportedCipherSuite(cipherSuites[index])) {
                return STATUS_NOT_SUPPORTED;
            }
            status = WriteUint16(static_cast<USHORT>(cipherSuites[index]), body.Get(), body.Count(), &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteByte(1, body.Get(), body.Count(), &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteByte(NullCompressionMethod, body.Get(), body.Count(), &offset);
        }

        SIZE_T extensionOffset = 0;
        if (NT_SUCCESS(status)) {
            status = BuildServerNameExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildSupportedVersionsExtension(extensions.Get(), extensions.Count(), &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildUint16VectorExtension(
                ExtensionSupportedGroups,
                namedGroups,
                namedGroupCount,
                extensions.Get(),
                extensions.Count(),
                &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildUint16VectorExtension(
                ExtensionSignatureAlgorithms,
                signatureSchemes,
                signatureSchemeCount,
                extensions.Get(),
                extensions.Count(),
                &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildUint16VectorExtension(
                ExtensionSignatureAlgorithmsCert,
                signatureSchemes,
                signatureSchemeCount,
                extensions.Get(),
                extensions.Count(),
                &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildKeyShareExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildPskModesExtension(extensions.Get(), extensions.Count(), &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildAlpnExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildEarlyDataExtension(options.OfferEarlyData, extensions.Get(), extensions.Count(), &extensionOffset);
        }
        if (NT_SUCCESS(status)) {
            status = BuildPreSharedKeyExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        }
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(body.Get(), body.Count());
            RtlSecureZeroMemory(extensions.Get(), extensions.Count());
            return status;
        }

        status = WriteUint16(static_cast<USHORT>(extensionOffset), body.Get(), body.Count(), &offset);
        if (NT_SUCCESS(status)) {
            status = WriteBytes(extensions.Get(), extensionOffset, body.Get(), body.Count(), &offset);
        }
        RtlSecureZeroMemory(extensions.Get(), extensions.Count());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(body.Get(), body.Count());
            return status;
        }

        const SIZE_T required = TlsHandshakeHeaderLength + offset;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            RtlSecureZeroMemory(body.Get(), body.Count());
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T outputOffset = 0;
        status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::ClientHello), destination, destinationCapacity, &outputOffset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(static_cast<ULONG>(offset), destination, destinationCapacity, &outputOffset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteBytes(body.Get(), offset, destination, destinationCapacity, &outputOffset);
        }
        RtlSecureZeroMemory(body.Get(), body.Count());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        context.SetState(TlsHandshakeState::ClientHelloSent);
        if (bytesWritten != nullptr) {
            *bytesWritten = outputOffset;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ParseServerHello(
        TlsContext& context,
        const TlsHandshakeMessageView& message,
        Tls13ServerHelloView& serverHello) noexcept
    {
        serverHello = {};
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::ServerHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        USHORT legacyVersion = 0;
        status = ReadUint16(message.Body, message.BodyLength, &offset, &legacyVersion);
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, TlsRandomLength, &serverHello.Random);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        serverHello.LegacyVersion = { static_cast<UCHAR>((legacyVersion >> 8) & 0xff), static_cast<UCHAR>(legacyVersion & 0xff) };
        if (legacyVersion != 0x0303) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        serverHello.RandomLength = TlsRandomLength;
        serverHello.IsHelloRetryRequest = MemoryEquals(serverHello.Random, HelloRetryRequestRandom, sizeof(HelloRetryRequestRandom));

        UCHAR sessionIdLength = 0;
        status = ReadByte(message.Body, message.BodyLength, &offset, &sessionIdLength);
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, sessionIdLength, &serverHello.SessionId);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        serverHello.SessionIdLength = sessionIdLength;

        USHORT cipherSuite = 0;
        status = ReadUint16(message.Body, message.BodyLength, &offset, &cipherSuite);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        serverHello.CipherSuite = static_cast<TlsCipherSuite>(cipherSuite);
        if (!IsSupportedCipherSuite(serverHello.CipherSuite)) {
            return STATUS_NOT_SUPPORTED;
        }

        UCHAR compression = 0xff;
        status = ReadByte(message.Body, message.BodyLength, &offset, &compression);
        if (!NT_SUCCESS(status) || compression != NullCompressionMethod) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        USHORT extensionsLength = 0;
        status = ReadUint16(message.Body, message.BodyLength, &offset, &extensionsLength);
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, extensionsLength, &serverHello.Extensions);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        serverHello.ExtensionsLength = extensionsLength;
        if (offset != message.BodyLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        status = ValidateNoDuplicateExtensions(serverHello.Extensions, serverHello.ExtensionsLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        bool found = false;
        status = FindExtension(serverHello.Extensions, serverHello.ExtensionsLength, ExtensionSupportedVersions, &extension, &extensionLength, &found);
        if (!NT_SUCCESS(status) || !found || extensionLength != 2) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        SIZE_T extensionOffset = 0;
        USHORT selectedVersion = 0;
        status = ReadUint16(extension, extensionLength, &extensionOffset, &selectedVersion);
        if (!NT_SUCCESS(status) || selectedVersion != Tls13Version) {
            return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        }
        serverHello.SelectedVersion = { 3, 4 };

        status = FindExtension(serverHello.Extensions, serverHello.ExtensionsLength, ExtensionKeyShare, &extension, &extensionLength, &found);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (serverHello.IsHelloRetryRequest) {
            if (!found || extensionLength != 2) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            extensionOffset = 0;
            USHORT retryGroup = 0;
            status = ReadUint16(extension, extensionLength, &extensionOffset, &retryGroup);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            serverHello.RetryGroup = static_cast<TlsNamedGroup>(retryGroup);
        }
        else {
            if (!found || extensionLength < 4) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            extensionOffset = 0;
            USHORT group = 0;
            USHORT keyExchangeLength = 0;
            status = ReadUint16(extension, extensionLength, &extensionOffset, &group);
            if (NT_SUCCESS(status)) {
                status = ReadUint16(extension, extensionLength, &extensionOffset, &keyExchangeLength);
            }
            if (NT_SUCCESS(status)) {
                status = ReadBytes(extension, extensionLength, &extensionOffset, keyExchangeLength, &serverHello.KeyShare.KeyExchange);
            }
            if (!NT_SUCCESS(status) || extensionOffset != extensionLength || keyExchangeLength == 0) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            serverHello.KeyShare.Group = static_cast<TlsNamedGroup>(group);
            serverHello.KeyShare.KeyExchangeLength = keyExchangeLength;
        }

        status = FindExtension(serverHello.Extensions, serverHello.ExtensionsLength, ExtensionPreSharedKey, &extension, &extensionLength, &found);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (found) {
            if (extensionLength != 2) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            extensionOffset = 0;
            status = ReadUint16(extension, extensionLength, &extensionOffset, &serverHello.SelectedPskIdentity);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = context.SetCipherSuite(serverHello.CipherSuite);
        if (NT_SUCCESS(status)) {
            status = context.SetServerRandom(serverHello.Random);
        }
        if (NT_SUCCESS(status)) {
            context.SetState(TlsHandshakeState::ServerHelloReceived);
        }
        return status;
    }

    NTSTATUS TlsHandshake13::ValidateServerHelloOffer(
        const Tls13ServerHelloView& serverHello,
        const Tls13ClientHelloOptions& clientHello) noexcept
    {
        const TlsCipherSuite* cipherSuites =
            clientHello.CipherSuites != nullptr ? clientHello.CipherSuites : DefaultCipherSuites;
        const SIZE_T cipherSuiteCount =
            clientHello.CipherSuites != nullptr ?
            clientHello.CipherSuiteCount :
            sizeof(DefaultCipherSuites) / sizeof(DefaultCipherSuites[0]);
        if (!ContainsCipherSuite(cipherSuites, cipherSuiteCount, serverHello.CipherSuite)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (serverHello.SessionIdLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (serverHello.IsHelloRetryRequest) {
            const TlsNamedGroup* namedGroups =
                clientHello.NamedGroups != nullptr ? clientHello.NamedGroups : DefaultNamedGroups;
            const SIZE_T namedGroupCount =
                clientHello.NamedGroups != nullptr ?
                clientHello.NamedGroupCount :
                sizeof(DefaultNamedGroups) / sizeof(DefaultNamedGroups[0]);
            if (!ContainsNamedGroup(namedGroups, namedGroupCount, serverHello.RetryGroup) ||
                ContainsKeyShareGroup(clientHello.KeyShares, clientHello.KeyShareCount, serverHello.RetryGroup)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else if (!ContainsKeyShareGroup(clientHello.KeyShares, clientHello.KeyShareCount, serverHello.KeyShare.Group)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ValidateSelectedPskIdentity(
        const Tls13ServerHelloView& serverHello,
        SIZE_T offeredPskIdentityCount) noexcept
    {
        if (serverHello.SelectedPskIdentity == 0xffff) {
            return STATUS_SUCCESS;
        }

        if (offeredPskIdentityCount == 0 ||
            offeredPskIdentityCount > 0xffff ||
            static_cast<SIZE_T>(serverHello.SelectedPskIdentity) >= offeredPskIdentityCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ComputePskBinder(
        const TlsContext& context,
        const UCHAR* resumptionSecret,
        SIZE_T resumptionSecretLength,
        const UCHAR* partialClientHelloHash,
        SIZE_T partialClientHelloHashLength,
        UCHAR* binder,
        SIZE_T binderCapacity,
        SIZE_T* binderLength) noexcept
    {
        if (binderLength != nullptr) {
            *binderLength = 0;
        }
        if (resumptionSecret == nullptr ||
            resumptionSecretLength == 0 ||
            partialClientHelloHash == nullptr ||
            partialClientHelloHashLength == 0 ||
            binder == nullptr ||
            binderLength == nullptr ||
            binderCapacity < HashLength(HashForCipherSuite(context.CipherSuite()))) {
            return STATUS_INVALID_PARAMETER;
        }

        const crypto::HashAlgorithm algorithm = HashForCipherSuite(context.CipherSuite());
        const SIZE_T digestLength = HashLength(algorithm);
        if (partialClientHelloHashLength != digestLength) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> earlySecret(Tls13MaxSecretLength);
        HeapArray<UCHAR> binderKey(Tls13MaxSecretLength);
        HeapArray<UCHAR> emptyHash(Tls13MaxHashLength);
        HeapArray<UCHAR> finishedKey(Tls13MaxSecretLength);
        if (!earlySecret.IsValid() || !binderKey.IsValid() || !emptyHash.IsValid() || !finishedKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T earlySecretLength = 0;
        NTSTATUS status = crypto::CngProvider::HkdfExtract(
            algorithm,
            nullptr,
            0,
            resumptionSecret,
            resumptionSecretLength,
            earlySecret.Get(),
            earlySecret.Count(),
            &earlySecretLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T emptyHashLength = 0;
        status = crypto::CngProvider::Hash(
            algorithm,
            nullptr,
            0,
            emptyHash.Get(),
            emptyHash.Count(),
            &emptyHashLength);
        if (!NT_SUCCESS(status) || emptyHashLength != digestLength) {
            RtlSecureZeroMemory(earlySecret.Get(), earlySecret.Count());
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        status = DeriveSecret(
            algorithm,
            earlySecret.Get(),
            earlySecretLength,
            "res binder",
            emptyHash.Get(),
            emptyHashLength,
            binderKey.Get(),
            digestLength);
        RtlSecureZeroMemory(emptyHash.Get(), emptyHash.Count());
        RtlSecureZeroMemory(earlySecret.Get(), earlySecret.Count());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = HkdfExpandLabel(
            algorithm,
            binderKey.Get(),
            digestLength,
            "finished",
            nullptr,
            0,
            finishedKey.Get(),
            digestLength);
        RtlSecureZeroMemory(binderKey.Get(), binderKey.Count());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T written = 0;
        status = crypto::CngProvider::Hmac(
            algorithm,
            finishedKey.Get(),
            digestLength,
            partialClientHelloHash,
            partialClientHelloHashLength,
            binder,
            binderCapacity,
            &written);
        RtlSecureZeroMemory(finishedKey.Get(), finishedKey.Count());
        if (NT_SUCCESS(status)) {
            *binderLength = written;
        }
        return status;
    }

    NTSTATUS TlsHandshake13::FindPskBinderTranscriptLength(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength,
        SIZE_T* transcriptLength) noexcept
    {
        if (transcriptLength != nullptr) {
            *transcriptLength = 0;
        }
        if (clientHello == nullptr || transcriptLength == nullptr || clientHelloLength < TlsHandshakeHeaderLength) {
            return STATUS_INVALID_PARAMETER;
        }

        TlsHandshakeMessageView parsed = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(clientHello, clientHelloLength, parsed);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (parsed.Type != TlsHandshakeType::ClientHello ||
            parsed.BytesConsumed != clientHelloLength ||
            parsed.Body == nullptr ||
            parsed.BodyLength < 42) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T offset = 34;
        UCHAR sessionIdLength = 0;
        status = ReadByte(parsed.Body, parsed.BodyLength, &offset, &sessionIdLength);
        if (NT_SUCCESS(status)) {
            const UCHAR* ignored = nullptr;
            status = ReadBytes(parsed.Body, parsed.BodyLength, &offset, sessionIdLength, &ignored);
        }

        USHORT cipherSuitesLength = 0;
        if (NT_SUCCESS(status)) {
            status = ReadUint16(parsed.Body, parsed.BodyLength, &offset, &cipherSuitesLength);
        }
        if (NT_SUCCESS(status)) {
            const UCHAR* ignored = nullptr;
            status = ReadBytes(parsed.Body, parsed.BodyLength, &offset, cipherSuitesLength, &ignored);
        }

        UCHAR compressionMethodsLength = 0;
        if (NT_SUCCESS(status)) {
            status = ReadByte(parsed.Body, parsed.BodyLength, &offset, &compressionMethodsLength);
        }
        if (NT_SUCCESS(status)) {
            const UCHAR* ignored = nullptr;
            status = ReadBytes(parsed.Body, parsed.BodyLength, &offset, compressionMethodsLength, &ignored);
        }

        USHORT extensionsLength = 0;
        if (NT_SUCCESS(status)) {
            status = ReadUint16(parsed.Body, parsed.BodyLength, &offset, &extensionsLength);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (extensionsLength != parsed.BodyLength - offset) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T extensionsStart = offset;
        const SIZE_T extensionsEnd = extensionsStart + extensionsLength;
        while (offset < extensionsEnd) {
            if (extensionsEnd - offset < 4) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            USHORT extensionType = 0;
            USHORT extensionLength = 0;
            status = ReadUint16(parsed.Body, parsed.BodyLength, &offset, &extensionType);
            if (NT_SUCCESS(status)) {
                status = ReadUint16(parsed.Body, parsed.BodyLength, &offset, &extensionLength);
            }
            if (!NT_SUCCESS(status) || extensionLength > extensionsEnd - offset) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            if (extensionType != ExtensionPreSharedKey) {
                offset += extensionLength;
                continue;
            }

            if (offset + extensionLength != extensionsEnd || extensionLength < 4) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T pskOffset = offset;
            USHORT identitiesLength = 0;
            status = ReadUint16(parsed.Body, parsed.BodyLength, &pskOffset, &identitiesLength);
            if (!NT_SUCCESS(status) || identitiesLength == 0 || identitiesLength > extensionLength - 2) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            const UCHAR* ignored = nullptr;
            status = ReadBytes(parsed.Body, parsed.BodyLength, &pskOffset, identitiesLength, &ignored);
            if (!NT_SUCCESS(status) || extensionLength - (pskOffset - offset) < 2) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            USHORT bindersLength = 0;
            status = ReadUint16(parsed.Body, parsed.BodyLength, &pskOffset, &bindersLength);
            if (!NT_SUCCESS(status) || bindersLength == 0 || bindersLength != extensionLength - (pskOffset - offset)) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }

            *transcriptLength = TlsHandshakeHeaderLength + pskOffset - 2;
            return STATUS_SUCCESS;
        }

        return STATUS_NOT_FOUND;
    }

    NTSTATUS TlsHandshake13::ParseEncryptedExtensions(
        const TlsHandshakeMessageView& message,
        Tls13EncryptedExtensionsView& encryptedExtensions) noexcept
    {
        encryptedExtensions = {};
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::EncryptedExtensions);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        USHORT extensionsLength = 0;
        status = ReadUint16(message.Body, message.BodyLength, &offset, &extensionsLength);
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, extensionsLength, &encryptedExtensions.Extensions);
        }
        if (!NT_SUCCESS(status) || offset != message.BodyLength) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        encryptedExtensions.ExtensionsLength = extensionsLength;
        status = ValidateNoDuplicateExtensions(encryptedExtensions.Extensions, encryptedExtensions.ExtensionsLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        bool found = false;
        status = FindExtension(encryptedExtensions.Extensions, encryptedExtensions.ExtensionsLength, ExtensionAlpn, &extension, &extensionLength, &found);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (found) {
            status = ParseAlpnExtension(extension, extensionLength, &encryptedExtensions.Alpn, &encryptedExtensions.AlpnLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = FindExtension(encryptedExtensions.Extensions, encryptedExtensions.ExtensionsLength, ExtensionEarlyData, &extension, &extensionLength, &found);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (found) {
            if (extensionLength != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            encryptedExtensions.EarlyDataAccepted = true;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ParseCertificateRequest(
        const TlsHandshakeMessageView& message,
        Tls13CertificateRequestView& certificateRequest) noexcept
    {
        certificateRequest = {};
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::CertificateRequest);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        UCHAR contextLength = 0;
        status = ReadByte(message.Body, message.BodyLength, &offset, &contextLength);
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, contextLength, &certificateRequest.Context);
        }
        USHORT extensionsLength = 0;
        if (NT_SUCCESS(status)) {
            status = ReadUint16(message.Body, message.BodyLength, &offset, &extensionsLength);
        }
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, extensionsLength, &certificateRequest.Extensions);
        }
        if (!NT_SUCCESS(status) || offset != message.BodyLength) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        certificateRequest.ContextLength = contextLength;
        certificateRequest.ExtensionsLength = extensionsLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ParseCertificate(
        const TlsHandshakeMessageView& message,
        Tls13CertificateView& certificate) noexcept
    {
        certificate = {};
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::Certificate);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        UCHAR contextLength = 0;
        status = ReadByte(message.Body, message.BodyLength, &offset, &contextLength);
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, contextLength, &certificate.RequestContext);
        }

        SIZE_T listLength = 0;
        if (NT_SUCCESS(status)) {
            status = ReadUint24(message.Body, message.BodyLength, &offset, &listLength);
        }
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, listLength, &certificate.Certificates);
        }
        if (!NT_SUCCESS(status) || offset != message.BodyLength || listLength == 0) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        certificate.RequestContextLength = contextLength;
        certificate.CertificatesLength = listLength;

        SIZE_T certificateOffset = 0;
        while (certificateOffset < certificate.CertificatesLength) {
            SIZE_T certLength = 0;
            status = ReadUint24(certificate.Certificates, certificate.CertificatesLength, &certificateOffset, &certLength);
            if (!NT_SUCCESS(status) || certLength == 0) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            const UCHAR* certData = nullptr;
            status = ReadBytes(certificate.Certificates, certificate.CertificatesLength, &certificateOffset, certLength, &certData);
            USHORT certExtensionsLength = 0;
            if (NT_SUCCESS(status)) {
                status = ReadUint16(certificate.Certificates, certificate.CertificatesLength, &certificateOffset, &certExtensionsLength);
            }
            const UCHAR* certExtensions = nullptr;
            if (NT_SUCCESS(status)) {
                status = ReadBytes(certificate.Certificates, certificate.CertificatesLength, &certificateOffset, certExtensionsLength, &certExtensions);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            UNREFERENCED_PARAMETER(certData);
            UNREFERENCED_PARAMETER(certExtensions);
            ++certificate.CertificateCount;
        }

        return certificate.CertificateCount == 0 ? STATUS_INVALID_NETWORK_RESPONSE : STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::EncodeEmptyCertificate(
        const UCHAR* requestContext,
        SIZE_T requestContextLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if ((requestContext == nullptr && requestContextLength != 0) ||
            requestContextLength > 255) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T bodyLength = 1 + requestContextLength + 3;
        const SIZE_T required = TlsHandshakeHeaderLength + bodyLength;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        NTSTATUS status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::Certificate), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(static_cast<ULONG>(bodyLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteByte(static_cast<UCHAR>(requestContextLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status) && requestContextLength != 0) {
            status = WriteBytes(requestContext, requestContextLength, destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteUint24(0, destination, destinationCapacity, &offset);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = offset;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::EncodeCertificate(
        const UCHAR* requestContext,
        SIZE_T requestContextLength,
        const UCHAR* certificateList,
        SIZE_T certificateListLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!IsValidBuffer(requestContext, requestContextLength) ||
            !IsValidBuffer(certificateList, certificateListLength) ||
            requestContextLength > 255 ||
            certificateListLength > TlsMaxHandshakeMessageLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T bodyLength = 1 + requestContextLength + 3 + certificateListLength;
        if (bodyLength > TlsMaxHandshakeMessageLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T required = TlsHandshakeHeaderLength + bodyLength;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        NTSTATUS status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::Certificate), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(static_cast<ULONG>(bodyLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteByte(static_cast<UCHAR>(requestContextLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteBytes(requestContext, requestContextLength, destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteUint24(static_cast<ULONG>(certificateListLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteBytes(certificateList, certificateListLength, destination, destinationCapacity, &offset);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = offset;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::EncodeCertificateVerify(
        TlsSignatureScheme signatureScheme,
        const UCHAR* signature,
        SIZE_T signatureLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (signature == nullptr || signatureLength == 0 || signatureLength > 0xffff) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T bodyLength = sizeof(USHORT) + sizeof(USHORT) + signatureLength;
        const SIZE_T required = TlsHandshakeHeaderLength + bodyLength;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        NTSTATUS status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::CertificateVerify), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(static_cast<ULONG>(bodyLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteUint16(static_cast<USHORT>(signatureScheme), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteUint16(static_cast<USHORT>(signatureLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteBytes(signature, signatureLength, destination, destinationCapacity, &offset);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = offset;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::EncodeEndOfEarlyData(
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        const SIZE_T required = TlsHandshakeHeaderLength;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        NTSTATUS status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::EndOfEarlyData), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(0, destination, destinationCapacity, &offset);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = offset;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ParseCertificateVerify(
        const TlsHandshakeMessageView& message,
        Tls13CertificateVerifyView& certificateVerify) noexcept
    {
        certificateVerify = {};
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::CertificateVerify);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        USHORT scheme = 0;
        USHORT signatureLength = 0;
        status = ReadUint16(message.Body, message.BodyLength, &offset, &scheme);
        if (NT_SUCCESS(status)) {
            status = ReadUint16(message.Body, message.BodyLength, &offset, &signatureLength);
        }
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, signatureLength, &certificateVerify.Signature);
        }
        if (!NT_SUCCESS(status) || offset != message.BodyLength || signatureLength == 0) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        certificateVerify.SignatureScheme = static_cast<TlsSignatureScheme>(scheme);
        certificateVerify.SignatureLength = signatureLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ParseKeyUpdate(
        const TlsHandshakeMessageView& message,
        Tls13KeyUpdateView& keyUpdate) noexcept
    {
        keyUpdate = {};
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::KeyUpdate);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (message.BodyLength != 1) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T offset = 0;
        UCHAR request = 0xff;
        status = ReadByte(message.Body, message.BodyLength, &offset, &request);
        if (!NT_SUCCESS(status) || offset != message.BodyLength) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        if (request != static_cast<UCHAR>(Tls13KeyUpdateRequest::UpdateNotRequested) &&
            request != static_cast<UCHAR>(Tls13KeyUpdateRequest::UpdateRequested)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        keyUpdate.Request = static_cast<Tls13KeyUpdateRequest>(request);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::EncodeKeyUpdate(
        Tls13KeyUpdateRequest request,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (request != Tls13KeyUpdateRequest::UpdateNotRequested &&
            request != Tls13KeyUpdateRequest::UpdateRequested) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T required = TlsHandshakeHeaderLength + 1;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        NTSTATUS status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::KeyUpdate), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(1, destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteByte(static_cast<UCHAR>(request), destination, destinationCapacity, &offset);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = offset;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ParseNewSessionTicket(
        const TlsHandshakeMessageView& message,
        Tls13NewSessionTicketView& ticket) noexcept
    {
        ticket = {};
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::NewSessionTicket);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        status = ReadUint32(message.Body, message.BodyLength, &offset, &ticket.LifetimeSeconds);
        if (NT_SUCCESS(status)) {
            status = ReadUint32(message.Body, message.BodyLength, &offset, &ticket.AgeAdd);
        }
        UCHAR nonceLength = 0;
        if (NT_SUCCESS(status)) {
            status = ReadByte(message.Body, message.BodyLength, &offset, &nonceLength);
        }
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, nonceLength, &ticket.Nonce);
        }
        USHORT ticketLength = 0;
        if (NT_SUCCESS(status)) {
            status = ReadUint16(message.Body, message.BodyLength, &offset, &ticketLength);
        }
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, ticketLength, &ticket.Ticket);
        }
        USHORT extensionsLength = 0;
        const UCHAR* extensions = nullptr;
        if (NT_SUCCESS(status)) {
            status = ReadUint16(message.Body, message.BodyLength, &offset, &extensionsLength);
        }
        if (NT_SUCCESS(status)) {
            status = ReadBytes(message.Body, message.BodyLength, &offset, extensionsLength, &extensions);
        }
        if (!NT_SUCCESS(status) || offset != message.BodyLength || ticketLength == 0) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        status = ValidateNoDuplicateExtensions(extensions, extensionsLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ticket.NonceLength = nonceLength;
        ticket.TicketLength = ticketLength;

        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        bool found = false;
        status = FindExtension(extensions, extensionsLength, ExtensionEarlyData, &extension, &extensionLength, &found);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (found) {
            if (extensionLength != 4) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            SIZE_T extensionOffset = 0;
            status = ReadUint32(extension, extensionLength, &extensionOffset, &ticket.MaxEarlyDataSize);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake13::ParseNextNewSessionTicket(
        const UCHAR* data,
        SIZE_T dataLength,
        SIZE_T* offset,
        Tls13NewSessionTicketView& ticket) noexcept
    {
        ticket = {};
        if (data == nullptr || offset == nullptr || *offset >= dataLength) {
            return STATUS_INVALID_PARAMETER;
        }

        TlsHandshakeMessageView message = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(
            data + *offset,
            dataLength - *offset,
            message);
        if (status == STATUS_MORE_PROCESSING_REQUIRED) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (message.BytesConsumed == 0 ||
            message.BytesConsumed > dataLength - *offset ||
            message.Type != TlsHandshakeType::NewSessionTicket) {
            return STATUS_NOT_SUPPORTED;
        }

        status = ParseNewSessionTicket(message, ticket);
        if (NT_SUCCESS(status)) {
            *offset += message.BytesConsumed;
        }

        return status;
    }

    NTSTATUS TlsHandshake13::EncodeFinished(
        const TlsContext& context,
        bool clientFinished,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }
        if (!IsValidBuffer(transcriptHash, transcriptHashLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T verifyDataLength = context.Tls13Secrets().SecretLength;
        const SIZE_T required = TlsHandshakeHeaderLength + verifyDataLength;
        if (verifyDataLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        HeapArray<UCHAR> verifyData(Tls13MaxSecretLength);
        if (!verifyData.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = ComputeFinishedData(
            context,
            clientFinished,
            transcriptHash,
            transcriptHashLength,
            verifyData.Get(),
            verifyDataLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::Finished), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(static_cast<ULONG>(verifyDataLength), destination, destinationCapacity, &offset);
        }
        if (NT_SUCCESS(status)) {
            status = WriteBytes(verifyData.Get(), verifyDataLength, destination, destinationCapacity, &offset);
        }
        RtlSecureZeroMemory(verifyData.Get(), verifyData.Count());
        if (NT_SUCCESS(status) && bytesWritten != nullptr) {
            *bytesWritten = offset;
        }
        return status;
    }

    NTSTATUS TlsHandshake13::VerifyFinished(
        const TlsContext& context,
        bool clientFinished,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength,
        const UCHAR* verifyData,
        SIZE_T verifyDataLength) noexcept
    {
        if (verifyData == nullptr ||
            verifyDataLength == 0 ||
            verifyDataLength != context.Tls13Secrets().SecretLength ||
            !IsValidBuffer(transcriptHash, transcriptHashLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> expected(Tls13MaxSecretLength);
        if (!expected.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = ComputeFinishedData(
            context,
            clientFinished,
            transcriptHash,
            transcriptHashLength,
            expected.Get(),
            verifyDataLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool matches = MemoryEquals(expected.Get(), verifyData, verifyDataLength);
        RtlSecureZeroMemory(expected.Get(), expected.Count());
        return matches ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }

    NTSTATUS TlsHandshake13::BuildCertificateVerifyInput(
        bool server,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }
        if (!IsValidBuffer(transcriptHash, transcriptHashLength) || destination == nullptr || bytesWritten == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const char* context = server ?
            "TLS 1.3, server CertificateVerify" :
            "TLS 1.3, client CertificateVerify";
        const SIZE_T contextLength = StringLength(context);
        const SIZE_T required = 64 + contextLength + 1 + transcriptHashLength;
        if (destinationCapacity < required) {
            *bytesWritten = required;
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        for (SIZE_T index = 0; index < 64; ++index) {
            destination[offset++] = 0x20;
        }
        RtlCopyMemory(destination + offset, context, contextLength);
        offset += contextLength;
        destination[offset++] = 0;
        if (transcriptHashLength != 0) {
            RtlCopyMemory(destination + offset, transcriptHash, transcriptHashLength);
            offset += transcriptHashLength;
        }
        *bytesWritten = offset;
        return STATUS_SUCCESS;
    }
}
}
