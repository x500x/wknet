#include <KernelHttp/tls/TlsHandshake12.h>
#include <KernelHttp/crypto/KeyExchange.h>
#include <KernelHttp/tls/TlsCapabilities.h>

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        constexpr UCHAR NullCompressionMethod = 0;
        constexpr USHORT ExtensionServerName = 0;
        constexpr USHORT ExtensionSupportedGroups = 10;
        constexpr USHORT ExtensionEcPointFormats = 11;
        constexpr USHORT ExtensionSignatureAlgorithms = 13;
        constexpr USHORT ExtensionStatusRequest = 5;
        constexpr USHORT ExtensionEncryptThenMac = 22;
        constexpr USHORT ExtensionSessionTicket = 35;
        constexpr USHORT ExtensionAlpn = 16;
        constexpr USHORT ExtensionExtendedMasterSecret = 23;
        constexpr USHORT ExtensionRenegotiationInfo = 0xff01;

        const TlsCipherSuite DefaultCipherSuites[] = {
            TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
            TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
            TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
            TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
            TlsCipherSuite::TlsDheRsaWithAes128GcmSha256,
            TlsCipherSuite::TlsDheRsaWithAes256GcmSha384,
            TlsCipherSuite::TlsDheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256,
            TlsCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256
        };

        const TlsNamedGroup DefaultNamedGroups[] = {
            TlsNamedGroup::Secp256r1,
            TlsNamedGroup::Secp384r1,
            TlsNamedGroup::Secp521r1,
            TlsNamedGroup::X25519,
            TlsNamedGroup::X448,
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
            TlsSignatureScheme::RsaPkcs1Sha256,
            TlsSignatureScheme::EcdsaSecp256r1Sha256,
            TlsSignatureScheme::RsaPkcs1Sha384,
            TlsSignatureScheme::EcdsaSecp384r1Sha384,
            TlsSignatureScheme::RsaPkcs1Sha512,
            TlsSignatureScheme::EcdsaSecp521r1Sha512,
            TlsSignatureScheme::Ed25519,
            TlsSignatureScheme::Ed448
        };

        _Must_inspect_result_
        Tls12KeyExchangeKind KeyExchangeForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
            return capability != nullptr ? capability->Tls12KeyExchange : Tls12KeyExchangeKind::None;
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
        SIZE_T ReadUint24(_In_reads_bytes_(3) const UCHAR* data) noexcept
        {
            return (static_cast<SIZE_T>(data[0]) << 16) |
                (static_cast<SIZE_T>(data[1]) << 8) |
                data[2];
        }

        _Must_inspect_result_
        bool IsSupportedCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
            return capability != nullptr && capability->Protocol == TlsProtocol::Tls12;
        }

        _Must_inspect_result_
        bool IsSupportedNamedGroup(TlsNamedGroup namedGroup) noexcept
        {
            return TlsIsKnownNamedGroup(namedGroup);
        }

        _Must_inspect_result_
        bool IsSupportedSignatureScheme(TlsSignatureScheme signatureScheme) noexcept
        {
            return TlsIsKnownSignatureScheme(signatureScheme);
        }

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
        bool ContainsSignatureScheme(
            _In_reads_(signatureSchemeCount) const TlsSignatureScheme* signatureSchemes,
            SIZE_T signatureSchemeCount,
            TlsSignatureScheme selected) noexcept
        {
            if (signatureSchemes == nullptr || signatureSchemeCount == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < signatureSchemeCount; ++index) {
                if (signatureSchemes[index] == selected) {
                    return true;
                }
            }
            return false;
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
        NTSTATUS ReadUint16Value(
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
        NTSTATUS ReadUint24Value(
            _In_reads_bytes_(capacity) const UCHAR* source,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset,
            _Out_ SIZE_T* value) noexcept
        {
            if (source == nullptr || offset == nullptr || value == nullptr || !HasCapacity(capacity, *offset, 3)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            *value = ReadUint24(source + *offset);
            *offset += 3;
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
        NTSTATUS ValidateHandshakeType(
            _In_ const TlsHandshakeMessageView& message,
            TlsHandshakeType expected) noexcept
        {
            if (message.Type != expected || (message.Body == nullptr && message.BodyLength != 0)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS PHash(
            crypto::HashAlgorithm algorithm,
            _In_reads_bytes_(secretLength) const UCHAR* secret,
            SIZE_T secretLength,
            _In_reads_bytes_(seedLength) const UCHAR* seed,
            SIZE_T seedLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept
        {
            if (secret == nullptr ||
                secretLength == 0 ||
                !IsValidBuffer(seed, seedLength) ||
                output == nullptr ||
                outputLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapArray<UCHAR> a(TlsMaxTranscriptHashLength);
            HeapArray<UCHAR> hmac(TlsMaxTranscriptHashLength);
            HeapArray<UCHAR> hmacSeed(TlsMaxTranscriptHashLength + 256);
            if (!a.IsValid() || !hmac.IsValid() || !hmacSeed.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T aLength = 0;
            SIZE_T hmacLength = 0;

            NTSTATUS status = crypto::CngProvider::Hmac(
                algorithm,
                secret,
                secretLength,
                seed,
                seedLength,
                a.Get(),
                a.Count(),
                &aLength);

            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T produced = 0;
            while (produced < outputLength) {
                RtlZeroMemory(hmacSeed.Get(), hmacSeed.Count());
                if (seedLength > hmacSeed.Count() - aLength) {
                    RtlSecureZeroMemory(a.Get(), a.Count());
                    return STATUS_INVALID_PARAMETER;
                }

                RtlCopyMemory(hmacSeed.Get(), a.Get(), aLength);
                if (seedLength != 0) {
                    RtlCopyMemory(hmacSeed.Get() + aLength, seed, seedLength);
                }

                status = crypto::CngProvider::Hmac(
                    algorithm,
                    secret,
                    secretLength,
                    hmacSeed.Get(),
                    aLength + seedLength,
                    hmac.Get(),
                    hmac.Count(),
                    &hmacLength);

                RtlSecureZeroMemory(hmacSeed.Get(), hmacSeed.Count());
                if (!NT_SUCCESS(status)) {
                    break;
                }

                const SIZE_T copyLength =
                    hmacLength < (outputLength - produced) ? hmacLength : (outputLength - produced);
                RtlCopyMemory(output + produced, hmac.Get(), copyLength);
                produced += copyLength;

                status = crypto::CngProvider::Hmac(
                    algorithm,
                    secret,
                    secretLength,
                    a.Get(),
                    aLength,
                    a.Get(),
                    a.Count(),
                    &aLength);

                if (!NT_SUCCESS(status)) {
                    break;
                }
            }

            RtlSecureZeroMemory(a.Get(), a.Count());
            RtlSecureZeroMemory(hmac.Get(), hmac.Count());

            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildServerNameExtension(
            _In_ const TlsClientHelloOptions& options,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (options.ServerName == nullptr || options.ServerNameLength == 0) {
                return STATUS_SUCCESS;
            }

            if (options.ServerNameLength > 0xffff - 5 ||
                !IsValidSniDnsName(options.ServerName, options.ServerNameLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = WriteUint16(ExtensionServerName, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const SIZE_T extensionLengthOffset = *offset;
            status = WriteUint16(0, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const USHORT serverNameListLength = static_cast<USHORT>(options.ServerNameLength + 3);
            status = WriteUint16(serverNameListLength, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = WriteByte(0, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = WriteUint16(static_cast<USHORT>(options.ServerNameLength), destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = WriteBytes(
                reinterpret_cast<const UCHAR*>(options.ServerName),
                options.ServerNameLength,
                destination,
                capacity,
                offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const USHORT extensionLength = static_cast<USHORT>(options.ServerNameLength + 5);
            destination[extensionLengthOffset] = static_cast<UCHAR>((extensionLength >> 8) & 0xff);
            destination[extensionLengthOffset + 1] = static_cast<UCHAR>(extensionLength & 0xff);
            return STATUS_SUCCESS;
        }

        template <typename TValue>
        _Must_inspect_result_
        NTSTATUS BuildUint16VectorExtension(
            USHORT extensionType,
            _In_reads_(valueCount) const TValue* values,
            SIZE_T valueCount,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (values == nullptr || valueCount == 0) {
                return STATUS_SUCCESS;
            }

            if (valueCount > 0x7fff) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = WriteUint16(extensionType, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const USHORT vectorLength = static_cast<USHORT>(valueCount * sizeof(USHORT));
            const USHORT extensionLength = static_cast<USHORT>(vectorLength + sizeof(USHORT));

            status = WriteUint16(extensionLength, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = WriteUint16(vectorLength, destination, capacity, offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            for (SIZE_T index = 0; index < valueCount; ++index) {
                status = WriteUint16(static_cast<USHORT>(values[index]), destination, capacity, offset);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS BuildEcPointFormatsExtension(
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            NTSTATUS status = WriteUint16(ExtensionEcPointFormats, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(2, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(1, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(0, destination, capacity, offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildEmptyExtension(
            USHORT extensionType,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            NTSTATUS status = WriteUint16(extensionType, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }

            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildSessionTicketExtension(
            _In_ const TlsClientHelloOptions& options,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (!IsValidBuffer(options.SessionTicket, options.SessionTicketLength) ||
                options.SessionTicketLength > 0xffff) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = WriteUint16(ExtensionSessionTicket, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(static_cast<USHORT>(options.SessionTicketLength), destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteBytes(options.SessionTicket, options.SessionTicketLength, destination, capacity, offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildStatusRequestExtension(
            bool offerStatusRequest,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (!offerStatusRequest) {
                return STATUS_SUCCESS;
            }

            NTSTATUS status = WriteUint16(ExtensionStatusRequest, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(5, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(1, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteUint16(0, destination, capacity, offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS BuildAlpnExtension(
            _In_ const TlsClientHelloOptions& options,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (options.AlpnProtocols == nullptr || options.AlpnProtocolCount == 0) {
                return STATUS_SUCCESS;
            }

            // Compute total list length
            SIZE_T listLength = 0;
            for (SIZE_T i = 0; i < options.AlpnProtocolCount; ++i) {
                const TlsAlpnProtocol& proto = options.AlpnProtocols[i];
                if (proto.Name == nullptr || proto.NameLength == 0 || proto.NameLength > 255) {
                    return STATUS_INVALID_PARAMETER;
                }
                listLength += 1 + proto.NameLength;
            }

            if (listLength > 0xfffd) {
                return STATUS_INVALID_PARAMETER;
            }

            const USHORT extensionLength = static_cast<USHORT>(listLength + 2);

            NTSTATUS status = WriteUint16(ExtensionAlpn, destination, capacity, offset);
            if (!NT_SUCCESS(status)) return status;

            status = WriteUint16(extensionLength, destination, capacity, offset);
            if (!NT_SUCCESS(status)) return status;

            status = WriteUint16(static_cast<USHORT>(listLength), destination, capacity, offset);
            if (!NT_SUCCESS(status)) return status;

            for (SIZE_T i = 0; i < options.AlpnProtocolCount; ++i) {
                const TlsAlpnProtocol& proto = options.AlpnProtocols[i];
                status = WriteByte(static_cast<UCHAR>(proto.NameLength), destination, capacity, offset);
                if (!NT_SUCCESS(status)) return status;
                status = WriteBytes(
                    reinterpret_cast<const UCHAR*>(proto.Name),
                    proto.NameLength,
                    destination,
                    capacity,
                    offset);
                if (!NT_SUCCESS(status)) return status;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS BuildRenegotiationInfoExtension(
            _In_ const TlsClientHelloOptions& options,
            _Out_writes_bytes_(capacity) UCHAR* destination,
            SIZE_T capacity,
            _Inout_ SIZE_T* offset) noexcept
        {
            if (!IsValidBuffer(options.RenegotiationInfo, options.RenegotiationInfoLength) ||
                options.RenegotiationInfoLength > 255) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = WriteUint16(ExtensionRenegotiationInfo, destination, capacity, offset);
            if (NT_SUCCESS(status)) {
                status = WriteUint16(static_cast<USHORT>(1 + options.RenegotiationInfoLength), destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteByte(static_cast<UCHAR>(options.RenegotiationInfoLength), destination, capacity, offset);
            }
            if (NT_SUCCESS(status)) {
                status = WriteBytes(
                    options.RenegotiationInfo,
                    options.RenegotiationInfoLength,
                    destination,
                    capacity,
                    offset);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS ParseServerHelloExtensions(_Inout_ TlsServerHelloView& serverHello) noexcept
        {
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

                const SIZE_T currentOffset = offset;
                const USHORT extensionType = static_cast<USHORT>(
                    (static_cast<USHORT>(serverHello.Extensions[offset]) << 8) |
                    serverHello.Extensions[offset + 1]);
                const SIZE_T extensionLength =
                    (static_cast<SIZE_T>(serverHello.Extensions[offset + 2]) << 8) |
                    serverHello.Extensions[offset + 3];
                offset += 4;
                if (extensionLength > serverHello.ExtensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                SIZE_T priorOffset = 0;
                while (priorOffset < currentOffset) {
                    if (currentOffset - priorOffset < 4) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const USHORT priorType = static_cast<USHORT>(
                        (static_cast<USHORT>(serverHello.Extensions[priorOffset]) << 8) |
                        serverHello.Extensions[priorOffset + 1]);
                    const SIZE_T priorLength =
                        (static_cast<SIZE_T>(serverHello.Extensions[priorOffset + 2]) << 8) |
                        serverHello.Extensions[priorOffset + 3];
                    priorOffset += 4;
                    if (priorLength > currentOffset - priorOffset) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (priorType == extensionType) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    priorOffset += priorLength;
                }

                if (extensionType == ExtensionExtendedMasterSecret) {
                    if (extensionLength != 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    serverHello.HasExtendedMasterSecret = true;
                }
                else if (extensionType == ExtensionRenegotiationInfo) {
                    if (extensionLength == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T renegotiationInfoLength = serverHello.Extensions[offset];
                    if (renegotiationInfoLength + 1 != extensionLength) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    serverHello.HasSecureRenegotiation = true;
                    serverHello.SecureRenegotiationData = serverHello.Extensions + offset + 1;
                    serverHello.SecureRenegotiationDataLength = renegotiationInfoLength;
                }
                else if (extensionType == ExtensionEncryptThenMac) {
                    if (extensionLength != 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    serverHello.HasEncryptThenMac = true;
                }

                offset += extensionLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ComputeVerifyData(
            const TlsContext& context,
            bool clientFinished,
            const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength,
            UCHAR* verifyData,
            SIZE_T verifyDataLength) noexcept
        {
            const TlsSessionSecrets& secrets = context.Secrets();
            if (secrets.MasterSecretLength != TlsMasterSecretLength ||
                !IsValidBuffer(transcriptHash, transcriptHashLength) ||
                verifyData == nullptr ||
                verifyDataLength != TlsVerifyDataLength) {
                return STATUS_INVALID_PARAMETER;
            }

            return TlsHandshake12::Prf(
                TlsHandshake12::PrfHashForCipherSuite(secrets.CipherSuite),
                secrets.MasterSecret,
                secrets.MasterSecretLength,
                clientFinished ? "client finished" : "server finished",
                transcriptHash,
                transcriptHashLength,
                verifyData,
                verifyDataLength);
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
    }

    NTSTATUS TlsTranscriptHash::Initialize(crypto::HashAlgorithm algorithm) noexcept
    {
        algorithm_ = algorithm;
        return hash_.Initialize(algorithm);
    }

    void TlsTranscriptHash::Reset() noexcept
    {
        hash_.Reset();
    }

    NTSTATUS TlsTranscriptHash::Update(const UCHAR* data, SIZE_T dataLength) noexcept
    {
        return hash_.Update(data, dataLength);
    }

    NTSTATUS TlsTranscriptHash::Finish(UCHAR* output, SIZE_T outputLength, SIZE_T* bytesWritten) const noexcept
    {
        return hash_.Finish(output, outputLength, bytesWritten);
    }

    crypto::HashAlgorithm TlsHandshake12::PrfHashForCipherSuite(TlsCipherSuite cipherSuite) noexcept
    {
        const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
        if (capability != nullptr && capability->PrfHash == TlsPrfHashKind::Sha384) {
            return crypto::HashAlgorithm::Sha384;
        }

        return crypto::HashAlgorithm::Sha256;
    }

    NTSTATUS TlsHandshake12::Prf(
        crypto::HashAlgorithm algorithm,
        const UCHAR* secret,
        SIZE_T secretLength,
        const char* label,
        const UCHAR* seed,
        SIZE_T seedLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        if (secret == nullptr ||
            secretLength == 0 ||
            label == nullptr ||
            !IsValidBuffer(seed, seedLength) ||
            output == nullptr ||
            outputLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T labelLength = StringLength(label);
        if (labelLength == 0 || labelLength + seedLength > 512) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> fullSeed(512);
        if (!fullSeed.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(fullSeed.Get(), label, labelLength);
        if (seedLength != 0) {
            RtlCopyMemory(fullSeed.Get() + labelLength, seed, seedLength);
        }

        NTSTATUS status = PHash(
            algorithm,
            secret,
            secretLength,
            fullSeed.Get(),
            labelLength + seedLength,
            output,
            outputLength);

        RtlSecureZeroMemory(fullSeed.Get(), fullSeed.Count());
        return status;
    }

    NTSTATUS TlsHandshake12::ParseMessage(
        const UCHAR* data,
        SIZE_T dataLength,
        TlsHandshakeMessageView& message) noexcept
    {
        message = {};

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength < TlsHandshakeHeaderLength) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        const SIZE_T bodyLength = ReadUint24(data + 1);
        if (bodyLength > TlsMaxHandshakeMessageLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (dataLength - TlsHandshakeHeaderLength < bodyLength) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        message.Type = static_cast<TlsHandshakeType>(data[0]);
        message.Body = data + TlsHandshakeHeaderLength;
        message.BodyLength = bodyLength;
        message.BytesConsumed = TlsHandshakeHeaderLength + bodyLength;

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::ParseNewSessionTicket(
        const TlsHandshakeMessageView& message,
        Tls12NewSessionTicketView& ticket) noexcept
    {
        ticket = {};

        if (message.Type != TlsHandshakeType::NewSessionTicket) {
            return STATUS_NOT_SUPPORTED;
        }
        if (message.Body == nullptr || message.BodyLength < 6) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T ticketLength =
            (static_cast<SIZE_T>(message.Body[4]) << 8) | message.Body[5];
        if (ticketLength != message.BodyLength - 6) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ticket.LifetimeHintSeconds =
            (static_cast<ULONG>(message.Body[0]) << 24) |
            (static_cast<ULONG>(message.Body[1]) << 16) |
            (static_cast<ULONG>(message.Body[2]) << 8) |
            message.Body[3];
        ticket.Ticket = message.Body + 6;
        ticket.TicketLength = ticketLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::ParseCertificateStatus(
        const TlsHandshakeMessageView& message,
        Tls12CertificateStatusView& certificateStatus) noexcept
    {
        certificateStatus = {};

        if (message.Type != TlsHandshakeType::CertificateStatus) {
            return STATUS_NOT_SUPPORTED;
        }
        if (message.Body == nullptr || message.BodyLength < 4) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        constexpr UCHAR CertificateStatusTypeOcsp = 1;
        if (message.Body[0] != CertificateStatusTypeOcsp) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T responseLength = ReadUint24(message.Body + 1);
        if (responseLength == 0 || responseLength != message.BodyLength - 4) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        certificateStatus.StatusType = message.Body[0];
        certificateStatus.OcspResponse = message.Body + 4;
        certificateStatus.OcspResponseLength = responseLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::EncodeClientHello(
        TlsContext& context,
        const TlsClientHelloOptions& options,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        const TlsCipherSuite* cipherSuites =
            options.CipherSuites != nullptr ? options.CipherSuites : DefaultCipherSuites;
        SIZE_T cipherSuiteCount =
            options.CipherSuites != nullptr ? options.CipherSuiteCount : (sizeof(DefaultCipherSuites) / sizeof(DefaultCipherSuites[0]));

        const TlsNamedGroup* namedGroups =
            options.NamedGroups != nullptr ? options.NamedGroups : DefaultNamedGroups;
        SIZE_T namedGroupCount =
            options.NamedGroups != nullptr ? options.NamedGroupCount : (sizeof(DefaultNamedGroups) / sizeof(DefaultNamedGroups[0]));

        const TlsSignatureScheme* signatureSchemes =
            options.SignatureSchemes != nullptr ? options.SignatureSchemes : DefaultSignatureSchemes;
        SIZE_T signatureSchemeCount =
            options.SignatureSchemes != nullptr ? options.SignatureSchemeCount : (sizeof(DefaultSignatureSchemes) / sizeof(DefaultSignatureSchemes[0]));

        if (cipherSuites == nullptr ||
            cipherSuiteCount == 0 ||
            cipherSuiteCount > 0x7fff ||
            namedGroupCount > 0x7fff ||
            signatureSchemeCount > 0x7fff ||
            options.SessionIdLength > Tls12MaxSessionIdLength ||
            !IsValidBuffer(options.SessionId, options.SessionIdLength) ||
            !IsValidBuffer(options.SessionTicket, options.SessionTicketLength) ||
            !IsValidBuffer(options.RenegotiationInfo, options.RenegotiationInfoLength) ||
            options.RenegotiationInfoLength > 255) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> body(1024);
        if (!body.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T offset = 0;

        NTSTATUS status = WriteByte(context.Version().Major, body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteByte(context.Version().Minor, body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteBytes(context.Secrets().ClientRandom, TlsRandomLength, body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteByte(static_cast<UCHAR>(options.SessionIdLength), body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteBytes(options.SessionId, options.SessionIdLength, body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteUint16(static_cast<USHORT>(cipherSuiteCount * sizeof(USHORT)), body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < cipherSuiteCount; ++index) {
            status = WriteUint16(static_cast<USHORT>(cipherSuites[index]), body.Get(), body.Count(), &offset);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = WriteByte(1, body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteByte(NullCompressionMethod, body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> extensions(512);
        if (!extensions.IsValid()) {
            RtlSecureZeroMemory(body.Get(), body.Count());
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T extensionOffset = 0;

        status = BuildServerNameExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildUint16VectorExtension(
            ExtensionSupportedGroups,
            namedGroups,
            namedGroupCount,
            extensions.Get(),
            extensions.Count(),
            &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildEcPointFormatsExtension(extensions.Get(), extensions.Count(), &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildUint16VectorExtension(
            ExtensionSignatureAlgorithms,
            signatureSchemes,
            signatureSchemeCount,
            extensions.Get(),
            extensions.Count(),
            &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildSessionTicketExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildAlpnExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildEmptyExtension(
            ExtensionExtendedMasterSecret,
            extensions.Get(),
            extensions.Count(),
            &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = BuildRenegotiationInfoExtension(options, extensions.Get(), extensions.Count(), &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (options.OfferEncryptThenMac) {
            status = BuildEmptyExtension(
                ExtensionEncryptThenMac,
                extensions.Get(),
                extensions.Count(),
                &extensionOffset);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = BuildStatusRequestExtension(
            options.OfferStatusRequest,
            extensions.Get(),
            extensions.Count(),
            &extensionOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteUint16(static_cast<USHORT>(extensionOffset), body.Get(), body.Count(), &offset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteBytes(extensions.Get(), extensionOffset, body.Get(), body.Count(), &offset);
        RtlSecureZeroMemory(extensions.Get(), extensions.Count());
        if (!NT_SUCCESS(status)) {
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

    NTSTATUS TlsHandshake12::ParseServerHello(
        TlsContext& context,
        const TlsHandshakeMessageView& message,
        TlsServerHelloView& serverHello) noexcept
    {
        serverHello = {};

        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::ServerHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        UCHAR major = 0;
        UCHAR minor = 0;
        status = ReadByte(message.Body, message.BodyLength, &offset, &major);
        if (NT_SUCCESS(status)) {
            status = ReadByte(message.Body, message.BodyLength, &offset, &minor);
        }

        if (!NT_SUCCESS(status)) {
            return status;
        }

        serverHello.Version = { major, minor };
        if (serverHello.Version.Major != context.Version().Major ||
            serverHello.Version.Minor != context.Version().Minor) {
            return STATUS_NOT_SUPPORTED;
        }

        status = ReadBytes(
            message.Body,
            message.BodyLength,
            &offset,
            TlsRandomLength,
            &serverHello.Random);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        serverHello.RandomLength = TlsRandomLength;

        UCHAR sessionIdLength = 0;
        status = ReadByte(message.Body, message.BodyLength, &offset, &sessionIdLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (sessionIdLength > 32) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = ReadBytes(
            message.Body,
            message.BodyLength,
            &offset,
            sessionIdLength,
            &serverHello.SessionId);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        serverHello.SessionIdLength = sessionIdLength;

        USHORT cipherSuite = 0;
        status = ReadUint16Value(message.Body, message.BodyLength, &offset, &cipherSuite);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        serverHello.CipherSuite = static_cast<TlsCipherSuite>(cipherSuite);
        if (!IsSupportedCipherSuite(serverHello.CipherSuite)) {
            return STATUS_NOT_SUPPORTED;
        }

        status = ReadByte(message.Body, message.BodyLength, &offset, &serverHello.CompressionMethod);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (serverHello.CompressionMethod != NullCompressionMethod) {
            return STATUS_NOT_SUPPORTED;
        }

        if (offset < message.BodyLength) {
            USHORT extensionsLength = 0;
            status = ReadUint16Value(message.Body, message.BodyLength, &offset, &extensionsLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadBytes(
                message.Body,
                message.BodyLength,
                &offset,
                extensionsLength,
                &serverHello.Extensions);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            serverHello.ExtensionsLength = extensionsLength;
        }

        if (offset != message.BodyLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = ParseServerHelloExtensions(serverHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = context.SetCipherSuite(serverHello.CipherSuite);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = context.SetServerRandom(serverHello.Random);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        context.SetState(TlsHandshakeState::ServerHelloReceived);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::ValidateServerHelloOffer(
        const TlsServerHelloView& serverHello,
        const TlsClientHelloOptions& clientHello) noexcept
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

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::ParseCertificateList(
        TlsContext& context,
        const TlsHandshakeMessageView& message,
        TlsCertificateListView& certificates) noexcept
    {
        certificates = {};

        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::Certificate);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        SIZE_T certificateListLength = 0;
        status = ReadUint24Value(message.Body, message.BodyLength, &offset, &certificateListLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadBytes(
            message.Body,
            message.BodyLength,
            &offset,
            certificateListLength,
            &certificates.Certificates);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        certificates.CertificatesLength = certificateListLength;

        SIZE_T certificateOffset = 0;
        while (certificateOffset < certificateListLength) {
            SIZE_T certificateLength = 0;
            status = ReadUint24Value(
                certificates.Certificates,
                certificates.CertificatesLength,
                &certificateOffset,
                &certificateLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const UCHAR* certificate = nullptr;
            status = ReadBytes(
                certificates.Certificates,
                certificates.CertificatesLength,
                &certificateOffset,
                certificateLength,
                &certificate);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            ++certificates.CertificateCount;
        }

        if (offset != message.BodyLength || certificates.CertificateCount == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        context.SetState(TlsHandshakeState::ServerCertificateReceived);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::ParseServerKeyExchange(
        TlsContext& context,
        const TlsHandshakeMessageView& message,
        TlsServerKeyExchangeView& keyExchange) noexcept
    {
        keyExchange = {};

        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::ServerKeyExchange);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        const UCHAR* parameterStart = message.Body;

        const Tls12KeyExchangeKind keyExchangeKind = KeyExchangeForCipherSuite(context.CipherSuite());
        if (keyExchangeKind == Tls12KeyExchangeKind::DheRsa) {
            USHORT primeLength = 0;
            status = ReadUint16Value(message.Body, message.BodyLength, &offset, &primeLength);
            if (NT_SUCCESS(status)) {
                status = ReadBytes(
                    message.Body,
                    message.BodyLength,
                    &offset,
                    primeLength,
                    &keyExchange.DhPrime);
            }
            if (NT_SUCCESS(status)) {
                keyExchange.DhPrimeLength = primeLength;
            }

            USHORT generatorLength = 0;
            if (NT_SUCCESS(status)) {
                status = ReadUint16Value(message.Body, message.BodyLength, &offset, &generatorLength);
            }
            if (NT_SUCCESS(status)) {
                status = ReadBytes(
                    message.Body,
                    message.BodyLength,
                    &offset,
                    generatorLength,
                    &keyExchange.DhGenerator);
            }
            if (NT_SUCCESS(status)) {
                keyExchange.DhGeneratorLength = generatorLength;
            }

            USHORT publicKeyLength = 0;
            if (NT_SUCCESS(status)) {
                status = ReadUint16Value(message.Body, message.BodyLength, &offset, &publicKeyLength);
            }
            if (NT_SUCCESS(status)) {
                status = ReadBytes(
                    message.Body,
                    message.BodyLength,
                    &offset,
                    publicKeyLength,
                    &keyExchange.DhPublicKey);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            keyExchange.DhPublicKeyLength = publicKeyLength;

            crypto::KeyExchangeGroup ffdheGroup = crypto::KeyExchangeGroup::Ffdhe2048;
            status = crypto::KeyExchange::FindFiniteFieldGroup(
                keyExchange.DhPrime,
                keyExchange.DhPrimeLength,
                keyExchange.DhGenerator,
                keyExchange.DhGeneratorLength,
                &ffdheGroup);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            keyExchange.NamedGroup = static_cast<TlsNamedGroup>(ffdheGroup);

            status = crypto::KeyExchange::ValidateFiniteFieldPublicKey(
                ffdheGroup,
                keyExchange.DhPublicKey,
                keyExchange.DhPublicKeyLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            keyExchange.Parameters = parameterStart;
            keyExchange.ParametersLength = offset;
        }
        else if (keyExchangeKind == Tls12KeyExchangeKind::EcdheRsa ||
            keyExchangeKind == Tls12KeyExchangeKind::EcdheEcdsa) {
            UCHAR curveType = 0;
            status = ReadByte(message.Body, message.BodyLength, &offset, &curveType);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (curveType != 3) {
                return STATUS_NOT_SUPPORTED;
            }

            USHORT namedGroup = 0;
            status = ReadUint16Value(message.Body, message.BodyLength, &offset, &namedGroup);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            keyExchange.NamedGroup = static_cast<TlsNamedGroup>(namedGroup);
            if (!IsSupportedNamedGroup(keyExchange.NamedGroup)) {
                return STATUS_NOT_SUPPORTED;
            }

            UCHAR pointLength = 0;
            status = ReadByte(message.Body, message.BodyLength, &offset, &pointLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadBytes(
                message.Body,
                message.BodyLength,
                &offset,
                pointLength,
                &keyExchange.EcPoint);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            keyExchange.EcPointLength = pointLength;
            keyExchange.Parameters = parameterStart;
            keyExchange.ParametersLength = offset;
        }
        else {
            return STATUS_NOT_SUPPORTED;
        }

        USHORT signatureScheme = 0;
        status = ReadUint16Value(message.Body, message.BodyLength, &offset, &signatureScheme);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        keyExchange.SignatureScheme = static_cast<TlsSignatureScheme>(signatureScheme);
        if (!IsSupportedSignatureScheme(keyExchange.SignatureScheme)) {
            return STATUS_NOT_SUPPORTED;
        }

        USHORT signatureLength = 0;
        status = ReadUint16Value(message.Body, message.BodyLength, &offset, &signatureLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadBytes(
            message.Body,
            message.BodyLength,
            &offset,
            signatureLength,
            &keyExchange.Signature);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        keyExchange.SignatureLength = signatureLength;

        if (offset != message.BodyLength ||
            (keyExchangeKind != Tls12KeyExchangeKind::DheRsa && keyExchange.EcPointLength == 0) ||
            (keyExchangeKind == Tls12KeyExchangeKind::DheRsa && keyExchange.DhPublicKeyLength == 0) ||
            keyExchange.SignatureLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        context.SetState(TlsHandshakeState::ServerKeyExchangeReceived);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::ValidateServerKeyExchangeOffer(
        const TlsServerKeyExchangeView& keyExchange,
        const TlsClientHelloOptions& clientHello) noexcept
    {
        const TlsNamedGroup* namedGroups =
            clientHello.NamedGroups != nullptr ? clientHello.NamedGroups : DefaultNamedGroups;
        const SIZE_T namedGroupCount =
            clientHello.NamedGroups != nullptr ?
            clientHello.NamedGroupCount :
            sizeof(DefaultNamedGroups) / sizeof(DefaultNamedGroups[0]);
        const TlsSignatureScheme* signatureSchemes =
            clientHello.SignatureSchemes != nullptr ? clientHello.SignatureSchemes : DefaultSignatureSchemes;
        const SIZE_T signatureSchemeCount =
            clientHello.SignatureSchemes != nullptr ?
            clientHello.SignatureSchemeCount :
            sizeof(DefaultSignatureSchemes) / sizeof(DefaultSignatureSchemes[0]);

        if (!ContainsNamedGroup(namedGroups, namedGroupCount, keyExchange.NamedGroup) ||
            !ContainsSignatureScheme(signatureSchemes, signatureSchemeCount, keyExchange.SignatureScheme)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::ParseCertificateRequest(
        TlsContext& context,
        const TlsHandshakeMessageView& message,
        TlsCertificateRequestView& certificateRequest) noexcept
    {
        certificateRequest = {};

        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::CertificateRequest);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        UCHAR certificateTypeCount = 0;
        status = ReadByte(message.Body, message.BodyLength, &offset, &certificateTypeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadBytes(
            message.Body,
            message.BodyLength,
            &offset,
            certificateTypeCount,
            &certificateRequest.CertificateTypes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        certificateRequest.CertificateTypeCount = certificateTypeCount;

        USHORT signatureSchemeBytes = 0;
        status = ReadUint16Value(message.Body, message.BodyLength, &offset, &signatureSchemeBytes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if ((signatureSchemeBytes % sizeof(USHORT)) != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = ReadBytes(
            message.Body,
            message.BodyLength,
            &offset,
            signatureSchemeBytes,
            &certificateRequest.SignatureSchemes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        certificateRequest.SignatureSchemeCount = signatureSchemeBytes / sizeof(USHORT);

        USHORT distinguishedNameBytes = 0;
        status = ReadUint16Value(message.Body, message.BodyLength, &offset, &distinguishedNameBytes);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadBytes(
            message.Body,
            message.BodyLength,
            &offset,
            distinguishedNameBytes,
            &certificateRequest.DistinguishedNames);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        certificateRequest.DistinguishedNamesLength = distinguishedNameBytes;

        if (offset != message.BodyLength ||
            certificateRequest.CertificateTypeCount == 0 ||
            certificateRequest.SignatureSchemeCount == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        context.SetState(TlsHandshakeState::CertificateRequestReceived);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::MarkServerHelloDone(
        TlsContext& context,
        const TlsHandshakeMessageView& message) noexcept
    {
        NTSTATUS status = ValidateHandshakeType(message, TlsHandshakeType::ServerHelloDone);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (message.BodyLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        context.SetState(TlsHandshakeState::ServerHelloDoneReceived);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::EncodeClientKeyExchange(
        const UCHAR* publicKey,
        SIZE_T publicKeyLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (publicKey == nullptr || publicKeyLength == 0 || publicKeyLength > 255) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T bodyLength = 1 + publicKeyLength;
        const SIZE_T required = TlsHandshakeHeaderLength + bodyLength;

        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }

            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        NTSTATUS status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::ClientKeyExchange), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(static_cast<ULONG>(bodyLength), destination, destinationCapacity, &offset);
        }

        if (NT_SUCCESS(status)) {
            status = WriteByte(static_cast<UCHAR>(publicKeyLength), destination, destinationCapacity, &offset);
        }

        if (NT_SUCCESS(status)) {
            status = WriteBytes(publicKey, publicKeyLength, destination, destinationCapacity, &offset);
        }

        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = offset;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::EncodeCertificate(
        const UCHAR* certificateList,
        SIZE_T certificateListLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (!IsValidBuffer(certificateList, certificateListLength) ||
            certificateListLength > TlsMaxHandshakeMessageLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T bodyLength = 3 + certificateListLength;
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

    NTSTATUS TlsHandshake12::EncodeCertificateVerify(
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

    NTSTATUS TlsHandshake12::EncodeFinished(
        TlsContext& context,
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

        const SIZE_T required = TlsHandshakeHeaderLength + TlsVerifyDataLength;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }

            return STATUS_BUFFER_TOO_SMALL;
        }

        HeapArray<UCHAR> verifyData(TlsVerifyDataLength);
        if (!verifyData.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = ComputeVerifyData(
            context,
            clientFinished,
            transcriptHash,
            transcriptHashLength,
            verifyData.Get(),
            verifyData.Count());

        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T offset = 0;
        status = WriteByte(static_cast<UCHAR>(TlsHandshakeType::Finished), destination, destinationCapacity, &offset);
        if (NT_SUCCESS(status)) {
            status = WriteUint24(TlsVerifyDataLength, destination, destinationCapacity, &offset);
        }

        if (NT_SUCCESS(status)) {
            status = WriteBytes(verifyData.Get(), verifyData.Count(), destination, destinationCapacity, &offset);
        }

        RtlSecureZeroMemory(verifyData.Get(), verifyData.Count());

        if (!NT_SUCCESS(status)) {
            return status;
        }

        context.SetState(clientFinished ? TlsHandshakeState::ClientFinishedSent : context.State());

        if (bytesWritten != nullptr) {
            *bytesWritten = offset;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsHandshake12::VerifyFinished(
        const TlsContext& context,
        bool clientFinished,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength,
        const UCHAR* verifyData,
        SIZE_T verifyDataLength) noexcept
    {
        if (verifyData == nullptr || verifyDataLength != TlsVerifyDataLength) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> expected(TlsVerifyDataLength);
        if (!expected.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = ComputeVerifyData(
            context,
            clientFinished,
            transcriptHash,
            transcriptHashLength,
            expected.Get(),
            expected.Count());

        if (!NT_SUCCESS(status)) {
            return status;
        }

        const bool matches = MemoryEquals(expected.Get(), verifyData, verifyDataLength);
        RtlSecureZeroMemory(expected.Get(), expected.Count());

        return matches ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }
}
}
