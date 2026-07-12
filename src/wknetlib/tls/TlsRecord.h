#pragma once

#include <wknet/crypto/Aead.h>

namespace wknet
{
namespace tls
{
    constexpr SIZE_T TlsRecordHeaderLength = 5;
    constexpr SIZE_T TlsMaxPlaintextLength = 16384;
    constexpr SIZE_T TlsAesGcmExplicitNonceLength = 8;
    constexpr SIZE_T TlsAesGcmTagLength = 16;
    constexpr SIZE_T TlsAesGcmFixedIvLength = 4;
    constexpr SIZE_T TlsAesGcmTls13IvLength = 12;
    constexpr SIZE_T TlsAesGcmMaxEncryptedOverhead = TlsAesGcmExplicitNonceLength + TlsAesGcmTagLength;
    constexpr SIZE_T TlsAesGcm13MaxEncryptedOverhead = 1 + TlsAesGcmTagLength;
    constexpr SIZE_T TlsAesCbcBlockLength = 16;
    constexpr SIZE_T TlsMaxRecordMacLength = 64;
    constexpr SIZE_T Tls13MaxRecordPaddingLength = TlsMaxPlaintextLength - 1;

    enum class TlsContentType : UCHAR
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    };

    enum class TlsAlertLevel : UCHAR
    {
        Warning = 1,
        Fatal = 2
    };

    enum class TlsAlertDescription : UCHAR
    {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        HandshakeFailure = 40,
        DecodeError = 50,
        DecryptError = 51,
        ProtocolVersion = 70,
        BadCertificate = 42,
        InternalError = 80
    };

    struct TlsAlert final
    {
        TlsAlertLevel Level = TlsAlertLevel::Fatal;
        TlsAlertDescription Description = TlsAlertDescription::InternalError;
        bool CloseNotify = false;
    };

    struct TlsProtocolVersion final
    {
        UCHAR Major = 3;
        UCHAR Minor = 3;
    };

    struct TlsRecordView final
    {
        TlsContentType ContentType = TlsContentType::ApplicationData;
        TlsProtocolVersion Version = {};
        const UCHAR* Fragment = nullptr;
        SIZE_T FragmentLength = 0;
        SIZE_T BytesConsumed = 0;
    };

    struct TlsPlaintextRecord final
    {
        TlsContentType ContentType = TlsContentType::ApplicationData;
        TlsProtocolVersion Version = {};
        const UCHAR* Fragment = nullptr;
        SIZE_T FragmentLength = 0;
        SIZE_T Tls13PaddingLength = 0;
    };

    struct TlsMutablePlaintextRecord final
    {
        TlsContentType ContentType = TlsContentType::ApplicationData;
        TlsProtocolVersion Version = {};
        UCHAR* Fragment = nullptr;
        SIZE_T FragmentLength = 0;
    };

    struct TlsAeadCipherState final
    {
        crypto::AeadAlgorithm Algorithm = crypto::AeadAlgorithm::Aes128Gcm;
        UCHAR Key[32] = {};
        SIZE_T KeyLength = 0;
        UCHAR FixedIv[TlsAesGcmTls13IvLength] = {};
        SIZE_T FixedIvLength = 0;
        UCHAR MacKey[TlsMaxRecordMacLength] = {};
        SIZE_T MacKeyLength = 0;
        crypto::HashAlgorithm MacAlgorithm = crypto::HashAlgorithm::Sha256;
        bool EncryptThenMac = false;
        UCHAR NonceScratch[TlsAesGcmTls13IvLength] = {};
        UCHAR AadScratch[13] = {};
        unsigned long long SequenceNumber = 0;

        void Reset() noexcept;
    };

    class TlsRecordLayer final
    {
    public:
        TlsRecordLayer() = delete;

        _Must_inspect_result_
        static bool IsSupportedVersion(TlsProtocolVersion version) noexcept;

        _Must_inspect_result_
        static NTSTATUS Parse(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            _Out_ TlsRecordView& record) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodePlaintext(
            _In_ const TlsPlaintextRecord& record,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS EncodeAlert(
            TlsProtocolVersion version,
            TlsAlertLevel level,
            TlsAlertDescription description,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS DecodeAlert(
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength,
            _Out_ TlsAlert& alert) noexcept;

        _Must_inspect_result_
        static NTSTATUS ProtectAesGcm(
            _In_ const TlsPlaintextRecord& plaintext,
            _Inout_ TlsAeadCipherState& writeState,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS UnprotectAesGcm(
            _In_ const TlsRecordView& encrypted,
            _Inout_ TlsAeadCipherState& readState,
            _Out_writes_bytes_(plaintextCapacity) UCHAR* plaintext,
            SIZE_T plaintextCapacity,
            _Out_ TlsMutablePlaintextRecord& output) noexcept;

        _Must_inspect_result_
        static NTSTATUS ProtectAesCbcEncryptThenMac(
            _In_ const TlsPlaintextRecord& plaintext,
            _Inout_ TlsAeadCipherState& writeState,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS UnprotectAesCbcEncryptThenMac(
            _In_ const TlsRecordView& encrypted,
            _Inout_ TlsAeadCipherState& readState,
            _Out_writes_bytes_(plaintextCapacity) UCHAR* plaintext,
            SIZE_T plaintextCapacity,
            _Out_ TlsMutablePlaintextRecord& output) noexcept;

        _Must_inspect_result_
        static NTSTATUS ProtectAesGcm13(
            _In_ const TlsPlaintextRecord& plaintext,
            _Inout_ TlsAeadCipherState& writeState,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS ProtectAesGcm13WithScratch(
            _In_ const TlsPlaintextRecord& plaintext,
            _Inout_ TlsAeadCipherState& writeState,
            _Out_writes_bytes_(scratchCapacity) UCHAR* innerPlaintext,
            SIZE_T scratchCapacity,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_opt_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS UnprotectAesGcm13(
            _In_ const TlsRecordView& encrypted,
            _Inout_ TlsAeadCipherState& readState,
            _Out_writes_bytes_(plaintextCapacity) UCHAR* plaintext,
            SIZE_T plaintextCapacity,
            _Out_ TlsMutablePlaintextRecord& output) noexcept;

        static void WriteSequenceNumber(
            unsigned long long sequenceNumber,
            _Out_writes_bytes_(TlsAesGcmExplicitNonceLength) UCHAR* destination) noexcept;

    private:
        _Must_inspect_result_
        static NTSTATUS IncrementSequence(_Inout_ TlsAeadCipherState& state) noexcept;
    };
}
}
