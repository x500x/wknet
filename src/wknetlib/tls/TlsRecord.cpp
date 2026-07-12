#include "tls/TlsRecord.h"

namespace wknet
{
namespace tls
{
    namespace
    {
        constexpr UCHAR TlsMajorVersion = 3;
        constexpr UCHAR Tls10MinorVersion = 1;
        constexpr UCHAR Tls12MinorVersion = 3;
        constexpr unsigned long long TlsMaxRecordSequenceNumber = ~0ull;

        _Must_inspect_result_
        bool IsValidContentType(UCHAR contentType) noexcept
        {
            return contentType == static_cast<UCHAR>(TlsContentType::ChangeCipherSpec) ||
                contentType == static_cast<UCHAR>(TlsContentType::Alert) ||
                contentType == static_cast<UCHAR>(TlsContentType::Handshake) ||
                contentType == static_cast<UCHAR>(TlsContentType::ApplicationData);
        }

        _Must_inspect_result_
        SIZE_T ReadUint16(_In_reads_bytes_(2) const UCHAR* data) noexcept
        {
            return (static_cast<SIZE_T>(data[0]) << 8) | data[1];
        }

        void WriteUint16(USHORT value, _Out_writes_bytes_(2) UCHAR* data) noexcept
        {
            data[0] = static_cast<UCHAR>((value >> 8) & 0xff);
            data[1] = static_cast<UCHAR>(value & 0xff);
        }

        _Must_inspect_result_
        NTSTATUS ValidatePlaintextRecord(_In_ const TlsPlaintextRecord& record) noexcept
        {
            if (!TlsRecordLayer::IsSupportedVersion(record.Version) ||
                record.FragmentLength > TlsMaxPlaintextLength ||
                (record.Fragment == nullptr && record.FragmentLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }

        void BuildAesGcmNonce(
            _In_ const TlsAeadCipherState& state,
            _In_reads_bytes_(TlsAesGcmExplicitNonceLength) const UCHAR* explicitNonce,
            _Out_writes_bytes_(TlsAesGcmFixedIvLength + TlsAesGcmExplicitNonceLength) UCHAR* nonce) noexcept
        {
            RtlCopyMemory(nonce, state.FixedIv, TlsAesGcmFixedIvLength);
            RtlCopyMemory(nonce + TlsAesGcmFixedIvLength, explicitNonce, TlsAesGcmExplicitNonceLength);
        }

        void BuildAad(
            unsigned long long sequenceNumber,
            TlsContentType contentType,
            TlsProtocolVersion version,
            SIZE_T plaintextLength,
            _Out_writes_bytes_(13) UCHAR* aad) noexcept
        {
            TlsRecordLayer::WriteSequenceNumber(sequenceNumber, aad);
            aad[8] = static_cast<UCHAR>(contentType);
            aad[9] = version.Major;
            aad[10] = version.Minor;
            WriteUint16(static_cast<USHORT>(plaintextLength), aad + 11);
        }

        _Must_inspect_result_
        SIZE_T HashDigestLength(crypto::HashAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case crypto::HashAlgorithm::Sha512:
                return 64;
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
        bool MemoryEqualsConstantTime(
            _In_reads_bytes_(length) const UCHAR* left,
            _In_reads_bytes_(length) const UCHAR* right,
            SIZE_T length) noexcept
        {
            if (left == nullptr || right == nullptr) {
                return false;
            }

            UCHAR difference = 0;
            for (SIZE_T index = 0; index < length; ++index) {
                difference = static_cast<UCHAR>(difference | (left[index] ^ right[index]));
            }
            return difference == 0;
        }

        void BuildTls13Nonce(
            _In_ const TlsAeadCipherState& state,
            _Out_writes_bytes_(TlsAesGcmTls13IvLength) UCHAR* nonce) noexcept
        {
            RtlCopyMemory(nonce, state.FixedIv, TlsAesGcmTls13IvLength);
            for (SIZE_T index = 0; index < TlsAesGcmExplicitNonceLength; ++index) {
                const unsigned shift = static_cast<unsigned>((TlsAesGcmExplicitNonceLength - 1 - index) * 8);
                nonce[TlsAesGcmTls13IvLength - TlsAesGcmExplicitNonceLength + index] =
                    static_cast<UCHAR>(
                        nonce[TlsAesGcmTls13IvLength - TlsAesGcmExplicitNonceLength + index] ^
                        static_cast<UCHAR>((state.SequenceNumber >> shift) & 0xff));
            }
        }

        void BuildTls13Aad(
            SIZE_T encryptedFragmentLength,
            _Out_writes_bytes_(TlsRecordHeaderLength) UCHAR* aad) noexcept
        {
            aad[0] = static_cast<UCHAR>(TlsContentType::ApplicationData);
            aad[1] = 3;
            aad[2] = 3;
            WriteUint16(static_cast<USHORT>(encryptedFragmentLength), aad + 3);
        }

        _Must_inspect_result_
        NTSTATUS ValidateSequenceCanAdvance(_In_ const TlsAeadCipherState& state) noexcept
        {
            return state.SequenceNumber == TlsMaxRecordSequenceNumber ?
                STATUS_INVALID_DEVICE_STATE :
                STATUS_SUCCESS;
        }
    }

    void TlsAeadCipherState::Reset() noexcept
    {
        Algorithm = crypto::AeadAlgorithm::Aes128Gcm;
        RtlZeroMemory(Key, sizeof(Key));
        KeyLength = 0;
        RtlZeroMemory(FixedIv, sizeof(FixedIv));
        FixedIvLength = 0;
        RtlZeroMemory(MacKey, sizeof(MacKey));
        MacKeyLength = 0;
        MacAlgorithm = crypto::HashAlgorithm::Sha256;
        EncryptThenMac = false;
        RtlZeroMemory(NonceScratch, sizeof(NonceScratch));
        RtlZeroMemory(AadScratch, sizeof(AadScratch));
        SequenceNumber = 0;
    }

    bool TlsRecordLayer::IsSupportedVersion(TlsProtocolVersion version) noexcept
    {
        return version.Major == TlsMajorVersion &&
            version.Minor >= Tls10MinorVersion &&
            version.Minor <= Tls12MinorVersion;
    }

    NTSTATUS TlsRecordLayer::Parse(
        const UCHAR* data,
        SIZE_T dataLength,
        TlsRecordView& record) noexcept
    {
        record = {};

        if (data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength < TlsRecordHeaderLength) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        if (!IsValidContentType(data[0])) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        TlsProtocolVersion version = { data[1], data[2] };
        if (!IsSupportedVersion(version)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T fragmentLength = ReadUint16(data + 3);
        if (fragmentLength > TlsMaxPlaintextLength + 2048) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (dataLength - TlsRecordHeaderLength < fragmentLength) {
            return STATUS_MORE_PROCESSING_REQUIRED;
        }

        record.ContentType = static_cast<TlsContentType>(data[0]);
        record.Version = version;
        record.Fragment = data + TlsRecordHeaderLength;
        record.FragmentLength = fragmentLength;
        record.BytesConsumed = TlsRecordHeaderLength + fragmentLength;

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::EncodePlaintext(
        const TlsPlaintextRecord& record,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = ValidatePlaintextRecord(record);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T required = TlsRecordHeaderLength + record.FragmentLength;
        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }

            return STATUS_BUFFER_TOO_SMALL;
        }

        destination[0] = static_cast<UCHAR>(record.ContentType);
        destination[1] = record.Version.Major;
        destination[2] = record.Version.Minor;
        WriteUint16(static_cast<USHORT>(record.FragmentLength), destination + 3);

        if (record.FragmentLength != 0) {
            RtlCopyMemory(destination + TlsRecordHeaderLength, record.Fragment, record.FragmentLength);
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = required;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::EncodeAlert(
        TlsProtocolVersion version,
        TlsAlertLevel level,
        TlsAlertDescription description,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        HeapArray<UCHAR> alert(2);
        if (!alert.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        alert[0] = static_cast<UCHAR>(level);
        alert[1] = static_cast<UCHAR>(description);

        TlsPlaintextRecord record = {};
        record.ContentType = TlsContentType::Alert;
        record.Version = version;
        record.Fragment = alert.Get();
        record.FragmentLength = alert.Count();

        return EncodePlaintext(record, destination, destinationCapacity, bytesWritten);
    }

    NTSTATUS TlsRecordLayer::DecodeAlert(
        const UCHAR* fragment,
        SIZE_T fragmentLength,
        TlsAlert& alert) noexcept
    {
        alert = {};

        if (fragment == nullptr || fragmentLength != 2) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const TlsAlertLevel level = static_cast<TlsAlertLevel>(fragment[0]);
        if (level != TlsAlertLevel::Warning && level != TlsAlertLevel::Fatal) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        alert.Level = level;
        alert.Description = static_cast<TlsAlertDescription>(fragment[1]);
        alert.CloseNotify = alert.Description == TlsAlertDescription::CloseNotify;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::ProtectAesGcm(
        const TlsPlaintextRecord& plaintext,
        TlsAeadCipherState& writeState,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = ValidatePlaintextRecord(plaintext);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (writeState.KeyLength == 0 ||
            writeState.KeyLength > sizeof(writeState.Key) ||
            writeState.FixedIvLength != TlsAesGcmFixedIvLength) {
            return STATUS_INVALID_PARAMETER;
        }

        status = ValidateSequenceCanAdvance(writeState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T encryptedFragmentLength =
            TlsAesGcmExplicitNonceLength + plaintext.FragmentLength + TlsAesGcmTagLength;
        const SIZE_T required = TlsRecordHeaderLength + encryptedFragmentLength;

        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }

            return STATUS_BUFFER_TOO_SMALL;
        }

        destination[0] = static_cast<UCHAR>(plaintext.ContentType);
        destination[1] = plaintext.Version.Major;
        destination[2] = plaintext.Version.Minor;
        WriteUint16(static_cast<USHORT>(encryptedFragmentLength), destination + 3);

        UCHAR* explicitNonce = destination + TlsRecordHeaderLength;
        WriteSequenceNumber(writeState.SequenceNumber, explicitNonce);

        UCHAR* nonce = writeState.NonceScratch;
        BuildAesGcmNonce(writeState, explicitNonce, nonce);

        UCHAR* aad = writeState.AadScratch;
        BuildAad(
            writeState.SequenceNumber,
            plaintext.ContentType,
            plaintext.Version,
            plaintext.FragmentLength,
            aad);

        crypto::AeadKey key = {};
        key.Algorithm = writeState.Algorithm;
        key.Key = writeState.Key;
        key.KeyLength = writeState.KeyLength;

        crypto::AeadParameters parameters = {};
        parameters.Nonce = { nonce, TlsAesGcmFixedIvLength + TlsAesGcmExplicitNonceLength };
        parameters.Aad = { aad, 13 };

        UCHAR* ciphertext = explicitNonce + TlsAesGcmExplicitNonceLength;
        UCHAR* tag = ciphertext + plaintext.FragmentLength;
        SIZE_T encryptedLength = 0;

        status = crypto::Aead::Encrypt(
            nullptr,
            key,
            parameters,
            plaintext.Fragment,
            plaintext.FragmentLength,
            ciphertext,
            plaintext.FragmentLength,
            tag,
            TlsAesGcmTagLength,
            &encryptedLength);

        RtlSecureZeroMemory(nonce, sizeof(writeState.NonceScratch));
        RtlSecureZeroMemory(aad, sizeof(writeState.AadScratch));

        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (encryptedLength != plaintext.FragmentLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = IncrementSequence(writeState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = required;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::UnprotectAesGcm(
        const TlsRecordView& encrypted,
        TlsAeadCipherState& readState,
        UCHAR* plaintext,
        SIZE_T plaintextCapacity,
        TlsMutablePlaintextRecord& output) noexcept
    {
        output = {};

        if (encrypted.Fragment == nullptr ||
            encrypted.FragmentLength < TlsAesGcmExplicitNonceLength + TlsAesGcmTagLength ||
            readState.KeyLength == 0 ||
            readState.KeyLength > sizeof(readState.Key) ||
            readState.FixedIvLength != TlsAesGcmFixedIvLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T plaintextLength =
            encrypted.FragmentLength - TlsAesGcmExplicitNonceLength - TlsAesGcmTagLength;

        if (plaintext == nullptr || plaintextCapacity < plaintextLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        NTSTATUS status = ValidateSequenceCanAdvance(readState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const UCHAR* explicitNonce = encrypted.Fragment;
        const UCHAR* ciphertext = encrypted.Fragment + TlsAesGcmExplicitNonceLength;
        const UCHAR* tag = encrypted.Fragment + encrypted.FragmentLength - TlsAesGcmTagLength;

        UCHAR* nonce = readState.NonceScratch;
        BuildAesGcmNonce(readState, explicitNonce, nonce);

        UCHAR* aad = readState.AadScratch;
        BuildAad(
            readState.SequenceNumber,
            encrypted.ContentType,
            encrypted.Version,
            plaintextLength,
            aad);

        crypto::AeadKey key = {};
        key.Algorithm = readState.Algorithm;
        key.Key = readState.Key;
        key.KeyLength = readState.KeyLength;

        crypto::AeadParameters parameters = {};
        parameters.Nonce = { nonce, TlsAesGcmFixedIvLength + TlsAesGcmExplicitNonceLength };
        parameters.Aad = { aad, 13 };
        parameters.Tag = { tag, TlsAesGcmTagLength };

        SIZE_T decryptedLength = 0;
        status = crypto::Aead::Decrypt(
            nullptr,
            key,
            parameters,
            ciphertext,
            plaintextLength,
            plaintext,
            plaintextCapacity,
            &decryptedLength);

        RtlSecureZeroMemory(nonce, sizeof(readState.NonceScratch));
        RtlSecureZeroMemory(aad, sizeof(readState.AadScratch));

        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (decryptedLength != plaintextLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = IncrementSequence(readState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        output.ContentType = encrypted.ContentType;
        output.Version = encrypted.Version;
        output.Fragment = plaintext;
        output.FragmentLength = plaintextLength;

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::ProtectAesCbcEncryptThenMac(
        const TlsPlaintextRecord& plaintext,
        TlsAeadCipherState& writeState,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = ValidatePlaintextRecord(plaintext);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (destination == nullptr ||
            !writeState.EncryptThenMac ||
            writeState.KeyLength == 0 ||
            writeState.MacKeyLength == 0 ||
            writeState.MacKeyLength != HashDigestLength(writeState.MacAlgorithm)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = ValidateSequenceCanAdvance(writeState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T paddingLength =
            TlsAesCbcBlockLength - ((plaintext.FragmentLength + 1) % TlsAesCbcBlockLength);
        const SIZE_T paddedLength = plaintext.FragmentLength + paddingLength + 1;
        const SIZE_T encryptedPartLength = TlsAesCbcBlockLength + paddedLength;
        const SIZE_T recordFragmentLength = encryptedPartLength + writeState.MacKeyLength;
        const SIZE_T required = TlsRecordHeaderLength + recordFragmentLength;
        if (paddedLength > TlsMaxPlaintextLength + TlsAesCbcBlockLength ||
            recordFragmentLength > 0xffff ||
            destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }

        HeapArray<UCHAR> explicitIv(TlsAesCbcBlockLength);
        HeapArray<UCHAR> padded(paddedLength);
        HeapArray<UCHAR> macInput(13 + encryptedPartLength);
        HeapArray<UCHAR> mac(writeState.MacKeyLength);
        if (!explicitIv.IsValid() || !padded.IsValid() || !macInput.IsValid() || !mac.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = crypto::CngProvider::GenerateRandom(explicitIv.Get(), explicitIv.Count());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (plaintext.FragmentLength != 0) {
            RtlCopyMemory(padded.Get(), plaintext.Fragment, plaintext.FragmentLength);
        }
        for (SIZE_T index = plaintext.FragmentLength; index < paddedLength; ++index) {
            padded[index] = static_cast<UCHAR>(paddingLength);
        }

        destination[0] = static_cast<UCHAR>(plaintext.ContentType);
        destination[1] = plaintext.Version.Major;
        destination[2] = plaintext.Version.Minor;
        WriteUint16(static_cast<USHORT>(recordFragmentLength), destination + 3);
        RtlCopyMemory(destination + TlsRecordHeaderLength, explicitIv.Get(), explicitIv.Count());

        SIZE_T encryptedLength = 0;
        status = crypto::CngProvider::AesCbcEncrypt(
            writeState.Key,
            writeState.KeyLength,
            explicitIv.Get(),
            explicitIv.Count(),
            padded.Get(),
            paddedLength,
            destination + TlsRecordHeaderLength + TlsAesCbcBlockLength,
            destinationCapacity - TlsRecordHeaderLength - TlsAesCbcBlockLength,
            &encryptedLength);
        RtlSecureZeroMemory(padded.Get(), padded.Count());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(destination, required);
            return status;
        }
        if (encryptedLength != paddedLength) {
            RtlSecureZeroMemory(destination, required);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        BuildAad(
            writeState.SequenceNumber,
            plaintext.ContentType,
            plaintext.Version,
            encryptedPartLength,
            macInput.Get());
        RtlCopyMemory(macInput.Get() + 13, destination + TlsRecordHeaderLength, encryptedPartLength);

        SIZE_T macLength = 0;
        status = crypto::CngProvider::Hmac(
            writeState.MacAlgorithm,
            writeState.MacKey,
            writeState.MacKeyLength,
            macInput.Get(),
            macInput.Count(),
            mac.Get(),
            mac.Count(),
            &macLength);
        RtlSecureZeroMemory(macInput.Get(), macInput.Count());
        if (!NT_SUCCESS(status) || macLength != writeState.MacKeyLength) {
            RtlSecureZeroMemory(destination, required);
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        RtlCopyMemory(destination + TlsRecordHeaderLength + encryptedPartLength, mac.Get(), macLength);
        RtlSecureZeroMemory(mac.Get(), mac.Count());

        status = IncrementSequence(writeState);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(destination, required);
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = required;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::UnprotectAesCbcEncryptThenMac(
        const TlsRecordView& encrypted,
        TlsAeadCipherState& readState,
        UCHAR* plaintext,
        SIZE_T plaintextCapacity,
        TlsMutablePlaintextRecord& output) noexcept
    {
        output = {};

        if (!readState.EncryptThenMac ||
            readState.KeyLength == 0 ||
            readState.MacKeyLength == 0 ||
            readState.MacKeyLength != HashDigestLength(readState.MacAlgorithm) ||
            plaintext == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (encrypted.Fragment == nullptr ||
            encrypted.FragmentLength <= TlsAesCbcBlockLength + readState.MacKeyLength ||
            plaintextCapacity < encrypted.FragmentLength ||
            encrypted.FragmentLength > TlsMaxPlaintextLength + 2048) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T encryptedPartLength = encrypted.FragmentLength - readState.MacKeyLength;
        const SIZE_T ciphertextLength = encryptedPartLength - TlsAesCbcBlockLength;
        if (ciphertextLength == 0 || (ciphertextLength % TlsAesCbcBlockLength) != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        NTSTATUS status = ValidateSequenceCanAdvance(readState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> macInput(13 + encryptedPartLength);
        HeapArray<UCHAR> expectedMac(readState.MacKeyLength);
        if (!macInput.IsValid() || !expectedMac.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BuildAad(
            readState.SequenceNumber,
            encrypted.ContentType,
            encrypted.Version,
            encryptedPartLength,
            macInput.Get());
        RtlCopyMemory(macInput.Get() + 13, encrypted.Fragment, encryptedPartLength);

        SIZE_T expectedMacLength = 0;
        status = crypto::CngProvider::Hmac(
            readState.MacAlgorithm,
            readState.MacKey,
            readState.MacKeyLength,
            macInput.Get(),
            macInput.Count(),
            expectedMac.Get(),
            expectedMac.Count(),
            &expectedMacLength);
        RtlSecureZeroMemory(macInput.Get(), macInput.Count());
        if (!NT_SUCCESS(status) || expectedMacLength != readState.MacKeyLength) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }

        const UCHAR* receivedMac = encrypted.Fragment + encryptedPartLength;
        if (!MemoryEqualsConstantTime(expectedMac.Get(), receivedMac, readState.MacKeyLength)) {
            RtlSecureZeroMemory(expectedMac.Get(), expectedMac.Count());
            return STATUS_INVALID_SIGNATURE;
        }
        RtlSecureZeroMemory(expectedMac.Get(), expectedMac.Count());

        const UCHAR* explicitIv = encrypted.Fragment;
        const UCHAR* ciphertext = encrypted.Fragment + TlsAesCbcBlockLength;
        SIZE_T decryptedLength = 0;
        status = crypto::CngProvider::AesCbcDecrypt(
            readState.Key,
            readState.KeyLength,
            explicitIv,
            TlsAesCbcBlockLength,
            ciphertext,
            ciphertextLength,
            plaintext,
            plaintextCapacity,
            &decryptedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (decryptedLength == 0 || decryptedLength != ciphertextLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const UCHAR paddingValue = plaintext[decryptedLength - 1];
        const SIZE_T paddingBytes = static_cast<SIZE_T>(paddingValue) + 1;
        if (paddingBytes > decryptedLength) {
            RtlSecureZeroMemory(plaintext, decryptedLength);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        UCHAR paddingDifference = 0;
        for (SIZE_T index = 0; index < paddingBytes; ++index) {
            paddingDifference = static_cast<UCHAR>(
                paddingDifference | (plaintext[decryptedLength - 1 - index] ^ paddingValue));
        }
        if (paddingDifference != 0) {
            RtlSecureZeroMemory(plaintext, decryptedLength);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = IncrementSequence(readState);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(plaintext, decryptedLength);
            return status;
        }

        output.ContentType = encrypted.ContentType;
        output.Version = encrypted.Version;
        output.Fragment = plaintext;
        output.FragmentLength = decryptedLength - paddingBytes;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::ProtectAesGcm13(
        const TlsPlaintextRecord& plaintext,
        TlsAeadCipherState& writeState,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        HeapArray<UCHAR> innerPlaintext(TlsMaxPlaintextLength + 1);
        if (!innerPlaintext.IsValid()) {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        return ProtectAesGcm13WithScratch(
            plaintext,
            writeState,
            innerPlaintext.Get(),
            innerPlaintext.Count(),
            destination,
            destinationCapacity,
            bytesWritten);
    }

    NTSTATUS TlsRecordLayer::ProtectAesGcm13WithScratch(
        const TlsPlaintextRecord& plaintext,
        TlsAeadCipherState& writeState,
        UCHAR* innerPlaintext,
        SIZE_T scratchCapacity,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        NTSTATUS status = ValidatePlaintextRecord(plaintext);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (writeState.KeyLength == 0 ||
            writeState.KeyLength > sizeof(writeState.Key) ||
            writeState.FixedIvLength != TlsAesGcmTls13IvLength ||
            plaintext.FragmentLength + 1 < plaintext.FragmentLength ||
            plaintext.Tls13PaddingLength > Tls13MaxRecordPaddingLength ||
            plaintext.Tls13PaddingLength > TlsMaxPlaintextLength - plaintext.FragmentLength) {
            return STATUS_INVALID_PARAMETER;
        }

        status = ValidateSequenceCanAdvance(writeState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T innerPlaintextLength =
            plaintext.FragmentLength + 1 + plaintext.Tls13PaddingLength;
        const SIZE_T encryptedFragmentLength = innerPlaintextLength + TlsAesGcmTagLength;
        const SIZE_T required = TlsRecordHeaderLength + encryptedFragmentLength;

        if (encryptedFragmentLength > 0xffff) {
            return STATUS_INVALID_PARAMETER;
        }

        if (destination == nullptr || destinationCapacity < required) {
            if (bytesWritten != nullptr) {
                *bytesWritten = required;
            }

            return STATUS_BUFFER_TOO_SMALL;
        }

        if (innerPlaintext == nullptr || scratchCapacity < innerPlaintextLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        UCHAR* aad = writeState.AadScratch;
        BuildTls13Aad(encryptedFragmentLength, aad);

        UCHAR* nonce = writeState.NonceScratch;
        BuildTls13Nonce(writeState, nonce);

        crypto::AeadKey key = {};
        key.Algorithm = writeState.Algorithm;
        key.Key = writeState.Key;
        key.KeyLength = writeState.KeyLength;

        crypto::AeadParameters parameters = {};
        parameters.Nonce = { nonce, TlsAesGcmTls13IvLength };
        parameters.Aad = { aad, TlsRecordHeaderLength };

        UCHAR* ciphertext = destination + TlsRecordHeaderLength;
        if (plaintext.FragmentLength != 0) {
            RtlMoveMemory(innerPlaintext, plaintext.Fragment, plaintext.FragmentLength);
        }
        innerPlaintext[plaintext.FragmentLength] = static_cast<UCHAR>(plaintext.ContentType);
        if (plaintext.Tls13PaddingLength != 0) {
            RtlZeroMemory(
                innerPlaintext + plaintext.FragmentLength + 1,
                plaintext.Tls13PaddingLength);
        }

        destination[0] = aad[0];
        destination[1] = aad[1];
        destination[2] = aad[2];
        destination[3] = aad[3];
        destination[4] = aad[4];

        UCHAR* tag = ciphertext + innerPlaintextLength;
        SIZE_T encryptedLength = 0;

        status = crypto::Aead::Encrypt(
            nullptr,
            key,
            parameters,
            innerPlaintext,
            innerPlaintextLength,
            ciphertext,
            innerPlaintextLength,
            tag,
            TlsAesGcmTagLength,
            &encryptedLength);

        RtlSecureZeroMemory(innerPlaintext, innerPlaintextLength);
        RtlSecureZeroMemory(nonce, sizeof(writeState.NonceScratch));
        RtlSecureZeroMemory(aad, sizeof(writeState.AadScratch));

        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(ciphertext, innerPlaintextLength);
            return status;
        }

        if (encryptedLength != innerPlaintextLength) {
            RtlSecureZeroMemory(ciphertext, innerPlaintextLength + TlsAesGcmTagLength);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = IncrementSequence(writeState);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(ciphertext, innerPlaintextLength + TlsAesGcmTagLength);
            return status;
        }

        if (bytesWritten != nullptr) {
            *bytesWritten = required;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsRecordLayer::UnprotectAesGcm13(
        const TlsRecordView& encrypted,
        TlsAeadCipherState& readState,
        UCHAR* plaintext,
        SIZE_T plaintextCapacity,
        TlsMutablePlaintextRecord& output) noexcept
    {
        output = {};

        if (encrypted.ContentType != TlsContentType::ApplicationData ||
            encrypted.Fragment == nullptr ||
            encrypted.FragmentLength < 1 + TlsAesGcmTagLength ||
            readState.KeyLength == 0 ||
            readState.KeyLength > sizeof(readState.Key) ||
            readState.FixedIvLength != TlsAesGcmTls13IvLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T innerPlaintextLength = encrypted.FragmentLength - TlsAesGcmTagLength;
        if (plaintext == nullptr || plaintextCapacity < innerPlaintextLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        NTSTATUS status = ValidateSequenceCanAdvance(readState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UCHAR* aad = readState.AadScratch;
        BuildTls13Aad(encrypted.FragmentLength, aad);

        UCHAR* nonce = readState.NonceScratch;
        BuildTls13Nonce(readState, nonce);

        crypto::AeadKey key = {};
        key.Algorithm = readState.Algorithm;
        key.Key = readState.Key;
        key.KeyLength = readState.KeyLength;

        crypto::AeadParameters parameters = {};
        parameters.Nonce = { nonce, TlsAesGcmTls13IvLength };
        parameters.Aad = { aad, TlsRecordHeaderLength };
        parameters.Tag = {
            encrypted.Fragment + encrypted.FragmentLength - TlsAesGcmTagLength,
            TlsAesGcmTagLength
        };

        SIZE_T decryptedLength = 0;
        status = crypto::Aead::Decrypt(
            nullptr,
            key,
            parameters,
            encrypted.Fragment,
            innerPlaintextLength,
            plaintext,
            plaintextCapacity,
            &decryptedLength);

        RtlSecureZeroMemory(nonce, sizeof(readState.NonceScratch));
        RtlSecureZeroMemory(aad, sizeof(readState.AadScratch));

        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (decryptedLength == 0 || decryptedLength != innerPlaintextLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T contentTypeOffset = decryptedLength;
        while (contentTypeOffset > 0 && plaintext[contentTypeOffset - 1] == 0) {
            --contentTypeOffset;
        }

        if (contentTypeOffset == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const UCHAR innerType = plaintext[contentTypeOffset - 1];
        if (!IsValidContentType(innerType)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = IncrementSequence(readState);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        output.ContentType = static_cast<TlsContentType>(innerType);
        output.Version = encrypted.Version;
        output.Fragment = plaintext;
        output.FragmentLength = contentTypeOffset - 1;
        return STATUS_SUCCESS;
    }

    void TlsRecordLayer::WriteSequenceNumber(unsigned long long sequenceNumber, UCHAR* destination) noexcept
    {
        for (SIZE_T index = 0; index < TlsAesGcmExplicitNonceLength; ++index) {
            const unsigned shift = static_cast<unsigned>((TlsAesGcmExplicitNonceLength - 1 - index) * 8);
            destination[index] = static_cast<UCHAR>((sequenceNumber >> shift) & 0xff);
        }
    }

    NTSTATUS TlsRecordLayer::IncrementSequence(TlsAeadCipherState& state) noexcept
    {
        if (state.SequenceNumber == TlsMaxRecordSequenceNumber) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        ++state.SequenceNumber;
        return STATUS_SUCCESS;
    }
}
}
