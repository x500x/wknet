#include <KernelHttp/tls/TlsContext.h>
#include <KernelHttp/tls/TlsHandshake12.h>

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        constexpr SIZE_T Aes128GcmKeyLength = 16;
        constexpr SIZE_T Aes256GcmKeyLength = 32;
        constexpr SIZE_T ChaCha20Poly1305KeyLength = 32;

        _Must_inspect_result_
        SIZE_T CipherSuiteKeyLength(TlsCipherSuite cipherSuite) noexcept
        {
            switch (cipherSuite) {
            case TlsCipherSuite::TlsAes128GcmSha256:
            case TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256:
            case TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256:
                return Aes128GcmKeyLength;
            case TlsCipherSuite::TlsAes256GcmSha384:
            case TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384:
            case TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384:
                return Aes256GcmKeyLength;
            case TlsCipherSuite::TlsChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsDheRsaWithChaCha20Poly1305Sha256:
                return ChaCha20Poly1305KeyLength;
            default:
                return 0;
            }
        }

        _Must_inspect_result_
        bool IsSupportedCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            return CipherSuiteKeyLength(cipherSuite) != 0;
        }

        _Must_inspect_result_
        bool IsTls13CipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            return cipherSuite == TlsCipherSuite::TlsAes128GcmSha256 ||
                cipherSuite == TlsCipherSuite::TlsAes256GcmSha384 ||
                cipherSuite == TlsCipherSuite::TlsChaCha20Poly1305Sha256 ||
                cipherSuite == TlsCipherSuite::TlsAes128CcmSha256 ||
                cipherSuite == TlsCipherSuite::TlsAes128Ccm8Sha256;
        }

        _Must_inspect_result_
        crypto::AeadAlgorithm AeadAlgorithmForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            switch (cipherSuite) {
            case TlsCipherSuite::TlsAes256GcmSha384:
            case TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384:
            case TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384:
                return crypto::AeadAlgorithm::Aes256Gcm;
            case TlsCipherSuite::TlsChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256:
            case TlsCipherSuite::TlsDheRsaWithChaCha20Poly1305Sha256:
                return crypto::AeadAlgorithm::ChaCha20Poly1305;
            case TlsCipherSuite::TlsAes128CcmSha256:
                return crypto::AeadAlgorithm::Aes128Ccm;
            case TlsCipherSuite::TlsAes128Ccm8Sha256:
                return crypto::AeadAlgorithm::Aes128Ccm8;
            case TlsCipherSuite::TlsAes128GcmSha256:
            case TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256:
            case TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256:
            default:
                return crypto::AeadAlgorithm::Aes128Gcm;
            }
        }

        _Must_inspect_result_
        crypto::HashAlgorithm HashForCipherSuite(TlsCipherSuite cipherSuite) noexcept
        {
            return cipherSuite == TlsCipherSuite::TlsAes256GcmSha384 ?
                crypto::HashAlgorithm::Sha384 :
                crypto::HashAlgorithm::Sha256;
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
        bool IsValidBuffer(_In_reads_bytes_opt_(length) const UCHAR* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
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
                !IsValidBuffer(context, contextLength) ||
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
            _In_reads_bytes_(transcriptHashLength) const UCHAR* transcriptHash,
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
        NTSTATUS DeriveEmptyHash(
            crypto::HashAlgorithm algorithm,
            _Out_writes_bytes_(hashLength) UCHAR* hash,
            SIZE_T hashLength) noexcept
        {
            return crypto::CngProvider::Hash(algorithm, nullptr, 0, hash, hashLength);
        }

        _Must_inspect_result_
        NTSTATUS DeriveTrafficState(
            TlsCipherSuite cipherSuite,
            _In_reads_bytes_(secretLength) const UCHAR* trafficSecret,
            SIZE_T secretLength,
            _Out_ TlsAeadCipherState& state) noexcept
        {
            const crypto::HashAlgorithm algorithm = HashForCipherSuite(cipherSuite);
            const SIZE_T keyLength = CipherSuiteKeyLength(cipherSuite);
            if (keyLength == 0 || trafficSecret == nullptr || secretLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            state.Reset();
            NTSTATUS status = HkdfExpandLabel(
                algorithm,
                trafficSecret,
                secretLength,
                "key",
                nullptr,
                0,
                state.Key,
                keyLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = HkdfExpandLabel(
                algorithm,
                trafficSecret,
                secretLength,
                "iv",
                nullptr,
                0,
                state.FixedIv,
                TlsAesGcmTls13IvLength);
            if (!NT_SUCCESS(status)) {
                state.Reset();
                return status;
            }

            state.KeyLength = keyLength;
            state.FixedIvLength = TlsAesGcmTls13IvLength;
            state.SequenceNumber = 0;
            state.Algorithm = AeadAlgorithmForCipherSuite(cipherSuite);
            return STATUS_SUCCESS;
        }

        void SecureZeroContextSecrets(
            _Inout_ TlsSessionSecrets& secrets,
            _Inout_ Tls13TrafficSecrets& tls13Secrets,
            _Inout_ Tls13SessionCache& tls13SessionCache) noexcept
        {
            RtlSecureZeroMemory(&secrets, sizeof(secrets));
            RtlSecureZeroMemory(&tls13Secrets, sizeof(tls13Secrets));
            RtlSecureZeroMemory(&tls13SessionCache, sizeof(tls13SessionCache));
        }
    }

    TlsContext::TlsContext() noexcept
    {
        Reset();
    }

    TlsContext::~TlsContext() noexcept
    {
        SecureZeroContextSecrets(secrets_, tls13Secrets_, tls13SessionCache_);
    }

    void TlsContext::Reset() noexcept
    {
        SecureZeroContextSecrets(secrets_, tls13Secrets_, tls13SessionCache_);
        protocol_ = TlsProtocol::Tls12;
        version_ = { 3, 3 };
        state_ = TlsHandshakeState::Idle;
        secrets_.CipherSuite = TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256;
    }

    NTSTATUS TlsContext::InitializeClient(TlsProtocolVersion version) noexcept
    {
        if (!TlsRecordLayer::IsSupportedVersion(version) || version.Minor != 3) {
            return STATUS_NOT_SUPPORTED;
        }

        Reset();
        version_ = version;

        NTSTATUS status = crypto::CngProvider::GenerateRandom(secrets_.ClientRandom, sizeof(secrets_.ClientRandom));
        if (!NT_SUCCESS(status)) {
            state_ = TlsHandshakeState::Failed;
            return status;
        }

        state_ = TlsHandshakeState::Idle;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsContext::InitializeClient13() noexcept
    {
        Reset();
        protocol_ = TlsProtocol::Tls13;
        version_ = { 3, 4 };
        secrets_.CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;

        NTSTATUS status = crypto::CngProvider::GenerateRandom(secrets_.ClientRandom, sizeof(secrets_.ClientRandom));
        if (!NT_SUCCESS(status)) {
            state_ = TlsHandshakeState::Failed;
            return status;
        }

        state_ = TlsHandshakeState::Idle;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsContext::SetCipherSuite(TlsCipherSuite cipherSuite) noexcept
    {
        if (!IsSupportedCipherSuite(cipherSuite)) {
            return STATUS_NOT_SUPPORTED;
        }

        secrets_.CipherSuite = cipherSuite;
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsContext::SetServerRandom(const UCHAR* random) noexcept
    {
        if (random == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(secrets_.ServerRandom, random, sizeof(secrets_.ServerRandom));
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsContext::DeriveMasterSecret(
        const UCHAR* premasterSecret,
        SIZE_T premasterSecretLength) noexcept
    {
        if (protocol_ != TlsProtocol::Tls12 ||
            premasterSecret == nullptr ||
            premasterSecretLength == 0 ||
            IsTls13CipherSuite(secrets_.CipherSuite)) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> seed(TlsRandomLength * 2);
        if (!seed.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(seed.Get(), secrets_.ClientRandom, TlsRandomLength);
        RtlCopyMemory(seed.Get() + TlsRandomLength, secrets_.ServerRandom, TlsRandomLength);

        NTSTATUS status = TlsHandshake12::Prf(
            TlsHandshake12::PrfHashForCipherSuite(secrets_.CipherSuite),
            premasterSecret,
            premasterSecretLength,
            "master secret",
            seed.Get(),
            seed.Count(),
            secrets_.MasterSecret,
            sizeof(secrets_.MasterSecret));

        RtlSecureZeroMemory(seed.Get(), seed.Count());

        if (NT_SUCCESS(status)) {
            secrets_.MasterSecretLength = sizeof(secrets_.MasterSecret);
        }

        return status;
    }

    NTSTATUS TlsContext::DeriveExtendedMasterSecret(
        const UCHAR* premasterSecret,
        SIZE_T premasterSecretLength,
        const UCHAR* sessionHash,
        SIZE_T sessionHashLength) noexcept
    {
        if (protocol_ != TlsProtocol::Tls12 ||
            premasterSecret == nullptr ||
            premasterSecretLength == 0 ||
            sessionHash == nullptr ||
            sessionHashLength == 0 ||
            IsTls13CipherSuite(secrets_.CipherSuite)) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlSecureZeroMemory(secrets_.MasterSecret, sizeof(secrets_.MasterSecret));
        secrets_.MasterSecretLength = 0;

        NTSTATUS status = TlsHandshake12::Prf(
            TlsHandshake12::PrfHashForCipherSuite(secrets_.CipherSuite),
            premasterSecret,
            premasterSecretLength,
            "extended master secret",
            sessionHash,
            sessionHashLength,
            secrets_.MasterSecret,
            sizeof(secrets_.MasterSecret));

        if (NT_SUCCESS(status)) {
            secrets_.MasterSecretLength = sizeof(secrets_.MasterSecret);
        }

        return status;
    }

    NTSTATUS TlsContext::DeriveKeyBlock(TlsKeyBlock& keyBlock, SIZE_T requiredLength) const noexcept
    {
        keyBlock = {};

        if (secrets_.MasterSecretLength != TlsMasterSecretLength ||
            protocol_ != TlsProtocol::Tls12 ||
            IsTls13CipherSuite(secrets_.CipherSuite) ||
            requiredLength == 0 ||
            requiredLength > sizeof(keyBlock.Data)) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<UCHAR> seed(TlsRandomLength * 2);
        if (!seed.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(seed.Get(), secrets_.ServerRandom, TlsRandomLength);
        RtlCopyMemory(seed.Get() + TlsRandomLength, secrets_.ClientRandom, TlsRandomLength);

        NTSTATUS status = TlsHandshake12::Prf(
            TlsHandshake12::PrfHashForCipherSuite(secrets_.CipherSuite),
            secrets_.MasterSecret,
            secrets_.MasterSecretLength,
            "key expansion",
            seed.Get(),
            seed.Count(),
            keyBlock.Data,
            requiredLength);

        RtlSecureZeroMemory(seed.Get(), seed.Count());

        if (NT_SUCCESS(status)) {
            keyBlock.Length = requiredLength;
        }

        return status;
    }

    NTSTATUS TlsContext::ConfigureAesGcmStates(
        const TlsKeyBlock& keyBlock,
        TlsAeadCipherState& clientWriteState,
        TlsAeadCipherState& serverWriteState) const noexcept
    {
        const SIZE_T keyLength = CipherSuiteKeyLength(secrets_.CipherSuite);
        if (protocol_ != TlsProtocol::Tls12 || keyLength == 0 || IsTls13CipherSuite(secrets_.CipherSuite)) {
            return STATUS_NOT_SUPPORTED;
        }

        const SIZE_T requiredLength = (keyLength * 2) + (TlsAesGcmFixedIvLength * 2);
        if (keyBlock.Length < requiredLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        clientWriteState.Reset();
        serverWriteState.Reset();

        SIZE_T offset = 0;
        RtlCopyMemory(clientWriteState.Key, keyBlock.Data + offset, keyLength);
        clientWriteState.KeyLength = keyLength;
        offset += keyLength;

        RtlCopyMemory(serverWriteState.Key, keyBlock.Data + offset, keyLength);
        serverWriteState.KeyLength = keyLength;
        offset += keyLength;

        RtlCopyMemory(clientWriteState.FixedIv, keyBlock.Data + offset, TlsAesGcmFixedIvLength);
        clientWriteState.FixedIvLength = TlsAesGcmFixedIvLength;
        clientWriteState.Algorithm = AeadAlgorithmForCipherSuite(secrets_.CipherSuite);
        offset += TlsAesGcmFixedIvLength;

        RtlCopyMemory(serverWriteState.FixedIv, keyBlock.Data + offset, TlsAesGcmFixedIvLength);
        serverWriteState.FixedIvLength = TlsAesGcmFixedIvLength;
        serverWriteState.Algorithm = AeadAlgorithmForCipherSuite(secrets_.CipherSuite);

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsContext::DeriveTls13EarlySecret(const UCHAR* psk, SIZE_T pskLength) noexcept
    {
        if (protocol_ != TlsProtocol::Tls13 || !IsValidBuffer(psk, pskLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        const crypto::HashAlgorithm algorithm = HashForCipherSuite(secrets_.CipherSuite);
        const SIZE_T digestLength = HashLength(algorithm);
        HeapArray<UCHAR> zeroPsk(Tls13MaxSecretLength);
        if (!zeroPsk.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const UCHAR* actualPsk = psk;
        SIZE_T actualPskLength = pskLength;
        if (actualPsk == nullptr || actualPskLength == 0) {
            actualPsk = zeroPsk.Get();
            actualPskLength = digestLength;
        }

        NTSTATUS status = crypto::CngProvider::HkdfExtract(
            algorithm,
            nullptr,
            0,
            actualPsk,
            actualPskLength,
            tls13Secrets_.EarlySecret,
            sizeof(tls13Secrets_.EarlySecret),
            &tls13Secrets_.SecretLength);
        RtlSecureZeroMemory(zeroPsk.Get(), zeroPsk.Count());
        if (NT_SUCCESS(status) && tls13Secrets_.SecretLength != digestLength) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }

        return status;
    }

    NTSTATUS TlsContext::DeriveTls13HandshakeSecrets(
        const UCHAR* sharedSecret,
        SIZE_T sharedSecretLength,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength) noexcept
    {
        if (protocol_ != TlsProtocol::Tls13 ||
            sharedSecret == nullptr ||
            sharedSecretLength == 0 ||
            !IsValidBuffer(transcriptHash, transcriptHashLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (tls13Secrets_.SecretLength == 0) {
            NTSTATUS status = DeriveTls13EarlySecret(nullptr, 0);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        const crypto::HashAlgorithm algorithm = HashForCipherSuite(secrets_.CipherSuite);
        const SIZE_T digestLength = HashLength(algorithm);
        HeapArray<UCHAR> emptyHash(Tls13MaxHashLength);
        HeapArray<UCHAR> derived(Tls13MaxSecretLength);
        if (!emptyHash.IsValid() || !derived.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = DeriveEmptyHash(algorithm, emptyHash.Get(), digestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = DeriveSecret(
            algorithm,
            tls13Secrets_.EarlySecret,
            tls13Secrets_.SecretLength,
            "derived",
            emptyHash.Get(),
            digestLength,
            derived.Get(),
            digestLength);
        if (NT_SUCCESS(status)) {
            SIZE_T written = 0;
            status = crypto::CngProvider::HkdfExtract(
                algorithm,
                derived.Get(),
                digestLength,
                sharedSecret,
                sharedSecretLength,
                tls13Secrets_.HandshakeSecret,
                sizeof(tls13Secrets_.HandshakeSecret),
                &written);
            if (NT_SUCCESS(status) && written != digestLength) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        if (NT_SUCCESS(status)) {
            tls13Secrets_.SecretLength = digestLength;
            status = DeriveSecret(
                algorithm,
                tls13Secrets_.HandshakeSecret,
                digestLength,
                "c hs traffic",
                transcriptHash,
                transcriptHashLength,
                tls13Secrets_.ClientHandshakeTrafficSecret,
                digestLength);
        }

        if (NT_SUCCESS(status)) {
            status = DeriveSecret(
                algorithm,
                tls13Secrets_.HandshakeSecret,
                digestLength,
                "s hs traffic",
                transcriptHash,
                transcriptHashLength,
                tls13Secrets_.ServerHandshakeTrafficSecret,
                digestLength);
        }

        RtlSecureZeroMemory(emptyHash.Get(), emptyHash.Count());
        RtlSecureZeroMemory(derived.Get(), derived.Count());
        return status;
    }

    NTSTATUS TlsContext::DeriveTls13ClientEarlyTrafficSecret(
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength) noexcept
    {
        if (protocol_ != TlsProtocol::Tls13 ||
            tls13Secrets_.SecretLength == 0 ||
            !IsValidBuffer(transcriptHash, transcriptHashLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        const crypto::HashAlgorithm algorithm = HashForCipherSuite(secrets_.CipherSuite);
        return DeriveSecret(
            algorithm,
            tls13Secrets_.EarlySecret,
            tls13Secrets_.SecretLength,
            "c e traffic",
            transcriptHash,
            transcriptHashLength,
            tls13Secrets_.ClientEarlyTrafficSecret,
            tls13Secrets_.SecretLength);
    }

    NTSTATUS TlsContext::DeriveTls13ApplicationSecrets(
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength) noexcept
    {
        if (protocol_ != TlsProtocol::Tls13 ||
            tls13Secrets_.SecretLength == 0 ||
            !IsValidBuffer(transcriptHash, transcriptHashLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        const crypto::HashAlgorithm algorithm = HashForCipherSuite(secrets_.CipherSuite);
        const SIZE_T digestLength = HashLength(algorithm);

        HeapArray<UCHAR> emptyHash(Tls13MaxHashLength);
        HeapArray<UCHAR> derived(Tls13MaxSecretLength);
        HeapArray<UCHAR> zeroIkm(Tls13MaxSecretLength);
        if (!emptyHash.IsValid() || !derived.IsValid() || !zeroIkm.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = DeriveEmptyHash(algorithm, emptyHash.Get(), digestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = DeriveSecret(
            algorithm,
            tls13Secrets_.HandshakeSecret,
            digestLength,
            "derived",
            emptyHash.Get(),
            digestLength,
            derived.Get(),
            digestLength);

        if (NT_SUCCESS(status)) {
            SIZE_T written = 0;
            status = crypto::CngProvider::HkdfExtract(
                algorithm,
                derived.Get(),
                digestLength,
                zeroIkm.Get(),
                digestLength,
                tls13Secrets_.MasterSecret,
                sizeof(tls13Secrets_.MasterSecret),
                &written);
            if (NT_SUCCESS(status) && written != digestLength) {
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        if (NT_SUCCESS(status)) {
            status = DeriveSecret(
                algorithm,
                tls13Secrets_.MasterSecret,
                digestLength,
                "c ap traffic",
                transcriptHash,
                transcriptHashLength,
                tls13Secrets_.ClientApplicationTrafficSecret,
                digestLength);
        }

        if (NT_SUCCESS(status)) {
            status = DeriveSecret(
                algorithm,
                tls13Secrets_.MasterSecret,
                digestLength,
                "s ap traffic",
                transcriptHash,
                transcriptHashLength,
                tls13Secrets_.ServerApplicationTrafficSecret,
                digestLength);
        }

        if (NT_SUCCESS(status)) {
            status = DeriveSecret(
                algorithm,
                tls13Secrets_.MasterSecret,
                digestLength,
                "exp master",
                transcriptHash,
                transcriptHashLength,
                tls13Secrets_.ExporterMasterSecret,
                digestLength);
        }

        if (NT_SUCCESS(status)) {
            status = DeriveSecret(
                algorithm,
                tls13Secrets_.MasterSecret,
                digestLength,
                "res master",
                transcriptHash,
                transcriptHashLength,
                tls13Secrets_.ResumptionMasterSecret,
                digestLength);
        }

        RtlSecureZeroMemory(emptyHash.Get(), emptyHash.Count());
        RtlSecureZeroMemory(derived.Get(), derived.Count());
        RtlSecureZeroMemory(zeroIkm.Get(), zeroIkm.Count());
        return status;
    }

    NTSTATUS TlsContext::ConfigureTls13EarlyAesGcmState(
        TlsAeadCipherState& clientWriteState) const noexcept
    {
        if (protocol_ != TlsProtocol::Tls13 || tls13Secrets_.SecretLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return DeriveTrafficState(
            secrets_.CipherSuite,
            tls13Secrets_.ClientEarlyTrafficSecret,
            tls13Secrets_.SecretLength,
            clientWriteState);
    }

    NTSTATUS TlsContext::ConfigureTls13HandshakeAesGcmStates(
        TlsAeadCipherState& clientWriteState,
        TlsAeadCipherState& serverWriteState) const noexcept
    {
        if (protocol_ != TlsProtocol::Tls13 || tls13Secrets_.SecretLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = DeriveTrafficState(
            secrets_.CipherSuite,
            tls13Secrets_.ClientHandshakeTrafficSecret,
            tls13Secrets_.SecretLength,
            clientWriteState);
        if (NT_SUCCESS(status)) {
            status = DeriveTrafficState(
                secrets_.CipherSuite,
                tls13Secrets_.ServerHandshakeTrafficSecret,
                tls13Secrets_.SecretLength,
                serverWriteState);
        }

        return status;
    }

    NTSTATUS TlsContext::ConfigureTls13ApplicationAesGcmStates(
        TlsAeadCipherState& clientWriteState,
        TlsAeadCipherState& serverWriteState) const noexcept
    {
        if (protocol_ != TlsProtocol::Tls13 || tls13Secrets_.SecretLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = DeriveTrafficState(
            secrets_.CipherSuite,
            tls13Secrets_.ClientApplicationTrafficSecret,
            tls13Secrets_.SecretLength,
            clientWriteState);
        if (NT_SUCCESS(status)) {
            status = DeriveTrafficState(
                secrets_.CipherSuite,
                tls13Secrets_.ServerApplicationTrafficSecret,
                tls13Secrets_.SecretLength,
                serverWriteState);
        }

        return status;
    }

    NTSTATUS TlsContext::DeriveTls13FinishedKey(
        bool clientFinished,
        UCHAR* key,
        SIZE_T keyCapacity,
        SIZE_T* keyLength) const noexcept
    {
        if (keyLength != nullptr) {
            *keyLength = 0;
        }

        if (protocol_ != TlsProtocol::Tls13 ||
            key == nullptr ||
            keyLength == nullptr ||
            tls13Secrets_.SecretLength == 0 ||
            keyCapacity < tls13Secrets_.SecretLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const UCHAR* trafficSecret = clientFinished ?
            tls13Secrets_.ClientHandshakeTrafficSecret :
            tls13Secrets_.ServerHandshakeTrafficSecret;

        NTSTATUS status = HkdfExpandLabel(
            HashForCipherSuite(secrets_.CipherSuite),
            trafficSecret,
            tls13Secrets_.SecretLength,
            "finished",
            nullptr,
            0,
            key,
            tls13Secrets_.SecretLength);
        if (NT_SUCCESS(status)) {
            *keyLength = tls13Secrets_.SecretLength;
        }

        return status;
    }

    NTSTATUS TlsContext::DeriveTls13ResumptionSecret(
        const UCHAR* ticketNonce,
        SIZE_T ticketNonceLength,
        UCHAR* secret,
        SIZE_T secretCapacity,
        SIZE_T* secretLength) const noexcept
    {
        if (secretLength != nullptr) {
            *secretLength = 0;
        }

        if (protocol_ != TlsProtocol::Tls13 ||
            !IsValidBuffer(ticketNonce, ticketNonceLength) ||
            secret == nullptr ||
            secretLength == nullptr ||
            tls13Secrets_.SecretLength == 0 ||
            secretCapacity < tls13Secrets_.SecretLength) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = HkdfExpandLabel(
            HashForCipherSuite(secrets_.CipherSuite),
            tls13Secrets_.ResumptionMasterSecret,
            tls13Secrets_.SecretLength,
            "resumption",
            ticketNonce,
            ticketNonceLength,
            secret,
            tls13Secrets_.SecretLength);
        if (NT_SUCCESS(status)) {
            *secretLength = tls13Secrets_.SecretLength;
        }

        return status;
    }

    NTSTATUS TlsContext::StoreTls13Ticket(const Tls13SessionTicket& ticket) noexcept
    {
        if (ticket.IdentityLength == 0 ||
            ticket.IdentityLength > Tls13MaxTicketIdentityLength ||
            ticket.NonceLength > Tls13MaxTicketNonceLength ||
            ticket.ResumptionSecretLength == 0 ||
            ticket.ResumptionSecretLength > Tls13MaxSecretLength) {
            return STATUS_INVALID_PARAMETER;
        }

        if (tls13SessionCache_.TicketCount < Tls13MaxTicketCount) {
            tls13SessionCache_.Tickets[tls13SessionCache_.TicketCount] = ticket;
            ++tls13SessionCache_.TicketCount;
            return STATUS_SUCCESS;
        }

        for (SIZE_T index = 1; index < Tls13MaxTicketCount; ++index) {
            tls13SessionCache_.Tickets[index - 1] = tls13SessionCache_.Tickets[index];
        }
        tls13SessionCache_.Tickets[Tls13MaxTicketCount - 1] = ticket;
        return STATUS_SUCCESS;
    }

    TlsProtocolVersion TlsContext::Version() const noexcept
    {
        return version_;
    }

    TlsProtocol TlsContext::Protocol() const noexcept
    {
        return protocol_;
    }

    TlsHandshakeState TlsContext::State() const noexcept
    {
        return state_;
    }

    TlsCipherSuite TlsContext::CipherSuite() const noexcept
    {
        return secrets_.CipherSuite;
    }

    const TlsSessionSecrets& TlsContext::Secrets() const noexcept
    {
        return secrets_;
    }

    const Tls13TrafficSecrets& TlsContext::Tls13Secrets() const noexcept
    {
        return tls13Secrets_;
    }

    Tls13SessionCache& TlsContext::SessionCache() noexcept
    {
        return tls13SessionCache_;
    }

    const Tls13SessionCache& TlsContext::SessionCache() const noexcept
    {
        return tls13SessionCache_;
    }

    void TlsContext::SetState(TlsHandshakeState state) noexcept
    {
        state_ = state;
    }
}
}
