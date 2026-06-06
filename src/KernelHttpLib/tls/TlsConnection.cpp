#include <KernelHttp/tls/TlsConnection.h>

#include <KernelHttp/crypto/CngProviderCache.h>
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
        constexpr SIZE_T TlsScratchClientHelloLength = 2048;
        constexpr SIZE_T TlsScratchFirstClientHelloOffset =
            TlsScratchClientHelloOffset + TlsScratchClientHelloLength;
        constexpr SIZE_T TlsScratchFirstClientHelloLength = 2048;
        constexpr SIZE_T TlsScratchSecondClientHelloOffset =
            TlsScratchFirstClientHelloOffset + TlsScratchFirstClientHelloLength;
        constexpr SIZE_T TlsScratchSecondClientHelloLength = 2048;
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
        constexpr SIZE_T TlsScratchSignedDataLength = (TlsRandomLength * 2) + 256;
        constexpr SIZE_T TlsScratchHandshakeBufferOffset =
            TlsScratchSignedDataOffset + TlsScratchSignedDataLength;
        constexpr SIZE_T TlsScratchHandshakeBufferLength = TlsHandshakeBufferLength;
        constexpr SIZE_T TlsScratchRequiredLength =
            TlsScratchHandshakeBufferOffset + TlsScratchHandshakeBufferLength;

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
        NTSTATUS ToSignatureAlgorithm(
            TlsSignatureScheme scheme,
            _Out_ crypto::SignatureAlgorithm* algorithm) noexcept
        {
            if (algorithm == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            switch (scheme) {
            case TlsSignatureScheme::RsaPkcs1Sha256:
                *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPkcs1Sha384:
                *algorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha384;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSecp256r1Sha256:
                *algorithm = crypto::SignatureAlgorithm::EcdsaSha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSecp384r1Sha384:
                *algorithm = crypto::SignatureAlgorithm::EcdsaSha384;
                return STATUS_SUCCESS;
            default:
                return STATUS_NOT_SUPPORTED;
            }
        }

        _Must_inspect_result_
        crypto::HashAlgorithm HashForSignature(TlsSignatureScheme scheme) noexcept
        {
            switch (scheme) {
            case TlsSignatureScheme::RsaPkcs1Sha384:
            case TlsSignatureScheme::EcdsaSecp384r1Sha384:
                return crypto::HashAlgorithm::Sha384;
            default:
                return crypto::HashAlgorithm::Sha256;
            }
        }

        _Must_inspect_result_
        bool IsValidBuffer(const void* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
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
        const UCHAR Tls12DowngradeSentinel[] = { 'D', 'O', 'W', 'N', 'G', 'R', 'D', 0x01 };
        const UCHAR TlsLegacyDowngradeSentinel[] = { 'D', 'O', 'W', 'N', 'G', 'R', 'D', 0x00 };
        _Must_inspect_result_
        bool ProtocolAllowed(const TlsClientConnectionOptions& options, TlsProtocol protocol) noexcept
        {
            return static_cast<UCHAR>(options.MinimumProtocol) <= static_cast<UCHAR>(protocol) &&
                static_cast<UCHAR>(protocol) <= static_cast<UCHAR>(options.MaximumProtocol);
        }

        _Must_inspect_result_
        bool HasDowngradeSentinel(_In_ const TlsServerHelloView& serverHello) noexcept
        {
            if (serverHello.Random == nullptr || serverHello.RandomLength != TlsRandomLength) {
                return false;
            }

            const UCHAR* suffix = serverHello.Random + TlsRandomLength - sizeof(Tls12DowngradeSentinel);
            return RtlCompareMemory(suffix, Tls12DowngradeSentinel, sizeof(Tls12DowngradeSentinel)) ==
                    sizeof(Tls12DowngradeSentinel) ||
                RtlCompareMemory(suffix, TlsLegacyDowngradeSentinel, sizeof(TlsLegacyDowngradeSentinel)) ==
                    sizeof(TlsLegacyDowngradeSentinel);
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
                    // ALPN extension: 2 bytes list length, then 1 byte proto length + proto
                    if (currentLength < 4) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const UCHAR* extData = serverHello.Extensions + offset;
                    // Skip list length (2 bytes)
                    SIZE_T protoLen = extData[2];
                    if (protoLen == 0 || protoLen + 3 > currentLength) {
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
        NTSTATUS GetTls13SignatureParameters(
            TlsSignatureScheme scheme,
            _Out_ crypto::HashAlgorithm* hashAlgorithm,
            _Out_ crypto::SignatureAlgorithm* signatureAlgorithm) noexcept
        {
            if (hashAlgorithm == nullptr || signatureAlgorithm == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            switch (scheme) {
            case TlsSignatureScheme::RsaPssRsaeSha256:
                *hashAlgorithm = crypto::HashAlgorithm::Sha256;
                *signatureAlgorithm = crypto::SignatureAlgorithm::RsaPssSha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPssRsaeSha384:
                *hashAlgorithm = crypto::HashAlgorithm::Sha384;
                *signatureAlgorithm = crypto::SignatureAlgorithm::RsaPssSha384;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSecp256r1Sha256:
                *hashAlgorithm = crypto::HashAlgorithm::Sha256;
                *signatureAlgorithm = crypto::SignatureAlgorithm::EcdsaSha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::EcdsaSecp384r1Sha384:
                *hashAlgorithm = crypto::HashAlgorithm::Sha384;
                *signatureAlgorithm = crypto::SignatureAlgorithm::EcdsaSha384;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPkcs1Sha256:
                *hashAlgorithm = crypto::HashAlgorithm::Sha256;
                *signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
                return STATUS_SUCCESS;
            case TlsSignatureScheme::RsaPkcs1Sha384:
                *hashAlgorithm = crypto::HashAlgorithm::Sha384;
                *signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha384;
                return STATUS_SUCCESS;
            default:
                *hashAlgorithm = crypto::HashAlgorithm::Sha256;
                *signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
                return STATUS_NOT_SUPPORTED;
            }
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
        delete[] inputBuffer_;
        delete[] outputBuffer_;
        delete[] tls13InnerPlaintextBuffer_;
        delete[] plaintextBuffer_;
        delete[] negotiatedAlpn_;
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
        handshakeBuffer_ = nullptr;
        handshakeLength_ = 0;
        handshakeConsumed_ = 0;
        lastHandshakeOffset_ = 0;
        lastHandshakeLength_ = 0;
        handshakeReceiveTimeoutMilliseconds_ = TlsHandshakeReceiveTimeoutMilliseconds;
        encrypted_ = false;
        tls13RecordProtection_ = false;
        if (negotiatedAlpn_ != nullptr) {
            RtlSecureZeroMemory(negotiatedAlpn_, 16);
        }
        negotiatedAlpnLength_ = 0;
    }

    NTSTATUS TlsConnection::EnsureBuffers() noexcept
    {
        if (inputBuffer_ == nullptr) {
            inputBuffer_ = new UCHAR[TlsIoBufferLength]();
            if (inputBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (outputBuffer_ == nullptr) {
            outputBuffer_ = new UCHAR[TlsIoBufferLength]();
            if (outputBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (tls13InnerPlaintextBuffer_ == nullptr) {
            tls13InnerPlaintextBuffer_ = new UCHAR[TlsMaxPlaintextLength + 1]();
            if (tls13InnerPlaintextBuffer_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        if (plaintextBuffer_ == nullptr) {
            plaintextBuffer_ = new UCHAR[TlsApplicationBufferLength]();
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
            negotiatedAlpn_ = new char[16]();
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
                delete[] ownedTlsScratch_;
                ownedTlsScratch_ = nullptr;
                ownedTlsScratchLength_ = 0;
            }

            ownedTlsScratch_ = new UCHAR[TlsScratchRequiredLength];
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
            delete[] ownedTlsScratch_;
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
        if (options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            options.HandshakeReceiveTimeoutMilliseconds == 0 ||
            (options.VerifyCertificate && options.CertificateStore == nullptr) ||
            static_cast<UCHAR>(options.MinimumProtocol) > static_cast<UCHAR>(options.MaximumProtocol)) {
            return STATUS_INVALID_PARAMETER;
        }

        Reset();
        handshakeReceiveTimeoutMilliseconds_ = options.HandshakeReceiveTimeoutMilliseconds;

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

        if (ProtocolAllowed(options, TlsProtocol::Tls13) && HasDowngradeSentinel(serverHello)) {
            kprintf("TlsConnection rejected TLS downgrade sentinel\r\n");
            return STATUS_INVALID_NETWORK_RESPONSE;
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

        CertificateValidationResult validationResult = {};
        CertificateChainView chain = {};
        chain.Certificates = certificates.Certificates;
        chain.CertificatesLength = certificates.CertificatesLength;
        chain.CertificateCount = certificates.CertificateCount;
        status = CertificateValidator::ValidateChain(chain, validation, &validationResult);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection validate Certificate failed: 0x%08X count=%Iu bytes=%Iu\r\n",
                static_cast<ULONG>(status),
                chain.CertificateCount,
                chain.CertificatesLength);
            return status;
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = CertificateValidator::ImportSubjectPublicKey(providerCache_, validationResult.Leaf, *serverPublicKey.Get());
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection import server public key failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read ServerKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsServerKeyExchangeView keyExchange = {};
        status = TlsHandshake12::ParseServerKeyExchange(context_, handshake, keyExchange);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerKeyExchange failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }

        status = VerifyServerKeyExchange(keyExchange, *serverPublicKey.Get());
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection verify ServerKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapObject<crypto::CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

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

        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read ServerHelloDone failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            TlsCertificateRequestView request = {};
            status = TlsHandshake12::ParseCertificateRequest(context_, handshake, request);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message[0] = static_cast<UCHAR>(TlsHandshakeType::Certificate);
            message[1] = 0;
            message[2] = 0;
            message[3] = 3;
            message[4] = 0;
            message[5] = 0;
            message[6] = 0;
            messageLength = 7;

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

        status = GenerateClientKeyExchange(
            keyExchange.NamedGroup,
            *peerKey.Get(),
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection generate ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        static const UCHAR changeCipherSpec[] = { 1 };
        status = SendPlainRecord(transport, TlsContentType::ChangeCipherSpec, changeCipherSpec, sizeof(changeCipherSpec));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send ChangeCipherSpec failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!transcriptHash.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T transcriptHashLength = 0;
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

        status = AppendTranscript(handshakeBuffer_, handshakeLength_);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection append server Finished transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

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

        HeapObject<crypto::CngKey> privateKey;
        if (!privateKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = crypto::CngProvider::GenerateEcdhKeyPair(providerCache_, crypto::EcCurve::P256, *privateKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> publicPoint(1 + (66 * 2));
        if (!publicPoint.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T publicPointLength = 0;
#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        HeapArray<UCHAR> publicBlob(sizeof(BCRYPT_ECCKEY_BLOB) + (66 * 2));
        if (!publicBlob.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T publicBlobLength = 0;
        status = privateKey->ExportPublicKey(BCRYPT_ECCPUBLIC_BLOB, publicBlob.Get(), publicBlob.Count(), &publicBlobLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(publicBlob.Get());
        publicPointLength = (static_cast<SIZE_T>(header->cbKey) * 2) + 1;
        if (publicPointLength > publicPoint.Count() ||
            publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB) + (static_cast<SIZE_T>(header->cbKey) * 2)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        publicPoint[0] = 4;
        RtlCopyMemory(publicPoint.Get() + 1, publicBlob.Get() + sizeof(BCRYPT_ECCKEY_BLOB), header->cbKey * 2);
#else
        status = privateKey->ExportPublicKey(L"ECCPUBLICBLOB", publicPoint.Get(), publicPoint.Count(), &publicPointLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
#endif

        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::Secp256r1;
        keyShare.KeyExchange = publicPoint.Get();
        keyShare.KeyExchangeLength = publicPointLength;

        Tls13PskIdentity pskIdentity = {};
        const UCHAR* resumptionSecret = nullptr;
        SIZE_T resumptionSecretLength = 0;
        bool earlyDataAllowed = false;
        status = SelectTls13Ticket(
            options,
            pskIdentity,
            &resumptionSecret,
            &resumptionSecretLength,
            &earlyDataAllowed);
        if (status == STATUS_NOT_FOUND) {
            status = STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> binder(Tls13MaxBinderLength);
        if (!binder.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
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
            return status;
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
            return status;
        }

        if (pskIdentity.IdentityLength != 0) {
            HeapArray<UCHAR> partialHash(TlsMaxTranscriptHashLength);
            if (!partialHash.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T partialHashLength = 0;
            SIZE_T binderTranscriptLength = 0;
            status = TlsHandshake13::FindPskBinderTranscriptLength(
                message,
                messageLength,
                &binderTranscriptLength);
            if (NT_SUCCESS(status)) {
                status = crypto::CngProvider::Hash(
                    providerCache_,
                    TlsHandshake13::HashForCipherSuite(context_.CipherSuite()),
                    message,
                    binderTranscriptLength,
                    partialHash.Get(),
                    partialHash.Count(),
                    &partialHashLength);
            }
            if (NT_SUCCESS(status)) {
                status = TlsHandshake13::ComputePskBinder(
                    context_,
                    resumptionSecret,
                    resumptionSecretLength,
                    partialHash.Get(),
                    partialHashLength,
                    binder.Get(),
                    binder.Count(),
                    &pskIdentity.BinderLength);
            }
            RtlSecureZeroMemory(partialHash.Get(), partialHash.Count());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = TlsHandshake13::EncodeClientHello(
                context_,
                hello,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        UCHAR* firstClientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchFirstClientHelloOffset,
            TlsScratchFirstClientHelloLength,
            &firstClientHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(firstClientHello, TlsScratchFirstClientHelloLength);
        SIZE_T firstClientHelloLength = messageLength;
        if (firstClientHelloLength > TlsScratchFirstClientHelloLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(firstClientHello, message, firstClientHelloLength);

        UCHAR* secondClientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchSecondClientHelloOffset,
            TlsScratchSecondClientHelloLength,
            &secondClientHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(secondClientHello, TlsScratchSecondClientHelloLength);
        SIZE_T secondClientHelloLength = 0;
        UCHAR* helloRetryRequest = nullptr;
        status = GetHandshakeScratch(
            TlsScratchHelloRetryOffset,
            TlsScratchHelloRetryLength,
            &helloRetryRequest);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(helloRetryRequest, TlsScratchHelloRetryLength);
        SIZE_T helloRetryRequestLength = 0;
        bool usedHelloRetryRequest = false;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecordWithVersion(transport, { 3, 3 }, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (hello.OfferEarlyData && options.EarlyData != nullptr && options.EarlyDataLength != 0) {
            HeapArray<UCHAR> clientHelloHash(TlsMaxTranscriptHashLength);
            if (!clientHelloHash.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
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
                return status;
            }

            SIZE_T sent = 0;
            while (sent < options.EarlyDataLength) {
                const SIZE_T chunk = (options.EarlyDataLength - sent) > TlsMaxPlaintextLength ?
                    TlsMaxPlaintextLength :
                    (options.EarlyDataLength - sent);
                status = SendProtectedRecord13(
                    transport,
                    TlsContentType::ApplicationData,
                    options.EarlyData + sent,
                    chunk);
                if (!NT_SUCCESS(status)) {
                    return status;
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
            return status;
        }

        Tls13ServerHelloView serverHello = {};
        status = TlsHandshake13::ParseServerHello(context_, handshake, serverHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (serverHello.IsHelloRetryRequest) {
            usedHelloRetryRequest = true;
            helloRetryRequestLength = lastHandshakeLength_;
            if (helloRetryRequestLength > TlsScratchHelloRetryLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            RtlCopyMemory(helloRetryRequest, handshakeBuffer_ + lastHandshakeOffset_, helloRetryRequestLength);

            if (serverHello.RetryGroup != TlsNamedGroup::Secp384r1 &&
                serverHello.RetryGroup != TlsNamedGroup::Secp521r1 &&
                serverHello.RetryGroup != TlsNamedGroup::Secp256r1) {
                return STATUS_NOT_SUPPORTED;
            }

            privateKey->Close();
            status = crypto::CngProvider::GenerateEcdhKeyPair(
                providerCache_,
                ToEcCurve(serverHello.RetryGroup),
                *privateKey.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
            RtlSecureZeroMemory(publicBlob.Get(), publicBlob.Count());
            publicBlobLength = 0;
            status = privateKey->ExportPublicKey(BCRYPT_ECCPUBLIC_BLOB, publicBlob.Get(), publicBlob.Count(), &publicBlobLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(publicBlob.Get());
            publicPointLength = (static_cast<SIZE_T>(header->cbKey) * 2) + 1;
            if (publicPointLength > publicPoint.Count() ||
                publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB) + (static_cast<SIZE_T>(header->cbKey) * 2)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            publicPoint[0] = 4;
            RtlCopyMemory(publicPoint.Get() + 1, publicBlob.Get() + sizeof(BCRYPT_ECCKEY_BLOB), header->cbKey * 2);
#else
            status = privateKey->ExportPublicKey(L"ECCPUBLICBLOB", publicPoint.Get(), publicPoint.Count(), &publicPointLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
#endif

            keyShare.Group = serverHello.RetryGroup;
            keyShare.KeyExchange = publicPoint.Get();
            keyShare.KeyExchangeLength = publicPointLength;
            status = TlsHandshake13::EncodeClientHello(
                context_,
                hello,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            secondClientHelloLength = messageLength;
            if (secondClientHelloLength > TlsScratchSecondClientHelloLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            RtlCopyMemory(secondClientHello, message, secondClientHelloLength);

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendPlainRecordWithVersion(transport, { 3, 3 }, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadHandshakeMessage13(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = TlsHandshake13::ParseServerHello(context_, handshake, serverHello);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (serverHello.IsHelloRetryRequest) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        HeapObject<crypto::CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = crypto::CngProvider::ImportEcdhPublicKey(
            providerCache_,
            ToEcCurve(serverHello.KeyShare.Group),
            serverHello.KeyShare.KeyExchange,
            serverHello.KeyShare.KeyExchangeLength,
            *peerKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> sharedSecret(66);
        if (!sharedSecret.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T sharedSecretLength = 0;
        status = crypto::CngProvider::DeriveEcdhSecret(
            providerCache_,
            *privateKey.Get(),
            *peerKey.Get(),
            sharedSecret.Get(),
            sharedSecret.Count(),
            &sharedSecretLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return status;
        }

        status = transcript_.Initialize(TlsHandshake13::HashForCipherSuite(context_.CipherSuite()));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return status;
        }

        if (usedHelloRetryRequest) {
            HeapArray<UCHAR> firstHash(TlsMaxTranscriptHashLength);
            if (!firstHash.IsValid()) {
                RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
                return STATUS_INSUFFICIENT_RESOURCES;
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
            return status;
        }

        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!transcriptHash.IsValid()) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return STATUS_INSUFFICIENT_RESOURCES;
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
            return status;
        }

        encrypted_ = true;
        tls13RecordProtection_ = true;

        status = ReadOptionalCompatibilityChangeCipherSpec(transport);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        Tls13EncryptedExtensionsView encryptedExtensions = {};
        status = TlsHandshake13::ParseEncryptedExtensions(handshake, encryptedExtensions);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (encryptedExtensions.AlpnLength != 0) {
            if (encryptedExtensions.AlpnLength >= 16) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            RtlCopyMemory(negotiatedAlpn_, encryptedExtensions.Alpn, encryptedExtensions.AlpnLength);
            negotiatedAlpn_[encryptedExtensions.AlpnLength] = '\0';
            negotiatedAlpnLength_ = encryptedExtensions.AlpnLength;
        }
        if (options.EarlyDataAccepted != nullptr) {
            *options.EarlyDataAccepted = encryptedExtensions.EarlyDataAccepted;
        }
        if (hello.OfferEarlyData &&
            options.EarlyData != nullptr &&
            options.EarlyDataLength != 0 &&
            !encryptedExtensions.EarlyDataAccepted) {
            return STATUS_NOT_SUPPORTED;
        }

        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            Tls13CertificateRequestView certificateRequest = {};
            status = TlsHandshake13::ParseCertificateRequest(handshake, certificateRequest);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return STATUS_NOT_SUPPORTED;
        }

        Tls13CertificateView certificate = {};
        status = TlsHandshake13::ParseCertificate(handshake, certificate);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ValidateTls13Certificate(certificate, options, *serverPublicKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadHandshakeMessage13(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return status;
        }

        Tls13CertificateVerifyView certificateVerify = {};
        status = TlsHandshake13::ParseCertificateVerify(handshake, certificateVerify);
        if (NT_SUCCESS(status)) {
            status = VerifyTls13CertificateVerify(
                certificateVerify,
                *serverPublicKey.Get(),
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ReadHandshakeMessage13(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return status;
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
            return status;
        }

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = context_.DeriveTls13ApplicationSecrets(transcriptHash.Get(), transcriptHashLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return status;
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
            return status;
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = context_.ConfigureTls13ApplicationAesGcmStates(clientWriteState_, serverWriteState_);
        if (!NT_SUCCESS(status)) {
            return status;
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
            const SIZE_T chunk = (length - sent) > TlsMaxPlaintextLength ? TlsMaxPlaintextLength : (length - sent);
            NTSTATUS status = tls13RecordProtection_ ?
                SendProtectedRecord13(transport, TlsContentType::ApplicationData, bytes + sent, chunk) :
                SendProtectedRecord(transport, TlsContentType::ApplicationData, bytes + sent, chunk);
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
        for (;;) {
            TlsMutablePlaintextRecord record = {};
            NTSTATUS status = ReadRecord(transport, record, receiveTimeoutMilliseconds, &receiveDeadline);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection read record failed before HTTP: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }

            if (tls13RecordProtection_ && record.ContentType == TlsContentType::Handshake) {
                status = ConsumeTls13PostHandshakeRecord(record.Fragment, record.FragmentLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                continue;
            }

            if (!tls13RecordProtection_ &&
                context_.Protocol() == TlsProtocol::Tls12 &&
                record.ContentType == TlsContentType::Handshake) {
                status = ConsumeOptionalPlainHandshakeRecord(record.Fragment, record.FragmentLength);
                if (!NT_SUCCESS(status)) {
                    kprintf("TlsConnection consume TLS1.2 NewSessionTicket during HTTP read failed: 0x%08X length=%Iu\r\n",
                        static_cast<ULONG>(status),
                        record.FragmentLength);
                    return status;
                }
                continue;
            }

            if (record.ContentType == TlsContentType::Alert) {
                kprintf("TlsConnection receive alert during HTTP read length=%Iu\r\n", record.FragmentLength);
                return STATUS_CONNECTION_DISCONNECTED;
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

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm(record, clientWriteState_, outputBuffer_, TlsIoBufferLength, &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(transport, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, TlsIoBufferLength);
        return status;
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

            if (encrypted_ && view.ContentType != TlsContentType::ChangeCipherSpec) {
                if (tls13RecordProtection_) {
                    status = TlsRecordLayer::UnprotectAesGcm13(
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
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS TlsConnection::ReadServerChangeCipherSpec(
        core::ITransport& transport,
        bool allowNewSessionTicket) noexcept
    {
        for (;;) {
            TlsMutablePlaintextRecord record = {};
            NTSTATUS status = ReadRecord(transport, record, handshakeReceiveTimeoutMilliseconds_);
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
                    handshakeReceiveTimeoutMilliseconds_);
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
                handshakeReceiveTimeoutMilliseconds_);
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
            return status;
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
            return status;
        }

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = options.ProviderCache;
        validation.VerifyCertificate = options.VerifyCertificate;

        CertificateChainView chain = {};
        chain.Certificates = legacyCertificateList;
        chain.CertificatesLength = legacyCertificateListLength;
        chain.CertificateCount = certificateCount;

        CertificateValidationResult result = {};
        status = CertificateValidator::ValidateChain(chain, validation, &result);
        if (NT_SUCCESS(status)) {
            status = CertificateValidator::ImportSubjectPublicKey(providerCache_, result.Leaf, serverPublicKey);
        }
        RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
        return status;
    }

    NTSTATUS TlsConnection::VerifyTls13CertificateVerify(
        const Tls13CertificateVerifyView& certificateVerify,
        const crypto::CngKey& serverPublicKey,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength) noexcept
    {
        crypto::HashAlgorithm hashAlgorithm = crypto::HashAlgorithm::Sha256;
        crypto::SignatureAlgorithm signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        NTSTATUS status = GetTls13SignatureParameters(
            certificateVerify.SignatureScheme,
            &hashAlgorithm,
            &signatureAlgorithm);
        if (!NT_SUCCESS(status)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        UCHAR* signedInput = nullptr;
        status = GetHandshakeScratch(
            TlsScratchSignedInputOffset,
            TlsScratchSignedInputLength,
            &signedInput);
        if (!NT_SUCCESS(status)) {
            return status;
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
            return status;
        }

        HeapArray<UCHAR> hash(48);
        if (!hash.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
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
            return status;
        }

        status = crypto::CngProvider::VerifySignature(
            providerCache_,
            signatureAlgorithm,
            serverPublicKey,
            hash.Get(),
            hashLength,
            certificateVerify.Signature,
            certificateVerify.SignatureLength);
        RtlSecureZeroMemory(hash.Get(), hash.Count());
        return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
    }

    NTSTATUS TlsConnection::StoreTls13Ticket(
        const Tls13NewSessionTicketView& ticket,
        Tls13SessionCache* externalCache) noexcept
    {
        if (ticket.Ticket == nullptr ||
            ticket.TicketLength == 0 ||
            ticket.TicketLength > Tls13MaxTicketIdentityLength ||
            ticket.NonceLength > Tls13MaxTicketNonceLength) {
            return STATUS_INVALID_PARAMETER;
        }

        Tls13SessionTicket stored = {};
        stored.IdentityLength = ticket.TicketLength;
        RtlCopyMemory(stored.Identity, ticket.Ticket, ticket.TicketLength);
        stored.NonceLength = ticket.NonceLength;
        if (ticket.NonceLength != 0) {
            RtlCopyMemory(stored.Nonce, ticket.Nonce, ticket.NonceLength);
        }
        stored.LifetimeSeconds = ticket.LifetimeSeconds;
        stored.AgeAdd = ticket.AgeAdd;
        stored.MaxEarlyDataSize = ticket.MaxEarlyDataSize;
        stored.CipherSuite = context_.CipherSuite();

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
        bool* earlyDataAllowed) noexcept
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

        if (resumptionSecret == nullptr || resumptionSecretLength == nullptr || earlyDataAllowed == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!options.EnableSessionResumption || options.SessionCache == nullptr || options.SessionCache->TicketCount == 0) {
            return STATUS_NOT_FOUND;
        }

        for (SIZE_T index = options.SessionCache->TicketCount; index > 0; --index) {
            const Tls13SessionTicket& ticket = options.SessionCache->Tickets[index - 1];
            if (ticket.IdentityLength == 0 ||
                ticket.IdentityLength > Tls13MaxTicketIdentityLength ||
                ticket.ResumptionSecretLength == 0 ||
                ticket.CipherSuite != context_.CipherSuite()) {
                continue;
            }

            identity.Identity = ticket.Identity;
            identity.IdentityLength = ticket.IdentityLength;
            identity.ObfuscatedTicketAge = ticket.AgeAdd;
            *resumptionSecret = ticket.ResumptionSecret;
            *resumptionSecretLength = ticket.ResumptionSecretLength;
            *earlyDataAllowed = options.EnableEarlyData &&
                ticket.MaxEarlyDataSize != 0 &&
                options.EarlyData != nullptr &&
                options.EarlyDataLength <= ticket.MaxEarlyDataSize;
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

            Tls12NewSessionTicketView ticket = {};
            status = TlsHandshake12::ParseNewSessionTicket(parsed, ticket);
            if (!NT_SUCCESS(status)) {
                if (status == STATUS_NOT_SUPPORTED) {
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                return status;
            }

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

    NTSTATUS TlsConnection::ConsumeTls13PostHandshakeRecord(const UCHAR* fragment, SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr || fragmentLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T offset = 0;
        while (offset < fragmentLength) {
            Tls13NewSessionTicketView ticket = {};
            const NTSTATUS parseStatus = TlsHandshake13::ParseNextNewSessionTicket(
                fragment,
                fragmentLength,
                &offset,
                ticket);
            if (!NT_SUCCESS(parseStatus)) {
                return parseStatus;
            }

            const NTSTATUS status = StoreTls13Ticket(ticket, nullptr);
            if (!NT_SUCCESS(status)) {
                return status;
            }
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
                status = ReadRecord(transport, record, handshakeReceiveTimeoutMilliseconds_);
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

        HeapArray<UCHAR> hash(48);
        if (!hash.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T hashLength = 0;
        status = crypto::CngProvider::Hash(
            providerCache_,
            HashForSignature(keyExchange.SignatureScheme),
            signedData,
            (TlsRandomLength * 2) + keyExchange.ParametersLength,
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
        TlsNamedGroup namedGroup,
        const crypto::CngKey& peerKey,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *bytesWritten = 0;

        HeapObject<crypto::CngKey> privateKey;
        if (!privateKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS status = crypto::CngProvider::GenerateEcdhKeyPair(
            providerCache_,
            ToEcCurve(namedGroup),
            *privateKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        HeapArray<UCHAR> publicBlob(sizeof(BCRYPT_ECCKEY_BLOB) + (66 * 2));
        if (!publicBlob.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T publicBlobLength = 0;
        status = privateKey->ExportPublicKey(BCRYPT_ECCPUBLIC_BLOB, publicBlob.Get(), publicBlob.Count(), &publicBlobLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(publicBlob.Get());
        const SIZE_T pointLength = (static_cast<SIZE_T>(header->cbKey) * 2) + 1;
        HeapArray<UCHAR> publicPoint(1 + (66 * 2));
        if (!publicPoint.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (pointLength > publicPoint.Count() ||
            publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB) + (static_cast<SIZE_T>(header->cbKey) * 2)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        publicPoint[0] = 4;
        RtlCopyMemory(publicPoint.Get() + 1, publicBlob.Get() + sizeof(BCRYPT_ECCKEY_BLOB), header->cbKey * 2);
#else
        HeapArray<UCHAR> publicPoint(65);
        if (!publicPoint.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T pointLength = 0;
        status = privateKey->ExportPublicKey(L"ECCPUBLICBLOB", publicPoint.Get(), publicPoint.Count(), &pointLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
#endif

        HeapArray<UCHAR> premasterSecret(66);
        if (!premasterSecret.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T secretLength = 0;
        status = crypto::CngProvider::DeriveEcdhSecret(
            providerCache_,
            *privateKey.Get(),
            peerKey,
            premasterSecret.Get(),
            premasterSecret.Count(),
            &secretLength);
        if (NT_SUCCESS(status)) {
            status = context_.DeriveMasterSecret(premasterSecret.Get(), secretLength);
        }
        RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        TlsKeyBlock keyBlock = {};
        const SIZE_T keyLength =
            (context_.CipherSuite() == TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 ||
                context_.CipherSuite() == TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384) ? 32 : 16;
        status = context_.DeriveKeyBlock(keyBlock, (keyLength * 2) + (TlsAesGcmFixedIvLength * 2));
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureAesGcmStates(keyBlock, clientWriteState_, serverWriteState_);
        }
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return TlsHandshake12::EncodeClientKeyExchange(
            publicPoint.Get(),
            pointLength,
            destination,
            destinationCapacity,
            bytesWritten);
    }
}
}
