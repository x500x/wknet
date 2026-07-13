#include "tls/TlsTranscriptHash.h"

namespace wknet
{
namespace tls
{
    namespace
    {
        constexpr UCHAR Tls13MessageHashType = 254;

        SIZE_T HashLength(crypto::HashAlgorithm algorithm) noexcept
        {
            switch (algorithm) {
            case crypto::HashAlgorithm::Sha1:
                return 20;
            case crypto::HashAlgorithm::Sha384:
                return 48;
            case crypto::HashAlgorithm::Sha512:
                return 64;
            case crypto::HashAlgorithm::Sha256:
            default:
                return 32;
            }
        }
    }

    NTSTATUS TlsTranscriptHash::Initialize(crypto::HashAlgorithm algorithm) noexcept
    {
        Reset();
        algorithm_ = algorithm;
        const NTSTATUS status = hash_.Initialize(algorithm);
        initialized_ = NT_SUCCESS(status);
        return status;
    }

    void TlsTranscriptHash::Reset() noexcept
    {
        hash_.Reset();
        initialized_ = false;
    }

    NTSTATUS TlsTranscriptHash::Update(const UCHAR* data, SIZE_T dataLength) noexcept
    {
        if (!initialized_ || (data == nullptr && dataLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        return hash_.Update(data, dataLength);
    }

    NTSTATUS TlsTranscriptHash::Snapshot(
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) const noexcept
    {
        if (!initialized_ || output == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        return hash_.Finish(output, outputLength, bytesWritten);
    }

    NTSTATUS TlsTranscriptHash::Finish(
        UCHAR* output,
        SIZE_T outputLength,
        SIZE_T* bytesWritten) const noexcept
    {
        return Snapshot(output, outputLength, bytesWritten);
    }

    NTSTATUS TlsTranscriptHash::ReplaceWithMessageHash(
        const UCHAR* clientHelloHash,
        SIZE_T clientHelloHashLength) noexcept
    {
        const SIZE_T expectedLength = HashLength(algorithm_);
        if (!initialized_ || clientHelloHash == nullptr || clientHelloHashLength != expectedLength) {
            return STATUS_INVALID_PARAMETER;
        }

        const UCHAR messageType = Tls13MessageHashType;
        const UCHAR lengthHigh = static_cast<UCHAR>((clientHelloHashLength >> 16) & 0xff);
        const UCHAR lengthMiddle = static_cast<UCHAR>((clientHelloHashLength >> 8) & 0xff);
        const UCHAR lengthLow = static_cast<UCHAR>(clientHelloHashLength & 0xff);

        NTSTATUS status = Initialize(algorithm_);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = Update(&messageType, sizeof(messageType));
        if (NT_SUCCESS(status)) {
            status = Update(&lengthHigh, sizeof(lengthHigh));
        }
        if (NT_SUCCESS(status)) {
            status = Update(&lengthMiddle, sizeof(lengthMiddle));
        }
        if (NT_SUCCESS(status)) {
            status = Update(&lengthLow, sizeof(lengthLow));
        }
        if (NT_SUCCESS(status)) {
            status = Update(clientHelloHash, clientHelloHashLength);
        }
        return status;
    }
}
}
