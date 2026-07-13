#include "tls/Tls13KeySchedule.h"

namespace wknet
{
namespace tls
{
    SIZE_T Tls13KeySchedule::HashLength(crypto::HashAlgorithm algorithm) noexcept
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

    NTSTATUS Tls13KeySchedule::BuildHkdfLabel(
        const char* label,
        const UCHAR* context,
        SIZE_T contextLength,
        SIZE_T outputLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
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

        static constexpr char LabelPrefix[] = "tls13 ";
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

    NTSTATUS Tls13KeySchedule::HkdfExpandLabel(
        crypto::HashAlgorithm algorithm,
        const UCHAR* secret,
        SIZE_T secretLength,
        const char* label,
        const UCHAR* context,
        SIZE_T contextLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        if (secret == nullptr || secretLength == 0 || output == nullptr || outputLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

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
        if (NT_SUCCESS(status)) {
            status = crypto::CngProvider::HkdfExpand(
                algorithm,
                secret,
                secretLength,
                info.Get(),
                infoLength,
                output,
                outputLength);
        }

        RtlSecureZeroMemory(info.Get(), info.Count());
        return status;
    }

    NTSTATUS Tls13KeySchedule::DeriveSecret(
        crypto::HashAlgorithm algorithm,
        const UCHAR* secret,
        SIZE_T secretLength,
        const char* label,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength,
        UCHAR* output,
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

    NTSTATUS Tls13KeySchedule::DeriveEmptyHash(
        crypto::HashAlgorithm algorithm,
        UCHAR* hash,
        SIZE_T hashLength) noexcept
    {
        if (hash == nullptr || hashLength != HashLength(algorithm)) {
            return STATUS_INVALID_PARAMETER;
        }

        return crypto::CngProvider::Hash(algorithm, nullptr, 0, hash, hashLength);
    }
}
}
