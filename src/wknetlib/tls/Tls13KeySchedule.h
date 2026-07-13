#pragma once

#include <wknet/WknetConfig.h>
#include <wknet/crypto/CngProvider.h>

namespace wknet
{
namespace tls
{
    class Tls13KeySchedule final
    {
    public:
        Tls13KeySchedule() = delete;

        _Must_inspect_result_
        static SIZE_T HashLength(crypto::HashAlgorithm algorithm) noexcept;

        _Must_inspect_result_
        static NTSTATUS BuildHkdfLabel(
            _In_z_ const char* label,
            _In_reads_bytes_opt_(contextLength) const UCHAR* context,
            SIZE_T contextLength,
            SIZE_T outputLength,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        _Must_inspect_result_
        static NTSTATUS HkdfExpandLabel(
            crypto::HashAlgorithm algorithm,
            _In_reads_bytes_(secretLength) const UCHAR* secret,
            SIZE_T secretLength,
            _In_z_ const char* label,
            _In_reads_bytes_opt_(contextLength) const UCHAR* context,
            SIZE_T contextLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS DeriveSecret(
            crypto::HashAlgorithm algorithm,
            _In_reads_bytes_(secretLength) const UCHAR* secret,
            SIZE_T secretLength,
            _In_z_ const char* label,
            _In_reads_bytes_opt_(transcriptHashLength) const UCHAR* transcriptHash,
            SIZE_T transcriptHashLength,
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength) noexcept;

        _Must_inspect_result_
        static NTSTATUS DeriveEmptyHash(
            crypto::HashAlgorithm algorithm,
            _Out_writes_bytes_(hashLength) UCHAR* hash,
            SIZE_T hashLength) noexcept;
    };

    // Thin source-compatibility adapters for existing TLS call sites. The
    // implementation remains uniquely owned by Tls13KeySchedule.
    inline NTSTATUS HkdfExpandLabel(
        crypto::HashAlgorithm algorithm,
        const UCHAR* secret,
        SIZE_T secretLength,
        const char* label,
        const UCHAR* context,
        SIZE_T contextLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        return Tls13KeySchedule::HkdfExpandLabel(
            algorithm,
            secret,
            secretLength,
            label,
            context,
            contextLength,
            output,
            outputLength);
    }

    inline NTSTATUS DeriveSecret(
        crypto::HashAlgorithm algorithm,
        const UCHAR* secret,
        SIZE_T secretLength,
        const char* label,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength,
        UCHAR* output,
        SIZE_T outputLength) noexcept
    {
        return Tls13KeySchedule::DeriveSecret(
            algorithm,
            secret,
            secretLength,
            label,
            transcriptHash,
            transcriptHashLength,
            output,
            outputLength);
    }

    inline NTSTATUS DeriveEmptyHash(
        crypto::HashAlgorithm algorithm,
        UCHAR* hash,
        SIZE_T hashLength) noexcept
    {
        return Tls13KeySchedule::DeriveEmptyHash(algorithm, hash, hashLength);
    }
}
}
