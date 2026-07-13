#pragma once

#include <wknet/WknetConfig.h>
#include <wknet/crypto/CngProvider.h>

namespace wknet
{
namespace tls
{
    constexpr SIZE_T TlsMaxTranscriptHashLength = 64;

    class TlsTranscriptHash final
    {
    public:
        TlsTranscriptHash() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(crypto::HashAlgorithm algorithm) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Update(
            _In_reads_bytes_(dataLength) const UCHAR* data,
            SIZE_T dataLength) noexcept;

        _Must_inspect_result_
        NTSTATUS Snapshot(
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) const noexcept;

        _Must_inspect_result_
        NTSTATUS Finish(
            _Out_writes_bytes_(outputLength) UCHAR* output,
            SIZE_T outputLength,
            _Out_opt_ SIZE_T* bytesWritten = nullptr) const noexcept;

        _Must_inspect_result_
        NTSTATUS ReplaceWithMessageHash(
            _In_reads_bytes_(clientHelloHashLength) const UCHAR* clientHelloHash,
            SIZE_T clientHelloHashLength) noexcept;

    private:
        crypto::HashAlgorithm algorithm_ = crypto::HashAlgorithm::Sha256;
        crypto::CngHashContext hash_ = {};
        bool initialized_ = false;
    };
}
}
