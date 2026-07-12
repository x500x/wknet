#pragma once

#include <wknet/crypto/CngProvider.h>

namespace wknet
{
namespace crypto
{
    constexpr SIZE_T Ed448PublicKeyLength = 57;
    constexpr SIZE_T Ed448SignatureLength = 114;

    _Must_inspect_result_
    bool Ed448Verify(
        _In_reads_bytes_(publicKeyLength) const UCHAR* publicKey,
        SIZE_T publicKeyLength,
        _In_reads_bytes_(messageLength) const UCHAR* message,
        SIZE_T messageLength,
        _In_reads_bytes_(signatureLength) const UCHAR* signature,
        SIZE_T signatureLength) noexcept;

    _Must_inspect_result_
    bool Shake256Compute(
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _Out_writes_bytes_(outputLength) UCHAR* output,
        SIZE_T outputLength) noexcept;
}
}
