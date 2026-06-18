#pragma once

#include <KernelHttp/crypto/CngProvider.h>

namespace KernelHttp
{
namespace crypto
{
    constexpr SIZE_T Ed25519PublicKeyLength = 32;
    constexpr SIZE_T Ed25519SignatureLength = 64;

    // Software Ed25519 (PureEdDSA, RFC 8032) signature verification.
    //
    // Verification operates on the full message — Ed25519 hashes internally with
    // SHA-512 (computing SHA512(R || A || M)), so callers must pass the message
    // bytes, NOT a pre-computed digest. This is why Ed25519 cannot reuse the
    // hash-based CngProvider::VerifySignature path.
    //
    // The public key must be exactly 32 bytes and the signature exactly 64 bytes.
    // Returns true only for a valid signature; false for any malformed input,
    // non-canonical encoding, S >= group order, or verification mismatch. The
    // implementation is built in both kernel and user-mode test configurations,
    // so it is self-contained (its own SHA-512) and depends on no CNG provider.
    _Must_inspect_result_
    bool Ed25519Verify(
        _In_reads_bytes_(publicKeyLength) const UCHAR* publicKey,
        SIZE_T publicKeyLength,
        _In_reads_bytes_(messageLength) const UCHAR* message,
        SIZE_T messageLength,
        _In_reads_bytes_(signatureLength) const UCHAR* signature,
        SIZE_T signatureLength) noexcept;

    // Self-contained SHA-512 (FIPS 180-4). Exposed so Ed25519 internals and tests
    // can share one implementation. `output` must hold 64 bytes.
    _Must_inspect_result_
    bool Sha512Compute(
        _In_reads_bytes_(dataLength) const UCHAR* data,
        SIZE_T dataLength,
        _Out_writes_bytes_(64) UCHAR* output) noexcept;
}
}
