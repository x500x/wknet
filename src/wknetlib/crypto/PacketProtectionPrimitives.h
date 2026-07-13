#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::crypto {
    NTSTATUS PacketProtectionAesEncryptBlock(
        _In_reads_bytes_(keyLength) const UCHAR* key,
        SIZE_T keyLength,
        _In_reads_bytes_(16) const UCHAR* input,
        _Out_writes_bytes_(16) UCHAR* output) noexcept;

    NTSTATUS PacketProtectionChaCha20Block(
        _In_reads_bytes_(32) const UCHAR* key,
        ULONG counter,
        _In_reads_bytes_(12) const UCHAR* nonce,
        _Out_writes_bytes_(64) UCHAR* output) noexcept;
}
