#pragma once

#include "quic/QuicTypes.h"
#include <wknet/crypto/Aead.h>

namespace wknet::quic
{
    enum class QuicCipherSuite : UCHAR
    {
        Aes128GcmSha256,
        Aes256GcmSha384,
        ChaCha20Poly1305Sha256
    };

    struct QuicPacketKeySet final
    {
        QuicCipherSuite Suite = QuicCipherSuite::Aes128GcmSha256;
        UCHAR Secret[48] = {};
        SIZE_T SecretLength = 0;
        UCHAR Key[32] = {};
        SIZE_T KeyLength = 0;
        UCHAR Iv[12] = {};
        UCHAR HeaderProtectionKey[32] = {};
        SIZE_T HeaderProtectionKeyLength = 0;
    };

    void QuicClearPacketKeySet(_Inout_ QuicPacketKeySet* keySet) noexcept;

    NTSTATUS QuicDeriveInitialKeySets(_In_ QuicBufferView destinationConnectionId, _Out_ QuicPacketKeySet* client,
                                      _Out_ QuicPacketKeySet* server) noexcept;

    NTSTATUS QuicDerivePacketKeySet(QuicCipherSuite suite, _In_reads_bytes_(secretLength) const UCHAR* secret,
                                    SIZE_T secretLength, _Out_ QuicPacketKeySet* keySet) noexcept;

    NTSTATUS QuicDeriveNextPacketKeySet(_In_ const QuicPacketKeySet& current, _Out_ QuicPacketKeySet* next) noexcept;

    inline NTSTATUS QuicInstallReadSecret(QuicCipherSuite suite, const UCHAR* secret, SIZE_T secretLength,
                                          QuicPacketKeySet* keySet) noexcept
    {
        return QuicDerivePacketKeySet(suite, secret, secretLength, keySet);
    }

    inline NTSTATUS QuicInstallWriteSecret(QuicCipherSuite suite, const UCHAR* secret, SIZE_T secretLength,
                                           QuicPacketKeySet* keySet) noexcept
    {
        return QuicDerivePacketKeySet(suite, secret, secretLength, keySet);
    }

    NTSTATUS QuicBuildPacketNonce(_In_reads_bytes_(12) const UCHAR* iv, ULONGLONG packetNumber,
                                  _Out_writes_bytes_(12) UCHAR* nonce) noexcept;

    NTSTATUS QuicHeaderProtectionMask(_In_ const QuicPacketKeySet& keySet, _In_reads_bytes_(16) const UCHAR* sample,
                                      _Out_writes_bytes_(5) UCHAR* mask) noexcept;

    NTSTATUS QuicProtectPacket(_In_ const QuicPacketKeySet& keySet, _Inout_updates_(packetCapacity) UCHAR* packet,
                               SIZE_T packetCapacity, SIZE_T packetNumberOffset, SIZE_T packetNumberLength,
                               ULONGLONG packetNumber, SIZE_T plaintextLength, _Out_ SIZE_T* packetLength) noexcept;

    NTSTATUS QuicUnprotectPacket(_In_ const QuicPacketKeySet& keySet, _Inout_updates_(packetLength) UCHAR* packet,
                                 SIZE_T packetLength, SIZE_T packetNumberOffset, ULONGLONG expectedPacketNumber,
                                 _Out_ ULONGLONG* packetNumber, _Out_ SIZE_T* plaintextLength) noexcept;

    NTSTATUS QuicInspectProtectedPacketHeader(_In_ const QuicPacketKeySet& keySet,
                                              _In_reads_bytes_(packetLength) const UCHAR* packet, SIZE_T packetLength,
                                              SIZE_T packetNumberOffset, ULONGLONG expectedPacketNumber,
                                              _Out_ UCHAR* firstByte, _Out_ ULONGLONG* packetNumber) noexcept;

    NTSTATUS QuicComputeRetryIntegrityTag(_In_ QuicBufferView originalDestinationConnectionId,
                                          _In_reads_bytes_(retryWithoutTagLength) const UCHAR* retryWithoutTag,
                                          SIZE_T retryWithoutTagLength,
                                          _Out_writes_bytes_(QuicRetryIntegrityTagLength) UCHAR* tag) noexcept;

    NTSTATUS QuicValidateRetryIntegrityTag(_In_ QuicBufferView originalDestinationConnectionId,
                                           _In_reads_bytes_(retryPacketLength) const UCHAR* retryPacket,
                                           SIZE_T retryPacketLength) noexcept;
} // namespace wknet::quic
