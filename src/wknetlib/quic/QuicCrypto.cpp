#include "quic/QuicCrypto.h"
#include "crypto/PacketProtectionPrimitives.h"
#include "quic/QuicPacket.h"
#include "tls/Tls13KeySchedule.h"

namespace wknet::quic
{
namespace
{
const UCHAR InitialSaltV1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
const UCHAR RetryKeyV1[16] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                              0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
const UCHAR RetryNonceV1[12] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

crypto::HashAlgorithm HashForSuite(QuicCipherSuite suite) noexcept
{
    return suite == QuicCipherSuite::Aes256GcmSha384 ? crypto::HashAlgorithm::Sha384 : crypto::HashAlgorithm::Sha256;
}

SIZE_T SecretLengthForSuite(QuicCipherSuite suite) noexcept
{
    return suite == QuicCipherSuite::Aes256GcmSha384 ? 48 : 32;
}

SIZE_T KeyLengthForSuite(QuicCipherSuite suite) noexcept
{
    return suite == QuicCipherSuite::Aes128GcmSha256 ? 16 : 32;
}

bool SecureEquals(const UCHAR *left, const UCHAR *right, SIZE_T length) noexcept
{
    UCHAR difference = 0;
    for (SIZE_T index = 0; index < length; ++index)
        difference |= left[index] ^ right[index];
    return difference == 0;
}

crypto::AeadAlgorithm AeadForSuite(QuicCipherSuite suite) noexcept
{
    if (suite == QuicCipherSuite::Aes128GcmSha256)
        return crypto::AeadAlgorithm::Aes128Gcm;
    if (suite == QuicCipherSuite::Aes256GcmSha384)
        return crypto::AeadAlgorithm::Aes256Gcm;
    return crypto::AeadAlgorithm::ChaCha20Poly1305;
}
} // namespace

void QuicClearPacketKeySet(QuicPacketKeySet *keySet) noexcept
{
    if (keySet != nullptr)
        RtlSecureZeroMemory(keySet, sizeof(*keySet));
}

NTSTATUS QuicDerivePacketKeySet(QuicCipherSuite suite, const UCHAR *secret, SIZE_T secretLength,
                                QuicPacketKeySet *keySet) noexcept
{
    if (keySet != nullptr)
        *keySet = {};
    const SIZE_T requiredSecret = SecretLengthForSuite(suite);
    if (secret == nullptr || keySet == nullptr || secretLength != requiredSecret)
        return STATUS_INVALID_PARAMETER;
    keySet->Suite = suite;
    keySet->SecretLength = secretLength;
    keySet->KeyLength = KeyLengthForSuite(suite);
    keySet->HeaderProtectionKeyLength = keySet->KeyLength;
    RtlCopyMemory(keySet->Secret, secret, secretLength);
    const crypto::HashAlgorithm hash = HashForSuite(suite);
    NTSTATUS status = tls::Tls13KeySchedule::HkdfExpandLabel(hash, secret, secretLength, "quic key", nullptr, 0,
                                                             keySet->Key, keySet->KeyLength);
    if (NT_SUCCESS(status))
        status = tls::Tls13KeySchedule::HkdfExpandLabel(hash, secret, secretLength, "quic iv", nullptr, 0, keySet->Iv,
                                                        sizeof(keySet->Iv));
    if (NT_SUCCESS(status))
        status = tls::Tls13KeySchedule::HkdfExpandLabel(hash, secret, secretLength, "quic hp", nullptr, 0,
                                                        keySet->HeaderProtectionKey, keySet->HeaderProtectionKeyLength);
    if (!NT_SUCCESS(status))
        QuicClearPacketKeySet(keySet);
    return status;
}

NTSTATUS QuicDeriveNextPacketKeySet(const QuicPacketKeySet &current, QuicPacketKeySet *next) noexcept
{
    if (next != nullptr)
    {
        *next = {};
    }
    if (next == nullptr || current.SecretLength == 0 || current.SecretLength != SecretLengthForSuite(current.Suite))
    {
        return STATUS_INVALID_PARAMETER;
    }

    HeapArray<UCHAR> nextSecret(current.SecretLength);
    if (!nextSecret.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NTSTATUS status =
        tls::Tls13KeySchedule::HkdfExpandLabel(HashForSuite(current.Suite), current.Secret, current.SecretLength,
                                               "quic ku", nullptr, 0, nextSecret.Get(), nextSecret.Count());
    if (NT_SUCCESS(status))
    {
        status = QuicDerivePacketKeySet(current.Suite, nextSecret.Get(), nextSecret.Count(), next);
    }
    RtlSecureZeroMemory(nextSecret.Get(), nextSecret.Count());
    return status;
}

NTSTATUS QuicDeriveInitialKeySets(QuicBufferView destinationConnectionId, QuicPacketKeySet *client,
                                  QuicPacketKeySet *server) noexcept
{
    if (client != nullptr)
        *client = {};
    if (server != nullptr)
        *server = {};
    if (destinationConnectionId.Data == nullptr || destinationConnectionId.Length == 0 ||
        destinationConnectionId.Length > QuicMaximumConnectionIdLength || client == nullptr || server == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    HeapArray<UCHAR> initialSecret(32), clientSecret(32), serverSecret(32);
    if (!initialSecret.IsValid() || !clientSecret.IsValid() || !serverSecret.IsValid())
        return STATUS_INSUFFICIENT_RESOURCES;
    SIZE_T written = 0;
    NTSTATUS status = crypto::CngProvider::HkdfExtract(
        crypto::HashAlgorithm::Sha256, InitialSaltV1, sizeof(InitialSaltV1), destinationConnectionId.Data,
        destinationConnectionId.Length, initialSecret.Get(), initialSecret.Count(), &written);
    if (NT_SUCCESS(status))
        status = tls::Tls13KeySchedule::HkdfExpandLabel(crypto::HashAlgorithm::Sha256, initialSecret.Get(),
                                                        initialSecret.Count(), "client in", nullptr, 0,
                                                        clientSecret.Get(), clientSecret.Count());
    if (NT_SUCCESS(status))
        status = tls::Tls13KeySchedule::HkdfExpandLabel(crypto::HashAlgorithm::Sha256, initialSecret.Get(),
                                                        initialSecret.Count(), "server in", nullptr, 0,
                                                        serverSecret.Get(), serverSecret.Count());
    if (NT_SUCCESS(status))
        status =
            QuicDerivePacketKeySet(QuicCipherSuite::Aes128GcmSha256, clientSecret.Get(), clientSecret.Count(), client);
    if (NT_SUCCESS(status))
        status =
            QuicDerivePacketKeySet(QuicCipherSuite::Aes128GcmSha256, serverSecret.Get(), serverSecret.Count(), server);
    RtlSecureZeroMemory(initialSecret.Get(), initialSecret.Count());
    RtlSecureZeroMemory(clientSecret.Get(), clientSecret.Count());
    RtlSecureZeroMemory(serverSecret.Get(), serverSecret.Count());
    if (!NT_SUCCESS(status))
    {
        QuicClearPacketKeySet(client);
        QuicClearPacketKeySet(server);
    }
    return status;
}

NTSTATUS QuicBuildPacketNonce(const UCHAR *iv, ULONGLONG packetNumber, UCHAR *nonce) noexcept
{
    if (iv == nullptr || nonce == nullptr || packetNumber > QuicVarIntMaximum)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(nonce, iv, 12);
    for (SIZE_T index = 0; index < 8; ++index)
    {
        nonce[11 - index] ^= static_cast<UCHAR>((packetNumber >> (index * 8)) & 0xffU);
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicHeaderProtectionMask(const QuicPacketKeySet &keySet, const UCHAR *sample, UCHAR *mask) noexcept
{
    if (sample == nullptr || mask == nullptr || keySet.HeaderProtectionKeyLength == 0)
        return STATUS_INVALID_PARAMETER;
    if (keySet.Suite == QuicCipherSuite::ChaCha20Poly1305Sha256)
    {
        HeapArray<UCHAR> block(64);
        if (!block.IsValid())
            return STATUS_INSUFFICIENT_RESOURCES;
        const ULONG counter = static_cast<ULONG>(sample[0]) | (static_cast<ULONG>(sample[1]) << 8) |
                              (static_cast<ULONG>(sample[2]) << 16) | (static_cast<ULONG>(sample[3]) << 24);
        const NTSTATUS status =
            crypto::PacketProtectionChaCha20Block(keySet.HeaderProtectionKey, counter, sample + 4, block.Get());
        if (NT_SUCCESS(status))
            RtlCopyMemory(mask, block.Get(), 5);
        RtlSecureZeroMemory(block.Get(), block.Count());
        return status;
    }
    HeapArray<UCHAR> encrypted(16);
    if (!encrypted.IsValid())
        return STATUS_INSUFFICIENT_RESOURCES;
    const NTSTATUS status = crypto::PacketProtectionAesEncryptBlock(
        keySet.HeaderProtectionKey, keySet.HeaderProtectionKeyLength, sample, encrypted.Get());
    if (NT_SUCCESS(status))
        RtlCopyMemory(mask, encrypted.Get(), 5);
    RtlSecureZeroMemory(encrypted.Get(), encrypted.Count());
    return status;
}

NTSTATUS QuicProtectPacket(const QuicPacketKeySet &keySet, UCHAR *packet, SIZE_T packetCapacity,
                           SIZE_T packetNumberOffset, SIZE_T packetNumberLength, ULONGLONG packetNumber,
                           SIZE_T plaintextLength, SIZE_T *packetLength) noexcept
{
    if (packetLength != nullptr)
        *packetLength = 0;
    if (packet == nullptr || packetLength == nullptr || packetNumberLength == 0 || packetNumberLength > 4 ||
        packetNumberOffset > packetCapacity || packetNumberLength > packetCapacity - packetNumberOffset)
        return STATUS_INVALID_PARAMETER;
    const SIZE_T headerLength = packetNumberOffset + packetNumberLength;
    if (plaintextLength > packetCapacity - headerLength ||
        QuicRetryIntegrityTagLength > packetCapacity - headerLength - plaintextLength)
        return STATUS_BUFFER_TOO_SMALL;
    const SIZE_T protectedLength = headerLength + plaintextLength + QuicRetryIntegrityTagLength;
    if (packetNumberOffset > protectedLength || 4 > protectedLength - packetNumberOffset ||
        16 > protectedLength - (packetNumberOffset + 4))
        return STATUS_INVALID_PARAMETER;
    HeapArray<UCHAR> nonce(12), ciphertext(plaintextLength == 0 ? 1 : plaintextLength), tag(16), mask(5);
    if (!nonce.IsValid() || !ciphertext.IsValid() || !tag.IsValid() || !mask.IsValid())
        return STATUS_INSUFFICIENT_RESOURCES;
    NTSTATUS status = QuicBuildPacketNonce(keySet.Iv, packetNumber, nonce.Get());
    crypto::AeadKey key = {AeadForSuite(keySet.Suite), keySet.Key, keySet.KeyLength};
    crypto::AeadParameters parameters = {};
    parameters.Nonce = {nonce.Get(), nonce.Count()};
    parameters.Aad = {packet, headerLength};
    SIZE_T written = 0;
    if (NT_SUCCESS(status))
        status = crypto::Aead::Encrypt(nullptr, key, parameters, packet + headerLength, plaintextLength,
                                       ciphertext.Get(), plaintextLength, tag.Get(), tag.Count(), &written);
    if (NT_SUCCESS(status) && written != plaintextLength)
        status = STATUS_INVALID_NETWORK_RESPONSE;
    if (NT_SUCCESS(status))
    {
        if (plaintextLength != 0)
            RtlCopyMemory(packet + headerLength, ciphertext.Get(), plaintextLength);
        RtlCopyMemory(packet + headerLength + plaintextLength, tag.Get(), tag.Count());
        status = QuicHeaderProtectionMask(keySet, packet + packetNumberOffset + 4, mask.Get());
    }
    if (NT_SUCCESS(status))
    {
        packet[0] ^= static_cast<UCHAR>(mask[0] & ((packet[0] & 0x80U) != 0 ? 0x0fU : 0x1fU));
        for (SIZE_T index = 0; index < packetNumberLength; ++index)
            packet[packetNumberOffset + index] ^= mask[index + 1];
        *packetLength = protectedLength;
    }
    RtlSecureZeroMemory(nonce.Get(), nonce.Count());
    RtlSecureZeroMemory(ciphertext.Get(), ciphertext.Count());
    RtlSecureZeroMemory(tag.Get(), tag.Count());
    RtlSecureZeroMemory(mask.Get(), mask.Count());
    return status;
}

NTSTATUS QuicUnprotectPacket(const QuicPacketKeySet &keySet, UCHAR *packet, SIZE_T packetLength,
                             SIZE_T packetNumberOffset, ULONGLONG expectedPacketNumber, ULONGLONG *packetNumber,
                             SIZE_T *plaintextLength) noexcept
{
    if (packetNumber != nullptr)
        *packetNumber = 0;
    if (plaintextLength != nullptr)
        *plaintextLength = 0;
    if (packet == nullptr || packetNumber == nullptr || plaintextLength == nullptr ||
        packetNumberOffset > packetLength || 4 > packetLength - packetNumberOffset ||
        16 > packetLength - (packetNumberOffset + 4))
        return STATUS_INVALID_PARAMETER;
    HeapArray<UCHAR> mask(5), nonce(12);
    if (!mask.IsValid() || !nonce.IsValid())
        return STATUS_INSUFFICIENT_RESOURCES;
    NTSTATUS status = QuicHeaderProtectionMask(keySet, packet + packetNumberOffset + 4, mask.Get());
    if (!NT_SUCCESS(status))
        return status;
    packet[0] ^= static_cast<UCHAR>(mask[0] & ((packet[0] & 0x80U) != 0 ? 0x0fU : 0x1fU));
    const bool longHeader = (packet[0] & 0x80U) != 0;
    if ((longHeader && (packet[0] & 0x0cU) != 0) || (!longHeader && (packet[0] & 0x18U) != 0))
    {
        RtlSecureZeroMemory(mask.Get(), mask.Count());
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    const SIZE_T pnLength = (packet[0] & 0x03U) + 1U;
    if (pnLength > packetLength - packetNumberOffset)
        return STATUS_INVALID_NETWORK_RESPONSE;
    ULONGLONG truncated = 0;
    for (SIZE_T index = 0; index < pnLength; ++index)
    {
        packet[packetNumberOffset + index] ^= mask[index + 1];
        truncated = (truncated << 8) | packet[packetNumberOffset + index];
    }
    status = QuicReconstructPacketNumber(truncated, pnLength, expectedPacketNumber, packetNumber);
    const SIZE_T headerLength = packetNumberOffset + pnLength;
    if (!NT_SUCCESS(status) || packetLength < headerLength + 16)
        return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
    const SIZE_T ciphertextLength = packetLength - headerLength - 16;
    HeapArray<UCHAR> plaintext(ciphertextLength == 0 ? 1 : ciphertextLength);
    if (!plaintext.IsValid())
        return STATUS_INSUFFICIENT_RESOURCES;
    status = QuicBuildPacketNonce(keySet.Iv, *packetNumber, nonce.Get());
    crypto::AeadKey key = {AeadForSuite(keySet.Suite), keySet.Key, keySet.KeyLength};
    crypto::AeadParameters parameters = {};
    parameters.Nonce = {nonce.Get(), nonce.Count()};
    parameters.Aad = {packet, headerLength};
    parameters.Tag = {packet + headerLength + ciphertextLength, 16};
    SIZE_T written = 0;
    if (NT_SUCCESS(status))
        status = crypto::Aead::Decrypt(nullptr, key, parameters, packet + headerLength, ciphertextLength,
                                       plaintext.Get(), ciphertextLength, &written);
    if (NT_SUCCESS(status) && written == ciphertextLength)
    {
        if (ciphertextLength != 0)
            RtlCopyMemory(packet + headerLength, plaintext.Get(), ciphertextLength);
        *plaintextLength = ciphertextLength;
    }
    else if (NT_SUCCESS(status))
        status = STATUS_INVALID_NETWORK_RESPONSE;
    if (!NT_SUCCESS(status) && ciphertextLength != 0)
        RtlSecureZeroMemory(packet + headerLength, ciphertextLength);
    RtlSecureZeroMemory(mask.Get(), mask.Count());
    RtlSecureZeroMemory(nonce.Get(), nonce.Count());
    RtlSecureZeroMemory(plaintext.Get(), plaintext.Count());
    return status;
}

NTSTATUS QuicComputeRetryIntegrityTag(QuicBufferView odcid, const UCHAR *retryWithoutTag, SIZE_T retryWithoutTagLength,
                                      UCHAR *tag) noexcept
{
    if (odcid.Data == nullptr || odcid.Length == 0 || odcid.Length > QuicMaximumConnectionIdLength ||
        retryWithoutTag == nullptr || retryWithoutTagLength == 0 || tag == nullptr)
        return STATUS_INVALID_PARAMETER;
    const SIZE_T pseudoLength = 1 + odcid.Length + retryWithoutTagLength;
    HeapArray<UCHAR> pseudo(pseudoLength);
    if (!pseudo.IsValid())
        return STATUS_INSUFFICIENT_RESOURCES;
    pseudo[0] = static_cast<UCHAR>(odcid.Length);
    RtlCopyMemory(pseudo.Get() + 1, odcid.Data, odcid.Length);
    RtlCopyMemory(pseudo.Get() + 1 + odcid.Length, retryWithoutTag, retryWithoutTagLength);
    crypto::AeadKey key = {crypto::AeadAlgorithm::Aes128Gcm, RetryKeyV1, sizeof(RetryKeyV1)};
    crypto::AeadParameters parameters = {};
    parameters.Nonce = {RetryNonceV1, sizeof(RetryNonceV1)};
    parameters.Aad = {pseudo.Get(), pseudo.Count()};
    UCHAR dummy = 0;
    SIZE_T written = 0;
    const NTSTATUS status = crypto::Aead::Encrypt(nullptr, key, parameters, nullptr, 0, &dummy, 0, tag,
                                                  QuicRetryIntegrityTagLength, &written);
    RtlSecureZeroMemory(pseudo.Get(), pseudo.Count());
    return status;
}

NTSTATUS QuicValidateRetryIntegrityTag(QuicBufferView odcid, const UCHAR *retryPacket,
                                       SIZE_T retryPacketLength) noexcept
{
    if (retryPacket == nullptr || retryPacketLength <= QuicRetryIntegrityTagLength)
        return STATUS_INVALID_PARAMETER;
    HeapArray<UCHAR> expected(QuicRetryIntegrityTagLength);
    if (!expected.IsValid())
        return STATUS_INSUFFICIENT_RESOURCES;
    const SIZE_T withoutTag = retryPacketLength - QuicRetryIntegrityTagLength;
    NTSTATUS status = QuicComputeRetryIntegrityTag(odcid, retryPacket, withoutTag, expected.Get());
    if (NT_SUCCESS(status) && !SecureEquals(expected.Get(), retryPacket + withoutTag, expected.Count()))
    {
        status = STATUS_INVALID_SIGNATURE;
    }
    RtlSecureZeroMemory(expected.Get(), expected.Count());
    return status;
}
} // namespace wknet::quic
