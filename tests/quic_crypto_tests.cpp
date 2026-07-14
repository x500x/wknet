#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif
#include "crypto/PacketProtectionPrimitives.h"
#include "quic/QuicAttemptValidation.h"
#include "quic/QuicCrypto.h"
#include "quic/QuicPacket.h"
#include <stdio.h>
#include <string.h>
namespace
{
    bool failed = false;
    void E(bool c, const char* m)
    {
        if (!c)
        {
            failed = true;
            printf("FAIL: %s\n", m);
        }
    }
    UCHAR H(char c)
    {
        return static_cast<UCHAR>(c >= '0' && c <= '9' ? c - '0'
                                                       : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : c - 'A' + 10));
    }
    SIZE_T Hex(const char* s, UCHAR* out, SIZE_T cap)
    {
        SIZE_T n = strlen(s) / 2;
        if (n > cap)
            return 0;
        for (SIZE_T i = 0; i < n; ++i)
            out[i] = static_cast<UCHAR>((H(s[i * 2]) << 4) | H(s[i * 2 + 1]));
        return n;
    }
    bool Eq(const UCHAR* a, const char* hex, SIZE_T n)
    {
        UCHAR e[64] = {};
        return Hex(hex, e, sizeof(e)) == n && memcmp(a, e, n) == 0;
    }
    void RoundTripSuite(wknet::quic::QuicCipherSuite suite, SIZE_T secretLength, const char* message)
    {
        UCHAR secret[48] = {};
        for (SIZE_T i = 0; i < secretLength; ++i)
            secret[i] = static_cast<UCHAR>(i + 1);
        wknet::quic::QuicPacketKeySet keys = {};
        E(NT_SUCCESS(wknet::quic::QuicInstallWriteSecret(suite, secret, secretLength, &keys)), message);
        UCHAR packet[128] = {0x41, 1, 2, 3, 4, 0x12, 0x34};
        for (SIZE_T i = 0; i < 40; ++i)
            packet[7 + i] = static_cast<UCHAR>(0xa0 + i);
        UCHAR original[40] = {};
        RtlCopyMemory(original, packet + 7, 40);
        SIZE_T packetLength = 0;
        E(NT_SUCCESS(wknet::quic::QuicProtectPacket(keys, packet, sizeof(packet), 5, 2, 0x1234, 40, &packetLength)),
          "suite protects");
        ULONGLONG pn = 0;
        SIZE_T plain = 0;
        E(NT_SUCCESS(wknet::quic::QuicUnprotectPacket(keys, packet, packetLength, 5, 0x1234, &pn, &plain)),
          "suite unprotects");
        E(pn == 0x1234 && plain == 40 && memcmp(packet + 7, original, 40) == 0, "suite round-trips");
        wknet::quic::QuicClearPacketKeySet(&keys);
    }
} // namespace
int main()
{
    UCHAR dcid[8] = {};
    Hex("8394c8f03e515708", dcid, sizeof(dcid));
    wknet::quic::QuicPacketKeySet client = {}, server = {};
    E(NT_SUCCESS(wknet::quic::QuicDeriveInitialKeySets({dcid, sizeof(dcid)}, &client, &server)), "Initial keys derive");
    E(Eq(client.Secret, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", 32),
      "client initial secret vector");
    E(Eq(server.Secret, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", 32),
      "server initial secret vector");
    E(Eq(client.Key, "1f369613dd76d5467730efcbe3b1a22d", 16), "client key vector");
    E(Eq(client.Iv, "fa044b2f42a3fd3b46fb255c", 12), "client iv vector");
    E(Eq(client.HeaderProtectionKey, "9f50449e04a0e810283a1e9933adedd2", 16), "client hp vector");
    wknet::quic::QuicPacketKeySet nextClient = {};
    wknet::quic::QuicPacketKeySet repeatedNextClient = {};
    E(NT_SUCCESS(wknet::quic::QuicDeriveNextPacketKeySet(client, &nextClient)) &&
          NT_SUCCESS(wknet::quic::QuicDeriveNextPacketKeySet(client, &repeatedNextClient)),
      "QUIC key update derives next packet protection keys");
    E(memcmp(nextClient.Secret, client.Secret, client.SecretLength) != 0 &&
          memcmp(nextClient.Secret, repeatedNextClient.Secret, nextClient.SecretLength) == 0,
      "QUIC key update is deterministic and advances the traffic secret");
    E(Eq(nextClient.Secret, "4428ffa195ad665b9ebf9456945b99e8ff848512cab93d0426436409047d666c", 32),
      "QUIC key update matches the RFC HKDF label result");
    E(nextClient.HeaderProtectionKeyLength == client.HeaderProtectionKeyLength &&
          memcmp(nextClient.HeaderProtectionKey, client.HeaderProtectionKey, client.HeaderProtectionKeyLength) == 0,
      "QUIC key update retains the header protection key");
    wknet::quic::QuicClearPacketKeySet(&nextClient);
    wknet::quic::QuicClearPacketKeySet(&repeatedNextClient);
    UCHAR sample[16] = {};
    Hex("d1b1c98dd7689fb8ec11d242b123dc9b", sample, sizeof(sample));
    UCHAR mask[5] = {};
    E(NT_SUCCESS(wknet::quic::QuicHeaderProtectionMask(client, sample, mask)), "AES HP mask");
    E(Eq(mask, "437b9aec36", 5), "AES HP vector");
    wknet::quic::QuicPacketKeySet chacha = {};
    chacha.Suite = wknet::quic::QuicCipherSuite::ChaCha20Poly1305Sha256;
    chacha.HeaderProtectionKeyLength = Hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
                                           chacha.HeaderProtectionKey, sizeof(chacha.HeaderProtectionKey));
    Hex("5e5cd55c41f69080575d7999c25a5bfb", sample, sizeof(sample));
    E(NT_SUCCESS(wknet::quic::QuicHeaderProtectionMask(chacha, sample, mask)), "ChaCha HP mask");
    E(Eq(mask, "aefefe7d03", 5), "ChaCha HP vector");
    UCHAR aes256Key[32] = {}, aesBlock[16] = {}, aesOut[16] = {};
    Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", aes256Key, sizeof(aes256Key));
    Hex("00112233445566778899aabbccddeeff", aesBlock, sizeof(aesBlock));
    E(NT_SUCCESS(wknet::crypto::PacketProtectionAesEncryptBlock(aes256Key, sizeof(aes256Key), aesBlock, aesOut)),
      "AES-256 HP primitive");
    E(Eq(aesOut, "8ea2b7ca516745bfeafc49904b496089", 16), "AES-256 block vector");
    UCHAR nonce[12] = {};
    E(NT_SUCCESS(wknet::quic::QuicBuildPacketNonce(client.Iv, 2, nonce)), "nonce builds");
    E(nonce[11] == (client.Iv[11] ^ 2), "packet number XORs low nonce bytes");
    UCHAR retry[64] = {};
    const SIZE_T retryNoTag = Hex("ff000000010008f067a5502a4262b5746f6b656e", retry, sizeof(retry));
    UCHAR tag[16] = {};
    E(NT_SUCCESS(wknet::quic::QuicComputeRetryIntegrityTag({dcid, sizeof(dcid)}, retry, retryNoTag, tag)),
      "Retry tag computes");
    E(Eq(tag, "04a265ba2eff4d829058fb3f0f2496ba", 16), "Retry vector");
    RtlCopyMemory(retry + retryNoTag, tag, sizeof(tag));
    E(NT_SUCCESS(wknet::quic::QuicValidateRetryIntegrityTag({dcid, sizeof(dcid)}, retry, retryNoTag + sizeof(tag))),
      "Retry tag validates");
    retry[retryNoTag] ^= 1;
    E(wknet::quic::QuicValidateRetryIntegrityTag({dcid, sizeof(dcid)}, retry, retryNoTag + sizeof(tag)) ==
          STATUS_INVALID_SIGNATURE,
      "Retry tamper rejected");
    retry[retryNoTag] ^= 1;
    wknet::quic::QuicPacketHeader retryHeader = {};
    E(NT_SUCCESS(wknet::quic::QuicParsePacketHeader(retry, retryNoTag + sizeof(tag), 0, &retryHeader)),
      "Retry vector parses");
    wknet::quic::QuicAttemptValidation attempt;
    E(NT_SUCCESS(attempt.Initialize(wknet::quic::QuicVersion1, {dcid, sizeof(dcid)}, {nullptr, 0})),
      "attempt initializes");
    E(NT_SUCCESS(attempt.ValidateRetry(retryHeader, retry, retryNoTag + sizeof(tag))), "attempt accepts valid Retry");
    E(attempt.RetryAccepted() && attempt.RetryToken().Length == 5, "Retry token becomes owned attempt state");
    E(attempt.ValidateRetry(retryHeader, retry, retryNoTag + sizeof(tag)) == STATUS_INVALID_NETWORK_RESPONSE,
      "second Retry rejected");
    UCHAR protectedPacket[128] = {0x41, 1, 2, 3, 4, 0x12, 0x34};
    for (SIZE_T i = 0; i < 40; ++i)
        protectedPacket[7 + i] = static_cast<UCHAR>(i);
    UCHAR original[40] = {};
    RtlCopyMemory(original, protectedPacket + 7, sizeof(original));
    SIZE_T protectedLength = 0;
    E(NT_SUCCESS(wknet::quic::QuicProtectPacket(client, protectedPacket, sizeof(protectedPacket), 5, 2, 0x1234, 40,
                                                &protectedLength)),
      "packet protects in place");
    UCHAR inspectedFirstByte = 0;
    ULONGLONG inspectedPacketNumber = 0;
    E(NT_SUCCESS(wknet::quic::QuicInspectProtectedPacketHeader(client, protectedPacket, protectedLength, 5, 0x1234,
                                                               &inspectedFirstByte, &inspectedPacketNumber)),
      "protected short header inspects without AEAD trial");
    E((inspectedFirstByte & 0x04U) == 0 && inspectedPacketNumber == 0x1234,
      "protected short header exposes key phase and packet number");
    ULONGLONG fullPn = 0;
    SIZE_T plainLength = 0;
    E(NT_SUCCESS(
          wknet::quic::QuicUnprotectPacket(client, protectedPacket, protectedLength, 5, 0x1234, &fullPn, &plainLength)),
      "packet unprotects");
    E(fullPn == 0x1234 && plainLength == 40 && memcmp(protectedPacket + 7, original, 40) == 0,
      "packet protection round-trips header PN and payload");
    RoundTripSuite(wknet::quic::QuicCipherSuite::Aes256GcmSha384, 48, "AES-256 traffic secret installs");
    RoundTripSuite(wknet::quic::QuicCipherSuite::ChaCha20Poly1305Sha256, 32, "ChaCha traffic secret installs");
    wknet::quic::QuicClearPacketKeySet(&client);
    E(client.KeyLength == 0 && client.SecretLength == 0, "key set clears");
    if (failed)
    {
        printf("QUIC CRYPTO TESTS FAILED\n");
        return 1;
    }
    printf("QUIC CRYPTO TESTS PASSED\n");
    return 0;
}
