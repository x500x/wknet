#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/crypto/Ed25519.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::crypto::Ed25519Verify;
using KernelHttp::crypto::Sha512Compute;

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message)
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    int HexValue(char value)
    {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'a' && value <= 'f') {
            return value - 'a' + 10;
        }
        if (value >= 'A' && value <= 'F') {
            return value - 'A' + 10;
        }
        return -1;
    }

    // Decodes a NUL-terminated hex string into output; returns the byte count, or
    // SIZE_MAX on malformed input. Pass capacity for the destination buffer.
    SIZE_T DecodeHex(const char* hex, UCHAR* output, SIZE_T capacity)
    {
        SIZE_T hexLength = 0;
        while (hex[hexLength] != '\0') {
            ++hexLength;
        }
        if ((hexLength % 2) != 0 || (hexLength / 2) > capacity) {
            return static_cast<SIZE_T>(-1);
        }
        for (SIZE_T index = 0; index < hexLength / 2; ++index) {
            const int high = HexValue(hex[index * 2]);
            const int low = HexValue(hex[(index * 2) + 1]);
            if (high < 0 || low < 0) {
                return static_cast<SIZE_T>(-1);
            }
            output[index] = static_cast<UCHAR>((high << 4) | low);
        }
        return hexLength / 2;
    }

    struct Ed25519Vector final
    {
        const char* PublicKey;
        const char* Message;   // may be empty
        const char* Signature;
        const char* Name;
    };

    // RFC 8032 §7.1 test vectors (public key, message, signature).
    const Ed25519Vector kVectors[] = {
        {
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            "RFC8032 TEST 1 (empty message)"
        },
        {
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            "RFC8032 TEST 2 (1-byte message)"
        },
        {
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            "RFC8032 TEST 3 (2-byte message)"
        }
    };

    void TestSha512KnownVectors()
    {
        UCHAR digest[64] = {};

        // SHA-512("") = cf83e135...
        Expect(Sha512Compute(reinterpret_cast<const UCHAR*>(""), 0, digest), "SHA-512 empty computes");
        UCHAR expectedEmpty[64] = {};
        const SIZE_T n0 = DecodeHex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            expectedEmpty, sizeof(expectedEmpty));
        Expect(n0 == 64 && memcmp(digest, expectedEmpty, 64) == 0, "SHA-512 empty matches NIST");

        // SHA-512("abc")
        Expect(Sha512Compute(reinterpret_cast<const UCHAR*>("abc"), 3, digest), "SHA-512 abc computes");
        UCHAR expectedAbc[64] = {};
        const SIZE_T n1 = DecodeHex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            expectedAbc, sizeof(expectedAbc));
        Expect(n1 == 64 && memcmp(digest, expectedAbc, 64) == 0, "SHA-512 abc matches NIST");
    }

    void RunVector(const Ed25519Vector& vector)
    {
        UCHAR publicKey[32] = {};
        UCHAR signature[64] = {};
        static UCHAR message[2048] = {};

        const SIZE_T keyLength = DecodeHex(vector.PublicKey, publicKey, sizeof(publicKey));
        const SIZE_T sigLength = DecodeHex(vector.Signature, signature, sizeof(signature));
        const SIZE_T messageLength =
            vector.Message[0] == '\0' ? 0 : DecodeHex(vector.Message, message, sizeof(message));

        Expect(keyLength == 32, vector.Name);
        Expect(sigLength == 64, vector.Name);
        Expect(messageLength != static_cast<SIZE_T>(-1), vector.Name);

        const bool valid = Ed25519Verify(publicKey, 32, message, messageLength, signature, 64);
        Expect(valid, vector.Name);

        // Tamper with the signature R: must fail.
        UCHAR tamperedSig[64] = {};
        memcpy(tamperedSig, signature, 64);
        tamperedSig[0] ^= 0x01;
        Expect(!Ed25519Verify(publicKey, 32, message, messageLength, tamperedSig, 64),
            "tampered signature R rejected");

        // Tamper with the signature S: must fail.
        memcpy(tamperedSig, signature, 64);
        tamperedSig[40] ^= 0x01;
        Expect(!Ed25519Verify(publicKey, 32, message, messageLength, tamperedSig, 64),
            "tampered signature S rejected");

        // Tamper with the public key: must fail.
        UCHAR tamperedKey[32] = {};
        memcpy(tamperedKey, publicKey, 32);
        tamperedKey[0] ^= 0x01;
        Expect(!Ed25519Verify(tamperedKey, 32, message, messageLength, signature, 64),
            "tampered public key rejected");

        // Tamper with the message (when non-empty): must fail.
        if (messageLength != 0) {
            message[0] ^= 0x01;
            Expect(!Ed25519Verify(publicKey, 32, message, messageLength, signature, 64),
                "tampered message rejected");
            message[0] ^= 0x01;
        }
    }

    void TestRejectionConditions()
    {
        UCHAR publicKey[32] = {};
        UCHAR signature[64] = {};
        (void)DecodeHex(kVectors[1].PublicKey, publicKey, sizeof(publicKey));
        (void)DecodeHex(kVectors[1].Signature, signature, sizeof(signature));
        const UCHAR message[1] = { 0x72 };

        // Wrong public-key length.
        Expect(!Ed25519Verify(publicKey, 31, message, 1, signature, 64), "rejects 31-byte key");
        Expect(!Ed25519Verify(publicKey, 33, message, 1, signature, 64), "rejects 33-byte key");

        // Wrong signature length.
        Expect(!Ed25519Verify(publicKey, 32, message, 1, signature, 63), "rejects 63-byte signature");
        Expect(!Ed25519Verify(publicKey, 32, message, 1, signature, 65), "rejects 65-byte signature");

        // Null inputs.
        Expect(!Ed25519Verify(nullptr, 32, message, 1, signature, 64), "rejects null key");
        Expect(!Ed25519Verify(publicKey, 32, message, 1, nullptr, 64), "rejects null signature");

        // S >= L: set S to all 0xFF (well above the group order).
        UCHAR oversS[64] = {};
        memcpy(oversS, signature, 32);
        memset(oversS + 32, 0xff, 32);
        Expect(!Ed25519Verify(publicKey, 32, message, 1, oversS, 64), "rejects S >= L");
    }
}

int main()
{
    TestSha512KnownVectors();

    for (SIZE_T index = 0; index < sizeof(kVectors) / sizeof(kVectors[0]); ++index) {
        RunVector(kVectors[index]);
    }

    TestRejectionConditions();

    if (g_failed) {
        printf("ED25519 TESTS FAILED\n");
        return 1;
    }
    printf("ED25519 TESTS PASSED\n");
    return 0;
}
