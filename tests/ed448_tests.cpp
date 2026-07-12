#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/crypto/Ed448.h>

#include <stdio.h>
#include <string.h>

using wknet::crypto::Ed448Verify;
using wknet::crypto::Shake256Compute;

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

    struct Ed448Vector final
    {
        const char* PublicKey;
        const char* Message;
        const char* Signature;
        const char* Name;
    };

    const Ed448Vector kVectors[] = {
        {
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778"
            "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
            "",
            "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f"
            "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b"
            "18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113"
            "a0f4dbb61149f05a7363268c71d95808ff2e652600",
            "RFC8032 Ed448 TEST 1 (empty message)"
        },
        {
            "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
            "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
            "03",
            "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435"
            "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1"
            "cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2"
            "a0ff3348ab21aa4adafd1d234441cf807c03a00",
            "RFC8032 Ed448 TEST 2 (1-byte message)"
        }
    };

    void TestShake256KnownVector()
    {
        UCHAR digest[64] = {};
        UCHAR expected[64] = {};
        const SIZE_T expectedLength = DecodeHex(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
            expected,
            sizeof(expected));

        Expect(expectedLength == sizeof(expected), "SHAKE256 expected vector decodes");
        Expect(Shake256Compute(reinterpret_cast<const UCHAR*>(""), 0, digest, sizeof(digest)),
            "SHAKE256 empty computes");
        Expect(memcmp(digest, expected, sizeof(digest)) == 0, "SHAKE256 empty matches FIPS 202");
    }

    void RunVector(const Ed448Vector& vector)
    {
        UCHAR publicKey[57] = {};
        UCHAR signature[114] = {};
        static UCHAR message[2048] = {};

        const SIZE_T keyLength = DecodeHex(vector.PublicKey, publicKey, sizeof(publicKey));
        const SIZE_T sigLength = DecodeHex(vector.Signature, signature, sizeof(signature));
        const SIZE_T messageLength =
            vector.Message[0] == '\0' ? 0 : DecodeHex(vector.Message, message, sizeof(message));

        Expect(keyLength == 57, vector.Name);
        Expect(sigLength == 114, vector.Name);
        Expect(messageLength != static_cast<SIZE_T>(-1), vector.Name);
        Expect(Ed448Verify(publicKey, keyLength, message, messageLength, signature, sigLength), vector.Name);

        UCHAR tamperedSig[114] = {};
        memcpy(tamperedSig, signature, sizeof(tamperedSig));
        tamperedSig[0] ^= 0x01;
        Expect(!Ed448Verify(publicKey, keyLength, message, messageLength, tamperedSig, sigLength),
            "tampered Ed448 signature R rejected");

        memcpy(tamperedSig, signature, sizeof(tamperedSig));
        tamperedSig[80] ^= 0x01;
        Expect(!Ed448Verify(publicKey, keyLength, message, messageLength, tamperedSig, sigLength),
            "tampered Ed448 signature S rejected");

        UCHAR tamperedKey[57] = {};
        memcpy(tamperedKey, publicKey, sizeof(tamperedKey));
        tamperedKey[0] ^= 0x01;
        Expect(!Ed448Verify(tamperedKey, keyLength, message, messageLength, signature, sigLength),
            "tampered Ed448 public key rejected");

        if (messageLength != 0) {
            message[0] ^= 0x01;
            Expect(!Ed448Verify(publicKey, keyLength, message, messageLength, signature, sigLength),
                "tampered Ed448 message rejected");
            message[0] ^= 0x01;
        }
    }

    void TestRejectionConditions()
    {
        UCHAR publicKey[57] = {};
        UCHAR signature[114] = {};
        const UCHAR message[1] = { 0x03 };
        (void)DecodeHex(kVectors[1].PublicKey, publicKey, sizeof(publicKey));
        (void)DecodeHex(kVectors[1].Signature, signature, sizeof(signature));

        Expect(!Ed448Verify(publicKey, 56, message, 1, signature, 114), "rejects 56-byte Ed448 key");
        Expect(!Ed448Verify(publicKey, 58, message, 1, signature, 114), "rejects 58-byte Ed448 key");
        Expect(!Ed448Verify(publicKey, 57, message, 1, signature, 113), "rejects 113-byte Ed448 signature");
        Expect(!Ed448Verify(publicKey, 57, message, 1, signature, 115), "rejects 115-byte Ed448 signature");
        Expect(!Ed448Verify(nullptr, 57, message, 1, signature, 114), "rejects null Ed448 key");
        Expect(!Ed448Verify(publicKey, 57, message, 1, nullptr, 114), "rejects null Ed448 signature");

        UCHAR oversS[114] = {};
        memcpy(oversS, signature, 57);
        memset(oversS + 57, 0xff, 57);
        Expect(!Ed448Verify(publicKey, 57, message, 1, oversS, 114), "rejects Ed448 S >= L");
    }
}

int main()
{
    TestShake256KnownVector();

    for (SIZE_T index = 0; index < sizeof(kVectors) / sizeof(kVectors[0]); ++index) {
        RunVector(kVectors[index]);
    }

    TestRejectionConditions();

    if (g_failed) {
        printf("ED448 TESTS FAILED\n");
        return 1;
    }
    printf("ED448 TESTS PASSED\n");
    return 0;
}
