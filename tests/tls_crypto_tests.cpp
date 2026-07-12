#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include <wknet/crypto/Aead.h>
#include <wknet/crypto/CngProvider.h>
#include <wknet/crypto/KeyExchange.h>

#include <stdio.h>
#include <string.h>

using wknet::crypto::Aead;
using wknet::crypto::AeadAlgorithm;
using wknet::crypto::AeadKey;
using wknet::crypto::AeadParameters;
using wknet::crypto::CngKey;
using wknet::crypto::CngProvider;
using wknet::crypto::KeyExchange;
using wknet::crypto::KeyExchangeGroup;
using wknet::crypto::KeyExchangeKeyPair;
using wknet::crypto::KeyExchangeFfdhe2048Length;
using wknet::crypto::KeyExchangeX25519KeyLength;
using wknet::crypto::KeyExchangeX448KeyLength;
using wknet::crypto::SignatureAlgorithm;

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

    void ExpectStatus(NTSTATUS actual, NTSTATUS expected, const char* message)
    {
        if (actual != expected) {
            g_failed = true;
            printf(
                "FAIL: %s (actual=0x%08X expected=0x%08X)\n",
                message,
                static_cast<unsigned int>(actual),
                static_cast<unsigned int>(expected));
        }
    }

    bool Equals(const UCHAR* left, const UCHAR* right, SIZE_T length)
    {
        return left != nullptr && right != nullptr && memcmp(left, right, length) == 0;
    }

    int HexValue(char value)
    {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'A' && value <= 'F') {
            return value - 'A' + 10;
        }
        if (value >= 'a' && value <= 'f') {
            return value - 'a' + 10;
        }
        return -1;
    }

    bool DecodeHex(const char* hex, UCHAR* output, SIZE_T outputLength)
    {
        if (hex == nullptr || output == nullptr || outputLength == 0) {
            return false;
        }

        SIZE_T hexLength = 0;
        while (hex[hexLength] != '\0') {
            ++hexLength;
        }
        if (hexLength != outputLength * 2) {
            return false;
        }

        for (SIZE_T index = 0; index < outputLength; ++index) {
            const int high = HexValue(hex[index * 2]);
            const int low = HexValue(hex[(index * 2) + 1]);
            if (high < 0 || low < 0) {
                return false;
            }
            output[index] = static_cast<UCHAR>((high << 4) | low);
        }

        return true;
    }

    void TestX25519Rfc7748Vector()
    {
        static const UCHAR alicePrivate[32] = {
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
        };
        static const UCHAR expectedAlicePublic[32] = {
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
        };
        static const UCHAR bobPublic[32] = {
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
        };
        static const UCHAR expectedSharedSecret[32] = {
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
            0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
            0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
            0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
        };

        UCHAR publicKey[32] = {};
        SIZE_T publicKeyLength = 0;
        NTSTATUS status = KeyExchange::DerivePublicKey(
            KeyExchangeGroup::X25519,
            alicePrivate,
            sizeof(alicePrivate),
            publicKey,
            sizeof(publicKey),
            &publicKeyLength);
        ExpectStatus(status, STATUS_SUCCESS, "X25519 public key derives");
        Expect(publicKeyLength == sizeof(publicKey), "X25519 public key length is 32");
        Expect(Equals(publicKey, expectedAlicePublic, sizeof(publicKey)), "X25519 public key matches RFC 7748 vector");

        UCHAR sharedSecret[32] = {};
        SIZE_T sharedSecretLength = 0;
        status = KeyExchange::DeriveSharedSecret(
            KeyExchangeGroup::X25519,
            alicePrivate,
            sizeof(alicePrivate),
            bobPublic,
            sizeof(bobPublic),
            sharedSecret,
            sizeof(sharedSecret),
            &sharedSecretLength);
        ExpectStatus(status, STATUS_SUCCESS, "X25519 shared secret derives");
        Expect(sharedSecretLength == sizeof(sharedSecret), "X25519 shared secret length is 32");
        Expect(Equals(sharedSecret, expectedSharedSecret, sizeof(sharedSecret)), "X25519 shared secret matches RFC 7748 vector");
    }

    void TestX25519GeneratedKeyPairUsesRawShare()
    {
        KeyExchangeKeyPair keyPair;
        NTSTATUS status = KeyExchange::GenerateKeyPair(nullptr, KeyExchangeGroup::X25519, keyPair);
        ExpectStatus(status, STATUS_SUCCESS, "X25519 key pair generates");
        Expect(keyPair.PrivateKeyLength == KeyExchangeX25519KeyLength, "X25519 private key is 32 bytes");
        Expect(keyPair.PublicKeyLength == KeyExchangeX25519KeyLength, "X25519 public key is raw 32 bytes");
        Expect(keyPair.PublicKey[0] != 4, "X25519 key share is not an uncompressed EC point");
    }

    void TestX448Rfc7748Vectors()
    {
        static const UCHAR baseScalar[56] = {
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        static const UCHAR expectedBasePublic[56] = {
            0x3f, 0x48, 0x2c, 0x8a, 0x9f, 0x19, 0xb0, 0x1e,
            0x6c, 0x46, 0xee, 0x97, 0x11, 0xd9, 0xdc, 0x14,
            0xfd, 0x4b, 0xf6, 0x7a, 0xf3, 0x07, 0x65, 0xc2,
            0xae, 0x2b, 0x84, 0x6a, 0x4d, 0x23, 0xa8, 0xcd,
            0x0d, 0xb8, 0x97, 0x08, 0x62, 0x39, 0x49, 0x2c,
            0xaf, 0x35, 0x0b, 0x51, 0xf8, 0x33, 0x86, 0x8b,
            0x9b, 0xc2, 0xb3, 0xbc, 0xa9, 0xcf, 0x41, 0x13
        };
        static const UCHAR privateKey[56] = {
            0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88,
            0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2,
            0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0,
            0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c,
            0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf,
            0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b,
            0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3
        };
        static const UCHAR peerPublic[56] = {
            0x06, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf,
            0xda, 0x5f, 0x6c, 0xf2, 0xd5, 0x26, 0x3f, 0x8a,
            0xad, 0x88, 0x33, 0x4c, 0xbd, 0x07, 0x43, 0x7f,
            0x02, 0x0f, 0x08, 0xf9, 0x81, 0x4d, 0xc0, 0x31,
            0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25,
            0x83, 0xfa, 0x54, 0x29, 0xdb, 0x94, 0xad, 0xa1,
            0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0, 0x86
        };
        static const UCHAR expectedSharedSecret[56] = {
            0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66,
            0x97, 0xda, 0x1d, 0xb1, 0xd8, 0x5e, 0x6a, 0xfb,
            0xdf, 0x79, 0xb5, 0x0a, 0x24, 0x12, 0xd7, 0x54,
            0x6d, 0x5f, 0x23, 0x9f, 0xe1, 0x4f, 0xba, 0xad,
            0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77,
            0x9d, 0x98, 0x22, 0x39, 0x61, 0x11, 0x1e, 0x21,
            0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b, 0x6f
        };

        UCHAR publicKey[KeyExchangeX448KeyLength] = {};
        SIZE_T publicKeyLength = 0;
        NTSTATUS status = KeyExchange::DerivePublicKey(
            KeyExchangeGroup::X448,
            baseScalar,
            sizeof(baseScalar),
            publicKey,
            sizeof(publicKey),
            &publicKeyLength);
        ExpectStatus(status, STATUS_SUCCESS, "X448 public key derives");
        Expect(publicKeyLength == sizeof(publicKey), "X448 public key length is 56");
        Expect(Equals(publicKey, expectedBasePublic, sizeof(publicKey)), "X448 public key matches RFC 7748 vector");

        UCHAR sharedSecret[KeyExchangeX448KeyLength] = {};
        SIZE_T sharedSecretLength = 0;
        status = KeyExchange::DeriveSharedSecret(
            KeyExchangeGroup::X448,
            privateKey,
            sizeof(privateKey),
            peerPublic,
            sizeof(peerPublic),
            sharedSecret,
            sizeof(sharedSecret),
            &sharedSecretLength);
        ExpectStatus(status, STATUS_SUCCESS, "X448 shared secret derives");
        Expect(sharedSecretLength == sizeof(sharedSecret), "X448 shared secret length is 56");
        Expect(Equals(sharedSecret, expectedSharedSecret, sizeof(sharedSecret)), "X448 shared secret matches RFC 7748 vector");
    }

    void TestX448GeneratedKeyPairUsesRawShare()
    {
        KeyExchangeKeyPair keyPair;
        NTSTATUS status = KeyExchange::GenerateKeyPair(nullptr, KeyExchangeGroup::X448, keyPair);
        ExpectStatus(status, STATUS_SUCCESS, "X448 key pair generates");
        Expect(keyPair.PrivateKeyLength == KeyExchangeX448KeyLength, "X448 private key is 56 bytes");
        Expect(keyPair.PublicKeyLength == KeyExchangeX448KeyLength, "X448 public key is raw 56 bytes");
        Expect(keyPair.PublicKey[0] != 4, "X448 key share is not an uncompressed EC point");
    }

    void TestAesGcmNistVector()
    {
        static const UCHAR key[16] = {};
        static const UCHAR nonce[12] = {};
        static const UCHAR plaintext[16] = {};
        static const UCHAR expectedCiphertext[16] = {
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
            0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
        };
        static const UCHAR expectedTag[16] = {
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
            0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
        };

        UCHAR ciphertext[sizeof(plaintext)] = {};
        UCHAR tag[sizeof(expectedTag)] = {};
        SIZE_T written = 0;

        AeadKey aeadKey = {};
        aeadKey.Algorithm = AeadAlgorithm::Aes128Gcm;
        aeadKey.Key = key;
        aeadKey.KeyLength = sizeof(key);

        AeadParameters parameters = {};
        parameters.Nonce = { nonce, sizeof(nonce) };

        NTSTATUS status = Aead::Encrypt(
            nullptr,
            aeadKey,
            parameters,
            plaintext,
            sizeof(plaintext),
            ciphertext,
            sizeof(ciphertext),
            tag,
            sizeof(tag),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "AES-GCM encrypts NIST vector");
        Expect(written == sizeof(plaintext), "AES-GCM encrypted length matches plaintext");
        Expect(Equals(ciphertext, expectedCiphertext, sizeof(ciphertext)), "AES-GCM ciphertext matches NIST vector");
        Expect(Equals(tag, expectedTag, sizeof(tag)), "AES-GCM tag matches NIST vector");

        UCHAR decrypted[sizeof(plaintext)] = {};
        parameters.Tag = { tag, sizeof(tag) };
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "AES-GCM decrypts NIST vector");
        Expect(written == sizeof(plaintext), "AES-GCM decrypted length matches plaintext");
        Expect(Equals(decrypted, plaintext, sizeof(plaintext)), "AES-GCM decrypts original plaintext");

        tag[0] ^= 1;
        parameters.Tag = { tag, sizeof(tag) };
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);
        ExpectStatus(status, STATUS_INVALID_SIGNATURE, "AES-GCM rejects wrong tag");
    }

    void TestFfdhe2048KeyAgreement()
    {
        KeyExchangeKeyPair alice;
        KeyExchangeKeyPair bob;
        NTSTATUS status = KeyExchange::GenerateKeyPair(nullptr, KeyExchangeGroup::Ffdhe2048, alice);
        ExpectStatus(status, STATUS_SUCCESS, "FFDHE2048 Alice key pair generates");
        Expect(alice.PrivateKeyLength != 0, "FFDHE2048 Alice private exponent is present");
        Expect(alice.PublicKeyLength == KeyExchangeFfdhe2048Length, "FFDHE2048 Alice public key length matches group");

        status = KeyExchange::GenerateKeyPair(nullptr, KeyExchangeGroup::Ffdhe2048, bob);
        ExpectStatus(status, STATUS_SUCCESS, "FFDHE2048 Bob key pair generates");
        Expect(bob.PrivateKeyLength != 0, "FFDHE2048 Bob private exponent is present");
        Expect(bob.PublicKeyLength == KeyExchangeFfdhe2048Length, "FFDHE2048 Bob public key length matches group");

        status = KeyExchange::ValidateFiniteFieldPublicKey(
            KeyExchangeGroup::Ffdhe2048,
            alice.PublicKey,
            alice.PublicKeyLength);
        ExpectStatus(status, STATUS_SUCCESS, "FFDHE2048 validates generated public key");

        UCHAR aliceSecret[KeyExchangeFfdhe2048Length] = {};
        UCHAR bobSecret[KeyExchangeFfdhe2048Length] = {};
        SIZE_T aliceSecretLength = 0;
        SIZE_T bobSecretLength = 0;
        status = KeyExchange::DeriveSharedSecret(
            nullptr,
            alice,
            bob.PublicKey,
            bob.PublicKeyLength,
            aliceSecret,
            sizeof(aliceSecret),
            &aliceSecretLength);
        ExpectStatus(status, STATUS_SUCCESS, "FFDHE2048 Alice derives shared secret");
        Expect(aliceSecretLength == sizeof(aliceSecret), "FFDHE2048 Alice secret length matches group");

        status = KeyExchange::DeriveSharedSecret(
            nullptr,
            bob,
            alice.PublicKey,
            alice.PublicKeyLength,
            bobSecret,
            sizeof(bobSecret),
            &bobSecretLength);
        ExpectStatus(status, STATUS_SUCCESS, "FFDHE2048 Bob derives shared secret");
        Expect(bobSecretLength == sizeof(bobSecret), "FFDHE2048 Bob secret length matches group");
        Expect(Equals(aliceSecret, bobSecret, sizeof(aliceSecret)), "FFDHE2048 shared secrets match");

        UCHAR invalid[KeyExchangeFfdhe2048Length] = {};
        status = KeyExchange::ValidateFiniteFieldPublicKey(
            KeyExchangeGroup::Ffdhe2048,
            invalid,
            sizeof(invalid));
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "FFDHE rejects all-zero public value");

        invalid[sizeof(invalid) - 1] = 1;
        status = KeyExchange::ValidateFiniteFieldPublicKey(
            KeyExchangeGroup::Ffdhe2048,
            invalid,
            sizeof(invalid));
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "FFDHE rejects public value one");
    }

    void TestFfdhe2048ParameterRecognition()
    {
        static const char Ffdhe2048ModulusHex[] =
            "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
            "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
            "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
            "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
            "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
            "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
            "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
            "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

        UCHAR prime[KeyExchangeFfdhe2048Length] = {};
        const UCHAR generator[] = { 2 };
        Expect(DecodeHex(Ffdhe2048ModulusHex, prime, sizeof(prime)), "FFDHE2048 test modulus decodes");

        KeyExchangeGroup group = KeyExchangeGroup::Secp256r1;
        NTSTATUS status = KeyExchange::FindFiniteFieldGroup(
            prime,
            sizeof(prime),
            generator,
            sizeof(generator),
            &group);
        ExpectStatus(status, STATUS_SUCCESS, "FFDHE2048 parameters map to known group");
        Expect(group == KeyExchangeGroup::Ffdhe2048, "FFDHE2048 parameters return Ffdhe2048 group");

        prime[0] ^= 1;
        status = KeyExchange::FindFiniteFieldGroup(
            prime,
            sizeof(prime),
            generator,
            sizeof(generator),
            &group);
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "non-RFC finite-field parameters are rejected");
    }

    void TestChaCha20Poly1305Rfc8439Vector()
    {
        static const UCHAR key[32] = {
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        };
        static const UCHAR nonce[12] = {
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47
        };
        static const UCHAR aad[12] = {
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7
        };
        static const UCHAR plaintext[] = {
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
            0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
            0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
            0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
            0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
            0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e
        };
        static const UCHAR expectedCiphertext[] = {
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
            0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
            0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
            0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
            0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
            0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
            0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16
        };
        static const UCHAR expectedTag[16] = {
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
        };

        UCHAR ciphertext[sizeof(plaintext)] = {};
        UCHAR tag[16] = {};
        SIZE_T written = 0;

        AeadKey aeadKey = {};
        aeadKey.Algorithm = AeadAlgorithm::ChaCha20Poly1305;
        aeadKey.Key = key;
        aeadKey.KeyLength = sizeof(key);

        AeadParameters parameters = {};
        parameters.Nonce = { nonce, sizeof(nonce) };
        parameters.Aad = { aad, sizeof(aad) };

        NTSTATUS status = Aead::Encrypt(
            nullptr,
            aeadKey,
            parameters,
            plaintext,
            sizeof(plaintext),
            ciphertext,
            sizeof(ciphertext),
            tag,
            sizeof(tag),
            &written);

        ExpectStatus(status, STATUS_SUCCESS, "ChaCha20-Poly1305 encrypts");
        Expect(written == sizeof(plaintext), "ChaCha20-Poly1305 encrypted length matches plaintext");
        Expect(Equals(ciphertext, expectedCiphertext, sizeof(ciphertext)), "ChaCha20-Poly1305 ciphertext matches RFC 8439 vector");
        Expect(Equals(tag, expectedTag, sizeof(tag)), "ChaCha20-Poly1305 tag matches RFC 8439 vector");

        UCHAR decrypted[sizeof(plaintext)] = {};
        parameters.Tag = { tag, sizeof(tag) };
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);

        ExpectStatus(status, STATUS_SUCCESS, "ChaCha20-Poly1305 decrypts");
        Expect(written == sizeof(plaintext), "ChaCha20-Poly1305 decrypted length matches plaintext");
        Expect(Equals(decrypted, plaintext, sizeof(plaintext)), "ChaCha20-Poly1305 decrypts original plaintext");

        tag[0] ^= 1;
        parameters.Tag = { tag, sizeof(tag) };
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);
        ExpectStatus(status, STATUS_INVALID_SIGNATURE, "ChaCha20-Poly1305 rejects wrong tag");
    }

    void TestAesCcm8Rfc3610Vector()
    {
        static const UCHAR key[16] = {
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
            0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
        };
        static const UCHAR nonce[13] = {
            0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5
        };
        static const UCHAR aad[8] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
        };
        static const UCHAR plaintext[23] = {
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
        };
        static const UCHAR expectedCiphertext[23] = {
            0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
            0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
            0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84
        };
        static const UCHAR expectedTag[8] = {
            0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
        };

        UCHAR ciphertext[sizeof(plaintext)] = {};
        UCHAR tag[sizeof(expectedTag)] = {};
        SIZE_T written = 0;

        AeadKey aeadKey = {};
        aeadKey.Algorithm = AeadAlgorithm::Aes128Ccm8;
        aeadKey.Key = key;
        aeadKey.KeyLength = sizeof(key);

        AeadParameters parameters = {};
        parameters.Nonce = { nonce, sizeof(nonce) };
        parameters.Aad = { aad, sizeof(aad) };

        NTSTATUS status = Aead::Encrypt(
            nullptr,
            aeadKey,
            parameters,
            plaintext,
            sizeof(plaintext),
            ciphertext,
            sizeof(ciphertext),
            tag,
            sizeof(tag),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CCM_8 encrypts");
        Expect(written == sizeof(plaintext), "AES-CCM_8 encrypted length matches plaintext");
        Expect(Equals(ciphertext, expectedCiphertext, sizeof(ciphertext)), "AES-CCM_8 ciphertext matches RFC 3610 vector");
        Expect(Equals(tag, expectedTag, sizeof(tag)), "AES-CCM_8 tag matches RFC 3610 vector");

        UCHAR decrypted[sizeof(plaintext)] = {};
        parameters.Tag = { tag, sizeof(tag) };
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CCM_8 decrypts");
        Expect(written == sizeof(plaintext), "AES-CCM_8 decrypted length matches plaintext");
        Expect(Equals(decrypted, plaintext, sizeof(plaintext)), "AES-CCM_8 decrypts original plaintext");

        tag[0] ^= 1;
        parameters.Tag = { tag, sizeof(tag) };
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);
        ExpectStatus(status, STATUS_INVALID_SIGNATURE, "AES-CCM_8 rejects wrong tag");
    }

    void TestAesCcmRoundTripAndTamper()
    {
        static const UCHAR key[16] = {
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
        };
        static const UCHAR nonce[12] = {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b
        };
        static const UCHAR aad[5] = { 0x17, 0x03, 0x03, 0x00, 0x20 };
        static const UCHAR plaintext[32] = {
            0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x61, 0x65,
            0x73, 0x2d, 0x63, 0x63, 0x6d, 0x20, 0x72, 0x6f,
            0x75, 0x6e, 0x64, 0x74, 0x72, 0x69, 0x70, 0x20,
            0x74, 0x61, 0x67, 0x31, 0x36, 0x20, 0x21, 0x21
        };

        UCHAR ciphertext[sizeof(plaintext)] = {};
        UCHAR tag[16] = {};
        SIZE_T written = 0;

        AeadKey aeadKey = {};
        aeadKey.Algorithm = AeadAlgorithm::Aes128Ccm;
        aeadKey.Key = key;
        aeadKey.KeyLength = sizeof(key);

        AeadParameters parameters = {};
        parameters.Nonce = { nonce, sizeof(nonce) };
        parameters.Aad = { aad, sizeof(aad) };

        NTSTATUS status = Aead::Encrypt(
            nullptr,
            aeadKey,
            parameters,
            plaintext,
            sizeof(plaintext),
            ciphertext,
            sizeof(ciphertext),
            tag,
            sizeof(tag),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CCM encrypts with 16-byte tag");
        Expect(written == sizeof(plaintext), "AES-CCM encrypted length matches plaintext");

        UCHAR decrypted[sizeof(plaintext)] = {};
        parameters.Tag = { tag, sizeof(tag) };
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);
        ExpectStatus(status, STATUS_SUCCESS, "AES-CCM decrypts with 16-byte tag");
        Expect(written == sizeof(plaintext), "AES-CCM decrypted length matches plaintext");
        Expect(Equals(decrypted, plaintext, sizeof(plaintext)), "AES-CCM decrypts original plaintext");

        ciphertext[0] ^= 1;
        status = Aead::Decrypt(
            nullptr,
            aeadKey,
            parameters,
            ciphertext,
            sizeof(ciphertext),
            decrypted,
            sizeof(decrypted),
            &written);
        ExpectStatus(status, STATUS_INVALID_SIGNATURE, "AES-CCM rejects tampered ciphertext");
    }

    void TestSha1SignatureAlgorithmsAreCallable()
    {
        static const UCHAR sha1Digest[20] = {
            0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc,
            0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39,
            0x1b, 0x93, 0xeb, 0x12
        };
        static const UCHAR signature[64] = {
            0x30, 0x2e, 0x02, 0x15, 0x00, 0xd1, 0x5f, 0x9a,
            0x65, 0x51, 0x4a, 0x3f, 0x81, 0xba, 0xe2, 0x69,
            0xb1, 0x8b, 0x3f, 0x5a, 0x90, 0x4c, 0x8b, 0x02,
            0x15, 0x00, 0xb7, 0x8d, 0x8e, 0xab, 0x48, 0x15,
            0x6f, 0x7f, 0x41, 0x16, 0x43, 0x9d, 0xba, 0x9b,
            0xd2, 0x22, 0x12, 0xb0, 0x00, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
        };

        CngKey publicKey;
        NTSTATUS status = CngProvider::VerifySignature(
            SignatureAlgorithm::RsaPkcs1Sha1,
            publicKey,
            sha1Digest,
            sizeof(sha1Digest),
            signature,
            sizeof(signature));
        ExpectStatus(status, STATUS_SUCCESS, "RSA PKCS1 SHA1 signature algorithm is callable");

        status = CngProvider::VerifySignature(
            SignatureAlgorithm::EcdsaSha1,
            publicKey,
            sha1Digest,
            sizeof(sha1Digest),
            signature,
            sizeof(signature));
        ExpectStatus(status, STATUS_SUCCESS, "ECDSA SHA1 signature algorithm is callable");
    }
}

int main()
{
    TestX25519Rfc7748Vector();
    TestX25519GeneratedKeyPairUsesRawShare();
    TestX448Rfc7748Vectors();
    TestX448GeneratedKeyPairUsesRawShare();
    TestAesGcmNistVector();
    TestFfdhe2048KeyAgreement();
    TestFfdhe2048ParameterRecognition();
    TestChaCha20Poly1305Rfc8439Vector();
    TestAesCcm8Rfc3610Vector();
    TestAesCcmRoundTripAndTamper();
    TestSha1SignatureAlgorithmsAreCallable();

    if (g_failed) {
        return 1;
    }

    printf("PASS: TLS crypto tests\n");
    return 0;
}
