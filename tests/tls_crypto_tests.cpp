#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/crypto/Aead.h>
#include <KernelHttp/crypto/KeyExchange.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::crypto::Aead;
using KernelHttp::crypto::AeadAlgorithm;
using KernelHttp::crypto::AeadKey;
using KernelHttp::crypto::AeadParameters;
using KernelHttp::crypto::KeyExchange;
using KernelHttp::crypto::KeyExchangeGroup;
using KernelHttp::crypto::KeyExchangeKeyPair;
using KernelHttp::crypto::KeyExchangeX25519KeyLength;

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

    void TestX448AndFfdheAreExplicitlyUnsupported()
    {
        UCHAR buffer[64] = {};
        SIZE_T written = 0;
        NTSTATUS status = KeyExchange::DerivePublicKey(
            KeyExchangeGroup::X448,
            buffer,
            56,
            buffer,
            sizeof(buffer),
            &written);
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "X448 returns explicit unsupported until implemented");

        buffer[sizeof(buffer) - 1] = 2;
        status = KeyExchange::ValidateFiniteFieldPublicKey(
            KeyExchangeGroup::Ffdhe2048,
            buffer,
            sizeof(buffer));
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "FFDHE range validation is not advertised as complete");

        memset(buffer, 0, sizeof(buffer));
        status = KeyExchange::ValidateFiniteFieldPublicKey(
            KeyExchangeGroup::Ffdhe2048,
            buffer,
            sizeof(buffer));
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "FFDHE rejects all-zero public value");
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

    void TestAesCcmIsExplicitlyUnsupported()
    {
        UCHAR key[16] = {};
        UCHAR nonce[12] = {};
        UCHAR output[16] = {};
        UCHAR tag[16] = {};

        AeadKey aeadKey = {};
        aeadKey.Algorithm = AeadAlgorithm::Aes128Ccm;
        aeadKey.Key = key;
        aeadKey.KeyLength = sizeof(key);

        AeadParameters parameters = {};
        parameters.Nonce = { nonce, sizeof(nonce) };

        const NTSTATUS status = Aead::Encrypt(
            nullptr,
            aeadKey,
            parameters,
            output,
            0,
            output,
            sizeof(output),
            tag,
            sizeof(tag));
        ExpectStatus(status, STATUS_NOT_SUPPORTED, "AES-CCM returns explicit unsupported until implemented");
    }
}

int main()
{
    TestX25519Rfc7748Vector();
    TestX25519GeneratedKeyPairUsesRawShare();
    TestX448AndFfdheAreExplicitlyUnsupported();
    TestChaCha20Poly1305Rfc8439Vector();
    TestAesCcmIsExplicitlyUnsupported();

    if (g_failed) {
        return 1;
    }

    printf("PASS: TLS crypto tests\n");
    return 0;
}
