#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/tls/TlsHandshake13.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::tls::TlsCipherSuite;
using KernelHttp::tls::TlsContext;
using KernelHttp::tls::TlsHandshake13;
using KernelHttp::tls::TlsHandshakeMessageView;
using KernelHttp::tls::TlsHandshakeType;
using KernelHttp::tls::TlsNamedGroup;
using KernelHttp::tls::Tls13ClientHelloOptions;
using KernelHttp::tls::Tls13KeyShareEntry;
using KernelHttp::tls::Tls13ServerHelloView;

namespace
{
    constexpr USHORT ExtensionSupportedGroups = 10;
    constexpr USHORT ExtensionKeyShare = 51;

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

    USHORT ReadUint16(const UCHAR* data)
    {
        return static_cast<USHORT>((static_cast<USHORT>(data[0]) << 8) | data[1]);
    }

    bool FindExtension(
        const UCHAR* clientHello,
        SIZE_T clientHelloLength,
        USHORT extensionType,
        const UCHAR** extension,
        SIZE_T* extensionLength)
    {
        if (extension != nullptr) {
            *extension = nullptr;
        }
        if (extensionLength != nullptr) {
            *extensionLength = 0;
        }
        if (clientHello == nullptr || extension == nullptr || extensionLength == nullptr || clientHelloLength < 4 + 34) {
            return false;
        }

        SIZE_T offset = 4 + 34;
        if (offset >= clientHelloLength) {
            return false;
        }

        const UCHAR sessionIdLength = clientHello[offset++];
        if (sessionIdLength > clientHelloLength - offset) {
            return false;
        }
        offset += sessionIdLength;

        if (clientHelloLength - offset < 2) {
            return false;
        }
        const SIZE_T cipherSuitesLength = ReadUint16(clientHello + offset);
        offset += 2;
        if (cipherSuitesLength > clientHelloLength - offset) {
            return false;
        }
        offset += cipherSuitesLength;

        if (clientHelloLength - offset < 1) {
            return false;
        }
        const UCHAR compressionMethodsLength = clientHello[offset++];
        if (compressionMethodsLength > clientHelloLength - offset) {
            return false;
        }
        offset += compressionMethodsLength;

        if (clientHelloLength - offset < 2) {
            return false;
        }
        const SIZE_T extensionsLength = ReadUint16(clientHello + offset);
        offset += 2;
        if (extensionsLength != clientHelloLength - offset) {
            return false;
        }

        const SIZE_T extensionsEnd = offset + extensionsLength;
        while (offset < extensionsEnd) {
            if (extensionsEnd - offset < 4) {
                return false;
            }

            const USHORT currentType = ReadUint16(clientHello + offset);
            const SIZE_T currentLength = ReadUint16(clientHello + offset + 2);
            offset += 4;
            if (currentLength > extensionsEnd - offset) {
                return false;
            }

            if (currentType == extensionType) {
                *extension = clientHello + offset;
                *extensionLength = currentLength;
                return true;
            }

            offset += currentLength;
        }

        return false;
    }

    bool FirstSupportedGroupIs(const UCHAR* clientHello, SIZE_T clientHelloLength, TlsNamedGroup expected)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindExtension(clientHello, clientHelloLength, ExtensionSupportedGroups, &extension, &extensionLength) ||
            extensionLength < 4) {
            return false;
        }

        const SIZE_T vectorLength = ReadUint16(extension);
        if (vectorLength + 2 != extensionLength || vectorLength < 2) {
            return false;
        }

        return ReadUint16(extension + 2) == static_cast<USHORT>(expected);
    }

    bool KeyShareIsRawX25519(const UCHAR* clientHello, SIZE_T clientHelloLength)
    {
        const UCHAR* extension = nullptr;
        SIZE_T extensionLength = 0;
        if (!FindExtension(clientHello, clientHelloLength, ExtensionKeyShare, &extension, &extensionLength) ||
            extensionLength < 6) {
            return false;
        }

        const SIZE_T vectorLength = ReadUint16(extension);
        if (vectorLength + 2 != extensionLength || vectorLength < 4) {
            return false;
        }

        const USHORT group = ReadUint16(extension + 2);
        const SIZE_T keyLength = ReadUint16(extension + 4);
        return group == static_cast<USHORT>(TlsNamedGroup::X25519) &&
            keyLength == 32 &&
            vectorLength == 4 + keyLength &&
            extension[6] != 4;
    }

    void TestDefaultTls13ClientHelloOffersX25519First()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 context initializes");

        UCHAR message[2048] = {};
        SIZE_T written = 0;
        Tls13ClientHelloOptions options = {};
        status = TlsHandshake13::EncodeClientHello(context, options, message, sizeof(message), &written);

        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 ClientHello encodes with defaults");
        Expect(written > 0, "TLS 1.3 ClientHello has content");
        Expect(message[0] == static_cast<UCHAR>(TlsHandshakeType::ClientHello), "ClientHello type is written");
        Expect(FirstSupportedGroupIs(message, written, TlsNamedGroup::X25519), "default supported_groups starts with X25519");
    }

    void TestTls13ClientHelloEncodesRawX25519KeyShare()
    {
        TlsContext context;
        NTSTATUS status = context.InitializeClient13();
        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 context initializes for X25519 key share");

        UCHAR rawShare[32] = {};
        for (SIZE_T index = 0; index < sizeof(rawShare); ++index) {
            rawShare[index] = static_cast<UCHAR>(index + 1);
        }

        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::X25519;
        keyShare.KeyExchange = rawShare;
        keyShare.KeyExchangeLength = sizeof(rawShare);

        Tls13ClientHelloOptions options = {};
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;

        UCHAR message[2048] = {};
        SIZE_T written = 0;
        status = TlsHandshake13::EncodeClientHello(context, options, message, sizeof(message), &written);

        ExpectStatus(status, STATUS_SUCCESS, "TLS 1.3 ClientHello encodes X25519 key share");
        Expect(KeyShareIsRawX25519(message, written), "TLS 1.3 X25519 key_share is raw 32 bytes");
    }

    void TestTls13HelloRetryRequestCanSelectP256AfterX25519Offer()
    {
        UCHAR rawShare[32] = {};
        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::X25519;
        keyShare.KeyExchange = rawShare;
        keyShare.KeyExchangeLength = sizeof(rawShare);

        TlsNamedGroup groups[] = {
            TlsNamedGroup::X25519,
            TlsNamedGroup::Secp256r1,
            TlsNamedGroup::Secp384r1
        };

        TlsCipherSuite cipherSuites[] = {
            TlsCipherSuite::TlsAes128GcmSha256
        };

        Tls13ClientHelloOptions options = {};
        options.CipherSuites = cipherSuites;
        options.CipherSuiteCount = sizeof(cipherSuites) / sizeof(cipherSuites[0]);
        options.NamedGroups = groups;
        options.NamedGroupCount = sizeof(groups) / sizeof(groups[0]);
        options.KeyShares = &keyShare;
        options.KeyShareCount = 1;

        Tls13ServerHelloView serverHello = {};
        serverHello.CipherSuite = TlsCipherSuite::TlsAes128GcmSha256;
        serverHello.IsHelloRetryRequest = true;
        serverHello.RetryGroup = TlsNamedGroup::Secp256r1;

        NTSTATUS status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
        ExpectStatus(status, STATUS_SUCCESS, "HRR can request offered P-256 after initial X25519 share");

        serverHello.RetryGroup = TlsNamedGroup::X25519;
        status = TlsHandshake13::ValidateServerHelloOffer(serverHello, options);
        ExpectStatus(status, STATUS_INVALID_NETWORK_RESPONSE, "HRR rejects group already carrying a key_share");
    }
}

int main()
{
    TestDefaultTls13ClientHelloOffersX25519First();
    TestTls13ClientHelloEncodesRawX25519KeyShare();
    TestTls13HelloRetryRequestCanSelectP256AfterX25519Offer();

    if (g_failed) {
        return 1;
    }

    printf("PASS: TLS handshake tests\n");
    return 0;
}
