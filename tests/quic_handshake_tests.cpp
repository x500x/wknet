#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "quic/QuicTls.h"
#include <stdio.h>
#include <string.h>

namespace
{
bool failed = false;

void E(bool condition, const char *message)
{
    if (!condition)
    {
        failed = true;
        printf("FAIL: %s\n", message);
    }
}

bool FindClientHelloExtensions(const UCHAR *message, SIZE_T length, const UCHAR **extensions, SIZE_T *extensionsLength)
{
    *extensions = nullptr;
    *extensionsLength = 0;
    if (message == nullptr || length < 4 + 2 + 32 + 1 || message[0] != 1)
    {
        return false;
    }
    SIZE_T offset = 4 + 2 + 32;
    const SIZE_T sessionIdLength = message[offset++];
    if (sessionIdLength > length - offset)
    {
        return false;
    }
    offset += sessionIdLength;
    if (length - offset < 2)
    {
        return false;
    }
    const SIZE_T cipherSuiteLength = (static_cast<SIZE_T>(message[offset]) << 8) | message[offset + 1];
    offset += 2;
    if (cipherSuiteLength > length - offset)
    {
        return false;
    }
    offset += cipherSuiteLength;
    if (offset >= length)
    {
        return false;
    }
    const SIZE_T compressionLength = message[offset++];
    if (compressionLength > length - offset)
    {
        return false;
    }
    offset += compressionLength;
    if (length - offset < 2)
    {
        return false;
    }
    const SIZE_T encodedExtensionsLength = (static_cast<SIZE_T>(message[offset]) << 8) | message[offset + 1];
    offset += 2;
    if (encodedExtensionsLength != length - offset)
    {
        return false;
    }
    *extensions = message + offset;
    *extensionsLength = encodedExtensionsLength;
    return true;
}

SIZE_T BuildServerHello(const UCHAR *keyShare, SIZE_T keyShareLength, UCHAR *output, SIZE_T capacity)
{
    const SIZE_T bodyLength = 2 + 32 + 1 + 2 + 1 + 2 + 6 + 8 + keyShareLength;
    const SIZE_T totalLength = 4 + bodyLength;
    if (output == nullptr || keyShare == nullptr || keyShareLength > 0xffff || capacity < totalLength)
    {
        return 0;
    }
    SIZE_T offset = 0;
    output[offset++] = 2;
    output[offset++] = static_cast<UCHAR>((bodyLength >> 16) & 0xff);
    output[offset++] = static_cast<UCHAR>((bodyLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(bodyLength & 0xff);
    output[offset++] = 3;
    output[offset++] = 3;
    for (SIZE_T index = 0; index < 32; ++index)
    {
        output[offset++] = static_cast<UCHAR>(0x40 + index);
    }
    output[offset++] = 0;
    output[offset++] = 0x13;
    output[offset++] = 0x01;
    output[offset++] = 0;
    const SIZE_T extensionsLength = 6 + 8 + keyShareLength;
    output[offset++] = static_cast<UCHAR>((extensionsLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(extensionsLength & 0xff);
    output[offset++] = 0;
    output[offset++] = 43;
    output[offset++] = 0;
    output[offset++] = 2;
    output[offset++] = 3;
    output[offset++] = 4;
    output[offset++] = 0;
    output[offset++] = 51;
    const SIZE_T keyShareExtensionLength = 4 + keyShareLength;
    output[offset++] = static_cast<UCHAR>((keyShareExtensionLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(keyShareExtensionLength & 0xff);
    output[offset++] = 0;
    output[offset++] = 29;
    output[offset++] = static_cast<UCHAR>((keyShareLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(keyShareLength & 0xff);
    memcpy(output + offset, keyShare, keyShareLength);
    offset += keyShareLength;
    return offset;
}

NTSTATUS TestClientCredentialSign(void *, wknet::crypto::TlsSignatureScheme, const UCHAR *, SIZE_T, UCHAR *signature,
                                  SIZE_T signatureCapacity, SIZE_T *signatureLength)
{
    if (signature == nullptr || signatureLength == nullptr || signatureCapacity < 4)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    signature[0] = 1;
    signature[1] = 2;
    signature[2] = 3;
    signature[3] = 4;
    *signatureLength = 4;
    return STATUS_SUCCESS;
}

SIZE_T BuildHelloRetryRequest(UCHAR *output, SIZE_T capacity)
{
    const UCHAR helloRetryRequestRandom[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
                                               0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
                                               0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    const UCHAR extensions[] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02,
                                0x00, 0x17, 0x00, 0x2c, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb};
    const SIZE_T bodyLength = 2 + sizeof(helloRetryRequestRandom) + 1 + 2 + 1 + 2 + sizeof(extensions);
    const SIZE_T totalLength = 4 + bodyLength;
    if (output == nullptr || capacity < totalLength)
    {
        return 0;
    }
    SIZE_T offset = 0;
    output[offset++] = 2;
    output[offset++] = static_cast<UCHAR>((bodyLength >> 16) & 0xff);
    output[offset++] = static_cast<UCHAR>((bodyLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(bodyLength & 0xff);
    output[offset++] = 3;
    output[offset++] = 3;
    memcpy(output + offset, helloRetryRequestRandom, sizeof(helloRetryRequestRandom));
    offset += sizeof(helloRetryRequestRandom);
    output[offset++] = 0;
    output[offset++] = 0x13;
    output[offset++] = 0x01;
    output[offset++] = 0;
    output[offset++] = 0;
    output[offset++] = static_cast<UCHAR>(sizeof(extensions));
    memcpy(output + offset, extensions, sizeof(extensions));
    offset += sizeof(extensions);
    return offset;
}

SIZE_T BuildEncryptedExtensions(const UCHAR *transportParameters, SIZE_T transportParametersLength, UCHAR *output,
                                SIZE_T capacity)
{
    const SIZE_T extensionsLength = 4 + 5 + 4 + transportParametersLength;
    const SIZE_T bodyLength = 2 + extensionsLength;
    const SIZE_T totalLength = 4 + bodyLength;
    if (output == nullptr || transportParameters == nullptr || capacity < totalLength)
    {
        return 0;
    }
    SIZE_T offset = 0;
    output[offset++] = 8;
    output[offset++] = 0;
    output[offset++] = static_cast<UCHAR>((bodyLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(bodyLength & 0xff);
    output[offset++] = static_cast<UCHAR>((extensionsLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(extensionsLength & 0xff);
    output[offset++] = 0;
    output[offset++] = 16;
    output[offset++] = 0;
    output[offset++] = 5;
    output[offset++] = 0;
    output[offset++] = 3;
    output[offset++] = 2;
    output[offset++] = 'h';
    output[offset++] = '3';
    output[offset++] = 0;
    output[offset++] = 57;
    output[offset++] = static_cast<UCHAR>((transportParametersLength >> 8) & 0xff);
    output[offset++] = static_cast<UCHAR>(transportParametersLength & 0xff);
    memcpy(output + offset, transportParameters, transportParametersLength);
    offset += transportParametersLength;
    return offset;
}

SIZE_T BuildCertificateRequest(UCHAR *output, SIZE_T capacity)
{
    const UCHAR body[] = {0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x04};
    if (output == nullptr || capacity < sizeof(body) + 4)
    {
        return 0;
    }
    output[0] = 13;
    output[1] = 0;
    output[2] = 0;
    output[3] = static_cast<UCHAR>(sizeof(body));
    memcpy(output + 4, body, sizeof(body));
    return sizeof(body) + 4;
}

NTSTATUS InitializeTls(wknet::quic::QuicTls &tls, const UCHAR *clientKeyShare, SIZE_T clientKeyShareLength,
                       UCHAR *clientHello, SIZE_T clientHelloCapacity, SIZE_T *clientHelloLength,
                       const wknet::crypto::TlsClientCredential *clientCredential = nullptr)
{
    UCHAR localTransportParameters[128] = {};
    SIZE_T localTransportParametersLength = 0;
    const UCHAR sourceConnectionId[] = {1, 2, 3, 4};
    NTSTATUS status = wknet::quic::QuicEncodeClientTransportParameters(
        {sourceConnectionId, sizeof(sourceConnectionId)}, localTransportParameters, sizeof(localTransportParameters),
        &localTransportParametersLength);
    wknet::tls::Tls13KeyShareEntry keyShare = {};
    keyShare.Group = wknet::tls::TlsNamedGroup::X25519;
    keyShare.KeyExchange = clientKeyShare;
    keyShare.KeyExchangeLength = clientKeyShareLength;
    wknet::quic::QuicTlsClientOptions options = {};
    options.ServerName = "example.com";
    options.ServerNameLength = 11;
    options.LocalTransportParameters = {localTransportParameters, localTransportParametersLength};
    options.KeyShares = &keyShare;
    options.KeyShareCount = 1;
    options.ClientCredential = clientCredential;
    options.VerifyCertificate = false;
    if (NT_SUCCESS(status))
    {
        status = tls.Initialize(options);
    }
    if (NT_SUCCESS(status))
    {
        status = tls.Start(clientHello, clientHelloCapacity, clientHelloLength);
    }
    return status;
}

NTSTATUS AdvanceToHandshake(wknet::quic::QuicTls &tls, const UCHAR *clientKeyShare, SIZE_T clientKeyShareLength,
                            UCHAR *clientHello, SIZE_T clientHelloCapacity, SIZE_T *clientHelloLength,
                            const wknet::crypto::TlsClientCredential *clientCredential = nullptr)
{
    NTSTATUS status = InitializeTls(tls, clientKeyShare, clientKeyShareLength, clientHello, clientHelloCapacity,
                                    clientHelloLength, clientCredential);
    UCHAR serverHello[128] = {};
    UCHAR serverKeyShare[32] = {};
    for (SIZE_T index = 0; index < sizeof(serverKeyShare); ++index)
    {
        serverKeyShare[index] = static_cast<UCHAR>(0x80 + index);
    }
    const SIZE_T serverHelloLength =
        BuildServerHello(serverKeyShare, sizeof(serverKeyShare), serverHello, sizeof(serverHello));
    E(serverHelloLength > 16, "ServerHello fixture builds");
    if (NT_SUCCESS(status))
    {
        status =
            tls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Initial, 12, serverHello + 12, serverHelloLength - 12);
    }
    if (NT_SUCCESS(status))
    {
        status = tls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Initial, 0, serverHello, 12);
    }
    UCHAR sharedSecret[32] = {};
    for (SIZE_T index = 0; index < sizeof(sharedSecret); ++index)
    {
        sharedSecret[index] = static_cast<UCHAR>(index + 1);
    }
    if (NT_SUCCESS(status))
    {
        status = tls.InstallSharedSecret(sharedSecret, sizeof(sharedSecret));
    }
    return status;
}
} // namespace

int main()
{
    UCHAR clientKeyShare[32] = {};
    for (SIZE_T index = 0; index < sizeof(clientKeyShare); ++index)
    {
        clientKeyShare[index] = static_cast<UCHAR>(index + 1);
    }

    wknet::quic::QuicTls tls;
    UCHAR clientHello[2048] = {};
    SIZE_T clientHelloLength = 0;
    E(NT_SUCCESS(AdvanceToHandshake(tls, clientKeyShare, sizeof(clientKeyShare), clientHello, sizeof(clientHello),
                                    &clientHelloLength)),
      "out-of-order ServerHello CRYPTO data advances to handshake keys");
    E(tls.State() == wknet::quic::QuicTlsState::AwaitEncryptedExtensions,
      "shared secret installs handshake traffic keys");
    E(tls.HandshakeReadKey().SecretLength != 0 && tls.HandshakeWriteKey().SecretLength != 0,
      "both handshake packet key directions install");

    const UCHAR *clientHelloExtensions = nullptr;
    SIZE_T clientHelloExtensionsLength = 0;
    E(FindClientHelloExtensions(clientHello, clientHelloLength, &clientHelloExtensions, &clientHelloExtensionsLength),
      "ClientHello extension block locates");
    wknet::tls::Tls13ExtensionView extension = {};
    bool found = false;
    E(NT_SUCCESS(wknet::tls::Tls13HandshakeMessages::FindExtensionView(
          clientHelloExtensions, clientHelloExtensionsLength, 57, extension, &found)) &&
          found && extension.Length != 0,
      "ClientHello carries QUIC transport parameters");
    E(NT_SUCCESS(wknet::tls::Tls13HandshakeMessages::FindExtensionView(
          clientHelloExtensions, clientHelloExtensionsLength, 16, extension, &found)) &&
          found && extension.Length == 5 && extension.Data[3] == 'h' && extension.Data[4] == '3',
      "ClientHello offers h3 ALPN");
    E(NT_SUCCESS(tls.DiscardInitialKeys()) && tls.InitialKeysDiscarded(),
      "Initial keys discard only after handshake keys install");

    wknet::quic::QuicTls retryTls;
    UCHAR retryTransportParameters[128] = {};
    SIZE_T retryTransportParametersLength = 0;
    const UCHAR retrySourceConnectionId[] = {5, 6, 7, 8};
    E(NT_SUCCESS(wknet::quic::QuicEncodeClientTransportParameters(
          {retrySourceConnectionId, sizeof(retrySourceConnectionId)}, retryTransportParameters,
          sizeof(retryTransportParameters), &retryTransportParametersLength)),
      "HRR client transport parameters encode");
    wknet::quic::QuicTlsClientOptions retryOptions = {};
    retryOptions.ServerName = "example.com";
    retryOptions.ServerNameLength = 11;
    retryOptions.LocalTransportParameters = {retryTransportParameters, retryTransportParametersLength};
    retryOptions.VerifyCertificate = false;
    UCHAR firstRetryClientHello[2048] = {};
    SIZE_T firstRetryClientHelloLength = 0;
    E(NT_SUCCESS(retryTls.Initialize(retryOptions)) &&
          NT_SUCCESS(
              retryTls.Start(firstRetryClientHello, sizeof(firstRetryClientHello), &firstRetryClientHelloLength)),
      "HRR test starts with an internally owned X25519 key share");
    UCHAR helloRetryRequest[128] = {};
    const SIZE_T helloRetryRequestLength = BuildHelloRetryRequest(helloRetryRequest, sizeof(helloRetryRequest));
    E(helloRetryRequestLength != 0 && NT_SUCCESS(retryTls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Initial, 0,
                                                                        helloRetryRequest, helloRetryRequestLength)),
      "HelloRetryRequest requests a supported replacement group");
    UCHAR secondRetryClientHello[2048] = {};
    SIZE_T secondRetryClientHelloLength = 0;
    E(NT_SUCCESS(retryTls.TakeInitialOutput(secondRetryClientHello, sizeof(secondRetryClientHello),
                                            &secondRetryClientHelloLength)) &&
          secondRetryClientHelloLength != 0 &&
          (secondRetryClientHelloLength != firstRetryClientHelloLength ||
           memcmp(secondRetryClientHello, firstRetryClientHello, secondRetryClientHelloLength) != 0),
      "HelloRetryRequest produces a distinct second ClientHello on Initial CRYPTO");
    const UCHAR *retryExtensions = nullptr;
    SIZE_T retryExtensionsLength = 0;
    E(FindClientHelloExtensions(secondRetryClientHello, secondRetryClientHelloLength, &retryExtensions,
                                &retryExtensionsLength),
      "second ClientHello extension block locates");
    E(NT_SUCCESS(wknet::tls::Tls13HandshakeMessages::FindExtensionView(retryExtensions, retryExtensionsLength, 51,
                                                                       extension, &found)) &&
          found && extension.Length > 4 && extension.Data[2] == 0 && extension.Data[3] == 23,
      "second ClientHello replaces X25519 with the requested P-256 key share");
    E(NT_SUCCESS(wknet::tls::Tls13HandshakeMessages::FindExtensionView(retryExtensions, retryExtensionsLength, 44,
                                                                       extension, &found)) &&
          found && extension.Length == 4 && extension.Data[2] == 0xaa && extension.Data[3] == 0xbb,
      "second ClientHello echoes the HRR cookie exactly");
    E(!NT_SUCCESS(retryTls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Initial, helloRetryRequestLength,
                                         helloRetryRequest, helloRetryRequestLength)),
      "a repeated HelloRetryRequest is rejected");

    const UCHAR serverTransportParameters[] = {0x40, 0x20, 0x02, 1, 2};
    UCHAR encryptedExtensions[64] = {};
    const SIZE_T encryptedExtensionsLength = BuildEncryptedExtensions(
        serverTransportParameters, sizeof(serverTransportParameters), encryptedExtensions, sizeof(encryptedExtensions));
    E(NT_SUCCESS(tls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Handshake, 0, encryptedExtensions,
                                   encryptedExtensionsLength)),
      "h3 EncryptedExtensions and server transport parameters process");
    E(tls.State() == wknet::quic::QuicTlsState::AwaitCertificate,
      "validated EncryptedExtensions advances to certificate");

    const UCHAR clientCertificateList[] = {0, 0, 0};
    const wknet::crypto::TlsSignatureScheme clientSignatureSchemes[] = {
        wknet::crypto::TlsSignatureScheme::RsaPssRsaeSha256};
    wknet::crypto::TlsClientCredential clientCredential = {};
    clientCredential.CertificateList = clientCertificateList;
    clientCredential.CertificateListLength = sizeof(clientCertificateList);
    clientCredential.KeyAlgorithm = wknet::crypto::TlsClientCredentialKeyAlgorithm::Rsa;
    clientCredential.SupportedSignatureSchemes = clientSignatureSchemes;
    clientCredential.SupportedSignatureSchemeCount = 1;
    clientCredential.Sign = TestClientCredentialSign;
    wknet::quic::QuicTls credentialTls;
    UCHAR credentialClientHello[2048] = {};
    SIZE_T credentialClientHelloLength = 0;
    E(NT_SUCCESS(AdvanceToHandshake(credentialTls, clientKeyShare, sizeof(clientKeyShare), credentialClientHello,
                                    sizeof(credentialClientHello), &credentialClientHelloLength, &clientCredential)) &&
          NT_SUCCESS(credentialTls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Handshake, 0, encryptedExtensions,
                                                 encryptedExtensionsLength)),
      "client credential handshake reaches CertificateRequest");
    UCHAR certificateRequest[32] = {};
    const SIZE_T certificateRequestLength = BuildCertificateRequest(certificateRequest, sizeof(certificateRequest));
    E(certificateRequestLength != 0 &&
          NT_SUCCESS(credentialTls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Handshake, encryptedExtensionsLength,
                                                 certificateRequest, certificateRequestLength)) &&
          credentialTls.ClientCertificateVerifySelectedForTest() &&
          credentialTls.ClientCertificateSignatureSchemeForTest() == wknet::tls::TlsSignatureScheme::RsaPssRsaeSha256,
      "CertificateRequest selects the configured client credential signature scheme");

    const UCHAR keyUpdate[] = {24, 0, 0, 1, 0};
    E(tls.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Handshake, encryptedExtensionsLength, keyUpdate,
                        sizeof(keyUpdate)) == STATUS_INVALID_NETWORK_RESPONSE &&
          tls.State() == wknet::quic::QuicTlsState::Failed,
      "TLS KeyUpdate is a QUIC protocol failure");

    wknet::quic::QuicTls overlap;
    E(NT_SUCCESS(InitializeTls(overlap, clientKeyShare, sizeof(clientKeyShare), clientHello, sizeof(clientHello),
                               &clientHelloLength)),
      "overlap test initializes");
    UCHAR serverHello[128] = {};
    UCHAR serverKeyShare[32] = {};
    const SIZE_T serverHelloLength =
        BuildServerHello(serverKeyShare, sizeof(serverKeyShare), serverHello, sizeof(serverHello));
    E(serverHelloLength > 16, "overlap ServerHello fixture builds");
    E(NT_SUCCESS(overlap.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Initial, 0, serverHello, 16)),
      "first CRYPTO fragment receives");
    UCHAR conflicting[1] = {static_cast<UCHAR>(serverHello[8] ^ 0xff)};
    E(overlap.ReceiveCrypto(wknet::quic::QuicEncryptionLevel::Initial, 8, conflicting, sizeof(conflicting)) ==
          STATUS_INVALID_NETWORK_RESPONSE,
      "inconsistent CRYPTO overlap fails the handshake");

    wknet::quic::QuicTls alerted;
    E(NT_SUCCESS(InitializeTls(alerted, clientKeyShare, sizeof(clientKeyShare), clientHello, sizeof(clientHello),
                               &clientHelloLength)),
      "alert test initializes");
    E(alerted.OnTlsAlert(42) == STATUS_CONNECTION_ABORTED && alerted.TransportError() == 0x12a,
      "TLS alert maps to CRYPTO_ERROR");

    if (failed)
    {
        printf("QUIC HANDSHAKE TESTS FAILED\n");
        return 1;
    }
    printf("QUIC HANDSHAKE TESTS PASSED\n");
    return 0;
}
