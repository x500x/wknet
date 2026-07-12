#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::crypto {
    enum class TlsSignatureScheme : USHORT
    {
        RsaPkcs1Sha1 = 0x0201,
        EcdsaSha1 = 0x0203,
        RsaPkcs1Sha256 = 0x0401,
        EcdsaSecp256r1Sha256 = 0x0403,
        RsaPkcs1Sha384 = 0x0501,
        EcdsaSecp384r1Sha384 = 0x0503,
        RsaPkcs1Sha512 = 0x0601,
        EcdsaSecp521r1Sha512 = 0x0603,
        Ed25519 = 0x0807,
        Ed448 = 0x0808,
        RsaPssRsaeSha256 = 0x0804,
        RsaPssRsaeSha384 = 0x0805,
        RsaPssRsaeSha512 = 0x0806,
        RsaPssPssSha256 = 0x0809,
        RsaPssPssSha384 = 0x080a,
        RsaPssPssSha512 = 0x080b
    };

    enum class TlsClientCredentialKeyAlgorithm : UCHAR
    {
        Unknown,
        Rsa,
        RsaPss,
        EcdsaP256,
        EcdsaP384,
        EcdsaP521,
        Ed25519,
        Ed448
    };

    using TlsClientCredentialSignCallback = NTSTATUS(*)(
        _In_opt_ void* context,
        TlsSignatureScheme scheme,
        _In_reads_bytes_(inputLength) const UCHAR* input,
        SIZE_T inputLength,
        _Out_writes_bytes_(signatureCapacity) UCHAR* signature,
        SIZE_T signatureCapacity,
        _Out_ SIZE_T* signatureLength);

    struct TlsClientCredential final
    {
        const UCHAR* CertificateList = nullptr;
        SIZE_T CertificateListLength = 0;
        TlsClientCredentialKeyAlgorithm KeyAlgorithm = TlsClientCredentialKeyAlgorithm::Unknown;
        const TlsSignatureScheme* SupportedSignatureSchemes = nullptr;
        SIZE_T SupportedSignatureSchemeCount = 0;
        TlsClientCredentialSignCallback Sign = nullptr;
        void* SignContext = nullptr;
        bool AllowsDigitalSignature = true;
    };
}
