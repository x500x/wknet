#pragma once

#include <wknet/WknetConfig.h>

namespace wknet
{
namespace tls
{
    // Public subset of TLS type codes needed by certificate / mTLS configuration.
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
}
}
