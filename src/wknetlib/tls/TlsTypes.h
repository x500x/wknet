#pragma once

#include <wknet/crypto/TlsCredential.h>

namespace wknet
{
namespace tls
{
    using TlsSignatureScheme = crypto::TlsSignatureScheme;
    using TlsClientCredentialKeyAlgorithm = crypto::TlsClientCredentialKeyAlgorithm;
    using TlsClientCredentialSignCallback = crypto::TlsClientCredentialSignCallback;
    using TlsClientCredential = crypto::TlsClientCredential;
}
}
