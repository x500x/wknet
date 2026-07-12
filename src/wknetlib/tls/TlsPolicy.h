#pragma once

#include "tls/TlsCapabilities.h"

namespace wknet
{
namespace tls
{
    enum class TlsSecurityProfile : UCHAR
    {
        ModernDefault,
        CompatibilityExplicit
    };

    struct TlsPolicy final
    {
        TlsSecurityProfile Profile = TlsSecurityProfile::ModernDefault;
        bool EnableTls12RsaKeyExchange = false;
        bool EnableTls12Cbc = false;
        bool EnableTls12Renegotiation = false;
        bool EnableTls12Sha1Signatures = false;
        bool EnablePostHandshakeClientAuth = false;
        bool RequireRevocationCheck = false;
    };

    _Must_inspect_result_
    NTSTATUS TlsValidatePolicy(_In_ const TlsPolicy& policy) noexcept;

    _Must_inspect_result_
    bool TlsPolicyAllowsCipherSuite(_In_ const TlsPolicy& policy, TlsCipherSuite cipherSuite) noexcept;

    _Must_inspect_result_
    bool TlsPolicyAllowsNamedGroup(_In_ const TlsPolicy& policy, TlsNamedGroup group) noexcept;

    _Must_inspect_result_
    bool TlsPolicyAllowsSignatureScheme(_In_ const TlsPolicy& policy, TlsSignatureScheme scheme) noexcept;

    _Must_inspect_result_
    bool TlsPolicyAllowsTls12KeyExchange(_In_ const TlsPolicy& policy, Tls12KeyExchangeKind keyExchange) noexcept;

    _Must_inspect_result_
    bool TlsPolicyAllowsTls12Renegotiation(_In_ const TlsPolicy& policy) noexcept;
}
}
