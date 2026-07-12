#include <wknet/tls/TlsPolicy.h>

namespace wknet
{
namespace tls
{
    namespace
    {
        _Must_inspect_result_
        bool IsCompatibilityProfile(_In_ const TlsPolicy& policy) noexcept
        {
            return policy.Profile == TlsSecurityProfile::CompatibilityExplicit;
        }

        _Must_inspect_result_
        bool IsLegacyCipherSuite(_In_ const TlsCipherSuiteCapability& capability) noexcept
        {
            return capability.DefaultDisposition == TlsCapabilityDisposition::Legacy ||
                capability.Tls12KeyExchange == Tls12KeyExchangeKind::Rsa ||
                capability.BulkCipher == TlsBulkCipherKind::AesCbc;
        }

        _Must_inspect_result_
        bool IsDefaultOrOptional(TlsCapabilityDisposition disposition) noexcept
        {
            return disposition == TlsCapabilityDisposition::Default ||
                disposition == TlsCapabilityDisposition::Optional;
        }
    }

    NTSTATUS TlsValidatePolicy(const TlsPolicy& policy) noexcept
    {
        switch (policy.Profile) {
        case TlsSecurityProfile::ModernDefault:
            if (policy.EnableTls12RsaKeyExchange ||
                policy.EnableTls12Cbc ||
                policy.EnableTls12Renegotiation ||
                policy.EnableTls12Sha1Signatures) {
                return STATUS_INVALID_PARAMETER;
            }
            return STATUS_SUCCESS;
        case TlsSecurityProfile::CompatibilityExplicit:
            return STATUS_SUCCESS;
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    bool TlsPolicyAllowsCipherSuite(const TlsPolicy& policy, TlsCipherSuite cipherSuite) noexcept
    {
        if (!NT_SUCCESS(TlsValidatePolicy(policy))) {
            return false;
        }

        const TlsCipherSuiteCapability* capability = TlsFindCipherSuiteCapability(cipherSuite);
        if (capability == nullptr) {
            return false;
        }

        if (!IsLegacyCipherSuite(*capability)) {
            return IsDefaultOrOptional(capability->DefaultDisposition);
        }

        if (!IsCompatibilityProfile(policy)) {
            return false;
        }

        if (capability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
            !policy.EnableTls12RsaKeyExchange) {
            return false;
        }

        if (capability->BulkCipher == TlsBulkCipherKind::AesCbc &&
            !policy.EnableTls12Cbc) {
            return false;
        }

        return capability->CompatibilityDisposition != TlsCapabilityDisposition::Unsupported;
    }

    bool TlsPolicyAllowsNamedGroup(const TlsPolicy& policy, TlsNamedGroup group) noexcept
    {
        if (!NT_SUCCESS(TlsValidatePolicy(policy))) {
            return false;
        }

        const TlsNamedGroupCapability* capability = TlsFindNamedGroupCapability(group);
        return capability != nullptr && IsDefaultOrOptional(capability->DefaultDisposition);
    }

    bool TlsPolicyAllowsSignatureScheme(const TlsPolicy& policy, TlsSignatureScheme scheme) noexcept
    {
        if (!NT_SUCCESS(TlsValidatePolicy(policy))) {
            return false;
        }

        const TlsSignatureSchemeCapability* capability = TlsFindSignatureSchemeCapability(scheme);
        if (capability == nullptr) {
            return false;
        }

        if (capability->DefaultDisposition == TlsCapabilityDisposition::Legacy) {
            if (scheme == TlsSignatureScheme::RsaPkcs1Sha1 ||
                scheme == TlsSignatureScheme::EcdsaSha1) {
                return IsCompatibilityProfile(policy) &&
                    policy.EnableTls12Sha1Signatures &&
                    capability->CompatibilityDisposition != TlsCapabilityDisposition::Unsupported;
            }
            return IsCompatibilityProfile(policy) &&
                capability->CompatibilityDisposition != TlsCapabilityDisposition::Unsupported;
        }

        return IsDefaultOrOptional(capability->DefaultDisposition);
    }

    bool TlsPolicyAllowsTls12KeyExchange(const TlsPolicy& policy, Tls12KeyExchangeKind keyExchange) noexcept
    {
        if (!NT_SUCCESS(TlsValidatePolicy(policy))) {
            return false;
        }

        if (keyExchange == Tls12KeyExchangeKind::Rsa) {
            return IsCompatibilityProfile(policy) && policy.EnableTls12RsaKeyExchange;
        }

        return TlsIsDefaultEnabledTls12KeyExchange(keyExchange);
    }

    bool TlsPolicyAllowsTls12Renegotiation(const TlsPolicy& policy) noexcept
    {
        return NT_SUCCESS(TlsValidatePolicy(policy)) &&
            IsCompatibilityProfile(policy) &&
            policy.EnableTls12Renegotiation;
    }
}
}
