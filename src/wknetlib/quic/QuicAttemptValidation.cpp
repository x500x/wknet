#include "quic/QuicAttemptValidation.h"

namespace wknet::quic {
    namespace
    {
        bool ViewsEqual(QuicBufferView left, const UCHAR* right, SIZE_T rightLength) noexcept
        {
            return left.Length == rightLength &&
                (rightLength == 0 || RtlCompareMemory(left.Data, right, rightLength) == rightLength);
        }

        ULONG ReadVersion(const UCHAR* data) noexcept
        {
            return (static_cast<ULONG>(data[0]) << 24) |
                (static_cast<ULONG>(data[1]) << 16) |
                (static_cast<ULONG>(data[2]) << 8) | data[3];
        }
    }

    QuicAttemptValidation::~QuicAttemptValidation() noexcept { Reset(); }

    void QuicAttemptValidation::Reset() noexcept
    {
        RtlSecureZeroMemory(originalDestinationConnectionId_, sizeof(originalDestinationConnectionId_));
        RtlSecureZeroMemory(clientSourceConnectionId_, sizeof(clientSourceConnectionId_));
        RtlSecureZeroMemory(retrySourceConnectionId_, sizeof(retrySourceConnectionId_));
        if (retryToken_.IsValid()) RtlSecureZeroMemory(retryToken_.Get(), retryToken_.Count());
        retryToken_.Reset();
        originalVersion_ = 0;
        originalDestinationConnectionIdLength_ = 0;
        clientSourceConnectionIdLength_ = 0;
        retrySourceConnectionIdLength_ = 0;
        initialized_ = false;
        retryAccepted_ = false;
        versionNegotiationAccepted_ = false;
    }

    NTSTATUS QuicAttemptValidation::Initialize(
        ULONG originalVersion, QuicBufferView odcid, QuicBufferView clientScid) noexcept
    {
        Reset();
        if (originalVersion == 0 || odcid.Data == nullptr || odcid.Length == 0 ||
            odcid.Length > QuicMaximumConnectionIdLength ||
            (clientScid.Data == nullptr && clientScid.Length != 0) ||
            clientScid.Length > QuicMaximumConnectionIdLength) return STATUS_INVALID_PARAMETER;
        originalVersion_ = originalVersion;
        originalDestinationConnectionIdLength_ = odcid.Length;
        clientSourceConnectionIdLength_ = clientScid.Length;
        RtlCopyMemory(originalDestinationConnectionId_, odcid.Data, odcid.Length);
        RtlCopyMemory(clientSourceConnectionId_, clientScid.Data, clientScid.Length);
        initialized_ = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS QuicAttemptValidation::ValidateVersionNegotiation(
        const QuicPacketHeader& packet, const ULONG* supportedVersions,
        SIZE_T supportedVersionCount, ULONG* selectedVersion) noexcept
    {
        if (selectedVersion != nullptr) *selectedVersion = 0;
        NTSTATUS status = STATUS_SUCCESS;
        if (!initialized_ || packet.Type != QuicPacketType::VersionNegotiation || retryAccepted_ ||
            versionNegotiationAccepted_ || supportedVersions == nullptr || supportedVersionCount == 0 ||
            !ViewsEqual(packet.DestinationConnectionId, clientSourceConnectionId_, clientSourceConnectionIdLength_) ||
            !ViewsEqual(packet.SourceConnectionId, originalDestinationConnectionId_, originalDestinationConnectionIdLength_)) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG selected = 0;
        if (NT_SUCCESS(status)) {
            for (SIZE_T offset = 0; offset < packet.VersionList.Length; offset += 4) {
                const ULONG offered = ReadVersion(packet.VersionList.Data + offset);
                if (offered == originalVersion_) { status = STATUS_INVALID_NETWORK_RESPONSE; break; }
                for (SIZE_T index = 0; index < supportedVersionCount; ++index) {
                    if (supportedVersions[index] == offered && offered != originalVersion_) selected = offered;
                }
            }
        }
        const TraceCorrelation correlation = {};
        if (NT_SUCCESS(status)) {
            versionNegotiationAccepted_ = true;
            WKNET_TRACE_CORRELATED(ComponentQuic, TraceLevel::Info, &correlation,
                "quic.version_negotiation.accepted selected_version=%u dcid_bytes=%Iu scid_bytes=%Iu",
                selected, packet.DestinationConnectionId.Length, packet.SourceConnectionId.Length);
            if (selectedVersion != nullptr) *selectedVersion = selected;
            return selected != 0 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
        }
        WKNET_TRACE_CORRELATED(ComponentQuic, TraceLevel::Warning, &correlation,
            "quic.version_negotiation.rejected status=0x%08X dcid_bytes=%Iu scid_bytes=%Iu",
            static_cast<ULONG>(status), packet.DestinationConnectionId.Length, packet.SourceConnectionId.Length);
        return status;
    }

    NTSTATUS QuicAttemptValidation::ValidateRetry(
        const QuicPacketHeader& packet, const UCHAR* packetBytes, SIZE_T packetLength) noexcept
    {
        NTSTATUS status = STATUS_SUCCESS;
        if (!initialized_ || packet.Type != QuicPacketType::Retry || retryAccepted_ ||
            versionNegotiationAccepted_ || packet.Version != originalVersion_ ||
            !ViewsEqual(packet.DestinationConnectionId, clientSourceConnectionId_, clientSourceConnectionIdLength_) ||
            packet.SourceConnectionId.Length == 0 || packet.Token.Length == 0 ||
            packet.Token.Length > QuicMaximumRetryTokenLength || packetBytes == nullptr) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (NT_SUCCESS(status)) status = QuicValidateRetryIntegrityTag(
            { originalDestinationConnectionId_, originalDestinationConnectionIdLength_ }, packetBytes, packetLength);
        if (NT_SUCCESS(status)) {
            status = retryToken_.Allocate(packet.Token.Length);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(retryToken_.Get(), packet.Token.Data, packet.Token.Length);
                retrySourceConnectionIdLength_ = packet.SourceConnectionId.Length;
                RtlCopyMemory(retrySourceConnectionId_, packet.SourceConnectionId.Data, packet.SourceConnectionId.Length);
                retryAccepted_ = true;
            }
        }
        const TraceCorrelation correlation = {};
        if (NT_SUCCESS(status)) {
            WKNET_TRACE_CORRELATED(ComponentQuic, TraceLevel::Info, &correlation,
                "quic.retry.accepted version=%u dcid_bytes=%Iu scid_bytes=%Iu",
                packet.Version, packet.DestinationConnectionId.Length,
                packet.SourceConnectionId.Length);
        }
        else {
            WKNET_TRACE_CORRELATED(ComponentQuic, TraceLevel::Warning, &correlation,
                "quic.retry.rejected status=0x%08X version=%u dcid_bytes=%Iu scid_bytes=%Iu",
                static_cast<ULONG>(status), packet.Version,
                packet.DestinationConnectionId.Length, packet.SourceConnectionId.Length);
        }
        return status;
    }

    QuicBufferView QuicAttemptValidation::RetryToken() const noexcept
    {
        return { retryToken_.Get(), retryToken_.Count() };
    }

    QuicBufferView QuicAttemptValidation::RetrySourceConnectionId() const noexcept
    {
        return { retrySourceConnectionId_, retrySourceConnectionIdLength_ };
    }
}
