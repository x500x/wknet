#pragma once

#include "quic/QuicCrypto.h"
#include "quic/QuicPacket.h"

namespace wknet::quic {
    constexpr SIZE_T QuicMaximumRetryTokenLength = 1024;

    class QuicAttemptValidation final
    {
    public:
        QuicAttemptValidation() noexcept = default;
        QuicAttemptValidation(const QuicAttemptValidation&) = delete;
        QuicAttemptValidation& operator=(const QuicAttemptValidation&) = delete;
        ~QuicAttemptValidation() noexcept;

        NTSTATUS Initialize(
            ULONG originalVersion,
            QuicBufferView originalDestinationConnectionId,
            QuicBufferView clientSourceConnectionId) noexcept;

        NTSTATUS ValidateVersionNegotiation(
            _In_ const QuicPacketHeader& packet,
            _In_reads_(supportedVersionCount) const ULONG* supportedVersions,
            SIZE_T supportedVersionCount,
            _Out_opt_ ULONG* selectedVersion) noexcept;

        NTSTATUS ValidateRetry(
            _In_ const QuicPacketHeader& packet,
            _In_reads_bytes_(packetLength) const UCHAR* packetBytes,
            SIZE_T packetLength) noexcept;

        QuicBufferView RetryToken() const noexcept;
        QuicBufferView RetrySourceConnectionId() const noexcept;
        bool RetryAccepted() const noexcept { return retryAccepted_; }
        bool VersionNegotiationAccepted() const noexcept { return versionNegotiationAccepted_; }
        void Reset() noexcept;

    private:
        ULONG originalVersion_ = 0;
        UCHAR originalDestinationConnectionId_[QuicMaximumConnectionIdLength] = {};
        SIZE_T originalDestinationConnectionIdLength_ = 0;
        UCHAR clientSourceConnectionId_[QuicMaximumConnectionIdLength] = {};
        SIZE_T clientSourceConnectionIdLength_ = 0;
        UCHAR retrySourceConnectionId_[QuicMaximumConnectionIdLength] = {};
        SIZE_T retrySourceConnectionIdLength_ = 0;
        HeapArray<UCHAR> retryToken_;
        bool initialized_ = false;
        bool retryAccepted_ = false;
        bool versionNegotiationAccepted_ = false;
    };
}
