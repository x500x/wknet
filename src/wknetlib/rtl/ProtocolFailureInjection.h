#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::rtl
{
    enum class ProtocolAllocationSite : ULONG
    {
        Invalid = 0,

        DatagramSocketObject = 1,
        DatagramReceiveIrp = 2,
        DatagramReceiveMdl = 3,
        DatagramReceiveDescriptor = 4,
        DatagramSendOperation = 5,
        DatagramCompletionRecord = 6,

        QuicPacketScratch = 7,
        QuicFrameScratch = 8,
        QuicTransportParameterBytes = 9,
        QuicRecoveryPackets = 10,
        QuicAckRanges = 11,
        QuicConnectionObject = 12,
        QuicCommandObject = 13,
        QuicCommandData = 14,
        QuicCommandAuxiliaryData = 15,
        QuicCommandQueue = 16,
        QuicStreamTable = 17,
        QuicLocalConnectionIdTable = 18,
        QuicPeerConnectionIdTable = 19,
        QuicReceiveBuffer = 20,
        QuicPacketBuffer = 21,
        QuicDecryptBuffer = 22,
        QuicFrameBuffer = 23,
        QuicClientHelloBuffer = 24,
        QuicAckRangeScratch = 25,
        QuicStreamObject = 26,
        QuicStreamChunks = 27,
        QuicStreamAffectedScratch = 28,
        QuicStreamMergeBuffer = 29,
        QuicTokenCacheEntries = 30,
        QuicTokenBytes = 31,

        QpackDynamicTableData = 32,
        QpackDynamicTableEntries = 33,
        QpackDynamicEntryCopy = 34,
        QpackEncoderFieldLines = 35,
        QpackEncoderReferences = 36,
        QpackEncoderOutstandingSection = 37,
        QpackDecoderValue = 38,
        QpackDecoderBlockedSection = 39,

        Http3ConnectionObject = 40,
        Http3TrackedStreams = 41,
        Http3ReadScratch = 42,
        Http3WriteScratch = 43,
        Http3Settings = 44,
        Http3RequestFields = 45,
        Http3StreamPayload = 46,
        Http3StreamFieldBytes = 47,

        SessionPoolEntries = 48,
        SessionHttp3ResponseAccumulator = 49,
        SessionHttp3CompletionFence = 50,
        SessionHttp3PeerRouter = 51,
        SessionHttp3CertificateScratch = 52,
        SessionHttp3PeerLease = 53,
        QuicServerName = 54,

        AltSvcCacheObject = 55,
        AltSvcCacheEntries = 56,
        AltSvcParsedSet = 57,
        AltSvcParseScratch = 58,

        Count = 59
    };

    ULONG ProtocolFailureInjectionMaximumSite() noexcept;
    bool ProtocolFailureInjectionIsValidSite(ProtocolAllocationSite site) noexcept;
    const char* ProtocolFailureInjectionSiteName(ProtocolAllocationSite site) noexcept;

#if defined(WKNET_USER_MODE_TEST)
    void ProtocolFailureInjectionReset() noexcept;
    void ProtocolFailureInjectionSetFailOnNth(ProtocolAllocationSite site, ULONG occurrence) noexcept;
    void ProtocolFailureInjectionSetFailAlways(ProtocolAllocationSite site, bool enabled) noexcept;
    bool ProtocolFailureInjectionShouldFail(ProtocolAllocationSite site) noexcept;
    ULONG ProtocolFailureInjectionHitCount(ProtocolAllocationSite site) noexcept;
    void ProtocolFailureInjectionRecordAcquire(ProtocolAllocationSite site) noexcept;
    bool ProtocolFailureInjectionRecordRelease(ProtocolAllocationSite site) noexcept;
    LONG ProtocolFailureInjectionLiveCount(ProtocolAllocationSite site) noexcept;
    LONG ProtocolFailureInjectionTotalLiveCount() noexcept;
#else
    inline void ProtocolFailureInjectionReset() noexcept
    {
    }

    inline void ProtocolFailureInjectionSetFailOnNth(ProtocolAllocationSite, ULONG) noexcept
    {
    }

    inline void ProtocolFailureInjectionSetFailAlways(ProtocolAllocationSite, bool) noexcept
    {
    }

    inline bool ProtocolFailureInjectionShouldFail(ProtocolAllocationSite) noexcept
    {
        return false;
    }

    inline ULONG ProtocolFailureInjectionHitCount(ProtocolAllocationSite) noexcept
    {
        return 0;
    }

    inline void ProtocolFailureInjectionRecordAcquire(ProtocolAllocationSite) noexcept
    {
    }

    inline bool ProtocolFailureInjectionRecordRelease(ProtocolAllocationSite) noexcept
    {
        return true;
    }

    inline LONG ProtocolFailureInjectionLiveCount(ProtocolAllocationSite) noexcept
    {
        return 0;
    }

    inline LONG ProtocolFailureInjectionTotalLiveCount() noexcept
    {
        return 0;
    }
#endif
} // namespace wknet::rtl
