#include "rtl/ProtocolFailureInjection.h"

#if defined(WKNET_USER_MODE_TEST)
#include <atomic>
#endif

namespace wknet::rtl
{
    namespace
    {
        constexpr ULONG ProtocolAllocationSiteCount = static_cast<ULONG>(ProtocolAllocationSite::Count);

        ULONG SiteIndex(ProtocolAllocationSite site) noexcept
        {
            return static_cast<ULONG>(site);
        }

#if defined(WKNET_USER_MODE_TEST)
        std::atomic<ULONG> g_failOnNth[ProtocolAllocationSiteCount] = {};
        std::atomic<ULONG> g_hitCount[ProtocolAllocationSiteCount] = {};
        std::atomic<LONG> g_liveCount[ProtocolAllocationSiteCount] = {};
#endif
    } // namespace

    ULONG ProtocolFailureInjectionMaximumSite() noexcept
    {
        return ProtocolAllocationSiteCount - 1;
    }

    bool ProtocolFailureInjectionIsValidSite(ProtocolAllocationSite site) noexcept
    {
        const ULONG index = SiteIndex(site);
        return index != 0 && index < ProtocolAllocationSiteCount;
    }

    const char* ProtocolFailureInjectionSiteName(ProtocolAllocationSite site) noexcept
    {
        switch (site)
        {
        case ProtocolAllocationSite::DatagramSocketObject:
            return "datagram.socket_object";
        case ProtocolAllocationSite::DatagramReceiveIrp:
            return "datagram.receive_irp";
        case ProtocolAllocationSite::DatagramReceiveMdl:
            return "datagram.receive_mdl";
        case ProtocolAllocationSite::DatagramReceiveDescriptor:
            return "datagram.receive_descriptor";
        case ProtocolAllocationSite::DatagramSendOperation:
            return "datagram.send_operation";
        case ProtocolAllocationSite::DatagramCompletionRecord:
            return "datagram.completion_record";
        case ProtocolAllocationSite::QuicPacketScratch:
            return "quic.packet_scratch";
        case ProtocolAllocationSite::QuicFrameScratch:
            return "quic.frame_scratch";
        case ProtocolAllocationSite::QuicTransportParameterBytes:
            return "quic.transport_parameter_bytes";
        case ProtocolAllocationSite::QuicRecoveryPackets:
            return "quic.recovery_packets";
        case ProtocolAllocationSite::QuicAckRanges:
            return "quic.ack_ranges";
        case ProtocolAllocationSite::QuicConnectionObject:
            return "quic.connection_object";
        case ProtocolAllocationSite::QuicCommandObject:
            return "quic.command_object";
        case ProtocolAllocationSite::QuicCommandData:
            return "quic.command_data";
        case ProtocolAllocationSite::QuicCommandAuxiliaryData:
            return "quic.command_auxiliary_data";
        case ProtocolAllocationSite::QuicCommandQueue:
            return "quic.command_queue";
        case ProtocolAllocationSite::QuicStreamTable:
            return "quic.stream_table";
        case ProtocolAllocationSite::QuicLocalConnectionIdTable:
            return "quic.local_connection_id_table";
        case ProtocolAllocationSite::QuicPeerConnectionIdTable:
            return "quic.peer_connection_id_table";
        case ProtocolAllocationSite::QuicReceiveBuffer:
            return "quic.receive_buffer";
        case ProtocolAllocationSite::QuicPacketBuffer:
            return "quic.packet_buffer";
        case ProtocolAllocationSite::QuicDecryptBuffer:
            return "quic.decrypt_buffer";
        case ProtocolAllocationSite::QuicFrameBuffer:
            return "quic.frame_buffer";
        case ProtocolAllocationSite::QuicClientHelloBuffer:
            return "quic.client_hello_buffer";
        case ProtocolAllocationSite::QuicAckRangeScratch:
            return "quic.ack_range_scratch";
        case ProtocolAllocationSite::QuicStreamObject:
            return "quic.stream_object";
        case ProtocolAllocationSite::QuicStreamChunks:
            return "quic.stream_chunks";
        case ProtocolAllocationSite::QuicStreamAffectedScratch:
            return "quic.stream_affected_scratch";
        case ProtocolAllocationSite::QuicStreamMergeBuffer:
            return "quic.stream_merge_buffer";
        case ProtocolAllocationSite::QuicTokenCacheEntries:
            return "quic.token_cache_entries";
        case ProtocolAllocationSite::QuicTokenBytes:
            return "quic.token_bytes";
        case ProtocolAllocationSite::QpackDynamicTableData:
            return "qpack.dynamic_table_data";
        case ProtocolAllocationSite::QpackDynamicTableEntries:
            return "qpack.dynamic_table_entries";
        case ProtocolAllocationSite::QpackDynamicEntryCopy:
            return "qpack.dynamic_entry_copy";
        case ProtocolAllocationSite::QpackEncoderFieldLines:
            return "qpack.encoder_field_lines";
        case ProtocolAllocationSite::QpackEncoderReferences:
            return "qpack.encoder_references";
        case ProtocolAllocationSite::QpackEncoderOutstandingSection:
            return "qpack.encoder_outstanding_section";
        case ProtocolAllocationSite::QpackDecoderValue:
            return "qpack.decoder_value";
        case ProtocolAllocationSite::QpackDecoderBlockedSection:
            return "qpack.decoder_blocked_section";
        case ProtocolAllocationSite::Http3ConnectionObject:
            return "http3.connection_object";
        case ProtocolAllocationSite::Http3TrackedStreams:
            return "http3.tracked_streams";
        case ProtocolAllocationSite::Http3ReadScratch:
            return "http3.read_scratch";
        case ProtocolAllocationSite::Http3WriteScratch:
            return "http3.write_scratch";
        case ProtocolAllocationSite::Http3Settings:
            return "http3.settings";
        case ProtocolAllocationSite::Http3RequestFields:
            return "http3.request_fields";
        case ProtocolAllocationSite::Http3StreamPayload:
            return "http3.stream_payload";
        case ProtocolAllocationSite::Http3StreamFieldBytes:
            return "http3.stream_field_bytes";
        case ProtocolAllocationSite::SessionPoolEntries:
            return "session.pool_entries";
        case ProtocolAllocationSite::SessionHttp3ResponseAccumulator:
            return "session.http3_response_accumulator";
        case ProtocolAllocationSite::SessionHttp3CompletionFence:
            return "session.http3_completion_fence";
        case ProtocolAllocationSite::SessionHttp3PeerRouter:
            return "session.http3_peer_router";
        case ProtocolAllocationSite::SessionHttp3CertificateScratch:
            return "session.http3_certificate_scratch";
        case ProtocolAllocationSite::SessionHttp3PeerLease:
            return "session.http3_peer_lease";
        case ProtocolAllocationSite::QuicServerName:
            return "quic.server_name";
        case ProtocolAllocationSite::AltSvcCacheObject:
            return "session.altsvc_cache_object";
        case ProtocolAllocationSite::AltSvcCacheEntries:
            return "session.altsvc_cache_entries";
        case ProtocolAllocationSite::AltSvcParsedSet:
            return "session.altsvc_parsed_set";
        case ProtocolAllocationSite::AltSvcParseScratch:
            return "session.altsvc_parse_scratch";
        case ProtocolAllocationSite::Invalid:
        case ProtocolAllocationSite::Count:
        default:
            return "invalid";
        }
    }

#if defined(WKNET_USER_MODE_TEST)
    void ProtocolFailureInjectionReset() noexcept
    {
        for (ULONG index = 0; index < ProtocolAllocationSiteCount; ++index)
        {
            g_failOnNth[index].store(0, std::memory_order_relaxed);
            g_hitCount[index].store(0, std::memory_order_relaxed);
            g_liveCount[index].store(0, std::memory_order_relaxed);
        }
    }

    void ProtocolFailureInjectionSetFailOnNth(ProtocolAllocationSite site, ULONG occurrence) noexcept
    {
        if (!ProtocolFailureInjectionIsValidSite(site))
        {
            return;
        }

        const ULONG index = SiteIndex(site);
        g_hitCount[index].store(0, std::memory_order_relaxed);
        g_failOnNth[index].store(occurrence, std::memory_order_release);
    }

    void ProtocolFailureInjectionSetFailAlways(ProtocolAllocationSite site, bool enabled) noexcept
    {
        ProtocolFailureInjectionSetFailOnNth(site, enabled ? static_cast<ULONG>(-1) : 0);
    }

    bool ProtocolFailureInjectionShouldFail(ProtocolAllocationSite site) noexcept
    {
        if (!ProtocolFailureInjectionIsValidSite(site))
        {
            return false;
        }

        const ULONG index = SiteIndex(site);
        const ULONG occurrence = g_hitCount[index].fetch_add(1, std::memory_order_acq_rel) + 1;
        const ULONG failOnNth = g_failOnNth[index].load(std::memory_order_acquire);
        return failOnNth == static_cast<ULONG>(-1) || (failOnNth != 0 && occurrence == failOnNth);
    }

    ULONG ProtocolFailureInjectionHitCount(ProtocolAllocationSite site) noexcept
    {
        return ProtocolFailureInjectionIsValidSite(site) ? g_hitCount[SiteIndex(site)].load(std::memory_order_acquire)
                                                         : 0;
    }

    void ProtocolFailureInjectionRecordAcquire(ProtocolAllocationSite site) noexcept
    {
        if (ProtocolFailureInjectionIsValidSite(site))
        {
            g_liveCount[SiteIndex(site)].fetch_add(1, std::memory_order_acq_rel);
        }
    }

    bool ProtocolFailureInjectionRecordRelease(ProtocolAllocationSite site) noexcept
    {
        if (!ProtocolFailureInjectionIsValidSite(site))
        {
            return false;
        }

        std::atomic<LONG>& counter = g_liveCount[SiteIndex(site)];
        LONG current = counter.load(std::memory_order_acquire);
        while (current > 0)
        {
            if (counter.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel,
                                              std::memory_order_acquire))
            {
                return true;
            }
        }
        return false;
    }

    LONG ProtocolFailureInjectionLiveCount(ProtocolAllocationSite site) noexcept
    {
        return ProtocolFailureInjectionIsValidSite(site) ? g_liveCount[SiteIndex(site)].load(std::memory_order_acquire)
                                                         : 0;
    }

    LONG ProtocolFailureInjectionTotalLiveCount() noexcept
    {
        LONG total = 0;
        for (ULONG index = 1; index < ProtocolAllocationSiteCount; ++index)
        {
            total += g_liveCount[index].load(std::memory_order_acquire);
        }
        return total;
    }
#endif
} // namespace wknet::rtl
