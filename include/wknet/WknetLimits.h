#pragma once

#if defined(WKNET_USER_MODE_TEST)
#include <wknet/UmTypes.h>
#else
#include <ntddk.h>
#endif

namespace wknet
{
    // 0 means no library-wide byte cap for buffered responses; callers can
    // still set a nonzero MaxResponseBytes per session or per send.
    constexpr SIZE_T WKNET_HARD_MAX_RESPONSE_BYTES = 0;
    constexpr SIZE_T WKNET_HARD_MAX_HEADER_SECTION = 64 * 1024;
    constexpr SIZE_T WKNET_HARD_MAX_HEADERS = 200;
    // 0 means decoded aggregate size follows the response buffer/caller cap.
    // Decompression-bomb protection is enforced by expansion ratio.
    constexpr SIZE_T WKNET_HARD_MAX_DECODED_BYTES = 0;
    // Per-coding expansion ceiling for Content-Encoding / Transfer-Encoding /
    // WebSocket permessage-deflate / EXI deflate blocks. Absolute size is still
    // bounded by MaxResponseBytes / destination capacity. 1024x is high enough
    // for highly compressible legitimate JSON/text (e.g. postman-echo re-encoding
    // a 64 KiB payload into ~400 B gzip that inflates ~500-600x) while still
    // rejecting pathological bombs relative to the compressed input size.
    constexpr SIZE_T WKNET_HARD_MAX_DECODE_EXPANSION_RATIO = 1024;
    constexpr ULONG WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL = 100;
    // 0 disables a lifetime byte cap on long-lived connections.
    constexpr ULONGLONG WKNET_HARD_MAX_CONNECTION_BYTES = 0;
    constexpr ULONG WKNET_HARD_MAX_CONNECTION_FRAMES = 1U << 20;
    constexpr ULONG WKNET_HARD_MAX_CONNECTION_CONTROL_SIGNALS = 4096;

    // QUIC/HTTP/3 protocol-safety ceilings. These values bound peer-controlled
    // NonPaged state; they do not cap ordinary buffered HTTP response bodies.
    constexpr ULONG WKNET_HARD_MAX_QUIC_CONNECTIONS_PER_SESSION = 8;
    constexpr ULONG WKNET_HARD_MAX_QUIC_LOCAL_BIDI_STREAMS = 100;
    constexpr ULONG WKNET_HARD_MAX_QUIC_PEER_BIDI_STREAMS = 100;
    constexpr ULONG WKNET_HARD_MAX_QUIC_LOCAL_UNI_STREAMS = 8;
    constexpr ULONG WKNET_HARD_MAX_QUIC_PEER_UNI_STREAMS = 8;
    constexpr SIZE_T WKNET_HARD_MAX_QUIC_CRYPTO_REASSEMBLY_BYTES = 256 * 1024;
    constexpr ULONG WKNET_HARD_MAX_QUIC_CRYPTO_GAPS = 128;
    constexpr SIZE_T WKNET_HARD_MAX_QUIC_STREAM_REASSEMBLY_BYTES = 1024 * 1024;
    constexpr SIZE_T WKNET_HARD_MAX_QUIC_CONNECTION_REASSEMBLY_BYTES = 16 * 1024 * 1024;
    constexpr ULONG WKNET_HARD_MAX_QUIC_STREAM_GAPS = 256;
    constexpr ULONG WKNET_HARD_MAX_QUIC_CONNECTION_GAPS = 2048;
    constexpr ULONG WKNET_HARD_MAX_QUIC_SENT_PACKETS = 4096;
    constexpr ULONG WKNET_HARD_MAX_QUIC_ACK_RANGES = 256;
    constexpr ULONG WKNET_HARD_MAX_QUIC_CONNECTION_IDS = 8;
    constexpr ULONG WKNET_HARD_MAX_QUIC_TOKENS = 8;
    constexpr SIZE_T WKNET_HARD_MAX_QUIC_UDP_PAYLOAD_BYTES = 1200;
    constexpr SIZE_T WKNET_HARD_MAX_QUIC_FRAME_BYTES = 1200;
    constexpr SIZE_T WKNET_HARD_MAX_QUIC_TRANSPORT_PARAMETERS_BYTES = 4096;
    constexpr ULONG WKNET_HARD_MAX_QUIC_COMMANDS = 1024;
    constexpr ULONG WKNET_HARD_MAX_QUIC_PENDING_STREAM_OPERATIONS = 1024;

    constexpr SIZE_T WKNET_HARD_MAX_HTTP3_FIELD_SECTION_BYTES = WKNET_HARD_MAX_HEADER_SECTION;
    constexpr SIZE_T WKNET_HARD_MAX_HTTP3_FIELDS = WKNET_HARD_MAX_HEADERS;
    constexpr SIZE_T WKNET_HARD_MAX_QPACK_DYNAMIC_TABLE_BYTES = 64 * 1024;
    constexpr ULONG WKNET_HARD_MAX_QPACK_BLOCKED_STREAMS = 16;
    constexpr SIZE_T WKNET_HARD_MAX_QPACK_BLOCKED_SECTION_BYTES = WKNET_HARD_MAX_HEADER_SECTION;
    constexpr SIZE_T WKNET_HARD_MAX_QPACK_TOTAL_BLOCKED_BYTES = 512 * 1024;

    constexpr ULONG WKNET_HARD_MAX_ALT_SVC_ENTRIES = 64;
    constexpr ULONG WKNET_HARD_MAX_ALT_SVC_CANDIDATES_PER_ORIGIN = 4;
    constexpr SIZE_T WKNET_HARD_MAX_ALT_SVC_HOST_BYTES = 253;
    constexpr SIZE_T WKNET_HARD_MAX_ALT_SVC_AUTHORITY_BYTES = 512;
}
