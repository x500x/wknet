#pragma once

#if defined(WKNET_USER_MODE_TEST)
#include <wknet/http1/HttpTypes.h>
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
    constexpr ULONG WKNET_HARD_MAX_H2_CONCURRENT_STREAMS_LOCAL = 100;
    // 0 disables a lifetime byte cap on long-lived connections.
    constexpr ULONGLONG WKNET_HARD_MAX_CONNECTION_BYTES = 0;
    constexpr ULONG WKNET_HARD_MAX_CONNECTION_FRAMES = 1U << 20;
    constexpr ULONG WKNET_HARD_MAX_CONNECTION_CONTROL_SIGNALS = 4096;
}
