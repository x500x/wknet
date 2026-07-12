#pragma once

#if defined(WKNET_USER_MODE_TEST)
#include "http1/HttpTypes.h"
#include <stdarg.h>
#include <stdio.h>

namespace wknet
{
namespace testlog
{
    inline NTSTATUS Initialize(_In_z_ const char* path) noexcept
    {
        UNREFERENCED_PARAMETER(path);
        return STATUS_SUCCESS;
    }

    inline void Shutdown() noexcept
    {
    }

    inline void Print(_In_z_ const char* format, ...) noexcept
    {
        va_list args = {};
        va_start(args, format);
        (void)vprintf(format, args);
        va_end(args);
    }

    inline void WriteRaw(_In_reads_bytes_opt_(length) const char* data, SIZE_T length) noexcept
    {
        if (data == nullptr || length == 0) {
            return;
        }
        (void)fwrite(data, 1, length, stdout);
    }
}
}
#else
#include <wknet/WknetConfig.h>

namespace wknet
{
namespace testlog
{
    _Must_inspect_result_
    NTSTATUS Initialize(_In_z_ const char* path) noexcept;

    void Shutdown() noexcept;

    void Print(_In_z_ _Printf_format_string_ const char* format, ...) noexcept;

    void WriteRaw(_In_reads_bytes_opt_(length) const char* data, SIZE_T length) noexcept;
}
}
#endif

#undef WKNET_DBG_PRINT
#define WKNET_DBG_PRINT(...) wknet::testlog::Print(__VA_ARGS__)

// Prefer TraceSink for graded output; keep DBG_PRINT alias for sample verbosity.
// Test drivers also force TraceLevel::Max in DriverEntry.

#undef KHTTP_SAMPLE_LOG
#define KHTTP_SAMPLE_LOG(...) WKNET_DBG_PRINT(__VA_ARGS__)
