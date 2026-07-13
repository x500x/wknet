#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::qpack
{
constexpr ULONGLONG QpackIntegerMaximum = (1ULL << 62) - 1ULL;
constexpr ULONGLONG QpackDecompressionFailed = 0x200;
constexpr ULONGLONG QpackEncoderStreamError = 0x201;
constexpr ULONGLONG QpackDecoderStreamError = 0x202;

struct QpackStringView final
{
    const UCHAR *Data = nullptr;
    SIZE_T Length = 0;
};

struct QpackStaticEntryView final
{
    QpackStringView Name = {};
    QpackStringView Value = {};
};
} // namespace wknet::qpack
