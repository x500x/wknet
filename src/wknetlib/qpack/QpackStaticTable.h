#pragma once

#include "qpack/QpackTypes.h"

namespace wknet::qpack
{
constexpr SIZE_T QpackStaticTableSize = 99;

NTSTATUS QpackStaticTableLookup(SIZE_T index, _Out_ QpackStaticEntryView *entry) noexcept;
} // namespace wknet::qpack
