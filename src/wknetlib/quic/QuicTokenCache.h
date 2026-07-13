#pragma once

#include "quic/QuicTypes.h"
#include <wknet/WknetLimits.h>

namespace wknet::quic
{
constexpr SIZE_T QuicMaximumNewTokenLength = 1024;

struct QuicTokenCacheEntry final
{
    HeapArray<UCHAR> Token;
    ULONGLONG Sequence = 0;
};

class QuicTokenCache final
{
  public:
    NTSTATUS Initialize(SIZE_T capacity = WKNET_HARD_MAX_QUIC_TOKENS) noexcept;
    NTSTATUS Store(QuicBufferView token) noexcept;
    QuicBufferView Latest() const noexcept;
    SIZE_T Count() const noexcept;
    void Clear() noexcept;

  private:
    HeapArray<QuicTokenCacheEntry> entries_;
    SIZE_T count_ = 0;
    SIZE_T nextSlot_ = 0;
    ULONGLONG nextSequence_ = 1;
};
} // namespace wknet::quic
