#include "quic/QuicTokenCache.h"

namespace wknet::quic
{
NTSTATUS QuicTokenCache::Initialize(SIZE_T capacity) noexcept
{
    Clear();
    if (capacity == 0 || capacity > WKNET_HARD_MAX_QUIC_TOKENS)
    {
        return STATUS_INVALID_PARAMETER;
    }
    return entries_.Allocate(capacity);
}

NTSTATUS QuicTokenCache::Store(QuicBufferView token) noexcept
{
    if (!entries_.IsValid() || token.Data == nullptr || token.Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (token.Length > QuicMaximumNewTokenLength)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    QuicTokenCacheEntry &entry = entries_[nextSlot_];
    entry.Token.Reset();
    NTSTATUS status = entry.Token.Allocate(token.Length);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlCopyMemory(entry.Token.Get(), token.Data, token.Length);
    entry.Sequence = nextSequence_++;
    nextSlot_ = (nextSlot_ + 1) % entries_.Count();
    if (count_ < entries_.Count())
    {
        ++count_;
    }
    return STATUS_SUCCESS;
}

QuicBufferView QuicTokenCache::Latest() const noexcept
{
    const QuicTokenCacheEntry *latest = nullptr;
    for (SIZE_T index = 0; index < entries_.Count(); ++index)
    {
        const QuicTokenCacheEntry &entry = entries_[index];
        if (entry.Token.IsValid() && (latest == nullptr || entry.Sequence > latest->Sequence))
        {
            latest = &entry;
        }
    }
    return latest == nullptr ? QuicBufferView{} : QuicBufferView{latest->Token.Get(), latest->Token.Count()};
}

SIZE_T QuicTokenCache::Count() const noexcept
{
    return count_;
}

void QuicTokenCache::Clear() noexcept
{
    if (entries_.IsValid())
    {
        for (SIZE_T index = 0; index < entries_.Count(); ++index)
        {
            if (entries_[index].Token.IsValid())
            {
                RtlSecureZeroMemory(entries_[index].Token.Get(), entries_[index].Token.Count());
                entries_[index].Token.Reset();
            }
            entries_[index].Sequence = 0;
        }
    }
    entries_.Reset();
    count_ = 0;
    nextSlot_ = 0;
    nextSequence_ = 1;
}
} // namespace wknet::quic
