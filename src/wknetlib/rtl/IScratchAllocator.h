#pragma once

#include <wknet/WknetConfig.h>

namespace wknet
{
namespace core
{
    class IScratchAllocator
    {
    public:
        virtual ~IScratchAllocator() noexcept = default;

        _Must_inspect_result_
        virtual NTSTATUS Acquire(
            SIZE_T length,
            _Outptr_result_bytebuffer_(length) void** buffer) noexcept = 0;

        virtual void Release(_In_opt_ void* buffer) noexcept = 0;

        _Must_inspect_result_
        virtual NTSTATUS EnsureBuffer(
            SIZE_T length,
            _Outptr_result_bytebuffer_(length) void** buffer) noexcept = 0;
    };
}
}
