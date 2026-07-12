#pragma once

#include <wknet/WknetConfig.h>

namespace wknet
{
namespace core
{
    class LookasideList final
    {
    public:
        LookasideList() noexcept = default;

        ~LookasideList() noexcept
        {
            Shutdown();
        }

        LookasideList(const LookasideList&) = delete;
        LookasideList& operator=(const LookasideList&) = delete;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T blockSize) noexcept
        {
            Shutdown();
            if (blockSize == 0) {
                return STATUS_INVALID_PARAMETER;
            }

#if defined(WKNET_USER_MODE_TEST)
            blockSize_ = blockSize;
            initialized_ = true;
            return STATUS_SUCCESS;
#else
            NTSTATUS status = ExInitializeLookasideListEx(
                &list_,
                nullptr,
                nullptr,
                NonPagedPoolNx,
                0,
                blockSize,
                PoolTag,
                0);
            if (!NT_SUCCESS(status)) {
                blockSize_ = 0;
                initialized_ = false;
                return status;
            }

            blockSize_ = blockSize;
            initialized_ = true;
            return STATUS_SUCCESS;
#endif
        }

        void Shutdown() noexcept
        {
            if (!initialized_) {
                return;
            }

#if !defined(WKNET_USER_MODE_TEST)
            ExDeleteLookasideListEx(&list_);
            RtlZeroMemory(&list_, sizeof(list_));
#endif
            blockSize_ = 0;
            initialized_ = false;
        }

        _Ret_maybenull_
        void* Allocate() noexcept
        {
            if (!initialized_) {
                return nullptr;
            }

#if defined(WKNET_USER_MODE_TEST)
            return AllocateNonPagedPoolBytes(blockSize_);
#else
            return ExAllocateFromLookasideListEx(&list_);
#endif
        }

        void Free(_In_opt_ void* block) noexcept
        {
            if (block == nullptr || !initialized_) {
                return;
            }

            RtlSecureZeroMemory(block, blockSize_);
#if defined(WKNET_USER_MODE_TEST)
            FreeNonPagedPoolBytes(block);
#else
            ExFreeToLookasideListEx(&list_, block);
#endif
        }

        _Must_inspect_result_
        bool IsInitialized() const noexcept
        {
            return initialized_;
        }

        _Must_inspect_result_
        SIZE_T BlockSize() const noexcept
        {
            return blockSize_;
        }

    private:
#if !defined(WKNET_USER_MODE_TEST)
        LOOKASIDE_LIST_EX list_ = {};
#endif
        SIZE_T blockSize_ = 0;
        bool initialized_ = false;
    };
}
}
