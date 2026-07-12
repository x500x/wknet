#pragma once

#if defined(WKNET_USER_MODE_TEST)
#include "http1/HttpTypes.h"

struct WSK_BUF
{
    void* Mdl = nullptr;
    ULONG Offset = 0;
    SIZE_T Length = 0;
};

using PWSK_BUF = WSK_BUF*;
using PMDL = void*;

#ifndef WSK_FLAG_NODELAY
#define WSK_FLAG_NODELAY 0
#endif

#ifndef MAXULONG
#define MAXULONG 0xffffffffUL
#endif

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#else
#include <wknet/WknetConfig.h>

#include <wsk.h>
#endif

namespace wknet
{
namespace net
{
    class WskBuffer final
    {
    public:
        WskBuffer() noexcept = default;

        WskBuffer(const WskBuffer&) = delete;
        WskBuffer& operator=(const WskBuffer&) = delete;

        ~WskBuffer() noexcept
        {
            Free();
        }

        _Must_inspect_result_
        NTSTATUS Allocate(SIZE_T capacity) noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            if (capacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            Free();

            data_ = calloc(1, capacity);
            if (data_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            mdl_ = data_;
            capacity_ = capacity;
            return Prepare(capacity);
#else
            if (capacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (capacity > MAXULONG) {
                return STATUS_INTEGER_OVERFLOW;
            }

            Free();

            data_ = ExAllocatePool2(POOL_FLAG_NON_PAGED, capacity, PoolTag);
            if (data_ == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            mdl_ = IoAllocateMdl(data_, static_cast<ULONG>(capacity), FALSE, FALSE, nullptr);
            if (mdl_ == nullptr) {
                ExFreePoolWithTag(data_, PoolTag);
                data_ = nullptr;
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            MmBuildMdlForNonPagedPool(mdl_);
            capacity_ = capacity;

            return Prepare(capacity);
#endif
        }

        _Must_inspect_result_
        NTSTATUS EnsureCapacity(SIZE_T capacity) noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            if (capacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (capacity_ >= capacity) {
                return STATUS_SUCCESS;
            }

            return Allocate(capacity);
#else
            if (capacity == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (capacity_ >= capacity) {
                return STATUS_SUCCESS;
            }

            return Allocate(capacity);
#endif
        }

        void Free() noexcept
        {
#if defined(WKNET_USER_MODE_TEST)
            free(data_);
            wskBuffer_ = {};
            capacity_ = 0;
            data_ = nullptr;
            mdl_ = nullptr;
#else
            wskBuffer_ = {};
            capacity_ = 0;

            if (mdl_ != nullptr) {
                IoFreeMdl(mdl_);
                mdl_ = nullptr;
            }

            if (data_ != nullptr) {
                ExFreePoolWithTag(data_, PoolTag);
                data_ = nullptr;
            }
#endif
        }

        _Must_inspect_result_
        NTSTATUS Prepare(SIZE_T length, SIZE_T offset = 0) noexcept
        {
            if (mdl_ == nullptr || data_ == nullptr) {
                return STATUS_INVALID_DEVICE_STATE;
            }

            if (offset > MAXULONG ||
                offset > capacity_ ||
                length > (capacity_ - offset)) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            wskBuffer_.Mdl = mdl_;
            wskBuffer_.Offset = static_cast<ULONG>(offset);
            wskBuffer_.Length = length;

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS SetData(_In_reads_bytes_(length) const void* source, SIZE_T length) noexcept
        {
            if (source == nullptr || data_ == nullptr || length == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (length > capacity_) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            RtlCopyMemory(data_, source, length);
            return Prepare(length);
        }

        _Must_inspect_result_
        NTSTATUS CopyTo(_Out_writes_bytes_(length) void* destination, SIZE_T length) const noexcept
        {
            if (destination == nullptr || data_ == nullptr || length == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (length > capacity_) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            RtlCopyMemory(destination, data_, length);
            return STATUS_SUCCESS;
        }

        _Ret_maybenull_
        void* Data() noexcept
        {
            return data_;
        }

        _Ret_maybenull_
        const void* Data() const noexcept
        {
            return data_;
        }

        SIZE_T Capacity() const noexcept
        {
            return capacity_;
        }

        PWSK_BUF WskBuf() noexcept
        {
            return &wskBuffer_;
        }

    private:
        void* data_ = nullptr;
        SIZE_T capacity_ = 0;
        PMDL mdl_ = nullptr;
        WSK_BUF wskBuffer_ = {};
    };
}
}
