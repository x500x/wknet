#pragma once

#include <wknet/WknetConfig.h>

#include "rtl/ProtocolFailureInjection.h"

namespace wknet
{
    _Ret_maybenull_ inline void* AllocateProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite site,
                                                                   SIZE_T length) noexcept
    {
        if (rtl::ProtocolFailureInjectionShouldFail(site))
        {
            return nullptr;
        }

        void* data = AllocateNonPagedPoolBytes(length);
        if (data != nullptr)
        {
            rtl::ProtocolFailureInjectionRecordAcquire(site);
        }
        return data;
    }

    inline void FreeProtocolNonPagedPoolBytes(rtl::ProtocolAllocationSite site, _In_opt_ void* data) noexcept
    {
        if (data == nullptr)
        {
            return;
        }
        const bool released = rtl::ProtocolFailureInjectionRecordRelease(site);
        UNREFERENCED_PARAMETER(released);
        FreeNonPagedPoolBytes(data);
    }

    template <typename T, rtl::ProtocolAllocationSite Site> class ProtocolHeapArray final
    {
      public:
        ProtocolHeapArray() noexcept = default;

        explicit ProtocolHeapArray(SIZE_T count) noexcept
        {
            Allocate(count);
        }

        ~ProtocolHeapArray() noexcept
        {
            Reset();
        }

        ProtocolHeapArray(const ProtocolHeapArray&) = delete;
        ProtocolHeapArray& operator=(const ProtocolHeapArray&) = delete;

        _Must_inspect_result_ NTSTATUS Allocate(SIZE_T count) noexcept
        {
            Reset();
            if (rtl::ProtocolFailureInjectionShouldFail(Site))
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            const NTSTATUS status = storage_.Allocate(count);
            if (NT_SUCCESS(status))
            {
                rtl::ProtocolFailureInjectionRecordAcquire(Site);
            }
            return status;
        }

        void Reset() noexcept
        {
            if (storage_.IsValid())
            {
                const bool released = rtl::ProtocolFailureInjectionRecordRelease(Site);
                UNREFERENCED_PARAMETER(released);
            }
            storage_.Reset();
        }

        _Must_inspect_result_ bool IsValid() const noexcept
        {
            return storage_.IsValid();
        }

        _Ret_maybenull_ T* Get() noexcept
        {
            return storage_.Get();
        }

        _Ret_maybenull_ const T* Get() const noexcept
        {
            return storage_.Get();
        }

        _Must_inspect_result_ SIZE_T Count() const noexcept
        {
            return storage_.Count();
        }

        T& operator[](SIZE_T index) noexcept
        {
            return storage_[index];
        }

        const T& operator[](SIZE_T index) const noexcept
        {
            return storage_[index];
        }

      private:
        HeapArray<T> storage_;
    };

    template <typename T, typename... Args>
    _Ret_maybenull_ T* AllocateProtocolNonPagedObject(rtl::ProtocolAllocationSite site, Args&&... args) noexcept
    {
        if (rtl::ProtocolFailureInjectionShouldFail(site))
        {
            return nullptr;
        }

        T* object = AllocateNonPagedObject<T>(args...);
        if (object != nullptr)
        {
            rtl::ProtocolFailureInjectionRecordAcquire(site);
        }
        return object;
    }

    template <typename T> void FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite site, _In_opt_ T* object) noexcept
    {
        if (object == nullptr)
        {
            return;
        }
        const bool released = rtl::ProtocolFailureInjectionRecordRelease(site);
        UNREFERENCED_PARAMETER(released);
        FreeNonPagedObject(object);
    }

    template <typename T>
    _Ret_maybenull_ T* AllocateProtocolNonPagedArray(rtl::ProtocolAllocationSite site, SIZE_T count) noexcept
    {
        if (rtl::ProtocolFailureInjectionShouldFail(site))
        {
            return nullptr;
        }

        T* array = AllocateNonPagedArray<T>(count);
        if (array != nullptr)
        {
            rtl::ProtocolFailureInjectionRecordAcquire(site);
        }
        return array;
    }

    template <typename T> void FreeProtocolNonPagedArray(rtl::ProtocolAllocationSite site, _In_opt_ T* array) noexcept
    {
        if (array == nullptr)
        {
            return;
        }
        const bool released = rtl::ProtocolFailureInjectionRecordRelease(site);
        UNREFERENCED_PARAMETER(released);
        FreeNonPagedArray(array);
    }
} // namespace wknet
