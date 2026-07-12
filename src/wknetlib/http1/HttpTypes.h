#pragma once

#if defined(WKNET_USER_MODE_TEST)
#include <wknet/UmTypes.h>
#else
#include <wknet/WknetConfig.h>
#endif

#include "rtl/Text.h"

#ifndef WKNET_ALLOCATOR_DEFINED
#define WKNET_ALLOCATOR_DEFINED
namespace wknet
{
    _Ret_maybenull_
    inline void* AllocateNonPagedPoolBytes(SIZE_T length) noexcept
    {
        if (length == 0) {
            return nullptr;
        }

        return calloc(1, length);
    }

    inline void FreeNonPagedPoolBytes(_In_opt_ void* pointer) noexcept
    {
        free(pointer);
    }

    template<typename T>
    _Must_inspect_result_
    inline bool NonPagedArrayCountIsValid(SIZE_T count) noexcept
    {
        return count != 0 &&
            count <= (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / sizeof(T));
    }

    template<typename T, typename... Args>
    _Ret_maybenull_
    inline T* AllocateNonPagedObject(Args&&... args) noexcept
    {
        return new T(args...);
    }

    template<typename T>
    inline void FreeNonPagedObject(_In_opt_ T* object) noexcept
    {
        delete object;
    }

    template<typename T>
    _Ret_maybenull_
    inline T* AllocateNonPagedArray(SIZE_T count) noexcept
    {
        if (!NonPagedArrayCountIsValid<T>(count)) {
            return nullptr;
        }

        return new T[count]();
    }

    template<typename T>
    inline void FreeNonPagedArray(_In_opt_ T* array) noexcept
    {
        delete[] array;
    }
}
#endif

#ifndef WKNET_HEAP_ARRAY_DEFINED
#define WKNET_HEAP_ARRAY_DEFINED
namespace wknet
{
    template<typename T>
    class HeapArray final
    {
    public:
        HeapArray() noexcept = default;

        explicit HeapArray(SIZE_T count) noexcept
        {
            Allocate(count);
        }

        ~HeapArray() noexcept
        {
            Reset();
        }

        HeapArray(const HeapArray&) = delete;
        HeapArray& operator=(const HeapArray&) = delete;

        _Must_inspect_result_
        NTSTATUS Allocate(SIZE_T count) noexcept
        {
            Reset();
            if (!NonPagedArrayCountIsValid<T>(count)) {
                return STATUS_INVALID_PARAMETER;
            }

            T* data = AllocateNonPagedArray<T>(count);
            if (data == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            data_ = data;
            count_ = count;
            return STATUS_SUCCESS;
        }

        void Reset() noexcept
        {
            FreeNonPagedArray(data_);
            data_ = nullptr;
            count_ = 0;
        }

        _Must_inspect_result_
        bool IsValid() const noexcept
        {
            return data_ != nullptr;
        }

        _Ret_maybenull_
        T* Get() noexcept
        {
            return data_;
        }

        _Ret_maybenull_
        const T* Get() const noexcept
        {
            return data_;
        }

        _Must_inspect_result_
        SIZE_T Count() const noexcept
        {
            return count_;
        }

        T& operator[](SIZE_T index) noexcept
        {
            return data_[index];
        }

        const T& operator[](SIZE_T index) const noexcept
        {
            return data_[index];
        }

    private:
        T* data_ = nullptr;
        SIZE_T count_ = 0;
    };

    template<typename T>
    class HeapObject final
    {
    public:
        HeapObject() noexcept
        {
            Allocate();
        }

        ~HeapObject() noexcept
        {
            Reset();
        }

        HeapObject(const HeapObject&) = delete;
        HeapObject& operator=(const HeapObject&) = delete;

        _Must_inspect_result_
        NTSTATUS Allocate() noexcept
        {
            Reset();

            T* data = AllocateNonPagedObject<T>();
            if (data == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            data_ = data;
            return STATUS_SUCCESS;
        }

        void Reset() noexcept
        {
            FreeNonPagedObject(data_);
            data_ = nullptr;
        }

        _Must_inspect_result_
        bool IsValid() const noexcept
        {
            return data_ != nullptr;
        }

        _Ret_maybenull_
        T* Get() noexcept
        {
            return data_;
        }

        _Ret_maybenull_
        const T* Get() const noexcept
        {
            return data_;
        }

        T& operator*() noexcept
        {
            return *data_;
        }

        const T& operator*() const noexcept
        {
            return *data_;
        }

        _Ret_maybenull_
        T* operator->() noexcept
        {
            return data_;
        }

        _Ret_maybenull_
        const T* operator->() const noexcept
        {
            return data_;
        }

    private:
        T* data_ = nullptr;
    };
}
#endif

namespace wknet
{
namespace http1
{
    using HttpText = rtl::Text;

    struct HttpHeader final
    {
        HttpText Name = {};
        HttpText Value = {};
    };

    using rtl::MakeText;
    using rtl::TextEqualsIgnoreCase;

    _Must_inspect_result_
    bool HeaderValueHasToken(HttpText value, HttpText token) noexcept;
}
}
