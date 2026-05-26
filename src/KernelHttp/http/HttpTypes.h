#pragma once

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stddef.h>
#include <stdint.h>
#include <string.h>

using NTSTATUS = long;
using SIZE_T = size_t;
using ULONG = uint32_t;
using LONG = int32_t;
using USHORT = uint16_t;
using UCHAR = uint8_t;
using ULONGLONG = uint64_t;

#ifndef RtlCopyMemory
#define RtlCopyMemory(Destination, Source, Length) memcpy((Destination), (Source), (Length))
#endif

#ifndef RtlMoveMemory
#define RtlMoveMemory(Destination, Source, Length) memmove((Destination), (Source), (Length))
#endif

#ifndef RtlZeroMemory
#define RtlZeroMemory(Destination, Length) memset((Destination), 0, (Length))
#endif

#ifndef RtlSecureZeroMemory
#define RtlSecureZeroMemory(Destination, Length) memset((Destination), 0, (Length))
#endif

#ifndef RtlCompareMemory
#define RtlCompareMemory(Source1, Source2, Length) \
    (memcmp((Source1), (Source2), (Length)) == 0 ? (Length) : 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif

#ifndef STATUS_CANCELLED
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120L)
#endif

#ifndef STATUS_MORE_PROCESSING_REQUIRED
#define STATUS_MORE_PROCESSING_REQUIRED ((NTSTATUS)0xC0000016L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_INTEGER_OVERFLOW
#define STATUS_INTEGER_OVERFLOW ((NTSTATUS)0xC0000095L)
#endif

#ifndef STATUS_INVALID_NETWORK_RESPONSE
#define STATUS_INVALID_NETWORK_RESPONSE ((NTSTATUS)0xC00000C3L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif

#ifndef STATUS_TRUST_FAILURE
#define STATUS_TRUST_FAILURE ((NTSTATUS)0xC0000190L)
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_INVALID_SIGNATURE
#define STATUS_INVALID_SIGNATURE ((NTSTATUS)0xC000A000L)
#endif

#ifndef STATUS_CONNECTION_DISCONNECTED
#define STATUS_CONNECTION_DISCONNECTED ((NTSTATUS)0xC000020CL)
#endif

#ifndef STATUS_CONNECTION_RESET
#define STATUS_CONNECTION_RESET ((NTSTATUS)0xC000020DL)
#endif

#ifndef STATUS_CONNECTION_ABORTED
#define STATUS_CONNECTION_ABORTED ((NTSTATUS)0xC0000241L)
#endif

#ifndef STATUS_INVALID_DEVICE_STATE
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#endif

#ifndef STATUS_INVALID_CONNECTION
#define STATUS_INVALID_CONNECTION ((NTSTATUS)0xC0000140L)
#endif

#ifndef STATUS_DEVICE_NOT_READY
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3L)
#endif

#ifndef STATUS_IO_TIMEOUT
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xC00000B5L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef _Must_inspect_result_
#define _Must_inspect_result_
#endif

#ifndef _In_reads_bytes_
#define _In_reads_bytes_(x)
#endif

#ifndef _In_reads_bytes_opt_
#define _In_reads_bytes_opt_(x)
#endif

#ifndef _In_reads_
#define _In_reads_(x)
#endif

#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(x)
#endif

#ifndef _Out_writes_
#define _Out_writes_(x)
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Outptr_result_bytebuffer_
#define _Outptr_result_bytebuffer_(x)
#endif

#ifndef _Out_opt_
#define _Out_opt_
#endif

#ifndef _Inout_
#define _Inout_
#endif

#ifndef _Inout_updates_
#define _Inout_updates_(x)
#endif

#ifndef _In_
#define _In_
#endif

#ifndef _In_opt_
#define _In_opt_
#endif

#ifndef _Ret_maybenull_
#define _Ret_maybenull_
#endif

#ifndef _In_z_
#define _In_z_
#endif

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#ifndef kprintf
#define kprintf(...)
#endif

#else
#include "KernelHttpConfig.h"
#endif

#ifndef KERNEL_HTTP_HEAP_ARRAY_DEFINED
#define KERNEL_HTTP_HEAP_ARRAY_DEFINED
namespace KernelHttp
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
            if (count == 0 || count > (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / sizeof(T))) {
                return STATUS_INVALID_PARAMETER;
            }

            T* data = new T[count]();
            if (data == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            data_ = data;
            count_ = count;
            return STATUS_SUCCESS;
        }

        void Reset() noexcept
        {
            delete[] data_;
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
}
#endif

namespace KernelHttp
{
namespace http
{
    struct HttpText final
    {
        const char* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct HttpHeader final
    {
        HttpText Name = {};
        HttpText Value = {};
    };

    _Must_inspect_result_
    HttpText MakeText(_In_opt_ const char* value) noexcept;

    _Must_inspect_result_
    bool TextEqualsIgnoreCase(HttpText left, HttpText right) noexcept;

    _Must_inspect_result_
    bool HeaderValueHasToken(HttpText value, HttpText token) noexcept;
}
}
