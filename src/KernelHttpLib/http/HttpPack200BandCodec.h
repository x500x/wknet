#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace http
{
    enum class HttpPack200CodingKind : UCHAR
    {
        Byte1,
        Char3,
        Unsigned5,
        Signed5,
        Delta5,
        UnsignedDelta5,
        MDelta5,
        Bci5,
        Branch5
    };

    struct HttpPack200Coding final
    {
        UCHAR B = 1;
        USHORT H = 256;
        UCHAR S = 0;
        UCHAR D = 0;
    };

    _Must_inspect_result_
    constexpr HttpPack200Coding HttpPack200CodingFor(HttpPack200CodingKind kind) noexcept
    {
        switch (kind) {
        case HttpPack200CodingKind::Byte1:
            return { 1, 256, 0, 0 };
        case HttpPack200CodingKind::Char3:
            return { 3, 128, 0, 0 };
        case HttpPack200CodingKind::Unsigned5:
            return { 5, 64, 0, 0 };
        case HttpPack200CodingKind::Signed5:
            return { 5, 64, 1, 0 };
        case HttpPack200CodingKind::Delta5:
            return { 5, 64, 1, 1 };
        case HttpPack200CodingKind::UnsignedDelta5:
            return { 5, 64, 0, 1 };
        case HttpPack200CodingKind::MDelta5:
            return { 5, 64, 2, 1 };
        case HttpPack200CodingKind::Bci5:
            return { 5, 4, 0, 0 };
        case HttpPack200CodingKind::Branch5:
            return { 5, 4, 2, 0 };
        default:
            return { 1, 256, 0, 0 };
        }
    }

    class HttpPack200BandReader final
    {
    public:
        HttpPack200BandReader(const UCHAR* data, SIZE_T length) noexcept;

        _Must_inspect_result_
        bool ReadByte(_Out_ UCHAR* value) noexcept;

        _Must_inspect_result_
        bool ReadBigEndian32(_Out_ ULONG* value) noexcept;

        _Must_inspect_result_
        bool ReadInt(HttpPack200Coding coding, _Out_ LONG* value) noexcept;

        _Must_inspect_result_
        bool ReadUnsigned(HttpPack200CodingKind kind, _Out_ ULONG* value) noexcept;

        void ResetDelta() noexcept;

        _Must_inspect_result_
        SIZE_T Remaining() const noexcept;

        _Must_inspect_result_
        const UCHAR* Current() const noexcept;

        _Must_inspect_result_
        bool Skip(SIZE_T length) noexcept;

    private:
        const UCHAR* data_ = nullptr;
        SIZE_T length_ = 0;
        SIZE_T cursor_ = 0;
        LONG previousValue_ = 0;
    };
}
}
