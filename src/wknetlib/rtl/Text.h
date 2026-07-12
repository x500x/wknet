#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::rtl
{
    struct Text final
    {
        const char* Data = nullptr;
        SIZE_T Length = 0;
    };

    _Must_inspect_result_
    Text MakeText(_In_opt_ const char* value) noexcept;

    _Must_inspect_result_
    bool TextEqualsIgnoreCase(Text left, Text right) noexcept;
}
