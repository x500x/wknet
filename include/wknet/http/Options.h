#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS SendOptionsCreate(_Out_ SendOptions** options) noexcept;

    void SendOptionsRelease(_In_opt_ SendOptions* options) noexcept;

    _Must_inspect_result_
    NTSTATUS AsyncOptionsCreate(_Out_ AsyncOptions** options) noexcept;

    void AsyncOptionsRelease(_In_opt_ AsyncOptions* options) noexcept;
}
