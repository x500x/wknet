#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    _Must_inspect_result_
    NTSTATUS SessionCreate(_Out_ Session** session) noexcept;

    _Must_inspect_result_
    NTSTATUS SessionCreate(_In_opt_ const SessionConfig* config, _Out_ Session** session) noexcept;

    void SessionClose(_In_opt_ Session* session) noexcept;
}
