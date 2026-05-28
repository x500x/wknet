#pragma once

#include "Types.h"

namespace KernelHttp
{
namespace khttp
{
    _Must_inspect_result_
    NTSTATUS SessionCreate(
        _In_ net::WskClient* wskClient,
        _In_opt_ const SessionConfig* config,
        _Out_ Session** out) noexcept;

    void SessionClose(_In_opt_ Session* session) noexcept;
}
}
