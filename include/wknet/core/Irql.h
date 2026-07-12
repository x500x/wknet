#pragma once

#include <wknet/http1/HttpTypes.h>

namespace wknet
{
namespace core
{
    inline NTSTATUS CheckPassiveLevel() noexcept
    {
#if defined(WKNET_USER_MODE_TEST)
        return STATUS_SUCCESS;
#else
        return KeGetCurrentIrql() == PASSIVE_LEVEL ?
            STATUS_SUCCESS :
            STATUS_INVALID_DEVICE_REQUEST;
#endif
    }
}
}
