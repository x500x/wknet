#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace core
{
    inline NTSTATUS CheckPassiveLevel() noexcept
    {
#if defined(KERNEL_HTTP_USER_MODE_TEST)
        return STATUS_SUCCESS;
#else
        return KeGetCurrentIrql() == PASSIVE_LEVEL ?
            STATUS_SUCCESS :
            STATUS_INVALID_DEVICE_REQUEST;
#endif
    }
}
}
