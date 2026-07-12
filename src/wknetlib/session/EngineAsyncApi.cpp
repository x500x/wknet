#include "session/EnginePrivate.hpp"

namespace wknet
{
namespace session
{
    NTSTATUS AsyncCancel(AsyncOperationHandle operation) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return AsyncOperationCancel(operation);
    }

    NTSTATUS AsyncWait(AsyncOperationHandle operation, ULONG timeoutMilliseconds) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return AsyncOperationWait(operation, timeoutMilliseconds);
    }

    void AsyncRelease(AsyncOperationHandle operation) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || operation == nullptr) {
            return;
        }

        AsyncOperationRelease(operation);
    }


}
}
