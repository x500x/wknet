#include <KernelHttp/khttp/Response.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace KernelHttp
{
namespace khttp
{
ULONG ResponseStatusCode(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    engine::KhResponseView view = {};
    NTSTATUS status = engine::KhResponseGetView(
        const_cast<engine::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.StatusCode : 0;
}

const UCHAR* ResponseBody(const Response* response) noexcept
{
    if (response == nullptr) {
        return nullptr;
    }
    engine::KhResponseView view = {};
    NTSTATUS status = engine::KhResponseGetView(
        const_cast<engine::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.Body : nullptr;
}

SIZE_T ResponseBodyLength(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    engine::KhResponseView view = {};
    NTSTATUS status = engine::KhResponseGetView(
        const_cast<engine::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.BodyLength : 0;
}

SIZE_T ResponseHeaderCount(const Response* response) noexcept
{
    return engine::KhResponseHeaderCount(
        const_cast<engine::KH_RESPONSE>(detail::ToApiResponseConst(response)));
}

NTSTATUS ResponseGetHeader(
    const Response* response,
    const char* name,
    SIZE_T nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept
{
    return engine::KhResponseGetHeader(
        const_cast<engine::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        name,
        nameLength,
        value,
        valueLength);
}

NTSTATUS ResponseGetHeaderAt(
    const Response* response,
    SIZE_T index,
    const char** name,
    SIZE_T* nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept
{
    return engine::KhResponseGetHeaderAt(
        const_cast<engine::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        index,
        name,
        nameLength,
        value,
        valueLength);
}

void ResponseRelease(Response* response) noexcept
{
    engine::KhResponseRelease(detail::ToApiResponse(response));
}
}
}
