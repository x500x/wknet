#include <wknet/http/Response.h>
#include "Detail.h"
#include "session/Engine.h"

namespace wknet::http {
ULONG ResponseStatusCode(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    ::wknet::session::ResponseView view = {};
    NTSTATUS status = ::wknet::session::ResponseGetView(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.StatusCode : 0;
}

const UCHAR* ResponseBody(const Response* response) noexcept
{
    if (response == nullptr) {
        return nullptr;
    }
    ::wknet::session::ResponseView view = {};
    NTSTATUS status = ::wknet::session::ResponseGetView(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.Body : nullptr;
}

SIZE_T ResponseBodyLength(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    ::wknet::session::ResponseView view = {};
    NTSTATUS status = ::wknet::session::ResponseGetView(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.BodyLength : 0;
}

SIZE_T ResponseHeaderCount(const Response* response) noexcept
{
    return ::wknet::session::ResponseHeaderCount(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)));
}

SIZE_T ResponseTrailerCount(const Response* response) noexcept
{
    return ::wknet::session::ResponseTrailerCount(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)));
}

NTSTATUS ResponseGetHeader(
    const Response* response,
    const char* name,
    SIZE_T nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept
{
    return ::wknet::session::ResponseGetHeader(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)),
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
    return ::wknet::session::ResponseGetHeaderAt(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)),
        index,
        name,
        nameLength,
        value,
        valueLength);
}

NTSTATUS ResponseGetTrailer(
    const Response* response,
    const char* name,
    SIZE_T nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept
{
    return ::wknet::session::ResponseGetTrailer(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)),
        name,
        nameLength,
        value,
        valueLength);
}

NTSTATUS ResponseGetTrailerAt(
    const Response* response,
    SIZE_T index,
    const char** name,
    SIZE_T* nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept
{
    return ::wknet::session::ResponseGetTrailerAt(
        const_cast<::wknet::session::ResponseHandle>(detail::ToApiResponseConst(response)),
        index,
        name,
        nameLength,
        value,
        valueLength);
}

void ResponseRelease(Response* response) noexcept
{
    ::wknet::session::ResponseRelease(detail::ToApiResponse(response));
}
}
