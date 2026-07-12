#include <wknet/http/Response.h>
#include "Detail.h"
#include <wknet/engine/Engine.h>

namespace wknet::http {
ULONG ResponseStatusCode(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    ::wknet::session::KhResponseView view = {};
    NTSTATUS status = ::wknet::session::KhResponseGetView(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.StatusCode : 0;
}

const UCHAR* ResponseBody(const Response* response) noexcept
{
    if (response == nullptr) {
        return nullptr;
    }
    ::wknet::session::KhResponseView view = {};
    NTSTATUS status = ::wknet::session::KhResponseGetView(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.Body : nullptr;
}

SIZE_T ResponseBodyLength(const Response* response) noexcept
{
    if (response == nullptr) {
        return 0;
    }
    ::wknet::session::KhResponseView view = {};
    NTSTATUS status = ::wknet::session::KhResponseGetView(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        &view);
    return NT_SUCCESS(status) ? view.BodyLength : 0;
}

SIZE_T ResponseHeaderCount(const Response* response) noexcept
{
    return ::wknet::session::KhResponseHeaderCount(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)));
}

SIZE_T ResponseTrailerCount(const Response* response) noexcept
{
    return ::wknet::session::KhResponseTrailerCount(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)));
}

NTSTATUS ResponseGetHeader(
    const Response* response,
    const char* name,
    SIZE_T nameLength,
    const char** value,
    SIZE_T* valueLength) noexcept
{
    return ::wknet::session::KhResponseGetHeader(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)),
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
    return ::wknet::session::KhResponseGetHeaderAt(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)),
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
    return ::wknet::session::KhResponseGetTrailer(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)),
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
    return ::wknet::session::KhResponseGetTrailerAt(
        const_cast<::wknet::session::KH_RESPONSE>(detail::ToApiResponseConst(response)),
        index,
        name,
        nameLength,
        value,
        valueLength);
}

void ResponseRelease(Response* response) noexcept
{
    ::wknet::session::KhResponseRelease(detail::ToApiResponse(response));
}
}
