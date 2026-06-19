#include <KernelHttp/khttp/Request.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace khttp
{
namespace
{
    bool IsValidMethod(Method method) noexcept
    {
        switch (method) {
        case Method::Get:
        case Method::Post:
        case Method::Put:
        case Method::Patch:
        case Method::Delete:
        case Method::Head:
        case Method::Options:
        case Method::Connect:
            return true;
        default:
            return false;
        }
    }
}

NTSTATUS RequestCreate(Session* session, Request** out) noexcept
{
    if (out != nullptr) {
        *out = nullptr;
    }
    ::KernelHttp::engine::KH_REQUEST apiRequest = nullptr;
    NTSTATUS status = ::KernelHttp::engine::KhHttpRequestCreate(detail::ToApiSession(session), &apiRequest);
    if (NT_SUCCESS(status) && out != nullptr) {
        *out = detail::FromApiRequest(apiRequest);
    }
    return status;
}

void RequestRelease(Request* request) noexcept
{
    ::KernelHttp::engine::KhHttpRequestRelease(detail::ToApiRequest(request));
}

NTSTATUS RequestSetUrl(Request* request, const char* url, SIZE_T urlLength) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetUrl(detail::ToApiRequest(request), url, urlLength);
}

NTSTATUS RequestSetMethod(Request* request, Method method) noexcept
{
    if (!IsValidMethod(method)) {
        return STATUS_INVALID_PARAMETER;
    }

    return ::KernelHttp::engine::KhHttpRequestSetMethod(detail::ToApiRequest(request), detail::ToApiMethod(method));
}

NTSTATUS RequestSetHeader(
    Request* request,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetHeader(detail::ToApiRequest(request), name, nameLength, value, valueLength);
}

NTSTATUS RequestSetBody(Request* request, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetBody(detail::ToApiRequest(request), data, dataLength);
}

NTSTATUS RequestSetBodyMode(Request* request, RequestBodyMode mode) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetBodyMode(detail::ToApiRequest(request), detail::ToApiRequestBodyMode(mode));
}

NTSTATUS RequestAddTrailer(
    Request* request,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestAddTrailer(detail::ToApiRequest(request), name, nameLength, value, valueLength);
}

NTSTATUS RequestClearBody(Request* request) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestClearBody(detail::ToApiRequest(request));
}

NTSTATUS RequestSetTextBody(
    Request* request,
    const char* text,
    SIZE_T textLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetTextBody(
        detail::ToApiRequest(request),
        text,
        textLength,
        contentType,
        contentTypeLength);
}

NTSTATUS RequestSetJsonBody(Request* request, const char* json, SIZE_T jsonLength) noexcept
{
    static const char kJsonContentType[] = "application/json; charset=utf-8";
    constexpr SIZE_T kJsonContentTypeLength = sizeof(kJsonContentType) - 1;
    return ::KernelHttp::engine::KhHttpRequestSetRawBody(
        detail::ToApiRequest(request),
        reinterpret_cast<const UCHAR*>(json),
        jsonLength,
        kJsonContentType,
        kJsonContentTypeLength);
}

NTSTATUS RequestSetRawBody(
    Request* request,
    const UCHAR* data,
    SIZE_T dataLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetRawBody(
        detail::ToApiRequest(request),
        data,
        dataLength,
        contentType,
        contentTypeLength);
}

NTSTATUS RequestSetFormBody(Request* request, const NameValuePair* pairs, SIZE_T pairCount) noexcept
{
    if (pairs == nullptr || pairCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (pairCount > 16) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ::KernelHttp::HeapArray<::KernelHttp::engine::KhNameValuePair> apiPairs(16);
    if (!apiPairs.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (SIZE_T index = 0; index < pairCount; ++index) {
        apiPairs[index].Name = pairs[index].Name;
        apiPairs[index].NameLength = pairs[index].NameLength;
        apiPairs[index].Value = pairs[index].Value;
        apiPairs[index].ValueLength = pairs[index].ValueLength;
    }
    return ::KernelHttp::engine::KhHttpRequestSetUrlEncodedBody(detail::ToApiRequest(request), apiPairs.Get(), pairCount);
}

NTSTATUS RequestSetMultipartBody(Request* request, const MultipartPart* parts, SIZE_T partCount) noexcept
{
    if (parts == nullptr || partCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (partCount > 16) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ::KernelHttp::HeapArray<::KernelHttp::engine::KhMultipartFormDataPart> apiParts(16);
    if (!apiParts.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (SIZE_T index = 0; index < partCount; ++index) {
        apiParts[index].Kind = detail::ToApiBodyPartKind(parts[index].Kind);
        apiParts[index].Name = parts[index].Name;
        apiParts[index].NameLength = parts[index].NameLength;
        apiParts[index].Value = parts[index].Value;
        apiParts[index].ValueLength = parts[index].ValueLength;
        apiParts[index].Data = parts[index].Data;
        apiParts[index].DataLength = parts[index].DataLength;
        apiParts[index].FilePath = parts[index].FilePath;
        apiParts[index].FilePathLength = parts[index].FilePathLength;
        apiParts[index].FileName = parts[index].FileName;
        apiParts[index].FileNameLength = parts[index].FileNameLength;
        apiParts[index].ContentType = parts[index].ContentType;
        apiParts[index].ContentTypeLength = parts[index].ContentTypeLength;
    }
    return ::KernelHttp::engine::KhHttpRequestSetMultipartFormDataBody(detail::ToApiRequest(request), apiParts.Get(), partCount);
}

NTSTATUS RequestSetFileBody(
    Request* request,
    const char* filePath,
    SIZE_T filePathLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetFileBody(
        detail::ToApiRequest(request),
        filePath,
        filePathLength,
        contentType,
        contentTypeLength);
}

NTSTATUS RequestSetTls(Request* request, const TlsConfig* config) noexcept
{
    if (config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    ::KernelHttp::engine::KhTlsOptions options = {};
    detail::FillApiTlsOptions(*config, options);
    return ::KernelHttp::engine::KhHttpRequestSetTlsOptions(detail::ToApiRequest(request), &options);
}

NTSTATUS RequestSetConnPolicy(Request* request, ConnPolicy policy) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetConnectionPolicy(detail::ToApiRequest(request), detail::ToApiConnPolicy(policy));
}

NTSTATUS RequestSetAddressFamily(Request* request, AddressFamily family) noexcept
{
    return ::KernelHttp::engine::KhHttpRequestSetAddressFamily(detail::ToApiRequest(request), detail::ToApiAddressFamily(family));
}
}
