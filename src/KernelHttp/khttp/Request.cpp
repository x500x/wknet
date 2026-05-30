#include <KernelHttp/khttp/Request.h>
#include <KernelHttp/khttp/Detail.h>
#include <KernelHttp/engine/Engine.h>

namespace KernelHttp
{
namespace khttp
{
NTSTATUS RequestCreate(Session* session, Request** out) noexcept
{
    if (out != nullptr) {
        *out = nullptr;
    }
    engine::KH_REQUEST apiRequest = nullptr;
    NTSTATUS status = engine::KhHttpRequestCreate(detail::ToApiSession(session), &apiRequest);
    if (NT_SUCCESS(status) && out != nullptr) {
        *out = detail::FromApiRequest(apiRequest);
    }
    return status;
}

void RequestRelease(Request* request) noexcept
{
    engine::KhHttpRequestRelease(detail::ToApiRequest(request));
}

NTSTATUS RequestSetUrl(Request* request, const char* url, SIZE_T urlLength) noexcept
{
    return engine::KhHttpRequestSetUrl(detail::ToApiRequest(request), url, urlLength);
}

NTSTATUS RequestSetMethod(Request* request, Method method) noexcept
{
    return engine::KhHttpRequestSetMethod(detail::ToApiRequest(request), detail::ToApiMethod(method));
}

NTSTATUS RequestSetHeader(
    Request* request,
    const char* name,
    SIZE_T nameLength,
    const char* value,
    SIZE_T valueLength) noexcept
{
    return engine::KhHttpRequestSetHeader(detail::ToApiRequest(request), name, nameLength, value, valueLength);
}

NTSTATUS RequestSetBody(Request* request, const UCHAR* data, SIZE_T dataLength) noexcept
{
    return engine::KhHttpRequestSetBody(detail::ToApiRequest(request), data, dataLength);
}

NTSTATUS RequestClearBody(Request* request) noexcept
{
    return engine::KhHttpRequestClearBody(detail::ToApiRequest(request));
}

NTSTATUS RequestSetTextBody(
    Request* request,
    const char* text,
    SIZE_T textLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return engine::KhHttpRequestSetTextBody(
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
    return engine::KhHttpRequestSetRawBody(
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
    return engine::KhHttpRequestSetRawBody(
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

    engine::KhNameValuePair apiPairs[16] = {};
    for (SIZE_T index = 0; index < pairCount; ++index) {
        apiPairs[index].Name = pairs[index].Name;
        apiPairs[index].NameLength = pairs[index].NameLength;
        apiPairs[index].Value = pairs[index].Value;
        apiPairs[index].ValueLength = pairs[index].ValueLength;
    }
    return engine::KhHttpRequestSetUrlEncodedBody(detail::ToApiRequest(request), apiPairs, pairCount);
}

NTSTATUS RequestSetMultipartBody(Request* request, const MultipartPart* parts, SIZE_T partCount) noexcept
{
    if (parts == nullptr || partCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (partCount > 16) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    engine::KhMultipartFormDataPart apiParts[16] = {};
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
    return engine::KhHttpRequestSetMultipartFormDataBody(detail::ToApiRequest(request), apiParts, partCount);
}

NTSTATUS RequestSetFileBody(
    Request* request,
    const char* filePath,
    SIZE_T filePathLength,
    const char* contentType,
    SIZE_T contentTypeLength) noexcept
{
    return engine::KhHttpRequestSetFileBody(
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
    engine::KhTlsOptions options = {};
    detail::FillApiTlsOptions(*config, options);
    return engine::KhHttpRequestSetTlsOptions(detail::ToApiRequest(request), &options);
}

NTSTATUS RequestSetConnPolicy(Request* request, ConnPolicy policy) noexcept
{
    return engine::KhHttpRequestSetConnectionPolicy(detail::ToApiRequest(request), detail::ToApiConnPolicy(policy));
}

NTSTATUS RequestSetAddressFamily(Request* request, AddressFamily family) noexcept
{
    return engine::KhHttpRequestSetAddressFamily(detail::ToApiRequest(request), detail::ToApiAddressFamily(family));
}
}
}
