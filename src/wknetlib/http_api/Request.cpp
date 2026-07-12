#include <wknet/http/Request.h>
#include "session/detail/HttpHandles.h"
#include <wknet/http/Body.h>
#include <wknet/http/Headers.h>
#include <wknet/http/Options.h>
#include "session/Engine.h"

namespace wknet::http {
#if defined(WKNET_USER_MODE_TEST)
namespace
{
    char* CopyText(const char* text, SIZE_T length) noexcept
    {
        if (text == nullptr || length == 0) {
            return nullptr;
        }
        char* copy = ::wknet::AllocateNonPagedArray<char>(length + 1);
        if (copy == nullptr) {
            return nullptr;
        }
        RtlCopyMemory(copy, text, length);
        copy[length] = '\0';
        return copy;
    }

    bool IsValidRequestBuilder(Request* request) noexcept
    {
        return request != nullptr &&
            request->Magic == detail::HighRequestMagic &&
            request->Closed == 0;
    }

    void ReleaseBuilderState(Request* request) noexcept
    {
        if (request == nullptr) {
            return;
        }
        ::wknet::FreeNonPagedArray(request->BuilderUrl);
        request->BuilderUrl = nullptr;
        request->BuilderUrlLength = 0;
        HeadersRelease(request->BuilderHeaders);
        request->BuilderHeaders = nullptr;
        BodyRelease(request->BuilderBody);
        request->BuilderBody = nullptr;
        SendOptionsRelease(request->BuilderOptions);
        request->BuilderOptions = nullptr;
    }

    NTSTATUS EnsureBuilderOptions(Request* request) noexcept
    {
        if (request->BuilderOptions != nullptr) {
            return STATUS_SUCCESS;
        }
        return SendOptionsCreate(&request->BuilderOptions);
    }

    NTSTATUS AppendGeneratedByte(
        char* destination,
        SIZE_T capacity,
        SIZE_T* offset,
        char value) noexcept
    {
        if (destination == nullptr || offset == nullptr || *offset >= capacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        destination[*offset] = value;
        ++(*offset);
        return STATUS_SUCCESS;
    }

    NTSTATUS AppendGeneratedLiteral(
        char* destination,
        SIZE_T capacity,
        SIZE_T* offset,
        const char* literal) noexcept
    {
        if (literal == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T index = 0; literal[index] != '\0'; ++index) {
            NTSTATUS status = AppendGeneratedByte(destination, capacity, offset, literal[index]);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS AppendGeneratedUnsigned(
        char* destination,
        SIZE_T capacity,
        SIZE_T* offset,
        ULONGLONG value) noexcept
    {
        ULONGLONG divisor = 1;
        while ((value / divisor) >= 10) {
            divisor *= 10;
        }
        do {
            const char digit = static_cast<char>('0' + ((value / divisor) % 10));
            NTSTATUS status = AppendGeneratedByte(destination, capacity, offset, digit);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            divisor /= 10;
        } while (divisor != 0);
        return STATUS_SUCCESS;
    }
}
#endif

NTSTATUS RequestCreate(Session* session, Request** out) noexcept
{
    if (out != nullptr) {
        *out = nullptr;
    }
    if (out == nullptr || !detail::AddSessionRef(session)) {
        return STATUS_INVALID_PARAMETER;
    }

#if defined(WKNET_USER_MODE_TEST)
    ::wknet::session::RequestHandle validationRequest = nullptr;
    NTSTATUS validationStatus = ::wknet::session::HttpRequestCreate(session->Engine, &validationRequest);
    if (!NT_SUCCESS(validationStatus)) {
        detail::ReleaseSessionRef(session);
        return validationStatus;
    }
    ::wknet::session::HttpRequestRelease(validationRequest);
#endif

    auto* request = ::wknet::AllocateNonPagedObject<Request>();
    if (request == nullptr) {
        detail::ReleaseSessionRef(session);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    request->Parent = session;
    *out = request;
    return STATUS_SUCCESS;
}

void RequestRelease(Request* request) noexcept
{
    if (request == nullptr || request->Magic != detail::HighRequestMagic) {
        return;
    }
    if (request->Closed != 0) {
        return;
    }

#if defined(WKNET_USER_MODE_TEST)
    ReleaseBuilderState(request);
#endif

    request->Closed = 1;
    Session* parent = request->Parent;
    request->Parent = nullptr;
    request->Magic = 0;
    ::wknet::FreeNonPagedObject(request);

    if (detail::ReleaseSessionRef(parent)) {
        detail::FreeClosedSession(parent);
    }
}

#if defined(WKNET_USER_MODE_TEST)
NTSTATUS RequestSetUrl(Request* request, const char* url, SIZE_T urlLength) noexcept
{
    if (!IsValidRequestBuilder(request) || url == nullptr || urlLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ::wknet::session::RequestHandle validationRequest = nullptr;
    NTSTATUS status = ::wknet::session::HttpRequestCreate(request->Parent->Engine, &validationRequest);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ::wknet::session::HttpRequestSetUrl(validationRequest, url, urlLength);
    ::wknet::session::HttpRequestRelease(validationRequest);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    char* copy = CopyText(url, urlLength);
    if (copy == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ::wknet::FreeNonPagedArray(request->BuilderUrl);
    request->BuilderUrl = copy;
    request->BuilderUrlLength = urlLength;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetMethod(Request* request, Method method) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    switch (method) {
    case Method::Get:
    case Method::Post:
    case Method::Put:
    case Method::Patch:
    case Method::Delete:
    case Method::Head:
    case Method::Options:
    case Method::Connect:
    case Method::Trace:
        request->BuilderMethod = method;
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS RequestSetHeader(Request* request, const char* name, SIZE_T nameLength, const char* value, SIZE_T valueLength) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }

    ::wknet::session::RequestHandle validationRequest = nullptr;
    NTSTATUS status = ::wknet::session::HttpRequestCreate(request->Parent->Engine, &validationRequest);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ::wknet::session::HttpRequestSetHeader(validationRequest, name, nameLength, value, valueLength);
    ::wknet::session::HttpRequestRelease(validationRequest);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (request->BuilderHeaders == nullptr) {
        status = HeadersCreate(&request->BuilderHeaders);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (request->BuilderHeaders->Count >= ::wknet::session::MaxHeadersPerRequest) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    char* nameCopy = CopyText(name, nameLength);
    if (nameCopy == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    char* valueCopy = nullptr;
    if (valueLength != 0) {
        valueCopy = CopyText(value, valueLength);
        if (valueCopy == nullptr) {
            ::wknet::FreeNonPagedArray(nameCopy);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    detail::StoredHeader& header = request->BuilderHeaders->Items[request->BuilderHeaders->Count++];
    header.Name = nameCopy;
    header.NameLength = nameLength;
    header.Value = valueCopy;
    header.ValueLength = valueLength;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetRangeBytes(Request* request, ULONGLONG firstByte, ULONGLONG lastByte, bool hasLastByte) noexcept
{
    if (!IsValidRequestBuilder(request) || (hasLastByte && lastByte < firstByte)) {
        return STATUS_INVALID_PARAMETER;
    }

    wknet::HeapArray<char> value(64);
    if (!value.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SIZE_T offset = 0;
    NTSTATUS status = AppendGeneratedLiteral(value.Get(), value.Count(), &offset, "bytes=");
    if (NT_SUCCESS(status)) {
        status = AppendGeneratedUnsigned(value.Get(), value.Count(), &offset, firstByte);
    }
    if (NT_SUCCESS(status)) {
        status = AppendGeneratedByte(value.Get(), value.Count(), &offset, '-');
    }
    if (NT_SUCCESS(status) && hasLastByte) {
        status = AppendGeneratedUnsigned(value.Get(), value.Count(), &offset, lastByte);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return RequestSetHeader(request, "Range", 5, value.Get(), offset);
}

NTSTATUS RequestSetRangeSuffix(Request* request, ULONGLONG suffixLength) noexcept
{
    if (!IsValidRequestBuilder(request) || suffixLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    wknet::HeapArray<char> value(64);
    if (!value.IsValid()) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SIZE_T offset = 0;
    NTSTATUS status = AppendGeneratedLiteral(value.Get(), value.Count(), &offset, "bytes=-");
    if (NT_SUCCESS(status)) {
        status = AppendGeneratedUnsigned(value.Get(), value.Count(), &offset, suffixLength);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return RequestSetHeader(request, "Range", 5, value.Get(), offset);
}

NTSTATUS RequestSetIfMatch(Request* request, const char* value, SIZE_T valueLength) noexcept
{
    return RequestSetHeader(request, "If-Match", 8, value, valueLength);
}

NTSTATUS RequestSetIfNoneMatch(Request* request, const char* value, SIZE_T valueLength) noexcept
{
    return RequestSetHeader(request, "If-None-Match", 13, value, valueLength);
}

NTSTATUS RequestSetIfModifiedSince(Request* request, const char* value, SIZE_T valueLength) noexcept
{
    return RequestSetHeader(request, "If-Modified-Since", 17, value, valueLength);
}

NTSTATUS RequestSetIfUnmodifiedSince(Request* request, const char* value, SIZE_T valueLength) noexcept
{
    return RequestSetHeader(request, "If-Unmodified-Since", 19, value, valueLength);
}

NTSTATUS RequestSetBody(Request* request, const UCHAR* data, SIZE_T dataLength) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* body = nullptr;
    NTSTATUS status = BodyCreateBytes(data, dataLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = body;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetBodyMode(Request* request, RequestBodyMode mode) noexcept
{
    if (!IsValidRequestBuilder(request) || request->BuilderBody == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return BodySetMode(request->BuilderBody, mode);
}

NTSTATUS RequestAddTrailer(Request* request, const char* name, SIZE_T nameLength, const char* value, SIZE_T valueLength) noexcept
{
    if (!IsValidRequestBuilder(request) || request->BuilderBody == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    return BodyAddTrailerEx(request->BuilderBody, name, nameLength, value, valueLength);
}

NTSTATUS RequestClearBody(Request* request) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = nullptr;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetTextBody(Request* request, const char* text, SIZE_T textLength, const char* contentType, SIZE_T contentTypeLength) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* body = nullptr;
    NTSTATUS status = BodyCreateTextEx(text, textLength, contentType, contentTypeLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = body;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetJsonBody(Request* request, const char* json, SIZE_T jsonLength) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* body = nullptr;
    NTSTATUS status = BodyCreateJson(json, jsonLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = body;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetRawBody(Request* request, const UCHAR* data, SIZE_T dataLength, const char* contentType, SIZE_T contentTypeLength) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* body = nullptr;
    NTSTATUS status = BodyCreateBytes(data, dataLength, &body);
    if (NT_SUCCESS(status) && contentType != nullptr) {
        Headers* headers = request->BuilderHeaders;
        if (headers == nullptr) {
            status = HeadersCreate(&headers);
            if (NT_SUCCESS(status)) {
                request->BuilderHeaders = headers;
            }
        }
        if (NT_SUCCESS(status)) {
            status = HeadersAddEx(headers, "Content-Type", 12, contentType, contentTypeLength);
        }
    }
    if (!NT_SUCCESS(status)) {
        BodyRelease(body);
        return status;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = body;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetFormBody(Request* request, const NameValuePair* pairs, SIZE_T pairCount) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* body = nullptr;
    NTSTATUS status = BodyCreateForm(pairs, pairCount, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = body;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetMultipartBody(Request* request, const MultipartPart* parts, SIZE_T partCount) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* body = nullptr;
    NTSTATUS status = BodyCreateMultipart(parts, partCount, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = body;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetFileBody(Request* request, const char* filePath, SIZE_T filePathLength, const char* contentType, SIZE_T contentTypeLength) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* body = nullptr;
    NTSTATUS status = BodyCreateFileEx(filePath, filePathLength, contentType, contentTypeLength, &body);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    BodyRelease(request->BuilderBody);
    request->BuilderBody = body;
    return STATUS_SUCCESS;
}

NTSTATUS RequestSetTls(Request* request, const TlsConfig* config) noexcept
{
    if (!IsValidRequestBuilder(request) || config == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = EnsureBuilderOptions(request);
    if (NT_SUCCESS(status)) {
        request->BuilderOptions->Tls = *config;
        request->BuilderOptions->HasTlsOverride = true;
    }
    return status;
}

NTSTATUS RequestSetConnPolicy(Request* request, ConnPolicy policy) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = EnsureBuilderOptions(request);
    if (NT_SUCCESS(status)) {
        request->BuilderOptions->ConnectionPolicy = policy;
    }
    return status;
}

NTSTATUS RequestSetAddressFamily(Request* request, AddressFamily family) noexcept
{
    if (!IsValidRequestBuilder(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = EnsureBuilderOptions(request);
    if (NT_SUCCESS(status)) {
        request->BuilderOptions->Family = family;
    }
    return status;
}
#endif
}
