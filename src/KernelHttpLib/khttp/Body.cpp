#include <KernelHttp/khttp/Body.h>
#include <KernelHttp/khttp/Detail.h>

namespace khttp
{
namespace
{
    constexpr const char* JsonContentType = "application/json; charset=utf-8";

    SIZE_T StringLength(const char* text) noexcept
    {
        if (text == nullptr) {
            return 0;
        }
        SIZE_T length = 0;
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    char* CopyText(const char* text, SIZE_T length) noexcept
    {
        if (text == nullptr && length != 0) {
            return nullptr;
        }
        char* copy = ::KernelHttp::AllocateNonPagedArray<char>(length + 1);
        if (copy == nullptr) {
            return nullptr;
        }
        if (length != 0) {
            RtlCopyMemory(copy, text, length);
        }
        copy[length] = '\0';
        return copy;
    }

    UCHAR* CopyBytes(const UCHAR* data, SIZE_T length) noexcept
    {
        if (data == nullptr && length != 0) {
            return nullptr;
        }
        if (length == 0) {
            return nullptr;
        }
        UCHAR* copy = ::KernelHttp::AllocateNonPagedArray<UCHAR>(length);
        if (copy == nullptr) {
            return nullptr;
        }
        RtlCopyMemory(copy, data, length);
        return copy;
    }

    bool IsValidHeaderName(const char* name, SIZE_T nameLength) noexcept
    {
        if (name == nullptr || nameLength == 0 || nameLength > ::KernelHttp::engine::KhMaxHeaderNameLength) {
            return false;
        }
        for (SIZE_T index = 0; index < nameLength; ++index) {
            const unsigned char value = static_cast<unsigned char>(name[index]);
            const bool alpha = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
            const bool digit = value >= '0' && value <= '9';
            const bool token = alpha || digit || value == '!' || value == '#' || value == '$' ||
                value == '%' || value == '&' || value == '\'' || value == '*' || value == '+' ||
                value == '-' || value == '.' || value == '^' || value == '_' || value == '`' ||
                value == '|' || value == '~';
            if (!token) {
                return false;
            }
        }
        return true;
    }

    bool IsValidHeaderValue(const char* value, SIZE_T valueLength) noexcept
    {
        if (value == nullptr && valueLength != 0) {
            return false;
        }
        if (valueLength > ::KernelHttp::engine::KhMaxHeaderValueLength) {
            return false;
        }
        for (SIZE_T index = 0; index < valueLength; ++index) {
            const unsigned char ch = static_cast<unsigned char>(value[index]);
            if (value[index] != '\t' && (ch < 0x20 || ch == 0x7f)) {
                return false;
            }
        }
        return true;
    }

    bool EqualsLiteralIgnoreCase(const char* left, SIZE_T leftLength, const char* literal) noexcept
    {
        const SIZE_T rightLength = StringLength(literal);
        if (left == nullptr || leftLength != rightLength) {
            return false;
        }
        for (SIZE_T index = 0; index < leftLength; ++index) {
            char a = left[index];
            char b = literal[index];
            if (a >= 'A' && a <= 'Z') {
                a = static_cast<char>(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = static_cast<char>(b - 'A' + 'a');
            }
            if (a != b) {
                return false;
            }
        }
        return true;
    }

    bool IsForbiddenTrailer(const char* name, SIZE_T nameLength) noexcept
    {
        return EqualsLiteralIgnoreCase(name, nameLength, "Content-Length") ||
            EqualsLiteralIgnoreCase(name, nameLength, "Transfer-Encoding") ||
            EqualsLiteralIgnoreCase(name, nameLength, "Host") ||
            EqualsLiteralIgnoreCase(name, nameLength, "Authorization") ||
            EqualsLiteralIgnoreCase(name, nameLength, "Proxy-Authorization") ||
            EqualsLiteralIgnoreCase(name, nameLength, "Cookie") ||
            EqualsLiteralIgnoreCase(name, nameLength, "Set-Cookie");
    }

    NTSTATUS AllocateBody(Body** body) noexcept
    {
        if (body != nullptr) {
            *body = nullptr;
        }
        if (body == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        auto* created = ::KernelHttp::AllocateNonPagedObject<Body>();
        if (created == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        *body = created;
        return STATUS_SUCCESS;
    }

    NTSTATUS CreateRawBody(
        const UCHAR* data,
        SIZE_T dataLength,
        const char* contentType,
        SIZE_T contentTypeLength,
        bool copy,
        detail::BodyStorageKind kind,
        Body** body) noexcept
    {
        if ((data == nullptr && dataLength != 0) ||
            (contentType == nullptr && contentTypeLength != 0) ||
            !IsValidHeaderValue(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        Body* created = nullptr;
        NTSTATUS status = AllocateBody(&created);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        created->Kind = kind;
        created->OwnsData = copy && dataLength != 0;
        if (copy && dataLength != 0) {
            created->Data = CopyBytes(data, dataLength);
            if (created->Data == nullptr) {
                BodyRelease(created);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        else {
            created->Data = data;
        }
        created->DataLength = dataLength;

        if (contentType != nullptr) {
            created->ContentType = CopyText(contentType, contentTypeLength);
            if (created->ContentType == nullptr) {
                BodyRelease(created);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            created->ContentTypeLength = contentTypeLength;
        }

        *body = created;
        return STATUS_SUCCESS;
    }
}

NTSTATUS BodyCreateBytes(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept
{
    return BodyCreateBytesEx(data, dataLength, body);
}

NTSTATUS BodyCreateBytesEx(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept
{
    return CreateRawBody(data, dataLength, nullptr, 0, false, detail::BodyStorageKind::Bytes, body);
}

NTSTATUS BodyCreateBytesCopy(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept
{
    return BodyCreateBytesCopyEx(data, dataLength, body);
}

NTSTATUS BodyCreateBytesCopyEx(const UCHAR* data, SIZE_T dataLength, Body** body) noexcept
{
    return CreateRawBody(data, dataLength, nullptr, 0, true, detail::BodyStorageKind::Bytes, body);
}

NTSTATUS BodyCreateText(const char* text, SIZE_T textLength, const char* contentType, Body** body) noexcept
{
    return BodyCreateTextEx(text, textLength, contentType, StringLength(contentType), body);
}

NTSTATUS BodyCreateTextEx(const char* text, SIZE_T textLength, const char* contentType, SIZE_T contentTypeLength, Body** body) noexcept
{
    return CreateRawBody(
        reinterpret_cast<const UCHAR*>(text),
        textLength,
        contentType,
        contentTypeLength,
        false,
        detail::BodyStorageKind::Text,
        body);
}

NTSTATUS BodyCreateTextCopy(const char* text, SIZE_T textLength, const char* contentType, Body** body) noexcept
{
    return BodyCreateTextCopyEx(text, textLength, contentType, StringLength(contentType), body);
}

NTSTATUS BodyCreateTextCopyEx(const char* text, SIZE_T textLength, const char* contentType, SIZE_T contentTypeLength, Body** body) noexcept
{
    return CreateRawBody(
        reinterpret_cast<const UCHAR*>(text),
        textLength,
        contentType,
        contentTypeLength,
        true,
        detail::BodyStorageKind::Text,
        body);
}

NTSTATUS BodyCreateJson(const char* json, SIZE_T jsonLength, Body** body) noexcept
{
    return BodyCreateJsonEx(json, jsonLength, body);
}

NTSTATUS BodyCreateJsonEx(const char* json, SIZE_T jsonLength, Body** body) noexcept
{
    return CreateRawBody(
        reinterpret_cast<const UCHAR*>(json),
        jsonLength,
        JsonContentType,
        StringLength(JsonContentType),
        false,
        detail::BodyStorageKind::Json,
        body);
}

NTSTATUS BodyCreateJsonCopy(const char* json, SIZE_T jsonLength, Body** body) noexcept
{
    return BodyCreateJsonCopyEx(json, jsonLength, body);
}

NTSTATUS BodyCreateJsonCopyEx(const char* json, SIZE_T jsonLength, Body** body) noexcept
{
    return CreateRawBody(
        reinterpret_cast<const UCHAR*>(json),
        jsonLength,
        JsonContentType,
        StringLength(JsonContentType),
        true,
        detail::BodyStorageKind::Json,
        body);
}

NTSTATUS BodyCreateForm(const NameValuePair* pairs, SIZE_T pairCount, Body** body) noexcept
{
    if (pairs == nullptr || pairCount == 0 || pairCount > ::KernelHttp::engine::KhMaxHeadersPerRequest) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* created = nullptr;
    NTSTATUS status = AllocateBody(&created);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    created->FormPairs = ::KernelHttp::AllocateNonPagedArray<NameValuePair>(pairCount);
    if (created->FormPairs == nullptr) {
        BodyRelease(created);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    created->Kind = detail::BodyStorageKind::Form;
    created->FormPairCount = pairCount;
    for (SIZE_T index = 0; index < pairCount; ++index) {
        created->FormPairs[index] = pairs[index];
    }
    *body = created;
    return STATUS_SUCCESS;
}

NTSTATUS BodyCreateMultipart(const MultipartPart* parts, SIZE_T partCount, Body** body) noexcept
{
    if (parts == nullptr || partCount == 0 || partCount > ::KernelHttp::engine::KhMaxHeadersPerRequest) {
        return STATUS_INVALID_PARAMETER;
    }
    for (SIZE_T index = 0; index < partCount; ++index) {
        if (!IsValidHeaderValue(parts[index].ContentType, parts[index].ContentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    Body* created = nullptr;
    NTSTATUS status = AllocateBody(&created);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    created->MultipartParts = ::KernelHttp::AllocateNonPagedArray<MultipartPart>(partCount);
    if (created->MultipartParts == nullptr) {
        BodyRelease(created);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    created->Kind = detail::BodyStorageKind::Multipart;
    created->MultipartPartCount = partCount;
    for (SIZE_T index = 0; index < partCount; ++index) {
        created->MultipartParts[index] = parts[index];
    }
    *body = created;
    return STATUS_SUCCESS;
}

NTSTATUS BodyCreateFile(const char* filePath, const char* contentType, Body** body) noexcept
{
    return BodyCreateFileEx(filePath, StringLength(filePath), contentType, StringLength(contentType), body);
}

NTSTATUS BodyCreateFileEx(
    const char* filePath,
    SIZE_T filePathLength,
    const char* contentType,
    SIZE_T contentTypeLength,
    Body** body) noexcept
{
    if (filePath == nullptr || filePathLength == 0 ||
        (contentType == nullptr && contentTypeLength != 0) ||
        !IsValidHeaderValue(contentType, contentTypeLength)) {
        return STATUS_INVALID_PARAMETER;
    }
    Body* created = nullptr;
    NTSTATUS status = AllocateBody(&created);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    created->FilePath = CopyText(filePath, filePathLength);
    if (created->FilePath == nullptr) {
        BodyRelease(created);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    created->FilePathLength = filePathLength;
    if (contentType != nullptr) {
        created->ContentType = CopyText(contentType, contentTypeLength);
        if (created->ContentType == nullptr) {
            BodyRelease(created);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        created->ContentTypeLength = contentTypeLength;
    }
    created->Kind = detail::BodyStorageKind::File;
    *body = created;
    return STATUS_SUCCESS;
}

NTSTATUS BodyCreateStream(
    RequestBodyReadCallback callback,
    void* context,
    SIZE_T contentLength,
    bool contentLengthKnown,
    const char* contentType,
    SIZE_T contentTypeLength,
    Body** body) noexcept
{
    if (callback == nullptr ||
        (contentType == nullptr && contentTypeLength != 0) ||
        !IsValidHeaderValue(contentType, contentTypeLength)) {
        return STATUS_INVALID_PARAMETER;
    }

    Body* created = nullptr;
    NTSTATUS status = AllocateBody(&created);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (contentType != nullptr) {
        created->ContentType = CopyText(contentType, contentTypeLength);
        if (created->ContentType == nullptr) {
            BodyRelease(created);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        created->ContentTypeLength = contentTypeLength;
    }

    created->Kind = detail::BodyStorageKind::Stream;
    created->Mode = contentLengthKnown ? RequestBodyMode::ContentLength : RequestBodyMode::Chunked;
    created->StreamCallback = callback;
    created->StreamContext = context;
    created->StreamContentLength = contentLength;
    created->StreamContentLengthKnown = contentLengthKnown;
    *body = created;
    return STATUS_SUCCESS;
}

NTSTATUS BodySetMode(Body* body, RequestBodyMode mode) noexcept
{
    if (body == nullptr || body->Magic != detail::KhHighBodyMagic) {
        return STATUS_INVALID_PARAMETER;
    }
    if (mode != RequestBodyMode::ContentLength && mode != RequestBodyMode::Chunked) {
        return STATUS_INVALID_PARAMETER;
    }
    body->Mode = mode;
    return STATUS_SUCCESS;
}

NTSTATUS BodyAddTrailer(Body* body, const char* name, const char* value) noexcept
{
    return BodyAddTrailerEx(body, name, StringLength(name), value, StringLength(value));
}

NTSTATUS BodyAddTrailerEx(Body* body, const char* name, SIZE_T nameLength, const char* value, SIZE_T valueLength) noexcept
{
    if (body == nullptr || body->Magic != detail::KhHighBodyMagic ||
        !IsValidHeaderName(name, nameLength) ||
        !IsValidHeaderValue(value, valueLength)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (IsForbiddenTrailer(name, nameLength)) {
        return STATUS_NOT_SUPPORTED;
    }
    if (body->TrailerCount >= ::KernelHttp::engine::KhMaxHeadersPerRequest) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    char* nameCopy = CopyText(name, nameLength);
    if (nameCopy == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    char* valueCopy = CopyText(value, valueLength);
    if (valueCopy == nullptr) {
        ::KernelHttp::FreeNonPagedArray(nameCopy);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    detail::StoredHeader& trailer = body->Trailers[body->TrailerCount++];
    trailer.Name = nameCopy;
    trailer.NameLength = nameLength;
    trailer.Value = valueCopy;
    trailer.ValueLength = valueLength;
    return STATUS_SUCCESS;
}

void BodyRelease(Body* body) noexcept
{
    if (body == nullptr || body->Magic != detail::KhHighBodyMagic) {
        return;
    }
    if (body->OwnsData) {
        ::KernelHttp::FreeNonPagedArray(const_cast<UCHAR*>(body->Data));
    }
    ::KernelHttp::FreeNonPagedArray(body->ContentType);
    ::KernelHttp::FreeNonPagedArray(body->FormPairs);
    ::KernelHttp::FreeNonPagedArray(body->MultipartParts);
    ::KernelHttp::FreeNonPagedArray(body->FilePath);
    for (SIZE_T index = 0; index < body->TrailerCount; ++index) {
        ::KernelHttp::FreeNonPagedArray(body->Trailers[index].Name);
        ::KernelHttp::FreeNonPagedArray(body->Trailers[index].Value);
        body->Trailers[index] = {};
    }
    body->Magic = 0;
    ::KernelHttp::FreeNonPagedObject(body);
}
}
