#include "session/EnginePrivate.hpp"

namespace wknet
{
namespace session
{
    NTSTATUS HttpRequestCreate(SessionHandle session, RequestHandle* request) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *request = nullptr;

        SessionOperationScope sessionScope(session);
        if (!sessionScope.IsActive()) {
            return STATUS_INVALID_PARAMETER;
        }

        RequestHandle newRequest = AllocateRequestHandle();
        if (newRequest == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newRequest->Header = { HandleKind::Request, 0, nullptr };
        newRequest->Session = session;
        newRequest->Method = HttpMethod::Get;
        newRequest->Tls = session->Options.Tls;
        newRequest->InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeEvent(&newRequest->DrainEvent, NotificationEvent, TRUE);
#endif
        status = RegisterActiveRequestHandle(newRequest);
        if (!NT_SUCCESS(status)) {
            FreeHandle(newRequest);
            return status;
        }
        *request = newRequest;
        return STATUS_SUCCESS;
    }

    void HttpRequestRelease(RequestHandle request) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || request == nullptr) {
            return;
        }

        if (!TryCloseActiveRequestHandle(request)) {
            return;
        }

        WaitForRequestDrain(request);
        ReleaseRequestStorage(*request);
        FreeHandle(request);
    }

    NTSTATUS HttpRequestSetUrl(RequestHandle request, const char* url, SIZE_T urlLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || url == nullptr || urlLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        char* urlCopy = AllocateTextCopy(url, urlLength);
        if (urlCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        HeapObject<Request> parsed;
        if (!parsed.IsValid()) {
            FreeApiMemory(urlCopy);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS parseStatus = ParseUrlIntoRequest(*parsed.Get(), urlCopy, urlLength);
        if (!NT_SUCCESS(parseStatus)) {
            FreeApiMemory(urlCopy);
            return parseStatus;
        }

        FreeApiMemory(request->Url);
        request->Url = urlCopy;
        request->UrlLength = urlLength;
        RtlCopyMemory(request->Scheme, parsed->Scheme, sizeof(request->Scheme));
        request->SchemeLength = parsed->SchemeLength;
        RtlCopyMemory(request->Host, parsed->Host, sizeof(request->Host));
        request->HostLength = parsed->HostLength;
        RtlCopyMemory(request->Path, parsed->Path, sizeof(request->Path));
        request->PathLength = parsed->PathLength;
        request->Port = parsed->Port;

        if (!request->HasTlsOverride && TextEqualsLiteralIgnoreCase(request->Scheme, request->SchemeLength, "https")) {
            request->Tls.ServerName = request->Host;
            request->Tls.ServerNameLength = request->HostLength;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS HttpRequestSetMethod(RequestHandle request, HttpMethod method) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        switch (method) {
        case HttpMethod::Get:
        case HttpMethod::Post:
        case HttpMethod::Put:
        case HttpMethod::Patch:
        case HttpMethod::Delete:
        case HttpMethod::Head:
        case HttpMethod::Options:
        case HttpMethod::Connect:
        case HttpMethod::Trace:
            request->Method = method;
            return STATUS_SUCCESS;
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS HttpRequestSetHeader(
        RequestHandle request,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            name == nullptr ||
            nameLength == 0 ||
            (value == nullptr && valueLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (nameLength > MaxHeaderNameLength || valueLength > MaxHeaderValueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return AddStoredHeader(*request, name, nameLength, value, valueLength);
    }

    SIZE_T HeaderLiteralLength(const char* text) noexcept
    {
        SIZE_T length = 0;
        if (text == nullptr) {
            return 0;
        }
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    NTSTATUS AppendGeneratedByte(
        _Out_writes_(capacity) char* destination,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset,
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
        _Out_writes_(capacity) char* destination,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset,
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
        _Out_writes_(capacity) char* destination,
        SIZE_T capacity,
        _Inout_ SIZE_T* offset,
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

    NTSTATUS StoreGeneratedHeader(
        RequestHandle request,
        const char* name,
        const char* value,
        SIZE_T valueLength) noexcept
    {
        return HttpRequestSetHeader(
            request,
            name,
            HeaderLiteralLength(name),
            value,
            valueLength);
    }

    NTSTATUS HttpRequestSetRangeBytes(
        RequestHandle request,
        ULONGLONG firstByte,
        ULONGLONG lastByte,
        bool hasLastByte) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || (hasLastByte && lastByte < firstByte)) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> value(64);
        if (!value.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T offset = 0;
        status = AppendGeneratedLiteral(value.Get(), value.Count(), &offset, "bytes=");
        if (NT_SUCCESS(status)) {
            status = AppendGeneratedUnsigned(value.Get(), value.Count(), &offset, firstByte);
        }
        if (NT_SUCCESS(status)) {
            status = AppendGeneratedByte(value.Get(), value.Count(), &offset, '-');
        }
        if (NT_SUCCESS(status) && hasLastByte) {
            status = AppendGeneratedUnsigned(value.Get(), value.Count(), &offset, lastByte);
        }
        if (NT_SUCCESS(status) && offset < value.Count()) {
            value[offset] = '\0';
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return StoreGeneratedHeader(request, "Range", value.Get(), offset);
    }

    NTSTATUS HttpRequestSetRangeSuffix(RequestHandle request, ULONGLONG suffixLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || suffixLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> value(64);
        if (!value.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T offset = 0;
        status = AppendGeneratedLiteral(value.Get(), value.Count(), &offset, "bytes=-");
        if (NT_SUCCESS(status)) {
            status = AppendGeneratedUnsigned(value.Get(), value.Count(), &offset, suffixLength);
        }
        if (NT_SUCCESS(status) && offset < value.Count()) {
            value[offset] = '\0';
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return StoreGeneratedHeader(request, "Range", value.Get(), offset);
    }

    NTSTATUS HttpRequestSetIfMatch(RequestHandle request, const char* value, SIZE_T valueLength) noexcept
    {
        return StoreGeneratedHeader(request, "If-Match", value, valueLength);
    }

    NTSTATUS HttpRequestSetIfNoneMatch(RequestHandle request, const char* value, SIZE_T valueLength) noexcept
    {
        return StoreGeneratedHeader(request, "If-None-Match", value, valueLength);
    }

    NTSTATUS HttpRequestSetIfModifiedSince(RequestHandle request, const char* value, SIZE_T valueLength) noexcept
    {
        return StoreGeneratedHeader(request, "If-Modified-Since", value, valueLength);
    }

    NTSTATUS HttpRequestSetIfUnmodifiedSince(RequestHandle request, const char* value, SIZE_T valueLength) noexcept
    {
        return StoreGeneratedHeader(request, "If-Unmodified-Since", value, valueLength);
    }

    NTSTATUS HttpRequestSetBody(RequestHandle request, const UCHAR* body, SIZE_T bodyLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (body == nullptr && bodyLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        ReleaseOwnedBody(*request);
        request->Body = body;
        request->BodyLength = bodyLength;
        request->HasBody = body != nullptr || bodyLength != 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpRequestSetBodySource(
        RequestHandle request,
        RequestBodyReadCallback callback,
        void* context,
        SIZE_T contentLength,
        bool contentLengthKnown) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || callback == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ReleaseOwnedBody(*request);
        request->Body = nullptr;
        request->BodyLength = contentLengthKnown ? contentLength : 0;
        request->HasBody = true;
        request->BodyMode = contentLengthKnown ?
            RequestBodyMode::ContentLength :
            RequestBodyMode::Chunked;
        request->BodySourceCallback = callback;
        request->BodySourceContext = context;
        request->BodySourceContentLength = contentLength;
        request->BodySourceContentLengthKnown = contentLengthKnown;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpRequestSetBodyMode(RequestHandle request, RequestBodyMode mode) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (mode != RequestBodyMode::ContentLength &&
            mode != RequestBodyMode::Chunked) {
            return STATUS_INVALID_PARAMETER;
        }

        if (request->BodySourceCallback != nullptr &&
            mode == RequestBodyMode::ContentLength &&
            !request->BodySourceContentLengthKnown) {
            return STATUS_INVALID_PARAMETER;
        }

        request->BodyMode = mode;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpRequestAddTrailer(
        RequestHandle request,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            name == nullptr ||
            nameLength == 0 ||
            (value == nullptr && valueLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (nameLength > MaxHeaderNameLength || valueLength > MaxHeaderValueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        return AddStoredTrailer(*request, name, nameLength, value, valueLength);
    }

    NTSTATUS HttpRequestClearBody(RequestHandle request) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        ReleaseOwnedBody(*request);
        RemoveStoredHeadersByName(*request, "Content-Type");
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpRequestSetTextBody(
        RequestHandle request,
        const char* text,
        SIZE_T textLength,
        const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            (text == nullptr && textLength != 0) ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendOwnedText(*request, text, textLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        if (contentType == nullptr) {
            const http1::HttpText defaultType = http1::MakeText("text/plain; charset=utf-8");
            contentType = defaultType.Data;
            contentTypeLength = defaultType.Length;
        }

        return ReplaceContentType(*request, contentType, contentTypeLength);
    }

    NTSTATUS HttpRequestSetRawBody(
        RequestHandle request,
        const UCHAR* data,
        SIZE_T dataLength,
        const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            (data == nullptr && dataLength != 0) ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendOwnedBody(*request, data, dataLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        if (contentType != nullptr) {
            status = ReplaceContentType(*request, contentType, contentTypeLength);
        }

        return status;
    }

    NTSTATUS HttpRequestSetUrlEncodedBody(
        RequestHandle request,
        const NameValuePair* pairs,
        SIZE_T pairCount) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            pairs == nullptr ||
            pairCount == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < pairCount; ++index) {
            const NameValuePair& pair = pairs[index];
            if (pair.Name == nullptr ||
                pair.NameLength == 0 ||
                (pair.Value == nullptr && pair.ValueLength != 0)) {
                return STATUS_INVALID_PARAMETER;
            }
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < pairCount; ++index) {
            if (index != 0) {
                status = AppendOwnedLiteral(*request, "&");
                if (!NT_SUCCESS(status)) {
                    AbortOwnedBodyBuild(*request);
                    return status;
                }
            }

            status = AppendUrlEncodedText(*request, pairs[index].Name, pairs[index].NameLength);
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
            status = AppendOwnedLiteral(*request, "=");
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
            status = AppendUrlEncodedText(*request, pairs[index].Value, pairs[index].ValueLength);
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
        }

        const http1::HttpText contentType = http1::MakeText("application/x-www-form-urlencoded");
        return ReplaceContentType(*request, contentType.Data, contentType.Length);
    }

    NTSTATUS HttpRequestSetMultipartFormDataBody(
        RequestHandle request,
        const MultipartFormDataPart* parts,
        SIZE_T partCount) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            parts == nullptr ||
            partCount == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < partCount; ++index) {
            const MultipartFormDataPart& part = parts[index];
            if (part.Name == nullptr ||
                part.NameLength == 0 ||
                !IsOptionalTextValid(part.FileName, part.FileNameLength) ||
                !IsOptionalTextValid(part.ContentType, part.ContentTypeLength)) {
                return STATUS_INVALID_PARAMETER;
            }

            switch (part.Kind) {
            case RequestBodyPartKind::Field:
                if (part.Value == nullptr && part.ValueLength != 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                break;
            case RequestBodyPartKind::FileBytes:
                if ((part.Data == nullptr && part.DataLength != 0) ||
                    part.FileName == nullptr ||
                    part.FileNameLength == 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                break;
            case RequestBodyPartKind::FilePath:
                if (part.FilePath == nullptr || part.FilePathLength == 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                break;
            default:
                return STATUS_INVALID_PARAMETER;
            }
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T boundaryLength = 0;
        status = GenerateMultipartBoundary(*request, &boundaryLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        for (SIZE_T index = 0; index < partCount; ++index) {
            const MultipartFormDataPart& part = parts[index];
            const char* fileName = part.FileName;
            SIZE_T fileNameLength = part.FileNameLength;
            if (part.Kind == RequestBodyPartKind::FilePath && fileName == nullptr) {
                DeriveFileNameFromPath(part.FilePath, part.FilePathLength, &fileName, &fileNameLength);
                if (fileName == nullptr || fileNameLength == 0) {
                    AbortOwnedBodyBuild(*request);
                    return STATUS_INVALID_PARAMETER;
                }
            }

            status = AppendMultipartPartHeader(
                *request,
                request->MultipartBoundary,
                boundaryLength,
                part.Name,
                part.NameLength,
                fileName,
                fileNameLength,
                part.ContentType,
                part.ContentTypeLength);
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }

            if (part.Kind == RequestBodyPartKind::Field) {
                status = AppendOwnedText(*request, part.Value, part.ValueLength);
            }
            else if (part.Kind == RequestBodyPartKind::FileBytes) {
                status = AppendOwnedBody(*request, part.Data, part.DataLength);
            }
            else {
                status = AppendFileToOwnedBody(*request, part.FilePath, part.FilePathLength);
            }
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }

            status = AppendOwnedLiteral(*request, "\r\n");
            if (!NT_SUCCESS(status)) {
                AbortOwnedBodyBuild(*request);
                return status;
            }
        }

        status = AppendOwnedLiteral(*request, "--");
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }
        status = AppendOwnedText(*request, request->MultipartBoundary, boundaryLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }
        status = AppendOwnedLiteral(*request, "--\r\n");
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        return SetMultipartContentType(*request, request->MultipartBoundary, boundaryLength);
    }

    NTSTATUS HttpRequestSetFileBody(
        RequestHandle request,
        const char* filePath,
        SIZE_T filePathLength,
        const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) ||
            filePath == nullptr ||
            filePathLength == 0 ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = BeginOwnedBodyBuild(*request);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = AppendFileToOwnedBody(*request, filePath, filePathLength);
        if (!NT_SUCCESS(status)) {
            AbortOwnedBodyBuild(*request);
            return status;
        }

        if (contentType == nullptr) {
            const http1::HttpText defaultType = http1::MakeText("application/octet-stream");
            contentType = defaultType.Data;
            contentTypeLength = defaultType.Length;
        }

        return ReplaceContentType(*request, contentType, contentTypeLength);
    }

    NTSTATUS HttpRequestSetTlsOptions(RequestHandle request, const TlsOptions* options) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || options == nullptr || !IsValidTlsOptions(*options)) {
            return STATUS_INVALID_PARAMETER;
        }

        request->Tls = *options;
        request->HasTlsOverride = true;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpRequestSetConnectionPolicy(RequestHandle request, ConnectionPolicy policy) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request)) {
            return STATUS_INVALID_PARAMETER;
        }

        switch (policy) {
        case ConnectionPolicy::ReuseOrCreate:
        case ConnectionPolicy::ForceNew:
        case ConnectionPolicy::NoPool:
            request->ConnectionPolicy = policy;
            return STATUS_SUCCESS;
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS HttpRequestSetAddressFamily(RequestHandle request, AddressFamily addressFamily) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsRequestHandle(request) || !IsValidAddressFamily(addressFamily)) {
            return STATUS_INVALID_PARAMETER;
        }

        request->AddressFamily = addressFamily;
        return STATUS_SUCCESS;
    }


}
}
