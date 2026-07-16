#include "session/EnginePrivate.hpp"

namespace wknet
{
namespace session
{
    void ReleaseStoredHeader(_Inout_ StoredHeader& header) noexcept
    {
        FreeApiMemory(header.Name);
        FreeApiMemory(header.Value);
        header = {};
    }

    void ReleaseStoredHeaderList(_Inout_ StoredHeaderList& list) noexcept
    {
        if (list.Items != nullptr) {
            for (SIZE_T index = 0; index < list.Count; ++index) {
                ReleaseStoredHeader(list.Items[index]);
            }
            FreeApiMemory(list.Items);
        }
        list.Items = nullptr;
        list.Count = 0;
        list.Capacity = 0;
    }

    _Must_inspect_result_
    NTSTATUS EnsureStoredHeaderListCapacity(
        _Inout_ StoredHeaderList& list,
        SIZE_T requiredCount) noexcept
    {
        if (requiredCount == 0) {
            return STATUS_SUCCESS;
        }
        if (requiredCount > MaxHeadersPerRequest) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (requiredCount <= list.Capacity) {
            return STATUS_SUCCESS;
        }

        SIZE_T newCapacity = list.Capacity;
        if (newCapacity == 0) {
            newCapacity = InitialHeaderListCapacity;
        }
        while (newCapacity < requiredCount) {
            SIZE_T doubled = 0;
            if (!AddSize(newCapacity, newCapacity, &doubled)) {
                newCapacity = requiredCount;
                break;
            }
            newCapacity = doubled;
        }
        if (newCapacity > MaxHeadersPerRequest) {
            newCapacity = MaxHeadersPerRequest;
        }
        if (newCapacity < requiredCount) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        if (newCapacity == 0 ||
            newCapacity > (static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / sizeof(StoredHeader))) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T bytes = newCapacity * sizeof(StoredHeader);

        auto* replacement = static_cast<StoredHeader*>(AllocateApiMemory(bytes));
        if (replacement == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(replacement, bytes);
        if (list.Items != nullptr && list.Count != 0) {
            RtlCopyMemory(replacement, list.Items, list.Count * sizeof(StoredHeader));
        }
        FreeApiMemory(list.Items);
        list.Items = replacement;
        list.Capacity = newCapacity;
        return STATUS_SUCCESS;
    }

    void ReleaseOwnedBody(_Inout_ Request& request) noexcept
    {
        if (request.OwnedBody != nullptr && request.OwnedBodyCapacity != 0) {
            RtlSecureZeroMemory(request.OwnedBody, request.OwnedBodyCapacity);
        }
        FreeApiMemory(request.OwnedBody);
        request.OwnedBody = nullptr;
        request.OwnedBodyLength = 0;
        request.OwnedBodyCapacity = 0;
        request.Body = nullptr;
        request.BodyLength = 0;
        request.HasBody = false;
        request.BodySourceCallback = nullptr;
        request.BodySourceContext = nullptr;
        request.BodySourceContentLength = 0;
        request.BodySourceContentLengthKnown = false;
    }

    void ResetOwnedBodyContent(_Inout_ Request& request) noexcept
    {
        if (request.OwnedBody != nullptr && request.OwnedBodyCapacity != 0) {
            RtlSecureZeroMemory(request.OwnedBody, request.OwnedBodyCapacity);
        }
        request.OwnedBodyLength = 0;
        request.HasBody = false;
        request.BodySourceCallback = nullptr;
        request.BodySourceContext = nullptr;
        request.BodySourceContentLength = 0;
        request.BodySourceContentLengthKnown = false;
    }

    void AbortOwnedBodyBuild(_Inout_ Request& request) noexcept
    {
        ResetOwnedBodyContent(request);
        request.Body = nullptr;
        request.BodyLength = 0;
    }

    _Must_inspect_result_
    bool AddSize(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
    {
        if (result == nullptr) {
            return false;
        }
        if (left > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - right) {
            *result = 0;
            return false;
        }
        *result = left + right;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS EnsureOwnedBodyCapacity(_Inout_ Request& request, SIZE_T requiredCapacity) noexcept
    {
        if (requiredCapacity == 0 || requiredCapacity <= request.OwnedBodyCapacity) {
            return STATUS_SUCCESS;
        }

        SIZE_T newCapacity = request.OwnedBodyCapacity;
        if (newCapacity == 0) {
            newCapacity = InitialOwnedBodyCapacity;
        }

        while (newCapacity < requiredCapacity) {
            SIZE_T doubled = 0;
            if (!AddSize(newCapacity, newCapacity, &doubled)) {
                newCapacity = requiredCapacity;
                break;
            }
            newCapacity = doubled < requiredCapacity ? requiredCapacity : doubled;
        }

        UCHAR* replacement = static_cast<UCHAR*>(AllocateApiMemory(newCapacity));
        if (replacement == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (request.OwnedBody != nullptr && request.OwnedBodyLength != 0) {
            RtlCopyMemory(replacement, request.OwnedBody, request.OwnedBodyLength);
        }
        if (request.OwnedBody != nullptr && request.OwnedBodyCapacity != 0) {
            RtlSecureZeroMemory(request.OwnedBody, request.OwnedBodyCapacity);
        }
        FreeApiMemory(request.OwnedBody);
        request.OwnedBody = replacement;
        request.OwnedBodyCapacity = newCapacity;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BeginOwnedBodyBuild(_Inout_ Request& request) noexcept
    {
        ResetOwnedBodyContent(request);
        request.Body = request.OwnedBody;
        request.BodyLength = 0;
        request.HasBody = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS AppendOwnedBody(
        _Inout_ Request& request,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        if (data == nullptr && dataLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (dataLength == 0) {
            request.Body = request.OwnedBody;
            request.BodyLength = request.OwnedBodyLength;
            request.HasBody = true;
            return STATUS_SUCCESS;
        }

        SIZE_T required = 0;
        if (!AddSize(request.OwnedBodyLength, dataLength, &required)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        NTSTATUS status = EnsureOwnedBodyCapacity(request, required);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        RtlCopyMemory(request.OwnedBody + request.OwnedBodyLength, data, dataLength);
        request.OwnedBodyLength = required;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS AppendOwnedText(_Inout_ Request& request, _In_opt_ const char* text, SIZE_T textLength) noexcept
    {
        return AppendOwnedBody(request, reinterpret_cast<const UCHAR*>(text), textLength);
    }

    _Must_inspect_result_
    NTSTATUS AppendOwnedLiteral(_Inout_ Request& request, _In_z_ const char* text) noexcept
    {
        const http1::HttpText value = http1::MakeText(text);
        return AppendOwnedText(request, value.Data, value.Length);
    }

    _Must_inspect_result_
    bool IsValidHeaderText(
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        bool name) noexcept;

    _Must_inspect_result_
    NTSTATUS AddStoredHeader(
        _Inout_ Request& request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
    {
        if (name == nullptr || nameLength == 0 || (value == nullptr && valueLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (nameLength > MaxHeaderNameLength || valueLength > MaxHeaderValueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (!IsValidHeaderText(name, nameLength, true) ||
            !IsValidHeaderText(value, valueLength, false)) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T needed = request.HeaderCount + 1;
        NTSTATUS status = EnsureStoredHeaderListCapacity(request.Headers, needed);
        if (!NT_SUCCESS(status)) {
            return status == STATUS_BUFFER_TOO_SMALL ? STATUS_INSUFFICIENT_RESOURCES : status;
        }

        char* nameCopy = AllocateTextCopy(name, nameLength);
        if (nameCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        char* valueCopy = nullptr;
        if (valueLength != 0) {
            valueCopy = AllocateTextCopy(value, valueLength);
            if (valueCopy == nullptr) {
                FreeApiMemory(nameCopy);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        StoredHeader& header = request.Headers[request.HeaderCount];
        header.Name = nameCopy;
        header.NameLength = nameLength;
        header.Value = valueCopy;
        header.ValueLength = valueLength;
        ++request.HeaderCount;
        request.Headers.Count = request.HeaderCount;
        return STATUS_SUCCESS;
    }

    bool IsForbiddenRequestTrailerField(const char* name, SIZE_T nameLength) noexcept
    {
        return TextEqualsLiteralIgnoreCase(name, nameLength, "Content-Length") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Transfer-Encoding") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Host") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Authorization") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Proxy-Authorization") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Cookie") ||
            TextEqualsLiteralIgnoreCase(name, nameLength, "Set-Cookie");
    }

    NTSTATUS AddStoredTrailer(
        _Inout_ Request& request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
    {
        if (name == nullptr || nameLength == 0 || (value == nullptr && valueLength != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (nameLength > MaxHeaderNameLength || valueLength > MaxHeaderValueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        if (!IsValidHeaderText(name, nameLength, true) ||
            !IsValidHeaderText(value, valueLength, false)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (IsForbiddenRequestTrailerField(name, nameLength)) {
            return STATUS_NOT_SUPPORTED;
        }

        const SIZE_T needed = request.TrailerCount + 1;
        NTSTATUS status = EnsureStoredHeaderListCapacity(request.Trailers, needed);
        if (!NT_SUCCESS(status)) {
            return status == STATUS_BUFFER_TOO_SMALL ? STATUS_INSUFFICIENT_RESOURCES : status;
        }

        char* nameCopy = AllocateTextCopy(name, nameLength);
        if (nameCopy == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        char* valueCopy = nullptr;
        if (valueLength != 0) {
            valueCopy = AllocateTextCopy(value, valueLength);
            if (valueCopy == nullptr) {
                FreeApiMemory(nameCopy);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        StoredHeader& trailer = request.Trailers[request.TrailerCount];
        trailer.Name = nameCopy;
        trailer.NameLength = nameLength;
        trailer.Value = valueCopy;
        trailer.ValueLength = valueLength;
        ++request.TrailerCount;
        request.Trailers.Count = request.TrailerCount;
        return STATUS_SUCCESS;
    }

    void RemoveStoredHeadersByName(_Inout_ Request& request, _In_z_ const char* name) noexcept
    {
        SIZE_T index = 0;
        while (index < request.HeaderCount) {
            if (TextEqualsLiteralIgnoreCase(request.Headers[index].Name, request.Headers[index].NameLength, name)) {
                ReleaseStoredHeader(request.Headers[index]);
                for (SIZE_T moveIndex = index + 1; moveIndex < request.HeaderCount; ++moveIndex) {
                    request.Headers[moveIndex - 1] = request.Headers[moveIndex];
                }
                --request.HeaderCount;
                request.Headers.Count = request.HeaderCount;
                if (request.Headers.Items != nullptr) {
                    request.Headers[request.HeaderCount] = {};
                }
            }
            else {
                ++index;
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS ReplaceContentType(
        _Inout_ Request& request,
        _In_reads_bytes_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        if (contentType == nullptr || contentTypeLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        RemoveStoredHeadersByName(request, "Content-Type");
        return AddStoredHeader(
            request,
            "Content-Type",
            http1::MakeText("Content-Type").Length,
            contentType,
            contentTypeLength);
    }

    _Must_inspect_result_
    bool IsOptionalTextValid(const char* text, SIZE_T textLength) noexcept
    {
        return (text == nullptr && textLength == 0) || (text != nullptr && textLength != 0);
    }

    _Must_inspect_result_
    bool IsUnreservedFormChar(char value) noexcept
    {
        return (value >= 'A' && value <= 'Z') ||
            (value >= 'a' && value <= 'z') ||
            (value >= '0' && value <= '9') ||
            value == '-' ||
            value == '_' ||
            value == '.' ||
            value == '~';
    }

    _Must_inspect_result_
    NTSTATUS AppendUrlEncodedText(
        _Inout_ Request& request,
        _In_reads_bytes_opt_(textLength) const char* text,
        SIZE_T textLength) noexcept
    {
        if (text == nullptr && textLength != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        static constexpr char hex[] = "0123456789ABCDEF";
        for (SIZE_T index = 0; index < textLength; ++index) {
            const unsigned char value = static_cast<unsigned char>(text[index]);
            if (IsUnreservedFormChar(static_cast<char>(value))) {
                NTSTATUS status = AppendOwnedText(request, text + index, 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else if (value == ' ') {
                NTSTATUS status = AppendOwnedLiteral(request, "+");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else {
                NTSTATUS status = AppendOwnedLiteral(request, "%");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AppendOwnedText(request, hex + ((value >> 4) & 0x0F), 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AppendOwnedText(request, hex + (value & 0x0F), 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool IsValidHeaderQuotedByte(char value) noexcept
    {
        return value != '\r' && value != '\n';
    }

    _Must_inspect_result_
    bool IsValidHeaderNameByte(char value) noexcept
    {
        const unsigned char ch = static_cast<unsigned char>(value);
        if (ch <= 0x20 || ch >= 0x7f) {
            return false;
        }

        switch (value) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
            return false;
        default:
            return true;
        }
    }

    _Must_inspect_result_
    bool IsValidHeaderValueByte(char value) noexcept
    {
        const unsigned char ch = static_cast<unsigned char>(value);
        return value == '\t' || (ch >= 0x20 && ch != 0x7f);
    }

    _Must_inspect_result_
    bool IsValidHeaderText(
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        bool name) noexcept
    {
        if (text == nullptr && textLength != 0) {
            return false;
        }

        if (name && textLength == 0) {
            return false;
        }

        for (SIZE_T index = 0; index < textLength; ++index) {
            const bool valid = name ?
                IsValidHeaderNameByte(text[index]) :
                IsValidHeaderValueByte(text[index]);
            if (!valid) {
                return false;
            }
        }

        return true;
    }

    _Must_inspect_result_
    NTSTATUS AppendMultipartQuotedValue(
        _Inout_ Request& request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
    {
        if (value == nullptr || valueLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < valueLength; ++index) {
            const char ch = value[index];
            if (!IsValidHeaderQuotedByte(ch)) {
                return STATUS_INVALID_PARAMETER;
            }
            if (ch == '"' || ch == '\\') {
                NTSTATUS status = AppendOwnedLiteral(request, "\\");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            NTSTATUS status = AppendOwnedText(request, &ch, 1);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS GenerateMultipartBoundary(_Inout_ Request& request, _Out_ SIZE_T* boundaryLength) noexcept
    {
        if (boundaryLength != nullptr) {
            *boundaryLength = 0;
        }
        if (boundaryLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const http1::HttpText prefix = http1::MakeText("----WknetBoundary");
        if (prefix.Length + 8 >= MultipartBoundaryStorageLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(request.MultipartBoundary, sizeof(request.MultipartBoundary));
        RtlCopyMemory(request.MultipartBoundary, prefix.Data, prefix.Length);

        ++request.BodyBuildCounter;
        static constexpr char hex[] = "0123456789ABCDEF";
        ULONG value = request.BodyBuildCounter;
        for (SIZE_T index = 0; index < 8; ++index) {
            const ULONG shift = static_cast<ULONG>((7 - index) * 4);
            request.MultipartBoundary[prefix.Length + index] = hex[(value >> shift) & 0x0F];
        }

        *boundaryLength = prefix.Length + 8;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS SetMultipartContentType(
        _Inout_ Request& request,
        _In_reads_bytes_(boundaryLength) const char* boundary,
        SIZE_T boundaryLength) noexcept
    {
        const http1::HttpText prefix = http1::MakeText("multipart/form-data; boundary=");
        SIZE_T contentTypeLength = 0;
        if (!AddSize(prefix.Length, boundaryLength, &contentTypeLength)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        char* contentType = static_cast<char*>(AllocateApiMemory(contentTypeLength + 1));
        if (contentType == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(contentType, prefix.Data, prefix.Length);
        RtlCopyMemory(contentType + prefix.Length, boundary, boundaryLength);
        contentType[contentTypeLength] = '\0';

        const NTSTATUS status = ReplaceContentType(request, contentType, contentTypeLength);
        FreeApiMemory(contentType);
        return status;
    }

    _Must_inspect_result_
    NTSTATUS AppendMultipartPartHeader(
        _Inout_ Request& request,
        _In_reads_bytes_(boundaryLength) const char* boundary,
        SIZE_T boundaryLength,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_opt_(fileNameLength) const char* fileName,
        SIZE_T fileNameLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept
    {
        if (boundary == nullptr ||
            boundaryLength == 0 ||
            name == nullptr ||
            nameLength == 0 ||
            !IsOptionalTextValid(fileName, fileNameLength) ||
            !IsOptionalTextValid(contentType, contentTypeLength)) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = AppendOwnedLiteral(request, "--");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendOwnedText(request, boundary, boundaryLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendOwnedLiteral(request, "\r\nContent-Disposition: form-data; name=\"");
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendMultipartQuotedValue(request, name, nameLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendOwnedLiteral(request, "\"");
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (fileName != nullptr && fileNameLength != 0) {
            status = AppendOwnedLiteral(request, "; filename=\"");
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendMultipartQuotedValue(request, fileName, fileNameLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendOwnedLiteral(request, "\"");
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = AppendOwnedLiteral(request, "\r\n");
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (contentType != nullptr && contentTypeLength != 0) {
            if (!IsValidHeaderText(contentType, contentTypeLength, false)) {
                return STATUS_INVALID_PARAMETER;
            }

            status = AppendOwnedLiteral(request, "Content-Type: ");
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendOwnedText(request, contentType, contentTypeLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = AppendOwnedLiteral(request, "\r\n");
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return AppendOwnedLiteral(request, "\r\n");
    }

    void DeriveFileNameFromPath(
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength,
        _Outptr_result_bytebuffer_(*fileNameLength) const char** fileName,
        _Out_ SIZE_T* fileNameLength) noexcept
    {
        if (fileName != nullptr) {
            *fileName = nullptr;
        }
        if (fileNameLength != nullptr) {
            *fileNameLength = 0;
        }
        if (filePath == nullptr || filePathLength == 0 || fileName == nullptr || fileNameLength == nullptr) {
            return;
        }

        SIZE_T start = 0;
        for (SIZE_T index = 0; index < filePathLength; ++index) {
            if (filePath[index] == '\\' || filePath[index] == '/') {
                start = index + 1;
            }
        }

        *fileName = filePath + start;
        *fileNameLength = filePathLength - start;
    }

    _Must_inspect_result_
    NTSTATUS AppendFileToOwnedBody(
        _Inout_ Request& request,
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength) noexcept
    {
        if (filePath == nullptr || filePathLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }

#if defined(WKNET_USER_MODE_TEST)
        char* path = AllocateTextCopy(filePath, filePathLength);
        if (path == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        FILE* file = nullptr;
        if (fopen_s(&file, path, "rb") != 0 || file == nullptr) {
            FreeApiMemory(path);
            return STATUS_NOT_FOUND;
        }

        if (_fseeki64(file, 0, SEEK_END) != 0) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_UNSUCCESSFUL;
        }
        const __int64 fileSize = _ftelli64(file);
        if (fileSize < 0) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_UNSUCCESSFUL;
        }
        if (_fseeki64(file, 0, SEEK_SET) != 0) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_UNSUCCESSFUL;
        }

        const unsigned __int64 unsignedSize = static_cast<unsigned __int64>(fileSize);
        if (unsignedSize > static_cast<unsigned __int64>(~static_cast<SIZE_T>(0))) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_BUFFER_TOO_SMALL;
        }

        const SIZE_T bytesToRead = static_cast<SIZE_T>(unsignedSize);
        SIZE_T required = 0;
        if (!AddSize(request.OwnedBodyLength, bytesToRead, &required)) {
            fclose(file);
            FreeApiMemory(path);
            return STATUS_INTEGER_OVERFLOW;
        }

        NTSTATUS status = EnsureOwnedBodyCapacity(request, required);
        if (!NT_SUCCESS(status)) {
            fclose(file);
            FreeApiMemory(path);
            return status;
        }

        if (bytesToRead != 0) {
            const size_t read = fread(request.OwnedBody + request.OwnedBodyLength, 1, bytesToRead, file);
            if (read != bytesToRead) {
                fclose(file);
                FreeApiMemory(path);
                return STATUS_UNSUCCESSFUL;
            }
        }

        request.OwnedBodyLength = required;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        fclose(file);
        FreeApiMemory(path);
        return STATUS_SUCCESS;
#else
        if (filePathLength > 0xFFFE) {
            return STATUS_INVALID_PARAMETER;
        }

        char* path = AllocateTextCopy(filePath, filePathLength);
        if (path == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ANSI_STRING ansiPath = {};
        RtlInitAnsiString(&ansiPath, path);
        UNICODE_STRING unicodePath = {};
        NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
        if (!NT_SUCCESS(status)) {
            FreeApiMemory(path);
            return status;
        }

        OBJECT_ATTRIBUTES objectAttributes = {};
        InitializeObjectAttributes(
            &objectAttributes,
            &unicodePath,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            nullptr,
            nullptr);

        IO_STATUS_BLOCK ioStatus = {};
        HANDLE fileHandle = nullptr;
        status = ZwCreateFile(
            &fileHandle,
            GENERIC_READ,
            &objectAttributes,
            &ioStatus,
            nullptr,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            nullptr,
            0);
        if (!NT_SUCCESS(status)) {
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return status;
        }

        FILE_STANDARD_INFORMATION fileInfo = {};
        status = ZwQueryInformationFile(
            fileHandle,
            &ioStatus,
            &fileInfo,
            sizeof(fileInfo),
            FileStandardInformation);
        if (!NT_SUCCESS(status) || fileInfo.EndOfFile.QuadPart < 0) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
        }

        const ULONGLONG fileSize = static_cast<ULONGLONG>(fileInfo.EndOfFile.QuadPart);
        if (fileSize > static_cast<ULONGLONG>(~static_cast<SIZE_T>(0))) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return STATUS_BUFFER_TOO_SMALL;
        }

        const SIZE_T bytesToRead = static_cast<SIZE_T>(fileSize);
        SIZE_T required = 0;
        if (!AddSize(request.OwnedBodyLength, bytesToRead, &required)) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return STATUS_INTEGER_OVERFLOW;
        }

        status = EnsureOwnedBodyCapacity(request, required);
        if (!NT_SUCCESS(status)) {
            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            FreeApiMemory(path);
            return status;
        }

        SIZE_T totalRead = 0;
        while (totalRead < bytesToRead) {
            SIZE_T remaining = bytesToRead - totalRead;
            ULONG chunk = remaining > static_cast<SIZE_T>(0x100000) ?
                0x100000UL :
                static_cast<ULONG>(remaining);
            LARGE_INTEGER offset = {};
            offset.QuadPart = static_cast<LONGLONG>(totalRead);
            status = ZwReadFile(
                fileHandle,
                nullptr,
                nullptr,
                nullptr,
                &ioStatus,
                request.OwnedBody + request.OwnedBodyLength + totalRead,
                chunk,
                &offset,
                nullptr);
            if (!NT_SUCCESS(status)) {
                ZwClose(fileHandle);
                RtlFreeUnicodeString(&unicodePath);
                FreeApiMemory(path);
                return status;
            }
            if (ioStatus.Information == 0) {
                ZwClose(fileHandle);
                RtlFreeUnicodeString(&unicodePath);
                FreeApiMemory(path);
                return STATUS_UNSUCCESSFUL;
            }
            totalRead += static_cast<SIZE_T>(ioStatus.Information);
        }

        request.OwnedBodyLength = required;
        request.Body = request.OwnedBody;
        request.BodyLength = request.OwnedBodyLength;
        request.HasBody = true;
        ZwClose(fileHandle);
        RtlFreeUnicodeString(&unicodePath);
        FreeApiMemory(path);
        return STATUS_SUCCESS;
#endif
    }

    void ReleaseRequestStorage(_Inout_ Request& request) noexcept
    {
        FreeApiMemory(request.Url);
        request.Url = nullptr;
        request.UrlLength = 0;
        request.SchemeLength = 0;
        request.HostLength = 0;
        FreeNonPagedArray(request.Path);
        request.Path = nullptr;
        request.PathLength = 0;
        request.Port = 0;
        ReleaseOwnedBody(request);
        FreeApiMemory(request.OwnedTlsServerName);
        FreeApiMemory(request.OwnedTlsAlpn);
        request.OwnedTlsServerName = nullptr;
        request.OwnedTlsAlpn = nullptr;

        ReleaseStoredHeaderList(request.Headers);
        request.HeaderCount = 0;
        ReleaseStoredHeaderList(request.Trailers);
        request.TrailerCount = 0;
    }

    _Must_inspect_result_
    NTSTATUS CloneRequestForAsync(_In_ const Request& source, _Out_ RequestHandle* clonedRequest) noexcept
    {
        if (clonedRequest != nullptr) {
            *clonedRequest = nullptr;
        }

        if (clonedRequest == nullptr || !IsRequestHandle(const_cast<RequestHandle>(&source))) {
            return STATUS_INVALID_PARAMETER;
        }

        RequestHandle clone = AllocateRequestHandle();
        if (clone == nullptr) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        clone->Header = { HandleKind::Request, 0, nullptr };
        clone->Session = source.Session;
        clone->Method = source.Method;
        clone->UrlLength = source.UrlLength;
        clone->SchemeLength = source.SchemeLength;
        clone->HostLength = source.HostLength;
        clone->PathLength = source.PathLength;
        clone->Port = source.Port;
        clone->BodyMode = source.BodyMode;
        clone->BodySourceCallback = source.BodySourceCallback;
        clone->BodySourceContext = source.BodySourceContext;
        clone->BodySourceContentLength = source.BodySourceContentLength;
        clone->BodySourceContentLengthKnown = source.BodySourceContentLengthKnown;
        clone->Tls = source.Tls;
        clone->HasTlsOverride = source.HasTlsOverride;
        clone->ConnectionPolicy = source.ConnectionPolicy;
        clone->AddressFamily = source.AddressFamily;
        clone->InFlight = 0;
#if !defined(WKNET_USER_MODE_TEST)
        KeInitializeEvent(&clone->DrainEvent, NotificationEvent, TRUE);
#endif
        RtlCopyMemory(clone->Scheme, source.Scheme, sizeof(clone->Scheme));
        RtlCopyMemory(clone->Host, source.Host, sizeof(clone->Host));
        RtlCopyMemory(clone->MultipartBoundary, source.MultipartBoundary, sizeof(clone->MultipartBoundary));

        if (source.Url != nullptr && source.UrlLength != 0) {
            clone->Url = AllocateTextCopy(source.Url, source.UrlLength);
            if (clone->Url == nullptr) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        if (source.Path != nullptr && source.PathLength != 0) {
            clone->Path = AllocateNonPagedArray<char>(source.PathLength + 1);
            if (clone->Path == nullptr) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(clone->Path, source.Path, source.PathLength);
            clone->Path[source.PathLength] = '\0';
            clone->PathLength = source.PathLength;
        }

        if (source.Tls.ServerName == source.Host) {
            clone->Tls.ServerName = clone->Host;
            clone->Tls.ServerNameLength = clone->HostLength;
        }
        else if (source.Tls.ServerName != nullptr && source.Tls.ServerNameLength != 0) {
            clone->OwnedTlsServerName = AllocateTextCopy(source.Tls.ServerName, source.Tls.ServerNameLength);
            if (clone->OwnedTlsServerName == nullptr) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            clone->Tls.ServerName = clone->OwnedTlsServerName;
        }

        if (source.Tls.Alpn != nullptr && source.Tls.AlpnLength != 0) {
            clone->OwnedTlsAlpn = AllocateTextCopy(source.Tls.Alpn, source.Tls.AlpnLength);
            if (clone->OwnedTlsAlpn == nullptr) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            clone->Tls.Alpn = clone->OwnedTlsAlpn;
        }

        if (source.BodySourceCallback != nullptr) {
            clone->HasBody = source.HasBody;
            clone->Body = nullptr;
            clone->BodyLength = source.BodyLength;
        }
        else if (source.HasBody && source.BodyLength != 0) {
            NTSTATUS status = BeginOwnedBodyBuild(*clone);
            if (NT_SUCCESS(status)) {
                status = AppendOwnedBody(*clone, source.Body, source.BodyLength);
            }
            if (!NT_SUCCESS(status)) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return status;
            }
        }
        else {
            clone->HasBody = source.HasBody;
            clone->Body = nullptr;
            clone->BodyLength = 0;
        }

        for (SIZE_T index = 0; index < source.HeaderCount && index < MaxHeadersPerRequest; ++index) {
            NTSTATUS status = AddStoredHeader(
                *clone,
                source.Headers[index].Name,
                source.Headers[index].NameLength,
                source.Headers[index].Value,
                source.Headers[index].ValueLength);
            if (!NT_SUCCESS(status)) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return status;
            }
        }

        for (SIZE_T index = 0; index < source.TrailerCount && index < MaxHeadersPerRequest; ++index) {
            NTSTATUS status = AddStoredTrailer(
                *clone,
                source.Trailers[index].Name,
                source.Trailers[index].NameLength,
                source.Trailers[index].Value,
                source.Trailers[index].ValueLength);
            if (!NT_SUCCESS(status)) {
                ReleaseRequestStorage(*clone);
                FreeHandle(clone);
                return status;
            }
        }

        NTSTATUS status = RegisterActiveRequestHandle(clone);
        if (!NT_SUCCESS(status)) {
            ReleaseRequestStorage(*clone);
            FreeHandle(clone);
            return status;
        }

        *clonedRequest = clone;
        return STATUS_SUCCESS;
    }


}
}
