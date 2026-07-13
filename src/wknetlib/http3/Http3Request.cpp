#include "http3/Http3Request.h"

namespace wknet::http3
{
namespace
{
constexpr UCHAR MethodName[] = {':', 'm', 'e', 't', 'h', 'o', 'd'};
constexpr UCHAR SchemeName[] = {':', 's', 'c', 'h', 'e', 'm', 'e'};
constexpr UCHAR AuthorityName[] = {':', 'a', 'u', 't', 'h', 'o', 'r', 'i', 't', 'y'};
constexpr UCHAR PathName[] = {':', 'p', 'a', 't', 'h'};

bool ByteEqualsIgnoreCase(UCHAR left, UCHAR right) noexcept
{
    if (left >= 'A' && left <= 'Z')
    {
        left = static_cast<UCHAR>(left + ('a' - 'A'));
    }
    if (right >= 'A' && right <= 'Z')
    {
        right = static_cast<UCHAR>(right + ('a' - 'A'));
    }
    return left == right;
}

bool TextEquals(qpack::QpackStringView value, const char *literal, SIZE_T literalLength,
                bool ignoreCase = false) noexcept
{
    if (value.Length != literalLength || (value.Data == nullptr && value.Length != 0))
    {
        return false;
    }
    for (SIZE_T index = 0; index < literalLength; ++index)
    {
        const UCHAR literalByte = static_cast<UCHAR>(literal[index]);
        if (ignoreCase ? !ByteEqualsIgnoreCase(value.Data[index], literalByte) : value.Data[index] != literalByte)
        {
            return false;
        }
    }
    return true;
}

bool ViewsEqualIgnoreCase(qpack::QpackStringView left, qpack::QpackStringView right) noexcept
{
    if (left.Length != right.Length || (left.Data == nullptr && left.Length != 0) ||
        (right.Data == nullptr && right.Length != 0))
    {
        return false;
    }
    for (SIZE_T index = 0; index < left.Length; ++index)
    {
        if (!ByteEqualsIgnoreCase(left.Data[index], right.Data[index]))
        {
            return false;
        }
    }
    return true;
}

bool IsTokenByte(UCHAR value) noexcept
{
    if ((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9'))
    {
        return true;
    }
    switch (value)
    {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
        return true;
    default:
        return false;
    }
}

bool IsMethodToken(qpack::QpackStringView method) noexcept
{
    if (method.Data == nullptr || method.Length == 0)
    {
        return false;
    }
    for (SIZE_T index = 0; index < method.Length; ++index)
    {
        UCHAR value = method.Data[index];
        if (value >= 'A' && value <= 'Z')
        {
            value = static_cast<UCHAR>(value + ('a' - 'A'));
        }
        if (!IsTokenByte(value))
        {
            return false;
        }
    }
    return true;
}

bool IsValidFieldName(qpack::QpackStringView name, bool allowPseudo) noexcept
{
    if (name.Data == nullptr || name.Length == 0)
    {
        return false;
    }
    SIZE_T offset = 0;
    if (name.Data[0] == ':')
    {
        if (!allowPseudo || name.Length == 1)
        {
            return false;
        }
        offset = 1;
    }
    for (; offset < name.Length; ++offset)
    {
        if (!IsTokenByte(name.Data[offset]))
        {
            return false;
        }
    }
    return true;
}

bool IsValidFieldValue(qpack::QpackStringView value) noexcept
{
    if (value.Data == nullptr && value.Length != 0)
    {
        return false;
    }
    for (SIZE_T index = 0; index < value.Length; ++index)
    {
        const UCHAR current = value.Data[index];
        if (current == 0 || current == '\r' || current == '\n')
        {
            return false;
        }
    }
    return true;
}

bool IsConnectionSpecific(qpack::QpackStringView name) noexcept
{
    return TextEquals(name, "connection", 10, true) || TextEquals(name, "proxy-connection", 16, true) ||
           TextEquals(name, "keep-alive", 10, true) || TextEquals(name, "transfer-encoding", 17, true) ||
           TextEquals(name, "upgrade", 7, true);
}

bool IsTeTrailers(qpack::QpackStringView value) noexcept
{
    if (value.Data == nullptr)
    {
        return false;
    }
    SIZE_T begin = 0;
    SIZE_T end = value.Length;
    while (begin < end && (value.Data[begin] == ' ' || value.Data[begin] == '\t'))
    {
        ++begin;
    }
    while (end > begin && (value.Data[end - 1] == ' ' || value.Data[end - 1] == '\t'))
    {
        --end;
    }
    return TextEquals({value.Data + begin, end - begin}, "trailers", 8, true);
}

NTSTATUS Fail(ULONGLONG *applicationError) noexcept
{
    if (applicationError != nullptr)
    {
        *applicationError = H3_MESSAGE_ERROR;
    }
    return STATUS_INVALID_NETWORK_RESPONSE;
}

NTSTATUS ValidateRegularField(const qpack::QpackFieldView &field, bool trailers, ULONGLONG *applicationError) noexcept
{
    if (!IsValidFieldName(field.Name, false) || !IsValidFieldValue(field.Value) || IsConnectionSpecific(field.Name))
    {
        return Fail(applicationError);
    }
    if (TextEquals(field.Name, "te", 2, true) && !IsTeTrailers(field.Value))
    {
        return Fail(applicationError);
    }
    if (trailers && (TextEquals(field.Name, "content-length", 14, true) || TextEquals(field.Name, "host", 4, true)))
    {
        return Fail(applicationError);
    }
    return STATUS_SUCCESS;
}

NTSTATUS ParseStatus(qpack::QpackStringView value, ULONG *statusCode) noexcept
{
    if (statusCode == nullptr || value.Data == nullptr || value.Length != 3)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    ULONG status = 0;
    for (SIZE_T index = 0; index < value.Length; ++index)
    {
        if (value.Data[index] < '0' || value.Data[index] > '9')
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        status = status * 10 + static_cast<ULONG>(value.Data[index] - '0');
    }
    if (status < 100 || status > 999 || status == 101)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    *statusCode = status;
    return STATUS_SUCCESS;
}

NTSTATUS ParseContentLength(qpack::QpackStringView value, ULONGLONG *contentLength) noexcept
{
    if (contentLength == nullptr || value.Data == nullptr || value.Length == 0)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    ULONGLONG parsed = 0;
    for (SIZE_T index = 0; index < value.Length; ++index)
    {
        const UCHAR current = value.Data[index];
        if (current < '0' || current > '9')
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const ULONGLONG digit = current - '0';
        if (parsed > (static_cast<ULONGLONG>(~0ULL) - digit) / 10)
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        parsed = parsed * 10 + digit;
    }
    *contentLength = parsed;
    return STATUS_SUCCESS;
}
} // namespace

NTSTATUS Http3BuildRequestFields(const Http3RequestFieldOptions &options, qpack::QpackFieldView *fields,
                                 SIZE_T fieldCapacity, SIZE_T *fieldCount, ULONGLONG *applicationError) noexcept
{
    if (fieldCount != nullptr)
    {
        *fieldCount = 0;
    }
    if (applicationError != nullptr)
    {
        *applicationError = H3_NO_ERROR;
    }
    if (fields == nullptr || fieldCount == nullptr || applicationError == nullptr ||
        (options.Headers == nullptr && options.HeaderCount != 0) || options.Method.Data == nullptr ||
        options.Method.Length == 0 || options.Authority.Data == nullptr || options.Authority.Length == 0 ||
        (!options.Connect && (options.Scheme.Data == nullptr || options.Scheme.Length == 0 ||
                              options.Path.Data == nullptr || options.Path.Length == 0)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    const bool connectMethod = TextEquals(options.Method, "CONNECT", 7, true);
    if (!IsMethodToken(options.Method) || connectMethod != options.Connect || !IsValidFieldValue(options.Authority) ||
        (!options.Connect && (!IsValidFieldValue(options.Scheme) || !IsValidFieldValue(options.Path))))
    {
        return Fail(applicationError);
    }

    const SIZE_T pseudoCount = options.Connect ? 2 : 4;
    qpack::QpackStringView host = {};
    bool hostSeen = false;
    SIZE_T regularCount = 0;
    for (SIZE_T index = 0; index < options.HeaderCount; ++index)
    {
        const qpack::QpackFieldView &field = options.Headers[index];
        if (!NT_SUCCESS(ValidateRegularField(field, false, applicationError)))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (TextEquals(field.Name, "host", 4, true))
        {
            if (hostSeen)
            {
                return Fail(applicationError);
            }
            hostSeen = true;
            host = field.Value;
            continue;
        }
        ++regularCount;
    }
    if (hostSeen && !ViewsEqualIgnoreCase(host, options.Authority))
    {
        return Fail(applicationError);
    }
    if (regularCount > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - pseudoCount ||
        pseudoCount + regularCount > fieldCapacity)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    SIZE_T output = 0;
    fields[output++] = {{MethodName, sizeof(MethodName)}, options.Method, false};
    if (!options.Connect)
    {
        fields[output++] = {{SchemeName, sizeof(SchemeName)}, options.Scheme, false};
    }
    fields[output++] = {{AuthorityName, sizeof(AuthorityName)}, options.Authority, false};
    if (!options.Connect)
    {
        fields[output++] = {{PathName, sizeof(PathName)}, options.Path, false};
    }
    for (SIZE_T index = 0; index < options.HeaderCount; ++index)
    {
        if (!TextEquals(options.Headers[index].Name, "host", 4, true))
        {
            fields[output++] = options.Headers[index];
        }
    }
    *fieldCount = output;
    return output == pseudoCount + regularCount ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS Http3ValidateTrailers(const qpack::QpackFieldView *fields, SIZE_T fieldCount,
                               ULONGLONG *applicationError) noexcept
{
    if (applicationError != nullptr)
    {
        *applicationError = H3_NO_ERROR;
    }
    if ((fields == nullptr && fieldCount != 0) || applicationError == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    for (SIZE_T index = 0; index < fieldCount; ++index)
    {
        if (!NT_SUCCESS(ValidateRegularField(fields[index], true, applicationError)))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
    }
    return STATUS_SUCCESS;
}

void Http3ResponseStateInitialize(Http3ResponseState *state, bool requestWasHead, bool requestWasConnect) noexcept
{
    if (state != nullptr)
    {
        *state = {};
        state->RequestWasHead = requestWasHead;
        state->RequestWasConnect = requestWasConnect;
    }
}

NTSTATUS Http3ProcessResponseFields(Http3ResponseState *state, const qpack::QpackFieldView *fields, SIZE_T fieldCount,
                                    bool trailers, ULONGLONG *applicationError) noexcept
{
    if (applicationError != nullptr)
    {
        *applicationError = H3_NO_ERROR;
    }
    if (state == nullptr || (fields == nullptr && fieldCount != 0) || applicationError == nullptr || state->Complete)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (trailers)
    {
        if (!state->FinalHeadersReceived || state->TrailersReceived ||
            !NT_SUCCESS(Http3ValidateTrailers(fields, fieldCount, applicationError)))
        {
            return Fail(applicationError);
        }
        state->TrailersReceived = true;
        return STATUS_SUCCESS;
    }
    if (state->FinalHeadersReceived)
    {
        return Fail(applicationError);
    }

    bool regularSeen = false;
    bool statusSeen = false;
    bool contentLengthSeen = false;
    ULONG statusCode = 0;
    ULONGLONG contentLength = 0;
    for (SIZE_T index = 0; index < fieldCount; ++index)
    {
        const qpack::QpackFieldView &field = fields[index];
        const bool pseudo = field.Name.Length != 0 && field.Name.Data != nullptr && field.Name.Data[0] == ':';
        if (pseudo)
        {
            if (regularSeen || statusSeen || !IsValidFieldValue(field.Value) ||
                !TextEquals(field.Name, ":status", 7, false) || !NT_SUCCESS(ParseStatus(field.Value, &statusCode)))
            {
                return Fail(applicationError);
            }
            statusSeen = true;
            continue;
        }
        regularSeen = true;
        if (!NT_SUCCESS(ValidateRegularField(field, false, applicationError)))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (TextEquals(field.Name, "content-length", 14, true))
        {
            if (contentLengthSeen || !NT_SUCCESS(ParseContentLength(field.Value, &contentLength)))
            {
                return Fail(applicationError);
            }
            contentLengthSeen = true;
        }
    }
    if (!statusSeen)
    {
        return Fail(applicationError);
    }
    if (statusCode < 200)
    {
        ++state->InformationalCount;
        return STATUS_SUCCESS;
    }

    state->StatusCode = statusCode;
    state->FinalHeadersReceived = true;
    state->ContentLengthPresent = contentLengthSeen;
    state->ContentLength = contentLength;
    state->BodyForbidden = state->RequestWasHead || statusCode == 204 || statusCode == 304 ||
                           (state->RequestWasConnect && statusCode >= 200 && statusCode < 300);
    if (state->BodyForbidden && contentLengthSeen && contentLength != 0)
    {
        return Fail(applicationError);
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3ProcessResponseData(Http3ResponseState *state, SIZE_T length, ULONGLONG *applicationError) noexcept
{
    if (applicationError != nullptr)
    {
        *applicationError = H3_NO_ERROR;
    }
    if (state == nullptr || applicationError == nullptr || state->Complete)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!state->FinalHeadersReceived || state->TrailersReceived || (state->BodyForbidden && length != 0) ||
        static_cast<ULONGLONG>(length) > static_cast<ULONGLONG>(~0ULL) - state->BodyBytes)
    {
        return Fail(applicationError);
    }
    state->BodyBytes += length;
    if (state->ContentLengthPresent && state->BodyBytes > state->ContentLength)
    {
        return Fail(applicationError);
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3CompleteResponse(Http3ResponseState *state, ULONGLONG *applicationError) noexcept
{
    if (applicationError != nullptr)
    {
        *applicationError = H3_NO_ERROR;
    }
    if (state == nullptr || applicationError == nullptr || state->Complete)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!state->FinalHeadersReceived || (state->ContentLengthPresent && state->BodyBytes != state->ContentLength))
    {
        return Fail(applicationError);
    }
    state->Complete = true;
    return STATUS_SUCCESS;
}
} // namespace wknet::http3
