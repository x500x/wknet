#include <wknet/http1/HttpRequest.h>

namespace wknet
{
namespace http1
{
    namespace
    {
        bool IsValidRequestTargetByte(char value) noexcept
        {
            const unsigned char ch = static_cast<unsigned char>(value);
            return ch > 0x20 && ch != 0x7f;
        }

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

        bool IsValidHeaderValueByte(char value) noexcept
        {
            const unsigned char ch = static_cast<unsigned char>(value);
            return value == '\t' || (ch >= 0x20 && ch != 0x7f);
        }

        bool IsValidText(
            HttpText text,
            _In_ bool (*predicate)(char)) noexcept
        {
            if (text.Data == nullptr || text.Length == 0 || predicate == nullptr) {
                return false;
            }

            for (SIZE_T index = 0; index < text.Length; ++index) {
                if (!predicate(text.Data[index])) {
                    return false;
                }
            }

            return true;
        }

        bool IsValidRequestTarget(HttpText path) noexcept
        {
            return IsValidText(path, IsValidRequestTargetByte);
        }

        bool IsValidHeaderName(HttpText text) noexcept
        {
            return IsValidText(text, IsValidHeaderNameByte);
        }

        bool IsValidHeaderValue(HttpText text) noexcept
        {
            if (text.Data == nullptr && text.Length != 0) {
                return false;
            }

            for (SIZE_T index = 0; index < text.Length; ++index) {
                if (!IsValidHeaderValueByte(text.Data[index])) {
                    return false;
                }
            }

            return true;
        }

        class BufferWriter final
        {
        public:
            BufferWriter(char* destination, SIZE_T capacity) noexcept
                : destination_(destination),
                  capacity_(capacity)
            {
            }

            _Must_inspect_result_
            NTSTATUS Append(HttpText text) noexcept
            {
                if (text.Length == 0) {
                    return STATUS_SUCCESS;
                }

                if (text.Data == nullptr) {
                    return STATUS_INVALID_PARAMETER;
                }

                if (required_ > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - text.Length) {
                    return STATUS_INTEGER_OVERFLOW;
                }

                if (destination_ != nullptr && required_ < capacity_) {
                    const SIZE_T writable = (text.Length <= (capacity_ - required_)) ?
                        text.Length :
                        (capacity_ - required_);

                    for (SIZE_T index = 0; index < writable; ++index) {
                        destination_[required_ + index] = text.Data[index];
                    }
                }

                required_ += text.Length;
                return STATUS_SUCCESS;
            }

            _Must_inspect_result_
            NTSTATUS AppendByte(char value) noexcept
            {
                if (required_ == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                    return STATUS_INTEGER_OVERFLOW;
                }

                if (destination_ != nullptr && required_ < capacity_) {
                    destination_[required_] = value;
                }

                ++required_;
                return STATUS_SUCCESS;
            }

            _Must_inspect_result_
            NTSTATUS AppendLiteral(const char* text) noexcept
            {
                return Append(MakeText(text));
            }

            _Must_inspect_result_
            NTSTATUS AppendHeader(HttpText name, HttpText value) noexcept
            {
                if (!IsValidHeaderName(name) || !IsValidHeaderValue(value)) {
                    return STATUS_INVALID_PARAMETER;
                }

                NTSTATUS status = Append(name);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = AppendLiteral(": ");
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = Append(value);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                return AppendLiteral("\r\n");
            }

            _Must_inspect_result_
            NTSTATUS AppendDecimal(SIZE_T value) noexcept
            {
                SIZE_T divisor = 1;
                while ((value / divisor) >= 10) {
                    divisor *= 10;
                }

                do {
                    NTSTATUS status = AppendByte(static_cast<char>('0' + ((value / divisor) % 10)));
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    divisor /= 10;
                } while (divisor != 0);

                return STATUS_SUCCESS;
            }

            _Must_inspect_result_
            NTSTATUS AppendHex(SIZE_T value) noexcept
            {
                SIZE_T shift = (sizeof(SIZE_T) * 8) - 4;
                bool wroteDigit = false;

                for (;;) {
                    const SIZE_T digit = (value >> shift) & 0x0f;
                    if (digit != 0 || wroteDigit || shift == 0) {
                        static constexpr char hex[] = "0123456789abcdef";
                        NTSTATUS status = AppendByte(hex[digit]);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        wroteDigit = true;
                    }

                    if (shift == 0) {
                        break;
                    }

                    shift -= 4;
                }

                return STATUS_SUCCESS;
            }

            SIZE_T Required() const noexcept
            {
                return required_;
            }

            bool Fits() const noexcept
            {
                return required_ <= capacity_;
            }

        private:
            char* destination_ = nullptr;
            SIZE_T capacity_ = 0;
            SIZE_T required_ = 0;
        };

        HttpText MethodText(const HttpRequestBuildOptions& options) noexcept
        {
            switch (options.Method) {
            case HttpMethod::Get:
                return MakeText("GET");
            case HttpMethod::Post:
                return MakeText("POST");
            case HttpMethod::Put:
                return MakeText("PUT");
            case HttpMethod::DeleteMethod:
                return MakeText("DELETE");
            case HttpMethod::Head:
                return MakeText("HEAD");
            case HttpMethod::Options:
                return MakeText("OPTIONS");
            case HttpMethod::Patch:
                return MakeText("PATCH");
            case HttpMethod::Connect:
                return MakeText("CONNECT");
            case HttpMethod::Trace:
                return MakeText("TRACE");
            case HttpMethod::Custom:
                return options.CustomMethod;
            default:
                return {};
            }
        }

        bool IsTraceMethod(const HttpRequestBuildOptions& options) noexcept
        {
            const HttpText method = MethodText(options);
            return TextEqualsIgnoreCase(method, MakeText("TRACE"));
        }

        bool IsTraceSensitiveHeader(HttpText name) noexcept
        {
            return TextEqualsIgnoreCase(name, MakeText("Authorization")) ||
                TextEqualsIgnoreCase(name, MakeText("Proxy-Authorization")) ||
                TextEqualsIgnoreCase(name, MakeText("Cookie"));
        }

        bool HeaderNameEquals(const HttpHeader& header, HttpText name) noexcept
        {
            return TextEqualsIgnoreCase(header.Name, name);
        }

        bool IsForbiddenTrailerField(HttpText name) noexcept
        {
            return TextEqualsIgnoreCase(name, MakeText("Content-Length")) ||
                TextEqualsIgnoreCase(name, MakeText("Transfer-Encoding")) ||
                TextEqualsIgnoreCase(name, MakeText("Host")) ||
                TextEqualsIgnoreCase(name, MakeText("Authorization")) ||
                TextEqualsIgnoreCase(name, MakeText("Proxy-Authorization")) ||
                TextEqualsIgnoreCase(name, MakeText("Cookie")) ||
                TextEqualsIgnoreCase(name, MakeText("Set-Cookie"));
        }

        bool RequestEmitsChunkedFraming(const HttpRequestBuildOptions& options) noexcept
        {
            return options.BodyMode == HttpRequestBodyMode::Chunked &&
                (options.BodyLength != 0 || options.IncludeContentLength);
        }

        _Must_inspect_result_
        NTSTATUS ValidateExtraHeaders(const HttpRequestBuildOptions& options) noexcept
        {
            const bool hasBody = options.BodyLength != 0 || options.IncludeContentLength;
            const bool chunkedFraming = RequestEmitsChunkedFraming(options);
            const bool traceMethod = IsTraceMethod(options);

            for (SIZE_T index = 0; index < options.ExtraHeaderCount; ++index) {
                const HttpHeader& header = options.ExtraHeaders[index];
                if (HeaderNameEquals(header, MakeText("Transfer-Encoding"))) {
                    return STATUS_NOT_SUPPORTED;
                }

                if (HeaderNameEquals(header, MakeText("TE"))) {
                    return STATUS_NOT_SUPPORTED;
                }

                // `Trailer` advertises which trailer fields will follow; it is only
                // meaningful when the request actually emits chunked framing.
                if (HeaderNameEquals(header, MakeText("Trailer")) && !chunkedFraming) {
                    return STATUS_NOT_SUPPORTED;
                }

                if (hasBody &&
                    HeaderNameEquals(header, MakeText("Expect")) &&
                    HeaderValueHasToken(header.Value, MakeText("100-continue")) &&
                    !options.AllowExpectContinue) {
                    return STATUS_NOT_SUPPORTED;
                }

                if (HeaderNameEquals(header, MakeText("Host")) ||
                    HeaderNameEquals(header, MakeText("Content-Length")) ||
                    HeaderNameEquals(header, MakeText("Connection"))) {
                    return STATUS_INVALID_PARAMETER;
                }

                if (traceMethod && IsTraceSensitiveHeader(header.Name)) {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ValidateTrailers(const HttpRequestBuildOptions& options) noexcept
        {
            if (options.TrailerCount == 0) {
                return STATUS_SUCCESS;
            }

            if (options.Trailers == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            // Trailers ride in the chunked trailer section, so the request must
            // actually emit chunked framing for there to be a place to put them.
            if (!RequestEmitsChunkedFraming(options)) {
                return STATUS_NOT_SUPPORTED;
            }

            for (SIZE_T index = 0; index < options.TrailerCount; ++index) {
                const HttpHeader& trailer = options.Trailers[index];
                if (!IsValidHeaderName(trailer.Name) || !IsValidHeaderValue(trailer.Value)) {
                    return STATUS_INVALID_PARAMETER;
                }

                if (IsForbiddenTrailerField(trailer.Name)) {
                    return STATUS_NOT_SUPPORTED;
                }
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AppendContentLength(BufferWriter& writer, SIZE_T bodyLength) noexcept
        {
            NTSTATUS status = writer.AppendLiteral("Content-Length: ");
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = writer.AppendDecimal(bodyLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            return writer.AppendLiteral("\r\n");
        }

        _Must_inspect_result_
        NTSTATUS AppendChunkedBody(
            BufferWriter& writer,
            const char* body,
            SIZE_T bodyLength,
            const HttpHeader* trailers,
            SIZE_T trailerCount) noexcept
        {
            if (body == nullptr && bodyLength != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (bodyLength != 0) {
                NTSTATUS status = writer.AppendHex(bodyLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = writer.AppendLiteral("\r\n");
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = writer.Append({ body, bodyLength });
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = writer.AppendLiteral("\r\n");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            NTSTATUS status = writer.AppendLiteral("0\r\n");
            if (!NT_SUCCESS(status)) {
                return status;
            }

            for (SIZE_T index = 0; index < trailerCount; ++index) {
                status = writer.AppendHeader(trailers[index].Name, trailers[index].Value);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            return writer.AppendLiteral("\r\n");
        }

        _Must_inspect_result_
        NTSTATUS ValidateBuildOptions(
            const HttpRequestBuildOptions& options,
            bool requireBodyBytes) noexcept
        {
            if (!IsValidRequestTarget(options.Path) || !IsValidHeaderValue(options.Host)) {
                return STATUS_INVALID_PARAMETER;
            }

            if (requireBodyBytes && options.BodyLength > 0 && options.Body == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (options.BodyMode != HttpRequestBodyMode::ContentLength &&
                options.BodyMode != HttpRequestBodyMode::Chunked) {
                return STATUS_INVALID_PARAMETER;
            }

            if (options.ExtraHeaderCount > 0 && options.ExtraHeaders == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            const bool traceMethod = IsTraceMethod(options);
            if (traceMethod && !options.AllowTrace) {
                return STATUS_NOT_SUPPORTED;
            }

            if (traceMethod &&
                (options.BodyLength != 0 ||
                    options.IncludeContentLength ||
                    options.TrailerCount != 0)) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = ValidateExtraHeaders(options);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ValidateTrailers(options);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const HttpText method = MethodText(options);
            if (!IsValidHeaderName(method)) {
                return STATUS_INVALID_PARAMETER;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AppendRequestHeaders(
            BufferWriter& writer,
            const HttpRequestBuildOptions& options) noexcept
        {
            const HttpText method = MethodText(options);
            NTSTATUS status = writer.Append(method);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = writer.AppendLiteral(" ");
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = writer.Append(options.Path);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = writer.AppendLiteral(" HTTP/1.1\r\n");
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = writer.AppendHeader(MakeText("Host"), options.Host);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (options.UserAgent.Length > 0) {
                status = writer.AppendHeader(MakeText("User-Agent"), options.UserAgent);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (options.ContentType.Length > 0) {
                status = writer.AppendHeader(MakeText("Content-Type"), options.ContentType);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            const bool hasBody = options.BodyLength > 0 || options.IncludeContentLength;
            if (hasBody) {
                if (options.BodyMode == HttpRequestBodyMode::Chunked) {
                    status = writer.AppendHeader(MakeText("Transfer-Encoding"), MakeText("chunked"));
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                else {
                    status = AppendContentLength(writer, options.BodyLength);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }

            if (options.Connection == HttpConnectionDirective::KeepAlive) {
                status = writer.AppendHeader(MakeText("Connection"), MakeText("keep-alive"));
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else if (options.Connection == HttpConnectionDirective::Close) {
                status = writer.AppendHeader(MakeText("Connection"), MakeText("close"));
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else if (options.Connection == HttpConnectionDirective::Upgrade) {
                status = writer.AppendHeader(MakeText("Connection"), MakeText("Upgrade"));
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            for (SIZE_T index = 0; index < options.ExtraHeaderCount; ++index) {
                status = writer.AppendHeader(options.ExtraHeaders[index].Name, options.ExtraHeaders[index].Value);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            return writer.AppendLiteral("\r\n");
        }

        _Must_inspect_result_
        NTSTATUS AppendRequestBody(
            BufferWriter& writer,
            const HttpRequestBuildOptions& options) noexcept
        {
            const bool hasBody = options.BodyLength > 0 || options.IncludeContentLength;
            if (!hasBody) {
                return STATUS_SUCCESS;
            }

            if (options.BodyMode == HttpRequestBodyMode::Chunked) {
                return AppendChunkedBody(
                    writer,
                    options.Body,
                    options.BodyLength,
                    options.Trailers,
                    options.TrailerCount);
            }

            if (options.BodyLength == 0) {
                return STATUS_SUCCESS;
            }

            return writer.Append({ options.Body, options.BodyLength });
        }

        _Must_inspect_result_
        NTSTATUS BuildInto(
            const HttpRequestBuildOptions& options,
            char* destination,
            SIZE_T destinationCapacity,
            SIZE_T* bytesWritten,
            bool includeHeaders,
            bool includeBody) noexcept
        {
            if (bytesWritten != nullptr) {
                *bytesWritten = 0;
            }

            if (destination == nullptr && destinationCapacity != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            NTSTATUS status = ValidateBuildOptions(options, includeBody);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            BufferWriter writer(destination, destinationCapacity);

            if (includeHeaders) {
                status = AppendRequestHeaders(writer, options);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (includeBody) {
                status = AppendRequestBody(writer, options);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            if (bytesWritten != nullptr) {
                *bytesWritten = writer.Required();
            }

            return writer.Fits() ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
        }
    }

    NTSTATUS HttpRequestBuilder::Build(
        const HttpRequestBuildOptions& options,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        return BuildInto(
            options,
            destination,
            destinationCapacity,
            bytesWritten,
            true,
            true);
    }

    NTSTATUS HttpRequestBuilder::BuildHeaders(
        const HttpRequestBuildOptions& options,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        return BuildInto(
            options,
            destination,
            destinationCapacity,
            bytesWritten,
            true,
            false);
    }

    NTSTATUS HttpRequestBuilder::BuildBody(
        const HttpRequestBuildOptions& options,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        return BuildInto(
            options,
            destination,
            destinationCapacity,
            bytesWritten,
            false,
            true);
    }
}
}
