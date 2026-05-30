#include <KernelHttp/http/HttpRequest.h>

namespace KernelHttp
{
namespace http
{
    namespace
    {
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
            NTSTATUS AppendLiteral(const char* text) noexcept
            {
                return Append(MakeText(text));
            }

            _Must_inspect_result_
            NTSTATUS AppendHeader(HttpText name, HttpText value) noexcept
            {
                if (name.Data == nullptr || name.Length == 0 ||
                    value.Data == nullptr || value.Length == 0) {
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
                HeapArray<char> digits((sizeof(SIZE_T) * 3) + 1);
                if (!digits.IsValid()) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                SIZE_T digitCount = 0;

                do {
                    digits[digitCount] = static_cast<char>('0' + (value % 10));
                    value /= 10;
                    ++digitCount;
                } while (value != 0);

                for (SIZE_T index = 0; index < (digitCount / 2); ++index) {
                    const char temp = digits[index];
                    digits[index] = digits[digitCount - 1 - index];
                    digits[digitCount - 1 - index] = temp;
                }

                return Append({ digits.Get(), digitCount });
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
            case HttpMethod::Custom:
                return options.CustomMethod;
            default:
                return {};
            }
        }

        bool IsValidRequestTarget(HttpText path) noexcept
        {
            return path.Data != nullptr && path.Length > 0;
        }

        bool IsValidHeaderText(HttpText text) noexcept
        {
            return text.Data != nullptr && text.Length > 0;
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
    }

    NTSTATUS HttpRequestBuilder::Build(
        const HttpRequestBuildOptions& options,
        char* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten != nullptr) {
            *bytesWritten = 0;
        }

        if (destination == nullptr && destinationCapacity != 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!IsValidRequestTarget(options.Path) || !IsValidHeaderText(options.Host)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options.BodyLength > 0 && options.Body == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (options.ExtraHeaderCount > 0 && options.ExtraHeaders == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const HttpText method = MethodText(options);
        if (!IsValidHeaderText(method)) {
            return STATUS_INVALID_PARAMETER;
        }

        BufferWriter writer(destination, destinationCapacity);

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

        if (options.BodyLength > 0 || options.IncludeContentLength) {
            status = AppendContentLength(writer, options.BodyLength);
            if (!NT_SUCCESS(status)) {
                return status;
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

        for (SIZE_T index = 0; index < options.ExtraHeaderCount; ++index) {
            status = writer.AppendHeader(options.ExtraHeaders[index].Name, options.ExtraHeaders[index].Value);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = writer.AppendLiteral("\r\n");
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (options.BodyLength > 0) {
            status = writer.Append({ options.Body, options.BodyLength });
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
}
