#include <KernelHttp/http/HttpContentEncoding.h>

#include <KernelHttp/http/HttpCoding.h>

namespace KernelHttp
{
namespace http
{
    namespace
    {
        constexpr SIZE_T MaxContentCodings = 2;
        constexpr char DefaultAcceptEncoding[] = "gzip, deflate, br, identity";
        constexpr char DeflateUnavailableAcceptEncoding[] = "br, identity";

        bool IsOptionalWhitespace(char value) noexcept
        {
            return value == ' ' || value == '\t';
        }

        HttpText TrimOptionalWhitespace(HttpText text) noexcept
        {
            while (text.Length > 0 && IsOptionalWhitespace(text.Data[0])) {
                ++text.Data;
                --text.Length;
            }

            while (text.Length > 0 && IsOptionalWhitespace(text.Data[text.Length - 1])) {
                --text.Length;
            }

            return text;
        }

        _Must_inspect_result_
        NTSTATUS ParseCoding(HttpText token, HttpCoding* coding) noexcept
        {
            if (coding == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            token = TrimOptionalWhitespace(token);
            if (token.Length == 0 || token.Data == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (TextEqualsIgnoreCase(token, MakeText("identity"))) {
                *coding = HttpCoding::Identity;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("gzip"))) {
                *coding = HttpCoding::Gzip;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("deflate"))) {
                *coding = HttpCoding::Deflate;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("br"))) {
                *coding = HttpCoding::Brotli;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("compress")) ||
                TextEqualsIgnoreCase(token, MakeText("x-compress"))) {
                *coding = HttpCoding::Compress;
                return STATUS_SUCCESS;
            }

            return STATUS_NOT_SUPPORTED;
        }

        _Must_inspect_result_
        NTSTATUS AppendCodings(
            HttpText value,
            HttpCoding* codings,
            SIZE_T* codingCount) noexcept
        {
            if (codings == nullptr || codingCount == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T cursor = 0;
            for (;;) {
                const SIZE_T tokenStart = cursor;
                while (cursor < value.Length && value.Data[cursor] != ',') {
                    ++cursor;
                }

                if (*codingCount >= MaxContentCodings) {
                    return STATUS_NOT_SUPPORTED;
                }

                NTSTATUS status = ParseCoding(
                    { value.Data + tokenStart, cursor - tokenStart },
                    &codings[*codingCount]);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                ++(*codingCount);

                if (cursor == value.Length) {
                    return STATUS_SUCCESS;
                }

                ++cursor;
                if (cursor == value.Length) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }

        bool IsValidAcceptCoding(HttpAcceptCoding coding) noexcept
        {
            switch (coding) {
            case HttpAcceptCoding::Identity:
            case HttpAcceptCoding::Gzip:
            case HttpAcceptCoding::Deflate:
            case HttpAcceptCoding::Brotli:
            case HttpAcceptCoding::Compress:
            case HttpAcceptCoding::Any:
                return true;
            default:
                return false;
            }
        }

        SIZE_T AcceptCodingMask(HttpAcceptCoding coding) noexcept
        {
            return static_cast<SIZE_T>(1) << static_cast<UCHAR>(coding);
        }

        HttpText AcceptCodingText(HttpAcceptCoding coding) noexcept
        {
            switch (coding) {
            case HttpAcceptCoding::Identity:
                return MakeText("identity");
            case HttpAcceptCoding::Gzip:
                return MakeText("gzip");
            case HttpAcceptCoding::Deflate:
                return MakeText("deflate");
            case HttpAcceptCoding::Brotli:
                return MakeText("br");
            case HttpAcceptCoding::Compress:
                return MakeText("compress");
            case HttpAcceptCoding::Any:
                return MakeText("*");
            default:
                return {};
            }
        }

        HttpAcceptCoding ToAcceptCoding(HttpCoding coding) noexcept
        {
            switch (coding) {
            case HttpCoding::Gzip:
                return HttpAcceptCoding::Gzip;
            case HttpCoding::Deflate:
                return HttpAcceptCoding::Deflate;
            case HttpCoding::Brotli:
                return HttpAcceptCoding::Brotli;
            case HttpCoding::Compress:
                return HttpAcceptCoding::Compress;
            case HttpCoding::Identity:
            default:
                return HttpAcceptCoding::Identity;
            }
        }

        bool CodingRequiresDeflateRuntime(HttpAcceptCoding coding) noexcept
        {
            return coding == HttpAcceptCoding::Gzip ||
                coding == HttpAcceptCoding::Deflate;
        }

        class HeaderWriter final
        {
        public:
            HeaderWriter(char* destination, SIZE_T capacity) noexcept :
                destination_(destination),
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
                    const SIZE_T writable = text.Length <= (capacity_ - required_) ?
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

        _Must_inspect_result_
        NTSTATUS AppendQValue(HeaderWriter& writer, USHORT qvalue) noexcept
        {
            if (qvalue == HttpAcceptEncodingQValueMax) {
                return STATUS_SUCCESS;
            }

            NTSTATUS status = writer.AppendLiteral(";q=");
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (qvalue == 0) {
                return writer.AppendByte('0');
            }

            status = writer.AppendLiteral("0.");
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const USHORT hundreds = static_cast<USHORT>(qvalue / 100);
            const USHORT tens = static_cast<USHORT>((qvalue / 10) % 10);
            const USHORT ones = static_cast<USHORT>(qvalue % 10);
            status = writer.AppendByte(static_cast<char>('0' + hundreds));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (ones == 0 && tens == 0) {
                return STATUS_SUCCESS;
            }

            status = writer.AppendByte(static_cast<char>('0' + tens));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (ones == 0) {
                return STATUS_SUCCESS;
            }

            return writer.AppendByte(static_cast<char>('0' + ones));
        }

        _Must_inspect_result_
        NTSTATUS ValidatePolicy(const HttpAcceptEncodingPolicy* policy) noexcept
        {
            if (policy == nullptr || policy->PreferenceCount == 0) {
                return STATUS_SUCCESS;
            }

            return HttpContentEncoding::ValidateAcceptEncodingPreferences(
                policy->Preferences,
                policy->PreferenceCount);
        }

        bool PolicyForbidsCoding(
            const HttpAcceptEncodingPolicy* policy,
            HttpAcceptCoding coding) noexcept
        {
            if (policy == nullptr ||
                policy->Preferences == nullptr ||
                policy->PreferenceCount == 0) {
                return false;
            }

            bool exactFound = false;
            USHORT exactQValue = HttpAcceptEncodingQValueMax;
            bool wildcardFound = false;
            USHORT wildcardQValue = HttpAcceptEncodingQValueMax;
            for (SIZE_T index = 0; index < policy->PreferenceCount; ++index) {
                const HttpAcceptEncodingPreference& preference = policy->Preferences[index];
                if (preference.Coding == coding) {
                    exactFound = true;
                    exactQValue = preference.QValue;
                }
                else if (preference.Coding == HttpAcceptCoding::Any) {
                    wildcardFound = true;
                    wildcardQValue = preference.QValue;
                }
            }

            if (exactFound) {
                return exactQValue == 0;
            }

            return wildcardFound && wildcardQValue == 0;
        }
    }

    NTSTATUS HttpContentEncoding::Decode(
        const HttpHeader* headers,
        SIZE_T headerCount,
        const char* body,
        SIZE_T bodyLength,
        const HttpContentDecodeBuffers& buffers,
        HttpContentDecodeResult& result,
        const HttpAcceptEncodingPolicy* acceptPolicy) noexcept
    {
        result = {};
        result.Body = bodyLength == 0 ? nullptr : body;
        result.BodyLength = bodyLength;

        if ((headers == nullptr && headerCount != 0) ||
            (body == nullptr && bodyLength != 0)) {
            result = {};
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<HttpCoding> codings(MaxContentCodings);
        if (!codings.IsValid()) {
            result = {};
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T codingCount = 0;
        NTSTATUS status = ValidatePolicy(acceptPolicy);
        if (!NT_SUCCESS(status)) {
            result = {};
            return status;
        }

        for (SIZE_T index = 0; index < headerCount; ++index) {
            if (!TextEqualsIgnoreCase(headers[index].Name, MakeText("Content-Encoding"))) {
                continue;
            }

            status = AppendCodings(headers[index].Value, codings.Get(), &codingCount);
            if (!NT_SUCCESS(status)) {
                result = {};
                return status;
            }
        }

        if (codingCount == 0 && bodyLength != 0) {
            if (PolicyForbidsCoding(acceptPolicy, HttpAcceptCoding::Identity)) {
                result = {};
                return STATUS_NOT_SUPPORTED;
            }
        }
        else {
            for (SIZE_T index = 0; index < codingCount; ++index) {
                if (PolicyForbidsCoding(acceptPolicy, ToAcceptCoding(codings[index]))) {
                    result = {};
                    return STATUS_NOT_SUPPORTED;
                }
            }
        }

        if (codingCount == 0 || bodyLength == 0) {
            return STATUS_SUCCESS;
        }

        HttpCodingDecodeBuffers codingBuffers = {};
        codingBuffers.DecodedBody = buffers.DecodedBody;
        codingBuffers.DecodedBodyCapacity = buffers.DecodedBodyCapacity;
        codingBuffers.ScratchBody = buffers.ScratchBody;
        codingBuffers.ScratchBodyCapacity = buffers.ScratchBodyCapacity;

        HttpCodingDecodeResult decoded = {};
        status = HttpCodingCodec::DecodeChainReverse(
            codings.Get(),
            codingCount,
            body,
            bodyLength,
            codingBuffers,
            decoded);
        if (!NT_SUCCESS(status)) {
            result = {};
            return status;
        }

        result.Body = decoded.Body;
        result.BodyLength = decoded.BodyLength;
        result.AppliedContentCoding = decoded.AppliedCoding;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpContentEncoding::ValidateAcceptEncodingPreferences(
        const HttpAcceptEncodingPreference* preferences,
        SIZE_T preferenceCount) noexcept
    {
        if (preferenceCount == 0) {
            return STATUS_SUCCESS;
        }

        if (preferences == nullptr ||
            preferenceCount > HttpMaxAcceptEncodingPreferences) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T seenMask = 0;
        for (SIZE_T index = 0; index < preferenceCount; ++index) {
            const HttpAcceptEncodingPreference& preference = preferences[index];
            if (!IsValidAcceptCoding(preference.Coding) ||
                preference.QValue > HttpAcceptEncodingQValueMax) {
                return STATUS_INVALID_PARAMETER;
            }

            const SIZE_T mask = AcceptCodingMask(preference.Coding);
            if ((seenMask & mask) != 0) {
                return STATUS_INVALID_PARAMETER;
            }
            seenMask |= mask;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS HttpContentEncoding::BuildAcceptEncodingHeader(
        const HttpAcceptEncodingPreference* preferences,
        SIZE_T preferenceCount,
        char* destination,
        SIZE_T destinationCapacity,
        HttpText* value) noexcept
    {
        if (value != nullptr) {
            *value = {};
        }
        if (value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = ValidateAcceptEncodingPreferences(preferences, preferenceCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (preferenceCount == 0) {
            *value = MakeText(
                HttpCodingCodec::DeflateRuntimeAvailable() ?
                    DefaultAcceptEncoding :
                    DeflateUnavailableAcceptEncoding);
            return STATUS_SUCCESS;
        }

        if (destination == nullptr || destinationCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        HeaderWriter writer(destination, destinationCapacity);
        const bool deflateRuntimeAvailable = HttpCodingCodec::DeflateRuntimeAvailable();
        for (SIZE_T index = 0; index < preferenceCount; ++index) {
            const HttpAcceptEncodingPreference& preference = preferences[index];
            if (preference.QValue != 0 &&
                CodingRequiresDeflateRuntime(preference.Coding) &&
                !deflateRuntimeAvailable) {
                return STATUS_NOT_SUPPORTED;
            }

            if (index != 0) {
                status = writer.AppendLiteral(", ");
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            status = writer.Append(AcceptCodingText(preference.Coding));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = AppendQValue(writer, preference.QValue);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (!writer.Fits()) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        *value = { destination, writer.Required() };
        return STATUS_SUCCESS;
    }
}
}
