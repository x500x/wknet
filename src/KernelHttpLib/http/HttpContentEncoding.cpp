#include <KernelHttp/http/HttpContentEncoding.h>

#include <KernelHttp/http/HttpCoding.h>

namespace KernelHttp
{
namespace http
{
    namespace
    {
        constexpr SIZE_T MaxContentCodings = 8;
        constexpr char DefaultAcceptEncoding[] = "gzip, deflate, br, zstd, identity";
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

        bool IsUpperAscii(char value) noexcept
        {
            return value >= 'A' && value <= 'Z';
        }

        char ToLowerAscii(char value) noexcept
        {
            return IsUpperAscii(value) ? static_cast<char>(value - 'A' + 'a') : value;
        }

        bool IsTokenChar(char value) noexcept
        {
            const unsigned char ch = static_cast<unsigned char>(value);
            if ((ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9')) {
                return true;
            }

            switch (value) {
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

        bool TokenEqualsIgnoreCase(HttpText left, HttpText right) noexcept
        {
            if (left.Length != right.Length || left.Data == nullptr || right.Data == nullptr) {
                return false;
            }

            for (SIZE_T index = 0; index < left.Length; ++index) {
                if (ToLowerAscii(left.Data[index]) != ToLowerAscii(right.Data[index])) {
                    return false;
                }
            }

            return true;
        }

        bool IsValidToken(HttpText token) noexcept
        {
            if (token.Data == nullptr || token.Length == 0) {
                return false;
            }

            for (SIZE_T index = 0; index < token.Length; ++index) {
                if (!IsTokenChar(token.Data[index])) {
                    return false;
                }
            }

            return true;
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

            if (TextEqualsIgnoreCase(token, MakeText("gzip")) ||
                TextEqualsIgnoreCase(token, MakeText("x-gzip"))) {
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

            if (TextEqualsIgnoreCase(token, MakeText("zstd"))) {
                *coding = HttpCoding::Zstd;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("dcb"))) {
                *coding = HttpCoding::DictionaryCompressedBrotli;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("dcz"))) {
                *coding = HttpCoding::DictionaryCompressedZstd;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("aes128gcm"))) {
                *coding = HttpCoding::Aes128Gcm;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("exi"))) {
                *coding = HttpCoding::Exi;
                return STATUS_SUCCESS;
            }

            if (TextEqualsIgnoreCase(token, MakeText("pack200-gzip"))) {
                *coding = HttpCoding::Pack200Gzip;
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
            case HttpAcceptCoding::Zstd:
            case HttpAcceptCoding::DictionaryCompressedBrotli:
            case HttpAcceptCoding::DictionaryCompressedZstd:
            case HttpAcceptCoding::Aes128Gcm:
            case HttpAcceptCoding::Exi:
            case HttpAcceptCoding::Pack200Gzip:
            case HttpAcceptCoding::Any:
            case HttpAcceptCoding::Extension:
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
            case HttpAcceptCoding::Zstd:
                return MakeText("zstd");
            case HttpAcceptCoding::DictionaryCompressedBrotli:
                return MakeText("dcb");
            case HttpAcceptCoding::DictionaryCompressedZstd:
                return MakeText("dcz");
            case HttpAcceptCoding::Aes128Gcm:
                return MakeText("aes128gcm");
            case HttpAcceptCoding::Exi:
                return MakeText("exi");
            case HttpAcceptCoding::Pack200Gzip:
                return MakeText("pack200-gzip");
            case HttpAcceptCoding::Any:
                return MakeText("*");
            case HttpAcceptCoding::Extension:
                return {};
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
            case HttpCoding::Zstd:
                return HttpAcceptCoding::Zstd;
            case HttpCoding::DictionaryCompressedBrotli:
                return HttpAcceptCoding::DictionaryCompressedBrotli;
            case HttpCoding::DictionaryCompressedZstd:
                return HttpAcceptCoding::DictionaryCompressedZstd;
            case HttpCoding::Aes128Gcm:
                return HttpAcceptCoding::Aes128Gcm;
            case HttpCoding::Exi:
                return HttpAcceptCoding::Exi;
            case HttpCoding::Pack200Gzip:
                return HttpAcceptCoding::Pack200Gzip;
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

        _Must_inspect_result_
        HttpAcceptCoding AcceptCodingFromToken(HttpText token, bool* wildcard, bool* extension) noexcept
        {
            if (wildcard != nullptr) {
                *wildcard = false;
            }
            if (extension != nullptr) {
                *extension = false;
            }

            token = TrimOptionalWhitespace(token);
            if (TextEqualsIgnoreCase(token, MakeText("*"))) {
                if (wildcard != nullptr) {
                    *wildcard = true;
                }
                return HttpAcceptCoding::Any;
            }
            if (TextEqualsIgnoreCase(token, MakeText("identity"))) {
                return HttpAcceptCoding::Identity;
            }
            if (TextEqualsIgnoreCase(token, MakeText("gzip")) ||
                TextEqualsIgnoreCase(token, MakeText("x-gzip"))) {
                return HttpAcceptCoding::Gzip;
            }
            if (TextEqualsIgnoreCase(token, MakeText("deflate"))) {
                return HttpAcceptCoding::Deflate;
            }
            if (TextEqualsIgnoreCase(token, MakeText("br"))) {
                return HttpAcceptCoding::Brotli;
            }
            if (TextEqualsIgnoreCase(token, MakeText("compress")) ||
                TextEqualsIgnoreCase(token, MakeText("x-compress"))) {
                return HttpAcceptCoding::Compress;
            }
            if (TextEqualsIgnoreCase(token, MakeText("zstd"))) {
                return HttpAcceptCoding::Zstd;
            }
            if (TextEqualsIgnoreCase(token, MakeText("dcb"))) {
                return HttpAcceptCoding::DictionaryCompressedBrotli;
            }
            if (TextEqualsIgnoreCase(token, MakeText("dcz"))) {
                return HttpAcceptCoding::DictionaryCompressedZstd;
            }
            if (TextEqualsIgnoreCase(token, MakeText("aes128gcm"))) {
                return HttpAcceptCoding::Aes128Gcm;
            }
            if (TextEqualsIgnoreCase(token, MakeText("exi"))) {
                return HttpAcceptCoding::Exi;
            }
            if (TextEqualsIgnoreCase(token, MakeText("pack200-gzip"))) {
                return HttpAcceptCoding::Pack200Gzip;
            }

            if (extension != nullptr) {
                *extension = true;
            }
            return HttpAcceptCoding::Extension;
        }

        _Must_inspect_result_
        bool EntryMatchesCoding(const HttpAcceptEncodingEntry& entry, HttpAcceptCoding coding, HttpText token) noexcept
        {
            if (entry.Wildcard) {
                return false;
            }

            if (entry.Extension || coding == HttpAcceptCoding::Extension) {
                return entry.Extension &&
                    coding == HttpAcceptCoding::Extension &&
                    TokenEqualsIgnoreCase(entry.Token, token);
            }

            return entry.Coding == coding;
        }

        _Must_inspect_result_
        NTSTATUS AddAcceptEncodingEntry(
            HttpText token,
            HttpAcceptCoding coding,
            USHORT qvalue,
            bool wildcard,
            bool extension,
            HttpAcceptEncodingRules* rules) noexcept
        {
            if (rules == nullptr || rules->Entries == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            if (rules->EmptyHeader) {
                return STATUS_INVALID_PARAMETER;
            }

            if (rules->EntryCount >= rules->EntryCapacity ||
                rules->EntryCount >= HttpMaxAcceptEncodingEntries) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            for (SIZE_T index = 0; index < rules->EntryCount; ++index) {
                const HttpAcceptEncodingEntry& existing = rules->Entries[index];
                if (wildcard && existing.Wildcard) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (!wildcard && EntryMatchesCoding(existing, coding, token)) {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            HttpAcceptEncodingEntry& entry = rules->Entries[rules->EntryCount];
            entry.Token = token;
            entry.Coding = coding;
            entry.QValue = qvalue;
            entry.Order = rules->EntryCount;
            entry.Wildcard = wildcard;
            entry.Extension = extension;
            ++rules->EntryCount;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseQValue(HttpText value, USHORT* qvalue) noexcept
        {
            if (qvalue == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            *qvalue = 0;

            value = TrimOptionalWhitespace(value);
            if (value.Data == nullptr || value.Length == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            if (value.Data[0] == '1') {
                if (value.Length == 1) {
                    *qvalue = HttpAcceptEncodingQValueMax;
                    return STATUS_SUCCESS;
                }
                if (value.Length < 3 || value.Data[1] != '.' || value.Length > 5) {
                    return STATUS_INVALID_PARAMETER;
                }
                for (SIZE_T index = 2; index < value.Length; ++index) {
                    if (value.Data[index] != '0') {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                *qvalue = HttpAcceptEncodingQValueMax;
                return STATUS_SUCCESS;
            }

            if (value.Data[0] != '0') {
                return STATUS_INVALID_PARAMETER;
            }

            if (value.Length == 1) {
                *qvalue = 0;
                return STATUS_SUCCESS;
            }

            if (value.Length < 3 || value.Data[1] != '.' || value.Length > 5) {
                return STATUS_INVALID_PARAMETER;
            }

            USHORT parsed = 0;
            USHORT scale = 100;
            for (SIZE_T index = 2; index < value.Length; ++index) {
                const char digit = value.Data[index];
                if (digit < '0' || digit > '9') {
                    return STATUS_INVALID_PARAMETER;
                }
                parsed = static_cast<USHORT>(parsed + ((digit - '0') * scale));
                scale = static_cast<USHORT>(scale / 10);
            }

            *qvalue = parsed;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseAcceptEncodingElement(HttpText element, HttpAcceptEncodingRules* rules) noexcept
        {
            element = TrimOptionalWhitespace(element);
            if (element.Data == nullptr || element.Length == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T cursor = 0;
            while (cursor < element.Length && element.Data[cursor] != ';') {
                ++cursor;
            }

            HttpText token = TrimOptionalWhitespace({ element.Data, cursor });
            if (!IsValidToken(token)) {
                return STATUS_INVALID_PARAMETER;
            }

            USHORT qvalue = HttpAcceptEncodingQValueMax;
            bool sawQValue = false;
            while (cursor < element.Length) {
                ++cursor;
                while (cursor < element.Length && IsOptionalWhitespace(element.Data[cursor])) {
                    ++cursor;
                }
                const SIZE_T nameStart = cursor;
                while (cursor < element.Length &&
                    element.Data[cursor] != '=' &&
                    element.Data[cursor] != ';') {
                    ++cursor;
                }

                HttpText name = TrimOptionalWhitespace({ element.Data + nameStart, cursor - nameStart });
                if (!TextEqualsIgnoreCase(name, MakeText("q")) || sawQValue) {
                    return STATUS_INVALID_PARAMETER;
                }
                if (cursor >= element.Length || element.Data[cursor] != '=') {
                    return STATUS_INVALID_PARAMETER;
                }
                ++cursor;

                const SIZE_T valueStart = cursor;
                while (cursor < element.Length && element.Data[cursor] != ';') {
                    ++cursor;
                }
                NTSTATUS status = ParseQValue(
                    { element.Data + valueStart, cursor - valueStart },
                    &qvalue);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                sawQValue = true;
            }

            bool wildcard = false;
            bool extension = false;
            const HttpAcceptCoding coding = AcceptCodingFromToken(token, &wildcard, &extension);
            return AddAcceptEncodingEntry(token, coding, qvalue, wildcard, extension, rules);
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

        _Must_inspect_result_
        NTSTATUS RulesQValueForCoding(
            const HttpAcceptEncodingRules* rules,
            HttpText token,
            HttpAcceptCoding coding,
            USHORT* qvalue) noexcept
        {
            if (qvalue == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *qvalue = HttpAcceptEncodingQValueMax;

            if (rules == nullptr) {
                return STATUS_SUCCESS;
            }

            if (rules->EmptyHeader) {
                *qvalue = coding == HttpAcceptCoding::Identity ? HttpAcceptEncodingQValueMax : 0;
                return STATUS_SUCCESS;
            }

            if (rules->Entries == nullptr && rules->EntryCount != 0) {
                return STATUS_INVALID_PARAMETER;
            }

            bool exactFound = false;
            USHORT exactQValue = 0;
            bool wildcardFound = false;
            USHORT wildcardQValue = HttpAcceptEncodingQValueMax;
            for (SIZE_T index = 0; index < rules->EntryCount; ++index) {
                const HttpAcceptEncodingEntry& entry = rules->Entries[index];
                if (entry.Wildcard) {
                    wildcardFound = true;
                    wildcardQValue = entry.QValue;
                    continue;
                }

                if (EntryMatchesCoding(entry, coding, token)) {
                    exactFound = true;
                    exactQValue = entry.QValue;
                    break;
                }
            }

            if (exactFound) {
                *qvalue = exactQValue;
                return STATUS_SUCCESS;
            }

            if (coding == HttpAcceptCoding::Identity) {
                *qvalue = wildcardFound && wildcardQValue == 0 ?
                    0 :
                    HttpAcceptEncodingQValueMax;
                return STATUS_SUCCESS;
            }

            *qvalue = wildcardFound ? wildcardQValue : 0;
            return STATUS_SUCCESS;
        }

        bool PolicyForbidsCoding(
            const HttpAcceptEncodingPolicy* policy,
            HttpText token,
            HttpAcceptCoding coding) noexcept
        {
            if (policy == nullptr ||
                ((policy->Preferences == nullptr || policy->PreferenceCount == 0) &&
                    policy->Rules == nullptr)) {
                return false;
            }

            if (policy->Rules != nullptr) {
                USHORT qvalue = 0;
                const NTSTATUS status = RulesQValueForCoding(policy->Rules, token, coding, &qvalue);
                return !NT_SUCCESS(status) || qvalue == 0;
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

            if (coding == HttpAcceptCoding::Identity) {
                return wildcardFound && wildcardQValue == 0;
            }

            return !wildcardFound || wildcardQValue == 0;
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
            if (PolicyForbidsCoding(acceptPolicy, MakeText("identity"), HttpAcceptCoding::Identity)) {
                result = {};
                return STATUS_NOT_SUPPORTED;
            }
        }
        else {
            for (SIZE_T index = 0; index < codingCount; ++index) {
                const HttpAcceptCoding acceptCoding = ToAcceptCoding(codings[index]);
                if (PolicyForbidsCoding(acceptPolicy, AcceptCodingText(acceptCoding), acceptCoding)) {
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
        codingBuffers.Materials = buffers.Materials;

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
                preference.Coding == HttpAcceptCoding::Extension ||
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

    NTSTATUS HttpContentEncoding::ParseAcceptEncoding(
        HttpText value,
        HttpAcceptEncodingRules* rules) noexcept
    {
        if (rules == nullptr ||
            rules->Entries == nullptr ||
            rules->EntryCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        value = TrimOptionalWhitespace(value);
        if (value.Data == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (value.Length == 0) {
            if (rules->EntryCount != 0 || rules->EmptyHeader) {
                return STATUS_INVALID_PARAMETER;
            }
            rules->EmptyHeader = true;
            return STATUS_SUCCESS;
        }

        if (rules->EmptyHeader) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T cursor = 0;
        for (;;) {
            const SIZE_T elementStart = cursor;
            while (cursor < value.Length && value.Data[cursor] != ',') {
                ++cursor;
            }

            NTSTATUS status = ParseAcceptEncodingElement(
                { value.Data + elementStart, cursor - elementStart },
                rules);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (cursor == value.Length) {
                return STATUS_SUCCESS;
            }

            ++cursor;
            if (cursor == value.Length) {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    NTSTATUS HttpContentEncoding::BuildAcceptEncodingRulesFromPreferences(
        const HttpAcceptEncodingPreference* preferences,
        SIZE_T preferenceCount,
        HttpAcceptEncodingRules* rules) noexcept
    {
        if (rules == nullptr ||
            rules->Entries == nullptr ||
            rules->EntryCapacity == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        rules->EntryCount = 0;
        rules->EmptyHeader = false;

        NTSTATUS status = ValidateAcceptEncodingPreferences(preferences, preferenceCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        for (SIZE_T index = 0; index < preferenceCount; ++index) {
            const HttpAcceptEncodingPreference& preference = preferences[index];
            const HttpText token = AcceptCodingText(preference.Coding);
            if (token.Data == nullptr || token.Length == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            const bool wildcard = preference.Coding == HttpAcceptCoding::Any;
            status = AddAcceptEncodingEntry(
                token,
                preference.Coding,
                preference.QValue,
                wildcard,
                false,
                rules);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS HttpContentEncoding::IsContentCodingAcceptable(
        const HttpAcceptEncodingRules* rules,
        HttpText coding,
        bool* acceptable,
        USHORT* qvalue) noexcept
    {
        if (acceptable == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *acceptable = false;
        if (qvalue != nullptr) {
            *qvalue = 0;
        }

        coding = TrimOptionalWhitespace(coding);
        if (!IsValidToken(coding)) {
            return STATUS_INVALID_PARAMETER;
        }

        bool wildcard = false;
        bool extension = false;
        const HttpAcceptCoding acceptCoding = AcceptCodingFromToken(coding, &wildcard, &extension);
        UNREFERENCED_PARAMETER(wildcard);
        UNREFERENCED_PARAMETER(extension);

        USHORT resolvedQValue = 0;
        NTSTATUS status = RulesQValueForCoding(rules, coding, acceptCoding, &resolvedQValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        *acceptable = resolvedQValue != 0;
        if (qvalue != nullptr) {
            *qvalue = resolvedQValue;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpContentEncoding::NegotiateContentCoding(
        const HttpAcceptEncodingRules* rules,
        const HttpText* serverCodings,
        SIZE_T codingCount,
        HttpText* selected,
        USHORT* qvalue) noexcept
    {
        if (selected != nullptr) {
            *selected = {};
        }
        if (qvalue != nullptr) {
            *qvalue = 0;
        }
        if (selected == nullptr ||
            (serverCodings == nullptr && codingCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        USHORT bestQValue = 0;
        SIZE_T bestIndex = static_cast<SIZE_T>(-1);
        for (SIZE_T index = 0; index < codingCount; ++index) {
            bool acceptable = false;
            USHORT currentQValue = 0;
            NTSTATUS status = IsContentCodingAcceptable(
                rules,
                serverCodings[index],
                &acceptable,
                &currentQValue);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!acceptable) {
                continue;
            }
            if (bestIndex == static_cast<SIZE_T>(-1) || currentQValue > bestQValue) {
                bestIndex = index;
                bestQValue = currentQValue;
            }
        }

        if (bestIndex == static_cast<SIZE_T>(-1)) {
            return STATUS_NOT_SUPPORTED;
        }

        *selected = serverCodings[bestIndex];
        if (qvalue != nullptr) {
            *qvalue = bestQValue;
        }
        return STATUS_SUCCESS;
    }
}
}
