#include <KernelHttp/http/HttpCachePolicy.h>

namespace KernelHttp
{
namespace http
{
namespace
{
    constexpr LONGLONG SecondsPerDay = 24 * 60 * 60;

    bool IsSpace(char c) noexcept
    {
        return c == ' ' || c == '\t';
    }

    bool IsDigit(char c) noexcept
    {
        return c >= '0' && c <= '9';
    }

    char LowerAscii(char c) noexcept
    {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    }

    HttpText Trim(HttpText text) noexcept
    {
        SIZE_T first = 0;
        while (first < text.Length && IsSpace(text.Data[first])) {
            ++first;
        }

        SIZE_T last = text.Length;
        while (last > first && IsSpace(text.Data[last - 1])) {
            --last;
        }

        return { text.Data + first, last - first };
    }

    bool TextEqualsLiteralIgnoreCase(HttpText text, const char* literal) noexcept
    {
        SIZE_T literalLength = 0;
        while (literal[literalLength] != '\0') {
            ++literalLength;
        }
        if (text.Data == nullptr || text.Length != literalLength) {
            return false;
        }
        for (SIZE_T index = 0; index < text.Length; ++index) {
            if (LowerAscii(text.Data[index]) != LowerAscii(literal[index])) {
                return false;
            }
        }
        return true;
    }

    bool TextStartsLiteralIgnoreCase(HttpText text, const char* literal) noexcept
    {
        SIZE_T literalLength = 0;
        while (literal[literalLength] != '\0') {
            ++literalLength;
        }
        if (text.Data == nullptr || text.Length < literalLength) {
            return false;
        }
        for (SIZE_T index = 0; index < literalLength; ++index) {
            if (LowerAscii(text.Data[index]) != LowerAscii(literal[index])) {
                return false;
            }
        }
        return true;
    }

    bool ParseUnsigned(HttpText text, ULONG* value) noexcept
    {
        if (value != nullptr) {
            *value = 0;
        }
        if (value == nullptr || text.Data == nullptr || text.Length == 0) {
            return false;
        }

        ULONG result = 0;
        for (SIZE_T index = 0; index < text.Length; ++index) {
            const char c = text.Data[index];
            if (!IsDigit(c)) {
                return false;
            }
            const ULONG digit = static_cast<ULONG>(c - '0');
            if (result > (~0UL - digit) / 10UL) {
                result = ~0UL;
            }
            else {
                result = result * 10UL + digit;
            }
        }

        *value = result;
        return true;
    }

    bool ParseFixedUnsigned(
        HttpText text,
        SIZE_T offset,
        SIZE_T digits,
        ULONG* value) noexcept
    {
        if (value != nullptr) {
            *value = 0;
        }
        if (value == nullptr || text.Data == nullptr || offset + digits > text.Length) {
            return false;
        }

        ULONG result = 0;
        for (SIZE_T index = 0; index < digits; ++index) {
            const char c = text.Data[offset + index];
            if (!IsDigit(c)) {
                return false;
            }
            result = result * 10UL + static_cast<ULONG>(c - '0');
        }
        *value = result;
        return true;
    }

    bool MonthFromText(HttpText text, ULONG* month) noexcept
    {
        if (month != nullptr) {
            *month = 0;
        }
        if (month == nullptr || text.Length != 3) {
            return false;
        }

        static const char* names[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        for (ULONG index = 0; index < 12; ++index) {
            if (TextEqualsLiteralIgnoreCase(text, names[index])) {
                *month = index + 1;
                return true;
            }
        }
        return false;
    }

    bool IsLeapYear(ULONG year) noexcept
    {
        return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    }

    bool ValidateCalendar(
        ULONG year,
        ULONG month,
        ULONG day,
        ULONG hour,
        ULONG minute,
        ULONG second) noexcept
    {
        static const ULONG daysByMonth[] = {
            31, 28, 31, 30, 31, 30,
            31, 31, 30, 31, 30, 31
        };
        if (year < 1970 || month < 1 || month > 12 || day < 1 ||
            hour > 23 || minute > 59 || second > 60) {
            return false;
        }
        ULONG days = daysByMonth[month - 1];
        if (month == 2 && IsLeapYear(year)) {
            days = 29;
        }
        return day <= days;
    }

    LONGLONG DaysBeforeYear(ULONG year) noexcept
    {
        const LONGLONG y = static_cast<LONGLONG>(year);
        return 365 * (y - 1970) +
            ((y - 1) / 4 - 1969 / 4) -
            ((y - 1) / 100 - 1969 / 100) +
            ((y - 1) / 400 - 1969 / 400);
    }

    LONGLONG DaysBeforeMonth(ULONG year, ULONG month) noexcept
    {
        static const ULONG cumulative[] = {
            0, 31, 59, 90, 120, 151,
            181, 212, 243, 273, 304, 334
        };
        LONGLONG days = cumulative[month - 1];
        if (month > 2 && IsLeapYear(year)) {
            ++days;
        }
        return days;
    }

    bool PackHttpTime(
        ULONG year,
        ULONG month,
        ULONG day,
        ULONG hour,
        ULONG minute,
        ULONG second,
        LONGLONG* seconds) noexcept
    {
        if (seconds != nullptr) {
            *seconds = 0;
        }
        if (seconds == nullptr ||
            !ValidateCalendar(year, month, day, hour, minute, second)) {
            return false;
        }
        if (second == 60) {
            second = 59;
        }

        const LONGLONG days =
            DaysBeforeYear(year) +
            DaysBeforeMonth(year, month) +
            static_cast<LONGLONG>(day - 1);
        *seconds =
            days * SecondsPerDay +
            static_cast<LONGLONG>(hour) * 3600 +
            static_cast<LONGLONG>(minute) * 60 +
            static_cast<LONGLONG>(second);
        return true;
    }

    bool ParseImfFixdate(HttpText text, LONGLONG* seconds) noexcept
    {
        if (text.Length != 29 ||
            text.Data[3] != ',' ||
            text.Data[4] != ' ' ||
            text.Data[7] != ' ' ||
            text.Data[11] != ' ' ||
            text.Data[16] != ' ' ||
            text.Data[19] != ':' ||
            text.Data[22] != ':' ||
            text.Data[25] != ' ' ||
            !TextEqualsLiteralIgnoreCase({ text.Data + 26, 3 }, "GMT")) {
            return false;
        }

        ULONG day = 0;
        ULONG year = 0;
        ULONG month = 0;
        ULONG hour = 0;
        ULONG minute = 0;
        ULONG second = 0;
        return ParseFixedUnsigned(text, 5, 2, &day) &&
            MonthFromText({ text.Data + 8, 3 }, &month) &&
            ParseFixedUnsigned(text, 12, 4, &year) &&
            ParseFixedUnsigned(text, 17, 2, &hour) &&
            ParseFixedUnsigned(text, 20, 2, &minute) &&
            ParseFixedUnsigned(text, 23, 2, &second) &&
            PackHttpTime(year, month, day, hour, minute, second, seconds);
    }

    bool ParseRfc850Date(HttpText text, LONGLONG* seconds) noexcept
    {
        SIZE_T comma = 0;
        while (comma < text.Length && text.Data[comma] != ',') {
            ++comma;
        }
        if (comma == text.Length || comma + 24 != text.Length || text.Data[comma + 1] != ' ') {
            return false;
        }
        const SIZE_T base = comma + 2;
        if (text.Data[base + 2] != '-' ||
            text.Data[base + 6] != '-' ||
            text.Data[base + 9] != ' ' ||
            text.Data[base + 12] != ':' ||
            text.Data[base + 15] != ':' ||
            text.Data[base + 18] != ' ' ||
            !TextEqualsLiteralIgnoreCase({ text.Data + base + 19, 3 }, "GMT")) {
            return false;
        }

        ULONG day = 0;
        ULONG year2 = 0;
        ULONG month = 0;
        ULONG hour = 0;
        ULONG minute = 0;
        ULONG second = 0;
        if (!ParseFixedUnsigned(text, base, 2, &day) ||
            !MonthFromText({ text.Data + base + 3, 3 }, &month) ||
            !ParseFixedUnsigned(text, base + 7, 2, &year2) ||
            !ParseFixedUnsigned(text, base + 10, 2, &hour) ||
            !ParseFixedUnsigned(text, base + 13, 2, &minute) ||
            !ParseFixedUnsigned(text, base + 16, 2, &second)) {
            return false;
        }

        const ULONG year = year2 >= 70 ? 1900 + year2 : 2000 + year2;
        return PackHttpTime(year, month, day, hour, minute, second, seconds);
    }

    bool ParseAsctimeDate(HttpText text, LONGLONG* seconds) noexcept
    {
        if (text.Length != 24 ||
            text.Data[3] != ' ' ||
            text.Data[7] != ' ' ||
            text.Data[10] != ' ' ||
            text.Data[13] != ':' ||
            text.Data[16] != ':' ||
            text.Data[19] != ' ') {
            return false;
        }

        ULONG month = 0;
        ULONG day = 0;
        ULONG hour = 0;
        ULONG minute = 0;
        ULONG second = 0;
        ULONG year = 0;
        if (!MonthFromText({ text.Data + 4, 3 }, &month) ||
            !ParseFixedUnsigned(text, 11, 2, &hour) ||
            !ParseFixedUnsigned(text, 14, 2, &minute) ||
            !ParseFixedUnsigned(text, 17, 2, &second) ||
            !ParseFixedUnsigned(text, 20, 4, &year)) {
            return false;
        }

        if (text.Data[8] == ' ') {
            if (!IsDigit(text.Data[9])) {
                return false;
            }
            day = static_cast<ULONG>(text.Data[9] - '0');
        }
        else {
            if (!ParseFixedUnsigned(text, 8, 2, &day)) {
                return false;
            }
        }
        return PackHttpTime(year, month, day, hour, minute, second, seconds);
    }

    void MergeCacheControl(HttpCacheControl* dst, const HttpCacheControl& src) noexcept
    {
        dst->NoStore = dst->NoStore || src.NoStore;
        dst->NoCache = dst->NoCache || src.NoCache;
        dst->Private = dst->Private || src.Private;
        dst->Public = dst->Public || src.Public;
        dst->MustRevalidate = dst->MustRevalidate || src.MustRevalidate;
        dst->ProxyRevalidate = dst->ProxyRevalidate || src.ProxyRevalidate;
        dst->Immutable = dst->Immutable || src.Immutable;
        dst->OnlyIfCached = dst->OnlyIfCached || src.OnlyIfCached;
        if (src.HasMaxAge) {
            dst->HasMaxAge = true;
            dst->MaxAgeSeconds = src.MaxAgeSeconds;
        }
        if (src.HasSharedMaxAge) {
            dst->HasSharedMaxAge = true;
            dst->SharedMaxAgeSeconds = src.SharedMaxAgeSeconds;
        }
        if (src.HasMinFresh) {
            dst->HasMinFresh = true;
            dst->MinFreshSeconds = src.MinFreshSeconds;
        }
        if (src.HasMaxStale) {
            dst->HasMaxStale = true;
            dst->MaxStaleAny = src.MaxStaleAny;
            dst->MaxStaleSeconds = src.MaxStaleSeconds;
        }
    }

    bool HeaderHasToken(
        const HttpHeader* headers,
        SIZE_T headerCount,
        const char* name,
        const char* token) noexcept
    {
        for (SIZE_T index = 0; index < headerCount; ++index) {
            if (TextEqualsIgnoreCase(headers[index].Name, MakeText(name)) &&
                HeaderValueHasToken(headers[index].Value, MakeText(token))) {
                return true;
            }
        }
        return false;
    }

    bool VaryStar(HttpText vary) noexcept
    {
        return HeaderValueHasToken(vary, MakeText("*"));
    }
}

bool ParseHttpDate(HttpText value, LONGLONG* seconds) noexcept
{
    if (seconds != nullptr) {
        *seconds = 0;
    }
    if (seconds == nullptr || value.Data == nullptr) {
        return false;
    }

    const HttpText trimmed = Trim(value);
    return ParseImfFixdate(trimmed, seconds) ||
        ParseRfc850Date(trimmed, seconds) ||
        ParseAsctimeDate(trimmed, seconds);
}

bool ParseCacheControl(HttpText value, HttpCacheControl* control) noexcept
{
    if (control != nullptr) {
        *control = {};
    }
    if (control == nullptr) {
        return false;
    }
    if (value.Data == nullptr || value.Length == 0) {
        return true;
    }

    SIZE_T start = 0;
    while (start <= value.Length) {
        SIZE_T end = start;
        bool quoted = false;
        while (end < value.Length) {
            const char c = value.Data[end];
            if (c == '"') {
                quoted = !quoted;
            }
            else if (c == ',' && !quoted) {
                break;
            }
            ++end;
        }

        HttpText directive = Trim({ value.Data + start, end - start });
        SIZE_T equals = 0;
        while (equals < directive.Length && directive.Data[equals] != '=') {
            ++equals;
        }
        HttpText name = Trim({ directive.Data, equals });
        HttpText parameter = {};
        if (equals < directive.Length) {
            parameter = Trim({ directive.Data + equals + 1, directive.Length - equals - 1 });
            if (parameter.Length >= 2 && parameter.Data[0] == '"' && parameter.Data[parameter.Length - 1] == '"') {
                parameter.Data += 1;
                parameter.Length -= 2;
            }
        }

        ULONG seconds = 0;
        if (TextEqualsLiteralIgnoreCase(name, "no-store")) {
            control->NoStore = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "no-cache")) {
            control->NoCache = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "private")) {
            control->Private = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "public")) {
            control->Public = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "must-revalidate")) {
            control->MustRevalidate = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "proxy-revalidate")) {
            control->ProxyRevalidate = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "immutable")) {
            control->Immutable = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "only-if-cached")) {
            control->OnlyIfCached = true;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "max-age") && ParseUnsigned(parameter, &seconds)) {
            control->HasMaxAge = true;
            control->MaxAgeSeconds = seconds;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "s-maxage") && ParseUnsigned(parameter, &seconds)) {
            control->HasSharedMaxAge = true;
            control->SharedMaxAgeSeconds = seconds;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "min-fresh") && ParseUnsigned(parameter, &seconds)) {
            control->HasMinFresh = true;
            control->MinFreshSeconds = seconds;
        }
        else if (TextEqualsLiteralIgnoreCase(name, "max-stale")) {
            control->HasMaxStale = true;
            if (parameter.Length == 0) {
                control->MaxStaleAny = true;
            }
            else if (ParseUnsigned(parameter, &seconds)) {
                control->MaxStaleSeconds = seconds;
            }
        }

        if (end == value.Length) {
            break;
        }
        start = end + 1;
    }

    return true;
}

bool ParseSingleByteRange(HttpText value, HttpByteRange* range) noexcept
{
    if (range != nullptr) {
        *range = {};
    }
    if (range == nullptr || value.Data == nullptr) {
        return false;
    }
    HttpText text = Trim(value);
    if (!TextStartsLiteralIgnoreCase(text, "bytes=")) {
        return false;
    }
    text.Data += 6;
    text.Length -= 6;
    for (SIZE_T index = 0; index < text.Length; ++index) {
        if (text.Data[index] == ',') {
            return false;
        }
    }

    SIZE_T dash = 0;
    while (dash < text.Length && text.Data[dash] != '-') {
        ++dash;
    }
    if (dash == text.Length) {
        return false;
    }

    if (dash == 0) {
        ULONG suffix = 0;
        if (!ParseUnsigned(Trim({ text.Data + 1, text.Length - 1 }), &suffix) || suffix == 0) {
            return false;
        }
        range->Suffix = true;
        range->SuffixLength = suffix;
        range->Valid = true;
        return true;
    }

    ULONG first = 0;
    if (!ParseUnsigned(Trim({ text.Data, dash }), &first)) {
        return false;
    }
    HttpText lastText = Trim({ text.Data + dash + 1, text.Length - dash - 1 });
    ULONG last = 0;
    if (lastText.Length == 0) {
        last = ~0UL;
    }
    else if (!ParseUnsigned(lastText, &last) || last < first) {
        return false;
    }

    range->First = first;
    range->Last = last;
    range->Valid = true;
    return true;
}

bool CollectCacheMetadata(
    const HttpHeader* headers,
    SIZE_T headersCount,
    HttpCacheMetadata* metadata) noexcept
{
    if (metadata != nullptr) {
        *metadata = {};
    }
    if (metadata == nullptr) {
        return false;
    }

    for (SIZE_T index = 0; index < headersCount; ++index) {
        const HttpHeader& header = headers[index];
        if (TextEqualsIgnoreCase(header.Name, MakeText("Cache-Control"))) {
            HttpCacheControl parsed = {};
            if (ParseCacheControl(header.Value, &parsed)) {
                MergeCacheControl(&metadata->CacheControl, parsed);
            }
        }
        else if (TextEqualsIgnoreCase(header.Name, MakeText("Date"))) {
            metadata->HasDate = ParseHttpDate(header.Value, &metadata->DateSeconds);
        }
        else if (TextEqualsIgnoreCase(header.Name, MakeText("Expires"))) {
            metadata->HasExpires = ParseHttpDate(header.Value, &metadata->ExpiresSeconds);
        }
        else if (TextEqualsIgnoreCase(header.Name, MakeText("Age"))) {
            metadata->HasAge = ParseUnsigned(Trim(header.Value), &metadata->AgeSeconds);
        }
        else if (TextEqualsIgnoreCase(header.Name, MakeText("ETag"))) {
            metadata->HasETag = header.Value.Data != nullptr && header.Value.Length != 0;
            metadata->ETag = header.Value;
        }
        else if (TextEqualsIgnoreCase(header.Name, MakeText("Last-Modified"))) {
            metadata->HasLastModified = header.Value.Data != nullptr && header.Value.Length != 0;
            metadata->LastModified = header.Value;
            metadata->HasLastModifiedSeconds = ParseHttpDate(header.Value, &metadata->LastModifiedSeconds);
        }
        else if (TextEqualsIgnoreCase(header.Name, MakeText("Vary"))) {
            metadata->Vary = header.Value;
        }
    }

    return true;
}

bool CollectCacheMetadata(const HttpResponse& response, HttpCacheMetadata* metadata) noexcept
{
    return CollectCacheMetadata(response.Headers, response.HeaderCount, metadata);
}

bool IsDefaultCacheableStatus(USHORT statusCode) noexcept
{
    switch (statusCode) {
    case 200:
    case 203:
    case 204:
    case 206:
    case 300:
    case 301:
    case 308:
    case 404:
    case 405:
    case 410:
    case 414:
    case 501:
        return true;
    default:
        return false;
    }
}

bool IsMethodSafeForCache(ULONG method) noexcept
{
    return method == 0 || method == 5;
}

bool IsUnsafeMethodForInvalidation(ULONG method) noexcept
{
    return method == 1 || method == 2 || method == 3 || method == 4;
}

bool ResponseMayBeStored(
    ULONG method,
    bool requestHasAuthorization,
    const HttpCacheControl& requestControl,
    const HttpResponse& response,
    const HttpCacheMetadata& responseMetadata,
    HttpCacheScope scope) noexcept
{
    if (requestControl.NoStore || responseMetadata.CacheControl.NoStore || VaryStar(responseMetadata.Vary)) {
        return false;
    }
    if (!IsMethodSafeForCache(method) && method != 1) {
        return false;
    }
    if (scope == HttpCacheScope::Shared && responseMetadata.CacheControl.Private) {
        return false;
    }
    if (scope == HttpCacheScope::Shared &&
        requestHasAuthorization &&
        !responseMetadata.CacheControl.Public &&
        !responseMetadata.CacheControl.HasSharedMaxAge &&
        !responseMetadata.CacheControl.MustRevalidate) {
        return false;
    }
    if (HeaderHasToken(response.Headers, response.HeaderCount, "Connection", "close")) {
        return false;
    }

    const bool explicitFreshness =
        responseMetadata.CacheControl.HasMaxAge ||
        (scope == HttpCacheScope::Shared && responseMetadata.CacheControl.HasSharedMaxAge) ||
        responseMetadata.HasExpires;
    return IsDefaultCacheableStatus(response.StatusCode) || explicitFreshness;
}

LONGLONG FreshnessLifetimeSeconds(
    const HttpCacheMetadata& metadata,
    USHORT statusCode,
    HttpCacheScope scope) noexcept
{
    if (scope == HttpCacheScope::Shared && metadata.CacheControl.HasSharedMaxAge) {
        return metadata.CacheControl.SharedMaxAgeSeconds;
    }
    if (metadata.CacheControl.HasMaxAge) {
        return metadata.CacheControl.MaxAgeSeconds;
    }
    if (metadata.HasExpires) {
        const LONGLONG date = metadata.HasDate ? metadata.DateSeconds : 0;
        const LONGLONG lifetime = metadata.ExpiresSeconds - date;
        return lifetime > 0 ? lifetime : 0;
    }
    if (IsDefaultCacheableStatus(statusCode) &&
        metadata.HasDate &&
        metadata.HasLastModifiedSeconds &&
        metadata.DateSeconds > metadata.LastModifiedSeconds) {
        return (metadata.DateSeconds - metadata.LastModifiedSeconds) / 10;
    }
    return 0;
}

LONGLONG CurrentAgeSeconds(
    const HttpCacheMetadata& metadata,
    LONGLONG storedAtSeconds,
    LONGLONG nowSeconds) noexcept
{
    LONGLONG apparentAge = 0;
    if (metadata.HasDate && storedAtSeconds > metadata.DateSeconds) {
        apparentAge = storedAtSeconds - metadata.DateSeconds;
    }
    LONGLONG correctedAge = apparentAge;
    if (metadata.HasAge && static_cast<LONGLONG>(metadata.AgeSeconds) > correctedAge) {
        correctedAge = metadata.AgeSeconds;
    }
    if (nowSeconds > storedAtSeconds) {
        correctedAge += nowSeconds - storedAtSeconds;
    }
    return correctedAge;
}

bool CanUseStoredResponse(
    const HttpCacheMetadata& requestMetadata,
    const HttpCacheMetadata& responseMetadata,
    USHORT statusCode,
    LONGLONG storedAtSeconds,
    LONGLONG nowSeconds,
    HttpCacheScope scope,
    bool* requiresValidation) noexcept
{
    if (requiresValidation != nullptr) {
        *requiresValidation = true;
    }
    if (requiresValidation == nullptr || requestMetadata.CacheControl.NoStore) {
        return false;
    }
    if (requestMetadata.CacheControl.NoCache || responseMetadata.CacheControl.NoCache) {
        *requiresValidation = true;
        return true;
    }

    const LONGLONG lifetime = FreshnessLifetimeSeconds(responseMetadata, statusCode, scope);
    LONGLONG age = CurrentAgeSeconds(responseMetadata, storedAtSeconds, nowSeconds);
    if (requestMetadata.CacheControl.HasMaxAge &&
        age > static_cast<LONGLONG>(requestMetadata.CacheControl.MaxAgeSeconds)) {
        *requiresValidation = true;
        return true;
    }
    if (requestMetadata.CacheControl.HasMinFresh) {
        age += requestMetadata.CacheControl.MinFreshSeconds;
    }

    if (age < lifetime) {
        *requiresValidation = false;
        return true;
    }

    if (requestMetadata.CacheControl.HasMaxStale &&
        !responseMetadata.CacheControl.MustRevalidate &&
        !(scope == HttpCacheScope::Shared && responseMetadata.CacheControl.ProxyRevalidate)) {
        if (requestMetadata.CacheControl.MaxStaleAny ||
            age - lifetime <= static_cast<LONGLONG>(requestMetadata.CacheControl.MaxStaleSeconds)) {
            *requiresValidation = false;
            return true;
        }
    }

    *requiresValidation = true;
    return true;
}
}
}
