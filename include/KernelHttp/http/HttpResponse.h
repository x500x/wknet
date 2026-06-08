#pragma once

#include <KernelHttp/http/HttpTypes.h>

namespace KernelHttp
{
namespace http
{
    enum class HttpBodyKind : UCHAR
    {
        None,
        ContentLength,
        Chunked,
        CloseDelimited
    };

    struct HttpResponse final
    {
        USHORT MajorVersion = 0;
        USHORT MinorVersion = 0;
        USHORT StatusCode = 0;
        HttpText ReasonPhrase = {};
        HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        HttpBodyKind BodyKind = HttpBodyKind::None;
        bool BodyEndsOnConnectionClose = false;
        SIZE_T BytesConsumed = 0;

        _Must_inspect_result_
        bool FindHeader(HttpText name, _Out_ const HttpHeader** header) const noexcept;

        _Must_inspect_result_
        bool HasHeaderValueToken(HttpText name, HttpText token) const noexcept;

        _Must_inspect_result_
        bool HasConnectionClose() const noexcept;

        _Must_inspect_result_
        bool HasConnectionKeepAlive() const noexcept;

        _Must_inspect_result_
        bool HasChunkedTransferEncoding() const noexcept;
    };
}
}
