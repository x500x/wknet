#pragma once

#include "http1/HttpTypes.h"

namespace wknet
{
namespace http1
{
    enum class HttpBodyKind : UCHAR
    {
        None,
        ContentLength,
        Chunked,
        CloseDelimited
    };

    // Parsed `Content-Range: bytes <first>-<last>/<complete>` per RFC 7233 §4.2.
    // `HasRange` is false for an unsatisfied-range form (`bytes */<complete>`),
    // in which case only the complete length is meaningful (if `HasCompleteLength`).
    struct HttpContentRange final
    {
        ULONGLONG FirstBytePos = 0;
        ULONGLONG LastBytePos = 0;
        ULONGLONG CompleteLength = 0;
        bool HasRange = false;
        bool HasCompleteLength = false;
    };

    struct HttpResponse final
    {
        USHORT MajorVersion = 0;
        USHORT MinorVersion = 0;
        USHORT StatusCode = 0;
        HttpText ReasonPhrase = {};
        HttpHeader* Headers = nullptr;
        SIZE_T HeaderCount = 0;
        HttpHeader* Trailers = nullptr;
        SIZE_T TrailerCount = 0;
        const char* Body = nullptr;
        SIZE_T BodyLength = 0;
        HttpBodyKind BodyKind = HttpBodyKind::None;
        bool BodyEndsOnConnectionClose = false;
        // True when body bytes were already delivered via BodyCallback during receive.
        bool BodyDeliveredViaCallback = false;
        // True when headers were already delivered via HeaderCallback during receive.
        bool HeadersDeliveredViaCallback = false;
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

        // True for 206 Partial Content.
        _Must_inspect_result_
        bool IsPartialContent() const noexcept;

        // Parses the `Content-Range` header (read-only; does not affect Body framing).
        // Returns false if the header is absent or malformed.
        _Must_inspect_result_
        bool GetContentRange(_Out_ HttpContentRange* range) const noexcept;
    };
}
}
