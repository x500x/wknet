#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include <KernelHttp/http/HttpParser.h>
#include <KernelHttp/http/HttpRequest.h>

#include <stdio.h>
#include <string.h>

using KernelHttp::http::HeaderValueHasToken;
using KernelHttp::http::HttpBodyKind;
using KernelHttp::http::HttpConnectionDirective;
using KernelHttp::http::HttpHeader;
using KernelHttp::http::HttpMethod;
using KernelHttp::http::HttpParseOptions;
using KernelHttp::http::HttpParser;
using KernelHttp::http::HttpRequestBuilder;
using KernelHttp::http::HttpRequestBodyMode;
using KernelHttp::http::HttpRequestBuildOptions;
using KernelHttp::http::HttpResponse;
using KernelHttp::http::HttpText;
using KernelHttp::http::MakeText;
using KernelHttp::http::TextEqualsIgnoreCase;

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message)
    {
        if (!condition) {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    bool TextEqualsLiteral(HttpText text, const char* literal)
    {
        const HttpText expected = MakeText(literal);
        return text.Length == expected.Length &&
            text.Data != nullptr &&
            memcmp(text.Data, expected.Data, expected.Length) == 0;
    }

    bool MemoryEqualsLiteral(const char* data, size_t length, const char* literal)
    {
        const size_t literalLength = strlen(literal);
        return data != nullptr &&
            length == literalLength &&
            memcmp(data, literal, literalLength) == 0;
    }

    bool BuildEncodedResponse(
        const char* encoding,
        const unsigned char* encodedBody,
        size_t encodedBodyLength,
        char* response,
        size_t responseCapacity,
        size_t* responseLength)
    {
        if (encoding == nullptr ||
            encodedBody == nullptr ||
            response == nullptr ||
            responseLength == nullptr) {
            return false;
        }

        const int headerLength = snprintf(
            response,
            responseCapacity,
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: %s\r\n"
            "Content-Length: %zu\r\n"
            "\r\n",
            encoding,
            encodedBodyLength);
        if (headerLength <= 0 ||
            static_cast<size_t>(headerLength) > responseCapacity ||
            encodedBodyLength > (responseCapacity - static_cast<size_t>(headerLength))) {
            return false;
        }

        memcpy(response + headerLength, encodedBody, encodedBodyLength);
        *responseLength = static_cast<size_t>(headerLength) + encodedBodyLength;
        return true;
    }

    bool BuildChunkedBody(
        const unsigned char* body,
        size_t bodyLength,
        char* destination,
        size_t destinationCapacity,
        size_t* destinationLength)
    {
        if (body == nullptr ||
            destination == nullptr ||
            destinationLength == nullptr) {
            return false;
        }

        const int chunkHeaderLength = snprintf(destination, destinationCapacity, "%zx\r\n", bodyLength);
        if (chunkHeaderLength <= 0 || static_cast<size_t>(chunkHeaderLength) > destinationCapacity) {
            return false;
        }

        size_t cursor = static_cast<size_t>(chunkHeaderLength);
        if (bodyLength > destinationCapacity - cursor) {
            return false;
        }

        memcpy(destination + cursor, body, bodyLength);
        cursor += bodyLength;

        const char trailer[] = "\r\n0\r\n\r\n";
        if (sizeof(trailer) - 1 > destinationCapacity - cursor) {
            return false;
        }

        memcpy(destination + cursor, trailer, sizeof(trailer) - 1);
        cursor += sizeof(trailer) - 1;
        *destinationLength = cursor;
        return true;
    }

    bool BuildTransferEncodedResponse(
        const char* transferEncoding,
        const unsigned char* wireBody,
        size_t wireBodyLength,
        char* response,
        size_t responseCapacity,
        size_t* responseLength)
    {
        if (transferEncoding == nullptr ||
            wireBody == nullptr ||
            response == nullptr ||
            responseLength == nullptr) {
            return false;
        }

        const int headerLength = snprintf(
            response,
            responseCapacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: %s\r\n"
            "\r\n",
            transferEncoding);
        if (headerLength <= 0 ||
            static_cast<size_t>(headerLength) > responseCapacity ||
            wireBodyLength > responseCapacity - static_cast<size_t>(headerLength)) {
            return false;
        }

        memcpy(response + headerLength, wireBody, wireBodyLength);
        *responseLength = static_cast<size_t>(headerLength) + wireBodyLength;
        return true;
    }

    bool BuildChunkedGzipResponse(
        const unsigned char* encodedBody,
        size_t encodedBodyLength,
        char* response,
        size_t responseCapacity,
        size_t* responseLength)
    {
        if (encodedBody == nullptr ||
            response == nullptr ||
            responseLength == nullptr) {
            return false;
        }

        const int headerLength = snprintf(
            response,
            responseCapacity,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Encoding: gzip\r\n"
            "\r\n"
            "%zx\r\n",
            encodedBodyLength);
        if (headerLength <= 0 || static_cast<size_t>(headerLength) > responseCapacity) {
            return false;
        }

        size_t cursor = static_cast<size_t>(headerLength);
        if (encodedBodyLength > (responseCapacity - cursor)) {
            return false;
        }

        memcpy(response + cursor, encodedBody, encodedBodyLength);
        cursor += encodedBodyLength;

        const char trailer[] = "\r\n0\r\n\r\n";
        if (sizeof(trailer) - 1 > (responseCapacity - cursor)) {
            return false;
        }

        memcpy(response + cursor, trailer, sizeof(trailer) - 1);
        cursor += sizeof(trailer) - 1;
        *responseLength = cursor;
        return true;
    }

    constexpr const char* EncodedBodyLiteral = "encoded response body";

    const unsigned char DeflateRawBody[] = {
        0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49, 0x4d, 0x51,
        0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e,
        0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04, 0x00
    };

    const unsigned char DeflateZlibBody[] = {
        0x78, 0x9c, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49,
        0x4d, 0x51, 0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf,
        0x2b, 0x4e, 0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04,
        0x00, 0x5a, 0x14, 0x08, 0x30
    };

    const unsigned char GzipBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0xff, 0x4b, 0xcd, 0x4b, 0xce, 0x4f, 0x49,
        0x4d, 0x51, 0x28, 0x4a, 0x2d, 0x2e, 0xc8, 0xcf,
        0x2b, 0x4e, 0x55, 0x48, 0xca, 0x4f, 0xa9, 0x04,
        0x00, 0xec, 0xa9, 0xb0, 0x05, 0x15, 0x00, 0x00,
        0x00
    };

    const unsigned char BrotliBody[] = {
        0x1b, 0x14, 0x00, 0x00, 0x04, 0x26, 0x72, 0xa4,
        0x31, 0xb7, 0xfc, 0xfc, 0x2c, 0xc4, 0x11, 0x55,
        0x2a, 0x03, 0xbd, 0x1b, 0xc2, 0xb8, 0x0e
    };

    // UNIX compress .Z stream for "encoded response body" with 16-bit max codes and no block reset.
    const unsigned char CompressBody[] = {
        0x1f, 0x9d, 0x10, 0x65, 0xdc, 0x8c, 0x79, 0x43,
        0xa6, 0x0c, 0x19, 0x10, 0x72, 0xca, 0xcc, 0x81,
        0xf3, 0xc6, 0xcd, 0x9c, 0x32, 0x20, 0xc4, 0xbc,
        0x21, 0x93, 0x07
    };

    // gzip stream for "15\r\nencoded response body\r\n0\r\n\r\n".
    const unsigned char GzipChunkedStreamBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x0a, 0x33, 0x34, 0xe5, 0xe5, 0x4a, 0xcd,
        0x4b, 0xce, 0x4f, 0x49, 0x4d, 0x51, 0x28, 0x4a,
        0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0x55, 0x48,
        0xca, 0x4f, 0xa9, 0xe4, 0xe5, 0x32, 0xe0, 0xe5,
        0xe2, 0xe5, 0x02, 0x00, 0x97, 0xd3, 0x0a, 0x85,
        0x20, 0x00, 0x00, 0x00
    };

    // gzip stream for "15\r\nencoded response body\r\n0\r\n\r\njunk".
    const unsigned char GzipChunkedStreamWithTailBody[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x0a, 0x33, 0x34, 0xe5, 0xe5, 0x4a, 0xcd,
        0x4b, 0xce, 0x4f, 0x49, 0x4d, 0x51, 0x28, 0x4a,
        0x2d, 0x2e, 0xc8, 0xcf, 0x2b, 0x4e, 0x55, 0x48,
        0xca, 0x4f, 0xa9, 0xe4, 0xe5, 0x32, 0xe0, 0xe5,
        0xe2, 0xe5, 0xca, 0x2a, 0xcd, 0xcb, 0x06, 0x00,
        0x68, 0x51, 0x9e, 0xce, 0x24, 0x00, 0x00, 0x00
    };

    void TestBuildGetRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Accept"), MakeText("*/*") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/index.html");
        options.Host = MakeText("example.com");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.Connection = HttpConnectionDirective::KeepAlive;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET /index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Connection: keep-alive\r\n"
            "Accept: */*\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "GET request builds successfully");
        Expect(written == strlen(expected), "GET request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "GET request bytes match expected output");
    }

    void TestBuildPostRequest()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.ContentType = MakeText("application/x-www-form-urlencoded");
        options.Connection = HttpConnectionDirective::Close;
        options.Body = body;
        options.BodyLength = strlen(body);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 10\r\n"
            "Connection: close\r\n"
            "\r\n"
            "alpha=beta";

        Expect(status == STATUS_SUCCESS, "POST request builds successfully");
        Expect(written == strlen(expected), "POST request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "POST request bytes match expected output");
    }

    void TestBuildChunkedPostRequest()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.ContentType = MakeText("application/x-www-form-urlencoded");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.IncludeContentLength = true;
        options.BodyMode = HttpRequestBodyMode::Chunked;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "a\r\n"
            "alpha=beta\r\n"
            "0\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "chunked POST request builds successfully");
        Expect(written == strlen(expected), "chunked POST request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "chunked POST request bytes match expected output");
    }

    void TestBuildUpgradeRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Upgrade"), MakeText("websocket") },
            { MakeText("Sec-WebSocket-Key"), MakeText("dGhlIHNhbXBsZSBub25jZQ==") },
            { MakeText("Sec-WebSocket-Version"), MakeText("13") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/chat");
        options.Host = MakeText("server.example.com");
        options.Connection = HttpConnectionDirective::Upgrade;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = sizeof(extra) / sizeof(extra[0]);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET /chat HTTP/1.1\r\n"
            "Host: server.example.com\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "Upgrade request builds successfully");
        Expect(written == strlen(expected), "Upgrade request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "Upgrade request bytes match expected output");
    }

    void TestRequestBuilderRejectsInjectionText()
    {
        char buffer[512] = {};
        size_t written = 0;

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/safe path");
        options.Host = MakeText("example.com");
        NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects spaces in request target");

        options.Path = MakeText("/safe");
        options.Host = MakeText("example.com\r\nX-Test: yes");
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects CRLF in Host header");

        const HttpHeader badName[] = {
            { MakeText("Bad\rName"), MakeText("value") }
        };
        options.Host = MakeText("example.com");
        options.ExtraHeaders = badName;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects invalid header name");

        const HttpHeader badValue[] = {
            { MakeText("X-Test"), MakeText("ok\r\nInjected: yes") }
        };
        options.ExtraHeaders = badValue;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects invalid header value");

        const HttpHeader controlledConnection[] = {
            { MakeText("Connection"), MakeText("Upgrade") }
        };
        options.ExtraHeaders = controlledConnection;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects caller-supplied Connection header");

        const HttpHeader controlledHost[] = {
            { MakeText("Host"), MakeText("other.example") }
        };
        options.ExtraHeaders = controlledHost;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects caller-supplied Host header");

        const HttpHeader controlledLength[] = {
            { MakeText("Content-Length"), MakeText("10") }
        };
        options.ExtraHeaders = controlledLength;
        options.ExtraHeaderCount = 1;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_INVALID_PARAMETER, "request builder rejects caller-supplied Content-Length header");
    }

    void TestRequestBuilderRejectsTransferEncoding()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "upload body";

        const HttpHeader headers[] = {
            { MakeText("Transfer-Encoding"), MakeText("chunked") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/upload");
        options.Host = MakeText("example.com");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.ExtraHeaders = headers;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects request Transfer-Encoding");
        Expect(written == 0, "request builder reports no bytes for rejected Transfer-Encoding");
    }

    void TestRequestBuilderRejectsUnsupportedRequestFraming()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "upload body";

        const HttpHeader teHeader[] = {
            { MakeText("TE"), MakeText("trailers") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/upload");
        options.Host = MakeText("example.com");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.ExtraHeaders = teHeader;
        options.ExtraHeaderCount = 1;

        NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects request TE header");

        const HttpHeader trailerHeader[] = {
            { MakeText("Trailer"), MakeText("Digest") }
        };
        options.ExtraHeaders = trailerHeader;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects request Trailer header");

        const HttpHeader expectHeader[] = {
            { MakeText("Expect"), MakeText("100-continue") }
        };
        options.ExtraHeaders = expectHeader;
        status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        Expect(status == STATUS_NOT_SUPPORTED, "request builder rejects body with Expect: 100-continue");
    }

    void TestBuildChunkedRequestWithTrailers()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        const HttpHeader extra[] = {
            { MakeText("Trailer"), MakeText("Expires, X-Checksum") }
        };
        const HttpHeader trailers[] = {
            { MakeText("Expires"), MakeText("Wed, 21 Oct 2015 07:28:00 GMT") },
            { MakeText("X-Checksum"), MakeText("abc123") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.ContentType = MakeText("application/x-www-form-urlencoded");
        options.Body = body;
        options.BodyLength = strlen(body);
        options.BodyMode = HttpRequestBodyMode::Chunked;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = 1;
        options.Trailers = trailers;
        options.TrailerCount = sizeof(trailers) / sizeof(trailers[0]);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Trailer: Expires, X-Checksum\r\n"
            "\r\n"
            "a\r\n"
            "alpha=beta\r\n"
            "0\r\n"
            "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
            "X-Checksum: abc123\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "chunked request with trailers builds successfully");
        Expect(written == strlen(expected), "chunked trailers request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "chunked trailers request bytes match expected output");
    }

    void TestBuildChunkedRequestWithEmptyBodyTrailers()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader trailers[] = {
            { MakeText("X-Checksum"), MakeText("deadbeef") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Post;
        options.Path = MakeText("/submit");
        options.Host = MakeText("example.com");
        options.IncludeContentLength = true;
        options.BodyMode = HttpRequestBodyMode::Chunked;
        options.Trailers = trailers;
        options.TrailerCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "X-Checksum: deadbeef\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "empty-body chunked request with trailers builds successfully");
        Expect(written == strlen(expected), "empty-body trailers request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "empty-body trailers request bytes match expected output");
    }

    void TestRequestBuilderTrailerValidation()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "alpha=beta";

        HttpRequestBuildOptions base = {};
        base.Method = HttpMethod::Post;
        base.Path = MakeText("/submit");
        base.Host = MakeText("example.com");
        base.Body = body;
        base.BodyLength = strlen(body);
        base.BodyMode = HttpRequestBodyMode::Chunked;

        const HttpHeader good[] = {
            { MakeText("X-Checksum"), MakeText("abc123") }
        };

        // Trailers require chunked transfer; reject in Content-Length mode.
        {
            HttpRequestBuildOptions options = base;
            options.BodyMode = HttpRequestBodyMode::ContentLength;
            options.Trailers = good;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_NOT_SUPPORTED, "trailers rejected without chunked transfer");
        }

        // Chunked mode but no framing emitted (no body, no Content-Length opt-in).
        {
            HttpRequestBuildOptions options = base;
            options.Body = nullptr;
            options.BodyLength = 0;
            options.Trailers = good;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_NOT_SUPPORTED, "trailers rejected when no chunked framing is emitted");
        }

        // Non-null count with null pointer.
        {
            HttpRequestBuildOptions options = base;
            options.Trailers = nullptr;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_INVALID_PARAMETER, "null trailer pointer with non-zero count rejected");
        }

        // Forbidden trailer fields (framing / auth / cookie).
        const char* forbidden[] = {
            "Content-Length", "Transfer-Encoding", "Host",
            "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"
        };
        for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
            const HttpHeader trailer[] = {
                { MakeText(forbidden[i]), MakeText("x") }
            };
            HttpRequestBuildOptions options = base;
            options.Trailers = trailer;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_NOT_SUPPORTED, "forbidden trailer field rejected");
        }

        // Invalid trailer name (illegal token character).
        {
            const HttpHeader trailer[] = {
                { MakeText("Bad Name"), MakeText("x") }
            };
            HttpRequestBuildOptions options = base;
            options.Trailers = trailer;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_INVALID_PARAMETER, "invalid trailer name rejected");
        }

        // CRLF injection in a trailer value.
        {
            const HttpHeader trailer[] = {
                { MakeText("X-Checksum"), MakeText("ok\r\nInjected: yes") }
            };
            HttpRequestBuildOptions options = base;
            options.Trailers = trailer;
            options.TrailerCount = 1;
            const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
            Expect(status == STATUS_INVALID_PARAMETER, "CRLF injection in trailer value rejected");
        }
    }

    void TestRequestBuilderAllowsEmptyHeaderValue()
    {
        char buffer[256] = {};
        size_t written = 0;

        const HttpHeader headers[] = {
            { MakeText("X-Empty"), { "", 0 } }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/");
        options.Host = MakeText("example.com");
        options.ExtraHeaders = headers;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(options, buffer, sizeof(buffer), &written);
        const char expected[] =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "X-Empty: \r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "request builder accepts an empty header value");
        Expect(written == strlen(expected), "empty header request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "empty header request bytes match expected output");
    }

    void TestBuildPutRequest()
    {
        char buffer[512] = {};
        size_t written = 0;
        const char body[] = "{\"enabled\":true}";

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Put;
        options.Path = MakeText("/put");
        options.Host = MakeText("httpbin.org");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.ContentType = MakeText("application/json");
        options.Connection = HttpConnectionDirective::Close;
        options.Body = body;
        options.BodyLength = strlen(body);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "PUT /put HTTP/1.1\r\n"
            "Host: httpbin.org\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 16\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"enabled\":true}";

        Expect(status == STATUS_SUCCESS, "PUT request builds successfully");
        Expect(written == strlen(expected), "PUT request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "PUT request bytes match expected output");
    }

    void TestBuildRealHostGetRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Accept"), MakeText("*/*") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/");
        options.Host = MakeText("www.baidu.com");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.Connection = HttpConnectionDirective::Close;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = 1;

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET / HTTP/1.1\r\n"
            "Host: www.baidu.com\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Connection: close\r\n"
            "Accept: */*\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "real-host GET request builds successfully");
        Expect(written == strlen(expected), "real-host GET request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "real-host GET request bytes match expected output");
    }

    void TestRequestSizeProbe()
    {
        size_t written = 0;

        HttpRequestBuildOptions options = {};
        options.Path = MakeText("/");
        options.Host = MakeText("example.com");

        const NTSTATUS status = HttpRequestBuilder::Build(options, nullptr, 0, &written);

        const char expected[] =
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";

        Expect(status == STATUS_BUFFER_TOO_SMALL, "request builder supports size probe");
        Expect(written == strlen(expected), "request size probe returns required length");
    }

    void TestBuildAcceptEncodingRequest()
    {
        char buffer[512] = {};
        size_t written = 0;

        const HttpHeader extra[] = {
            { MakeText("Accept"), MakeText("*/*") },
            { MakeText("Accept-Encoding"), MakeText("gzip, deflate, br, identity") }
        };

        HttpRequestBuildOptions options = {};
        options.Method = HttpMethod::Get;
        options.Path = MakeText("/brotli");
        options.Host = MakeText("httpbin.org");
        options.UserAgent = MakeText("KernelHttp/0.1");
        options.Connection = HttpConnectionDirective::Close;
        options.ExtraHeaders = extra;
        options.ExtraHeaderCount = sizeof(extra) / sizeof(extra[0]);

        const NTSTATUS status = HttpRequestBuilder::Build(
            options,
            buffer,
            sizeof(buffer),
            &written);

        const char expected[] =
            "GET /brotli HTTP/1.1\r\n"
            "Host: httpbin.org\r\n"
            "User-Agent: KernelHttp/0.1\r\n"
            "Connection: close\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: gzip, deflate, br, identity\r\n"
            "\r\n";

        Expect(status == STATUS_SUCCESS, "Accept-Encoding request builds successfully");
        Expect(written == strlen(expected), "Accept-Encoding request reports exact byte count");
        Expect(memcmp(buffer, expected, strlen(expected)) == 0, "Accept-Encoding request bytes match expected output");
    }

    void TestParseContentLengthResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "hello"
            "next";

        HttpHeader headers[8] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "Content-Length response parses successfully");
        Expect(response.MajorVersion == 1 && response.MinorVersion == 1, "HTTP version is parsed");
        Expect(response.StatusCode == 200, "status code is parsed");
        Expect(TextEqualsLiteral(response.ReasonPhrase, "OK"), "reason phrase is parsed");
        Expect(response.HeaderCount == 2, "header count is parsed");
        Expect(response.BodyKind == HttpBodyKind::ContentLength, "body kind is ContentLength");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "hello"), "body points to Content-Length bytes");
        Expect(response.BytesConsumed == strlen(responseBytes) - strlen("next"), "parser leaves pipelined bytes unread");
        Expect(response.HasHeaderValueToken(MakeText("Connection"), MakeText("keep-alive")), "connection token lookup works");
    }

    void TestParseChunkedResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "4\r\n"
            "Wiki\r\n"
            "5;ext=value\r\n"
            "pedia\r\n"
            "0\r\n"
            "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
            "\r\n"
            "tail";

        HttpHeader headers[8] = {};
        HttpHeader trailers[4] = {};
        char decoded[32] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.Trailers = trailers;
        options.TrailerCapacity = 4;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "chunked response parses successfully");
        Expect(response.BodyKind == HttpBodyKind::Chunked, "body kind is Chunked");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "Wikipedia"), "chunked body is decoded");
        Expect(response.BytesConsumed == strlen(responseBytes) - strlen("tail"), "chunked parser leaves trailing bytes unread");
        Expect(response.HasChunkedTransferEncoding(), "chunked transfer token lookup works");
        Expect(response.TrailerCount == 1, "chunked trailer count is exposed");
        Expect(TextEqualsLiteral(response.Trailers[0].Name, "Expires"), "chunked trailer name is exposed");
        Expect(TextEqualsLiteral(response.Trailers[0].Value, "Wed, 21 Oct 2015 07:28:00 GMT"), "chunked trailer value is exposed");
    }

    void TestParseIdentityContentEncoding()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: identity\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "identity body";

        HttpHeader headers[8] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "identity content encoding parses successfully");
        Expect(response.BodyKind == HttpBodyKind::ContentLength, "identity body keeps ContentLength kind");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "identity body"), "identity body is exposed unchanged");
    }

    void TestParseDeflateZlibContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("deflate", DeflateZlibBody, sizeof(DeflateZlibBody), responseBytes, sizeof(responseBytes), &responseLength),
            "zlib-wrapped deflate response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "zlib-wrapped deflate content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "zlib-wrapped deflate body is decoded");
    }

    void TestParseDeflateRawContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("deflate", DeflateRawBody, sizeof(DeflateRawBody), responseBytes, sizeof(responseBytes), &responseLength),
            "raw deflate response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "raw deflate content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "raw deflate body is decoded");
    }

    void TestParseGzipContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("gzip", GzipBody, sizeof(GzipBody), responseBytes, sizeof(responseBytes), &responseLength),
            "gzip response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "gzip content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "gzip body is decoded");
    }

    void TestParseBrotliContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("br", BrotliBody, sizeof(BrotliBody), responseBytes, sizeof(responseBytes), &responseLength),
            "brotli response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "brotli content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "brotli body is decoded");
    }

    void TestParseCompressContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("compress", CompressBody, sizeof(CompressBody), responseBytes, sizeof(responseBytes), &responseLength),
            "compress response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "compress content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "compress content body is decoded");

        memset(responseBytes, 0, sizeof(responseBytes));
        responseLength = 0;
        Expect(
            BuildEncodedResponse("x-compress", CompressBody, sizeof(CompressBody), responseBytes, sizeof(responseBytes), &responseLength),
            "x-compress response fixture builds");

        memset(decoded, 0, sizeof(decoded));
        response = {};
        status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "x-compress content encoding parses successfully");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "x-compress content body is decoded");
    }

    void TestParseChunkedGzipContentEncoding()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildChunkedGzipResponse(GzipBody, sizeof(GzipBody), responseBytes, sizeof(responseBytes), &responseLength),
            "chunked gzip response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        char scratch[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_SUCCESS, "chunked gzip response parses successfully");
        Expect(response.BodyKind == HttpBodyKind::Chunked, "chunked gzip keeps Chunked body kind");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "chunked gzip body is transfer-decoded and decompressed");
    }

    void TestTransferEncodingGzipChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(GzipBody, sizeof(GzipBody), chunked, sizeof(chunked), &chunkedLength),
            "gzip transfer body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "gzip, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "gzip chunked transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "gzip, chunked transfer coding parses");
        Expect(response.BodyKind == HttpBodyKind::Chunked, "gzip, chunked body kind is Chunked");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "gzip transfer coding decodes after chunked framing");
    }

    void TestTransferEncodingDeflateChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(DeflateZlibBody, sizeof(DeflateZlibBody), chunked, sizeof(chunked), &chunkedLength),
            "deflate transfer body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "deflate, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "deflate chunked transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "deflate, chunked transfer coding parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "deflate transfer coding decodes after chunked framing");
    }

    void TestTransferEncodingCompressChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(CompressBody, sizeof(CompressBody), chunked, sizeof(chunked), &chunkedLength),
            "compress transfer body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "compress, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "compress chunked transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "compress, chunked transfer coding parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "compress transfer coding decodes after chunked framing");
    }

    void TestTransferEncodingAliasesChunked()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(GzipBody, sizeof(GzipBody), chunked, sizeof(chunked), &chunkedLength),
            "x-gzip transfer alias body is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "x-gzip, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "x-gzip transfer alias response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "x-gzip transfer alias parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "x-gzip transfer alias decodes");

        memset(chunked, 0, sizeof(chunked));
        chunkedLength = 0;
        Expect(
            BuildChunkedBody(CompressBody, sizeof(CompressBody), chunked, sizeof(chunked), &chunkedLength),
            "x-compress transfer alias body is chunked");

        memset(responseBytes, 0, sizeof(responseBytes));
        responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "x-compress, chunked",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "x-compress transfer alias response fixture builds");

        memset(decoded, 0, sizeof(decoded));
        memset(scratch, 0, sizeof(scratch));
        response = {};
        status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);

        Expect(status == STATUS_SUCCESS, "x-compress transfer alias parses");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "x-compress transfer alias decodes");
    }

    void TestTransferEncodingGzipCloseDelimited()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "gzip",
                GzipBody,
                sizeof(GzipBody),
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "close-delimited gzip transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "final non-chunked transfer coding waits for connection close");

        options.MessageCompleteOnConnectionClose = true;
        status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_SUCCESS, "close-delimited gzip transfer coding parses after connection close");
        Expect(response.BodyKind == HttpBodyKind::CloseDelimited, "close-delimited gzip keeps CloseDelimited body kind");
        Expect(response.BytesConsumed == responseLength, "close-delimited gzip consumes all response bytes");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "close-delimited gzip transfer coding decodes");
    }

    void TestTransferEncodingChunkedThenGzipCloseDelimited()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "chunked, gzip",
                GzipChunkedStreamBody,
                sizeof(GzipChunkedStreamBody),
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "chunked then gzip close-delimited transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "chunked, gzip waits for connection close");

        options.MessageCompleteOnConnectionClose = true;
        status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_SUCCESS, "chunked, gzip transfer coding parses after connection close");
        Expect(response.BodyKind == HttpBodyKind::CloseDelimited, "chunked, gzip is close-delimited on the wire");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, EncodedBodyLiteral), "chunked, gzip decodes gzip then inner chunked stream");
    }

    void TestTransferEncodingRejectsInnerChunkedTail()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "chunked, gzip",
                GzipChunkedStreamWithTailBody,
                sizeof(GzipChunkedStreamWithTailBody),
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "chunked tail rejection fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);
        options.MessageCompleteOnConnectionClose = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "inner chunked stream must consume all decoded bytes");
    }

    void TestTransferEncodingRejectsEmptyListMember()
    {
        char chunked[128] = {};
        size_t chunkedLength = 0;
        Expect(
            BuildChunkedBody(GzipBody, sizeof(GzipBody), chunked, sizeof(chunked), &chunkedLength),
            "gzip transfer body with empty list members is chunked");

        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildTransferEncodedResponse(
                "gzip,, chunked,",
                reinterpret_cast<const unsigned char*>(chunked),
                chunkedLength,
                responseBytes,
                sizeof(responseBytes),
                &responseLength),
            "empty list member transfer response fixture builds");

        HttpHeader headers[8] = {};
        char decoded[128] = {};
        char scratch[128] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(responseBytes, responseLength, options, response);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "empty transfer-coding list members are rejected");
    }

    void TestUnsupportedContentEncoding()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: zstd\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "data";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_NOT_SUPPORTED, "unsupported content encoding is rejected");
    }

    void TestContentEncodingRequiresCapacity()
    {
        char responseBytes[256] = {};
        size_t responseLength = 0;
        Expect(
            BuildEncodedResponse("gzip", GzipBody, sizeof(GzipBody), responseBytes, sizeof(responseBytes), &responseLength),
            "gzip small-buffer fixture builds");

        HttpHeader headers[8] = {};
        char decoded[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            responseLength,
            options,
            response);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "content decoder rejects undersized output buffer");
    }

    void TestContentEncodingRejectsTooManyCodings()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: gzip, gzip, gzip\r\n"
            "Content-Length: 1\r\n"
            "\r\n"
            "x";

        HttpHeader headers[8] = {};
        char decoded[64] = {};
        char scratch[64] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);
        options.ScratchBody = scratch;
        options.ScratchBodyCapacity = sizeof(scratch);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_NOT_SUPPORTED, "content decoder rejects more than two content codings");
    }

    void TestChunkedDecodeRequiresCapacity()
    {
        const char chunkedBody[] =
            "3\r\n"
            "abc\r\n"
            "0\r\n"
            "\r\n";

        char decoded[2] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "chunked decoder rejects undersized output buffer");
        Expect(decodedLength == 0, "chunked decoder does not report a partial body as complete");
        Expect(bytesConsumed == 0, "chunked decoder does not consume partial output on capacity failure");
    }

    void TestChunkedDecodeRejectsBadTerminator()
    {
        const char chunkedBody[] =
            "3\r\n"
            "abc\n"
            "0\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects missing CRLF after data");
    }

    void TestChunkedDecodeRejectsMalformedExtension()
    {
        const char chunkedBody[] =
            "3;=bad\r\n"
            "abc\r\n"
            "0\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects malformed extension");
    }

    void TestChunkedDecodeRejectsMalformedTrailer()
    {
        const char chunkedBody[] =
            "0\r\n"
            "Bad Name: value\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects malformed trailer field name");
        Expect(decodedLength == 0, "malformed trailer does not expose decoded body");
        Expect(bytesConsumed == 0, "malformed trailer does not consume the message");
    }

    void TestChunkedDecodeRejectsForbiddenTrailer()
    {
        const char chunkedBody[] =
            "0\r\n"
            "Content-Length: 7\r\n"
            "\r\n";

        char decoded[8] = {};
        size_t decodedLength = 0;
        size_t bytesConsumed = 0;

        const NTSTATUS status = HttpParser::DecodeChunkedBody(
            chunkedBody,
            strlen(chunkedBody),
            decoded,
            sizeof(decoded),
            &decodedLength,
            &bytesConsumed);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "chunked decoder rejects forbidden trailer field");
        Expect(decodedLength == 0, "forbidden trailer does not expose decoded body");
        Expect(bytesConsumed == 0, "forbidden trailer does not consume the message");
    }

    void TestUnsupportedTransferEncoding()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: br, chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_NOT_SUPPORTED, "br transfer coding is rejected while br content coding remains separate");
    }

    void TestTransferEncodingRejectsContentLength()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "Transfer-Encoding plus Content-Length is rejected");
    }

    void TestTransferEncodingRejectsHttp10()
    {
        const char responseBytes[] =
            "HTTP/1.0 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "HTTP/1.0 Transfer-Encoding is framing faulty");
    }

    void TestTransferEncodingRejectsDuplicateChunked()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked, chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "duplicate chunked transfer coding is rejected");
    }

    void TestTransferEncodingRejectsParameters()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked;foo=bar\r\n"
            "\r\n"
            "3\r\n"
            "abc\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "parameters on chunked transfer coding are rejected");

        const char gzipResponseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: gzip;foo=bar\r\n"
            "\r\n";
        response = {};
        status = HttpParser::ParseResponse(
            gzipResponseBytes,
            strlen(gzipResponseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "parameters on compression transfer coding are rejected");
    }

    void TestTransferEncodingRejectsMalformedParameters()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked;=bad\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "malformed transfer coding parameter is rejected");
    }

    void TestTransferEncodingRejectsIdentity()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: identity, chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "identity is not valid in Transfer-Encoding");
    }

    void TestTransferEncodingRejectsOnlyEmptyList()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: ,,\r\n"
            "\r\n";

        HttpHeader headers[8] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 8;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "Transfer-Encoding with no effective coding is rejected");
    }

    void TestHeaderCapacityFailure()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";

        HttpHeader headers[1] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 1;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_BUFFER_TOO_SMALL, "parser reports header storage exhaustion");
        Expect(response.HeaderCount == 0, "parser clears response on header storage failure");
    }

    void TestResponseRejectsInvalidHeaders()
    {
        const char whitespaceBeforeColon[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length : 5\r\n"
            "\r\n"
            "hello";
        const char invalidFieldName[] =
            "HTTP/1.1 200 OK\r\n"
            "Bad(Header): value\r\n"
            "\r\n";
        const char invalidFieldValue[] =
            "HTTP/1.1 200 OK\r\n"
            "X-Test: bad\001value\r\n"
            "\r\n";

        const char* cases[] = {
            whitespaceBeforeColon,
            invalidFieldName,
            invalidFieldValue
        };

        for (SIZE_T index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            HttpHeader headers[4] = {};
            HttpParseOptions options = {};
            options.Headers = headers;
            options.HeaderCapacity = 4;
            options.MessageCompleteOnConnectionClose = true;

            HttpResponse response = {};
            const NTSTATUS status = HttpParser::ParseResponse(
                cases[index],
                strlen(cases[index]),
                options,
                response);

            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "response parser rejects invalid header syntax");
        }
    }

    void TestResponseRejectsInvalidStatusLines()
    {
        const char unsupportedVersion[] =
            "HTTP/2.0 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        const char zeroStatus[] =
            "HTTP/1.1 000 Invalid\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        const char unsupportedStatus[] =
            "HTTP/1.1 999 Invalid\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        const char* cases[] = {
            unsupportedVersion,
            zeroStatus,
            unsupportedStatus
        };

        for (SIZE_T index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            HttpHeader headers[4] = {};
            HttpParseOptions options = {};
            options.Headers = headers;
            options.HeaderCapacity = 4;

            HttpResponse response = {};
            const NTSTATUS status = HttpParser::ParseResponse(
                cases[index],
                strlen(cases[index]),
                options,
                response);

            Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "response parser rejects unsupported status line");
        }
    }

    void TestParseCloseDelimitedResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "close-body";

        HttpHeader headers[2] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 2;
        options.MessageCompleteOnConnectionClose = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "close-delimited response parses when marked complete");
        Expect(response.BodyKind == HttpBodyKind::CloseDelimited, "body kind is CloseDelimited");
        Expect(response.BodyEndsOnConnectionClose, "response records close-delimited completion");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "close-body"), "close-delimited body is exposed");
    }

    void TestParseEmptyCloseDelimitedResponse()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "\r\n";

        HttpHeader headers[2] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 2;
        options.MessageCompleteOnConnectionClose = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "empty close-delimited response parses when EOF completes it");
        Expect(response.BodyKind == HttpBodyKind::None, "empty close-delimited response has no body bytes");
        Expect(response.BodyEndsOnConnectionClose, "empty EOF-delimited response still records close ownership");
    }

    void TestParseHttp10ConnectionDirectives()
    {
        const char keepAliveResponse[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "ok";
        const char closeResponse[] =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        NTSTATUS status = HttpParser::ParseResponse(
            keepAliveResponse,
            strlen(keepAliveResponse),
            options,
            response);
        Expect(status == STATUS_SUCCESS, "HTTP/1.0 keep-alive response parses");
        Expect(response.MajorVersion == 1 && response.MinorVersion == 0, "HTTP/1.0 version is recorded");
        Expect(response.HasConnectionKeepAlive(), "HTTP/1.0 keep-alive token is recorded");

        memset(headers, 0, sizeof(headers));
        response = {};
        status = HttpParser::ParseResponse(
            closeResponse,
            strlen(closeResponse),
            options,
            response);
        Expect(status == STATUS_SUCCESS, "HTTP/1.0 close response parses");
        Expect(response.HasConnectionClose(), "HTTP/1.0 close token is recorded");
    }


    void TestIncompleteResponseNeedsMoreData()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "he";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "incomplete Content-Length body requests more data");
    }

    void TestIncompleteChunkedResponseNeedsMoreData()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        char decoded[16] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.DecodedBody = decoded;
        options.DecodedBodyCapacity = sizeof(decoded);

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "chunked header without body requests more data");
    }

    void TestEmptyResponseNeedsMoreData()
    {
        const char responseBytes[] = "";
        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            0,
            options,
            response);

        Expect(status == STATUS_MORE_PROCESSING_REQUIRED, "empty response buffer requests more data");
    }

    void TestDuplicateContentLengthConflict()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "hello!";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "conflicting Content-Length headers are rejected");
    }

    void TestContentLengthEquivalentListRejected()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5, 5\r\n"
            "\r\n"
            "hello"
            "next";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "equivalent Content-Length list is rejected");
    }

    void TestContentLengthListConflict()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5, 6\r\n"
            "\r\n"
            "hello!";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "conflicting Content-Length list is rejected");
    }

    void TestNoBodyStatus()
    {
        const char responseBytes[] =
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 10\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "204 response parses successfully");
        Expect(response.BodyKind == HttpBodyKind::None, "204 response ignores message body");
        Expect(response.BodyLength == 0, "204 response body length is zero");
    }

    void TestHeadResponseForbidsBody()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 128\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.ResponseBodyForbidden = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "HEAD response parses without waiting for Content-Length body");
        Expect(response.BodyKind == HttpBodyKind::None, "HEAD response body kind is None");
        Expect(response.BodyLength == 0, "HEAD response body length is zero");
    }

    void TestSwitchingProtocolsLeavesWebSocketBytes()
    {
        const char responseBytes[] =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "\r\n"
            "frame";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;
        options.ResponseBodyForbidden = true;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_SUCCESS, "101 response parses without treating websocket bytes as HTTP body");
        Expect(response.StatusCode == 101, "101 status code is parsed");
        Expect(response.BodyKind == HttpBodyKind::None, "101 response body kind is None");
        Expect(response.BytesConsumed == strlen(responseBytes) - strlen("frame"), "101 parser leaves upgraded bytes unread");
    }

    void TestHeaderTokenMatching()
    {
        Expect(HeaderValueHasToken(MakeText("gzip, chunked"), MakeText("chunked")), "header token matching handles comma lists");
        Expect(HeaderValueHasToken(MakeText(" keep-alive "), MakeText("KEEP-ALIVE")), "header token matching is case-insensitive");
        Expect(!HeaderValueHasToken(MakeText("notchunked"), MakeText("chunked")), "header token matching does not match substrings");
        Expect(TextEqualsIgnoreCase(MakeText("Content-Length"), MakeText("content-length")), "case-insensitive text matching works");
    }

    void TestObsFoldRejected()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "X-Test: a\r\n"
            " b\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        HttpHeader headers[4] = {};
        HttpParseOptions options = {};
        options.Headers = headers;
        options.HeaderCapacity = 4;

        HttpResponse response = {};
        const NTSTATUS status = HttpParser::ParseResponse(
            responseBytes,
            strlen(responseBytes),
            options,
            response);

        Expect(status == STATUS_INVALID_NETWORK_RESPONSE, "obs-fold header continuation is rejected");
    }

    void TestContentRangeParsing()
    {
        using KernelHttp::http::HttpContentRange;

        HttpHeader headers[2] = {};
        headers[0].Name = MakeText("Content-Range");
        headers[0].Value = MakeText("bytes 0-499/1234");
        headers[1].Name = MakeText("Content-Length");
        headers[1].Value = MakeText("500");

        HttpResponse response = {};
        response.StatusCode = 206;
        response.Headers = headers;
        response.HeaderCount = 2;

        Expect(response.IsPartialContent(), "206 reports partial content");

        HttpContentRange range = {};
        Expect(response.GetContentRange(&range), "well-formed Content-Range parses");
        Expect(range.HasRange && range.FirstBytePos == 0 && range.LastBytePos == 499, "range bounds parse");
        Expect(range.HasCompleteLength && range.CompleteLength == 1234, "complete length parses");
    }

    void TestContentRangeUnknownAndUnsatisfied()
    {
        using KernelHttp::http::HttpContentRange;

        {
            HttpHeader headers[1] = {};
            headers[0].Name = MakeText("Content-Range");
            headers[0].Value = MakeText("bytes 100-200/*");
            HttpResponse response = {};
            response.Headers = headers;
            response.HeaderCount = 1;

            HttpContentRange range = {};
            Expect(response.GetContentRange(&range), "range with unknown complete length parses");
            Expect(range.HasRange && range.FirstBytePos == 100 && range.LastBytePos == 200, "bounds parse with unknown length");
            Expect(!range.HasCompleteLength, "unknown complete length is flagged");
        }

        {
            HttpHeader headers[1] = {};
            headers[0].Name = MakeText("Content-Range");
            headers[0].Value = MakeText("bytes */1234");
            HttpResponse response = {};
            response.Headers = headers;
            response.HeaderCount = 1;

            HttpContentRange range = {};
            Expect(response.GetContentRange(&range), "unsatisfied range parses");
            Expect(!range.HasRange, "unsatisfied range has no bounds");
            Expect(range.HasCompleteLength && range.CompleteLength == 1234, "unsatisfied range carries complete length");
        }
    }

    void TestContentRangeRejectsMalformed()
    {
        using KernelHttp::http::HttpContentRange;

        const char* badValues[] = {
            "bytes 500-499/1234",
            "bytes 0-1234/1234",
            "items 0-1/2",
            "bytes 0-1",
            "bytes 0500/1234",
            "bytes 0-1/1234  extra",
            "bytes -1/1234",
            ""
        };

        for (size_t i = 0; i < sizeof(badValues) / sizeof(badValues[0]); ++i) {
            HttpHeader headers[1] = {};
            headers[0].Name = MakeText("Content-Range");
            headers[0].Value = MakeText(badValues[i]);
            HttpResponse response = {};
            response.Headers = headers;
            response.HeaderCount = 1;

            HttpContentRange range = {};
            Expect(!response.GetContentRange(&range), "malformed Content-Range is rejected");
        }

        HttpResponse empty = {};
        HttpContentRange range = {};
        Expect(!empty.GetContentRange(&range), "absent Content-Range returns false");
    }
}

int main()
{
    TestBuildGetRequest();
    TestBuildPostRequest();
    TestBuildChunkedPostRequest();
    TestBuildUpgradeRequest();
    TestRequestBuilderRejectsInjectionText();
    TestRequestBuilderRejectsTransferEncoding();
    TestRequestBuilderRejectsUnsupportedRequestFraming();
    TestBuildChunkedRequestWithTrailers();
    TestBuildChunkedRequestWithEmptyBodyTrailers();
    TestRequestBuilderTrailerValidation();
    TestRequestBuilderAllowsEmptyHeaderValue();
    TestBuildPutRequest();
    TestBuildRealHostGetRequest();
    TestRequestSizeProbe();
    TestBuildAcceptEncodingRequest();
    TestParseContentLengthResponse();
    TestParseChunkedResponse();
    TestParseIdentityContentEncoding();
    TestParseDeflateZlibContentEncoding();
    TestParseDeflateRawContentEncoding();
    TestParseGzipContentEncoding();
    TestParseBrotliContentEncoding();
    TestParseCompressContentEncoding();
    TestParseChunkedGzipContentEncoding();
    TestTransferEncodingGzipChunked();
    TestTransferEncodingDeflateChunked();
    TestTransferEncodingCompressChunked();
    TestTransferEncodingAliasesChunked();
    TestTransferEncodingGzipCloseDelimited();
    TestTransferEncodingChunkedThenGzipCloseDelimited();
    TestTransferEncodingRejectsInnerChunkedTail();
    TestTransferEncodingRejectsEmptyListMember();
    TestUnsupportedContentEncoding();
    TestContentEncodingRequiresCapacity();
    TestContentEncodingRejectsTooManyCodings();
    TestChunkedDecodeRequiresCapacity();
    TestChunkedDecodeRejectsBadTerminator();
    TestChunkedDecodeRejectsMalformedExtension();
    TestChunkedDecodeRejectsMalformedTrailer();
    TestChunkedDecodeRejectsForbiddenTrailer();
    TestUnsupportedTransferEncoding();
    TestTransferEncodingRejectsContentLength();
    TestTransferEncodingRejectsHttp10();
    TestTransferEncodingRejectsDuplicateChunked();
    TestTransferEncodingRejectsParameters();
    TestTransferEncodingRejectsMalformedParameters();
    TestTransferEncodingRejectsIdentity();
    TestTransferEncodingRejectsOnlyEmptyList();
    TestHeaderCapacityFailure();
    TestResponseRejectsInvalidHeaders();
    TestResponseRejectsInvalidStatusLines();
    TestParseCloseDelimitedResponse();
    TestParseEmptyCloseDelimitedResponse();
    TestParseHttp10ConnectionDirectives();
    TestIncompleteResponseNeedsMoreData();
    TestIncompleteChunkedResponseNeedsMoreData();
    TestEmptyResponseNeedsMoreData();
    TestDuplicateContentLengthConflict();
    TestContentLengthEquivalentListRejected();
    TestContentLengthListConflict();
    TestNoBodyStatus();
    TestHeadResponseForbidsBody();
    TestSwitchingProtocolsLeavesWebSocketBytes();
    TestHeaderTokenMatching();
    TestObsFoldRejected();
    TestContentRangeParsing();
    TestContentRangeUnknownAndUnsatisfied();
    TestContentRangeRejectsMalformed();

    if (g_failed) {
        return 1;
    }

    printf("PASS: HTTP parser tests\n");
    return 0;
}
