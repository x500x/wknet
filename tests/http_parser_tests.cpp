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
            "Transfer-Encoding: gzip, chunked\r\n"
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
        char decoded[32] = {};
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

        Expect(status == STATUS_SUCCESS, "chunked response parses successfully");
        Expect(response.BodyKind == HttpBodyKind::Chunked, "body kind is Chunked");
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "Wikipedia"), "chunked body is decoded");
        Expect(response.BytesConsumed == strlen(responseBytes) - strlen("tail"), "chunked parser leaves trailing bytes unread");
        Expect(response.HasChunkedTransferEncoding(), "chunked transfer token lookup works");
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

    void TestUnsupportedTransferEncoding()
    {
        const char responseBytes[] =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: gzip\r\n"
            "\r\n"
            "compressed";

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

        Expect(status == STATUS_NOT_SUPPORTED, "unsupported transfer coding is rejected instead of close-delimited");
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

    void TestParseCloseDelimitedResponse()
    {
        const char responseBytes[] =
            "HTTP/1.0 200 OK\r\n"
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
        Expect(MemoryEqualsLiteral(response.Body, response.BodyLength, "close-body"), "close-delimited body is exposed");
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
}

int main()
{
    TestBuildGetRequest();
    TestBuildPostRequest();
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
    TestParseChunkedGzipContentEncoding();
    TestUnsupportedContentEncoding();
    TestContentEncodingRequiresCapacity();
    TestChunkedDecodeRequiresCapacity();
    TestChunkedDecodeRejectsBadTerminator();
    TestUnsupportedTransferEncoding();
    TestHeaderCapacityFailure();
    TestParseCloseDelimitedResponse();
    TestIncompleteResponseNeedsMoreData();
    TestEmptyResponseNeedsMoreData();
    TestDuplicateContentLengthConflict();
    TestNoBodyStatus();
    TestHeadResponseForbidsBody();
    TestSwitchingProtocolsLeavesWebSocketBytes();
    TestHeaderTokenMatching();

    if (g_failed) {
        return 1;
    }

    printf("PASS: HTTP parser tests\n");
    return 0;
}
