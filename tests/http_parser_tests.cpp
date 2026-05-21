#ifndef KERNEL_HTTP_USER_MODE_TEST
#define KERNEL_HTTP_USER_MODE_TEST 1
#endif

#include "../src/KernelHttp/http/HttpParser.h"
#include "../src/KernelHttp/http/HttpRequest.h"

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
    TestParseContentLengthResponse();
    TestParseChunkedResponse();
    TestChunkedDecodeRequiresCapacity();
    TestChunkedDecodeRejectsBadTerminator();
    TestUnsupportedTransferEncoding();
    TestHeaderCapacityFailure();
    TestParseCloseDelimitedResponse();
    TestIncompleteResponseNeedsMoreData();
    TestDuplicateContentLengthConflict();
    TestNoBodyStatus();
    TestHeadResponseForbidsBody();
    TestHeaderTokenMatching();

    if (g_failed) {
        return 1;
    }

    printf("PASS: HTTP parser tests\n");
    return 0;
}
