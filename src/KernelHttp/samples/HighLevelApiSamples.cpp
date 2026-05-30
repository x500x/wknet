#include "samples/HighLevelApiSamples.h"

#include "khttp/AsyncOp.h"
#include "khttp/Http.h"
#include "khttp/HttpAsync.h"
#include "khttp/Request.h"
#include "khttp/Response.h"
#include "khttp/Session.h"
#include "khttp/WebSocket.h"
#include "samples/ExternalTrustStore.h"

#if defined(KERNEL_HTTP_USER_MODE_TEST)
#include <stdio.h>
#define KHTTP_SAMPLE_LOG(...) printf(__VA_ARGS__)
#else
#define KHTTP_SAMPLE_LOG(...) kprintf(__VA_ARGS__)
#endif

namespace KernelHttp
{
namespace samples
{
namespace
{
    constexpr ULONG AsyncWaitTimeoutMs = 60000;

    constexpr const char* HttpGetUrl = "http://nghttp2.org/httpbin/get";
    constexpr const char* HttpPostUrl = "http://nghttp2.org/httpbin/post";
    constexpr const char* HttpPutUrl = "http://nghttp2.org/httpbin/put";
    constexpr const char* HttpPatchUrl = "http://nghttp2.org/httpbin/patch";
    constexpr const char* HttpDeleteUrl = "http://nghttp2.org/httpbin/delete";
    constexpr const char* HttpHeadUrl = "http://nghttp2.org/httpbin/get";
    constexpr const char* HttpOptionsUrl = "http://nghttp2.org/httpbin/";
    constexpr const char* HttpsGetUrl = "https://nghttp2.org/httpbin/get";
    constexpr const char* HttpsBuilderUrl = "https://nghttp2.org/httpbin/anything";
    constexpr const char* WebSocketSecureEchoUrl = "wss://ws.postman-echo.com/raw";
    constexpr const char* WebSocketBinaryEchoUrl = "wss://websocket-echo.com";
    constexpr const char* AlpnHttp11 = "http/1.1";
    constexpr const char* AlpnH2 = "h2";

#if defined(KERNEL_HTTP_USER_MODE_TEST)
    constexpr const char* FileBodyPath = "tests/testdata/request_body_file.txt";
#else
    constexpr const char* FileBodyPath = "\\SystemRoot\\System32\\drivers\\etc\\hosts";
#endif

    constexpr const char* JsonBody = "{\"hello\":\"world\"}";
    constexpr const char* TextBody = "hello from high-level khttp";
    constexpr UCHAR RawBody[] = { 0x6B, 0x68, 0x74, 0x74, 0x70 };
    constexpr const char* WsHelloMessage = "hello-from-khttp";
    constexpr UCHAR WsBinaryMessage[] = { 0x01, 0x02, 0x03, 0x04 };
    constexpr khttp::AddressFamily DefaultSampleAddressFamily = khttp::AddressFamily::Ipv4;

    enum class SendVariant : ULONG
    {
        Send = 0,
        SendWithOptions = 1,
        SendEx = 2
    };

    enum class AsyncSendVariant : ULONG
    {
        SendAsync = 0,
        SendAsyncWithOptions = 1,
        SendAsyncEx = 2
    };

    enum class WsConnectVariant : ULONG
    {
        Url = 0,
        Config = 1,
        Ex = 2
    };

    enum class WsSendVariant : ULONG
    {
        None = 0,
        Text = 1,
        TextEx = 2,
        Binary = 3,
        BinaryEx = 4
    };

    struct CallbackStats final
    {
        SIZE_T HeaderCount = 0;
        SIZE_T BodyChunks = 0;
        SIZE_T BodyBytes = 0;
        bool BodyFinal = false;
        SIZE_T CompletionCount = 0;
        NTSTATUS CompletionStatus = STATUS_PENDING;
        SIZE_T WsMessageBytes = 0;
        khttp::WsMsgType WsMessageType = khttp::WsMsgType::Binary;
        bool WsFinalFragment = false;
    };

    SIZE_T LiteralLength(const char* value) noexcept
    {
        SIZE_T length = 0;
        if (value == nullptr) {
            return 0;
        }
        while (value[length] != '\0') {
            ++length;
        }
        return length;
    }

    int PrintLength(SIZE_T length) noexcept
    {
        constexpr SIZE_T MaxPrintLength = 0x7fffffff;
        return static_cast<int>(length > MaxPrintLength ? MaxPrintLength : length);
    }

    SIZE_T MinSize(SIZE_T left, SIZE_T right) noexcept
    {
        return left < right ? left : right;
    }

    bool IsTextPayload(const UCHAR* data, SIZE_T dataLength) noexcept
    {
        for (SIZE_T i = 0; i < dataLength; ++i) {
            const UCHAR byte = data[i];
            if (byte >= 0x20 && byte <= 0x7E) {
                continue;
            }
            if (byte == '\r' || byte == '\n' || byte == '\t') {
                continue;
            }
            return false;
        }
        return true;
    }

    void LogBytePayload(
        const char* prefix,
        const char* sampleName,
        const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        if (data == nullptr || dataLength == 0) {
            KHTTP_SAMPLE_LOG(
                "%s 示例=%s 内容=<空>\r\n",
                prefix,
                sampleName);
            return;
        }

        if (IsTextPayload(data, dataLength)) {
            KHTTP_SAMPLE_LOG(
                "%s 示例=%s 内容长度=%Iu 内容=%.*s\r\n",
                prefix,
                sampleName,
                dataLength,
                PrintLength(dataLength),
                reinterpret_cast<const char*>(data));
            return;
        }

        KHTTP_SAMPLE_LOG(
            "%s 示例=%s 内容长度=%Iu HEX:\r\n",
            prefix,
            sampleName,
            dataLength);
        for (SIZE_T offset = 0; offset < dataLength; offset += 16) {
            const SIZE_T chunkLength = MinSize(dataLength - offset, 16);
            KHTTP_SAMPLE_LOG(
                "%s 示例=%s HEX偏移=%Iu 长度=%Iu %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
                prefix,
                sampleName,
                offset,
                chunkLength,
                chunkLength > 0 ? data[offset + 0] : 0,
                chunkLength > 1 ? data[offset + 1] : 0,
                chunkLength > 2 ? data[offset + 2] : 0,
                chunkLength > 3 ? data[offset + 3] : 0,
                chunkLength > 4 ? data[offset + 4] : 0,
                chunkLength > 5 ? data[offset + 5] : 0,
                chunkLength > 6 ? data[offset + 6] : 0,
                chunkLength > 7 ? data[offset + 7] : 0,
                chunkLength > 8 ? data[offset + 8] : 0,
                chunkLength > 9 ? data[offset + 9] : 0,
                chunkLength > 10 ? data[offset + 10] : 0,
                chunkLength > 11 ? data[offset + 11] : 0,
                chunkLength > 12 ? data[offset + 12] : 0,
                chunkLength > 13 ? data[offset + 13] : 0,
                chunkLength > 14 ? data[offset + 14] : 0,
                chunkLength > 15 ? data[offset + 15] : 0);
        }
    }

    const char* MethodName(khttp::Method method) noexcept
    {
        switch (method) {
        case khttp::Method::Get: return "GET";
        case khttp::Method::Post: return "POST";
        case khttp::Method::Put: return "PUT";
        case khttp::Method::Patch: return "PATCH";
        case khttp::Method::Delete: return "DELETE";
        case khttp::Method::Head: return "HEAD";
        case khttp::Method::Options: return "OPTIONS";
        default: return "UNKNOWN";
        }
    }

    const char* PoolTypeName(khttp::PoolType poolType) noexcept
    {
        return poolType == khttp::PoolType::Paged ? "分页池" : "非分页池";
    }

    const char* TlsVersionName(khttp::TlsVersion version) noexcept
    {
        return version == khttp::TlsVersion::Tls13 ? "TLS1.3" : "TLS1.2";
    }

    const char* CertPolicyName(khttp::CertPolicy policy) noexcept
    {
        return policy == khttp::CertPolicy::NoVerify ? "不校验证书" : "校验证书";
    }

    const char* AddressFamilyName(khttp::AddressFamily family) noexcept
    {
        switch (family) {
        case khttp::AddressFamily::Ipv4: return "IPv4";
        case khttp::AddressFamily::Ipv6: return "IPv6";
        case khttp::AddressFamily::Any: return "系统默认";
        default: return "未知地址族";
        }
    }

    const char* ConnPolicyName(khttp::ConnPolicy policy) noexcept
    {
        switch (policy) {
        case khttp::ConnPolicy::ReuseOrCreate: return "复用或新建连接";
        case khttp::ConnPolicy::ForceNew: return "强制新建连接";
        case khttp::ConnPolicy::NoPool: return "不进入连接池";
        default: return "未知连接策略";
        }
    }

    const char* WsMsgTypeName(khttp::WsMsgType type) noexcept
    {
        switch (type) {
        case khttp::WsMsgType::Text: return "文本";
        case khttp::WsMsgType::Binary: return "二进制";
        case khttp::WsMsgType::Close: return "关闭";
        default: return "未知消息";
        }
    }

    const char* BoolName(bool value) noexcept
    {
        return value ? "是" : "否";
    }

    const char* SendVariantName(SendVariant variant) noexcept
    {
        switch (variant) {
        case SendVariant::Send: return "Send";
        case SendVariant::SendWithOptions: return "Send(带选项)";
        case SendVariant::SendEx: return "SendEx";
        default: return "未知发送入口";
        }
    }

    const char* AsyncSendVariantName(AsyncSendVariant variant) noexcept
    {
        switch (variant) {
        case AsyncSendVariant::SendAsync: return "SendAsync";
        case AsyncSendVariant::SendAsyncWithOptions: return "SendAsync(带选项)";
        case AsyncSendVariant::SendAsyncEx: return "SendAsyncEx";
        default: return "未知异步入口";
        }
    }

    const char* WsConnectVariantName(WsConnectVariant variant) noexcept
    {
        switch (variant) {
        case WsConnectVariant::Url: return "WsConnect(URL)";
        case WsConnectVariant::Config: return "WsConnect(配置)";
        case WsConnectVariant::Ex: return "WsConnectEx";
        default: return "未知连接入口";
        }
    }

    const char* WsSendVariantName(WsSendVariant variant) noexcept
    {
        switch (variant) {
        case WsSendVariant::None: return "不发送";
        case WsSendVariant::Text: return "WsSendText";
        case WsSendVariant::TextEx: return "WsSendTextEx";
        case WsSendVariant::Binary: return "WsSendBinary";
        case WsSendVariant::BinaryEx: return "WsSendBinaryEx";
        default: return "未知发送入口";
        }
    }

    void MergeSampleStatus(NTSTATUS& aggregate, NTSTATUS status) noexcept
    {
        if (!NT_SUCCESS(status) && NT_SUCCESS(aggregate)) {
            aggregate = status;
        }
    }

    void CaptureStatus(
        HighLevelApiSampleResult& result,
        NTSTATUS status,
        ULONG statusCode,
        SIZE_T bodyLength) noexcept
    {
        result.Status = status;
        result.StatusCode = statusCode;
        result.BodyLength = bodyLength;
    }

    void LogSessionConfig(const char* sampleName, const khttp::SessionConfig& config) noexcept
    {
        KHTTP_SAMPLE_LOG(
            "[会话示例] %s：响应池=%s 最大响应=%Iu 连接池容量=%lu 每主机最大连接=%lu 空闲超时=%lums TLS=%s-%s 证书策略=%s TLS握手超时=%lums\r\n",
            sampleName,
            PoolTypeName(config.ResponsePool),
            config.MaxResponseBytes,
            config.PoolCapacity,
            config.MaxConnsPerHost,
            config.IdleTimeoutMs,
            TlsVersionName(config.Tls.MinVersion),
            TlsVersionName(config.Tls.MaxVersion),
            CertPolicyName(config.Tls.Certificate),
            config.Tls.HandshakeTimeoutMs);
    }

    void LogHttpRequest(
        const char* sampleName,
        const char* entryName,
        khttp::Method method,
        const char* url,
        const char* bodyKind,
        SIZE_T bodyLength,
        const khttp::TlsConfig* tlsConfig,
        khttp::AddressFamily family,
        khttp::ConnPolicy policy) noexcept
    {
        const char* certPolicy = tlsConfig != nullptr ? CertPolicyName(tlsConfig->Certificate) : "使用会话默认";
        const char* alpn = "使用会话默认";
        SIZE_T alpnLength = LiteralLength(alpn);
        if (tlsConfig != nullptr && tlsConfig->Alpn != nullptr && tlsConfig->AlpnLength != 0) {
            alpn = tlsConfig->Alpn;
            alpnLength = tlsConfig->AlpnLength;
        }
        KHTTP_SAMPLE_LOG(
            "[HTTP请求] 示例=%s 入口=%s 方法=%s URL=%s 请求体=%s 长度=%Iu 证书策略=%s TLS ALPN=%.*s 地址族=%s 连接策略=%s\r\n",
            sampleName,
            entryName,
            MethodName(method),
            url != nullptr ? url : "",
            bodyKind != nullptr ? bodyKind : "无",
            bodyLength,
            certPolicy,
            PrintLength(alpnLength),
            alpn,
            AddressFamilyName(family),
            ConnPolicyName(policy));
    }

    void LogHttpResponse(
        const char* sampleName,
        NTSTATUS status,
        const khttp::Response* response) noexcept
    {
        const ULONG statusCode = khttp::ResponseStatusCode(response);
        const SIZE_T bodyLength = khttp::ResponseBodyLength(response);
        KHTTP_SAMPLE_LOG(
            "[HTTP响应] 示例=%s NTSTATUS=0x%08X 状态码=%lu 响应体长度=%Iu\r\n",
            sampleName,
            static_cast<ULONG>(status),
            statusCode,
            bodyLength);

        if (response == nullptr) {
            return;
        }

        const SIZE_T headerCount = khttp::ResponseHeaderCount(response);
        KHTTP_SAMPLE_LOG(
            "[HTTP响应] 示例=%s 响应头数量=%Iu\r\n",
            sampleName,
            headerCount);
        for (SIZE_T index = 0; index < headerCount; ++index) {
            const char* headerName = nullptr;
            SIZE_T headerNameLength = 0;
            const char* headerValue = nullptr;
            SIZE_T headerValueLength = 0;
            const NTSTATUS headerAtStatus = khttp::ResponseGetHeaderAt(
                response,
                index,
                &headerName,
                &headerNameLength,
                &headerValue,
                &headerValueLength);
            if (NT_SUCCESS(headerAtStatus)) {
                KHTTP_SAMPLE_LOG(
                    "[HTTP响应] 示例=%s 响应头[%Iu] %.*s: %.*s\r\n",
                    sampleName,
                    index,
                    PrintLength(headerNameLength),
                    headerName != nullptr ? headerName : "",
                    PrintLength(headerValueLength),
                    headerValue != nullptr ? headerValue : "");
            }
        }

        const char* headerValue = nullptr;
        SIZE_T headerValueLength = 0;
        const NTSTATUS headerStatus = khttp::ResponseGetHeader(
            response,
            "Content-Length",
            LiteralLength("Content-Length"),
            &headerValue,
            &headerValueLength);
        if (NT_SUCCESS(headerStatus)) {
            KHTTP_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 响应头 Content-Length=%.*s\r\n",
                sampleName,
                PrintLength(headerValueLength),
                headerValue != nullptr ? headerValue : "");
        }
        else {
            KHTTP_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 未找到响应头 Content-Length，查询状态=0x%08X\r\n",
                sampleName,
                static_cast<ULONG>(headerStatus));
        }

        LogBytePayload(
            "[HTTP响应体]",
            sampleName,
            khttp::ResponseBody(response),
            bodyLength);
    }

    void CaptureResponse(
        const char* sampleName,
        HighLevelApiSampleResult& result,
        NTSTATUS status,
        khttp::Response* response) noexcept
    {
        result.Status = status;
        result.StatusCode = khttp::ResponseStatusCode(response);
        result.BodyLength = khttp::ResponseBodyLength(response);
        LogHttpResponse(sampleName, status, response);
    }

    NTSTATUS HeaderCallback(
        void* context,
        const char* name,
        SIZE_T nameLength,
        const char* value,
        SIZE_T valueLength) noexcept
    {
        auto* stats = static_cast<CallbackStats*>(context);
        if (stats == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++stats->HeaderCount;
        KHTTP_SAMPLE_LOG(
            "[HTTP回调] 收到响应头 %.*s: %.*s\r\n",
            PrintLength(nameLength),
            name != nullptr ? name : "",
            PrintLength(valueLength),
            value != nullptr ? value : "");
        return STATUS_SUCCESS;
    }

    NTSTATUS BodyCallback(
        void* context,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalChunk) noexcept
    {
        UNREFERENCED_PARAMETER(data);
        auto* stats = static_cast<CallbackStats*>(context);
        if (stats == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ++stats->BodyChunks;
        stats->BodyBytes += dataLength;
        stats->BodyFinal = finalChunk;
        KHTTP_SAMPLE_LOG(
            "[HTTP回调] 收到响应体分块 长度=%Iu 是否最后一块=%s\r\n",
            dataLength,
            BoolName(finalChunk));
        LogBytePayload("[HTTP回调响应体]", "回调分块", data, dataLength);
        return STATUS_SUCCESS;
    }

    void CompletionCallback(void* context, NTSTATUS status) noexcept
    {
        auto* stats = static_cast<CallbackStats*>(context);
        if (stats == nullptr) {
            return;
        }

        ++stats->CompletionCount;
        stats->CompletionStatus = status;
        KHTTP_SAMPLE_LOG(
            "[异步回调] 操作完成 NTSTATUS=0x%08X\r\n",
            static_cast<ULONG>(status));
    }

    NTSTATUS WebSocketMessageCallback(
        void* context,
        khttp::WsMsgType type,
        const UCHAR* data,
        SIZE_T dataLength,
        bool finalFragment) noexcept
    {
        auto* stats = static_cast<CallbackStats*>(context);
        if (stats == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        stats->WsMessageBytes = dataLength;
        stats->WsMessageType = type;
        stats->WsFinalFragment = finalFragment;
        KHTTP_SAMPLE_LOG(
            "[WebSocket回调] 收到%s消息 长度=%Iu 是否最后分片=%s\r\n",
            WsMsgTypeName(type),
            dataLength,
            BoolName(finalFragment));
        LogBytePayload("[WebSocket回调消息]", "WebSocket 接收 Ex 回调", data, dataLength);
        return STATUS_SUCCESS;
    }

    NTSTATUS CreateSampleRequest(
        khttp::Session* session,
        khttp::Method method,
        const char* url,
        const khttp::TlsConfig* tlsConfig,
        khttp::AddressFamily family,
        khttp::ConnPolicy policy,
        khttp::Request** request) noexcept
    {
        if (session == nullptr || url == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *request = nullptr;
        khttp::Request* newRequest = nullptr;
        NTSTATUS status = khttp::RequestCreate(session, &newRequest);
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetUrl(newRequest, url, LiteralLength(url));
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetMethod(newRequest, method);
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetAddressFamily(newRequest, family);
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetConnPolicy(newRequest, policy);
        }
        if (NT_SUCCESS(status) && tlsConfig != nullptr) {
            status = khttp::RequestSetTls(newRequest, tlsConfig);
        }
        if (NT_SUCCESS(status)) {
            const char* userAgent = "KernelHttp/0.1";
            status = khttp::RequestSetHeader(
                newRequest,
                "User-Agent",
                LiteralLength("User-Agent"),
                userAgent,
                LiteralLength(userAgent));
        }

        if (!NT_SUCCESS(status)) {
            khttp::RequestRelease(newRequest);
            return status;
        }

        *request = newRequest;
        return STATUS_SUCCESS;
    }

    NTSTATUS SendPreparedRequest(
        khttp::Session* session,
        const char* sampleName,
        khttp::Method method,
        const char* url,
        const char* bodyKind,
        SIZE_T bodyLength,
        const khttp::TlsConfig* tlsConfig,
        khttp::AddressFamily family,
        khttp::ConnPolicy policy,
        khttp::Request* request,
        const khttp::SendOptions* options,
        SendVariant variant,
        HighLevelApiSampleResult& result) noexcept
    {
        if (session == nullptr || request == nullptr) {
            result.Status = STATUS_INVALID_PARAMETER;
            return result.Status;
        }

        LogHttpRequest(
            sampleName,
            SendVariantName(variant),
            method,
            url,
            bodyKind,
            bodyLength,
            tlsConfig,
            family,
            policy);

        khttp::Response* response = nullptr;
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        if (variant == SendVariant::Send) {
            status = khttp::Send(session, request, &response);
        }
        else if (variant == SendVariant::SendWithOptions) {
            status = khttp::Send(session, request, options, &response);
        }
        else {
            status = khttp::SendEx(session, request, options, &response);
        }

        CaptureResponse(sampleName, result, status, response);
        khttp::ResponseRelease(response);
        return status;
    }

    NTSTATUS RunRequestBodySample(
        khttp::Session* session,
        const char* sampleName,
        const char* bodyKind,
        SIZE_T displayBodyLength,
        HighLevelApiSampleResult& result,
        NTSTATUS (*setBody)(khttp::Request* request) noexcept) noexcept
    {
        khttp::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            khttp::Method::Post,
            HttpPostUrl,
            nullptr,
            DefaultSampleAddressFamily,
            khttp::ConnPolicy::NoPool,
            &request);
        if (NT_SUCCESS(status)) {
            status = setBody(request);
        }
        if (NT_SUCCESS(status)) {
            status = SendPreparedRequest(
                session,
                sampleName,
                khttp::Method::Post,
                HttpPostUrl,
                bodyKind,
                displayBodyLength,
                nullptr,
                DefaultSampleAddressFamily,
                khttp::ConnPolicy::NoPool,
                request,
                nullptr,
                SendVariant::Send,
                result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
            KHTTP_SAMPLE_LOG("[HTTP请求] 示例=%s 构造请求体失败 NTSTATUS=0x%08X\r\n",
                sampleName,
                static_cast<ULONG>(status));
        }

        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS SetTextBody(khttp::Request* request) noexcept
    {
        return khttp::RequestSetTextBody(
            request,
            TextBody,
            LiteralLength(TextBody),
            nullptr,
            0);
    }

    NTSTATUS SetJsonBody(khttp::Request* request) noexcept
    {
        return khttp::RequestSetJsonBody(request, JsonBody, LiteralLength(JsonBody));
    }

    NTSTATUS SetRawBody(khttp::Request* request) noexcept
    {
        return khttp::RequestSetRawBody(
            request,
            RawBody,
            sizeof(RawBody),
            "application/octet-stream",
            LiteralLength("application/octet-stream"));
    }

    NTSTATUS SetFormBody(khttp::Request* request) noexcept
    {
        const khttp::NameValuePair pairs[] = {
            { "source", LiteralLength("source"), "kernel-http", LiteralLength("kernel-http") },
            { "kind", LiteralLength("kind"), "form", LiteralLength("form") }
        };
        return khttp::RequestSetFormBody(request, pairs, sizeof(pairs) / sizeof(pairs[0]));
    }

    NTSTATUS SetMultipartBody(khttp::Request* request) noexcept
    {
        const UCHAR fileBytes[] = { 'f', 'i', 'l', 'e', '-', 'b', 'y', 't', 'e', 's' };
        const khttp::MultipartPart parts[] = {
            {
                khttp::BodyPartKind::Field,
                "field",
                LiteralLength("field"),
                "value",
                LiteralLength("value"),
                nullptr,
                0,
                nullptr,
                0,
                nullptr,
                0,
                nullptr,
                0
            },
            {
                khttp::BodyPartKind::FileBytes,
                "upload",
                LiteralLength("upload"),
                nullptr,
                0,
                fileBytes,
                sizeof(fileBytes),
                nullptr,
                0,
                "sample.txt",
                LiteralLength("sample.txt"),
                "text/plain",
                LiteralLength("text/plain")
            }
        };
        return khttp::RequestSetMultipartBody(request, parts, sizeof(parts) / sizeof(parts[0]));
    }

    NTSTATUS SetFileBody(khttp::Request* request) noexcept
    {
        KHTTP_SAMPLE_LOG("[HTTP请求] 文件请求体示例路径=%s\r\n", FileBodyPath);
        return khttp::RequestSetFileBody(
            request,
            FileBodyPath,
            LiteralLength(FileBodyPath),
            "text/plain",
            LiteralLength("text/plain"));
    }

    NTSTATUS SetClearBody(khttp::Request* request) noexcept
    {
        NTSTATUS status = khttp::RequestSetJsonBody(request, JsonBody, LiteralLength(JsonBody));
        if (NT_SUCCESS(status)) {
            status = khttp::RequestClearBody(request);
        }
        return status;
    }

    NTSTATUS RunSimpleSync(
        khttp::Session* session,
        const char* sampleName,
        khttp::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        const char* bodyKind,
        HighLevelApiSampleResult& result,
        const khttp::TlsConfig* tlsConfig = nullptr,
        khttp::ConnPolicy policy = khttp::ConnPolicy::ReuseOrCreate,
        khttp::AddressFamily family = DefaultSampleAddressFamily) noexcept
    {
        khttp::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            method,
            url,
            tlsConfig,
            family,
            policy,
            &request);
        if (NT_SUCCESS(status) && bodyLength != 0) {
            status = khttp::RequestSetBody(request, body, bodyLength);
        }
        if (NT_SUCCESS(status)) {
            status = SendPreparedRequest(
                session,
                sampleName,
                method,
                url,
                bodyKind,
                bodyLength,
                tlsConfig,
                family,
                policy,
                request,
                nullptr,
                SendVariant::Send,
                result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS RunShortcutHttp(
        khttp::Session* session,
        const char* sampleName,
        khttp::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        const char* bodyKind,
        HighLevelApiSampleResult& result) noexcept
    {
        LogHttpRequest(
            sampleName,
            "快捷函数",
            method,
            url,
            bodyKind,
            bodyLength,
            nullptr,
            khttp::AddressFamily::Any,
            khttp::ConnPolicy::ReuseOrCreate);

        khttp::Response* response = nullptr;
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        switch (method) {
        case khttp::Method::Get:
            status = khttp::Get(session, url, LiteralLength(url), &response);
            break;
        case khttp::Method::Post:
            status = khttp::Post(session, url, LiteralLength(url), body, bodyLength, &response);
            break;
        case khttp::Method::Put:
            status = khttp::Put(session, url, LiteralLength(url), body, bodyLength, &response);
            break;
        case khttp::Method::Patch:
            status = khttp::Patch(session, url, LiteralLength(url), body, bodyLength, &response);
            break;
        case khttp::Method::Delete:
            status = khttp::Delete(session, url, LiteralLength(url), &response);
            break;
        case khttp::Method::Head:
            status = khttp::Head(session, url, LiteralLength(url), &response);
            break;
        case khttp::Method::Options:
            status = khttp::Options(session, url, LiteralLength(url), &response);
            break;
        default:
            break;
        }

        CaptureResponse(sampleName, result, status, response);
        khttp::ResponseRelease(response);
        return status;
    }

    NTSTATUS RunSendWithOptions(
        khttp::Session* session,
        HighLevelApiSampleResult& result,
        bool useSendEx) noexcept
    {
        khttp::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            khttp::Method::Get,
            HttpGetUrl,
            nullptr,
            DefaultSampleAddressFamily,
            useSendEx ? khttp::ConnPolicy::ForceNew : khttp::ConnPolicy::NoPool,
            &request);

        CallbackStats stats = {};
        khttp::SendOptions options = khttp::DefaultSendOptions();
        options.MaxResponseBytes = 64 * 1024;
        options.Flags = khttp::SendFlagAggregateWithCallbacks;
        options.OnHeader = HeaderCallback;
        options.OnBody = BodyCallback;
        options.CallbackContext = &stats;

        if (NT_SUCCESS(status)) {
            status = SendPreparedRequest(
                session,
                useSendEx ? "HTTP SendEx" : "HTTP Send(带选项)",
                khttp::Method::Get,
                HttpGetUrl,
                "无",
                0,
                nullptr,
                DefaultSampleAddressFamily,
                useSendEx ? khttp::ConnPolicy::ForceNew : khttp::ConnPolicy::NoPool,
                request,
                &options,
                useSendEx ? SendVariant::SendEx : SendVariant::SendWithOptions,
                result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        KHTTP_SAMPLE_LOG(
            "[HTTP回调] 示例=%s 响应头数量=%Iu 响应体分块=%Iu 回调累计字节=%Iu\r\n",
            useSendEx ? "HTTP SendEx" : "HTTP Send(带选项)",
            stats.HeaderCount,
            stats.BodyChunks,
            stats.BodyBytes);

        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS RunResponseHeaderSample(khttp::Session* session, HighLevelApiSampleResult& result) noexcept
    {
        khttp::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            khttp::Method::Get,
            HttpGetUrl,
            nullptr,
            DefaultSampleAddressFamily,
            khttp::ConnPolicy::ReuseOrCreate,
            &request);

        khttp::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            LogHttpRequest(
                "HTTP 响应头读取",
                "Send",
                khttp::Method::Get,
                HttpGetUrl,
                "无",
                0,
                nullptr,
                DefaultSampleAddressFamily,
                khttp::ConnPolicy::ReuseOrCreate);
            status = khttp::Send(session, request, &response);
        }
        CaptureResponse("HTTP 响应头读取", result, status, response);

        if (NT_SUCCESS(status) && response != nullptr) {
            const char* headerValue = nullptr;
            SIZE_T headerLength = 0;
            const NTSTATUS headerStatus = khttp::ResponseGetHeader(
                response,
                "Content-Length",
                LiteralLength("Content-Length"),
                &headerValue,
                &headerLength);
            KHTTP_SAMPLE_LOG(
                "[HTTP响应] ResponseGetHeader(Content-Length) 状态=0x%08X 值=%.*s\r\n",
                static_cast<ULONG>(headerStatus),
                PrintLength(headerLength),
                headerValue != nullptr ? headerValue : "");
        }

        khttp::ResponseRelease(response);
        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS CompleteHttpAsync(
        const char* sampleName,
        khttp::AsyncOp* op,
        HighLevelApiSampleResult& result) noexcept
    {
        if (op == nullptr) {
            CaptureStatus(result, STATUS_INVALID_PARAMETER, 0, 0);
            return STATUS_INVALID_PARAMETER;
        }

        KHTTP_SAMPLE_LOG(
            "[HTTP异步] 示例=%s 等待前：状态=0x%08X 已完成=%s 已取消=%s\r\n",
            sampleName,
            static_cast<ULONG>(khttp::AsyncGetStatus(op)),
            BoolName(khttp::AsyncIsCompleted(op)),
            BoolName(khttp::AsyncIsCanceled(op)));

        NTSTATUS status = khttp::AsyncWait(op, AsyncWaitTimeoutMs);
        KHTTP_SAMPLE_LOG(
            "[HTTP异步] 示例=%s 等待后：状态=0x%08X 已完成=%s 已取消=%s\r\n",
            sampleName,
            static_cast<ULONG>(khttp::AsyncGetStatus(op)),
            BoolName(khttp::AsyncIsCompleted(op)),
            BoolName(khttp::AsyncIsCanceled(op)));

        khttp::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            status = khttp::AsyncGetResponse(op, &response);
        }
        CaptureResponse(sampleName, result, status, response);
        khttp::ResponseRelease(response);
        khttp::AsyncRelease(op);
        return status;
    }

    NTSTATUS RunSimpleAsync(
        khttp::Session* session,
        const char* sampleName,
        khttp::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        const char* bodyKind,
        HighLevelApiSampleResult& result) noexcept
    {
        LogHttpRequest(
            sampleName,
            method == khttp::Method::Post ? "PostAsync" : "GetAsync",
            method,
            url,
            bodyKind,
            bodyLength,
            nullptr,
            khttp::AddressFamily::Any,
            khttp::ConnPolicy::ReuseOrCreate);

        khttp::AsyncOp* op = nullptr;
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        if (method == khttp::Method::Post) {
            status = khttp::PostAsync(session, url, LiteralLength(url), body, bodyLength, &op);
        }
        else {
            status = khttp::GetAsync(session, url, LiteralLength(url), &op);
        }
        if (!NT_SUCCESS(status)) {
            CaptureStatus(result, status, 0, 0);
            return status;
        }

        return CompleteHttpAsync(sampleName, op, result);
    }

    NTSTATUS RunPreparedAsync(
        khttp::Session* session,
        const char* sampleName,
        AsyncSendVariant variant,
        HighLevelApiSampleResult& result) noexcept
    {
        khttp::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            khttp::Method::Post,
            HttpPostUrl,
            nullptr,
            DefaultSampleAddressFamily,
            khttp::ConnPolicy::NoPool,
            &request);
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetJsonBody(request, JsonBody, LiteralLength(JsonBody));
        }

        CallbackStats stats = {};
        khttp::SendOptions options = khttp::DefaultSendOptions();
        options.MaxResponseBytes = 64 * 1024;
        options.Flags = khttp::SendFlagAggregateWithCallbacks;
        options.OnHeader = HeaderCallback;
        options.OnBody = BodyCallback;
        options.CallbackContext = &stats;
        options.OnComplete = CompletionCallback;
        options.CompletionContext = &stats;

        khttp::AsyncOp* op = nullptr;
        if (NT_SUCCESS(status)) {
            LogHttpRequest(
                sampleName,
                AsyncSendVariantName(variant),
                khttp::Method::Post,
                HttpPostUrl,
                "JSON",
                LiteralLength(JsonBody),
                nullptr,
                DefaultSampleAddressFamily,
                khttp::ConnPolicy::NoPool);

            if (variant == AsyncSendVariant::SendAsync) {
                status = khttp::SendAsync(session, request, &op);
            }
            else if (variant == AsyncSendVariant::SendAsyncWithOptions) {
                status = khttp::SendAsync(session, request, &options, &op);
            }
            else {
                status = khttp::SendAsyncEx(session, request, &options, &op);
            }
        }

        if (NT_SUCCESS(status)) {
            status = CompleteHttpAsync(sampleName, op, result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        if (variant == AsyncSendVariant::SendAsync) {
            KHTTP_SAMPLE_LOG(
                "[HTTP异步] 示例=%s 完成回调=未配置\r\n",
                sampleName);
        }
        else {
            KHTTP_SAMPLE_LOG(
                "[HTTP异步] 示例=%s 完成回调次数=%Iu 完成回调状态=0x%08X\r\n",
                sampleName,
                stats.CompletionCount,
                static_cast<ULONG>(stats.CompletionStatus));
        }

        khttp::RequestRelease(request);
        return status;
    }

    NTSTATUS RunAsyncCancelSample(khttp::Session* session, HighLevelApiSampleResult& result) noexcept
    {
        KHTTP_SAMPLE_LOG("[HTTP异步] 示例=AsyncCancel 创建一个异步 GET 后立即请求取消\r\n");
        khttp::AsyncOp* op = nullptr;
        NTSTATUS status = khttp::GetAsync(session, HttpGetUrl, LiteralLength(HttpGetUrl), &op);
        if (NT_SUCCESS(status)) {
            status = khttp::AsyncCancel(op);
        }

        const bool canceled = khttp::AsyncIsCanceled(op);
        KHTTP_SAMPLE_LOG(
            "[HTTP异步] 示例=AsyncCancel 取消状态=0x%08X 已取消=%s 当前状态=0x%08X\r\n",
            static_cast<ULONG>(status),
            BoolName(canceled),
            static_cast<ULONG>(khttp::AsyncGetStatus(op)));

        CaptureStatus(result, status, canceled ? 1 : 0, 0);
        khttp::AsyncRelease(op);
        return status;
    }

    NTSTATUS RunHttpsRequestBuilder(
        khttp::Session* session,
        HighLevelApiSampleResult& result,
        const khttp::TlsConfig& tlsConfig) noexcept
    {
        khttp::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            khttp::Method::Post,
            HttpsBuilderUrl,
            &tlsConfig,
            DefaultSampleAddressFamily,
            khttp::ConnPolicy::ReuseOrCreate,
            &request);
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetHeader(
                request,
                "X-KernelHttp-Sample",
                LiteralLength("X-KernelHttp-Sample"),
                "request-builder",
                LiteralLength("request-builder"));
        }
        if (NT_SUCCESS(status)) {
            status = khttp::RequestSetJsonBody(request, JsonBody, LiteralLength(JsonBody));
        }
        if (NT_SUCCESS(status)) {
            status = SendPreparedRequest(
                session,
                "HTTPS Request Builder",
                khttp::Method::Post,
                HttpsBuilderUrl,
                "JSON",
                LiteralLength(JsonBody),
                &tlsConfig,
                DefaultSampleAddressFamily,
                khttp::ConnPolicy::ReuseOrCreate,
                request,
                nullptr,
                SendVariant::Send,
                result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        khttp::RequestRelease(request);
        return status;
    }

    khttp::WsConnectConfig MakeWsConfig(
        const char* url,
        const khttp::TlsConfig* tlsConfig,
        khttp::AddressFamily family) noexcept
    {
        khttp::WsConnectConfig config = khttp::DefaultWsConnectConfig();
        config.Url = url;
        config.UrlLength = LiteralLength(url);
        config.Family = family;
        config.MaxMessageBytes = 64 * 1024;
        config.AutoReplyPing = true;
        if (tlsConfig != nullptr) {
            config.Tls = *tlsConfig;
        }
        return config;
    }

    void LogWebSocketRequest(
        const char* sampleName,
        WsConnectVariant connectVariant,
        const khttp::WsConnectConfig& config,
        WsSendVariant sendVariant,
        SIZE_T sendLength) noexcept
    {
        KHTTP_SAMPLE_LOG(
            "[WebSocket请求] 示例=%s 入口=%s URL=%s 子协议=%.*s 发送=%s 发送长度=%Iu 地址族=%s 证书策略=%s 自动Ping响应=%s 最大消息=%Iu\r\n",
            sampleName,
            WsConnectVariantName(connectVariant),
            config.Url != nullptr ? config.Url : "",
            PrintLength(config.SubprotocolLength),
            config.Subprotocol != nullptr ? config.Subprotocol : "",
            WsSendVariantName(sendVariant),
            sendLength,
            AddressFamilyName(config.Family),
            CertPolicyName(config.Tls.Certificate),
            BoolName(config.AutoReplyPing),
            config.MaxMessageBytes);
    }

    void LogWebSocketResponse(
        const char* sampleName,
        NTSTATUS status,
        const khttp::WsMessage* message,
        NTSTATUS closeStatus) noexcept
    {
        KHTTP_SAMPLE_LOG(
            "[WebSocket响应] 示例=%s NTSTATUS=0x%08X 消息类型=%s 消息长度=%Iu 是否最后分片=%s 关闭状态=0x%08X\r\n",
            sampleName,
            static_cast<ULONG>(status),
            message != nullptr ? WsMsgTypeName(message->Type) : "无消息",
            message != nullptr ? message->DataLength : 0,
            message != nullptr ? BoolName(message->FinalFragment) : "否",
            static_cast<ULONG>(closeStatus));
        if (message != nullptr && message->DataLength != 0) {
            LogBytePayload("[WebSocket响应体]", sampleName, message->Data, message->DataLength);
        }
    }

    NTSTATUS ConnectWebSocket(
        khttp::Session* session,
        WsConnectVariant variant,
        const khttp::WsConnectConfig& config,
        khttp::WebSocket** websocket) noexcept
    {
        if (variant == WsConnectVariant::Url) {
            return khttp::WsConnect(session, config.Url, config.UrlLength, websocket);
        }
        if (variant == WsConnectVariant::Config) {
            return khttp::WsConnect(session, &config, websocket);
        }
        return khttp::WsConnectEx(session, &config, websocket);
    }

    NTSTATUS SendWebSocketMessage(
        khttp::WebSocket* websocket,
        WsSendVariant variant) noexcept
    {
        khttp::WsSendOptions sendOptions = {};
        sendOptions.FinalFragment = true;
        switch (variant) {
        case WsSendVariant::Text:
            return khttp::WsSendText(websocket, WsHelloMessage, LiteralLength(WsHelloMessage));
        case WsSendVariant::TextEx:
            return khttp::WsSendTextEx(websocket, WsHelloMessage, LiteralLength(WsHelloMessage), &sendOptions);
        case WsSendVariant::Binary:
            return khttp::WsSendBinary(websocket, WsBinaryMessage, sizeof(WsBinaryMessage));
        case WsSendVariant::BinaryEx:
            return khttp::WsSendBinaryEx(websocket, WsBinaryMessage, sizeof(WsBinaryMessage), &sendOptions);
        case WsSendVariant::None:
        default:
            return STATUS_SUCCESS;
        }
    }

    SIZE_T WebSocketSendLength(WsSendVariant variant) noexcept
    {
        return variant == WsSendVariant::Binary || variant == WsSendVariant::BinaryEx ?
            sizeof(WsBinaryMessage) :
            (variant == WsSendVariant::None ? 0 : LiteralLength(WsHelloMessage));
    }

    khttp::WsMsgType ExpectedWebSocketEchoType(WsSendVariant variant) noexcept
    {
        return variant == WsSendVariant::Binary || variant == WsSendVariant::BinaryEx ?
            khttp::WsMsgType::Binary :
            khttp::WsMsgType::Text;
    }

    const UCHAR* ExpectedWebSocketEchoPayload(WsSendVariant variant, SIZE_T* dataLength) noexcept
    {
        if (dataLength != nullptr) {
            *dataLength = WebSocketSendLength(variant);
        }

        return variant == WsSendVariant::Binary || variant == WsSendVariant::BinaryEx ?
            WsBinaryMessage :
            reinterpret_cast<const UCHAR*>(WsHelloMessage);
    }

    NTSTATUS ValidateWebSocketEcho(
        const char* sampleName,
        WsSendVariant variant,
        const khttp::WsMessage& message) noexcept
    {
        if (variant == WsSendVariant::None) {
            return STATUS_SUCCESS;
        }

        SIZE_T expectedLength = 0;
        const UCHAR* expected = ExpectedWebSocketEchoPayload(variant, &expectedLength);
        const khttp::WsMsgType expectedType = ExpectedWebSocketEchoType(variant);
        const bool payloadMatches =
            expectedLength == 0 ||
            (message.DataLength == expectedLength &&
                message.Data != nullptr &&
                expected != nullptr &&
                RtlCompareMemory(message.Data, expected, expectedLength) == expectedLength);

        if (message.Type == expectedType &&
            message.FinalFragment &&
            message.DataLength == expectedLength &&
            payloadMatches) {
            return STATUS_SUCCESS;
        }

        KHTTP_SAMPLE_LOG(
            "[WebSocket响应] 示例=%s Echo校验失败 期望类型=%s 实际类型=%s 期望长度=%Iu 实际长度=%Iu 最后分片=%s\r\n",
            sampleName,
            WsMsgTypeName(expectedType),
            WsMsgTypeName(message.Type),
            expectedLength,
            message.DataLength,
            BoolName(message.FinalFragment));
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    NTSTATUS RunWebSocketSample(
        khttp::Session* session,
        const char* sampleName,
        WsConnectVariant connectVariant,
        WsSendVariant sendVariant,
        bool receiveWithCallback,
        const char* url,
        const khttp::TlsConfig* tlsConfig,
        HighLevelApiSampleResult& result) noexcept
    {
        khttp::WsConnectConfig config = MakeWsConfig(url, tlsConfig, DefaultSampleAddressFamily);
        if (connectVariant == WsConnectVariant::Url) {
            config = MakeWsConfig(url, nullptr, khttp::AddressFamily::Any);
        }

        LogWebSocketRequest(
            sampleName,
            connectVariant,
            config,
            sendVariant,
            WebSocketSendLength(sendVariant));

        khttp::WebSocket* websocket = nullptr;
        NTSTATUS status = ConnectWebSocket(session, connectVariant, config, &websocket);
        khttp::WsMessage message = {};
        CallbackStats callbackStats = {};

        if (NT_SUCCESS(status) && sendVariant != WsSendVariant::None) {
            status = SendWebSocketMessage(websocket, sendVariant);
        }
        const bool expectEcho = sendVariant != WsSendVariant::None;
        if (NT_SUCCESS(status) && expectEcho) {
            if (receiveWithCallback) {
                khttp::WsReceiveOptions receiveOptions = {};
                receiveOptions.MaxMessageBytes = 64 * 1024;
                receiveOptions.AutoAllocate = true;
                receiveOptions.OnMessage = WebSocketMessageCallback;
                receiveOptions.CallbackContext = &callbackStats;
                status = khttp::WsReceiveEx(websocket, &receiveOptions, &message);
            }
            else {
                status = khttp::WsReceive(websocket, &message);
            }
        }
        if (NT_SUCCESS(status) && expectEcho) {
            status = ValidateWebSocketEcho(sampleName, sendVariant, message);
        }

        result.Status = status;
        result.StatusCode = NT_SUCCESS(status) ? 1 : 0;
        result.BodyLength = expectEcho ?
            (receiveWithCallback ? callbackStats.WsMessageBytes : message.DataLength) :
            WebSocketSendLength(sendVariant);

        khttp::WsMessage logMessage = message;
        HeapArray<UCHAR> logMessageData;
        if (message.DataLength != 0 && message.Data != nullptr) {
            const NTSTATUS copyStatus = logMessageData.Allocate(message.DataLength);
            if (NT_SUCCESS(copyStatus)) {
                RtlCopyMemory(logMessageData.Get(), message.Data, message.DataLength);
                logMessage.Data = logMessageData.Get();
            }
            else {
                KHTTP_SAMPLE_LOG(
                    "[WebSocket响应] 示例=%s 响应体日志复制失败 NTSTATUS=0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(copyStatus));
                logMessage.Data = nullptr;
            }
        }

        NTSTATUS closeStatus = STATUS_SUCCESS;
        if (websocket != nullptr) {
            closeStatus = khttp::WsClose(websocket);
            if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
                result.Status = closeStatus;
                status = closeStatus;
            }
        }

        LogWebSocketResponse(sampleName, status, &logMessage, closeStatus);
        return status;
    }

    NTSTATUS RunWebSocketAsyncSample(
        khttp::Session* session,
        const char* sampleName,
        WsConnectVariant connectVariant,
        const char* url,
        const khttp::TlsConfig* tlsConfig,
        HighLevelApiSampleResult& result) noexcept
    {
        khttp::WsConnectConfig config = MakeWsConfig(url, tlsConfig, DefaultSampleAddressFamily);
        if (connectVariant == WsConnectVariant::Url) {
            config = MakeWsConfig(url, nullptr, khttp::AddressFamily::Any);
        }

        LogWebSocketRequest(
            sampleName,
            connectVariant,
            config,
            WsSendVariant::None,
            0);

        khttp::AsyncOp* op = nullptr;
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        if (connectVariant == WsConnectVariant::Url) {
            status = khttp::WsConnectAsync(session, config.Url, config.UrlLength, &op);
        }
        else if (connectVariant == WsConnectVariant::Config) {
            status = khttp::WsConnectAsync(session, &config, &op);
        }
        else {
            status = khttp::WsConnectAsyncEx(session, &config, &op);
        }

        khttp::WebSocket* websocket = nullptr;
        if (NT_SUCCESS(status)) {
            KHTTP_SAMPLE_LOG(
                "[WebSocket异步] 示例=%s 等待前：状态=0x%08X 已完成=%s\r\n",
                sampleName,
                static_cast<ULONG>(khttp::AsyncGetStatus(op)),
                BoolName(khttp::AsyncIsCompleted(op)));
            status = khttp::AsyncWait(op, AsyncWaitTimeoutMs);
        }
        if (NT_SUCCESS(status)) {
            status = khttp::AsyncGetWebSocket(op, &websocket);
        }

        NTSTATUS closeStatus = STATUS_SUCCESS;
        if (websocket != nullptr) {
            closeStatus = khttp::WsClose(websocket);
            if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
                status = closeStatus;
            }
        }

        result.Status = status;
        result.StatusCode = NT_SUCCESS(status) ? 1 : 0;
        result.BodyLength = 0;
        LogWebSocketResponse(sampleName, status, nullptr, closeStatus);
        khttp::AsyncRelease(op);
        return status;
    }

    NTSTATUS RunSessionCreateSample(
        net::WskClient* wskClient,
        const char* sampleName,
        const khttp::SessionConfig* config,
        HighLevelApiSampleResult& result,
        khttp::Session** keepSession) noexcept
    {
        if (keepSession != nullptr) {
            *keepSession = nullptr;
        }
        if (wskClient == nullptr) {
            CaptureStatus(result, STATUS_INVALID_PARAMETER, 0, 0);
            return STATUS_INVALID_PARAMETER;
        }

        if (config != nullptr) {
            LogSessionConfig(sampleName, *config);
        }
        else {
            khttp::SessionConfig defaultConfig = khttp::DefaultSessionConfig();
            LogSessionConfig(sampleName, defaultConfig);
        }

        khttp::Session* session = nullptr;
        NTSTATUS status = khttp::SessionCreate(wskClient, config, &session);
        CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, config != nullptr ? config->MaxResponseBytes : 0);
        KHTTP_SAMPLE_LOG(
            "[会话示例] %s：SessionCreate 状态=0x%08X 会话=%s\r\n",
            sampleName,
            static_cast<ULONG>(status),
            session != nullptr ? "已创建" : "未创建");

        if (keepSession != nullptr && NT_SUCCESS(status)) {
            *keepSession = session;
        }
        else {
            khttp::SessionClose(session);
            KHTTP_SAMPLE_LOG("[会话示例] %s：SessionClose 已调用\r\n", sampleName);
        }
        return status;
    }

    NTSTATUS RunHighLevelApiSamplesOnSession(
        khttp::Session* session,
        HighLevelApiSampleResults* results) noexcept
    {
        if (session == nullptr || results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS aggregate = STATUS_SUCCESS;
        NTSTATUS status = STATUS_SUCCESS;

        const UCHAR* jsonBytes = reinterpret_cast<const UCHAR*>(JsonBody);
        const SIZE_T jsonLen = LiteralLength(JsonBody);

        ExternalTrustStore trustStore = {};
        status = InitializeExternalTrustStore(trustStore);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        khttp::TlsConfig ngHttp2Tls = khttp::DefaultTlsConfig();
        ngHttp2Tls.Store = &trustStore.Store;

        khttp::TlsConfig noVerifyTls = khttp::DefaultTlsConfig();
        noVerifyTls.Certificate = khttp::CertPolicy::NoVerify;

        khttp::TlsConfig ngHttp2Http11Tls = ngHttp2Tls;
        ngHttp2Http11Tls.Alpn = AlpnHttp11;
        ngHttp2Http11Tls.AlpnLength = LiteralLength(AlpnHttp11);

        khttp::TlsConfig ngHttp2Http2Tls = ngHttp2Tls;
        ngHttp2Http2Tls.Alpn = AlpnH2;
        ngHttp2Http2Tls.AlpnLength = LiteralLength(AlpnH2);

        khttp::TlsConfig webSocketTls = khttp::DefaultTlsConfig();
        webSocketTls.Store = &trustStore.Store;
        webSocketTls.MaxVersion = khttp::TlsVersion::Tls12;

        // HTTP 快捷函数示例：这些入口直接创建并发送请求。
        status = RunShortcutHttp(session, "HTTP GET 快捷函数", khttp::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpShortcutGet);
        MergeSampleStatus(aggregate, status);
        status = RunShortcutHttp(session, "HTTP POST 快捷函数", khttp::Method::Post, HttpPostUrl, jsonBytes, jsonLen, "原始字节", results->HttpShortcutPost);
        MergeSampleStatus(aggregate, status);
        status = RunShortcutHttp(session, "HTTP PUT 快捷函数", khttp::Method::Put, HttpPutUrl, jsonBytes, jsonLen, "原始字节", results->HttpShortcutPut);
        MergeSampleStatus(aggregate, status);
        status = RunShortcutHttp(session, "HTTP PATCH 快捷函数", khttp::Method::Patch, HttpPatchUrl, jsonBytes, jsonLen, "原始字节", results->HttpShortcutPatch);
        MergeSampleStatus(aggregate, status);
        status = RunShortcutHttp(session, "HTTP DELETE 快捷函数", khttp::Method::Delete, HttpDeleteUrl, nullptr, 0, "无", results->HttpShortcutDelete);
        MergeSampleStatus(aggregate, status);
        status = RunShortcutHttp(session, "HTTP HEAD 快捷函数", khttp::Method::Head, HttpHeadUrl, nullptr, 0, "无", results->HttpShortcutHead);
        MergeSampleStatus(aggregate, status);
        status = RunShortcutHttp(session, "HTTP OPTIONS 快捷函数", khttp::Method::Options, HttpOptionsUrl, nullptr, 0, "无", results->HttpShortcutOptions);
        MergeSampleStatus(aggregate, status);

        // Request Builder 示例：这些入口展示 URL、方法、Header、Body、TLS、连接策略和地址族配置。
        status = RunSimpleSync(session, "HTTP GET 构造请求", khttp::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpGet);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP POST 原始请求体", khttp::Method::Post, HttpPostUrl, jsonBytes, jsonLen, "原始字节", results->HttpPost);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP PUT 原始请求体", khttp::Method::Put, HttpPutUrl, jsonBytes, jsonLen, "原始字节", results->HttpPut);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP PATCH 原始请求体", khttp::Method::Patch, HttpPatchUrl, jsonBytes, jsonLen, "原始字节", results->HttpPatch);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP DELETE", khttp::Method::Delete, HttpDeleteUrl, nullptr, 0, "无", results->HttpDelete);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP HEAD", khttp::Method::Head, HttpHeadUrl, nullptr, 0, "无", results->HttpHead);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP OPTIONS", khttp::Method::Options, HttpOptionsUrl, nullptr, 0, "无", results->HttpOptions);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP GET IPv4 地址族", khttp::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpGetIpv4, nullptr, khttp::ConnPolicy::ReuseOrCreate, khttp::AddressFamily::Ipv4);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP GET IPv6 地址族", khttp::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpGetIpv6, nullptr, khttp::ConnPolicy::ReuseOrCreate, khttp::AddressFamily::Ipv6);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTP GET Any 地址族", khttp::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpGetAny, nullptr, khttp::ConnPolicy::ReuseOrCreate, khttp::AddressFamily::Any);
        MergeSampleStatus(aggregate, status);

        status = RunSendWithOptions(session, results->HttpSendWithOptions, false);
        MergeSampleStatus(aggregate, status);
        status = RunSendWithOptions(session, results->HttpSendEx, true);
        MergeSampleStatus(aggregate, status);
        status = RunResponseHeaderSample(session, results->HttpResponseHeader);
        MergeSampleStatus(aggregate, status);

        status = RunRequestBodySample(session, "HTTP 文本请求体", "文本", LiteralLength(TextBody), results->HttpTextBody, SetTextBody);
        MergeSampleStatus(aggregate, status);
        status = RunRequestBodySample(session, "HTTP JSON 请求体", "JSON", LiteralLength(JsonBody), results->HttpJsonBody, SetJsonBody);
        MergeSampleStatus(aggregate, status);
        status = RunRequestBodySample(session, "HTTP Raw 请求体", "Raw", sizeof(RawBody), results->HttpRawBody, SetRawBody);
        MergeSampleStatus(aggregate, status);
        status = RunRequestBodySample(session, "HTTP 表单请求体", "表单", LiteralLength("source=kernel-http&kind=form"), results->HttpFormBody, SetFormBody);
        MergeSampleStatus(aggregate, status);
        status = RunRequestBodySample(session, "HTTP Multipart 请求体", "Multipart", LiteralLength("field+file-bytes"), results->HttpMultipartBody, SetMultipartBody);
        MergeSampleStatus(aggregate, status);
        status = RunRequestBodySample(session, "HTTP 文件请求体", "文件", 0, results->HttpFileBody, SetFileBody);
        MergeSampleStatus(aggregate, status);
        status = RunRequestBodySample(session, "HTTP 清空请求体", "清空后的空请求体", 0, results->HttpClearBody, SetClearBody);
        MergeSampleStatus(aggregate, status);

        status = RunSimpleAsync(session, "HTTP GET 异步快捷函数", khttp::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpGetAsync);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleAsync(session, "HTTP POST 异步快捷函数", khttp::Method::Post, HttpPostUrl, jsonBytes, jsonLen, "原始字节", results->HttpPostAsync);
        MergeSampleStatus(aggregate, status);
        status = RunPreparedAsync(session, "HTTP SendAsync", AsyncSendVariant::SendAsync, results->HttpSendAsync);
        MergeSampleStatus(aggregate, status);
        status = RunPreparedAsync(session, "HTTP SendAsync 带选项", AsyncSendVariant::SendAsyncWithOptions, results->HttpSendAsyncWithOptions);
        MergeSampleStatus(aggregate, status);
        status = RunPreparedAsync(session, "HTTP SendAsyncEx", AsyncSendVariant::SendAsyncEx, results->HttpSendAsyncEx);
        MergeSampleStatus(aggregate, status);
        status = RunAsyncCancelSample(session, results->HttpAsyncCancel);
        MergeSampleStatus(aggregate, status);

        status = RunSimpleSync(session, "HTTPS GET 校验证书", khttp::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsVerifyGet, &ngHttp2Tls);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTPS GET 不校验证书", khttp::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsNoVerifyGet, &noVerifyTls);
        MergeSampleStatus(aggregate, status);
        status = RunHttpsRequestBuilder(session, results->HttpsRequestBuilder, ngHttp2Tls);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTPS GET HTTP/1.1 ALPN", khttp::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsHttp11, &ngHttp2Http11Tls);
        MergeSampleStatus(aggregate, status);
        status = RunSimpleSync(session, "HTTPS GET HTTP/2 ALPN", khttp::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsHttp2, &ngHttp2Http2Tls);
        MergeSampleStatus(aggregate, status);

        status = RunWebSocketSample(session, "WebSocket Echo", WsConnectVariant::Config, WsSendVariant::Text, false, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketEcho);
        MergeSampleStatus(aggregate, status);
        results->WebSocketConfigConnect = results->WebSocketEcho;
        status = RunWebSocketSample(session, "WebSocket URL 直连", WsConnectVariant::Url, WsSendVariant::Text, false, WebSocketSecureEchoUrl, nullptr, results->WebSocketUrlConnect);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketSample(session, "WebSocket ConnectEx", WsConnectVariant::Ex, WsSendVariant::Text, false, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketConnectEx);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketSample(session, "WebSocket 文本发送 Ex", WsConnectVariant::Ex, WsSendVariant::TextEx, false, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketTextEx);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketSample(session, "WebSocket 二进制发送", WsConnectVariant::Ex, WsSendVariant::Binary, false, WebSocketBinaryEchoUrl, &webSocketTls, results->WebSocketBinary);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketSample(session, "WebSocket 二进制发送 Ex", WsConnectVariant::Ex, WsSendVariant::BinaryEx, false, WebSocketBinaryEchoUrl, &webSocketTls, results->WebSocketBinaryEx);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketSample(session, "WebSocket 接收 Ex 回调", WsConnectVariant::Ex, WsSendVariant::Text, true, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketReceiveEx);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketAsyncSample(session, "WebSocket 异步 URL 直连", WsConnectVariant::Url, WebSocketSecureEchoUrl, nullptr, results->WebSocketConnectAsync);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketAsyncSample(session, "WebSocket 异步配置连接", WsConnectVariant::Config, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketConfigConnectAsync);
        MergeSampleStatus(aggregate, status);
        status = RunWebSocketAsyncSample(session, "WebSocket 异步 ConnectEx", WsConnectVariant::Ex, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketConnectAsyncEx);
        MergeSampleStatus(aggregate, status);

        ResetExternalTrustStore(trustStore);
        return aggregate;
    }
}

NTSTATUS RunHighLevelApiSamples(khttp::Session* session, HighLevelApiSampleResults* results) noexcept
{
    if (session == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};
    khttp::SessionConfig defaultConfig = khttp::DefaultSessionConfig();
    LogSessionConfig("已有 Session 使用默认配置说明", defaultConfig);
    CaptureStatus(results->SessionDefaultConfig, STATUS_SUCCESS, 1, defaultConfig.MaxResponseBytes);

    khttp::SessionConfig customConfig = khttp::DefaultSessionConfig();
    customConfig.MaxResponseBytes = 2 * 1024 * 1024;
    customConfig.PoolCapacity = 4;
    customConfig.MaxConnsPerHost = 1;
    customConfig.IdleTimeoutMs = 15000;
    customConfig.Tls.HandshakeTimeoutMs = 90000;
    LogSessionConfig("自定义 SessionConfig 写法说明", customConfig);
    CaptureStatus(results->SessionCustomConfig, STATUS_SUCCESS, 1, customConfig.MaxResponseBytes);

    return RunHighLevelApiSamplesOnSession(session, results);
}

NTSTATUS RunHighLevelApiSamples(net::WskClient* wskClient, HighLevelApiSampleResults* results) noexcept
{
    if (wskClient == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};
    NTSTATUS aggregate = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    ExternalTrustStore trustStore = {};
    status = InitializeExternalTrustStore(trustStore);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    khttp::SessionConfig defaultConfig = khttp::DefaultSessionConfig();
    defaultConfig.Tls.Store = &trustStore.Store;

    khttp::Session* session = nullptr;
    status = RunSessionCreateSample(
        wskClient,
        "默认 SessionCreate/SessionClose",
        &defaultConfig,
        results->SessionDefaultConfig,
        &session);
    MergeSampleStatus(aggregate, status);

    if (NT_SUCCESS(status)) {
        status = RunHighLevelApiSamplesOnSession(session, results);
        MergeSampleStatus(aggregate, status);
        khttp::SessionClose(session);
        KHTTP_SAMPLE_LOG("[会话示例] 默认会话请求矩阵结束，SessionClose 已调用\r\n");
    }

    khttp::SessionConfig customConfig = khttp::DefaultSessionConfig();
    customConfig.MaxResponseBytes = 2 * 1024 * 1024;
    customConfig.PoolCapacity = 4;
    customConfig.MaxConnsPerHost = 1;
    customConfig.IdleTimeoutMs = 15000;
    customConfig.Tls.HandshakeTimeoutMs = 90000;
    customConfig.Tls.Store = &trustStore.Store;
    status = RunSessionCreateSample(
        wskClient,
        "自定义 SessionConfig",
        &customConfig,
        results->SessionCustomConfig,
        nullptr);
    MergeSampleStatus(aggregate, status);

    ResetExternalTrustStore(trustStore);
    return aggregate;
}
}
}

#undef KHTTP_SAMPLE_LOG
