#include "samples/HighLevelApiSamples.h"

#include <wknet/http/AsyncOp.h>
#include <wknet/http/Http.h>
#include <wknet/http/HttpAsync.h>
#include <wknet/http/Request.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknet/websocket/WebSocket.h>
#include <wknettest/SampleStatus.h>
#include "samples/ExternalTrustStore.h"
#include "WknetTestLog.h"

#ifndef STATUS_CONNECTION_REFUSED
#define STATUS_CONNECTION_REFUSED ((NTSTATUS)0xC0000236L)
#endif

#ifndef STATUS_NETWORK_UNREACHABLE
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xC000023CL)
#endif

#ifndef STATUS_HOST_UNREACHABLE
#define STATUS_HOST_UNREACHABLE ((NTSTATUS)0xC000023DL)
#endif

#ifndef STATUS_PROTOCOL_UNREACHABLE
#define STATUS_PROTOCOL_UNREACHABLE ((NTSTATUS)0xC000023EL)
#endif

#ifndef STATUS_NO_MATCH
#define STATUS_NO_MATCH ((NTSTATUS)0xC0000272L)
#endif

namespace wknet
{
namespace samples
{
namespace
{
    constexpr ULONG AsyncWaitTimeoutMs = 60000;
    constexpr ULONG AsyncWaitForeverMs = 0xffffffffUL;

    constexpr const char* HttpGetUrl = "http://httpbun.com/get";
    constexpr const char* HttpAddressFamilyGetUrl = "http://nghttp2.org/httpbin/get";
    constexpr const char* HttpPostUrl = "http://httpbun.com/post";
    constexpr const char* HttpPutUrl = "http://httpbun.com/put";
    constexpr const char* HttpPatchUrl = "http://httpbun.com/patch";
    constexpr const char* HttpDeleteUrl = "http://httpbun.com/delete";
    constexpr const char* HttpHeadUrl = "http://nghttp2.org/httpbin/get";
    constexpr const char* HttpOptionsUrl = "http://nghttp2.org/httpbin/";
    constexpr const char* HttpsGetUrl = "https://httpbin.dev/get";
    constexpr const char* HttpsBuilderUrl = "https://httpbin.dev/anything";
    constexpr const char* WebSocketSecureEchoUrl = "wss://websocket-echo.com";
    constexpr const char* WebSocketBinaryEchoUrl = "wss://websocket-echo.com";
    constexpr const char* AlpnHttp11 = "http/1.1";
    constexpr const char* AlpnH2 = "h2";

#if defined(WKNET_USER_MODE_TEST)
    constexpr const char* FileBodyPath = "tests/testdata/request_body_file.txt";
#else
    constexpr const char* FileBodyPath = "\\SystemRoot\\System32\\drivers\\etc\\hosts";
#endif

    constexpr const char* JsonBody = "{\"hello\":\"world\"}";
    constexpr const char* TextBody = "hello from high-level wknet";
    constexpr UCHAR RawBody[] = { 0x6B, 0x68, 0x74, 0x74, 0x70 };
    constexpr const char* WsHelloMessage = "hello-from-wknet";
    constexpr UCHAR WsBinaryMessage[] = { 0x01, 0x02, 0x03, 0x04 };
    constexpr SIZE_T TextLogChunkBytes = 256;
    constexpr SIZE_T MaxLoggedTextBytes = 8 * 1024;
    constexpr ULONG MaxWebSocketEchoReceiveFrames = 4;
    constexpr wknet::http::AddressFamily DefaultHttpSampleAddressFamily = wknet::http::AddressFamily::Any;
    constexpr wknet::http::AddressFamily DefaultWebSocketSampleAddressFamily = wknet::http::AddressFamily::Any;

    enum class SendVariant : ULONG
    {
        Send = 0,
        SendWithOptions = 1,
        SendEx = 2
    };

    enum class AsyncSendVariant : ULONG
    {
        AsyncSend = 0,
        AsyncSendWithOptions = 1,
        AsyncSendEx = 2
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
        wknet::websocket::MsgType WsMessageType = wknet::websocket::MsgType::Binary;
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

    SIZE_T ClampLoggedBytes(SIZE_T dataLength) noexcept
    {
        return MinSize(dataLength, MaxLoggedTextBytes);
    }

    void LogBytePayload(
        const char* prefix,
        const char* sampleName,
        const UCHAR* data,
        SIZE_T dataLength) noexcept
    {
        if (data == nullptr || dataLength == 0) {
            WKNET_SAMPLE_LOG(
                "%s 示例=%s 内容长度=0 原始响应体如下\r\n",
                prefix,
                sampleName);
            return;
        }

        WKNET_SAMPLE_LOG(
            "%s 示例=%s 内容长度=%Iu 原始响应体如下\r\n",
            prefix,
            sampleName,
            dataLength);
        const char* text = reinterpret_cast<const char*>(data);
        SIZE_T offset = 0;
        while (offset < dataLength) {
            constexpr SIZE_T MaxPrintLength = 0x7fffffff;
            const SIZE_T chunkLength = MinSize(dataLength - offset, MaxPrintLength);
            wknet::testlog::WriteRaw(text + offset, chunkLength);
            offset += chunkLength;
        }
    }

    void LogResponseHeaderValue(
        const char* sampleName,
        SIZE_T index,
        const char* headerName,
        SIZE_T headerNameLength,
        const char* headerValue,
        SIZE_T headerValueLength) noexcept
    {
        const char* safeSampleName = sampleName != nullptr ? sampleName : "";
        const char* safeHeaderName = headerName != nullptr ? headerName : "";
        if (headerValue == nullptr || headerValueLength == 0) {
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 响应头[%Iu] %.*s: <空>\r\n",
                safeSampleName,
                index,
                PrintLength(headerNameLength),
                safeHeaderName);
            return;
        }

        const SIZE_T loggedBytes = ClampLoggedBytes(headerValueLength);
        const bool truncated = loggedBytes < headerValueLength;
        if (!truncated && headerValueLength <= TextLogChunkBytes) {
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 响应头[%Iu] %.*s: %.*s\r\n",
                safeSampleName,
                index,
                PrintLength(headerNameLength),
                safeHeaderName,
                PrintLength(headerValueLength),
                headerValue);
            return;
        }

        WKNET_SAMPLE_LOG(
            "[HTTP响应] 示例=%s 响应头[%Iu] %.*s: 值长度=%Iu 日志分块输出=%Iu%s\r\n",
            safeSampleName,
            index,
            PrintLength(headerNameLength),
            safeHeaderName,
            headerValueLength,
            loggedBytes,
            truncated ? " <truncated>" : "");
        for (SIZE_T offset = 0; offset < loggedBytes; offset += TextLogChunkBytes) {
            const SIZE_T chunkLength = MinSize(loggedBytes - offset, TextLogChunkBytes);
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 响应头[%Iu] 值偏移=%Iu 长度=%Iu 内容=%.*s\r\n",
                safeSampleName,
                index,
                offset,
                chunkLength,
                PrintLength(chunkLength),
                headerValue + offset);
        }
        if (truncated) {
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 响应头[%Iu] 日志展示截断 已输出=%Iu 总长度=%Iu\r\n",
                safeSampleName,
                index,
                loggedBytes,
                headerValueLength);
        }
    }

    void LogCallbackHeaderValue(
        const char* headerName,
        SIZE_T headerNameLength,
        const char* headerValue,
        SIZE_T headerValueLength) noexcept
    {
        const char* safeHeaderName = headerName != nullptr ? headerName : "";
        if (headerValue == nullptr || headerValueLength == 0) {
            WKNET_SAMPLE_LOG(
                "[HTTP回调] 收到响应头 %.*s: <空>\r\n",
                PrintLength(headerNameLength),
                safeHeaderName);
            return;
        }

        const SIZE_T loggedBytes = ClampLoggedBytes(headerValueLength);
        const bool truncated = loggedBytes < headerValueLength;
        if (!truncated && headerValueLength <= TextLogChunkBytes) {
            WKNET_SAMPLE_LOG(
                "[HTTP回调] 收到响应头 %.*s: %.*s\r\n",
                PrintLength(headerNameLength),
                safeHeaderName,
                PrintLength(headerValueLength),
                headerValue);
            return;
        }

        WKNET_SAMPLE_LOG(
            "[HTTP回调] 收到响应头 %.*s: 值长度=%Iu 日志分块输出=%Iu%s\r\n",
            PrintLength(headerNameLength),
            safeHeaderName,
            headerValueLength,
            loggedBytes,
            truncated ? " <truncated>" : "");
        for (SIZE_T offset = 0; offset < loggedBytes; offset += TextLogChunkBytes) {
            const SIZE_T chunkLength = MinSize(loggedBytes - offset, TextLogChunkBytes);
            WKNET_SAMPLE_LOG(
                "[HTTP回调] 响应头值偏移=%Iu 长度=%Iu 内容=%.*s\r\n",
                offset,
                chunkLength,
                PrintLength(chunkLength),
                headerValue + offset);
        }
        if (truncated) {
            WKNET_SAMPLE_LOG(
                "[HTTP回调] 响应头日志展示截断 已输出=%Iu 总长度=%Iu\r\n",
                loggedBytes,
                headerValueLength);
        }
    }

    const char* MethodName(wknet::http::Method method) noexcept
    {
        switch (method) {
        case wknet::http::Method::Get: return "GET";
        case wknet::http::Method::Post: return "POST";
        case wknet::http::Method::Put: return "PUT";
        case wknet::http::Method::Patch: return "PATCH";
        case wknet::http::Method::Delete: return "DELETE";
        case wknet::http::Method::Head: return "HEAD";
        case wknet::http::Method::Options: return "OPTIONS";
        case wknet::http::Method::Connect: return "CONNECT";
        case wknet::http::Method::Trace: return "TRACE";
        default: return "UNKNOWN";
        }
    }

    const char* PoolTypeName(wknet::http::PoolType poolType) noexcept
    {
        return poolType == wknet::http::PoolType::Paged ? "分页池" : "非分页池";
    }

    const char* TlsVersionName(wknet::http::TlsVersion version) noexcept
    {
        return version == wknet::http::TlsVersion::Tls13 ? "TLS1.3" : "TLS1.2";
    }

    const char* CertPolicyName(wknet::http::CertPolicy policy) noexcept
    {
        return policy == wknet::http::CertPolicy::NoVerify ? "不校验证书" : "校验证书";
    }

    const char* AddressFamilyName(wknet::http::AddressFamily family) noexcept
    {
        switch (family) {
        case wknet::http::AddressFamily::Ipv4: return "IPv4";
        case wknet::http::AddressFamily::Ipv6: return "IPv6";
        case wknet::http::AddressFamily::Any: return "系统默认";
        default: return "未知地址族";
        }
    }

    const char* ConnPolicyName(wknet::http::ConnPolicy policy) noexcept
    {
        switch (policy) {
        case wknet::http::ConnPolicy::ReuseOrCreate: return "复用或新建连接";
        case wknet::http::ConnPolicy::ForceNew: return "强制新建连接";
        case wknet::http::ConnPolicy::NoPool: return "不进入连接池";
        default: return "未知连接策略";
        }
    }

    const char* WsMsgTypeName(wknet::websocket::MsgType type) noexcept
    {
        switch (type) {
        case wknet::websocket::MsgType::Text: return "文本";
        case wknet::websocket::MsgType::Binary: return "二进制";
        case wknet::websocket::MsgType::Close: return "关闭";
        case wknet::websocket::MsgType::Continuation: return "延续";
        case wknet::websocket::MsgType::Ping: return "Ping";
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
        case AsyncSendVariant::AsyncSend: return "AsyncSend";
        case AsyncSendVariant::AsyncSendWithOptions: return "AsyncSend(带选项)";
        case AsyncSendVariant::AsyncSendEx: return "AsyncSendEx";
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

    void MergePublicHttpSampleStatus(
        NTSTATUS& aggregate,
        NTSTATUS status,
        const char* sampleName = "HTTP 公网样例") noexcept
    {
        if (NT_SUCCESS(status)) {
            return;
        }

        if (IsPublicEndpointDiagnosticStatus(status)) {
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 公网端点环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                sampleName,
                static_cast<ULONG>(status));
            return;
        }

        MergeFatalSampleStatus(aggregate, status);
    }

    void MergeAddressFamilySampleStatus(
        NTSTATUS& aggregate,
        NTSTATUS status,
        wknet::http::AddressFamily family,
        const char* sampleName) noexcept
    {
        if (NT_SUCCESS(status)) {
            return;
        }

        if ((family == wknet::http::AddressFamily::Ipv4 || family == wknet::http::AddressFamily::Ipv6) &&
            IsPublicEndpointDiagnosticStatus(status)) {
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 公网 %s 环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                sampleName,
                AddressFamilyName(family),
                static_cast<ULONG>(status));
            return;
        }

        MergeFatalSampleStatus(aggregate, status);
    }

    void MergePublicWebSocketSampleStatus(
        NTSTATUS& aggregate,
        NTSTATUS status,
        const char* sampleName) noexcept
    {
        if (NT_SUCCESS(status)) {
            return;
        }

        if (IsPublicEndpointDiagnosticStatus(status)) {
            WKNET_SAMPLE_LOG(
                "[WebSocket响应] 示例=%s 公网连接环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                sampleName,
                static_cast<ULONG>(status));
            return;
        }

        MergeFatalSampleStatus(aggregate, status);
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

    void LogSessionConfig(const char* sampleName, const wknet::http::SessionConfig& config) noexcept
    {
        WKNET_SAMPLE_LOG(
            "[会话示例] %s：响应池=%s 请求缓冲=%Iu 最大响应=%Iu 连接池容量=%lu 每主机最大连接=%lu 空闲超时=%lums TLS=%s-%s 证书策略=%s TLS握手超时=%lums TLS1.2最大重协商=%lu\r\n",
            sampleName,
            PoolTypeName(config.ResponsePool),
            config.RequestBufferBytes,
            config.MaxResponseBytes,
            config.PoolCapacity,
            config.MaxConnsPerHost,
            config.IdleTimeoutMs,
            TlsVersionName(config.Tls.MinVersion),
            TlsVersionName(config.Tls.MaxVersion),
            CertPolicyName(config.Tls.Certificate),
            config.Tls.HandshakeTimeoutMs,
            config.Tls.MaxTls12Renegotiations);
    }

    void LogHttpRequest(
        const char* sampleName,
        const char* entryName,
        wknet::http::Method method,
        const char* url,
        const char* bodyKind,
        SIZE_T bodyLength,
        const wknet::http::TlsConfig* tlsConfig,
        wknet::http::AddressFamily family,
        wknet::http::ConnPolicy policy) noexcept
    {
        const bool isHttps = url != nullptr &&
            LiteralLength(url) >= LiteralLength("https://") &&
            RtlCompareMemory(url, "https://", LiteralLength("https://")) == LiteralLength("https://");
        const char* certPolicy = tlsConfig != nullptr ? CertPolicyName(tlsConfig->Certificate) : "使用会话默认";
        const char* alpn = isHttps ? "自动(h2,http/1.1)" : "使用会话默认";
        SIZE_T alpnLength = LiteralLength(alpn);
        if (tlsConfig != nullptr && tlsConfig->Alpn != nullptr && tlsConfig->AlpnLength != 0) {
            alpn = tlsConfig->Alpn;
            alpnLength = tlsConfig->AlpnLength;
        }
        else if (tlsConfig != nullptr && !tlsConfig->PreferHttp2) {
            alpn = "不自动";
            alpnLength = LiteralLength(alpn);
        }
        WKNET_SAMPLE_LOG(
            "[HTTP请求] 示例=%s 入口=%s 方法=%s URL=%s 请求体=%s 长度=%Iu 证书策略=%s TLS ALPN=%.*s TLS1.2最大重协商=%lu 地址族=%s 连接策略=%s\r\n",
            sampleName,
            entryName,
            MethodName(method),
            url != nullptr ? url : "",
            bodyKind != nullptr ? bodyKind : "无",
            bodyLength,
            certPolicy,
            PrintLength(alpnLength),
            alpn,
            tlsConfig != nullptr ? tlsConfig->MaxTls12Renegotiations : wknet::http::DefaultMaxTls12Renegotiations,
            AddressFamilyName(family),
            ConnPolicyName(policy));
    }

    void LogHttpResponse(
        const char* sampleName,
        NTSTATUS status,
        const wknet::http::Response* response) noexcept
    {
        const ULONG statusCode = wknet::http::ResponseStatusCode(response);
        const SIZE_T bodyLength = wknet::http::ResponseBodyLength(response);
        WKNET_SAMPLE_LOG(
            "[HTTP响应] 示例=%s NTSTATUS=0x%08X 状态码=%lu 响应体长度=%Iu\r\n",
            sampleName,
            static_cast<ULONG>(status),
            statusCode,
            bodyLength);

        if (response == nullptr) {
            return;
        }

        const SIZE_T headerCount = wknet::http::ResponseHeaderCount(response);
        WKNET_SAMPLE_LOG(
            "[HTTP响应] 示例=%s 响应头数量=%Iu\r\n",
            sampleName,
            headerCount);
        for (SIZE_T index = 0; index < headerCount; ++index) {
            const char* headerName = nullptr;
            SIZE_T headerNameLength = 0;
            const char* headerValue = nullptr;
            SIZE_T headerValueLength = 0;
            const NTSTATUS headerAtStatus = wknet::http::ResponseGetHeaderAt(
                response,
                index,
                &headerName,
                &headerNameLength,
                &headerValue,
                &headerValueLength);
            if (NT_SUCCESS(headerAtStatus)) {
                LogResponseHeaderValue(
                    sampleName,
                    index,
                    headerName,
                    headerNameLength,
                    headerValue,
                    headerValueLength);
            }
        }

        const char* headerValue = nullptr;
        SIZE_T headerValueLength = 0;
        const NTSTATUS headerStatus = wknet::http::ResponseGetHeader(
            response,
            "Content-Length",
            LiteralLength("Content-Length"),
            &headerValue,
            &headerValueLength);
        if (NT_SUCCESS(headerStatus)) {
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 响应头 Content-Length=%.*s\r\n",
                sampleName,
                PrintLength(headerValueLength),
                headerValue != nullptr ? headerValue : "");
        }
        else {
            WKNET_SAMPLE_LOG(
                "[HTTP响应] 示例=%s 未找到响应头 Content-Length，查询状态=0x%08X\r\n",
                sampleName,
                static_cast<ULONG>(headerStatus));
        }

        LogBytePayload(
            "[HTTP响应体]",
            sampleName,
            wknet::http::ResponseBody(response),
            bodyLength);
    }

    void CaptureResponse(
        const char* sampleName,
        HighLevelApiSampleResult& result,
        NTSTATUS status,
        wknet::http::Response* response) noexcept
    {
        result.Status = status;
        result.StatusCode = wknet::http::ResponseStatusCode(response);
        result.BodyLength = wknet::http::ResponseBodyLength(response);
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
        LogCallbackHeaderValue(name, nameLength, value, valueLength);
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
        WKNET_SAMPLE_LOG(
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
        WKNET_SAMPLE_LOG(
            "[异步回调] 操作完成 NTSTATUS=0x%08X\r\n",
            static_cast<ULONG>(status));
    }

    NTSTATUS WebSocketMessageCallback(
        void* context,
        wknet::websocket::MsgType type,
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
        WKNET_SAMPLE_LOG(
            "[WebSocket回调] 收到%s消息 长度=%Iu 是否最后分片=%s\r\n",
            WsMsgTypeName(type),
            dataLength,
            BoolName(finalFragment));
        LogBytePayload("[WebSocket回调消息]", "WebSocket 接收 Ex 回调", data, dataLength);
        return STATUS_SUCCESS;
    }

    NTSTATUS CreateSampleRequest(
        wknet::http::Session* session,
        wknet::http::Method method,
        const char* url,
        const wknet::http::TlsConfig* tlsConfig,
        wknet::http::AddressFamily family,
        wknet::http::ConnPolicy policy,
        wknet::http::Request** request) noexcept
    {
        (void)method;
        (void)url;
        (void)tlsConfig;
        (void)family;
        (void)policy;

        if (session == nullptr || request == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *request = nullptr;
        wknet::http::Request* newRequest = nullptr;
        NTSTATUS status = wknet::http::RequestCreate(session, &newRequest);
        if (NT_SUCCESS(status)) {
            *request = newRequest;
        }
        return status;
    }

    NTSTATUS CreateSampleHeaders(_Out_ wknet::http::Headers** headers) noexcept
    {
        if (headers == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *headers = nullptr;
        NTSTATUS status = wknet::http::HeadersCreate(headers);
        if (NT_SUCCESS(status)) {
            status = wknet::http::HeadersAdd(*headers, "User-Agent", "wknet/0.1");
        }
        if (!NT_SUCCESS(status)) {
            wknet::http::HeadersRelease(*headers);
            *headers = nullptr;
        }
        return status;
    }

    void ApplySendControls(
        _In_ wknet::http::SendOptions* options,
        _In_opt_ const wknet::http::TlsConfig* tlsConfig,
        wknet::http::AddressFamily family,
        wknet::http::ConnPolicy policy) noexcept
    {
        if (options == nullptr) {
            return;
        }

        options->Family = family;
        options->ConnectionPolicy = policy;
        if (tlsConfig != nullptr) {
            options->Tls = *tlsConfig;
            options->HasTlsOverride = true;
        }
    }

    NTSTATUS CreateSampleOptions(
        _In_opt_ const wknet::http::TlsConfig* tlsConfig,
        wknet::http::AddressFamily family,
        wknet::http::ConnPolicy policy,
        _Out_ wknet::http::SendOptions** options) noexcept
    {
        if (options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *options = nullptr;
        NTSTATUS status = wknet::http::SendOptionsCreate(options);
        if (NT_SUCCESS(status)) {
            ApplySendControls(*options, tlsConfig, family, policy);
        }
        return status;
    }

    NTSTATUS SendPreparedRequest(
        wknet::http::Session* session,
        const char* sampleName,
        wknet::http::Method method,
        const char* url,
        const char* bodyKind,
        SIZE_T bodyLength,
        const wknet::http::TlsConfig* tlsConfig,
        wknet::http::AddressFamily family,
        wknet::http::ConnPolicy policy,
        wknet::http::Request* request,
        const wknet::http::Body* body,
        wknet::http::SendOptions* options,
        SendVariant variant,
        HighLevelApiSampleResult& result) noexcept
    {
        (void)session;
        if (request == nullptr || url == nullptr) {
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

        wknet::http::Headers* headers = nullptr;
        NTSTATUS status = CreateSampleHeaders(&headers);
        wknet::http::SendOptions* localOptions = nullptr;
        if (NT_SUCCESS(status) && options == nullptr) {
            status = CreateSampleOptions(tlsConfig, family, policy, &localOptions);
            options = localOptions;
        }
        if (NT_SUCCESS(status) && options != nullptr) {
            ApplySendControls(options, tlsConfig, family, policy);
        }

        wknet::http::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            if (variant == SendVariant::SendEx) {
                status = wknet::http::SendEx(
                    request,
                    method,
                    url,
                    LiteralLength(url),
                    headers,
                    body,
                    options,
                    &response);
            }
            else {
                status = wknet::http::Send(
                    request,
                    method,
                    url,
                    headers,
                    body,
                    options,
                    &response);
            }
        }

        CaptureResponse(sampleName, result, status, response);
        wknet::http::ResponseRelease(response);
        wknet::http::SendOptionsRelease(localOptions);
        wknet::http::HeadersRelease(headers);
        return status;
    }

    NTSTATUS RunRequestBodySample(
        wknet::http::Session* session,
        const char* sampleName,
        const char* bodyKind,
        SIZE_T displayBodyLength,
        HighLevelApiSampleResult& result,
        NTSTATUS (*createBody)(wknet::http::Body** body) noexcept) noexcept
    {
        wknet::http::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            wknet::http::Method::Post,
            HttpPostUrl,
            nullptr,
            DefaultHttpSampleAddressFamily,
            wknet::http::ConnPolicy::NoPool,
            &request);
        wknet::http::Body* body = nullptr;
        if (NT_SUCCESS(status)) {
            status = createBody(&body);
        }
        if (NT_SUCCESS(status)) {
            status = SendPreparedRequest(
                session,
                sampleName,
                wknet::http::Method::Post,
                HttpPostUrl,
                bodyKind,
                displayBodyLength,
                nullptr,
                DefaultHttpSampleAddressFamily,
                wknet::http::ConnPolicy::NoPool,
                request,
                body,
                nullptr,
                SendVariant::Send,
                result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
            WKNET_SAMPLE_LOG("[HTTP请求] 示例=%s 构造请求体失败 NTSTATUS=0x%08X\r\n",
                sampleName,
                static_cast<ULONG>(status));
        }

        wknet::http::BodyRelease(body);
        wknet::http::RequestRelease(request);
        return status;
    }

    NTSTATUS CreateTextBody(wknet::http::Body** body) noexcept
    {
        return wknet::http::BodyCreateText(
            TextBody,
            LiteralLength(TextBody),
            nullptr,
            body);
    }

    NTSTATUS CreateJsonBody(wknet::http::Body** body) noexcept
    {
        return wknet::http::BodyCreateJson(JsonBody, LiteralLength(JsonBody), body);
    }

    NTSTATUS CreateRawBody(wknet::http::Body** body) noexcept
    {
        return wknet::http::BodyCreateTextEx(
            reinterpret_cast<const char*>(RawBody),
            sizeof(RawBody),
            "application/octet-stream",
            LiteralLength("application/octet-stream"),
            body);
    }

    NTSTATUS CreateFormBody(wknet::http::Body** body) noexcept
    {
        const wknet::http::NameValuePair pairs[] = {
            { "source", LiteralLength("source"), "kernel-http", LiteralLength("kernel-http") },
            { "kind", LiteralLength("kind"), "form", LiteralLength("form") }
        };
        return wknet::http::BodyCreateForm(pairs, sizeof(pairs) / sizeof(pairs[0]), body);
    }

    NTSTATUS CreateMultipartBody(wknet::http::Body** body) noexcept
    {
        const UCHAR fileBytes[] = { 'f', 'i', 'l', 'e', '-', 'b', 'y', 't', 'e', 's' };
        const wknet::http::MultipartPart parts[] = {
            {
                wknet::http::BodyPartKind::Field,
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
                wknet::http::BodyPartKind::FileBytes,
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
        return wknet::http::BodyCreateMultipart(parts, sizeof(parts) / sizeof(parts[0]), body);
    }

    NTSTATUS CreateFileBody(wknet::http::Body** body) noexcept
    {
        WKNET_SAMPLE_LOG("[HTTP请求] 文件请求体示例路径=%s\r\n", FileBodyPath);
        return wknet::http::BodyCreateFileEx(
            FileBodyPath,
            LiteralLength(FileBodyPath),
            "text/plain",
            LiteralLength("text/plain"),
            body);
    }

    NTSTATUS CreateEmptyBody(wknet::http::Body** body) noexcept
    {
        return wknet::http::BodyCreateBytes(nullptr, 0, body);
    }

    NTSTATUS RunSimpleSync(
        wknet::http::Session* session,
        const char* sampleName,
        wknet::http::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        const char* bodyKind,
        HighLevelApiSampleResult& result,
        const wknet::http::TlsConfig* tlsConfig = nullptr,
        wknet::http::ConnPolicy policy = wknet::http::ConnPolicy::ReuseOrCreate,
        wknet::http::AddressFamily family = DefaultHttpSampleAddressFamily) noexcept
    {
        wknet::http::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            method,
            url,
            tlsConfig,
            family,
            policy,
            &request);
        wknet::http::Body* requestBody = nullptr;
        if (NT_SUCCESS(status) && bodyLength != 0) {
            status = wknet::http::BodyCreateBytes(body, bodyLength, &requestBody);
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
                requestBody,
                nullptr,
                SendVariant::Send,
                result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        wknet::http::BodyRelease(requestBody);
        wknet::http::RequestRelease(request);
        return status;
    }

    NTSTATUS RunShortcutHttp(
        wknet::http::Session* session,
        const char* sampleName,
        wknet::http::Method method,
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
            wknet::http::AddressFamily::Any,
            wknet::http::ConnPolicy::ReuseOrCreate);

        wknet::http::Body* requestBody = nullptr;
        NTSTATUS status = STATUS_SUCCESS;
        if (bodyLength != 0) {
            status = wknet::http::BodyCreateBytes(body, bodyLength, &requestBody);
        }

        wknet::http::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            switch (method) {
            case wknet::http::Method::Get:
                status = wknet::http::GetEx(session, url, LiteralLength(url), nullptr, nullptr, &response);
                break;
            case wknet::http::Method::Post:
                status = wknet::http::PostEx(session, url, LiteralLength(url), nullptr, requestBody, nullptr, &response);
                break;
            case wknet::http::Method::Put:
                status = wknet::http::PutEx(session, url, LiteralLength(url), nullptr, requestBody, nullptr, &response);
                break;
            case wknet::http::Method::Patch:
                status = wknet::http::PatchEx(session, url, LiteralLength(url), nullptr, requestBody, nullptr, &response);
                break;
            case wknet::http::Method::Delete:
                status = wknet::http::DeleteEx(session, url, LiteralLength(url), nullptr, nullptr, &response);
                break;
            case wknet::http::Method::Head:
                status = wknet::http::HeadEx(session, url, LiteralLength(url), nullptr, nullptr, &response);
                break;
            case wknet::http::Method::Options:
                status = wknet::http::OptionsEx(session, url, LiteralLength(url), nullptr, nullptr, &response);
                break;
            default:
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }

        CaptureResponse(sampleName, result, status, response);
        wknet::http::ResponseRelease(response);
        wknet::http::BodyRelease(requestBody);
        return status;
    }

    NTSTATUS RunSendWithOptions(
        wknet::http::Session* session,
        HighLevelApiSampleResult& result,
        bool useSendEx) noexcept
    {
        wknet::http::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            wknet::http::Method::Get,
            HttpGetUrl,
            nullptr,
            DefaultHttpSampleAddressFamily,
            useSendEx ? wknet::http::ConnPolicy::ForceNew : wknet::http::ConnPolicy::NoPool,
            &request);

        CallbackStats stats = {};
        wknet::http::SendOptions* options = nullptr;
        if (NT_SUCCESS(status)) {
            status = CreateSampleOptions(
                nullptr,
                DefaultHttpSampleAddressFamily,
                useSendEx ? wknet::http::ConnPolicy::ForceNew : wknet::http::ConnPolicy::NoPool,
                &options);
        }
        if (NT_SUCCESS(status)) {
            options->MaxResponseBytes = 0;
            options->Flags = wknet::http::SendFlagAggregateWithCallbacks;
            options->OnHeader = HeaderCallback;
            options->OnBody = BodyCallback;
            options->CallbackContext = &stats;
        }

        if (NT_SUCCESS(status)) {
            status = SendPreparedRequest(
                session,
                useSendEx ? "HTTP SendEx" : "HTTP Send(带选项)",
                wknet::http::Method::Get,
                HttpGetUrl,
                "无",
                0,
                nullptr,
                DefaultHttpSampleAddressFamily,
                useSendEx ? wknet::http::ConnPolicy::ForceNew : wknet::http::ConnPolicy::NoPool,
                request,
                nullptr,
                options,
                useSendEx ? SendVariant::SendEx : SendVariant::SendWithOptions,
                result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        WKNET_SAMPLE_LOG(
            "[HTTP回调] 示例=%s 响应头数量=%Iu 响应体分块=%Iu 回调累计字节=%Iu\r\n",
            useSendEx ? "HTTP SendEx" : "HTTP Send(带选项)",
            stats.HeaderCount,
            stats.BodyChunks,
            stats.BodyBytes);

        wknet::http::SendOptionsRelease(options);
        wknet::http::RequestRelease(request);
        return status;
    }

    NTSTATUS RunResponseHeaderSample(wknet::http::Session* session, HighLevelApiSampleResult& result) noexcept
    {
        wknet::http::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            wknet::http::Method::Get,
            HttpGetUrl,
            nullptr,
            DefaultHttpSampleAddressFamily,
            wknet::http::ConnPolicy::ReuseOrCreate,
            &request);

        wknet::http::Headers* headers = nullptr;
        if (NT_SUCCESS(status)) {
            status = CreateSampleHeaders(&headers);
        }
        wknet::http::SendOptions* options = nullptr;
        if (NT_SUCCESS(status)) {
            status = CreateSampleOptions(
                nullptr,
                DefaultHttpSampleAddressFamily,
                wknet::http::ConnPolicy::ReuseOrCreate,
                &options);
        }

        wknet::http::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            LogHttpRequest(
                "HTTP 响应头读取",
                "Send",
                wknet::http::Method::Get,
                HttpGetUrl,
                "无",
                0,
                nullptr,
                DefaultHttpSampleAddressFamily,
                wknet::http::ConnPolicy::ReuseOrCreate);
            status = wknet::http::SendEx(
                request,
                wknet::http::Method::Get,
                HttpGetUrl,
                LiteralLength(HttpGetUrl),
                headers,
                nullptr,
                options,
                &response);
        }
        CaptureResponse("HTTP 响应头读取", result, status, response);

        if (NT_SUCCESS(status) && response != nullptr) {
            const char* headerValue = nullptr;
            SIZE_T headerLength = 0;
            const NTSTATUS headerStatus = wknet::http::ResponseGetHeader(
                response,
                "Content-Length",
                LiteralLength("Content-Length"),
                &headerValue,
                &headerLength);
            WKNET_SAMPLE_LOG(
                "[HTTP响应] ResponseGetHeader(Content-Length) 状态=0x%08X 值=%.*s\r\n",
                static_cast<ULONG>(headerStatus),
                PrintLength(headerLength),
                headerValue != nullptr ? headerValue : "");
        }

        wknet::http::ResponseRelease(response);
        wknet::http::SendOptionsRelease(options);
        wknet::http::HeadersRelease(headers);
        wknet::http::RequestRelease(request);
        return status;
    }

    NTSTATUS CompleteHttpAsync(
        const char* sampleName,
        wknet::http::AsyncOp* op,
        HighLevelApiSampleResult& result) noexcept
    {
        if (op == nullptr) {
            CaptureStatus(result, STATUS_INVALID_PARAMETER, 0, 0);
            return STATUS_INVALID_PARAMETER;
        }

        WKNET_SAMPLE_LOG(
            "[HTTP异步] 示例=%s 等待前：状态=0x%08X 已完成=%s 已取消=%s\r\n",
            sampleName,
            static_cast<ULONG>(wknet::http::AsyncGetStatus(op)),
            BoolName(wknet::http::AsyncIsCompleted(op)),
            BoolName(wknet::http::AsyncIsCanceled(op)));

        NTSTATUS status = wknet::http::AsyncWait(op, AsyncWaitTimeoutMs);
        WKNET_SAMPLE_LOG(
            "[HTTP异步] 示例=%s 等待后：状态=0x%08X 已完成=%s 已取消=%s\r\n",
            sampleName,
            static_cast<ULONG>(wknet::http::AsyncGetStatus(op)),
            BoolName(wknet::http::AsyncIsCompleted(op)),
            BoolName(wknet::http::AsyncIsCanceled(op)));

        wknet::http::Response* response = nullptr;
        if (NT_SUCCESS(status)) {
            status = wknet::http::AsyncGetResponse(op, &response);
        }
        CaptureResponse(sampleName, result, status, response);
        wknet::http::ResponseRelease(response);
        wknet::http::AsyncRelease(op);
        return status;
    }

    NTSTATUS RunSimpleAsync(
        wknet::http::Session* session,
        const char* sampleName,
        wknet::http::Method method,
        const char* url,
        const UCHAR* body,
        SIZE_T bodyLength,
        const char* bodyKind,
        HighLevelApiSampleResult& result) noexcept
    {
        LogHttpRequest(
            sampleName,
            method == wknet::http::Method::Post ? "AsyncPostEx" : "AsyncGetEx",
            method,
            url,
            bodyKind,
            bodyLength,
            nullptr,
            wknet::http::AddressFamily::Any,
            wknet::http::ConnPolicy::ReuseOrCreate);

        wknet::http::Body* requestBody = nullptr;
        NTSTATUS status = STATUS_SUCCESS;
        if (bodyLength != 0) {
            status = wknet::http::BodyCreateBytes(body, bodyLength, &requestBody);
        }

        wknet::http::AsyncOp* op = nullptr;
        if (NT_SUCCESS(status)) {
            if (method == wknet::http::Method::Post) {
                status = wknet::http::AsyncPostEx(
                    session,
                    url,
                    LiteralLength(url),
                    nullptr,
                    requestBody,
                    nullptr,
                    &op);
            }
            else {
                status = wknet::http::AsyncGetEx(
                    session,
                    url,
                    LiteralLength(url),
                    nullptr,
                    nullptr,
                    &op);
            }
        }
        if (!NT_SUCCESS(status)) {
            CaptureStatus(result, status, 0, 0);
            wknet::http::BodyRelease(requestBody);
            return status;
        }

        status = CompleteHttpAsync(sampleName, op, result);
        wknet::http::BodyRelease(requestBody);
        return status;
    }

    NTSTATUS RunPreparedAsync(
        wknet::http::Session* session,
        const char* sampleName,
        AsyncSendVariant variant,
        HighLevelApiSampleResult& result) noexcept
    {
        wknet::http::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            wknet::http::Method::Post,
            HttpPostUrl,
            nullptr,
            DefaultHttpSampleAddressFamily,
            wknet::http::ConnPolicy::NoPool,
            &request);
        wknet::http::Body* body = nullptr;
        if (NT_SUCCESS(status)) {
            status = wknet::http::BodyCreateJson(JsonBody, LiteralLength(JsonBody), &body);
        }

        CallbackStats stats = {};
        wknet::http::AsyncOptions* options = nullptr;
        if (NT_SUCCESS(status) && variant != AsyncSendVariant::AsyncSend) {
            status = wknet::http::AsyncOptionsCreate(&options);
        }
        const wknet::http::ConnPolicy policy =
            variant == AsyncSendVariant::AsyncSend ?
                wknet::http::ConnPolicy::ReuseOrCreate :
                wknet::http::ConnPolicy::NoPool;
        if (NT_SUCCESS(status) && options != nullptr) {
            ApplySendControls(
                &options->Send,
                nullptr,
                DefaultHttpSampleAddressFamily,
                policy);
            options->Send.MaxResponseBytes = 0;
            options->Send.Flags = wknet::http::SendFlagAggregateWithCallbacks;
            options->Send.OnHeader = HeaderCallback;
            options->Send.OnBody = BodyCallback;
            options->Send.CallbackContext = &stats;
            options->OnComplete = CompletionCallback;
            options->CompletionContext = &stats;
        }

        wknet::http::Headers* headers = nullptr;
        if (NT_SUCCESS(status)) {
            status = CreateSampleHeaders(&headers);
        }

        wknet::http::AsyncOp* op = nullptr;
        if (NT_SUCCESS(status)) {
            LogHttpRequest(
                sampleName,
                AsyncSendVariantName(variant),
                wknet::http::Method::Post,
                HttpPostUrl,
                "JSON",
                LiteralLength(JsonBody),
                nullptr,
                DefaultHttpSampleAddressFamily,
                policy);

            if (variant == AsyncSendVariant::AsyncSend) {
                status = wknet::http::AsyncSend(
                    request,
                    wknet::http::Method::Post,
                    HttpPostUrl,
                    headers,
                    body,
                    nullptr,
                    &op);
            }
            else if (variant == AsyncSendVariant::AsyncSendWithOptions) {
                status = wknet::http::AsyncSend(
                    request,
                    wknet::http::Method::Post,
                    HttpPostUrl,
                    headers,
                    body,
                    options,
                    &op);
            }
            else {
                status = wknet::http::AsyncSendEx(
                    request,
                    wknet::http::Method::Post,
                    HttpPostUrl,
                    LiteralLength(HttpPostUrl),
                    headers,
                    body,
                    options,
                    &op);
            }
        }

        if (NT_SUCCESS(status)) {
            status = CompleteHttpAsync(sampleName, op, result);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        if (variant == AsyncSendVariant::AsyncSend) {
            WKNET_SAMPLE_LOG(
                "[HTTP异步] 示例=%s 完成回调=未配置\r\n",
                sampleName);
        }
        else {
            WKNET_SAMPLE_LOG(
                "[HTTP异步] 示例=%s 完成回调次数=%Iu 完成回调状态=0x%08X\r\n",
                sampleName,
                stats.CompletionCount,
                static_cast<ULONG>(stats.CompletionStatus));
        }

        wknet::http::AsyncOptionsRelease(options);
        wknet::http::HeadersRelease(headers);
        wknet::http::BodyRelease(body);
        wknet::http::RequestRelease(request);
        return status;
    }

    NTSTATUS RunAsyncCancelSample(wknet::http::Session* session, HighLevelApiSampleResult& result) noexcept
    {
        WKNET_SAMPLE_LOG("[HTTP异步] 示例=AsyncCancel 创建一个异步 GET 后立即请求取消并等待终态\r\n");
        wknet::http::AsyncOp* op = nullptr;
        NTSTATUS status = wknet::http::AsyncGetEx(
            session,
            HttpGetUrl,
            LiteralLength(HttpGetUrl),
            nullptr,
            nullptr,
            &op);
        NTSTATUS cancelStatus = status;
        NTSTATUS waitStatus = status;
        if (NT_SUCCESS(status)) {
            cancelStatus = wknet::http::AsyncCancel(op);
            status = cancelStatus;
        }
        if (NT_SUCCESS(status)) {
            waitStatus = wknet::http::AsyncWait(op, AsyncWaitForeverMs);
            if (wknet::http::AsyncIsCompleted(op)) {
                status = STATUS_SUCCESS;
            }
            else {
                status = waitStatus;
            }
        }

        const bool canceled = wknet::http::AsyncIsCanceled(op);
        const bool terminalObserved = wknet::http::AsyncIsCompleted(op);
        WKNET_SAMPLE_LOG(
            "[HTTP异步] 示例=AsyncCancel 取消状态=0x%08X 等待状态=0x%08X 已取消=%s 当前状态=0x%08X\r\n",
            static_cast<ULONG>(cancelStatus),
            static_cast<ULONG>(waitStatus),
            BoolName(canceled),
            static_cast<ULONG>(wknet::http::AsyncGetStatus(op)));

        CaptureStatus(result, status, canceled && terminalObserved ? 1 : 0, terminalObserved ? 1 : 0);
        wknet::http::AsyncRelease(op);
        return status;
    }

    NTSTATUS RunHttpsRequestBuilder(
        wknet::http::Session* session,
        HighLevelApiSampleResult& result,
        const wknet::http::TlsConfig& tlsConfig) noexcept
    {
        wknet::http::Request* request = nullptr;
        NTSTATUS status = CreateSampleRequest(
            session,
            wknet::http::Method::Post,
            HttpsBuilderUrl,
            &tlsConfig,
            DefaultHttpSampleAddressFamily,
            wknet::http::ConnPolicy::ReuseOrCreate,
            &request);
        wknet::http::Headers* headers = nullptr;
        if (NT_SUCCESS(status)) {
            status = CreateSampleHeaders(&headers);
        }
        if (NT_SUCCESS(status)) {
            status = wknet::http::HeadersAdd(headers, "X-Wknet-Sample", "request-builder");
        }
        wknet::http::Body* body = nullptr;
        if (NT_SUCCESS(status)) {
            status = wknet::http::BodyCreateJson(JsonBody, LiteralLength(JsonBody), &body);
        }
        wknet::http::SendOptions* options = nullptr;
        if (NT_SUCCESS(status)) {
            status = CreateSampleOptions(
                &tlsConfig,
                DefaultHttpSampleAddressFamily,
                wknet::http::ConnPolicy::ReuseOrCreate,
                &options);
        }
        if (NT_SUCCESS(status)) {
            LogHttpRequest(
                "HTTPS Request Builder",
                "SendEx",
                wknet::http::Method::Post,
                HttpsBuilderUrl,
                "JSON",
                LiteralLength(JsonBody),
                &tlsConfig,
                DefaultHttpSampleAddressFamily,
                wknet::http::ConnPolicy::ReuseOrCreate);
            wknet::http::Response* response = nullptr;
            status = wknet::http::SendEx(
                request,
                wknet::http::Method::Post,
                HttpsBuilderUrl,
                LiteralLength(HttpsBuilderUrl),
                headers,
                body,
                options,
                &response);
            CaptureResponse("HTTPS Request Builder", result, status, response);
            wknet::http::ResponseRelease(response);
        }
        else {
            CaptureStatus(result, status, 0, 0);
        }

        wknet::http::SendOptionsRelease(options);
        wknet::http::BodyRelease(body);
        wknet::http::HeadersRelease(headers);
        wknet::http::RequestRelease(request);
        return status;
    }

    wknet::websocket::ConnectConfig MakeWsConfig(
        const char* url,
        const wknet::http::TlsConfig* tlsConfig,
        wknet::http::AddressFamily family) noexcept
    {
        wknet::websocket::ConnectConfig config = wknet::websocket::DefaultConnectConfig();
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
        const wknet::websocket::ConnectConfig& config,
        WsSendVariant sendVariant,
        SIZE_T sendLength) noexcept
    {
        WKNET_SAMPLE_LOG(
            "[WebSocket请求] 示例=%s 入口=%s URL=%s 子协议=%.*s 发送=%s 发送长度=%Iu 地址族=%s 证书策略=%s 自动Ping响应=%s 最大消息=%Iu TLS策略=%s SHA1签名=%s TLS1.2最大重协商=%lu\r\n",
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
            config.MaxMessageBytes,
            config.Tls.Policy.Profile == wknet::http::TlsSecurityProfile::CompatibilityExplicit ? "CompatibilityExplicit" : "ModernDefault",
            config.Tls.Policy.EnableTls12Sha1Signatures ? "启用(endpoint兼容)" : "关闭",
            config.Tls.MaxTls12Renegotiations);
    }

    void LogWebSocketResponse(
        const char* sampleName,
        NTSTATUS status,
        const wknet::websocket::Message* message,
        NTSTATUS closeStatus) noexcept
    {
        WKNET_SAMPLE_LOG(
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
        wknet::http::Session* session,
        WsConnectVariant variant,
        const wknet::websocket::ConnectConfig& config,
        wknet::websocket::WebSocket** websocket) noexcept
    {
        if (variant == WsConnectVariant::Url) {
            return wknet::websocket::Connect(session, config.Url, config.UrlLength, websocket);
        }
        if (variant == WsConnectVariant::Config) {
            return wknet::websocket::Connect(session, &config, websocket);
        }
        return wknet::websocket::ConnectEx(session, &config, websocket);
    }

    NTSTATUS SendWebSocketMessage(
        wknet::websocket::WebSocket* websocket,
        WsSendVariant variant) noexcept
    {
        wknet::websocket::SendOptions sendOptions = {};
        sendOptions.FinalFragment = true;
        switch (variant) {
        case WsSendVariant::Text:
            return wknet::websocket::SendText(websocket, WsHelloMessage, LiteralLength(WsHelloMessage));
        case WsSendVariant::TextEx:
            return wknet::websocket::SendTextEx(websocket, WsHelloMessage, LiteralLength(WsHelloMessage), &sendOptions);
        case WsSendVariant::Binary:
            return wknet::websocket::SendBinary(websocket, WsBinaryMessage, sizeof(WsBinaryMessage));
        case WsSendVariant::BinaryEx:
            return wknet::websocket::SendBinaryEx(websocket, WsBinaryMessage, sizeof(WsBinaryMessage), &sendOptions);
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

    wknet::websocket::MsgType ExpectedWebSocketEchoType(WsSendVariant variant) noexcept
    {
        return variant == WsSendVariant::Binary || variant == WsSendVariant::BinaryEx ?
            wknet::websocket::MsgType::Binary :
            wknet::websocket::MsgType::Text;
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

    bool IsExpectedWebSocketEcho(WsSendVariant variant, const wknet::websocket::Message& message) noexcept
    {
        if (variant == WsSendVariant::None) {
            return true;
        }

        SIZE_T expectedLength = 0;
        const UCHAR* expected = ExpectedWebSocketEchoPayload(variant, &expectedLength);
        const wknet::websocket::MsgType expectedType = ExpectedWebSocketEchoType(variant);

        if (message.Type != expectedType ||
            !message.FinalFragment ||
            message.DataLength != expectedLength) {
            return false;
        }
        if (expectedLength == 0) {
            return true;
        }

        return message.Data != nullptr &&
            expected != nullptr &&
            RtlCompareMemory(message.Data, expected, expectedLength) == expectedLength;
    }

    NTSTATUS ValidateWebSocketEcho(
        const char* sampleName,
        WsSendVariant variant,
        const wknet::websocket::Message& message) noexcept
    {
        if (IsExpectedWebSocketEcho(variant, message)) {
            return STATUS_SUCCESS;
        }

        SIZE_T expectedLength = 0;
        const wknet::websocket::MsgType expectedType = ExpectedWebSocketEchoType(variant);
        ExpectedWebSocketEchoPayload(variant, &expectedLength);

        WKNET_SAMPLE_LOG(
            "[WebSocket响应] 示例=%s Echo校验失败 期望类型=%s 实际类型=%s 期望长度=%Iu 实际长度=%Iu 最后分片=%s\r\n",
            sampleName,
            WsMsgTypeName(expectedType),
            WsMsgTypeName(message.Type),
            expectedLength,
            message.DataLength,
            BoolName(message.FinalFragment));
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    NTSTATUS ReceiveWebSocketEcho(
        wknet::websocket::WebSocket* websocket,
        const char* sampleName,
        WsSendVariant sendVariant,
        bool receiveWithCallback,
        CallbackStats& callbackStats,
        wknet::websocket::Message& message) noexcept
    {
        for (ULONG frameIndex = 0; frameIndex < MaxWebSocketEchoReceiveFrames; ++frameIndex) {
            NTSTATUS status = STATUS_SUCCESS;
            if (receiveWithCallback) {
                wknet::websocket::ReceiveOptions receiveOptions = {};
                receiveOptions.MaxMessageBytes = 64 * 1024;
                receiveOptions.AutoAllocate = true;
                receiveOptions.OnMessage = WebSocketMessageCallback;
                receiveOptions.CallbackContext = &callbackStats;
                status = wknet::websocket::ReceiveEx(websocket, &receiveOptions, &message);
            }
            else {
                status = wknet::websocket::Receive(websocket, &message);
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (IsExpectedWebSocketEcho(sendVariant, message)) {
                return STATUS_SUCCESS;
            }

            WKNET_SAMPLE_LOG(
                "[WebSocket响应] 示例=%s 跳过非目标Echo帧 序号=%lu 类型=%s 长度=%Iu\r\n",
                sampleName,
                frameIndex,
                WsMsgTypeName(message.Type),
                message.DataLength);
            if (message.Type == wknet::websocket::MsgType::Close) {
                return STATUS_SUCCESS;
            }
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS RunWebSocketSample(
        wknet::http::Session* session,
        const char* sampleName,
        WsConnectVariant connectVariant,
        WsSendVariant sendVariant,
        bool receiveWithCallback,
        const char* url,
        const wknet::http::TlsConfig* tlsConfig,
        HighLevelApiSampleResult& result) noexcept
    {
        wknet::websocket::ConnectConfig config = MakeWsConfig(url, tlsConfig, DefaultWebSocketSampleAddressFamily);
        if (connectVariant == WsConnectVariant::Url) {
            config = MakeWsConfig(url, nullptr, wknet::http::AddressFamily::Any);
        }

        LogWebSocketRequest(
            sampleName,
            connectVariant,
            config,
            sendVariant,
            WebSocketSendLength(sendVariant));

        wknet::websocket::WebSocket* websocket = nullptr;
        NTSTATUS status = ConnectWebSocket(session, connectVariant, config, &websocket);
        wknet::websocket::Message message = {};
        CallbackStats callbackStats = {};

        if (NT_SUCCESS(status) && sendVariant != WsSendVariant::None) {
            status = SendWebSocketMessage(websocket, sendVariant);
        }
        const bool expectEcho = sendVariant != WsSendVariant::None;
        if (NT_SUCCESS(status) && expectEcho) {
            status = ReceiveWebSocketEcho(
                websocket,
                sampleName,
                sendVariant,
                receiveWithCallback,
                callbackStats,
                message);
        }
        if (NT_SUCCESS(status) && expectEcho) {
            status = ValidateWebSocketEcho(sampleName, sendVariant, message);
        }

        result.Status = status;
        result.StatusCode = NT_SUCCESS(status) ? 1 : 0;
        result.BodyLength = expectEcho ?
            (receiveWithCallback ? callbackStats.WsMessageBytes : message.DataLength) :
            WebSocketSendLength(sendVariant);

        wknet::websocket::Message logMessage = message;
        HeapArray<UCHAR> logMessageData;
        if (message.DataLength != 0 && message.Data != nullptr) {
            const NTSTATUS copyStatus = logMessageData.Allocate(message.DataLength);
            if (NT_SUCCESS(copyStatus)) {
                RtlCopyMemory(logMessageData.Get(), message.Data, message.DataLength);
                logMessage.Data = logMessageData.Get();
            }
            else {
                WKNET_SAMPLE_LOG(
                    "[WebSocket响应] 示例=%s 响应体日志复制失败 NTSTATUS=0x%08X\r\n",
                    sampleName,
                    static_cast<ULONG>(copyStatus));
                logMessage.Data = nullptr;
            }
        }

        NTSTATUS closeStatus = STATUS_SUCCESS;
        if (websocket != nullptr) {
            closeStatus = wknet::websocket::Close(websocket);
            if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
                result.Status = closeStatus;
                status = closeStatus;
            }
        }

        LogWebSocketResponse(sampleName, status, &logMessage, closeStatus);
        return status;
    }

    NTSTATUS RunWebSocketAsyncSample(
        wknet::http::Session* session,
        const char* sampleName,
        WsConnectVariant connectVariant,
        const char* url,
        const wknet::http::TlsConfig* tlsConfig,
        HighLevelApiSampleResult& result) noexcept
    {
        wknet::websocket::ConnectConfig config = MakeWsConfig(url, tlsConfig, DefaultWebSocketSampleAddressFamily);
        if (connectVariant == WsConnectVariant::Url) {
            config = MakeWsConfig(url, nullptr, wknet::http::AddressFamily::Any);
        }

        LogWebSocketRequest(
            sampleName,
            connectVariant,
            config,
            WsSendVariant::None,
            0);

        wknet::http::AsyncOp* op = nullptr;
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        if (connectVariant == WsConnectVariant::Url) {
            status = wknet::websocket::ConnectAsync(session, config.Url, config.UrlLength, &op);
        }
        else if (connectVariant == WsConnectVariant::Config) {
            status = wknet::websocket::ConnectAsync(session, &config, &op);
        }
        else {
            status = wknet::websocket::ConnectAsyncEx(session, &config, &op);
        }

        wknet::websocket::WebSocket* websocket = nullptr;
        if (NT_SUCCESS(status)) {
            WKNET_SAMPLE_LOG(
                "[WebSocket异步] 示例=%s 等待前：状态=0x%08X 已完成=%s\r\n",
                sampleName,
                static_cast<ULONG>(wknet::http::AsyncGetStatus(op)),
                BoolName(wknet::http::AsyncIsCompleted(op)));
            status = wknet::http::AsyncWait(op, AsyncWaitTimeoutMs);
        }
        if (NT_SUCCESS(status)) {
            status = wknet::websocket::AsyncGetWebSocket(op, &websocket);
        }

        NTSTATUS closeStatus = STATUS_SUCCESS;
        if (websocket != nullptr) {
            closeStatus = wknet::websocket::Close(websocket);
            if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
                status = closeStatus;
            }
        }

        result.Status = status;
        result.StatusCode = NT_SUCCESS(status) ? 1 : 0;
        result.BodyLength = 0;
        LogWebSocketResponse(sampleName, status, nullptr, closeStatus);
        wknet::http::AsyncRelease(op);
        return status;
    }

    NTSTATUS RunSessionCreateSample(
        net::WskClient* wskClient,
        const char* sampleName,
        const wknet::http::SessionConfig* config,
        HighLevelApiSampleResult& result,
        wknet::http::Session** keepSession) noexcept
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
            wknet::http::SessionConfig defaultConfig = wknet::http::DefaultSessionConfig();
            LogSessionConfig(sampleName, defaultConfig);
        }

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(config, &session);
        CaptureStatus(result, status, NT_SUCCESS(status) ? 1 : 0, config != nullptr ? config->MaxResponseBytes : 0);
        WKNET_SAMPLE_LOG(
            "[会话示例] %s：SessionCreate 状态=0x%08X 会话=%s\r\n",
            sampleName,
            static_cast<ULONG>(status),
            session != nullptr ? "已创建" : "未创建");

        if (keepSession != nullptr && NT_SUCCESS(status)) {
            *keepSession = session;
        }
        else {
            wknet::http::SessionClose(session);
            WKNET_SAMPLE_LOG("[会话示例] %s：SessionClose 已调用\r\n", sampleName);
        }
        return status;
    }

    NTSTATUS RunHighLevelApiSamplesOnSession(
        wknet::http::Session* session,
        wknet::http::Session* urlConnectSession,
        const char* certificateBundlePath,
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
        status = InitializeExternalTrustStore(
            trustStore,
            certificateBundlePath != nullptr ? certificateBundlePath : ExternalTrustStoreDefaultBundlePath);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        wknet::http::TlsConfig ngHttp2Tls = wknet::http::DefaultTlsConfig();
        ngHttp2Tls.Store = trustStore.Store;

        wknet::http::TlsConfig noVerifyTls = wknet::http::DefaultTlsConfig();
        noVerifyTls.Certificate = wknet::http::CertPolicy::NoVerify;

        wknet::http::TlsConfig ngHttp2Http11Tls = ngHttp2Tls;
        ngHttp2Http11Tls.Alpn = AlpnHttp11;
        ngHttp2Http11Tls.AlpnLength = LiteralLength(AlpnHttp11);

        wknet::http::TlsConfig ngHttp2Http2Tls = ngHttp2Tls;
        ngHttp2Http2Tls.Alpn = AlpnH2;
        ngHttp2Http2Tls.AlpnLength = LiteralLength(AlpnH2);

        wknet::http::TlsConfig webSocketTls = wknet::http::DefaultTlsConfig();
        webSocketTls.Store = trustStore.Store;

        wknet::http::TlsConfig webSocketTls13Only = webSocketTls;
        webSocketTls13Only.MinVersion = wknet::http::TlsVersion::Tls13;
        webSocketTls13Only.MaxVersion = wknet::http::TlsVersion::Tls13;

        // HTTP 快捷函数示例：这些入口直接创建并发送请求。
        status = RunShortcutHttp(session, "HTTP GET 快捷函数", wknet::http::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpShortcutGet);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP GET 快捷函数");
        status = RunShortcutHttp(session, "HTTP POST 快捷函数", wknet::http::Method::Post, HttpPostUrl, jsonBytes, jsonLen, "原始字节", results->HttpShortcutPost);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP POST 快捷函数");
        status = RunShortcutHttp(session, "HTTP PUT 快捷函数", wknet::http::Method::Put, HttpPutUrl, jsonBytes, jsonLen, "原始字节", results->HttpShortcutPut);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP PUT 快捷函数");
        status = RunShortcutHttp(session, "HTTP PATCH 快捷函数", wknet::http::Method::Patch, HttpPatchUrl, jsonBytes, jsonLen, "原始字节", results->HttpShortcutPatch);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP PATCH 快捷函数");
        status = RunShortcutHttp(session, "HTTP DELETE 快捷函数", wknet::http::Method::Delete, HttpDeleteUrl, nullptr, 0, "无", results->HttpShortcutDelete);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP DELETE 快捷函数");
        status = RunShortcutHttp(session, "HTTP HEAD 快捷函数", wknet::http::Method::Head, HttpHeadUrl, nullptr, 0, "无", results->HttpShortcutHead);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP HEAD 快捷函数");
        status = RunShortcutHttp(session, "HTTP OPTIONS 快捷函数", wknet::http::Method::Options, HttpOptionsUrl, nullptr, 0, "无", results->HttpShortcutOptions);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP OPTIONS 快捷函数");

        // Request Builder 示例：这些入口展示 URL、方法、Header、Body、TLS、连接策略和地址族配置。
        status = RunSimpleSync(session, "HTTP GET 构造请求", wknet::http::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpGet);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP GET 构造请求");
        status = RunSimpleSync(session, "HTTP POST 原始请求体", wknet::http::Method::Post, HttpPostUrl, jsonBytes, jsonLen, "原始字节", results->HttpPost);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP POST 原始请求体");
        status = RunSimpleSync(session, "HTTP PUT 原始请求体", wknet::http::Method::Put, HttpPutUrl, jsonBytes, jsonLen, "原始字节", results->HttpPut);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP PUT 原始请求体");
        status = RunSimpleSync(session, "HTTP PATCH 原始请求体", wknet::http::Method::Patch, HttpPatchUrl, jsonBytes, jsonLen, "原始字节", results->HttpPatch);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP PATCH 原始请求体");
        status = RunSimpleSync(session, "HTTP DELETE", wknet::http::Method::Delete, HttpDeleteUrl, nullptr, 0, "无", results->HttpDelete);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP DELETE");
        status = RunSimpleSync(session, "HTTP HEAD", wknet::http::Method::Head, HttpHeadUrl, nullptr, 0, "无", results->HttpHead);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP HEAD");
        status = RunSimpleSync(session, "HTTP OPTIONS", wknet::http::Method::Options, HttpOptionsUrl, nullptr, 0, "无", results->HttpOptions);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP OPTIONS");
        status = RunSimpleSync(session, "HTTP GET IPv4 地址族", wknet::http::Method::Get, HttpAddressFamilyGetUrl, nullptr, 0, "无", results->HttpGetIpv4, nullptr, wknet::http::ConnPolicy::ReuseOrCreate, wknet::http::AddressFamily::Ipv4);
        MergeAddressFamilySampleStatus(aggregate, status, wknet::http::AddressFamily::Ipv4, "HTTP GET IPv4 地址族");
        status = RunSimpleSync(session, "HTTP GET IPv6 地址族", wknet::http::Method::Get, HttpAddressFamilyGetUrl, nullptr, 0, "无", results->HttpGetIpv6, nullptr, wknet::http::ConnPolicy::ReuseOrCreate, wknet::http::AddressFamily::Ipv6);
        MergeAddressFamilySampleStatus(aggregate, status, wknet::http::AddressFamily::Ipv6, "HTTP GET IPv6 地址族");
        status = RunSimpleSync(session, "HTTP GET Any 地址族", wknet::http::Method::Get, HttpAddressFamilyGetUrl, nullptr, 0, "无", results->HttpGetAny, nullptr, wknet::http::ConnPolicy::ReuseOrCreate, wknet::http::AddressFamily::Any);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP GET Any 地址族");

        status = RunSendWithOptions(session, results->HttpSendWithOptions, false);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP Send 带选项");
        status = RunSendWithOptions(session, results->HttpSendEx, true);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP SendEx");
        status = RunResponseHeaderSample(session, results->HttpResponseHeader);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP 响应头");

        status = RunRequestBodySample(session, "HTTP 文本请求体", "文本", LiteralLength(TextBody), results->HttpTextBody, CreateTextBody);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP 文本请求体");
        status = RunRequestBodySample(session, "HTTP JSON 请求体", "JSON", LiteralLength(JsonBody), results->HttpJsonBody, CreateJsonBody);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP JSON 请求体");
        status = RunRequestBodySample(session, "HTTP Raw 请求体", "Raw", sizeof(RawBody), results->HttpRawBody, CreateRawBody);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP Raw 请求体");
        status = RunRequestBodySample(session, "HTTP 表单请求体", "表单", LiteralLength("source=kernel-http&kind=form"), results->HttpFormBody, CreateFormBody);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP 表单请求体");
        status = RunRequestBodySample(session, "HTTP Multipart 请求体", "Multipart", LiteralLength("field+file-bytes"), results->HttpMultipartBody, CreateMultipartBody);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP Multipart 请求体");
        status = RunRequestBodySample(session, "HTTP 文件请求体", "文件", 0, results->HttpFileBody, CreateFileBody);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP 文件请求体");
        status = RunRequestBodySample(session, "HTTP 空请求体", "空请求体", 0, results->HttpClearBody, CreateEmptyBody);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP 清空请求体");

        status = RunSimpleAsync(session, "HTTP GET 异步快捷函数", wknet::http::Method::Get, HttpGetUrl, nullptr, 0, "无", results->HttpGetAsync);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP GET 异步快捷函数");
        status = RunSimpleAsync(session, "HTTP POST 异步快捷函数", wknet::http::Method::Post, HttpPostUrl, jsonBytes, jsonLen, "原始字节", results->HttpPostAsync);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP POST 异步快捷函数");
        status = RunPreparedAsync(session, "HTTP AsyncSend", AsyncSendVariant::AsyncSend, results->HttpSendAsync);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP AsyncSend");
        status = RunPreparedAsync(session, "HTTP AsyncSend 带选项", AsyncSendVariant::AsyncSendWithOptions, results->HttpSendAsyncWithOptions);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP AsyncSend 带选项");
        status = RunPreparedAsync(session, "HTTP AsyncSendEx", AsyncSendVariant::AsyncSendEx, results->HttpSendAsyncEx);
        MergePublicHttpSampleStatus(aggregate, status, "HTTP AsyncSendEx");
        status = RunAsyncCancelSample(session, results->HttpAsyncCancel);
        MergeSampleStatus(aggregate, status);

        status = RunSimpleSync(session, "HTTPS GET 自动协议", wknet::http::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsVerifyGet, &ngHttp2Tls);
        MergePublicHttpSampleStatus(aggregate, status, "HTTPS GET 自动协议");
        status = RunSimpleSync(session, "HTTPS GET 不校验证书", wknet::http::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsNoVerifyGet, &noVerifyTls);
        MergePublicHttpSampleStatus(aggregate, status, "HTTPS GET 不校验证书");
        status = RunHttpsRequestBuilder(session, results->HttpsRequestBuilder, ngHttp2Tls);
        MergePublicHttpSampleStatus(aggregate, status, "HTTPS Request Builder");
        status = RunSimpleSync(session, "HTTPS GET HTTP/1.1 ALPN", wknet::http::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsHttp11, &ngHttp2Http11Tls);
        MergePublicHttpSampleStatus(aggregate, status, "HTTPS GET HTTP/1.1 ALPN");
        status = RunSimpleSync(session, "HTTPS GET HTTP/2 ALPN", wknet::http::Method::Get, HttpsGetUrl, nullptr, 0, "无", results->HttpsHttp2, &ngHttp2Http2Tls);
        MergePublicHttpSampleStatus(aggregate, status, "HTTPS GET HTTP/2 ALPN");

        status = RunWebSocketSample(session, "WebSocket Echo", WsConnectVariant::Config, WsSendVariant::Text, false, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketEcho);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket Echo");
        results->WebSocketConfigConnect = results->WebSocketEcho;
        status = RunWebSocketSample(
            urlConnectSession != nullptr ? urlConnectSession : session,
            "WebSocket URL 直连",
            WsConnectVariant::Url,
            WsSendVariant::Text,
            false,
            WebSocketSecureEchoUrl,
            nullptr,
            results->WebSocketUrlConnect);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket URL 直连");
        status = RunWebSocketSample(session, "WebSocket ConnectEx", WsConnectVariant::Ex, WsSendVariant::Text, false, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketConnectEx);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket ConnectEx");
        status = RunWebSocketSample(session, "WebSocket 文本发送 Ex", WsConnectVariant::Ex, WsSendVariant::TextEx, false, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketTextEx);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket 文本发送 Ex");
        status = RunWebSocketSample(session, "WebSocket 二进制发送", WsConnectVariant::Ex, WsSendVariant::Binary, false, WebSocketBinaryEchoUrl, &webSocketTls, results->WebSocketBinary);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket 二进制发送");
        status = RunWebSocketSample(session, "WebSocket 二进制发送 Ex", WsConnectVariant::Ex, WsSendVariant::BinaryEx, false, WebSocketBinaryEchoUrl, &webSocketTls, results->WebSocketBinaryEx);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket 二进制发送 Ex");
        status = RunWebSocketSample(session, "WebSocket TLS1.3 Echo", WsConnectVariant::Config, WsSendVariant::Text, false, WebSocketBinaryEchoUrl, &webSocketTls13Only, results->WebSocketTls13Only);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket TLS1.3 Echo");
        status = RunWebSocketSample(session, "WebSocket 接收 Ex 回调", WsConnectVariant::Ex, WsSendVariant::Text, true, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketReceiveEx);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket 接收 Ex 回调");
        status = RunWebSocketAsyncSample(
            urlConnectSession != nullptr ? urlConnectSession : session,
            "WebSocket 异步 URL 直连",
            WsConnectVariant::Url,
            WebSocketSecureEchoUrl,
            nullptr,
            results->WebSocketConnectAsync);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket 异步 URL 直连");
        status = RunWebSocketAsyncSample(session, "WebSocket 异步配置连接", WsConnectVariant::Config, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketConfigConnectAsync);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket 异步配置连接");
        status = RunWebSocketAsyncSample(session, "WebSocket 异步 ConnectEx", WsConnectVariant::Ex, WebSocketSecureEchoUrl, &webSocketTls, results->WebSocketConnectAsyncEx);
        MergePublicWebSocketSampleStatus(aggregate, status, "WebSocket 异步 ConnectEx");

        ResetExternalTrustStore(trustStore);
        return aggregate;
    }
}

NTSTATUS RunHighLevelApiSamples(wknet::http::Session* session, HighLevelApiSampleResults* results) noexcept
{
    return RunHighLevelApiSamples(session, ExternalTrustStoreDefaultBundlePath, results);
}

NTSTATUS RunHighLevelApiSamples(
    wknet::http::Session* session,
    const char* certificateBundlePath,
    HighLevelApiSampleResults* results) noexcept
{
    if (session == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};
    wknet::http::SessionConfig defaultConfig = wknet::http::DefaultSessionConfig();
    LogSessionConfig("已有 Session 使用默认配置说明", defaultConfig);
    CaptureStatus(results->SessionDefaultConfig, STATUS_SUCCESS, 1, defaultConfig.MaxResponseBytes);

    wknet::http::SessionConfig customConfig = wknet::http::DefaultSessionConfig();
    customConfig.MaxResponseBytes = 0;
    customConfig.PoolCapacity = 4;
    customConfig.MaxConnsPerHost = 1;
    customConfig.IdleTimeoutMs = 15000;
    customConfig.Tls.HandshakeTimeoutMs = 90000;
    LogSessionConfig("自定义 SessionConfig 写法说明", customConfig);
    CaptureStatus(results->SessionCustomConfig, STATUS_SUCCESS, 1, customConfig.MaxResponseBytes);

    return RunHighLevelApiSamplesOnSession(session, nullptr, certificateBundlePath, results);
}

NTSTATUS RunHighLevelApiSamples(net::WskClient* wskClient, HighLevelApiSampleResults* results) noexcept
{
    return RunHighLevelApiSamples(wskClient, ExternalTrustStoreDefaultBundlePath, results);
}

NTSTATUS RunHighLevelApiSamples(
    net::WskClient* wskClient,
    const char* certificateBundlePath,
    HighLevelApiSampleResults* results) noexcept
{
    if (wskClient == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};
    NTSTATUS aggregate = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    ExternalTrustStore trustStore = {};
    status = InitializeExternalTrustStore(
        trustStore,
        certificateBundlePath != nullptr ? certificateBundlePath : ExternalTrustStoreDefaultBundlePath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    wknet::http::SessionConfig defaultConfig = wknet::http::DefaultSessionConfig();
    defaultConfig.Tls.Store = trustStore.Store;

    wknet::http::Session* session = nullptr;
    status = RunSessionCreateSample(
        wskClient,
        "默认 SessionCreate/SessionClose",
        &defaultConfig,
        results->SessionDefaultConfig,
        &session);
    MergeSampleStatus(aggregate, status);

    if (NT_SUCCESS(status)) {
        status = RunHighLevelApiSamplesOnSession(
            session,
            nullptr,
            certificateBundlePath,
            results);
        MergeSampleStatus(aggregate, status);
        wknet::http::SessionClose(session);
        WKNET_SAMPLE_LOG("[会话示例] 默认会话请求矩阵结束，SessionClose 已调用\r\n");
    }

    wknet::http::SessionConfig customConfig = wknet::http::DefaultSessionConfig();
    customConfig.MaxResponseBytes = 0;
    customConfig.PoolCapacity = 4;
    customConfig.MaxConnsPerHost = 1;
    customConfig.IdleTimeoutMs = 15000;
    customConfig.Tls.HandshakeTimeoutMs = 90000;
    customConfig.Tls.Store = trustStore.Store;
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

#undef WKNET_SAMPLE_LOG
