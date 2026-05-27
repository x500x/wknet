#include "samples/HighLevelApiSamples.h"

#include "samples/ExternalTrustStore.h"
#include "tls/CertificateStore.h"

namespace KernelHttp
{
namespace samples
{
    namespace
    {
        constexpr const char* UserAgentName = "User-Agent";
        constexpr const char* UserAgentValue = "KernelHttp/0.1";
        constexpr const char* AcceptName = "Accept";
        constexpr const char* AcceptValue = "*/*";
        constexpr const char* AcceptEncodingName = "Accept-Encoding";
        constexpr const char* AcceptEncodingValue = "identity";
        constexpr const char* ContentTypeName = "Content-Type";
        constexpr const char* JsonContentType = "application/json";
        constexpr const char* H2Alpn = "h2";
        // DbgPrintEx narrow strings are consumed as the local ANSI code page.
        constexpr const char* SampleStartPrefix = "\xD5\xE2\xCA\xC7 ";
        constexpr const char* SampleStartSuffix = " \xCA\xBE\xC0\xFD";

        constexpr const char* HttpGetUrl = "http://nghttp2.org/httpbin/get";
        constexpr const char* HttpPostUrl = "http://nghttp2.org/httpbin/post";
        constexpr const char* HttpPutUrl = "http://nghttp2.org/httpbin/put";
        constexpr const char* HttpPatchUrl = "http://nghttp2.org/httpbin/patch";
        constexpr const char* HttpDeleteUrl = "http://nghttp2.org/httpbin/delete";
        constexpr const char* HttpHeadUrl = "http://nghttp2.org/httpbin/get";
        constexpr const char* HttpOptionsUrl = "http://nghttp2.org/httpbin/";
        constexpr const char* HttpsGetUrl = "https://nghttp2.org/httpbin/get";
        constexpr const char* HttpsPostUrl = "https://nghttp2.org/httpbin/post";
        constexpr const char* HttpsPutUrl = "https://nghttp2.org/httpbin/put";
        constexpr const char* HttpsPatchUrl = "https://nghttp2.org/httpbin/patch";
        constexpr const char* HttpsDeleteUrl = "https://nghttp2.org/httpbin/delete";
        constexpr const char* HttpsHeadUrl = "https://nghttp2.org/httpbin/get";
        constexpr const char* HttpsOptionsUrl = "https://nghttp2.org/httpbin/";
        constexpr const char* RemoteHttpsAddressFamilyUrl = "https://nghttp2.org/httpbin/get";
        constexpr const char* WebSocketEchoUrl = "wss://ws.postman-echo.com/raw";
        constexpr const char* NgHttp2TlsServerName = "nghttp2.org";
        constexpr SIZE_T NgHttp2TlsServerNameLength = sizeof("nghttp2.org") - 1;
        constexpr const char* WebSocketEchoTlsServerName = "ws.postman-echo.com";
        constexpr SIZE_T WebSocketEchoTlsServerNameLength = sizeof("ws.postman-echo.com") - 1;
        constexpr api::KhAddressFamily DefaultSampleAddressFamily = api::KhAddressFamily::Ipv4;
        constexpr SIZE_T HttpSampleTransientRetryCount = 2;

        constexpr const char* RequestSessionSampleName = "Request & Session";
        constexpr const char* Http11Ipv4GetSampleName = "HTTP/1.1 IPv4 GET";
        constexpr const char* Http11Ipv4GetAsyncSampleName = "HTTP/1.1 IPv4 GET async";
        constexpr const char* Http11Ipv4PostSampleName = "HTTP/1.1 IPv4 POST";
        constexpr const char* Http11Ipv4PutSampleName = "HTTP/1.1 IPv4 PUT";
        constexpr const char* Http11Ipv4PatchSampleName = "HTTP/1.1 IPv4 PATCH";
        constexpr const char* Http11Ipv4DeleteSampleName = "HTTP/1.1 IPv4 DELETE";
        constexpr const char* Http11Ipv4HeadSampleName = "HTTP/1.1 IPv4 HEAD";
        constexpr const char* Http11Ipv4OptionsSampleName = "HTTP/1.1 IPv4 OPTIONS";
        constexpr const char* HttpsVerifyGetSampleName = "HTTPS \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 GET";
        constexpr const char* HttpsVerifyPostSampleName = "HTTPS \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 POST";
        constexpr const char* HttpsVerifyPutSampleName = "HTTPS \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 PUT";
        constexpr const char* HttpsVerifyPatchSampleName = "HTTPS \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 PATCH";
        constexpr const char* HttpsVerifyDeleteSampleName = "HTTPS \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 DELETE";
        constexpr const char* HttpsVerifyHeadSampleName = "HTTPS \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 HEAD";
        constexpr const char* HttpsVerifyOptionsSampleName = "HTTPS \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 OPTIONS";
        constexpr const char* HttpsNoVerifyGetSampleName = "HTTPS \xB2\xBB\xD1\xE9\xD6\xA4\xD6\xA4\xCA\xE9 GET";
        constexpr const char* HttpsNoVerifyPostSampleName = "HTTPS \xB2\xBB\xD1\xE9\xD6\xA4\xD6\xA4\xCA\xE9 POST";
        constexpr const char* HttpsNoVerifyPutSampleName = "HTTPS \xB2\xBB\xD1\xE9\xD6\xA4\xD6\xA4\xCA\xE9 PUT";
        constexpr const char* HttpsNoVerifyPatchSampleName = "HTTPS \xB2\xBB\xD1\xE9\xD6\xA4\xD6\xA4\xCA\xE9 PATCH";
        constexpr const char* HttpsNoVerifyDeleteSampleName = "HTTPS \xB2\xBB\xD1\xE9\xD6\xA4\xD6\xA4\xCA\xE9 DELETE";
        constexpr const char* Http2AlpnSampleName = "HTTP/2 ALPN GET";
        constexpr const char* WebSocketVerifyEchoSampleName = "WebSocket \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 Echo";
        constexpr const char* WebSocketVerifyEchoAsyncSampleName = "WebSocket \xD6\xA4\xCA\xE9\xD1\xE9\xD6\xA4 Echo async";
        constexpr const char* WebSocketNoVerifyEchoSampleName = "WebSocket \xB2\xBB\xD1\xE9\xD6\xA4\xD6\xA4\xCA\xE9 Echo";
        constexpr const char* RemoteHttpsIpv4SampleName = "IPv4 HTTPS GET";
        constexpr const char* RemoteHttpsIpv6SampleName = "IPv6 HTTPS GET";

        _Must_inspect_result_
        SIZE_T LiteralLength(_In_z_ const char* value) noexcept
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

        _Must_inspect_result_
        NTSTATUS MergeSampleStatus(NTSTATUS current, NTSTATUS next) noexcept
        {
            return NT_SUCCESS(current) ? next : current;
        }

        _Must_inspect_result_
        bool IsTransientHttpSampleStatus(NTSTATUS status) noexcept
        {
            return status == STATUS_IO_TIMEOUT ||
                status == STATUS_CONNECTION_DISCONNECTED ||
                status == STATUS_CONNECTION_RESET ||
                status == STATUS_CONNECTION_ABORTED;
        }

        void LogSampleStart(_In_z_ const char* sampleName) noexcept
        {
#if !defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
            UNREFERENCED_PARAMETER(sampleName);
#endif
            kprintf(
                "[high-level sample] %s%s%s\r\n",
                SampleStartPrefix,
                sampleName != nullptr ? sampleName : "unknown",
                SampleStartSuffix);
        }

        struct ExternalTrustStoreBundle final
        {
            ExternalTrustStore TrustStore = {};
        };

        _Ret_maybenull_
        ExternalTrustStoreBundle* AllocateExternalTrustStoreBundle() noexcept
        {
            return new ExternalTrustStoreBundle();
        }

        void ReleaseExternalTrustStoreBundle(_In_opt_ ExternalTrustStoreBundle* bundle) noexcept
        {
            if (bundle != nullptr) {
                ResetExternalTrustStore(bundle->TrustStore);
            }
            delete bundle;
        }

        _Must_inspect_result_
        NTSTATUS SetHeaderLiteral(
            _In_ api::KH_REQUEST request,
            _In_z_ const char* name,
            _In_z_ const char* value) noexcept
        {
            return api::KhHttpRequestSetHeader(
                request,
                name,
                LiteralLength(name),
                value,
                LiteralLength(value));
        }

        _Must_inspect_result_
        NTSTATUS SetCommonHeaders(_In_ api::KH_REQUEST request) noexcept
        {
            NTSTATUS status = SetHeaderLiteral(request, UserAgentName, UserAgentValue);
            if (NT_SUCCESS(status)) {
                status = SetHeaderLiteral(request, AcceptName, AcceptValue);
            }
            if (NT_SUCCESS(status)) {
                status = SetHeaderLiteral(request, AcceptEncodingName, AcceptEncodingValue);
            }
            return status;
        }

        struct ResponseLogContext final
        {
            const char* SampleName = nullptr;
            SIZE_T HeaderCount = 0;
            SIZE_T BodyLength = 0;
            bool BodyLogged = false;
        };

        struct AsyncHttpSampleContext final
        {
            ResponseLogContext ResponseLog = {};
            SIZE_T CompletionCount = 0;
            NTSTATUS CompletionStatus = STATUS_PENDING;
        };

        bool IsPrintableResponseBodyByte(UCHAR value) noexcept
        {
            return value == '\r' ||
                value == '\n' ||
                value == '\t' ||
                (value >= 0x20 && value <= 0x7E);
        }

        void LogSampleBytes(
            _In_z_ const char* sampleName,
            _In_z_ const char* label,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength) noexcept
        {
            if (sampleName == nullptr) {
                sampleName = "unknown";
            }
            if (label == nullptr) {
                label = "bytes";
            }

            kprintf("[high-level %s] %s length=%Iu\r\n", sampleName, label, dataLength);
            if (data == nullptr || dataLength == 0) {
                kprintf("[high-level %s] %s <empty>\r\n", sampleName, label);
                return;
            }

            bool printable = true;
            for (SIZE_T index = 0; index < dataLength; ++index) {
                if (!IsPrintableResponseBodyByte(data[index])) {
                    printable = false;
                    break;
                }
            }

            if (printable) {
                constexpr SIZE_T TextChunkLength = 512;
                for (SIZE_T offset = 0; offset < dataLength; offset += TextChunkLength) {
                    const SIZE_T remaining = dataLength - offset;
                    const SIZE_T chunkLength =
                        remaining < TextChunkLength ? remaining : TextChunkLength;
                    UNREFERENCED_PARAMETER(chunkLength);
                    kprintf(
                        "%.*s",
                        static_cast<int>(chunkLength),
                        reinterpret_cast<const char*>(data + offset));
                }
                kprintf("\r\n");
                return;
            }

            constexpr SIZE_T HexBytesPerLine = 16;
            for (SIZE_T offset = 0; offset < dataLength; offset += HexBytesPerLine) {
                const SIZE_T remaining = dataLength - offset;
                const SIZE_T lineLength =
                    remaining < HexBytesPerLine ? remaining : HexBytesPerLine;
                kprintf("[high-level %s] %s-hex %Iu:", sampleName, label, offset);
                for (SIZE_T byteIndex = 0; byteIndex < lineLength; ++byteIndex) {
                    kprintf(" %02X", static_cast<unsigned>(data[offset + byteIndex]));
                }
                kprintf("\r\n");
            }
        }

        _Must_inspect_result_
        NTSTATUS LogResponseHeaderCallback(
            void* context,
            const char* name,
            SIZE_T nameLength,
            const char* value,
            SIZE_T valueLength) noexcept
        {
#if !defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
            UNREFERENCED_PARAMETER(name);
            UNREFERENCED_PARAMETER(nameLength);
            UNREFERENCED_PARAMETER(value);
            UNREFERENCED_PARAMETER(valueLength);
#endif
            auto* logContext = static_cast<ResponseLogContext*>(context);
            if (logContext != nullptr) {
                ++logContext->HeaderCount;
            }

            kprintf(
                "[high-level %s] response-header %.*s: %.*s\r\n",
                logContext != nullptr && logContext->SampleName != nullptr ? logContext->SampleName : "unknown",
                static_cast<int>(nameLength),
                name != nullptr ? name : "",
                static_cast<int>(valueLength),
                value != nullptr ? value : "");
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS LogResponseBodyCallback(
            void* context,
            const UCHAR* data,
            SIZE_T dataLength,
            bool finalChunk) noexcept
        {
            UNREFERENCED_PARAMETER(finalChunk);

            auto* logContext = static_cast<ResponseLogContext*>(context);
            const char* sampleName =
                logContext != nullptr && logContext->SampleName != nullptr ?
                logContext->SampleName :
                "unknown";

            if (logContext != nullptr) {
                logContext->BodyLength += dataLength;
                logContext->BodyLogged = true;
            }

            LogSampleBytes(sampleName, "response-body", data, dataLength);
            return STATUS_SUCCESS;
        }

        void LogAsyncCompletionCallback(
            void* context,
            api::KH_ASYNC_OPERATION operation,
            NTSTATUS status) noexcept
        {
            UNREFERENCED_PARAMETER(operation);

            auto* asyncContext = static_cast<AsyncHttpSampleContext*>(context);
            if (asyncContext == nullptr) {
                return;
            }

            ++asyncContext->CompletionCount;
            asyncContext->CompletionStatus = status;
        }

        void LogHttpSampleResult(_In_z_ const char* sampleName, const HighLevelApiSampleResult& result) noexcept
        {
#if !defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
            UNREFERENCED_PARAMETER(sampleName);
#endif
            if (NT_SUCCESS(result.Status)) {
                kprintf(
                    "[high-level %s] status=%u bodyLength=%Iu\r\n",
                    sampleName,
                    result.StatusCode,
                    result.BodyLength);
            }
            else {
                kprintf(
                    "[high-level %s] failed: 0x%08X status=%u bodyLength=%Iu\r\n",
                    sampleName,
                    static_cast<ULONG>(result.Status),
                    result.StatusCode,
                    result.BodyLength);
            }
        }

        void LogWebSocketSampleResult(_In_z_ const char* sampleName, const HighLevelApiSampleResult& result) noexcept
        {
#if !defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
            UNREFERENCED_PARAMETER(sampleName);
#endif
            if (NT_SUCCESS(result.Status)) {
                kprintf(
                    "[high-level %s] echoLength=%Iu\r\n",
                    sampleName,
                    result.BodyLength);
            }
            else {
                kprintf(
                    "[high-level %s] failed: 0x%08X echoLength=%Iu\r\n",
                    sampleName,
                    static_cast<ULONG>(result.Status),
                    result.BodyLength);
            }
        }

        _Must_inspect_result_
        NTSTATUS PrepareHttpRequest(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_opt_ const api::KhTlsOptions* tlsOptions,
            api::KhConnectionPolicy connectionPolicy,
            api::KhAddressFamily addressFamily,
            _Out_ api::KH_REQUEST* request) noexcept
        {
            if (session == nullptr || sampleName == nullptr || url == nullptr || request == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *request = nullptr;

            NTSTATUS status = api::KhHttpRequestCreate(session, request);
            if (NT_SUCCESS(status)) {
                status = api::KhHttpRequestSetUrl(*request, url, LiteralLength(url));
            }
            if (NT_SUCCESS(status)) {
                status = api::KhHttpRequestSetMethod(*request, method);
            }
            if (NT_SUCCESS(status)) {
                status = SetCommonHeaders(*request);
            }
            if (NT_SUCCESS(status) && tlsOptions != nullptr) {
                status = api::KhHttpRequestSetTlsOptions(*request, tlsOptions);
            }
            if (NT_SUCCESS(status) && connectionPolicy != api::KhConnectionPolicy::ReuseOrCreate) {
                status = api::KhHttpRequestSetConnectionPolicy(*request, connectionPolicy);
            }
            if (NT_SUCCESS(status) && addressFamily != api::KhAddressFamily::Any) {
                status = api::KhHttpRequestSetAddressFamily(*request, addressFamily);
            }

            if (!NT_SUCCESS(status)) {
                api::KhHttpRequestRelease(*request);
                *request = nullptr;
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS SendPreparedHttpRequest(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            _In_ api::KH_REQUEST request,
            _Out_ HighLevelApiSampleResult* result,
            bool logFailure) noexcept
        {
            if (session == nullptr || sampleName == nullptr || request == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};
            ResponseLogContext logContext = {};
            logContext.SampleName = sampleName;

            api::KhHttpSendOptions sendOptions = {};
            sendOptions.HeaderCallback = LogResponseHeaderCallback;
            sendOptions.BodyCallback = LogResponseBodyCallback;
            sendOptions.CallbackContext = &logContext;
            sendOptions.Flags = api::KhHttpSendFlagAggregateWithCallbacks;

            api::KH_RESPONSE response = nullptr;
            NTSTATUS status = api::KhHttpSendSync(session, request, &sendOptions, &response);

            if (NT_SUCCESS(status)) {
                api::KhResponseView view = {};
                status = api::KhResponseGetView(response, &view);
                if (NT_SUCCESS(status)) {
                    result->StatusCode = view.StatusCode;
                    result->BodyLength = view.BodyLength;
                    kprintf(
                        "[high-level %s] response-complete status=%u headers=%Iu body=%Iu\r\n",
                        sampleName,
                        result->StatusCode,
                        logContext.HeaderCount,
                        result->BodyLength);
                }
            }

            api::KhResponseRelease(response);
            result->Status = status;
            if (NT_SUCCESS(status) || logFailure) {
                LogHttpSampleResult(sampleName, *result);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS SendPreparedHttpRequestAsync(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            _In_ api::KH_REQUEST request,
            _Out_ HighLevelApiSampleResult* result,
            bool logFailure) noexcept
        {
            if (session == nullptr || sampleName == nullptr || request == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};

            auto* asyncContext = new AsyncHttpSampleContext();
            if (asyncContext == nullptr) {
                result->Status = STATUS_INSUFFICIENT_RESOURCES;
                LogHttpSampleResult(sampleName, *result);
                return result->Status;
            }
            asyncContext->ResponseLog.SampleName = sampleName;

            api::KhHttpSendOptions sendOptions = {};
            sendOptions.HeaderCallback = LogResponseHeaderCallback;
            sendOptions.BodyCallback = LogResponseBodyCallback;
            sendOptions.CallbackContext = &asyncContext->ResponseLog;
            sendOptions.Flags = api::KhHttpSendFlagAggregateWithCallbacks;
            sendOptions.CompletionCallback = LogAsyncCompletionCallback;
            sendOptions.CompletionContext = asyncContext;

            api::KH_ASYNC_OPERATION operation = nullptr;
            NTSTATUS status = api::KhHttpSendAsync(session, request, &sendOptions, &operation);
            if (NT_SUCCESS(status)) {
                status = api::KhAsyncWait(operation, 0xffffffffUL);
            }

            api::KH_RESPONSE response = nullptr;
            if (NT_SUCCESS(status)) {
                status = api::KhAsyncGetHttpResponse(operation, &response);
            }

            if (NT_SUCCESS(status)) {
                api::KhResponseView view = {};
                status = api::KhResponseGetView(response, &view);
                if (NT_SUCCESS(status)) {
                    result->StatusCode = view.StatusCode;
                    result->BodyLength = view.BodyLength;
                    kprintf(
                        "[high-level %s] async-response-complete status=%u headers=%Iu body=%Iu completions=%Iu completionStatus=0x%08X\r\n",
                        sampleName,
                        result->StatusCode,
                        asyncContext->ResponseLog.HeaderCount,
                        result->BodyLength,
                        asyncContext->CompletionCount,
                        static_cast<ULONG>(asyncContext->CompletionStatus));
                }
            }

            api::KhResponseRelease(response);
            api::KhAsyncRelease(operation);
            result->Status = status;
            delete asyncContext;
            if (NT_SUCCESS(status) || logFailure) {
                LogHttpSampleResult(sampleName, *result);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunHttpSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _In_opt_ const api::KhTlsOptions* tlsOptions,
            api::KhConnectionPolicy connectionPolicy,
            api::KhAddressFamily addressFamily,
            bool logSampleStart,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (session == nullptr || sampleName == nullptr || url == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};

            if (logSampleStart) {
                LogSampleStart(sampleName);
            }

            // Request sample: create a KH_REQUEST, set URL/method/common headers,
            // then apply optional TLS, connection policy, address family and body.
            api::KH_REQUEST request = nullptr;
            NTSTATUS status = PrepareHttpRequest(
                session,
                sampleName,
                method,
                url,
                tlsOptions,
                connectionPolicy,
                addressFamily,
                &request);
            if (NT_SUCCESS(status) && bodyLength != 0) {
                status = SetHeaderLiteral(request, ContentTypeName, JsonContentType);
            }
            if (NT_SUCCESS(status) && (body != nullptr || bodyLength != 0)) {
                status = api::KhHttpRequestSetBody(request, body, bodyLength);
            }
            bool sent = false;
            if (NT_SUCCESS(status)) {
                for (SIZE_T attempt = 0; attempt <= HttpSampleTransientRetryCount; ++attempt) {
                    sent = true;
                    status = SendPreparedHttpRequest(session, sampleName, request, result, false);
                    if (!IsTransientHttpSampleStatus(status) || attempt == HttpSampleTransientRetryCount) {
                        break;
                    }

                    kprintf(
                        "[high-level %s] transient transport status 0x%08X, retrying attempt %Iu/%Iu\r\n",
                        sampleName,
                        static_cast<ULONG>(status),
                        attempt + 1,
                        HttpSampleTransientRetryCount);
                }
            }

            api::KhHttpRequestRelease(request);
            if (!sent) {
                result->Status = status;
                LogHttpSampleResult(sampleName, *result);
            }
            else if (!NT_SUCCESS(status)) {
                LogHttpSampleResult(sampleName, *result);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunHttpAddressFamilySample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_opt_ const api::KhTlsOptions* tlsOptions,
            api::KhAddressFamily addressFamily,
            bool logSampleStart,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (session == nullptr || sampleName == nullptr || url == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};

            if (logSampleStart) {
                LogSampleStart(sampleName);
            }

            // IPv4/IPv6 sample: force address-family resolution on a fresh request
            // so the transport path cannot silently reuse an existing connection.
            api::KH_REQUEST request = nullptr;
            NTSTATUS status = PrepareHttpRequest(
                session,
                sampleName,
                method,
                url,
                tlsOptions,
                api::KhConnectionPolicy::ForceNew,
                addressFamily,
                &request);

            bool sent = false;
            if (NT_SUCCESS(status)) {
                for (SIZE_T attempt = 0; attempt <= HttpSampleTransientRetryCount; ++attempt) {
                    sent = true;
                    status = SendPreparedHttpRequest(session, sampleName, request, result, false);
                    if (!IsTransientHttpSampleStatus(status) || attempt == HttpSampleTransientRetryCount) {
                        break;
                    }

                    kprintf(
                        "[high-level %s] transient transport status 0x%08X, retrying attempt %Iu/%Iu\r\n",
                        sampleName,
                        static_cast<ULONG>(status),
                        attempt + 1,
                        HttpSampleTransientRetryCount);
                }
            }

            api::KhHttpRequestRelease(request);
            if (!sent) {
                result->Status = status;
                LogHttpSampleResult(sampleName, *result);
            }
            else if (!NT_SUCCESS(status)) {
                LogHttpSampleResult(sampleName, *result);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunHttpAsyncSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _In_opt_ const api::KhTlsOptions* tlsOptions,
            api::KhConnectionPolicy connectionPolicy,
            api::KhAddressFamily addressFamily,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (session == nullptr || sampleName == nullptr || url == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};

            LogSampleStart(sampleName);

            // Async request sample: build the same KH_REQUEST shape as sync HTTP,
            // submit it through KhHttpSendAsync, then wait and read the response.
            api::KH_REQUEST request = nullptr;
            NTSTATUS status = PrepareHttpRequest(
                session,
                sampleName,
                method,
                url,
                tlsOptions,
                connectionPolicy,
                addressFamily,
                &request);
            if (NT_SUCCESS(status) && bodyLength != 0) {
                status = SetHeaderLiteral(request, ContentTypeName, JsonContentType);
            }
            if (NT_SUCCESS(status) && (body != nullptr || bodyLength != 0)) {
                status = api::KhHttpRequestSetBody(request, body, bodyLength);
            }
            bool sent = false;
            if (NT_SUCCESS(status)) {
                for (SIZE_T attempt = 0; attempt <= HttpSampleTransientRetryCount; ++attempt) {
                    sent = true;
                    status = SendPreparedHttpRequestAsync(session, sampleName, request, result, false);
                    if (!IsTransientHttpSampleStatus(status) || attempt == HttpSampleTransientRetryCount) {
                        break;
                    }

                    kprintf(
                        "[high-level %s] transient async transport status 0x%08X, retrying attempt %Iu/%Iu\r\n",
                        sampleName,
                        static_cast<ULONG>(status),
                        attempt + 1,
                        HttpSampleTransientRetryCount);
                }
            }

            api::KhHttpRequestRelease(request);
            if (!sent) {
                result->Status = status;
                LogHttpSampleResult(sampleName, *result);
            }
            else if (!NT_SUCCESS(status)) {
                LogHttpSampleResult(sampleName, *result);
            }
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunVerifiedNgHttp2Sample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            bool forceHttp2Alpn,
            api::KhAddressFamily addressFamily,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (sampleName != nullptr) {
                LogSampleStart(sampleName);
            }

            ExternalTrustStoreBundle* trustBundle = AllocateExternalTrustStoreBundle();
            if (trustBundle == nullptr) {
                if (result != nullptr) {
                    *result = {};
                    result->Status = STATUS_INSUFFICIENT_RESOURCES;
                }
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = InitializeExternalTrustStore(trustBundle->TrustStore);
            if (!NT_SUCCESS(status)) {
                if (result != nullptr) {
                    *result = {};
                    result->Status = status;
                }
                ReleaseExternalTrustStoreBundle(trustBundle);
                return status;
            }

            api::KhTlsOptions tlsOptions = {};
            tlsOptions.CertificateStore = &trustBundle->TrustStore.Store;
            tlsOptions.CertificatePolicy = api::KhCertificatePolicy::Verify;
            if (forceHttp2Alpn) {
                tlsOptions.Alpn = H2Alpn;
                tlsOptions.AlpnLength = sizeof("h2") - 1;
            }

            status = RunHttpSample(
                session,
                sampleName,
                method,
                url,
                body,
                bodyLength,
                &tlsOptions,
                api::KhConnectionPolicy::ForceNew,
                addressFamily,
                false,
                result);
            ReleaseExternalTrustStoreBundle(trustBundle);
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunNoVerifyHttpsSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhHttpMethod method,
            _In_z_ const char* url,
            _In_reads_bytes_opt_(bodyLength) const UCHAR* body,
            SIZE_T bodyLength,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (sampleName != nullptr) {
                LogSampleStart(sampleName);
            }

            api::KhTlsOptions tlsOptions = {};
            tlsOptions.CertificatePolicy = api::KhCertificatePolicy::NoVerify;
            return RunHttpSample(
                session,
                sampleName,
                method,
                url,
                body,
                bodyLength,
                &tlsOptions,
                api::KhConnectionPolicy::ForceNew,
                api::KhAddressFamily::Ipv4,
                false,
                result);
        }

        const char* WebSocketMessageTypeName(api::KhWebSocketMessageType type) noexcept
        {
            switch (type) {
            case api::KhWebSocketMessageType::Text:
                return "text";
            case api::KhWebSocketMessageType::Binary:
                return "binary";
            case api::KhWebSocketMessageType::Close:
                return "close";
            default:
                return "unknown";
            }
        }

        void LogWebSocketMessage(
            _In_z_ const char* sampleName,
            _In_z_ const char* direction,
            api::KhWebSocketMessageType type,
            _In_reads_bytes_opt_(dataLength) const UCHAR* data,
            SIZE_T dataLength,
            bool finalFragment) noexcept
        {
#if !defined(DBG) && !defined(KERNEL_HTTP_USER_MODE_TEST)
            UNREFERENCED_PARAMETER(type);
            UNREFERENCED_PARAMETER(finalFragment);
#endif
            kprintf(
                "[high-level %s] websocket-%s type=%s final=%s\r\n",
                sampleName,
                direction,
                WebSocketMessageTypeName(type),
                finalFragment ? "true" : "false");

            if (direction != nullptr && direction[0] == 's') {
                LogSampleBytes(sampleName, "websocket-send-body", data, dataLength);
            }
            else {
                LogSampleBytes(sampleName, "websocket-recv-body", data, dataLength);
            }
        }

        _Must_inspect_result_
        NTSTATUS ReceiveExpectedWebSocketMessage(
            _In_ api::KH_WEBSOCKET websocket,
            _In_z_ const char* sampleName,
            api::KhWebSocketMessageType expectedType,
            _In_reads_bytes_(expectedDataLength) const UCHAR* expectedData,
            SIZE_T expectedDataLength,
            _Out_ SIZE_T* receivedLength) noexcept
        {
            if (websocket == nullptr || sampleName == nullptr || receivedLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *receivedLength = 0;
            constexpr SIZE_T MaxFramesBeforeEcho = 8;
            for (SIZE_T frameIndex = 0; frameIndex < MaxFramesBeforeEcho; ++frameIndex) {
                api::KhWebSocketMessage received = {};
                NTSTATUS status = api::KhWebSocketReceiveSync(websocket, nullptr, &received);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                LogWebSocketMessage(
                    sampleName,
                    "recv",
                    received.Type,
                    received.Data,
                    received.DataLength,
                    received.FinalFragment);

                if (received.Type == api::KhWebSocketMessageType::Close) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                if (received.Type == expectedType &&
                    received.DataLength == expectedDataLength &&
                    (expectedDataLength == 0 ||
                        (received.Data != nullptr &&
                            expectedData != nullptr &&
                            RtlCompareMemory(received.Data, expectedData, expectedDataLength) == expectedDataLength))) {
                    *receivedLength = received.DataLength;
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        _Must_inspect_result_
        NTSTATUS ConnectWebSocketForSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            _In_ const api::KhWebSocketConnectOptions& connectOptions,
            bool connectAsync,
            _Out_ api::KH_WEBSOCKET* websocket) noexcept
        {
            if (session == nullptr || sampleName == nullptr || websocket == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *websocket = nullptr;
            if (!connectAsync) {
                return api::KhWebSocketConnectSync(session, &connectOptions, websocket);
            }

            api::KH_ASYNC_OPERATION operation = nullptr;
            NTSTATUS status = api::KhWebSocketConnectAsync(session, &connectOptions, &operation);
            if (NT_SUCCESS(status)) {
                status = api::KhAsyncWait(operation, 0xffffffffUL);
            }
            if (NT_SUCCESS(status)) {
                status = api::KhAsyncGetWebSocket(operation, websocket);
            }

            kprintf(
                "[high-level %s] websocket-async-connect status=0x%08X\r\n",
                sampleName,
                static_cast<ULONG>(status));

            api::KhAsyncRelease(operation);
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunWebSocketEchoSample(
            _In_ api::KH_SESSION session,
            _In_z_ const char* sampleName,
            bool verifyCertificate,
            bool connectAsync,
            _Out_ HighLevelApiSampleResult* result) noexcept
        {
            if (session == nullptr || result == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *result = {};

            LogSampleStart(sampleName);

            // WebSocket sample: connect through the high-level API, send one text
            // message, skip any server banner frames, and require the echoed text.
            ExternalTrustStoreBundle* trustBundle = nullptr;
            api::KhTlsOptions tlsOptions = {};
            if (verifyCertificate) {
                trustBundle = AllocateExternalTrustStoreBundle();
                if (trustBundle == nullptr) {
                    result->Status = STATUS_INSUFFICIENT_RESOURCES;
                    return result->Status;
                }

                NTSTATUS status = InitializeExternalTrustStore(trustBundle->TrustStore);
                if (!NT_SUCCESS(status)) {
                    result->Status = status;
                    ReleaseExternalTrustStoreBundle(trustBundle);
                    return status;
                }
                tlsOptions.CertificateStore = &trustBundle->TrustStore.Store;
                tlsOptions.CertificatePolicy = api::KhCertificatePolicy::Verify;
            }
            else {
                tlsOptions.CertificatePolicy = api::KhCertificatePolicy::NoVerify;
            }
            tlsOptions.MinVersion = api::KhTlsVersion::Tls12;
            tlsOptions.MaxVersion = api::KhTlsVersion::Tls12;

            api::KhWebSocketConnectOptions connectOptions = {};
            connectOptions.Url = WebSocketEchoUrl;
            connectOptions.UrlLength = LiteralLength(WebSocketEchoUrl);
            connectOptions.Tls = tlsOptions;
            connectOptions.AddressFamily = api::KhAddressFamily::Ipv4;
            connectOptions.MaxMessageBytes = 4096;
            connectOptions.AutoReplyPing = true;

            api::KH_WEBSOCKET websocket = nullptr;
            NTSTATUS status = ConnectWebSocketForSample(
                session,
                sampleName,
                connectOptions,
                connectAsync,
                &websocket);

            const char textMessage[] = "kernel-http high-level websocket echo";
            if (NT_SUCCESS(status)) {
                LogWebSocketMessage(
                    sampleName,
                    "send",
                    api::KhWebSocketMessageType::Text,
                    reinterpret_cast<const UCHAR*>(textMessage),
                    sizeof(textMessage) - 1,
                    true);
                status = api::KhWebSocketSendTextSync(websocket, textMessage, sizeof(textMessage) - 1, nullptr);
            }

            SIZE_T receivedLength = 0;
            if (NT_SUCCESS(status)) {
                status = ReceiveExpectedWebSocketMessage(
                    websocket,
                    sampleName,
                    api::KhWebSocketMessageType::Text,
                    reinterpret_cast<const UCHAR*>(textMessage),
                    sizeof(textMessage) - 1,
                    &receivedLength);
                if (NT_SUCCESS(status)) {
                    result->BodyLength += receivedLength;
                }
            }

            const NTSTATUS closeStatus = api::KhWebSocketCloseSync(websocket);
            UNREFERENCED_PARAMETER(closeStatus);
            ReleaseExternalTrustStoreBundle(trustBundle);

            result->Status = status;
            LogWebSocketSampleResult(sampleName, *result);
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunHighLevelRemoteHttpsAddressFamilySample(
            api::KH_SESSION session,
            _In_z_ const char* sampleName,
            api::KhAddressFamily addressFamily,
            HighLevelApiSampleResult* result) noexcept
        {
            if (sampleName != nullptr) {
                LogSampleStart(sampleName);
            }

            ExternalTrustStoreBundle* trustBundle = AllocateExternalTrustStoreBundle();
            if (trustBundle == nullptr) {
                if (result != nullptr) {
                    *result = {};
                    result->Status = STATUS_INSUFFICIENT_RESOURCES;
                }
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            NTSTATUS status = InitializeExternalTrustStore(trustBundle->TrustStore);
            if (!NT_SUCCESS(status)) {
                if (result != nullptr) {
                    *result = {};
                    result->Status = status;
                }
                ReleaseExternalTrustStoreBundle(trustBundle);
                return status;
            }

            api::KhTlsOptions tlsOptions = {};
            tlsOptions.CertificateStore = &trustBundle->TrustStore.Store;
            tlsOptions.CertificatePolicy = api::KhCertificatePolicy::Verify;

            status = RunHttpAddressFamilySample(
                session,
                sampleName,
                api::KhHttpMethod::Get,
                RemoteHttpsAddressFamilyUrl,
                &tlsOptions,
                addressFamily,
                false,
                result);
            ReleaseExternalTrustStoreBundle(trustBundle);
            return status;
        }

        _Must_inspect_result_
        NTSTATUS RunHighLevelRemoteHttpsAddressFamilySamples(
            api::KH_SESSION session,
            HighLevelApiSampleResults* results) noexcept
        {
            if (session == nullptr || results == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *results = {};

            NTSTATUS status = RunHighLevelRemoteHttpsAddressFamilySample(
                session,
                RemoteHttpsIpv4SampleName,
                api::KhAddressFamily::Ipv4,
                &results->RemoteHttpsIpv4);

            status = MergeSampleStatus(
                status,
                RunHighLevelRemoteHttpsAddressFamilySample(
                    session,
                    RemoteHttpsIpv6SampleName,
                    api::KhAddressFamily::Ipv6,
                    &results->RemoteHttpsIpv6));

            return status;
        }
    }

    NTSTATUS RunHighLevelRemoteHttpsAddressFamilySample(
        api::KH_SESSION session,
        HighLevelApiSampleResults* results) noexcept
    {
        return RunHighLevelRemoteHttpsAddressFamilySamples(session, results);
    }

    NTSTATUS RunHighLevelApiSamples(
        api::KH_SESSION session,
        HighLevelApiSampleResults* results) noexcept
    {
        if (session == nullptr || results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *results = {};

        const UCHAR postBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"POST\"}";
        const UCHAR putBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"PUT\"}";
        const UCHAR patchBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"PATCH\"}";
        const UCHAR httpsPostBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS POST\"}";
        const UCHAR httpsPutBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS PUT\"}";
        const UCHAR httpsPatchBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS PATCH\"}";

        // Session sample: DriverEntry creates KH_SESSION once, then this runner
        // reuses it across HTTP, HTTPS, HTTP/2, IPv4/IPv6 and WebSocket examples.
        LogSampleStart(RequestSessionSampleName);

        // HTTP/1.1 IPv4 samples: plain http:// requests through the high-level API.
        // GET/POST demonstrate pooled reuse; mutating verbs force fresh sends.
        NTSTATUS status = RunHttpSample(
            session,
            Http11Ipv4GetSampleName,
            api::KhHttpMethod::Get,
            HttpGetUrl,
            nullptr,
            0,
            nullptr,
            api::KhConnectionPolicy::ReuseOrCreate,
            DefaultSampleAddressFamily,
            true,
            &results->HttpGet);

        status = MergeSampleStatus(
            status,
            RunHttpAsyncSample(
                session,
                Http11Ipv4GetAsyncSampleName,
                api::KhHttpMethod::Get,
                HttpGetUrl,
                nullptr,
                0,
                nullptr,
                api::KhConnectionPolicy::ReuseOrCreate,
                DefaultSampleAddressFamily,
                &results->HttpGetAsync));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                Http11Ipv4PostSampleName,
                api::KhHttpMethod::Post,
                HttpPostUrl,
                postBody,
                sizeof(postBody) - 1,
                nullptr,
                api::KhConnectionPolicy::ReuseOrCreate,
                DefaultSampleAddressFamily,
                true,
                &results->HttpPost));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                Http11Ipv4PutSampleName,
                api::KhHttpMethod::Put,
                HttpPutUrl,
                putBody,
                sizeof(putBody) - 1,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                DefaultSampleAddressFamily,
                true,
                &results->HttpPut));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                Http11Ipv4PatchSampleName,
                api::KhHttpMethod::Patch,
                HttpPatchUrl,
                patchBody,
                sizeof(patchBody) - 1,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                DefaultSampleAddressFamily,
                true,
                &results->HttpPatch));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                Http11Ipv4DeleteSampleName,
                api::KhHttpMethod::Delete,
                HttpDeleteUrl,
                nullptr,
                0,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                DefaultSampleAddressFamily,
                true,
                &results->HttpDelete));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                Http11Ipv4HeadSampleName,
                api::KhHttpMethod::Head,
                HttpHeadUrl,
                nullptr,
                0,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                DefaultSampleAddressFamily,
                true,
                &results->HttpHead));

        status = MergeSampleStatus(
            status,
            RunHttpSample(
                session,
                Http11Ipv4OptionsSampleName,
                api::KhHttpMethod::Options,
                HttpOptionsUrl,
                nullptr,
                0,
                nullptr,
                api::KhConnectionPolicy::ForceNew,
                DefaultSampleAddressFamily,
                true,
                &results->HttpOptions));

        // HTTPS certificate-verification samples: initialize the external CA bundle
        // and pass explicit verify TLS options into each request.
        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                HttpsVerifyGetSampleName,
                api::KhHttpMethod::Get,
                HttpsGetUrl,
                nullptr,
                0,
                false,
                DefaultSampleAddressFamily,
                &results->HttpsTlsOptions));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                HttpsVerifyPostSampleName,
                api::KhHttpMethod::Post,
                HttpsPostUrl,
                httpsPostBody,
                sizeof(httpsPostBody) - 1,
                false,
                DefaultSampleAddressFamily,
                &results->HttpsPost));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                HttpsVerifyPutSampleName,
                api::KhHttpMethod::Put,
                HttpsPutUrl,
                httpsPutBody,
                sizeof(httpsPutBody) - 1,
                false,
                DefaultSampleAddressFamily,
                &results->HttpsPut));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                HttpsVerifyPatchSampleName,
                api::KhHttpMethod::Patch,
                HttpsPatchUrl,
                httpsPatchBody,
                sizeof(httpsPatchBody) - 1,
                false,
                DefaultSampleAddressFamily,
                &results->HttpsPatch));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                HttpsVerifyDeleteSampleName,
                api::KhHttpMethod::Delete,
                HttpsDeleteUrl,
                nullptr,
                0,
                false,
                DefaultSampleAddressFamily,
                &results->HttpsDelete));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                HttpsVerifyHeadSampleName,
                api::KhHttpMethod::Head,
                HttpsHeadUrl,
                nullptr,
                0,
                false,
                DefaultSampleAddressFamily,
                &results->HttpsHead));

        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                HttpsVerifyOptionsSampleName,
                api::KhHttpMethod::Options,
                HttpsOptionsUrl,
                nullptr,
                0,
                false,
                DefaultSampleAddressFamily,
                &results->HttpsOptions));

        // HTTP/2 sample: set ALPN to h2 so HTTPS negotiation selects the HTTP/2
        // client path instead of HTTP/1.1 over TLS.
        status = MergeSampleStatus(
            status,
            RunVerifiedNgHttp2Sample(
                session,
                Http2AlpnSampleName,
                api::KhHttpMethod::Get,
                HttpsGetUrl,
                nullptr,
                0,
                true,
                DefaultSampleAddressFamily,
                &results->Http2Alpn));

        // WebSocket samples: connect to a TLS echo endpoint, send one text message,
        // skip any server banner frames, and require the echoed payload.
        status = MergeSampleStatus(
            status,
            RunWebSocketEchoSample(
                session,
                WebSocketVerifyEchoSampleName,
                true,
                false,
                &results->WebSocketEcho));

        status = MergeSampleStatus(
            status,
            RunWebSocketEchoSample(
                session,
                WebSocketVerifyEchoAsyncSampleName,
                true,
                true,
                &results->WebSocketEchoAsync));

        // IPv4/IPv6 samples: force each address family against the same verified
        // HTTPS endpoint so resolution and connect behavior are both covered.
        HighLevelApiSampleResults remoteHttpsAddressFamilyResults = {};
        status = MergeSampleStatus(
            status,
            RunHighLevelRemoteHttpsAddressFamilySample(session, &remoteHttpsAddressFamilyResults));
        results->RemoteHttpsIpv4 = remoteHttpsAddressFamilyResults.RemoteHttpsIpv4;
        results->RemoteHttpsIpv6 = remoteHttpsAddressFamilyResults.RemoteHttpsIpv6;

        return status;
    }

    NTSTATUS RunHighLevelApiTestDriverSamples(
        api::KH_SESSION session,
        HighLevelApiSampleResults* results) noexcept
    {
        if (session == nullptr || results == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = RunHighLevelApiSamples(session, results);

        const UCHAR httpsPostBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS POST\"}";
        const UCHAR httpsPutBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS PUT\"}";
        const UCHAR httpsPatchBody[] = "{\"source\":\"kernel-http\",\"api\":\"high-level\",\"method\":\"HTTPS PATCH\"}";

        // HTTPS no-verify samples: explicit test-driver-only coverage for callers
        // that choose KhCertificatePolicy::NoVerify. This is not an implicit retry.
        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                HttpsNoVerifyGetSampleName,
                api::KhHttpMethod::Get,
                HttpsGetUrl,
                nullptr,
                0,
                &results->HttpsNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                HttpsNoVerifyPostSampleName,
                api::KhHttpMethod::Post,
                HttpsPostUrl,
                httpsPostBody,
                sizeof(httpsPostBody) - 1,
                &results->HttpsPostNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                HttpsNoVerifyPutSampleName,
                api::KhHttpMethod::Put,
                HttpsPutUrl,
                httpsPutBody,
                sizeof(httpsPutBody) - 1,
                &results->HttpsPutNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                HttpsNoVerifyPatchSampleName,
                api::KhHttpMethod::Patch,
                HttpsPatchUrl,
                httpsPatchBody,
                sizeof(httpsPatchBody) - 1,
                &results->HttpsPatchNoVerify));

        status = MergeSampleStatus(
            status,
            RunNoVerifyHttpsSample(
                session,
                HttpsNoVerifyDeleteSampleName,
                api::KhHttpMethod::Delete,
                HttpsDeleteUrl,
                nullptr,
                0,
                &results->HttpsDeleteNoVerify));

        status = MergeSampleStatus(
            status,
            RunWebSocketEchoSample(
                session,
                WebSocketNoVerifyEchoSampleName,
                false,
                false,
                &results->WebSocketEchoNoVerify));

        return status;
    }
}
}
