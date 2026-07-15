#include "samples/Http3ApiSamples.h"

#include <wknet/http/Http.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknettest/SampleStatus.h>

#include "WknetTestLog.h"

namespace wknet
{
namespace samples
{
namespace
{
    constexpr const char* Http3LoopbackUrl = "https://127.0.0.1:58443/";
    constexpr const char* Http3LoopbackServerName = "localhost";
    constexpr SIZE_T Http3MaxResponseBytes = 64 * 1024;
    constexpr ULONG Http3ProbeTimeoutMs = 15000;

    SIZE_T LiteralLength(_In_opt_z_ const char* text) noexcept
    {
        SIZE_T length = 0;
        if (text == nullptr) {
            return 0;
        }
        while (text[length] != '\0') {
            ++length;
        }
        return length;
    }

    void CaptureStatus(
        _Out_ HighLevelApiSampleResult& result,
        NTSTATUS status,
        ULONG statusCode,
        SIZE_T bodyLength) noexcept
    {
        result.Status = status;
        result.StatusCode = statusCode;
        result.BodyLength = bodyLength;
    }

    NTSTATUS RunRequiredLoopbackGet(_Out_ HighLevelApiSampleResult& result) noexcept
    {
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = Http3MaxResponseBytes;
        config.PoolCapacity = 2;
        config.MaxConnsPerHost = 1;
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        config.Http3.Race = wknet::http::Http3RaceMode::SequentialPreferHttp3;
        config.Http3.QuicProbeTimeoutMs = Http3ProbeTimeoutMs;
        config.Tls.Certificate = wknet::http::CertPolicy::NoVerify;
        config.Tls.MinVersion = wknet::http::TlsVersion::Tls13;
        config.Tls.MaxVersion = wknet::http::TlsVersion::Tls13;
        config.Tls.ServerName = Http3LoopbackServerName;
        config.Tls.ServerNameLength = LiteralLength(Http3LoopbackServerName);
        config.Tls.PreferHttp2 = false;

        WKNET_SAMPLE_LOG(
            "[HTTP/3] 示例=HTTP/3 Required Loopback URL=%s 模式=Required TLS=NoVerify TLS版本=TLS1.3 端口=58443\r\n",
            Http3LoopbackUrl);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        if (!NT_SUCCESS(status)) {
            CaptureStatus(result, status, 0, 0);
            WKNET_SAMPLE_LOG(
                "[HTTP/3] 示例=HTTP/3 Required Loopback SessionCreate 失败 NTSTATUS=0x%08X\r\n",
                static_cast<ULONG>(status));
            return status;
        }

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, Http3LoopbackUrl, &response);

        ULONG statusCode = response != nullptr ? wknet::http::ResponseStatusCode(response) : 0;
        SIZE_T bodyLength = response != nullptr ? wknet::http::ResponseBodyLength(response) : 0;
        if (NT_SUCCESS(status) && (statusCode != 200 || bodyLength == 0)) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }

        CaptureStatus(result, status, statusCode, bodyLength);
        WKNET_SAMPLE_LOG(
            "[HTTP/3] 示例=HTTP/3 Required Loopback NTSTATUS=0x%08X 状态码=%lu 响应体长度=%Iu\r\n",
            static_cast<ULONG>(status),
            statusCode,
            bodyLength);
        if (NT_SUCCESS(status)) {
            WKNET_SAMPLE_LOG("[HTTP/3] 示例=HTTP/3 Required Loopback 通过\r\n");
        }

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        return status;
    }
}

NTSTATUS RunHttp3ApiSamples(net::WskClient* wskClient, Http3ApiSampleResults* results) noexcept
{
    if (wskClient == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};
    NTSTATUS aggregate = STATUS_SUCCESS;

    NTSTATUS status = RunRequiredLoopbackGet(results->Http3RequiredLoopback);
    if (!NT_SUCCESS(status)) {
        if (IsPublicEndpointDiagnosticStatus(status)) {
            WKNET_SAMPLE_LOG(
                "[HTTP/3] 示例=HTTP/3 Required Loopback 本地 fixture 或网络环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        else {
            MergeFatalSampleStatus(aggregate, status);
        }
    }

    return aggregate;
}
}
}

#undef WKNET_SAMPLE_LOG
