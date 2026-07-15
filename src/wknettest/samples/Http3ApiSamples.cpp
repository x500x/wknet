#include "samples/Http3ApiSamples.h"

#include <wknet/http/Http.h>
#include <wknet/http/Response.h>
#include <wknet/http/Session.h>
#include <wknettest/SampleStatus.h>

#include "WknetTestLog.h"
#include "samples/ExternalTrustStore.h"

namespace wknet
{
namespace samples
{
namespace
{
    constexpr const char* Http3ExternalUrl = "https://cloudflare-quic.com/";
    constexpr const char* Http3ExternalServerName = "cloudflare-quic.com";
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

    NTSTATUS RunRequiredExternalGet(
        _In_ const wknet::http::CertificateStore* trustStore,
        _Out_ HighLevelApiSampleResult& result) noexcept
    {
        wknet::http::SessionConfig config = wknet::http::DefaultSessionConfig();
        config.MaxResponseBytes = Http3MaxResponseBytes;
        config.PoolCapacity = 2;
        config.MaxConnsPerHost = 1;
        config.Http3.Mode = wknet::http::Http3ConnectMode::Required;
        config.Http3.Race = wknet::http::Http3RaceMode::SequentialPreferHttp3;
        config.Http3.QuicProbeTimeoutMs = Http3ProbeTimeoutMs;
        config.Tls.Certificate = wknet::http::CertPolicy::Verify;
        config.Tls.Store = trustStore;
        config.Tls.MinVersion = wknet::http::TlsVersion::Tls13;
        config.Tls.MaxVersion = wknet::http::TlsVersion::Tls13;
        config.Tls.ServerName = Http3ExternalServerName;
        config.Tls.ServerNameLength = LiteralLength(Http3ExternalServerName);
        config.Tls.PreferHttp2 = false;

        WKNET_SAMPLE_LOG(
            "[HTTP/3] 示例=HTTP/3 Required External URL=%s 模式=Required TLS=Verify TLS版本=TLS1.3\r\n",
            Http3ExternalUrl);

        wknet::http::Session* session = nullptr;
        NTSTATUS status = wknet::http::SessionCreate(&config, &session);
        if (!NT_SUCCESS(status)) {
            CaptureStatus(result, status, 0, 0);
            WKNET_SAMPLE_LOG(
                "[HTTP/3] 示例=HTTP/3 Required External SessionCreate 失败 NTSTATUS=0x%08X\r\n",
                static_cast<ULONG>(status));
            return status;
        }

        wknet::http::Response* response = nullptr;
        status = wknet::http::Get(session, Http3ExternalUrl, &response);

        ULONG statusCode = response != nullptr ? wknet::http::ResponseStatusCode(response) : 0;
        SIZE_T bodyLength = response != nullptr ? wknet::http::ResponseBodyLength(response) : 0;
        if (NT_SUCCESS(status) && (statusCode != 200 || bodyLength == 0)) {
            status = STATUS_INVALID_NETWORK_RESPONSE;
        }

        CaptureStatus(result, status, statusCode, bodyLength);
        WKNET_SAMPLE_LOG(
            "[HTTP/3] 示例=HTTP/3 Required External NTSTATUS=0x%08X 状态码=%lu 响应体长度=%Iu\r\n",
            static_cast<ULONG>(status),
            statusCode,
            bodyLength);
        if (NT_SUCCESS(status)) {
            WKNET_SAMPLE_LOG("[HTTP/3] 示例=HTTP/3 Required External 通过\r\n");
        }

        wknet::http::ResponseRelease(response);
        wknet::http::SessionClose(session);
        return status;
    }
}

NTSTATUS RunHttp3ApiSamples(
    net::WskClient* wskClient,
    const char* certificateBundlePath,
    Http3ApiSampleResults* results) noexcept
{
    if (wskClient == nullptr || results == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    *results = {};
    NTSTATUS aggregate = STATUS_SUCCESS;

    ExternalTrustStore trustStore = {};
    NTSTATUS status = InitializeExternalTrustStore(
        trustStore,
        certificateBundlePath != nullptr ? certificateBundlePath : ExternalTrustStoreDefaultBundlePath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RunRequiredExternalGet(trustStore.Store, results->Http3RequiredExternal);
    if (!NT_SUCCESS(status)) {
        if (IsPublicEndpointDiagnosticStatus(status)) {
            WKNET_SAMPLE_LOG(
                "[HTTP/3] 示例=HTTP/3 Required External 外部端点或网络环境失败已记录，不计入总失败 NTSTATUS=0x%08X\r\n",
                static_cast<ULONG>(status));
        }
        else {
            MergeFatalSampleStatus(aggregate, status);
        }
    }

    ResetExternalTrustStore(trustStore);
    return aggregate;
}
}
}

#undef WKNET_SAMPLE_LOG
