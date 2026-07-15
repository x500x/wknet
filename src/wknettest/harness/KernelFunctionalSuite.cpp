#include "harness/KernelFunctionalSuite.h"

#include "samples/HttpApiSamples.h"
#include "WknetTestLog.h"
#include <wknettest/SampleStatus.h>

namespace wknet::ktest
{
namespace
{
    void Map(
        MatrixReport* report,
        const char* name,
        Module mod,
        Property prop,
        const samples::HighLevelApiSampleResult& result) noexcept
    {
        ReportSampleField(
            report,
            name,
            mod,
            prop,
            result.Status,
            result.StatusCode,
            result.BodyLength);
    }
}

NTSTATUS RunFunctionalSampleSuite(MatrixContext* context) noexcept
{
    if (context == nullptr || context->WskClient == nullptr || context->Report == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    samples::DriverSampleResults samples = {};
    const NTSTATUS sampleStatus = samples::RunDriverSamples(
        context->WskClient,
        context->CertificateBundlePath,
        &samples);

    MatrixReport* report = context->Report;
    const auto& hl = samples.HighLevel;
    const auto& adv = samples.Advanced;
    const auto& h3 = samples.Http3;

    // --- High-level API surface (Functional / Lifecycle / Cancel) ---
    Map(report, "hl.session_default_config", Module::HttpApi, Property::Functional, hl.SessionDefaultConfig);
    Map(report, "hl.session_custom_config", Module::HttpApi, Property::Functional, hl.SessionCustomConfig);
    Map(report, "hl.http_get", Module::HttpApi, Property::Functional, hl.HttpGet);
    Map(report, "hl.http_get_shortcut", Module::HttpApi, Property::Functional, hl.HttpShortcutGet);
    Map(report, "hl.http_post_shortcut", Module::HttpApi, Property::Functional, hl.HttpShortcutPost);
    Map(report, "hl.http_put_shortcut", Module::HttpApi, Property::Functional, hl.HttpShortcutPut);
    Map(report, "hl.http_patch_shortcut", Module::HttpApi, Property::Functional, hl.HttpShortcutPatch);
    Map(report, "hl.http_delete_shortcut", Module::HttpApi, Property::Functional, hl.HttpShortcutDelete);
    Map(report, "hl.http_head_shortcut", Module::HttpApi, Property::Functional, hl.HttpShortcutHead);
    Map(report, "hl.http_options_shortcut", Module::HttpApi, Property::Functional, hl.HttpShortcutOptions);
    Map(report, "hl.http_get_async", Module::HttpApi, Property::Functional, hl.HttpGetAsync);
    Map(report, "hl.http_post", Module::HttpApi, Property::Functional, hl.HttpPost);
    Map(report, "hl.http_post_async", Module::HttpApi, Property::Functional, hl.HttpPostAsync);
    Map(report, "hl.http_put", Module::HttpApi, Property::Functional, hl.HttpPut);
    Map(report, "hl.http_patch", Module::HttpApi, Property::Functional, hl.HttpPatch);
    Map(report, "hl.http_delete", Module::HttpApi, Property::Functional, hl.HttpDelete);
    Map(report, "hl.http_head", Module::HttpApi, Property::Functional, hl.HttpHead);
    Map(report, "hl.http_options", Module::HttpApi, Property::Functional, hl.HttpOptions);
    Map(report, "hl.http_get_ipv4", Module::Net, Property::Functional, hl.HttpGetIpv4);
    Map(report, "hl.http_get_ipv6", Module::Net, Property::Functional, hl.HttpGetIpv6);
    Map(report, "hl.http_get_any", Module::Net, Property::Functional, hl.HttpGetAny);
    Map(report, "hl.http_send_options", Module::HttpApi, Property::Functional, hl.HttpSendWithOptions);
    Map(report, "hl.http_send_ex", Module::HttpApi, Property::Functional, hl.HttpSendEx);
    Map(report, "hl.http_response_header", Module::HttpApi, Property::Functional, hl.HttpResponseHeader);
    Map(report, "hl.http_text_body", Module::HttpApi, Property::Functional, hl.HttpTextBody);
    Map(report, "hl.http_json_body", Module::HttpApi, Property::Functional, hl.HttpJsonBody);
    Map(report, "hl.http_raw_body", Module::HttpApi, Property::Functional, hl.HttpRawBody);
    Map(report, "hl.http_form_body", Module::HttpApi, Property::Functional, hl.HttpFormBody);
    Map(report, "hl.http_multipart_body", Module::HttpApi, Property::Functional, hl.HttpMultipartBody);
    Map(report, "hl.http_file_body", Module::HttpApi, Property::Functional, hl.HttpFileBody);
    Map(report, "hl.http_clear_body", Module::HttpApi, Property::Functional, hl.HttpClearBody);
    Map(report, "hl.http_send_async", Module::HttpApi, Property::Functional, hl.HttpSendAsync);
    Map(report, "hl.http_send_async_options", Module::HttpApi, Property::Functional, hl.HttpSendAsyncWithOptions);
    Map(report, "hl.http_send_async_ex", Module::HttpApi, Property::Functional, hl.HttpSendAsyncEx);
    Map(report, "hl.http_async_cancel", Module::HttpApi, Property::CancelTimeout, hl.HttpAsyncCancel);
    Map(report, "hl.https_verify_get", Module::Tls, Property::Functional, hl.HttpsVerifyGet);
    Map(report, "hl.https_no_verify_get", Module::Tls, Property::Functional, hl.HttpsNoVerifyGet);
    Map(report, "hl.https_request_builder", Module::HttpApi, Property::Functional, hl.HttpsRequestBuilder);
    Map(report, "hl.https_http11", Module::Http1, Property::Functional, hl.HttpsHttp11);
    Map(report, "hl.https_http2", Module::Http2, Property::Functional, hl.HttpsHttp2);
    Map(report, "hl.ws_echo", Module::Ws, Property::Functional, hl.WebSocketEcho);
    Map(report, "hl.ws_url_connect", Module::Ws, Property::Functional, hl.WebSocketUrlConnect);
    Map(report, "hl.ws_config_connect", Module::Ws, Property::Functional, hl.WebSocketConfigConnect);
    Map(report, "hl.ws_connect_ex", Module::Ws, Property::Functional, hl.WebSocketConnectEx);
    Map(report, "hl.ws_text_ex", Module::Ws, Property::Functional, hl.WebSocketTextEx);
    Map(report, "hl.ws_binary", Module::Ws, Property::Functional, hl.WebSocketBinary);
    Map(report, "hl.ws_binary_ex", Module::Ws, Property::Functional, hl.WebSocketBinaryEx);
    Map(report, "hl.ws_tls13_only", Module::Tls, Property::Functional, hl.WebSocketTls13Only);
    Map(report, "hl.ws_receive_ex", Module::Ws, Property::Functional, hl.WebSocketReceiveEx);
    Map(report, "hl.ws_connect_async", Module::Ws, Property::Functional, hl.WebSocketConnectAsync);
    Map(report, "hl.ws_config_connect_async", Module::Ws, Property::Functional, hl.WebSocketConfigConnectAsync);
    Map(report, "hl.ws_connect_async_ex", Module::Ws, Property::Functional, hl.WebSocketConnectAsyncEx);

    // --- Advanced scenarios (Reject / Resource / Concurrency / Lifecycle) ---
    Map(report, "adv.http_redirect", Module::Session, Property::Functional, adv.HttpRedirect);
    Map(report, "adv.http_redirect_disabled", Module::Session, Property::Reject, adv.HttpRedirectDisabled);
    Map(report, "adv.http_not_found", Module::HttpApi, Property::Functional, adv.HttpNotFound);
    Map(report, "adv.http_server_error", Module::HttpApi, Property::Functional, adv.HttpServerError);
    Map(report, "adv.http_large_response", Module::Session, Property::Resource, adv.HttpLargeResponse);
    Map(report, "adv.http_response_limit", Module::Session, Property::Resource, adv.HttpResponseLimit);
    Map(report, "adv.http_large_post", Module::HttpApi, Property::Resource, adv.HttpLargePost);
    Map(report, "adv.http_concurrent_async", Module::HttpApi, Property::Concurrency, adv.HttpConcurrentAsync);
    Map(report, "adv.http_async_wait_timeout", Module::HttpApi, Property::CancelTimeout, adv.HttpAsyncWaitTimeout);
    Map(report, "adv.https_trust_failure", Module::Tls, Property::Reject, adv.HttpsTrustFailure);
    Map(report, "adv.https_alpn_mismatch", Module::Tls, Property::Reject, adv.HttpsAlpnMismatch);
    Map(report, "adv.ws_close", Module::Ws, Property::Lifecycle, adv.WebSocketClose);
    Map(report, "adv.ws_fragment_send", Module::Ws, Property::Functional, adv.WebSocketFragmentSend);

    // --- HTTP/3 product path ---
    Map(report, "h3.required_external", Module::Http3, Property::Functional, h3.Http3RequiredExternal);

    // RuntimeKm marker: samples ran under real WSK in the test driver.
    ReportCase(
        report,
        "km.runtime_samples_executed",
        Module::Net,
        Property::RuntimeKm,
        CaseOutcome::Pass,
        STATUS_SUCCESS,
        0,
        samples.HighLevel.HttpGet.BodyLength);

    if (!NT_SUCCESS(sampleStatus) &&
        !samples::IsPublicEndpointDiagnosticStatus(sampleStatus) &&
        NT_SUCCESS(report->AggregateStatus)) {
        // RunDriverSamples aggregate may already be reflected in fields; keep as safety net.
        report->AggregateStatus = sampleStatus;
    }

    WKNET_SAMPLE_LOG(
        "[ktest] functional suite finished sample_aggregate=0x%08X\r\n",
        static_cast<ULONG>(sampleStatus));
    return report->AggregateStatus;
}
}
