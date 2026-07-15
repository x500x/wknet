#pragma once

#include <wknet/WknetConfig.h>

// Kernel-side full-library quality matrix for wknettest.sys.
// Axes mirror docs/module-quality-ledger.md (Module × Property × Runtime=KM).

namespace wknet::ktest
{
    enum class Module : ULONG
    {
        HttpApi = 0,
        Session,
        Tls,
        Http1,
        Http2,
        Http3,
        Ws,
        Net,
        Transport,
        Rtl,
        Codec,
        Crypto,
        Quic,
        Qpack,
        Count
    };

    enum class Property : ULONG
    {
        Functional = 0,
        Reject,
        Resource,
        Fault,
        CancelTimeout,
        Concurrency,
        Lifecycle,
        Stress,
        RuntimeKm,
        Count
    };

    enum class CaseOutcome : ULONG
    {
        Pass = 0,
        Fail,
        // Public-network / environment failure that must not fail DriverEntry.
        EnvironmentSkip,
        // Capability not exercised in this build/path.
        NotRun
    };

    struct CaseResult final
    {
        const char* Name = nullptr;
        Module Mod = Module::HttpApi;
        Property Prop = Property::Functional;
        CaseOutcome Outcome = CaseOutcome::NotRun;
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG HttpStatusCode = 0;
        SIZE_T Detail = 0;
    };

    inline const char* ModuleName(Module mod) noexcept
    {
        switch (mod) {
        case Module::HttpApi: return "http_api";
        case Module::Session: return "session";
        case Module::Tls: return "tls";
        case Module::Http1: return "http1";
        case Module::Http2: return "http2";
        case Module::Http3: return "http3";
        case Module::Ws: return "ws";
        case Module::Net: return "net";
        case Module::Transport: return "transport";
        case Module::Rtl: return "rtl";
        case Module::Codec: return "codec";
        case Module::Crypto: return "crypto";
        case Module::Quic: return "quic";
        case Module::Qpack: return "qpack";
        default: return "unknown";
        }
    }

    inline const char* PropertyName(Property prop) noexcept
    {
        switch (prop) {
        case Property::Functional: return "Functional";
        case Property::Reject: return "Reject";
        case Property::Resource: return "Resource";
        case Property::Fault: return "Fault";
        case Property::CancelTimeout: return "CancelTimeout";
        case Property::Concurrency: return "Concurrency";
        case Property::Lifecycle: return "Lifecycle";
        case Property::Stress: return "Stress";
        case Property::RuntimeKm: return "RuntimeKm";
        default: return "unknown";
        }
    }

    inline const char* OutcomeName(CaseOutcome outcome) noexcept
    {
        switch (outcome) {
        case CaseOutcome::Pass: return "PASS";
        case CaseOutcome::Fail: return "FAIL";
        case CaseOutcome::EnvironmentSkip: return "ENV";
        case CaseOutcome::NotRun: return "SKIP";
        default: return "?";
        }
    }
}
