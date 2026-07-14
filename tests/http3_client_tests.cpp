#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "http3/Http3Connection.h"
#include "http3/Http3Frame.h"
#include "http3/Http3Request.h"
#include "qpack/QpackEncoder.h"
#include "quic/QuicFrame.h"
#include "quic/QuicVarInt.h"
#include "rtl/ProtocolFailureInjection.h"

#include <stdio.h>

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition)
        {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void TestErrorConstants() noexcept
    {
        Expect(wknet::http3::H3_NO_ERROR == 0x100, "H3_NO_ERROR value");
        Expect(wknet::http3::H3_FRAME_UNEXPECTED == 0x105, "H3_FRAME_UNEXPECTED value");
        Expect(wknet::http3::H3_FRAME_ERROR == 0x106, "H3_FRAME_ERROR value");
        Expect(wknet::http3::H3_ID_ERROR == 0x108, "H3_ID_ERROR value");
        Expect(wknet::http3::H3_SETTINGS_ERROR == 0x109, "H3_SETTINGS_ERROR value");
        Expect(wknet::http3::H3_MISSING_SETTINGS == 0x10a, "H3_MISSING_SETTINGS value");
    }

    void TestConnectionFailureInjection() noexcept
    {
        wknet::rtl::ProtocolFailureInjectionReset();
        constexpr wknet::rtl::ProtocolAllocationSite sites[] = {
            wknet::rtl::ProtocolAllocationSite::Http3ConnectionObject,
            wknet::rtl::ProtocolAllocationSite::Http3TrackedStreams,
            wknet::rtl::ProtocolAllocationSite::Http3ReadScratch, wknet::rtl::ProtocolAllocationSite::Http3WriteScratch,
            wknet::rtl::ProtocolAllocationSite::Http3Settings};
        for (const auto site : sites)
        {
            wknet::rtl::ProtocolFailureInjectionSetFailOnNth(site, 1);
            wknet::http3::Http3Connection* connection = nullptr;
            wknet::http3::Http3ConnectionCreateOptions options = {};
            Expect(wknet::http3::Http3ConnectionCreate(options, &connection) == STATUS_INSUFFICIENT_RESOURCES &&
                       connection == nullptr,
                   "HTTP/3 connection allocation failpoint is propagated");
            Expect(wknet::rtl::ProtocolFailureInjectionLiveCount(site) == 0 &&
                       wknet::rtl::ProtocolFailureInjectionLiveCount(
                           wknet::rtl::ProtocolAllocationSite::Http3ConnectionObject) == 0,
                   "partial HTTP/3 connection initialization releases tracked storage");
            wknet::rtl::ProtocolFailureInjectionSetFailOnNth(site, 0);
        }
    }

    void TestIncrementalHeader() noexcept
    {
        wknet::http3::Http3FrameHeaderParser parser = {};
        wknet::http3::Http3FrameHeaderParserInitialize(&parser);

        static const UCHAR first[] = {0x01, 0x40};
        SIZE_T consumed = 0;
        bool complete = false;
        NTSTATUS status = wknet::http3::Http3ConsumeFrameHeader(&parser, first, sizeof(first), &consumed, &complete);
        Expect(NT_SUCCESS(status), "fragmented frame header first part parses");
        Expect(consumed == sizeof(first) && !complete, "fragmented frame header waits for length");

        static const UCHAR second[] = {0x40};
        status = wknet::http3::Http3ConsumeFrameHeader(&parser, second, sizeof(second), &consumed, &complete);
        Expect(NT_SUCCESS(status), "fragmented frame header second part parses");
        Expect(consumed == sizeof(second) && complete, "fragmented frame header completes");
        Expect(parser.Header.Type == wknet::http3::Http3FrameTypeHeaders, "HEADERS type decoded");
        Expect(parser.Header.Length == 64, "two-byte payload length decoded");
        Expect(parser.Header.Kind == wknet::http3::Http3FrameKind::Headers, "HEADERS kind classified");
    }

    void TestFrameTypeClassification() noexcept
    {
        Expect(wknet::http3::Http3ClassifyFrameType(wknet::http3::Http3FrameTypeData) ==
                   wknet::http3::Http3FrameKind::Data,
               "DATA classified");
        Expect(wknet::http3::Http3ClassifyFrameType(wknet::http3::Http3FrameTypeSettings) ==
                   wknet::http3::Http3FrameKind::Settings,
               "SETTINGS classified");
        Expect(wknet::http3::Http3ClassifyFrameType(0x02) == wknet::http3::Http3FrameKind::ReservedHttp2,
               "HTTP/2 PRIORITY frame type remains reserved");
        Expect(wknet::http3::Http3ClassifyFrameType(0x06) == wknet::http3::Http3FrameKind::ReservedHttp2,
               "HTTP/2 PING frame type remains reserved");
        Expect(wknet::http3::Http3ClassifyFrameType(0x21) == wknet::http3::Http3FrameKind::Unknown,
               "GREASE frame type is treated as unknown");
        Expect(wknet::http3::Http3ClassifyFrameType(0x0a) == wknet::http3::Http3FrameKind::Unknown,
               "ordinary unknown frame classified");
    }

    void TestPayloadCursor() noexcept
    {
        wknet::http3::Http3FramePayloadCursor cursor = {};
        wknet::http3::Http3FramePayloadCursorInitialize(&cursor, 5);

        static const UCHAR first[] = {1, 2};
        wknet::http3::Http3BufferView view = {};
        SIZE_T consumed = 0;
        bool complete = false;
        NTSTATUS status =
            wknet::http3::Http3ConsumeFramePayload(&cursor, first, sizeof(first), &view, &consumed, &complete);
        Expect(NT_SUCCESS(status), "payload cursor consumes first fragment");
        Expect(view.Data == first && view.Length == sizeof(first) && consumed == sizeof(first) && !complete,
               "payload cursor exposes first fragment without copying");

        static const UCHAR second[] = {3, 4, 5, 6};
        status = wknet::http3::Http3ConsumeFramePayload(&cursor, second, sizeof(second), &view, &consumed, &complete);
        Expect(NT_SUCCESS(status), "payload cursor consumes final fragment");
        Expect(view.Data == second && view.Length == 3 && consumed == 3 && complete,
               "payload cursor stops at declared payload boundary");
    }

    void TestSingleValuePayload() noexcept
    {
        wknet::http3::Http3SingleValueParser parser = {};
        wknet::http3::Http3SingleValueParserInitialize(&parser, 2);

        static const UCHAR first[] = {0x40};
        SIZE_T consumed = 0;
        bool complete = false;
        ULONGLONG value = 0;
        ULONGLONG errorCode = 0;
        NTSTATUS status = wknet::http3::Http3ConsumeSingleValuePayload(&parser, first, sizeof(first), &consumed,
                                                                       &complete, &value, &errorCode);
        Expect(NT_SUCCESS(status) && !complete, "single-value payload waits for fragmented varint");

        static const UCHAR second[] = {0x40};
        status = wknet::http3::Http3ConsumeSingleValuePayload(&parser, second, sizeof(second), &consumed, &complete,
                                                              &value, &errorCode);
        Expect(NT_SUCCESS(status) && complete && value == 64, "single-value payload completes");

        wknet::http3::Http3SingleValueParser trailing = {};
        wknet::http3::Http3SingleValueParserInitialize(&trailing, 2);
        static const UCHAR invalid[] = {0x01, 0x00};
        status = wknet::http3::Http3ConsumeSingleValuePayload(&trailing, invalid, sizeof(invalid), &consumed, &complete,
                                                              &value, &errorCode);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE && errorCode == wknet::http3::H3_FRAME_ERROR,
               "single-value frame rejects trailing payload");
    }

    void TestSettings() noexcept
    {
        ULONGLONG identifiers[4] = {};
        wknet::http3::Http3SettingsParser parser = {};
        Expect(NT_SUCCESS(wknet::http3::Http3SettingsParserInitialize(&parser, 4, identifiers,
                                                                      sizeof(identifiers) / sizeof(identifiers[0]))),
               "SETTINGS parser initializes");

        static const UCHAR payload[] = {0x01, 0x20, 0x21, 0x01};
        SIZE_T offset = 0;
        SIZE_T settingCount = 0;
        while (offset < sizeof(payload))
        {
            wknet::http3::Http3Setting setting = {};
            SIZE_T consumed = 0;
            bool settingReady = false;
            bool complete = false;
            ULONGLONG errorCode = 0;
            const NTSTATUS status = wknet::http3::Http3ConsumeSettings(&parser, payload + offset, 1, &consumed,
                                                                       &settingReady, &setting, &complete, &errorCode);
            Expect(NT_SUCCESS(status), "SETTINGS fragmented byte parses");
            Expect(consumed == 1, "SETTINGS consumes fragmented byte");
            if (settingReady)
            {
                if (settingCount == 0)
                {
                    Expect(setting.Identifier == wknet::http3::Http3SettingQpackMaxTableCapacity &&
                               setting.Value == 32 &&
                               setting.Kind == wknet::http3::Http3SettingKind::QpackMaxTableCapacity,
                           "known SETTINGS value decoded");
                }
                else
                {
                    Expect(setting.Identifier == 0x21 && setting.Value == 1 &&
                               setting.Kind == wknet::http3::Http3SettingKind::Unknown,
                           "unknown SETTINGS value preserved and ignored by policy");
                }
                ++settingCount;
            }
            ++offset;
        }
        Expect(parser.Complete && settingCount == 2, "SETTINGS frame completes with two entries");

        ULONGLONG duplicateIdentifiers[2] = {};
        wknet::http3::Http3SettingsParser duplicate = {};
        Expect(
            NT_SUCCESS(wknet::http3::Http3SettingsParserInitialize(
                &duplicate, 4, duplicateIdentifiers, sizeof(duplicateIdentifiers) / sizeof(duplicateIdentifiers[0]))),
            "duplicate SETTINGS parser initializes");
        static const UCHAR duplicatePayload[] = {0x21, 0x01, 0x21, 0x02};
        SIZE_T consumed = 0;
        bool settingReady = false;
        bool complete = false;
        ULONGLONG errorCode = 0;
        wknet::http3::Http3Setting setting = {};
        NTSTATUS status = wknet::http3::Http3ConsumeSettings(&duplicate, duplicatePayload, sizeof(duplicatePayload),
                                                             &consumed, &settingReady, &setting, &complete, &errorCode);
        Expect(NT_SUCCESS(status) && settingReady && consumed == 2, "first duplicate candidate setting parsed");
        status = wknet::http3::Http3ConsumeSettings(&duplicate, duplicatePayload + consumed,
                                                    sizeof(duplicatePayload) - consumed, &consumed, &settingReady,
                                                    &setting, &complete, &errorCode);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE && errorCode == wknet::http3::H3_SETTINGS_ERROR,
               "duplicate unknown SETTINGS identifier rejected");

        ULONGLONG reservedIdentifiers[1] = {};
        wknet::http3::Http3SettingsParser reserved = {};
        Expect(NT_SUCCESS(wknet::http3::Http3SettingsParserInitialize(
                   &reserved, 2, reservedIdentifiers, sizeof(reservedIdentifiers) / sizeof(reservedIdentifiers[0]))),
               "reserved SETTINGS parser initializes");
        static const UCHAR reservedPayload[] = {0x02, 0x00};
        status = wknet::http3::Http3ConsumeSettings(&reserved, reservedPayload, sizeof(reservedPayload), &consumed,
                                                    &settingReady, &setting, &complete, &errorCode);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE && errorCode == wknet::http3::H3_SETTINGS_ERROR,
               "HTTP/2 reserved SETTINGS identifier rejected");
    }

    void TestPlacement() noexcept
    {
        ULONGLONG errorCode = 0;
        Expect(NT_SUCCESS(wknet::http3::Http3ValidateFramePlacement(
                   wknet::http3::Http3FrameKind::Data, wknet::http3::Http3StreamKind::Request,
                   wknet::http3::Http3EndpointRole::Server, &errorCode)),
               "DATA accepted on request stream");
        Expect(wknet::http3::Http3ValidateFramePlacement(
                   wknet::http3::Http3FrameKind::Data, wknet::http3::Http3StreamKind::Control,
                   wknet::http3::Http3EndpointRole::Server, &errorCode) == STATUS_INVALID_NETWORK_RESPONSE &&
                   errorCode == wknet::http3::H3_FRAME_UNEXPECTED,
               "DATA rejected on control stream");
        Expect(wknet::http3::Http3ValidateFramePlacement(
                   wknet::http3::Http3FrameKind::Settings, wknet::http3::Http3StreamKind::Request,
                   wknet::http3::Http3EndpointRole::Server, &errorCode) == STATUS_INVALID_NETWORK_RESPONSE &&
                   errorCode == wknet::http3::H3_FRAME_UNEXPECTED,
               "SETTINGS rejected on request stream");
        Expect(wknet::http3::Http3ValidateFramePlacement(
                   wknet::http3::Http3FrameKind::CancelPush, wknet::http3::Http3StreamKind::Control,
                   wknet::http3::Http3EndpointRole::Server, &errorCode) == STATUS_INVALID_NETWORK_RESPONSE &&
                   errorCode == wknet::http3::H3_FRAME_UNEXPECTED,
               "server CANCEL_PUSH rejected");
        Expect(wknet::http3::Http3ValidateFramePlacement(
                   wknet::http3::Http3FrameKind::ReservedHttp2, wknet::http3::Http3StreamKind::Request,
                   wknet::http3::Http3EndpointRole::Server, &errorCode) == STATUS_INVALID_NETWORK_RESPONSE &&
                   errorCode == wknet::http3::H3_FRAME_UNEXPECTED,
               "reserved HTTP/2 frame rejected");
        Expect(NT_SUCCESS(wknet::http3::Http3ValidateFramePlacement(
                   wknet::http3::Http3FrameKind::Unknown, wknet::http3::Http3StreamKind::Request,
                   wknet::http3::Http3EndpointRole::Server, &errorCode)),
               "unknown frame ignored on request stream");
    }

    wknet::qpack::QpackStringView View(const UCHAR* data, SIZE_T length) noexcept { return {data, length}; }

    void TestRequestFields() noexcept
    {
        static const UCHAR method[] = "GET";
        static const UCHAR scheme[] = "https";
        static const UCHAR authority[] = "example.com";
        static const UCHAR path[] = "/resource";
        static const UCHAR hostName[] = "host";
        static const UCHAR authorizationName[] = "authorization";
        static const UCHAR authorizationValue[] = "secret";
        wknet::qpack::QpackFieldView input[] = {
            {View(hostName, sizeof(hostName) - 1), View(authority, sizeof(authority) - 1), false},
            {View(authorizationName, sizeof(authorizationName) - 1),
             View(authorizationValue, sizeof(authorizationValue) - 1), true}};
        wknet::http3::Http3RequestFieldOptions options = {};
        options.Method = View(method, sizeof(method) - 1);
        options.Scheme = View(scheme, sizeof(scheme) - 1);
        options.Authority = View(authority, sizeof(authority) - 1);
        options.Path = View(path, sizeof(path) - 1);
        options.Headers = input;
        options.HeaderCount = sizeof(input) / sizeof(input[0]);
        wknet::qpack::QpackFieldView output[8] = {};
        SIZE_T outputCount = 0;
        ULONGLONG errorCode = 0;
        NTSTATUS status = wknet::http3::Http3BuildRequestFields(options, output, sizeof(output) / sizeof(output[0]),
                                                                &outputCount, &errorCode);
        Expect(NT_SUCCESS(status) && outputCount == 5, "request fields normalize Host into :authority");
        Expect(output[0].Name.Length == 7 && output[0].Name.Data[0] == ':' && output[4].Sensitive,
               "request pseudo fields precede sensitive regular fields");

        static const UCHAR wrongAuthority[] = "other.example";
        input[0].Value = View(wrongAuthority, sizeof(wrongAuthority) - 1);
        status = wknet::http3::Http3BuildRequestFields(options, output, sizeof(output) / sizeof(output[0]),
                                                       &outputCount, &errorCode);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE && errorCode == wknet::http3::H3_MESSAGE_ERROR,
               "Host and :authority mismatch is rejected");
        input[0].Value = View(authority, sizeof(authority) - 1);

        static const UCHAR connectMethod[] = "CONNECT";
        options.Method = View(connectMethod, sizeof(connectMethod) - 1);
        options.Connect = true;
        status = wknet::http3::Http3BuildRequestFields(options, output, sizeof(output) / sizeof(output[0]),
                                                       &outputCount, &errorCode);
        Expect(NT_SUCCESS(status) && outputCount == 3 && output[0].Name.Length == 7 && output[1].Name.Length == 10,
               "ordinary CONNECT emits only :method/:authority plus regular fields");

        static const UCHAR connectionName[] = "connection";
        static const UCHAR closeValue[] = "close";
        wknet::qpack::QpackFieldView invalid = {View(connectionName, sizeof(connectionName) - 1),
                                                View(closeValue, sizeof(closeValue) - 1), false};
        options.Connect = false;
        options.Method = View(method, sizeof(method) - 1);
        options.Headers = &invalid;
        options.HeaderCount = 1;
        status = wknet::http3::Http3BuildRequestFields(options, output, sizeof(output) / sizeof(output[0]),
                                                       &outputCount, &errorCode);
        Expect(status == STATUS_INVALID_NETWORK_RESPONSE && errorCode == wknet::http3::H3_MESSAGE_ERROR,
               "connection-specific request header is rejected");
    }

    void TestResponseSemantics() noexcept
    {
        static const UCHAR statusName[] = ":status";
        static const UCHAR status103[] = "103";
        static const UCHAR status200[] = "200";
        static const UCHAR status204[] = "204";
        static const UCHAR contentLengthName[] = "content-length";
        static const UCHAR length3[] = "3";
        static const UCHAR trailerName[] = "x-checksum";
        static const UCHAR trailerValue[] = "ok";

        wknet::http3::Http3ResponseState state = {};
        wknet::http3::Http3ResponseStateInitialize(&state, false, false);
        wknet::qpack::QpackFieldView informational[] = {
            {View(statusName, sizeof(statusName) - 1), View(status103, sizeof(status103) - 1), false}};
        ULONGLONG errorCode = 0;
        Expect(NT_SUCCESS(wknet::http3::Http3ProcessResponseFields(
                   &state, informational, sizeof(informational) / sizeof(informational[0]), false, &errorCode)) &&
                   state.InformationalCount == 1 && !state.FinalHeadersReceived,
               "informational response precedes the final response");

        wknet::qpack::QpackFieldView finalFields[] = {
            {View(statusName, sizeof(statusName) - 1), View(status200, sizeof(status200) - 1), false},
            {View(contentLengthName, sizeof(contentLengthName) - 1), View(length3, sizeof(length3) - 1), false}};
        Expect(NT_SUCCESS(wknet::http3::Http3ProcessResponseFields(
                   &state, finalFields, sizeof(finalFields) / sizeof(finalFields[0]), false, &errorCode)) &&
                   state.FinalHeadersReceived && state.StatusCode == 200 && state.ContentLength == 3,
               "final response status and Content-Length are accepted");
        Expect(NT_SUCCESS(wknet::http3::Http3ProcessResponseData(&state, 3, &errorCode)),
               "response DATA contributes to the content length");
        wknet::qpack::QpackFieldView trailers[] = {
            {View(trailerName, sizeof(trailerName) - 1), View(trailerValue, sizeof(trailerValue) - 1), false}};
        Expect(NT_SUCCESS(wknet::http3::Http3ProcessResponseFields(
                   &state, trailers, sizeof(trailers) / sizeof(trailers[0]), true, &errorCode)),
               "response trailers are accepted after DATA");
        Expect(NT_SUCCESS(wknet::http3::Http3CompleteResponse(&state, &errorCode)) && state.Complete,
               "response completes when Content-Length matches DATA");

        wknet::http3::Http3ResponseState earlyData = {};
        wknet::http3::Http3ResponseStateInitialize(&earlyData, false, false);
        Expect(wknet::http3::Http3ProcessResponseData(&earlyData, 1, &errorCode) == STATUS_INVALID_NETWORK_RESPONSE &&
                   errorCode == wknet::http3::H3_MESSAGE_ERROR,
               "DATA before initial HEADERS is rejected");

        wknet::http3::Http3ResponseState head = {};
        wknet::http3::Http3ResponseStateInitialize(&head, true, false);
        wknet::qpack::QpackFieldView headFields[] = {
            {View(statusName, sizeof(statusName) - 1), View(status200, sizeof(status200) - 1), false},
            {View(contentLengthName, sizeof(contentLengthName) - 1), View(length3, sizeof(length3) - 1), false}};
        Expect(NT_SUCCESS(wknet::http3::Http3ProcessResponseFields(
                   &head, headFields, sizeof(headFields) / sizeof(headFields[0]), false, &errorCode)),
               "HEAD final headers may carry the corresponding GET Content-Length");
        Expect(wknet::http3::Http3ProcessResponseData(&head, 1, &errorCode) == STATUS_INVALID_NETWORK_RESPONSE,
               "HEAD response DATA is rejected");
        Expect(NT_SUCCESS(wknet::http3::Http3CompleteResponse(&head, &errorCode)),
               "HEAD response completes without transferring the represented Content-Length");

        wknet::http3::Http3ResponseState noContent = {};
        wknet::http3::Http3ResponseStateInitialize(&noContent, false, false);
        wknet::qpack::QpackFieldView invalid204[] = {
            {View(statusName, sizeof(statusName) - 1), View(status204, sizeof(status204) - 1), false},
            {View(contentLengthName, sizeof(contentLengthName) - 1), View(length3, sizeof(length3) - 1), false}};
        Expect(wknet::http3::Http3ProcessResponseFields(&noContent, invalid204,
                                                        sizeof(invalid204) / sizeof(invalid204[0]), false,
                                                        &errorCode) == STATUS_INVALID_NETWORK_RESPONSE,
               "204 response rejects Content-Length");

        wknet::http3::Http3ResponseState shortBody = {};
        wknet::http3::Http3ResponseStateInitialize(&shortBody, false, false);
        Expect(NT_SUCCESS(wknet::http3::Http3ProcessResponseFields(
                   &shortBody, finalFields, sizeof(finalFields) / sizeof(finalFields[0]), false, &errorCode)),
               "short response headers initialize");
        Expect(NT_SUCCESS(wknet::http3::Http3ProcessResponseData(&shortBody, 2, &errorCode)),
               "short response DATA remains pending");
        Expect(wknet::http3::Http3CompleteResponse(&shortBody, &errorCode) == STATUS_INVALID_NETWORK_RESPONSE,
               "response FIN rejects a Content-Length mismatch");
    }

    struct Http3ConnectionCapture final
    {
        wknet::http3::Http3Connection* Connection = nullptr;
        SIZE_T Headers = 0;
        SIZE_T DataBytes = 0;
        SIZE_T Completed = 0;
        SIZE_T Errors = 0;
        SIZE_T Goaways = 0;
        ULONGLONG LastError = 0;
        ULONGLONG LastGoaway = 0;
        NTSTATUS OpenStatus = STATUS_UNSUCCESSFUL;
        NTSTATUS DataStatus = STATUS_UNSUCCESSFUL;
        NTSTATUS TrailersStatus = STATUS_UNSUCCESSFUL;
        NTSTATUS CancelStatus = STATUS_UNSUCCESSFUL;
        ULONGLONG SentDataStream = 0;
        ULONGLONG SentTrailerStream = 0;
        ULONGLONG CancelledStream = 0;
        bool ExerciseSend = false;
    };

    void OnHttp3Headers(void* context, ULONGLONG streamId, const wknet::qpack::QpackFieldView* fields,
                        SIZE_T fieldCount, bool trailers) noexcept
    {
        UNREFERENCED_PARAMETER(streamId);
        UNREFERENCED_PARAMETER(fields);
        UNREFERENCED_PARAMETER(fieldCount);
        UNREFERENCED_PARAMETER(trailers);
        Http3ConnectionCapture* capture = static_cast<Http3ConnectionCapture*>(context);
        ++capture->Headers;
        if (!capture->ExerciseSend || capture->Headers != 1)
        {
            return;
        }

        static const UCHAR getMethod[] = "GET";
        static const UCHAR connectMethod[] = "CONNECT";
        static const UCHAR scheme[] = "https";
        static const UCHAR authority[] = "example.com";
        static const UCHAR path[] = "/";
        static const UCHAR requestData[] = {9, 8, 7};
        static const UCHAR trailerName[] = "x-finish";
        static const UCHAR trailerValue[] = "yes";

        wknet::http3::Http3RequestOpenOptions open = {};
        open.Fields.Method = View(getMethod, sizeof(getMethod) - 1);
        open.Fields.Scheme = View(scheme, sizeof(scheme) - 1);
        open.Fields.Authority = View(authority, sizeof(authority) - 1);
        open.Fields.Path = View(path, sizeof(path) - 1);
        capture->OpenStatus =
            wknet::http3::Http3ConnectionWorkerOpenRequest(capture->Connection, open, &capture->SentDataStream);
        if (NT_SUCCESS(capture->OpenStatus))
        {
            capture->DataStatus = wknet::http3::Http3ConnectionWorkerWriteRequestData(
                capture->Connection, capture->SentDataStream, requestData, sizeof(requestData), true);
        }

        open.Fields.Method = View(connectMethod, sizeof(connectMethod) - 1);
        open.Fields.Connect = true;
        open.Fields.Scheme = {};
        open.Fields.Path = {};
        NTSTATUS status =
            wknet::http3::Http3ConnectionWorkerOpenRequest(capture->Connection, open, &capture->SentTrailerStream);
        wknet::qpack::QpackFieldView trailer = {View(trailerName, sizeof(trailerName) - 1),
                                                View(trailerValue, sizeof(trailerValue) - 1), false};
        if (NT_SUCCESS(status))
        {
            capture->TrailersStatus = wknet::http3::Http3ConnectionWorkerWriteRequestTrailers(
                capture->Connection, capture->SentTrailerStream, &trailer, 1);
        }

        open.Fields.Method = View(getMethod, sizeof(getMethod) - 1);
        open.Fields.Connect = false;
        open.Fields.Scheme = View(scheme, sizeof(scheme) - 1);
        open.Fields.Path = View(path, sizeof(path) - 1);
        status = wknet::http3::Http3ConnectionWorkerOpenRequest(capture->Connection, open, &capture->CancelledStream);
        if (NT_SUCCESS(status))
        {
            capture->CancelStatus = wknet::http3::Http3ConnectionWorkerCancelRequest(
                capture->Connection, capture->CancelledStream, wknet::http3::H3_REQUEST_CANCELLED);
        }
    }

    void OnHttp3Data(void* context, ULONGLONG streamId, const UCHAR* data, SIZE_T length) noexcept
    {
        UNREFERENCED_PARAMETER(streamId);
        UNREFERENCED_PARAMETER(data);
        static_cast<Http3ConnectionCapture*>(context)->DataBytes += length;
    }

    void OnHttp3Complete(void* context, ULONGLONG streamId, NTSTATUS status, ULONGLONG applicationError) noexcept
    {
        UNREFERENCED_PARAMETER(streamId);
        UNREFERENCED_PARAMETER(status);
        UNREFERENCED_PARAMETER(applicationError);
        ++static_cast<Http3ConnectionCapture*>(context)->Completed;
    }

    void OnHttp3Goaway(void* context, ULONGLONG streamId) noexcept
    {
        Http3ConnectionCapture* capture = static_cast<Http3ConnectionCapture*>(context);
        ++capture->Goaways;
        capture->LastGoaway = streamId;
    }

    void OnHttp3Error(void* context, NTSTATUS status, ULONGLONG applicationError) noexcept
    {
        UNREFERENCED_PARAMETER(status);
        Http3ConnectionCapture* capture = static_cast<Http3ConnectionCapture*>(context);
        ++capture->Errors;
        capture->LastError = applicationError;
    }

    SIZE_T AppendTestVarInt(ULONGLONG value, UCHAR* output, SIZE_T capacity, SIZE_T offset) noexcept
    {
        const SIZE_T encodedLength = wknet::quic::QuicVarIntEncodedLength(value);
        SIZE_T written = 0;
        if (encodedLength == 0 || offset > capacity ||
            !NT_SUCCESS(
                wknet::quic::QuicEncodeVarInt(value, encodedLength, output + offset, capacity - offset, &written)))
        {
            return capacity + 1;
        }
        return offset + written;
    }

    NTSTATUS InjectStream(wknet::quic::QuicConnection* connection, ULONGLONG streamId, ULONGLONG offset,
                          const UCHAR* data, SIZE_T length, bool fin) noexcept
    {
        wknet::quic::QuicFrame frame = {};
        frame.Kind = wknet::quic::QuicFrameKind::Stream;
        frame.StreamId = streamId;
        frame.Offset = offset;
        frame.Data = {data, length};
        frame.Fin = fin;
        return wknet::quic::QuicConnectionTestInjectFrame(connection, wknet::quic::QuicEncryptionLevel::Application,
                                                          wknet::quic::QuicPacketNumberSpace::Application, frame);
    }

    bool CreateHttp3Harness(Http3ConnectionCapture* capture, wknet::http3::Http3Connection** http3,
                            wknet::quic::QuicConnection** quicConnection, ULONGLONG* requestStreamId) noexcept
    {
        wknet::http3::Http3ConnectionCreateOptions http3Options = {};
        http3Options.Callbacks.Context = capture;
        http3Options.Callbacks.Headers = OnHttp3Headers;
        http3Options.Callbacks.Data = OnHttp3Data;
        http3Options.Callbacks.StreamComplete = OnHttp3Complete;
        http3Options.Callbacks.Goaway = OnHttp3Goaway;
        http3Options.Callbacks.ConnectionError = OnHttp3Error;
        if (!NT_SUCCESS(wknet::http3::Http3ConnectionCreate(http3Options, http3)))
        {
            return false;
        }
        capture->Connection = *http3;

        wknet::quic::QuicConnectionCreateOptions quicOptions = {};
        quicOptions.ApplicationEventSink = wknet::http3::Http3ConnectionApplicationSink(*http3);
        if (!NT_SUCCESS(wknet::quic::QuicConnectionCreate(quicOptions, quicConnection)) ||
            !NT_SUCCESS(wknet::http3::Http3ConnectionBindQuic(*http3, *quicConnection)))
        {
            return false;
        }
        wknet::quic::QuicOperation connect = {};
        wknet::quic::QuicOperationInitialize(&connect);
        if (!NT_SUCCESS(wknet::quic::QuicConnectionConnect(*quicConnection, &connect)) ||
            !NT_SUCCESS(wknet::quic::QuicOperationWait(&connect, 1000)) ||
            !NT_SUCCESS(wknet::quic::QuicConnectionTestConfirmHandshake(*quicConnection)))
        {
            return false;
        }
        wknet::quic::QuicOperation open = {};
        wknet::quic::QuicOperationInitialize(&open);
        if (!NT_SUCCESS(wknet::quic::QuicConnectionOpenStream(*quicConnection, &open)) ||
            !NT_SUCCESS(wknet::quic::QuicOperationWait(&open, 1000)))
        {
            return false;
        }
        *requestStreamId = open.StreamId;
        return true;
    }

    void DestroyHttp3Harness(wknet::http3::Http3Connection* http3, wknet::quic::QuicConnection* quicConnection) noexcept
    {
        if (quicConnection != nullptr)
        {
            wknet::http3::Http3ConnectionBeginShutdown(http3);
            wknet::quic::QuicOperation close = {};
            wknet::quic::QuicOperationInitialize(&close);
            const NTSTATUS status = wknet::quic::QuicConnectionCloseAsync(quicConnection, &close);
            if (NT_SUCCESS(status))
            {
                wknet::quic::QuicOperationWait(&close, 1000);
            }
            wknet::quic::QuicConnectionDestroy(quicConnection);
        }
        wknet::http3::Http3ConnectionDestroy(http3);
    }

    struct RequestFailpointContext final
    {
        wknet::http3::Http3Connection* Connection = nullptr;
        wknet::http3::Http3RequestOpenOptions Options = {};
        ULONGLONG StreamId = 0;
    };

    NTSTATUS OpenRequestForFailpoint(void* context, wknet::quic::QuicConnection*) noexcept
    {
        RequestFailpointContext* request = static_cast<RequestFailpointContext*>(context);
        return wknet::http3::Http3ConnectionWorkerOpenRequest(request->Connection, request->Options,
                                                              &request->StreamId);
    }

    void TestStreamFailureInjection() noexcept
    {
        static const UCHAR settings[] = {0x00, 0x04, 0x00};
        static const UCHAR responseHeaders[] = {0x01, 0x03, 0x00, 0x00, 0xd9};

        {
            wknet::rtl::ProtocolFailureInjectionReset();
            Http3ConnectionCapture capture = {};
            wknet::http3::Http3Connection* http3 = nullptr;
            wknet::quic::QuicConnection* connection = nullptr;
            ULONGLONG requestStreamId = 0;
            Expect(CreateHttp3Harness(&capture, &http3, &connection, &requestStreamId),
                   "request-field failpoint harness creates");
            NTSTATUS status = STATUS_UNSUCCESSFUL;
            if (http3 != nullptr && connection != nullptr &&
                NT_SUCCESS(InjectStream(connection, 3, 0, settings, sizeof(settings), false)))
            {
                static const UCHAR method[] = "GET";
                static const UCHAR scheme[] = "https";
                static const UCHAR authority[] = "example.com";
                static const UCHAR path[] = "/";
                RequestFailpointContext request = {};
                request.Connection = http3;
                request.Options.Fields.Method = View(method, sizeof(method) - 1);
                request.Options.Fields.Scheme = View(scheme, sizeof(scheme) - 1);
                request.Options.Fields.Authority = View(authority, sizeof(authority) - 1);
                request.Options.Fields.Path = View(path, sizeof(path) - 1);
                const auto site = wknet::rtl::ProtocolAllocationSite::Http3RequestFields;
                wknet::rtl::ProtocolFailureInjectionSetFailOnNth(
                    site, wknet::rtl::ProtocolFailureInjectionHitCount(site) + 1);
                wknet::quic::QuicOperation operation = {};
                wknet::quic::QuicOperationInitialize(&operation);
                status = wknet::quic::QuicConnectionExecuteApplication(connection, OpenRequestForFailpoint, &request,
                                                                       &operation);
                if (NT_SUCCESS(status))
                {
                    status = wknet::quic::QuicOperationWait(&operation, 1000);
                }
            }
            DestroyHttp3Harness(http3, connection);
            Expect(status == STATUS_INSUFFICIENT_RESOURCES &&
                       wknet::rtl::ProtocolFailureInjectionHitCount(
                           wknet::rtl::ProtocolAllocationSite::Http3RequestFields) != 0,
                   "HTTP/3 request-field allocation failpoint is propagated on the QUIC worker");
            Expect(wknet::rtl::ProtocolFailureInjectionTotalLiveCount() == 0,
                   "HTTP/3 request-field failure releases every tracked owner");
        }

        constexpr wknet::rtl::ProtocolAllocationSite streamSites[] = {
            wknet::rtl::ProtocolAllocationSite::Http3StreamPayload,
            wknet::rtl::ProtocolAllocationSite::Http3StreamFieldBytes};
        for (const auto site : streamSites)
        {
            wknet::rtl::ProtocolFailureInjectionReset();
            Http3ConnectionCapture capture = {};
            wknet::http3::Http3Connection* http3 = nullptr;
            wknet::quic::QuicConnection* connection = nullptr;
            ULONGLONG requestStreamId = 0;
            Expect(CreateHttp3Harness(&capture, &http3, &connection, &requestStreamId),
                   "HTTP/3 stream failpoint harness creates");
            NTSTATUS status = STATUS_UNSUCCESSFUL;
            if (http3 != nullptr && connection != nullptr &&
                NT_SUCCESS(InjectStream(connection, 3, 0, settings, sizeof(settings), false)))
            {
                wknet::rtl::ProtocolFailureInjectionSetFailOnNth(
                    site, wknet::rtl::ProtocolFailureInjectionHitCount(site) + 1);
                status = InjectStream(connection, requestStreamId, 0, responseHeaders, sizeof(responseHeaders), false);
            }
            DestroyHttp3Harness(http3, connection);
            Expect(NT_SUCCESS(status) && capture.Errors == 1 &&
                       capture.LastError == wknet::http3::H3_GENERAL_PROTOCOL_ERROR &&
                       wknet::rtl::ProtocolFailureInjectionHitCount(site) != 0,
                   "HTTP/3 stream allocation failpoint maps to a connection-level internal error");
            Expect(wknet::rtl::ProtocolFailureInjectionTotalLiveCount() == 0,
                   "HTTP/3 stream allocation failure releases every tracked owner");
        }
    }

    void TestConnectionControlQpackAndRequest() noexcept
    {
        Http3ConnectionCapture capture = {};
        capture.ExerciseSend = true;
        wknet::http3::Http3Connection* http3 = nullptr;
        wknet::quic::QuicConnection* connection = nullptr;
        ULONGLONG requestStreamId = 0;
        Expect(CreateHttp3Harness(&capture, &http3, &connection, &requestStreamId),
               "HTTP/3 harness uses the real QUIC application sink");
        if (http3 == nullptr || connection == nullptr)
        {
            DestroyHttp3Harness(http3, connection);
            return;
        }

        static const UCHAR settings[] = {0x00, 0x04, 0x08, 0x01, 0x40, 0x80, 0x07, 0x02, 0x06, 0x44, 0x00};
        Expect(NT_SUCCESS(InjectStream(connection, 3, 0, settings, sizeof(settings), false)),
               "peer control stream SETTINGS are delivered through the sink");
        Expect(wknet::http3::Http3ConnectionPeerSettingsReceived(http3) &&
                   wknet::http3::Http3ConnectionPeerQpackMaximumCapacity(http3) == 128 &&
                   wknet::http3::Http3ConnectionPeerQpackBlockedStreams(http3) == 2,
               "peer SETTINGS negotiate bounded QPACK values");

        wknet::qpack::QpackEncoder peerEncoder;
        Expect(NT_SUCCESS(peerEncoder.Initialize(128, 2)), "peer QPACK encoder initializes");
        UCHAR capacityInstruction[16] = {};
        SIZE_T capacityInstructionLength = 0;
        Expect(NT_SUCCESS(peerEncoder.SetCapacity(128, capacityInstruction, sizeof(capacityInstruction),
                                                  &capacityInstructionLength)),
               "peer QPACK capacity instruction encodes");
        static const UCHAR dynamicName[] = "x-dynamic";
        static const UCHAR dynamicValue[] = "ready";
        UCHAR insertInstruction[64] = {};
        SIZE_T insertInstructionLength = 0;
        Expect(NT_SUCCESS(peerEncoder.InsertWithLiteralName(dynamicName, sizeof(dynamicName) - 1, false, dynamicValue,
                                                            sizeof(dynamicValue) - 1, false, insertInstruction,
                                                            sizeof(insertInstruction), &insertInstructionLength)),
               "peer QPACK dynamic entry instruction encodes");

        static const UCHAR statusName[] = ":status";
        static const UCHAR statusValue[] = "200";
        wknet::qpack::QpackFieldView responseFields[] = {
            {View(statusName, sizeof(statusName) - 1), View(statusValue, sizeof(statusValue) - 1), false},
            {View(dynamicName, sizeof(dynamicName) - 1), View(dynamicValue, sizeof(dynamicValue) - 1), false}};
        UCHAR fieldSection[128] = {};
        SIZE_T fieldSectionLength = 0;
        Expect(NT_SUCCESS(peerEncoder.EncodeFieldSection(requestStreamId, responseFields,
                                                         sizeof(responseFields) / sizeof(responseFields[0]),
                                                         fieldSection, sizeof(fieldSection), &fieldSectionLength)),
               "blocked response field section encodes");

        UCHAR headersFrame[160] = {};
        SIZE_T headersLength =
            AppendTestVarInt(wknet::http3::Http3FrameTypeHeaders, headersFrame, sizeof(headersFrame), 0);
        headersLength = AppendTestVarInt(fieldSectionLength, headersFrame, sizeof(headersFrame), headersLength);
        RtlCopyMemory(headersFrame + headersLength, fieldSection, fieldSectionLength);
        headersLength += fieldSectionLength;
        Expect(NT_SUCCESS(InjectStream(connection, requestStreamId, 0, headersFrame, headersLength, false)) &&
                   wknet::http3::Http3ConnectionBlockedStreamCount(http3) == 1 && capture.Headers == 0,
               "HEADERS block until peer encoder instructions arrive");

        wknet::quic::QuicOperation openReset = {};
        wknet::quic::QuicOperationInitialize(&openReset);
        Expect(NT_SUCCESS(wknet::quic::QuicConnectionOpenStream(connection, &openReset)) &&
                   NT_SUCCESS(wknet::quic::QuicOperationWait(&openReset, 1000)),
               "second request stream opens for blocked cancellation");
        UCHAR cancelSection[128] = {};
        SIZE_T cancelSectionLength = 0;
        Expect(NT_SUCCESS(peerEncoder.EncodeFieldSection(openReset.StreamId, responseFields,
                                                         sizeof(responseFields) / sizeof(responseFields[0]),
                                                         cancelSection, sizeof(cancelSection), &cancelSectionLength)),
               "second blocked field section encodes");
        UCHAR cancelHeaders[160] = {};
        SIZE_T cancelHeadersLength =
            AppendTestVarInt(wknet::http3::Http3FrameTypeHeaders, cancelHeaders, sizeof(cancelHeaders), 0);
        cancelHeadersLength =
            AppendTestVarInt(cancelSectionLength, cancelHeaders, sizeof(cancelHeaders), cancelHeadersLength);
        RtlCopyMemory(cancelHeaders + cancelHeadersLength, cancelSection, cancelSectionLength);
        cancelHeadersLength += cancelSectionLength;
        Expect(NT_SUCCESS(InjectStream(connection, openReset.StreamId, 0, cancelHeaders, cancelHeadersLength, false)) &&
                   wknet::http3::Http3ConnectionBlockedStreamCount(http3) == 2,
               "second response also blocks on the missing insert");
        wknet::quic::QuicFrame resetFrame = {};
        resetFrame.Kind = wknet::quic::QuicFrameKind::ResetStream;
        resetFrame.StreamId = openReset.StreamId;
        resetFrame.ErrorCode = wknet::http3::H3_REQUEST_CANCELLED;
        resetFrame.FinalSize = cancelHeadersLength;
        Expect(NT_SUCCESS(wknet::quic::QuicConnectionTestInjectFrame(
                   connection, wknet::quic::QuicEncryptionLevel::Application,
                   wknet::quic::QuicPacketNumberSpace::Application, resetFrame)) &&
                   wknet::http3::Http3ConnectionBlockedStreamCount(http3) == 1 &&
                   wknet::http3::Http3ConnectionLocalDecoderBytesSent(http3) != 0,
               "reset of a blocked request emits QPACK Stream Cancellation");

        UCHAR encoderStream[96] = {};
        SIZE_T encoderLength = 0;
        encoderStream[encoderLength++] = 0x02;
        RtlCopyMemory(encoderStream + encoderLength, capacityInstruction, capacityInstructionLength);
        encoderLength += capacityInstructionLength;
        RtlCopyMemory(encoderStream + encoderLength, insertInstruction, insertInstructionLength);
        encoderLength += insertInstructionLength;
        Expect(NT_SUCCESS(InjectStream(connection, 7, 0, encoderStream, encoderLength, false)) &&
                   wknet::http3::Http3ConnectionBlockedStreamCount(http3) == 0 && capture.Headers == 1 &&
                   wknet::http3::Http3ConnectionLocalDecoderBytesSent(http3) != 0,
               "QPACK encoder stream resumes HEADERS and queues Section Ack");

        static const UCHAR dataFrame[] = {0x00, 0x03, 1, 2, 3};
        Expect(
            NT_SUCCESS(InjectStream(connection, requestStreamId, headersLength, dataFrame, sizeof(dataFrame), true)) &&
                capture.DataBytes == 3 && capture.Completed >= 2,
            "request stream DATA and FIN complete through callbacks");
        Expect(NT_SUCCESS(capture.OpenStatus) && NT_SUCCESS(capture.DataStatus) && NT_SUCCESS(capture.TrailersStatus) &&
                   NT_SUCCESS(capture.CancelStatus) && capture.SentDataStream != capture.SentTrailerStream &&
                   capture.CancelledStream != capture.SentDataStream,
               "worker-side request HEADERS/DATA/trailers/CONNECT/cancel use real QUIC streams");

        static const UCHAR goaway[] = {0x07, 0x01, 0x00};
        Expect(NT_SUCCESS(InjectStream(connection, 3, sizeof(settings), goaway, sizeof(goaway), false)) &&
                   capture.Goaways == 1 && capture.LastGoaway == 0 && wknet::http3::Http3ConnectionGoawayId(http3) == 0,
               "GOAWAY validates and records a client request stream boundary");

        static const UCHAR unknownUni[] = {0x21, 1, 2, 3};
        Expect(NT_SUCCESS(InjectStream(connection, 11, 0, unknownUni, sizeof(unknownUni), true)) && capture.Errors == 0,
               "unknown unidirectional stream drains without allocation by declared length");
        static const UCHAR duplicateControl[] = {0x00};
        InjectStream(connection, 15, 0, duplicateControl, sizeof(duplicateControl), false);
        Expect(capture.Errors == 1 && capture.LastError == wknet::http3::H3_STREAM_CREATION_ERROR,
               "duplicate control stream closes with H3_STREAM_CREATION_ERROR");

        DestroyHttp3Harness(http3, connection);
    }

    void TestPushStreamRejected() noexcept
    {
        Http3ConnectionCapture capture = {};
        wknet::http3::Http3Connection* http3 = nullptr;
        wknet::quic::QuicConnection* connection = nullptr;
        ULONGLONG requestStreamId = 0;
        Expect(CreateHttp3Harness(&capture, &http3, &connection, &requestStreamId), "push rejection harness creates");
        if (http3 != nullptr && connection != nullptr)
        {
            static const UCHAR pushStream[] = {0x01, 0x00};
            InjectStream(connection, 3, 0, pushStream, sizeof(pushStream), false);
            Expect(capture.Errors == 1 && capture.LastError == wknet::http3::H3_ID_ERROR,
                   "push stream is safely rejected when MAX_PUSH_ID was never sent");
        }
        DestroyHttp3Harness(http3, connection);
    }

    void TestControlStreamErrors() noexcept
    {
        {
            Http3ConnectionCapture capture = {};
            wknet::http3::Http3Connection* http3 = nullptr;
            wknet::quic::QuicConnection* connection = nullptr;
            ULONGLONG requestStreamId = 0;
            Expect(CreateHttp3Harness(&capture, &http3, &connection, &requestStreamId),
                   "missing SETTINGS harness creates");
            if (http3 != nullptr && connection != nullptr)
            {
                static const UCHAR goawayFirst[] = {0x00, 0x07, 0x01, 0x00};
                InjectStream(connection, 3, 0, goawayFirst, sizeof(goawayFirst), false);
                Expect(capture.Errors == 1 && capture.LastError == wknet::http3::H3_MISSING_SETTINGS,
                       "control stream rejects a non-SETTINGS first frame");
            }
            DestroyHttp3Harness(http3, connection);
        }

        {
            Http3ConnectionCapture capture = {};
            wknet::http3::Http3Connection* http3 = nullptr;
            wknet::quic::QuicConnection* connection = nullptr;
            ULONGLONG requestStreamId = 0;
            Expect(CreateHttp3Harness(&capture, &http3, &connection, &requestStreamId),
                   "duplicate SETTINGS harness creates");
            if (http3 != nullptr && connection != nullptr)
            {
                static const UCHAR duplicateSettings[] = {0x00, 0x04, 0x00, 0x04, 0x00};
                InjectStream(connection, 3, 0, duplicateSettings, sizeof(duplicateSettings), false);
                Expect(capture.Errors == 1 && capture.LastError == wknet::http3::H3_FRAME_UNEXPECTED,
                       "control stream rejects a second SETTINGS frame");
            }
            DestroyHttp3Harness(http3, connection);
        }

        {
            Http3ConnectionCapture capture = {};
            wknet::http3::Http3Connection* http3 = nullptr;
            wknet::quic::QuicConnection* connection = nullptr;
            ULONGLONG requestStreamId = 0;
            Expect(CreateHttp3Harness(&capture, &http3, &connection, &requestStreamId),
                   "critical stream closure harness creates");
            if (http3 != nullptr && connection != nullptr)
            {
                static const UCHAR settingsAndFin[] = {0x00, 0x04, 0x00};
                InjectStream(connection, 3, 0, settingsAndFin, sizeof(settingsAndFin), true);
                Expect(capture.Errors == 1 && capture.LastError == wknet::http3::H3_CLOSED_CRITICAL_STREAM,
                       "closing the peer control stream fails the connection");
            }
            DestroyHttp3Harness(http3, connection);
        }
    }

} // namespace

int main()
{
    TestConnectionFailureInjection();
    TestErrorConstants();
    TestIncrementalHeader();
    TestFrameTypeClassification();
    TestPayloadCursor();
    TestSingleValuePayload();
    TestSettings();
    TestPlacement();
    TestRequestFields();
    TestResponseSemantics();
    TestStreamFailureInjection();
    TestConnectionControlQpackAndRequest();
    TestPushStreamRejected();
    TestControlStreamErrors();

    if (g_failed)
    {
        printf("HTTP/3 CLIENT TESTS FAILED\n");
        return 1;
    }

    printf("HTTP/3 CLIENT TESTS PASSED\n");
    return 0;
}
