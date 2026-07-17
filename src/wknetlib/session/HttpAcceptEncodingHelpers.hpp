#pragma once

// Accept-Encoding helper inlines extracted from HttpEngineInternal to keep the
// session orchestration header thinner. Included by HttpEngineInternal.hpp.

#include "session/HttpEngine.h"
#include "session/Workspace.h"
#include <wknet/codec/Codec.h>
#include "http1/HttpContentEncoding.h"

namespace wknet
{
namespace session
{
    constexpr char DefaultAcceptEncodingValue[] = "gzip, deflate, br, zstd, identity";
    constexpr char DeflateUnavailableAcceptEncoding[] = "br, identity";

    inline http1::HttpText DefaultAcceptEncoding() noexcept
    {
        return http1::MakeText(
            codec::DeflateRuntimeAvailable() ?
                DefaultAcceptEncodingValue :
                DeflateUnavailableAcceptEncoding);
    }

    _Must_inspect_result_
    inline NTSTATUS BuildEffectiveAcceptEncoding(
        _In_ const HttpSendOptions& sendOptions,
        _Inout_ Workspace& workspace,
        _Out_ http1::HttpText* value) noexcept
    {
        if (value != nullptr) {
            *value = {};
        }
        if (value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (sendOptions.AcceptEncodingPreferenceCount == 0) {
            *value = DefaultAcceptEncoding();
            return STATUS_SUCCESS;
        }
        if (workspace.DecodedBody.Data == nullptr || workspace.DecodedBody.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        return http1::HttpContentEncoding::BuildAcceptEncodingHeader(
            sendOptions.AcceptEncodingPreferences,
            sendOptions.AcceptEncodingPreferenceCount,
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            workspace.DecodedBody.Length,
            value);
    }

    _Must_inspect_result_
    inline NTSTATUS BuildAcceptEncodingPolicyFromRequestHeaders(
        _In_reads_(requestHeaderCount) const http1::HttpHeader* requestHeaders,
        SIZE_T requestHeaderCount,
        _Inout_ http1::HttpAcceptEncodingRules* rules,
        _Out_ http1::HttpAcceptEncodingPolicy* policy) noexcept
    {
        if (policy != nullptr) {
            *policy = {};
        }
        if (policy == nullptr ||
            rules == nullptr ||
            rules->Entries == nullptr ||
            (requestHeaders == nullptr && requestHeaderCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        rules->EntryCount = 0;
        rules->EmptyHeader = false;
        bool foundAcceptEncoding = false;
        for (SIZE_T index = 0; index < requestHeaderCount; ++index) {
            const http1::HttpHeader& header = requestHeaders[index];
            if (!http1::TextEqualsIgnoreCase(header.Name, http1::MakeText("Accept-Encoding"))) {
                continue;
            }

            foundAcceptEncoding = true;
            NTSTATUS status = http1::HttpContentEncoding::ParseAcceptEncoding(header.Value, rules);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (!foundAcceptEncoding) {
            return STATUS_INVALID_PARAMETER;
        }

        policy->Rules = rules;
        return STATUS_SUCCESS;
    }

} // namespace session
} // namespace wknet
