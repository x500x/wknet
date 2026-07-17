#pragma once

#include <wknet/http/Types.h>

namespace wknet::http {
    // IRQL: all Session* entry points require PASSIVE_LEVEL in kernel builds.
    // Higher IRQL returns STATUS_INVALID_DEVICE_REQUEST (or void no-op for Clear*).

    _Must_inspect_result_
    NTSTATUS SessionCreate(_Out_ Session** session) noexcept;

    _Must_inspect_result_
    NTSTATUS SessionCreate(_In_opt_ const SessionConfig* config, _Out_ Session** session) noexcept;

    void SessionClose(_In_opt_ Session* session) noexcept;

    _Must_inspect_result_
    NTSTATUS SessionSetDefaultHeader(
        _In_ Session* session,
        _In_z_ const char* name,
        _In_z_ const char* value) noexcept;

    _Must_inspect_result_
    NTSTATUS SessionSetDefaultHeaderEx(
        _In_ Session* session,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept;

    void SessionClearDefaultHeaders(_In_opt_ Session* session) noexcept;

    _Must_inspect_result_
    NTSTATUS SessionSetBasicAuth(
        _In_ Session* session,
        _In_reads_bytes_(userLength) const char* user,
        SIZE_T userLength,
        _In_reads_bytes_(passwordLength) const char* password,
        SIZE_T passwordLength) noexcept;

    _Must_inspect_result_
    NTSTATUS SessionSetBearerAuth(
        _In_ Session* session,
        _In_reads_bytes_(tokenLength) const char* token,
        SIZE_T tokenLength) noexcept;

    void SessionClearAuth(_In_opt_ Session* session) noexcept;

    void SessionClearCookies(_In_opt_ Session* session) noexcept;
}
