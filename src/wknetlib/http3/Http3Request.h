#pragma once

#include "http3/Http3Types.h"
#include "qpack/QpackEncoder.h"

namespace wknet::http3
{
struct Http3RequestFieldOptions final
{
    qpack::QpackStringView Method = {};
    qpack::QpackStringView Scheme = {};
    qpack::QpackStringView Authority = {};
    qpack::QpackStringView Path = {};
    const qpack::QpackFieldView *Headers = nullptr;
    SIZE_T HeaderCount = 0;
    bool Connect = false;
};

struct Http3ResponseState final
{
    ULONGLONG BodyBytes = 0;
    ULONGLONG ContentLength = 0;
    ULONG StatusCode = 0;
    ULONG InformationalCount = 0;
    bool RequestWasHead = false;
    bool RequestWasConnect = false;
    bool FinalHeadersReceived = false;
    bool TrailersReceived = false;
    bool BodyForbidden = false;
    bool ContentLengthPresent = false;
    bool Complete = false;
};

NTSTATUS Http3BuildRequestFields(const Http3RequestFieldOptions &options,
                                 _Out_writes_(fieldCapacity) qpack::QpackFieldView *fields, SIZE_T fieldCapacity,
                                 _Out_ SIZE_T *fieldCount, _Out_ ULONGLONG *applicationError) noexcept;

NTSTATUS Http3ValidateTrailers(_In_reads_(fieldCount) const qpack::QpackFieldView *fields, SIZE_T fieldCount,
                               _Out_ ULONGLONG *applicationError) noexcept;

void Http3ResponseStateInitialize(_Out_ Http3ResponseState *state, bool requestWasHead,
                                  bool requestWasConnect) noexcept;

NTSTATUS Http3ProcessResponseFields(_Inout_ Http3ResponseState *state,
                                    _In_reads_(fieldCount) const qpack::QpackFieldView *fields, SIZE_T fieldCount,
                                    bool trailers, _Out_ ULONGLONG *applicationError) noexcept;

NTSTATUS Http3ProcessResponseData(_Inout_ Http3ResponseState *state, SIZE_T length,
                                  _Out_ ULONGLONG *applicationError) noexcept;

NTSTATUS Http3CompleteResponse(_Inout_ Http3ResponseState *state, _Out_ ULONGLONG *applicationError) noexcept;
} // namespace wknet::http3
