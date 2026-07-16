#include "session/HttpEngineInternal.hpp"

#include "http3/Http3Connection.h"
#include "qpack/QpackEncoder.h"
#include "quic/QuicConnection.h"
#include "rtl/ProtocolAllocator.h"
#if defined(WKNET_USER_MODE_TEST)
#include "session/HttpH3TestHooks.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#endif

namespace wknet::session
{
namespace
{
constexpr SIZE_T HttpH3BodyChunkBytes = 16 * 1024;

struct HttpH3StoredField final
{
    SIZE_T NameOffset = 0;
    SIZE_T NameLength = 0;
    SIZE_T ValueOffset = 0;
    SIZE_T ValueLength = 0;
};

struct HttpH3ResponseAccumulator final
{
    Workspace *WorkspaceObject = nullptr;
    http1::HttpResponse *Parsed = nullptr;
    http1::HttpHeader *Headers = nullptr;
    SIZE_T HeaderCapacity = 0;
    http1::HttpHeader *Trailers = nullptr;
    SIZE_T TrailerCapacity = 0;
    SIZE_T *RawResponseLength = nullptr;
    HeapArray<HttpH3StoredField> StoredHeaders;
    HeapArray<HttpH3StoredField> StoredTrailers;
    SIZE_T HeaderCount = 0;
    SIZE_T TrailerCount = 0;
    SIZE_T BodyOffset = 0;
    SIZE_T BodyLength = 0;
    bool BodyStarted = false;
};

struct HttpH3CompletionFence final
{
    bool Signaled = false;
#if defined(WKNET_USER_MODE_TEST)
    std::mutex Lock;
    std::condition_variable Event;
#else
    KEVENT Event = {};
#endif
};

struct HttpH3WriteApplicationContext final
{
    HttpH3DispatchContext *Dispatch = nullptr;
    const UCHAR *Data = nullptr;
    SIZE_T Length = 0;
    bool Fin = false;
};

struct HttpH3TrailersApplicationContext final
{
    HttpH3DispatchContext *Dispatch = nullptr;
    const qpack::QpackFieldView *Fields = nullptr;
    SIZE_T FieldCount = 0;
};

struct HttpH3CancelApplicationContext final
{
    HttpH3DispatchContext *Dispatch = nullptr;
};

bool IsTerminalState(HttpH3RequestState state) noexcept
{
    return state == HttpH3RequestState::Completed || state == HttpH3RequestState::Cancelled;
}

void ObserveDispatch(const HttpH3DispatchContext *context) noexcept
{
#if defined(WKNET_USER_MODE_TEST)
    HttpH3TestObserveDispatch(context);
#else
    UNREFERENCED_PARAMETER(context);
#endif
}

void SignalCompletionFence(HttpH3DispatchContext *context) noexcept
{
    if (context == nullptr || context->CompletionFence == nullptr)
    {
        return;
    }
    HttpH3CompletionFence *fence = static_cast<HttpH3CompletionFence *>(context->CompletionFence);
#if defined(WKNET_USER_MODE_TEST)
    {
        std::lock_guard<std::mutex> lock(fence->Lock);
        fence->Signaled = true;
    }
    fence->Event.notify_all();
#else
    fence->Signaled = true;
    KeSetEvent(&fence->Event, IO_NO_INCREMENT, FALSE);
#endif
}

bool TryClaimDispatchCompletion(HttpH3DispatchContext *context) noexcept
{
    if (context == nullptr || context->CompletionFence == nullptr)
    {
        return false;
    }
#if defined(WKNET_USER_MODE_TEST)
    HttpH3CompletionFence *fence = static_cast<HttpH3CompletionFence *>(context->CompletionFence);
    std::lock_guard<std::mutex> lock(fence->Lock);
    if (context->CompletionClaim != 0)
    {
        return false;
    }
    context->CompletionClaim = 1;
    return true;
#else
    return InterlockedCompareExchange(&context->CompletionClaim, 1, 0) == 0;
#endif
}

NTSTATUS InitializeResponseAccumulator(HttpH3DispatchContext *context,
                                       const HttpH3DispatchStartOptions *options) noexcept
{
    if (context == nullptr || options == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (options->DirectCallbacks)
    {
        return STATUS_SUCCESS;
    }
    if (options->ResponseWorkspace == nullptr || options->ParsedResponse == nullptr ||
        options->ResponseHeaders == nullptr || options->ResponseHeaderCapacity == 0 ||
        options->ResponseTrailers == nullptr || options->ResponseTrailerCapacity == 0 ||
        options->RawResponseLength == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    HttpH3ResponseAccumulator *accumulator = AllocateProtocolNonPagedObject<HttpH3ResponseAccumulator>(
        rtl::ProtocolAllocationSite::SessionHttp3ResponseAccumulator);
    if (accumulator == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    accumulator->WorkspaceObject = options->ResponseWorkspace;
    accumulator->Parsed = options->ParsedResponse;
    accumulator->Headers = options->ResponseHeaders;
    accumulator->HeaderCapacity = options->ResponseHeaderCapacity;
    accumulator->Trailers = options->ResponseTrailers;
    accumulator->TrailerCapacity = options->ResponseTrailerCapacity;
    accumulator->RawResponseLength = options->RawResponseLength;
    NTSTATUS status = accumulator->StoredHeaders.Allocate(options->ResponseHeaderCapacity);
    if (NT_SUCCESS(status))
    {
        status = accumulator->StoredTrailers.Allocate(options->ResponseTrailerCapacity);
    }
    if (!NT_SUCCESS(status))
    {
        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::SessionHttp3ResponseAccumulator, accumulator);
        return status;
    }
    *options->ParsedResponse = {};
    *options->RawResponseLength = 0;
    context->ResponseAccumulator = accumulator;
    return STATUS_SUCCESS;
}

NTSTATUS AppendResponseField(HttpH3ResponseAccumulator *accumulator, const char *name, SIZE_T nameLength,
                             const char *value, SIZE_T valueLength, bool trailers) noexcept
{
    if (accumulator == nullptr || (name == nullptr && nameLength != 0) || (value == nullptr && valueLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    HttpH3StoredField *stored = nullptr;
    if (trailers)
    {
        if (accumulator->TrailerCount >= accumulator->TrailerCapacity)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        stored = &accumulator->StoredTrailers[accumulator->TrailerCount++];
    }
    else
    {
        if (accumulator->BodyStarted || accumulator->HeaderCount >= accumulator->HeaderCapacity)
        {
            return accumulator->BodyStarted ? STATUS_INVALID_NETWORK_RESPONSE : STATUS_BUFFER_TOO_SMALL;
        }
        stored = &accumulator->StoredHeaders[accumulator->HeaderCount++];
    }

    stored->NameOffset = accumulator->WorkspaceObject->ResponseLength;
    stored->NameLength = nameLength;
    NTSTATUS status = nameLength == 0 ? STATUS_SUCCESS
                                      : WorkspaceAppendResponse(accumulator->WorkspaceObject,
                                                                reinterpret_cast<const UCHAR *>(name), nameLength);
    if (NT_SUCCESS(status))
    {
        stored->ValueOffset = accumulator->WorkspaceObject->ResponseLength;
        stored->ValueLength = valueLength;
        status = valueLength == 0 ? STATUS_SUCCESS
                                  : WorkspaceAppendResponse(accumulator->WorkspaceObject,
                                                            reinterpret_cast<const UCHAR *>(value), valueLength);
    }
    return status;
}

NTSTATUS AppendResponseBody(HttpH3ResponseAccumulator *accumulator, const UCHAR *data, SIZE_T dataLength) noexcept
{
    if (accumulator == nullptr || (data == nullptr && dataLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (!accumulator->BodyStarted)
    {
        accumulator->BodyStarted = true;
        accumulator->BodyOffset = accumulator->WorkspaceObject->ResponseLength;
    }
    if (dataLength > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - accumulator->BodyLength)
    {
        return STATUS_INTEGER_OVERFLOW;
    }
    const NTSTATUS status =
        dataLength == 0 ? STATUS_SUCCESS : WorkspaceAppendResponse(accumulator->WorkspaceObject, data, dataLength);
    if (NT_SUCCESS(status))
    {
        accumulator->BodyLength += dataLength;
    }
    return status;
}

void MaterializeFields(const UCHAR *base, const HeapArray<HttpH3StoredField> &stored, SIZE_T count,
                       http1::HttpHeader *fields) noexcept
{
    for (SIZE_T index = 0; index < count; ++index)
    {
        fields[index].Name.Data = reinterpret_cast<const char *>(base + stored[index].NameOffset);
        fields[index].Name.Length = stored[index].NameLength;
        fields[index].Value.Data = reinterpret_cast<const char *>(base + stored[index].ValueOffset);
        fields[index].Value.Length = stored[index].ValueLength;
    }
}

NTSTATUS FinalizeResponse(HttpH3DispatchContext *context) noexcept
{
    if (context == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (context->DirectCallbacks)
    {
        if (context->ResponseStatusCode < 200 || context->ResponseStatusCode > 999)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (context->ParsedResponse != nullptr)
        {
            http1::HttpResponse &parsed = *context->ParsedResponse;
            parsed.MajorVersion = 3;
            parsed.MinorVersion = 0;
            parsed.StatusCode = static_cast<USHORT>(context->ResponseStatusCode);
            parsed.BodyDeliveredViaCallback = context->SendOptions != nullptr &&
                context->SendOptions->BodyCallback != nullptr;
            if (parsed.BodyDeliveredViaCallback &&
                context->SendOptions != nullptr &&
                (context->SendOptions->Flags & HttpSendFlagAggregateWithCallbacks) == 0)
            {
                parsed.Body = nullptr;
                parsed.BodyLength = 0;
            }
        }
        return STATUS_SUCCESS;
    }
    if (context->ResponseAccumulator == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    HttpH3ResponseAccumulator *accumulator = static_cast<HttpH3ResponseAccumulator *>(context->ResponseAccumulator);
    if (context->ResponseStatusCode < 200 || context->ResponseStatusCode > 999)
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    const UCHAR *base = accumulator->WorkspaceObject->Response.Data;
    MaterializeFields(base, accumulator->StoredHeaders, accumulator->HeaderCount, accumulator->Headers);
    MaterializeFields(base, accumulator->StoredTrailers, accumulator->TrailerCount, accumulator->Trailers);

    http1::HttpResponse &parsed = *accumulator->Parsed;
    parsed = {};
    parsed.MajorVersion = 3;
    parsed.MinorVersion = 0;
    parsed.StatusCode = static_cast<USHORT>(context->ResponseStatusCode);
    parsed.Headers = accumulator->Headers;
    parsed.HeaderCount = accumulator->HeaderCount;
    parsed.Trailers = accumulator->Trailers;
    parsed.TrailerCount = accumulator->TrailerCount;
    parsed.Body =
        accumulator->BodyLength == 0 ? nullptr : reinterpret_cast<const char *>(base + accumulator->BodyOffset);
    parsed.BodyLength = accumulator->BodyLength;
    parsed.BodyKind = accumulator->BodyLength == 0 ? http1::HttpBodyKind::None : http1::HttpBodyKind::ContentLength;

    if (parsed.BodyLength != 0)
    {
        http1::HttpContentDecodeBuffers decodeBuffers = {};
        decodeBuffers.ScratchBody = reinterpret_cast<char *>(accumulator->WorkspaceObject->Request.Data);
        decodeBuffers.ScratchBodyCapacity = accumulator->WorkspaceObject->Request.Length;
        decodeBuffers.Materials = context->SendOptions->ContentCodingMaterials;
        for (;;)
        {
            decodeBuffers.DecodedBody = reinterpret_cast<char *>(accumulator->WorkspaceObject->DecodedBody.Data);
            decodeBuffers.DecodedBodyCapacity = accumulator->WorkspaceObject->DecodedBody.Length;
            http1::HttpContentDecodeResult decoded = {};
            NTSTATUS status = http1::HttpContentEncoding::Decode(parsed.Headers, parsed.HeaderCount, parsed.Body,
                                                                 parsed.BodyLength, decodeBuffers, decoded, nullptr);
            if (status == STATUS_BUFFER_TOO_SMALL)
            {
                status = GrowDecodedBodyAfterBufferTooSmall(*accumulator->WorkspaceObject);
                if (NT_SUCCESS(status))
                {
                    continue;
                }
            }
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            parsed.Body = decoded.BodyLength == 0 ? nullptr : decoded.Body;
            parsed.BodyLength = decoded.BodyLength;
            break;
        }
    }
    *accumulator->RawResponseLength = 0;
    return STATUS_SUCCESS;
}

qpack::QpackStringView MakeQpackView(const char *value, SIZE_T length) noexcept
{
    qpack::QpackStringView view = {};
    view.Data = reinterpret_cast<const UCHAR *>(value);
    view.Length = length;
    return view;
}

qpack::QpackStringView MethodView(HttpMethod method) noexcept
{
    switch (method)
    {
    case HttpMethod::Get:
        return MakeQpackView("GET", 3);
    case HttpMethod::Post:
        return MakeQpackView("POST", 4);
    case HttpMethod::Put:
        return MakeQpackView("PUT", 3);
    case HttpMethod::Patch:
        return MakeQpackView("PATCH", 5);
    case HttpMethod::Delete:
        return MakeQpackView("DELETE", 6);
    case HttpMethod::Head:
        return MakeQpackView("HEAD", 4);
    case HttpMethod::Options:
        return MakeQpackView("OPTIONS", 7);
    case HttpMethod::Connect:
        return MakeQpackView("CONNECT", 7);
    case HttpMethod::Trace:
        return MakeQpackView("TRACE", 5);
    }
    return {};
}

char ToLowerAscii(char value) noexcept
{
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

bool IsDefaultPort(const Request &request) noexcept
{
    const bool https = request.SchemeLength == 5 && ToLowerAscii(request.Scheme[0]) == 'h' &&
                       ToLowerAscii(request.Scheme[1]) == 't' && ToLowerAscii(request.Scheme[2]) == 't' &&
                       ToLowerAscii(request.Scheme[3]) == 'p' && ToLowerAscii(request.Scheme[4]) == 's';
    return (https && request.Port == 443) || (!https && request.Port == 80);
}

SIZE_T DecimalDigitCount(USHORT value) noexcept
{
    SIZE_T digits = 1;
    while (value >= 10)
    {
        value = static_cast<USHORT>(value / 10);
        ++digits;
    }
    return digits;
}

NTSTATUS BuildAuthority(const Request &request, HeapArray<char> &authority, qpack::QpackStringView *view) noexcept
{
    if (view == nullptr || request.HostLength == 0 || request.Port == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *view = {};

    bool ipv6Literal = false;
    for (SIZE_T index = 0; index < request.HostLength; ++index)
    {
        if (request.Host[index] == ':')
        {
            ipv6Literal = true;
            break;
        }
    }
    const bool bracketHost = ipv6Literal && request.Host[0] != '[';
    const bool appendPort = !IsDefaultPort(request);
    const SIZE_T portDigits = appendPort ? DecimalDigitCount(request.Port) : 0;
    const SIZE_T capacity = request.HostLength + (bracketHost ? 2 : 0) + (appendPort ? 1 + portDigits : 0);
    NTSTATUS status = authority.Allocate(capacity);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SIZE_T offset = 0;
    if (bracketHost)
    {
        authority[offset++] = '[';
    }
    RtlCopyMemory(authority.Get() + offset, request.Host, request.HostLength);
    offset += request.HostLength;
    if (bracketHost)
    {
        authority[offset++] = ']';
    }
    if (appendPort)
    {
        authority[offset++] = ':';
        USHORT port = request.Port;
        for (SIZE_T digit = 0; digit < portDigits; ++digit)
        {
            authority[offset + portDigits - digit - 1] = static_cast<char>('0' + (port % 10));
            port = static_cast<USHORT>(port / 10);
        }
        offset += portDigits;
    }
    view->Data = reinterpret_cast<const UCHAR *>(authority.Get());
    view->Length = offset;
    return STATUS_SUCCESS;
}

NTSTATUS BuildFieldViews(const StoredHeader *headers, SIZE_T headerCount, HeapArray<qpack::QpackFieldView> &fields,
                         HeapArray<char> &lowerNames) noexcept
{
    if (headers == nullptr && headerCount != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (headerCount == 0)
    {
        return STATUS_SUCCESS;
    }
    if (headerCount > MaxHeadersPerRequest || headerCount > static_cast<SIZE_T>(~0ULL) / MaxHeaderNameLength)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = fields.Allocate(headerCount);
    if (NT_SUCCESS(status))
    {
        status = lowerNames.Allocate(headerCount * MaxHeaderNameLength);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    for (SIZE_T index = 0; index < headerCount; ++index)
    {
        const StoredHeader &source = headers[index];
        if (source.Name == nullptr || source.NameLength == 0 || source.NameLength > MaxHeaderNameLength ||
            (source.Value == nullptr && source.ValueLength != 0))
        {
            return STATUS_INVALID_PARAMETER;
        }
        char *lowerName = lowerNames.Get() + (index * MaxHeaderNameLength);
        for (SIZE_T character = 0; character < source.NameLength; ++character)
        {
            lowerName[character] = ToLowerAscii(source.Name[character]);
        }
        fields[index].Name = MakeQpackView(lowerName, source.NameLength);
        fields[index].Value = MakeQpackView(source.Value, source.ValueLength);
        fields[index].Sensitive =
            qpack::QpackEncoder::IsSensitiveName(fields[index].Name.Data, fields[index].Name.Length);
    }
    return STATUS_SUCCESS;
}

bool IsForbiddenHttp3RequestHeader(const StoredHeader &header) noexcept
{
    return HeaderNameEquals(header, "Connection") || HeaderNameEquals(header, "Content-Length") ||
           HeaderNameEquals(header, "Host") || HeaderNameEquals(header, "Keep-Alive") ||
           HeaderNameEquals(header, "Proxy-Connection") || HeaderNameEquals(header, "TE") ||
           HeaderNameEquals(header, "Transfer-Encoding") || HeaderNameEquals(header, "Upgrade") ||
           (header.NameLength != 0 && header.Name != nullptr && header.Name[0] == ':');
}

SIZE_T WriteDecimal(SIZE_T value, char *destination, SIZE_T capacity) noexcept
{
    SIZE_T digits = 1;
    SIZE_T remaining = value;
    while (remaining >= 10)
    {
        remaining /= 10;
        ++digits;
    }
    if (destination == nullptr || capacity < digits)
    {
        return 0;
    }
    remaining = value;
    for (SIZE_T index = 0; index < digits; ++index)
    {
        destination[digits - index - 1] = static_cast<char>('0' + (remaining % 10));
        remaining /= 10;
    }
    return digits;
}

NTSTATUS BuildRequestFieldViews(HttpH3DispatchContext *context, HeapArray<qpack::QpackFieldView> &fields,
                                HeapArray<char> &lowerNames, HeapArray<char> &generatedValues,
                                SIZE_T *fieldCount) noexcept
{
    if (fieldCount != nullptr)
    {
        *fieldCount = 0;
    }
    if (context == nullptr || context->RequestObject == nullptr || context->SendOptions == nullptr ||
        fieldCount == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const Request &request = *context->RequestObject;
    if (request.Method == HttpMethod::Trace)
    {
        if ((context->SendOptions->Flags & HttpSendFlagAllowTrace) == 0)
        {
            return STATUS_NOT_SUPPORTED;
        }
        if (request.HasBody || request.BodyLength != 0 || request.BodySourceCallback != nullptr ||
            request.TrailerCount != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if ((context->SendOptions->Flags & HttpSendFlagExpectContinue) != 0 && request.HasBody)
    {
        return STATUS_NOT_SUPPORTED;
    }
    if (request.HeaderCount > MaxHeadersPerRequest || request.HeaderCount > WKNET_HARD_MAX_HTTP3_FIELDS - 2)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS status = fields.Allocate(request.HeaderCount + 2);
    if (NT_SUCCESS(status) && request.HeaderCount != 0)
    {
        status = lowerNames.Allocate(request.HeaderCount * MaxHeaderNameLength);
    }
    if (NT_SUCCESS(status))
    {
        status = generatedValues.Allocate(MaxHeaderValueLength + 32);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    bool hasAcceptEncoding = false;
    SIZE_T count = 0;
    for (SIZE_T index = 0; index < request.HeaderCount; ++index)
    {
        const StoredHeader &source = request.Headers[index];
        if (source.Name == nullptr || source.NameLength == 0 || source.NameLength > MaxHeaderNameLength ||
            (source.Value == nullptr && source.ValueLength != 0))
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (IsForbiddenHttp3RequestHeader(source))
        {
            return STATUS_INVALID_PARAMETER;
        }
        char *lowerName = lowerNames.Get() + (index * MaxHeaderNameLength);
        for (SIZE_T character = 0; character < source.NameLength; ++character)
        {
            lowerName[character] = ToLowerAscii(source.Name[character]);
        }
        fields[count].Name = MakeQpackView(lowerName, source.NameLength);
        fields[count].Value = MakeQpackView(source.Value, source.ValueLength);
        fields[count].Sensitive =
            qpack::QpackEncoder::IsSensitiveName(fields[count].Name.Data, fields[count].Name.Length);
        hasAcceptEncoding = hasAcceptEncoding || HeaderNameEquals(source, "Accept-Encoding");
        ++count;
    }

    SIZE_T generatedOffset = 0;
    if (!hasAcceptEncoding)
    {
        http1::HttpText acceptEncoding = DefaultAcceptEncoding();
        if (context->SendOptions->AcceptEncodingPreferenceCount != 0)
        {
            status = http1::HttpContentEncoding::BuildAcceptEncodingHeader(
                context->SendOptions->AcceptEncodingPreferences, context->SendOptions->AcceptEncodingPreferenceCount,
                generatedValues.Get(), MaxHeaderValueLength, &acceptEncoding);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            generatedOffset = acceptEncoding.Length;
        }
        fields[count].Name = MakeQpackView("accept-encoding", sizeof("accept-encoding") - 1);
        fields[count].Value = MakeQpackView(acceptEncoding.Data, acceptEncoding.Length);
        ++count;
    }

    const bool knownBodyLength =
        request.HasBody && (request.BodySourceCallback == nullptr || request.BodySourceContentLengthKnown);
    if (knownBodyLength)
    {
        const SIZE_T bodyLength =
            request.BodySourceCallback != nullptr ? request.BodySourceContentLength : request.BodyLength;
        char *lengthValue = generatedValues.Get() + generatedOffset;
        const SIZE_T lengthCapacity = generatedValues.Count() - generatedOffset;
        const SIZE_T length = WriteDecimal(bodyLength, lengthValue, lengthCapacity);
        if (length == 0)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        fields[count].Name = MakeQpackView("content-length", sizeof("content-length") - 1);
        fields[count].Value = MakeQpackView(lengthValue, length);
        ++count;
    }

    *fieldCount = count;
    return STATUS_SUCCESS;
}

NTSTATUS ExecuteApplication(HttpH3DispatchContext *context, quic::QuicApplicationCommandCallback callback,
                            void *callbackContext) noexcept
{
    if (context == nullptr || context->Peer.Quic == nullptr || callback == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    HeapObject<quic::QuicOperation> operation;
    if (!operation.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    quic::QuicOperationInitialize(operation.Get());
    NTSTATUS status =
        quic::QuicConnectionExecuteApplication(context->Peer.Quic, callback, callbackContext, operation.Get());
    return NT_SUCCESS(status) ? quic::QuicOperationWait(operation.Get(), WskOperationTimeoutMilliseconds) : status;
}

NTSTATUS OpenRequestOnWorker(void *commandContext, quic::QuicConnection *connection) noexcept
{
    UNREFERENCED_PARAMETER(connection);
    HttpH3DispatchContext *context = static_cast<HttpH3DispatchContext *>(commandContext);
    if (context == nullptr || context->Peer.Http3 == nullptr || context->RequestObject == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const Request &request = *context->RequestObject;
    HeapArray<qpack::QpackFieldView> fields;
    HeapArray<char> lowerNames;
    HeapArray<char> generatedValues;
    SIZE_T fieldCount = 0;
    NTSTATUS status = BuildRequestFieldViews(context, fields, lowerNames, generatedValues, &fieldCount);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    HeapArray<char> authority;
    qpack::QpackStringView authorityView = {};
    status = BuildAuthority(request, authority, &authorityView);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    http3::Http3RequestOpenOptions options = {};
    options.Fields.Method = MethodView(request.Method);
    options.Fields.Scheme = MakeQpackView(request.Scheme, request.SchemeLength);
    options.Fields.Authority = authorityView;
    options.Fields.Path = MakeQpackView(request.Path, request.PathLength);
    options.Fields.Headers = fields.Get();
    options.Fields.HeaderCount = fieldCount;
    options.Fields.Connect = request.Method == HttpMethod::Connect;
    options.RequestWasHead = request.Method == HttpMethod::Head;

    ULONGLONG streamId = HttpH3UnsetStreamId;
    status = http3::Http3ConnectionWorkerOpenRequest(context->Peer.Http3, options, &streamId);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = HttpH3DispatchAdvanceState(context, HttpH3RequestState::StreamCreated, streamId, STATUS_PENDING);
    if (NT_SUCCESS(status))
    {
        status = HttpH3DispatchAdvanceState(context, HttpH3RequestState::HeadersQueued, streamId, STATUS_PENDING);
    }
    if (NT_SUCCESS(status))
    {
        status = HttpH3DispatchAdvanceState(context, HttpH3RequestState::HeadersCommitted, streamId, STATUS_PENDING);
    }
    return status;
}

NTSTATUS WriteRequestOnWorker(void *commandContext, quic::QuicConnection *connection) noexcept
{
    UNREFERENCED_PARAMETER(connection);
    HttpH3WriteApplicationContext *command = static_cast<HttpH3WriteApplicationContext *>(commandContext);
    if (command == nullptr || command->Dispatch == nullptr || command->Dispatch->Peer.Http3 == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = http3::Http3ConnectionWorkerWriteRequestData(
        command->Dispatch->Peer.Http3, command->Dispatch->StreamId, command->Data, command->Length, command->Fin);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (command->Length != 0)
    {
        status = HttpH3DispatchAdvanceState(command->Dispatch, HttpH3RequestState::RequestPartiallySent,
                                            command->Dispatch->StreamId, STATUS_PENDING);
    }
    if (NT_SUCCESS(status) && command->Fin)
    {
        status = HttpH3DispatchAdvanceState(command->Dispatch, HttpH3RequestState::RequestFullySent,
                                            command->Dispatch->StreamId, STATUS_PENDING);
    }
    return status;
}

NTSTATUS WriteTrailersOnWorker(void *commandContext, quic::QuicConnection *connection) noexcept
{
    UNREFERENCED_PARAMETER(connection);
    HttpH3TrailersApplicationContext *command = static_cast<HttpH3TrailersApplicationContext *>(commandContext);
    if (command == nullptr || command->Dispatch == nullptr || command->Dispatch->Peer.Http3 == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = http3::Http3ConnectionWorkerWriteRequestTrailers(
        command->Dispatch->Peer.Http3, command->Dispatch->StreamId, command->Fields, command->FieldCount);
    return NT_SUCCESS(status) ? HttpH3DispatchAdvanceState(command->Dispatch, HttpH3RequestState::RequestFullySent,
                                                           command->Dispatch->StreamId, STATUS_PENDING)
                              : status;
}

NTSTATUS CancelRequestOnWorker(void *commandContext, quic::QuicConnection *connection) noexcept
{
    UNREFERENCED_PARAMETER(connection);
    HttpH3CancelApplicationContext *command = static_cast<HttpH3CancelApplicationContext *>(commandContext);
    if (command == nullptr || command->Dispatch == nullptr || command->Dispatch->Peer.Http3 == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    return http3::Http3ConnectionWorkerCancelRequest(command->Dispatch->Peer.Http3, command->Dispatch->StreamId,
                                                     http3::H3_REQUEST_CANCELLED);
}

NTSTATUS SubmitBodyChunk(HttpH3DispatchContext *context, const UCHAR *data, SIZE_T length, bool fin) noexcept
{
    HeapObject<HttpH3WriteApplicationContext> command;
    if (!command.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    command->Dispatch = context;
    command->Data = data;
    command->Length = length;
    command->Fin = fin;
    return ExecuteApplication(context, WriteRequestOnWorker, command.Get());
}

NTSTATUS ReadBody(HttpH3DispatchContext *context, UCHAR *buffer, SIZE_T capacity, SIZE_T *bytesRead,
                  bool *endOfBody) noexcept
{
    if (bytesRead != nullptr)
    {
        *bytesRead = 0;
    }
    if (endOfBody != nullptr)
    {
        *endOfBody = false;
    }
    if (context == nullptr || context->RequestObject == nullptr || buffer == nullptr || bytesRead == nullptr ||
        endOfBody == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const Request &request = *context->RequestObject;
    ++context->BodyReadCount;
    ObserveDispatch(context);
    if (request.BodySourceCallback != nullptr)
    {
        NTSTATUS status = request.BodySourceCallback(request.BodySourceContext, buffer, capacity, bytesRead, endOfBody);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (*bytesRead > capacity || context->BodyOffset > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - *bytesRead)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        context->BodyOffset += *bytesRead;
        if (request.BodySourceContentLengthKnown &&
            (context->BodyOffset > request.BodySourceContentLength ||
             (*endOfBody && context->BodyOffset != request.BodySourceContentLength)))
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return STATUS_SUCCESS;
    }
    if (context->BodyOffset > request.BodyLength)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    const SIZE_T remaining = request.BodyLength - context->BodyOffset;
    const SIZE_T copyLength = remaining < capacity ? remaining : capacity;
    if (copyLength != 0)
    {
        if (request.Body == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        RtlCopyMemory(buffer, request.Body + context->BodyOffset, copyLength);
        context->BodyOffset += copyLength;
    }
    *bytesRead = copyLength;
    *endOfBody = context->BodyOffset == request.BodyLength;
    return STATUS_SUCCESS;
}

NTSTATUS SubmitRequestBody(HttpH3DispatchContext *context) noexcept
{
    if (context == nullptr || context->RequestObject == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const Request &request = *context->RequestObject;
    const bool hasTrailers = request.TrailerCount != 0;
    if (!request.HasBody && request.BodyLength == 0 && request.BodySourceCallback == nullptr)
    {
        return hasTrailers ? STATUS_SUCCESS : SubmitBodyChunk(context, nullptr, 0, true);
    }

    HeapArray<UCHAR> buffer(HttpH3BodyChunkBytes);
    if (!buffer.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (;;)
    {
        SIZE_T bytesRead = 0;
        bool endOfBody = false;
        NTSTATUS status = ReadBody(context, buffer.Get(), buffer.Count(), &bytesRead, &endOfBody);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (bytesRead == 0 && !endOfBody)
        {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (bytesRead != 0 || (endOfBody && !hasTrailers))
        {
            status = SubmitBodyChunk(context, buffer.Get(), bytesRead, endOfBody && !hasTrailers);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
        if (endOfBody)
        {
            return STATUS_SUCCESS;
        }
    }
}

NTSTATUS SubmitRequestTrailers(HttpH3DispatchContext *context) noexcept
{
    if (context == nullptr || context->RequestObject == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const Request &request = *context->RequestObject;
    if (request.TrailerCount == 0)
    {
        return STATUS_SUCCESS;
    }
    HeapArray<qpack::QpackFieldView> fields;
    HeapArray<char> lowerNames;
    NTSTATUS status = BuildFieldViews(request.Trailers.Data(), request.TrailerCount, fields, lowerNames);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    HeapObject<HttpH3TrailersApplicationContext> command;
    if (!command.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    command->Dispatch = context;
    command->Fields = fields.Get();
    command->FieldCount = request.TrailerCount;
    return ExecuteApplication(context, WriteTrailersOnWorker, command.Get());
}

} // namespace

NTSTATUS HttpH3DispatchInitialize(HttpH3DispatchContext *context, const HttpH3DispatchStartOptions *options) noexcept
{
    if (context == nullptr || options == nullptr || options->RequestObject == nullptr ||
        options->SendOptions == nullptr || options->PeerFactory == nullptr || options->PeerFactory->Create == nullptr ||
        options->AttemptGeneration == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *context = {};
    HttpH3CompletionFence *fence =
        AllocateProtocolNonPagedObject<HttpH3CompletionFence>(rtl::ProtocolAllocationSite::SessionHttp3CompletionFence);
    if (fence == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
#if !defined(WKNET_USER_MODE_TEST)
    KeInitializeEvent(&fence->Event, NotificationEvent, FALSE);
#endif
    context->CompletionFence = fence;
    context->Session = options->Session;
    context->RequestObject = options->RequestObject;
    context->SendOptions = options->SendOptions;
    context->DirectCallbacks = options->DirectCallbacks;
    context->ParsedResponse = options->ParsedResponse;
    context->AttemptGeneration = options->AttemptGeneration;
    context->StreamId = HttpH3UnsetStreamId;
    context->LastGoawayId = HttpH3MaximumStreamId;
    context->State = HttpH3RequestState::NoStream;
    context->TerminalStatus = STATUS_PENDING;
    const NTSTATUS status = InitializeResponseAccumulator(context, options);
    if (!NT_SUCCESS(status))
    {
        FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::SessionHttp3CompletionFence, fence);
        context->CompletionFence = nullptr;
        return status;
    }
    ObserveDispatch(context);
    return STATUS_SUCCESS;
}

NTSTATUS HttpH3DispatchRequired(HttpH3DispatchContext *context, const HttpH3DispatchStartOptions *options) noexcept
{
    NTSTATUS status = HttpH3DispatchInitialize(context, options);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    HttpH3PeerCreateOptions createOptions = {};
    createOptions.Session = options->Session;
    createOptions.RequestObject = options->RequestObject;
    createOptions.SendOptions = options->SendOptions;
    createOptions.Dispatch = context;
    createOptions.Alternative = options->Alternative;
    createOptions.ProbeTimeoutMilliseconds = options->ProbeTimeoutMilliseconds;
    createOptions.AttemptGeneration = options->AttemptGeneration;
    HeapObject<HttpH3Peer> createdPeer;
    if (!createdPeer.IsValid())
    {
        HttpH3DispatchNotifyComplete(context, STATUS_INSUFFICIENT_RESOURCES, http3::H3_INTERNAL_ERROR);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = options->PeerFactory->Create(options->PeerFactory->Context, &createOptions, createdPeer.Get());
    if (!NT_SUCCESS(status) || createdPeer->Quic == nullptr || createdPeer->Http3 == nullptr ||
        createdPeer->AttachRequest == nullptr || createdPeer->BindStream == nullptr || createdPeer->Destroy == nullptr)
    {
        status = NT_SUCCESS(status) ? STATUS_INVALID_DEVICE_STATE : status;
        if (createdPeer->Destroy != nullptr)
        {
            createdPeer->Destroy(createdPeer->Context);
        }
        HttpH3DispatchNotifyComplete(context, status, http3::H3_INTERNAL_ERROR);
        return status;
    }
    context->Peer = *createdPeer;
    context->PeerCreated = true;
    status = context->Peer.AttachRequest(context->Peer.Context, context);
    if (NT_SUCCESS(status))
    {
        status = ExecuteApplication(context, OpenRequestOnWorker, context);
    }
    if (NT_SUCCESS(status))
    {
        status = context->Peer.BindStream(context->Peer.Context, context, context->StreamId);
    }
    if (NT_SUCCESS(status))
    {
        status = SubmitRequestBody(context);
    }
    if (NT_SUCCESS(status))
    {
        status = SubmitRequestTrailers(context);
    }
    if (!NT_SUCCESS(status))
    {
        HttpH3DispatchNotifyComplete(context, status, http3::H3_INTERNAL_ERROR);
        return status;
    }
#if defined(WKNET_USER_MODE_TEST)
    HttpH3TestRecordDispatch(HttpH3TestDispatchKind::Http3);
#endif
    ObserveDispatch(context);
    return context->CompletionDelivered ? context->TerminalStatus : STATUS_PENDING;
}

NTSTATUS HttpH3DispatchWait(HttpH3DispatchContext *context, AsyncOperationHandle cancellationOperation) noexcept
{
    if (context == nullptr || context->CompletionFence == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    HttpH3CompletionFence *fence = static_cast<HttpH3CompletionFence *>(context->CompletionFence);
    bool cancellationIssued = false;
    for (;;)
    {
#if defined(WKNET_USER_MODE_TEST)
        {
            std::unique_lock<std::mutex> lock(fence->Lock);
            if (fence->Signaled)
            {
                return context->TerminalStatus;
            }
            if (cancellationOperation == nullptr)
            {
                fence->Event.wait(lock, [fence]() noexcept { return fence->Signaled; });
                return context->TerminalStatus;
            }
            (void)fence->Event.wait_for(lock, std::chrono::milliseconds(25),
                                        [fence]() noexcept { return fence->Signaled; });
            if (fence->Signaled)
            {
                return context->TerminalStatus;
            }
        }
#else
        LARGE_INTEGER timeout = {};
        LARGE_INTEGER *timeoutPointer = nullptr;
        if (cancellationOperation != nullptr)
        {
            timeout.QuadPart = -250000LL;
            timeoutPointer = &timeout;
        }
        const NTSTATUS waitStatus = KeWaitForSingleObject(&fence->Event, Executive, KernelMode, FALSE, timeoutPointer);
        if (NT_SUCCESS(waitStatus))
        {
            return context->TerminalStatus;
        }
        if (waitStatus != STATUS_TIMEOUT)
        {
            return waitStatus;
        }
#endif
        if (!cancellationIssued && AsyncOperationIsCanceled(cancellationOperation))
        {
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Verbose,
                        "http3.request.cancel.start stream_id=%I64u", context->StreamId);
            HttpH3CancelResult cancelResult = HttpH3CancelResult::AlreadyTerminal;
            const NTSTATUS cancelStatus = HttpH3DispatchRequestCancel(context, &cancelResult);
            if (!NT_SUCCESS(cancelStatus))
            {
                return cancelStatus;
            }
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Verbose,
                        "http3.request.cancel.complete stream_id=%I64u mode=%u", context->StreamId,
                        static_cast<ULONG>(cancelResult));
            cancellationIssued = true;
        }
    }
}

void HttpH3DispatchRelease(HttpH3DispatchContext *context) noexcept
{
    if (context == nullptr)
    {
        return;
    }
    if (context->Peer.Destroy != nullptr)
    {
        context->Peer.Destroy(context->Peer.Context);
    }
    context->Peer = {};
    context->PeerCreated = false;
    FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::SessionHttp3ResponseAccumulator,
                               static_cast<HttpH3ResponseAccumulator *>(context->ResponseAccumulator));
    context->ResponseAccumulator = nullptr;
    FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::SessionHttp3CompletionFence,
                               static_cast<HttpH3CompletionFence *>(context->CompletionFence));
    context->CompletionFence = nullptr;
}

NTSTATUS HttpH3DispatchAdvanceState(HttpH3DispatchContext *context, HttpH3RequestState target, ULONGLONG streamId,
                                    NTSTATUS terminalStatus) noexcept
{
    if (context == nullptr || context->AttemptGeneration == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const HttpH3RequestState current = context->State;
    if (IsTerminalState(current))
    {
        if (target != current)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
        return context->TerminalStatus;
    }
    if (target == HttpH3RequestState::NoStream || static_cast<ULONG>(target) < static_cast<ULONG>(current))
    {
        if (current == HttpH3RequestState::ResponseStarted && target >= HttpH3RequestState::HeadersCommitted &&
            target <= HttpH3RequestState::RequestFullySent)
        {
            return STATUS_SUCCESS;
        }
        return target == current ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
    }
    if (target >= HttpH3RequestState::StreamCreated && target <= HttpH3RequestState::ResponseStarted)
    {
        if (streamId > HttpH3MaximumStreamId)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (context->StreamId == HttpH3UnsetStreamId)
        {
            context->StreamId = streamId;
        }
        else if (context->StreamId != streamId)
        {
            return STATUS_INVALID_DEVICE_STATE;
        }
    }
    if (target == HttpH3RequestState::Completed || target == HttpH3RequestState::Cancelled)
    {
        if (terminalStatus == STATUS_PENDING)
        {
            return STATUS_INVALID_PARAMETER;
        }
        context->TerminalStatus = target == HttpH3RequestState::Cancelled ? STATUS_CANCELLED : terminalStatus;
    }
    else
    {
        context->LastProgressState = target;
    }
    context->State = target;
    ObserveDispatch(context);
    return STATUS_SUCCESS;
}

NTSTATUS HttpH3DispatchRequestCancel(HttpH3DispatchContext *context, HttpH3CancelResult *result) noexcept
{
    if (result != nullptr)
    {
        *result = HttpH3CancelResult::AlreadyTerminal;
    }
    if (context == nullptr || result == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (IsTerminalState(context->State))
    {
        return STATUS_SUCCESS;
    }
    context->CancelRequested = 1;
    if (context->State == HttpH3RequestState::NoStream || context->State == HttpH3RequestState::StreamCreated)
    {
        *result = HttpH3CancelResult::LocalOnly;
    }
    else if (context->State == HttpH3RequestState::HeadersQueued)
    {
        *result = HttpH3CancelResult::CancelQueuedAndFence;
    }
    else
    {
        *result = HttpH3CancelResult::ResetAndStop;
    }
    if (*result != HttpH3CancelResult::LocalOnly && context->Peer.Quic != nullptr && context->Peer.Http3 != nullptr &&
        context->StreamId != HttpH3UnsetStreamId)
    {
        HeapObject<HttpH3CancelApplicationContext> command;
        if (!command.IsValid())
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        command->Dispatch = context;
        const NTSTATUS cancelStatus = ExecuteApplication(context, CancelRequestOnWorker, command.Get());
        if (!NT_SUCCESS(cancelStatus))
        {
            return cancelStatus;
        }
    }
    HttpH3DispatchNotifyComplete(context, STATUS_CANCELLED, http3::H3_REQUEST_CANCELLED);
    return STATUS_SUCCESS;
}

NTSTATUS HttpH3DispatchProcessGoaway(HttpH3DispatchContext *context, ULONGLONG goawayId,
                                     HttpH3GoawayResult *result) noexcept
{
    if (result != nullptr)
    {
        *result = HttpH3GoawayResult::NoActiveStream;
    }
    if (context == nullptr || result == nullptr || goawayId > HttpH3MaximumStreamId || (goawayId & 3ULL) != 0 ||
        (context->GoawayReceived && goawayId > context->LastGoawayId))
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    context->GoawayReceived = true;
    context->LastGoawayId = goawayId;
    if (context->StreamId == HttpH3UnsetStreamId)
    {
        *result = HttpH3GoawayResult::NoActiveStream;
    }
    else if (context->StreamId >= goawayId)
    {
        *result = HttpH3GoawayResult::StreamRejected;
    }
    else
    {
        *result = HttpH3GoawayResult::StreamMayHaveBeenProcessed;
    }
    context->GoawayResult = *result;
    ObserveDispatch(context);
    return STATUS_SUCCESS;
}

void HttpH3DispatchNotifyResponseStarted(HttpH3DispatchContext *context, ULONG statusCode) noexcept
{
    if (context == nullptr || statusCode < 200)
    {
        return;
    }
    context->ResponseStatusCode = statusCode;
    (void)HttpH3DispatchAdvanceState(context, HttpH3RequestState::ResponseStarted, context->StreamId, STATUS_PENDING);
    if (context->DirectCallbacks &&
        context->SendOptions != nullptr &&
        context->SendOptions->ResponseStartCallback != nullptr &&
        statusCode <= 999)
    {
        (void)context->SendOptions->ResponseStartCallback(
            context->SendOptions->CallbackContext,
            static_cast<USHORT>(statusCode));
    }
}

NTSTATUS HttpH3DispatchNotifyHeader(HttpH3DispatchContext *context, const char *name, SIZE_T nameLength,
                                    const char *value, SIZE_T valueLength, bool trailers) noexcept
{
    if (context == nullptr || context->SendOptions == nullptr || (name == nullptr && nameLength != 0) ||
        (value == nullptr && valueLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (context->DirectCallbacks)
    {
        return context->SendOptions->HeaderCallback != nullptr
                   ? context->SendOptions->HeaderCallback(context->SendOptions->CallbackContext, name, nameLength,
                                                          value, valueLength)
                   : STATUS_SUCCESS;
    }
    return AppendResponseField(static_cast<HttpH3ResponseAccumulator *>(context->ResponseAccumulator), name, nameLength,
                               value, valueLength, trailers);
}

NTSTATUS HttpH3DispatchNotifyBody(HttpH3DispatchContext *context, const UCHAR *data, SIZE_T dataLength,
                                  bool finalChunk) noexcept
{
    if (context == nullptr || context->SendOptions == nullptr || (data == nullptr && dataLength != 0) ||
        (context->BodyFinalDelivered && (dataLength != 0 || finalChunk)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (finalChunk)
    {
        context->BodyFinalDelivered = true;
    }
    if (context->DirectCallbacks)
    {
        return context->SendOptions->BodyCallback != nullptr
                   ? context->SendOptions->BodyCallback(context->SendOptions->CallbackContext, data, dataLength,
                                                        finalChunk)
                   : STATUS_SUCCESS;
    }
    return AppendResponseBody(static_cast<HttpH3ResponseAccumulator *>(context->ResponseAccumulator), data, dataLength);
}

void HttpH3DispatchNotifyComplete(HttpH3DispatchContext *context, NTSTATUS status, ULONGLONG applicationError) noexcept
{
    if (!TryClaimDispatchCompletion(context))
    {
        return;
    }
    if (NT_SUCCESS(status))
    {
        status = FinalizeResponse(context);
        if (!NT_SUCCESS(status))
        {
            applicationError = http3::H3_INTERNAL_ERROR;
        }
    }
    context->ApplicationError = applicationError;
    const HttpH3RequestState terminal = context->CancelRequested != 0 || status == STATUS_CANCELLED
                                            ? HttpH3RequestState::Cancelled
                                            : HttpH3RequestState::Completed;
    const NTSTATUS transitionStatus = HttpH3DispatchAdvanceState(context, terminal, context->StreamId, status);
    if (!NT_SUCCESS(transitionStatus) && transitionStatus != status)
    {
        context->TerminalStatus = transitionStatus;
    }
    context->CompletionDelivered = true;
    ObserveDispatch(context);
    SignalCompletionFence(context);
}

bool HttpH3DispatchDefinitelyUnsent(const HttpH3DispatchContext *context) noexcept
{
    return context != nullptr && (context->LastProgressState == HttpH3RequestState::NoStream ||
                                  context->LastProgressState == HttpH3RequestState::StreamCreated);
}

bool HttpH3DispatchResponseStarted(const HttpH3DispatchContext *context) noexcept
{
    return context != nullptr && context->LastProgressState >= HttpH3RequestState::ResponseStarted;
}
} // namespace wknet::session
