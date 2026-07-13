#include "http3/Http3Frame.h"

#include "quic/QuicVarInt.h"

namespace wknet::http3
{
namespace
{
void ResetVarIntParser(Http3VarIntParser *parser) noexcept
{
    if (parser != nullptr)
    {
        *parser = {};
    }
}

NTSTATUS ConsumeVarIntByte(Http3VarIntParser *parser, UCHAR byte) noexcept
{
    if (parser == nullptr || parser->Complete || parser->Count >= sizeof(parser->Bytes))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (parser->Count == 0)
    {
        parser->Expected = static_cast<UCHAR>(1U << (byte >> 6));
    }

    parser->Bytes[parser->Count] = byte;
    ++parser->Count;
    if (parser->Count != parser->Expected)
    {
        return STATUS_SUCCESS;
    }

    SIZE_T consumed = 0;
    const NTSTATUS status = quic::QuicDecodeVarInt(parser->Bytes, parser->Count, &parser->Value, &consumed);
    if (!NT_SUCCESS(status) || consumed != parser->Count)
    {
        return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
    }

    parser->Complete = true;
    return STATUS_SUCCESS;
}

bool IsReservedHttp2FrameType(ULONGLONG type) noexcept
{
    return type == 0x02 || type == 0x06 || type == 0x08 || type == 0x09;
}

bool IsReservedHttp2SettingIdentifier(ULONGLONG identifier) noexcept
{
    return identifier >= 0x02 && identifier <= 0x05;
}

bool IsSeenIdentifier(const Http3SettingsParser &parser, ULONGLONG identifier) noexcept
{
    for (SIZE_T index = 0; index < parser.SeenCount; ++index)
    {
        if (parser.SeenIdentifiers[index] == identifier)
        {
            return true;
        }
    }
    return false;
}

NTSTATUS FailParser(bool *failed, ULONGLONG error, ULONGLONG *applicationError,
                    NTSTATUS status = STATUS_INVALID_NETWORK_RESPONSE) noexcept
{
    if (failed != nullptr)
    {
        *failed = true;
    }
    if (applicationError != nullptr)
    {
        *applicationError = error;
    }
    return status;
}
} // namespace

Http3FrameKind Http3ClassifyFrameType(ULONGLONG type) noexcept
{
    switch (type)
    {
    case Http3FrameTypeData:
        return Http3FrameKind::Data;
    case Http3FrameTypeHeaders:
        return Http3FrameKind::Headers;
    case Http3FrameTypeCancelPush:
        return Http3FrameKind::CancelPush;
    case Http3FrameTypeSettings:
        return Http3FrameKind::Settings;
    case Http3FrameTypePushPromise:
        return Http3FrameKind::PushPromise;
    case Http3FrameTypeGoaway:
        return Http3FrameKind::Goaway;
    case Http3FrameTypeMaxPushId:
        return Http3FrameKind::MaxPushId;
    default:
        return IsReservedHttp2FrameType(type) ? Http3FrameKind::ReservedHttp2 : Http3FrameKind::Unknown;
    }
}

Http3SettingKind Http3ClassifySettingIdentifier(ULONGLONG identifier) noexcept
{
    switch (identifier)
    {
    case Http3SettingQpackMaxTableCapacity:
        return Http3SettingKind::QpackMaxTableCapacity;
    case Http3SettingMaxFieldSectionSize:
        return Http3SettingKind::MaxFieldSectionSize;
    case Http3SettingQpackBlockedStreams:
        return Http3SettingKind::QpackBlockedStreams;
    case Http3SettingEnableConnectProtocol:
        return Http3SettingKind::EnableConnectProtocol;
    case Http3SettingH3Datagram:
        return Http3SettingKind::H3Datagram;
    default:
        return IsReservedHttp2SettingIdentifier(identifier) ? Http3SettingKind::ReservedHttp2
                                                            : Http3SettingKind::Unknown;
    }
}

void Http3FrameHeaderParserInitialize(Http3FrameHeaderParser *parser) noexcept
{
    if (parser != nullptr)
    {
        *parser = {};
    }
}

NTSTATUS Http3ConsumeFrameHeader(Http3FrameHeaderParser *parser, const UCHAR *data, SIZE_T dataLength,
                                 SIZE_T *bytesConsumed, bool *complete) noexcept
{
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (complete != nullptr)
    {
        *complete = false;
    }
    if (parser == nullptr || bytesConsumed == nullptr || complete == nullptr || (data == nullptr && dataLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (parser->Phase == Http3FrameHeaderPhase::Failed)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (parser->Phase == Http3FrameHeaderPhase::Complete)
    {
        *complete = true;
        return STATUS_SUCCESS;
    }

    SIZE_T offset = 0;
    while (offset < dataLength && parser->Phase != Http3FrameHeaderPhase::Complete)
    {
        const NTSTATUS status = ConsumeVarIntByte(&parser->VarInt, data[offset]);
        ++offset;
        if (!NT_SUCCESS(status))
        {
            parser->Phase = Http3FrameHeaderPhase::Failed;
            *bytesConsumed = offset;
            return status;
        }
        if (!parser->VarInt.Complete)
        {
            continue;
        }

        if (parser->Phase == Http3FrameHeaderPhase::Type)
        {
            parser->Header.Type = parser->VarInt.Value;
            parser->Header.Kind = Http3ClassifyFrameType(parser->Header.Type);
            parser->Phase = Http3FrameHeaderPhase::Length;
            ResetVarIntParser(&parser->VarInt);
        }
        else
        {
            parser->Header.Length = parser->VarInt.Value;
            parser->Phase = Http3FrameHeaderPhase::Complete;
        }
    }

    *bytesConsumed = offset;
    *complete = parser->Phase == Http3FrameHeaderPhase::Complete;
    return STATUS_SUCCESS;
}

void Http3FramePayloadCursorInitialize(Http3FramePayloadCursor *cursor, ULONGLONG payloadLength) noexcept
{
    if (cursor != nullptr)
    {
        cursor->Remaining = payloadLength;
    }
}

NTSTATUS Http3ConsumeFramePayload(Http3FramePayloadCursor *cursor, const UCHAR *data, SIZE_T dataLength,
                                  Http3BufferView *view, SIZE_T *bytesConsumed, bool *complete) noexcept
{
    if (view != nullptr)
    {
        *view = {};
    }
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (complete != nullptr)
    {
        *complete = false;
    }
    if (cursor == nullptr || view == nullptr || bytesConsumed == nullptr || complete == nullptr ||
        (data == nullptr && dataLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    const SIZE_T take =
        cursor->Remaining < static_cast<ULONGLONG>(dataLength) ? static_cast<SIZE_T>(cursor->Remaining) : dataLength;
    view->Data = take == 0 ? nullptr : data;
    view->Length = take;
    cursor->Remaining -= take;
    *bytesConsumed = take;
    *complete = cursor->Remaining == 0;
    return STATUS_SUCCESS;
}

void Http3SingleValueParserInitialize(Http3SingleValueParser *parser, ULONGLONG payloadLength) noexcept
{
    if (parser != nullptr)
    {
        *parser = {};
        parser->Remaining = payloadLength;
    }
}

NTSTATUS Http3ConsumeSingleValuePayload(Http3SingleValueParser *parser, const UCHAR *data, SIZE_T dataLength,
                                        SIZE_T *bytesConsumed, bool *complete, ULONGLONG *value,
                                        ULONGLONG *applicationError) noexcept
{
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (complete != nullptr)
    {
        *complete = false;
    }
    if (value != nullptr)
    {
        *value = 0;
    }
    if (applicationError != nullptr)
    {
        *applicationError = H3_NO_ERROR;
    }
    if (parser == nullptr || bytesConsumed == nullptr || complete == nullptr || value == nullptr ||
        applicationError == nullptr || (data == nullptr && dataLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (parser->Failed)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (parser->Complete)
    {
        *complete = true;
        *value = parser->VarInt.Value;
        return STATUS_SUCCESS;
    }
    if (parser->Remaining == 0)
    {
        return FailParser(&parser->Failed, H3_FRAME_ERROR, applicationError);
    }

    SIZE_T offset = 0;
    while (offset < dataLength && parser->Remaining != 0)
    {
        const NTSTATUS status = ConsumeVarIntByte(&parser->VarInt, data[offset]);
        ++offset;
        --parser->Remaining;
        if (!NT_SUCCESS(status))
        {
            *bytesConsumed = offset;
            return FailParser(&parser->Failed, H3_FRAME_ERROR, applicationError);
        }
        if (parser->VarInt.Complete)
        {
            if (parser->Remaining != 0)
            {
                *bytesConsumed = offset;
                return FailParser(&parser->Failed, H3_FRAME_ERROR, applicationError);
            }
            parser->Complete = true;
            *bytesConsumed = offset;
            *complete = true;
            *value = parser->VarInt.Value;
            return STATUS_SUCCESS;
        }
    }

    *bytesConsumed = offset;
    if (parser->Remaining == 0)
    {
        return FailParser(&parser->Failed, H3_FRAME_ERROR, applicationError);
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3SettingsParserInitialize(Http3SettingsParser *parser, ULONGLONG payloadLength,
                                       ULONGLONG *identifierStorage, SIZE_T identifierCapacity) noexcept
{
    if (parser == nullptr || (identifierStorage == nullptr && identifierCapacity != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }

    *parser = {};
    parser->Remaining = payloadLength;
    parser->SeenIdentifiers = identifierStorage;
    parser->SeenCapacity = identifierCapacity;
    parser->ReadingIdentifier = true;
    parser->Complete = payloadLength == 0;
    return STATUS_SUCCESS;
}

NTSTATUS Http3ConsumeSettings(Http3SettingsParser *parser, const UCHAR *data, SIZE_T dataLength, SIZE_T *bytesConsumed,
                              bool *settingReady, Http3Setting *setting, bool *complete,
                              ULONGLONG *applicationError) noexcept
{
    if (bytesConsumed != nullptr)
    {
        *bytesConsumed = 0;
    }
    if (settingReady != nullptr)
    {
        *settingReady = false;
    }
    if (setting != nullptr)
    {
        *setting = {};
    }
    if (complete != nullptr)
    {
        *complete = false;
    }
    if (applicationError != nullptr)
    {
        *applicationError = H3_NO_ERROR;
    }
    if (parser == nullptr || bytesConsumed == nullptr || settingReady == nullptr || setting == nullptr ||
        complete == nullptr || applicationError == nullptr || (data == nullptr && dataLength != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (parser->Failed)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (parser->Complete)
    {
        *complete = true;
        return STATUS_SUCCESS;
    }

    SIZE_T offset = 0;
    while (offset < dataLength && parser->Remaining != 0)
    {
        const NTSTATUS status = ConsumeVarIntByte(&parser->VarInt, data[offset]);
        ++offset;
        --parser->Remaining;
        if (!NT_SUCCESS(status))
        {
            *bytesConsumed = offset;
            return FailParser(&parser->Failed, H3_FRAME_ERROR, applicationError);
        }
        if (!parser->VarInt.Complete)
        {
            continue;
        }

        if (parser->ReadingIdentifier)
        {
            parser->CurrentIdentifier = parser->VarInt.Value;
            parser->ReadingIdentifier = false;
            ResetVarIntParser(&parser->VarInt);
            continue;
        }

        if (IsSeenIdentifier(*parser, parser->CurrentIdentifier))
        {
            *bytesConsumed = offset;
            return FailParser(&parser->Failed, H3_SETTINGS_ERROR, applicationError);
        }
        if (parser->SeenCount >= parser->SeenCapacity)
        {
            *bytesConsumed = offset;
            return FailParser(&parser->Failed, H3_EXCESSIVE_LOAD, applicationError, STATUS_INSUFFICIENT_RESOURCES);
        }

        const Http3SettingKind kind = Http3ClassifySettingIdentifier(parser->CurrentIdentifier);
        if (kind == Http3SettingKind::ReservedHttp2)
        {
            *bytesConsumed = offset;
            return FailParser(&parser->Failed, H3_SETTINGS_ERROR, applicationError);
        }

        parser->SeenIdentifiers[parser->SeenCount] = parser->CurrentIdentifier;
        ++parser->SeenCount;
        setting->Identifier = parser->CurrentIdentifier;
        setting->Value = parser->VarInt.Value;
        setting->Kind = kind;
        *settingReady = true;
        parser->ReadingIdentifier = true;
        ResetVarIntParser(&parser->VarInt);
        if (parser->Remaining == 0)
        {
            parser->Complete = true;
            *complete = true;
        }
        *bytesConsumed = offset;
        return STATUS_SUCCESS;
    }

    *bytesConsumed = offset;
    if (parser->Remaining == 0)
    {
        if (!parser->ReadingIdentifier || parser->VarInt.Count != 0)
        {
            return FailParser(&parser->Failed, H3_FRAME_ERROR, applicationError);
        }
        parser->Complete = true;
        *complete = true;
    }
    return STATUS_SUCCESS;
}

NTSTATUS Http3ValidateFramePlacement(Http3FrameKind frameKind, Http3StreamKind streamKind, Http3EndpointRole senderRole,
                                     ULONGLONG *applicationError) noexcept
{
    if (applicationError == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *applicationError = H3_NO_ERROR;

    bool allowed = false;
    switch (frameKind)
    {
    case Http3FrameKind::Data:
    case Http3FrameKind::Headers:
        allowed = streamKind == Http3StreamKind::Request;
        break;
    case Http3FrameKind::CancelPush:
    case Http3FrameKind::MaxPushId:
        allowed = streamKind == Http3StreamKind::Control && senderRole == Http3EndpointRole::Client;
        break;
    case Http3FrameKind::Settings:
    case Http3FrameKind::Goaway:
        allowed = streamKind == Http3StreamKind::Control;
        break;
    case Http3FrameKind::PushPromise:
        allowed = streamKind == Http3StreamKind::Request && senderRole == Http3EndpointRole::Server;
        break;
    case Http3FrameKind::Unknown:
        allowed = streamKind == Http3StreamKind::Request || streamKind == Http3StreamKind::Control ||
                  streamKind == Http3StreamKind::Push;
        break;
    case Http3FrameKind::ReservedHttp2:
    default:
        allowed = false;
        break;
    }

    if (!allowed)
    {
        *applicationError = H3_FRAME_UNEXPECTED;
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    return STATUS_SUCCESS;
}
} // namespace wknet::http3
