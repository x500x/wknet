#pragma once

#include "http3/Http3Types.h"

namespace wknet::http3
{
struct Http3FrameHeader final
{
    ULONGLONG Type = 0;
    ULONGLONG Length = 0;
    Http3FrameKind Kind = Http3FrameKind::Unknown;
};

struct Http3VarIntParser final
{
    UCHAR Bytes[8] = {};
    UCHAR Count = 0;
    UCHAR Expected = 0;
    bool Complete = false;
    ULONGLONG Value = 0;
};

enum class Http3FrameHeaderPhase : UCHAR
{
    Type,
    Length,
    Complete,
    Failed
};

struct Http3FrameHeaderParser final
{
    Http3FrameHeader Header = {};
    Http3VarIntParser VarInt = {};
    Http3FrameHeaderPhase Phase = Http3FrameHeaderPhase::Type;
};

struct Http3FramePayloadCursor final
{
    ULONGLONG Remaining = 0;
};

struct Http3SingleValueParser final
{
    Http3VarIntParser VarInt = {};
    ULONGLONG Remaining = 0;
    bool Complete = false;
    bool Failed = false;
};

struct Http3Setting final
{
    ULONGLONG Identifier = 0;
    ULONGLONG Value = 0;
    Http3SettingKind Kind = Http3SettingKind::Unknown;
};

struct Http3SettingsParser final
{
    Http3VarIntParser VarInt = {};
    ULONGLONG Remaining = 0;
    ULONGLONG CurrentIdentifier = 0;
    ULONGLONG *SeenIdentifiers = nullptr;
    SIZE_T SeenCapacity = 0;
    SIZE_T SeenCount = 0;
    bool ReadingIdentifier = true;
    bool Complete = false;
    bool Failed = false;
};

Http3FrameKind Http3ClassifyFrameType(ULONGLONG type) noexcept;
Http3SettingKind Http3ClassifySettingIdentifier(ULONGLONG identifier) noexcept;

void Http3FrameHeaderParserInitialize(_Out_ Http3FrameHeaderParser *parser) noexcept;

NTSTATUS Http3ConsumeFrameHeader(_Inout_ Http3FrameHeaderParser *parser,
                                 _In_reads_bytes_opt_(dataLength) const UCHAR *data, SIZE_T dataLength,
                                 _Out_ SIZE_T *bytesConsumed, _Out_ bool *complete) noexcept;

void Http3FramePayloadCursorInitialize(_Out_ Http3FramePayloadCursor *cursor, ULONGLONG payloadLength) noexcept;

NTSTATUS Http3ConsumeFramePayload(_Inout_ Http3FramePayloadCursor *cursor,
                                  _In_reads_bytes_opt_(dataLength) const UCHAR *data, SIZE_T dataLength,
                                  _Out_ Http3BufferView *view, _Out_ SIZE_T *bytesConsumed,
                                  _Out_ bool *complete) noexcept;

void Http3SingleValueParserInitialize(_Out_ Http3SingleValueParser *parser, ULONGLONG payloadLength) noexcept;

NTSTATUS Http3ConsumeSingleValuePayload(_Inout_ Http3SingleValueParser *parser,
                                        _In_reads_bytes_opt_(dataLength) const UCHAR *data, SIZE_T dataLength,
                                        _Out_ SIZE_T *bytesConsumed, _Out_ bool *complete, _Out_ ULONGLONG *value,
                                        _Out_ ULONGLONG *applicationError) noexcept;

NTSTATUS Http3SettingsParserInitialize(_Out_ Http3SettingsParser *parser, ULONGLONG payloadLength,
                                       _Out_writes_opt_(identifierCapacity) ULONGLONG *identifierStorage,
                                       SIZE_T identifierCapacity) noexcept;

NTSTATUS Http3ConsumeSettings(_Inout_ Http3SettingsParser *parser, _In_reads_bytes_opt_(dataLength) const UCHAR *data,
                              SIZE_T dataLength, _Out_ SIZE_T *bytesConsumed, _Out_ bool *settingReady,
                              _Out_ Http3Setting *setting, _Out_ bool *complete,
                              _Out_ ULONGLONG *applicationError) noexcept;

NTSTATUS Http3ValidateFramePlacement(Http3FrameKind frameKind, Http3StreamKind streamKind, Http3EndpointRole senderRole,
                                     _Out_ ULONGLONG *applicationError) noexcept;
} // namespace wknet::http3
