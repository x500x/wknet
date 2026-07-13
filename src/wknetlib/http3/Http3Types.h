#pragma once

#include <wknet/WknetConfig.h>

namespace wknet::http3
{
constexpr ULONGLONG H3_NO_ERROR = 0x100;
constexpr ULONGLONG H3_GENERAL_PROTOCOL_ERROR = 0x101;
constexpr ULONGLONG H3_INTERNAL_ERROR = 0x102;
constexpr ULONGLONG H3_STREAM_CREATION_ERROR = 0x103;
constexpr ULONGLONG H3_CLOSED_CRITICAL_STREAM = 0x104;
constexpr ULONGLONG H3_FRAME_UNEXPECTED = 0x105;
constexpr ULONGLONG H3_FRAME_ERROR = 0x106;
constexpr ULONGLONG H3_EXCESSIVE_LOAD = 0x107;
constexpr ULONGLONG H3_ID_ERROR = 0x108;
constexpr ULONGLONG H3_SETTINGS_ERROR = 0x109;
constexpr ULONGLONG H3_MISSING_SETTINGS = 0x10a;
constexpr ULONGLONG H3_REQUEST_REJECTED = 0x10b;
constexpr ULONGLONG H3_REQUEST_CANCELLED = 0x10c;
constexpr ULONGLONG H3_REQUEST_INCOMPLETE = 0x10d;
constexpr ULONGLONG H3_MESSAGE_ERROR = 0x10e;
constexpr ULONGLONG H3_CONNECT_ERROR = 0x10f;
constexpr ULONGLONG H3_VERSION_FALLBACK = 0x110;

constexpr ULONGLONG Http3FrameTypeData = 0x00;
constexpr ULONGLONG Http3FrameTypeHeaders = 0x01;
constexpr ULONGLONG Http3FrameTypeCancelPush = 0x03;
constexpr ULONGLONG Http3FrameTypeSettings = 0x04;
constexpr ULONGLONG Http3FrameTypePushPromise = 0x05;
constexpr ULONGLONG Http3FrameTypeGoaway = 0x07;
constexpr ULONGLONG Http3FrameTypeMaxPushId = 0x0d;

constexpr ULONGLONG Http3SettingQpackMaxTableCapacity = 0x01;
constexpr ULONGLONG Http3SettingMaxFieldSectionSize = 0x06;
constexpr ULONGLONG Http3SettingQpackBlockedStreams = 0x07;
constexpr ULONGLONG Http3SettingEnableConnectProtocol = 0x08;
constexpr ULONGLONG Http3SettingH3Datagram = 0x33;

enum class Http3FrameKind : UCHAR
{
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    ReservedHttp2,
    Unknown
};

enum class Http3SettingKind : UCHAR
{
    QpackMaxTableCapacity,
    MaxFieldSectionSize,
    QpackBlockedStreams,
    EnableConnectProtocol,
    H3Datagram,
    ReservedHttp2,
    Unknown
};

enum class Http3StreamKind : UCHAR
{
    Request,
    Control,
    Push,
    QpackEncoder,
    QpackDecoder,
    UnknownUnidirectional
};

enum class Http3EndpointRole : UCHAR
{
    Client,
    Server
};

struct Http3BufferView final
{
    const UCHAR *Data = nullptr;
    SIZE_T Length = 0;
};
} // namespace wknet::http3
