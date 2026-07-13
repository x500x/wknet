#pragma once

#include "quic/QuicTypes.h"

namespace wknet::quic {
    struct QuicPacketHeader final
    {
        QuicPacketType Type = QuicPacketType::Initial;
        ULONG Version = 0;
        bool IsLongHeader = false;
        bool FixedBit = false;
        UCHAR FirstByte = 0;
        QuicBufferView DestinationConnectionId = {};
        QuicBufferView SourceConnectionId = {};
        QuicBufferView Token = {};
        QuicBufferView VersionList = {};
        QuicBufferView RetryIntegrityTag = {};
        SIZE_T HeaderLength = 0;
        SIZE_T PacketNumberOffset = 0;
        SIZE_T PacketNumberLength = 0;
        SIZE_T PayloadOffset = 0;
        SIZE_T PayloadLength = 0;
        SIZE_T PacketLength = 0;
    };

    struct QuicPacketIterator final
    {
        const UCHAR* Datagram = nullptr;
        SIZE_T DatagramLength = 0;
        SIZE_T Offset = 0;
        SIZE_T ShortHeaderDestinationConnectionIdLength = 0;
    };

    NTSTATUS QuicParsePacketHeader(
        _In_reads_bytes_(packetLength) const UCHAR* packet,
        SIZE_T packetLength,
        SIZE_T shortHeaderDestinationConnectionIdLength,
        _Out_ QuicPacketHeader* header) noexcept;

    NTSTATUS QuicEncodePacketNumber(
        ULONGLONG packetNumber,
        SIZE_T packetNumberLength,
        _Out_writes_bytes_(capacity) UCHAR* output,
        SIZE_T capacity,
        _Out_opt_ SIZE_T* bytesWritten) noexcept;

    NTSTATUS QuicReconstructPacketNumber(
        ULONGLONG truncatedPacketNumber,
        SIZE_T packetNumberLength,
        ULONGLONG expectedPacketNumber,
        _Out_ ULONGLONG* packetNumber) noexcept;

    void QuicPacketIteratorInitialize(
        _Out_ QuicPacketIterator* iterator,
        _In_reads_bytes_(datagramLength) const UCHAR* datagram,
        SIZE_T datagramLength,
        SIZE_T shortHeaderDestinationConnectionIdLength) noexcept;

    NTSTATUS QuicPacketIteratorNext(
        _Inout_ QuicPacketIterator* iterator,
        _Out_ QuicPacketHeader* header,
        _Out_ QuicBufferView* packet) noexcept;

    NTSTATUS QuicValidateInitialDatagramLength(SIZE_T datagramLength) noexcept;
}
