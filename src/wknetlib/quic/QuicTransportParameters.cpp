#include "quic/QuicTransportParameters.h"
#include "quic/QuicVarInt.h"

namespace wknet::quic
{
namespace
{
enum : ULONGLONG
{
    TpOriginalDcid = 0x00,
    TpMaxIdleTimeout = 0x01,
    TpStatelessResetToken = 0x02,
    TpMaxUdpPayloadSize = 0x03,
    TpInitialMaxData = 0x04,
    TpInitialMaxStreamDataBidiLocal = 0x05,
    TpInitialMaxStreamDataBidiRemote = 0x06,
    TpInitialMaxStreamDataUni = 0x07,
    TpInitialMaxStreamsBidi = 0x08,
    TpInitialMaxStreamsUni = 0x09,
    TpAckDelayExponent = 0x0a,
    TpMaxAckDelay = 0x0b,
    TpDisableActiveMigration = 0x0c,
    TpPreferredAddress = 0x0d,
    TpActiveConnectionIdLimit = 0x0e,
    TpInitialScid = 0x0f,
    TpRetryScid = 0x10
};

USHORT ReadPort(const UCHAR *data) noexcept
{
    return static_cast<USHORT>((static_cast<USHORT>(data[0]) << 8) | data[1]);
}

bool Seen(QuicTransportParameters *parameters, ULONGLONG id) noexcept
{
    for (SIZE_T index = 0; index < parameters->ObservedCount; ++index)
    {
        if (parameters->ObservedIds[index] == id)
            return true;
    }
    if (parameters->ObservedCount >= QuicMaximumTransportParameterCount)
        return true;
    parameters->ObservedIds[parameters->ObservedCount++] = id;
    return false;
}

NTSTATUS DecodeSingleVarInt(QuicBufferView value, ULONGLONG *decoded) noexcept
{
    SIZE_T consumed = 0;
    const NTSTATUS status = QuicDecodeVarInt(value.Data, value.Length, decoded, &consumed);
    if (!NT_SUCCESS(status))
        return status;
    return consumed == value.Length ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
}

NTSTATUS WriteParameter(ULONGLONG id, const UCHAR *value, SIZE_T valueLength, UCHAR *output, SIZE_T capacity,
                        SIZE_T *offset) noexcept
{
    SIZE_T written = 0;
    NTSTATUS status = QuicEncodeVarInt(id, 0, output + *offset, capacity - *offset, &written);
    if (!NT_SUCCESS(status))
        return status;
    *offset += written;
    status = QuicEncodeVarInt(valueLength, 0, output + *offset, capacity - *offset, &written);
    if (!NT_SUCCESS(status))
        return status;
    *offset += written;
    if (valueLength > capacity - *offset)
        return STATUS_BUFFER_TOO_SMALL;
    if (valueLength != 0)
        RtlCopyMemory(output + *offset, value, valueLength);
    *offset += valueLength;
    return STATUS_SUCCESS;
}
} // namespace

NTSTATUS QuicParseTransportParameters(const UCHAR *data, SIZE_T dataLength, QuicTransportParameterPeerRole peerRole,
                                      QuicTransportParameters *parameters) noexcept
{
    if (parameters != nullptr)
        *parameters = {};
    if ((data == nullptr && dataLength != 0) || parameters == nullptr ||
        dataLength > WKNET_HARD_MAX_QUIC_TRANSPORT_PARAMETERS_BYTES)
        return STATUS_INVALID_PARAMETER;
    parameters->MaxUdpPayloadSize = 65527;
    parameters->AckDelayExponent = 3;
    parameters->MaxAckDelay = 25;
    parameters->ActiveConnectionIdLimit = 2;
    SIZE_T offset = 0;
    while (offset < dataLength)
    {
        ULONGLONG id = 0, length64 = 0;
        SIZE_T consumed = 0;
        NTSTATUS status = QuicDecodeVarInt(data + offset, dataLength - offset, &id, &consumed);
        if (!NT_SUCCESS(status))
            return status;
        offset += consumed;
        status = QuicDecodeVarInt(data + offset, dataLength - offset, &length64, &consumed);
        if (!NT_SUCCESS(status))
            return status;
        offset += consumed;
        if (length64 > dataLength || static_cast<SIZE_T>(length64) > dataLength - offset)
            return STATUS_INVALID_NETWORK_RESPONSE;
        if (Seen(parameters, id))
            return STATUS_INVALID_NETWORK_RESPONSE;
        QuicBufferView value = {data + offset, static_cast<SIZE_T>(length64)};
        offset += value.Length;
        ULONGLONG decoded = 0;
        const bool serverOnly =
            id == TpOriginalDcid || id == TpStatelessResetToken || id == TpPreferredAddress || id == TpRetryScid;
        if (serverOnly && peerRole != QuicTransportParameterPeerRole::Server)
            return STATUS_INVALID_NETWORK_RESPONSE;
        switch (id)
        {
        case TpOriginalDcid:
            if (value.Length > QuicMaximumConnectionIdLength)
                return STATUS_INVALID_NETWORK_RESPONSE;
            parameters->OriginalDestinationConnectionId = value;
            break;
        case TpMaxIdleTimeout:
            status = DecodeSingleVarInt(value, &parameters->MaxIdleTimeout);
            break;
        case TpStatelessResetToken:
            if (value.Length != 16)
                return STATUS_INVALID_NETWORK_RESPONSE;
            parameters->StatelessResetToken = value;
            break;
        case TpMaxUdpPayloadSize:
            status = DecodeSingleVarInt(value, &parameters->MaxUdpPayloadSize);
            if (NT_SUCCESS(status) && (parameters->MaxUdpPayloadSize < 1200 || parameters->MaxUdpPayloadSize > 65527))
                status = STATUS_INVALID_NETWORK_RESPONSE;
            break;
        case TpInitialMaxData:
            status = DecodeSingleVarInt(value, &parameters->InitialMaxData);
            break;
        case TpInitialMaxStreamDataBidiLocal:
            status = DecodeSingleVarInt(value, &parameters->InitialMaxStreamDataBidiLocal);
            break;
        case TpInitialMaxStreamDataBidiRemote:
            status = DecodeSingleVarInt(value, &parameters->InitialMaxStreamDataBidiRemote);
            break;
        case TpInitialMaxStreamDataUni:
            status = DecodeSingleVarInt(value, &parameters->InitialMaxStreamDataUni);
            break;
        case TpInitialMaxStreamsBidi:
            status = DecodeSingleVarInt(value, &parameters->InitialMaxStreamsBidi);
            if (NT_SUCCESS(status) && parameters->InitialMaxStreamsBidi > (1ULL << 60))
                status = STATUS_INVALID_NETWORK_RESPONSE;
            break;
        case TpInitialMaxStreamsUni:
            status = DecodeSingleVarInt(value, &parameters->InitialMaxStreamsUni);
            if (NT_SUCCESS(status) && parameters->InitialMaxStreamsUni > (1ULL << 60))
                status = STATUS_INVALID_NETWORK_RESPONSE;
            break;
        case TpAckDelayExponent:
            status = DecodeSingleVarInt(value, &parameters->AckDelayExponent);
            if (NT_SUCCESS(status) && parameters->AckDelayExponent > 20)
                status = STATUS_INVALID_NETWORK_RESPONSE;
            break;
        case TpMaxAckDelay:
            status = DecodeSingleVarInt(value, &parameters->MaxAckDelay);
            if (NT_SUCCESS(status) && parameters->MaxAckDelay >= (1ULL << 14))
                status = STATUS_INVALID_NETWORK_RESPONSE;
            break;
        case TpDisableActiveMigration:
            if (value.Length != 0)
                return STATUS_INVALID_NETWORK_RESPONSE;
            parameters->DisableActiveMigration = true;
            break;
        case TpPreferredAddress:
            if (value.Length < 4 + 2 + 16 + 2 + 1 + 16)
                return STATUS_INVALID_NETWORK_RESPONSE;
            RtlCopyMemory(parameters->PreferredAddress.Ipv4Address, value.Data, 4);
            parameters->PreferredAddress.Ipv4Port = ReadPort(value.Data + 4);
            RtlCopyMemory(parameters->PreferredAddress.Ipv6Address, value.Data + 6, 16);
            parameters->PreferredAddress.Ipv6Port = ReadPort(value.Data + 22);
            {
                const SIZE_T cidLength = value.Data[24];
                if (cidLength > QuicMaximumConnectionIdLength || value.Length != 25 + cidLength + 16)
                    return STATUS_INVALID_NETWORK_RESPONSE;
                parameters->PreferredAddress.ConnectionId = {value.Data + 25, cidLength};
                RtlCopyMemory(parameters->PreferredAddress.StatelessResetToken, value.Data + 25 + cidLength, 16);
                parameters->PreferredAddress.Present = true;
            }
            break;
        case TpActiveConnectionIdLimit:
            status = DecodeSingleVarInt(value, &parameters->ActiveConnectionIdLimit);
            if (NT_SUCCESS(status) && parameters->ActiveConnectionIdLimit < 2)
                status = STATUS_INVALID_NETWORK_RESPONSE;
            break;
        case TpInitialScid:
            if (value.Length > QuicMaximumConnectionIdLength)
                return STATUS_INVALID_NETWORK_RESPONSE;
            parameters->InitialSourceConnectionId = value;
            break;
        case TpRetryScid:
            if (value.Length > QuicMaximumConnectionIdLength)
                return STATUS_INVALID_NETWORK_RESPONSE;
            parameters->RetrySourceConnectionId = value;
            break;
        default:
            status = STATUS_SUCCESS;
            UNREFERENCED_PARAMETER(decoded);
            break;
        }
        if (!NT_SUCCESS(status))
            return status;
    }
    return STATUS_SUCCESS;
}

NTSTATUS QuicEncodeClientTransportParameters(QuicBufferView initialSourceConnectionId, UCHAR *output, SIZE_T capacity,
                                             SIZE_T *bytesWritten) noexcept
{
    QuicClientTransportParameterOptions options = {};
    options.InitialSourceConnectionId = initialSourceConnectionId;
    options.DisableActiveMigration = true;
    return QuicEncodeClientTransportParametersWithLimits(options, output, capacity, bytesWritten);
}

NTSTATUS QuicEncodeClientTransportParametersWithLimits(const QuicClientTransportParameterOptions &options,
                                                       UCHAR *output, SIZE_T capacity, SIZE_T *bytesWritten) noexcept
{
    if (bytesWritten != nullptr)
    {
        *bytesWritten = 0;
    }
    if (output == nullptr || bytesWritten == nullptr ||
        options.InitialSourceConnectionId.Length > QuicMaximumConnectionIdLength ||
        (options.InitialSourceConnectionId.Data == nullptr && options.InitialSourceConnectionId.Length != 0) ||
        options.MaxIdleTimeout > QuicVarIntMaximum || options.InitialMaxData > QuicVarIntMaximum ||
        options.InitialMaxStreamDataBidiLocal > QuicVarIntMaximum ||
        options.InitialMaxStreamDataBidiRemote > QuicVarIntMaximum ||
        options.InitialMaxStreamDataUni > QuicVarIntMaximum || options.InitialMaxStreamsBidi > (1ULL << 60) ||
        options.InitialMaxStreamsUni > (1ULL << 60) || options.ActiveConnectionIdLimit < 2 ||
        options.ActiveConnectionIdLimit > QuicVarIntMaximum)
    {
        return STATUS_INVALID_PARAMETER;
    }

    HeapArray<UCHAR> encoded(8);
    if (!encoded.IsValid())
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SIZE_T encodedLength = 0;
    NTSTATUS status = QuicEncodeVarInt(1200, 0, encoded.Get(), encoded.Count(), &encodedLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SIZE_T offset = 0;
    status = WriteParameter(TpMaxUdpPayloadSize, encoded.Get(), encodedLength, output, capacity, &offset);
    if (NT_SUCCESS(status) && options.MaxIdleTimeout != 0)
    {
        status = QuicEncodeVarInt(options.MaxIdleTimeout, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpMaxIdleTimeout, encoded.Get(), encodedLength, output, capacity, &offset);
        }
    }
    if (NT_SUCCESS(status) && options.InitialMaxData != 0)
    {
        status = QuicEncodeVarInt(options.InitialMaxData, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpInitialMaxData, encoded.Get(), encodedLength, output, capacity, &offset);
        }
    }
    if (NT_SUCCESS(status) && options.InitialMaxStreamDataBidiLocal != 0)
    {
        status =
            QuicEncodeVarInt(options.InitialMaxStreamDataBidiLocal, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpInitialMaxStreamDataBidiLocal, encoded.Get(), encodedLength, output, capacity,
                                    &offset);
        }
    }
    if (NT_SUCCESS(status) && options.InitialMaxStreamDataBidiRemote != 0)
    {
        status =
            QuicEncodeVarInt(options.InitialMaxStreamDataBidiRemote, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpInitialMaxStreamDataBidiRemote, encoded.Get(), encodedLength, output, capacity,
                                    &offset);
        }
    }
    if (NT_SUCCESS(status) && options.InitialMaxStreamDataUni != 0)
    {
        status = QuicEncodeVarInt(options.InitialMaxStreamDataUni, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpInitialMaxStreamDataUni, encoded.Get(), encodedLength, output, capacity, &offset);
        }
    }
    if (NT_SUCCESS(status) && options.InitialMaxStreamsBidi != 0)
    {
        status = QuicEncodeVarInt(options.InitialMaxStreamsBidi, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpInitialMaxStreamsBidi, encoded.Get(), encodedLength, output, capacity, &offset);
        }
    }
    if (NT_SUCCESS(status) && options.InitialMaxStreamsUni != 0)
    {
        status = QuicEncodeVarInt(options.InitialMaxStreamsUni, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpInitialMaxStreamsUni, encoded.Get(), encodedLength, output, capacity, &offset);
        }
    }
    if (NT_SUCCESS(status))
    {
        status = QuicEncodeVarInt(options.ActiveConnectionIdLimit, 0, encoded.Get(), encoded.Count(), &encodedLength);
        if (NT_SUCCESS(status))
        {
            status = WriteParameter(TpActiveConnectionIdLimit, encoded.Get(), encodedLength, output, capacity, &offset);
        }
    }
    if (NT_SUCCESS(status) && options.DisableActiveMigration)
    {
        status = WriteParameter(TpDisableActiveMigration, nullptr, 0, output, capacity, &offset);
    }
    if (NT_SUCCESS(status))
    {
        status = WriteParameter(TpInitialScid, options.InitialSourceConnectionId.Data,
                                options.InitialSourceConnectionId.Length, output, capacity, &offset);
    }
    if (NT_SUCCESS(status))
    {
        *bytesWritten = offset;
    }
    return status;
}
} // namespace wknet::quic
