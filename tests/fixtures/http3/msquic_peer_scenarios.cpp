#include "msquic_peer.h"

#include <windows.h>

#include <stdio.h>
#include <string.h>

namespace
{
    constexpr uint64_t Http3FrameData = 0x00;
    constexpr uint64_t Http3FrameHeaders = 0x01;
    constexpr uint64_t Http3FrameGoaway = 0x07;

    struct MsQuicPeerSendContext final
    {
        QUIC_BUFFER Buffer = {};
        uint8_t Data[1] = {};
    };

    bool AppendVarInt(uint64_t value, uint8_t* output, uint32_t capacity, uint32_t* offset) noexcept
    {
        uint32_t length = 0;
        if (value <= 63)
        {
            length = 1;
        }
        else if (value <= 16383)
        {
            length = 2;
        }
        else if (value <= 1073741823)
        {
            length = 4;
        }
        else if (value <= 4611686018427387903ULL)
        {
            length = 8;
        }
        else
        {
            return false;
        }
        if (*offset > capacity || length > capacity - *offset)
        {
            return false;
        }
        uint64_t encoded = value;
        if (length == 2)
        {
            encoded |= 0x4000ULL;
        }
        else if (length == 4)
        {
            encoded |= 0x80000000ULL;
        }
        else if (length == 8)
        {
            encoded |= 0xc000000000000000ULL;
        }
        for (uint32_t index = 0; index < length; ++index)
        {
            output[*offset + length - index - 1] = static_cast<uint8_t>(encoded & 0xffU);
            encoded >>= 8;
        }
        *offset += length;
        return true;
    }

    bool AppendBytes(const uint8_t* data, uint32_t length, uint8_t* output, uint32_t capacity,
                     uint32_t* offset) noexcept
    {
        if ((data == nullptr && length != 0) || *offset > capacity || length > capacity - *offset)
        {
            return false;
        }
        if (length != 0)
        {
            memcpy(output + *offset, data, length);
            *offset += length;
        }
        return true;
    }

    bool AppendFieldSection(uint32_t contentLength, uint8_t* output, uint32_t capacity, uint32_t* offset) noexcept
    {
        char lengthText[16] = {};
        const int lengthCharacters = sprintf_s(lengthText, "%u", contentLength);
        if (lengthCharacters <= 0 || lengthCharacters > 127)
        {
            return false;
        }
        const uint8_t prefix[] = {0x00, 0x00, 0xd9, 0x54, static_cast<uint8_t>(lengthCharacters)};
        return AppendBytes(prefix, sizeof(prefix), output, capacity, offset) &&
               AppendBytes(reinterpret_cast<const uint8_t*>(lengthText), static_cast<uint32_t>(lengthCharacters),
                           output, capacity, offset);
    }

    bool AppendHeadersFrame(uint32_t contentLength, uint8_t* output, uint32_t capacity, uint32_t* offset) noexcept
    {
        uint8_t fieldSection[32] = {};
        uint32_t fieldSectionLength = 0;
        if (!AppendFieldSection(contentLength, fieldSection, sizeof(fieldSection), &fieldSectionLength) ||
            !AppendVarInt(Http3FrameHeaders, output, capacity, offset) ||
            !AppendVarInt(fieldSectionLength, output, capacity, offset))
        {
            return false;
        }
        return AppendBytes(fieldSection, fieldSectionLength, output, capacity, offset);
    }

    bool AppendTrailerFrame(uint8_t* output, uint32_t capacity, uint32_t* offset) noexcept
    {
        const uint8_t fieldSection[] = {0x00, 0x00, 0x5f, 0x4d, 0x04, 'd', 'o', 'n', 'e'};
        return AppendVarInt(Http3FrameHeaders, output, capacity, offset) &&
               AppendVarInt(sizeof(fieldSection), output, capacity, offset) &&
               AppendBytes(fieldSection, sizeof(fieldSection), output, capacity, offset);
    }

    MsQuicPeerSendContext* AllocateSendContext(const uint8_t* data, uint32_t length) noexcept
    {
        if (data == nullptr || length == 0 || length > MAXDWORD - sizeof(MsQuicPeerSendContext))
        {
            return nullptr;
        }
        const SIZE_T allocationBytes = sizeof(MsQuicPeerSendContext) + length - 1;
        auto* context =
            static_cast<MsQuicPeerSendContext*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocationBytes));
        if (context == nullptr)
        {
            return nullptr;
        }
        memcpy(context->Data, data, length);
        context->Buffer.Buffer = context->Data;
        context->Buffer.Length = length;
        return context;
    }
} // namespace

bool MsQuicPeerBuildResponse(const char* scenario, uint8_t* output, uint32_t capacity, uint32_t* length) noexcept
{
    if (scenario == nullptr || output == nullptr || length == nullptr)
    {
        return false;
    }
    *length = 0;
    const bool head = _stricmp(scenario, "head-no-body") == 0;
    const bool post = _stricmp(scenario, "post-request-body") == 0;
    const bool trailers = _stricmp(scenario, "trailers") == 0;
    const bool lossReorder = _stricmp(scenario, "loss-reorder") == 0;
    static const uint8_t normalBody[] = "wknet-http3-aioquic";
    static const uint8_t postBody[] = "received:21";
    const uint8_t* body = post ? postBody : normalBody;
    uint32_t bodyLength = post ? sizeof(postBody) - 1 : sizeof(normalBody) - 1;
    if (lossReorder)
    {
        body = nullptr;
        bodyLength = 3000;
    }
    if (!AppendHeadersFrame(bodyLength, output, capacity, length))
    {
        return false;
    }
    if (!head)
    {
        if (!AppendVarInt(Http3FrameData, output, capacity, length) ||
            !AppendVarInt(bodyLength, output, capacity, length))
        {
            return false;
        }
        if (lossReorder)
        {
            if (*length > capacity || bodyLength > capacity - *length)
            {
                return false;
            }
            memset(output + *length, 'L', bodyLength);
            *length += bodyLength;
        }
        else if (!AppendBytes(body, bodyLength, output, capacity, length))
        {
            return false;
        }
    }
    return !trailers || AppendTrailerFrame(output, capacity, length);
}

bool MsQuicPeerQueueSend(HQUIC stream, const uint8_t* data, uint32_t length, QUIC_SEND_FLAGS flags) noexcept
{
    MsQuicPeerSendContext* context = AllocateSendContext(data, length);
    if (context == nullptr)
    {
        return false;
    }
    const QUIC_STATUS status = g_msquic->StreamSend(stream, &context->Buffer, 1, flags, context);
    if (QUIC_FAILED(status))
    {
        HeapFree(GetProcessHeap(), 0, context);
        return false;
    }
    return true;
}

void MsQuicPeerReleaseSend(void* clientContext) noexcept
{
    if (clientContext != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, clientContext);
    }
}

bool MsQuicPeerBuildGoaway(uint8_t* output, uint32_t capacity, uint32_t* length) noexcept
{
    *length = 0;
    return AppendVarInt(Http3FrameGoaway, output, capacity, length) && AppendVarInt(1, output, capacity, length) &&
           AppendVarInt(4, output, capacity, length);
}
