#pragma once

#include <msquic.h>

#include <stdint.h>

struct MsQuicPeerOptions final
{
    const char* Scenario = nullptr;
    const char* Certificate = nullptr;
    const char* PrivateKey = nullptr;
    const char* ReadyFile = nullptr;
    const char* LogFile = nullptr;
    uint16_t Port = 0;
};

struct MsQuicPeerServer;
struct MsQuicPeerConnection;

extern const QUIC_API_TABLE* g_msquic;

bool MsQuicPeerParseOptions(int argc, char** argv, MsQuicPeerOptions* options) noexcept;
bool MsQuicPeerRun(const MsQuicPeerOptions& options) noexcept;
void MsQuicPeerLog(const MsQuicPeerOptions& options, const char* format, ...) noexcept;

bool MsQuicPeerBuildResponse(const char* scenario, uint8_t* output, uint32_t capacity, uint32_t* length) noexcept;
bool MsQuicPeerQueueSend(HQUIC stream, const uint8_t* data, uint32_t length, QUIC_SEND_FLAGS flags) noexcept;
void MsQuicPeerReleaseSend(void* clientContext) noexcept;
bool MsQuicPeerBuildGoaway(uint8_t* output, uint32_t capacity, uint32_t* length) noexcept;
bool MsQuicPeerForceKeyUpdate(HQUIC connection) noexcept;
bool MsQuicPeerSendConnectionStreams(MsQuicPeerConnection* connection) noexcept;
bool MsQuicPeerSendResponse(MsQuicPeerConnection* connection, HQUIC stream) noexcept;
bool MsQuicPeerSendGoaway(MsQuicPeerConnection* connection) noexcept;
bool MsQuicPeerApplyScenarioGlobalSettings(const MsQuicPeerOptions& options) noexcept;
bool MsQuicPeerStartImpairment(const MsQuicPeerOptions& options, uint16_t listenerPort) noexcept;
void MsQuicPeerArmImpairment(const MsQuicPeerOptions& options) noexcept;
void MsQuicPeerStopImpairment() noexcept;
