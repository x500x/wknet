#include "msquic_peer.h"

#include <wincrypt.h>
#include <windows.h>
#include <winsock2.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const QUIC_API_TABLE* g_msquic = nullptr;

struct MsQuicPeerServer final
{
    MsQuicPeerOptions Options = {};
    HQUIC Registration = nullptr;
    HQUIC Configuration = nullptr;
    HQUIC Listener = nullptr;
};

struct MsQuicPeerConnection final
{
    MsQuicPeerServer* Server = nullptr;
    HQUIC Connection = nullptr;
    HQUIC ControlStream = nullptr;
    LONG ResponseCount = 0;
    LONG GoawaySent = 0;
};

namespace
{
    struct MsQuicPeerStream final
    {
        MsQuicPeerConnection* Connection = nullptr;
        HQUIC Stream = nullptr;
        bool Unidirectional = false;
        bool Responded = false;
    };

    SRWLOCK g_logLock = SRWLOCK_INIT;

    const char* FindOption(int argc, char** argv, const char* name) noexcept
    {
        for (int index = 1; index + 1 < argc; ++index)
        {
            if (_stricmp(argv[index], name) == 0)
            {
                return argv[index + 1];
            }
        }
        return nullptr;
    }

    bool WriteTextFile(const char* path, const char* text) noexcept
    {
        HANDLE file =
            CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        DWORD written = 0;
        const DWORD length = static_cast<DWORD>(strlen(text));
        const BOOL success = WriteFile(file, text, length, &written, nullptr);
        CloseHandle(file);
        return success && written == length;
    }

    bool ReadBinaryFile(const char* path, uint8_t** data, uint32_t* length) noexcept
    {
        *data = nullptr;
        *length = 0;
        HANDLE file =
            CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        LARGE_INTEGER size = {};
        bool success = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= MAXDWORD;
        uint8_t* bytes = nullptr;
        if (success)
        {
            bytes = static_cast<uint8_t*>(
                HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, static_cast<SIZE_T>(size.QuadPart)));
            success = bytes != nullptr;
        }
        DWORD bytesRead = 0;
        if (success)
        {
            success = ReadFile(file, bytes, static_cast<DWORD>(size.QuadPart), &bytesRead, nullptr) &&
                      bytesRead == static_cast<DWORD>(size.QuadPart);
        }
        CloseHandle(file);
        if (!success)
        {
            HeapFree(GetProcessHeap(), 0, bytes);
            return false;
        }
        *data = bytes;
        *length = bytesRead;
        return true;
    }

    QUIC_STATUS QUIC_API LocalStreamCallback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event) noexcept
    {
        UNREFERENCED_PARAMETER(stream);
        UNREFERENCED_PARAMETER(context);
        if (event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
        {
            MsQuicPeerReleaseSend(event->SEND_COMPLETE.ClientContext);
        }
        return QUIC_STATUS_SUCCESS;
    }

    bool OpenLocalStream(MsQuicPeerConnection* connection, const uint8_t* data, uint32_t length, HQUIC* stream) noexcept
    {
        *stream = nullptr;
        QUIC_STATUS status = g_msquic->StreamOpen(connection->Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                                                  LocalStreamCallback, connection, stream);
        if (QUIC_FAILED(status))
        {
            MsQuicPeerLog(connection->Server->Options, "local StreamOpen failed status=0x%08X", status);
            return false;
        }
        if (!MsQuicPeerQueueSend(*stream, data, length, QUIC_SEND_FLAG_START))
        {
            MsQuicPeerLog(connection->Server->Options, "local StreamSend failed bytes=%u", length);
            g_msquic->StreamClose(*stream);
            *stream = nullptr;
            return false;
        }
        return true;
    }

    QUIC_STATUS QUIC_API RequestStreamCallback(HQUIC stream, void* context, QUIC_STREAM_EVENT* event) noexcept
    {
        auto* request = static_cast<MsQuicPeerStream*>(context);
        switch (event->Type)
        {
        case QUIC_STREAM_EVENT_RECEIVE:
            if ((event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0 && !request->Unidirectional && !request->Responded)
            {
                request->Responded = true;
                if (!MsQuicPeerSendResponse(request->Connection, stream))
                {
                    g_msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0x102);
                }
            }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            if (!request->Unidirectional && !request->Responded)
            {
                request->Responded = true;
                if (!MsQuicPeerSendResponse(request->Connection, stream))
                {
                    g_msquic->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0x102);
                }
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            MsQuicPeerReleaseSend(event->SEND_COMPLETE.ClientContext);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            MsQuicPeerLog(request->Connection->Server->Options, "request cancelled stream=%p", stream);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            g_msquic->StreamClose(stream);
            HeapFree(GetProcessHeap(), 0, request);
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS QUIC_API ConnectionCallback(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event) noexcept
    {
        auto* peerConnection = static_cast<MsQuicPeerConnection*>(context);
        switch (event->Type)
        {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            MsQuicPeerLog(peerConnection->Server->Options, "connection connected");
            if (!MsQuicPeerSendConnectionStreams(peerConnection))
            {
                MsQuicPeerLog(peerConnection->Server->Options, "critical stream initialization failed");
                g_msquic->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0x102);
            }
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            MsQuicPeerLog(peerConnection->Server->Options, "transport shutdown status=0x%08X error=%llu",
                          event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status,
                          static_cast<unsigned long long>(event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode));
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            MsQuicPeerLog(peerConnection->Server->Options, "peer shutdown error=%llu",
                          static_cast<unsigned long long>(event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode));
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        {
            auto* stream =
                static_cast<MsQuicPeerStream*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MsQuicPeerStream)));
            if (stream == nullptr)
            {
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            stream->Connection = peerConnection;
            stream->Stream = event->PEER_STREAM_STARTED.Stream;
            stream->Unidirectional = (event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) != 0;
            g_msquic->SetCallbackHandler(stream->Stream, reinterpret_cast<void*>(RequestStreamCallback), stream);
            break;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            MsQuicPeerLog(peerConnection->Server->Options, "connection shutdown complete");
            g_msquic->ConnectionClose(connection);
            HeapFree(GetProcessHeap(), 0, peerConnection);
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS QUIC_API ListenerCallback(HQUIC listener, void* context, QUIC_LISTENER_EVENT* event) noexcept
    {
        UNREFERENCED_PARAMETER(listener);
        auto* server = static_cast<MsQuicPeerServer*>(context);
        if (event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION)
        {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        auto* connection = static_cast<MsQuicPeerConnection*>(
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MsQuicPeerConnection)));
        if (connection == nullptr)
        {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        connection->Server = server;
        connection->Connection = event->NEW_CONNECTION.Connection;
        g_msquic->SetCallbackHandler(connection->Connection, reinterpret_cast<void*>(ConnectionCallback), connection);
        const QUIC_STATUS status = g_msquic->ConnectionSetConfiguration(connection->Connection, server->Configuration);
        if (QUIC_FAILED(status))
        {
            HeapFree(GetProcessHeap(), 0, connection);
        }
        return status;
    }
} // namespace

bool MsQuicPeerParseOptions(int argc, char** argv, MsQuicPeerOptions* options) noexcept
{
    if (options == nullptr)
    {
        return false;
    }
    *options = {};
    options->Scenario = FindOption(argc, argv, "-Scenario");
    options->Certificate = FindOption(argc, argv, "-Certificate");
    options->PrivateKey = FindOption(argc, argv, "-Key");
    options->ReadyFile = FindOption(argc, argv, "-ReadyFile");
    options->LogFile = FindOption(argc, argv, "-LogFile");
    const char* port = FindOption(argc, argv, "-Port");
    if (port != nullptr)
    {
        const unsigned long value = strtoul(port, nullptr, 10);
        if (value != 0 && value <= 65535)
        {
            options->Port = static_cast<uint16_t>(value);
        }
    }
    return options->Scenario != nullptr && options->Certificate != nullptr && options->PrivateKey != nullptr &&
           options->ReadyFile != nullptr && options->LogFile != nullptr && options->Port != 0;
}

void MsQuicPeerLog(const MsQuicPeerOptions& options, const char* format, ...) noexcept
{
    char message[512] = {};
    va_list arguments;
    va_start(arguments, format);
    const int length = vsprintf_s(message, format, arguments);
    va_end(arguments);
    if (length <= 0)
    {
        return;
    }
    AcquireSRWLockExclusive(&g_logLock);
    HANDLE file = CreateFileA(options.LogFile, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(file, message, static_cast<DWORD>(length), &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&g_logLock);
}

bool MsQuicPeerSendConnectionStreams(MsQuicPeerConnection* connection) noexcept
{
    const uint8_t control[] = {0x00, 0x04, 0x00};
    const uint8_t encoder[] = {0x02};
    const uint8_t decoder[] = {0x03};
    HQUIC encoderStream = nullptr;
    HQUIC decoderStream = nullptr;
    return OpenLocalStream(connection, control, sizeof(control), &connection->ControlStream) &&
           OpenLocalStream(connection, encoder, sizeof(encoder), &encoderStream) &&
           OpenLocalStream(connection, decoder, sizeof(decoder), &decoderStream);
}

bool MsQuicPeerSendGoaway(MsQuicPeerConnection* connection) noexcept
{
    uint8_t frame[16] = {};
    uint32_t length = 0;
    return connection->ControlStream != nullptr && MsQuicPeerBuildGoaway(frame, sizeof(frame), &length) &&
           MsQuicPeerQueueSend(connection->ControlStream, frame, length, QUIC_SEND_FLAG_NONE);
}

bool MsQuicPeerSendResponse(MsQuicPeerConnection* connection, HQUIC stream) noexcept
{
    uint8_t response[4096] = {};
    uint32_t responseLength = 0;
    const MsQuicPeerOptions& options = connection->Server->Options;
    if (_stricmp(options.Scenario, "cancel") == 0 ||
        !MsQuicPeerBuildResponse(options.Scenario, response, sizeof(response), &responseLength))
    {
        return _stricmp(options.Scenario, "cancel") == 0;
    }
    if (_stricmp(options.Scenario, "key-update") == 0 && !MsQuicPeerForceKeyUpdate(connection->Connection))
    {
        return false;
    }
    MsQuicPeerArmImpairment(options);
    if (!MsQuicPeerQueueSend(stream, response, responseLength, QUIC_SEND_FLAG_FIN))
    {
        return false;
    }
    const LONG responseNumber = InterlockedIncrement(&connection->ResponseCount);
    MsQuicPeerLog(options, "response queued count=%ld bytes=%u", responseNumber, responseLength);
    if (_stricmp(options.Scenario, "goaway") == 0 && InterlockedCompareExchange(&connection->GoawaySent, 1, 0) == 0)
    {
        return MsQuicPeerSendGoaway(connection);
    }
    return true;
}

bool MsQuicPeerRun(const MsQuicPeerOptions& options) noexcept
{
    MsQuicPeerServer server = {};
    server.Options = options;
    if (!WriteTextFile(options.LogFile, ""))
    {
        return false;
    }
    QUIC_STATUS status = MsQuicOpen2(&g_msquic);
    if (QUIC_FAILED(status))
    {
        MsQuicPeerLog(options, "MsQuicOpen2 failed status=0x%08X", status);
        return false;
    }
    bool success = MsQuicPeerApplyScenarioGlobalSettings(options);
    if (!success)
    {
        MsQuicPeerLog(options, "scenario global settings failed");
        MsQuicClose(g_msquic);
        g_msquic = nullptr;
        return false;
    }
    QUIC_REGISTRATION_CONFIG registrationConfig = {"wknet-msquic-peer", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    if (success)
    {
        status = g_msquic->RegistrationOpen(&registrationConfig, &server.Registration);
        success = QUIC_SUCCEEDED(status);
        if (!success)
        {
            MsQuicPeerLog(options, "RegistrationOpen failed status=0x%08X", status);
        }
    }
    QUIC_SETTINGS settings = {};
    settings.IdleTimeoutMs = 30000;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.PeerBidiStreamCount = 100;
    settings.IsSet.PeerBidiStreamCount = TRUE;
    settings.PeerUnidiStreamCount = 16;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    settings.MinimumMtu = 1200;
    settings.IsSet.MinimumMtu = TRUE;
    settings.MaximumMtu = 1200;
    settings.IsSet.MaximumMtu = TRUE;
    const uint8_t alpnBytes[] = {'h', '3'};
    const QUIC_BUFFER alpn = {sizeof(alpnBytes), const_cast<uint8_t*>(alpnBytes)};
    if (success)
    {
        status = g_msquic->ConfigurationOpen(server.Registration, &alpn, 1, &settings, sizeof(settings), nullptr,
                                             &server.Configuration);
        success = QUIC_SUCCEEDED(status);
        if (!success)
        {
            MsQuicPeerLog(options, "ConfigurationOpen failed status=0x%08X", status);
        }
    }
    QUIC_CREDENTIAL_CONFIG credential = {};
    credential.Flags = QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
    credential.AllowedCipherSuites = QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256;
    QUIC_CERTIFICATE_FILE certificateFile = {};
    uint8_t* pkcs12Bytes = nullptr;
    uint32_t pkcs12Length = 0;
    HCERTSTORE certificateStore = nullptr;
    PCCERT_CONTEXT certificateContext = nullptr;
    const char* certificateExtension = strrchr(options.Certificate, '.');
    if (certificateExtension != nullptr &&
        (_stricmp(certificateExtension, ".pfx") == 0 || _stricmp(certificateExtension, ".p12") == 0))
    {
        success = ReadBinaryFile(options.Certificate, &pkcs12Bytes, &pkcs12Length);
        if (success)
        {
            CRYPT_DATA_BLOB pfx = {pkcs12Length, pkcs12Bytes};
            certificateStore = PFXImportCertStore(&pfx, L"wknet-msquic-test", CRYPT_USER_KEYSET);
            success = certificateStore != nullptr;
        }
        if (success)
        {
            certificateContext = CertEnumCertificatesInStore(certificateStore, nullptr);
            success = certificateContext != nullptr;
        }
        credential.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
        credential.CertificateContext =
            reinterpret_cast<QUIC_CERTIFICATE*>(const_cast<CERT_CONTEXT*>(certificateContext));
    }
    else
    {
        certificateFile.CertificateFile = options.Certificate;
        certificateFile.PrivateKeyFile = options.PrivateKey;
        credential.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        credential.CertificateFile = &certificateFile;
    }
    if (success)
    {
        status = g_msquic->ConfigurationLoadCredential(server.Configuration, &credential);
        success = QUIC_SUCCEEDED(status);
        if (!success)
        {
            MsQuicPeerLog(options, "ConfigurationLoadCredential failed status=0x%08X", status);
        }
    }
    if (pkcs12Bytes != nullptr)
    {
        SecureZeroMemory(pkcs12Bytes, pkcs12Length);
        HeapFree(GetProcessHeap(), 0, pkcs12Bytes);
        pkcs12Bytes = nullptr;
    }
    if (certificateContext != nullptr)
    {
        CertFreeCertificateContext(certificateContext);
        certificateContext = nullptr;
    }
    if (certificateStore != nullptr)
    {
        CertCloseStore(certificateStore, 0);
        certificateStore = nullptr;
    }
    if (success)
    {
        status = g_msquic->ListenerOpen(server.Registration, ListenerCallback, &server, &server.Listener);
        success = QUIC_SUCCEEDED(status);
        if (!success)
        {
            MsQuicPeerLog(options, "ListenerOpen failed status=0x%08X", status);
        }
    }
    QUIC_ADDR address = {};
    address.Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
    address.Ipv4.sin_port = _stricmp(options.Scenario, "loss-reorder") == 0 ? 0 : htons(options.Port);
    address.Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (success)
    {
        status = g_msquic->ListenerStart(server.Listener, &alpn, 1, &address);
        success = QUIC_SUCCEEDED(status);
        if (!success)
        {
            MsQuicPeerLog(options, "ListenerStart failed status=0x%08X", status);
        }
    }
    if (success && _stricmp(options.Scenario, "loss-reorder") == 0)
    {
        QUIC_ADDR listenerAddress = {};
        uint32_t listenerAddressLength = sizeof(listenerAddress);
        status = g_msquic->GetParam(server.Listener, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &listenerAddressLength,
                                    &listenerAddress);
        success = QUIC_SUCCEEDED(status) && listenerAddressLength == sizeof(listenerAddress) &&
                  listenerAddress.Ipv4.sin_family == QUIC_ADDRESS_FAMILY_INET && listenerAddress.Ipv4.sin_port != 0;
        if (!success)
        {
            MsQuicPeerLog(options, "listener address query failed status=0x%08X length=%u", status,
                          listenerAddressLength);
        }
        else
        {
            success = MsQuicPeerStartImpairment(options, ntohs(listenerAddress.Ipv4.sin_port));
            if (!success)
            {
                MsQuicPeerLog(options, "loss-reorder UDP proxy startup failed");
            }
        }
    }
    if (success)
    {
        char ready[64] = {};
        sprintf_s(ready, "ready port=%u\r\n", options.Port);
        success = WriteTextFile(options.ReadyFile, ready);
    }
    if (success)
    {
        MsQuicPeerLog(options, "listener ready port=%u scenario=%s", options.Port, options.Scenario);
        Sleep(INFINITE);
    }
    if (server.Listener != nullptr)
    {
        g_msquic->ListenerClose(server.Listener);
    }
    MsQuicPeerStopImpairment();
    if (server.Configuration != nullptr)
    {
        g_msquic->ConfigurationClose(server.Configuration);
    }
    if (server.Registration != nullptr)
    {
        g_msquic->RegistrationClose(server.Registration);
    }
    MsQuicClose(g_msquic);
    g_msquic = nullptr;
    return success;
}

int main(int argc, char** argv)
{
    MsQuicPeerOptions options = {};
    if (!MsQuicPeerParseOptions(argc, argv, &options))
    {
        fprintf(stderr, "invalid MsQuic peer arguments\n");
        return 2;
    }
    return MsQuicPeerRun(options) ? 0 : 1;
}
