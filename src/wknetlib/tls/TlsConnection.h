#pragma once

#include "rtl/IScratchAllocator.h"
#include "transport/Transport.h"
#include "tls/CertificateValidator.h"
#include "tls/TlsHandshake13.h"
#include "tls/TlsPolicy.h"
#include "tls/TlsRecord.h"

namespace wknet
{
namespace crypto
{
    class CngProviderCache;
}

namespace tls
{
    constexpr SIZE_T TlsIoBufferLength = TlsRecordHeaderLength + TlsMaxPlaintextLength + 2048;
    constexpr SIZE_T TlsHandshakeBufferLength = 8192;
    constexpr SIZE_T TlsApplicationBufferLength = TlsMaxPlaintextLength + 1;
    constexpr ULONG TlsApplicationMaxEmptyRecords = 16;
    constexpr ULONG TlsApplicationMaxPostHandshakeRecords = 16;
    constexpr ULONG TlsHandshakeMaxRecords = 64;
    constexpr ULONG Tls12DefaultMaxRenegotiations = 1;
    constexpr ULONG Tls12HardMaxRenegotiations = 4;

    struct TlsReceiveDeadline final
    {
        bool Enabled = false;
        ULONGLONG DeadlineMilliseconds = 0;
    };

    enum class TlsHandshakeFailureCategory : ULONG
    {
        None = 0,
        VersionNegotiation = 1,
        CertificateValidation = 2,
        AlpnMismatch = 3,
        NetworkIo = 4,
        DecodeError = 5,
        CryptoError = 6,
        PeerAlert = 7,
        LocalPolicy = 8
    };

    struct TlsHandshakeFailure final
    {
        TlsHandshakeFailureCategory Category = TlsHandshakeFailureCategory::None;
        NTSTATUS Status = STATUS_SUCCESS;
        TlsAlert PeerAlert = {};
        bool HasPeerAlert = false;
        bool BeforeTls13FirstServerHello = false;
    };

    struct TlsClientConnectionOptions final
    {
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const CertificateStore* CertificateStore = nullptr;
        bool VerifyCertificate = true;
        const TlsAlpnProtocol* AlpnProtocols = nullptr;
        SIZE_T AlpnProtocolCount = 0;
        const UCHAR* EarlyData = nullptr;
        SIZE_T EarlyDataLength = 0;
        SIZE_T* EarlyDataBytesSent = nullptr;
        bool* EarlyDataAccepted = nullptr;
        TlsProtocol MinimumProtocol = TlsProtocol::Tls12;
        TlsProtocol MaximumProtocol = TlsProtocol::Tls13;
        TlsPolicy Policy = {};
        ULONG HandshakeReceiveTimeoutMilliseconds = TlsHandshakeReceiveTimeoutMilliseconds;
        Tls13SessionCache* SessionCache = nullptr;
        Tls12SessionCache* Tls12SessionCache = nullptr;
        const TlsClientCredential* ClientCredential = nullptr;
        rtl::IScratchAllocator* HandshakeScratchAllocator = nullptr;
        rtl::IScratchAllocator* CertificateScratchAllocator = nullptr;
        const crypto::CngProviderCache* ProviderCache = nullptr;
        bool EnableSessionResumption = true;
        bool EnableEarlyData = false;
        bool EarlyDataReplaySafe = false;
        SIZE_T Tls13RecordPaddingLength = 0;
        ULONG MaxTls12Renegotiations = Tls12DefaultMaxRenegotiations;
    };

    class TlsConnection;

    NTSTATUS TlsConnectionCreate(_Out_ TlsConnection** connection) noexcept;
    void TlsConnectionClose(_Inout_opt_ TlsConnection* connection) noexcept;
    NTSTATUS TlsConnectionConnect(
        _Inout_ TlsConnection* connection,
        _Inout_ transport::Transport* transport,
        _In_ const TlsClientConnectionOptions* options) noexcept;
    NTSTATUS TlsConnectionSend(
        _Inout_ TlsConnection* connection,
        _Inout_ transport::Transport* transport,
        _In_reads_bytes_(length) const void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesSent) noexcept;
    NTSTATUS TlsConnectionReceive(
        _Inout_ TlsConnection* connection,
        _Inout_ transport::Transport* transport,
        _Out_writes_bytes_(length) void* data,
        SIZE_T length,
        _Out_opt_ SIZE_T* bytesReceived,
        ULONG timeoutMilliseconds = WskOperationTimeoutMilliseconds) noexcept;
    bool TlsConnectionIsEstablished(_In_opt_ const TlsConnection* connection) noexcept;
    const char* TlsConnectionNegotiatedAlpn(_In_opt_ const TlsConnection* connection) noexcept;
    SIZE_T TlsConnectionNegotiatedAlpnLength(_In_opt_ const TlsConnection* connection) noexcept;
    TlsHandshakeFailure TlsConnectionLastHandshakeFailure(
        _In_opt_ const TlsConnection* connection) noexcept;
}
}
