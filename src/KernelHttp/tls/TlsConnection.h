#pragma once

#include "net/WskSocket.h"
#include "tls/CertificateValidator.h"

namespace KernelHttp
{
namespace tls
{
    constexpr SIZE_T TlsIoBufferLength = TlsRecordHeaderLength + TlsMaxPlaintextLength + 2048;
    constexpr SIZE_T TlsHandshakeBufferLength = 8192;
    constexpr SIZE_T TlsApplicationBufferLength = TlsMaxPlaintextLength;

    struct TlsClientConnectionOptions final
    {
        const char* ServerName = nullptr;
        SIZE_T ServerNameLength = 0;
        const CertificateStore* CertificateStore = nullptr;
    };

    class TlsConnection final
    {
    public:
        TlsConnection() noexcept = default;
        ~TlsConnection() noexcept;

        TlsConnection(const TlsConnection&) = delete;
        TlsConnection& operator=(const TlsConnection&) = delete;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Connect(
            _Inout_ net::WskSocket& socket,
            _In_ const TlsClientConnectionOptions& options) noexcept;

        _Must_inspect_result_
        NTSTATUS Send(
            _Inout_ net::WskSocket& socket,
            _In_reads_bytes_(length) const void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesSent = nullptr) noexcept;

        _Must_inspect_result_
        NTSTATUS Receive(
            _Inout_ net::WskSocket& socket,
            _Out_writes_bytes_(length) void* data,
            SIZE_T length,
            _Out_opt_ SIZE_T* bytesReceived = nullptr) noexcept;

        _Must_inspect_result_
        bool IsEstablished() const noexcept;

        const TlsContext& Context() const noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS SendPlainRecord(
            _Inout_ net::WskSocket& socket,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS SendProtectedRecord(
            _Inout_ net::WskSocket& socket,
            TlsContentType contentType,
            _In_reads_bytes_(fragmentLength) const UCHAR* fragment,
            SIZE_T fragmentLength) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadRecord(
            _Inout_ net::WskSocket& socket,
            _Out_ TlsMutablePlaintextRecord& record) noexcept;

        _Must_inspect_result_
        NTSTATUS ReadHandshakeMessage(
            _Inout_ net::WskSocket& socket,
            _Out_ TlsHandshakeMessageView& message,
            bool updateTranscript) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendTranscript(
            _In_reads_bytes_(length) const UCHAR* data,
            SIZE_T length) noexcept;

        _Must_inspect_result_
        NTSTATUS FinishTranscript(
            _Out_writes_bytes_(capacity) UCHAR* digest,
            SIZE_T capacity,
            _Out_ SIZE_T* digestLength) const noexcept;

        _Must_inspect_result_
        NTSTATUS VerifyServerKeyExchange(
            _In_ const TlsServerKeyExchangeView& keyExchange,
            _In_ const ParsedCertificate& leafCertificate) noexcept;

        _Must_inspect_result_
        NTSTATUS GenerateClientKeyExchange(
            _In_ const TlsServerKeyExchangeView& keyExchange,
            _Out_writes_bytes_(destinationCapacity) UCHAR* destination,
            SIZE_T destinationCapacity,
            _Out_ SIZE_T* bytesWritten) noexcept;

        TlsContext context_ = {};
        TlsAeadCipherState clientWriteState_ = {};
        TlsAeadCipherState serverWriteState_ = {};
        TlsTranscriptHash transcript_ = {};
        UCHAR inputBuffer_[TlsIoBufferLength] = {};
        UCHAR outputBuffer_[TlsIoBufferLength] = {};
        SIZE_T inputLength_ = 0;
        UCHAR plaintextBuffer_[TlsApplicationBufferLength] = {};
        SIZE_T plaintextLength_ = 0;
        UCHAR handshakeBuffer_[TlsHandshakeBufferLength] = {};
        SIZE_T handshakeLength_ = 0;
        SIZE_T handshakeConsumed_ = 0;
        SIZE_T lastHandshakeOffset_ = 0;
        SIZE_T lastHandshakeLength_ = 0;
        bool encrypted_ = false;
    };
}
}
