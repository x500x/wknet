#include "tls/TlsConnection.h"

namespace KernelHttp
{
namespace tls
{
    namespace
    {
        _Must_inspect_result_
        crypto::EcCurve ToEcCurve(TlsNamedGroup group) noexcept
        {
            switch (group) {
            case TlsNamedGroup::Secp256r1:
                return crypto::EcCurve::P256;
            case TlsNamedGroup::Secp384r1:
                return crypto::EcCurve::P384;
            case TlsNamedGroup::Secp521r1:
                return crypto::EcCurve::P521;
            default:
                return crypto::EcCurve::P256;
            }
        }

        _Must_inspect_result_
        crypto::SignatureAlgorithm ToSignatureAlgorithm(TlsSignatureScheme scheme) noexcept
        {
            switch (scheme) {
            case TlsSignatureScheme::RsaPkcs1Sha256:
                return crypto::SignatureAlgorithm::RsaPkcs1Sha256;
            case TlsSignatureScheme::RsaPkcs1Sha384:
                return crypto::SignatureAlgorithm::RsaPkcs1Sha384;
            case TlsSignatureScheme::EcdsaSecp256r1Sha256:
                return crypto::SignatureAlgorithm::EcdsaSha256;
            case TlsSignatureScheme::EcdsaSecp384r1Sha384:
                return crypto::SignatureAlgorithm::EcdsaSha384;
            default:
                return crypto::SignatureAlgorithm::RsaPkcs1Sha256;
            }
        }

        _Must_inspect_result_
        crypto::HashAlgorithm HashForSignature(TlsSignatureScheme scheme) noexcept
        {
            switch (scheme) {
            case TlsSignatureScheme::RsaPkcs1Sha384:
            case TlsSignatureScheme::EcdsaSecp384r1Sha384:
                return crypto::HashAlgorithm::Sha384;
            default:
                return crypto::HashAlgorithm::Sha256;
            }
        }

        _Must_inspect_result_
        bool IsValidBuffer(const void* data, SIZE_T length) noexcept
        {
            return length == 0 || data != nullptr;
        }

        constexpr USHORT TlsExtensionSessionTicket = 35;
        constexpr USHORT TlsExtensionAlpn = 16;

        _Must_inspect_result_
        NTSTATUS ServerHelloHasEmptyExtension(
            const TlsServerHelloView& serverHello,
            USHORT extensionType,
            bool* found) noexcept
        {
            if (found == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *found = false;
            if (serverHello.ExtensionsLength == 0) {
                return STATUS_SUCCESS;
            }

            if (serverHello.Extensions == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            SIZE_T offset = 0;
            while (offset < serverHello.ExtensionsLength) {
                if (serverHello.ExtensionsLength - offset < 4) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const USHORT currentType = static_cast<USHORT>(
                    (static_cast<USHORT>(serverHello.Extensions[offset]) << 8) |
                    serverHello.Extensions[offset + 1]);
                const SIZE_T currentLength =
                    (static_cast<SIZE_T>(serverHello.Extensions[offset + 2]) << 8) |
                    serverHello.Extensions[offset + 3];
                offset += 4;

                if (currentLength > serverHello.ExtensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (currentType == extensionType) {
                    if (*found || currentLength != 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    *found = true;
                }

                offset += currentLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ParseServerHelloAlpn(
            const TlsServerHelloView& serverHello,
            char* alpnOut,
            SIZE_T alpnCapacity,
            SIZE_T* alpnLength) noexcept
        {
            if (alpnOut == nullptr || alpnLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

            *alpnLength = 0;

            if (serverHello.ExtensionsLength == 0 || serverHello.Extensions == nullptr) {
                return STATUS_SUCCESS;
            }

            SIZE_T offset = 0;
            while (offset < serverHello.ExtensionsLength) {
                if (serverHello.ExtensionsLength - offset < 4) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const USHORT currentType = static_cast<USHORT>(
                    (static_cast<USHORT>(serverHello.Extensions[offset]) << 8) |
                    serverHello.Extensions[offset + 1]);
                const SIZE_T currentLength =
                    (static_cast<SIZE_T>(serverHello.Extensions[offset + 2]) << 8) |
                    serverHello.Extensions[offset + 3];
                offset += 4;

                if (currentLength > serverHello.ExtensionsLength - offset) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (currentType == TlsExtensionAlpn) {
                    // ALPN extension: 2 bytes list length, then 1 byte proto length + proto
                    if (currentLength < 4) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const UCHAR* extData = serverHello.Extensions + offset;
                    // Skip list length (2 bytes)
                    SIZE_T protoLen = extData[2];
                    if (protoLen == 0 || protoLen + 3 > currentLength) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (protoLen >= alpnCapacity) {
                        return STATUS_BUFFER_TOO_SMALL;
                    }
                    for (SIZE_T i = 0; i < protoLen; ++i) {
                        alpnOut[i] = static_cast<char>(extData[3 + i]);
                    }
                    alpnOut[protoLen] = '\0';
                    *alpnLength = protoLen;
                    return STATUS_SUCCESS;
                }

                offset += currentLength;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS SendAll(net::WskSocket& socket, const UCHAR* data, SIZE_T length) noexcept
        {
            if (!IsValidBuffer(data, length)) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T sentTotal = 0;
            while (sentTotal < length) {
                SIZE_T sent = 0;
                NTSTATUS status = socket.Send(data + sentTotal, length - sentTotal, &sent);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (sent == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                sentTotal += sent;
            }

            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReadExact(net::WskSocket& socket, UCHAR* data, SIZE_T length) noexcept
        {
            if (!IsValidBuffer(data, length)) {
                return STATUS_INVALID_PARAMETER;
            }

            SIZE_T receivedTotal = 0;
            while (receivedTotal < length) {
                SIZE_T received = 0;
                NTSTATUS status = socket.Receive(
                    data + receivedTotal,
                    length - receivedTotal,
                    &received);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (received == 0) {
                    return STATUS_CONNECTION_DISCONNECTED;
                }

                receivedTotal += received;
            }

            return STATUS_SUCCESS;
        }
    }

    TlsConnection::~TlsConnection() noexcept
    {
        Reset();
    }

    void TlsConnection::Reset() noexcept
    {
        context_.Reset();
        clientWriteState_.Reset();
        serverWriteState_.Reset();
        transcript_.Reset();
        RtlSecureZeroMemory(inputBuffer_, sizeof(inputBuffer_));
        RtlSecureZeroMemory(outputBuffer_, sizeof(outputBuffer_));
        RtlSecureZeroMemory(plaintextBuffer_, sizeof(plaintextBuffer_));
        RtlSecureZeroMemory(handshakeBuffer_, sizeof(handshakeBuffer_));
        inputLength_ = 0;
        plaintextLength_ = 0;
        handshakeLength_ = 0;
        handshakeConsumed_ = 0;
        lastHandshakeOffset_ = 0;
        lastHandshakeLength_ = 0;
        encrypted_ = false;
        RtlSecureZeroMemory(negotiatedAlpn_, sizeof(negotiatedAlpn_));
        negotiatedAlpnLength_ = 0;
    }

    NTSTATUS TlsConnection::Connect(
        net::WskSocket& socket,
        const TlsClientConnectionOptions& options) noexcept
    {
        if (!socket.IsConnected() ||
            options.ServerName == nullptr ||
            options.ServerNameLength == 0 ||
            (options.VerifyCertificate && options.CertificateStore == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }

        Reset();

        NTSTATUS status = context_.InitializeClient({ 3, 3 });
        if (NT_SUCCESS(status)) {
            status = transcript_.Initialize(crypto::HashAlgorithm::Sha256);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        UCHAR message[2048] = {};
        SIZE_T messageLength = 0;

        TlsClientHelloOptions hello = {};
        hello.ServerName = options.ServerName;
        hello.ServerNameLength = options.ServerNameLength;
        hello.AlpnProtocols = options.AlpnProtocols;
        hello.AlpnProtocolCount = options.AlpnProtocolCount;

        status = TlsHandshake12::EncodeClientHello(
            context_,
            hello,
            message,
            sizeof(message),
            &messageLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection encode ClientHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        UCHAR clientHello[2048] = {};
        if (messageLength > sizeof(clientHello)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(clientHello, message, messageLength);
        const SIZE_T clientHelloLength = messageLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecord(socket, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send ClientHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsHandshakeMessageView handshake = {};
        status = ReadHandshakeMessage(socket, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read ServerHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context_, handshake, serverHello);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerHello failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }

        bool serverMaySendNewSessionTicket = false;
        status = ServerHelloHasEmptyExtension(serverHello, TlsExtensionSessionTicket, &serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerHello extensions failed: 0x%08X len=%Iu\r\n",
                static_cast<ULONG>(status),
                serverHello.ExtensionsLength);
            return status;
        }
        kprintf("TlsConnection ServerHello cipher=0x%04X sessionTicket=%u extensions=%Iu\r\n",
            static_cast<unsigned>(serverHello.CipherSuite),
            serverMaySendNewSessionTicket ? 1u : 0u,
            serverHello.ExtensionsLength);

        // Parse ALPN from ServerHello
        status = ParseServerHelloAlpn(serverHello, negotiatedAlpn_, sizeof(negotiatedAlpn_), &negotiatedAlpnLength_);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ALPN failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }
        if (negotiatedAlpnLength_ > 0) {
            kprintf("TlsConnection ALPN negotiated: %.*s\r\n",
                static_cast<int>(negotiatedAlpnLength_), negotiatedAlpn_);
        }

        status = transcript_.Initialize(TlsHandshake12::PrfHashForCipherSuite(context_.CipherSuite()));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection reinitialize transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = transcript_.Update(clientHello, clientHelloLength);
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        }
        RtlSecureZeroMemory(clientHello, sizeof(clientHello));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection update transcript after ServerHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = ReadHandshakeMessage(socket, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read Certificate failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsCertificateListView certificates = {};
        status = TlsHandshake12::ParseCertificateList(context_, handshake, certificates);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse Certificate failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }
        kprintf("TlsConnection Certificate count=%Iu bytes=%Iu\r\n",
            certificates.CertificateCount,
            certificates.CertificatesLength);

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.VerifyCertificate = options.VerifyCertificate;

        CertificateValidationResult validationResult = {};
        CertificateChainView chain = {};
        chain.Certificates = certificates.Certificates;
        chain.CertificatesLength = certificates.CertificatesLength;
        chain.CertificateCount = certificates.CertificateCount;
        status = CertificateValidator::ValidateChain(chain, validation, &validationResult);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection validate Certificate failed: 0x%08X count=%Iu bytes=%Iu\r\n",
                static_cast<ULONG>(status),
                chain.CertificateCount,
                chain.CertificatesLength);
            return status;
        }

        crypto::CngKey serverPublicKey;
        status = CertificateValidator::ImportSubjectPublicKey(validationResult.Leaf, serverPublicKey);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection import server public key failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = ReadHandshakeMessage(socket, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read ServerKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsServerKeyExchangeView keyExchange = {};
        status = TlsHandshake12::ParseServerKeyExchange(context_, handshake, keyExchange);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerKeyExchange failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }

        status = VerifyServerKeyExchange(keyExchange, serverPublicKey);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection verify ServerKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        crypto::CngKey peerKey;
        status = crypto::CngProvider::ImportEcdhPublicKey(
            ToEcCurve(keyExchange.NamedGroup),
            keyExchange.EcPoint,
            keyExchange.EcPointLength,
            peerKey);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection import ServerKeyExchange ECDH key failed: 0x%08X group=%u point=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(keyExchange.NamedGroup),
                keyExchange.EcPointLength);
            return status;
        }

        status = ReadHandshakeMessage(socket, handshake, true);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read ServerHelloDone failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            TlsCertificateRequestView request = {};
            status = TlsHandshake12::ParseCertificateRequest(context_, handshake, request);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            message[0] = static_cast<UCHAR>(TlsHandshakeType::Certificate);
            message[1] = 0;
            message[2] = 0;
            message[3] = 3;
            message[4] = 0;
            message[5] = 0;
            message[6] = 0;
            messageLength = 7;

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendPlainRecord(socket, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadHandshakeMessage(socket, handshake, true);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = TlsHandshake12::MarkServerHelloDone(context_, handshake);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection parse ServerHelloDone failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }

        status = GenerateClientKeyExchange(keyExchange.NamedGroup, peerKey, message, sizeof(message), &messageLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection generate ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecord(socket, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        const UCHAR changeCipherSpec[] = { 1 };
        status = SendPlainRecord(socket, TlsContentType::ChangeCipherSpec, changeCipherSpec, sizeof(changeCipherSpec));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send ChangeCipherSpec failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        UCHAR transcriptHash[TlsMaxTranscriptHashLength] = {};
        SIZE_T transcriptHashLength = 0;
        status = FinishTranscript(transcriptHash, sizeof(transcriptHash), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection finish client transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = TlsHandshake12::EncodeFinished(
            context_,
            true,
            transcriptHash,
            transcriptHashLength,
            message,
            sizeof(message),
            &messageLength);
        RtlSecureZeroMemory(transcriptHash, sizeof(transcriptHash));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection encode client Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(socket, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection send client Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = ReadServerChangeCipherSpec(socket, serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read server ChangeCipherSpec failed: 0x%08X allowTicket=%u\r\n",
                static_cast<ULONG>(status),
                serverMaySendNewSessionTicket ? 1u : 0u);
            return status;
        }

        encrypted_ = true;

        status = ReadHandshakeMessage(socket, handshake, false);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read server Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (handshake.Type != TlsHandshakeType::Finished) {
            kprintf("TlsConnection unexpected server Finished type=%u body=%Iu\r\n",
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = FinishTranscript(transcriptHash, sizeof(transcriptHash), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection finish server transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = TlsHandshake12::VerifyFinished(
            context_,
            false,
            transcriptHash,
            transcriptHashLength,
            handshake.Body,
            handshake.BodyLength);
        RtlSecureZeroMemory(transcriptHash, sizeof(transcriptHash));
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection verify server Finished failed: 0x%08X body=%Iu\r\n",
                static_cast<ULONG>(status),
                handshake.BodyLength);
            return status;
        }

        status = AppendTranscript(handshakeBuffer_, handshakeLength_);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection append server Finished transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        context_.SetState(TlsHandshakeState::Established);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::Send(
        net::WskSocket& socket,
        const void* data,
        SIZE_T length,
        SIZE_T* bytesSent) noexcept
    {
        if (bytesSent != nullptr) {
            *bytesSent = 0;
        }

        if (!IsEstablished() || !IsValidBuffer(data, length)) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T sent = 0;
        const UCHAR* bytes = static_cast<const UCHAR*>(data);
        while (sent < length) {
            const SIZE_T chunk = (length - sent) > TlsMaxPlaintextLength ? TlsMaxPlaintextLength : (length - sent);
            NTSTATUS status = SendProtectedRecord(socket, TlsContentType::ApplicationData, bytes + sent, chunk);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            sent += chunk;
        }

        if (bytesSent != nullptr) {
            *bytesSent = sent;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::Receive(
        net::WskSocket& socket,
        void* data,
        SIZE_T length,
        SIZE_T* bytesReceived) noexcept
    {
        if (bytesReceived != nullptr) {
            *bytesReceived = 0;
        }

        if (!IsEstablished() || data == nullptr || length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        if (plaintextLength_ != 0) {
            const SIZE_T copyLength = plaintextLength_ < length ? plaintextLength_ : length;
            RtlCopyMemory(data, plaintextBuffer_, copyLength);

            if (copyLength < plaintextLength_) {
                RtlMoveMemory(plaintextBuffer_, plaintextBuffer_ + copyLength, plaintextLength_ - copyLength);
            }

            plaintextLength_ -= copyLength;
            if (bytesReceived != nullptr) {
                *bytesReceived = copyLength;
            }

            return STATUS_SUCCESS;
        }

        TlsMutablePlaintextRecord record = {};
        NTSTATUS status = ReadRecord(socket, record);
        if (!NT_SUCCESS(status)) {
            kprintf("TlsConnection read record failed before HTTP: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (record.ContentType == TlsContentType::Alert) {
            kprintf("TlsConnection receive alert during HTTP read length=%Iu\r\n", record.FragmentLength);
            return STATUS_CONNECTION_DISCONNECTED;
        }

        if (record.ContentType != TlsContentType::ApplicationData) {
            kprintf("TlsConnection unexpected record during HTTP read type=%u length=%Iu\r\n",
                static_cast<unsigned>(record.ContentType),
                record.FragmentLength);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T copyLength = record.FragmentLength < length ? record.FragmentLength : length;
        if (copyLength != 0) {
            RtlCopyMemory(data, record.Fragment, copyLength);
        }

        if (bytesReceived != nullptr) {
            *bytesReceived = copyLength;
        }

        if (copyLength < record.FragmentLength) {
            plaintextLength_ = record.FragmentLength - copyLength;
            RtlMoveMemory(plaintextBuffer_, record.Fragment + copyLength, plaintextLength_);
        }

        return STATUS_SUCCESS;
    }

    bool TlsConnection::IsEstablished() const noexcept
    {
        return context_.State() == TlsHandshakeState::Established;
    }

    const TlsContext& TlsConnection::Context() const noexcept
    {
        return context_;
    }

    const char* TlsConnection::NegotiatedAlpn() const noexcept
    {
        return negotiatedAlpnLength_ > 0 ? negotiatedAlpn_ : nullptr;
    }

    SIZE_T TlsConnection::NegotiatedAlpnLength() const noexcept
    {
        return negotiatedAlpnLength_;
    }

    NTSTATUS TlsConnection::SendPlainRecord(
        net::WskSocket& socket,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = context_.Version();
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;

        NTSTATUS status = TlsRecordLayer::EncodePlaintext(record, outputBuffer_, sizeof(outputBuffer_), &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(socket, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, sizeof(outputBuffer_));
        return status;
    }

    NTSTATUS TlsConnection::SendProtectedRecord(
        net::WskSocket& socket,
        TlsContentType contentType,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        SIZE_T written = 0;

        TlsPlaintextRecord record = {};
        record.ContentType = contentType;
        record.Version = context_.Version();
        record.Fragment = fragment;
        record.FragmentLength = fragmentLength;

        NTSTATUS status = TlsRecordLayer::ProtectAesGcm(record, clientWriteState_, outputBuffer_, sizeof(outputBuffer_), &written);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SendAll(socket, outputBuffer_, written);
        RtlSecureZeroMemory(outputBuffer_, sizeof(outputBuffer_));
        return status;
    }

    NTSTATUS TlsConnection::ReadRecord(
        net::WskSocket& socket,
        TlsMutablePlaintextRecord& record) noexcept
    {
        record = {};

        for (;;) {
            TlsRecordView view = {};
            NTSTATUS status = TlsRecordLayer::Parse(inputBuffer_, inputLength_, view);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (inputLength_ < TlsRecordHeaderLength) {
                    status = ReadExact(
                        socket,
                        inputBuffer_ + inputLength_,
                        TlsRecordHeaderLength - inputLength_);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    inputLength_ = TlsRecordHeaderLength;
                    continue;
                }

                const SIZE_T fragmentLength =
                    (static_cast<SIZE_T>(inputBuffer_[3]) << 8) | inputBuffer_[4];
                if (fragmentLength > TlsMaxPlaintextLength + 2048) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const SIZE_T recordLength = TlsRecordHeaderLength + fragmentLength;
                if (recordLength > sizeof(inputBuffer_)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                status = ReadExact(
                    socket,
                    inputBuffer_ + inputLength_,
                    recordLength - inputLength_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                inputLength_ = recordLength;
                continue;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (encrypted_ && view.ContentType != TlsContentType::ChangeCipherSpec) {
                status = TlsRecordLayer::UnprotectAesGcm(
                    view,
                    serverWriteState_,
                    plaintextBuffer_,
                    sizeof(plaintextBuffer_),
                    record);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                plaintextLength_ = 0;
            }
            else {
                if (view.FragmentLength > sizeof(plaintextBuffer_)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                record.ContentType = view.ContentType;
                record.Version = view.Version;
                record.FragmentLength = view.FragmentLength;

                if (view.FragmentLength != 0) {
                    RtlCopyMemory(plaintextBuffer_, view.Fragment, view.FragmentLength);
                }

                record.Fragment = plaintextBuffer_;
                plaintextLength_ = 0;
            }

            const SIZE_T consumed = view.BytesConsumed;
            if (consumed < inputLength_) {
                RtlMoveMemory(inputBuffer_, inputBuffer_ + consumed, inputLength_ - consumed);
            }

            inputLength_ -= consumed;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS TlsConnection::ReadServerChangeCipherSpec(
        net::WskSocket& socket,
        bool allowNewSessionTicket) noexcept
    {
        for (;;) {
            TlsMutablePlaintextRecord record = {};
            NTSTATUS status = ReadRecord(socket, record);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection ReadServerChangeCipherSpec ReadRecord failed: 0x%08X\r\n",
                    static_cast<ULONG>(status));
                return status;
            }

            if (record.ContentType == TlsContentType::Alert) {
                kprintf("TlsConnection ReadServerChangeCipherSpec alert length=%Iu\r\n", record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (record.ContentType == TlsContentType::ChangeCipherSpec) {
                if (handshakeLength_ != 0 ||
                    handshakeConsumed_ != 0 ||
                    record.FragmentLength != 1 ||
                    record.Fragment == nullptr ||
                    record.Fragment[0] != 1) {
                    kprintf("TlsConnection invalid server ChangeCipherSpec len=%Iu hs=%Iu consumed=%Iu\r\n",
                        record.FragmentLength,
                        handshakeLength_,
                        handshakeConsumed_);
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                return STATUS_SUCCESS;
            }

            if (record.ContentType != TlsContentType::Handshake) {
                kprintf("TlsConnection expected ChangeCipherSpec got type=%u length=%Iu\r\n",
                    static_cast<unsigned>(record.ContentType),
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (!allowNewSessionTicket) {
                kprintf("TlsConnection got unnegotiated handshake before ChangeCipherSpec length=%Iu\r\n",
                    record.FragmentLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = ConsumeOptionalPlainHandshakeRecord(record.Fragment, record.FragmentLength);
            if (!NT_SUCCESS(status)) {
                kprintf("TlsConnection consume NewSessionTicket failed: 0x%08X length=%Iu\r\n",
                    static_cast<ULONG>(status),
                    record.FragmentLength);
                return status;
            }
        }
    }

    NTSTATUS TlsConnection::ConsumeOptionalPlainHandshakeRecord(const UCHAR* fragment, SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr ||
            fragmentLength == 0 ||
            fragmentLength > sizeof(handshakeBuffer_) - handshakeLength_) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (fragmentLength != 0) {
            RtlCopyMemory(handshakeBuffer_ + handshakeLength_, fragment, fragmentLength);
            handshakeLength_ += fragmentLength;
        }

        for (;;) {
            TlsHandshakeMessageView parsed = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                handshakeBuffer_ + handshakeConsumed_,
                handshakeLength_ - handshakeConsumed_,
                parsed);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (handshakeConsumed_ != 0) {
                    if (handshakeConsumed_ < handshakeLength_) {
                        RtlMoveMemory(
                            handshakeBuffer_,
                            handshakeBuffer_ + handshakeConsumed_,
                            handshakeLength_ - handshakeConsumed_);
                    }

                    handshakeLength_ -= handshakeConsumed_;
                    handshakeConsumed_ = 0;
                }

                return STATUS_SUCCESS;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (parsed.Type != TlsHandshakeType::NewSessionTicket) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (parsed.Body == nullptr || parsed.BodyLength < 6) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const SIZE_T ticketLength =
                (static_cast<SIZE_T>(parsed.Body[4]) << 8) | parsed.Body[5];
            if (ticketLength != parsed.BodyLength - 6) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = AppendTranscript(handshakeBuffer_ + handshakeConsumed_, parsed.BytesConsumed);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            handshakeConsumed_ += parsed.BytesConsumed;
            if (handshakeConsumed_ == handshakeLength_) {
                handshakeLength_ = 0;
                handshakeConsumed_ = 0;
                return STATUS_SUCCESS;
            }
        }
    }

    NTSTATUS TlsConnection::ReadHandshakeMessage(
        net::WskSocket& socket,
        TlsHandshakeMessageView& message,
        bool updateTranscript) noexcept
    {
        message = {};
        lastHandshakeLength_ = 0;
        lastHandshakeOffset_ = handshakeConsumed_;

        for (;;) {
            TlsHandshakeMessageView parsed = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                handshakeBuffer_ + handshakeConsumed_,
                handshakeLength_ - handshakeConsumed_,
                parsed);
            if (status == STATUS_MORE_PROCESSING_REQUIRED) {
                if (handshakeConsumed_ != 0) {
                    if (handshakeConsumed_ < handshakeLength_) {
                        RtlMoveMemory(
                            handshakeBuffer_,
                            handshakeBuffer_ + handshakeConsumed_,
                            handshakeLength_ - handshakeConsumed_);
                    }

                    handshakeLength_ -= handshakeConsumed_;
                    handshakeConsumed_ = 0;
                }

                TlsMutablePlaintextRecord record = {};
                status = ReadRecord(socket, record);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (record.ContentType == TlsContentType::Alert) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                if (record.ContentType != TlsContentType::Handshake ||
                    record.FragmentLength > (sizeof(handshakeBuffer_) - handshakeLength_)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                RtlCopyMemory(handshakeBuffer_ + handshakeLength_, record.Fragment, record.FragmentLength);
                handshakeLength_ += record.FragmentLength;
                continue;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (updateTranscript) {
                status = AppendTranscript(handshakeBuffer_ + handshakeConsumed_, parsed.BytesConsumed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            lastHandshakeOffset_ = handshakeConsumed_;
            lastHandshakeLength_ = parsed.BytesConsumed;
            message = parsed;
            handshakeConsumed_ += parsed.BytesConsumed;
            if (handshakeConsumed_ == handshakeLength_) {
                handshakeLength_ = 0;
                handshakeConsumed_ = 0;
            }

            return STATUS_SUCCESS;
        }
    }

    NTSTATUS TlsConnection::AppendTranscript(const UCHAR* data, SIZE_T length) noexcept
    {
        return transcript_.Update(data, length);
    }

    NTSTATUS TlsConnection::FinishTranscript(UCHAR* digest, SIZE_T capacity, SIZE_T* digestLength) const noexcept
    {
        return transcript_.Finish(digest, capacity, digestLength);
    }

    NTSTATUS TlsConnection::VerifyServerKeyExchange(
        const TlsServerKeyExchangeView& keyExchange,
        const crypto::CngKey& serverPublicKey) noexcept
    {
        UCHAR signedData[(TlsRandomLength * 2) + 256] = {};
        if (keyExchange.ParametersLength > sizeof(signedData) - (TlsRandomLength * 2)) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(signedData, context_.Secrets().ClientRandom, TlsRandomLength);
        RtlCopyMemory(signedData + TlsRandomLength, context_.Secrets().ServerRandom, TlsRandomLength);
        RtlCopyMemory(signedData + (TlsRandomLength * 2), keyExchange.Parameters, keyExchange.ParametersLength);

        UCHAR hash[48] = {};
        SIZE_T hashLength = 0;
        NTSTATUS status = crypto::CngProvider::Hash(
            HashForSignature(keyExchange.SignatureScheme),
            signedData,
            (TlsRandomLength * 2) + keyExchange.ParametersLength,
            hash,
            sizeof(hash),
            &hashLength);
        RtlSecureZeroMemory(signedData, sizeof(signedData));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = crypto::CngProvider::VerifySignature(
            ToSignatureAlgorithm(keyExchange.SignatureScheme),
            serverPublicKey,
            hash,
            hashLength,
            keyExchange.Signature,
            keyExchange.SignatureLength);
        RtlSecureZeroMemory(hash, sizeof(hash));
        return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
    }

    NTSTATUS TlsConnection::GenerateClientKeyExchange(
        TlsNamedGroup namedGroup,
        const crypto::CngKey& peerKey,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (bytesWritten == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *bytesWritten = 0;

        crypto::CngKey privateKey;
        NTSTATUS status = crypto::CngProvider::GenerateEcdhKeyPair(ToEcCurve(namedGroup), privateKey);
        if (!NT_SUCCESS(status)) {
            return status;
        }

#if !defined(KERNEL_HTTP_USER_MODE_TEST)
        UCHAR publicBlob[sizeof(BCRYPT_ECCKEY_BLOB) + (66 * 2)] = {};
        SIZE_T publicBlobLength = 0;
        status = privateKey.ExportPublicKey(BCRYPT_ECCPUBLIC_BLOB, publicBlob, sizeof(publicBlob), &publicBlobLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(publicBlob);
        const SIZE_T pointLength = (static_cast<SIZE_T>(header->cbKey) * 2) + 1;
        UCHAR publicPoint[1 + (66 * 2)] = {};
        if (pointLength > sizeof(publicPoint) ||
            publicBlobLength < sizeof(BCRYPT_ECCKEY_BLOB) + (static_cast<SIZE_T>(header->cbKey) * 2)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        publicPoint[0] = 4;
        RtlCopyMemory(publicPoint + 1, publicBlob + sizeof(BCRYPT_ECCKEY_BLOB), header->cbKey * 2);
#else
        UCHAR publicPoint[65] = {};
        SIZE_T pointLength = 0;
        status = privateKey.ExportPublicKey(L"ECCPUBLICBLOB", publicPoint, sizeof(publicPoint), &pointLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
#endif

        UCHAR premasterSecret[66] = {};
        SIZE_T secretLength = 0;
        status = crypto::CngProvider::DeriveEcdhSecret(
            privateKey,
            peerKey,
            premasterSecret,
            sizeof(premasterSecret),
            &secretLength);
        if (NT_SUCCESS(status)) {
            status = context_.DeriveMasterSecret(premasterSecret, secretLength);
        }
        RtlSecureZeroMemory(premasterSecret, sizeof(premasterSecret));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        TlsKeyBlock keyBlock = {};
        const SIZE_T keyLength =
            (context_.CipherSuite() == TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 ||
                context_.CipherSuite() == TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384) ? 32 : 16;
        status = context_.DeriveKeyBlock(keyBlock, (keyLength * 2) + (TlsAesGcmFixedIvLength * 2));
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureAesGcmStates(keyBlock, clientWriteState_, serverWriteState_);
        }
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        return TlsHandshake12::EncodeClientKeyExchange(
            publicPoint,
            pointLength,
            destination,
            destinationCapacity,
            bytesWritten);
    }
}
}
