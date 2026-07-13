#include "tls/TlsConnectionInternal.hpp"

namespace wknet
{
namespace tls
{
    NTSTATUS TlsConnection::ConnectTls13(
        transport::Transport* transport,
        const TlsClientConnectionOptions& options) noexcept
    {
        tls13RecordProtection_ = false;
        encrypted_ = false;

        NTSTATUS status = context_.InitializeClient13();
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("InitializeClient13", status);
        }
        status = transcript_.Initialize(crypto::HashAlgorithm::Sha256);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("InitializeSha256Transcript", status);
        }
        if (options.EarlyDataAccepted != nullptr) {
            *options.EarlyDataAccepted = false;
        }
        if (options.EarlyDataBytesSent != nullptr) {
            *options.EarlyDataBytesSent = 0;
        }
        RtlSecureZeroMemory(tls13TicketServerName_, sizeof(tls13TicketServerName_));
        tls13TicketServerNameLength_ = 0;
        tls13TicketServerNameCacheable_ = options.ServerNameLength <= Tls13MaxTicketServerNameLength;
        if (tls13TicketServerNameCacheable_) {
            RtlCopyMemory(tls13TicketServerName_, options.ServerName, options.ServerNameLength);
            tls13TicketServerName_[options.ServerNameLength] = '\0';
            tls13TicketServerNameLength_ = options.ServerNameLength;
        }

        HeapObject<crypto::KeyExchangeKeyPair> keyPair;
        if (!keyPair.IsValid()) {
            return LogTls13Failure("AllocateClientKeyExchangePair", STATUS_INSUFFICIENT_RESOURCES);
        }

        status = crypto::KeyExchange::GenerateKeyPair(
            providerCache_,
            crypto::KeyExchangeGroup::X25519,
            *keyPair.Get());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GenerateInitialKeyShare", status);
        }

        Tls13KeyShareEntry keyShare = {};
        keyShare.Group = TlsNamedGroup::X25519;
        keyShare.KeyExchange = keyPair->PublicKey;
        keyShare.KeyExchangeLength = keyPair->PublicKeyLength;

        Tls13PskIdentity pskIdentity = {};
        const UCHAR* resumptionSecret = nullptr;
        SIZE_T resumptionSecretLength = 0;
        bool earlyDataAllowed = false;
        const Tls13SessionTicket* selectedTicket = nullptr;
        status = SelectTls13Ticket(
            options,
            pskIdentity,
            &resumptionSecret,
            &resumptionSecretLength,
            &earlyDataAllowed,
            &selectedTicket);
        if (status == STATUS_NOT_FOUND) {
            status = STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("SelectTls13Ticket", status);
        }

        HeapArray<UCHAR> binder(Tls13MaxBinderLength);
        if (!binder.IsValid()) {
            return LogTls13Failure("AllocatePskBinder", STATUS_INSUFFICIENT_RESOURCES);
        }
        if (pskIdentity.IdentityLength != 0) {
            pskIdentity.Binder = binder.Get();
            pskIdentity.BinderLength = context_.CipherSuite() == TlsCipherSuite::TlsAes256GcmSha384 ? 48 : 32;
        }

        Tls13ClientHelloOptions hello = {};
        hello.ServerName = options.ServerName;
        hello.ServerNameLength = options.ServerNameLength;
        hello.AlpnProtocols = options.AlpnProtocols;
        hello.AlpnProtocolCount = options.AlpnProtocolCount;
        hello.KeyShares = &keyShare;
        hello.KeyShareCount = 1;
        hello.PskIdentities = pskIdentity.IdentityLength != 0 ? &pskIdentity : nullptr;
        hello.PskIdentityCount = pskIdentity.IdentityLength != 0 ? 1 : 0;
        hello.OfferEarlyData = options.EnableEarlyData && earlyDataAllowed;

        UCHAR* message = nullptr;
        status = GetHandshakeScratch(
            TlsScratchClientHelloOffset,
            TlsScratchClientHelloLength,
            &message);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetClientHelloScratch", status);
        }
        RtlSecureZeroMemory(message, TlsScratchClientHelloLength);
        SIZE_T messageLength = 0;
        status = TlsHandshake13::EncodeClientHello(
            context_,
            hello,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("EncodeInitialClientHello", status);
        }

        if (pskIdentity.IdentityLength != 0) {
            status = ComputePskBinderForClientHello(
                providerCache_,
                context_,
                resumptionSecret,
                resumptionSecretLength,
                nullptr,
                0,
                nullptr,
                0,
                message,
                messageLength,
                binder.Get(),
                binder.Count(),
                &pskIdentity.BinderLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ComputePskBinder", status);
            }

            status = TlsHandshake13::EncodeClientHello(
                context_,
                hello,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodePskClientHello", status);
            }
        }

        UCHAR* firstClientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchFirstClientHelloOffset,
            TlsScratchFirstClientHelloLength,
            &firstClientHello);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetFirstClientHelloScratch", status);
        }
        RtlSecureZeroMemory(firstClientHello, TlsScratchFirstClientHelloLength);
        SIZE_T firstClientHelloLength = messageLength;
        if (firstClientHelloLength > TlsScratchFirstClientHelloLength) {
            return LogTls13Failure("StoreFirstClientHello", STATUS_BUFFER_TOO_SMALL);
        }
        RtlCopyMemory(firstClientHello, message, firstClientHelloLength);

        UCHAR* secondClientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchSecondClientHelloOffset,
            TlsScratchSecondClientHelloLength,
            &secondClientHello);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetSecondClientHelloScratch", status);
        }
        RtlSecureZeroMemory(secondClientHello, TlsScratchSecondClientHelloLength);
        SIZE_T secondClientHelloLength = 0;
        UCHAR* helloRetryRequest = nullptr;
        status = GetHandshakeScratch(
            TlsScratchHelloRetryOffset,
            TlsScratchHelloRetryLength,
            &helloRetryRequest);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetHelloRetryScratch", status);
        }
        RtlSecureZeroMemory(helloRetryRequest, TlsScratchHelloRetryLength);
        SIZE_T helloRetryRequestLength = 0;
        bool usedHelloRetryRequest = false;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecordWithVersion(transport, { 3, 3 }, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("SendInitialClientHello", status);
        }

        if (hello.OfferEarlyData &&
            options.EarlyDataReplaySafe &&
            options.EarlyData != nullptr &&
            options.EarlyDataLength != 0) {
            HeapArray<UCHAR> clientHelloHash(TlsMaxTranscriptHashLength);
            if (!clientHelloHash.IsValid()) {
                return LogTls13Failure("AllocateEarlyDataClientHelloHash", STATUS_INSUFFICIENT_RESOURCES);
            }

            SIZE_T clientHelloHashLength = 0;
            status = FinishTranscript(clientHelloHash.Get(), clientHelloHash.Count(), &clientHelloHashLength);
            if (NT_SUCCESS(status)) {
                status = context_.DeriveTls13EarlySecret(resumptionSecret, resumptionSecretLength);
            }
            if (NT_SUCCESS(status)) {
                status = context_.DeriveTls13ClientEarlyTrafficSecret(clientHelloHash.Get(), clientHelloHashLength);
            }
            if (NT_SUCCESS(status)) {
                status = context_.ConfigureTls13EarlyAesGcmState(clientWriteState_);
            }
            RtlSecureZeroMemory(clientHelloHash.Get(), clientHelloHash.Count());
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ConfigureEarlyDataKeys", status);
            }

            SIZE_T sent = 0;
            while (sent < options.EarlyDataLength) {
                const SIZE_T fragmentLimit = TlsMaxPlaintextLength - tls13RecordPaddingLength_;
                const SIZE_T chunk = (options.EarlyDataLength - sent) > fragmentLimit ?
                    fragmentLimit :
                    (options.EarlyDataLength - sent);
                status = SendProtectedRecord13(
                    transport,
                    TlsContentType::ApplicationData,
                    options.EarlyData + sent,
                    chunk);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("SendEarlyData", status);
                }
                sent += chunk;
            }
            if (options.EarlyDataBytesSent != nullptr) {
                *options.EarlyDataBytesSent = sent;
            }
        }

        TlsHandshakeMessageView handshake = {};
        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            RecordTls13FirstServerHelloFailure(options, status);
            return LogTls13Failure("ReadFirstServerHello", status);
        }

        Tls13ServerHelloView serverHello = {};
        status = TlsHandshake13::ParseServerHello(context_, handshake, serverHello);
        if (!NT_SUCCESS(status)) {
            const Tls13ServerHelloVersionSelection selection =
                ClassifyTls12ServerHelloFromTls13Attempt(options, handshake);
            if (selection == Tls13ServerHelloVersionSelection::Tls12Selected) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
            }
            else if (selection == Tls13ServerHelloVersionSelection::RejectedDowngrade) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::DecodeError, STATUS_INVALID_NETWORK_RESPONSE);
                status = STATUS_INVALID_NETWORK_RESPONSE;
            }
            else if (status == STATUS_NOT_SUPPORTED) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
            }
            return LogTls13Failure("ParseFirstServerHello", status);
        }
        status = TlsHandshake13::ValidateServerHelloOffer(serverHello, hello);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ValidateFirstServerHelloOffer", status);
        }
        // TLS 1.3 parsing requires supported_versions == 0x0304. This client
        // does not perform in-handshake fallback; future fallback must validate
        // RFC 8446 downgrade sentinels at the negotiated version boundary.
        status = ValidateSelectedPskForConnection(
            context_,
            serverHello,
            hello.PskIdentityCount,
            selectedTicket);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ValidateFirstSelectedPskIdentity", status);
        }

        if (serverHello.IsHelloRetryRequest) {
            usedHelloRetryRequest = true;
            helloRetryRequestLength = lastHandshakeLength_;
            if (helloRetryRequestLength > TlsScratchHelloRetryLength) {
                return LogTls13Failure("StoreHelloRetryRequest", STATUS_BUFFER_TOO_SMALL);
            }
            RtlCopyMemory(helloRetryRequest, handshakeBuffer_ + lastHandshakeOffset_, helloRetryRequestLength);

            crypto::KeyExchangeGroup retryGroup = crypto::KeyExchangeGroup::Secp256r1;
            status = ToKeyExchangeGroup(serverHello.RetryGroup, &retryGroup);
            if (!NT_SUCCESS(status) || !crypto::KeyExchange::IsSupportedGroup(retryGroup)) {
                return LogTls13Failure("ValidateHelloRetryGroup", STATUS_NOT_SUPPORTED);
            }

            status = crypto::KeyExchange::GenerateKeyPair(
                providerCache_,
                retryGroup,
                *keyPair.Get());
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("GenerateRetryKeyShare", status);
            }

            keyShare.Group = serverHello.RetryGroup;
            keyShare.KeyExchange = keyPair->PublicKey;
            keyShare.KeyExchangeLength = keyPair->PublicKeyLength;
            if (pskIdentity.IdentityLength != 0 &&
                selectedTicket != nullptr &&
                selectedTicket->CipherSuite != context_.CipherSuite()) {
                return LogTls13Failure("ValidateHelloRetryPskCipher", STATUS_INVALID_NETWORK_RESPONSE);
            }
            status = TlsHandshake13::EncodeClientHello(
                context_,
                hello,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodeRetryClientHello", status);
            }
            if (pskIdentity.IdentityLength != 0) {
                status = ComputePskBinderForClientHello(
                    providerCache_,
                    context_,
                    resumptionSecret,
                    resumptionSecretLength,
                    firstClientHello,
                    firstClientHelloLength,
                    helloRetryRequest,
                    helloRetryRequestLength,
                    message,
                    messageLength,
                    binder.Get(),
                    binder.Count(),
                    &pskIdentity.BinderLength);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("ComputeRetryPskBinder", status);
                }

                status = TlsHandshake13::EncodeClientHello(
                    context_,
                    hello,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("EncodeRetryPskClientHello", status);
                }
            }
            secondClientHelloLength = messageLength;
            if (secondClientHelloLength > TlsScratchSecondClientHelloLength) {
                return LogTls13Failure("StoreSecondClientHello", STATUS_BUFFER_TOO_SMALL);
            }
            RtlCopyMemory(secondClientHello, message, secondClientHelloLength);

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendPlainRecordWithVersion(transport, { 3, 3 }, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("SendRetryClientHello", status);
            }

            status = ReadHandshakeMessage13(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ReadRetryServerHello", status);
            }

            status = TlsHandshake13::ParseServerHello(context_, handshake, serverHello);
            if (!NT_SUCCESS(status)) {
                const Tls13ServerHelloVersionSelection selection =
                    ClassifyTls12ServerHelloFromTls13Attempt(options, handshake);
                if (selection == Tls13ServerHelloVersionSelection::Tls12Selected) {
                    RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
                }
                else if (selection == Tls13ServerHelloVersionSelection::RejectedDowngrade) {
                    RecordHandshakeFailure(TlsHandshakeFailureCategory::DecodeError, STATUS_INVALID_NETWORK_RESPONSE);
                    status = STATUS_INVALID_NETWORK_RESPONSE;
                }
                else if (status == STATUS_NOT_SUPPORTED) {
                    RecordHandshakeFailure(TlsHandshakeFailureCategory::VersionNegotiation, status);
                }
                return LogTls13Failure("ParseRetryServerHello", status);
            }
            status = TlsHandshake13::ValidateServerHelloOffer(serverHello, hello);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ValidateRetryServerHelloOffer", status);
            }
            if (serverHello.IsHelloRetryRequest) {
                return LogTls13Failure("RejectRepeatedHelloRetryRequest", STATUS_INVALID_NETWORK_RESPONSE);
            }
            status = ValidateSelectedPskForConnection(
                context_,
                serverHello,
                hello.PskIdentityCount,
                selectedTicket);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ValidateRetrySelectedPskIdentity", status);
            }
        }

        HeapArray<UCHAR> sharedSecret(crypto::KeyExchangeMaxSharedSecretLength);
        if (!sharedSecret.IsValid()) {
            return LogTls13Failure("AllocateEcdhSharedSecret", STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T sharedSecretLength = 0;
        status = crypto::KeyExchange::DeriveSharedSecret(
            providerCache_,
            *keyPair.Get(),
            serverHello.KeyShare.KeyExchange,
            serverHello.KeyShare.KeyExchangeLength,
            sharedSecret.Get(),
            sharedSecret.Count(),
            &sharedSecretLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("DeriveEcdhSharedSecret", status);
        }

        status = transcript_.Initialize(TlsHandshake13::HashForCipherSuite(context_.CipherSuite()));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("InitializeSelectedCipherTranscript", status);
        }

        if (usedHelloRetryRequest) {
            HeapArray<UCHAR> firstHash(TlsMaxTranscriptHashLength);
            if (!firstHash.IsValid()) {
                RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
                return LogTls13Failure("AllocateHelloRetryFirstHash", STATUS_INSUFFICIENT_RESOURCES);
            }

            SIZE_T firstHashLength = 0;
            TlsTranscriptHash firstTranscript;
            status = firstTranscript.Initialize(TlsHandshake13::HashForCipherSuite(context_.CipherSuite()));
            if (NT_SUCCESS(status)) {
                status = firstTranscript.Update(firstClientHello, firstClientHelloLength);
            }
            if (NT_SUCCESS(status)) {
                status = firstTranscript.Finish(firstHash.Get(), firstHash.Count(), &firstHashLength);
            }

            if (NT_SUCCESS(status)) {
                status = transcript_.ReplaceWithMessageHash(firstHash.Get(), firstHashLength);
            }
            RtlSecureZeroMemory(firstHash.Get(), firstHash.Count());
            if (NT_SUCCESS(status)) {
                status = transcript_.Update(helloRetryRequest, helloRetryRequestLength);
            }
            if (NT_SUCCESS(status)) {
                status = transcript_.Update(secondClientHello, secondClientHelloLength);
            }
        }
        else {
            status = transcript_.Update(firstClientHello, firstClientHelloLength);
        }
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        }
        RtlSecureZeroMemory(firstClientHello, TlsScratchFirstClientHelloLength);
        RtlSecureZeroMemory(secondClientHello, TlsScratchSecondClientHelloLength);
        RtlSecureZeroMemory(helloRetryRequest, TlsScratchHelloRetryLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("RebuildTls13Transcript", status);
        }

        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!transcriptHash.IsValid()) {
            RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
            return LogTls13Failure("AllocateTls13TranscriptHash", STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T transcriptHashLength = 0;
        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = context_.DeriveTls13EarlySecret(
                serverHello.SelectedPskIdentity != 0xffff ? resumptionSecret : nullptr,
                serverHello.SelectedPskIdentity != 0xffff ? resumptionSecretLength : 0);
        }
        if (NT_SUCCESS(status)) {
            status = context_.DeriveTls13HandshakeSecrets(
                sharedSecret.Get(),
                sharedSecretLength,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(sharedSecret.Get(), sharedSecret.Count());
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureTls13HandshakeAesGcmStates(clientWriteState_, serverWriteState_);
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("DeriveTls13HandshakeKeys", status);
        }

        encrypted_ = true;
        tls13RecordProtection_ = true;

        status = ReadOptionalCompatibilityChangeCipherSpec(transport);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ReadCompatibilityChangeCipherSpec", status);
        }

        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ReadEncryptedExtensions", status);
        }

        Tls13EncryptedExtensionsView encryptedExtensions = {};
        status = TlsHandshake13::ParseEncryptedExtensions(handshake, encryptedExtensions);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ParseEncryptedExtensions", status);
        }
        if (encryptedExtensions.AlpnLength != 0) {
            if (encryptedExtensions.AlpnLength >= 16) {
                return LogTls13Failure("StoreNegotiatedAlpn", STATUS_BUFFER_TOO_SMALL);
            }
            RtlCopyMemory(negotiatedAlpn_, encryptedExtensions.Alpn, encryptedExtensions.AlpnLength);
            negotiatedAlpn_[encryptedExtensions.AlpnLength] = '\0';
            negotiatedAlpnLength_ = encryptedExtensions.AlpnLength;
            if (!IsOfferedAlpn(options, negotiatedAlpn_, negotiatedAlpnLength_)) {
                RecordHandshakeFailure(TlsHandshakeFailureCategory::AlpnMismatch, STATUS_NOT_SUPPORTED);
                return LogTls13Failure("ValidateNegotiatedAlpn", STATUS_NOT_SUPPORTED);
            }
        }
        if (serverHello.SelectedPskIdentity != 0xffff && selectedTicket != nullptr) {
            if (selectedTicket->AlpnLength != encryptedExtensions.AlpnLength ||
                (selectedTicket->AlpnLength != 0 &&
                    RtlCompareMemory(
                        selectedTicket->Alpn,
                        encryptedExtensions.Alpn,
                        selectedTicket->AlpnLength) != selectedTicket->AlpnLength)) {
                return LogTls13Failure("ValidateResumedAlpnBinding", STATUS_INVALID_NETWORK_RESPONSE);
            }
        }
        if (encryptedExtensions.EarlyDataAccepted &&
            (!hello.OfferEarlyData || serverHello.SelectedPskIdentity == 0xffff)) {
            return LogTls13Failure("RejectUnexpectedEarlyDataAcceptance", STATUS_INVALID_NETWORK_RESPONSE);
        }
        if (options.EarlyDataAccepted != nullptr) {
            *options.EarlyDataAccepted = encryptedExtensions.EarlyDataAccepted;
        }

        HeapArray<UCHAR> clientCertificateRequestContext(255);
        if (!clientCertificateRequestContext.IsValid()) {
            return LogTls13Failure("AllocateClientCertificateRequestContext", STATUS_INSUFFICIENT_RESOURCES);
        }
        bool clientCertificateRequested = false;
        SIZE_T clientCertificateRequestContextLength = 0;
        bool sendClientCertificateVerify = false;
        TlsSignatureScheme clientCertificateSignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;

        status = ReadHandshakeMessage13(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ReadCertificateOrRequest", status);
        }

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            Tls13CertificateRequestView certificateRequest = {};
            status = TlsHandshake13::ParseCertificateRequest(handshake, certificateRequest);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ParseCertificateRequest", status);
            }
            if (certificateRequest.ContextLength != 0 ||
                certificateRequest.ContextLength > clientCertificateRequestContext.Count()) {
                return LogTls13Failure("ValidateTls13ClientCertificateRequestContext", STATUS_INVALID_NETWORK_RESPONSE);
            }
            clientCertificateRequested = true;
            clientCertificateRequestContextLength = certificateRequest.ContextLength;
            if (clientCertificateRequestContextLength != 0) {
                RtlCopyMemory(
                    clientCertificateRequestContext.Get(),
                    certificateRequest.Context,
                    clientCertificateRequestContextLength);
            }
            const UCHAR* peerSignatureSchemes = nullptr;
            SIZE_T peerSignatureSchemesLength = 0;
            status = FindTls13CertificateRequestSignatureAlgorithms(
                certificateRequest,
                &peerSignatureSchemes,
                &peerSignatureSchemesLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("FindTls13ClientCertificateRequestSignatureAlgorithms", status);
            }
            if (clientCredential_ != nullptr &&
                clientCredential_->CertificateList != nullptr &&
                clientCredential_->CertificateListLength != 0 &&
                clientCredential_->Sign != nullptr) {
                status = SelectClientCredentialSignatureScheme(
                    options.Policy,
                    *clientCredential_,
                    peerSignatureSchemes,
                    peerSignatureSchemesLength,
                    &clientCertificateSignatureScheme);
                if (NT_SUCCESS(status)) {
                    sendClientCertificateVerify = true;
                }
                else if (status != STATUS_NOT_SUPPORTED) {
                    return LogTls13Failure("SelectTls13ClientCertificateSignature", status);
                }
            }

            status = ReadHandshakeMessage13(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("ReadCertificateAfterRequest", status);
            }
        }

        Tls13CertificateView certificate = {};
        status = TlsHandshake13::ParseCertificate(handshake, certificate);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ParseCertificate", status);
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return LogTls13Failure("AllocateServerCertificatePublicKey", STATUS_INSUFFICIENT_RESOURCES);
        }

        status = ValidateTls13Certificate(certificate, options, *serverPublicKey.Get());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ValidateTls13Certificate", status);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("FinishTranscriptBeforeCertificateVerify", status);
        }

        status = ReadHandshakeMessage13(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return LogTls13Failure("ReadCertificateVerify", status);
        }

        Tls13CertificateVerifyView certificateVerify = {};
        status = TlsHandshake13::ParseCertificateVerify(handshake, certificateVerify);
        if (NT_SUCCESS(status)) {
            status = VerifyTls13CertificateVerify(
                certificateVerify,
                *serverPublicKey.Get(),
                serverCertificatePublicKeyAlgorithm_,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("VerifyCertificateVerify", status);
        }

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("AppendCertificateVerifyTranscript", status);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("FinishTranscriptBeforeServerFinished", status);
        }

        status = ReadHandshakeMessage13(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return LogTls13Failure("ReadServerFinished", status);
        }
        status = TlsHandshake13::VerifyFinished(
            context_,
            false,
            transcriptHash.Get(),
            transcriptHashLength,
            handshake.Body,
            handshake.BodyLength);
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("VerifyServerFinished", status);
        }

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("AppendServerFinishedTranscript", status);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = context_.DeriveTls13ApplicationSecrets(transcriptHash.Get(), transcriptHashLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("DeriveTls13ApplicationSecrets", status);
        }

        if (encryptedExtensions.EarlyDataAccepted) {
            status = TlsHandshake13::EncodeEndOfEarlyData(
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodeEndOfEarlyData", status);
            }

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("SendEndOfEarlyData", status);
            }
        }

        if (clientCertificateRequested) {
            const UCHAR* credentialCertificateList = sendClientCertificateVerify ? clientCredential_->CertificateList : nullptr;
            const SIZE_T credentialCertificateListLength = sendClientCertificateVerify ? clientCredential_->CertificateListLength : 0;
            status = TlsHandshake13::EncodeCertificate(
                clientCertificateRequestContext.Get(),
                clientCertificateRequestContextLength,
                credentialCertificateList,
                credentialCertificateListLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("EncodeClientCertificate", status);
            }

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return LogTls13Failure("SendClientCertificate", status);
            }

            if (sendClientCertificateVerify) {
                status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("FinishTranscriptBeforeClientCertificateVerify", status);
                }

                UCHAR* signedInput = nullptr;
                status = GetHandshakeScratch(
                    TlsScratchSignedInputOffset,
                    TlsScratchSignedInputLength,
                    &signedInput);
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                    return LogTls13Failure("GetClientCertificateVerifyInputScratch", status);
                }

                SIZE_T signedInputLength = 0;
                status = TlsHandshake13::BuildCertificateVerifyInput(
                    false,
                    transcriptHash.Get(),
                    transcriptHashLength,
                    signedInput,
                    TlsScratchSignedInputLength,
                    &signedInputLength);
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                    return LogTls13Failure("BuildClientCertificateVerifyInput", status);
                }

                HeapArray<UCHAR> signature(TlsScratchHandshakeBufferLength);
                if (!signature.IsValid()) {
                    RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                    return LogTls13Failure("AllocateClientCertificateVerifySignature", STATUS_INSUFFICIENT_RESOURCES);
                }

                SIZE_T signatureLength = 0;
                status = clientCredential_->Sign(
                    clientCredential_->SignContext,
                    clientCertificateSignatureScheme,
                    signedInput,
                    signedInputLength,
                    signature.Get(),
                    signature.Count(),
                    &signatureLength);
                RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                if (NT_SUCCESS(status)) {
                    status = TlsHandshake13::EncodeCertificateVerify(
                        clientCertificateSignatureScheme,
                        signature.Get(),
                        signatureLength,
                        message,
                        TlsScratchClientHelloLength,
                        &messageLength);
                }
                RtlSecureZeroMemory(signature.Get(), signature.Count());
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("EncodeClientCertificateVerify", status);
                }

                status = AppendTranscript(message, messageLength);
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
                }
                if (!NT_SUCCESS(status)) {
                    return LogTls13Failure("SendClientCertificateVerify", status);
                }
            }
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake13::EncodeFinished(
                context_,
                true,
                transcriptHash.Get(),
                transcriptHashLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("EncodeClientFinished", status);
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord13(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("SendClientFinished", status);
        }

        status = context_.ConfigureTls13ApplicationAesGcmStates(clientWriteState_, serverWriteState_);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("ConfigureTls13ApplicationKeys", status);
        }

        context_.SetState(TlsHandshakeState::Established);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::ReadHandshakeMessage13(
        transport::Transport* transport,
        TlsHandshakeMessageView& message,
        bool updateTranscript) noexcept
    {
        return ReadHandshakeMessage(transport, message, updateTranscript);
    }

    NTSTATUS TlsConnection::ValidateTls13Certificate(
        const Tls13CertificateView& certificate,
        const TlsClientConnectionOptions& options,
        crypto::CngKey& serverPublicKey) noexcept
    {
        UCHAR* legacyCertificateList = nullptr;
        NTSTATUS status = GetHandshakeScratch(
            TlsScratchLegacyCertificateOffset,
            TlsScratchLegacyCertificateLength,
            &legacyCertificateList);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetTls13LegacyCertificateScratch", status);
        }

        RtlZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
        SIZE_T legacyCertificateListLength = 0;
        SIZE_T certificateCount = 0;
        status = ConvertTls13CertificateListToLegacy(
            certificate,
            legacyCertificateList,
            TlsScratchLegacyCertificateLength,
            &legacyCertificateListLength,
            &certificateCount);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return LogTls13Failure("ConvertTls13CertificateList", status);
        }

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = options.ProviderCache;
        validation.VerifyCertificate = options.VerifyCertificate;
        validation.RequireRevocationCheck = options.Policy.RequireRevocationCheck;

        CertificateChainView chain = {};
        chain.Certificates = legacyCertificateList;
        chain.CertificatesLength = legacyCertificateListLength;
        chain.CertificateCount = certificateCount;

        HeapObject<CertificateValidationResult> result;
        if (!result.IsValid()) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = CertificateValidator::ValidateChain(chain, validation, result.Get());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return LogTls13Failure("ValidateTls13CertificateChain", status);
        }
        serverCertificatePublicKeyAlgorithm_ = result->Leaf.PublicKeyAlgorithm;
        if (result->Leaf.HasKeyUsage && !result->Leaf.AllowsDigitalSignature) {
            RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
            return STATUS_TRUST_FAILURE;
        }

        if (result->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed25519) {
            if (result->Leaf.PublicKey == nullptr ||
                result->Leaf.PublicKeyLength != crypto::Ed25519PublicKeyLength) {
                RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd25519PublicKey_, result->Leaf.PublicKey, crypto::Ed25519PublicKeyLength);
            serverEd25519PublicKeyLength_ = crypto::Ed25519PublicKeyLength;
        }
        else if (result->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed448) {
            if (result->Leaf.PublicKey == nullptr ||
                result->Leaf.PublicKeyLength != crypto::Ed448PublicKeyLength) {
                RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd448PublicKey_, result->Leaf.PublicKey, crypto::Ed448PublicKeyLength);
            serverEd448PublicKeyLength_ = crypto::Ed448PublicKeyLength;
        }
        else {
            status = CertificateValidator::ImportSubjectPublicKey(providerCache_, result->Leaf, serverPublicKey);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
                return LogTls13Failure("ImportTls13CertificatePublicKey", status);
            }
        }
        RtlSecureZeroMemory(legacyCertificateList, TlsScratchLegacyCertificateLength);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::VerifyTls13CertificateVerify(
        const Tls13CertificateVerifyView& certificateVerify,
        const crypto::CngKey& serverPublicKey,
        CertificatePublicKeyAlgorithm publicKeyAlgorithm,
        const UCHAR* transcriptHash,
        SIZE_T transcriptHashLength) noexcept
    {
        if (!SignatureSchemeMatchesPublicKey(publicKeyAlgorithm, certificateVerify.SignatureScheme)) {
            return LogTls13Failure("ValidateTls13CertificateVerifyKeyAlgorithm", STATUS_INVALID_NETWORK_RESPONSE);
        }

        crypto::HashAlgorithm hashAlgorithm = crypto::HashAlgorithm::Sha256;
        crypto::SignatureAlgorithm signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        NTSTATUS status = GetTls13SignatureParameters(
            certificateVerify.SignatureScheme,
            &hashAlgorithm,
            &signatureAlgorithm);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetTls13CertificateVerifySignatureParameters", STATUS_INVALID_NETWORK_RESPONSE);
        }

        UCHAR* signedInput = nullptr;
        status = GetHandshakeScratch(
            TlsScratchSignedInputOffset,
            TlsScratchSignedInputLength,
            &signedInput);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("GetTls13CertificateVerifyInputScratch", status);
        }
        RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
        SIZE_T signedInputLength = 0;
        status = TlsHandshake13::BuildCertificateVerifyInput(
            true,
            transcriptHash,
            transcriptHashLength,
            signedInput,
            TlsScratchSignedInputLength,
            &signedInputLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("BuildTls13CertificateVerifyInput", status);
        }

        if (certificateVerify.SignatureScheme == TlsSignatureScheme::Ed25519) {
            if (serverEd25519PublicKeyLength_ != crypto::Ed25519PublicKeyLength) {
                RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                return LogTls13Failure("VerifyTls13CertificateVerifyEd25519Key", STATUS_INVALID_NETWORK_RESPONSE);
            }

            status = crypto::CngProvider::VerifyEd25519(
                serverEd25519PublicKey_,
                serverEd25519PublicKeyLength_,
                signedInput,
                signedInputLength,
                certificateVerify.Signature,
                certificateVerify.SignatureLength);
            RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
            if (!NT_SUCCESS(status)) {
                status = LogTls13Failure("VerifyTls13CertificateVerifyEd25519Signature", status);
            }
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }
        if (certificateVerify.SignatureScheme == TlsSignatureScheme::Ed448) {
            if (serverEd448PublicKeyLength_ != crypto::Ed448PublicKeyLength) {
                RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
                return LogTls13Failure("VerifyTls13CertificateVerifyEd448Key", STATUS_INVALID_NETWORK_RESPONSE);
            }

            status = crypto::CngProvider::VerifyEd448(
                serverEd448PublicKey_,
                serverEd448PublicKeyLength_,
                signedInput,
                signedInputLength,
                certificateVerify.Signature,
                certificateVerify.SignatureLength);
            RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
            if (!NT_SUCCESS(status)) {
                status = LogTls13Failure("VerifyTls13CertificateVerifyEd448Signature", status);
            }
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }

        HeapArray<UCHAR> hash(64);
        if (!hash.IsValid()) {
            return LogTls13Failure("AllocateTls13CertificateVerifyHash", STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T hashLength = 0;
        status = crypto::CngProvider::Hash(
            providerCache_,
            hashAlgorithm,
            signedInput,
            signedInputLength,
            hash.Get(),
            hash.Count(),
            &hashLength);
        RtlSecureZeroMemory(signedInput, TlsScratchSignedInputLength);
        if (!NT_SUCCESS(status)) {
            return LogTls13Failure("HashTls13CertificateVerifyInput", status);
        }

        status = crypto::CngProvider::VerifySignature(
            providerCache_,
            signatureAlgorithm,
            serverPublicKey,
            hash.Get(),
            hashLength,
            certificateVerify.Signature,
            certificateVerify.SignatureLength);
        if (!NT_SUCCESS(status)) {
            status = LogTls13Failure("VerifyTls13CertificateVerifySignature", status);
        }
        RtlSecureZeroMemory(hash.Get(), hash.Count());
        return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
    }

    NTSTATUS TlsConnection::StoreTls13Ticket(
        const Tls13NewSessionTicketView& ticket,
        Tls13SessionCache* externalCache) noexcept
    {
        if (ticket.Ticket == nullptr ||
            ticket.TicketLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        if (ticket.LifetimeSeconds == 0 ||
            ticket.LifetimeSeconds > Tls13MaxTicketLifetimeSeconds ||
            !tls13TicketServerNameCacheable_ ||
            tls13TicketServerNameLength_ == 0 ||
            negotiatedAlpnLength_ > Tls13MaxTicketAlpnLength) {
            return STATUS_SUCCESS;
        }
        if (ticket.TicketLength > Tls13MaxTicketIdentityLength ||
            ticket.NonceLength > Tls13MaxTicketNonceLength) {
#if defined(DBG) && !defined(WKNET_USER_MODE_TEST)
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Warning,
                "tls13.session_ticket.cache_skipped ticket_bytes=%Iu nonce_bytes=%Iu reason=oversized",
                ticket.TicketLength,
                ticket.NonceLength);
#endif
            return STATUS_SUCCESS;
        }

        if (!tls13SessionTicketScratch_.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Tls13SessionTicket& stored = *tls13SessionTicketScratch_.Get();
        RtlSecureZeroMemory(&stored, sizeof(stored));
        stored.IdentityLength = ticket.TicketLength;
        RtlCopyMemory(stored.Identity, ticket.Ticket, ticket.TicketLength);
        stored.NonceLength = ticket.NonceLength;
        if (ticket.NonceLength != 0) {
            RtlCopyMemory(stored.Nonce, ticket.Nonce, ticket.NonceLength);
        }
        stored.LifetimeSeconds = ticket.LifetimeSeconds;
        stored.AgeAdd = ticket.AgeAdd;
        stored.MaxEarlyDataSize = ticket.MaxEarlyDataSize;
        stored.IssueTimeMilliseconds = CurrentMilliseconds();
        stored.Version = { 3, 4 };
        stored.ServerNameLength = tls13TicketServerNameLength_;
        RtlCopyMemory(stored.ServerName, tls13TicketServerName_, tls13TicketServerNameLength_);
        stored.ServerName[tls13TicketServerNameLength_] = '\0';
        stored.AlpnLength = negotiatedAlpnLength_;
        if (negotiatedAlpnLength_ != 0) {
            RtlCopyMemory(stored.Alpn, negotiatedAlpn_, negotiatedAlpnLength_);
            stored.Alpn[negotiatedAlpnLength_] = '\0';
        }
        stored.CipherSuite = context_.CipherSuite();
        stored.PolicyIdentity = tlsPolicyIdentity_;

        NTSTATUS status = context_.DeriveTls13ResumptionSecret(
            stored.Nonce,
            stored.NonceLength,
            stored.ResumptionSecret,
            sizeof(stored.ResumptionSecret),
            &stored.ResumptionSecretLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = context_.StoreTls13Ticket(stored);
        if (NT_SUCCESS(status) && externalCache != nullptr) {
            if (externalCache->TicketCount < Tls13MaxTicketCount) {
                externalCache->Tickets[externalCache->TicketCount] = stored;
                ++externalCache->TicketCount;
            }
            else {
                for (SIZE_T index = 1; index < Tls13MaxTicketCount; ++index) {
                    externalCache->Tickets[index - 1] = externalCache->Tickets[index];
                }
                externalCache->Tickets[Tls13MaxTicketCount - 1] = stored;
            }
        }
        RtlSecureZeroMemory(&stored, sizeof(stored));
        return status;
    }

    NTSTATUS TlsConnection::SelectTls13Ticket(
        const TlsClientConnectionOptions& options,
        Tls13PskIdentity& identity,
        const UCHAR** resumptionSecret,
        SIZE_T* resumptionSecretLength,
        bool* earlyDataAllowed,
        const Tls13SessionTicket** selectedTicket) noexcept
    {
        identity = {};
        if (resumptionSecret != nullptr) {
            *resumptionSecret = nullptr;
        }
        if (resumptionSecretLength != nullptr) {
            *resumptionSecretLength = 0;
        }
        if (earlyDataAllowed != nullptr) {
            *earlyDataAllowed = false;
        }
        if (selectedTicket != nullptr) {
            *selectedTicket = nullptr;
        }

        if (resumptionSecret == nullptr ||
            resumptionSecretLength == nullptr ||
            earlyDataAllowed == nullptr ||
            selectedTicket == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!options.EnableSessionResumption || options.SessionCache == nullptr || options.SessionCache->TicketCount == 0) {
            return STATUS_NOT_FOUND;
        }
        if (options.SessionCache->TicketCount > Tls13MaxTicketCount) {
            return STATUS_INVALID_PARAMETER;
        }

        const ULONGLONG now = CurrentMilliseconds();
        for (SIZE_T index = options.SessionCache->TicketCount; index > 0; --index) {
            const Tls13SessionTicket& ticket = options.SessionCache->Tickets[index - 1];
            if (ticket.IdentityLength == 0 ||
                ticket.IdentityLength > Tls13MaxTicketIdentityLength ||
                ticket.ResumptionSecretLength == 0 ||
                ticket.ResumptionSecretLength > Tls13MaxSecretLength ||
                ticket.LifetimeSeconds == 0 ||
                ticket.LifetimeSeconds > Tls13MaxTicketLifetimeSeconds ||
                ticket.IssueTimeMilliseconds == 0 ||
                ticket.Version.Major != 3 ||
                ticket.Version.Minor != 4 ||
                ticket.PolicyIdentity != tlsPolicyIdentity_ ||
                !TlsHandshake13::IsSupportedCipherSuite(ticket.CipherSuite) ||
                !TicketServerNameMatches(ticket, options) ||
                !TicketAlpnMatches(ticket, options)) {
                continue;
            }

            ULONGLONG lifetimeMilliseconds = 0;
            ULONGLONG expiresAt = 0;
            if (!MultiplySecondsToMilliseconds(ticket.LifetimeSeconds, &lifetimeMilliseconds) ||
                !AddUnsigned64(ticket.IssueTimeMilliseconds, lifetimeMilliseconds, &expiresAt) ||
                now < ticket.IssueTimeMilliseconds ||
                now >= expiresAt) {
                continue;
            }

            const NTSTATUS status = context_.SetCipherSuite(ticket.CipherSuite);
            if (!NT_SUCCESS(status)) {
                continue;
            }

            identity.Identity = ticket.Identity;
            identity.IdentityLength = ticket.IdentityLength;
            identity.ObfuscatedTicketAge =
                static_cast<ULONG>(now - ticket.IssueTimeMilliseconds) + ticket.AgeAdd;
            *resumptionSecret = ticket.ResumptionSecret;
            *resumptionSecretLength = ticket.ResumptionSecretLength;
            *earlyDataAllowed = options.EnableEarlyData &&
                options.EarlyDataReplaySafe &&
                ticket.MaxEarlyDataSize != 0 &&
                options.EarlyData != nullptr &&
                options.EarlyDataLength <= ticket.MaxEarlyDataSize;
            *selectedTicket = &ticket;
            return STATUS_SUCCESS;
        }

        return STATUS_NOT_FOUND;
    }
}
}
