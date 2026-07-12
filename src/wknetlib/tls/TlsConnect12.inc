
    NTSTATUS TlsConnection::ConnectTls12(
        core::ITransport& transport,
        const TlsClientConnectionOptions& options) noexcept
    {
        tls13RecordProtection_ = false;

        NTSTATUS status = context_.InitializeClient({ 3, 3 });
        if (NT_SUCCESS(status)) {
            status = transcript_.Initialize(crypto::HashAlgorithm::Sha256);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (options.EarlyDataAccepted != nullptr) {
            *options.EarlyDataAccepted = false;
        }
        if (options.EarlyDataBytesSent != nullptr) {
            *options.EarlyDataBytesSent = 0;
        }
        if (options.EnableEarlyData) {
            return STATUS_NOT_SUPPORTED;
        }

        UCHAR* message = nullptr;
        status = GetHandshakeScratch(
            TlsScratchClientHelloOffset,
            TlsScratchClientHelloLength,
            &message);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(message, TlsScratchClientHelloLength);
        SIZE_T messageLength = 0;

        TlsClientHelloOptions hello = {};
        hello.ServerName = options.ServerName;
        hello.ServerNameLength = options.ServerNameLength;
        hello.AlpnProtocols = options.AlpnProtocols;
        hello.AlpnProtocolCount = options.AlpnProtocolCount;
        hello.OfferEncryptThenMac = options.Policy.EnableTls12Cbc;
        hello.OfferStatusRequest = true;

        HeapArray<TlsCipherSuite> offeredCipherSuites;
        HeapArray<TlsNamedGroup> offeredNamedGroups;
        HeapArray<TlsSignatureScheme> offeredSignatureSchemes;
        SIZE_T offeredCipherSuiteCount = 0;
        SIZE_T offeredNamedGroupCount = 0;
        SIZE_T offeredSignatureSchemeCount = 0;
        status = BuildTls12PolicyOffers(
            options.Policy,
            offeredCipherSuites,
            &offeredCipherSuiteCount,
            offeredNamedGroups,
            &offeredNamedGroupCount,
            offeredSignatureSchemes,
            &offeredSignatureSchemeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        hello.CipherSuites = offeredCipherSuites.Get();
        hello.CipherSuiteCount = offeredCipherSuiteCount;
        hello.NamedGroups = offeredNamedGroups.Get();
        hello.NamedGroupCount = offeredNamedGroupCount;
        hello.SignatureSchemes = offeredSignatureSchemes.Get();
        hello.SignatureSchemeCount = offeredSignatureSchemeCount;

        const Tls12Session* selectedTls12Session = SelectTls12Session(options, tlsPolicyIdentity_);
        if (selectedTls12Session != nullptr) {
            hello.SessionId = selectedTls12Session->SessionId;
            hello.SessionIdLength = selectedTls12Session->SessionIdLength;
            hello.SessionTicket = selectedTls12Session->Ticket;
            hello.SessionTicketLength = selectedTls12Session->TicketLength;
        }

        status = TlsHandshake12::EncodeClientHello(
            context_,
            hello,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection encode ClientHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        UCHAR* clientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchFirstClientHelloOffset,
            TlsScratchFirstClientHelloLength,
            &clientHello);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (messageLength > TlsScratchFirstClientHelloLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlCopyMemory(clientHello, message, messageLength);
        const SIZE_T clientHelloLength = messageLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection send ClientHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsHandshakeMessageView handshake = {};
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read ServerHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context_, handshake, serverHello);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection parse ServerHello failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }
        status = TlsHandshake12::ValidateServerHelloOffer(serverHello, hello);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection ServerHello selected value was not offered: 0x%08X cipher=0x%04X\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(serverHello.CipherSuite));
            return status;
        }
        if (!serverHello.HasExtendedMasterSecret) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection TLS1.2 ServerHello missing extended_master_secret\r\n");
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }
        if (!serverHello.HasSecureRenegotiation ||
            serverHello.SecureRenegotiationDataLength != 0) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection TLS1.2 ServerHello missing secure renegotiation indication\r\n");
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }
        const TlsCipherSuiteCapability* selectedCapability = TlsFindCipherSuiteCapability(context_.CipherSuite());
        if (selectedCapability == nullptr ||
            !TlsPolicyAllowsCipherSuite(options.Policy, context_.CipherSuite())) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }
        if (selectedCapability->BulkCipher == TlsBulkCipherKind::AesCbc && !serverHello.HasEncryptThenMac) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection TLS1.2 CBC ServerHello missing encrypt_then_mac\r\n");
            RecordHandshakeFailure(TlsHandshakeFailureCategory::LocalPolicy, STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }

        bool serverMaySendNewSessionTicket = false;
        status = ServerHelloHasEmptyExtension(serverHello, TlsExtensionSessionTicket, &serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection parse ServerHello extensions failed: 0x%08X len=%Iu\r\n",
                static_cast<ULONG>(status),
                serverHello.ExtensionsLength);
            return status;
        }
        WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Verbose, "TlsConnection ServerHello cipher=0x%04X sessionTicket=%u extensions=%Iu\r\n",
            static_cast<unsigned>(serverHello.CipherSuite),
            serverMaySendNewSessionTicket ? 1u : 0u,
            serverHello.ExtensionsLength);

        // Parse ALPN from ServerHello
        status = ParseServerHelloAlpn(serverHello, negotiatedAlpn_, 16, &negotiatedAlpnLength_);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection parse ALPN failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }
        if (negotiatedAlpnLength_ > 0) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Info, "TlsConnection ALPN negotiated: %.*s\r\n",
                static_cast<int>(negotiatedAlpnLength_), negotiatedAlpn_);
            if (!IsOfferedAlpn(options, negotiatedAlpn_, negotiatedAlpnLength_)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection ALPN was not offered by client\r\n");
                RecordHandshakeFailure(TlsHandshakeFailureCategory::AlpnMismatch, STATUS_NOT_SUPPORTED);
                return STATUS_NOT_SUPPORTED;
            }
        }

        status = transcript_.Initialize(TlsHandshake12::PrfHashForCipherSuite(context_.CipherSuite()));
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection reinitialize transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = transcript_.Update(clientHello, clientHelloLength);
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection update transcript after ServerHello failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (selectedTls12Session != nullptr && Tls12ServerHelloEchoedSessionId(serverHello, *selectedTls12Session)) {
            if (selectedTls12Session->CipherSuite != context_.CipherSuite() ||
                selectedTls12Session->AlpnLength != negotiatedAlpnLength_ ||
                (selectedTls12Session->AlpnLength != 0 &&
                    RtlCompareMemory(
                        selectedTls12Session->Alpn,
                        negotiatedAlpn_,
                        selectedTls12Session->AlpnLength) != selectedTls12Session->AlpnLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = context_.SetTls12ResumedMasterSecret(
                selectedTls12Session->CipherSuite,
                selectedTls12Session->MasterSecret,
                selectedTls12Session->MasterSecretLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (!tlsKeyBlockScratch_.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            TlsKeyBlock& resumedKeyBlock = *tlsKeyBlockScratch_.Get();
            RtlSecureZeroMemory(&resumedKeyBlock, sizeof(resumedKeyBlock));
            const SIZE_T resumedKeyLength = Tls12AeadKeyLengthForCipherSuite(context_.CipherSuite());
            const SIZE_T resumedMacKeyLength = Tls12MacKeyLengthForCipherSuite(context_.CipherSuite());
            const SIZE_T resumedFixedIvLength = Tls12FixedIvLengthForCipherSuite(context_.CipherSuite());
            status = context_.DeriveKeyBlock(
                resumedKeyBlock,
                (resumedMacKeyLength * 2) + (resumedKeyLength * 2) + (resumedFixedIvLength * 2));
            if (NT_SUCCESS(status)) {
                status = context_.ConfigureAesGcmStates(resumedKeyBlock, clientWriteState_, serverWriteState_);
            }
            RtlSecureZeroMemory(&resumedKeyBlock, sizeof(resumedKeyBlock));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadServerChangeCipherSpec(transport, serverMaySendNewSessionTicket);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            encrypted_ = true;

            status = ReadHandshakeMessage(transport, handshake, false);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (handshake.Type != TlsHandshakeType::Finished) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            HeapArray<UCHAR> resumedTranscriptHash(TlsMaxTranscriptHashLength);
            if (!resumedTranscriptHash.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T resumedTranscriptHashLength = 0;
            status = FinishTranscript(
                resumedTranscriptHash.Get(),
                resumedTranscriptHash.Count(),
                &resumedTranscriptHashLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::VerifyFinished(
                    context_,
                    false,
                    resumedTranscriptHash.Get(),
                    resumedTranscriptHashLength,
                    handshake.Body,
                    handshake.BodyLength);
            }
            RtlSecureZeroMemory(resumedTranscriptHash.Get(), resumedTranscriptHash.Count());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (handshake.BodyLength != TlsVerifyDataLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(tls12LastServerVerifyData_, handshake.Body, TlsVerifyDataLength);
            tls12LastServerVerifyDataLength_ = TlsVerifyDataLength;

            status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            static const UCHAR changeCipherSpec[] = { 1 };
            status = SendPlainRecord(
                transport,
                TlsContentType::ChangeCipherSpec,
                changeCipherSpec,
                sizeof(changeCipherSpec));
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = FinishTranscript(
                resumedTranscriptHash.Get(),
                resumedTranscriptHash.Count(),
                &resumedTranscriptHashLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::EncodeFinished(
                    context_,
                    true,
                    resumedTranscriptHash.Get(),
                    resumedTranscriptHashLength,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
            }
            RtlSecureZeroMemory(resumedTranscriptHash.Get(), resumedTranscriptHash.Count());
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (messageLength != TlsHandshakeHeaderLength + TlsVerifyDataLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(tls12LastClientVerifyData_, message + TlsHandshakeHeaderLength, TlsVerifyDataLength);
            tls12LastClientVerifyDataLength_ = TlsVerifyDataLength;

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (!tls12SessionScratch_.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            StoreTls12SessionFromHandshake(
                tls12SessionCache_,
                *tls12SessionScratch_.Get(),
                options,
                tlsPolicyIdentity_,
                serverHello,
                context_.Secrets(),
                tls12PendingTicket_,
                tls12PendingTicketLength_,
                tls12PendingTicketLifetimeHintSeconds_,
                negotiatedAlpn_,
                negotiatedAlpnLength_);
            context_.SetState(TlsHandshakeState::Established);
            return STATUS_SUCCESS;
        }

        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read Certificate failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        TlsCertificateListView certificates = {};
        status = TlsHandshake12::ParseCertificateList(context_, handshake, certificates);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection parse Certificate failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }
        WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Verbose, "TlsConnection Certificate count=%Iu bytes=%Iu\r\n",
            certificates.CertificateCount,
            certificates.CertificatesLength);

        const UCHAR* stapledOcspResponse = nullptr;
        SIZE_T stapledOcspResponseLength = 0;
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read post-Certificate handshake failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (handshake.Type == TlsHandshakeType::CertificateStatus) {
            Tls12CertificateStatusView certificateStatus = {};
            status = TlsHandshake12::ParseCertificateStatus(handshake, certificateStatus);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection parse CertificateStatus failed: 0x%08X body=%Iu\r\n",
                    static_cast<ULONG>(status),
                    handshake.BodyLength);
                return status;
            }

            stapledOcspResponse = certificateStatus.OcspResponse;
            stapledOcspResponseLength = certificateStatus.OcspResponseLength;
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Verbose, "TlsConnection CertificateStatus OCSP bytes=%Iu\r\n",
                stapledOcspResponseLength);

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read post-CertificateStatus handshake failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }
        }

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = options.ProviderCache;
        validation.VerifyCertificate = options.VerifyCertificate;
        validation.RequireRevocationCheck = options.Policy.RequireRevocationCheck;
        validation.StapledOcspResponse = stapledOcspResponse;
        validation.StapledOcspResponseLength = stapledOcspResponseLength;

        HeapObject<CertificateValidationResult> validationResult;
        if (!validationResult.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        CertificateChainView chain = {};
        chain.Certificates = certificates.Certificates;
        chain.CertificatesLength = certificates.CertificatesLength;
        chain.CertificateCount = certificates.CertificateCount;
        status = CertificateValidator::ValidateChain(chain, validation, validationResult.Get());
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection validate Certificate failed: 0x%08X count=%Iu bytes=%Iu\r\n",
                static_cast<ULONG>(status),
                chain.CertificateCount,
                chain.CertificatesLength);
            return status;
        }
        serverCertificatePublicKeyAlgorithm_ = validationResult->Leaf.PublicKeyAlgorithm;
        if ((selectedCapability->Authentication == TlsAuthenticationKind::Rsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) ||
            (selectedCapability->Authentication == TlsAuthenticationKind::Ecdsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP256 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP384 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP521 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed25519 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed448)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
            serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (validationResult->Leaf.HasKeyUsage) {
            if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsKeyEncipherment) {
                return STATUS_TRUST_FAILURE;
            }
            if (selectedCapability->Tls12KeyExchange != Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsDigitalSignature) {
                return STATUS_TRUST_FAILURE;
            }
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed25519) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed25519PublicKeyLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd25519PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed25519PublicKeyLength);
            serverEd25519PublicKeyLength_ = crypto::Ed25519PublicKeyLength;
        }
        else if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed448) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed448PublicKeyLength) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(serverEd448PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed448PublicKeyLength);
            serverEd448PublicKeyLength_ = crypto::Ed448PublicKeyLength;
        }
        else {
            status = CertificateValidator::ImportSubjectPublicKey(providerCache_, validationResult->Leaf, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection import server public key failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }
        }

        const Tls12KeyExchangeKind serverKeyExchangeKind =
            Tls12KeyExchangeForCipherSuite(context_.CipherSuite());
        TlsServerKeyExchangeView keyExchange = {};
        HeapObject<crypto::CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        bool needsCngPeerKey = false;
        if (serverKeyExchangeKind != Tls12KeyExchangeKind::Rsa) {
            status = TlsHandshake12::ParseServerKeyExchange(context_, handshake, keyExchange);
            if (!NT_SUCCESS(status)) {
                LogServerKeyExchangeParseFailure(
                    status,
                    context_.CipherSuite(),
                    serverKeyExchangeKind,
                    handshake);
                return status;
            }
            status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, hello);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection ServerKeyExchange selected value was not offered: 0x%08X group=%u signature=0x%04X\r\n",
                    static_cast<ULONG>(status),
                    static_cast<unsigned>(keyExchange.NamedGroup),
                    static_cast<unsigned>(keyExchange.SignatureScheme));
                return status;
            }

            status = VerifyServerKeyExchange(keyExchange, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection verify ServerKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }

            crypto::KeyExchangeGroup selectedGroup = crypto::KeyExchangeGroup::Secp256r1;
            status = ToKeyExchangeGroup(keyExchange.NamedGroup, &selectedGroup);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            needsCngPeerKey =
                serverKeyExchangeKind != Tls12KeyExchangeKind::DheRsa &&
                selectedGroup != crypto::KeyExchangeGroup::X25519 &&
                selectedGroup != crypto::KeyExchangeGroup::X448;
            if (needsCngPeerKey) {
                status = crypto::CngProvider::ImportEcdhPublicKey(
                    providerCache_,
                    ToEcCurve(keyExchange.NamedGroup),
                    keyExchange.EcPoint,
                    keyExchange.EcPointLength,
                    *peerKey.Get());
                if (!NT_SUCCESS(status)) {
                    WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection import ServerKeyExchange ECDH key failed: 0x%08X group=%u point=%Iu\r\n",
                        static_cast<ULONG>(status),
                        static_cast<unsigned>(keyExchange.NamedGroup),
                        keyExchange.EcPointLength);
                    return status;
                }
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read ServerHelloDone failed: 0x%08X\r\n", static_cast<ULONG>(status));
                return status;
            }
        }

        bool clientCertificateRequested = false;
        bool sendClientCertificateVerify = false;
        TlsSignatureScheme clientCertificateSignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            TlsCertificateRequestView request = {};
            status = TlsHandshake12::ParseCertificateRequest(context_, handshake, request);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            clientCertificateRequested = true;
            const UCHAR* credentialCertificateList = nullptr;
            SIZE_T credentialCertificateListLength = 0;
            if (clientCredential_ != nullptr &&
                clientCredential_->CertificateList != nullptr &&
                clientCredential_->CertificateListLength != 0 &&
                clientCredential_->Sign != nullptr) {
                const SIZE_T peerSignatureSchemesLength = request.SignatureSchemeCount * sizeof(USHORT);
                status = SelectClientCredentialSignatureScheme(
                    options.Policy,
                    *clientCredential_,
                    request.SignatureSchemes,
                    peerSignatureSchemesLength,
                    &clientCertificateSignatureScheme);
                if (NT_SUCCESS(status)) {
                    credentialCertificateList = clientCredential_->CertificateList;
                    credentialCertificateListLength = clientCredential_->CertificateListLength;
                    sendClientCertificateVerify = true;
                }
                else if (status != STATUS_NOT_SUPPORTED) {
                    return status;
                }
            }

            status = TlsHandshake12::EncodeCertificate(
                credentialCertificateList,
                credentialCertificateListLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = TlsHandshake12::MarkServerHelloDone(context_, handshake);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection parse ServerHelloDone failed: 0x%08X type=%u body=%Iu\r\n",
                static_cast<ULONG>(status),
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return status;
        }

        HeapArray<UCHAR> premasterSecret(crypto::KeyExchangeMaxSharedSecretLength);
        if (!premasterSecret.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T premasterSecretLength = 0;
        status = GenerateClientKeyExchange(
            keyExchange,
            needsCngPeerKey ? peerKey.Get() : nullptr,
            serverKeyExchangeKind == Tls12KeyExchangeKind::Rsa ? serverPublicKey.Get() : nullptr,
            validationResult->Leaf.RsaModulusLength,
            premasterSecret.Get(),
            premasterSecret.Count(),
            &premasterSecretLength,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection generate ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection send ClientKeyExchange failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!transcriptHash.IsValid()) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T transcriptHashLength = 0;
        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status) && clientCertificateRequested && sendClientCertificateVerify) {
            HeapArray<UCHAR> signature(TlsScratchHandshakeBufferLength);
            if (!signature.IsValid()) {
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T signatureLength = 0;
            status = clientCredential_->Sign(
                clientCredential_->SignContext,
                clientCertificateSignatureScheme,
                transcriptHash.Get(),
                transcriptHashLength,
                signature.Get(),
                signature.Count(),
                &signatureLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::EncodeCertificateVerify(
                    clientCertificateSignatureScheme,
                    signature.Get(),
                    signatureLength,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
            }
            RtlSecureZeroMemory(signature.Get(), signature.Count());
            if (NT_SUCCESS(status)) {
                status = AppendTranscript(message, messageLength);
            }
            if (NT_SUCCESS(status)) {
                status = SendPlainRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
        }
        if (NT_SUCCESS(status)) {
            status = context_.DeriveExtendedMasterSecret(
                premasterSecret.Get(),
                premasterSecretLength,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection derive TLS1.2 extended master secret failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (!tlsKeyBlockScratch_.IsValid()) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        TlsKeyBlock& keyBlock = *tlsKeyBlockScratch_.Get();
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        const SIZE_T keyLength = Tls12AeadKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T macKeyLength = Tls12MacKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T fixedIvLength = Tls12FixedIvLengthForCipherSuite(context_.CipherSuite());
        status = context_.DeriveKeyBlock(keyBlock, (macKeyLength * 2) + (keyLength * 2) + (fixedIvLength * 2));
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureAesGcmStates(keyBlock, clientWriteState_, serverWriteState_);
        }
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection derive TLS1.2 key block failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        static const UCHAR changeCipherSpec[] = { 1 };
        status = SendPlainRecord(transport, TlsContentType::ChangeCipherSpec, changeCipherSpec, sizeof(changeCipherSpec));
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection send ChangeCipherSpec failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection finish client transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = TlsHandshake12::EncodeFinished(
            context_,
            true,
            transcriptHash.Get(),
            transcriptHashLength,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection encode client Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }
        if (messageLength != TlsHandshakeHeaderLength + TlsVerifyDataLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        RtlCopyMemory(tls12LastClientVerifyData_, message + TlsHandshakeHeaderLength, TlsVerifyDataLength);
        tls12LastClientVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection send client Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = ReadServerChangeCipherSpec(transport, serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read server ChangeCipherSpec failed: 0x%08X allowTicket=%u\r\n",
                static_cast<ULONG>(status),
                serverMaySendNewSessionTicket ? 1u : 0u);
            return status;
        }

        encrypted_ = true;

        status = ReadHandshakeMessage(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection read server Finished failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (handshake.Type != TlsHandshakeType::Finished) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection unexpected server Finished type=%u body=%Iu\r\n",
                static_cast<unsigned>(handshake.Type),
                handshake.BodyLength);
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection finish server transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        status = TlsHandshake12::VerifyFinished(
            context_,
            false,
            transcriptHash.Get(),
            transcriptHashLength,
            handshake.Body,
            handshake.BodyLength);
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection verify server Finished failed: 0x%08X body=%Iu\r\n",
                static_cast<ULONG>(status),
                handshake.BodyLength);
            return status;
        }
        if (handshake.BodyLength != TlsVerifyDataLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        RtlCopyMemory(tls12LastServerVerifyData_, handshake.Body, TlsVerifyDataLength);
        tls12LastServerVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentTls, ::wknet::TraceLevel::Error, "TlsConnection append server Finished transcript failed: 0x%08X\r\n", static_cast<ULONG>(status));
            return status;
        }

        if (!tls12SessionScratch_.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        StoreTls12SessionFromHandshake(
            tls12SessionCache_,
            *tls12SessionScratch_.Get(),
            options,
            tlsPolicyIdentity_,
            serverHello,
            context_.Secrets(),
            tls12PendingTicket_,
            tls12PendingTicketLength_,
            tls12PendingTicketLifetimeHintSeconds_,
            negotiatedAlpn_,
            negotiatedAlpnLength_);
        context_.SetState(TlsHandshakeState::Established);
        return STATUS_SUCCESS;
    }

    NTSTATUS TlsConnection::FinishTls12RenegotiationAttempt(NTSTATUS status) noexcept
    {
        tls12Renegotiating_ = false;
        tls12PendingClientWriteState_.Reset();
        tls12PendingServerWriteState_.Reset();
        ReleaseHandshakeScratch();
        certificateScratchAllocator_ = nullptr;
        if (!NT_SUCCESS(status)) {
            if (lastHandshakeFailure_.Category == TlsHandshakeFailureCategory::None) {
                RecordHandshakeFailure(CategoryForStatus(status), status);
            }
            context_.SetState(TlsHandshakeState::Failed);
        }
        return status;
    }

    NTSTATUS TlsConnection::ConsumeTls12PostHandshakeRecord(
        core::ITransport& transport,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr || fragmentLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        TlsHandshakeMessageView message = {};
        NTSTATUS status = TlsHandshake12::ParseMessage(fragment, fragmentLength, message);
        if (!NT_SUCCESS(status)) {
            return status == STATUS_MORE_PROCESSING_REQUIRED ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        if (message.BytesConsumed != fragmentLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (message.Type == TlsHandshakeType::NewSessionTicket) {
            return ConsumeOptionalPlainHandshakeRecord(fragment, fragmentLength);
        }
        if (message.Type != TlsHandshakeType::HelloRequest) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (message.BodyLength != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return RenegotiateTls12(transport);
    }

    NTSTATUS TlsConnection::RenegotiateTls12(core::ITransport& transport) noexcept
    {
        if (tls12Renegotiating_ ||
            tls13RecordProtection_ ||
            context_.Protocol() != TlsProtocol::Tls12 ||
            context_.State() != TlsHandshakeState::Established ||
            !encrypted_ ||
            !TlsPolicyAllowsTls12Renegotiation(tlsPolicy_) ||
            tls12MaxRenegotiations_ == 0 ||
            tls12RenegotiationCount_ >= tls12MaxRenegotiations_ ||
            tls12LastClientVerifyDataLength_ != TlsVerifyDataLength ||
            tls12LastServerVerifyDataLength_ != TlsVerifyDataLength) {
            return STATUS_NOT_SUPPORTED;
        }

        tls12Renegotiating_ = true;
        handshakeLength_ = 0;
        handshakeConsumed_ = 0;
        lastHandshakeOffset_ = 0;
        lastHandshakeLength_ = 0;
        RtlSecureZeroMemory(tls12PendingTicket_, sizeof(tls12PendingTicket_));
        tls12PendingTicketLength_ = 0;
        tls12PendingTicketLifetimeHintSeconds_ = 0;

        TlsClientConnectionOptions options = tls12RenegotiationOptions_;
        options.EnableSessionResumption = false;
        options.Tls12SessionCache = nullptr;
        options.SessionCache = nullptr;
        options.EnableEarlyData = false;
        options.EarlyData = nullptr;
        options.EarlyDataLength = 0;
        options.EarlyDataAccepted = nullptr;
        options.EarlyDataBytesSent = nullptr;

        NTSTATUS status = PrepareScratch(options);
        if (NT_SUCCESS(status)) {
            status = EnsureBuffers();
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = context_.InitializeClient({ 3, 3 });
        if (NT_SUCCESS(status)) {
            status = transcript_.Initialize(crypto::HashAlgorithm::Sha256);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        UCHAR* message = nullptr;
        status = GetHandshakeScratch(
            TlsScratchClientHelloOffset,
            TlsScratchClientHelloLength,
            &message);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        RtlSecureZeroMemory(message, TlsScratchClientHelloLength);
        SIZE_T messageLength = 0;

        TlsClientHelloOptions hello = {};
        hello.ServerName = options.ServerName;
        hello.ServerNameLength = options.ServerNameLength;
        hello.AlpnProtocols = options.AlpnProtocols;
        hello.AlpnProtocolCount = options.AlpnProtocolCount;
        hello.OfferEncryptThenMac = options.Policy.EnableTls12Cbc;
        hello.OfferStatusRequest = true;
        hello.RenegotiationInfo = tls12LastClientVerifyData_;
        hello.RenegotiationInfoLength = tls12LastClientVerifyDataLength_;

        HeapArray<TlsCipherSuite> offeredCipherSuites;
        HeapArray<TlsNamedGroup> offeredNamedGroups;
        HeapArray<TlsSignatureScheme> offeredSignatureSchemes;
        SIZE_T offeredCipherSuiteCount = 0;
        SIZE_T offeredNamedGroupCount = 0;
        SIZE_T offeredSignatureSchemeCount = 0;
        status = BuildTls12PolicyOffers(
            options.Policy,
            offeredCipherSuites,
            &offeredCipherSuiteCount,
            offeredNamedGroups,
            &offeredNamedGroupCount,
            offeredSignatureSchemes,
            &offeredSignatureSchemeCount);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        hello.CipherSuites = offeredCipherSuites.Get();
        hello.CipherSuiteCount = offeredCipherSuiteCount;
        hello.NamedGroups = offeredNamedGroups.Get();
        hello.NamedGroupCount = offeredNamedGroupCount;
        hello.SignatureSchemes = offeredSignatureSchemes.Get();
        hello.SignatureSchemeCount = offeredSignatureSchemeCount;

        status = TlsHandshake12::EncodeClientHello(
            context_,
            hello,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        UCHAR* clientHello = nullptr;
        status = GetHandshakeScratch(
            TlsScratchFirstClientHelloOffset,
            TlsScratchFirstClientHelloLength,
            &clientHello);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (messageLength > TlsScratchFirstClientHelloLength) {
            return FinishTls12RenegotiationAttempt(STATUS_BUFFER_TOO_SMALL);
        }
        RtlCopyMemory(clientHello, message, messageLength);
        const SIZE_T clientHelloLength = messageLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        TlsHandshakeMessageView handshake = {};
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        TlsServerHelloView serverHello = {};
        status = TlsHandshake12::ParseServerHello(context_, handshake, serverHello);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake12::ValidateServerHelloOffer(serverHello, hello);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (!serverHello.HasExtendedMasterSecret ||
            !serverHello.HasSecureRenegotiation ||
            serverHello.SecureRenegotiationDataLength != (TlsVerifyDataLength * 2) ||
            serverHello.SecureRenegotiationData == nullptr ||
            RtlCompareMemory(
                serverHello.SecureRenegotiationData,
                tls12LastClientVerifyData_,
                TlsVerifyDataLength) != TlsVerifyDataLength ||
            RtlCompareMemory(
                serverHello.SecureRenegotiationData + TlsVerifyDataLength,
                tls12LastServerVerifyData_,
                TlsVerifyDataLength) != TlsVerifyDataLength) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }

        const TlsCipherSuiteCapability* selectedCapability = TlsFindCipherSuiteCapability(context_.CipherSuite());
        if (selectedCapability == nullptr ||
            !TlsPolicyAllowsCipherSuite(options.Policy, context_.CipherSuite())) {
            return FinishTls12RenegotiationAttempt(STATUS_NOT_SUPPORTED);
        }
        if (selectedCapability->BulkCipher == TlsBulkCipherKind::AesCbc && !serverHello.HasEncryptThenMac) {
            return FinishTls12RenegotiationAttempt(STATUS_NOT_SUPPORTED);
        }

        bool serverMaySendNewSessionTicket = false;
        status = ServerHelloHasEmptyExtension(serverHello, TlsExtensionSessionTicket, &serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = ParseServerHelloAlpn(serverHello, negotiatedAlpn_, 16, &negotiatedAlpnLength_);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (negotiatedAlpnLength_ != 0 &&
            !IsOfferedAlpn(options, negotiatedAlpn_, negotiatedAlpnLength_)) {
            RecordHandshakeFailure(TlsHandshakeFailureCategory::AlpnMismatch, STATUS_NOT_SUPPORTED);
            return FinishTls12RenegotiationAttempt(STATUS_NOT_SUPPORTED);
        }

        status = transcript_.Initialize(TlsHandshake12::PrfHashForCipherSuite(context_.CipherSuite()));
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(clientHello, clientHelloLength);
        }
        if (NT_SUCCESS(status)) {
            status = transcript_.Update(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        }
        RtlSecureZeroMemory(clientHello, TlsScratchFirstClientHelloLength);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        TlsCertificateListView certificates = {};
        status = TlsHandshake12::ParseCertificateList(context_, handshake, certificates);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        const UCHAR* stapledOcspResponse = nullptr;
        SIZE_T stapledOcspResponseLength = 0;
        status = ReadHandshakeMessage(transport, handshake, true);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        if (handshake.Type == TlsHandshakeType::CertificateStatus) {
            Tls12CertificateStatusView certificateStatus = {};
            status = TlsHandshake12::ParseCertificateStatus(handshake, certificateStatus);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            stapledOcspResponse = certificateStatus.OcspResponse;
            stapledOcspResponseLength = certificateStatus.OcspResponseLength;
            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        CertificateValidationOptions validation = {};
        validation.HostName = options.ServerName;
        validation.HostNameLength = options.ServerNameLength;
        validation.Store = options.CertificateStore;
        validation.ScratchAllocator = certificateScratchAllocator_;
        validation.ProviderCache = options.ProviderCache;
        validation.VerifyCertificate = options.VerifyCertificate;
        validation.RequireRevocationCheck = options.Policy.RequireRevocationCheck;
        validation.StapledOcspResponse = stapledOcspResponse;
        validation.StapledOcspResponseLength = stapledOcspResponseLength;

        HeapObject<CertificateValidationResult> validationResult;
        if (!validationResult.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        CertificateChainView chain = {};
        chain.Certificates = certificates.Certificates;
        chain.CertificatesLength = certificates.CertificatesLength;
        chain.CertificateCount = certificates.CertificateCount;
        status = CertificateValidator::ValidateChain(chain, validation, validationResult.Get());
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        serverCertificatePublicKeyAlgorithm_ = validationResult->Leaf.PublicKeyAlgorithm;
        if ((selectedCapability->Authentication == TlsAuthenticationKind::Rsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) ||
            (selectedCapability->Authentication == TlsAuthenticationKind::Ecdsa &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP256 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP384 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::EcdsaP521 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed25519 &&
                serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Ed448)) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
            serverCertificatePublicKeyAlgorithm_ != CertificatePublicKeyAlgorithm::Rsa) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        if (validationResult->Leaf.HasKeyUsage) {
            if (selectedCapability->Tls12KeyExchange == Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsKeyEncipherment) {
                return FinishTls12RenegotiationAttempt(STATUS_TRUST_FAILURE);
            }
            if (selectedCapability->Tls12KeyExchange != Tls12KeyExchangeKind::Rsa &&
                !validationResult->Leaf.AllowsDigitalSignature) {
                return FinishTls12RenegotiationAttempt(STATUS_TRUST_FAILURE);
            }
        }

        HeapObject<crypto::CngKey> serverPublicKey;
        if (!serverPublicKey.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed25519) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed25519PublicKeyLength) {
                return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
            }
            RtlCopyMemory(serverEd25519PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed25519PublicKeyLength);
            serverEd25519PublicKeyLength_ = crypto::Ed25519PublicKeyLength;
        }
        else if (validationResult->Leaf.PublicKeyAlgorithm == CertificatePublicKeyAlgorithm::Ed448) {
            if (validationResult->Leaf.PublicKey == nullptr ||
                validationResult->Leaf.PublicKeyLength != crypto::Ed448PublicKeyLength) {
                return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
            }
            RtlCopyMemory(serverEd448PublicKey_, validationResult->Leaf.PublicKey, crypto::Ed448PublicKeyLength);
            serverEd448PublicKeyLength_ = crypto::Ed448PublicKeyLength;
        }
        else {
            status = CertificateValidator::ImportSubjectPublicKey(providerCache_, validationResult->Leaf, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        const Tls12KeyExchangeKind serverKeyExchangeKind =
            Tls12KeyExchangeForCipherSuite(context_.CipherSuite());
        TlsServerKeyExchangeView keyExchange = {};
        HeapObject<crypto::CngKey> peerKey;
        if (!peerKey.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        bool needsCngPeerKey = false;
        if (serverKeyExchangeKind != Tls12KeyExchangeKind::Rsa) {
            status = TlsHandshake12::ParseServerKeyExchange(context_, handshake, keyExchange);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            status = TlsHandshake12::ValidateServerKeyExchangeOffer(keyExchange, hello);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            status = VerifyServerKeyExchange(keyExchange, *serverPublicKey.Get());
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            crypto::KeyExchangeGroup selectedGroup = crypto::KeyExchangeGroup::Secp256r1;
            status = ToKeyExchangeGroup(keyExchange.NamedGroup, &selectedGroup);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            needsCngPeerKey =
                serverKeyExchangeKind != Tls12KeyExchangeKind::DheRsa &&
                selectedGroup != crypto::KeyExchangeGroup::X25519 &&
                selectedGroup != crypto::KeyExchangeGroup::X448;
            if (needsCngPeerKey) {
                status = crypto::CngProvider::ImportEcdhPublicKey(
                    providerCache_,
                    ToEcCurve(keyExchange.NamedGroup),
                    keyExchange.EcPoint,
                    keyExchange.EcPointLength,
                    *peerKey.Get());
                if (!NT_SUCCESS(status)) {
                    return FinishTls12RenegotiationAttempt(status);
                }
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        bool clientCertificateRequested = false;
        bool sendClientCertificateVerify = false;
        TlsSignatureScheme clientCertificateSignatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;

        if (handshake.Type == TlsHandshakeType::CertificateRequest) {
            TlsCertificateRequestView request = {};
            status = TlsHandshake12::ParseCertificateRequest(context_, handshake, request);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            clientCertificateRequested = true;
            const UCHAR* credentialCertificateList = nullptr;
            SIZE_T credentialCertificateListLength = 0;
            if (clientCredential_ != nullptr &&
                clientCredential_->CertificateList != nullptr &&
                clientCredential_->CertificateListLength != 0 &&
                clientCredential_->Sign != nullptr) {
                const SIZE_T peerSignatureSchemesLength = request.SignatureSchemeCount * sizeof(USHORT);
                status = SelectClientCredentialSignatureScheme(
                    options.Policy,
                    *clientCredential_,
                    request.SignatureSchemes,
                    peerSignatureSchemesLength,
                    &clientCertificateSignatureScheme);
                if (NT_SUCCESS(status)) {
                    credentialCertificateList = clientCredential_->CertificateList;
                    credentialCertificateListLength = clientCredential_->CertificateListLength;
                    sendClientCertificateVerify = true;
                }
                else if (status != STATUS_NOT_SUPPORTED) {
                    return FinishTls12RenegotiationAttempt(status);
                }
            }

            status = TlsHandshake12::EncodeCertificate(
                credentialCertificateList,
                credentialCertificateListLength,
                message,
                TlsScratchClientHelloLength,
                &messageLength);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
            status = AppendTranscript(message, messageLength);
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }

            status = ReadHandshakeMessage(transport, handshake, true);
            if (!NT_SUCCESS(status)) {
                return FinishTls12RenegotiationAttempt(status);
            }
        }

        status = TlsHandshake12::MarkServerHelloDone(context_, handshake);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        HeapArray<UCHAR> premasterSecret(crypto::KeyExchangeMaxSharedSecretLength);
        HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
        if (!premasterSecret.IsValid() || !transcriptHash.IsValid()) {
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }

        SIZE_T premasterSecretLength = 0;
        status = GenerateClientKeyExchange(
            keyExchange,
            needsCngPeerKey ? peerKey.Get() : nullptr,
            serverKeyExchangeKind == Tls12KeyExchangeKind::Rsa ? serverPublicKey.Get() : nullptr,
            validationResult->Leaf.RsaModulusLength,
            premasterSecret.Get(),
            premasterSecret.Count(),
            &premasterSecretLength,
            message,
            TlsScratchClientHelloLength,
            &messageLength);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        SIZE_T transcriptHashLength = 0;
        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status) && clientCertificateRequested && sendClientCertificateVerify) {
            HeapArray<UCHAR> signature(TlsScratchHandshakeBufferLength);
            if (!signature.IsValid()) {
                RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
            }

            SIZE_T signatureLength = 0;
            status = clientCredential_->Sign(
                clientCredential_->SignContext,
                clientCertificateSignatureScheme,
                transcriptHash.Get(),
                transcriptHashLength,
                signature.Get(),
                signature.Count(),
                &signatureLength);
            if (NT_SUCCESS(status)) {
                status = TlsHandshake12::EncodeCertificateVerify(
                    clientCertificateSignatureScheme,
                    signature.Get(),
                    signatureLength,
                    message,
                    TlsScratchClientHelloLength,
                    &messageLength);
            }
            RtlSecureZeroMemory(signature.Get(), signature.Count());
            if (NT_SUCCESS(status)) {
                status = AppendTranscript(message, messageLength);
            }
            if (NT_SUCCESS(status)) {
                status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
            }
        }
        if (NT_SUCCESS(status)) {
            status = context_.DeriveExtendedMasterSecret(
                premasterSecret.Get(),
                premasterSecretLength,
                transcriptHash.Get(),
                transcriptHashLength);
        }
        RtlSecureZeroMemory(premasterSecret.Get(), premasterSecret.Count());
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        if (!tlsKeyBlockScratch_.IsValid()) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(STATUS_INSUFFICIENT_RESOURCES);
        }
        TlsKeyBlock& keyBlock = *tlsKeyBlockScratch_.Get();
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        const SIZE_T keyLength = Tls12AeadKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T macKeyLength = Tls12MacKeyLengthForCipherSuite(context_.CipherSuite());
        const SIZE_T fixedIvLength = Tls12FixedIvLengthForCipherSuite(context_.CipherSuite());
        status = context_.DeriveKeyBlock(keyBlock, (macKeyLength * 2) + (keyLength * 2) + (fixedIvLength * 2));
        if (NT_SUCCESS(status)) {
            status = context_.ConfigureAesGcmStates(keyBlock, tls12PendingClientWriteState_, tls12PendingServerWriteState_);
        }
        RtlSecureZeroMemory(&keyBlock, sizeof(keyBlock));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }

        static const UCHAR changeCipherSpec[] = { 1 };
        status = SendProtectedRecord(transport, TlsContentType::ChangeCipherSpec, changeCipherSpec, sizeof(changeCipherSpec));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
            return FinishTls12RenegotiationAttempt(status);
        }
        clientWriteState_ = tls12PendingClientWriteState_;
        tls12PendingClientWriteState_.Reset();

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake12::EncodeFinished(
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
            return FinishTls12RenegotiationAttempt(status);
        }
        if (messageLength != TlsHandshakeHeaderLength + TlsVerifyDataLength) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        RtlCopyMemory(tls12LastClientVerifyData_, message + TlsHandshakeHeaderLength, TlsVerifyDataLength);
        tls12LastClientVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(message, messageLength);
        if (NT_SUCCESS(status)) {
            status = SendProtectedRecord(transport, TlsContentType::Handshake, message, messageLength);
        }
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        status = ReadServerChangeCipherSpec(transport, serverMaySendNewSessionTicket);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        serverWriteState_ = tls12PendingServerWriteState_;
        tls12PendingServerWriteState_.Reset();
        encrypted_ = true;

        status = ReadHandshakeMessage(transport, handshake, false);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (handshake.Type != TlsHandshakeType::Finished) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }

        status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
        if (NT_SUCCESS(status)) {
            status = TlsHandshake12::VerifyFinished(
                context_,
                false,
                transcriptHash.Get(),
                transcriptHashLength,
                handshake.Body,
                handshake.BodyLength);
        }
        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }
        if (handshake.BodyLength != TlsVerifyDataLength) {
            return FinishTls12RenegotiationAttempt(STATUS_INVALID_NETWORK_RESPONSE);
        }
        RtlCopyMemory(tls12LastServerVerifyData_, handshake.Body, TlsVerifyDataLength);
        tls12LastServerVerifyDataLength_ = TlsVerifyDataLength;

        status = AppendTranscript(handshakeBuffer_ + lastHandshakeOffset_, lastHandshakeLength_);
        if (!NT_SUCCESS(status)) {
            return FinishTls12RenegotiationAttempt(status);
        }

        ++tls12RenegotiationCount_;
        context_.SetState(TlsHandshakeState::Established);
        return FinishTls12RenegotiationAttempt(STATUS_SUCCESS);
    }

    NTSTATUS TlsConnection::VerifyServerKeyExchange(
        const TlsServerKeyExchangeView& keyExchange,
        const crypto::CngKey& serverPublicKey) noexcept
    {
        if (!SignatureSchemeMatchesPublicKey(serverCertificatePublicKeyAlgorithm_, keyExchange.SignatureScheme)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        UCHAR* signedData = nullptr;
        NTSTATUS status = GetHandshakeScratch(
            TlsScratchSignedDataOffset,
            TlsScratchSignedDataLength,
            &signedData);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);

        if (keyExchange.ParametersLength > TlsScratchSignedDataLength - (TlsRandomLength * 2)) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(signedData, context_.Secrets().ClientRandom, TlsRandomLength);
        RtlCopyMemory(signedData + TlsRandomLength, context_.Secrets().ServerRandom, TlsRandomLength);
        RtlCopyMemory(signedData + (TlsRandomLength * 2), keyExchange.Parameters, keyExchange.ParametersLength);
        const SIZE_T signedDataLength = (TlsRandomLength * 2) + keyExchange.ParametersLength;

        if (keyExchange.SignatureScheme == TlsSignatureScheme::Ed25519) {
            if (serverEd25519PublicKeyLength_ != crypto::Ed25519PublicKeyLength) {
                RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = crypto::CngProvider::VerifyEd25519(
                serverEd25519PublicKey_,
                serverEd25519PublicKeyLength_,
                signedData,
                signedDataLength,
                keyExchange.Signature,
                keyExchange.SignatureLength);
            RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }
        if (keyExchange.SignatureScheme == TlsSignatureScheme::Ed448) {
            if (serverEd448PublicKeyLength_ != crypto::Ed448PublicKeyLength) {
                RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = crypto::CngProvider::VerifyEd448(
                serverEd448PublicKey_,
                serverEd448PublicKeyLength_,
                signedData,
                signedDataLength,
                keyExchange.Signature,
                keyExchange.SignatureLength);
            RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
            return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
        }

        HeapArray<UCHAR> hash(64);
        if (!hash.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T hashLength = 0;
        status = crypto::CngProvider::Hash(
            providerCache_,
            HashForSignature(keyExchange.SignatureScheme),
            signedData,
            signedDataLength,
            hash.Get(),
            hash.Count(),
            &hashLength);
        RtlSecureZeroMemory(signedData, TlsScratchSignedDataLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        crypto::SignatureAlgorithm signatureAlgorithm = crypto::SignatureAlgorithm::RsaPkcs1Sha256;
        status = ToSignatureAlgorithm(keyExchange.SignatureScheme, &signatureAlgorithm);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(hash.Get(), hash.Count());
            return status;
        }

        status = crypto::CngProvider::VerifySignature(
            providerCache_,
            signatureAlgorithm,
            serverPublicKey,
            hash.Get(),
            hashLength,
            keyExchange.Signature,
            keyExchange.SignatureLength);
        RtlSecureZeroMemory(hash.Get(), hash.Count());
        return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
    }

    NTSTATUS TlsConnection::GenerateClientKeyExchange(
        const TlsServerKeyExchangeView& keyExchange,
        const crypto::CngKey* peerKey,
        const crypto::CngKey* rsaPublicKey,
        SIZE_T rsaCiphertextLength,
        UCHAR* premasterSecret,
        SIZE_T premasterSecretCapacity,
        SIZE_T* premasterSecretLength,
        UCHAR* destination,
        SIZE_T destinationCapacity,
        SIZE_T* bytesWritten) noexcept
    {
        if (premasterSecret == nullptr ||
            premasterSecretCapacity == 0 ||
            premasterSecretLength == nullptr ||
            bytesWritten == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        *premasterSecretLength = 0;
        *bytesWritten = 0;

        const Tls12KeyExchangeKind keyExchangeKind = Tls12KeyExchangeForCipherSuite(context_.CipherSuite());
        NTSTATUS status = STATUS_SUCCESS;
        if (keyExchangeKind == Tls12KeyExchangeKind::Rsa) {
            if (rsaPublicKey == nullptr ||
                rsaCiphertextLength == 0 ||
                premasterSecretCapacity < TlsMasterSecretLength) {
                return STATUS_INVALID_PARAMETER;
            }

            premasterSecret[0] = 3;
            premasterSecret[1] = 3;
            status = crypto::CngProvider::GenerateRandom(premasterSecret + 2, TlsMasterSecretLength - 2);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                return status;
            }
            *premasterSecretLength = TlsMasterSecretLength;

            HeapArray<UCHAR> ciphertext(rsaCiphertextLength);
            if (!ciphertext.IsValid()) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T ciphertextLength = 0;
            status = crypto::CngProvider::EncryptRsaPkcs1(
                providerCache_,
                *rsaPublicKey,
                premasterSecret,
                *premasterSecretLength,
                ciphertext.Get(),
                ciphertext.Count(),
                &ciphertextLength);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(ciphertext.Get(), ciphertext.Count());
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
                return status;
            }

            status = EncodeClientKeyExchangeOpaque16(
                ciphertext.Get(),
                ciphertextLength,
                destination,
                destinationCapacity,
                bytesWritten);
            RtlSecureZeroMemory(ciphertext.Get(), ciphertext.Count());
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
            }
            return status;
        }

        crypto::KeyExchangeGroup group = crypto::KeyExchangeGroup::Secp256r1;
        status = ToKeyExchangeGroup(keyExchange.NamedGroup, &group);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (keyExchangeKind == Tls12KeyExchangeKind::DheRsa ||
            group == crypto::KeyExchangeGroup::X25519 ||
            group == crypto::KeyExchangeGroup::X448) {
            const UCHAR* peerPublicKey = keyExchangeKind == Tls12KeyExchangeKind::DheRsa ?
                keyExchange.DhPublicKey :
                keyExchange.EcPoint;
            const SIZE_T peerPublicKeyLength = keyExchangeKind == Tls12KeyExchangeKind::DheRsa ?
                keyExchange.DhPublicKeyLength :
                keyExchange.EcPointLength;
            if (peerPublicKey == nullptr || peerPublicKeyLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }

            HeapObject<crypto::KeyExchangeKeyPair> keyPair;
            if (!keyPair.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            status = crypto::KeyExchange::GenerateKeyPair(providerCache_, group, *keyPair.Get());
            if (!NT_SUCCESS(status)) {
                return status;
            }

            status = crypto::KeyExchange::DeriveSharedSecret(
                providerCache_,
                *keyPair.Get(),
                peerPublicKey,
                peerPublicKeyLength,
                premasterSecret,
                premasterSecretCapacity,
                premasterSecretLength);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                return status;
            }

            status = keyExchangeKind == Tls12KeyExchangeKind::DheRsa ?
                EncodeClientKeyExchangeOpaque16(
                    keyPair->PublicKey,
                    keyPair->PublicKeyLength,
                    destination,
                    destinationCapacity,
                    bytesWritten) :
                TlsHandshake12::EncodeClientKeyExchange(
                    keyPair->PublicKey,
                    keyPair->PublicKeyLength,
                    destination,
                    destinationCapacity,
                    bytesWritten);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
                *premasterSecretLength = 0;
            }
            return status;
        }

        if (peerKey == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapObject<crypto::CngKey> privateKey;
        if (!privateKey.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = crypto::CngProvider::GenerateEcdhKeyPair(
            providerCache_,
            ToEcCurve(keyExchange.NamedGroup),
            *privateKey.Get());
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HeapArray<UCHAR> publicPoint(1 + (66 * 2));
        if (!publicPoint.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T pointLength = 0;
        status = ExportTlsEcPoint(*privateKey.Get(), publicPoint.Get(), publicPoint.Count(), &pointLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = crypto::CngProvider::DeriveEcdhSecret(
            providerCache_,
            *privateKey.Get(),
            *peerKey,
            premasterSecret,
            premasterSecretCapacity,
            premasterSecretLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = TlsHandshake12::EncodeClientKeyExchange(
            publicPoint.Get(),
            pointLength,
            destination,
            destinationCapacity,
            bytesWritten);
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(premasterSecret, premasterSecretCapacity);
            *premasterSecretLength = 0;
        }

        return status;
    }
