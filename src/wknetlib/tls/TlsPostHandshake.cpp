#include "tls/TlsConnectionInternal.hpp"

namespace wknet
{
namespace tls
{
    NTSTATUS TlsConnection::ConsumeTls13PostHandshakeRecord(
        core::ITransport& transport,
        const UCHAR* fragment,
        SIZE_T fragmentLength) noexcept
    {
        if (fragment == nullptr || fragmentLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T offset = 0;
        SIZE_T messageCount = 0;
        bool keyUpdated = false;
        bool updateRequested = false;
        while (offset < fragmentLength) {
            TlsHandshakeMessageView message = {};
            NTSTATUS status = TlsHandshake12::ParseMessage(
                fragment + offset,
                fragmentLength - offset,
                message);
            if (!NT_SUCCESS(status)) {
                return status == STATUS_MORE_PROCESSING_REQUIRED ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            if (++messageCount > TlsMaxPostHandshakeMessagesPerRecord) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            if (message.Type == TlsHandshakeType::NewSessionTicket) {
                Tls13NewSessionTicketView ticket = {};
                status = TlsHandshake13::ParseNewSessionTicket(message, ticket);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                status = StoreTls13Ticket(ticket, tls13ExternalSessionCache_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else if (message.Type == TlsHandshakeType::KeyUpdate) {
                Tls13KeyUpdateView keyUpdate = {};
                status = TlsHandshake13::ParseKeyUpdate(message, keyUpdate);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (!keyUpdated) {
                    status = context_.UpdateTls13ApplicationTrafficSecret(false, serverWriteState_);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    keyUpdated = true;
                }
                if (keyUpdate.Request == Tls13KeyUpdateRequest::UpdateRequested) {
                    updateRequested = true;
                }
            }
            else if (message.Type == TlsHandshakeType::CertificateRequest) {
                if (!tls13PostHandshakeClientAuthAllowed_) {
                    return STATUS_NOT_SUPPORTED;
                }

                Tls13CertificateRequestView request = {};
                status = TlsHandshake13::ParseCertificateRequest(message, request);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (request.ContextLength == 0 || request.ContextLength > 255) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                const UCHAR* peerSignatureSchemes = nullptr;
                SIZE_T peerSignatureSchemesLength = 0;
                status = FindTls13CertificateRequestSignatureAlgorithms(
                    request,
                    &peerSignatureSchemes,
                    &peerSignatureSchemesLength);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                bool sendCertificateVerify = false;
                TlsSignatureScheme signatureScheme = TlsSignatureScheme::RsaPkcs1Sha256;
                if (clientCredential_ != nullptr &&
                    clientCredential_->CertificateList != nullptr &&
                    clientCredential_->CertificateListLength != 0 &&
                    clientCredential_->Sign != nullptr) {
                    status = SelectClientCredentialSignatureScheme(
                        tlsPolicy_,
                        *clientCredential_,
                        peerSignatureSchemes,
                        peerSignatureSchemesLength,
                        &signatureScheme);
                    if (NT_SUCCESS(status)) {
                        sendCertificateVerify = true;
                    }
                    else if (status != STATUS_NOT_SUPPORTED) {
                        return status;
                    }
                }

                status = AppendTranscript(fragment + offset, message.BytesConsumed);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                HeapArray<UCHAR> output(TlsHandshakeBufferLength);
                if (!output.IsValid()) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                const UCHAR* certificateList = sendCertificateVerify ? clientCredential_->CertificateList : nullptr;
                const SIZE_T certificateListLength = sendCertificateVerify ? clientCredential_->CertificateListLength : 0;
                SIZE_T outputLength = 0;
                status = TlsHandshake13::EncodeCertificate(
                    request.Context,
                    request.ContextLength,
                    certificateList,
                    certificateListLength,
                    output.Get(),
                    output.Count(),
                    &outputLength);
                if (NT_SUCCESS(status)) {
                    status = AppendTranscript(output.Get(), outputLength);
                }
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::Handshake, output.Get(), outputLength);
                }
                if (!NT_SUCCESS(status)) {
                    RtlSecureZeroMemory(output.Get(), output.Count());
                    return status;
                }

                HeapArray<UCHAR> transcriptHash(TlsMaxTranscriptHashLength);
                if (!transcriptHash.IsValid()) {
                    RtlSecureZeroMemory(output.Get(), output.Count());
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                SIZE_T transcriptHashLength = 0;
                if (sendCertificateVerify) {
                    status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
                    if (!NT_SUCCESS(status)) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                        return status;
                    }

                    HeapArray<UCHAR> signedInput(Tls13CertificateVerifyInputMaxLength);
                    HeapArray<UCHAR> signature(TlsHandshakeBufferLength);
                    if (!signedInput.IsValid() || !signature.IsValid()) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    SIZE_T signedInputLength = 0;
                    status = TlsHandshake13::BuildCertificateVerifyInput(
                        false,
                        transcriptHash.Get(),
                        transcriptHashLength,
                        signedInput.Get(),
                        signedInput.Count(),
                        &signedInputLength);
                    RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                    if (NT_SUCCESS(status)) {
                        SIZE_T signatureLength = 0;
                        status = clientCredential_->Sign(
                            clientCredential_->SignContext,
                            signatureScheme,
                            signedInput.Get(),
                            signedInputLength,
                            signature.Get(),
                            signature.Count(),
                            &signatureLength);
                        if (NT_SUCCESS(status)) {
                            status = TlsHandshake13::EncodeCertificateVerify(
                                signatureScheme,
                                signature.Get(),
                                signatureLength,
                                output.Get(),
                                output.Count(),
                                &outputLength);
                        }
                    }
                    RtlSecureZeroMemory(signedInput.Get(), signedInput.Count());
                    RtlSecureZeroMemory(signature.Get(), signature.Count());
                    if (!NT_SUCCESS(status)) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        return status;
                    }

                    status = AppendTranscript(output.Get(), outputLength);
                    if (NT_SUCCESS(status)) {
                        status = SendProtectedRecord13(transport, TlsContentType::Handshake, output.Get(), outputLength);
                    }
                    if (!NT_SUCCESS(status)) {
                        RtlSecureZeroMemory(output.Get(), output.Count());
                        return status;
                    }
                }

                status = FinishTranscript(transcriptHash.Get(), transcriptHash.Count(), &transcriptHashLength);
                if (NT_SUCCESS(status)) {
                    status = TlsHandshake13::EncodeFinished(
                        context_,
                        true,
                        transcriptHash.Get(),
                        transcriptHashLength,
                        output.Get(),
                        output.Count(),
                        &outputLength);
                }
                RtlSecureZeroMemory(transcriptHash.Get(), transcriptHash.Count());
                if (NT_SUCCESS(status)) {
                    status = AppendTranscript(output.Get(), outputLength);
                }
                if (NT_SUCCESS(status)) {
                    status = SendProtectedRecord13(transport, TlsContentType::Handshake, output.Get(), outputLength);
                }
                RtlSecureZeroMemory(output.Get(), output.Count());
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            else {
                return STATUS_NOT_SUPPORTED;
            }

            offset += message.BytesConsumed;
        }

        if (updateRequested) {
            ExchangeTlsFlag(&tls13PeerRequestedKeyUpdate_, 1);
        }

        return STATUS_SUCCESS;
    }
}
}
