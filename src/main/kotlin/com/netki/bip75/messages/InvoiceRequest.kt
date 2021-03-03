package com.netki.bip75.messages

import com.netki.bip75.extensions.*
import com.netki.bip75.protocol.Messages
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_VALIDATION_EV_NOT_VALID
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_VALIDATION_INVALID_BENEFICIARY_CERTIFICATE_CA
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_VALIDATION_INVALID_ORIGINATOR_CERTIFICATE_CA
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_ORIGINATOR_SIGNATURE
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE
import com.netki.exceptions.InvalidCertificateChainException
import com.netki.exceptions.InvalidCertificateException
import com.netki.exceptions.InvalidSignatureException
import com.netki.extensions.toStringLocal
import com.netki.model.*
import com.netki.security.Certificate

class InvoiceRequest {

    fun create(
        protocolMessageParameters: ProtocolMessageParameters
    ): ByteArray {
        val invoiceRequestParameters = protocolMessageParameters as InvoiceRequestParameters
        invoiceRequestParameters.originatorParameters.validate(true, OwnerType.ORIGINATOR)
        invoiceRequestParameters.beneficiaryParameters?.validate(false, OwnerType.BENEFICIARY)

        val messageInvoiceRequestBuilder =
            invoiceRequestParameters.toMessageInvoiceRequestBuilderUnsigned(
                invoiceRequestParameters.senderParameters,
                invoiceRequestParameters.attestationsRequested,
                invoiceRequestParameters.recipientParameters
            )

        invoiceRequestParameters.beneficiaryParameters?.forEach { beneficiary ->
            val beneficiaryMessage = beneficiary.toMessageBeneficiaryBuilderWithoutAttestations()

            beneficiary.pkiDataParametersSets.forEach { pkiData ->
                beneficiaryMessage.addAttestations(pkiData.toMessageAttestation(false))
            }

            messageInvoiceRequestBuilder.addBeneficiaries(beneficiaryMessage)
        }

        invoiceRequestParameters.originatorParameters.forEach { originator ->
            val originatorMessage = originator.toMessageOriginatorBuilderWithoutAttestations()

            originator.pkiDataParametersSets.forEach { pkiData ->
                originatorMessage.addAttestations(pkiData.toMessageAttestation(originator.isPrimaryForTransaction))
            }

            messageInvoiceRequestBuilder.addOriginators(originatorMessage)
        }

        val messageInvoiceRequest = messageInvoiceRequestBuilder.build()

        val invoiceRequest =
            messageInvoiceRequest.signMessage(invoiceRequestParameters.senderParameters)
                .toByteArray()
        return invoiceRequest.toProtocolMessage(
            MessageType.INVOICE_REQUEST,
            invoiceRequestParameters.messageInformation,
            invoiceRequestParameters.senderParameters,
            invoiceRequestParameters.recipientParameters
        )
    }

    fun isValid(
        protocolMessageBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ): Boolean {
        val protocolMessageMetadata = protocolMessageBinary.extractProtocolMessageMetadata()
        val messageInvoiceRequest =
            protocolMessageBinary.getSerializedMessage(
                protocolMessageMetadata.encrypted,
                recipientParameters
            )
                .toMessageInvoiceRequest()

        if (protocolMessageMetadata.encrypted) {
            val isSenderEncryptionSignatureValid =
                protocolMessageBinary.validateMessageEncryptionSignature()

            check(isSenderEncryptionSignatureValid) {
                throw InvalidSignatureException(SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE)
            }
        }

        val messageInvoiceRequestUnsigned =
            messageInvoiceRequest.removeMessageSenderSignature() as Messages.InvoiceRequest

        val isSenderSignatureValid =
            messageInvoiceRequestUnsigned.validateMessageSignature(messageInvoiceRequest.senderSignature.toStringLocal())

        check(isSenderSignatureValid) {
            throw InvalidSignatureException(SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE)
        }

        val senderEvCert = messageInvoiceRequest.senderEvCert.toStringLocal()
        if (!senderEvCert.isBlank()) {
            val isEvCert = Certificate.isEvCertificate(senderEvCert)
            check(isEvCert) {
                throw InvalidCertificateException(CERTIFICATE_VALIDATION_EV_NOT_VALID)
            }
        }

        messageInvoiceRequestUnsigned.originatorsList.forEach { originatorMessage ->
            originatorMessage.attestationsList.forEach { attestationMessage ->
                val isCertificateOwnerChainValid = Certificate.validateCertificate(
                    attestationMessage.getAttestationPkiType(),
                    attestationMessage.pkiData.toStringLocal()
                )

                check(isCertificateOwnerChainValid) {
                    throw InvalidCertificateChainException(
                        CERTIFICATE_VALIDATION_INVALID_ORIGINATOR_CERTIFICATE_CA.format(
                            attestationMessage.attestation
                        )
                    )
                }

                val isSignatureValid =
                    attestationMessage.validateMessageSignature(originatorMessage.primaryForTransaction)

                check(isSignatureValid) {
                    throw InvalidSignatureException(
                        SIGNATURE_VALIDATION_INVALID_ORIGINATOR_SIGNATURE.format(
                            attestationMessage.attestation
                        )
                    )
                }
            }
        }

        messageInvoiceRequestUnsigned.beneficiariesList.forEach { beneficiaryMessage ->
            beneficiaryMessage.attestationsList.forEach { attestationMessage ->
                val isCertificateOwnerChainValid = Certificate.validateCertificate(
                    attestationMessage.getAttestationPkiType(),
                    attestationMessage.pkiData.toStringLocal()
                )

                check(isCertificateOwnerChainValid) {
                    throw InvalidCertificateChainException(
                        CERTIFICATE_VALIDATION_INVALID_BENEFICIARY_CERTIFICATE_CA.format(
                            attestationMessage.attestation
                        )
                    )
                }
            }
        }

        return true
    }
}
