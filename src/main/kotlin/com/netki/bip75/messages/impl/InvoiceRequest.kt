package com.netki.bip75.messages.impl

import com.netki.bip75.extensions.*
import com.netki.bip75.messages.ProtocolMessageDefinition
import com.netki.bip75.protocol.Messages
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_VALIDATION_EV_NOT_VALID
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_VALIDATION_NOT_CORRECT_CERTIFICATE_ERROR
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_ORIGINATOR_SIGNATURE
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE
import com.netki.exceptions.InvalidCertificateChainException
import com.netki.exceptions.InvalidCertificateException
import com.netki.exceptions.InvalidSignatureException
import com.netki.extensions.toStringLocal
import com.netki.model.*
import com.netki.model.InvoiceRequest
import com.netki.security.Certificate

class InvoiceRequest : ProtocolMessageDefinition {

    /**
     * {@inheritDoc}
     */
    override fun create(
        protocolMessageParameters: ProtocolMessageParameters,
        identifier: String?
    ): ByteArray {
        val invoiceRequestParameters = protocolMessageParameters as InvoiceRequestParameters
        invoiceRequestParameters.originatorParameters.validate(true, OwnerType.ORIGINATOR)
        invoiceRequestParameters.beneficiaryParameters?.validate(false, OwnerType.BENEFICIARY)

        val messageInvoiceRequestBuilder = invoiceRequestParameters.toMessageInvoiceRequestBuilderUnsigned(
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

        val invoiceRequest = messageInvoiceRequest.signMessage(invoiceRequestParameters.senderParameters).toByteArray()
        return invoiceRequest.toProtocolMessage(
            MessageType.INVOICE_REQUEST,
            invoiceRequestParameters.messageInformation,
            invoiceRequestParameters.senderParameters,
            invoiceRequestParameters.recipientParameters
        )
    }

    /**
     * {@inheritDoc}
     */
    override fun isValid(
        protocolMessageBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ): Boolean {
        val protocolMessageMetadata = protocolMessageBinary.extractProtocolMessageMetadata()
        val messageInvoiceRequest = protocolMessageBinary.getSerializedMessage(
            protocolMessageMetadata.encrypted,
            recipientParameters
        ).toMessageInvoiceRequest()

        if (protocolMessageMetadata.encrypted) {
            val isSenderEncryptionSignatureValid = protocolMessageBinary.validateMessageEncryptionSignature()

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
                Certificate.validateCertificate(
                    attestationMessage.getAttestationPkiType(),
                    attestationMessage.pkiData.toStringLocal()
                )

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
                val isCertificateValid = Certificate.validateCertificate(
                    attestationMessage.getAttestationPkiType(),
                    attestationMessage.pkiData.toStringLocal()
                )

                check(isCertificateValid) {
                    throw InvalidCertificateChainException(
                        CERTIFICATE_VALIDATION_NOT_CORRECT_CERTIFICATE_ERROR.format(
                            attestationMessage.attestation
                        )
                    )
                }
            }
        }

        return true
    }

    /**
     * {@inheritDoc}
     */
    override fun parse(
        protocolMessageBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ) = parseInvoiceRequestBinary(protocolMessageBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun parseWithAddressesInfo(
        protocolMessageBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ): ProtocolMessage {
        TODO("Not yet implemented")
    }

    private fun parseInvoiceRequestBinary(
        invoiceRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ): InvoiceRequest {
        val protocolMessageMetadata = invoiceRequestBinary.extractProtocolMessageMetadata()
        val messageInvoiceRequest = invoiceRequestBinary.getSerializedMessage(
            protocolMessageMetadata.encrypted,
            recipientParameters
        ).toMessageInvoiceRequest()
        return messageInvoiceRequest.toInvoiceRequest(protocolMessageMetadata)
    }
}
