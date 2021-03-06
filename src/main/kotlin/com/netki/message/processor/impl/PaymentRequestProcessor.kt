package com.netki.message.processor.impl

import com.netki.address.info.service.AddressInformationService
import com.netki.message.extensions.*
import com.netki.message.processor.ProtocolMessageProcessor
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_VALIDATION_INVALID_BENEFICIARY_CERTIFICATE_CA
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_BENEFICIARY_SIGNATURE
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE
import com.netki.exceptions.InvalidCertificateChainException
import com.netki.exceptions.InvalidSignatureException
import com.netki.extensions.toStringLocal
import com.netki.message.protocol.Messages
import com.netki.model.*
import com.netki.model.PaymentRequest
import com.netki.security.Certificate

internal class PaymentRequestProcessor(
    private val addressInformationService: AddressInformationService,
    private val certificate: Certificate
) : ProtocolMessageProcessor(addressInformationService, certificate) {

    /**
     * {@inheritDoc}
     */
    override fun create(
        protocolMessageParameters: ProtocolMessageParameters,
        identifier: String?
    ): ByteArray {
        val paymentRequestParameters = protocolMessageParameters as PaymentRequestParameters
        paymentRequestParameters.beneficiaryParameters.validate(true, OwnerType.BENEFICIARY)

        val messagePaymentRequestBuilder = paymentRequestParameters.toMessagePaymentDetails().toPaymentRequest(
            paymentRequestParameters.senderParameters,
            paymentRequestParameters.paymentParametersVersion,
            paymentRequestParameters.attestationsRequested
        )

        paymentRequestParameters.beneficiaryParameters.forEach { beneficiary ->
            val beneficiaryMessage = beneficiary.toMessageBeneficiaryBuilderWithoutAttestations()

            beneficiary.pkiDataParametersSets.forEach { pkiData ->
                beneficiaryMessage.addAttestations(pkiData.toMessageAttestation(beneficiary.isPrimaryForTransaction))
            }

            messagePaymentRequestBuilder.addBeneficiaries(beneficiaryMessage)
        }

        val messagePaymentRequest = messagePaymentRequestBuilder.build()

        val paymentRequest = messagePaymentRequest.signMessage(paymentRequestParameters.senderParameters).toByteArray()

        return paymentRequest.toProtocolMessage(
            MessageType.PAYMENT_REQUEST,
            paymentRequestParameters.messageInformation,
            paymentRequestParameters.senderParameters,
            paymentRequestParameters.recipientParameters,
            identifier
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
        val messagePaymentRequest =
            protocolMessageBinary.getSerializedMessage(
                protocolMessageMetadata.encrypted,
                recipientParameters
            )
                .toMessagePaymentRequest()

        if (protocolMessageMetadata.encrypted) {
            val isSenderEncryptionSignatureValid =
                protocolMessageBinary.validateMessageEncryptionSignature()

            check(isSenderEncryptionSignatureValid) {
                throw InvalidSignatureException(SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE)
            }
        }

        val messagePaymentRequestUnsigned =
            messagePaymentRequest.removeMessageSenderSignature() as Messages.PaymentRequest

        certificate.validateCertificate(
            messagePaymentRequest.getMessagePkiType(),
            messagePaymentRequest.senderPkiData.toStringLocal()
        )

        val isSenderSignatureValid =
            messagePaymentRequestUnsigned.validateMessageSignature(messagePaymentRequest.senderSignature.toStringLocal())

        check(isSenderSignatureValid) {
            throw InvalidSignatureException(SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE)
        }
        messagePaymentRequestUnsigned.beneficiariesList.forEach { beneficiaryMessage ->
            beneficiaryMessage.attestationsList.forEach { attestationMessage ->
                val isCertificateOwnerChainValid = certificate.validateCertificate(
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

                val isSignatureValid =
                    attestationMessage.validateMessageSignature(beneficiaryMessage.primaryForTransaction)

                check(isSignatureValid) {
                    throw InvalidSignatureException(
                        SIGNATURE_VALIDATION_INVALID_BENEFICIARY_SIGNATURE.format(
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
    ) = parsePaymentRequestBinary(protocolMessageBinary, recipientParameters)


    /**
     * {@inheritDoc}
     */
    override fun parseWithAddressesInfo(
        protocolMessageBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ): PaymentRequest {
        val paymentRequest = parsePaymentRequestBinary(protocolMessageBinary, recipientParameters)
        paymentRequest.beneficiariesAddresses.forEach { output ->
            output.addressInformation = addressInformationService.getAddressInformation(output.currency, output.script)
        }
        return paymentRequest
    }

    private fun parsePaymentRequestBinary(
        paymentRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ): PaymentRequest {
        val protocolMessageMetadata = paymentRequestBinary.extractProtocolMessageMetadata()
        val messagePaymentRequest = paymentRequestBinary.getSerializedMessage(
            protocolMessageMetadata.encrypted,
            recipientParameters
        ).toMessagePaymentRequest()
        return messagePaymentRequest.toPaymentRequest(protocolMessageMetadata)
    }
}
