package com.netki.bip75.messages.impl

import com.netki.bip75.extensions.*
import com.netki.bip75.messages.ProtocolMessageDefinition
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_ORIGINATOR_SIGNATURE
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE
import com.netki.exceptions.InvalidSignatureException
import com.netki.extensions.toStringLocal
import com.netki.model.*
import com.netki.model.Payment
import com.netki.security.Certificate

class Payment : ProtocolMessageDefinition {

    /**
     * {@inheritDoc}
     */
    override fun create(
        protocolMessageParameters: ProtocolMessageParameters,
        identifier: String?
    ): ByteArray {
        val paymentParameters = protocolMessageParameters as PaymentParameters
        paymentParameters.originatorParameters.validate(true, OwnerType.ORIGINATOR)
        paymentParameters.beneficiaryParameters?.validate(false, OwnerType.BENEFICIARY)

        val paymentBuilder = paymentParameters.toMessagePaymentBuilder()

        paymentParameters.beneficiaryParameters?.forEach { beneficiary ->
            val beneficiaryMessage = beneficiary.toMessageBeneficiaryBuilderWithoutAttestations()

            beneficiary.pkiDataParametersSets.forEach { pkiData ->
                beneficiaryMessage.addAttestations(pkiData.toMessageAttestation(false))
            }

            paymentBuilder.addBeneficiaries(beneficiaryMessage)
        }

        paymentParameters.originatorParameters.forEach { originator ->
            val originatorMessage = originator.toMessageOriginatorBuilderWithoutAttestations()

            originator.pkiDataParametersSets.forEach { pkiData ->
                originatorMessage.addAttestations(pkiData.toMessageAttestation(originator.isPrimaryForTransaction))
            }

            paymentBuilder.addOriginators(originatorMessage)
        }

        val payment = paymentBuilder.build().toByteArray()

        return payment.toProtocolMessage(
            MessageType.PAYMENT,
            paymentParameters.messageInformation,
            paymentParameters.senderParameters,
            paymentParameters.recipientParameters,
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
        val payment = protocolMessageBinary
            .getSerializedMessage(protocolMessageMetadata.encrypted, recipientParameters)
            .toMessagePayment()

        if (protocolMessageMetadata.encrypted) {
            val isSenderEncryptionSignatureValid =
                protocolMessageBinary.validateMessageEncryptionSignature()

            check(isSenderEncryptionSignatureValid) {
                throw InvalidSignatureException(SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE)
            }
        }

        payment.originatorsList.forEach { originatorMessage ->
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

        payment.beneficiariesList.forEach { beneficiaryMessage ->
            beneficiaryMessage.attestationsList.forEach { attestationMessage ->
                Certificate.validateCertificate(
                    attestationMessage.getAttestationPkiType(),
                    attestationMessage.pkiData.toStringLocal()
                )
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
    ): Payment {
        val protocolMessageMetadata = protocolMessageBinary.extractProtocolMessageMetadata()
        val messagePayment =
            protocolMessageBinary.getSerializedMessage(
                protocolMessageMetadata.encrypted,
                recipientParameters
            )
                .toMessagePayment()
        return messagePayment.toPayment(protocolMessageMetadata)
    }

    /**
     * {@inheritDoc}
     */
    override fun parseWithAddressesInfo(
        protocolMessageBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ): ProtocolMessage {
        throw NotImplementedError("Method not supported for this message")
    }
}
