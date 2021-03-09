package com.netki.bip75.messages.impl

import com.netki.bip75.extensions.*
import com.netki.bip75.messages.ProtocolMessageDefinition
import com.netki.exceptions.ExceptionInformation.SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE
import com.netki.exceptions.InvalidSignatureException
import com.netki.model.*
import com.netki.model.PaymentAck

class PaymentAck : ProtocolMessageDefinition {

    /**
     * {@inheritDoc}
     */
    override fun create(
        protocolMessageParameters: ProtocolMessageParameters,
        identifier: String?
    ): ByteArray {
        val paymentAckParameters = protocolMessageParameters as PaymentAckParameters
        val paymentAck = paymentAckParameters.payment.toMessagePaymentAck(paymentAckParameters.memo)
            .toByteArray()

        return paymentAck.toProtocolMessage(
            MessageType.PAYMENT_ACK,
            paymentAckParameters.messageInformation,
            paymentAckParameters.senderParameters,
            paymentAckParameters.recipientParameters,
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
        protocolMessageBinary.getSerializedMessage(
            protocolMessageMetadata.encrypted,
            recipientParameters
        ).toMessagePaymentAck()

        if (protocolMessageMetadata.encrypted) {
            val isSenderEncryptionSignatureValid =
                protocolMessageBinary.validateMessageEncryptionSignature()

            check(isSenderEncryptionSignatureValid) {
                throw InvalidSignatureException(SIGNATURE_VALIDATION_INVALID_SENDER_SIGNATURE)
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
    ): PaymentAck {
        val protocolMessageMetadata = protocolMessageBinary.extractProtocolMessageMetadata()
        val messagePaymentAck =
            protocolMessageBinary.getSerializedMessage(
                protocolMessageMetadata.encrypted,
                recipientParameters
            )
                .toMessagePaymentAck()

        return messagePaymentAck.toPaymentAck(protocolMessageBinary.extractProtocolMessageMetadata())
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
