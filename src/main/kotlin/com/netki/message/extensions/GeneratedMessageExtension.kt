package com.netki.message.extensions

import com.google.protobuf.GeneratedMessageV3
import com.netki.message.protocol.Messages
import com.netki.model.PkiType
import com.netki.model.SenderParameters
import com.netki.security.Signature
import com.netki.security.Util

/**
 * Sign the Hash256 value of a Messages object.
 *
 * @return Signature.
 */
internal fun GeneratedMessageV3.sign(privateKeyPem: String): String {
    val hash = Util.getHash256(this.toByteArray())
    return Signature.signString(hash, privateKeyPem)
}

/**
 * Sign a GeneratedMessageV3 with the sender information.
 *
 * @return GeneratedMessageV3 signed.
 */
@Throws(IllegalArgumentException::class)
internal fun GeneratedMessageV3.signMessage(senderParameters: SenderParameters): GeneratedMessageV3 {
    return when (this.getMessagePkiType()) {
        PkiType.NONE -> this
        PkiType.X509SHA256 -> when (this) {
            is Messages.InvoiceRequest -> this.signWithSender(senderParameters)
            is Messages.PaymentRequest -> this.signWithSender(senderParameters)
            else -> throw IllegalArgumentException("Message: ${this.javaClass}, not supported to sign message")
        }
    }
}

/**
 * Get sender's pkiData of a GeneratedMessageV3.
 *
 * @return PkiData.
 */
@Throws(IllegalArgumentException::class)
internal fun GeneratedMessageV3.getMessagePkiType(): PkiType = when (this) {
    is Messages.InvoiceRequest -> this.senderPkiType.getType()
    is Messages.PaymentRequest -> this.senderPkiType.getType()
    is Messages.Attestation -> this.pkiType.getType()
    else -> throw IllegalArgumentException("Message: ${this.javaClass}, not supported to get Sender PkiType")
}

/**
 * Transform an string to its correspondent PkiType.
 *
 * @return PkiType.
 */
internal fun String.getType(): PkiType = requireNotNull(PkiType.values().find {
    it.value == this
}) {
    "No PkiType found for: ${this.javaClass}"
}

/**
 * Remove sender signature of a GeneratedMessageV3.
 *
 * @return Unsigned message.
 */
internal fun GeneratedMessageV3.removeMessageSenderSignature(): GeneratedMessageV3 {
    return when (this.getMessagePkiType()) {
        PkiType.NONE -> this
        PkiType.X509SHA256 -> when (this) {
            is Messages.InvoiceRequest -> this.removeSenderSignature()
            is Messages.PaymentRequest -> this.removeSenderSignature()
            else -> throw IllegalArgumentException("Message: ${this.javaClass}, not supported to remove sender signature")
        }
    }
}

/**
 * Validate if sender signature of a GeneratedMessageV3 is valid.
 *
 * @return true if yes, false otherwise.
 */
internal fun GeneratedMessageV3.validateMessageSignature(signature: String): Boolean {
    return when (this.getMessagePkiType()) {
        PkiType.NONE -> true
        PkiType.X509SHA256 -> when (this) {
            is Messages.InvoiceRequest -> this.validateSignature(signature)
            is Messages.PaymentRequest -> this.validateSignature(signature)
            else -> throw IllegalArgumentException("Message: ${this.javaClass}, not supported to validate sender signature")
        }
    }
}
