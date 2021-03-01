package com.netki.bip75.extensions

import com.google.protobuf.GeneratedMessageV3
import com.netki.bip75.protocol.Messages
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
            // TODO remove comment is Messages.PaymentRequest -> this.signWithSender(senderParameters)
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
