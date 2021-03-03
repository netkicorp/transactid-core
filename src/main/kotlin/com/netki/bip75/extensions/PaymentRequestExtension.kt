package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.extensions.toByteString
import com.netki.extensions.toStringLocal
import com.netki.security.Signature
import com.netki.security.Util

/**
 * Remove sender signature of a Messages.PaymentRequest.
 *
 * @return Unsigned message.
 */
internal fun Messages.PaymentRequest.removeSenderSignature(): Messages.PaymentRequest =
    Messages.PaymentRequest.newBuilder()
        .mergeFrom(this)
        .setSenderSignature("".toByteString())
        .build()

/**
 * Validate that a signature corresponds to a Messages.PaymentRequest.
 *
 * @return  true if yes, false otherwise.
 */
internal fun Messages.PaymentRequest.validateSignature(signature: String): Boolean {
    val bytesHash = Util.getHash256(this.toByteArray())
    return Signature.validateSignature(signature, bytesHash, this.senderPkiData.toStringLocal())
}
