package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.extensions.toByteString
import com.netki.model.SenderParameters

/**
 * Sign a Messages.InvoiceRequest.
 *
 * @return Messages.InvoiceRequest signed.
 */
internal fun Messages.InvoiceRequest.signWithSender(senderParameters: SenderParameters): Messages.InvoiceRequest {
    val signature = this.sign(senderParameters.pkiDataParameters?.privateKeyPem!!)

    return Messages.InvoiceRequest.newBuilder()
        .mergeFrom(this)
        .setSenderSignature(signature.toByteString())
        .build()
}
