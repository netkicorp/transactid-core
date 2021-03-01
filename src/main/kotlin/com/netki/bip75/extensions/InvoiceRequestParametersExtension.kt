package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.extensions.toByteString
import com.netki.model.*

/**
 * Transform InvoiceRequestParameters to Messages.InvoiceRequest.Builder.
 *
 * @param senderParameters the sender of the message.
 * @return Messages.InvoiceRequest.Builder.
 */
internal fun InvoiceRequestParameters.toMessageInvoiceRequestBuilderUnsigned(
    senderParameters: SenderParameters,
    attestationsRequested: List<Attestation>,
    recipientParameters: RecipientParameters?
): Messages.InvoiceRequest.Builder {
    val invoiceRequestBuilder = Messages.InvoiceRequest.newBuilder()
        .setAmount(this.amount ?: 0)
        .setMemo(this.memo)
        .setNotificationUrl(this.notificationUrl)
        .setSenderPkiType(senderParameters.pkiDataParameters?.type?.value ?: PkiType.NONE.value)
        .setSenderPkiData(senderParameters.pkiDataParameters?.certificatePem?.toByteString() ?: "".toByteString())
        .setSenderSignature("".toByteString())
        .setSenderEvCert(senderParameters.evCertificatePem?.toByteString() ?: "".toByteString())

    this.originatorsAddresses.forEach { output ->
        invoiceRequestBuilder.addOriginatorsAddresses(output.toMessageOutput())
    }

    attestationsRequested.forEach {
        invoiceRequestBuilder.addAttestationsRequested(it.toAttestationType())
    }

    recipientParameters?.let {
        invoiceRequestBuilder.recipientChainAddress = recipientParameters.chainAddress ?: ""
        invoiceRequestBuilder.recipientVaspName = recipientParameters.vaspName
    }

    return invoiceRequestBuilder
}
