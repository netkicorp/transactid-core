package com.netki.message.extensions

import com.netki.message.protocol.Messages
import com.netki.exceptions.ExceptionInformation.PARSE_BINARY_MESSAGE_INVALID_INPUT
import com.netki.exceptions.InvalidObjectException
import com.netki.extensions.toByteString
import com.netki.extensions.toStringLocal
import com.netki.model.*
import com.netki.security.Signature
import com.netki.security.Util

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

/**
 * Transform binary InvoiceRequest to Messages.InvoiceRequest.
 *
 * @return Messages.InvoiceRequest
 * @throws InvalidObjectException if there is an error parsing the object.
 */
internal fun ByteArray.toMessageInvoiceRequest(): Messages.InvoiceRequest = try {
    Messages.InvoiceRequest.parseFrom(this)
} catch (exception: Exception) {
    exception.printStackTrace()
    throw InvalidObjectException(
        PARSE_BINARY_MESSAGE_INVALID_INPUT.format(
            "invoiceRequest",
            exception.message
        )
    )
}

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
        .setSenderPkiData(
            senderParameters.pkiDataParameters?.certificatePem?.toByteString() ?: "".toByteString()
        )
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

/**
 * Remove sender signature of a Messages.InvoiceRequest
 *
 * @return Unsigned message.
 */
internal fun Messages.InvoiceRequest.removeSenderSignature(): Messages.InvoiceRequest =
    Messages.InvoiceRequest.newBuilder()
        .mergeFrom(this)
        .setSenderSignature("".toByteString())
        .build()

/**
 * Validate that a signature corresponds to a Messages.InvoiceRequest.
 *
 * @return  true if yes, false otherwise.
 */
internal fun Messages.InvoiceRequest.validateSignature(signature: String): Boolean {
    val bytesHash = Util.getHash256(this.toByteArray())
    return Signature.validateSignature(signature, bytesHash, this.senderPkiData.toStringLocal())
}

/**
 * Transform Messages.InvoiceRequest to InvoiceRequest object.
 *
 * @return InvoiceRequest.
 */
internal fun Messages.InvoiceRequest.toInvoiceRequest(protocolMessageMetadata: ProtocolMessageMetadata): InvoiceRequest {
    val beneficiaries = mutableListOf<Beneficiary>()
    this.beneficiariesList.forEach { messageBeneficiary ->
        beneficiaries.add(messageBeneficiary.toBeneficiary())
    }

    val originators = mutableListOf<Originator>()
    this.originatorsList.forEach { messageOriginator ->
        originators.add(messageOriginator.toOriginator())
    }

    val originatorsAddresses = mutableListOf<Output>()
    this.originatorsAddressesList.forEach { messageOutput ->
        originatorsAddresses.add(messageOutput.toOutput())
    }

    val attestationsRequested = mutableListOf<Attestation>()
    this.attestationsRequestedList.forEach { attestationType ->
        attestationsRequested.add(attestationType.toAttestation())
    }

    return InvoiceRequest(
        amount = this.amount,
        memo = this.memo,
        notificationUrl = this.notificationUrl,
        originators = originators,
        beneficiaries = beneficiaries,
        originatorsAddresses = originatorsAddresses,
        attestationsRequested = attestationsRequested,
        senderPkiType = this.senderPkiType.getType(),
        senderPkiData = this.senderPkiData.toStringLocal(),
        senderSignature = this.senderSignature.toStringLocal(),
        senderEvCert = this.senderEvCert.toStringLocal(),
        recipientVaspName = this.recipientVaspName,
        recipientChainAddress = this.recipientChainAddress,
        protocolMessageMetadata = protocolMessageMetadata
    )
}
