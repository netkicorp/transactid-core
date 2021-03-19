package com.netki.message.extensions

import com.google.protobuf.ByteString
import com.netki.message.protocol.Messages
import com.netki.exceptions.ExceptionInformation.PARSE_BINARY_MESSAGE_INVALID_INPUT
import com.netki.exceptions.InvalidObjectException
import com.netki.extensions.toByteString
import com.netki.extensions.toStringLocal
import com.netki.model.*
import com.netki.security.Signature
import com.netki.security.Util
import java.sql.Timestamp

/**
 * Sign a Messages.PaymentRequest.
 *
 * @return Messages.PaymentRequest signed.
 */
internal fun Messages.PaymentRequest.signWithSender(senderParameters: SenderParameters): Messages.PaymentRequest {
    val signature = this.sign(senderParameters.pkiDataParameters?.privateKeyPem!!)

    return Messages.PaymentRequest.newBuilder()
        .mergeFrom(this)
        .setSenderSignature(signature.toByteString())
        .build()
}

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

/**
 * Transform PaymentParameters object to Messages.PaymentDetails object.
 *
 * @return Messages.PaymentDetails.
 */
internal fun PaymentRequestParameters.toMessagePaymentDetails(): Messages.PaymentDetails {
    val messagePaymentDetailsBuilder = Messages.PaymentDetails.newBuilder()
        .setNetwork(this.network)
        .setTime(this.time.time)
        .setExpires(this.expires?.time ?: 0)
        .setMemo(this.memo)
        .setPaymentUrl(this.paymentUrl)
        .setMerchantData(this.merchantData?.toByteString() ?: "".toByteString())

    this.beneficiariesAddresses.forEach { output ->
        messagePaymentDetailsBuilder.addBeneficiariesAddresses(output.toMessageOutput())
    }

    return messagePaymentDetailsBuilder.build()
}

/**
 * Transform Messages.PaymentDetails to Messages.PaymentRequest.Builder.
 *
 * @param senderParameters the sender of the message.
 * @param paymentParametersVersion
 * @return Messages.PaymentRequest.Builder.
 */
internal fun Messages.PaymentDetails.toPaymentRequest(
    senderParameters: SenderParameters,
    paymentParametersVersion: Int,
    attestationsRequested: List<Attestation>
): Messages.PaymentRequest.Builder {
    val paymentRequestBuilder = Messages.PaymentRequest.newBuilder()
        .setPaymentDetailsVersion(paymentParametersVersion)
        .setSerializedPaymentDetails(this.toByteString())
        .setSenderPkiType(senderParameters.pkiDataParameters?.type?.value ?: PkiType.NONE.value)
        .setSenderPkiData(senderParameters.pkiDataParameters?.certificatePem?.toByteString() ?: "".toByteString())
        .setSenderSignature("".toByteString())

    attestationsRequested.forEach {
        paymentRequestBuilder.addAttestationsRequested(it.toAttestationType())
    }

    return paymentRequestBuilder
}

/**
 * Transform binary PaymentRequest to Messages.PaymentRequest.
 *
 * @return Messages.PaymentRequest
 * @throws InvalidObjectException if there is an error parsing the object.
 */
internal fun ByteArray.toMessagePaymentRequest(): Messages.PaymentRequest = try {
    Messages.PaymentRequest.parseFrom(this)
} catch (exception: Exception) {
    exception.printStackTrace()
    throw InvalidObjectException(PARSE_BINARY_MESSAGE_INVALID_INPUT.format("paymentRequest", exception.message))
}

/**
 * Transform Messages.PaymentRequest to PaymentRequest object.
 *
 * @return PaymentRequest.
 */
internal fun Messages.PaymentRequest.toPaymentRequest(protocolMessageMetadata: ProtocolMessageMetadata): PaymentRequest {
    val paymentDetails = this.serializedPaymentDetails.toMessagePaymentDetails()

    val beneficiaries = mutableListOf<Beneficiary>()
    this.beneficiariesList.forEach { messageBeneficiary ->
        beneficiaries.add(messageBeneficiary.toBeneficiary())
    }

    val beneficiariesAddresses = mutableListOf<Output>()
    paymentDetails.beneficiariesAddressesList.forEach { messageOutput ->
        beneficiariesAddresses.add(messageOutput.toOutput())
    }

    val attestationsRequested = mutableListOf<Attestation>()
    this.attestationsRequestedList.forEach { attestationType ->
        attestationsRequested.add(attestationType.toAttestation())
    }

    return PaymentRequest(
        paymentDetailsVersion = this.paymentDetailsVersion,
        network = paymentDetails.network,
        beneficiariesAddresses = beneficiariesAddresses,
        time = Timestamp(paymentDetails.time),
        expires = Timestamp(paymentDetails.expires),
        memo = paymentDetails.memo,
        paymentUrl = paymentDetails.paymentUrl,
        merchantData = paymentDetails.merchantData.toStringLocal(),
        beneficiaries = beneficiaries,
        attestationsRequested = attestationsRequested,
        senderPkiType = this.senderPkiType.getType(),
        senderPkiData = this.senderPkiData.toStringLocal(),
        senderSignature = this.senderSignature.toStringLocal(),
        protocolMessageMetadata = protocolMessageMetadata
    )
}

/**
 * Transform binary PaymentDetails to Messages.PaymentDetails.
 *
 * @return Messages.PaymentDetails
 * @throws InvalidObjectException if there is an error parsing the object.
 */
internal fun ByteString.toMessagePaymentDetails(): Messages.PaymentDetails = try {
    Messages.PaymentDetails.parseFrom(this)
} catch (exception: Exception) {
    exception.printStackTrace()
    throw InvalidObjectException(PARSE_BINARY_MESSAGE_INVALID_INPUT.format("paymentDetails", exception.message))
}
