package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.exceptions.ExceptionInformation.PARSE_BINARY_MESSAGE_INVALID_INPUT
import com.netki.exceptions.InvalidObjectException
import com.netki.extensions.toByteString
import com.netki.extensions.toStringLocal
import com.netki.model.*

/**
 * Transform PaymentParameters object to Messages.Payment.Builder object.
 *
 * @return Messages.Payment.Builder.
 */
internal fun PaymentParameters.toMessagePaymentBuilder(): Messages.Payment.Builder {
    val messagePaymentBuilder = Messages.Payment.newBuilder()
        .setMerchantData(this.merchantData?.toByteString() ?: "".toByteString())
        .setMemo(this.memo)

    this.transactions.forEach { transaction ->
        messagePaymentBuilder.addTransactions(transaction.toByteString())
    }

    this.outputs.forEach { output ->
        messagePaymentBuilder.addRefundTo(output.toMessageOutput())
    }

    return messagePaymentBuilder
}

/**
 * Transform binary Payment to Messages.Payment.
 *
 * @return Messages.Payment
 * @throws InvalidObjectException if there is an error parsing the object.
 */
internal fun ByteArray.toMessagePayment(): Messages.Payment = try {
    Messages.Payment.parseFrom(this)
} catch (exception: Exception) {
    exception.printStackTrace()
    throw InvalidObjectException(
        PARSE_BINARY_MESSAGE_INVALID_INPUT.format("payment", exception.message)
    )
}

/**
 * Transform Messages.Payment to Payment object.
 *
 * @return Payment.
 */
internal fun Messages.Payment.toPayment(protocolMessageMetadata: ProtocolMessageMetadata? = null): Payment {
    val transactionList = mutableListOf<ByteArray>()
    for (messageTransaction in this.transactionsList) {
        transactionList.add(messageTransaction.toByteArray())
    }

    val outputs = mutableListOf<Output>()
    for (messageOutput in this.refundToList) {
        outputs.add(messageOutput.toOutput())
    }

    val beneficiaries = mutableListOf<Beneficiary>()
    for (messageBeneficiary in this.beneficiariesList) {
        beneficiaries.add(messageBeneficiary.toBeneficiary())
    }

    val originators = mutableListOf<Originator>()
    for (messageOriginator in this.originatorsList) {
        originators.add(messageOriginator.toOriginator())
    }

    return Payment(
        merchantData = this.merchantData.toStringLocal(),
        transactions = transactionList,
        outputs = outputs,
        memo = this.memo,
        beneficiaries = beneficiaries,
        originators = originators,
        protocolMessageMetadata = protocolMessageMetadata
    )
}

/**
 * Transform Payment object to Messages.Payment object.
 *
 * @return Messages.Payment.
 */
internal fun Payment.toMessagePayment(): Messages.Payment {
    val messagePaymentBuilder = Messages.Payment.newBuilder()
        .setMerchantData(this.merchantData?.toByteString())
        .setMemo(this.memo)

    this.transactions.forEach { transaction ->
        messagePaymentBuilder.addTransactions(transaction.toByteString())
    }

    this.outputs.forEach { output ->
        messagePaymentBuilder.addRefundTo(output.toMessageOutput())
    }

    this.beneficiaries.forEach { beneficiary ->
        messagePaymentBuilder.addBeneficiaries(beneficiary.toMessageBeneficiary())
    }

    this.originators.forEach { originator ->
        messagePaymentBuilder.addOriginators(originator.toMessageOriginator())
    }

    return messagePaymentBuilder.build()
}

/**
 * Transform Payment object to Messages.PaymentACK object.
 *
 * @return Messages.PaymentACK.
 */
internal fun Payment.toMessagePaymentAck(memo: String?): Messages.PaymentACK =
    Messages.PaymentACK.newBuilder()
        .setPayment(this.toMessagePayment())
        .setMemo(memo)
        .build()

/**
 * Transform binary PaymentACK to Messages.PaymentACK.
 *
 * @return Messages.PaymentACK
 * @throws InvalidObjectException if there is an error parsing the object.
 */
internal fun ByteArray.toMessagePaymentAck(): Messages.PaymentACK = try {
    Messages.PaymentACK.parseFrom(this)
} catch (exception: Exception) {
    exception.printStackTrace()
    throw InvalidObjectException(
        PARSE_BINARY_MESSAGE_INVALID_INPUT.format("paymentAck", exception.message)
    )
}

/**
 * Transform Messages.PaymentACK to PaymentAck object.
 *
 * @return PaymentAck.
 */
internal fun Messages.PaymentACK.toPaymentAck(protocolMessageMetadata: ProtocolMessageMetadata): PaymentAck =
    PaymentAck(this.payment.toPayment(), this.memo, protocolMessageMetadata)

