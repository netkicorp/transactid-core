package com.netki.message.service.impl

import com.netki.message.extensions.changeStatus
import com.netki.message.extensions.extractProtocolMessageMetadata
import com.netki.message.processor.impl.InvoiceRequestProcessor
import com.netki.message.processor.impl.PaymentAckProcessor
import com.netki.message.processor.impl.PaymentProcessor
import com.netki.message.processor.impl.PaymentRequestProcessor
import com.netki.message.service.MessageService
import com.netki.model.*

/**
 * {@inheritDoc}
 */
internal class MessageServiceNetki(
    private val invoiceRequestProcessor: InvoiceRequestProcessor,
    private val paymentRequestProcessor: PaymentRequestProcessor,
    private val paymentProcessor: PaymentProcessor,
    private val paymentAckProcessor: PaymentAckProcessor
) : MessageService {

    /**
     * {@inheritDoc}
     */
    override fun createInvoiceRequest(invoiceRequestParameters: InvoiceRequestParameters) =
        invoiceRequestProcessor.create(invoiceRequestParameters)

    /**
     * {@inheritDoc}
     */
    override fun parseInvoiceRequest(invoiceRequestBinary: ByteArray, recipientParameters: RecipientParameters?) =
        invoiceRequestProcessor.parse(invoiceRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun parseInvoiceRequestWithAddressesInfo(
        invoiceRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ) = invoiceRequestProcessor.parseWithAddressesInfo(invoiceRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun isInvoiceRequestValid(
        invoiceRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ) = invoiceRequestProcessor.isValid(invoiceRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun createPaymentRequest(paymentRequestParameters: PaymentRequestParameters, identifier: String) =
        paymentRequestProcessor.create(paymentRequestParameters, identifier)

    /**
     * {@inheritDoc}
     */
    override fun parsePaymentRequest(paymentRequestBinary: ByteArray, recipientParameters: RecipientParameters?) =
        paymentRequestProcessor.parse(paymentRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun parsePaymentRequestWithAddressesInfo(
        paymentRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ) = paymentRequestProcessor.parseWithAddressesInfo(paymentRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun isPaymentRequestValid(
        paymentRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ) = paymentRequestProcessor.isValid(paymentRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun createPayment(paymentParameters: PaymentParameters, identifier: String) =
        paymentProcessor.create(paymentParameters, identifier)

    /**
     * {@inheritDoc}
     */
    override fun parsePayment(paymentBinary: ByteArray, recipientParameters: RecipientParameters?) =
        paymentProcessor.parse(paymentBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun isPaymentValid(paymentBinary: ByteArray, recipientParameters: RecipientParameters?) =
        paymentProcessor.isValid(paymentBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun createPaymentAck(paymentAckParameters: PaymentAckParameters, identifier: String) =
        paymentAckProcessor.create(paymentAckParameters, identifier)

    /**
     * {@inheritDoc}
     */
    override fun parsePaymentAck(paymentAckBinary: ByteArray, recipientParameters: RecipientParameters?) =
        paymentAckProcessor.parse(paymentAckBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun isPaymentAckValid(paymentAckBinary: ByteArray, recipientParameters: RecipientParameters?) =
        paymentAckProcessor.isValid(paymentAckBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun changeStatusProtocolMessage(
        protocolMessage: ByteArray,
        statusCode: StatusCode,
        statusMessage: String
    ) = protocolMessage.changeStatus(statusCode, statusMessage)

    /**
     * {@inheritDoc}
     */
    override fun getProtocolMessageMetadata(protocolMessage: ByteArray) =
        protocolMessage.extractProtocolMessageMetadata()
}
