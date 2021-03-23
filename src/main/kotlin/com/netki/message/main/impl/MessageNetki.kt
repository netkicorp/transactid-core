package com.netki.message.main.impl

import com.netki.message.main.Message
import com.netki.message.service.MessageService
import com.netki.model.*

/**
 * {@inheritDoc}
 */
internal class MessageNetki(private val messageService: MessageService) : Message {

    /**
     * {@inheritDoc}
     */
    override fun createInvoiceRequest(invoiceRequestParameters: InvoiceRequestParameters) =
        messageService.createInvoiceRequest(invoiceRequestParameters)

    /**
     * {@inheritDoc}
     */
    override fun isInvoiceRequestValid(invoiceRequestBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.isInvoiceRequestValid(invoiceRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun parseInvoiceRequest(invoiceRequestBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.parseInvoiceRequest(invoiceRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun parseInvoiceRequestWithAddressesInfo(
        invoiceRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ) = messageService.parseInvoiceRequestWithAddressesInfo(invoiceRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun createPaymentRequest(paymentRequestParameters: PaymentRequestParameters, identifier: String) =
        messageService.createPaymentRequest(paymentRequestParameters, identifier)

    /**
     * {@inheritDoc}
     */
    override fun parsePaymentRequest(paymentRequestBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.parsePaymentRequest(paymentRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun parsePaymentRequestWithAddressesInfo(
        paymentRequestBinary: ByteArray,
        recipientParameters: RecipientParameters?
    ) =
        messageService.parsePaymentRequestWithAddressesInfo(paymentRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun isPaymentRequestValid(paymentRequestBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.isPaymentRequestValid(paymentRequestBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun createPayment(paymentParameters: PaymentParameters, identifier: String) =
        messageService.createPayment(paymentParameters, identifier)

    /**
     * {@inheritDoc}
     */
    override fun parsePayment(paymentBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.parsePayment(paymentBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun isPaymentValid(paymentBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.isPaymentValid(paymentBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun createPaymentAck(paymentAckParameters: PaymentAckParameters, identifier: String) =
        messageService.createPaymentAck(paymentAckParameters, identifier)

    /**
     * {@inheritDoc}
     */
    override fun parsePaymentAck(paymentAckBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.parsePaymentAck(paymentAckBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun isPaymentAckValid(paymentAckBinary: ByteArray, recipientParameters: RecipientParameters?) =
        messageService.isPaymentAckValid(paymentAckBinary, recipientParameters)

    /**
     * {@inheritDoc}
     */
    override fun changeStatusProtocolMessage(
        protocolMessage: ByteArray,
        statusCode: StatusCode,
        statusMessage: String
    ) = messageService.changeStatusProtocolMessage(protocolMessage, statusCode, statusMessage)

    /**
     * {@inheritDoc}
     */
    override fun getProtocolMessageMetadata(protocolMessage: ByteArray): ProtocolMessageMetadata =
        messageService.getProtocolMessageMetadata(protocolMessage)
}
