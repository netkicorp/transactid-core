package com.netki.message.service.impl

import com.netki.address.info.service.AddressInformationService
import com.netki.message.processor.impl.InvoiceRequestProcessor
import com.netki.message.processor.impl.PaymentAckProcessor
import com.netki.message.processor.impl.PaymentProcessor
import com.netki.message.processor.impl.PaymentRequestProcessor
import com.netki.message.service.MessageService
import com.netki.model.InvoiceRequestParameters
import com.netki.model.MessageType
import com.netki.model.PaymentRequestParameters
import com.netki.model.StatusCode
import com.netki.security.Certificate
import com.netki.util.TestData
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.mockito.Mockito
import java.sql.Timestamp

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class MessageServiceNetkiTest {

    private lateinit var mockAddressInformationService: AddressInformationService
    private lateinit var invoiceRequestProcessor: InvoiceRequestProcessor
    private lateinit var paymentRequestProcessor: PaymentRequestProcessor
    private lateinit var paymentProcessor: PaymentProcessor
    private lateinit var paymentAckProcessor: PaymentAckProcessor
    private lateinit var messageService: MessageService

    @BeforeAll
    fun setUp() {
        mockAddressInformationService = Mockito.mock(AddressInformationService::class.java)
        invoiceRequestProcessor = InvoiceRequestProcessor(mockAddressInformationService, Certificate)
        paymentRequestProcessor = PaymentRequestProcessor(mockAddressInformationService, Certificate)
        paymentProcessor = PaymentProcessor(mockAddressInformationService, Certificate)
        paymentAckProcessor = PaymentAckProcessor(mockAddressInformationService, Certificate)
        messageService = MessageServiceNetki(
            invoiceRequestProcessor,
            paymentRequestProcessor,
            paymentProcessor,
            paymentAckProcessor
        )
    }

    @Test
    fun `Change status from OK to CANCEL to InvoiceRequest`() {
        val originators = listOf(
            TestData.Originators.PRIMARY_ORIGINATOR_PKI_X509SHA256,
            TestData.Originators.NO_PRIMARY_ORIGINATOR_PKI_X509SHA256
        )
        val beneficiaries = listOf(
            TestData.Beneficiaries.PRIMARY_BENEFICIARY_PKI_X509SHA256
        )
        val sender = TestData.Senders.SENDER_PKI_X509SHA256
        val invoiceRequestParameters = InvoiceRequestParameters(
            amount = 1000,
            memo = "memo",
            notificationUrl = "notificationUrl",
            originatorsAddresses = TestData.Payment.Output.OUTPUTS,
            originatorParameters = originators,
            beneficiaryParameters = beneficiaries,
            senderParameters = sender,
            attestationsRequested = TestData.Attestations.REQUESTED_ATTESTATIONS
        )

        val invoiceRequestBinary = messageService.createInvoiceRequest(invoiceRequestParameters)
        val invoiceRequest = messageService.parseInvoiceRequest(invoiceRequestBinary)
        val identifier = invoiceRequest.protocolMessageMetadata.identifier

        assert(invoiceRequest.protocolMessageMetadata.statusCode == StatusCode.OK)
        assert(invoiceRequest.protocolMessageMetadata.statusMessage.isEmpty())

        val newStatusCode = StatusCode.CANCEL
        val newStatusMessage = "Random cancel"
        val updatedInvoiceRequestBinary =
            messageService.changeStatusProtocolMessage(invoiceRequestBinary, newStatusCode, newStatusMessage)
        val updatedInvoiceRequest = messageService.parseInvoiceRequest(updatedInvoiceRequestBinary)

        assert(updatedInvoiceRequest.protocolMessageMetadata.statusCode == newStatusCode)
        assert(updatedInvoiceRequest.protocolMessageMetadata.statusMessage == newStatusMessage)
        assert(updatedInvoiceRequest.protocolMessageMetadata.identifier == invoiceRequest.protocolMessageMetadata.identifier)
        assert(updatedInvoiceRequest.protocolMessageMetadata.nonce == invoiceRequest.protocolMessageMetadata.nonce)
    }

    @Test
    fun `Change status from OK to CERTIFICATE_EXPIRED to PaymentRequest Encrypted`() {
        val beneficiaries = listOf(
            TestData.Beneficiaries.PRIMARY_BENEFICIARY_PKI_X509SHA256,
            TestData.Beneficiaries.NO_PRIMARY_BENEFICIARY_PKI_X509SHA256
        )
        val sender = TestData.Senders.SENDER_PKI_X509SHA256_WITH_ENCRYPTION
        val paymentRequestParameters = PaymentRequestParameters(
            network = "main",
            beneficiariesAddresses = TestData.Payment.Output.OUTPUTS,
            time = Timestamp(System.currentTimeMillis()),
            expires = Timestamp(System.currentTimeMillis()),
            memo = "memo",
            paymentUrl = "www.payment.url/test",
            merchantData = "merchant data",
            beneficiaryParameters = beneficiaries,
            senderParameters = sender,
            attestationsRequested = TestData.Attestations.REQUESTED_ATTESTATIONS,
            messageInformation = TestData.MessageInformationData.MESSAGE_INFORMATION_ENCRYPTION,
            recipientParameters = TestData.Recipients.RECIPIENTS_PARAMETERS_WITH_ENCRYPTION
        )

        val paymentRequestBinary = messageService.createPaymentRequest(paymentRequestParameters, "1234")
        val paymentRequest = messageService.parsePaymentRequest(
            paymentRequestBinary,
            TestData.Recipients.RECIPIENTS_PARAMETERS_WITH_ENCRYPTION
        )
        val identifier = paymentRequest.protocolMessageMetadata.identifier
        val encryptedMessage = paymentRequest.protocolMessageMetadata.encryptedMessage

        assert(paymentRequest.protocolMessageMetadata.statusCode == StatusCode.OK)
        assert(paymentRequest.protocolMessageMetadata.statusMessage.isEmpty())

        val newStatusCode = StatusCode.CERTIFICATE_EXPIRED
        val newStatusMessage = "Random cancel"
        val updatedPaymentRequestBinary =
            messageService.changeStatusProtocolMessage(paymentRequestBinary, newStatusCode, newStatusMessage)
        val updatedPaymentRequest =
            messageService.parsePaymentRequest(
                updatedPaymentRequestBinary,
                TestData.Recipients.RECIPIENTS_PARAMETERS_WITH_ENCRYPTION
            )

        assert(updatedPaymentRequest.protocolMessageMetadata.statusCode == newStatusCode)
        assert(updatedPaymentRequest.protocolMessageMetadata.statusMessage == newStatusMessage)
        assert(updatedPaymentRequest.protocolMessageMetadata.identifier == identifier)
        assert(updatedPaymentRequest.protocolMessageMetadata.encryptedMessage == encryptedMessage)
        assert(updatedPaymentRequest.protocolMessageMetadata.identifier == updatedPaymentRequest.protocolMessageMetadata.identifier)
        assert(updatedPaymentRequest.protocolMessageMetadata.nonce == updatedPaymentRequest.protocolMessageMetadata.nonce)
    }

    @Test
    fun `Create InvoiceRequestBinary and extract protocolMessageMetadata`() {
        val originators = listOf(
            TestData.Originators.PRIMARY_ORIGINATOR_PKI_X509SHA256,
            TestData.Originators.NO_PRIMARY_ORIGINATOR_PKI_X509SHA256
        )
        val sender = TestData.Senders.SENDER_PKI_X509SHA256

        val invoiceRequestParameters = InvoiceRequestParameters(
            amount = 1000,
            memo = "memo",
            notificationUrl = "notificationUrl",
            originatorsAddresses = TestData.Payment.Output.OUTPUTS,
            originatorParameters = originators,
            beneficiaryParameters = emptyList(),
            senderParameters = sender,
            attestationsRequested = TestData.Attestations.REQUESTED_ATTESTATIONS
        )

        val protocolMessageBinary = messageService.createInvoiceRequest(invoiceRequestParameters)
        val protocolMessageMetadata = messageService.getProtocolMessageMetadata(protocolMessageBinary)

        assert(protocolMessageMetadata.statusCode == StatusCode.OK)
        assert(protocolMessageMetadata.statusMessage.isEmpty())
        assert(protocolMessageMetadata.messageType == MessageType.INVOICE_REQUEST)
    }

    @Test
    fun `Create PaymentRequestBinary and extract protocolMessageMetadata`() {
        val beneficiaries = listOf(
            TestData.Beneficiaries.PRIMARY_BENEFICIARY_PKI_X509SHA256,
            TestData.Beneficiaries.NO_PRIMARY_BENEFICIARY_PKI_X509SHA256
        )
        val sender = TestData.Senders.SENDER_PKI_X509SHA256
        val paymentRequestParameters = PaymentRequestParameters(
            network = "main",
            beneficiariesAddresses = TestData.Payment.Output.OUTPUTS,
            time = Timestamp(System.currentTimeMillis()),
            expires = Timestamp(System.currentTimeMillis()),
            memo = "memo",
            paymentUrl = "www.payment.url/test",
            merchantData = "merchant data",
            beneficiaryParameters = beneficiaries,
            senderParameters = sender,
            attestationsRequested = TestData.Attestations.REQUESTED_ATTESTATIONS
        )

        val protocolMessageBinary = messageService.createPaymentRequest(paymentRequestParameters, "1234")
        val protocolMessageMetadata = messageService.getProtocolMessageMetadata(protocolMessageBinary)

        assert(protocolMessageMetadata.statusCode == StatusCode.OK)
        assert(protocolMessageMetadata.statusMessage.isEmpty())
        assert(protocolMessageMetadata.messageType == MessageType.PAYMENT_REQUEST)
    }
}
