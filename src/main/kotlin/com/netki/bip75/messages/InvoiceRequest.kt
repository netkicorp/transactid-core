package com.netki.bip75.messages

import com.netki.bip75.extensions.*
import com.netki.model.InvoiceRequestParameters
import com.netki.model.MessageType
import com.netki.model.OwnerType
import com.netki.model.ProtocolMessageParameters

class InvoiceRequest {

    fun create(
        protocolMessageParameters: ProtocolMessageParameters
    ): ByteArray {
        val invoiceRequestParameters = protocolMessageParameters as InvoiceRequestParameters
        invoiceRequestParameters.originatorParameters.validate(true, OwnerType.ORIGINATOR)
        invoiceRequestParameters.beneficiaryParameters?.validate(false, OwnerType.BENEFICIARY)

        val messageInvoiceRequestBuilder =
            invoiceRequestParameters.toMessageInvoiceRequestBuilderUnsigned(
                invoiceRequestParameters.senderParameters,
                invoiceRequestParameters.attestationsRequested,
                invoiceRequestParameters.recipientParameters
            )

        invoiceRequestParameters.beneficiaryParameters?.forEach { beneficiary ->
            val beneficiaryMessage = beneficiary.toMessageBeneficiaryBuilderWithoutAttestations()

            beneficiary.pkiDataParametersSets.forEach { pkiData ->
                beneficiaryMessage.addAttestations(pkiData.toMessageAttestation(false))
            }

            messageInvoiceRequestBuilder.addBeneficiaries(beneficiaryMessage)
        }

        invoiceRequestParameters.originatorParameters.forEach { originator ->
            val originatorMessage = originator.toMessageOriginatorBuilderWithoutAttestations()

            originator.pkiDataParametersSets.forEach { pkiData ->
                originatorMessage.addAttestations(pkiData.toMessageAttestation(originator.isPrimaryForTransaction))
            }

            messageInvoiceRequestBuilder.addOriginators(originatorMessage)
        }

        val messageInvoiceRequest = messageInvoiceRequestBuilder.build()

        val invoiceRequest =
            messageInvoiceRequest.signMessage(invoiceRequestParameters.senderParameters)
                .toByteArray()
        return invoiceRequest.toProtocolMessage(
            MessageType.INVOICE_REQUEST,
            invoiceRequestParameters.messageInformation,
            invoiceRequestParameters.senderParameters,
            invoiceRequestParameters.recipientParameters
        )
    }
}
