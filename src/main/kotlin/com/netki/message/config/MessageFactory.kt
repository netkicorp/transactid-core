package com.netki.message.config

import com.netki.address.info.repo.impl.MerkleRepo
import com.netki.address.info.service.impl.AddressInformationNetkiService
import com.netki.message.main.Message
import com.netki.message.main.impl.MessageNetki
import com.netki.message.processor.impl.InvoiceRequestProcessor
import com.netki.message.processor.impl.PaymentAckProcessor
import com.netki.message.processor.impl.PaymentProcessor
import com.netki.message.processor.impl.PaymentRequestProcessor
import com.netki.message.service.MessageService
import com.netki.message.service.impl.MessageServiceNetki
import com.netki.security.Certificate
import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.features.json.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Factory to generate Message instance.
 */
object MessageFactory {

    /**
     * Get an instance of Message.
     * @param authorizationKey pass this parameter if address information will be required.
     * @return Message instance.
     */
    @JvmOverloads
    fun getInstance(
        authorizationKey: String? = null
    ): Message {
        Security.addProvider(BouncyCastleProvider())

        val client: HttpClient by lazy {
            HttpClient(OkHttp) {
                install(JsonFeature) {
                    serializer = GsonSerializer()
                }
            }
        }

        val addressInformationRepo = MerkleRepo(client, authorizationKey ?: "")

        val addressInformationService = AddressInformationNetkiService(addressInformationRepo)

        val certificate = Certificate

        val invoiceRequestProcessor = InvoiceRequestProcessor(addressInformationService, certificate)
        val paymentRequestProcessor = PaymentRequestProcessor(addressInformationService, certificate)
        val paymentProcessor = PaymentProcessor(addressInformationService, certificate)
        val paymentAckProcessor = PaymentAckProcessor(addressInformationService, certificate)

        val messageService: MessageService =
            MessageServiceNetki(invoiceRequestProcessor, paymentRequestProcessor, paymentProcessor, paymentAckProcessor)

        return MessageNetki(messageService)
    }
}
