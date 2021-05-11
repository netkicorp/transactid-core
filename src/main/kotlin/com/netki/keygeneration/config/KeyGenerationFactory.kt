package com.netki.keygeneration.config

import com.netki.keygeneration.main.KeyGeneration
import com.netki.keygeneration.main.impl.KeyGenerationNetki
import com.netki.keygeneration.repo.KeyProvider
import com.netki.keygeneration.repo.impl.NetkiKeyProvider
import com.netki.keygeneration.service.KeyGenerationService
import com.netki.keygeneration.service.impl.KeyGenerationNetkiService
import com.netki.security.Certificate
import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.features.*
import io.ktor.client.features.json.*

/**
 * Factory to generate KeyGeneration instance.
 */
object KeyGenerationFactory {

    /**
     * Get an instance of KeyGeneration.
     *
     * @return KeyGeneration instance.
     */
    fun getInstance(
        authorizationCertificateProviderKey: String,
        authorizationCertificateProviderUrl: String
    ): KeyGeneration {

        val client: HttpClient by lazy {
            HttpClient(OkHttp) {
                install(JsonFeature) {
                    serializer = GsonSerializer()
                }
                install(HttpTimeout) {
                    requestTimeoutMillis = 60000
                    connectTimeoutMillis = 60000
                    socketTimeoutMillis = 60000
                }
            }
        }

        val keyProvider: KeyProvider =
            NetkiKeyProvider(client, authorizationCertificateProviderKey, authorizationCertificateProviderUrl)

        val keyGenerationService: KeyGenerationService = KeyGenerationNetkiService(keyProvider)

        return KeyGenerationNetki(keyGenerationService)
    }
}
