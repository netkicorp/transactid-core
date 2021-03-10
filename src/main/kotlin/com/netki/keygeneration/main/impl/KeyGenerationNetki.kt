package com.netki.keygeneration.main.impl

import com.netki.keygeneration.main.KeyGeneration
import com.netki.keygeneration.service.KeyGenerationService
import com.netki.model.AttestationInformation

internal class KeyGenerationNetki(private val keyGenerationService: KeyGenerationService) : KeyGeneration {

    /**
     * {@inheritDoc}
     */
    override fun generateCertificates(attestationsInformation: List<AttestationInformation>) =
        keyGenerationService.generateCertificates(attestationsInformation)
}
