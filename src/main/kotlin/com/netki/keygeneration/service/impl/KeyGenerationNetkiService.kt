package com.netki.keygeneration.service.impl

import com.netki.keygeneration.repo.KeyProvider
import com.netki.keygeneration.repo.data.CsrAttestation
import com.netki.keygeneration.service.KeyGenerationService
import com.netki.model.AttestationCertificate

internal class KeyGenerationNetkiService(
    private val keyProvider: KeyProvider
) : KeyGenerationService {

    /**
     * {@inheritDoc}
     */
    override fun generateCertificates(attestationCertificate: List<AttestationCertificate>): List<AttestationCertificate> {
        val transactionId = keyProvider.requestTransactionId(attestationCertificate.map { it.attestation })
        keyProvider.submitCsrsAttestations(transactionId, attestationCertificate.map {
            CsrAttestation(it.csr!!, it.attestation, it.publicKeyPem!!)
        })
        val certificates = keyProvider.getCertificates(transactionId)

        return if (certificates.count == 0) {
            emptyList()
        } else {
            certificates.certificates.map {
                AttestationCertificate(
                    it.attestation!!,
                    it.certificate!!
                )
            }
        }
    }
}
