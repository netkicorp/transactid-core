package com.netki.keygeneration.service.impl

import com.netki.exceptions.CertificateProviderException
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_INFORMATION_STRING_NOT_CORRECT_ERROR_PROVIDER
import com.netki.extensions.isAlphaNumeric
import com.netki.keygeneration.repo.KeyProvider
import com.netki.keygeneration.repo.data.CsrAttestation
import com.netki.keygeneration.service.KeyGenerationService
import com.netki.keygeneration.util.toPrincipal
import com.netki.model.AttestationCertificate
import com.netki.model.AttestationInformation
import com.netki.security.Certificate
import com.netki.security.Keys
import com.netki.security.toPemFormat

internal class KeyGenerationNetkiService(
    private val keyProvider: KeyProvider,
    private val certificate: Certificate
) : KeyGenerationService {

    /**
     * {@inheritDoc}
     */
    override fun generateCertificates(attestationsInformation: List<AttestationInformation>): List<AttestationCertificate> {
        validateAttestationData(attestationsInformation)
        val transactionId = keyProvider.requestTransactionId(attestationsInformation.map { it.attestation })

        val keyPair = Keys.generateKeyPair()

        val csrsAttestations = attestationsInformation.map {
            CsrAttestation(
                certificate.csrObjectToPem(
                    Certificate.generateCSR(it.attestation.toPrincipal(it.data, it.ivmsConstraint), keyPair)
                ),
                it.attestation,
                keyPair.public.toPemFormat()
            )
        }

        keyProvider.submitCsrsAttestations(transactionId, csrsAttestations)
        val certificates = keyProvider.getCertificates(transactionId)

        return if (certificates.count == 0) {
            emptyList()
        } else {
            certificates.certificates.map {
                AttestationCertificate(
                    it.attestation!!,
                    it.certificate!!,
                    keyPair.private.toPemFormat()
                )
            }
        }
    }

    private fun validateAttestationData(attestationsInformation: List<AttestationInformation>) {
        attestationsInformation.forEach { information ->
            if (!information.data.isAlphaNumeric()) {
                throw CertificateProviderException(
                    String.format(
                        CERTIFICATE_INFORMATION_STRING_NOT_CORRECT_ERROR_PROVIDER,
                        information.data,
                        information.attestation
                    )
                )
            }
        }
    }
}
