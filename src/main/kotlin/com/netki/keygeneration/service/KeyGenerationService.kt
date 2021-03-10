package com.netki.keygeneration.service

import com.netki.exceptions.*
import com.netki.model.AttestationCertificate
import com.netki.model.AttestationInformation

internal interface KeyGenerationService {

    /**
     * Generate a certificate for each one of the attestations provided.
     *
     * @param attestationsInformation list of attestations with their corresponding data.
     * @return list of certificate per attestation.
     * @throws CertificateProviderException if there is an error creating the certificates.
     * @throws CertificateProviderUnauthorizedException if there is an error with the authorization to connect to the provider.
     */
    @Throws(CertificateProviderException::class, CertificateProviderUnauthorizedException::class)
    fun generateCertificates(attestationsInformation: List<AttestationInformation>): List<AttestationCertificate>
}
