package com.netki.model

/**
 * Contains the data associated to an specific attestation.
 */
data class AttestationCertificate constructor(

    /**
     * The type of attestation.
     */
    val attestation: Attestation,

    /**
     * Certificate associated to the attestation.
     * The certificate is a X509 certificate in PEM format.
     */
    val certificatePem: String? = null,

    /**
     * CSR associated to the attestation.
     */
    val csr: String? = null,

    /**
     * PublicKey associated to the CSR.
     */
    val publicKeyPem: String? = null
)
