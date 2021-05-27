package com.netki.model

/**
 * Contains a certificate associated to an specific attestation.
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
     * PublicKey.
     */
    val publicKeyPem: String? = null,

    /**
     * Unique identifier for this AttestationCertificate.
     */
    val identifier: String? = null,

    /**
     * PrivateKey.
     */
    val privateKeyPem: String? = null,
)
