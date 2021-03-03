package com.netki.security

import com.netki.security.Parameters.SIGNATURE_ALGORITHM
import com.netki.security.Parameters.SIGNATURE_ALGORITHM_ECDSA
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.util.*

object Signature {

    /**
     * Sign string with private key provided.
     *
     * @param stringToSign plain string to sign.
     * @param privateKeyPem in PEM format to sign.
     * @return signature.
     */
    fun signString(stringToSign: String, privateKeyPem: String) =
        signString(stringToSign, privateKeyPem.toPrivateKey())

    /**
     * Sign string with private key provided.
     *
     * @param stringToSign plain string to sign.
     * @param privateKey to sign.
     * @return signature.
     */
    fun signString(stringToSign: String, privateKey: PrivateKey): String {
        val signature: ByteArray = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(stringToSign.toByteArray())
            sign()
        }
        return Base64.getEncoder().encodeToString(signature)
    }

    /**
     * Sign string with ECDSA private key.
     *
     * @param stringToSign plain string to sign.
     * @param privateKeyPem to sign.
     * @return signature.
     */
    fun signStringECDSA(stringToSign: String, privateKeyPem: String): String {
        val privateKey = privateKeyPem.toPrivateKey()
        val signature: ByteArray = Signature.getInstance(SIGNATURE_ALGORITHM_ECDSA).run {
            initSign(privateKey)
            update(stringToSign.toByteArray())
            sign()
        }
        return Base64.getEncoder().encodeToString(signature)
    }

    /**
     * Validate if a signature is valid with ECDSA public key.
     *
     * @param signature to validate.
     * @param data that was signed.
     * @param publicKeyPem to validate the signature.
     * @return true if is valid, false otherwise.
     */
    fun validateSignatureECDSA(signature: String, data: String, publicKeyPem: String): Boolean {
        return try {
            val publicKey = publicKeyPem.toPublicKey()
            val signBytes = Base64.getDecoder().decode(signature.toByteArray(Charsets.UTF_8))
            Signature.getInstance(SIGNATURE_ALGORITHM_ECDSA).run {
                initVerify(publicKey)
                update(data.toByteArray())
                verify(signBytes)
            }
        } catch (exception: Exception) {
            exception.printStackTrace()
            false
        }
    }

    /**
     * Validate if a signature is valid.
     *
     * @param signature to validate.
     * @param data that was signed.
     * @param certificatePem in PEM format to validate the signature.
     * @return true if is valid, false otherwise.
     */
    fun validateSignature(signature: String, data: String, certificatePem: String) =
        validateSignature(signature, data, certificatePem.toCertificate())

    /**
     * Validate if a signature is valid.
     *
     * @param signature to validate.
     * @param data that was signed.
     * @param certificate to validate the signature.
     * @return true if is valid, false otherwise.
     */
    fun validateSignature(signature: String, data: String, certificate: Certificate): Boolean {
        val signBytes = Base64.getDecoder().decode(signature.toByteArray(Charsets.UTF_8))
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(certificate)
            update(data.toByteArray())
            verify(signBytes)
        }
    }
}
