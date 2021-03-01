package com.netki.security

import com.netki.security.Parameters.SIGNATURE_ALGORITHM
import com.netki.security.Parameters.SIGNATURE_ALGORITHM_ECDSA
import java.security.PrivateKey
import java.security.Signature
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

}
