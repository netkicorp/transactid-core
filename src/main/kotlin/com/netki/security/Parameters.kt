package com.netki.security

object Parameters {

    /**
     * Algorithm to create hash.
     */
    const val DIGEST_ALGORITHM = "SHA-256"

    /**
     * Algorithm to create digital signature.
     */
    const val SIGNATURE_ALGORITHM = "SHA256withRSA"

    /**
     * Algorithm to create digital signature with ECDSA keys.
     */
    const val SIGNATURE_ALGORITHM_ECDSA = "SHA256withECDSA"

    /**
     * Digits used for encryption.
     */
    val UPPER_HEX_DIGITS_ENCRYPTION =
        charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')

    /**
     * Maximum length for string in encryption.
     */
    const val MAXIMUM_LENGTH_PAD_ENCRYPTION = 64

    /**
     * Key generation algorithm
     */
    const val KEY_ALGORITHM = "RSA"
}
