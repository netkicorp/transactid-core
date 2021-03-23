package com.netki.security

import com.netki.security.Parameters.DIGEST_ALGORITHM
import java.security.MessageDigest

object Util {

    /**
     * Hash string with SHA-256 algorithm.
     *
     * @param stringToHash plain string to be hashed.
     * @return hash string.
     */
    fun getHash256(stringToHash: String) = getHash256(stringToHash.toByteArray(Charsets.UTF_8))

    /**
     * Hash string with SHA-256 algorithm.
     *
     * @param bytesToHash byteArray to be hashed.
     * @return hash string.
     */
    fun getHash256(bytesToHash: ByteArray): String {
        val messageDigest: MessageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM)
        messageDigest.update(bytesToHash)
        return bytesToHex(messageDigest.digest())
    }

    /**
     * Transform bytes to Hex String.
     *
     * @param hash bytes.
     * @return hex string.
     */
    private fun bytesToHex(hash: ByteArray): String {
        val hexString = StringBuffer()
        for (i in hash.indices) {
            val hex = Integer.toHexString(0xff and hash[i].toInt())
            if (hex.length == 1) hexString.append('0')
            hexString.append(hex)
        }
        return hexString.toString()
    }

    /**
     * Generate identifier for an specific message in ByteArray format
     */
    fun generateIdentifier(byteArray: ByteArray): String {
        val hash256 = getHash256(byteArray)
        val epochTime = System.currentTimeMillis() / 1000
        return "$hash256$epochTime"
    }
}
