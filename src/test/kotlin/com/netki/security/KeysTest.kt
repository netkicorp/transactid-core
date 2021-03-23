package com.netki.security

import com.netki.util.TestData
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class KeysTest {

    private lateinit var privateKey: PrivateKey
    private lateinit var certificate: Certificate
    private lateinit var publicKey: PublicKey

    @BeforeAll
    fun setUp() {
        val keyPair = TestData.Keys.generateKeyPair()
        privateKey = keyPair.private
        certificate = TestData.Keys.generateCertificate(keyPair, TestData.Keys.HASH_ALGORITHM, "test")
        publicKey = certificate.publicKey
    }

    @Test
    fun `Transform valid PrivateKey in PEM format to object`() {
        val privateKeyPem = privateKey.toPemFormat()
        privateKeyPem.toPrivateKey()
    }

    @Test
    fun `Transform invalid PrivateKey in PEM format to object`() {
        Assertions.assertThrows(Exception::class.java) {
            "invalid_private_key".toPrivateKey()
        }
    }

    @Test
    fun `Transform valid PrivateKey object to PEM format`() {
        privateKey.toPemFormat()
    }

    @Test
    fun `Transform valid Certificate in PEM format to object`() {
        val certificatePem = certificate.toPemFormat()
        certificatePem.toCertificate()
    }

    @Test
    fun `Transform invalid Certificate in PEM format to object`() {
        Assertions.assertThrows(Exception::class.java) {
            "invalid_certificate".toCertificate()
        }
    }

    @Test
    fun `Transform valid Certificate object to PEM format`() {
        certificate.toPemFormat()
    }

    @Test
    fun `Transform valid PublicKey in PEM format to object`() {
        val publicKeyPem = publicKey.toPemFormat()
        publicKeyPem.toPublicKey()
    }

    @Test
    fun `Transform invalid PublicKey in PEM format to object`() {
        Assertions.assertThrows(Exception::class.java) {
            "invalid_public_key".toPublicKey()
        }
    }

    @Test
    fun `Transform valid PublicKey object to PEM format`() {
        publicKey.toPemFormat()
    }

    @Test
    fun `Validate the key is type ECDSA with valid key`() {
        val pairKey = TestData.Keys.generateKeyPairECDSA()
        val keyPem = pairKey.private.toPemFormat()

        assertTrue(keyPem.isECDSAKey())
    }

    @Test
    fun `Validate the key is type ECDSA with invalid key`() {
        val keyPem = privateKey.toPemFormat()

        assertFalse(keyPem.isECDSAKey())
    }
}
