package com.netki.security

import com.netki.util.TestData
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class SignatureTest {

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
    fun `Sign string and validate with PrivateKeyPem`() {
        val privateKeyPem = privateKey.toPemFormat()
        val signature = Signature.signString(TestData.Signature.STRING_TEST, privateKeyPem)
        val certificatePem = certificate.toPemFormat()
        assert(Signature.validateSignature(signature, TestData.Signature.STRING_TEST, certificatePem))
    }

    @Test
    fun `Sign string and validate with PrivateKeyObject`() {
        val signature = Signature.signString(TestData.Signature.STRING_TEST, privateKey)
        assert(Signature.validateSignature(signature, TestData.Signature.STRING_TEST, certificate))
    }

    @Test
    fun `Sign string and validate with PrivateKeyPem ECDSA`() {
        val keyPair = TestData.Keys.generateKeyPairECDSA()
        val signature = Signature.signStringECDSA(
            TestData.Signature.STRING_TEST,
            keyPair.private.toPemFormat()
        )
        assert(
            Signature.validateSignatureECDSA(
                signature,
                TestData.Signature.STRING_TEST,
                keyPair.public.toPemFormat()
            )
        )
    }
}
