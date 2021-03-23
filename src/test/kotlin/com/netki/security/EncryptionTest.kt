package com.netki.security

import com.netki.exceptions.EncryptionException
import com.netki.util.TestData
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class EncryptionTest {

    @Test
    fun `Test encryption successfully`() {
        val keyPairSender = TestData.Keys.generateKeyPairECDSA()
        val keyPairReceiver = TestData.Keys.generateKeyPairECDSA()
        val valueToEncrypt = "Encrypt string"
        val encryption = Encryption.encrypt(
            valueToEncrypt,
            keyPairReceiver.public.toPemFormat(),
            keyPairSender.public.toPemFormat(),
            keyPairSender.private.toPemFormat()
        )
        val decrypted = Encryption.decrypt(
            encryption,
            keyPairReceiver.private.toPemFormat(),
            keyPairSender.public.toPemFormat()
        )
        assertEquals(valueToEncrypt, decrypted)
    }

    @Test
    fun `Test encryption not same key`() {
        val keyPairSender = TestData.Keys.generateKeyPairECDSA()
        val keyPairReceiver = TestData.Keys.generateKeyPairECDSA()
        val keyPairRandom = TestData.Keys.generateKeyPairECDSA()
        val valueToEncrypt = "Encrypt string"
        val encryption = Encryption.encrypt(
            valueToEncrypt,
            keyPairReceiver.public.toPemFormat(),
            keyPairSender.public.toPemFormat(),
            keyPairSender.private.toPemFormat()
        )
        assertThrows(EncryptionException::class.java) {
            Encryption.decrypt(
                encryption,
                keyPairRandom.private.toPemFormat(),
                keyPairRandom.public.toPemFormat()
            )
        }
    }
}
