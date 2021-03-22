package com.netki.security

import com.netki.util.TestData
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class UtilTest {
    @Test
    fun `Hashing bytes successfully Algorithm SHA-256`() {
        val hash = Util.getHash256(TestData.Hash.STRING_TEST.toByteArray(Charsets.UTF_8))
        assert(hash.toByteArray().size == TestData.Hash.SHA_256_HASH_LENGTH)
        assert(hash == TestData.Hash.STRING_TEST_HASH)
    }

    @Test
    fun `Hashing string successfully Algorithm SHA-256`() {
        val hash = Util.getHash256(TestData.Hash.STRING_TEST)
        assert(hash.length == TestData.Hash.SHA_256_HASH_LENGTH)
        assert(hash == TestData.Hash.STRING_TEST_HASH)
    }

    @Test
    fun `Hashing string unsuccessfully Algorithm SHA-256`() {
        val hash = Util.getHash256("random string")
        assert(hash != TestData.Hash.STRING_TEST_HASH)
    }
}
