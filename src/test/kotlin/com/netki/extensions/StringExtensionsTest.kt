package com.netki.extensions

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class StringExtensionsTest {

    @Test
    fun `Validate that strings are valid alphanumeric strings`() {
        assertTrue("Abc1234".isAlphaNumeric())
        assertTrue("Valid_string".isAlphaNumeric())
        assertTrue("Another-Valid string 1234.5".isAlphaNumeric())
        assertFalse("Not Valid #".isAlphaNumeric())
        assertFalse("#$% less valid".isAlphaNumeric())
        assertFalse("%1234".isAlphaNumeric())
    }
}
