package com.netki

import kotlin.test.Test
import kotlin.test.assertEquals

class MathTestTest {

    @Test
    fun sum() {
        val mathTest = MathTest()
        assertEquals(5, mathTest.sum(2, 3))
    }
}


