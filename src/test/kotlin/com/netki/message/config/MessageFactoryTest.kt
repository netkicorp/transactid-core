package com.netki.message.config

import com.netki.message.main.Message
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.File

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class MessageFactoryTest {

    @Test
    fun `Validate proper instance creation of Message instance with Authorization key`() {
        val authorizationKey = "fake_key"
        val messageInstance = MessageFactory.getInstance(authorizationKey)

        assert(messageInstance is Message)
    }

}
