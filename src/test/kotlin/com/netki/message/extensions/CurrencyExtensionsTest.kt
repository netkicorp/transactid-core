package com.netki.message.extensions

import com.netki.message.protocol.Messages
import com.netki.model.AddressCurrency
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class CurrencyExtensionsTest {

    @Test
    fun `Test Address Currency Object conversion to Message`() {
        assertEquals(AddressCurrency.BITCOIN.toCurrencyType(), Messages.CurrencyType.BITCOIN)
        assertEquals(AddressCurrency.ETHEREUM.toCurrencyType(), Messages.CurrencyType.ETHEREUM)
        assertEquals(AddressCurrency.LITECOIN.toCurrencyType(), Messages.CurrencyType.LITECOIN)
        assertEquals(AddressCurrency.BITCOIN_CASH.toCurrencyType(), Messages.CurrencyType.BITCOIN_CASH)
    }

    @Test
    fun `Test Message conversion to Address Currency Object `() {
        assertEquals(Messages.CurrencyType.BITCOIN.toAddressCurrency(), AddressCurrency.BITCOIN)
        assertEquals(Messages.CurrencyType.ETHEREUM.toAddressCurrency(), AddressCurrency.ETHEREUM)
        assertEquals(Messages.CurrencyType.LITECOIN.toAddressCurrency(), AddressCurrency.LITECOIN)
        assertEquals(Messages.CurrencyType.BITCOIN_CASH.toAddressCurrency(), AddressCurrency.BITCOIN_CASH)
    }
}
