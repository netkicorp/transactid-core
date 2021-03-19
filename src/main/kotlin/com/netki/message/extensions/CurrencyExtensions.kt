package com.netki.message.extensions

import com.netki.message.protocol.Messages
import com.netki.model.AddressCurrency

/**
 * Transform Messages.CurrencyType to AddressCurrency.
 */
internal fun Messages.CurrencyType.toAddressCurrency(): AddressCurrency {
    return when (this) {
        Messages.CurrencyType.BITCOIN -> AddressCurrency.BITCOIN
        Messages.CurrencyType.ETHEREUM -> AddressCurrency.ETHEREUM
        Messages.CurrencyType.LITECOIN -> AddressCurrency.LITECOIN
        Messages.CurrencyType.BITCOIN_CASH -> AddressCurrency.BITCOIN_CASH
    }
}
