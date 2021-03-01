package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.model.AddressCurrency

/**
 * Transform AddressCurrency to Messages.CurrencyType.
 */
internal fun AddressCurrency.toCurrencyType(): Messages.CurrencyType {
    return when (this) {
        AddressCurrency.BITCOIN -> Messages.CurrencyType.BITCOIN
        AddressCurrency.ETHEREUM -> Messages.CurrencyType.ETHEREUM
        AddressCurrency.LITECOIN -> Messages.CurrencyType.LITECOIN
        AddressCurrency.BITCOIN_CASH -> Messages.CurrencyType.BITCOIN_CASH
    }
}
