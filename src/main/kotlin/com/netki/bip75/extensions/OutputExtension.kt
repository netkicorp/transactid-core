package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.extensions.toByteString
import com.netki.model.Output

/**
 * Transform Output object to Messages.Output object.
 *
 * @return Messages.Output.
 */
internal fun Output.toMessageOutput(): Messages.Output = Messages.Output.newBuilder()
    .setAmount(this.amount)
    .setScript(this.script.toByteString())
    .setCurrency(this.currency.toCurrencyType())
    .build()
