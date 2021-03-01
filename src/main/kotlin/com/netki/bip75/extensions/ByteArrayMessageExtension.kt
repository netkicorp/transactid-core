package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.exceptions.EncryptionException
import com.netki.exceptions.ExceptionInformation
import com.netki.extensions.toByteString
import com.netki.model.MessageInformation
import com.netki.model.MessageType
import com.netki.model.RecipientParameters
import com.netki.model.SenderParameters
import com.netki.security.Encryption
import com.netki.security.Util
import com.netki.security.Signature
import com.netki.security.isECDSAKey
import java.util.*

/**
 * Transform a message in ByteArray to ProtocolMessage
 */
internal fun ByteArray.toProtocolMessage(
    messageType: MessageType,
    messageInformation: MessageInformation,
    senderParameters: SenderParameters? = null,
    recipientParameters: RecipientParameters? = null,
    identifier: String? = null
) = when (messageInformation.encryptMessage) {
    true -> this.toProtocolMessageEncrypted(
        messageType,
        messageInformation,
        senderParameters,
        recipientParameters,
        identifier
    )
    false -> this.toProtocolMessageUnencrypted(messageType, messageInformation, identifier)
}

/**
 * Transform a message in ByteArray to Messages.EncryptedProtocolMessage
 */
internal fun ByteArray.toProtocolMessageEncrypted(
    messageType: MessageType,
    messageInformation: MessageInformation,
    senderParameters: SenderParameters? = null,
    recipientParameters: RecipientParameters? = null,
    identifier: String? = null
): ByteArray {

    check(recipientParameters?.encryptionParameters?.publicKeyPem != null) {
        throw EncryptionException(ExceptionInformation.ENCRYPTION_MISSING_RECIPIENT_KEYS_ERROR)
    }

    check(
        senderParameters?.encryptionParameters?.publicKeyPem != null &&
                senderParameters.encryptionParameters.privateKeyPem != null
    ) {
        throw EncryptionException(ExceptionInformation.ENCRYPTION_MISSING_SENDER_KEYS_ERROR)
    }

    check(senderParameters?.encryptionParameters?.privateKeyPem.isECDSAKey()) {
        throw EncryptionException(ExceptionInformation.ENCRYPTION_INCORRECT_KEY_FORMAT_ERROR)
    }

    val encryptedMessage = Encryption.encrypt(
        Base64.getEncoder().encodeToString(this),
        recipientParameters?.encryptionParameters?.publicKeyPem!!,
        senderParameters?.encryptionParameters?.publicKeyPem!!,
        senderParameters.encryptionParameters.privateKeyPem
    )

    val encryptedMessageUnsigned = Messages.EncryptedProtocolMessage.newBuilder()
        .setVersion(1)
        .setStatusCode(messageInformation.statusCode.code)
        .setMessageType(
            when (messageType) {
                MessageType.INVOICE_REQUEST -> Messages.ProtocolMessageType.INVOICE_REQUEST
                MessageType.PAYMENT_REQUEST -> Messages.ProtocolMessageType.PAYMENT_REQUEST
                MessageType.PAYMENT -> Messages.ProtocolMessageType.PAYMENT
                MessageType.PAYMENT_ACK -> Messages.ProtocolMessageType.PAYMENT_ACK
                else -> Messages.ProtocolMessageType.UNKNOWN_MESSAGE_TYPE
            }
        )
        .setStatusMessage(messageInformation.statusMessage)
        .setIdentifier(
            identifier?.let { identifier.toByteString() } ?: Util.generateIdentifier(this).toByteString()
        )
        .setReceiverPublicKey(recipientParameters.encryptionParameters.publicKeyPem.toByteString())
        .setSenderPublicKey(senderParameters.encryptionParameters.publicKeyPem.toByteString())
        .setNonce(System.currentTimeMillis() / 1000)
        .setEncryptedMessage(encryptedMessage.toByteString())
        .setSignature("".toByteString())
        .build()

    val hash = Util.getHash256(encryptedMessageUnsigned.toByteArray())
    val signature = Signature.signStringECDSA(hash, senderParameters.encryptionParameters.privateKeyPem)

    return Messages.EncryptedProtocolMessage.newBuilder()
        .mergeFrom(encryptedMessageUnsigned)
        .setSignature(signature.toByteString())
        .build()
        .toByteArray()
}

/**
 * Transform a message in ByteArray to Messages.ProtocolMessage
 */
internal fun ByteArray.toProtocolMessageUnencrypted(
    messageType: MessageType,
    messageInformation: MessageInformation,
    identifier: String?
) = Messages.ProtocolMessage.newBuilder()
    .setVersion(1)
    .setStatusCode(messageInformation.statusCode.code)
    .setMessageType(
        when (messageType) {
            MessageType.INVOICE_REQUEST -> Messages.ProtocolMessageType.INVOICE_REQUEST
            MessageType.PAYMENT_REQUEST -> Messages.ProtocolMessageType.PAYMENT_REQUEST
            MessageType.PAYMENT -> Messages.ProtocolMessageType.PAYMENT
            MessageType.PAYMENT_ACK -> Messages.ProtocolMessageType.PAYMENT_ACK
            else -> Messages.ProtocolMessageType.UNKNOWN_MESSAGE_TYPE
        }
    )
    .setSerializedMessage(this.toByteString())
    .setStatusMessage(messageInformation.statusMessage)
    .setIdentifier(
        identifier?.let { identifier.toByteString() } ?: Util.generateIdentifier(this).toByteString()
    )
    .build()
    .toByteArray()
