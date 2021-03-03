package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.exceptions.EncryptionException
import com.netki.exceptions.ExceptionInformation
import com.netki.exceptions.ExceptionInformation.DECRYPTION_MISSING_RECIPIENT_KEYS_ERROR
import com.netki.exceptions.ExceptionInformation.ENCRYPTION_INVALID_ERROR
import com.netki.exceptions.ExceptionInformation.PARSE_BINARY_MESSAGE_INVALID_INPUT
import com.netki.exceptions.InvalidObjectException
import com.netki.extensions.toByteString
import com.netki.extensions.toStringLocal
import com.netki.model.*
import com.netki.security.Encryption
import com.netki.security.Signature
import com.netki.security.Util
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
            identifier?.let { identifier.toByteString() } ?: Util.generateIdentifier(this)
                .toByteString()
        )
        .setReceiverPublicKey(recipientParameters.encryptionParameters.publicKeyPem.toByteString())
        .setSenderPublicKey(senderParameters.encryptionParameters.publicKeyPem.toByteString())
        .setNonce(System.currentTimeMillis() / 1000)
        .setEncryptedMessage(encryptedMessage.toByteString())
        .setSignature("".toByteString())
        .build()

    val hash = Util.getHash256(encryptedMessageUnsigned.toByteArray())
    val signature =
        Signature.signStringECDSA(hash, senderParameters.encryptionParameters.privateKeyPem)

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
        identifier?.let { identifier.toByteString() } ?: Util.generateIdentifier(this)
            .toByteString()
    )
    .build()
    .toByteArray()

/**
 * Method to extract the ProtocolMessageMetadata from a Messages.ProtocolMessage
 */
internal fun ByteArray.extractProtocolMessageMetadata(): ProtocolMessageMetadata {
    try {
        val protocolMessageMessages = Messages.EncryptedProtocolMessage.parseFrom(this)
        return ProtocolMessageMetadata(
            protocolMessageMessages.version,
            StatusCode.getByCode(protocolMessageMessages.statusCode)!!,
            when (protocolMessageMessages.messageType) {
                Messages.ProtocolMessageType.INVOICE_REQUEST -> MessageType.INVOICE_REQUEST
                Messages.ProtocolMessageType.PAYMENT_REQUEST -> MessageType.PAYMENT_REQUEST
                Messages.ProtocolMessageType.PAYMENT -> MessageType.PAYMENT
                Messages.ProtocolMessageType.PAYMENT_ACK -> MessageType.PAYMENT_ACK
                else -> MessageType.UNKNOWN_MESSAGE_TYPE
            },
            protocolMessageMessages.statusMessage,
            protocolMessageMessages.identifier.toStringLocal(),
            true,
            protocolMessageMessages.encryptedMessage.toStringLocal(),
            protocolMessageMessages.receiverPublicKey.toStringLocal(),
            protocolMessageMessages.senderPublicKey.toStringLocal(),
            protocolMessageMessages.nonce,
            protocolMessageMessages.signature.toStringLocal()
        )
    } catch (exception: Exception) {
        // nothing to do here
    }

    try {
        val protocolMessageMessages = Messages.ProtocolMessage.parseFrom(this)
        return ProtocolMessageMetadata(
            protocolMessageMessages.version,
            StatusCode.getByCode(protocolMessageMessages.statusCode)!!,
            when (protocolMessageMessages.messageType) {
                Messages.ProtocolMessageType.INVOICE_REQUEST -> MessageType.INVOICE_REQUEST
                Messages.ProtocolMessageType.PAYMENT_REQUEST -> MessageType.PAYMENT_REQUEST
                Messages.ProtocolMessageType.PAYMENT -> MessageType.PAYMENT
                Messages.ProtocolMessageType.PAYMENT_ACK -> MessageType.PAYMENT_ACK
                else -> MessageType.UNKNOWN_MESSAGE_TYPE
            },
            protocolMessageMessages.statusMessage,
            protocolMessageMessages.identifier.toStringLocal(),
            false
        )
    } catch (exception: Exception) {
        exception.printStackTrace()
        throw InvalidObjectException(PARSE_BINARY_MESSAGE_INVALID_INPUT.format(exception.message))
    }
}

/**
 * Method to extract serialized message from Messages.ProtocolMessage
 */
internal fun ByteArray.getSerializedMessage(
    isEncrypted: Boolean,
    recipientParameters: RecipientParameters? = null
) =
    when (isEncrypted) {
        true -> this.getSerializedMessageEncryptedProtocolMessage(recipientParameters)
        false -> this.getSerializedProtocolMessage()
    }

/**
 * Method to extract serialized message from Messages.ProtocolMessage
 */
internal fun ByteArray.getSerializedProtocolMessage(): ByteArray {
    try {
        val protocolMessageMessages = Messages.ProtocolMessage.parseFrom(this)
        return protocolMessageMessages.serializedMessage.toByteArray()
    } catch (exception: Exception) {
        exception.printStackTrace()
        throw InvalidObjectException(PARSE_BINARY_MESSAGE_INVALID_INPUT.format(exception.message))
    }
}

/**
 * Method to extract serialized message from Messages.EncryptedProtocolMessage
 */
internal fun ByteArray.getSerializedMessageEncryptedProtocolMessage(recipientParameters: RecipientParameters?): ByteArray {
    check(recipientParameters?.encryptionParameters?.privateKeyPem != null) {
        throw EncryptionException(DECRYPTION_MISSING_RECIPIENT_KEYS_ERROR)
    }

    val protocolMessageMessages = try {
        Messages.EncryptedProtocolMessage.parseFrom(this)
    } catch (exception: Exception) {
        exception.printStackTrace()
        throw InvalidObjectException(PARSE_BINARY_MESSAGE_INVALID_INPUT.format(exception.message))
    }
    try {
        val decryptedMessage = Encryption.decrypt(
            protocolMessageMessages.encryptedMessage.toStringLocal(),
            recipientParameters?.encryptionParameters!!.privateKeyPem!!,
            protocolMessageMessages.senderPublicKey.toStringLocal()
        )
        return Base64.getDecoder().decode(decryptedMessage)
    } catch (exception: Exception) {
        exception.printStackTrace()
        throw EncryptionException(ENCRYPTION_INVALID_ERROR.format(exception.message), exception)
    }
}

/**
 * Validate if sender signature of a EncryptedProtocolMessage is valid.
 *
 * @return true if yes, false otherwise.
 */
internal fun ByteArray.validateMessageEncryptionSignature(): Boolean {
    val signature = Messages.EncryptedProtocolMessage.parseFrom(this).signature.toStringLocal()
    val encryptedProtocolMessage = Messages.EncryptedProtocolMessage.newBuilder()
        .mergeFrom(this)
        .setSignature("".toByteString())
        .build()

    val bytesHash = Util.getHash256(encryptedProtocolMessage.toByteArray())
    return Signature.validateSignatureECDSA(
        signature,
        bytesHash,
        encryptedProtocolMessage.senderPublicKey.toStringLocal()
    )
}
