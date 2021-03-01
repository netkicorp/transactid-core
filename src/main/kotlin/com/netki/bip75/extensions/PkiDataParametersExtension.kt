package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.extensions.toByteString
import com.netki.model.PkiDataParameters
import com.netki.model.PkiType

/**
 * Transform PkiDataParameters object to Messages.Attestation object.
 * If there is a PkiType X509SHA256 this message should be signed.
 *
 * @return Messages.Attestation.
 */
internal fun PkiDataParameters.toMessageAttestation(requireSignature: Boolean): Messages.Attestation {
    val messageAttestationUnsignedBuilder = Messages.Attestation.newBuilder()
        .setPkiType(this.type.value)
        .setPkiData(this.certificatePem?.toByteString() ?: "".toByteString())
        .setSignature("".toByteString())

    this.attestation?.let {
        messageAttestationUnsignedBuilder.setAttestation(it.toAttestationType())
    }

    val messageAttestationUnsigned = messageAttestationUnsignedBuilder.build()

    return when {
        this.type == PkiType.X509SHA256 && requireSignature -> {
            val signature = messageAttestationUnsigned.sign(this.privateKeyPem!!)
            Messages.Attestation.newBuilder()
                .mergeFrom(messageAttestationUnsigned)
                .setSignature(signature.toByteString())
                .build()
        }
        else -> messageAttestationUnsigned
    }
}
