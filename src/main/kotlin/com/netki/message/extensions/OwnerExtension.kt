package com.netki.message.extensions

import com.netki.message.protocol.Messages
import com.netki.exceptions.ExceptionInformation
import com.netki.exceptions.InvalidOwnersException
import com.netki.extensions.toByteString
import com.netki.model.*

/**
 * Validate that a List<Owners> is valid.
 * Is valid, when it has one single primaryOwner.
 *
 * @throws InvalidOwnersException if is not a valid list.
 */
internal fun List<OwnerParameters>.validate(required: Boolean, ownerType: OwnerType) {
    if (required && this.isEmpty()) {
        throw InvalidOwnersException(
            String.format(
                ExceptionInformation.OWNERS_VALIDATION_EMPTY_ERROR,
                ownerType.description
            )
        )
    } else if (!required && this.isEmpty()) {
        return
    }

    val numberOfPrimaryOwners = this.filter { it.isPrimaryForTransaction }.size

    check(numberOfPrimaryOwners != 0) {
        throw InvalidOwnersException(
            String.format(
                ExceptionInformation.OWNERS_VALIDATION_NO_PRIMARY_OWNER,
                ownerType.description
            )
        )
    }

    check(numberOfPrimaryOwners <= 1) {
        throw InvalidOwnersException(
            String.format(
                ExceptionInformation.OWNERS_VALIDATION_MULTIPLE_PRIMARY_OWNERS,
                ownerType.description
            )
        )
    }
}

/**
 * Transform BeneficiaryParameters object to Messages.Beneficiary.Builder object.
 *
 * @return Messages.Beneficiary.
 */
internal fun OwnerParameters.toMessageBeneficiaryBuilderWithoutAttestations(): Messages.Beneficiary.Builder =
    Messages.Beneficiary.newBuilder().setPrimaryForTransaction(this.isPrimaryForTransaction)

/**
 * Transform OriginatorParameters object to Messages.Originator.Builder object.
 *
 * @return Messages.Originator.
 */
internal fun OriginatorParameters.toMessageOriginatorBuilderWithoutAttestations(): Messages.Originator.Builder =
    Messages.Originator.newBuilder().setPrimaryForTransaction(this.isPrimaryForTransaction)

/**
 * Transform Messages.Beneficiary to Beneficiary object.
 *
 * @return Beneficiary.
 */
internal fun Messages.Beneficiary.toBeneficiary(): Beneficiary {
    val pkiDataSets = mutableListOf<PkiData>()
    this.attestationsList.forEach { messageAttestation ->
        pkiDataSets.add(messageAttestation.toPkiData())
    }
    return Beneficiary(this.primaryForTransaction, pkiDataSets)
}

/**
 * Transform Messages.Originator to Originator object.
 *
 * @return Originator.
 */
internal fun Messages.Originator.toOriginator(): Originator {
    val pkiDataSets = mutableListOf<PkiData>()
    this.attestationsList.forEach { messageAttestation ->
        pkiDataSets.add(messageAttestation.toPkiData())
    }
    return Originator(this.primaryForTransaction, pkiDataSets)
}

/**
 * Transform Beneficiary to Messages.Beneficiary object.
 *
 * @return Messages.Beneficiary.
 */
internal fun Beneficiary.toMessageBeneficiary(): Messages.Beneficiary {
    val messageBeneficiary = Messages.Beneficiary.newBuilder()

    messageBeneficiary.primaryForTransaction = this.isPrimaryForTransaction
    this.pkiDataSet.forEach { pkiDataSet ->
        val attestation = Messages.Attestation.newBuilder()
            .setAttestation(pkiDataSet.attestation?.toAttestationType())
            .setPkiData(pkiDataSet.certificatePem.toByteString())
            .setPkiType(pkiDataSet.type.value)
            .setSignature(pkiDataSet.signature?.toByteString())
            .build()
        messageBeneficiary.addAttestations(attestation)
    }

    return messageBeneficiary.build()
}

/**
 * Transform Owner to Messages.Owner object.
 *
 * @return Messages.Owner.
 */
internal fun Originator.toMessageOriginator(): Messages.Originator {
    val messageOriginator = Messages.Originator.newBuilder()

    messageOriginator.primaryForTransaction = this.isPrimaryForTransaction
    this.pkiDataSet.forEach { pkiDataSet ->
        val attestation = Messages.Attestation.newBuilder()
            .setAttestation(pkiDataSet.attestation?.toAttestationType())
            .setPkiData(pkiDataSet.certificatePem.toByteString())
            .setPkiType(pkiDataSet.type.value)
            .setSignature(pkiDataSet.signature?.toByteString())
            .build()
        messageOriginator.addAttestations(attestation)
    }

    return messageOriginator.build()
}
