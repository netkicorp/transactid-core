package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.exceptions.ExceptionInformation
import com.netki.exceptions.InvalidOwnersException
import com.netki.model.OriginatorParameters
import com.netki.model.OwnerParameters
import com.netki.model.OwnerType

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

