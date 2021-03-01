package com.netki.bip75.extensions

import com.netki.bip75.protocol.Messages
import com.netki.model.Attestation

/**
 * Transform Attestation to Messages.AttestationType.
 */
internal fun Attestation.toAttestationType(): Messages.AttestationType {
    return when (this) {
        Attestation.LEGAL_PERSON_NAME -> Messages.AttestationType.LEGAL_PERSON_NAME
        Attestation.LEGAL_PERSON_PHONETIC_NAME_IDENTIFIER -> Messages.AttestationType.LEGAL_PERSON_PHONETIC_NAME_IDENTIFIER
        Attestation.ADDRESS_DEPARTMENT -> Messages.AttestationType.ADDRESS_DEPARTMENT
        Attestation.ADDRESS_SUB_DEPARTMENT -> Messages.AttestationType.ADDRESS_SUB_DEPARTMENT
        Attestation.ADDRESS_STREET_NAME -> Messages.AttestationType.ADDRESS_STREET_NAME
        Attestation.ADDRESS_BUILDING_NUMBER -> Messages.AttestationType.ADDRESS_BUILDING_NUMBER
        Attestation.ADDRESS_BUILDING_NAME -> Messages.AttestationType.ADDRESS_BUILDING_NAME
        Attestation.ADDRESS_FLOOR -> Messages.AttestationType.ADDRESS_FLOOR
        Attestation.ADDRESS_POSTBOX -> Messages.AttestationType.ADDRESS_POSTBOX
        Attestation.ADDRESS_ROOM -> Messages.AttestationType.ADDRESS_ROOM
        Attestation.ADDRESS_POSTCODE -> Messages.AttestationType.ADDRESS_POSTCODE
        Attestation.ADDRESS_TOWN_NAME -> Messages.AttestationType.ADDRESS_TOWN_NAME
        Attestation.ADDRESS_TOWN_LOCATION_NAME -> Messages.AttestationType.ADDRESS_TOWN_LOCATION_NAME
        Attestation.ADDRESS_DISTRICT_NAME -> Messages.AttestationType.ADDRESS_DISTRICT_NAME
        Attestation.ADDRESS_COUNTRY_SUB_DIVISION -> Messages.AttestationType.ADDRESS_COUNTRY_SUB_DIVISION
        Attestation.ADDRESS_ADDRESS_LINE -> Messages.AttestationType.ADDRESS_ADDRESS_LINE
        Attestation.ADDRESS_COUNTRY -> Messages.AttestationType.ADDRESS_COUNTRY
        Attestation.NATURAL_PERSON_PRIMARY_IDENTIFIER -> Messages.AttestationType.NATURAL_PERSON_PRIMARY_IDENTIFIER
        Attestation.NATURAL_PERSON_SECONDARY_IDENTIFIER -> Messages.AttestationType.NATURAL_PERSON_SECONDARY_IDENTIFIER
        Attestation.NATURAL_PERSON_PHONETIC_NAME_IDENTIFIER -> Messages.AttestationType.NATURAL_PERSON_PHONETIC_NAME_IDENTIFIER
        Attestation.DATE_OF_BIRTH -> Messages.AttestationType.DATE_OF_BIRTH
        Attestation.PLACE_OF_BIRTH -> Messages.AttestationType.PLACE_OF_BIRTH
        Attestation.COUNTRY_OF_RESIDENCE -> Messages.AttestationType.COUNTRY_OF_RESIDENCE
        Attestation.COUNTRY_OF_ISSUE -> Messages.AttestationType.COUNTRY_OF_ISSUE
        Attestation.COUNTRY_OF_REGISTRATION -> Messages.AttestationType.COUNTRY_OF_REGISTRATION
        Attestation.NATIONAL_IDENTIFIER -> Messages.AttestationType.NATIONAL_IDENTIFIER
        Attestation.ACCOUNT_NUMBER -> Messages.AttestationType.ACCOUNT_NUMBER
        Attestation.CUSTOMER_IDENTIFICATION -> Messages.AttestationType.CUSTOMER_IDENTIFICATION
        Attestation.REGISTRATION_AUTHORITY -> Messages.AttestationType.REGISTRATION_AUTHORITY
    }
}
