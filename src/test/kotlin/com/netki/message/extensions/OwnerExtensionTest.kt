package com.netki.message.extensions

import com.netki.exceptions.ExceptionInformation.OWNERS_VALIDATION_EMPTY_ERROR
import com.netki.exceptions.ExceptionInformation.OWNERS_VALIDATION_MULTIPLE_PRIMARY_OWNERS
import com.netki.exceptions.ExceptionInformation.OWNERS_VALIDATION_NO_PRIMARY_OWNER
import com.netki.exceptions.InvalidOwnersException
import com.netki.model.BeneficiaryParameters
import com.netki.model.OriginatorParameters
import com.netki.model.OwnerType
import com.netki.util.TestData
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class OwnerExtensionTest {

    @Test
    fun `Validate a correct list of beneficiaries required`() {
        val validListOfBeneficiaries = listOf(
            TestData.Beneficiaries.PRIMARY_BENEFICIARY_PKI_X509SHA256,
            TestData.Beneficiaries.NO_PRIMARY_BENEFICIARY_PKI_X509SHA256
        )

        validListOfBeneficiaries.validate(true, OwnerType.BENEFICIARY)
    }

    @Test
    fun `Validate a correct list of originators required`() {
        val validListOfOriginators = listOf(
            TestData.Originators.PRIMARY_ORIGINATOR_PKI_X509SHA256,
            TestData.Originators.NO_PRIMARY_ORIGINATOR_PKI_X509SHA256
        )

        validListOfOriginators.validate(true, OwnerType.ORIGINATOR)
    }

    @Test
    fun `Validate a incorrect list of beneficiaries required`() {
        val ownerType = OwnerType.BENEFICIARY
        val invalidListOfBeneficiaries = emptyList<BeneficiaryParameters>()

        val exception = assertThrows(InvalidOwnersException::class.java) {
            invalidListOfBeneficiaries.validate(true, ownerType)
        }

        assertEquals(exception.message, String.format(OWNERS_VALIDATION_EMPTY_ERROR, ownerType.description))
    }

    @Test
    fun `Validate a incorrect list of originators required`() {
        val ownerType = OwnerType.ORIGINATOR
        val invalidListOfOriginators = emptyList<OriginatorParameters>()

        val exception = assertThrows(InvalidOwnersException::class.java) {
            invalidListOfOriginators.validate(true, ownerType)
        }

        assertEquals(exception.message, String.format(OWNERS_VALIDATION_EMPTY_ERROR, ownerType.description))
    }

    @Test
    fun `Validate a incorrect list of beneficiaries not required`() {
        val ownerType = OwnerType.BENEFICIARY
        val invalidListOfBeneficiaries = emptyList<BeneficiaryParameters>()

        invalidListOfBeneficiaries.validate(false, ownerType)
    }

    @Test
    fun `Validate a incorrect list of originators not required`() {
        val ownerType = OwnerType.ORIGINATOR
        val invalidListOfOriginators = emptyList<OriginatorParameters>()

        invalidListOfOriginators.validate(false, ownerType)
    }

    @Test
    fun `Validate a list of beneficiaries with no primary owner`() {
        val ownerType = OwnerType.BENEFICIARY
        val invalidListOfBeneficiaries = listOf(
            TestData.Beneficiaries.NO_PRIMARY_BENEFICIARY_PKI_X509SHA256,
            TestData.Beneficiaries.NO_PRIMARY_BENEFICIARY_PKI_X509SHA256
        )
        val exception = assertThrows(InvalidOwnersException::class.java) {
            invalidListOfBeneficiaries.validate(true, ownerType)
        }

        assertEquals(exception.message, String.format(OWNERS_VALIDATION_NO_PRIMARY_OWNER, ownerType.description))
    }

    @Test
    fun `Validate a list of originators with no primary owner`() {
        val ownerType = OwnerType.ORIGINATOR
        val invalidListOfOriginators = listOf(
            TestData.Beneficiaries.NO_PRIMARY_BENEFICIARY_PKI_X509SHA256,
            TestData.Beneficiaries.NO_PRIMARY_BENEFICIARY_PKI_X509SHA256
        )
        val exception = assertThrows(InvalidOwnersException::class.java) {
            invalidListOfOriginators.validate(true, ownerType)
        }

        assertEquals(exception.message, String.format(OWNERS_VALIDATION_NO_PRIMARY_OWNER, ownerType.description))
    }

    @Test
    fun `Validate a list of beneficiaries with multiple primary owners`() {
        val ownerType = OwnerType.BENEFICIARY
        val invalidListOfBeneficiaries = listOf(
            TestData.Beneficiaries.PRIMARY_BENEFICIARY_PKI_X509SHA256,
            TestData.Beneficiaries.PRIMARY_BENEFICIARY_PKI_X509SHA256
        )
        val exception = assertThrows(InvalidOwnersException::class.java) {
            invalidListOfBeneficiaries.validate(true, ownerType)
        }

        assertEquals(exception.message, String.format(OWNERS_VALIDATION_MULTIPLE_PRIMARY_OWNERS, ownerType.description))
    }

    @Test
    fun `Validate a list of originators with multiple primary owners`() {
        val ownerType = OwnerType.ORIGINATOR
        val invalidListOfOriginators = listOf(
            TestData.Originators.PRIMARY_ORIGINATOR_PKI_X509SHA256,
            TestData.Originators.PRIMARY_ORIGINATOR_PKI_X509SHA256
        )
        val exception = assertThrows(InvalidOwnersException::class.java) {
            invalidListOfOriginators.validate(true, ownerType)
        }

        assertEquals(exception.message, String.format(OWNERS_VALIDATION_MULTIPLE_PRIMARY_OWNERS, ownerType.description))
    }
}
