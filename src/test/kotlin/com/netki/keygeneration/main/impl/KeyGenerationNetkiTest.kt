package com.netki.keymanagement.main.impl

import com.netki.exceptions.CertificateProviderException
import com.netki.exceptions.ExceptionInformation.CERTIFICATE_INFORMATION_STRING_NOT_CORRECT_ERROR_PROVIDER
import com.netki.keygeneration.main.impl.KeyGenerationNetki
import com.netki.keygeneration.repo.data.CertificateAttestationResponse
import com.netki.keygeneration.repo.impl.NetkiKeyProvider
import com.netki.keygeneration.service.impl.KeyGenerationNetkiService
import com.netki.model.Attestation
import com.netki.model.AttestationInformation
import com.netki.model.IvmsConstraint
import com.netki.security.Certificate
import com.netki.util.TestData.CertificateGeneration.ATTESTATIONS_INFORMATION
import com.netki.util.TestData.CertificateGeneration.ATTESTATIONS_REQUESTED
import com.netki.util.TestData.CertificateGeneration.CERTIFICATE_ATTESTATION_RESPONSE
import com.netki.util.TestData.CertificateGeneration.CSRS_ATTESTATIONS
import com.netki.util.TestData.CertificateGeneration.TRANSACTION_ID
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.mockito.Mockito
import org.mockito.Mockito.`when`
import org.mockito.Mockito.doNothing

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class KeyGenerationNetkiTest {

    private lateinit var keyGeneration: KeyGenerationNetki
    private lateinit var mockNetkiKeyProvider: NetkiKeyProvider

    @BeforeAll
    fun setUp() {
        mockNetkiKeyProvider = Mockito.mock(NetkiKeyProvider::class.java)
        val keyManagementService = KeyGenerationNetkiService(mockNetkiKeyProvider, Certificate)
        keyGeneration = KeyGenerationNetki(keyManagementService)
    }

    @BeforeEach
    fun resetMock() {
        Mockito.reset(mockNetkiKeyProvider)
    }

    @Test
    fun `Generate certificate for attestations successfully`() {
        `when`(mockNetkiKeyProvider.requestTransactionId(ATTESTATIONS_REQUESTED)).thenReturn(TRANSACTION_ID)
        doNothing().`when`(mockNetkiKeyProvider).submitCsrsAttestations(TRANSACTION_ID, CSRS_ATTESTATIONS)
        `when`(mockNetkiKeyProvider.getCertificates(TRANSACTION_ID)).thenReturn(CERTIFICATE_ATTESTATION_RESPONSE)

        val attestationCertificate = keyGeneration.generateCertificates(ATTESTATIONS_INFORMATION)

        assertEquals(attestationCertificate.size, CERTIFICATE_ATTESTATION_RESPONSE.count)
    }

    @Test
    fun `Generate certificate for attestations with invalid data`() {
        val attestationInformation = AttestationInformation(
            Attestation.LEGAL_PERSON_NAME,
            IvmsConstraint.LEGL,
            "This is invalid data #$#$#$"
        )
        val attestationInformationInvalid = listOf(attestationInformation)

        val exception = assertThrows(CertificateProviderException::class.java) {
            keyGeneration.generateCertificates(attestationInformationInvalid)
        }

        assert(
            exception.message != null && exception.message!!.contains(
                String.format(
                    CERTIFICATE_INFORMATION_STRING_NOT_CORRECT_ERROR_PROVIDER,
                    attestationInformation.data,
                    attestationInformation.attestation
                )
            )
        )
    }

    @Test
    fun `Generate certificate for attestations returning empty list of certificates`() {
        `when`(mockNetkiKeyProvider.requestTransactionId(ATTESTATIONS_REQUESTED)).thenReturn(TRANSACTION_ID)
        doNothing().`when`(mockNetkiKeyProvider).submitCsrsAttestations(TRANSACTION_ID, CSRS_ATTESTATIONS)
        `when`(mockNetkiKeyProvider.getCertificates(TRANSACTION_ID)).thenReturn(
            CertificateAttestationResponse(
                0,
                emptyList()
            )
        )

        val attestationCertificate = keyGeneration.generateCertificates(ATTESTATIONS_INFORMATION)

        assertTrue(attestationCertificate.isEmpty())
    }
}

