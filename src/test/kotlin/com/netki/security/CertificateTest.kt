package com.netki.security

import com.netki.exceptions.InvalidCertificateException
import com.netki.util.TestData
import com.netki.util.TestData.KeyPairs.INTERMEDIATE_CERTIFICATE_RANDOM
import com.netki.util.TestData.KeyPairs.ROOT_CERTIFICATE_RANDOM
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.cert.X509Certificate

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class CertificateTest {

    private val rootCertificateRandom = ROOT_CERTIFICATE_RANDOM.toCertificate() as X509Certificate
    private val intermediateCertificateRandom = INTERMEDIATE_CERTIFICATE_RANDOM.toCertificate() as X509Certificate

    @Test
    fun `Verify root certificate is self signed`() {
        assert(rootCertificateRandom.isSelfSigned())
    }

    @Test
    fun `Verify intermediate certificate is not self signed`() {
        assert(!intermediateCertificateRandom.isSelfSigned())
    }

    @Test
    fun `Verify client certificate is not self signed`() {
        assert(!intermediateCertificateRandom.isSelfSigned())
    }

    @Test
    fun `Verify correct certificate expiration date for valid certificate`() {
        assert(Certificate.validateCertificateExpiration(TestData.KeyPairs.CLIENT_CERTIFICATE_CHAIN_ONE))
    }

    @Test
    fun `Verify incorrect certificate expiration date for expired certificate`() {
        val exception = assertThrows(InvalidCertificateException::class.java) {
            Certificate.validateCertificateExpiration(TestData.KeyPairs.CLIENT_CERTIFICATE_EXPIRED)
        }
        assert(exception.message?.contains("The certificate is expired") ?: false)
    }

    @Test
    fun `Verify that a certificate is revoked`() {
        val exception = assertThrows(InvalidCertificateException::class.java) {
            Certificate.validateCertificateRevocation(TestData.KeyPairs.CLIENT_CERT_REVOKED)
        }
        assert(exception.message?.contains("The certificate is revoked by CRL") ?: false)
    }

    @Test
    fun `Verify a certificate is EV type`() {
        assert(Certificate.isEvCertificate(TestData.KeyPairs.EV_CERT))
    }

    @Test
    fun `Verify a certificate is not EV type`() {
        assertFalse(Certificate.isEvCertificate(TestData.KeyPairs.CLIENT_CERTIFICATE_CHAIN_ONE))
    }
}
