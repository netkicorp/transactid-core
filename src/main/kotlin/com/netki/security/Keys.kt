package com.netki.security

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io.ByteArrayInputStream
import java.io.StringReader
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

/**
 * Transform PrivateKey in PEM format to object.
 *
 * @return PrivateKey.
 */
fun String.toPrivateKey(): PrivateKey = this.stringPemToObject() as PrivateKey

/**
 * Transform PublicKey in PEM format to object.
 *
 * @param publicKeyPem string.
 * @return PublicKey.
 */
fun String.toPublicKey() = this.stringPemToObject() as PublicKey

/**
 * Transform Certificate in PEM format to Object.
 *
 * @param certificatePem string.
 * @return Certificate.
 */
fun String.toCertificate() = this.stringPemToObject() as Certificate

/**
 * Transform String in PEM format representing one of PrivateKey / PublicKey / Certificate to Object.
 *
 * @return Object.
 */
fun String.stringPemToObject(): Any {
    Security.addProvider(BouncyCastleProvider())

    val pemParser = PEMParser(StringReader(this))
    return when (val pemObject = pemParser.readObject()) {
        is X509CertificateHolder -> JcaX509CertificateConverter().getCertificate(pemObject)
        is PrivateKeyInfo -> JcaPEMKeyConverter().getPrivateKey(pemObject)
        is SubjectPublicKeyInfo -> JcaPEMKeyConverter().getPublicKey(pemObject)
        else -> throw IllegalArgumentException("String not supported")
    }
}

/**
 * Convert certificates in PEM format to Object.
 *
 * @param certificatesPem string.
 * @return List of certificates.
 */
@Suppress("UNCHECKED_CAST")
fun String.toCertificates(): List<X509Certificate> {
    val cf = CertificateFactory.getInstance("X.509")
    return cf.generateCertificates(ByteArrayInputStream(this.toByteArray(Charsets.UTF_8))) as List<X509Certificate>
}

/**
 * Validate if a private key is ECDSA type.
 */
fun String.isECDSAKey(): Boolean {
    val key = this.toPrivateKey()
    return key.algorithm == "ECDSA"
}
