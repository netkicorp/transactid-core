package com.netki.security

import com.netki.security.Parameters.KEY_ALGORITHM
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.StringReader
import java.io.StringWriter
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

object Keys {

    /**
     * Generate a keypair.
     *
     * @return key pair generated.
     */
    fun generateKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }
}

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

/**
 * Transform PrivateKey to String in PEM format.
 *
 * @param privateKey to transform.
 * @return String in PEM format.
 */
fun PrivateKey.toPemFormat() = objectToPemString(this)

/**
 * Transform PublicKey to String in PEM format.
 *
 * @param publicKey to transform.
 * @return String in PEM format.
 */
fun PublicKey.toPemFormat() = objectToPemString(this)

/**
 * Transform Certificate to String in PEM format.
 *
 * @param certificate to transform.
 * @return String in PEM format.
 */
fun Certificate.toPemFormat() = objectToPemString(this)

/**
 * Transform Object to String in PEM format.
 *
 * @param objectToParse one of PrivateKey / PublicKey / Certificate.
 * @return String in PEM format.
 */
private fun objectToPemString(objectToParse: Any): String {
    val stringWriter = StringWriter()
    val pemWriter = PemWriter(stringWriter)
    when (objectToParse) {
        is PrivateKey -> pemWriter.writeObject(PemObject("PRIVATE KEY", objectToParse.encoded))
        is PublicKey -> pemWriter.writeObject(PemObject("PUBLIC KEY", objectToParse.encoded))
        is Certificate -> pemWriter.writeObject(PemObject("CERTIFICATE", objectToParse.encoded))
    }
    pemWriter.flush()
    pemWriter.close()
    return stringWriter.toString()
}
