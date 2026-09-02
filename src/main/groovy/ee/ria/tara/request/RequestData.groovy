package ee.ria.tara.request

import ee.ria.tara.Utils
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder

import java.security.SecureRandom
import java.security.cert.X509Certificate

class RequestData {

    static final String DEFAULT_KEYSTORE = "src/test/resources/EE38001085718_auth_EC_TEST_of_ESTEID2018.p12"
    static final String DEFAULT_KEYSTORE_PASSWORD = "1234"

    static byte[] ocspRequestDefaultBody(boolean hasNonce, byte[] nonce = null) {
        return ocspRequestBody(defaultChain(), hasNonce, nonce)
    }

    static X509Certificate[] defaultChain() {
        return Utils.getCertificateChainFromKeystore(DEFAULT_KEYSTORE, DEFAULT_KEYSTORE_PASSWORD)
    }

    static byte[] ocspRequestBody(X509Certificate[] chain, boolean hasNonce, byte[] nonce = null) {
        X509Certificate[] leafAndIssuer = resolveLeafAndIssuer(chain)
        return ocspRequestBody(leafAndIssuer[0], leafAndIssuer[1], hasNonce, nonce)
    }

    static byte[] ocspRequestBody(X509Certificate cert, X509Certificate issuerCert, boolean hasNonce, byte[] nonce = null) {
        return ocspRequestBodyFromCertIds([buildCertificateId(cert, issuerCert, CertificateID.HASH_SHA1)], hasNonce, nonce)
    }

    static CertificateID certificateId(X509Certificate[] chain, AlgorithmIdentifier digestAlgorithm) {
        X509Certificate[] leafAndIssuer = resolveLeafAndIssuer(chain)
        return buildCertificateId(leafAndIssuer[0], leafAndIssuer[1], digestAlgorithm)
    }

    static byte[] ocspRequestBodyFromCertIds(List<CertificateID> certIds, boolean hasNonce, byte[] nonce = null) {
        def builder = new OCSPReqBuilder()
        certIds.each { builder.addRequest(it) }

        if (hasNonce) {
            if (nonce == null) {
                nonce = new byte[16]
                new SecureRandom().nextBytes(nonce)
            }

            def nonceExtension = new Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                    true,
                    new DEROctetString(new DEROctetString(nonce))
            )
            builder.setRequestExtensions(
                    new Extensions([nonceExtension] as Extension[])
            )
        }

        return builder.build().encoded
    }

    private static X509Certificate[] resolveLeafAndIssuer(X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("Cannot build OCSP request: certificate chain is empty")
        }
        X509Certificate leaf = chain[0]
        X509Certificate issuer = chain.find { it.subjectX500Principal == leaf.issuerX500Principal }
        if (issuer == null) {
            throw new IllegalStateException("Cannot build OCSP request: no issuer certificate for " +
                    "${leaf.subjectX500Principal} (issued by ${leaf.issuerX500Principal}).")
        }
        return [leaf, issuer] as X509Certificate[]
    }

    private static CertificateID buildCertificateId(X509Certificate cert, X509Certificate issuerCert,
                                                    AlgorithmIdentifier digestAlgorithm) {
        def digCalcProv = new JcaDigestCalculatorProviderBuilder().build()
        return new CertificateID(
                digCalcProv.get(digestAlgorithm),
                new JcaX509CertificateHolder(issuerCert),
                cert.serialNumber
        )
    }
}
