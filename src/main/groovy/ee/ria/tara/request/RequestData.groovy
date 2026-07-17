package ee.ria.tara.request

import ee.ria.tara.Utils
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder

import java.security.SecureRandom
import java.security.cert.X509Certificate

class RequestData {

    static byte[] ocspRequestDefaultBody(boolean hasNonce, byte[] nonce = null) {
        X509Certificate[] chain = Utils.getCertificateChainFromKeystore(
                "src/test/resources/EE38001085718_auth_EC_TEST_of_ESTEID2018.p12", "1234")
        return ocspRequestBody(chain, hasNonce, nonce)
    }

    static byte[] ocspRequestBody(X509Certificate[] chain, boolean hasNonce, byte[] nonce = null) {
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("Cannot build OCSP request: certificate chain is empty")
        }
        X509Certificate leaf = chain[0]
        X509Certificate issuer = chain.find { it.subjectX500Principal == leaf.issuerX500Principal }
        if (issuer == null) {
            throw new IllegalStateException("Cannot build OCSP request: no issuer certificate for " +
                    "${leaf.subjectX500Principal} (issued by ${leaf.issuerX500Principal}).")
        }
        return ocspRequestBody(leaf, issuer, hasNonce, nonce)
    }

    static byte[] ocspRequestBody(X509Certificate cert, X509Certificate issuerCert, boolean hasNonce, byte[] nonce = null) {
        def digCalcProv = new JcaDigestCalculatorProviderBuilder().build()

        def certId = new CertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1),
                new JcaX509CertificateHolder(issuerCert),
                cert.serialNumber
        )

        def builder = new OCSPReqBuilder()
        builder.addRequest(certId)

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
}
