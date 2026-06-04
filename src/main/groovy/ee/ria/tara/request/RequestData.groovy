package ee.ria.tara.request

import ee.ria.tara.Utils
import ee.ria.tara.configuration.ConfigHolder
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
        X509Certificate cert = Utils.getCertificateFromKeystore(
                "src/test/resources/joeorg_auth_EC.p12", "1234", "1")
        X509Certificate issuerCert = Utils.getIssuerCertificate(
                ConfigHolder.testConf.idCardIssuerCertsPath(), cert.issuerX500Principal)
        ocspRequestBody(cert, issuerCert, hasNonce, nonce)
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
