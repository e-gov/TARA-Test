package ee.ria.tara.ocspcrl

import ee.ria.tara.Requests
import ee.ria.tara.TaraSpecification
import ee.ria.tara.Utils
import ee.ria.tara.configuration.ConfigHolder
import ee.ria.tara.model.Issuer
import ee.ria.tara.request.RequestData
import ee.ria.tara.step.OcspCrlSteps
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateStatus
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.SingleResp
import org.bouncycastle.operator.ContentVerifierProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder

import java.security.SecureRandom
import java.security.cert.X509Certificate

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class FallbackOcspSpec extends TaraSpecification {

    def "Fallback OCSP request returns GOOD"() {
        given:
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = Requests.postOcspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        response.then().statusCode(HttpStatus.SC_OK)

        byte[] ocspResponseBytes = response.then().extract().asByteArray()
        OCSPResp ocspResponse = new OCSPResp(ocspResponseBytes)
        assertThat(ocspResponse.status, is(OCSPResp.SUCCESSFUL))

        BasicOCSPResp basicResp = ocspResponse.responseObject as BasicOCSPResp
        assertThat(basicResp.responses.size(), is(1))
        SingleResp singleResp = basicResp.responses[0]
        assertThat(singleResp.certStatus, is(CertificateStatus.GOOD))
    }

    // TODO: Fallback OCSP request returns Unknown/Revoked
    //        assertThat(singleResp.certStatus, is(instanceOf(UnknownStatus/RevokedStatus)))

    def "Fallback OCSP response has valid signature"() {
        given:
        X509Certificate ocspIssuerCert = Utils.loadCertificate(ConfigHolder.testConf.ocspResponderCertPath())
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true)

        when:
        Response response = Requests.postOcspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        BasicOCSPResp basicResp = OcspCrlSteps.extractBasicOCSPResp(response)

        // Verify signature
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .build(ocspIssuerCert.publicKey)
        assert basicResp.isSignatureValid(verifierProvider)
    }

    def "Fallback OCSP response has valid nonce"() {
        given:
        byte[] nonce = new byte[16]
        new SecureRandom().nextBytes(nonce)
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(true, nonce)

        when:
        Response response = Requests.postOcspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        BasicOCSPResp basicResp = OcspCrlSteps.extractBasicOCSPResp(response)

        // Verify nonce
        byte[] returnedNonce = ASN1OctetString.getInstance(
                basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).extnValue.octets
        ).octets
        assertThat(returnedNonce, is(nonce))
    }
}
