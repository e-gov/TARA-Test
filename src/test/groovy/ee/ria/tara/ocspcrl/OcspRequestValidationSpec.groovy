package ee.ria.tara.ocspcrl

import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.Issuer
import ee.ria.tara.request.RequestData
import ee.ria.tara.step.OcspCrlSteps
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class OcspRequestValidationSpec extends TaraSpecification {

    def "Fallback OCSP request without nonce returns MALFORMED_REQUEST"() {
        given: "an OCSP request built without the nonce extension"
        byte[] ocspRequestBody = RequestData.ocspRequestDefaultBody(false)

        when:
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then:
        response.then().statusCode(HttpStatus.SC_OK)
        assertThat(OcspCrlSteps.extractOcspResp(response).status, is(OCSPResp.MALFORMED_REQUEST))
    }

    def "Fallback OCSP request with more than one certificate returns MALFORMED_REQUEST"() {
        given: "an OCSP request whose requestList holds two entries"
        CertificateID certId = RequestData.certificateId(RequestData.defaultChain(), CertificateID.HASH_SHA1)
        byte[] ocspRequestBody = RequestData.ocspRequestBodyFromCertIds([certId, certId], true)

        when:
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then: "the service supports a single-entry requestList only"
        response.then().statusCode(HttpStatus.SC_OK)
        assertThat(OcspCrlSteps.extractOcspResp(response).status, is(OCSPResp.MALFORMED_REQUEST))
    }

    def "Fallback OCSP request with non-SHA-1 CertID digest: '#digestAlgorithm' returns MALFORMED_REQUEST"() {
        given:
        CertificateID certId = RequestData.certificateId(RequestData.defaultChain(),
                new DefaultDigestAlgorithmIdentifierFinder().find(digestAlgorithm))
        byte[] ocspRequestBody = RequestData.ocspRequestBodyFromCertIds([certId], true)

        when:
        Response response = OcspCrlSteps.ocspRequest(flow, ocspRequestBody, Issuer.TEST_OF_ESTEID2018)

        then: "the service accepts SHA-1 CertID hashes only"
        response.then().statusCode(HttpStatus.SC_OK)
        assertThat(OcspCrlSteps.extractOcspResp(response).status, is(OCSPResp.MALFORMED_REQUEST))

        where:
        digestAlgorithm << ["SHA-256", "SHA-512"]
    }
}
