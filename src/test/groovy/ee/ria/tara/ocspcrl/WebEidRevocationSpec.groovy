package ee.ria.tara.ocspcrl

import com.nimbusds.jose.jwk.JWKSet
import ee.ria.tara.Requests
import ee.ria.tara.TaraSpecification
import ee.ria.tara.model.ErrorMessage
import ee.ria.tara.step.EidTestPkiClient
import ee.ria.tara.step.WebEidSteps
import ee.ria.tara.util.ErrorValidator
import ee.ria.tara.util.PersonCodeGenerator
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.json.JSONObject
import spock.lang.Isolated
import spock.lang.Tag
import spock.util.concurrent.PollingConditions

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

@Isolated("Mutates CA-wide OCSP/CRL state in the eID test PKI")
@Tag("ee-eid-test-pki")
class WebEidRevocationSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

//    Duplicates the TEST of ESTEID2018 test in WebEidAuthSpec,
//    but relies on test-pki instead of hardcoded certificate and SK service
    @Feature("REJECT_REVOKED_CERTS")
    def "Web eID authentication with a revoked certificate returns IDC_REVOKED"() {
        given: "a freshly issued community ID-card certificate"
        String caId = "community-esteid2018"
        String code = PersonCodeGenerator.generateEstonianPersonCode()
        EidTestPkiClient.issueAuthCert(caId, code, "TESTER", "TESTING")

        byte[] authCertP12 = EidTestPkiClient.getAuthCertP12(caId, code, "1234")

        and: "revoked in the test PKI"
        EidTestPkiClient.setAuthCertStatus(caId, code, "revoked", "keyCompromise")

        when: "authentication is retried until the revocation reaches the OCSP responder TARA queries"
        // The assignment sits inside the assert deliberately: Spock's condition transform rejects a
        // bare assignment in a PollingConditions closure, and the response has to escape it.
        Response loginWebEid = null
        new PollingConditions(timeout: 120, delay: 5).eventually {
            JSONObject authToken = WebEidSteps.authenticationFlowToWebEidParams(flow, authCertP12)
            assert (loginWebEid = Requests.postRequestWithJsonBody(
                    flow, flow.loginService.fullWebEidLoginUrl, authToken)).statusCode == ErrorMessage.IDC_REVOKED.statusCode
        }

        then:
        ErrorValidator.validate(loginWebEid, ErrorMessage.IDC_REVOKED)
        loginWebEid.then().body("reportable", is(false))
    }

    def "Web eID authentication with a certificate unknown to the CA OCSP responder succeeds (via fallback)"() {
        given: "a freshly issued community ID-card certificate"
        String caId = "community-esteid2018"
        String code = PersonCodeGenerator.generateEstonianPersonCode()
        EidTestPkiClient.issueAuthCert(caId, code, "TESTER", "TESTING")

        byte[] authCertP12 = EidTestPkiClient.getAuthCertP12(caId, code, "1234")

        and: "the responder is made to disclaim knowledge of it"
        EidTestPkiClient.setAuthCertStatus(caId, code, "unknown")

        when:
        JSONObject authToken = WebEidSteps.authenticationFlowToWebEidParams(flow, authCertP12)
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then: "the unknown status is treated as a failed check, not as a revocation"
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(200))
        assertThat("Correct status", loginWebEid.jsonPath().getString("status"), is("COMPLETED"))

        cleanup: "restore the index row so the leaf is answerable again"
        EidTestPkiClient.setAuthCertStatus(caId, code, "good")
    }

    // With the CA's own OCSP responder unavailable, TARA must fall through to the configured fallback.
    def "Web eID authentication with the CA OCSP responder unavailable succeeds"() {
        given: "a freshly issued, non-revoked community ID-card certificate"
        String caId = "community-esteid2018"
        String code = PersonCodeGenerator.generateEstonianPersonCode()
        EidTestPkiClient.issueAuthCert(caId, code, "TESTER", "TESTING")
        byte[] authCertP12 = EidTestPkiClient.getAuthCertP12(caId, code, "1234")

        and: "the CA's OCSP responder is taken out of service"
        EidTestPkiClient.setOcspEnabled(caId, false)

        when:
        JSONObject authToken = WebEidSteps.authenticationFlowToWebEidParams(flow, authCertP12)
        Response loginWebEid = Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)

        then: "authentication completes"
        assertThat("Correct HTTP status code", loginWebEid.statusCode, is(200))
        assertThat("Correct status", loginWebEid.jsonPath().getString("status"), is("COMPLETED"))

        cleanup:
        EidTestPkiClient.setOcspEnabled(caId, true)
    }

    // Certificate set REVOKED -> OcspCrl reads the CRL with revocation
    // OCSP disabled -> TARA responds REVOKED (from fallback)
    // CRL disabled so it's no longer updated
    // Certificate set GOOD and OCSP enabled -> TARA responds GOOD (from primary)
    // Certificate set UNKNOWN -> TARA responds REVOKED (UNKNOWN from primary -> REVOKED from fallback stale CRL)
    def "Web eID authentication with an uncertain CA OCSP responder returns IDC_REVOKED from stale CRL data"() {
        given: "a freshly issued community ID-card certificate, revoked so the revocation reaches the CRL"
        String caId = "community-esteid2018"
        String code = PersonCodeGenerator.generateEstonianPersonCode()
        EidTestPkiClient.issueAuthCert(caId, code, "TESTER", "TESTING")
        byte[] authCertP12 = EidTestPkiClient.getAuthCertP12(caId, code, "1234")
        EidTestPkiClient.setAuthCertStatus(caId, code, "revoked", "keyCompromise")

        and: "the CA's OCSP responder is taken out of service, leaving only the fallback"
        EidTestPkiClient.setOcspEnabled(caId, false)

        when: "authentication is retried until the revocation reaches TARA through the fallback CRL"
        Response revokedViaCrl = null
        new PollingConditions(timeout: 120, delay: 5).eventually {
            assert (revokedViaCrl = submitWebEidLogin(authCertP12)).statusCode == ErrorMessage.IDC_REVOKED.statusCode
        }

        then: "the fallback carries revocation data, not merely a failure"
        ErrorValidator.validate(revokedViaCrl, ErrorMessage.IDC_REVOKED)

        when: "CRL publication is frozen, then the certificate is restored and the responder brought back"
        EidTestPkiClient.setCrlEnabled(caId, false)
        EidTestPkiClient.setAuthCertStatus(caId, code, "good")
        EidTestPkiClient.setOcspEnabled(caId, true)

        Response goodViaOcsp = null
        new PollingConditions(timeout: 60, delay: 5).eventually {
            assert (goodViaOcsp = submitWebEidLogin(authCertP12)).statusCode == 200
        }

        then: "a working primary responder decides, and the fallback's stale CRL is not consulted"
        assertThat("Correct status", goodViaOcsp.jsonPath().getString("status"), is("COMPLETED"))

        when: "the primary responder is made uncertain about the certificate"
        EidTestPkiClient.setAuthCertStatus(caId, code, "unknown")

        Response revokedViaStaleCrl = null
        new PollingConditions(timeout: 60, delay: 5).eventually {
            assert (revokedViaStaleCrl = submitWebEidLogin(authCertP12)).statusCode == ErrorMessage.IDC_REVOKED.statusCode
        }

        then: "the fallback decides again, from a CRL that still lists the certificate as revoked"
        ErrorValidator.validate(revokedViaStaleCrl, ErrorMessage.IDC_REVOKED)

        cleanup:
        EidTestPkiClient.setCrlEnabled(caId, true)
        EidTestPkiClient.setOcspEnabled(caId, true)
        EidTestPkiClient.setAuthCertStatus(caId, code, "good")
    }

    private Response submitWebEidLogin(byte[] p12Bytes) {
        JSONObject authToken = WebEidSteps.authenticationFlowToWebEidParams(flow, p12Bytes)
        return Requests.postRequestWithJsonBody(flow, flow.loginService.fullWebEidLoginUrl, authToken)
    }
}
