package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.hasSize
import static org.hamcrest.Matchers.is
import static org.hamcrest.Matchers.not

class LegalPersonAuthSpec extends TaraSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "Legal persons authentication request should return correct legal person name"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow)

        when:
        Response response = Steps.loadLegalPersonsList(flow)
        List<String> legalPersonIdentifiers = response.jsonPath().getList("legalPersons.legalPersonIdentifier")
        List<String> legalPersonNames = response.jsonPath().getList("legalPersons.legalName")

        then:
        assertThat("Legal person name present", legalPersonNames, not((hasSize(0))))
        assertThat("Legal person identifier present", legalPersonIdentifiers, not((hasSize(0))))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Legal persons authentication request with security checks should succeed"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow, "openid legalperson")
        Steps.authInitAsLegalPerson(flow)

        when:
        Response response = Steps.loadLegalPersonsList(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "Legal persons authentication request with invalid cookie should fail: #reason"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow, "openid legalperson")
        Steps.authInitAsLegalPerson(flow)

        when: "Request legal person authentication with invalid session cookie"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .get(flow.loginService.fullAuthLegalPersonUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))

        where:
        cookie               | reason
        [:]                  | "no cookie"
        [SESSION: null]      | "empty cookie"
        [SESSION: "1234567"] | "incorrect cookie value"
    }

    //TODO: AUT-630
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "Legal persons authentication request with invalid method should fail: #requestType"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, "60001019906", "00000766")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.followRedirectWithSessionId(flow, acceptResponse)

        when: "legal persons authentication request with invalid method"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(["SESSION": flow.sessionId])
                .params(["_csrf": flow.csrf])
                .request(requestType, flow.loginService.fullAuthLegalPersonUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))

        where:
        requestType | _
        "POST"      | _
        "PUT"       | _
        "PATCH"     | _
        "DELETE"    | _
    }
}
