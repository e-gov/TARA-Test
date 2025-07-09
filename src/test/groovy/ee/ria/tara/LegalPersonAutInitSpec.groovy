package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is

class LegalPersonAutInitSpec extends TaraSpecification {

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    @Feature("AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    @Feature("OIDC_SCOPE_LEGALPERSON")
    def "Request initialize legal person authentication should succeed"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, "60001017705", "69000366")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)

        when:
        Response response = Steps.followRedirectWithSessionId(flow, acceptResponse)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        assertThat("Continue button present", response.htmlPath().getString("**.find { it.@id == 'btn-select-legal-person'}"), is("Jätka"))
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "Request initialize legal person authentication with security checks should succeed"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)

        when:
        Response response = Steps.authInitAsLegalPerson(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        assertThat("Correct Content-Type", response.contentType, is("text/html;charset=UTF-8"))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "Request initialize legal person authentication with invalid session cookie should fail: #reason"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)

        when: "request authentication with invalid session cookie"
        Response response = given()
                .cookies(cookie)
                .get(flow.loginService.fullAuthLegalInitUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))

        where:
        cookie                        | reason
        [:]                           | "no cookie"
        ["__Host-SESSION": null]      | "empty cookie"
        ["__Host-SESSION": "1234567"] | "incorrect cookie value"
    }

    //TODO: AUT-630
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "Request initialize legal person authentication with invalid method should fail: #requestType"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, "60001017705", "69000366")
        Steps.pollMidResponse(flow)
        Requests.postRequest(flow, flow.loginService.fullAuthAcceptUrl)

        when: "request legal person authentication with invalid request type"
        Response response = Requests.requestWithType(flow, requestType, flow.loginService.fullAuthLegalInitUrl)

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
