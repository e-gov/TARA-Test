package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.hasItem
import static org.hamcrest.Matchers.is

class LegalPersonAuthSpec extends TaraSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
        flow.openIdServiceConfiguration = Requests.getOpenidConfiguration(flow.oidcService.fullConfigurationUrl)
        flow.jwkSet = JWKSet.load(Requests.getOpenidJwks(flow.oidcService.fullJwksUrl))
    }

    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.authInitAsLegalPerson(flow)

        when:
        Response response = Steps.loadLegalPersonsList(flow)
        // TODO: better environment selection solution here
        List<String> legalPersonIdentifiers = response.jsonPath().getList("legalPersons.legalPersonIdentifier")
        List<String> legalPersonNames = response.jsonPath().getList("legalPersons.legalName")

        then:
        if (flow.loginService.baseUrl.contains("service-backend")) { //local environment
            assertThat("Correct legal name", legalPersonNames, is("Acme INC OÜ"))
            assertThat("Correct person identifier", legalPersonIdentifiers, is("12341234"))
        } else {
            // other environments
            assertThat("Correct legal name", legalPersonNames, hasItem("Eesti Kurtide Spordiliit"))
            assertThat("Correct person identifier", legalPersonIdentifiers, hasItem("80092803"))
        }
    }

    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "legal persons authentication request with security checks"() {
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
    def "legal persons authentication request with invalid cookie: #reason"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow, "openid legalperson")
        Steps.authInitAsLegalPerson(flow)

        when: "Request legal person authentication with invalid session cookie"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(cookie)
                .when()
                .get(flow.loginService.fullAuthLegalPersonUrl)
                .then()
                .extract().response()

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
    def "legal persons authentication request with invalid method: #requestType"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, "60001019906", "00000766")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithParams(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.followRedirectWithSessionId(flow, acceptResponse)

        when: "legal persons authentication request with invalid method"
        Response response = given()
                .relaxedHTTPSValidation()
                .cookies(["SESSION": flow.sessionId])
                .params(["_csrf": flow.csrf])
                .when()
                .request(requestType, flow.loginService.fullAuthLegalPersonUrl)
                .then()
                .extract().response()

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
