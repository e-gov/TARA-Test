package ee.ria.tara

import com.nimbusds.jose.jwk.JWKSet
import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response

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
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")

        when:
        Response response = Steps.loadLegalPersonsList(flow)
        // TODO: better environment selection solution here
        List<String> legalPersonIdentifiers = response.jsonPath().getList("legalPersons.legalPersonIdentifier")
        List<String> legalPersonNames = response.jsonPath().getList("legalPersons.legalName")

        then:
        if(flow.loginService.baseUrl.contains("service-backend")) { //local environment
            assertThat("Correct legal name", legalPersonNames, is("Acme INC OÜ"))
            assertThat("Correct person identifier", legalPersonIdentifiers, is("12341234"))
        }  else {
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
        Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")

        when:
        Response response = Steps.loadLegalPersonsList(flow)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(200))
        Steps.verifyResponseHeaders(response)
    }

    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid session ID"() {
        given:
        flow.setSessionId("1234567")

        when:
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalPersonUrl)

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(400))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_BAD_REQUEST))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_SESSION_NOT_FOUND))
    }

    //TODO: AUT-630
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid method post"() {
        given:
        Steps.startAuthenticationInTaraWithLegalPerson(flow)
        Steps.initMidAuthSession(flow, flow.sessionId, "60001019906", "00000766")
        Steps.pollMidResponse(flow)
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        Steps.followRedirectWithSessionId(flow, acceptResponse)
        Map cookiesMap = ["SESSION": flow.sessionId]
        Map formParamsMap = ["_csrf": flow.csrf]

        when:
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalPersonUrl, cookiesMap, formParamsMap, [:])

        then:
        assertThat("Correct HTTP status code", response.statusCode, is(500))
        assertThat("Correct Content-Type", response.contentType, is("application/json;charset=UTF-8"))
        assertThat("Correct error", response.jsonPath().getString("error"), is(ERROR_INTERNAL))
        assertThat("Correct message", response.jsonPath().getString("message"), is(MESSAGE_INTERNAL_ERROR))
    }
}
