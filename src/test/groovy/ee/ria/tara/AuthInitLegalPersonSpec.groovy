package ee.ria.tara

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Unroll

import static org.hamcrest.Matchers.equalTo
import static org.junit.jupiter.api.Assertions.*
import static org.hamcrest.MatcherAssert.assertThat

@IgnoreIf({ properties['test.deployment.env'] != "idp" })
class AuthInitLegalPersonSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    @Feature("AUTH_REDIRECT_TO_LEGALPERSON_INIT")
    @Feature("OIDC_SCOPE_LEGALPERSON")
    def "request initialize legal person authentication"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001017705", "69000366", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(acceptResponse.getHeader("location"), Matchers.containsString(flow.loginService.authLegalInitUrl))

        Response response = Steps.followRedirectWithSessionId(flow, acceptResponse)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        assertEquals("et", response.getHeader("Content-Language"), "Correct header attribute Content-Language")
        assertThat(response.body().htmlPath().get("**.find { it.@id == 'btn-select-legal-person'}").toString(), equalTo("Jätkan"))
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "request initialize legal person authentication with security checks"() {
        expect:
        Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response response = Steps.authInitAsLegalPerson(flow, "60001017705", "69000366")
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("text/html;charset=UTF-8", response.getContentType(), "Correct content type")
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid session ID"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalInitUrl)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    @Ignore // TARA2-80 TARA2-165
    @Unroll
    @Feature("LEGAL_PERSON_INIT_START_ENDPOINT")
    def "request initialize legal person authentication with invalid method post"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthLegalInitUrl)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), equalTo("Request method 'POST' not supported"))
    }

}
