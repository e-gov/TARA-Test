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
class AuthLegalPersonSpec extends TaraSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initLegalPersonResponse = Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response response = Steps.loadLegalPersonsList(flow)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertTrue(response.body().jsonPath().getList("legalPersons").size() > 0)
        assertTrue(response.body().jsonPath().getList("legalPersons.legalName").size() > 0)
        assertTrue(response.body().jsonPath().getList("legalPersons.legalPersonIdentifier").size() > 0)
        // TODO better environment selection solution here
        List<String> legalPersonIdentifiers = response.body().jsonPath().getList("legalPersons.legalPersonIdentifier")
        List<String> legalPersonNames = response.body().jsonPath().getList("legalPersons.legalName")
        if(flow.loginService.baseUrl.contains("service-backend")) { //local environment
            assertTrue(legalPersonNames.contains("Acme INC OÜ"))
            assertTrue(legalPersonIdentifiers.contains("12341234"))
        }  else {
            // other environments
            assertTrue(legalPersonNames.contains("täisühing VAVILOV") || legalPersonNames.contains("AS Hallebygg"))
            assertTrue(legalPersonIdentifiers.contains("10910878") || legalPersonIdentifiers.contains("12597552"))
        }
    }

    @Unroll
    @Feature("DISALLOW_IFRAMES")
    @Feature("CSP_ENABLED")
    @Feature("HSTS_ENABLED")
    @Feature("SECURE_COOKIE_HANDLING")
    @Feature("CACHE_POLICY")
    @Feature("NOSNIFF")
    @Feature("XSS_DETECTION_FILTER_ENABLED")
    def "legal persons authentication request with security checks"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initLegalPersonResponse = Steps.authInitAsLegalPerson(flow, "60001019906", "00000766")
        Response response = Steps.loadLegalPersonsList(flow)
        assertEquals(200, response.statusCode(), "Correct HTTP status code is returned")
        Steps.verifyResponseHeaders(response)
    }

    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid session ID"() {
        expect:
        flow.setSessionId("1234567")
        Response response = Requests.getRequestWithSessionId(flow, flow.loginService.fullAuthLegalPersonUrl)
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertEquals("Teie sessiooni ei leitud! Sessioon aegus või on küpsiste kasutamine Teie brauseris piiratud.", response.body().jsonPath().get("message"), "Correct error message is returned")
    }

    @Ignore // TARA2-165
    @Unroll
    @Feature("LEGAL_PERSON_AUTH_START_ENDPOINT")
    def "legal persons authentication request with invalid method post"() {
        expect:
        Response initClientAuthenticationSession = Steps.startAuthenticationInTara(flow, "openid legalperson")
        Response initMidAuthenticationSession = Steps.initMidAuthSession(flow, flow.sessionId, "60001019906", "00000766", Collections.emptyMap())
        assertEquals(200, initMidAuthenticationSession.statusCode(), "Correct HTTP status code is returned")
        Response pollResponse = Steps.pollMidResponse(flow)
        assertEquals(200, pollResponse.statusCode(), "Correct HTTP status code is returned")
        assertThat(pollResponse.body().jsonPath().get("status").toString(), Matchers.not(equalTo("PENDING")))
        Response acceptResponse = Requests.postRequestWithSessionId(flow, flow.loginService.fullAuthAcceptUrl)
        assertEquals(302, acceptResponse.statusCode(), "Correct HTTP status code is returned")
        // /auth/legal_person/init
        Response initLegalResponse = Steps.followRedirectWithSessionId(flow, acceptResponse)
        HashMap<String, String> cookiesMap = (HashMap)Collections.emptyMap()
        def map2 = Utils.setParameter(cookiesMap, "SESSION",flow.sessionId)
        HashMap<String, String> formParamsMap = (HashMap) Collections.emptyMap()
        Utils.setParameter(formParamsMap, "_csrf", flow.csrf)
        Response response = Requests.postRequestWithCookiesAndParams(flow, flow.loginService.fullAuthLegalPersonUrl, cookiesMap, formParamsMap, Collections.emptyMap())
        assertEquals(400, response.statusCode(), "Correct HTTP status code is returned")
        assertEquals("application/json;charset=UTF-8", response.getContentType(), "Correct Content-Type is returned")
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Request method 'POST' not supported"))
    }

}
